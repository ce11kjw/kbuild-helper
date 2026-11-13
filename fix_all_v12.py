#!/usr/bin/env python3
"""
SELinux 5.4 审查修正 v12（最终版，幂等）

修 7 个缺陷：
 [1] latest_granting 偏移错位 → 访问器
 [2] double free → pol = NULL + 判空
 [3] sidtab 浅拷贝 UAF → 递归深拷贝 + context_cpy
 [4] destroy 对 view 炸全局策略 → KSU54_POL_IS_OWNED 保护
 [5] 函数调用当左值 → set_granting()
 [6] 替换顺序吃掉前缀 → 先长后短
 [7] reset_avc_cache 读到已释放的 pol → 局部变量
 [7b] 声明必须在函数顶部（-Wdeclaration-after-statement）
"""
import io
import os
import re
import sys

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
SUDIR = os.path.join(KDIR, 'KernelSU', 'kernel')
if not os.path.isdir(SUDIR):
    SUDIR = os.path.join(KDIR, 'drivers', 'kernelsu')

SPH = os.path.join(SUDIR, 'selinux', 'sepolicy.h')
RUL = os.path.join(SUDIR, 'selinux', 'rules.c')
SEC = os.path.join(SUDIR, 'selinux', 'sepolicy.c')
SIH = os.path.join(SUDIR, 'feature', 'selinux_hide.c')

SHIM = r'''#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define KSU54_SELINUX_POLICY_SHIM 1
#include <linux/sched.h>
#include <linux/slab.h>
#include "ss/services.h"
#include "ss/sidtab.h"
#include "ss/context.h"
/*
 * 5.4 has no struct selinux_policy (split out in 5.7); policydb, sidtab and
 * latest_granting live in struct selinux_ss. Two kinds of object use this
 * type below 5.7:
 *
 *   a) a live *view*: selinux_state.ss reinterpreted. Only ->sidtab and
 *      ->policydb may be dereferenced through it (offsets match selinux_ss).
 *   b) a real duplicated policy from ksu_dup_sepolicy(), owning its policydb
 *      and a deep-copied sidtab.
 *
 * latest_granting is NOT reachable through a view: in struct selinux_ss it
 * sits after rwlock_t policy_rwlock, so a cast-based read would land inside
 * the lock. Duplicated policies keep their value in ->ksu54_granting and the
 * accessors below pick the right storage.
 */
struct selinux_policy {
	struct sidtab *sidtab;
	struct policydb policydb;
	/* Only meaningful for duplicated policies. */
	u32 ksu54_granting;
};
extern struct selinux_state selinux_state;

#define KSU54_POL_IS_OWNED(pol) ((void *)(pol) != (void *)selinux_state.ss)

static inline u32 ksu54_pol_get_granting(struct selinux_policy *pol)
{
	if (!pol)
		return 0;
	if (KSU54_POL_IS_OWNED(pol))
		return pol->ksu54_granting;
	return selinux_state.ss->latest_granting;
}

static inline void ksu54_pol_set_granting(struct selinux_policy *pol, u32 v)
{
	if (!pol)
		return;
	if (KSU54_POL_IS_OWNED(pol))
		pol->ksu54_granting = v;
	else
		selinux_state.ss->latest_granting = v;
}

/*
 * Deep-clone a 5.4 sidtab. kmemdup would share the node tree and
 * sidtab_destroy() frees every node it walks, so the clone must own its own
 * nodes; each context is duplicated with context_cpy() for the same reason.
 */
static inline void *ksu54_sidtab_dup_tree(union sidtab_entry_inner src, u32 level)
{
	if (!src.ptr_leaf)
		return NULL;

	if (level != 0) {
		struct sidtab_node_inner *sn = src.ptr_inner;
		struct sidtab_node_inner *dn;
		int i, j;

		dn = kzalloc(sizeof(*dn), GFP_KERNEL);
		if (!dn)
			return NULL;
		for (i = 0; i < SIDTAB_INNER_ENTRIES; i++) {
			void *child;

			if (!sn->entries[i].ptr_leaf)
				continue;
			child = ksu54_sidtab_dup_tree(sn->entries[i], level - 1);
			if (!child) {
				for (j = 0; j < SIDTAB_INNER_ENTRIES; j++) {
					if (!dn->entries[j].ptr_leaf)
						continue;
					if (level - 1 == 0) {
						struct sidtab_node_leaf *lf = dn->entries[j].ptr_leaf;
						int k;
						for (k = 0; k < SIDTAB_LEAF_ENTRIES; k++)
							if (lf->entries[k].sid)
								context_destroy(&lf->entries[k].context);
						kfree(lf);
					} else {
						kfree(dn->entries[j].ptr_inner);
					}
				}
				kfree(dn);
				return NULL;
			}
			dn->entries[i].ptr_inner = child;
		}
		return dn;
	} else {
		struct sidtab_node_leaf *sl = src.ptr_leaf;
		struct sidtab_node_leaf *dl;
		int i;

		dl = kzalloc(sizeof(*dl), GFP_KERNEL);
		if (!dl)
			return NULL;
		for (i = 0; i < SIDTAB_LEAF_ENTRIES; i++) {
			if (!sl->entries[i].sid)
				continue;
			dl->entries[i].sid = sl->entries[i].sid;
			context_init(&dl->entries[i].context);
			if (context_cpy(&dl->entries[i].context,
					&sl->entries[i].context)) {
				int k;
				for (k = 0; k < i; k++)
					if (dl->entries[k].sid)
						context_destroy(&dl->entries[k].context);
				kfree(dl);
				return NULL;
			}
		}
		return dl;
	}
}

static inline struct sidtab *ksu54_sidtab_dup(struct sidtab *src)
{
	struct sidtab *dst;
	u32 level;
	int i;

	if (!src)
		return NULL;

	dst = kzalloc(sizeof(*dst), GFP_KERNEL);
	if (!dst)
		return NULL;

	spin_lock_init(&dst->lock);
	dst->count = src->count;
	dst->convert = NULL;

	for (i = 0; i < SECINITSID_NUM; i++) {
		if (!src->isids[i].set)
			continue;
		dst->isids[i].set = 1;
		context_init(&dst->isids[i].leaf.context);
		if (context_cpy(&dst->isids[i].leaf.context,
				&src->isids[i].leaf.context)) {
			int k;
			for (k = 0; k < i; k++)
				if (dst->isids[k].set)
					context_destroy(&dst->isids[k].leaf.context);
			kfree(dst);
			return NULL;
		}
	}

	level = SIDTAB_MAX_LEVEL;
	while (level && !src->roots[level].ptr_inner)
		--level;
	if (src->roots[level].ptr_leaf) {
		void *tree = ksu54_sidtab_dup_tree(src->roots[level], level);

		if (!tree) {
			for (i = 0; i < SECINITSID_NUM; i++)
				if (dst->isids[i].set)
					context_destroy(&dst->isids[i].leaf.context);
			kfree(dst);
			return NULL;
		}
		dst->roots[level].ptr_leaf = tree;
	}

	for (i = 0; i < (1 << SIDTAB_HASH_BITS); i++)
		INIT_HLIST_HEAD(&dst->context_to_sid[i]);

	return dst;
}
#endif
'''

MACROS = r'''#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define KSU54_POLICY_FIELD
/* The live policy is selinux_state.ss itself, reinterpreted. */
static inline struct selinux_policy *ksu54_live_policy(void)
{
	return (struct selinux_policy *)selinux_state.ss;
}

#define KSU_POLICY_GET() ksu54_live_policy()
/*
 * Push the duplicated policy into the live one. policydb is donated; the
 * generation counter goes through the accessor so a view never writes into
 * policy_rwlock.
 */
#define KSU_POLICY_COMMIT(pol) do { \
		u32 __g = ksu54_pol_get_granting(pol); \
		write_lock_irq(&selinux_state.ss->policy_rwlock); \
		selinux_state.ss->policydb = (pol)->policydb; \
		selinux_state.ss->latest_granting = __g; \
		write_unlock_irq(&selinux_state.ss->policy_rwlock); \
	} while (0)
#define KSU_POLICY_LOCK() mutex_lock(&selinux_state.ss->status_lock)
#define KSU_POLICY_UNLOCK() mutex_unlock(&selinux_state.ss->status_lock)
#else
#define KSU_POLICY_GET() rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex))
#define KSU_POLICY_COMMIT(pol) do { \
		rcu_assign_pointer(selinux_state.policy, (pol)); \
		synchronize_rcu(); \
	} while (0)
#define KSU_POLICY_LOCK() mutex_lock(&selinux_state.policy_mutex)
#define KSU_POLICY_UNLOCK() mutex_unlock(&selinux_state.policy_mutex)
#endif'''


def rd(p):
    return io.open(p, encoding='utf-8').read() if os.path.exists(p) else None


def wr(p, s):
    io.open(p, 'w', encoding='utf-8').write(s)


def patch_header():
    s = rd(SPH)
    if s is None:
        print("  [SKIP] sepolicy.h")
        return
    start = s.find('#include <linux/version.h>\n#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)\n#define KSU54_SELINUX_POLICY_SHIM')
    if start >= 0:
        mpos = s.find('ksu54_sidtab_dup', start)
        end = s.find('\n#endif\n', mpos)
        if end > 0:
            s = s[:start] + s[end + len('\n#endif\n'):]
    anchor = 'struct selinux_policy *ksu_dup_sepolicy'
    if anchor not in s:
        print("  !! sepolicy.h anchor missing")
        return
    s = s.replace(anchor, SHIM + '\n' + anchor, 1)
    wr(SPH, s)
    print("  [1][3] sepolicy.h: accessors + deep sidtab copy")


def patch_rules():
    s = rd(RUL)
    if s is None:
        print("  [SKIP] rules.c")
        return

    # 宏块
    start = s.find('#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)\n#define KSU54_POLICY_FIELD')
    if start >= 0:
        end = s.find('\n#endif', s.find('KSU_POLICY_UNLOCK()', start))
        if end > 0:
            s = s[:start] + MACROS + s[end + len('\n#endif'):]

    # [6] 先长后短，避免 old_pol 被吃掉
    s = s.replace('old_pol->latest_granting', 'ksu54_pol_get_granting(old_pol)')
    s = s.replace('pol->latest_granting', 'ksu54_pol_get_granting(pol)')

    # [5] 左值赋值 → setter
    s = re.sub(r'^(\s*)ksu54_pol_get_granting\((\w+)\)\s*=\s*(.+?);\s*$',
               lambda m: '%sksu54_pol_set_granting(%s, %s);' % (m.group(1), m.group(2), m.group(3)),
               s, flags=re.M)

    # [7] 保存 seqno 后再释放
    old = '''    kfree(pol);
    pol = NULL;   /* ksu54: out_drop_new_policy must not free it again */
    (void)old_pol;
#endif'''
    new = '''    __ksu54_seqno = ksu54_pol_get_granting(pol);
    kfree(pol);
    pol = NULL;   /* ksu54: out_drop_new_policy must not free it again */
    (void)old_pol;
#endif'''
    if old in s:
        s = s.replace(old, new)

    # 5.4 分支 reset_avc_cache 用局部变量
    s = s.replace('reset_avc_cache(ksu54_pol_get_granting(pol));',
                  'reset_avc_cache(__ksu54_seqno);')

    # [2] double free
    s = s.replace('    kfree(pol);\n    (void)old_pol;',
                  '    kfree(pol);\n    pol = NULL;\n    (void)old_pol;')

    # [2b] 失败标签判空
    s = s.replace('out_drop_new_policy:\n    ksu_destroy_sepolicy(pol);',
                  'out_drop_new_policy:\n    if (pol)\n        ksu_destroy_sepolicy(pol);')

    wr(RUL, s)
    print("  [2][5][6][7] rules.c patched")


def patch_sepolicy_c():
    s = rd(SEC)
    if s is None:
        print("  [SKIP] sepolicy.c")
        return

    # [4] destroy 保护
    if 'borrowed view over selinux_state.ss' not in s:
        old = '''	if (KSU54_POL_IS_OWNED(pol) && pol->sidtab) {'''
        new = '''	if (!KSU54_POL_IS_OWNED(pol))
		return;
	if (pol->sidtab) {'''
        if old in s:
            s = s.replace(old, new)
            print("  [4] destroy: view guard added")
        else:
            # 可能还没有 sidtab 块
            old2 = '''void ksu_destroy_sepolicy(struct selinux_policy *pol)
{
	if (!pol)
		return;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)'''
            new2 = '''void ksu_destroy_sepolicy(struct selinux_policy *pol)
{
	if (!pol)
		return;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
	/* A view aliases selinux_state.ss and is not ours to free. */
	if (!KSU54_POL_IS_OWNED(pol))
		return;'''
            if old2 in s:
                s = s.replace(old2, new2)
                print("  [4] destroy: view guard added (block absent form)")

    s = s.replace('new_pol->latest_granting = old_pol->latest_granting;',
                  'new_pol->ksu54_granting = ksu54_pol_get_granting(old_pol);')
    wr(SEC, s)
    print("  [4] sepolicy.c done")


def patch_hide():
    s = rd(SIH)
    if s is None:
        print("  [SKIP] selinux_hide.c")
        return
    n1 = s.count('orig_policy->latest_granting')
    s = s.replace('orig_policy->latest_granting', 'ksu54_pol_get_granting(orig_policy)')
    n2 = s.count('policy->latest_granting')
    s = s.replace('policy->latest_granting', 'ksu54_pol_get_granting(policy)')
    wr(SIH, s)
    print("  [1] selinux_hide.c: accessor x%d + x%d" % (n1, n2))


def ensure_decl():
    lines = rd(RUL).split('\n')
    out, i, removed = [], 0, 0
    while i < len(lines):
        if (i + 2 < len(lines) and
                lines[i].strip() == '#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)' and
                '__ksu54_seqno' in lines[i + 1] and
                lines[i + 2].strip() == '#endif'):
            i += 3
            removed += 1
            continue
        out.append(lines[i])
        i += 1
    lines = out

    uses = [i for i, l in enumerate(lines) if '__ksu54_seqno' in l]
    funcs = set()
    for u in uses:
        depth = 0
        for j in range(u, -1, -1):
            depth += lines[j].count('}') - lines[j].count('{')
            if depth < 0:
                funcs.add(j)
                break

    for fh in sorted(funcs, reverse=True):
        i = fh + 1
        last = fh
        while i < len(lines):
            t = lines[i].strip()
            if not t:
                i += 1
                continue
            if re.match(r'^(struct|union|int|u8|u16|u32|u64|s8|s16|s32|s64|size_t|ssize_t|loff_t|bool|char|long|unsigned|const|static|gfp_t|void)\b', t) and '(' not in t.split('=')[0]:
                last = i
                i += 1
                continue
            break
        indent = '    '
        if last > fh and lines[last].strip():
            indent = lines[last][:len(lines[last]) - len(lines[last].lstrip())]
        lines.insert(last + 1, indent + '#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)')
        lines.insert(last + 2, indent + 'u32 __ksu54_seqno = 0;')
        lines.insert(last + 3, indent + '#endif')
    wr(RUL, '\n'.join(lines))
    print("  [7b] declarations: %d function(s), removed %d stale" % (len(funcs), removed))


if __name__ == '__main__':
    print("=== SELinux 5.4 审查修正 v12 ===")
    patch_header()
    patch_rules()
    patch_sepolicy_c()
    patch_hide()
    ensure_decl()
    print("=== done ===")
