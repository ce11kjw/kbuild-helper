#!/usr/bin/env python3
"""
SELinux policy 5.4 shadow（v3）

关键约束：struct selinux_policy 的前三个成员必须与 struct selinux_ss 的
起始布局完全一致，因为 selinux_hide.c 用 (struct selinux_policy *)ss 强转。

5.4 struct selinux_ss:
    struct sidtab *sidtab;        <- offset 0
    struct policydb policydb;     <- offset 8
    rwlock_t policy_rwlock;
    u32 latest_granting;
    ...

所以 shim 必须写成：
    struct selinux_policy {
        struct sidtab *sidtab;
        struct policydb policydb;
        u32 latest_granting;      // 位置不必严格对齐 ss（不通过强转访问）
    };

同时 backup_sepolicy 是独立分配，ksu_dup_sepolicy 必须自己复制 sidtab。
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

SHIM = """#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define KSU54_SELINUX_POLICY_SHIM 1
#include <linux/sched.h>
#include <linux/slab.h>
#include "ss/services.h"
#include "ss/sidtab.h"
/*
 * 5.4 has no struct selinux_policy (split out in 5.7). FinaSU touches only
 * ->policydb, ->sidtab and ->latest_granting, all of which live in
 * struct selinux_ss on 5.4.
 *
 * The member order below mirrors the START of struct selinux_ss exactly
 * (sidtab first, then policydb), which is what lets selinux_hide.c reuse a
 * live->ss pointer as a policy pointer via a plain cast.
 *
 * latest_granting intentionally sits after those two: it is only accessed
 * through real struct selinux_policy objects (duplicated copies), never
 * through the cast, so it does not need to match ss offsets.
 */
struct selinux_policy {
	struct sidtab *sidtab;
	struct policydb policydb;
	u32 latest_granting;
};
extern struct selinux_state selinux_state;
#endif
"""

MACROS = """struct selinux_policy *backup_sepolicy;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define KSU54_POLICY_FIELD

/* Mirrors the live policy: ss itself, reinterpreted as a policy. */
static inline struct selinux_policy *ksu54_live_policy(void)
{
	return (struct selinux_policy *)selinux_state.ss;
}

#define KSU_POLICY_GET() ksu54_live_policy()
#define KSU_POLICY_COMMIT(pol) do { \\
		write_lock_irq(&selinux_state.ss->policy_rwlock); \\
		selinux_state.ss->policydb = (pol)->policydb; \\
		selinux_state.ss->latest_granting = (pol)->latest_granting; \\
		write_unlock_irq(&selinux_state.ss->policy_rwlock); \\
	} while (0)
#define KSU_POLICY_LOCK() mutex_lock(&selinux_state.ss->status_lock)
#define KSU_POLICY_UNLOCK() mutex_unlock(&selinux_state.ss->status_lock)
#else
#define KSU_POLICY_GET() rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex))
#define KSU_POLICY_COMMIT(pol) do { \\
		rcu_assign_pointer(selinux_state.policy, (pol)); \\
		synchronize_rcu(); \\
	} while (0)
#define KSU_POLICY_LOCK() mutex_lock(&selinux_state.policy_mutex)
#define KSU_POLICY_UNLOCK() mutex_unlock(&selinux_state.policy_mutex)
#endif
"""

# 5.4 版 dup/destroy：必须自带 sidtab 副本
DUP_54 = """/* KSU54_FNTRANS: 5.4 backport of dup/destroy. */
void ksu_destroy_sepolicy(struct selinux_policy *pol)
{
	if (!pol)
		return;
	/* A live-policy view owns nothing, but a dup does own both parts. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
	if (pol->sidtab) {
		sidtab_destroy(pol->sidtab);
		kfree(pol->sidtab);
		pol->sidtab = NULL;
	}
#endif
	policydb_destroy(&pol->policydb);
	kfree(pol);
}

struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol)
{
	struct selinux_policy *new_pol;
	struct policy_file fp;
	void *data;
	size_t len;
	int ret;

	if (!old_pol)
		return ERR_PTR(-EINVAL);

	len = old_pol->policydb.len;
	if (len < 4096)
		len = 4096;
	data = vmalloc(len);
	if (!data)
		return ERR_PTR(-ENOMEM);

	fp.data = data;
	fp.len = len;
	ret = policydb_write(&old_pol->policydb, &fp);
	if (ret) {
		pr_err("sepolicy54: policydb_write: %d\\n", ret);
		goto out_free_data;
	}
	len -= fp.len;

	new_pol = kzalloc(sizeof(*new_pol), GFP_KERNEL);
	if (!new_pol) {
		ret = -ENOMEM;
		goto out_free_data;
	}

	fp.data = data;
	fp.len = len;
	ret = policydb_read(&new_pol->policydb, &fp);
	if (ret) {
		pr_err("sepolicy54: policydb_read: %d\\n", ret);
		kfree(new_pol);
		goto out_free_data;
	}
	new_pol->policydb.len = len;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
	/*
	 * 5.4 keeps sidtab in selinux_state.ss, so a dup needs its own copy:
	 * the backup is queried for SIDs while the live policy gets replaced.
	 */
	new_pol->sidtab = ksu54_sidtab_dup(old_pol->sidtab);
	if (!new_pol->sidtab) {
		policydb_destroy(&new_pol->policydb);
		kfree(new_pol);
		ret = -ENOMEM;
		goto out_free_data;
	}
	new_pol->latest_granting = old_pol->latest_granting;
#else
	new_pol->sidtab = old_pol->sidtab;
	new_pol->latest_granting = old_pol->latest_granting;
#endif

	kvfree(data);
	pr_info("sepolicy54: dup policydb ok, len %zu\\n", len);
	return new_pol;

out_free_data:
	kvfree(data);
	return ERR_PTR(ret);
}
"""


def patch_sepolicy_h():
    if not os.path.exists(SPH):
        print("  [SKIP] sepolicy.h")
        return
    s = io.open(SPH, encoding='utf-8').read()
    # 移除任何旧 shim 后重写，保证字段顺序正确
    if 'KSU54_SELINUX_POLICY_SHIM' in s:
        pattern = re.compile(
            r'#include <linux/version\.h>\n#if LINUX_VERSION_CODE < KERNEL_VERSION\(5, 7, 0\)\n'
            r'#define KSU54_SELINUX_POLICY_SHIM 1\n.*?#endif\n',
            re.S)
        s2 = pattern.sub('', s, count=1)
        if s2 != s:
            s = s2
            print("  removed old shim")
    anchor = 'struct selinux_policy *ksu_dup_sepolicy'
    if anchor not in s:
        print("  !! sepolicy.h anchor not found")
        return
    s = s.replace(anchor, SHIM + anchor, 1)
    io.open(SPH, 'w', encoding='utf-8').write(s)
    print("  [OK] sepolicy.h: shim sidtab+policydb+latest_granting (ss-aligned)")


def patch_rules():
    if not os.path.exists(RUL):
        print("  [SKIP] rules.c")
        return
    s = io.open(RUL, encoding='utf-8').read()
    if 'KSU54_POLICY_FIELD' in s:
        # 替换旧宏块
        pattern = re.compile(
            r'#if LINUX_VERSION_CODE < KERNEL_VERSION\(5, 7, 0\)\n#define KSU54_POLICY_FIELD\n.*?#endif\n',
            re.S)
        s2 = pattern.sub(MACROS.split('#define KSU54_POLICY_FIELD\n', 1)[1].rstrip() + '\n', s, count=1)
        if s2 == s:
            print("  [--] rules.c macro block unchanged (manual check needed)")
        else:
            s = s2
            io.open(RUL, 'w', encoding='utf-8').write(s)
            print("  [OK] rules.c: macro block refreshed")
        return

    old = 'struct selinux_policy *backup_sepolicy;'
    if old not in s:
        print("  !! rules.c: backup_sepolicy anchor not found")
        return
    s = s.replace(old, MACROS, 1)

    s = s.replace('mutex_lock(&selinux_state.policy_mutex);', 'KSU_POLICY_LOCK();')
    s = s.replace('mutex_unlock(&selinux_state.policy_mutex);', 'KSU_POLICY_UNLOCK();')
    s = s.replace(
        'old_pol = rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex));',
        'old_pol = KSU_POLICY_GET();')

    old_commit = """    rcu_assign_pointer(selinux_state.policy, pol);
    synchronize_rcu();
    ksu_destroy_sepolicy(old_pol);"""
    new_commit = """    KSU_POLICY_COMMIT(pol);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    ksu_destroy_sepolicy(old_pol);
#else
    /* 5.4: old_pol is a live view over ss (already updated in place), so
     * there is nothing to free; pol's policydb was donated into ss, but its
     * sidtab copy is no longer referenced and must be released. */
    if (pol->sidtab) {
        sidtab_destroy(pol->sidtab);
        kfree(pol->sidtab);
        pol->sidtab = NULL;
    }
    kfree(pol);
    (void)old_pol;
#endif"""
    n = s.count(old_commit)
    if n:
        s = s.replace(old_commit, new_commit)
        print("  [OK] rules.c: %d commit sites" % n)

    a = s.find('backup_sepolicy->sidtab = kzalloc')
    if a != -1:
        b = s.find('    pol = ksu_dup_sepolicy(old_pol);', a)
        if b != -1:
            repl = ('        /* ksu54_dropped_sidtab: dup_sepolicy now clones it */\n'
                    '    }\n')
            s = s[:a] + repl + s[b:]
            print("  [OK] rules.c: sidtab backup block dropped")

    io.open(RUL, 'w', encoding='utf-8').write(s)
    print("  [OK] rules.c: macros applied")


def patch_sepolicy_c():
    if not os.path.exists(SEC):
        print("  [SKIP] sepolicy.c")
        return
    s = io.open(SEC, encoding='utf-8').read()
    if 'KSU54_FNTRANS' in s:
        print("  [--] sepolicy.c already patched")
        return

    s2 = re.sub(r'void ksu_destroy_sepolicy\(struct selinux_policy \*pol\)\s*\{.*?\n\}\n',
                '', s, count=1, flags=re.S)
    s3 = re.sub(r'struct selinux_policy \*ksu_dup_sepolicy\(struct selinux_policy \*old_pol\)\s*\{.*?\n\}\n',
                '', s2, count=1, flags=re.S)
    s = s3 if s3 != s else s

    anchor = '// ======== sepolicy ========'
    if anchor in s:
        s = s.replace(anchor, anchor + '\n' + DUP_54, 1)
    else:
        s = s.rstrip() + '\n\n' + DUP_54

    io.open(SEC, 'w', encoding='utf-8').write(s)
    print("  [OK] sepolicy.c: dup/destroy with sidtab clone")


if __name__ == '__main__':
    print("=== SELinux policy 5.4 (v3) ===")
    patch_sepolicy_h()
    patch_rules()
    patch_sepolicy_c()
