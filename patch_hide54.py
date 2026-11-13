#!/usr/bin/env python3
"""
selinux_hide.c 的 Linux 5.4 适配（v6）

v5 之后仅剩 2 个错误：symtab_search 未声明。
5.4 的 ss/symtab.h 只声明 symtab_init()，没有 symtab_search()；
查符号表要走 hashtab_search(s->table, name)。这个包装必须无条件引入，
所以放在文件靠前（symtab.h 已由 policydb.h 间接包含）。
"""
import io
import os
import re
import sys

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
SUDIR = os.path.join(KDIR, 'KernelSU', 'kernel')
if not os.path.isdir(SUDIR):
    SUDIR = os.path.join(KDIR, 'drivers', 'kernelsu')
SIH = os.path.join(SUDIR, 'feature', 'selinux_hide.c')

MARKER = 'KSU54_SELINUX_HIDE_PORT'

BLOCK = '''/* ===== KSU54_SELINUX_HIDE_PORT ==========================================
 * FinaSU's selinux_hide targets 5.7+, where the policy lives in a separate
 * struct selinux_policy and sidtab entries are struct sidtab_entry. This 5.4
 * kernel keeps everything in struct selinux_ss and stores a struct context
 * inline in each sidtab leaf, so the helpers below are re-implemented rather
 * than aliased.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define KSU54_HAVE_POLICY_VIEW 1

/* 5.4: no struct selinux_policy; the ss itself carries policydb + sidtab +
 * latest_granting. sepolicy.h widens the struct so its first two members
 * mirror selinux_ss exactly, making this a layout reinterpretation. */
static inline struct selinux_policy *ksu54_policy_view(void)
{
	return (struct selinux_policy *)selinux_state.ss;
}

/*
 * 5.4 ss/symtab.h declares only symtab_init(); 5.7 added symtab_search().
 * Lookups in this tree go through hashtab_search() on the symbol table.
 */
static inline void *ksu54_symtab_search(struct symtab *s, const char *name)
{
	return hashtab_search(s->table, name);
}
#endif
'''

NEW_FUNCS = '''#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
/*
 * 5.4 sidtab leaves store a struct context inline and expose no per-sid
 * string cache, so the 6.x helper collapses to a plain context render.
 */
static int sidtab_entry_to_string(struct policydb *p, struct sidtab *sidtab,
                                  struct context *entry, char **scontext,
                                  u32 *scontext_len)
{
	(void)sidtab;
	if (!entry)
		return -EINVAL;
	return context_struct_to_string(p, entry, scontext, scontext_len);
}

static int security_sid_to_context_with_policy(struct selinux_policy *policy,
                                               u32 sid, char **scontext,
                                               u32 *scontext_len)
{
	struct policydb *policydb;
	struct sidtab *sidtab;
	struct context *entry;
	int rc;

	if (scontext)
		*scontext = NULL;
	*scontext_len = 0;

	policydb = &policy->policydb;
	sidtab = policy->sidtab;

	entry = sidtab_search(sidtab, sid);
	if (!entry) {
		pr_err("SELinux: %s:  unrecognized SID %d\\n", __func__, sid);
		return -EINVAL;
	}

	rc = sidtab_entry_to_string(policydb, sidtab, entry, scontext, scontext_len);
	return rc;
}
#else
'''

ANCHOR = 'static DEFINE_MUTEX(selinux_hide_mutex);'


def main():
    if not os.path.exists(SIH):
        print("  [SKIP] selinux_hide.c")
        return
    s = io.open(SIH, encoding='utf-8').read()
    if MARKER in s:
        if 'ksu54_symtab_search' in s:
            print("  [--] already patched (idempotent skip)")
            return
        # v5 打过但没有 symtab shim，补上
        old = '#define KSU54_HAVE_POLICY_VIEW 1'
        add = '''#define KSU54_HAVE_POLICY_VIEW 1

/*
 * 5.4 ss/symtab.h declares only symtab_init(); 5.7 added symtab_search().
 * Lookups in this tree go through hashtab_search() on the symbol table.
 */
static inline void *ksu54_symtab_search(struct symtab *s, const char *name)
{
	return hashtab_search(s->table, name);
}'''
        s = s.replace(old, add, 1)
        # 替换调用点
        n = s.count('symtab_search(') - s.count('ksu54_symtab_search(')
        s = re.sub(r'(?<!ksu54_)symtab_search\(', 'ksu54_symtab_search(', s)
        io.open(SIH, 'w', encoding='utf-8').write(s)
        print("  [FIX] added ksu54_symtab_search, rewrote %d call sites" % n)
        return

    n0 = len(s)

    a = s.count('selinux_state.status_lock')
    s = s.replace('selinux_state.status_lock', 'selinux_state.ss->status_lock')
    b = s.count('selinux_state.status_page')
    s = s.replace('selinux_state.status_page', 'selinux_state.ss->status_page')
    print("  status_lock x%d / status_page x%d -> ss->" % (a, b))

    e = s.count('rcu_dereference(selinux_state.policy)')
    s = re.sub(r'rcu_dereference(?:_protected)?\(\s*selinux_state\.policy\s*(?:,[^)]*)?\)',
               'ksu54_policy_view()', s)
    print("  selinux_state.policy x%d -> ksu54_policy_view()" % e)

    old_start = s.find('static int sidtab_entry_to_string(struct policydb *p, struct sidtab *sidtab, struct sidtab_entry *entry,')
    if old_start < 0:
        print("  !! sidtab_entry_to_string not found")
        return
    anchor2 = 'static void avd_init(struct selinux_policy *policy'
    old_end = s.find(anchor2, old_start)
    if old_end < 0:
        print("  !! avd_init anchor not found")
        return
    s = s[:old_start] + NEW_FUNCS + s[old_start:old_end] + '#endif /* < 5.7 */\n\n' + s[old_end:]
    print("  [OK] sidtab_entry_to_string + security_sid_to_context replaced")

    idx = s.find(ANCHOR)
    if idx < 0:
        print("  !! DEFINE_MUTEX anchor not found")
        return
    s = s[:idx] + BLOCK + '\n' + s[idx:]
    print("  [OK] shim block inserted")

    # 最后统一改写 symtab_search 调用点
    n = s.count('symtab_search(') - s.count('ksu54_symtab_search(')
    s = re.sub(r'(?<!ksu54_)symtab_search\(', 'ksu54_symtab_search(', s)
    print("  [OK] symtab_search -> ksu54_symtab_search x%d" % n)

    io.open(SIH, 'w', encoding='utf-8').write(s)
    print("  [OK] selinux_hide.c %d -> %d bytes" % (n0, len(s)))


if __name__ == '__main__':
    print("=== selinux_hide.c 5.4 port v6 ===")
    main()
