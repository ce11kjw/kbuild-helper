#!/usr/bin/env python3
"""
selinux_hide.c 的 Linux 5.4 适配（v2，字段映射与 ss 布局严格对齐）
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

VIEW_BLOCK = '''
/*
 * ksu54_policy_view: 5.4 has no struct selinux_policy (split out in 5.7); the
 * policydb, sidtab and latest_granting all live in struct selinux_ss.
 * sepolicy.h widens struct selinux_policy below 5.7 so its first three
 * members mirror selinux_ss byte for byte, making this cast a plain
 * reinterpretation of the same layout.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define KSU54_HAVE_POLICY_VIEW 1
static inline struct selinux_policy *ksu54_policy_view(void)
{
    return (struct selinux_policy *)selinux_state.ss;
}
#endif
'''

SIDTAB_DUP = '''
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
/*
 * ksu54_sidtab_dup: clone a 5.4 sidtab for the policy backup.
 *
 * A 5.4 sidtab becomes an immutable radix tree once the policy is loaded;
 * entries are only added through sidtab_context_to_sid() under s->lock. The
 * backup exists purely for read-only SID lookups while the live policy is
 * swapped, so duplicating the node pointers and re-initialising the lock and
 * reverse map is sufficient (no live-convert machinery needed).
 */
static struct sidtab *ksu54_sidtab_dup(struct sidtab *src)
{
    struct sidtab *dst;
    int i;

    if (!src)
        return NULL;
    dst = kmemdup(src, sizeof(*dst), GFP_KERNEL);
    if (!dst)
        return NULL;
    spin_lock_init(&dst->lock);
    dst->convert = NULL;
    for (i = 0; i < (1 << SIDTAB_HASH_BITS); i++)
        INIT_HLIST_HEAD(&dst->context_to_sid[i]);
    return dst;
}
#endif
'''

HELPERS = '''
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
/* ksu54_selinux_hide_shims ------------------------------------------------ */
/*
 * 5.4 sidtab leaves store a struct context inline (there is no 6.x
 * struct sidtab_entry) and only sidtab_search() is available, so the two
 * newer helpers FinaSU calls get equivalents with upstream semantics.
 */
static inline struct context *ksu54_sidtab_search_entry(struct sidtab *s, u32 sid)
{
    return sidtab_search(s, sid);
}

static inline int ksu54_sidtab_entry_to_string(struct policydb *p,
                                               struct sidtab *sidtab,
                                               struct context *entry,
                                               char **scontext,
                                               u32 *scontext_len)
{
    (void)sidtab;   /* 5.4 has no per-sid string cache */
    if (!entry)
        return -EINVAL;
    return context_struct_to_string(p, entry, scontext, scontext_len);
}
#endif /* < 5.7 */
'''


def main():
    if not os.path.exists(SIH):
        print("  [SKIP] selinux_hide.c")
        return

    s = io.open(SIH, encoding='utf-8').read()
    if 'KSU54_HAVE_POLICY_VIEW' in s:
        print("  [--] already patched")
        return

    n0 = len(s)

    a = s.count('selinux_state.status_lock')
    s = s.replace('selinux_state.status_lock', 'selinux_state.ss->status_lock')
    b = s.count('selinux_state.status_page')
    s = s.replace('selinux_state.status_page', 'selinux_state.ss->status_page')
    print("  status_lock x%d / status_page x%d -> ss->" % (a, b))

    c = s.count('sidtab_search_entry(')
    s = s.replace('sidtab_search_entry(', 'ksu54_sidtab_search_entry(')
    d = s.count('sidtab_entry_to_string(')
    s = s.replace('sidtab_entry_to_string(', 'ksu54_sidtab_entry_to_string(')
    print("  sidtab_search_entry x%d / entry_to_string x%d -> shims" % (c, d))

    e = s.count('rcu_dereference(selinux_state.policy)')
    s = re.sub(r'rcu_dereference(?:_protected)?\(\s*selinux_state\.policy\s*(?:,[^)]*)?\)',
               'ksu54_policy_view()', s)
    print("  selinux_state.policy x%d -> ksu54_policy_view()" % e)

    idx = s.find('\n#include')
    if idx < 0:
        print("  !! no include anchor")
        return
    nxt = s.find('\n', idx + 1)
    s = s[:nxt+1] + VIEW_BLOCK + SIDTAB_DUP + HELPERS + s[nxt+1:]

    io.open(SIH, 'w', encoding='utf-8').write(s)
    print("  [OK] selinux_hide.c %d -> %d bytes" % (n0, len(s)))


if __name__ == '__main__':
    print("=== selinux_hide.c 5.4 port v2 ===")
    main()
