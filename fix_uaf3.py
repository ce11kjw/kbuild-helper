#!/usr/bin/env python3
"""
Fix the same use-after-free in handle_sepolicy() on the 5.4 path.

    if (ksu54_selinux_commit(pol)) ...
    ksu_destroy_sepolicy(pol);          /* kfree */
    ...
    reset_avc_cache(pol->latest_granting);   /* UAF */
    ret = success_cmd_count;
    goto out_unlock;
"""

import os
import sys

MARK = '/* 5.4: keep seqno before freeing pol (handle_sepolicy) */'

OLD = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    if (ksu54_selinux_commit(pol))
        pr_err("ksu: failed to commit policy into selinux_state.ss\\n");
    ksu_destroy_sepolicy(pol);
#else
    rcu_assign_pointer(selinux_state.policy, pol);
    synchronize_rcu();
    ksu_destroy_sepolicy(old_pol);
#endif

#ifdef KSU_SUSFS_HAS_TYPE_REGISTRATION
    reset_avc_cache(0);
#else
    reset_avc_cache(pol->latest_granting);
#endif
#ifdef CONFIG_KSU_SUSFS
    susfs_set_batch_sid();
#endif
    ret = success_cmd_count;"""

NEW = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    {
        /* 5.4: keep seqno before freeing pol (handle_sepolicy) */
        u32 ksu54_seqno = pol->latest_granting;
        if (ksu54_selinux_commit(pol))
            pr_err("ksu: failed to commit policy into selinux_state.ss\\n");
        ksu_destroy_sepolicy(pol);
        pol = NULL;
#ifdef KSU_SUSFS_HAS_TYPE_REGISTRATION
        reset_avc_cache(0);
#else
        reset_avc_cache(ksu54_seqno);
#endif
#ifdef CONFIG_KSU_SUSFS
        susfs_set_batch_sid();
#endif
    }
#else
    rcu_assign_pointer(selinux_state.policy, pol);
    synchronize_rcu();
    ksu_destroy_sepolicy(old_pol);

#ifdef KSU_SUSFS_HAS_TYPE_REGISTRATION
    reset_avc_cache(0);
#else
    reset_avc_cache(pol->latest_granting);
#endif
#ifdef CONFIG_KSU_SUSFS
    susfs_set_batch_sid();
#endif
#endif
    ret = success_cmd_count;"""


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'drivers/kernelsu'
    if os.path.islink(root):
        root = os.path.realpath(root)
    p = os.path.join(root, 'selinux', 'rules.c')
    print("target: %s" % p)
    s = open(p, encoding='utf-8', errors='surrogateescape').read()

    if MARK in s:
        print("  [OK] already fixed")
        return

    if OLD in s:
        s = s.replace(OLD, NEW, 1)
        open(p, 'w', encoding='utf-8', errors='surrogateescape').write(s)
        print("  [OK] handle_sepolicy: seqno captured before free")
    else:
        print("  !! handle_sepolicy block not matched")


if __name__ == '__main__':
    main()
