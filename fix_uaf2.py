#!/usr/bin/env python3
"""
Fix use-after-free on the 5.4 commit path.

Current order in apply_kernelsu_rules() and handle_sepolicy():

    ksu54_selinux_commit(pol);
    ksu_destroy_sepolicy(pol);          /* kfree(pol) */
    ...
    reset_avc_cache(pol->latest_granting);   /* UAF */

`pol->latest_granting` is needed only for the AVC sequence number, so read
it into a local before destroying the policy.

On the 5.9+ path `pol` survives (it is published via rcu_assign_pointer),
so the original ordering must stay there — the fix is guarded.
"""

import os
import sys

MARK_A = '/* 5.4: keep latest_granting before freeing pol */'


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'drivers/kernelsu'
    if os.path.islink(root):
        root = os.path.realpath(root)
    p = os.path.join(root, 'selinux', 'rules.c')
    print("target: %s" % p)
    s = open(p, encoding='utf-8', errors='surrogateescape').read()

    if MARK_A in s:
        print("  [OK] already fixed")
        return

    # --- apply_kernelsu_rules ---
    old1 = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
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
#endif"""

    new1 = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    {
        /* 5.4: keep latest_granting before freeing pol */
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
#endif"""

    if old1 in s:
        s = s.replace(old1, new1, 1)
        print("  [OK] apply_kernelsu_rules: seqno captured before free")
    else:
        print("  [!] apply_kernelsu_rules block not matched")

    open(p, 'w', encoding='utf-8', errors='surrogateescape').write(s)


if __name__ == '__main__':
    main()
