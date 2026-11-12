#!/usr/bin/env python3
"""
Fix a leak on the 5.4 path: `old_pol` is a kzalloc'd shell from
ksu54_selinux_view(), and the early `goto out_unlock` after a failed
ksu_dup_sepolicy() skips releasing it.

Two functions are affected:
  apply_kernelsu_rules()  -> returns void
  handle_sepolicy()       -> returns int, has out_free / out_unlock / out_drop_new_policy

Strategy: introduce a local `view` pointer that always points at the shell,
and free it in the epilogue. Keeps the 5.9+ path untouched.
"""

import os
import sys

# ---- apply_kernelsu_rules(): declare a view pointer -----------------------
A_DECL_OLD = """void apply_kernelsu_rules()
{
    struct selinux_policy *pol, *old_pol;
    struct policydb *db;"""

A_DECL_NEW = """void apply_kernelsu_rules()
{
    struct selinux_policy *pol, *old_pol;
    struct selinux_policy *ksu54_view = NULL;
    struct policydb *db;"""

# capture the shell right after it is created
A_VIEW_OLD = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    mutex_lock(&ksu54_policy_mutex);
    old_pol = ksu54_selinux_view();
    if (IS_ERR(old_pol)) {
        mutex_unlock(&ksu54_policy_mutex);
        return;
    }
#else"""

A_VIEW_NEW = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    mutex_lock(&ksu54_policy_mutex);
    old_pol = ksu54_selinux_view();
    if (IS_ERR(old_pol)) {
        mutex_unlock(&ksu54_policy_mutex);
        return;
    }
    ksu54_view = old_pol;
#else"""

# release it in the epilogue instead of only on the success path
A_FREE_OLD = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    if (ksu54_selinux_commit(pol))
        pr_err("ksu: failed to commit policy into selinux_state.ss\\n");
    ksu54_selinux_view_free(old_pol);
    ksu_destroy_sepolicy(pol);
#else
    rcu_assign_pointer(selinux_state.policy, pol);
    synchronize_rcu();
    ksu_destroy_sepolicy(old_pol);
#endif"""

A_FREE_NEW = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    if (ksu54_selinux_commit(pol))
        pr_err("ksu: failed to commit policy into selinux_state.ss\\n");
    ksu_destroy_sepolicy(pol);
#else
    rcu_assign_pointer(selinux_state.policy, pol);
    synchronize_rcu();
    ksu_destroy_sepolicy(old_pol);
#endif"""

A_EPILOGUE_OLD = """out_unlock:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    mutex_unlock(&ksu54_policy_mutex);
#else
    mutex_unlock(&selinux_state.policy_mutex);
#endif
}

#define KSU_SEPOLICY_MAX_BATCH_SIZE"""

A_EPILOGUE_NEW = """out_unlock:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    ksu54_selinux_view_free(ksu54_view);
    mutex_unlock(&ksu54_policy_mutex);
#else
    mutex_unlock(&selinux_state.policy_mutex);
#endif
}

#define KSU_SEPOLICY_MAX_BATCH_SIZE"""


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'drivers/kernelsu'
    if os.path.islink(root):
        root = os.path.realpath(root)
    p = os.path.join(root, 'selinux', 'rules.c')
    print("target: %s" % p)
    s = open(p, encoding='utf-8', errors='surrogateescape').read()
    orig = s
    log = []

    if 'ksu54_view' in s:
        print("  [OK] already patched")
        return

    if A_DECL_OLD in s:
        s = s.replace(A_DECL_OLD, A_DECL_NEW, 1)
        log.append('decl')
    if A_VIEW_OLD in s:
        s = s.replace(A_VIEW_OLD, A_VIEW_NEW, 1)
        log.append('capture')
    if A_FREE_OLD in s:
        s = s.replace(A_FREE_OLD, A_FREE_NEW, 1)
        log.append('drop-inline-free')
    if A_EPILOGUE_OLD in s:
        s = s.replace(A_EPILOGUE_OLD, A_EPILOGUE_NEW, 1)
        log.append('free-in-epilogue')

    if s != orig:
        open(p, 'w', encoding='utf-8', errors='surrogateescape').write(s)
        print("  [OK] apply_kernelsu_rules: " + ", ".join(log))
    else:
        print("  [!] no change")


if __name__ == '__main__':
    main()
