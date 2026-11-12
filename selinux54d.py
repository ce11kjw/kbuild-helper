#!/usr/bin/env python3
"""
FinaSU -> Linux 5.4 SELinux compat patch (build helper)  v4

Fixes v3: the commit replacement was applied to BOTH functions but only
apply_kernelsu_rules declares old_pol_backup. Split the two commit
patterns so each function gets its own correct version.
"""

import os
import sys

SEPOLICY_H_HEAD = r'''
/* ===== 5.4 compat: define struct selinux_policy (build helper) ===== */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
struct selinux_policy {
	struct sidtab *sidtab;
	struct policydb policydb;
	u32 latest_granting;
};
#endif
/* ===== end ===== */
'''

RULES_HELPERS = r'''
/* ===== 5.4 SELinux compat (build helper) ===== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
#include <linux/rwlock.h>

static DEFINE_MUTEX(ksu54_policy_mutex);

/* Temporary shell: ksu_dup_sepolicy() deep-copies out of it. */
static struct selinux_policy *ksu54_selinux_view(void)
{
	struct selinux_policy *p;
	struct selinux_ss *ss = selinux_state.ss;

	if (!ss)
		return ERR_PTR(-EINVAL);
	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);
	p->policydb = ss->policydb;
	p->sidtab = ss->sidtab;
	p->latest_granting = ss->latest_granting;
	return p;
}

static void ksu54_selinux_view_free(struct selinux_policy *p)
{
	if (!p || IS_ERR(p))
		return;
	kfree(p);
}

/* Install a deep-copied policy into the live selinux_state.ss */
static int ksu54_selinux_commit(struct selinux_policy *pol)
{
	struct selinux_ss *ss = selinux_state.ss;
	struct sidtab *new_sidtab;
	int ret;

	if (!ss)
		return -EINVAL;
	new_sidtab = kzalloc(sizeof(*new_sidtab), GFP_KERNEL);
	if (!new_sidtab)
		return -ENOMEM;
	ret = sidtab_init(new_sidtab);
	if (ret) {
		kfree(new_sidtab);
		return ret;
	}
	ret = policydb_load_isids(&pol->policydb, new_sidtab);
	if (ret) {
		sidtab_destroy(new_sidtab);
		kfree(new_sidtab);
		return ret;
	}

	write_lock(&ss->policy_rwlock);
	policydb_destroy(&ss->policydb);
	ss->policydb = pol->policydb;
	if (ss->sidtab) {
		sidtab_destroy(ss->sidtab);
		kfree(ss->sidtab);
	}
	ss->sidtab = new_sidtab;
	ss->latest_granting = pol->latest_granting;
	write_unlock(&ss->policy_rwlock);
	return 0;
}
#endif
/* ===== end 5.4 SELinux compat ===== */
'''

# ---------- handle_sepolicy (returns int, no backup var) ----------
H_OLD = """    mutex_lock(&selinux_state.policy_mutex);

    old_pol = rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex));
    pol = ksu_dup_sepolicy(old_pol);"""

H_NEW = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    mutex_lock(&ksu54_policy_mutex);
    old_pol = ksu54_selinux_view();
    if (IS_ERR(old_pol)) {
        ret = PTR_ERR(old_pol);
        mutex_unlock(&ksu54_policy_mutex);
        goto out_free;
    }
    pol = ksu_dup_sepolicy(old_pol);
    ksu54_selinux_view_free(old_pol);
#else
    mutex_lock(&selinux_state.policy_mutex);

    old_pol = rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex));
    pol = ksu_dup_sepolicy(old_pol);
#endif"""

# commit for handle_sepolicy (followed by drop_new_policy label context)
H_COMMIT_OLD = """    rcu_assign_pointer(selinux_state.policy, pol);
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
    ret = success_cmd_count;"""

H_COMMIT_NEW = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
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

# ---------- apply_kernelsu_rules (void, has backup var) ----------
A_OLD = """    mutex_lock(&selinux_state.policy_mutex);

    old_pol = rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex));
    backup_sepolicy = ksu_dup_sepolicy(old_pol);"""

A_NEW = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    mutex_lock(&ksu54_policy_mutex);
    old_pol = ksu54_selinux_view();
    if (IS_ERR(old_pol)) {
        mutex_unlock(&ksu54_policy_mutex);
        return;
    }
#else
    mutex_lock(&selinux_state.policy_mutex);

    old_pol = rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex));
#endif
    backup_sepolicy = ksu_dup_sepolicy(old_pol);"""

A_COMMIT_OLD = """    rcu_assign_pointer(selinux_state.policy, pol);
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
out_unlock:"""

A_COMMIT_NEW = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    if (ksu54_selinux_commit(pol))
        pr_err("ksu: failed to commit policy into selinux_state.ss\\n");
    ksu54_selinux_view_free(old_pol);
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
out_unlock:"""

UNLOCK_OLD = "    mutex_unlock(&selinux_state.policy_mutex);"
UNLOCK_NEW = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    mutex_unlock(&ksu54_policy_mutex);
#else
    mutex_unlock(&selinux_state.policy_mutex);
#endif"""


def patch_sepolicy_h(path):
    s = open(path, encoding='utf-8', errors='surrogateescape').read()
    if 'struct selinux_policy {' in s:
        print("  [OK] sepolicy.h already has struct")
        return
    marker = '#include "ss/policydb.h"'
    s = s.replace(marker, marker + '\n' + SEPOLICY_H_HEAD, 1) if marker in s else SEPOLICY_H_HEAD + '\n' + s
    open(path, 'w', encoding='utf-8', errors='surrogateescape').write(s)
    print("  [OK] sepolicy.h: struct added")


def patch_rules_c(path):
    s = open(path, encoding='utf-8', errors='surrogateescape').read()
    orig = s
    log = []

    if 'ksu54_selinux_view' in s:
        print("  [OK] rules.c already patched")
        return

    # helpers after last include
    lines = s.split('\n')
    last_inc = 0
    for i, ln in enumerate(lines):
        if ln.strip().startswith('#include'):
            last_inc = i
    lines.insert(last_inc + 1, RULES_HELPERS)
    s = '\n'.join(lines)

    # handle_sepolicy first (its commit block is carved out separately)
    if H_COMMIT_OLD in s:
        s = s.replace(H_COMMIT_OLD, H_COMMIT_NEW, 1)
        log.append('handle:commit')

    if A_COMMIT_OLD in s:
        s = s.replace(A_COMMIT_OLD, A_COMMIT_NEW, 1)
        log.append('apply:commit')

    if H_OLD in s:
        s = s.replace(H_OLD, H_NEW, 1)
        log.append('handle:read')

    if A_OLD in s:
        s = s.replace(A_OLD, A_NEW, 1)
        log.append('apply:read')

    n = s.count(UNLOCK_OLD)
    if n:
        s = s.replace(UNLOCK_OLD, UNLOCK_NEW)
        log.append('unlock x%d' % n)

    if s != orig:
        open(path, 'w', encoding='utf-8', errors='surrogateescape').write(s)
        print("  [OK] rules.c: " + ", ".join(log))
    else:
        print("  [!] rules.c unchanged")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'drivers/kernelsu'
    if os.path.islink(root):
        root = os.path.realpath(root)
    print("FinaSU root: %s" % root)
    sh = os.path.join(root, 'selinux', 'sepolicy.h')
    rc = os.path.join(root, 'selinux', 'rules.c')
    if os.path.exists(sh):
        patch_sepolicy_h(sh)
    else:
        print("  !! sepolicy.h not found")
    if os.path.exists(rc):
        patch_rules_c(rc)
    else:
        print("  !! rules.c not found")


if __name__ == '__main__':
    main()
