#!/usr/bin/env python3
"""SELinux policy 5.4 shadow 补丁（含 latest_granting 字段）"""
import io
import sys
import os

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
SUDIR = os.path.join(KDIR, 'KernelSU', 'kernel')
if not os.path.isdir(SUDIR):
    SUDIR = os.path.join(KDIR, 'drivers', 'kernelsu')

SPH = os.path.join(SUDIR, 'selinux', 'sepolicy.h')
RUL = os.path.join(SUDIR, 'selinux', 'rules.c')

SHIM = """#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define KSU54_SELINUX_POLICY_SHIM 1
#include <linux/sched.h>
#include "ss/services.h"
/*
 * 5.4 has no struct selinux_policy (split out in 5.7). FinaSU only touches
 * ->policydb and ->latest_granting, both of which live in struct selinux_ss
 * on 5.4, so mirror exactly those two fields here.
 */
struct selinux_policy {
    struct policydb policydb;
    u32 latest_granting;
};
extern struct selinux_state selinux_state;
#endif
"""

MACROS = """struct selinux_policy *backup_sepolicy;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define KSU54_POLICY_FIELD
/*
 * 5.4 keeps the policy in selinux_state.ss->policydb protected by
 * policy_rwlock, and the policy generation counter in ss->latest_granting.
 * Hand out a shadow that mirrors both, and commit by copying them back.
 */
static struct selinux_policy *ksu54_current_policy(void)
{
    static struct selinux_policy shadow;
    shadow.policydb = selinux_state.ss->policydb;
    shadow.latest_granting = selinux_state.ss->latest_granting;
    return &shadow;
}

#define KSU_POLICY_GET() ksu54_current_policy()
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


def patch_sepolicy_h():
    if not os.path.exists(SPH):
        print("  [SKIP] sepolicy.h")
        return
    s = io.open(SPH, encoding='utf-8').read()
    if 'KSU54_SELINUX_POLICY_SHIM' in s:
        if 'u32 latest_granting;' not in s:
            s = s.replace(
                'struct selinux_policy {\n    struct policydb policydb;\n};',
                'struct selinux_policy {\n    struct policydb policydb;\n    u32 latest_granting;\n};', 1)
            io.open(SPH, 'w', encoding='utf-8').write(s)
            print("  [FIX] sepolicy.h: added latest_granting field")
        else:
            print("  [--] sepolicy.h already ok")
        return
    anchor = 'struct selinux_policy *ksu_dup_sepolicy'
    if anchor not in s:
        print("  !! sepolicy.h anchor not found")
        return
    s = s.replace(anchor, SHIM + anchor, 1)
    io.open(SPH, 'w', encoding='utf-8').write(s)
    print("  [OK] sepolicy.h: shim (policydb + latest_granting)")


def patch_rules():
    if not os.path.exists(RUL):
        print("  [SKIP] rules.c")
        return
    s = io.open(RUL, encoding='utf-8').read()

    if 'KSU54_POLICY_FIELD' in s:
        if 'latest_granting = (pol)->latest_granting' not in s:
            s = s.replace(
                'selinux_state.ss->latest_granting++;',
                'selinux_state.ss->latest_granting = (pol)->latest_granting;', 1)
            io.open(RUL, 'w', encoding='utf-8').write(s)
            print("  [FIX] rules.c: COMMIT syncs latest_granting from pol")
        else:
            print("  [--] rules.c already ok")
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
    /* 5.4: old_pol mirrors ss->policydb (already replaced), free shell only.
     * pol->policydb was donated into ss, so free shell only as well. */
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
            repl = ('        /* ksu54_dropped_sidtab: 5.4 keeps sidtab in selinux_state.ss */\n'
                    '        backup_sepolicy = NULL;\n'
                    '    }\n')
            s = s[:a] + repl + s[b:]
            print("  [OK] rules.c: sidtab backup block dropped")

    io.open(RUL, 'w', encoding='utf-8').write(s)
    print("  [OK] rules.c: policy macros applied")


if __name__ == '__main__':
    print("=== SELinux policy 5.4 shadow ===")
    patch_sepolicy_h()
    patch_rules()
