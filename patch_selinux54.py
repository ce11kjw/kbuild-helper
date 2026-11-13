#!/usr/bin/env python3
"""
SELinux policy 5.4 shadow（v4，幂等）

修复点：
 - v3 在重复执行时用 re.S 贪婪匹配删除旧 shim，会吞掉后续内容
 - v4 改为：一旦检测到 KSU54_POLICY_FIELD 就立即返回，绝不二次改写
 - sepolicy.c 的 dup/destroy 交给 patch_sepolicy54b.py 统一处理
"""
import io
import os
import sys

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
#include <linux/slab.h>
#include "ss/services.h"
#include "ss/sidtab.h"
/*
 * 5.4 has no struct selinux_policy (split out in 5.7). FinaSU touches only
 * ->policydb, ->sidtab and ->latest_granting, all of which live in
 * struct selinux_ss on this kernel.
 *
 * The first two members mirror the START of struct selinux_ss exactly
 * (sidtab, then policydb), which is what lets selinux_hide.c reuse a
 * live->ss pointer as a policy pointer through a plain cast.
 * latest_granting sits after them: it is only read/written on real
 * duplicated policies, never through the cast.
 */
struct selinux_policy {
	struct sidtab *sidtab;
	struct policydb policydb;
	u32 latest_granting;
};
extern struct selinux_state selinux_state;

/* Clone a loaded 5.4 sidtab for a policy backup (read-only afterwards). */
static inline struct sidtab *ksu54_sidtab_dup(struct sidtab *src)
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
"""

MACROS = """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
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
#endif"""


def patch_sepolicy_h():
    if not os.path.exists(SPH):
        print("  [SKIP] sepolicy.h")
        return False
    s = io.open(SPH, encoding='utf-8').read()
    if 'KSU54_SELINUX_POLICY_SHIM' in s and 'struct sidtab *sidtab;' in s:
        print("  [--] sepolicy.h ok (idempotent skip)")
        return False
    if 'KSU54_SELINUX_POLICY_SHIM' in s:
        print("  !! sepolicy.h has old shim without sidtab; manual review needed")
        return False
    anchor = 'struct selinux_policy *ksu_dup_sepolicy'
    if anchor not in s:
        print("  !! sepolicy.h anchor not found")
        return False
    s = s.replace(anchor, SHIM + anchor, 1)
    io.open(SPH, 'w', encoding='utf-8').write(s)
    print("  [OK] sepolicy.h: shim + ksu54_sidtab_dup")
    return True


def patch_rules():
    if not os.path.exists(RUL):
        print("  [SKIP] rules.c")
        return False
    s = io.open(RUL, encoding='utf-8').read()
    if 'KSU54_POLICY_FIELD' in s:
        print("  [--] rules.c ok (idempotent skip)")
        return False

    old = 'struct selinux_policy *backup_sepolicy;'
    if old not in s:
        print("  !! rules.c: backup_sepolicy anchor not found")
        return False
    s = s.replace(old, old + '\n\n' + MACROS, 1)

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
    /* 5.4: old_pol is a live view over ss, already updated in place.
     * pol donated its policydb to ss; release the sidtab copy. */
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
            s = s[:a] + '        /* ksu54: sidtab cloned inside ksu_dup_sepolicy */\n    }\n' + s[b:]
            print("  [OK] rules.c: sidtab backup block dropped")

    io.open(RUL, 'w', encoding='utf-8').write(s)
    print("  [OK] rules.c: macros applied")
    return True


if __name__ == '__main__':
    print("=== SELinux policy 5.4 (v4, idempotent) ===")
    changed = patch_sepolicy_h() | patch_rules()
    print("  changed=%s" % changed)
