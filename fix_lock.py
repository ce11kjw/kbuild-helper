#!/usr/bin/env python3
"""
Harden the 5.4 SELinux hooks:

A) ksu54_selinux_view() took a shallow copy of ss->policydb without the
   policy read lock. Another CPU (or an IRQ context) can be walking those
   structures; copy under read_lock_irqsave.

B) ksu54_selinux_commit() used write_lock(); the 5.4 kernel itself uses
   write_lock_irq() for this swap because SELinux lookups also run from
   interrupt context. Match the kernel.
"""

import os
import sys

OLD_VIEW = r'''static struct selinux_policy *ksu54_selinux_view(void)
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
}'''

NEW_VIEW = r'''static struct selinux_policy *ksu54_selinux_view(void)
{
	struct selinux_policy *p;
	struct selinux_ss *ss = selinux_state.ss;
	unsigned long flags;

	if (!ss)
		return ERR_PTR(-EINVAL);
	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);

	/* Shallow copy: copy the struct under the policy lock so a concurrent
	 * swap cannot leave us with a half-updated policydb. */
	read_lock_irqsave(&ss->policy_rwlock, flags);
	p->policydb = ss->policydb;
	p->sidtab = ss->sidtab;
	p->latest_granting = ss->latest_granting;
	read_unlock_irqrestore(&ss->policy_rwlock, flags);
	return p;
}'''

OLD_LOCK = '''	write_lock(&ss->policy_rwlock);
	memcpy(&ss->policydb, &pol->policydb, sizeof(ss->policydb));
	ss->latest_granting = pol->latest_granting;
	write_unlock(&ss->policy_rwlock);'''

NEW_LOCK = '''	/* write_lock_irq, matching security_load_policy(): SELinux lookups
	 * also run from interrupt context on 5.4. */
	write_lock_irq(&ss->policy_rwlock);
	memcpy(&ss->policydb, &pol->policydb, sizeof(ss->policydb));
	ss->latest_granting = pol->latest_granting;
	write_unlock_irq(&ss->policy_rwlock);'''


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'drivers/kernelsu'
    if os.path.islink(root):
        root = os.path.realpath(root)
    p = os.path.join(root, 'selinux', 'rules.c')
    print("target: %s" % p)
    if not os.path.exists(p):
        print("  !! not found")
        return

    s = open(p, encoding='utf-8', errors='surrogateescape').read()

    if 'read_lock_irqsave(&ss->policy_rwlock' not in s:
        if OLD_VIEW in s:
            s = s.replace(OLD_VIEW, NEW_VIEW)
            print("  [OK] ksu54_selinux_view: read lock added")
        else:
            print("  !! view function not matched")
    else:
        print("  [OK] view already locked")

    if 'write_lock_irq(&ss->policy_rwlock)' not in s:
        if OLD_LOCK in s:
            s = s.replace(OLD_LOCK, NEW_LOCK)
            print("  [OK] commit: write_lock_irq")
        else:
            print("  !! commit lock block not matched")
    else:
        print("  [OK] commit already irq-safe")

    open(p, 'w', encoding='utf-8', errors='surrogateescape').write(s)


if __name__ == '__main__':
    main()
