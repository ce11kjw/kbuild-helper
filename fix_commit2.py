#!/usr/bin/env python3
"""
Fix ksu54_selinux_commit() — two bugs, one rewrite.

BUG 1 (use-after-free):
    policydb_destroy(&ss->policydb);
    ss->policydb = pol->policydb;      /* shallow copy */
    ...
    ksu_destroy_sepolicy(pol);         /* frees the same allocations again */

BUG 2 (sidtab loss):
    Rebuilding the sidtab with policydb_load_isids() only loads the initial
    SIDs. handle_sepolicy() runs at runtime, when the live sidtab holds a
    dynamic SID for every process and inode in the system. Throwing it away
    destroys all of them.

Correct semantics, matching what FinaSU does on 5.9+ (new policydb, keep
the live sidtab):
    stash old policydb -> memcpy new policydb in place -> keep ss->sidtab
    -> destroy the stashed copy.

pol->policydb is zeroed after the memcpy so ksu_destroy_sepolicy(pol)
only frees the shell.
"""

import os
import sys

MARKER = '/* 5.4: policy swap via memcpy, sidtab stays live */'

NEW_COMMIT = r'''/* 5.4: policy swap via memcpy, sidtab stays live.
 *
 * 5.4 embeds policydb inside selinux_ss, so this is not a pointer swap.
 * Follow security_load_policy()'s ordering (stash -> memcpy -> publish ->
 * destroy the stash), but deliberately keep the live sidtab: FinaSU's
 * 5.9+ path also reuses it (ksu_dup_sepolicy() kmemdup's the whole
 * selinux_policy including the sidtab pointer). Rebuilding it here would
 * drop every dynamic SID and break the running system.
 *
 * Ownership: after a successful commit the kernel owns the allocations
 * that used to hang off pol->policydb, so we zero it. The caller's
 * ksu_destroy_sepolicy(pol) then only frees the shell.
 */
static int ksu54_selinux_commit(struct selinux_policy *pol)
{
	struct selinux_ss *ss = selinux_state.ss;
	struct policydb old_db;

	if (!ss || !pol)
		return -EINVAL;

	/* Stash the outgoing policydb (shallow: it owns the allocations). */
	memcpy(&old_db, &ss->policydb, sizeof(old_db));

	/* Publish the new policydb, keeping ss->sidtab untouched. */
	write_lock(&ss->policy_rwlock);
	memcpy(&ss->policydb, &pol->policydb, sizeof(ss->policydb));
	ss->latest_granting = pol->latest_granting;
	write_unlock(&ss->policy_rwlock);

	/* The kernel now owns those allocations. */
	memset(&pol->policydb, 0, sizeof(pol->policydb));

	/* Free the superseded policydb outside the lock. */
	policydb_destroy(&old_db);
	return 0;
}'''


def find_and_replace(path):
    s = open(path, encoding='utf-8', errors='surrogateescape').read()

    if MARKER in s:
        print("  [OK] commit already rewritten")
        return

    # Locate the whole function and replace it wholesale.
    start_marker = '/* Install a deep-copied policy into the live selinux_state.ss */'
    start = s.find(start_marker)
    if start < 0:
        # try the newer comment we wrote earlier
        start_marker = '/* Install a deep-copied policy into the live selinux_state.ss.'
        start = s.find(start_marker)
    if start < 0:
        print("  !! commit function prologue not found")
        return

    # find the function end: scanning for "\n}\n" after start
    end = s.find('\n}\n', start)
    if end < 0:
        print("  !! commit function end not found")
        return
    end += len('\n}\n')

    s = s[:start] + NEW_COMMIT + '\n' + s[end:]
    open(path, 'w', encoding='utf-8', errors='surrogateescape').write(s)
    print("  [OK] rules.c: ksu54_selinux_commit rewritten (UAF + sidtab)")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'drivers/kernelsu'
    if os.path.islink(root):
        root = os.path.realpath(root)
    p = os.path.join(root, 'selinux', 'rules.c')
    print("target: %s" % p)
    if not os.path.exists(p):
        print("  !! rules.c not found")
        return
    find_and_replace(p)


if __name__ == '__main__':
    main()
