#!/usr/bin/env python3
"""
5.4 sidtab compat for feature/selinux_hide.c (build helper)

5.9+ wraps each SID in a struct sidtab_entry and caches string forms:
    sidtab_search_entry(sidtab, sid) -> struct sidtab_entry *
    sidtab_sid2str_get/put(sidtab, entry, ...)

5.4 returns the context directly and has no string cache:
    sidtab_search(sidtab, sid) -> struct context *

Strategy: rewrite the two helpers that depend on the 5.9 shape
(sidtab_entry_to_string / security_sid_to_context_with_policy) and drop
the sidtab_entry_to_string helper entirely on 5.4.

Impact: no per-SID string cache; context_struct_to_string() is called each
time. Correct, just a little slower on a rarely-hit path.
"""

import os
import re
import sys

# Replace sidtab_entry_to_string + security_sid_to_context_with_policy
OLD_BLOCK_START = 'static int sidtab_entry_to_string(struct policydb *p, struct sidtab *sidtab, struct sidtab_entry *entry,'

NEW_54 = r'''#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
/*
 * 5.4: sidtab_search() returns the context directly; there is no
 * sidtab_entry wrapper and no per-SID string cache.
 */
static int sidtab_entry_to_string(struct policydb *p, struct sidtab *sidtab,
				  struct context *entry, char **scontext,
				  u32 *scontext_len)
{
	return context_struct_to_string(p, entry, scontext, scontext_len);
}

static int security_sid_to_context_with_policy(struct selinux_policy *policy,
					       u32 sid, char **scontext,
					       u32 *scontext_len)
{
	struct policydb *policydb;
	struct sidtab *sidtab;
	struct context *entry;
	int rc = 0;

	if (scontext)
		*scontext = NULL;
	*scontext_len = 0;

	policydb = &policy->policydb;
	sidtab = policy->sidtab;

	entry = sidtab_search(sidtab, sid);
	if (!entry) {
		pr_err("SELinux: %s:  unrecognized SID %d\n", __func__, sid);
		rc = -EINVAL;
		goto out_unlock;
	}

	rc = sidtab_entry_to_string(policydb, sidtab, entry, scontext, scontext_len);

out_unlock:
	return rc;
}
#else
'''


def patch(path):
    s = open(path, encoding='utf-8', errors='surrogateescape').read()
    orig = s

    if 'KSU54_SIDTAB_COMPAT' in s:
        print("  [OK] selinux_hide.c sidtab already patched")
        return

    # find the start of sidtab_entry_to_string
    idx = s.find(OLD_BLOCK_START)
    if idx < 0:
        print("  !! sidtab_entry_to_string not found")
        return

    # find the end: the closing brace of security_sid_to_context_with_policy
    # locate "static void avd_init" which follows it
    end_marker = 'static void avd_init('
    end_idx = s.find(end_marker, idx)
    if end_idx < 0:
        print("  !! end marker not found")
        return

    original = s[idx:end_idx]
    s = s[:idx] + NEW_54 + original + '#endif /* KSU54_SIDTAB_COMPAT */\n\n' + s[end_idx:]

    open(path, 'w', encoding='utf-8', errors='surrogateescape').write(s)
    print("  [OK] selinux_hide.c: sidtab_entry_to_string + security_sid_to_context_with_policy wrapped")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'drivers/kernelsu'
    if os.path.islink(root):
        root = os.path.realpath(root)
    p = os.path.join(root, 'feature', 'selinux_hide.c')
    print("target: %s" % p)
    if os.path.exists(p):
        patch(p)


if __name__ == '__main__':
    main()
