#!/usr/bin/env python3
"""Patch feature/selinux_hide.c for Linux 5.4 (build helper)."""
import os, re, sys

INCLUDE_LINE = '#include "../selinux/selinux_access54.h"'
POLICY_RE = re.compile(
    r'rcu_dereference(?:_protected)?\(\s*selinux_state\.policy\s*(?:,[^)]*)?\)')

def patch(path):
    s = open(path, encoding='utf-8', errors='surrogateescape').read()
    orig = s
    log = []
    if 'selinux_access54.h' in s:
        print("  [OK] selinux_hide.c already patched")
        return
    lines = s.split('\n')
    for i, ln in enumerate(lines):
        if ln.strip().startswith('#include'):
            lines.insert(i + 1, INCLUDE_LINE)
            break
    s = '\n'.join(lines)
    log.append('include')

    s, n = POLICY_RE.subn('ksu54_selinux_policy()', s)
    if n:
        log.append('policy x%d' % n)

    n = s.count('&selinux_state.status_lock')
    if n:
        s = s.replace('&selinux_state.status_lock', 'ksu54_status_lock()')
        log.append('status_lock x%d' % n)

    n = s.count('selinux_state.status_page')
    if n:
        s = s.replace('selinux_state.status_page', 'ksu54_status_page()')
        log.append('status_page x%d' % n)

    if s != orig:
        open(path, 'w', encoding='utf-8', errors='surrogateescape').write(s)
        print("  [OK] selinux_hide.c: " + ", ".join(log))
    else:
        print("  [!] unchanged")

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
