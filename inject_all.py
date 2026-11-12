#!/usr/bin/env python3
"""给 FinaSU 所有源文件注入 ksu54_compat.h（幂等）"""
import os
import sys

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
SUDIR = os.path.join(KDIR, 'KernelSU', 'kernel')
if not os.path.isdir(SUDIR):
    SUDIR = os.path.join(KDIR, 'drivers', 'kernelsu')

SKIP_DIRS = {'preinit', 'riscv64'}  # preinit 独立编译；riscv64 不用于 arm64
SKIP_FILES = {'ksu54_stub.c'}

n = 0
for root, dirs, files in os.walk(SUDIR):
    rel = os.path.relpath(root, SUDIR)
    if any(part in SKIP_DIRS for part in rel.split(os.sep)):
        continue
    for fn in files:
        if not (fn.endswith('.c') or fn.endswith('.h')):
            continue
        if fn in SKIP_FILES:
            continue
        p = os.path.join(root, fn)
        try:
            s = open(p, encoding='utf-8', errors='surrogateescape').read()
        except Exception:
            continue
        if 'ksu54_compat.h' in s:
            continue
        # 保留首行注释/SPDX 在上，compat 插在其后
        lines = s.split('\n')
        idx = 0
        while idx < len(lines) and (lines[idx].startswith('//') or
                                    lines[idx].startswith('/*') or
                                    lines[idx].strip() == '' or
                                    lines[idx].startswith(' *')):
            if lines[idx].startswith('/*') and '*/' not in lines[idx]:
                # 跳过整段块注释
                idx += 1
                while idx < len(lines) and '*/' not in lines[idx]:
                    idx += 1
                idx += 1
                continue
            idx += 1
        lines.insert(idx, '#include <linux/ksu54_compat.h>')
        open(p, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(lines))
        n += 1
        if n <= 20:
            print('    inject: %s' % os.path.relpath(p, KDIR))
print('    total injected: %d files' % n)
