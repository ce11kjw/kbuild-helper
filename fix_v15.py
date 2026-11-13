#!/usr/bin/env python3
"""
v15：在每一处 5.4 释放块前插入 seqno 赋值（不用 re.sub 的回调闭包，避免状态污染）

匹配模式：
    <indent>kfree(pol);
    <indent>pol = NULL;
且该位置往前 40 行内没有 "__ksu54_seqno = "
"""
import io
import os
import re
import sys

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
SUDIR = os.path.join(KDIR, 'KernelSU', 'kernel')
if not os.path.isdir(SUDIR):
    SUDIR = os.path.join(KDIR, 'drivers', 'kernelsu')
RUL = os.path.join(SUDIR, 'selinux', 'rules.c')

lines = io.open(RUL, encoding='utf-8').read().split('\n')

inserted = 0
i = 0
out = []
while i < len(lines):
    cur = lines[i]
    nxt = lines[i + 1] if i + 1 < len(lines) else ''
    # 检测 "kfree(pol);" 后紧跟 "pol = NULL;"
    if (cur.strip() == 'kfree(pol);' and nxt.strip().startswith('pol = NULL;')):
        # 往前 40 行（在已输出的 out 里）看是否有赋值
        window = '\n'.join(out[-40:])
        if '__ksu54_seqno = ' in window:
            out.append(cur)
            i += 1
            continue
        indent = cur[:len(cur) - len(cur.lstrip())]
        out.append(indent + '__ksu54_seqno = ksu54_pol_get_granting(pol);')
        out.append(cur)
        inserted += 1
        i += 1
        continue
    out.append(cur)
    i += 1

print("  插入 seqno 赋值: %d 处" % inserted)
io.open(RUL, 'w', encoding='utf-8').write('\n'.join(out))

print()
for idx, l in enumerate(out, 1):
    if '__ksu54_seqno' in l:
        print('%4d| %s' % (idx, l))
