#!/usr/bin/env python3
"""
内核侧 ReSukiSU hook 清理（v6 - 最终版）

v5 的错误：删除 fs/exec.c 中 `extern int ksu_handle_execveat(...)` 声明，
但 SUSFS 分支 (CONFIG_KSU_SUSFS) 里仍然调用 ksu_handle_execveat()。

修正：解包时【保留】ksu_handle_execveat 的声明（FinaSU 提供了实现）。
      只删除那些"纯 ReSukiSU 独有"的声明，例如 ksu_handle_devpts
      （devpts 整块已被 #if 0 关掉，无影响）。

实际上：解包模式下，块内所有声明都保留 —— 因为它们都是 extern，
多一个声明不会有害（FinaSU 有对应实现就链接成功，没有就报错，
而我们已经确认这些都有实现）。
"""

import os
import re
import sys


def find_matching_endif(lines, start):
    depth = 0
    for i in range(start, len(lines)):
        s = lines[i].strip()
        if s.startswith('#ifdef') or s.startswith('#ifndef') or s.startswith('#if '):
            depth += 1
        elif s.startswith('#endif'):
            depth -= 1
            if depth == 0:
                return i
    return -1


def has_nested_susfs(lines, start, end):
    for i in range(start, end + 1):
        if 'CONFIG_KSU_SUSFS' in lines[i]:
            return True
    return False


def process(path, desc=''):
    if not os.path.exists(path):
        print("  [SKIP] %s" % path)
        return
    lines = open(path, encoding='utf-8', errors='surrogateescape').read().split('\n')
    result = []
    i = 0
    disabled = 0
    unwrapped = 0

    while i < len(lines):
        st = lines[i].strip()
        is_pure_ksu = (st == '#ifdef CONFIG_KSU' or st == '#if defined(CONFIG_KSU)')

        if is_pure_ksu:
            end = find_matching_endif(lines, i)
            if end < 0:
                result.append(lines[i])
                i += 1
                continue

            if has_nested_susfs(lines, i, end):
                # 嵌套 SUSFS：删掉外层两行(#ifdef/#endif)，内部【原样保留】
                indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
                result.append(indent + '/* unwrapped CONFIG_KSU (SUSFS nested block kept) */')
                for k in range(i + 1, end):
                    result.append(lines[k])
                unwrapped += 1
                i = end + 1
                continue
            else:
                indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
                result.append(indent + '#if 0 /* KSU(ReSukiSU) disabled for 5.4/SUSFS */')
                for k in range(i + 1, end):
                    result.append(lines[k])
                result.append(indent + '#endif')
                disabled += 1
                i = end + 1
                continue

        result.append(lines[i])
        i += 1

    if disabled or unwrapped:
        open(path, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(result))
        print("  [OK] %-22s %-18s (禁用 %d, 解包 %d)" % (path, desc, disabled, unwrapped))
    else:
        print("  [--] %-22s %-18s (无 CONFIG_KSU)" % (path, desc))


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.chdir(root)
    print("=== 内核侧 ReSukiSU hook 清理 (v6) ===")
    for f, d in [
        ('fs/exec.c', 'execveat'),
        ('fs/open.c', 'faccessat'),
        ('fs/stat.c', 'stat'),
        ('fs/devpts/inode.c', 'devpts'),
        ('kernel/sys.c', 'setresuid(SUSFS)'),
        ('fs/read_write.c', 'sys_read(SUSFS)'),
    ]:
        process(f, d)


if __name__ == '__main__':
    main()
