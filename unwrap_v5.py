#!/usr/bin/env python3
"""
内核侧 ReSukiSU hook 清理（v5 - 最终修正版）

修正点：fs/exec.c 的解包方式
  原代码：
      #ifdef CONFIG_KSU
      extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
                                     void *argv, void *envp, int *flags);      ← 2 行
      #ifdef CONFIG_KSU_SUSFS
      extern struct static_key_true ksu_su_compat_enabled;
      ...
      #endif
      #endif

  v4 只注释了第一行，第二行残留 → 语法错误。

  修正：解包时删除整个 `ksu_handle_execveat` 声明（跨行），只保留 SUSFS 子块。

v5 方法：先用正则删除块内所有以 `extern` 开头、含 `ksu_handle_` 但【不含 sucompat/susfs】
的语句（支持跨行用分号判断结束），再删外层一行。
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


def strip_pure_ksu_decls(inner_lines):
    """删除块内纯 ksu_handle_* 的 extern 声明（支持跨行）"""
    out = []
    i = 0
    while i < len(inner_lines):
        ln = inner_lines[i]
        st = ln.strip()
        if (st.startswith('extern') and 'ksu_handle_' in st
                and 'sucompat' not in st and 'susfs' not in st):
            # 累积到分号
            decl = ln
            j = i
            while ';' not in inner_lines[j] and j + 1 < len(inner_lines):
                j += 1
                decl += '\n' + inner_lines[j]
            indent = ln[:len(ln) - len(ln.lstrip())]
            out.append(indent + '/* removed (ReSukiSU decl) */')
            i = j + 1
            continue
        out.append(ln)
        i += 1
    return out


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
                # 嵌套 SUSFS：删外层包装 + 删纯 KSU 声明，保留 SUSFS 子块
                inner = lines[i + 1:end]
                cleaned = strip_pure_ksu_decls(inner)
                result.extend(cleaned)
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
    print("=== 内核侧 ReSukiSU hook 清理 (v5) ===")
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
