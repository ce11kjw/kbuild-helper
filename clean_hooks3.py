import re
import os

def comment_block_at(lines, start_idx, end_marker='#endif'):
    """从 start_idx 开始，把整块 #ifdef ... #endif 注释掉（保留结构）"""
    out = list(lines)
    depth = 0
    end = start_idx
    for i in range(start_idx, len(lines)):
        st = lines[i].strip()
        if st.startswith('#ifdef') or st.startswith('#if '):
            depth += 1
        elif st.startswith('#endif'):
            depth -= 1
            if depth == 0:
                end = i
                break
    for i in range(start_idx, end + 1):
        if out[i].strip() and not out[i].lstrip().startswith('/*'):
            indent = out[i][:len(out[i]) - len(out[i].lstrip())]
            out[i] = indent + '/* KSU removed: ' + out[i].strip()[:80] + ' */'
    return out, end

def patch_open_c(path):
    """fs/open.c: 处理多行 extern 声明"""
    if not os.path.exists(path):
        print("  [SKIP] %s" % path)
        return
    lines = open(path, encoding='utf-8', errors='surrogateescape').read().split('\n')
    out = []
    i = 0
    changed = 0
    while i < len(lines):
        ln = lines[i]
        st = ln.strip()
        # 找到 #ifdef CONFIG_KSU 且后面紧跟 ksu_handle extern 的块
        if st == '#ifdef CONFIG_KSU' and i + 1 < len(lines):
            nxt = lines[i+1].strip() if i+1 < len(lines) else ''
            if 'ksu_handle' in nxt or (i+2 < len(lines) and 'ksu_handle' in lines[i+2]):
                # 注释掉整块
                depth = 1
                j = i + 1
                while j < len(lines) and depth > 0:
                    s2 = lines[j].strip()
                    if s2.startswith('#ifdef') or s2.startswith('#if '):
                        depth += 1
                    elif s2.startswith('#endif'):
                        depth -= 1
                    j += 1
                for k in range(i, j):
                    if lines[k].strip():
                        indent = lines[k][:len(lines[k]) - len(lines[k].lstrip())]
                        out.append(indent + '/* KSU removed */')
                    else:
                        out.append(lines[k])
                changed += 1
                i = j
                continue
        # 注释单独的 ksu_handle 调用
        if re.match(r'^\s*ksu_handle_\w+\s*\(', ln) or re.match(r'^\s*\(void\)ksu_handle_\w+\s*\(', ln):
            indent = ln[:len(ln) - len(ln.lstrip())]
            out.append(indent + '/* KSU call removed: ' + st[:60] + ' */')
            changed += 1
            i += 1
            continue
        out.append(ln)
        i += 1
    if changed:
        open(path, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(out))
        print("  [OK] %s (%d changes)" % (path, changed))
    else:
        print("  [!] %s unchanged" % path)

def patch_simple(path, desc):
    """简单文件：注释 ksu_handle 调用和 extern"""
    if not os.path.exists(path):
        print("  [SKIP] %s" % path)
        return
    lines = open(path, encoding='utf-8', errors='surrogateescape').read().split('\n')
    out = []
    i = 0
    changed = 0
    while i < len(lines):
        ln = lines[i]
        st = ln.strip()
        if st == '#ifdef CONFIG_KSU' and i + 1 < len(lines) and 'ksu_handle' in lines[i+1]:
            depth = 1
            j = i + 1
            while j < len(lines) and depth > 0:
                s2 = lines[j].strip()
                if s2.startswith('#ifdef') or s2.startswith('#if '):
                    depth += 1
                elif s2.startswith('#endif'):
                    depth -= 1
                j += 1
            for k in range(i, j):
                if lines[k].strip():
                    indent = lines[k][:len(lines[k]) - len(lines[k].lstrip())]
                    out.append(indent + '/* KSU removed */')
                else:
                    out.append(lines[k])
            changed += 1
            i = j
            continue
        if re.match(r'^\s*ksu_handle_\w+\s*\(', ln) or re.match(r'^\s*\(void\)ksu_handle_\w+\s*\(', ln):
            indent = ln[:len(ln) - len(ln.lstrip())]
            out.append(indent + '/* KSU call removed: ' + st[:60] + ' */')
            changed += 1
            i += 1
            continue
        out.append(ln)
        i += 1
    if changed:
        open(path, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(out))
        print("  [OK] %s (%s, %d)" % (path, desc, changed))
    else:
        print("  [!] %s unchanged" % path)

print("=== 1. 清理 ReSukiSU hook ===")
patch_open_c('fs/open.c')
patch_simple('fs/exec.c', 'execveat')
patch_simple('fs/stat.c', 'stat')
patch_simple('fs/devpts/inode.c', 'devpts')
patch_simple('kernel/sys.c', 'setresuid')
patch_simple('fs/read_write.c', 'sys_read')

print("")
print("=== 2. 修复 FinaSU 的 5.4 兼容性 ===")
# 查找 FinaSU 目录
fin_dirs = ['drivers/kernelsu', 'KernelSU', 'FinaSU']
fin_root = None
for d in fin_dirs:
    if os.path.isdir(d) and os.path.exists(os.path.join(d, 'feature', 'sucompat.c')):
        fin_root = d
        break
if not fin_root and os.path.isdir('drivers/kernelsu'):
    # 可能是软链，用 realpath
    real = os.path.realpath('drivers/kernelsu')
    if os.path.exists(os.path.join(real, 'feature', 'sucompat.c')):
        fin_root = real

if fin_root:
    print("  FinaSU root: %s" % fin_root)
    # 所有 .c/.h 里把 linux/pgtable.h 注释掉
    fixed = 0
    for root, dirs, files in os.walk(fin_root):
        for f in files:
            if f.endswith(('.c', '.h')):
                p = os.path.join(root, f)
                try:
                    txt = open(p, encoding='utf-8', errors='surrogateescape').read()
                except:
                    continue
                if 'linux/pgtable.h' in txt:
                    new = txt.replace('#include <linux/pgtable.h>', '/* 5.4 has no linux/pgtable.h */')
                    new = new.replace('#include "linux/pgtable.h"', '/* 5.4 has no linux/pgtable.h */')
                    if new != txt:
                        open(p, 'w', encoding='utf-8', errors='surrogateescape').write(new)
                        print("  [OK] %s" % p)
                        fixed += 1
    print("  修复 pgtable.h 引用: %d 个文件" % fixed)
else:
    print("  [!] 未找到 FinaSU 目录")

print("")
print("=== 完成 ===")
