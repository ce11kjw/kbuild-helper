import re
import os

def comment_block(path, start_marker_starts_with_ifdef_ksu=True, desc=''):
    """注释掉 #ifdef CONFIG_KSU ... #endif 整块（含内部 ksu_handle）"""
    if not os.path.exists(path):
        print("  [SKIP] %s" % path)
        return 0
    lines = open(path, encoding='utf-8', errors='surrogateescape').read().split('\n')
    out = []
    i = 0
    changed = 0
    while i < len(lines):
        ln = lines[i]
        st = ln.strip()
        is_guard = (st == '#ifdef CONFIG_KSU') or (st == '#if defined(CONFIG_KSU)')
        if is_guard:
            # 检查块内 5 行内是否含 ksu_handle
            block_text = '\n'.join(lines[i:min(i+8, len(lines))])
            if 'ksu_handle' in block_text:
                depth = 0
                j = i
                while j < len(lines):
                    s2 = lines[j].strip()
                    if s2.startswith('#ifdef') or s2.startswith('#if defined') or s2.startswith('#if '):
                        depth += 1
                    elif s2.startswith('#endif'):
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                    j += 1
                for k in range(i, j):
                    if lines[k].strip():
                        indent = lines[k][:len(lines[k]) - len(lines[k].lstrip())]
                        out.append(indent + '/* removed */')
                    else:
                        out.append(lines[k])
                changed += 1
                i = j
                continue
        # 单行 ksu_handle 调用
        if re.match(r'^\s*ksu_handle_\w+\s*\(', ln) or re.match(r'^\s*\(void\)ksu_handle_\w+\s*\(', ln):
            indent = ln[:len(ln) - len(ln.lstrip())]
            out.append(indent + '/* removed: ' + st[:60] + ' */')
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
    return changed

print("=== 1. 清理 ReSukiSU hook ===")
for f, d in [
    ('fs/open.c', 'faccessat'),
    ('fs/exec.c', 'execveat'),
    ('fs/stat.c', 'stat'),
    ('fs/devpts/inode.c', 'devpts'),
    ('kernel/sys.c', 'setresuid'),
    ('fs/read_write.c', 'sys_read'),
]:
    comment_block(f, desc=d)

print("")
print("=== 2. 修复 FinaSU 5.4 兼容性 ===")
# 找 FinaSU 源代码目录（drivers/kernelsu 是软链）
fin_root = None
if os.path.islink('drivers/kernelsu'):
    fin_root = os.path.realpath('drivers/kernelsu')
elif os.path.isdir('drivers/kernelsu'):
    fin_root = 'drivers/kernelsu'

if fin_root and os.path.isdir(fin_root):
    print("  FinaSU root: %s" % fin_root)
    fixed_files = []

    # 2a. 所有 .c/.h 去掉 linux/pgtable.h
    for root, dirs, files in os.walk(fin_root):
        for f in files:
            if not f.endswith(('.c', '.h')):
                continue
            p = os.path.join(root, f)
            try:
                txt = open(p, encoding='utf-8', errors='surrogateescape').read()
            except:
                continue
            new = txt
            if '#include <linux/pgtable.h>' in new or '#include "linux/pgtable.h"' in new:
                new = new.replace('#include <linux/pgtable.h>', '/* 5.4: no linux/pgtable.h */')
                new = new.replace('#include "linux/pgtable.h"', '/* 5.4: no linux/pgtable.h */')
            if new != txt:
                open(p, 'w', encoding='utf-8', errors='surrogateescape').write(new)
                print("  [OK] pgtable: %s" % p)
                fixed_files.append(p)

    # 2b. sucompat.c 补 strncpy_from_user_nofault 兼容
    sucompat = os.path.join(fin_root, 'feature', 'sucompat.c')
    if os.path.exists(sucompat):
        txt = open(sucompat, encoding='utf-8', errors='surrogateescape').read()
        if 'strncpy_from_user_nofault' in txt and 'ksu_compat_strncpy_from_user_nofault' not in txt:
            # 在所有 include 之后插入兼容宏
            shim = '''
/* === 5.4 compat: strncpy_from_user_nofault (added by build helper) === */
#ifndef KSU_COMPAT_NOFAULT_DEFINED
#define KSU_COMPAT_NOFAULT_DEFINED
static inline long ksu_compat_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr, long count)
{
	int ret;
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	pagefault_disable();
	ret = strncpy_from_user(dst, unsafe_addr, count);
	pagefault_enable();
	set_fs(old_fs);
	return ret;
}
#define strncpy_from_user_nofault ksu_compat_strncpy_from_user_nofault
#endif
/* === end compat === */
'''
            # 插到最后一个 #include 行之后
            lines = txt.split('\n')
            last_inc = 0
            for idx, ln in enumerate(lines):
                if ln.strip().startswith('#include'):
                    last_inc = idx
            lines.insert(last_inc + 1, shim)
            open(sucompat, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(lines))
            print("  [OK] sucompat.c: 加了 strncpy_from_user_nofault 兼容 shim")
        else:
            print("  [!] sucompat.c 无需修改或已修改")

print("")
print("=== 完成 ===")
