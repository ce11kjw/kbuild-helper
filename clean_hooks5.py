import re
import os

def comment_block(path, desc=''):
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
print("=== 2. FinaSU 5.4 兼容性修复 ===")
fin_root = None
if os.path.islink('drivers/kernelsu'):
    fin_root = os.path.realpath('drivers/kernelsu')
elif os.path.isdir('drivers/kernelsu'):
    fin_root = 'drivers/kernelsu'

if fin_root and os.path.isdir(fin_root):
    print("  FinaSU root: %s" % fin_root)

    # 2a. 去掉 linux/pgtable.h
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
            if 'linux/pgtable.h' in new:
                new = new.replace('#include <linux/pgtable.h>', '/* 5.4: no linux/pgtable.h */')
                new = new.replace('#include "linux/pgtable.h"', '/* 5.4: no linux/pgtable.h */')
                if new != txt:
                    open(p, 'w', encoding='utf-8', errors='surrogateescape').write(new)
                    print("  [OK] pgtable: %s" % p)

    # 2b. sucompat.c 加 strncpy_from_user_nofault 兼容
    sucompat = os.path.join(fin_root, 'feature', 'sucompat.c')
    if os.path.exists(sucompat):
        txt = open(sucompat, encoding='utf-8', errors='surrogateescape').read()
        if 'strncpy_from_user_nofault' in txt and 'ksu_compat_strncpy_nofault' not in txt:
            shim = '''
/* === 5.4 compat shim (build helper) === */
#ifndef KSU_COMPAT_NOFAULT_5_4
#define KSU_COMPAT_NOFAULT_5_4
#include <linux/uaccess.h>
static inline long ksu_compat_strncpy_nofault(char *dst, const void __user *src, long n)
{
	int ret;
	mm_segment_t old = get_fs();
	set_fs(KERNEL_DS);
	pagefault_disable();
	ret = strncpy_from_user(dst, src, n);
	pagefault_enable();
	set_fs(old);
	return ret;
}
#define strncpy_from_user_nofault ksu_compat_strncpy_nofault
static inline long ksu_compat_copy_to_kernel_nofault(void *dst, const void *src, size_t n)
{
	memcpy(dst, src, n);
	return 0;
}
#define copy_to_kernel_nofault ksu_compat_copy_to_kernel_nofault
#endif
/* === end === */
'''
            lines = txt.split('\n')
            last_inc = 0
            for idx, ln in enumerate(lines):
                if ln.strip().startswith('#include'):
                    last_inc = idx
            lines.insert(last_inc + 1, shim)
            open(sucompat, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(lines))
            print("  [OK] sucompat.c: shim")

    # 2c. patch_memory.c 处理 p4d（5.4 无 p4d 层）
    pm = os.path.join(fin_root, 'hook', 'arm64', 'patch_memory.c')
    if os.path.exists(pm):
        txt = open(pm, encoding='utf-8', errors='surrogateescape').read()
        if '__p4d_to_phys' in txt and 'KSU_5_4_NO_P4D' not in txt:
            # 5.4 的 p4d_offset 直接返回 pgd（p4d 被折叠），且没有 __p4d_to_phys
            # 用 #if defined(__p4d_to_phys) 保护 + 提供 fallback
            shim = '''
/* === 5.4 compat: no p4d layer on arm64 (build helper) === */
#ifndef KSU_5_4_NO_P4D
#define KSU_5_4_NO_P4D
#if defined(__aarch64__) && (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0) + 0)
#endif
static inline unsigned long ksu_compat_p4d_to_phys(p4d_t p4d)
{
	return (unsigned long)p4d.pgd | ((unsigned long)p4d.pgd & 0);
}
#endif
/* === end === */
'''
            # 更简单直接的方案：把 __p4d_to_phys 调用改成 __pgd_to_phys（5.4 p4d 折叠为 pgd）
            new = txt
            # 5.4: p4d_t 就是 pgd_t 的别名，__p4d_to_phys 不存在，用 __pgd_to_phys
            new = new.replace('__p4d_to_phys(*p4d)', '__pgd_to_phys(*(pgd_t *)p4d)')
            if new != txt:
                open(pm, 'w', encoding='utf-8', errors='surrogateescape').write(new)
                print("  [OK] patch_memory.c: __p4d_to_phys -> __pgd_to_phys")
            else:
                print("  [!] patch_memory.c 替换失败")

        # copy_to_kernel_nofault 也要 shim
        txt2 = open(pm, encoding='utf-8', errors='surrogateescape').read()
        if 'copy_to_kernel_nofault' in txt2 and 'ksu_compat_copy_to_knofault' not in txt2:
            shim2 = '''
/* === 5.4 compat: copy_to_kernel_nofault (build helper) === */
#ifndef KSU_5_4_CTKN
#define KSU_5_4_CTKN
static inline long ksu_compat_copy_to_knofault(void *dst, const void *src, size_t n)
{
	memcpy(dst, src, n);
	return 0;
}
#define copy_to_kernel_nofault ksu_compat_copy_to_knofault
#endif
/* === end === */
'''
            lines = txt2.split('\n')
            last_inc = 0
            for idx, ln in enumerate(lines):
                if ln.strip().startswith('#include'):
                    last_inc = idx
            lines.insert(last_inc + 1, shim2)
            open(pm, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(lines))
            print("  [OK] patch_memory.c: copy_to_kernel_nofault shim")

print("")
print("=== 完成 ===")
