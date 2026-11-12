import re
import os
import shutil

# 找 seccomp 替换文件的多个可能位置
def find_stub():
    candidates = [
        '/tmp/seccomp_cache_54.c',
        os.environ.get('TMPDIR', '') + '/seccomp_cache_54.c',
        './seccomp_cache_54.c',
        os.path.expanduser('~/seccomp_cache_54.c'),
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return p
    # 兜底：搜索
    for root in ['/tmp', os.getcwd(), os.path.expanduser('~')]:
        try:
            for f in os.listdir(root):
                if f == 'seccomp_cache_54.c':
                    return os.path.join(root, f)
        except:
            pass
    return None

def comment_block(path, desc=''):
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
print("=== 2. FinaSU 5.4 兼容性 ===")
fin_root = None
if os.path.islink('drivers/kernelsu'):
    fin_root = os.path.realpath('drivers/kernelsu')
elif os.path.isdir('drivers/kernelsu'):
    fin_root = 'drivers/kernelsu'

if not fin_root or not os.path.isdir(fin_root):
    print("  !! FinaSU 未找到")
    raise SystemExit(1)

print("  FinaSU root: %s" % fin_root)

# 2a. pgtable
for root, dirs, files in os.walk(fin_root):
    for f in files:
        if not f.endswith(('.c', '.h')):
            continue
        p = os.path.join(root, f)
        try:
            txt = open(p, encoding='utf-8', errors='surrogateescape').read()
        except:
            continue
        if 'linux/pgtable.h' in txt:
            new = txt.replace('#include <linux/pgtable.h>', '/* 5.4: no linux/pgtable.h */')
            new = new.replace('#include "linux/pgtable.h"', '/* 5.4: no linux/pgtable.h */')
            if new != txt:
                open(p, 'w', encoding='utf-8', errors='surrogateescape').write(new)
                print("  [OK] pgtable: %s" % os.path.relpath(p, fin_root))

# 2b. sucompat shim
sucompat = os.path.join(fin_root, 'feature', 'sucompat.c')
if os.path.exists(sucompat):
    txt = open(sucompat, encoding='utf-8', errors='surrogateescape').read()
    if 'strncpy_from_user_nofault' in txt and 'ksu_compat_strncpy_nofault' not in txt:
        shim = '''
/* === 5.4 compat shim === */
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
static inline long ksu_compat_copy_to_knofault(void *dst, const void *src, size_t n)
{
	memcpy(dst, src, n);
	return 0;
}
#define copy_to_kernel_nofault ksu_compat_copy_to_knofault
#endif
'''
        lines = txt.split('\n')
        last = 0
        for idx, ln in enumerate(lines):
            if ln.strip().startswith('#include'):
                last = idx
        lines.insert(last + 1, shim)
        open(sucompat, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(lines))
        print("  [OK] sucompat.c: shim")

# 2c. patch_memory
pm = os.path.join(fin_root, 'hook', 'arm64', 'patch_memory.c')
if os.path.exists(pm):
    txt = open(pm, encoding='utf-8', errors='surrogateescape').read()
    new = txt
    if '__p4d_to_phys' in new:
        new = new.replace('__p4d_to_phys(*p4d)', '__pgd_to_phys(*(pgd_t *)p4d)')
    if new != txt:
        open(pm, 'w', encoding='utf-8', errors='surrogateescape').write(new)
        print("  [OK] patch_memory.c: p4d")
    txt2 = open(pm, encoding='utf-8', errors='surrogateescape').read()
    if 'copy_to_kernel_nofault' in txt2 and 'ksu_compat_copy_to_knofault' not in txt2:
        shim2 = '''
#ifndef KSU_5_4_CTKN
#define KSU_5_4_CTKN
static inline long ksu_compat_copy_to_knofault(void *dst, const void *src, size_t n)
{
	memcpy(dst, src, n);
	return 0;
}
#define copy_to_kernel_nofault ksu_compat_copy_to_knofault
#endif
'''
        lines = txt2.split('\n')
        last = 0
        for idx, ln in enumerate(lines):
            if ln.strip().startswith('#include'):
                last = idx
        lines.insert(last + 1, shim2)
        open(pm, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(lines))
        print("  [OK] patch_memory.c: ctkn")

# 2d. seccomp_cache - 用查找方式
sc = os.path.join(fin_root, 'infra', 'seccomp_cache.c')
stub = find_stub()
print("")
print("  seccomp stub 查找: %s" % (stub or '未找到'))
if os.path.exists(sc) and stub:
    shutil.copy(stub, sc)
    print("  [OK] seccomp_cache.c 已替换")
    print("  --- 替换后前 5 行 ---")
    for ln in open(sc, encoding='utf-8', errors='surrogateescape').read().split('\n')[:5]:
        print("    " + ln)
else:
    print("  !! seccomp_cache.c 替换失败 (sc_exists=%s, stub=%s)" % (os.path.exists(sc), stub))

# 2e. pkg_observer.c - 5.4 用空实现（依赖 5.9+ fsnotify）
po = os.path.join(fin_root, 'manager', 'pkg_observer.c')
pkg_stub = None
for cand in ['/tmp/pkg_observer_54.c', os.environ.get('TMPDIR','')+'/pkg_observer_54.c', './pkg_observer_54.c']:
    if cand and os.path.exists(cand):
        pkg_stub = cand
        break
if not pkg_stub:
    for root in ['/tmp', os.getcwd()]:
        try:
            for f in os.listdir(root):
                if f == 'pkg_observer_54.c':
                    pkg_stub = os.path.join(root, f)
                    break
        except: pass
        if pkg_stub: break

print("")
print("  pkg_observer stub: %s" % (pkg_stub or '未找到'))
if os.path.exists(po) and pkg_stub:
    shutil.copy(pkg_stub, po)
    print("  [OK] pkg_observer.c 已替换为空实现")
else:
    print("  !! pkg_observer.c 替换失败 (exists=%s)" % os.path.exists(po))

print("")
print("=== 完成 ===")
