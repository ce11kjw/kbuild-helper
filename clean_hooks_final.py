import re
import os
import shutil

SHIM_NOFAULT = r"""
/* === 5.4 compat: nofault helpers (build helper) === */
#ifndef KSU54_NOFAULT
#define KSU54_NOFAULT
#include <linux/uaccess.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
static inline long ksu54_strncpy_from_user_nofault(char *dst, const void __user *src, long n)
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
#define strncpy_from_user_nofault ksu54_strncpy_from_user_nofault

static inline long ksu54_copy_to_kernel_nofault(void *dst, const void *src, size_t n)
{
	memcpy(dst, src, n);
	return 0;
}
#define copy_to_kernel_nofault ksu54_copy_to_kernel_nofault
#endif
#endif
"""

SHIM_TWA = r"""
/* === 5.4 compat: TWA_* (build helper) === */
#ifndef KSU54_TWA
#define KSU54_TWA
#include <linux/task_work.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
#define TWA_RESUME true
#define TWA_SIGNAL true
#define TWA_NONE false
#endif
#endif
"""

SHIM_P4D = r"""
/* === 5.4 compat: p4d folded into pgd (build helper) === */
#ifndef KSU54_NOP4D
#define KSU54_NOP4D
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
#ifndef p4d_none
#define p4d_none(p4d) pgd_none((p4d).pgd)
#endif
#ifndef p4d_bad
#define p4d_bad(p4d) pgd_bad((p4d).pgd)
#endif
#ifndef p4d_present
#define p4d_present(p4d) pgd_present((p4d).pgd)
#endif
#ifndef p4d_leaf
/* 5.4 arm64 has no p4d leaf; leave undefined so #if defined(p4d_leaf) blocks are skipped */
#endif
#endif
#endif
"""

def find_file(name):
    for c in ['/tmp/' + name, os.environ.get('TMPDIR', '') + '/' + name, './' + name]:
        if c and os.path.exists(c):
            return c
    for root in ['/tmp', os.getcwd(), os.path.expanduser('~')]:
        try:
            for f in os.listdir(root):
                if f == name:
                    return os.path.join(root, f)
        except:
            pass
    return None

def add_shim(path, shim, marker):
    txt = open(path, encoding='utf-8', errors='surrogateescape').read()
    if marker in txt:
        return False
    lines = txt.split('\n')
    last = 0
    for idx, ln in enumerate(lines):
        if ln.strip().startswith('#include'):
            last = idx
    lines.insert(last + 1, shim)
    open(path, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(lines))
    return True

def clean_ksu_hooks(path, desc=''):
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
        if st == '#ifdef CONFIG_KSU' or st == '#if defined(CONFIG_KSU)':
            blk = '\n'.join(lines[i:min(i+8, len(lines))])
            if 'ksu_handle' in blk:
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
            out.append(indent + '/* removed */')
            changed += 1
            i += 1
            continue
        out.append(ln)
        i += 1
    if changed:
        open(path, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(out))
        print("  [OK] %s (%s)" % (path, desc))

print("=== 1. clean ReSukiSU hooks ===")
for f, d in [('fs/open.c','faccessat'), ('fs/exec.c','execveat'), ('fs/stat.c','stat'),
             ('fs/devpts/inode.c','devpts'), ('kernel/sys.c','setresuid'), ('fs/read_write.c','sys_read')]:
    clean_ksu_hooks(f, d)

print("")
print("=== 2. FinaSU 5.4 compat ===")
fin_root = None
if os.path.islink('drivers/kernelsu'):
    fin_root = os.path.realpath('drivers/kernelsu')
elif os.path.isdir('drivers/kernelsu'):
    fin_root = 'drivers/kernelsu'
if not fin_root or not os.path.isdir(fin_root):
    print("  !! FinaSU not found")
    raise SystemExit(1)
print("  root: %s" % fin_root)

# 2a. bad includes
BAD_INCLUDES = ['<linux/pgtable.h>', '<linux/minmax.h>']
cnt = 0
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
        for bi in BAD_INCLUDES:
            if bi in new:
                new = new.replace('#include ' + bi, '/* 5.4: missing ' + bi + ' */')
        if new != txt:
            open(p, 'w', encoding='utf-8', errors='surrogateescape').write(new)
            cnt += 1
            print("    - include: %s" % os.path.relpath(p, fin_root))
print("  [OK] bad includes: %d" % cnt)

# 2b. nofault
cnt = 0
for root, dirs, files in os.walk(fin_root):
    for f in files:
        if not f.endswith('.c'):
            continue
        p = os.path.join(root, f)
        try:
            txt = open(p, encoding='utf-8', errors='surrogateescape').read()
        except:
            continue
        if ('strncpy_from_user_nofault' in txt or 'copy_to_kernel_nofault' in txt) and 'KSU54_NOFAULT' not in txt:
            if add_shim(p, SHIM_NOFAULT, 'KSU54_NOFAULT'):
                cnt += 1
                print("    + nofault: %s" % os.path.relpath(p, fin_root))
print("  [OK] nofault: %d" % cnt)

# 2c. TWA
cnt = 0
for root, dirs, files in os.walk(fin_root):
    for f in files:
        if not f.endswith('.c'):
            continue
        p = os.path.join(root, f)
        try:
            txt = open(p, encoding='utf-8', errors='surrogateescape').read()
        except:
            continue
        if 'TWA_RESUME' in txt and 'KSU54_TWA' not in txt:
            if add_shim(p, SHIM_TWA, 'KSU54_TWA'):
                cnt += 1
                print("    + TWA: %s" % os.path.relpath(p, fin_root))
print("  [OK] TWA: %d" % cnt)

# 2d. patch_memory.c arm64: 去掉 p4d 层
pm = os.path.join(fin_root, 'hook', 'arm64', 'patch_memory.c')
if os.path.exists(pm):
    txt = open(pm, encoding='utf-8', errors='surrogateescape').read()
    orig = txt

    # 替换整段 p4d 处理为 5.4 版本（用 pgd 直接找 pud）
    old_block = """    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto fail;
#if defined(p4d_leaf)
    if (p4d_leaf(*p4d)) {
        return __p4d_to_phys(*p4d) + ((addr & ~P4D_MASK));
    }
#endif

    pud = pud_offset(p4d, addr);"""

    new_block = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto fail;
#if defined(p4d_leaf)
    if (p4d_leaf(*p4d)) {
        return __p4d_to_phys(*p4d) + ((addr & ~P4D_MASK));
    }
#endif
    pud = pud_offset(p4d, addr);
#else
    /* 5.4: p4d is folded into pgd, skip p4d level entirely */
    (void)p4d;
    pud = pud_offset(pgd, addr);
#endif"""

    if old_block in txt:
        txt = txt.replace(old_block, new_block)
        open(pm, 'w', encoding='utf-8', errors='surrogateescape').write(txt)
        print("  [OK] patch_memory.c: p4d block wrapped with version guard")
    else:
        # 检查是否已处理
        if 'p4d is folded into pgd' in txt:
            print("  [OK] patch_memory.c: already patched")
        else:
            print("  [!] patch_memory.c p4d 块未精确匹配，尝试后备方案")
            # 后备：把 p4d_none/p4d_bad 替换掉
            txt = txt.replace('p4d_none(*p4d) || p4d_bad(*p4d)',
                              'pgd_none(*(pgd_t *)p4d) || pgd_bad(*(pgd_t *)p4d)')
            txt = txt.replace('__p4d_to_phys(*p4d) + ((addr & ~P4D_MASK))',
                              '__pgd_to_phys(*(pgd_t *)p4d) + ((addr & ~PGDIR_MASK))')
            if txt != orig:
                open(pm, 'w', encoding='utf-8', errors='surrogateescape').write(txt)
                print("  [OK] patch_memory.c: fallback patch applied")

# 2e. seccomp stub
sc = os.path.join(fin_root, 'infra', 'seccomp_cache.c')
stub = find_file('seccomp_cache_54.c')
if os.path.exists(sc) and stub:
    shutil.copy(stub, sc)
    print("  [OK] seccomp_cache.c -> stub (1565 bytes)")
else:
    print("  !! seccomp stub FAILED (exists=%s stub=%s)" % (os.path.exists(sc), stub))

# 2f. pkg_observer stub
po = os.path.join(fin_root, 'manager', 'pkg_observer.c')
pkg_stub = find_file('pkg_observer_54.c')
if os.path.exists(po) and pkg_stub:
    shutil.copy(pkg_stub, po)
    print("  [OK] pkg_observer.c -> stub")
else:
    print("  !! pkg_observer stub FAILED (exists=%s stub=%s)" % (os.path.exists(po), pkg_stub))

# 2g. app_profile filter_count
ap = os.path.join(fin_root, 'policy', 'app_profile.c')
if os.path.exists(ap):
    txt = open(ap, encoding='utf-8', errors='surrogateescape').read()
    if 'filter_count' in txt and 'KSU54_NOFILTERCOUNT' not in txt:
        new = re.sub(
            r'([ \t]*)atomic_set\(&current->seccomp\.filter_count, 0\);',
            r'\1#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)\n\1atomic_set(&current->seccomp.filter_count, 0); /* KSU54_NOFILTERCOUNT */\n\1#endif',
            txt)
        if new != txt:
            if '#include <linux/version.h>' not in new:
                lines = new.split('\n')
                last = 0
                for idx, ln in enumerate(lines):
                    if ln.strip().startswith('#include'):
                        last = idx
                lines.insert(last + 1, '#include <linux/version.h>')
                new = '\n'.join(lines)
            open(ap, 'w', encoding='utf-8', errors='surrogateescape').write(new)
            print("  [OK] app_profile.c filter_count guarded")
        else:
            print("  [!] app_profile regex miss")

print("")
print("=== 3. 最终验证（打印修改后的关键文件头）===")
for chk in [os.path.join(fin_root,'infra','seccomp_cache.c'),
            os.path.join(fin_root,'manager','pkg_observer.c')]:
    if os.path.exists(chk):
        print("--- %s ---" % os.path.relpath(chk, fin_root))
        for ln in open(chk, encoding='utf-8', errors='surrogateescape').read().split('\n')[:6]:
            print("   " + ln)

print("")
print("=== done ===")
