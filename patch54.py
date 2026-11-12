import re
import os
import shutil

# === 完整的 5.4 nofault 兼容层 ===
SHIM_NOFAULT = r"""
/* === 5.4 compat: all *_nofault helpers (build helper) === */
#ifndef KSU54_NOFAULT_ALL
#define KSU54_NOFAULT_ALL
#include <linux/uaccess.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)

/* 5.4 has copy_from_kernel_nofault in uaccess.h, but not the user-side ones. */

static inline long ksu54_strncpy_from_user_nofault(char *dst,
						   const void __user *src,
						   long count)
{
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	pagefault_disable();
	ret = strncpy_from_user(dst, src, count);
	pagefault_enable();
	set_fs(old_fs);
	return ret;
}
#define strncpy_from_user_nofault ksu54_strncpy_from_user_nofault

static inline long ksu54_copy_from_user_nofault(void *dst,
						const void __user *src,
						size_t size)
{
	long ret = 0;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	pagefault_disable();
	if (copy_from_user(dst, src, size))
		ret = -EFAULT;
	pagefault_enable();
	set_fs(old_fs);
	return ret;
}
#define copy_from_user_nofault ksu54_copy_from_user_nofault

static inline long ksu54_copy_to_user_nofault(void __user *dst,
					      const void *src,
					      size_t size)
{
	long ret = 0;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	pagefault_disable();
	if (copy_to_user(dst, src, size))
		ret = -EFAULT;
	pagefault_enable();
	set_fs(old_fs);
	return ret;
}
#define copy_to_user_nofault ksu54_copy_to_user_nofault

static inline long ksu54_copy_to_kernel_nofault(void *dst,
						const void *src,
						size_t size)
{
	memcpy(dst, src, size);
	return 0;
}
#define copy_to_kernel_nofault ksu54_copy_to_kernel_nofault

#endif /* < 5.8 */
#endif /* KSU54_NOFAULT_ALL */
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

NOFAULT_FUNCS = (
    'strncpy_from_user_nofault',
    'copy_from_user_nofault',
    'copy_to_user_nofault',
    'copy_to_kernel_nofault',
)

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
    out, i, changed = [], 0, 0
    while i < len(lines):
        ln = lines[i]
        st = ln.strip()
        if st == '#ifdef CONFIG_KSU' or st == '#if defined(CONFIG_KSU)':
            blk = '\n'.join(lines[i:min(i + 8, len(lines))])
            if 'ksu_handle' in blk:
                depth, j = 0, i
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
for f, d in [('fs/open.c', 'faccessat'), ('fs/exec.c', 'execveat'), ('fs/stat.c', 'stat'),
             ('fs/devpts/inode.c', 'devpts'), ('kernel/sys.c', 'setresuid'),
             ('fs/read_write.c', 'sys_read')]:
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

# 2a. 不存在的头文件
BAD_INCLUDES = ['<linux/pgtable.h>', '<linux/minmax.h>']
cnt = 0
for root, dirs, files in os.walk(fin_root):
    for f in files:
        if not f.endswith(('.c', '.h')):
            continue
        p = os.path.join(root, f)
        try:
            txt = open(p, encoding='utf-8', errors='surrogateescape').read()
        except Exception:
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

# 2b. 所有 nofault shim（一次补 4 个函数）
cnt = 0
for root, dirs, files in os.walk(fin_root):
    for f in files:
        if not f.endswith('.c'):
            continue
        p = os.path.join(root, f)
        try:
            txt = open(p, encoding='utf-8', errors='surrogateescape').read()
        except Exception:
            continue
        need = any(fn in txt for fn in NOFAULT_FUNCS)
        if need and 'KSU54_NOFAULT_ALL' not in txt:
            if add_shim(p, SHIM_NOFAULT, 'KSU54_NOFAULT_ALL'):
                cnt += 1
                print("    + nofault: %s" % os.path.relpath(p, fin_root))
print("  [OK] nofault shim: %d" % cnt)

# 2c. TWA shim
cnt = 0
for root, dirs, files in os.walk(fin_root):
    for f in files:
        if not f.endswith('.c'):
            continue
        p = os.path.join(root, f)
        try:
            txt = open(p, encoding='utf-8', errors='surrogateescape').read()
        except Exception:
            continue
        if 'TWA_RESUME' in txt and 'KSU54_TWA' not in txt:
            if add_shim(p, SHIM_TWA, 'KSU54_TWA'):
                cnt += 1
                print("    + TWA: %s" % os.path.relpath(p, fin_root))
print("  [OK] TWA shim: %d" % cnt)

# 2d. patch_memory arm64: p4d 层
pm = os.path.join(fin_root, 'hook', 'arm64', 'patch_memory.c')
if os.path.exists(pm):
    txt = open(pm, encoding='utf-8', errors='surrogateescape').read()
    if 'p4d is folded into pgd' in txt:
        print("  [OK] patch_memory.c already patched")
    else:
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
            print("  [OK] patch_memory.c p4d guarded")
        else:
            print("  [!] patch_memory.c block mismatch")

# 2e. seccomp stub
sc = os.path.join(fin_root, 'infra', 'seccomp_cache.c')
stub = find_file('seccomp_cache_54.c')
if os.path.exists(sc) and stub:
    shutil.copy(stub, sc)
    print("  [OK] seccomp_cache.c -> stub")
else:
    print("  !! seccomp stub FAILED")

# 2f. pkg_observer stub
po = os.path.join(fin_root, 'manager', 'pkg_observer.c')
pkg_stub = find_file('pkg_observer_54.c')
if os.path.exists(po) and pkg_stub:
    shutil.copy(pkg_stub, po)
    print("  [OK] pkg_observer.c -> stub")
else:
    print("  !! pkg_observer stub FAILED")

# 2g. app_profile filter_count
ap = os.path.join(fin_root, 'policy', 'app_profile.c')
if os.path.exists(ap):
    txt = open(ap, encoding='utf-8', errors='surrogateescape').read()
    if 'filter_count' in txt and 'KSU54_NOFILTERCOUNT' not in txt:
        new = re.sub(
            r'([ \t]*)atomic_set\(&current->seccomp\.filter_count, 0\);',
            r'\1#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)\n'
            r'\1atomic_set(&current->seccomp.filter_count, 0); /* KSU54_NOFILTERCOUNT */\n'
            r'\1#endif',
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
print("=== 3. final verify ===")
import subprocess
for name in ['infra/seccomp_cache.c', 'manager/pkg_observer.c']:
    p = os.path.join(fin_root, name)
    if os.path.exists(p):
        print("--- %s (first 3 lines) ---" % name)
        for ln in open(p, encoding='utf-8', errors='surrogateescape').read().split('\n')[:3]:
            print("   " + ln)
print("")
print("=== done ===")


# ============ 2h. SELinux 5.4 compat (rules.c + sepolicy.h) ============
import subprocess
print("")
print("  --- SELinux 5.4 compat ---")
elsec = os.path.join(fin_root, 'selinux')
if os.path.isdir(elsec):
    # 用内联方式应用（与 selinux54d.py 相同逻辑）
    SEP_H = """
/* ===== 5.4 compat: define struct selinux_policy (build helper) ===== */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
struct selinux_policy {
	struct sidtab *sidtab;
	struct policydb policydb;
	u32 latest_granting;
};
#endif
/* ===== end ===== */
"""
    sh_path = os.path.join(elsec, 'sepolicy.h')
    if os.path.exists(sh_path):
        t = open(sh_path, encoding='utf-8', errors='surrogateescape').read()
        if 'struct selinux_policy {' not in t:
            mk = '#include "ss/policydb.h"'
            t = t.replace(mk, mk + chr(10) + SEP_H, 1) if mk in t else SEP_H + chr(10) + t
            open(sh_path, 'w', encoding='utf-8', errors='surrogateescape').write(t)
            print("    [OK] sepolicy.h: struct added")
    # 调用外部脚本处理 rules.c
    r = subprocess.run(['python3', '/tmp/selinux54d.py', fin_root],
                       capture_output=True, text=True)
    for line in (r.stdout or '').split(chr(10)):
        if line.strip():
            print("    " + line.strip())
else:
    print("    [!] selinux dir not found")



# ============ 2i. filename_trans 5.4 兼容 ============
print("")
print("  --- filename_trans 5.4 ---")
import subprocess as _sp
r = _sp.run(['python3', '/tmp/fntrans54.py', fin_root], capture_output=True, text=True)
for line in (r.stdout or '').split(chr(10)):
    if line.strip():
        print("    " + line.strip())
if r.returncode != 0:
    print("    stderr:", (r.stderr or '')[:300])


# ============ 2j. selinux_hide.c 5.4 兼容 ============
print("")
print("  --- selinux_hide.c 5.4 ---")
import subprocess as _sp2, shutil as _sh
_hdr = '/tmp/selinux_access54.h'
if os.path.exists(_hdr):
    dst = os.path.join(fin_root, 'selinux', 'selinux_access54.h')
    _sh.copy(_hdr, dst)
    print("    [OK] selinux_access54.h copied")
    r2 = _sp2.run(['python3', '/tmp/hide54.py', fin_root], capture_output=True, text=True)
    for line in (r2.stdout or '').split(chr(10)):
        if line.strip():
            print("    " + line.strip())
else:
    print("    !! selinux_access54.h missing")


# ============ 2k. sidtab 5.4 兼容 ============
print("")
print("  --- sidtab 5.4 ---")
import subprocess as _sp3
r3 = _sp3.run(['python3', '/tmp/sidtab54.py', fin_root], capture_output=True, text=True)
for line in (r3.stdout or '').split(chr(10)):
    if line.strip():
        print("    " + line.strip())
if r3.returncode != 0:
    print("    stderr:", (r3.stderr or '')[:300])


# ============ 2k2. SELinux commit 语义修正 ============
print("")
print("  --- commit 语义修正 ---")
import subprocess as _spc
for _s in ['fix_commit2.py', 'fix_lock.py']:
    r = _spc.run(['python3', '/tmp/' + _s, fin_root], capture_output=True, text=True)
    for line in (r.stdout or '').split(chr(10)):
        if line.strip():
            print("    " + line.strip())

# ============ 2k3. 泄漏与 UAF 修正 ============
print("")
print("  --- 泄漏与 UAF 修正 ---")
import subprocess as _spu
for _s in ['fix_leak.py', 'fix_uaf2.py', 'fix_uaf3.py']:
    r = _spu.run(['python3', '/tmp/' + _s, fin_root], capture_output=True, text=True)
    for line in (r.stdout or '').split(chr(10)):
        if line.strip():
            print("    " + line.strip())

# ============ 2l. 链接期符号补齐 ============
print("")
print("  --- link stubs 5.4 ---")
import subprocess as _sp4
r4 = _sp4.run(['python3', '/tmp/link54b.py', fin_root], capture_output=True, text=True)
for line in (r4.stdout or '').split(chr(10)):
    if line.strip():
        print("    " + line.strip())
if r4.returncode != 0:
    print("    stderr:", (r4.stderr or '')[:300])
