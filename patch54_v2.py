import re
import os
import shutil

# ============ 只清理 ReSukiSU 的 hook（CONFIG_KSU），保留 SUSFS 的（CONFIG_KSU_SUSFS）============
def clean_only_ksu_hooks(path, desc=''):
    """只删除 #ifdef CONFIG_KSU（严格匹配，不含 _SUSFS）包住的 ksu_handle 块"""
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
        # 严格匹配 CONFIG_KSU（不含 SUSFS 后缀）
        is_pure_ksu = (st == '#ifdef CONFIG_KSU') or (st == '#if defined(CONFIG_KSU)')
        if is_pure_ksu:
            # 检查这个块里是否有 ksu_handle 调用
            blk = '\n'.join(lines[i:min(i + 10, len(lines))])
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
                # 整块保留原样！只是把它变成 0 条件（不删代码，避免破坏函数结构）
                for k in range(i, j):
                    if lines[k].strip():
                        indent = lines[k][:len(lines[k]) - len(lines[k].lstrip())]
                        out.append(indent + '/* KSU hook disabled: ' + lines[k].strip()[:60] + ' */')
                    else:
                        out.append(lines[k])
                changed += 1
                i = j
                continue
        # 单独的 ksu_handle 调用（不在任何 ifdef 里）——这种很危险，先跳过
        out.append(ln)
        i += 1
    if changed:
        open(path, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(out))
        print("  [OK] %s (%s)" % (path, desc))
    else:
        print("  [--] %s 无需处理" % path)

def find_file(name):
    for c in ['/tmp/' + name, os.environ.get('TMPDIR', '') + '/' + name, './' + name]:
        if c and os.path.exists(c):
            return c
    for root in ['/tmp', os.getcwd(), os.path.expanduser('~')]:
        try:
            for f in os.listdir(root):
                if f == name:
                    return os.path.join(root, f)
        except Exception:
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

static inline long ksu54_copy_from_user_nofault(void *dst, const void __user *src, size_t n)
{
	long ret = 0;
	mm_segment_t old = get_fs();
	set_fs(KERNEL_DS);
	pagefault_disable();
	if (copy_from_user(dst, src, n))
		ret = -EFAULT;
	pagefault_enable();
	set_fs(old);
	return ret;
}
#define copy_from_user_nofault ksu54_copy_from_user_nofault

static inline long ksu54_copy_to_user_nofault(void __user *dst, const void *src, size_t n)
{
	long ret = 0;
	mm_segment_t old = get_fs();
	set_fs(KERNEL_DS);
	pagefault_disable();
	if (copy_to_user(dst, src, n))
		ret = -EFAULT;
	pagefault_enable();
	set_fs(old);
	return ret;
}
#define copy_to_user_nofault ksu54_copy_to_user_nofault

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

NOFAULT_FUNCS = ('strncpy_from_user_nofault', 'copy_from_user_nofault',
                 'copy_to_user_nofault', 'copy_to_kernel_nofault')

def main():
    print("=== 1. 只清理 ReSukiSU (CONFIG_KSU) hook，保留 SUSFS ===")
    for f, d in [('fs/open.c', 'faccessat'), ('fs/exec.c', 'execveat'),
                 ('fs/stat.c', 'stat'), ('fs/devpts/inode.c', 'devpts'),
                 ('kernel/sys.c', 'setresuid(susfs-keep)'), ('fs/read_write.c', 'sys_read(susfs-keep)')]:
        clean_only_ksu_hooks(f, d)

    print("")
    print("=== 2. FinaSU 5.4 兼容 ===")
    fin_root = None
    if os.path.islink('drivers/kernelsu'):
        fin_root = os.path.realpath('drivers/kernelsu')
    elif os.path.isdir('drivers/kernelsu'):
        fin_root = 'drivers/kernelsu'
    if not fin_root or not os.path.isdir(fin_root):
        print("  !! FinaSU not found")
        return
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
    print("  [OK] bad includes: %d" % cnt)

    # 2b. nofault shim
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
            if any(fn in txt for fn in NOFAULT_FUNCS) and 'KSU54_NOFAULT' not in txt:
                if add_shim(p, SHIM_NOFAULT, 'KSU54_NOFAULT'):
                    cnt += 1
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
    print("  [OK] TWA shim: %d" % cnt)

    # 2d. patch_memory p4d
    pm = os.path.join(fin_root, 'hook', 'arm64', 'patch_memory.c')
    if os.path.exists(pm):
        txt = open(pm, encoding='utf-8', errors='surrogateescape').read()
        if '5.4: no p4d layer' not in txt:
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
    /* 5.4: no p4d layer */
    (void)p4d;
    pud = pud_offset(pgd, addr);
#endif"""
            if old_block in txt:
                txt = txt.replace(old_block, new_block)
                open(pm, 'w', encoding='utf-8', errors='surrogateescape').write(txt)
                print("  [OK] patch_memory.c p4d")
            else:
                print("  [!] patch_memory.c block mismatch")

    # 2e. seccomp stub
    sc = os.path.join(fin_root, 'infra', 'seccomp_cache.c')
    stub = find_file('seccomp_cache_54.c')
    if os.path.exists(sc) and stub:
        shutil.copy(stub, sc)
        print("  [OK] seccomp_cache.c -> stub")
    else:
        print("  !! seccomp stub failed")

    # 2f. pkg_observer stub
    po = os.path.join(fin_root, 'manager', 'pkg_observer.c')
    pkg_stub = find_file('pkg_observer_54.c')
    if os.path.exists(po) and pkg_stub:
        shutil.copy(pkg_stub, po)
        print("  [OK] pkg_observer.c -> stub")
    else:
        print("  !! pkg_observer stub failed")

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
                print("  [OK] app_profile.c filter_count")
            else:
                print("  [!] app_profile regex miss")

    # ===== 后续补丁（SELinux / 链接 / UAF）=====
    print("")
    print("=== 3. SELinux 5.4 移植 ===")
    import subprocess as _sp
    for step in ['selinux54d.py', 'hide54.py', 'sidtab54.py', 'fix_commit2.py',
                 'fix_lock.py', 'fix_leak.py', 'fix_uaf2.py', 'fix_uaf3.py',
                 'link54b.py', 'fix_sysread.py', 'fntrans54.py']:
        pth = '/tmp/' + step
        if not os.path.exists(pth):
            print("    [SKIP] %s (missing)" % step)
            continue
        r = _sp.run(['python3', pth, fin_root], capture_output=True, text=True)
        for line in (r.stdout or '').split(chr(10)):
            if line.strip():
                print("    " + line.strip())
        if r.returncode != 0 and (r.stderr or '').strip():
            print("    ERR:", (r.stderr or '')[:200])

    # selinux_access54.h 需要放到 selinux/ 目录
    _hdr = '/tmp/selinux_access54.h'
    if os.path.exists(_hdr):
        _shutil = __import__('shutil')
        _shutil.copy(_hdr, os.path.join(fin_root, 'selinux', 'selinux_access54.h'))
        print("    [OK] selinux_access54.h copied")

    print("")
    print("=== 完成 ===")

if __name__ == '__main__':
    main()
