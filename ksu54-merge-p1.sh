#!/bin/bash
# ============================================================================
# ksu54-merge.sh —— FinaSU 5.4 + SUSFS 融合一键脚本
# ============================================================================
# 融合来源：
#   [cvbyisme] nofault(access_ok) / minmax宏 / __p4d_to_phys / TWA
#              SELinux policy shadow / pkg_observer 真backport
#              path_mount(do_mount) / path_umount(ksys_umount)
#              zygote_next 删除 / preinit 禁用 / 链接桩
#   [我们]     filename_trans 真5.4实现 / SUSFS v2.3.0 新版(反检测更强)
#
# 用法: bash ksu54-merge.sh [kernel_dir]
# ============================================================================
set -uo pipefail
KDIR="$(cd "${1:-.}" && pwd)"
cd "$KDIR"

SUDIR="$KDIR/KernelSU/kernel"
[ -d "$SUDIR" ] || SUDIR="$KDIR/drivers/kernelsu"
[ -d "$SUDIR" ] || { echo "::error::FinaSU tree not found"; exit 1; }

echo "=========================================="
echo " FinaSU 5.4 + SUSFS 融合补丁"
echo " KERNEL_DIR = $KDIR"
echo " FINASU_DIR = $SUDIR"
echo "=========================================="

# ---------- step 1: compat header ----------
echo ""
echo "[1/14] ksu54_compat.h"
mkdir -p "$KDIR/include/linux"
cat > "$KDIR/include/linux/ksu54_compat.h" <<'C54EOF'
#ifndef _KSU54_COMPAT_H
#define _KSU54_COMPAT_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>

/* <linux/pgtable.h> only exists since Linux 5.8 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#include <asm/pgtable.h>
#endif

/* untagged_addr() is Linux 5.7+ */
#ifndef untagged_addr
#define untagged_addr(addr) (addr)
#endif

/* TWA_* enum is 5.9+; 5.4 task_work_add() takes a bool */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
#ifndef TWA_RESUME
#define TWA_RESUME true
#endif
#ifndef TWA_SIGNAL
#define TWA_SIGNAL true
#endif
#ifndef TWA_NONE
#define TWA_NONE false
#endif
#endif

/* *_nofault are Linux 5.8+ */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
static inline int ksu54_strncpy_from_user_nofault(char *dst,
						  const void __user *src,
						  long count)
{
	long ret;
	if (count < 0)
		return -EINVAL;
	if (!access_ok(src, count))
		return -EFAULT;
	pagefault_disable();
	ret = strncpy_from_user(dst, src, count);
	pagefault_enable();
	if (ret < 0)
		return ret;
	if (ret >= count) {
		dst[count - 1] = 0;
		return -ERANGE;
	}
	return ret;
}
#define strncpy_from_user_nofault(dst, src, n) \
	ksu54_strncpy_from_user_nofault((char *)(dst), (const void __user *)(src), (long)(n))

static inline long ksu54_copy_from_user_nofault(void *dst,
						const void __user *src,
						size_t size)
{
	long ret;
	if (!access_ok(src, size))
		return -EFAULT;
	pagefault_disable();
	ret = __copy_from_user_inatomic(dst, src, size);
	pagefault_enable();
	return ret ? -EFAULT : 0;
}
#define copy_from_user_nofault(dst, src, n) \
	ksu54_copy_from_user_nofault((void *)(dst), (const void __user *)(src), (size_t)(n))

static inline long ksu54_copy_to_user_nofault(void __user *dst,
					      const void *src,
					      size_t size)
{
	long ret;
	if (!access_ok(dst, size))
		return -EFAULT;
	pagefault_disable();
	ret = __copy_to_user_inatomic(dst, src, size);
	pagefault_enable();
	return ret ? -EFAULT : 0;
}
#define copy_to_user_nofault(dst, src, n) \
	ksu54_copy_to_user_nofault((void __user *)(dst), (const void *)(src), (size_t)(n))

static inline int ksu54_copy_to_kernel_nofault(void *dst, const void *src,
					       size_t size)
{
	return copy_from_kernel_nofault(dst, src, size);
}
#define copy_to_kernel_nofault(dst, src, n) \
	ksu54_copy_to_kernel_nofault((void *)(dst), (const void *)(src), (size_t)(n))
#endif /* < 5.8 */

/* __p4d_to_phys(): p4d is folded away below Linux 5.8 */
#ifndef __p4d_to_phys
#define __p4d_to_phys(p4d) __pgd_to_phys(p4d)
#endif

/* <linux/minmax.h> split out of <linux/kernel.h> only in 5.10 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#ifndef min_t
#define min_t(type, x, y) ({ type __min1 = (x); type __min2 = (y); __min1 < __min2 ? __min1 : __min2; })
#endif
#ifndef max_t
#define max_t(type, x, y) ({ type __max1 = (x); type __max2 = (y); __max1 > __max2 ? __max1 : __max2; })
#endif
#endif

#endif /* _KSU54_COMPAT_H */
C54EOF
echo "    written"

# ---------- step 2: 删掉 5.4 缺失的 include + 注入 compat ----------
echo ""
echo "[2/14] fix includes + inject compat header"
for G in $(grep -rl '#include <linux/pgtable.h>\|#include <linux/minmax.h>\|#include <linux/hex.h>' "$SUDIR" --include=*.c --include=*.h 2>/dev/null); do
  sed -i 's|^#include <linux/pgtable.h>$|#include <linux/ksu54_compat.h>|' "$G"
  sed -i 's|^#include <linux/minmax.h>$|/* 5.4: minmax via ksu54_compat.h */|' "$G"
  sed -i 's|^#include <linux/hex.h>$|/* 5.4: hex via ksu54_compat.h */|' "$G"
  echo "    fixed: ${G#$KDIR/}"
done
for G in "$SUDIR/feature/sucompat.c" "$SUDIR/runtime/ksud_integration.c" \
         "$SUDIR/sulog/event.c" "$SUDIR/feature/adb_root.c" \
         "$SUDIR/hook/syscall_event_bridge.c" "$SUDIR/preinit/preinit.c" \
         "$SUDIR/hook/arm64/patch_memory.c" "$SUDIR/policy/app_profile.c" \
         "$SUDIR/feature/selinux_hide.c" "$SUDIR/selinux/rules.c" \
         "$SUDIR/selinux/sepolicy.c" "$SUDIR/manager/pkg_observer.c"; do
  [ -f "$G" ] || continue
  grep -q 'ksu54_compat.h' "$G" && continue
  sed -i '1i #include <linux/ksu54_compat.h>' "$G"
  echo "    inject: ${G#$KDIR/}"
done

# ---------- step 3: zygote_next ----------
echo ""
echo "[3/14] zygote_next collapse"
SH="$SUDIR/hook/setuid_hook.c"
if [ -f "$SH" ] && grep -q 'susfs_set_current_proc_umounted_for_zygote_next' "$SH"; then
  python3 - "$SH" <<'PYEOF'
import sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
old = """static void ksu_susfs_mark_umounted(bool zygote_next)
{
    susfs_set_current_proc_no_su();
    susfs_set_current_proc_umounted();
    if (zygote_next)
        susfs_set_current_proc_umounted_for_zygote_next();
}"""
new = """static void ksu_susfs_mark_umounted(bool zygote_next)
{
    /* 5.4 exposes a single TIF_PROC_UMOUNTED bit; no_su and zygote_next
     * collapse onto it. */
    (void)zygote_next;
    susfs_set_current_proc_no_su();
    susfs_set_current_proc_umounted();
}"""
if old in s:
    open(p, 'w', encoding='utf-8').write(s.replace(old, new, 1))
    print("    setuid_hook.c: collapsed")
else:
    print("    setuid_hook.c: anchor miss")
PYEOF
else
  echo "    skip"
fi

# ---------- step 4: app_profile seccomp ----------
echo ""
echo "[4/14] app_profile seccomp guards"
APF="$SUDIR/policy/app_profile.c"
if [ -f "$APF" ] && grep -q 'filter_count' "$APF"; then
  python3 - "$APF" <<'PYEOF'
import io, sys
p = sys.argv[1]
lines = io.open(p, encoding='utf-8').read().split('\n')
out, fc, rel = [], False, False
for l in lines:
    if 'seccomp.filter_count' in l and not fc:
        out += ['#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)', l, '#endif']
        fc = True
    elif l.strip() == 'seccomp_filter_release(fake);' and not rel:
        ind = l[:len(l) - len(l.lstrip())]
        out += ['#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)', l, '#else',
                ind + 'put_seccomp_filter(fake);', '#endif']
        rel = True
    else:
        out.append(l)
io.open(p, 'w', encoding='utf-8').write('\n'.join(out))
print("    app_profile.c: guards added")
PYEOF
else
  echo "    skip"
fi

echo ""
echo "=== [merge part 1/3] done ==="
