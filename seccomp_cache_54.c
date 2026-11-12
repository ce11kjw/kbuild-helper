# 5.4 兼容：seccomp cache 是 5.10+ 的优化，5.4 用空实现
# 影响：App 内 root 执行 reboot 可能被 seccomp 拦截（影响很小）

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
/* 5.4: 没有 SECCOMP_ARCH_NATIVE_NR / action_cache，用空实现 */
struct seccomp_filter;
void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr) { }
void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr) { }
#else
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/uaccess.h>
#include <linux/sched/task.h>
#include <linux/nsproxy.h>
#include <linux/fs.h>
#include "klog.h"
#include "infra/seccomp_cache.h"

struct action_cache {
    DECLARE_BITMAP(allow_native, SECCOMP_ARCH_NATIVE_NR);
#ifdef SECCOMP_ARCH_COMPAT
    DECLARE_BITMAP(allow_compat, SECCOMP_ARCH_COMPAT_NR);
#endif
};

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
    if (!filter) return;
    if (nr >= 0 && nr < SECCOMP_ARCH_NATIVE_NR)
        clear_bit(nr, filter->cache.allow_native);
#ifdef SECCOMP_ARCH_COMPAT
    if (nr >= 0 && nr < SECCOMP_ARCH_COMPAT_NR)
        clear_bit(nr, filter->cache.allow_compat);
#endif
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
    if (!filter) return;
    if (nr >= 0 && nr < SECCOMP_ARCH_NATIVE_NR)
        set_bit(nr, filter->cache.allow_native);
#ifdef SECCOMP_ARCH_COMPAT
    if (nr >= 0 && nr < SECCOMP_ARCH_COMPAT_NR)
        set_bit(nr, filter->cache.allow_compat);
#endif
}
#endif
