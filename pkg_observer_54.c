// SPDX-License-Identifier: GPL-2.0
/*
 * 5.4 compat: pkg_observer uses fsnotify APIs from 5.9+
 * (handle_inode_event, TWA_RESUME), which do not exist on 5.4.
 * Stub implementation: App install/uninstall events are not observed.
 * Impact: manager UI won't auto-refresh the app list.
 */

#include <linux/types.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)

struct ksu_pkg_observer_stub { int unused; };

int ksu_observer_init(void)
{
	return 0;
}

void ksu_observer_exit(void)
{
}

#else

/* 5.9+ uses the real implementation; this branch is unused in this build */
int ksu_observer_init(void)
{
	return 0;
}

void ksu_observer_exit(void)
{
}

#endif
