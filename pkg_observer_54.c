// SPDX-License-Identifier: GPL-2.0
/*
 * 5.4 compat stub for pkg_observer.
 *
 * The real implementation depends on fsnotify APIs added in 5.9
 * (fsnotify_ops.handle_inode_event) and on TWA_RESUME. Neither exists on
 * 5.4, so package install/uninstall notifications are disabled here.
 *
 * Impact: the manager UI does not auto-refresh its app list; it refreshes
 *         when reopened. Root, modules and App Profile are unaffected.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>

int ksu_observer_init(void)
{
	pr_info("KernelSU: pkg_observer disabled (kernel < 5.9)\n");
	return 0;
}

void __exit ksu_observer_exit(void)
{
}
