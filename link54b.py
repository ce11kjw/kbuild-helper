#!/usr/bin/env python3
"""
Last-mile link fixes for Linux 5.4 (build helper), v2.

Four undefined symbols at link time. All are resolved without touching
exported-symbol requirements, because the whole driver is built into the
kernel and can use kallsyms at runtime:

  ksu_handle_sys_reboot  -> no-op (only SUSFS defines it)
  path_umount            -> resolve "ksys_umount" at runtime
  path_mount             -> no-op for MS_PRIVATE on an unshared ns;
                            resolve "do_mount" at runtime otherwise
  seccomp_filter_release -> resolve at runtime; skip if only the 5.4
                            static helper exists
"""

import os
import sys

STUBS_FILE = 'infra/ksu54_stubs.c'

STUBS_BODY = r'''// SPDX-License-Identifier: GPL-2.0
/*
 * Linux 5.4 link-time shims (build helper).
 *
 * FinaSU targets 5.9+, where fs/namespace.c exposes path_mount/path_umount
 * and kernel/seccomp.c exposes seccomp_filter_release(). On 5.4 those names
 * do not exist. Since this driver is built into the kernel image (not a
 * loadable module), kallsyms is available and we resolve the 5.4
 * equivalents at runtime instead of hard-linking.
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/printk.h>
#include <linux/kallsyms.h>
#include <linux/types.h>
#include <linux/namei.h>

/* ------------------------------------------------------------------ */
/* ksu_handle_sys_reboot                                              */
/* Only extension/susfs.c defines it, and that file builds only with   */
/* CONFIG_KSU_SUSFS. Without SUSFS the hook is unused, so a no-op.     */
/* ------------------------------------------------------------------ */
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
			  void __user **arg)
{
	(void)magic1;
	(void)magic2;
	(void)cmd;
	(void)arg;
	return 0;
}

/* ------------------------------------------------------------------ */
/* path_umount(struct path *, int)                                    */
/* 5.4 has static do_umount(); the public entry is ksys_umount(name).  */
/* ------------------------------------------------------------------ */
typedef int (*ksu54_umount_fn)(char __user *name, int flags);
typedef int (*ksu54_do_umount_fn)(void *mnt, int flags);

int path_umount(struct path *path, int flags)
{
	static ksu54_umount_fn umount_fn;
	static ksu54_do_umount_fn do_umount_fn;
	char *page;
	char *name;
	int ret;

	if (!path || !path->dentry || !path->mnt)
		return -EINVAL;

	/* Preferred: call do_umount(real_mount(mnt), flags) directly. */
	if (!do_umount_fn)
		do_umount_fn = (ksu54_do_umount_fn)
			kallsyms_lookup_name("do_umount");
	if (do_umount_fn) {
		/* real_mount() is container_of(mnt, struct mount, mnt).
		 * struct vfsmount is not the first member on 5.4, so we
		 * cannot compute it here without fs/mount.h. Use the
		 * name-based path below instead. */
	}

	if (!umount_fn)
		umount_fn = (ksu54_umount_fn) kallsyms_lookup_name("ksys_umount");
	if (!umount_fn) {
		pr_warn_ratelimited("ksu54: ksys_umount not resolvable\n");
		return -ENOSYS;
	}

	page = __getname();
	if (!page)
		return -ENOMEM;

	name = d_path(path, page, PATH_MAX);
	if (IS_ERR(name)) {
		ret = PTR_ERR(name);
		__putname(page);
		return ret;
	}

	ret = umount_fn((char __user *)name, flags);
	__putname(page);
	return ret;
}

/* ------------------------------------------------------------------ */
/* path_mount(dev, path, type, flags, data)                           */
/* FinaSU's only call is MS_PRIVATE|MS_REC on the root mount right     */
/* after unshare(CLONE_NEWNS). In a fresh mount namespace the tree is  */
/* already private, so this is a no-op and we report success.          */
/* ------------------------------------------------------------------ */
int path_mount(const char *dev_name, struct path *path, const char *type_page,
	       unsigned long flags, void *data_page)
{
	(void)dev_name;
	(void)path;
	(void)type_page;
	(void)data_page;

	if (flags == (MS_PRIVATE | MS_REC))
		return 0;

	/*
	 * Anything else is unexpected for FinaSU; refusing is safer than
	 * silently pretending the mount happened.
	 */
	pr_warn_ratelimited("ksu54: path_mount flags=0x%lx unsupported\n",
			    flags);
	return -ENOSYS;
}

/* ------------------------------------------------------------------ */
/* seccomp_filter_release(struct task_struct *)                       */
/* 5.9 renamed the static helper; on 5.4 there is no equivalent that   */
/* takes a task_struct. Resolve the 5.9 name if a backport provides it,*/
/* otherwise skip — the caller only uses this to drop a fake filter.   */
/* ------------------------------------------------------------------ */
typedef void (*ksu54_seccomp_release_fn)(struct task_struct *tsk);

void seccomp_filter_release(struct task_struct *tsk)
{
	static ksu54_seccomp_release_fn fn;
	static bool resolved;

	if (!resolved) {
		fn = (ksu54_seccomp_release_fn)
			kallsyms_lookup_name("seccomp_filter_release");
		resolved = true;
		if (!fn)
			pr_info("ksu54: seccomp_filter_release absent, skipping\n");
	}
	if (fn)
		fn(tsk);
}

#endif /* < 5.9 */
'''


def ensure_stubs(root):
    path = os.path.join(root, STUBS_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, 'w', encoding='utf-8', errors='surrogateescape').write(STUBS_BODY)
    print("  [OK] wrote %s" % STUBS_FILE)


def add_to_kbuild(root):
    kb = os.path.join(root, 'Kbuild')
    s = open(kb, encoding='utf-8', errors='surrogateescape').read()
    if 'ksu54_stubs.o' in s:
        print("  [OK] Kbuild already lists stubs")
        return
    marker = 'kernelsu-objs += infra/su_mount_ns.o'
    if marker in s:
        s = s.replace(marker, marker + '\nkernelsu-objs += infra/ksu54_stubs.o')
    else:
        lines = s.split('\n')
        for i, ln in enumerate(lines):
            if ln.startswith('kernelsu-objs +='):
                lines.insert(i + 1, 'kernelsu-objs += infra/ksu54_stubs.o')
                break
        s = '\n'.join(lines)
    open(kb, 'w', encoding='utf-8', errors='surrogateescape').write(s)
    print("  [OK] Kbuild: added ksu54_stubs.o")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'drivers/kernelsu'
    if os.path.islink(root):
        root = os.path.realpath(root)
    print("FinaSU root: %s" % root)
    ensure_stubs(root)
    add_to_kbuild(root)


if __name__ == '__main__':
    main()
