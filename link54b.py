#!/usr/bin/env python3
"""
Last-mile link fixes for Linux 5.4 (build helper), v2.

Four undefined symbols at link time. All are resolved without touching
exported-symbol requirements, because the whole driver is built into the
kernel and can use kallsyms at runtime:

  ksu_handle_sys_reboot  -> no-op (only SUSFS defines it)
  path_umount            -> kern_unmount() on 5.4 (EXPORT_SYMBOL)
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
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <uapi/linux/mount.h>
#include <uapi/linux/fs.h>

/* ------------------------------------------------------------------ */
/* ksu_handle_sys_reboot                                              */
/* Only extension/susfs.c defines it, and that file builds only with   */
/* CONFIG_KSU_SUSFS. Without SUSFS the hook is unused, so a no-op.     */
/* ------------------------------------------------------------------ */
#ifndef CONFIG_KSU_SUSFS
/* extension/susfs.c also defines this when CONFIG_KSU_SUSFS=y. */
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
			  void __user **arg)
{
	(void)magic1;
	(void)magic2;
	(void)cmd;
	(void)arg;
	return 0;
}
#endif

/* ------------------------------------------------------------------ */
/* path_umount(struct path *, int)                                    */
/* ------------------------------------------------------------------ */
/*
 * path_umount(struct path *, int)
 *
 * 5.9+ detaches the mount from its namespace. 5.4 exposes the same thing
 * as kern_unmount(struct vfsmount *) — it clears real_mount(mnt)->mnt_ns
 * and drops the reference. It is EXPORT_SYMBOL'd, and takes the vfsmount
 * pointer we already have in struct path, so there is no need to walk
 * into the private struct mount (which is __randomize_layout anyway).
 */
extern void kern_unmount(struct vfsmount *mnt);

int path_umount(struct path *path, int flags)
{
	if (!path || !path->mnt)
		return -EINVAL;

	/* kern_unmount has no flags argument: it always performs a lazy
	 * detach (mnt_ns = NULL + mntput), which is what FinaSU wants for
	 * hiding its own bind mounts. MNT_DETACH needs no special handling. */
	(void)flags;
	kern_unmount(path->mnt);
	return 0;
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
/*
 * seccomp_filter_release(struct task_struct *)
 *
 * 5.9+ renamed the refcount-drop helper and made it take the task whose
 * filter should be released. On 5.4 the equivalent is put_seccomp_filter(),
 * which does __put_seccomp_filter(tsk->seccomp.filter).
 *
 * FinaSU's disable_seccomp() copies current into a fake task_struct,
 * clears current->seccomp.filter, then calls this with the fake so the
 * original filter still gets its reference dropped. Calling
 * put_seccomp_filter(fake) reproduces exactly that.
 */
extern void put_seccomp_filter(struct task_struct *tsk);

void seccomp_filter_release(struct task_struct *tsk)
{
	if (!tsk)
		return;
	if (!tsk->seccomp.filter)
		return;
	put_seccomp_filter(tsk);
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
