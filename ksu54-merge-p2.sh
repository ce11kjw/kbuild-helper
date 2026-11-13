#!/bin/bash
# ============================================================================
# ksu54-merge-p2.sh —— pkg_observer / seccomp / mount / SELinux
# ============================================================================
set -uo pipefail
KDIR="$(cd "${1:-.}" && pwd)"
cd "$KDIR"
SUDIR="$KDIR/KernelSU/kernel"
[ -d "$SUDIR" ] || SUDIR="$KDIR/drivers/kernelsu"

# ---------- step 5: pkg_observer 真 backport ----------
echo ""
echo "[5/14] pkg_observer 5.4 fsnotify backport"
POB="$SUDIR/manager/pkg_observer.c"
if [ -f "$POB" ] && ! grep -q 'ksu54_pkg_observer' "$POB"; then
cat > "$POB" <<'POBEOF'
// SPDX-License-Identifier: GPL-2.0
/* ksu54_pkg_observer: Linux 5.4 backport.
 *
 * 5.9+ fsnotify uses fsnotify_ops.handle_inode_event(mark, mask, inode, dir,
 * name, cookie, iter_info); 5.4 uses the older handle_event(mark, inode, mask,
 * data, data_type, file_name, cookie, iter_info). Same detection logic
 * (packages.list change -> defer track_throne via task_work), 5.4 callback
 * shape.
 */
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/fsnotify_backend.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/version.h>

#include "klog.h"
#include "manager/throne_tracker.h"

#define MASK_SYSTEM (FS_CREATE | FS_MOVE | FS_EVENT_ON_CHILD)

struct watch_dir {
	const char *path;
	u32 mask;
	struct path kpath;
	struct inode *inode;
	struct fsnotify_mark *mark;
};

static struct fsnotify_group *g;
static bool observer_ready;

static void ksu_track_throne_tw_func(struct callback_head *cb)
{
	kfree(cb);
	if (current->flags & PF_EXITING)
		return;
	track_throne(false);
}

static void ksu_defer_track_throne(void)
{
	struct callback_head *cb;

	if (!(current->flags & PF_KTHREAD)) {
		cb = kzalloc(sizeof(*cb), GFP_KERNEL);
		if (cb) {
			cb->func = ksu_track_throne_tw_func;
			if (!task_work_add(current, cb, true))
				return;
			kfree(cb);
		}
	}
	pr_warn("defer track_throne failed, run inline\n");
	track_throne(false);
}

static int ksu54_handle_event(struct fsnotify_group *group, struct inode *inode,
			      u32 mask, const void *data, int data_type,
			      const struct qstr *file_name, u32 cookie,
			      struct fsnotify_iter_info *iter_info)
{
	(void)group;
	(void)inode;
	(void)data;
	(void)data_type;
	(void)cookie;
	(void)iter_info;

	if (!file_name)
		return 0;
	if (mask & FS_ISDIR)
		return 0;
	if (file_name->len == 13 &&
	    !memcmp(file_name->name, "packages.list", 13)) {
		pr_info("packages.list detected: %u\n", mask);
		ksu_defer_track_throne();
	}
	return 0;
}

static const struct fsnotify_ops ksu54_ops = {
	.handle_event = ksu54_handle_event,
};

static int add_mark_on_inode(struct inode *inode, u32 mask,
			     struct fsnotify_mark **out)
{
	struct fsnotify_mark *m;
	int ret;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	fsnotify_init_mark(m, g);
	m->mask = mask;
	ret = fsnotify_add_inode_mark(m, inode, 0);
	if (ret) {
		fsnotify_put_mark(m);
		return -EINVAL;
	}
	*out = m;
	return 0;
}

static int watch_one_dir(struct watch_dir *wd)
{
	int ret;

	ret = kern_path(wd->path, LOOKUP_FOLLOW, &wd->kpath);
	if (ret) {
		pr_info("path not ready: %s (%d)\n", wd->path, ret);
		return ret;
	}
	wd->inode = d_inode(wd->kpath.dentry);
	ihold(wd->inode);
	ret = add_mark_on_inode(wd->inode, wd->mask, &wd->mark);
	if (ret) {
		pr_err("Add mark failed for %s (%d)\n", wd->path, ret);
		path_put(&wd->kpath);
		iput(wd->inode);
		wd->inode = NULL;
		return ret;
	}
	pr_info("watching %s\n", wd->path);
	return 0;
}

static void unwatch_one_dir(struct watch_dir *wd)
{
	if (wd->mark) {
		fsnotify_destroy_mark(wd->mark, g);
		fsnotify_put_mark(wd->mark);
		wd->mark = NULL;
	}
	if (wd->inode) {
		iput(wd->inode);
		wd->inode = NULL;
	}
	if (wd->kpath.dentry) {
		path_put(&wd->kpath);
		memset(&wd->kpath, 0, sizeof(wd->kpath));
	}
}

static struct watch_dir g_watch = { .path = "/data/system", .mask = MASK_SYSTEM };

int ksu_observer_init(void)
{
	int ret;

	g = fsnotify_alloc_group(&ksu54_ops);
	if (IS_ERR(g))
		return PTR_ERR(g);
	ret = watch_one_dir(&g_watch);
	observer_ready = true;
	pr_info("observer init done (5.4 fsnotify)\n");
	return 0;
}

void __exit ksu_observer_exit(void)
{
	if (!observer_ready)
		return;
	unwatch_one_dir(&g_watch);
	fsnotify_put_group(g);
	observer_ready = false;
	pr_info("observer exit done\n");
}
POBEOF
echo "    pkg_observer.c rewritten"
fi

# ---------- step 6: seccomp_cache ----------
echo ""
echo "[6/14] seccomp_cache stub"
SCC="$SUDIR/infra/seccomp_cache.c"
if [ -f "$SCC" ] && ! grep -q 'ksu54_seccomp_stub' "$SCC"; then
cat > "$SCC" <<'SCCEOF'
/* ksu54_seccomp_stub: Linux 5.4 has no seccomp syscall bitmap cache
 * (struct seccomp gained filter_count / action_cache only in 5.9), so both
 * helpers are no-ops. Root running reboot from a seccomp-filtered app may
 * still be blocked by that app's own filter; nothing else is affected.
 */
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)

struct seccomp_filter;

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
	(void)filter;
	(void)nr;
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
	(void)filter;
	(void)nr;
}

#else
#error "this stub is only for < 5.10"
#endif
SCCEOF
echo "    seccomp_cache.c stubbed"
fi

# ---------- step 7: mount helpers ----------
echo ""
echo "[7/14] export do_mount/ksys_umount + retarget callers"
NSC="$KDIR/fs/namespace.c"
if [ -f "$NSC" ] && ! grep -q 'EXPORT_SYMBOL(do_mount)' "$NSC"; then
cat > /tmp/_nsc_fix.py <<'NSCEOF'
import sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
a = "long do_mount(const char *dev_name, const char __user *dir_name,"
i = s.find(a)
if i >= 0:
    e = s.find("\n}\n", i)
    if e >= 0:
        s = s[:e+3] + "EXPORT_SYMBOL(do_mount);\n" + s[e+3:]
j = s.find("int ksys_umount(char __user *name, int flags)")
if j >= 0:
    k = s.find("\n}\n", j)
    if k >= 0:
        s = s[:k+3] + "EXPORT_SYMBOL(ksys_umount);\n" + s[k+3:]
open(p, 'w', encoding='utf-8').write(s)
print("    namespace.c: exported")
NSCEOF
python3 /tmp/_nsc_fix.py "$NSC"
fi

# su_mount_ns.c
SMN="$SUDIR/infra/su_mount_ns.c"
if [ -f "$SMN" ] && grep -q 'path_mount' "$SMN"; then
cat > /tmp/_smn_fix.py <<'SMNEOF'
import sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()

old_decl = ("extern int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags,\n"
            "                      void *data_page);")
new_decl = ("/* 5.4 has no path_mount(); do_mount() takes a __user dir_name. */\n"
            "extern long do_mount(const char *dev_name, const char __user *dir_name,\n"
            "                     const char *type_page, unsigned long flags, void *data_page);")
if old_decl in s:
    s = s.replace(old_decl, new_decl, 1)

old_call = "    int pm_ret = path_mount(NULL, &root_path, NULL, MS_PRIVATE | MS_REC, NULL);"
new_call = """    int pm_ret;
    {
        char *dirbuf = kmalloc(PATH_MAX, GFP_KERNEL);
        if (dirbuf) {
            char *p2 = d_path(&root_path, dirbuf, PATH_MAX);
            if (!IS_ERR(p2)) {
                mm_segment_t oldfs = get_fs();
                set_fs(KERNEL_DS);
                pm_ret = (int)do_mount(NULL, (const char __user *)p2, NULL,
                                       MS_PRIVATE | MS_REC, NULL);
                set_fs(oldfs);
            } else {
                pm_ret = (int)PTR_ERR(p2);
            }
            kfree(dirbuf);
        } else {
            pm_ret = -ENOMEM;
        }
    }"""
if old_call in s:
    s = s.replace(old_call, new_call, 1)

open(p, 'w', encoding='utf-8').write(s)
print("    su_mount_ns.c: path_mount -> do_mount")
SMNEOF
python3 /tmp/_smn_fix.py "$SMN"
fi

# kernel_umount.c
KUM="$SUDIR/feature/kernel_umount.c"
if [ -f "$KUM" ] && grep -q 'path_umount' "$KUM"; then
cat > /tmp/_kum_fix.py <<'KUMEOF'
import sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()

old_decl = 'extern int path_umount(struct path *path, int flags);'
new_decl = ("/* Linux 5.4 has no path_umount(); ksys_umount() takes a path string. */\n"
            "extern int ksys_umount(char __user *name, int flags);")
if old_decl in s:
    s = s.replace(old_decl, new_decl, 1)

old = """static void ksu_umount_mnt(struct path *path, int flags)
{
    int err = path_umount(path, flags);
    if (err) {
        pr_info_ratelimited("umount list entry failed: %d\\n", err);
    }
}"""
new = """static void ksu_umount_mnt(struct path *path, int flags)
{
    int err;
    char *dir = kmalloc(PATH_MAX, GFP_KERNEL);

    if (!dir)
        return;
    {
        char *p2 = d_path(path, dir, PATH_MAX);
        if (!IS_ERR(p2)) {
            mm_segment_t oldfs = get_fs();
            set_fs(KERNEL_DS);
            err = ksys_umount((char __user *)p2, flags);
            set_fs(oldfs);
        } else {
            err = (int)PTR_ERR(p2);
        }
    }
    kfree(dir);
    if (err) {
        pr_info_ratelimited("umount list entry failed: %d\\n", err);
    }
}"""
if old in s:
    s = s.replace(old, new, 1)
    open(p, 'w', encoding='utf-8').write(s)
    print("    kernel_umount.c: path_umount -> ksys_umount")
else:
    print("    kernel_umount.c: anchor miss")
KUMEOF
python3 /tmp/_kum_fix.py "$KUM"
fi

# ---------- SELinux ----------
# 由 workflow 的独立步骤统一执行（patch_selinux54 / patch_hide54 / patch_dup54 /
# patch_sepolicy54b），此处不再调用，避免重复执行导致 #if 结构被破坏。
echo ""
echo "[8-9/14] SELinux: delegated to workflow step"

echo ""
echo "=== [merge part 2/3] done ==="
