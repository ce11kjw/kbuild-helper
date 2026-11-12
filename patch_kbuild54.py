#!/usr/bin/env python3
"""Kbuild 处理：链接桩 + preinit 禁用（独立文件）"""
import io
import os
import sys

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
SUDIR = os.path.join(KDIR, 'KernelSU', 'kernel')
if not os.path.isdir(SUDIR):
    SUDIR = os.path.join(KDIR, 'drivers', 'kernelsu')
KB = os.path.join(SUDIR, 'Kbuild')

STUB_C = '''/*
 * ksu54_stub.c - 5.4 stand-ins for ksu_handle_* hooks.
 *
 * The vendor kernel tree calls these from fs/open.c, fs/stat.c, fs/exec.c and
 * kernel/reboot.c behind plain CONFIG_KSU. extension/susfs.c carries the real
 * definitions, but that file only builds with CONFIG_KSU_SUSFS=y, so without
 * SUSFS the vmlinux link fails with undefined symbols. Signatures mirror the
 * extern declarations in the vendor tree so pointer types match exactly.
 */
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>

struct user_arg_ptr;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
#ifndef CONFIG_KSU_SUSFS
int __maybe_unused ksu_handle_execveat(int *fd, struct filename **filename_ptr,
                                       void *argv, void *envp, int *flags)
{
    return -EINVAL;
}

int __maybe_unused ksu_handle_faccessat(int *dfd,
                                        const char __user **filename_user,
                                        int *mode, int *flags)
{
    return 0;
}

int __maybe_unused ksu_handle_stat(int *dfd, const char __user **filename_user,
                                   int *flags)
{
    return 0;
}

void __maybe_unused ksu_handle_vfs_fstat(int fd, loff_t *kstat_size_ptr)
{
    (void)fd;
    (void)kstat_size_ptr;
}

void __maybe_unused ksu_handle_sys_read(unsigned int fd)
{
    (void)fd;
}

int __maybe_unused ksu_handle_sys_reboot(int magic1, int magic2,
                                         unsigned int cmd, void __user **arg)
{
    (void)magic1;
    (void)magic2;
    (void)cmd;
    (void)arg;
    return -EINVAL;
}
#endif /* !CONFIG_KSU_SUSFS */
#endif /* < 5.9 */
'''


def main():
    # 1. 写链接桩
    stub = os.path.join(SUDIR, 'extension', 'ksu54_stub.c')
    os.makedirs(os.path.dirname(stub), exist_ok=True)
    io.open(stub, 'w', encoding='utf-8').write(STUB_C)
    print("  [OK] extension/ksu54_stub.c written")

    if not os.path.exists(KB):
        print("  !! Kbuild not found")
        return

    s = io.open(KB, encoding='utf-8').read()
    orig = s

    # 2. 加 ksu54_stub.o
    if 'ksu54_stub' not in s:
        anchor = 'kernelsu-$(CONFIG_KSU_SUSFS) += extension/susfs.o'
        if anchor in s:
            s = s.replace(anchor,
                          anchor + '\n# ksu54_stub: unconditional 5.4 link stubs\n'
                                   'kernelsu-y += extension/ksu54_stub.o', 1)
        else:
            lines = s.split('\n')
            for i, l in enumerate(lines):
                if ('kernelsu-objs +=' in l) or ('kernelsu-y +=' in l):
                    lines.insert(i + 1, 'kernelsu-y += extension/ksu54_stub.o')
                    break
            s = '\n'.join(lines)
        print("  [OK] Kbuild: ksu54_stub.o added")

    # 3. preinit 禁用（只加一次，替换对象行为 ccflags）
    if 'ksu54_force_no_preinit' not in s:
        old_objs = 'kernelsu-objs += preinit/preinit.o\nkernelsu-objs += preinit/blob.o\n'
        if old_objs in s:
            new_objs = ('# ksu54_force_no_preinit: preinit swaps a static runner.elf in\n'
                        '# for PID 1\'s "init selinux_setup" execve; that is the most\n'
                        '# likely cause of a silent hang at the boot logo with no log.\n'
                        'ccflags-y += -DKSU_NO_PREINIT\n')
            s = s.replace(old_objs, new_objs, 1)
            print("  [OK] Kbuild: preinit disabled (objects dropped + -DKSU_NO_PREINIT)")
        else:
            print("  [--] Kbuild: preinit object lines not found")

    if s != orig:
        io.open(KB, 'w', encoding='utf-8').write(s)
        # 统计
        n_pre = s.count('-DKSU_NO_PREINIT')
        n_stub = s.count('ksu54_stub')
        print("  Kbuild 检查: -DKSU_NO_PREINIT x%d, ksu54_stub x%d" % (n_pre, n_stub))


if __name__ == '__main__':
    print("=== Kbuild 处理 ===")
    main()
