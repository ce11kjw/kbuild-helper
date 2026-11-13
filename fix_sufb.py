#!/usr/bin/env python3
"""
su -> /system/bin/sh fallback（照 cvbyisme ksu-su-fallback.sh）

背景：Android 16 的 app seccomp 拦了 SYS_reboot，ksud 只能靠 /proc/self/fd
拿内核注入的 fd，而 sucompat 重定向的目标固定是 /data/adb/ksud。
文件缺失 = 两条路全断，管理器只会报「获取 Root 失败」。

FinaSU 里 SH_PATH 宏已定义但从未使用（死代码），这里把它接上。
"""
import io
import os
import sys

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
SUDIR = os.path.join(KDIR, 'KernelSU', 'kernel')
if not os.path.isdir(SUDIR):
    SUDIR = os.path.join(KDIR, 'drivers', 'kernelsu')
F = os.path.join(SUDIR, 'feature', 'sucompat.c')

OLD = '''    if (IS_ERR(ksud_file)) {
        pr_err("open ksud err: %ld\\n", PTR_ERR(ksud_file));
        put_unused_fd(tmp_fd);
        goto do_orig_execve;
    }'''

NEW = '''    if (IS_ERR(ksud_file)) {
        /* VENUS_SU_FALLBACK: /data/adb/ksud 缺失时改执行 /system/bin/sh，
         * 让首次刷入就能拿到 root shell，管理器随后自行释放 ksud。 */
        long ksud_err = PTR_ERR(ksud_file);

        pr_info("sucompat: %s not found (err %ld), fallback to %s\\n",
                KSUD_PATH, ksud_err, SH_PATH);
        old_cred = override_creds(ksu_cred);
        ksud_file = filp_open(SH_PATH, O_PATH, 0);
        revert_creds(old_cred);
        if (IS_ERR(ksud_file)) {
            pr_err("open ksud err: %ld, fallback sh err: %ld\\n",
                   ksud_err, PTR_ERR(ksud_file));
            put_unused_fd(tmp_fd);
            goto do_orig_execve;
        }
    }'''


def main():
    if not os.path.exists(F):
        print("  [SKIP] sucompat.c not found")
        return
    s = io.open(F, encoding='utf-8').read()
    if 'VENUS_SU_FALLBACK' in s:
        print("  [--] already patched")
        return
    if OLD not in s:
        print("  [!] anchor block not found; trying relaxed match")
        import re
        m = re.search(
            r'(\s*)if \(IS_ERR\(ksud_file\)\) \{\s*\n\s*pr_err\("open ksud err: %ld\\n", PTR_ERR\(ksud_file\)\);\s*\n\s*put_unused_fd\(tmp_fd\);\s*\n\s*goto do_orig_execve;\s*\n\s*\}',
            s)
        if not m:
            idx = s.find('open ksud err')
            if idx > 0:
                print("  nearby source:")
                print(s[max(0, idx - 500):idx + 300])
            return
        old_block = m.group(0)
        new_block = NEW.replace('    if (IS_ERR(ksud_file)) {',
                                m.group(1) + 'if (IS_ERR(ksud_file)) {', 1)
        s = s.replace(old_block, new_block, 1)
    else:
        s = s.replace(OLD, NEW, 1)

    io.open(F, 'w', encoding='utf-8').write(s)
    print("  [OK] su -> /system/bin/sh fallback installed")


if __name__ == '__main__':
    print("=== su fallback ===")
    main()
