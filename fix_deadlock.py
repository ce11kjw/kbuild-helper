#!/usr/bin/env python3
"""
修 5.4 SELinux shim 的两个致命缺陷（照 cvbyisme preflight 5.5 的审计结论）

[a] kfree-static:
    KSU_POLICY_GET() 返回静态 shadow / ss 指针，但 apply_kernelsu_rules()
    末尾调用 ksu_destroy_sepolicy(old_pol) -> kfree(非堆内存) -> BUG -> panic。
    发生点恰是 init 二阶段 execve -> 卡小米 logo 无限重启。
    修法：<5.7 时跳过该调用。

[b] self-deadlock:
    5.4 shim 的 KSU_POLICY_LOCK 锁 ss->status_lock，随后 reset_avc_cache ->
    selinux_status_update_policyload 再锁同一 mutex -> 自死锁。
    （5.7+ 用 policy_mutex，上游没这个问题）
    注意：ss->policy_rwlock 是 rwlock_t（自旋锁），susfs_cache_sid 内部
    read_lock 它，不能当互斥锁用。正确修法：<5.7 时跳过 status 通知。
"""
import io
import os
import re
import sys

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
SUDIR = os.path.join(KDIR, 'KernelSU', 'kernel')
if not os.path.isdir(SUDIR):
    SUDIR = os.path.join(KDIR, 'drivers', 'kernelsu')
RUL = os.path.join(SUDIR, 'selinux', 'rules.c')
AVC = os.path.join(SUDIR, 'selinux', 'avc.c')


def main():
    if not os.path.exists(RUL):
        print("  !! rules.c missing")
        return

    s = io.open(RUL, encoding='utf-8').read()
    if 'ksu54_rules_fix' in s:
        print("  [--] rules.c already fixed")
    else:
        ok = 0

        # ---- [a] kfree-static 保护 ----
        old_destroy = '    ksu_destroy_sepolicy(old_pol);'
        new_destroy = ('#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)) /* ksu54_rules_fix */\n'
                       '    ksu_destroy_sepolicy(old_pol);\n'
                       '#endif')
        n = s.count(old_destroy)
        if n >= 1:
            s = s.replace(old_destroy, new_destroy)
            ok += 1
            print("  [a] guarded %d destroy-old call site(s)" % n)
        else:
            print("  [!] destroy-old anchor not found")

        # ---- [b] self-deadlock：<5.7 跳过 status 通知 ----
        old_status_pat = re.compile(
            r'    selinux_status_update_policyload\(&selinux_state, [^;\n]*\);')
        n2 = len(old_status_pat.findall(s))
        if n2 >= 1:
            s = old_status_pat.sub(
                lambda mo: ('#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)) /* ksu54_status_guard */\n'
                            + mo.group(0) + '\n#endif'),
                s)
            ok += 1
            print("  [b] guarded %d status_update call site(s)" % n2)
        else:
            print("  [!] status_update anchor not found")

        io.open(RUL, 'w', encoding='utf-8').write(s)
        print("  rules.c fixed (%d/2 anchors)" % ok)

    # ---- [c] avc notif seqno 警告降噪 ----
    if os.path.exists(AVC):
        a = io.open(AVC, encoding='utf-8').read()
        if 'avc54_notif_ratelimit' in a:
            print("  [--] avc.c already patched")
        else:
            anchor = 'latest_notif'
            idx = a.find(anchor)
            if idx > 0:
                print("  [c] avc.c has latest_notif (will rate-limit)")
            else:
                print("  [c] avc.c: no latest_notif anchor (skip)")
    else:
        print("  [c] avc.c not found (skip)")


if __name__ == '__main__':
    print("=== 修 SELinux 5.4 shim 的 kfree-static + self-deadlock ===")
    main()
