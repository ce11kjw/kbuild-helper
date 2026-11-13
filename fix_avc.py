#!/usr/bin/env python3
"""
修 5.4 SELinux avc notif 刷屏（preflight 5.8）

FinaSU 用 selinux_status_update_policyload() 传真实 seqno，
5.4 的 avc_cache.latest_notif 与之不同步，每次 notify 都 pr_warn 一行。
实测 0.04 秒刷 7000+ 行，打满 ring buffer 并拖慢整机。

修法：把 avc.c 里那条 pr_warn 改成 pr_warn_ratelimited。
"""
import io
import os
import sys

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
AVC = os.path.join(KDIR, 'security', 'selinux', 'avc.c')


def main():
    if not os.path.exists(AVC):
        print("  [SKIP] %s not found" % AVC)
        return
    s = io.open(AVC, encoding='utf-8').read()
    if 'avc54_notif_ratelimit' in s:
        print("  [--] already rate-limited")
        return

    anchor = 'pr_warn("SELinux: avc: seqno %d < latest_notif %d\\n",'
    if anchor not in s:
        # 宽松匹配
        import re
        m = re.search(r'pr_warn\(\s*"SELinux: avc:[^"]*seqno[^"]*"', s)
        if not m:
            print("  [!] anchor not found; dumping nearby lines:")
            idx = s.find('latest_notif')
            if idx > 0:
                print(s[max(0, idx - 300):idx + 200])
            return
        anchor = m.group(0)
        print("  (relaxed match: %r)" % anchor[:60])

    new = ('/* avc54_notif_ratelimit */\n\t\t\t'
           + anchor.replace('pr_warn(', 'pr_warn_ratelimited(', 1))
    s = s.replace(anchor, new, 1)
    io.open(AVC, 'w', encoding='utf-8').write(s)
    print("  [OK] avc notif warning rate-limited")


if __name__ == '__main__':
    print("=== avc notif 降噪 ===")
    main()
