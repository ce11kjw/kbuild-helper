#!/usr/bin/env python3
"""
selinux_hide 5.4 真正启用（照 cvbyisme 思路，已核实 SUSFS 2.3.0 不碰 selinuxfs）

参考 cvbyisme/susfs-setup.sh step 4e：
  1) 去掉 enable() 里 backup_sepolicy 的硬门槛（5.4 直接查 live policy）
  2) 去掉 drop_backup_if_unused() 里对 sidtab 的释放（shim policy 无 sidtab）
  3) 5.7+ 的 policydb/sidtab 内部重建整段 #if 0
  4) 反转 CONFIG_KSU_SUSFS 守卫，让真正的 hook 生效
  5) 用内核原生 SELinux 服务实现三个 _with_policy 包装

已核实（fs/susfs.c 内 selinuxfs/write_op/sel_write_*/selinux_state 出现次数均为 0），
SUSFS 2.3.0 不会与 selinux_hide 争抢 selinuxfs，反转守卫安全。
"""
import io
import os
import re
import sys

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
SUDIR = os.path.join(KDIR, 'KernelSU', 'kernel')
if not os.path.isdir(SUDIR):
    SUDIR = os.path.join(KDIR, 'drivers', 'kernelsu')
SIH = os.path.join(SUDIR, 'feature', 'selinux_hide.c')

MARKER = 'ksu54_selinux_hide_54'

ADD = r'''
/* ===== ksu54_selinux_hide_54: Linux 5.4 backend =========================
 * 5.4 keeps the live policy in selinux_state.ss->policydb and its SELinux
 * services all take &selinux_state. Reuse those instead of rebuilding the
 * 5.7+ policy/sidtab internals (which are #if 0'd out above).
 * ====================================================================== */
static int security_context_to_sid_with_policy(struct selinux_policy *policy,
                                               const char *scontext, u32 scontext_len,
                                               u32 *sid, u32 def_sid, gfp_t gfp_flags,
                                               u32 *orig_sid_p, int *orig_rc_p)
{
	int rc;

	(void)policy;
	rc = security_context_to_sid_default(&selinux_state, scontext, scontext_len,
					     sid, def_sid, gfp_flags);
	if (orig_rc_p)
		*orig_rc_p = rc;
	if (orig_sid_p)
		*orig_sid_p = rc ? SECSID_NULL : *sid;
	return rc;
}

static int security_sid_to_context_with_policy(struct selinux_policy *policy,
                                               u32 sid, char **scontext,
                                               u32 *scontext_len)
{
	(void)policy;
	return security_sid_to_context(&selinux_state, sid, scontext, scontext_len);
}

static void security_compute_av_user_with_policy(struct selinux_policy *policy,
                                                 u32 ssid, u32 tsid, u16 tclass,
                                                 struct av_decision *avd)
{
	(void)policy;
	security_compute_av_user(&selinux_state, ssid, tsid, tclass, avd);
}
/* ===== ksu54_selinux_hide_54 done ===================================== */
'''


def main():
    if not os.path.exists(SIH):
        print("  [SKIP] selinux_hide.c")
        return
    s = io.open(SIH, encoding='utf-8').read()
    if MARKER in s:
        print("  [--] already patched")
        return

    n0 = len(s)

    # ---- 1) enable(): 去掉 backup_sepolicy 硬门槛 ----
    old_enable = '''    if (!backup_sepolicy) {
        pr_err("no backup sepolicy available, please save feature and reboot to retry!\\n");
        return -EAGAIN;
    }'''
    new_enable = ('    /* ksu54: 5.4 queries the live policy directly, '
                  'no backup sepolicy needed */')
    if old_enable in s:
        s = s.replace(old_enable, new_enable, 1)
        print("  [1] enable(): backup_sepolicy gate removed")
    else:
        print("  [!] enable() gate anchor not found")

    # ---- 2) drop_backup_if_unused(): 去掉 sidtab 释��� ----
    old_drop = '''        sidtab_destroy(backup_sepolicy->sidtab);
        kfree(backup_sepolicy->sidtab);
        ksu_destroy_sepolicy(backup_sepolicy);
        backup_sepolicy = NULL;'''
    new_drop = '''        /* ksu54: shim policy owns no sidtab */
        ksu_destroy_sepolicy(backup_sepolicy);
        backup_sepolicy = NULL;'''
    if old_drop in s:
        s = s.replace(old_drop, new_drop, 1)
        print("  [2] drop_backup(): sidtab release removed")
    else:
        print("  [!] drop_backup anchor not found")

    # ---- 3) 5.7+ 内部实现整段 #if 0 ----
    marker = '/*\n * Caveat:  Mutates scontext.\n */'
    idx = s.find(marker)
    if idx < 0:
        # 尝试另一种锚点
        idx = s.find('Caveat:  Mutates scontext')
        if idx > 0:
            idx = s.rfind('/*', 0, idx)
    if idx > 0:
        head, tail = s[:idx], s[idx:]
        tail = ('#if 0 /* ksu54: 5.7-only policydb/sidtab internals, unused on 5.4 */\n'
                + tail + '\n#endif /* ksu54 internals */\n')
        s = head + tail
        print("  [3] 5.7+ policydb/sidtab internals disabled")
    else:
        print("  [!] internals marker not found")

    # ---- 4) status_lock / status_page 重映射 ----
    a = s.count('selinux_state.status_lock')
    s = s.replace('selinux_state.status_lock', 'selinux_state.ss->status_lock')
    b = s.count('selinux_state.status_page')
    s = s.replace('selinux_state.status_page', 'selinux_state.ss->status_page')
    print("  [4] status_lock x%d / status_page x%d -> ss->" % (a, b))

    # ---- 5) 反转 CONFIG_KSU_SUSFS 守卫（最后做，避免影响上面替换）----
    c1 = s.count('#ifndef CONFIG_KSU_SUSFS')
    s = s.replace('#ifndef CONFIG_KSU_SUSFS',
                  '#if 1 /* ksu54: enable real selinux_hide under SUSFS */')
    c2 = len(re.findall(r'#ifdef CONFIG_KSU_SUSFS\b', s))
    s = re.sub(r'#ifdef CONFIG_KSU_SUSFS\b',
               '#if 0 /* ksu54: drop SUSFS no-op shortcut */', s)
    print("  [5] guards flipped: ifndef->if1 x%d, ifdef->if0 x%d" % (c1, c2))

    # ---- 6) 追加 5.4 后端实现 ----
    s = s.rstrip() + '\n' + ADD
    print("  [6] 5.4 native-service backend appended")

    io.open(SIH, 'w', encoding='utf-8').write(s)
    print("  [OK] selinux_hide.c %d -> %d bytes" % (n0, len(s)))


if __name__ == '__main__':
    print("=== selinux_hide 5.4 真正启用 ===")
    main()
