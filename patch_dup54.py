#!/usr/bin/env python3
"""把 ksu54_sidtab_dup 注入 sepolicy.h（供 sepolicy.c 和 selinux_hide.c 共用）"""
import io
import os
import sys

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
SUDIR = os.path.join(KDIR, 'KernelSU', 'kernel')
if not os.path.isdir(SUDIR):
    SUDIR = os.path.join(KDIR, 'drivers', 'kernelsu')
SPH = os.path.join(SUDIR, 'selinux', 'sepolicy.h')
SIH = os.path.join(SUDIR, 'feature', 'selinux_hide.c')

SIDTAB_DUP = '''
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
/*
 * ksu54_sidtab_dup: clone a 5.4 sidtab for a policy backup.
 *
 * A loaded 5.4 sidtab is an immutable radix tree: entries are only added by
 * sidtab_context_to_sid() under s->lock. The backup exists solely for
 * read-only SID lookups while the live policy is swapped, so copying the
 * node pointers and re-initialising the lock and the reverse map suffices.
 */
static inline struct sidtab *ksu54_sidtab_dup(struct sidtab *src)
{
	struct sidtab *dst;
	int i;

	if (!src)
		return NULL;
	dst = kmemdup(src, sizeof(*dst), GFP_KERNEL);
	if (!dst)
		return NULL;
	spin_lock_init(&dst->lock);
	dst->convert = NULL;
	for (i = 0; i < (1 << SIDTAB_HASH_BITS); i++)
		INIT_HLIST_HEAD(&dst->context_to_sid[i]);
	return dst;
}
#endif
'''


def main():
    if not os.path.exists(SPH):
        print("  !! sepolicy.h missing")
        return
    s = io.open(SPH, encoding='utf-8').read()

    if 'ksu54_sidtab_dup' not in s:
        # 插在 shim 的 #endif 之后（即 struct selinux_policy 定义完）
        anchor = 'extern struct selinux_state selinux_state;\n#endif\n'
        if anchor in s:
            s = s.replace(anchor, anchor + SIDTAB_DUP, 1)
            io.open(SPH, 'w', encoding='utf-8').write(s)
            print("  [OK] sepolicy.h: ksu54_sidtab_dup added")
        else:
            print("  !! shim anchor not found")
            return
    else:
        print("  [--] ksu54_sidtab_dup already present")

    # 从 selinux_hide.c 移除重复定义
    if os.path.exists(SIH):
        t = io.open(SIH, encoding='utf-8').read()
        if 'static struct sidtab *ksu54_sidtab_dup' in t:
            start = t.find('#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)\n/*\n * ksu54_sidtab_dup')
            if start >= 0:
                end = t.find('#endif\n', t.find('INIT_HLIST_HEAD', start)) + len('#endif\n')
                t = t[:start] + '/* ksu54_sidtab_dup lives in sepolicy.h */\n' + t[end:]
                io.open(SIH, 'w', encoding='utf-8').write(t)
                print("  [OK] selinux_hide.c: duplicate removed (uses sepolicy.h)")


if __name__ == '__main__':
    print("=== ksu54_sidtab_dup 归位 ===")
    main()
