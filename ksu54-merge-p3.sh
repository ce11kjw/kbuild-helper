#!/bin/bash
# ============================================================================
# ksu54-merge-p3.sh —— 内核 hook / 符号 / Kbuild / 自检
# ============================================================================
set -uo pipefail
KDIR="$(cd "${1:-.}" && pwd)"
cd "$KDIR"
SUDIR="$KDIR/KernelSU/kernel"
[ -d "$SUDIR" ] || SUDIR="$KDIR/drivers/kernelsu"

# ---------- step 10: 内核 hook ----------
echo ""
echo "[10/14] kernel-side ReSukiSU hook unwrap (SUSFS kept)"
cat > /tmp/_unwrap.py <<'UNWEOF'
import os, sys
root = sys.argv[1]

def match_endif(lines, start):
    d = 0
    for i in range(start, len(lines)):
        s = lines[i].strip()
        if s.startswith('#ifdef') or s.startswith('#ifndef') or s.startswith('#if '):
            d += 1
        elif s.startswith('#endif'):
            d -= 1
            if d == 0:
                return i
    return -1

def has_susfs(lines, a, b):
    return any('CONFIG_KSU_SUSFS' in lines[i] for i in range(a, b + 1))

def proc(path, desc):
    p = os.path.join(root, path)
    if not os.path.exists(p):
        print('    [SKIP] %s' % path); return
    lines = open(p, encoding='utf-8', errors='surrogateescape').read().split('\n')
    out, i, dis, unw = [], 0, 0, 0
    while i < len(lines):
        st = lines[i].strip()
        pure = (st == '#ifdef CONFIG_KSU' or st == '#if defined(CONFIG_KSU)')
        if pure:
            e = match_endif(lines, i)
            if e < 0:
                out.append(lines[i]); i += 1; continue
            ind = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
            if has_susfs(lines, i, e):
                out.append(ind + '/* unwrapped CONFIG_KSU (SUSFS kept) */')
                out.extend(lines[i+1:e])
                unw += 1
            else:
                out.append(ind + '#if 0 /* ReSukiSU hook disabled for 5.4 */')
                out.extend(lines[i+1:e])
                out.append(ind + '#endif')
                dis += 1
            i = e + 1
            continue
        out.append(lines[i]); i += 1
    if dis or unw:
        open(p, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(out))
        print('    [OK] %-22s %-10s dis=%d unw=%d' % (path, desc, dis, unw))
    else:
        print('    [--] %-22s %s' % (path, desc))

for f, d in [('fs/exec.c','execveat'), ('fs/open.c','faccessat'),
             ('fs/stat.c','stat'), ('fs/devpts/inode.c','devpts'),
             ('kernel/sys.c','setresuid'), ('fs/read_write.c','sys_read')]:
    proc(f, d)
UNWEOF
python3 /tmp/_unwrap.py "$KDIR"

# ---------- step 11-13: Kbuild ----------
echo ""
echo "[11-13/14] Kbuild: link stubs + preinit"
if [ -f /tmp/patch_kbuild54.py ]; then
  python3 /tmp/patch_kbuild54.py "$KDIR"
else
  echo "    !! patch_kbuild54.py missing"
fi

# ---------- step 12b: sys_read 符号 ----------
echo ""
echo "[12b/14] ksu_handle_sys_read symbol"
KI="$SUDIR/runtime/ksud_integration.c"
if [ -f "$KI" ] && grep -q 'static void ksu_handle_sys_read' "$KI"; then
cat > /tmp/_sysread.py <<'SREOF'
import sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
old = ('static void ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr)\n'
       '{\n'
       '    ksu_handle_init_rc_read(fd);\n'
       '}')
new = ('/* 5.4/SUSFS: non-static so fs/read_write.c (SUSFS patch) links 3-arg form */\n'
       'void ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr)\n'
       '{\n'
       '    (void)buf_ptr;\n'
       '    (void)count_ptr;\n'
       '    ksu_handle_init_rc_read(fd);\n'
       '}')
if old in s:
    open(p, 'w', encoding='utf-8').write(s.replace(old, new, 1))
    print("    ksud_integration.c: 3-arg global")
else:
    print("    ksud_integration.c: anchor miss")
SREOF
python3 /tmp/_sysread.py "$KI"
fi

ES="$SUDIR/extension/susfs.c"
if [ -f "$ES" ] && grep -q '^void ksu_handle_sys_read(unsigned int fd)$' "$ES"; then
cat > /tmp/_sysread2.py <<'SREOF2'
import sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
old = ('void ksu_handle_sys_read(unsigned int fd)\n'
       '{\n'
       '    ksu_handle_init_rc_read(fd);\n'
       '}')
new = ('/* 5.4: 1-arg form clashes with the 3-arg one in ksud_integration.c */\n'
       'static void ksu_handle_sys_read_1arg(unsigned int fd)\n'
       '{\n'
       '    ksu_handle_init_rc_read(fd);\n'
       '}')
if old in s:
    open(p, 'w', encoding='utf-8').write(s.replace(old, new, 1))
    print("    extension/susfs.c: 1-arg renamed")
SREOF2
python3 /tmp/_sysread2.py "$ES"
fi

# ---------- step 14: 自检 ----------
echo ""
echo "[14/14] self-check"
FAIL=0
chk() {
  local f="$1" d
  [ -f "$f" ] || { echo "    MISSING: $f"; FAIL=$((FAIL+1)); return; }
  d=$(awk '{s=$0; gsub(/^[ \t]+/,"",s);
            if (s ~ /^#if/) dd++;
            else if (s ~ /^#endif/) dd--;
           } END {print dd+0}' "$f")
  if [ "$d" != "0" ]; then
    echo "    BALANCE FAIL: ${f#$KDIR/} depth=$d"
    FAIL=$((FAIL+1))
  fi
}
for f in "$KDIR/fs/exec.c" "$KDIR/fs/open.c" "$KDIR/fs/stat.c" \
         "$KDIR/fs/devpts/inode.c" "$KDIR/fs/namespace.c" \
         "$SUDIR/selinux/rules.c" "$SUDIR/selinux/sepolicy.c" \
         "$SUDIR/selinux/sepolicy.h" "$SUDIR/manager/pkg_observer.c" \
         "$SUDIR/infra/seccomp_cache.c" "$SUDIR/policy/app_profile.c" \
         "$SUDIR/extension/ksu54_stub.c" "$SUDIR/infra/su_mount_ns.c" \
         "$SUDIR/feature/kernel_umount.c"; do
  chk "$f"
done

echo ""
echo "--- 关键项确认 ---"
printf "  %-28s " "ksu54_compat.h"
[ -f "$KDIR/include/linux/ksu54_compat.h" ] && echo "OK" || { echo "MISSING"; FAIL=$((FAIL+1)); }
printf "  %-28s " "pkg_observer backport"
grep -q 'ksu54_pkg_observer' "$SUDIR/manager/pkg_observer.c" 2>/dev/null && echo "OK" || echo "checksum-mismatch"
printf "  %-28s " "do_mount exported"
grep -q 'EXPORT_SYMBOL(do_mount)' "$KDIR/fs/namespace.c" 2>/dev/null && echo "OK" || echo "NO"
printf "  %-28s " "ksys_umount exported"
grep -q 'EXPORT_SYMBOL(ksys_umount)' "$KDIR/fs/namespace.c" 2>/dev/null && echo "OK" || echo "NO"
printf "  %-28s " "filename_trans 5.4"
grep -q 'one hashtab record per' "$SUDIR/selinux/sepolicy.c" 2>/dev/null && echo "OK" || echo "NO"
printf "  %-28s " "policy shadow"
grep -q 'KSU54_POLICY_FIELD' "$SUDIR/selinux/rules.c" 2>/dev/null && echo "OK" || echo "NO"
printf "  %-28s " "preinit disabled"
grep -q 'KSU_NO_PREINIT' "$SUDIR/Kbuild" 2>/dev/null && echo "OK" || echo "NO"
printf "  %-28s " "link stubs"
grep -q 'ksu54_stub' "$SUDIR/Kbuild" 2>/dev/null && echo "OK" || echo "NO"

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "=== [ALL OK] 融合补丁完成，0 错误 ==="
else
  echo "=== [WARN] $FAIL 项需检查 ==="
fi
