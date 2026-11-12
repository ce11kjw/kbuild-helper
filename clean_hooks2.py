import re
import sys
import os

def patch_file_safe(path, desc):
    """安全清理：注释掉 ksu_handle_* 调用，保留所有预处理结构"""
    if not os.path.exists(path):
        print("  [SKIP] %s" % path)
        return
    lines = open(path, encoding='utf-8', errors='surrogateescape').read().split('\n')
    out = []
    changed = 0
    for ln in lines:
        st = ln.strip()
        # 注释掉 ksu_handle_xxx(...) 调用
        if re.match(r'^\s*ksu_handle_\w+\s*\(', ln):
            indent = ln[:len(ln) - len(ln.lstrip())]
            out.append(indent + '/* KSU hook removed: ' + st[:70] + ' */')
            changed += 1
            continue
        # 注释掉 (void)ksu_handle_xxx(...)
        if re.match(r'^\s*\(void\)ksu_handle_\w+\s*\(', ln):
            indent = ln[:len(ln) - len(ln.lstrip())]
            out.append(indent + '/* KSU hook removed: ' + st[:70] + ' */')
            changed += 1
            continue
        # 注释掉 extern 声明
        if re.match(r'^\s*extern\s+.*ksu_handle_\w+', ln):
            indent = ln[:len(ln) - len(ln.lstrip())]
            out.append(indent + '/* KSU extern removed: ' + st[:70] + ' */')
            changed += 1
            continue
        out.append(ln)
    if changed:
        open(path, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(out))
        print("  [OK] %s (%s) - %d lines" % (path, desc, changed))
    else:
        print("  [!] %s unchanged" % path)

files = [
    ('fs/exec.c', 'execveat'),
    ('fs/open.c', 'faccessat'),
    ('fs/stat.c', 'stat'),
    ('fs/devpts/inode.c', 'devpts'),
    ('kernel/sys.c', 'setresuid'),
    ('fs/read_write.c', 'sys_read'),
]

print("=== 安全清理（注释方式）===")
for f, d in files:
    patch_file_safe(f, d)

print("")
print("=== 验证 ===")
for f, d in files:
    if os.path.exists(f):
        txt = open(f, encoding='utf-8', errors='surrogateescape').read()
        # 检查是否有未注释的 ksu_handle 调用
        bad = 0
        for i, ln in enumerate(txt.split('\n'), 1):
            st = ln.strip()
            if re.match(r'^ksu_handle_\w+\s*\(', st) or re.match(r'^\(void\)ksu_handle_\w+', st):
                print("  !! %s:%d 仍有调用: %s" % (f, i, st[:60]))
                bad += 1
        if bad == 0:
            print("  [OK] %s 无未注释调用" % f)
