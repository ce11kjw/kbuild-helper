import re
import sys

def patch_file(path, patterns, desc):
    try:
        s = open(path, encoding='utf-8', errors='surrogateescape').read()
    except FileNotFoundError:
        print("  [SKIP] %s (not found)" % path)
        return False
    orig = s
    for pat in patterns:
        s = re.sub(pat, '', s, flags=re.S)
    if s != orig:
        open(path, 'w', encoding='utf-8', errors='surrogateescape').write(s)
        print("  [OK] %s (%s)" % (path, desc))
        return True
    print("  [!] %s unchanged" % path)
    return False

# 1. fs/exec.c
patch_file('fs/exec.c', [
    r'#ifdef CONFIG_KSU\nextern int ksu_handle_execveat\([^;]*;\n(?:#ifdef CONFIG_KSU_SUSFS\n.*?#endif\n)?#endif\n',
    r'#ifdef CONFIG_KSU_SUSFS\n\tif \(likely\(susfs_is_current_proc_umounted\(\)\)\)\n\t\tgoto orig_flow;\n.*?#elif defined\(CONFIG_KSU\)\n\t\tksu_handle_execveat\([^;]*;\n#endif\n',
    r'[ \t]*ksu_handle_execveat(?:_sucompat)?\([^;]*;\n',
], 'execveat')

# 2. fs/open.c
patch_file('fs/open.c', [
    r'#ifdef CONFIG_KSU\nextern int ksu_handle_faccessat\([^;]*;\n#endif\n',
    r'#ifdef CONFIG_KSU\n[ \t]*ksu_handle_faccessat\([^;]*;\n#endif\n',
    r'[ \t]*ksu_handle_faccessat\([^;]*;\n',
], 'faccessat')

# 3. fs/stat.c
patch_file('fs/stat.c', [
    r'#ifdef CONFIG_KSU\nextern int ksu_handle_stat\([^;]*;\n(?:#ifdef CONFIG_KSU_MANUAL_HOOK\n.*?#endif\n)?#endif\n',
    r'#ifdef CONFIG_KSU_MANUAL_HOOK\nextern void ksu_handle_(?:newfstat_ret|fstat64_ret)\([^;]*;\n#endif\n',
    r'#ifdef CONFIG_KSU\n[ \t]*ksu_handle_stat\([^;]*;\n#endif\n',
    r'#ifdef CONFIG_KSU_MANUAL_HOOK[^\n]*\n[ \t]*ksu_handle_(?:newfstat_ret|fstat64_ret)\([^;]*;\n#endif\n',
    r'[ \t]*ksu_handle_(?:stat|newfstat_ret|fstat64_ret)\([^;]*;\n',
], 'stat')

# 4. fs/devpts/inode.c
patch_file('fs/devpts/inode.c', [
    r'#ifdef CONFIG_KSU\nextern int ksu_handle_devpts\([^;]*;\n#endif\n',
    r'#ifdef CONFIG_KSU\n[ \t]*ksu_handle_devpts\([^;]*;\n#endif\n',
    r'[ \t]*ksu_handle_devpts\([^;]*;\n',
], 'devpts')

# 5. kernel/sys.c
patch_file('kernel/sys.c', [
    r'#ifdef CONFIG_KSU\nextern int ksu_handle_setresuid\([^;]*;\n#endif\n',
    r'#ifdef CONFIG_KSU\n[ \t]*\(void\)ksu_handle_setresuid\([^;]*;\n#endif\n',
    r'[ \t]*\(void\)ksu_handle_setresuid\([^;]*;\n',
], 'setresuid')

# 6. fs/read_write.c
patch_file('fs/read_write.c', [
    r'#ifdef CONFIG_KSU_SUSFS\n\textern int ksu_handle_sys_read\([^;]*;\n.*?#endif\n',
    r'[ \t]*ksu_handle_sys_read\([^;]*;\n',
], 'sys_read')

print("=== done ===")
