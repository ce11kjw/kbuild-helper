import os
import re
import sys

"""
SUSFS + FinaSU 符号冲突修正

问题：
  extension/susfs.c:198     void ksu_handle_sys_read(unsigned int fd)        ← 1 参数
  runtime/ksud_integration.c:489  static void ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr)  ← 3 参数 static

内核 fs/read_write.c（SUSFS 补丁）调用的是 3 参数版本：
    ksu_handle_sys_read(fd, &buf, &count);

所以：
  1) ksud_integration.c 里的 static 版本要改成非 static（供内核链接）
  2) extension/susfs.c 里的 1 参数版本要改名或删除（避免重复定义）
"""

def patch_ksud(path):
    s = open(path, encoding='utf-8', errors='surrogateescape').read()
    old = ('static void ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr)\n'
           '{\n'
           '    ksu_handle_init_rc_read(fd);\n'
           '}')
    new = ('/* 5.4/SUSFS: non-static so fs/read_write.c (SUSFS patch) can link it */\n'
           'void ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr)\n'
           '{\n'
           '    (void)buf_ptr;\n'
           '    (void)count_ptr;\n'
           '    ksu_handle_init_rc_read(fd);\n'
           '}')
    if 'non-static so fs/read_write.c' in s:
        print("  [--] ksud_integration.c 已处理")
        return
    if old in s:
        s = s.replace(old, new, 1)
        open(path, 'w', encoding='utf-8', errors='surrogateescape').write(s)
        print("  [OK] ksud_integration.c: ksu_handle_sys_read 改为全局")
    else:
        print("  !! ksud_integration.c 未匹配")

def patch_susfs_ext(path):
    s = open(path, encoding='utf-8', errors='surrogateescape').read()
    old = ('void ksu_handle_sys_read(unsigned int fd)\n'
           '{\n'
           '    ksu_handle_init_rc_read(fd);\n'
           '}')
    new = ('/* 5.4/SUSFS: 1-arg version conflicts with the 3-arg one in\n'
           ' * ksud_integration.c, which the kernel-side SUSFS hook links against.\n'
           ' * Renamed so both can coexist. */\n'
           'static void ksu_handle_sys_read_1arg(unsigned int fd)\n'
           '{\n'
           '    ksu_handle_init_rc_read(fd);\n'
           '}')
    if 'ksu_handle_sys_read_1arg' in s:
        print("  [--] extension/susfs.c 已处理")
        return
    if old in s:
        s = s.replace(old, new, 1)
        open(path, 'w', encoding='utf-8', errors='surrogateescape').write(s)
        print("  [OK] extension/susfs.c: 1-arg 版本改名")
    else:
        print("  !! extension/susfs.c 未匹配")

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'drivers/kernelsu'
    if os.path.islink(root):
        root = os.path.realpath(root)
    print("FinaSU root: %s" % root)
    k = os.path.join(root, 'runtime', 'ksud_integration.c')
    e = os.path.join(root, 'extension', 'susfs.c')
    if os.path.exists(k):
        patch_ksud(k)
    if os.path.exists(e):
        patch_susfs_ext(e)

if __name__ == '__main__':
    main()
