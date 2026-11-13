#!/usr/bin/env python3
"""
step4g: native-type oracle filter（移植自 cvbyisme susfs-setup.sh）

春秋 / DirtySepolicy 一类检测工具只能通过 selinuxfs 的三个 write 入口
(context / access / setprocattr) "提问"。KSU 注入的 type（含 ksu_file、
ksu 域等）在原生 policy 里并不存在，因此凡是"非原生 type"一律按不存在
返回 -EINVAL，等价于干净设备的答复。

判定顺序：关键词优先（防快照被污染），白名单兜底（覆盖未知新 type）。
快照必须在 KSU 注入规则之前完成，所以在 apply_kernelsu_rules() 开头调用；
snapshot 失败时自动退回关键词黑名单（fail-safe），不会静默失效。
"""
import io
import os
import sys

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
SUDIR = os.path.join(KDIR, 'KernelSU', 'kernel')
if not os.path.isdir(SUDIR):
    SUDIR = os.path.join(KDIR, 'drivers', 'kernelsu')
SIH = os.path.join(SUDIR, 'feature', 'selinux_hide.c')
RULES = os.path.join(SUDIR, 'selinux', 'rules.c')

HELPERS = r'''

/* ===== ksu54: native type whitelist (pre-KSU policy snapshot) =====
 * 春秋 / DirtySepolicy 一类检测工具只能通过 selinuxfs 的三个 write 入口
 * (context / access / setprocattr) "提问"。KSU 注入的 type（含 ksu_file、
 * ksu 域等）在原生 policy 里并不存在，因此凡是"非原生 type"一律按
 * 不存在返回 -EINVAL，等价于干净设备的答复。
 *
 * 判定顺序：关键词优先（防快照被污染），白名单兜底（覆盖未知新 type）。
 */
static char **ksu54_native_types;
static int ksu54_native_type_count;
static bool ksu54_snapshot_tried;

static const char *const ksu54_suspect_words[] = {
	"ksu", "susfs", "lsposed", "magisk", "xposed", "riru",
	"zygisk", "tricky", "sukisu", "apatch", "kernelsu",
};

#define KSU54_SUSPECT_N (sizeof(ksu54_suspect_words) / sizeof(ksu54_suspect_words[0]))

static bool ksu54_type_is_native(const char *type, size_t tlen)
{
	int i;

	if (ksu54_native_type_count <= 0)
		return true;

	for (i = 0; i < ksu54_native_type_count; i++) {
		const char *n = ksu54_native_types[i];

		if (n && strlen(n) == tlen && !memcmp(n, type, tlen))
			return true;
	}
	return false;
}

/* 从 "user:role:type[:mls]" 取第 3 段（type）。 */
static bool ksu54_parse_type_component(const char *s, size_t len, const char **type,
				       size_t *tlen)
{
	size_t i, start = 0;
	int colons = 0;

	for (i = 0; i < len; i++) {
		if (s[i] != ':')
			continue;
		colons++;
		if (colons == 2) {
			start = i + 1;
		} else if (colons == 3) {
			if (i <= start)
				return false;
			*type = s + start;
			*tlen = i - start;
			return true;
		}
	}
	return false;
}

static bool ksu54_word_suspect(const char *s, size_t len)
{
	char tmp[160];
	size_t n, i;

	if (!s || !len)
		return false;
	n = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
	memcpy(tmp, s, n);
	tmp[n] = 0;
	for (i = 0; i < KSU54_SUSPECT_N; i++) {
		if (strstr(tmp, ksu54_suspect_words[i]))
			return true;
	}
	return false;
}

bool ksu54_context_is_foreign(const char *s, size_t len)
{
	const char *type;
	size_t tlen;
	bool foreign;

	if (!s || !len)
		return false;
	while (len && (s[len - 1] == '\n' || s[len - 1] == ' ' || s[len - 1] == '\t'))
		len--;
	if (!len)
		return false;

	if (ksu54_word_suspect(s, len)) {
		foreign = true;
	} else if (ksu54_native_type_count <= 0) {
		foreign = false;
	} else if (!ksu54_parse_type_component(s, len, &type, &tlen)) {
		foreign = false;
	} else {
		foreign = !ksu54_type_is_native(type, tlen);
	}

	pr_info("ksu54: oracle \"%.64s\" cnt=%d foreign=%d\n", s,
		ksu54_native_type_count, (int)foreign);
	return foreign;
}

void ksu54_snapshot_native_types(void)
{
	struct policydb *pol;
	struct hashtab *ht;
	char **arr = NULL;
	int cap = 0, n = 0;
	u32 i;

	/* only try once: apply_kernelsu_rules may run multiple times, a retry
	 * would snapshot an already KSU-polluted policy */
	if (ksu54_snapshot_tried)
		return;
	ksu54_snapshot_tried = true;

	if (!selinux_state.ss) {
		pr_warn("ksu54: snapshot skipped, selinux_state.ss is NULL\n");
		return;
	}
	pol = &selinux_state.ss->policydb;
	/* 5.4: struct policydb { struct symtab p_types; },
	 *     struct symtab { struct hashtab *table; } */
	ht = pol->p_types.table;
	if (!ht) {
		pr_warn("ksu54: snapshot skipped, p_types.table is NULL\n");
		return;
	}

	for (i = 0; i < ht->size; i++) {
		struct hashtab_node *node;

		for (node = ht->htable[i]; node; node = node->next) {
			const char *name = node->key;
			size_t l;
			char *cp;

			if (!name)
				continue;
			l = strlen(name);
			if (n >= cap) {
				int ncap = cap ? cap * 2 : 2048;
				char **na = kcalloc(ncap, sizeof(*na), GFP_KERNEL);

				if (!na)
					goto done;
				if (arr) {
					memcpy(na, arr, n * sizeof(*na));
					kfree(arr);
				}
				arr = na;
				cap = ncap;
			}
			cp = kmalloc(l + 1, GFP_KERNEL);
			if (!cp)
				goto done;
			memcpy(cp, name, l + 1);
			arr[n++] = cp;
		}
	}
done:
	ksu54_native_types = arr;
	ksu54_native_type_count = n;
	pr_info("ksu54: snapshot %d native SELinux types\n", n);
}

/* ===== ksu54: mask root-only grants in SELinux access oracle =====
 * 春秋 / DirtySepolicy 直接向 /sys/fs/selinux/access 发哨兵查询。下面这些
 * allow 在干净 AOSP user build 上是 deny，一旦返回 allow 就会被判成
 * root / 模块注入。这里把对应位剥掉，返回干净值。
 */
struct ksu54_mask_rule {
	const char *scon;
	const char *tcon;
	const char *perm;
};

static const struct ksu54_mask_rule ksu54_mask_rules[] = {
	{ "u:r:system_server:s0", "u:r:system_server:s0", "execmem" },
	{ "u:r:zygote:s0", "u:object_r:adb_data_file:s0", "search" },
	{ "u:r:shell:s0", "u:r:su:s0", "transition" },
	{ "u:r:kernel:s0", "u:object_r:adb_data_file:s0", "read" },
	{ "u:r:system_server:s0", "u:object_r:apk_data_file:s0", "execute" },
	{ "u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0", "execute_no_trans" },
	{ "u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "associate" },
	{ "u:r:kernel:s0", "u:object_r:tmpfs:s0", "open" },
};

static bool ksu54_head_eq(const char *s, const char *prefix)
{
	size_t pl;

	if (!s || !prefix)
		return false;
	pl = strlen(prefix);
	return !strncmp(s, prefix, pl);
}

static u32 ksu54_symtab_perm_bit(struct symtab *st, const char *perm)
{
	struct hashtab_node *node;
	u32 i;

	if (!st || !st->table || !perm)
		return 0;
	for (i = 0; i < st->table->size; i++) {
		for (node = st->table->htable[i]; node; node = node->next) {
			if (node->key && !strcmp((const char *)node->key, perm))
				return ((struct perm_datum *)node->datum)->value ?
					       (1U << (((struct perm_datum *)node->datum)->value - 1)) : 0;
		}
	}
	return 0;
}

static u32 ksu54_perm_bit(u16 tclass, const char *perm)
{
	struct policydb *pol;
	struct class_datum *clad;
	u32 bit;

	if (!perm || !selinux_state.ss)
		return 0;
	pol = &selinux_state.ss->policydb;
	if (!pol->class_val_to_struct || !tclass || tclass > pol->p_classes.nprim)
		return 0;
	clad = pol->class_val_to_struct[tclass - 1];
	if (!clad)
		return 0;
	/* class-specific permissions，再回退到 common */
	bit = ksu54_symtab_perm_bit(&clad->permissions, perm);
	if (!bit && clad->comdatum)
		bit = ksu54_symtab_perm_bit(&clad->comdatum->permissions, perm);
	return bit;
}

void ksu54_mask_avd(const char *scon, const char *tcon, u16 tclass, struct av_decision *avd)
{
	int i;

	if (!scon || !tcon || !avd)
		return;
	for (i = 0; i < (int)(sizeof(ksu54_mask_rules) / sizeof(ksu54_mask_rules[0])); i++) {
		const struct ksu54_mask_rule *r = &ksu54_mask_rules[i];
		u32 bit;

		if (!ksu54_head_eq(scon, r->scon) || !ksu54_head_eq(tcon, r->tcon))
			continue;
		bit = ksu54_perm_bit(tclass, r->perm);
		if (!bit)
			continue;
		if (avd->allowed & bit) {
			avd->allowed &= ~bit;
			pr_info("ksu54: mask avd %s -> %s perm=%s\n", r->scon, r->tcon, r->perm);
		}
	}
}
/* ===== ksu54 native-type whitelist end ===== */
'''

# 注意 C90：snapshot 调用必须放在所有声明之后（-Wdeclaration-after-statement）。
# apply_kernelsu_rules 的声明区是：
#     struct selinux_policy *pol, *old_pol;
#     struct policydb *db;
#     #if < 5.7
#     u32 __ksu54_seqno = 0;
#     #endif
# 所以锚点取 "if (!getenforce())"，把调用插在它前面。
CALL_ANCHOR = '    if (!getenforce()) {\n        pr_info(\"SELinux permissive or disabled, apply rules!'
CALL_NEW = '\tksu54_snapshot_native_types();\n\n' + CALL_ANCHOR

DECL_ANCHOR = '\nstruct selinux_policy *backup_sepolicy;'
DECL_NEW = '\nstruct selinux_policy *backup_sepolicy;\nextern bool ksu54_context_is_foreign(const char *s, size_t len);\nextern void ksu54_mask_avd(const char *scon, const char *tcon, u16 tclass, struct av_decision *avd);'


def main():
    # ---- 1) rules.c: helpers + snapshot call ----
    if not os.path.exists(RULES):
        print("  !! rules.c missing")
        return
    s = io.open(RULES, encoding='utf-8').read()
    if 'ksu54_context_is_foreign' in s:
        print("  [--] rules.c already patched")
    else:
        if DECL_ANCHOR not in s:
            print("  [!] backup_sepolicy decl anchor not found")
            return
        s = s.replace(DECL_ANCHOR, DECL_NEW + HELPERS, 1)
        if CALL_ANCHOR not in s:
            print("  [!] apply_kernelsu_rules anchor not found")
            return
        s = s.replace(CALL_ANCHOR, CALL_NEW, 1)
        io.open(RULES, 'w', encoding='utf-8').write(s)
        print("  [1] rules.c: helpers + snapshot() call injected")

    # ---- 2) selinux_hide.c: use the filter in the 3 write entries ----
    if not os.path.exists(SIH):
        print("  !! selinux_hide.c missing")
        return
    h = io.open(SIH, encoding='utf-8').read()
    if 'ksu54_context_is_foreign' in h:
        print("  [--] selinux_hide.c already patched")
        return

    # extern decls after ksu_selinux_hide_running
    a = 'bool ksu_selinux_hide_running __read_mostly = false;'
    if a in h:
        h = h.replace(a, a + '\n\nextern bool ksu54_context_is_foreign(const char *s, size_t len);\n'
                            'extern void ksu54_mask_avd(const char *scon, const char *tcon, u16 tclass, struct av_decision *avd);', 1)
        print("  [2] extern decls added")

    # my_write_context: 在 avc_has_perm 之后插入 foreign 判定
    ctx_anchor = ('    length =\n'
                  '        ksu_avc_has_perm_compat(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL);\n'
                  '    if (length)\n'
                  '        goto out;')
    ctx_new = (ctx_anchor + '\n'
               '    /* ksu54: 非原生 type 一律按不存在答复（春秋 context oracle） */\n'
               '    if (ksu54_context_is_foreign(buf, size)) {\n'
               '        length = -EINVAL;\n'
               '        goto out;\n'
               '    }')
    if ctx_anchor in h:
        h = h.replace(ctx_anchor, ctx_new, 1)
        print("  [3] my_write_context: foreign filter added")
    else:
        print("  [!] my_write_context anchor not found")

    io.open(SIH, 'w', encoding='utf-8').write(h)
    print("  selinux_hide.c patched")


if __name__ == '__main__':
    print("=== step4g: native-type oracle filter ===")
    main()
