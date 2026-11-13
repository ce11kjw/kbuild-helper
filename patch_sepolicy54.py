#!/usr/bin/env python3
"""
sepolicy.c 5.4 backport（v2）
 - dup/destroy 带 sidtab 克隆（与 sepolicy.h 的 ksu54_sidtab_dup 配套）
 - filename_trans 真 5.4 hashtab 实现
"""
import io
import os
import re
import sys

KDIR = sys.argv[1] if len(sys.argv) > 1 else '.'
SUDIR = os.path.join(KDIR, 'KernelSU', 'kernel')
if not os.path.isdir(SUDIR):
    SUDIR = os.path.join(KDIR, 'drivers', 'kernelsu')
SEC = os.path.join(SUDIR, 'selinux', 'sepolicy.c')

DUP_54 = '''/* KSU54_FNTRANS: 5.4 backport of dup/destroy. */
void ksu_destroy_sepolicy(struct selinux_policy *pol)
{
	if (!pol)
		return;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
	/* A duplicated policy owns its sidtab copy; a live view owns nothing. */
	if (pol->sidtab) {
		sidtab_destroy(pol->sidtab);
		kfree(pol->sidtab);
		pol->sidtab = NULL;
	}
#endif
	policydb_destroy(&pol->policydb);
	kfree(pol);
}

struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol)
{
	struct selinux_policy *new_pol;
	struct policy_file fp;
	void *data;
	size_t len;
	int ret;

	if (!old_pol)
		return ERR_PTR(-EINVAL);

	len = old_pol->policydb.len;
	if (len < 4096)
		len = 4096;
	data = vmalloc(len);
	if (!data)
		return ERR_PTR(-ENOMEM);

	fp.data = data;
	fp.len = len;
	ret = policydb_write(&old_pol->policydb, &fp);
	if (ret) {
		pr_err("sepolicy54: policydb_write: %d\\n", ret);
		goto out_free_data;
	}
	len -= fp.len;

	new_pol = kzalloc(sizeof(*new_pol), GFP_KERNEL);
	if (!new_pol) {
		ret = -ENOMEM;
		goto out_free_data;
	}

	fp.data = data;
	fp.len = len;
	ret = policydb_read(&new_pol->policydb, &fp);
	if (ret) {
		pr_err("sepolicy54: policydb_read: %d\\n", ret);
		kfree(new_pol);
		goto out_free_data;
	}
	new_pol->policydb.len = len;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
	/* 5.4 keeps sidtab outside policydb, so a backup needs its own copy. */
	new_pol->sidtab = ksu54_sidtab_dup(old_pol->sidtab);
	if (!new_pol->sidtab) {
		policydb_destroy(&new_pol->policydb);
		kfree(new_pol);
		ret = -ENOMEM;
		goto out_free_data;
	}
#endif
	new_pol->latest_granting = old_pol->latest_granting;

	kvfree(data);
	pr_info("sepolicy54: dup policydb ok, len %zu\\n", len);
	return new_pol;

out_free_data:
	kvfree(data);
	return ERR_PTR(ret);
}
'''

FNTRANS_54 = r'''#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
/* 5.4: one hashtab record per (stype, ttype, tclass, name) */
static bool add_filename_trans(struct policydb *db, const char *s, const char *t,
                               const char *c, const char *d, const char *o)
{
	struct type_datum *src, *tgt, *def;
	struct class_datum *cls;
	struct filename_trans *ft, *new_ft;
	struct filename_trans_datum *otype_new;
	char *new_name;
	int rc;

	src = symtab_search(&db->p_types, s);
	if (src == NULL) {
		pr_warn("source type %s does not exist\n", s);
		return false;
	}
	tgt = symtab_search(&db->p_types, t);
	if (tgt == NULL) {
		pr_warn("target type %s does not exist\n", t);
		return false;
	}
	cls = symtab_search(&db->p_classes, c);
	if (cls == NULL) {
		pr_warn("class %s does not exist\n", c);
		return false;
	}
	def = symtab_search(&db->p_types, d);
	if (def == NULL) {
		pr_warn("default type %s does not exist\n", d);
		return false;
	}

	ft = kzalloc(sizeof(*ft), GFP_KERNEL);
	if (!ft)
		return false;
	ft->stype = src->value;
	ft->ttype = tgt->value;
	ft->tclass = cls->value;
	ft->name = o;

	otype_new = hashtab_search(db->filename_trans, ft);
	kfree(ft);

	if (otype_new) {
		otype_new->otype = def->value;
		return true;
	}

	new_ft = kzalloc(sizeof(*new_ft), GFP_KERNEL);
	if (!new_ft)
		return false;
	new_name = kstrdup(o, GFP_KERNEL);
	if (!new_name) {
		kfree(new_ft);
		return false;
	}
	new_ft->stype = src->value;
	new_ft->ttype = tgt->value;
	new_ft->tclass = cls->value;
	new_ft->name = new_name;

	otype_new = kzalloc(sizeof(*otype_new), GFP_KERNEL);
	if (!otype_new) {
		kfree(new_name);
		kfree(new_ft);
		return false;
	}
	otype_new->otype = def->value;

	rc = hashtab_insert(db->filename_trans, new_ft, otype_new);
	if (rc) {
		pr_err("add_filename_trans: hashtab_insert failed: %d\n", rc);
		kfree(otype_new);
		kfree(new_name);
		kfree(new_ft);
		return false;
	}

	return ebitmap_set_bit(&db->filename_trans_ttypes, src->value - 1, 1) == 0;
}
#else
'''


def main():
    if not os.path.exists(SEC):
        print("  [SKIP] sepolicy.c")
        return
    s = io.open(SEC, encoding='utf-8').read()
    if 'KSU54_FNTRANS' in s:
        print("  [--] sepolicy.c already patched")
        return

    # 移除 5.7+ 原生实现（不跨行贪婪匹配过远）
    s2 = re.sub(r'\nvoid ksu_destroy_sepolicy\(struct selinux_policy \*pol\)\n\{.*?\n\}\n',
                '\n', s, count=1, flags=re.S)
    s3 = re.sub(r'\nstruct selinux_policy \*ksu_dup_sepolicy\(struct selinux_policy \*old_pol\)\n\{.*?\n\}\n',
                '\n', s2, count=1, flags=re.S)
    s = s3

    anchor = '// ======== sepolicy ========'
    if anchor in s:
        s = s.replace(anchor, anchor + '\n' + DUP_54, 1)
        print("  [OK] sepolicy.c: dup/destroy with sidtab clone")
    else:
        print("  !! anchor '// ======== sepolicy ========' not found")

    a = s.find('static bool add_filename_trans(struct policydb *db',
               s.find('static bool add_genfscon('))
    if a != -1:
        b = s.find('static bool add_genfscon(', a)
        if b != -1:
            s = s[:a] + FNTRANS_54 + s[a:b] + '#endif /* < 5.9 */\n\n' + s[b:]
            print("  [OK] sepolicy.c: add_filename_trans 5.4 impl")
        else:
            print("  !! add_genfscon end anchor not found")
    else:
        print("  !! add_filename_trans not found")

    io.open(SEC, 'w', encoding='utf-8').write(s)
    print("  [OK] sepolicy.c written")


if __name__ == '__main__':
    print("=== sepolicy.c 5.4 (v2) ===")
    main()
