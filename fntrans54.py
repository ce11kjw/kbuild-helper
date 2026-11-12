#!/usr/bin/env python3
"""
FinaSU -> Linux 5.4: filename_trans compat (build helper)

5.4 layout (linear, one record per stype):
    struct filename_trans       { u32 stype, ttype; u16 tclass; const char *name; }
    struct filename_trans_datum { u32 otype; }
    policydb.filename_trans -> hashtab, key hashed over (stype,ttype,tclass,name)

5.9+ layout (hashed, bitmap of stypes):
    struct filename_trans_key   { u32 ttype; u16 tclass; const char *name; }
    struct filename_trans_datum { u32 otype; struct ebitmap stypes;
                                  struct filename_trans_datum *next; }
    policydb.filename_trans -> hashtab (struct, not pointer)

This patch replaces add_filename_trans() with a 5.4-specific body guarded by
LINUX_VERSION_CODE, leaving the 5.9+ path untouched.
"""

import os
import re
import sys

IMPL_54 = r'''#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
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
	bool ok;

	if (hashtab_search(db->p_types.table, s) == NULL) {
		pr_warn("source type %s does not exist\n", s);
		return false;
	}
	src = symtab_search(&db->p_types, s);
	if (src == NULL)
		return false;
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

	/* look up existing record for this exact (stype,ttype,tclass,name) */
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
		/* record exists: overwrite the target type */
		otype_new->otype = def->value;
		return true;
	}

	/* create a new record */
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

	/* keep the fenametr ttypes bitmap in sync (used by policy writers) */
	ok = ebitmap_set_bit(&db->filename_trans_ttypes, src->value - 1, 1) == 0;
	return ok;
}
#else
'''

TAIL_54 = r'''#endif /* < 5.9 */
'''


def patch(path):
    s = open(path, encoding='utf-8', errors='surrogateescape').read()
    orig = s

    if '5.4: one hashtab record per' in s:
        print("  [OK] sepolicy.c filename_trans already patched")
        return

    # Locate the definition of add_filename_trans (the second occurrence,
    # i.e. the one followed by a '{' rather than ';').
    pat = re.compile(
        r'(static bool add_filename_trans\(struct policydb \*db, const char \*s, const char \*t, const char \*c, const char \*d,\s*\n\s*const char \*o\)\s*\n\{)',
        re.M)
    matches = list(pat.finditer(s))
    if not matches:
        print("  !! add_filename_trans definition not found")
        return

    m = matches[0]
    start = m.start()
    # find matching closing brace at column 0
    idx = s.find('\n}\n', m.end())
    if idx < 0:
        print("  !! closing brace not found")
        return
    end = idx + len('\n}\n')

    original_fn = s[start:end]
    replacement = IMPL_54 + original_fn + TAIL_54
    s = s[:start] + replacement + s[end:]

    open(path, 'w', encoding='utf-8', errors='surrogateescape').write(s)
    print("  [OK] sepolicy.c: add_filename_trans wrapped with 5.4 impl")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'drivers/kernelsu'
    if os.path.islink(root):
        root = os.path.realpath(root)
    p = os.path.join(root, 'selinux', 'sepolicy.c')
    print("target: %s" % p)
    if os.path.exists(p):
        patch(p)
    else:
        print("  !! sepolicy.c not found")


if __name__ == '__main__':
    main()
