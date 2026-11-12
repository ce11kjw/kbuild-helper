/* ===== SELinux access compat for Linux 5.4 (build helper) =====
 *
 * 5.4 keeps the policy inside selinux_state.ss:
 *   selinux_state.policy        -> selinux_state.ss
 *   selinux_state.status_lock   -> selinux_state.ss->status_lock
 *   selinux_state.status_page   -> selinux_state.ss->status_page
 *
 * symtab_search()/symtab_insert() appeared in 5.9; on 5.4 they are
 * hashtab_search()/hashtab_insert() over symtab->table.
 */
#ifndef KSU54_SELINUX_ACCESS_COMPAT
#define KSU54_SELINUX_ACCESS_COMPAT

#include <linux/version.h>
#include "ss/symtab.h"

#ifndef symtab_search
#define symtab_search(s, name) hashtab_search((s)->table, name)
#endif
#ifndef symtab_insert
#define symtab_insert(s, name, datum) hashtab_insert((s)->table, name, datum)
#endif

/* 5.4: policy / status lock+page all live in selinux_state.ss */
/* cast so it can be assigned to struct selinux_policy * variables:
 * on 5.4 the two share sidtab + policydb + latest_granting at the top,
 * which is all FinaSU reads through this pointer. */
#define ksu54_selinux_policy()      ((struct selinux_policy *)(void *)selinux_state.ss)
#define ksu54_status_lock()         (&selinux_state.ss->status_lock)
#define ksu54_status_page()         (selinux_state.ss->status_page)

#endif /* KSU54_SELINUX_ACCESS_COMPAT */
