/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_RECONCILE_WORK_H
#define _BCACHEFS_RECONCILE_WORK_H

#include "data/compress.h"
#include "alloc/disk_groups.h"

extern const char * const bch2_reconcile_opts[];

#define RECONCILE_SCAN_TYPES()		\
	x(fs)				\
	x(metadata)			\
	x(pending)			\
	x(stripes)			\
	x(device)			\
	x(inum)

struct reconcile_scan {
	enum reconcile_scan_type {
#define x(t)	RECONCILE_SCAN_##t,
		RECONCILE_SCAN_TYPES()
#undef x
	}			type;

	union {
		unsigned	dev;
		u64		inum;
	};
};

/* No opt change touches more than one bracketed reconcile scan today: */
#define BCH_OPT_CHANGE_SCANS_MAX	4

/*
 * The reconcile-scan cookies an opt change registered as in-flight - see
 * bch2_set_reconcile_needs_scan_pre(). Constructed empty, populated by
 * bch2_opt_hook_pre_set(); the destructor unregisters them, so an opt change
 * that errors out (or never reaches bch2_opt_hook_post_set()) doesn't leak a
 * registration and wedge the reconcile thread on that cookie.
 */
struct opt_change_scope {
	struct bch_fs		*c;
	unsigned		nr;
	u64			cookies[BCH_OPT_CHANGE_SCANS_MAX];
};

static inline struct opt_change_scope bch2_opt_change_scope_init(struct bch_fs *c)
{
	return (struct opt_change_scope) { .c = c };
}

void bch2_opt_change_scope_exit(struct opt_change_scope *);

DEFINE_CLASS(opt_change_scope, struct opt_change_scope,
	     bch2_opt_change_scope_exit(&_T),
	     bch2_opt_change_scope_init(c),
	     struct bch_fs *c);

int bch2_set_reconcile_needs_scan_trans(struct btree_trans *, struct reconcile_scan);
int bch2_set_reconcile_needs_scan(struct bch_fs *, struct reconcile_scan, bool);
int bch2_set_reconcile_needs_scan_pre(struct bch_fs *, struct reconcile_scan, struct opt_change_scope *);
int bch2_set_reconcile_needs_scan_post(struct bch_fs *, struct reconcile_scan);
int bch2_set_fs_needs_reconcile(struct bch_fs *);

int bch2_reconcile_scan_cookie_is_set(struct btree_trans *, u64);

static inline void bch2_reconcile_wakeup(struct bch_fs *c)
{
	c->reconcile.kick++;
	guard(rcu)();
	struct task_struct *p = rcu_dereference(c->reconcile.thread);
	if (p)
		wake_up_process(p);
}

static inline int bch2_reconcile_pending_wakeup(struct bch_fs *c)
{
	return bch2_set_reconcile_needs_scan(c,
		(struct reconcile_scan) { .type = RECONCILE_SCAN_pending}, true);
}

int bch2_extent_reconcile_pending_mod(struct btree_trans *, struct btree_iter *,
				      unsigned, struct bkey_s_c, bool);

void bch2_reconcile_status_to_text(struct printbuf *, struct bch_fs *);
void bch2_reconcile_scan_pending_to_text(struct printbuf *, struct bch_fs *);

void bch2_reconcile_stop(struct bch_fs *);
int bch2_reconcile_start(struct bch_fs *);

void bch2_fs_reconcile_exit(struct bch_fs *);
int bch2_fs_reconcile_init(struct bch_fs *);

#endif /* _BCACHEFS_RECONCILE_WORK_H */
