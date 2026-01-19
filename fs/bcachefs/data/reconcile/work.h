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

int bch2_set_reconcile_needs_scan_trans(struct btree_trans *, struct reconcile_scan);
int bch2_set_reconcile_needs_scan(struct bch_fs *, struct reconcile_scan, bool);
int bch2_set_fs_needs_reconcile(struct bch_fs *);

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

void bch2_reconcile_status_to_text(struct printbuf *, struct bch_fs *);
void bch2_reconcile_scan_pending_to_text(struct printbuf *, struct bch_fs *);

void bch2_reconcile_stop(struct bch_fs *);
int bch2_reconcile_start(struct bch_fs *);

void bch2_fs_reconcile_exit(struct bch_fs *);
int bch2_fs_reconcile_init(struct bch_fs *);

#endif /* _BCACHEFS_RECONCILE_WORK_H */
