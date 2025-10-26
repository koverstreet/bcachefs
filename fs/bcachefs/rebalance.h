/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_REBALANCE_H
#define _BCACHEFS_REBALANCE_H

#include "compress.h"
#include "disk_groups.h"
#include "opts.h"
#include "rebalance_types.h"

static inline struct bch_extent_rebalance io_opts_to_rebalance_opts(struct bch_fs *c,
								    struct bch_inode_opts *opts)
{
	struct bch_extent_rebalance r = {
		.type = BIT(BCH_EXTENT_ENTRY_rebalance),
#define x(_name)							\
		._name = opts->_name,					\
		._name##_from_inode = opts->_name##_from_inode,
		BCH_REBALANCE_OPTS()
#undef x
	};

	if (r.background_target &&
	    !bch2_target_accepts_data(c, BCH_DATA_user, r.background_target))
		r.background_target = 0;

	return r;
};

void bch2_extent_rebalance_to_text(struct printbuf *, struct bch_fs *,
				   const struct bch_extent_rebalance *);

u64 bch2_bkey_sectors_need_rebalance(struct bch_fs *, struct bkey_s_c);

enum set_needs_rebalance_ctx {
	SET_NEEDS_REBALANCE_opt_change,
	SET_NEEDS_REBALANCE_opt_change_indirect,
	SET_NEEDS_REBALANCE_foreground,
	SET_NEEDS_REBALANCE_other,
};

int bch2_bkey_set_needs_rebalance(struct bch_fs *, struct bch_inode_opts *,
				  struct bkey_i *, enum set_needs_rebalance_ctx, u32);

int bch2_get_update_rebalance_opts(struct btree_trans *, struct bch_inode_opts *,
				   struct btree_iter *, struct bkey_s_c,
				   enum set_needs_rebalance_ctx);

int bch2_set_rebalance_needs_scan_trans(struct btree_trans *, u64);
int bch2_set_rebalance_needs_scan(struct bch_fs *, u64 inum);
int bch2_set_fs_needs_rebalance(struct bch_fs *);

static inline void bch2_rebalance_wakeup(struct bch_fs *c)
{
	c->rebalance.kick++;
	guard(rcu)();
	struct task_struct *p = rcu_dereference(c->rebalance.thread);
	if (p)
		wake_up_process(p);
}

void bch2_rebalance_status_to_text(struct printbuf *, struct bch_fs *);

void bch2_rebalance_stop(struct bch_fs *);
int bch2_rebalance_start(struct bch_fs *);

void bch2_fs_rebalance_exit(struct bch_fs *);
int bch2_fs_rebalance_init(struct bch_fs *);

int bch2_check_rebalance_work(struct bch_fs *);

#endif /* _BCACHEFS_REBALANCE_H */
