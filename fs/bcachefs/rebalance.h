/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_REBALANCE_H
#define _BCACHEFS_REBALANCE_H

#include "compress.h"
#include "disk_groups.h"
#include "opts.h"
#include "rebalance_types.h"

int bch2_extent_rebalance_validate(struct bch_fs *, struct bkey_s_c,
				   struct bkey_validate_context,
				   const struct bch_extent_rebalance *);

static inline struct bch_extent_rebalance io_opts_to_rebalance_opts(struct bch_fs *c,
								    struct bch_inode_opts *opts)
{
	return (struct bch_extent_rebalance) {
		.type = BIT(BCH_EXTENT_ENTRY_rebalance),
#define x(_name)							\
		._name = opts->_name,					\
		._name##_from_inode = opts->_name##_from_inode,
		BCH_REBALANCE_OPTS()
#undef x
	};
};

void bch2_extent_rebalance_to_text(struct printbuf *, struct bch_fs *,
				   const struct bch_extent_rebalance *);

const struct bch_extent_rebalance *bch2_bkey_rebalance_opts(struct bkey_s_c);

static inline int bch2_bkey_needs_rb(struct bkey_s_c k)
{
	const struct bch_extent_rebalance *r = bch2_bkey_rebalance_opts(k);
	return r ? r->need_rb : 0;
}

int __bch2_trigger_extent_rebalance(struct btree_trans *,
				    struct bkey_s_c, struct bkey_s_c,
				    unsigned, unsigned,
				    enum btree_iter_update_trigger_flags);

static inline int bch2_trigger_extent_rebalance(struct btree_trans *trans,
				  struct bkey_s_c old, struct bkey_s_c new,
				  enum btree_iter_update_trigger_flags flags)
{
	unsigned old_r = bch2_bkey_needs_rb(old);
	unsigned new_r = bch2_bkey_needs_rb(new);

	return old_r != new_r ||
		(old.k->size != new.k->size && (old_r|new_r))
		? __bch2_trigger_extent_rebalance(trans, old, new, old_r, new_r, flags)
		: 0;
}

enum set_needs_rebalance_ctx {
	SET_NEEDS_REBALANCE_opt_change,
	SET_NEEDS_REBALANCE_opt_change_indirect,
	SET_NEEDS_REBALANCE_foreground,
	SET_NEEDS_REBALANCE_other,
};

/* Inodes in different snapshots may have different IO options: */
struct snapshot_io_opts_entry {
	u32			snapshot;
	struct bch_inode_opts	io_opts;
};

struct per_snapshot_io_opts {
	u64			cur_inum;
	bool			fs_scan_cookie;
	bool			inum_scan_cookie;
	struct bch_devs_mask	dev_cookie;

	struct bch_inode_opts	fs_io_opts;
	DARRAY(struct snapshot_io_opts_entry) d;
};

static inline void per_snapshot_io_opts_init(struct per_snapshot_io_opts *io_opts, struct bch_fs *c)
{
	memset(io_opts, 0, sizeof(*io_opts));
	bch2_inode_opts_get(c, &io_opts->fs_io_opts);
}

static inline void per_snapshot_io_opts_exit(struct per_snapshot_io_opts *io_opts)
{
	darray_exit(&io_opts->d);
}

int bch2_bkey_set_needs_rebalance(struct btree_trans *,
				  struct per_snapshot_io_opts *, struct bch_inode_opts *,
				  struct bkey_i *, enum set_needs_rebalance_ctx, u32);

struct bch_inode_opts *bch2_extent_get_apply_io_opts(struct btree_trans *,
			  struct per_snapshot_io_opts *, struct bpos,
			  struct btree_iter *, struct bkey_s_c,
			  enum set_needs_rebalance_ctx);

int bch2_extent_get_io_opts_one(struct btree_trans *, struct bch_inode_opts *,
				struct btree_iter *, struct bkey_s_c,
				enum set_needs_rebalance_ctx);
int bch2_extent_get_apply_io_opts_one(struct btree_trans *, struct bch_inode_opts *,
				      struct btree_iter *, struct bkey_s_c,
				      enum set_needs_rebalance_ctx);

int bch2_set_rebalance_needs_scan_trans(struct btree_trans *, u64);
int bch2_set_rebalance_needs_scan(struct bch_fs *, u64 inum);
int bch2_set_rebalance_needs_scan_device(struct bch_fs *, unsigned);
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
