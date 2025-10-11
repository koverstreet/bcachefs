/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_REBALANCE_H
#define _BCACHEFS_REBALANCE_H

#include "data/compress.h"
#include "alloc/disk_groups.h"
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

int __bch2_trigger_extent_rebalance(struct btree_trans *,
				    enum btree_id, unsigned,
				    struct bkey_s_c, struct bkey_s,
				    const struct bch_extent_rebalance *,
				    const struct bch_extent_rebalance *,
				    enum btree_iter_update_trigger_flags);

static inline unsigned rb_needs_trigger(const struct bch_extent_rebalance *r)
{
	return r ? r->need_rb|r->ptrs_moving : 0;
}

static inline int bch2_trigger_extent_rebalance(struct btree_trans *trans,
				enum btree_id btree, unsigned level,
				struct bkey_s_c old, struct bkey_s new,
				enum btree_iter_update_trigger_flags flags)
{
	const struct bch_extent_rebalance *old_r = bch2_bkey_rebalance_opts(old);
	const struct bch_extent_rebalance *new_r = bch2_bkey_rebalance_opts(new.s_c);

	return rb_needs_trigger(old_r) || rb_needs_trigger(new_r)
		? __bch2_trigger_extent_rebalance(trans, btree, level, old, new, old_r, new_r, flags)
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

static inline struct per_snapshot_io_opts per_snapshot_io_opts_init(struct bch_fs *c)
{
	return (struct per_snapshot_io_opts) {
		/* io_opts->fs_io_opts will be initialized when we know the key type */
		.fs_io_opts.change_cookie = atomic_read(&c->opt_change_cookie) - 1,
	};
}

static inline void per_snapshot_io_opts_exit(struct per_snapshot_io_opts *io_opts)
{
	darray_exit(&io_opts->d);
}

DEFINE_CLASS(per_snapshot_io_opts, struct per_snapshot_io_opts,
	     per_snapshot_io_opts_exit(&_T),
	     per_snapshot_io_opts_init(c),
	     struct bch_fs *c);

int bch2_bkey_get_io_opts(struct btree_trans *,
			  struct per_snapshot_io_opts *, struct bkey_s_c,
			  struct bch_inode_opts *opts);

int bch2_update_rebalance_opts(struct btree_trans *,
			       struct per_snapshot_io_opts *,
			       struct bch_inode_opts *,
			       struct btree_iter *,
			       unsigned level,
			       struct bkey_s_c,
			       enum set_needs_rebalance_ctx);

int bch2_bkey_set_needs_rebalance(struct btree_trans *,
				  struct per_snapshot_io_opts *, struct bch_inode_opts *,
				  struct bkey_i *, enum set_needs_rebalance_ctx, u32);

struct rebalance_scan {
	enum rebalance_scan_type {
		REBALANCE_SCAN_fs,
		REBALANCE_SCAN_metadata,
		REBALANCE_SCAN_pending,
		REBALANCE_SCAN_device,
		REBALANCE_SCAN_inum,
	}			type;

	union {
		unsigned	dev;
		u64		inum;
	};
};

int bch2_set_rebalance_needs_scan_trans(struct btree_trans *, struct rebalance_scan);
int bch2_set_rebalance_needs_scan(struct bch_fs *, struct rebalance_scan, bool);
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
