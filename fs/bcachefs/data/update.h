/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BCACHEFS_DATA_UPDATE_H
#define _BCACHEFS_DATA_UPDATE_H

#include "btree/bkey_buf.h"
#include "btree/update.h"
#include "data/read.h"
#include "data/write_types.h"

struct moving_context;

#define BCH_DATA_UPDATE_TYPES()	\
	x(other)		\
	x(copygc)		\
	x(rebalance)		\
	x(promote)		\
	x(self_heal)		\
	x(scrub)

enum bch_data_update_types {
#define x(n)	BCH_DATA_UPDATE_##n,
	BCH_DATA_UPDATE_TYPES()
#undef x
};

struct data_update_opts {
	enum bch_data_update_types	type;
	u8				ptrs_rewrite;
	u8				ptrs_io_error;
	u8				ptrs_kill;
	u8				ptrs_kill_ec;
	u8				extra_replicas;
	u16				target;
	int				read_dev;

	enum bch_write_flags		write_flags;
	enum bch_trans_commit_flags	commit_flags;
};

struct data_update {
	/* extent being updated: */
	enum btree_id		btree_id;
	struct bkey_buf		k;
	struct data_update_opts	opts;

	bool			read_done;
	u8			ptrs_held;

	/* associated with @ctxt */
	struct list_head	read_list;
	struct list_head	io_list;
	struct move_bucket	*b;
	struct moving_context	*ctxt;
	struct bch_move_stats	*stats;

	struct bch_read_bio	rbio;
	struct bch_write_op	op;
	struct bio_vec		*bvecs;
};

struct promote_op {
	struct rcu_head		rcu;
	u64			start_time;
#ifdef CONFIG_BCACHEFS_ASYNC_OBJECT_LISTS
	unsigned		list_idx;
#endif

	struct rhash_head	hash;
	struct bpos		pos;

	struct work_struct	work;
	struct data_update	write;
	struct bio_vec		bi_inline_vecs[]; /* must be last */
};

void bch2_data_update_opts_to_text(struct printbuf *, struct bch_fs *,
				   struct bch_inode_opts *, struct data_update_opts *);
void bch2_data_update_to_text(struct printbuf *, struct data_update *);
void bch2_data_update_inflight_to_text(struct printbuf *, struct data_update *);

int bch2_data_update_index_update(struct bch_write_op *);

void bch2_data_update_read_done(struct data_update *);

void bch2_data_update_exit(struct data_update *, int);
int bch2_data_update_init(struct btree_trans *, struct btree_iter *,
			  struct moving_context *,
			  struct data_update *,
			  struct write_point_specifier,
			  struct bch_inode_opts *, struct data_update_opts,
			  enum btree_id, struct bkey_s_c);

#endif /* _BCACHEFS_DATA_UPDATE_H */
