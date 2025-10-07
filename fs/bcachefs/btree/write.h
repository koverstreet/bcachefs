/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_WRITE_H
#define _BCACHEFS_BTREE_WRITE_H

#include "data/write_types.h"

struct btree_write_bio {
	struct work_struct	work;
	__BKEY_PADDED(key, BKEY_BTREE_PTR_VAL_U64s_MAX);
	void			*data;
	unsigned		data_bytes;
	unsigned		sector_offset;
	u64			start_time;
#ifdef CONFIG_BCACHEFS_ASYNC_OBJECT_LISTS
	unsigned		list_idx;
#endif
	struct bch_write_bio	wbio;
};

static inline void set_btree_node_dirty_acct(struct bch_fs *c, struct btree *b)
{
	if (!test_and_set_bit(BTREE_NODE_dirty, &b->flags))
		atomic_long_inc(&c->btree_cache.nr_dirty);
}

static inline void clear_btree_node_dirty_acct(struct bch_fs *c, struct btree *b)
{
	if (test_and_clear_bit(BTREE_NODE_dirty, &b->flags))
		atomic_long_dec(&c->btree_cache.nr_dirty);
}

bool bch2_btree_post_write_cleanup(struct bch_fs *, struct btree *);

enum btree_write_flags {
	__BTREE_WRITE_ONLY_IF_NEED = BTREE_WRITE_TYPE_BITS,
	__BTREE_WRITE_ALREADY_STARTED,
};
#define BTREE_WRITE_ONLY_IF_NEED	BIT(__BTREE_WRITE_ONLY_IF_NEED)
#define BTREE_WRITE_ALREADY_STARTED	BIT(__BTREE_WRITE_ALREADY_STARTED)

void __bch2_btree_node_write(struct bch_fs *, struct btree *, unsigned);
void bch2_btree_node_write(struct bch_fs *, struct btree *,
			   enum six_lock_type, unsigned);
void bch2_btree_node_write_trans(struct btree_trans *, struct btree *,
				 enum six_lock_type, unsigned);
void bch2_btree_init_next(struct btree_trans *, struct btree *);

static inline void btree_node_write_if_need(struct btree_trans *trans, struct btree *b,
					    enum six_lock_type lock_held)
{
	bch2_btree_node_write_trans(trans, b, lock_held, BTREE_WRITE_ONLY_IF_NEED);
}

void bch2_btree_write_stats_to_text(struct printbuf *, struct bch_fs *);

#endif /* _BCACHEFS_BTREE_WRITE_H */
