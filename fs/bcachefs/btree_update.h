/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_UPDATE_H
#define _BCACHEFS_BTREE_UPDATE_H

#include "btree_iter.h"
#include "journal.h"

struct bch_fs;
struct btree;

void bch2_btree_node_lock_for_insert(struct btree_trans *, struct btree_path *,
				     struct btree *);
bool bch2_btree_bset_insert_key(struct btree_trans *, struct btree_path *,
				struct btree *, struct btree_node_iter *,
				struct bkey_i *);
void bch2_btree_add_journal_pin(struct bch_fs *, struct btree *, u64);

enum btree_insert_flags {
	/* First two bits for journal watermark: */
	__BTREE_INSERT_NOFAIL = 2,
	__BTREE_INSERT_NOCHECK_RW,
	__BTREE_INSERT_LAZY_RW,
	__BTREE_INSERT_USE_RESERVE,
	__BTREE_INSERT_JOURNAL_REPLAY,
	__BTREE_INSERT_JOURNAL_RECLAIM,
	__BTREE_INSERT_NOWAIT,
	__BTREE_INSERT_GC_LOCK_HELD,
	__BCH_HASH_SET_MUST_CREATE,
	__BCH_HASH_SET_MUST_REPLACE,
};

/* Don't check for -ENOSPC: */
#define BTREE_INSERT_NOFAIL		(1 << __BTREE_INSERT_NOFAIL)

#define BTREE_INSERT_NOCHECK_RW		(1 << __BTREE_INSERT_NOCHECK_RW)
#define BTREE_INSERT_LAZY_RW		(1 << __BTREE_INSERT_LAZY_RW)

/* for copygc, or when merging btree nodes */
#define BTREE_INSERT_USE_RESERVE	(1 << __BTREE_INSERT_USE_RESERVE)

/* Insert is for journal replay - don't get journal reservations: */
#define BTREE_INSERT_JOURNAL_REPLAY	(1 << __BTREE_INSERT_JOURNAL_REPLAY)

/* Insert is being called from journal reclaim path: */
#define BTREE_INSERT_JOURNAL_RECLAIM (1 << __BTREE_INSERT_JOURNAL_RECLAIM)

/* Don't block on allocation failure (for new btree nodes: */
#define BTREE_INSERT_NOWAIT		(1 << __BTREE_INSERT_NOWAIT)
#define BTREE_INSERT_GC_LOCK_HELD	(1 << __BTREE_INSERT_GC_LOCK_HELD)

#define BCH_HASH_SET_MUST_CREATE	(1 << __BCH_HASH_SET_MUST_CREATE)
#define BCH_HASH_SET_MUST_REPLACE	(1 << __BCH_HASH_SET_MUST_REPLACE)

int bch2_btree_delete_extent_at(struct btree_trans *, struct btree_iter *,
				unsigned, unsigned);
int bch2_btree_delete_at(struct btree_trans *, struct btree_iter *, unsigned);

int __bch2_btree_insert(struct btree_trans *, enum btree_id, struct bkey_i *);
int bch2_btree_insert(struct bch_fs *, enum btree_id, struct bkey_i *,
		     struct disk_reservation *, u64 *, int flags);

int bch2_btree_delete_range_trans(struct btree_trans *, enum btree_id,
				  struct bpos, struct bpos, unsigned, u64 *);
int bch2_btree_delete_range(struct bch_fs *, enum btree_id,
			    struct bpos, struct bpos, unsigned, u64 *);

int bch2_btree_node_rewrite(struct btree_trans *, struct btree_iter *,
			    struct btree *, unsigned);
void bch2_btree_node_rewrite_async(struct bch_fs *, struct btree *);
int bch2_btree_node_update_key(struct btree_trans *, struct btree_iter *,
			       struct btree *, struct bkey_i *, bool);
int bch2_btree_node_update_key_get_iter(struct btree_trans *,
				struct btree *, struct bkey_i *, bool);

int bch2_trans_update_extent(struct btree_trans *, struct btree_iter *,
			     struct bkey_i *, enum btree_update_flags);

int __must_check bch2_trans_update(struct btree_trans *, struct btree_iter *,
				   struct bkey_i *, enum btree_update_flags);

void bch2_trans_commit_hook(struct btree_trans *,
			    struct btree_trans_commit_hook *);
int __bch2_trans_commit(struct btree_trans *);

int bch2_trans_log_msg(struct btree_trans *, const char *);

/**
 * bch2_trans_commit - insert keys at given iterator positions
 *
 * This is main entry point for btree updates.
 *
 * Return values:
 * -EINTR: locking changed, this function should be called again.
 * -EROFS: filesystem read only
 * -EIO: journal or btree node IO error
 */
static inline int bch2_trans_commit(struct btree_trans *trans,
				    struct disk_reservation *disk_res,
				    u64 *journal_seq,
				    unsigned flags)
{
	trans->disk_res		= disk_res;
	trans->journal_seq	= journal_seq;
	trans->flags		= flags;

	return __bch2_trans_commit(trans);
}

#define commit_do(_trans, _disk_res, _journal_seq, _flags, _do)	\
	lockrestart_do(_trans, _do ?: bch2_trans_commit(_trans, (_disk_res),\
					(_journal_seq), (_flags)))

#define nested_commit_do(_trans, _disk_res, _journal_seq, _flags, _do)	\
	nested_lockrestart_do(_trans, _do ?: bch2_trans_commit(_trans, (_disk_res),\
					(_journal_seq), (_flags)))

#define bch2_trans_do(_c, _disk_res, _journal_seq, _flags, _do)		\
({									\
	struct btree_trans trans;					\
	int _ret;							\
									\
	bch2_trans_init(&trans, (_c), 0, 0);				\
	_ret = commit_do(&trans, _disk_res, _journal_seq, _flags, _do);	\
	bch2_trans_exit(&trans);					\
									\
	_ret;								\
})

#define bch2_trans_run(_c, _do)						\
({									\
	struct btree_trans trans;					\
	int _ret;							\
									\
	bch2_trans_init(&trans, (_c), 0, 0);				\
	_ret = (_do);							\
	bch2_trans_exit(&trans);					\
									\
	_ret;								\
})

#define trans_for_each_update(_trans, _i)				\
	for ((_i) = (_trans)->updates;					\
	     (_i) < (_trans)->updates + (_trans)->nr_updates;		\
	     (_i)++)

static inline void bch2_trans_reset_updates(struct btree_trans *trans)
{
	struct btree_insert_entry *i;

	trans_for_each_update(trans, i)
		bch2_path_put(trans, i->path, true);

	trans->extra_journal_res	= 0;
	trans->nr_updates		= 0;
	trans->hooks			= NULL;
	trans->extra_journal_entries.nr	= 0;
}

#endif /* _BCACHEFS_BTREE_UPDATE_H */
