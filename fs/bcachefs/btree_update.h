#ifndef _BCACHEFS_BTREE_UPDATE_H
#define _BCACHEFS_BTREE_UPDATE_H

#include "btree_iter.h"
#include "journal.h"

struct bch_fs;
struct btree;
struct btree_insert;

void bch2_btree_node_lock_for_insert(struct bch_fs *, struct btree *,
				     struct btree_iter *);
bool bch2_btree_bset_insert_key(struct btree_iter *, struct btree *,
				struct btree_node_iter *, struct bkey_i *);
void bch2_btree_journal_key(struct btree_insert *trans, struct btree_iter *,
			    struct bkey_i *);

/* Normal update interface: */

struct btree_insert {
	struct bch_fs		*c;
	struct disk_reservation *disk_res;
	struct journal_res	journal_res;
	u64			*journal_seq;
	struct extent_insert_hook *hook;
	unsigned		flags;
	bool			did_work;

	unsigned short		nr;
	struct btree_insert_entry {
		struct btree_iter *iter;
		struct bkey_i	*k;
		unsigned	extra_res;
		/*
		 * true if entire key was inserted - can only be false for
		 * extents
		 */
		bool		done;
	}			*entries;
};

int __bch2_btree_insert_at(struct btree_insert *);

#define BTREE_INSERT_ENTRY(_iter, _k)					\
	((struct btree_insert_entry) {					\
		.iter		= (_iter),				\
		.k		= (_k),					\
		.done		= false,				\
	})

#define BTREE_INSERT_ENTRY_EXTRA_RES(_iter, _k, _extra)			\
	((struct btree_insert_entry) {					\
		.iter		= (_iter),				\
		.k		= (_k),					\
		.extra_res = (_extra),					\
		.done		= false,				\
	})

/**
 * bch_btree_insert_at - insert one or more keys at iterator positions
 * @iter:		btree iterator
 * @insert_key:		key to insert
 * @disk_res:		disk reservation
 * @hook:		extent insert callback
 *
 * Return values:
 * -EINTR: locking changed, this function should be called again. Only returned
 *  if passed BTREE_INSERT_ATOMIC.
 * -EROFS: filesystem read only
 * -EIO: journal or btree node IO error
 */
#define bch2_btree_insert_at(_c, _disk_res, _hook,			\
			    _journal_seq, _flags, ...)			\
	__bch2_btree_insert_at(&(struct btree_insert) {			\
		.c		= (_c),					\
		.disk_res	= (_disk_res),				\
		.journal_seq	= (_journal_seq),			\
		.hook		= (_hook),				\
		.flags		= (_flags),				\
		.nr		= COUNT_ARGS(__VA_ARGS__),		\
		.entries	= (struct btree_insert_entry[]) {	\
			__VA_ARGS__					\
		}})

/*
 * Don't drop/retake locks: instead return -EINTR if need to upgrade to intent
 * locks, -EAGAIN if need to wait on btree reserve
 */
#define BTREE_INSERT_ATOMIC		(1 << 0)

/* Don't check for -ENOSPC: */
#define BTREE_INSERT_NOFAIL		(1 << 1)

/* for copygc, or when merging btree nodes */
#define BTREE_INSERT_USE_RESERVE	(1 << 2)
#define BTREE_INSERT_USE_ALLOC_RESERVE	(1 << 3)

/*
 * Insert is for journal replay: don't get journal reservations, or mark extents
 * (bch_mark_key)
 */
#define BTREE_INSERT_JOURNAL_REPLAY	(1 << 4)

/* Don't block on allocation failure (for new btree nodes: */
#define BTREE_INSERT_NOWAIT		(1 << 5)
#define BTREE_INSERT_GC_LOCK_HELD	(1 << 6)

#define BCH_HASH_SET_MUST_CREATE	(1 << 7)
#define BCH_HASH_SET_MUST_REPLACE	(1 << 8)

int bch2_btree_delete_at(struct btree_iter *, unsigned);

int bch2_btree_insert_list_at(struct btree_iter *, struct keylist *,
			     struct disk_reservation *,
			     struct extent_insert_hook *, u64 *, unsigned);

int bch2_btree_insert(struct bch_fs *, enum btree_id, struct bkey_i *,
		     struct disk_reservation *,
		     struct extent_insert_hook *, u64 *, int flags);

int bch2_btree_delete_range(struct bch_fs *, enum btree_id,
			   struct bpos, struct bpos, struct bversion,
			   struct disk_reservation *,
			   struct extent_insert_hook *, u64 *);

int bch2_btree_node_rewrite(struct bch_fs *c, struct btree_iter *,
			    __le64, unsigned);
int bch2_btree_node_update_key(struct bch_fs *, struct btree_iter *,
			       struct btree *, struct bkey_i_extent *);

#endif /* _BCACHEFS_BTREE_UPDATE_H */
