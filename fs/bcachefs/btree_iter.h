/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_ITER_H
#define _BCACHEFS_BTREE_ITER_H

#include "bset.h"
#include "btree_types.h"

static inline void __btree_path_get(struct btree_path *path, bool intent)
{
	path->ref++;
	path->intent_ref += intent;
}

static inline bool __btree_path_put(struct btree_path *path, bool intent)
{
	EBUG_ON(!path->ref);
	EBUG_ON(!path->intent_ref && intent);
	path->intent_ref -= intent;
	return --path->ref == 0;
}

static inline void btree_path_set_dirty(struct btree_path *path,
					enum btree_path_uptodate u)
{
	path->uptodate = max_t(unsigned, path->uptodate, u);
}

static inline struct btree *btree_path_node(struct btree_path *path,
					    unsigned level)
{
	return level < BTREE_MAX_DEPTH ? path->l[level].b : NULL;
}

static inline bool btree_node_lock_seq_matches(const struct btree_path *path,
					const struct btree *b, unsigned level)
{
	/*
	 * We don't compare the low bits of the lock sequence numbers because
	 * @path might have taken a write lock on @b, and we don't want to skip
	 * the linked path if the sequence numbers were equal before taking that
	 * write lock. The lock sequence number is incremented by taking and
	 * releasing write locks and is even when unlocked:
	 */
	return path->l[level].lock_seq >> 1 == b->c.lock.state.seq >> 1;
}

static inline struct btree *btree_node_parent(struct btree_path *path,
					      struct btree *b)
{
	return btree_path_node(path, b->c.level + 1);
}

static inline int btree_iter_err(const struct btree_iter *iter)
{
	return iter->flags & BTREE_ITER_ERROR ? -EIO : 0;
}

/* Iterate over paths within a transaction: */

void __bch2_btree_trans_sort_paths(struct btree_trans *);

static inline void btree_trans_sort_paths(struct btree_trans *trans)
{
	if (!IS_ENABLED(CONFIG_BCACHEFS_DEBUG) &&
	    trans->paths_sorted)
		return;
	__bch2_btree_trans_sort_paths(trans);
}

static inline struct btree_path *
__trans_next_path(struct btree_trans *trans, unsigned idx)
{
	u64 l;

	if (idx == BTREE_ITER_MAX)
		return NULL;

	l = trans->paths_allocated >> idx;
	if (!l)
		return NULL;

	idx += __ffs64(l);
	EBUG_ON(idx >= BTREE_ITER_MAX);
	EBUG_ON(trans->paths[idx].idx != idx);
	return &trans->paths[idx];
}

#define trans_for_each_path(_trans, _path)				\
	for (_path = __trans_next_path((_trans), 0);			\
	     (_path);							\
	     _path = __trans_next_path((_trans), (_path)->idx + 1))

static inline struct btree_path *next_btree_path(struct btree_trans *trans, struct btree_path *path)
{
	unsigned idx = path ? path->sorted_idx + 1 : 0;

	EBUG_ON(idx > trans->nr_sorted);

	return idx < trans->nr_sorted
		? trans->paths + trans->sorted[idx]
		: NULL;
}

static inline struct btree_path *prev_btree_path(struct btree_trans *trans, struct btree_path *path)
{
	unsigned idx = path ? path->sorted_idx : trans->nr_sorted;

	return idx
		? trans->paths + trans->sorted[idx - 1]
		: NULL;
}

#define trans_for_each_path_inorder(_trans, _path, _i)			\
	for (_i = 0;							\
	     ((_path) = (_trans)->paths + trans->sorted[_i]), (_i) < (_trans)->nr_sorted;\
	     _i++)

#define trans_for_each_path_inorder_reverse(_trans, _path, _i)		\
	for (_i = trans->nr_sorted - 1;					\
	     ((_path) = (_trans)->paths + trans->sorted[_i]), (_i) >= 0;\
	     --_i)

static inline bool __path_has_node(const struct btree_path *path,
				   const struct btree *b)
{
	return path->l[b->c.level].b == b &&
		btree_node_lock_seq_matches(path, b, b->c.level);
}

static inline struct btree_path *
__trans_next_path_with_node(struct btree_trans *trans, struct btree *b,
			    unsigned idx)
{
	struct btree_path *path = __trans_next_path(trans, idx);

	while (path && !__path_has_node(path, b))
		path = __trans_next_path(trans, path->idx + 1);

	return path;
}

#define trans_for_each_path_with_node(_trans, _b, _path)		\
	for (_path = __trans_next_path_with_node((_trans), (_b), 0);	\
	     (_path);							\
	     _path = __trans_next_path_with_node((_trans), (_b),	\
						 (_path)->idx + 1))

struct btree_path *__bch2_btree_path_make_mut(struct btree_trans *,
					      struct btree_path *, bool);

static inline struct btree_path * __must_check
bch2_btree_path_make_mut(struct btree_trans *trans,
			 struct btree_path *path, bool intent)
{
	if (path->ref > 1 || path->preserve)
		path = __bch2_btree_path_make_mut(trans, path, intent);
	return path;
}

int __must_check bch2_btree_path_traverse(struct btree_trans *,
					  struct btree_path *, unsigned);
struct btree_path *bch2_path_get(struct btree_trans *, bool, enum btree_id,
				 struct bpos, unsigned, unsigned, bool);
inline struct bkey_s_c bch2_btree_path_peek_slot(struct btree_path *, struct bkey *);

#ifdef CONFIG_BCACHEFS_DEBUG
void bch2_trans_verify_paths(struct btree_trans *);
void bch2_trans_verify_locks(struct btree_trans *);
void bch2_assert_pos_locked(struct btree_trans *, enum btree_id,
			    struct bpos, bool);
#else
static inline void bch2_trans_verify_paths(struct btree_trans *trans) {}
static inline void bch2_trans_verify_locks(struct btree_trans *trans) {}
static inline void bch2_assert_pos_locked(struct btree_trans *trans, enum btree_id id,
					  struct bpos pos, bool key_cache) {}
#endif

void bch2_btree_path_fix_key_modified(struct btree_trans *trans,
				      struct btree *, struct bkey_packed *);
void bch2_btree_node_iter_fix(struct btree_trans *trans, struct btree_path *,
			      struct btree *, struct btree_node_iter *,
			      struct bkey_packed *, unsigned, unsigned);

bool bch2_btree_path_relock_intent(struct btree_trans *, struct btree_path *);

void bch2_path_put(struct btree_trans *, struct btree_path *, bool);

bool bch2_trans_relock(struct btree_trans *);
void bch2_trans_unlock(struct btree_trans *);

__always_inline
static inline int btree_trans_restart(struct btree_trans *trans)
{
	trans->restarted = true;
	bch2_trans_unlock(trans);
	return -EINTR;
}

bool bch2_btree_node_upgrade(struct btree_trans *,
			     struct btree_path *, unsigned);

bool __bch2_btree_path_upgrade(struct btree_trans *,
			       struct btree_path *, unsigned);

static inline bool bch2_btree_path_upgrade(struct btree_trans *trans,
					   struct btree_path *path,
					   unsigned new_locks_want)
{
	new_locks_want = min(new_locks_want, BTREE_MAX_DEPTH);

	return path->locks_want < new_locks_want
		? __bch2_btree_path_upgrade(trans, path, new_locks_want)
		: path->uptodate == BTREE_ITER_UPTODATE;
}

void __bch2_btree_path_downgrade(struct btree_path *, unsigned);

static inline void bch2_btree_path_downgrade(struct btree_path *path)
{
	unsigned new_locks_want = path->level + !!path->intent_ref;

	if (path->locks_want > new_locks_want)
		__bch2_btree_path_downgrade(path, new_locks_want);
}

void bch2_trans_downgrade(struct btree_trans *);

void bch2_trans_node_add(struct btree_trans *trans, struct btree *);
void bch2_trans_node_reinit_iter(struct btree_trans *, struct btree *);

int __must_check __bch2_btree_iter_traverse(struct btree_iter *iter);
int __must_check bch2_btree_iter_traverse(struct btree_iter *);

struct btree *bch2_btree_iter_peek_node(struct btree_iter *);
struct btree *bch2_btree_iter_next_node(struct btree_iter *);

struct bkey_s_c bch2_btree_iter_peek(struct btree_iter *);
struct bkey_s_c bch2_btree_iter_next(struct btree_iter *);

struct bkey_s_c bch2_btree_iter_peek_prev(struct btree_iter *);
struct bkey_s_c bch2_btree_iter_prev(struct btree_iter *);

struct bkey_s_c bch2_btree_iter_peek_slot(struct btree_iter *);
struct bkey_s_c bch2_btree_iter_next_slot(struct btree_iter *);
struct bkey_s_c bch2_btree_iter_prev_slot(struct btree_iter *);

bool bch2_btree_iter_advance(struct btree_iter *);
bool bch2_btree_iter_rewind(struct btree_iter *);

static inline void bch2_btree_iter_set_pos(struct btree_iter *iter, struct bpos new_pos)
{
	if (!(iter->flags & BTREE_ITER_ALL_SNAPSHOTS))
		new_pos.snapshot = iter->snapshot;

	iter->k.type = KEY_TYPE_deleted;
	iter->k.p.inode		= iter->pos.inode	= new_pos.inode;
	iter->k.p.offset	= iter->pos.offset	= new_pos.offset;
	iter->k.p.snapshot	= iter->pos.snapshot	= new_pos.snapshot;
	iter->k.size = 0;
}

static inline void bch2_btree_iter_set_pos_to_extent_start(struct btree_iter *iter)
{
	BUG_ON(!(iter->flags & BTREE_ITER_IS_EXTENTS));
	iter->pos = bkey_start_pos(&iter->k);
}

static inline void bch2_btree_iter_set_snapshot(struct btree_iter *iter, u32 snapshot)
{
	struct bpos pos = iter->pos;

	iter->snapshot = snapshot;
	pos.snapshot = snapshot;
	bch2_btree_iter_set_pos(iter, pos);
}

void bch2_trans_iter_exit(struct btree_trans *, struct btree_iter *);
void bch2_trans_iter_init(struct btree_trans *, struct btree_iter *,
			  unsigned, struct bpos, unsigned);
void bch2_trans_node_iter_init(struct btree_trans *, struct btree_iter *,
			       enum btree_id, struct bpos,
			       unsigned, unsigned, unsigned);
void bch2_trans_copy_iter(struct btree_iter *, struct btree_iter *);

static inline void set_btree_iter_dontneed(struct btree_iter *iter)
{
	iter->path->preserve = false;
}

void *bch2_trans_kmalloc(struct btree_trans *, size_t);
void bch2_trans_begin(struct btree_trans *);

static inline struct btree *
__btree_iter_peek_node_and_restart(struct btree_trans *trans, struct btree_iter *iter)
{
	struct btree *b;

	while (b = bch2_btree_iter_peek_node(iter),
	       PTR_ERR_OR_ZERO(b) == -EINTR)
		bch2_trans_begin(trans);

	return b;
}

#define __for_each_btree_node(_trans, _iter, _btree_id, _start,		\
			      _locks_want, _depth, _flags, _b, _ret)	\
	for (bch2_trans_node_iter_init((_trans), &(_iter), (_btree_id),	\
				_start, _locks_want, _depth, _flags);	\
	     (_b) = __btree_iter_peek_node_and_restart((_trans), &(_iter)),\
	     !((_ret) = PTR_ERR_OR_ZERO(_b)) && (_b);			\
	     (_b) = bch2_btree_iter_next_node(&(_iter)))

#define for_each_btree_node(_trans, _iter, _btree_id, _start,		\
			    _flags, _b, _ret)				\
	__for_each_btree_node(_trans, _iter, _btree_id, _start,		\
			      0, 0, _flags, _b, _ret)

static inline int bkey_err(struct bkey_s_c k)
{
	return PTR_ERR_OR_ZERO(k.k);
}

static inline struct bkey_s_c __bch2_btree_iter_peek(struct btree_iter *iter,
						     unsigned flags)
{
	return flags & BTREE_ITER_SLOTS
		? bch2_btree_iter_peek_slot(iter)
		: bch2_btree_iter_peek(iter);
}

static inline int btree_trans_too_many_iters(struct btree_trans *trans)
{
	return hweight64(trans->paths_allocated) > BTREE_ITER_MAX / 2
		? -EINTR : 0;
}

static inline struct bkey_s_c
__bch2_btree_iter_peek_and_restart(struct btree_trans *trans,
				   struct btree_iter *iter, unsigned flags)
{
	struct bkey_s_c k;

	while (btree_trans_too_many_iters(trans) ||
	       (k = __bch2_btree_iter_peek(iter, flags),
		bkey_err(k) == -EINTR))
		bch2_trans_begin(trans);

	return k;
}

#define for_each_btree_key(_trans, _iter, _btree_id,			\
			   _start, _flags, _k, _ret)			\
	for (bch2_trans_iter_init((_trans), &(_iter), (_btree_id),	\
				  (_start), (_flags));			\
	     (_k) = __bch2_btree_iter_peek_and_restart((_trans), &(_iter), _flags),\
	     !((_ret) = bkey_err(_k)) && (_k).k;			\
	     bch2_btree_iter_advance(&(_iter)))

#define for_each_btree_key_norestart(_trans, _iter, _btree_id,		\
			   _start, _flags, _k, _ret)			\
	for (bch2_trans_iter_init((_trans), &(_iter), (_btree_id),	\
				  (_start), (_flags));			\
	     (_k) = __bch2_btree_iter_peek(&(_iter), _flags),		\
	     !((_ret) = bkey_err(_k)) && (_k).k;			\
	     bch2_btree_iter_advance(&(_iter)))

#define for_each_btree_key_continue(_trans, _iter, _flags, _k, _ret)	\
	for (;								\
	     (_k) = __bch2_btree_iter_peek_and_restart((_trans), &(_iter), _flags),\
	     !((_ret) = bkey_err(_k)) && (_k).k;			\
	     bch2_btree_iter_advance(&(_iter)))

#define for_each_btree_key_continue_norestart(_iter, _flags, _k, _ret)	\
	for (;								\
	     (_k) = __bch2_btree_iter_peek(&(_iter), _flags),		\
	     !((_ret) = bkey_err(_k)) && (_k).k;			\
	     bch2_btree_iter_advance(&(_iter)))

/* new multiple iterator interface: */

void bch2_dump_trans_paths_updates(struct btree_trans *);
void bch2_trans_init(struct btree_trans *, struct bch_fs *, unsigned, size_t);
void bch2_trans_exit(struct btree_trans *);

void bch2_btree_trans_to_text(struct printbuf *, struct bch_fs *);

void bch2_fs_btree_iter_exit(struct bch_fs *);
int bch2_fs_btree_iter_init(struct bch_fs *);

#endif /* _BCACHEFS_BTREE_ITER_H */
