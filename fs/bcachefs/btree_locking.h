/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_LOCKING_H
#define _BCACHEFS_BTREE_LOCKING_H

/*
 * Only for internal btree use:
 *
 * The btree iterator tracks what locks it wants to take, and what locks it
 * currently has - here we have wrappers for locking/unlocking btree nodes and
 * updating the iterator state
 */

#include <linux/six.h>

#include "btree_iter.h"

/* matches six lock types */
enum btree_node_locked_type {
	BTREE_NODE_UNLOCKED		= -1,
	BTREE_NODE_READ_LOCKED		= SIX_LOCK_read,
	BTREE_NODE_INTENT_LOCKED	= SIX_LOCK_intent,
};

static inline int btree_node_locked_type(struct btree_path *path,
					 unsigned level)
{
	/*
	 * We're relying on the fact that if nodes_intent_locked is set
	 * nodes_locked must be set as well, so that we can compute without
	 * branches:
	 */
	return BTREE_NODE_UNLOCKED +
		((path->nodes_locked >> level) & 1) +
		((path->nodes_intent_locked >> level) & 1);
}

static inline bool btree_node_intent_locked(struct btree_path *path,
					    unsigned level)
{
	return btree_node_locked_type(path, level) == BTREE_NODE_INTENT_LOCKED;
}

static inline bool btree_node_read_locked(struct btree_path *path,
					  unsigned level)
{
	return btree_node_locked_type(path, level) == BTREE_NODE_READ_LOCKED;
}

static inline bool btree_node_locked(struct btree_path *path, unsigned level)
{
	return path->nodes_locked & (1 << level);
}

static inline void mark_btree_node_unlocked(struct btree_path *path,
					    unsigned level)
{
	path->nodes_locked &= ~(1 << level);
	path->nodes_intent_locked &= ~(1 << level);
}

static inline void mark_btree_node_locked(struct btree_path *path,
					  unsigned level,
					  enum six_lock_type type)
{
	/* relying on this to avoid a branch */
	BUILD_BUG_ON(SIX_LOCK_read   != 0);
	BUILD_BUG_ON(SIX_LOCK_intent != 1);

	path->nodes_locked |= 1 << level;
	path->nodes_intent_locked |= type << level;
}

static inline void mark_btree_node_intent_locked(struct btree_path *path,
						 unsigned level)
{
	mark_btree_node_locked(path, level, SIX_LOCK_intent);
}

static inline enum six_lock_type __btree_lock_want(struct btree_path *path, int level)
{
	return level < path->locks_want
		? SIX_LOCK_intent
		: SIX_LOCK_read;
}

static inline enum btree_node_locked_type
btree_lock_want(struct btree_path *path, int level)
{
	if (level < path->level)
		return BTREE_NODE_UNLOCKED;
	if (level < path->locks_want)
		return BTREE_NODE_INTENT_LOCKED;
	if (level == path->level)
		return BTREE_NODE_READ_LOCKED;
	return BTREE_NODE_UNLOCKED;
}

static inline void btree_node_unlock(struct btree_path *path, unsigned level)
{
	int lock_type = btree_node_locked_type(path, level);

	EBUG_ON(level >= BTREE_MAX_DEPTH);

	if (lock_type != BTREE_NODE_UNLOCKED)
		six_unlock_type(&path->l[level].b->c.lock, lock_type);
	mark_btree_node_unlocked(path, level);
}

static inline void __bch2_btree_path_unlock(struct btree_path *path)
{
	btree_path_set_dirty(path, BTREE_ITER_NEED_RELOCK);

	while (path->nodes_locked)
		btree_node_unlock(path, __ffs(path->nodes_locked));
}

static inline enum bch_time_stats lock_to_time_stat(enum six_lock_type type)
{
	switch (type) {
	case SIX_LOCK_read:
		return BCH_TIME_btree_lock_contended_read;
	case SIX_LOCK_intent:
		return BCH_TIME_btree_lock_contended_intent;
	case SIX_LOCK_write:
		return BCH_TIME_btree_lock_contended_write;
	default:
		BUG();
	}
}

/*
 * wrapper around six locks that just traces lock contended time
 */
static inline void __btree_node_lock_type(struct bch_fs *c, struct btree *b,
					  enum six_lock_type type)
{
	u64 start_time = local_clock();

	six_lock_type(&b->c.lock, type, NULL, NULL);
	bch2_time_stats_update(&c->times[lock_to_time_stat(type)], start_time);
}

static inline void btree_node_lock_type(struct bch_fs *c, struct btree *b,
					enum six_lock_type type)
{
	if (!six_trylock_type(&b->c.lock, type))
		__btree_node_lock_type(c, b, type);
}

/*
 * Lock a btree node if we already have it locked on one of our linked
 * iterators:
 */
static inline bool btree_node_lock_increment(struct btree_trans *trans,
					     struct btree *b, unsigned level,
					     enum btree_node_locked_type want)
{
	struct btree_path *path;

	trans_for_each_path(trans, path)
		if (path->l[level].b == b &&
		    btree_node_locked_type(path, level) >= want) {
			six_lock_increment(&b->c.lock, want);
			return true;
		}

	return false;
}

bool __bch2_btree_node_lock(struct btree_trans *, struct btree_path *,
			    struct btree *, struct bpos, unsigned,
			    enum six_lock_type,
			    six_lock_should_sleep_fn, void *,
			    unsigned long);

static inline bool btree_node_lock(struct btree_trans *trans,
			struct btree_path *path,
			struct btree *b, struct bpos pos, unsigned level,
			enum six_lock_type type,
			six_lock_should_sleep_fn should_sleep_fn, void *p,
			unsigned long ip)
{
	EBUG_ON(level >= BTREE_MAX_DEPTH);
	EBUG_ON(!(trans->paths_allocated & (1ULL << path->idx)));

	return likely(six_trylock_type(&b->c.lock, type)) ||
		btree_node_lock_increment(trans, b, level, type) ||
		__bch2_btree_node_lock(trans, path, b, pos, level, type,
				       should_sleep_fn, p, ip);
}

bool __bch2_btree_node_relock(struct btree_trans *, struct btree_path *, unsigned);

static inline bool bch2_btree_node_relock(struct btree_trans *trans,
					  struct btree_path *path, unsigned level)
{
	EBUG_ON(btree_node_locked(path, level) &&
		btree_node_locked_type(path, level) !=
		__btree_lock_want(path, level));

	return likely(btree_node_locked(path, level)) ||
		__bch2_btree_node_relock(trans, path, level);
}

/*
 * Updates the saved lock sequence number, so that bch2_btree_node_relock() will
 * succeed:
 */
static inline void
bch2_btree_node_unlock_write_inlined(struct btree_trans *trans, struct btree_path *path,
				     struct btree *b)
{
	struct btree_path *linked;

	EBUG_ON(path->l[b->c.level].b != b);
	EBUG_ON(path->l[b->c.level].lock_seq + 1 != b->c.lock.state.seq);

	trans_for_each_path_with_node(trans, b, linked)
		linked->l[b->c.level].lock_seq += 2;

	six_unlock_write(&b->c.lock);
}

void bch2_btree_node_unlock_write(struct btree_trans *,
			struct btree_path *, struct btree *);

void __bch2_btree_node_lock_write(struct btree_trans *, struct btree *);

static inline void bch2_btree_node_lock_write(struct btree_trans *trans,
					      struct btree_path *path,
					      struct btree *b)
{
	EBUG_ON(path->l[b->c.level].b != b);
	EBUG_ON(path->l[b->c.level].lock_seq != b->c.lock.state.seq);
	EBUG_ON(!btree_node_intent_locked(path, b->c.level));

	if (unlikely(!six_trylock_write(&b->c.lock)))
		__bch2_btree_node_lock_write(trans, b);
}

#endif /* _BCACHEFS_BTREE_LOCKING_H */


