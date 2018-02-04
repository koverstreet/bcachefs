#ifndef _BCACHEFS_BTREE_LOCKING_H
#define _BCACHEFS_BTREE_LOCKING_H

/*
 * Only for internal btree use:
 *
 * The btree iterator tracks what locks it wants to take, and what locks it
 * currently has - here we have wrappers for locking/unlocking btree nodes and
 * updating the iterator state
 */

#include "btree_iter.h"
#include "btree_io.h"
#include "six.h"

/* matches six lock types */
enum btree_node_locked_type {
	BTREE_NODE_UNLOCKED		= -1,
	BTREE_NODE_READ_LOCKED		= SIX_LOCK_read,
	BTREE_NODE_INTENT_LOCKED	= SIX_LOCK_intent,
};

static inline int btree_node_locked_type(struct btree_iter *iter,
					 unsigned level)
{
	/*
	 * We're relying on the fact that if nodes_intent_locked is set
	 * nodes_locked must be set as well, so that we can compute without
	 * branches:
	 */
	return BTREE_NODE_UNLOCKED +
		((iter->nodes_locked >> level) & 1) +
		((iter->nodes_intent_locked >> level) & 1);
}

static inline bool btree_node_intent_locked(struct btree_iter *iter,
					    unsigned level)
{
	return btree_node_locked_type(iter, level) == BTREE_NODE_INTENT_LOCKED;
}

static inline bool btree_node_read_locked(struct btree_iter *iter,
					  unsigned level)
{
	return btree_node_locked_type(iter, level) == BTREE_NODE_READ_LOCKED;
}

static inline bool btree_node_locked(struct btree_iter *iter, unsigned level)
{
	return iter->nodes_locked & (1 << level);
}

static inline void mark_btree_node_unlocked(struct btree_iter *iter,
					    unsigned level)
{
	iter->nodes_locked &= ~(1 << level);
	iter->nodes_intent_locked &= ~(1 << level);
}

static inline void mark_btree_node_locked(struct btree_iter *iter,
					  unsigned level,
					  enum six_lock_type type)
{
	/* relying on this to avoid a branch */
	BUILD_BUG_ON(SIX_LOCK_read   != 0);
	BUILD_BUG_ON(SIX_LOCK_intent != 1);

	iter->nodes_locked |= 1 << level;
	iter->nodes_intent_locked |= type << level;
}

static inline void mark_btree_node_intent_locked(struct btree_iter *iter,
						 unsigned level)
{
	mark_btree_node_locked(iter, level, SIX_LOCK_intent);
}

static inline enum six_lock_type btree_lock_want(struct btree_iter *iter, int level)
{
	return level < iter->locks_want
		? SIX_LOCK_intent
		: SIX_LOCK_read;
}

static inline bool btree_want_intent(struct btree_iter *iter, int level)
{
	return btree_lock_want(iter, level) == SIX_LOCK_intent;
}

static inline void btree_node_unlock(struct btree_iter *iter, unsigned level)
{
	int lock_type = btree_node_locked_type(iter, level);

	EBUG_ON(level >= BTREE_MAX_DEPTH);

	if (lock_type != BTREE_NODE_UNLOCKED)
		six_unlock_type(&iter->l[level].b->lock, lock_type);
	mark_btree_node_unlocked(iter, level);
}

bool __bch2_btree_node_lock(struct btree *, struct bpos, unsigned,
			   struct btree_iter *, enum six_lock_type);

static inline bool btree_node_lock(struct btree *b, struct bpos pos,
				   unsigned level,
				   struct btree_iter *iter,
				   enum six_lock_type type)
{
	EBUG_ON(level >= BTREE_MAX_DEPTH);

	return likely(six_trylock_type(&b->lock, type)) ||
		__bch2_btree_node_lock(b, pos, level, iter, type);
}

bool __bch2_btree_node_relock(struct btree_iter *, unsigned);

static inline bool bch2_btree_node_relock(struct btree_iter *iter,
					  unsigned level)
{
	return likely(btree_lock_want(iter, level) ==
		      btree_node_locked_type(iter, level)) ||
		__bch2_btree_node_relock(iter, level);
}

bool bch2_btree_iter_relock(struct btree_iter *);

void bch2_btree_node_unlock_write(struct btree *, struct btree_iter *);
void bch2_btree_node_lock_write(struct btree *, struct btree_iter *);

#endif /* _BCACHEFS_BTREE_LOCKING_H */


