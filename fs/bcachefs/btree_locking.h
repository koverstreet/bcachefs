#ifndef _BCACHE_BTREE_LOCKING_H
#define _BCACHE_BTREE_LOCKING_H

/* Only for internal btree use: */

#include "btree_iter.h"
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

static inline void mark_btree_node_intent_locked(struct btree_iter *iter,
						 unsigned level)
{
	iter->nodes_locked |= 1 << level;
	iter->nodes_intent_locked |= 1 << level;
}

static inline void mark_btree_node_read_locked(struct btree_iter *iter,
					       unsigned level)
{
	iter->nodes_locked |= 1 << level;
}

static inline bool btree_want_intent(struct btree_iter *iter, int level)
{
	return level <= iter->locks_want;
}

static inline void __btree_node_unlock(struct btree_iter *iter, unsigned level,
				       struct btree *b)
{
	switch (btree_node_locked_type(iter, level)) {
	case BTREE_NODE_READ_LOCKED:
		six_unlock_read(&b->lock);
		break;
	case BTREE_NODE_INTENT_LOCKED:
		six_unlock_intent(&b->lock);
		break;
	}

	mark_btree_node_unlocked(iter, level);
}

static inline void btree_node_unlock(struct btree_iter *iter, unsigned level)
{
	__btree_node_unlock(iter, level, iter->nodes[level]);
}

static inline void btree_node_lock_type(struct btree *b, struct btree_iter *iter,
					enum six_lock_type type)
{
	struct btree_iter *linked;

	if (six_trylock_type(&b->lock, type))
		return;

	for_each_linked_btree_iter(iter, linked)
		if (linked->nodes[b->level] == b &&
		    btree_node_locked_type(linked, b->level) == type) {
			six_lock_increment(&b->lock, type);
			return;
		}

	six_lock_type(&b->lock, type);
}

#define __btree_node_lock(b, iter, _level, check_if_raced, type)	\
({									\
	bool _raced;							\
									\
	btree_node_lock_type(b, iter, SIX_LOCK_##type);			\
	if ((_raced = ((check_if_raced) || ((b)->level != _level))))	\
		six_unlock_##type(&(b)->lock);				\
	else								\
		mark_btree_node_##type##_locked((iter), (_level));	\
									\
	!_raced;							\
})

#define btree_node_lock(b, iter, level, check_if_raced)			\
	(!race_fault() &&						\
	 (btree_want_intent(iter, level)				\
	  ? __btree_node_lock(b, iter, level, check_if_raced, intent)	\
	  : __btree_node_lock(b, iter, level, check_if_raced, read)))

bool btree_node_relock(struct btree_iter *, unsigned);

void btree_node_unlock_write(struct btree *, struct btree_iter *);
void btree_node_lock_write(struct btree *, struct btree_iter *);

#endif /* _BCACHE_BTREE_LOCKING_H */
