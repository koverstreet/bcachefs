#ifndef _BCACHE_BTREE_ITER_H
#define _BCACHE_BTREE_ITER_H

#include "btree_types.h"

struct btree_iter {
	struct closure		cl;

	/* Current btree depth */
	u8			level;

	/*
	 * Used in bch_btree_iter_traverse(), to indicate whether we're
	 * searching for @pos or the first key strictly greater than @pos
	 */
	u8			is_extents;

	/* Bitmasks for read/intent locks held per level */
	u8			nodes_locked;
	u8			nodes_intent_locked;

	/* Btree level below which we start taking intent locks */
	s8			locks_want;

	enum btree_id		btree_id:8;

	s8			error;

	struct cache_set	*c;

	/* Current position of the iterator */
	struct bpos		pos;

	u32			lock_seq[BTREE_MAX_DEPTH];

	/*
	 * NOTE: Never set iter->nodes to NULL except in btree_iter_lock_root().
	 *
	 * This is because iter->nodes[iter->level] == NULL is how
	 * btree_iter_next_node() knows that it's finished with a depth first
	 * traversal. Just unlocking a node (with btree_node_unlock()) is fine,
	 * and if you really don't want that node used again (e.g. btree_split()
	 * freed it) decrementing lock_seq will cause btree_node_relock() to
	 * always fail (but since freeing a btree node takes a write lock on the
	 * node, which increments the node's lock seq, that's not actually
	 * necessary in that example).
	 *
	 * One extra slot for a sentinel NULL:
	 */
	struct btree		*nodes[BTREE_MAX_DEPTH + 1];
	struct btree_node_iter	node_iters[BTREE_MAX_DEPTH];

	/*
	 * Current unpacked key - so that bch_btree_iter_next()/
	 * bch_btree_iter_next_with_holes() can correctly advance pos.
	 */
	struct bkey_tup		tup;

	/*
	 * Circular linked list of linked iterators: linked iterators share
	 * locks (e.g. two linked iterators may have the same node intent
	 * locked, or read and write locked, at the same time), and insertions
	 * through one iterator won't invalidate the other linked iterators.
	 */
	struct btree_iter	*next;
};

#define for_each_linked_btree_iter(_iter, _linked)			\
	for ((_linked) = (_iter)->next;					\
	     (_linked) != (_iter);					\
	     (_linked) = (_linked)->next)

void bch_btree_fix_linked_iter(struct btree_iter *, struct btree *,
			       struct bkey_packed *);

bool bch_btree_iter_upgrade(struct btree_iter *);
int bch_btree_iter_unlock(struct btree_iter *);

bool bch_btree_iter_node_replace(struct btree_iter *, struct btree *);
void bch_btree_iter_node_drop(struct btree_iter *, struct btree *);

void bch_btree_iter_reinit_node(struct btree_iter *, struct btree *);

int __must_check bch_btree_iter_traverse(struct btree_iter *);

struct btree *bch_btree_iter_peek_node(struct btree_iter *);
struct btree *bch_btree_iter_next_node(struct btree_iter *);

struct bkey_s_c bch_btree_iter_peek(struct btree_iter *);
struct bkey_s_c bch_btree_iter_peek_with_holes(struct btree_iter *);
void bch_btree_iter_set_pos(struct btree_iter *, struct bpos);
void bch_btree_iter_advance_pos(struct btree_iter *);
void bch_btree_iter_rewind(struct btree_iter *, struct bpos);

void __bch_btree_iter_init(struct btree_iter *, struct cache_set *,
			   enum btree_id, struct bpos, int);

static inline void bch_btree_iter_init(struct btree_iter *iter,
				       struct cache_set *c,
				       enum btree_id btree_id,
				       struct bpos pos)
{
	__bch_btree_iter_init(iter, c, btree_id, pos, -1);
}

static inline void bch_btree_iter_init_intent(struct btree_iter *iter,
					      struct cache_set *c,
					      enum btree_id btree_id,
					      struct bpos pos)
{
	__bch_btree_iter_init(iter, c, btree_id, pos, 0);
}

void bch_btree_iter_link(struct btree_iter *, struct btree_iter *);

static inline struct bpos btree_type_successor(enum btree_id id,
					       struct bpos pos)
{
	if (id == BTREE_ID_INODES) {
		pos.inode++;
		pos.offset = 0;
	} else if (id != BTREE_ID_EXTENTS) {
		pos = bkey_successor(pos);
	}

	return pos;
}

#define for_each_btree_node(_iter, _c, _btree_id, _start, _b)		\
	for (bch_btree_iter_init((_iter), (_c), (_btree_id), _start),	\
	     (_iter)->is_extents = false,				\
	     _b = bch_btree_iter_peek_node(_iter);			\
	     (_b);							\
	     (_b) = bch_btree_iter_next_node(_iter))

#define __for_each_btree_key(_iter, _c, _btree_id,  _start,		\
			     _k, _locks_want)				\
	for (__bch_btree_iter_init((_iter), (_c), (_btree_id),		\
				   _start, _locks_want);		\
	     ((_k) = bch_btree_iter_peek(_iter)).k;			\
	     bch_btree_iter_advance_pos(_iter))

#define for_each_btree_key(_iter, _c, _btree_id,  _start, _k)		\
	__for_each_btree_key(_iter, _c, _btree_id, _start, _k, -1)

#define for_each_btree_key_intent(_iter, _c, _btree_id,  _start, _k)	\
	__for_each_btree_key(_iter, _c, _btree_id, _start, _k, 0)

#define __for_each_btree_key_with_holes(_iter, _c, _btree_id,		\
					_start, _k, _locks_want)	\
	for (__bch_btree_iter_init((_iter), (_c), (_btree_id),		\
				   _start, _locks_want);		\
	     ((_k) = bch_btree_iter_peek_with_holes(_iter)).k;		\
	     bch_btree_iter_advance_pos(_iter))

#define for_each_btree_key_with_holes(_iter, _c, _btree_id, _start, _k)	\
	__for_each_btree_key_with_holes(_iter, _c, _btree_id, _start, _k, -1)

#define for_each_btree_key_with_holes_intent(_iter, _c, _btree_id,	\
					     _start, _k)		\
	__for_each_btree_key_with_holes(_iter, _c, _btree_id, _start, _k, 0)

/*
 * Unlocks before scheduling
 * Note: does not revalidate iterator
 */
static inline void bch_btree_iter_cond_resched(struct btree_iter *iter)
{
	if (need_resched()) {
		bch_btree_iter_unlock(iter);
		schedule();
		bch_btree_iter_upgrade(iter);
	} else if (race_fault()) {
		bch_btree_iter_unlock(iter);
		bch_btree_iter_upgrade(iter);
	}
}

#endif /* _BCACHE_BTREE_ITER_H */
