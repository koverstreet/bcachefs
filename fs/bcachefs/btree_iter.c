
#include "bcache.h"
#include "bkey_methods.h"
#include "btree_cache.h"
#include "btree_iter.h"
#include "btree_locking.h"
#include "debug.h"
#include "extents.h"

#include <trace/events/bcachefs.h>

#define BTREE_ITER_NOT_END	((struct btree *) 1)

static inline bool is_btree_node(struct btree_iter *iter, unsigned l)
{
	return iter->nodes[l] && iter->nodes[l] != BTREE_ITER_NOT_END;
}

/* Btree node locking: */

/*
 * Updates the saved lock sequence number, so that btree_node_relock() will
 * succeed:
 */
void btree_node_unlock_write(struct btree *b, struct btree_iter *iter)
{
	struct btree_iter *linked;

	EBUG_ON(iter->nodes[b->level] != b);
	EBUG_ON(iter->lock_seq[b->level] + 1 != b->lock.state.seq);

	for_each_linked_btree_node(iter, b, linked)
		linked->lock_seq[b->level] += 2;

	iter->lock_seq[b->level] += 2;

	six_unlock_write(&b->lock);
}

void btree_node_lock_write(struct btree *b, struct btree_iter *iter)
{
	struct btree_iter *linked;
	unsigned readers = 0;

	EBUG_ON(iter->nodes[b->level] != b);
	EBUG_ON(iter->lock_seq[b->level] != b->lock.state.seq);

	if (six_trylock_write(&b->lock))
		return;

	for_each_linked_btree_iter(iter, linked)
		if (linked->nodes[b->level] == b &&
		    btree_node_read_locked(linked, b->level))
			readers++;

	if (likely(!readers)) {
		six_lock_write(&b->lock);
	} else {
		/*
		 * Must drop our read locks before calling six_lock_write() -
		 * six_unlock() won't do wakeups until the reader count
		 * goes to 0, and it's safe because we have the node intent
		 * locked:
		 */
		atomic64_sub(__SIX_VAL(read_lock, readers),
			     &b->lock.state.counter);
		six_lock_write(&b->lock);
		atomic64_add(__SIX_VAL(read_lock, readers),
			     &b->lock.state.counter);
	}
}

/* versions that allow iter to be null: */
void __btree_node_unlock_write(struct btree *b, struct btree_iter *iter)
{
	if (likely(iter))
		btree_node_unlock_write(b, iter);
	else
		six_unlock_write(&b->lock);
}

void __btree_node_lock_write(struct btree *b, struct btree_iter *iter)
{
	if (likely(iter))
		btree_node_lock_write(b, iter);
	else
		six_lock_write(&b->lock);
}

static bool btree_lock_upgrade(struct btree_iter *iter, unsigned level)
{
	struct btree *b = iter->nodes[level];

	if (btree_node_intent_locked(iter, level))
		return true;

	if (!is_btree_node(iter, level))
		return false;

	if (btree_node_locked(iter, level)
	    ? six_trylock_convert(&b->lock, SIX_LOCK_read, SIX_LOCK_intent)
	    : six_relock_intent(&b->lock, iter->lock_seq[level])) {
		mark_btree_node_intent_locked(iter, level);
		trace_bcache_btree_upgrade_lock(b, iter);
		return true;
	}

	trace_bcache_btree_upgrade_lock_fail(b, iter);
	return false;
}

/* Btree iterator locking: */

bool bch_btree_iter_upgrade(struct btree_iter *iter)
{
	int i;

	EBUG_ON(iter->locks_want > BTREE_MAX_DEPTH);

	for (i = iter->locks_want; i >= iter->level; --i)
		if (iter->nodes[i] && !btree_lock_upgrade(iter, i)) {
			do {
				btree_node_unlock(iter, i);

				/*
				 * Make sure btree_node_relock() in
				 * btree_iter_traverse() fails, so that we keep
				 * going up and get all the intent locks we need
				 */
				iter->lock_seq[i]--;
			} while (--i >= 0);

			return false;
		}

	return true;
}

int bch_btree_iter_unlock(struct btree_iter *iter)
{
	unsigned l = 0;

	while (iter->nodes_locked)
		btree_node_unlock(iter, l++);

	return iter->error;
}

bool btree_node_relock(struct btree_iter *iter, unsigned level)
{
	struct btree *b = iter->nodes[level];
	enum six_lock_type type = btree_lock_want(iter, level);

	if (btree_node_locked(iter, level))
		return true;

	if (!race_fault() &&
	    is_btree_node(iter, level) &&
	    six_relock_type(&b->lock, iter->lock_seq[level], type)) {
		mark_btree_node_locked(iter, level, type);
		return true;
	}

	return false;
}

/* Btree iterator: */

static bool btree_iter_pos_cmp(struct btree_iter *iter,
			       struct bpos pos, struct bpos k)
{
	return iter->is_extents
		? bkey_cmp(pos, k) < 0
		: bkey_cmp(pos, k) <= 0;
}

void bch_btree_node_iter_fix(struct btree_iter *iter,
			     struct btree_keys *b,
			     struct btree_node_iter *node_iter,
			     struct bkey_packed *where,
			     bool overwrote)
{
	struct bkey_format *f = &b->format;
	struct bset *i = bset_tree_last(b)->data;
	const struct bkey_packed *end = bset_bkey_last(i);
	struct btree_node_iter_set *set;
	unsigned shift = overwrote ? 0 : where->u64s;
	unsigned offset = __btree_node_key_to_offset(b, where);
	unsigned old_end = __btree_node_key_to_offset(b, end) - shift;
	bool iter_pos_before_new = btree_iter_pos_cmp(iter, iter->pos,
				bkey_unpack_key(f, where).p);

	BUG_ON(node_iter->used > MAX_BSETS);

	for (set = node_iter->data;
	     set < node_iter->data + node_iter->used;
	     set++)
		if (set->end == old_end) {
			set->end += shift;

			if (set->k >= offset) {
				if (iter_pos_before_new)
					set->k = offset;
				else
					set->k += shift;
				bch_btree_node_iter_sort(node_iter, b);
			}
			return;
		}

	/* didn't find the bset in the iterator - might have to readd it: */
	if (iter_pos_before_new)
		bch_btree_node_iter_push(node_iter, b, where, end);
}

/* peek_all() doesn't skip deleted keys */
static inline struct bkey_s_c __btree_iter_peek_all(struct btree_iter *iter)
{
	const struct bkey_format *f = &iter->nodes[iter->level]->keys.format;
	struct bkey_packed *k =
		bch_btree_node_iter_peek_all(&iter->node_iters[iter->level],
					     &iter->nodes[iter->level]->keys);
	struct bkey_s_c ret;

	if (!k)
		return bkey_s_c_null;

	ret = bkey_disassemble(f, k, &iter->k);

	if (debug_check_bkeys(iter->c))
		bkey_debugcheck(iter->c, iter->nodes[iter->level], ret);

	return ret;
}

static inline struct bkey_s_c __btree_iter_peek(struct btree_iter *iter)
{
	const struct bkey_format *f = &iter->nodes[iter->level]->keys.format;
	struct bkey_packed *k =
		bch_btree_node_iter_peek(&iter->node_iters[iter->level],
					 &iter->nodes[iter->level]->keys);
	struct bkey_s_c ret;

	if (!k)
		return bkey_s_c_null;

	ret = bkey_disassemble(f, k, &iter->k);

	if (debug_check_bkeys(iter->c))
		bkey_debugcheck(iter->c, iter->nodes[iter->level], ret);

	return ret;
}

static inline void __btree_iter_advance(struct btree_iter *iter)
{
	bch_btree_node_iter_advance(&iter->node_iters[iter->level],
				    &iter->nodes[iter->level]->keys);
}

static inline void btree_iter_node_set(struct btree_iter *iter,
				       struct btree *b,
				       struct bpos pos)
{
	BUG_ON(b->lock.state.seq & 1);

	iter->lock_seq[b->level] = b->lock.state.seq;
	iter->nodes[b->level] = b;
	bch_btree_node_iter_init(&iter->node_iters[b->level], &b->keys,
				 pos, iter->is_extents);
}

static bool btree_iter_pos_in_node(struct btree_iter *iter,
					  struct btree *b)
{
	return iter->btree_id == b->btree_id &&
		bkey_cmp(iter->pos, b->data->min_key) >= 0 &&
		btree_iter_pos_cmp(iter, iter->pos, b->key.k.p);
}

/*
 * A btree node is being replaced - update the iterator to point to the new
 * node:
 */
bool bch_btree_iter_node_replace(struct btree_iter *iter, struct btree *b)
{
	struct btree_iter *linked;

	for_each_linked_btree_iter(iter, linked)
		if (btree_iter_pos_in_node(linked, b)) {
			/*
			 * bch_btree_iter_node_drop() has already been called -
			 * the old node we're replacing has already been
			 * unlocked and the pointer invalidated
			 */
			BUG_ON(btree_node_locked(linked, b->level));

			/*
			 * If @linked wants this node read locked, we don't want
			 * to actually take the read lock now because it's not
			 * legal to hold read locks on other nodes while we take
			 * write locks, so the journal can make forward
			 * progress...
			 *
			 * Instead, btree_iter_node_set() sets things up so
			 * btree_node_relock() will succeed:
			 */

			if (btree_want_intent(linked, b->level)) {
				six_lock_increment(&b->lock, SIX_LOCK_intent);
				mark_btree_node_intent_locked(linked, b->level);
			}

			btree_iter_node_set(linked, b, linked->pos);
		}

	if (!btree_iter_pos_in_node(iter, b)) {
		six_unlock_intent(&b->lock);
		return false;
	}

	mark_btree_node_intent_locked(iter, b->level);
	btree_iter_node_set(iter, b, iter->pos);
	return true;
}

void bch_btree_iter_node_drop_linked(struct btree_iter *iter, struct btree *b)
{
	struct btree_iter *linked;
	unsigned level = b->level;

	for_each_linked_btree_iter(iter, linked)
		if (linked->nodes[level] == b) {
			btree_node_unlock(linked, level);
			linked->nodes[level] = BTREE_ITER_NOT_END;
		}
}

void bch_btree_iter_node_drop(struct btree_iter *iter, struct btree *b)
{
	unsigned level = b->level;

	if (iter->nodes[level] == b) {
		BUG_ON(b->lock.state.intent_lock != 1);
		btree_node_unlock(iter, level);
		iter->nodes[level] = BTREE_ITER_NOT_END;
	}
}

/*
 * A btree node has been modified in such a way as to invalidate iterators - fix
 * them:
 */
void bch_btree_iter_reinit_node(struct btree_iter *iter, struct btree *b)
{
	struct btree_iter *linked;

	for_each_linked_btree_node(iter, b, linked)
		bch_btree_node_iter_init(&linked->node_iters[b->level],
					 &linked->nodes[b->level]->keys,
					 linked->pos, linked->is_extents);

	bch_btree_node_iter_init(&iter->node_iters[b->level],
				 &iter->nodes[b->level]->keys,
				 iter->pos, iter->is_extents);
}

static inline void btree_iter_lock_root(struct btree_iter *iter, struct bpos pos)
{
	struct cache_set *c = iter->c;

	iter->nodes_locked		= 0;
	iter->nodes_intent_locked	= 0;
	memset(iter->nodes, 0, sizeof(iter->nodes));

	while (1) {
		struct btree *b = c->btree_roots[iter->btree_id].b;

		iter->level = b->level;

		if (btree_node_lock(b, iter, iter->level,
				(b != c->btree_roots[iter->btree_id].b))) {
			btree_iter_node_set(iter, b, pos);
			break;
		}
	}
}

static inline int btree_iter_down(struct btree_iter *iter, struct bpos pos,
				  struct closure *cl)
{
	struct btree *b;
	struct bkey_s_c k = __btree_iter_peek(iter);
	BKEY_PADDED(k) tmp;

	bkey_reassemble(&tmp.k, k);

	b = bch_btree_node_get(iter, &tmp.k, iter->level - 1, cl);
	if (unlikely(IS_ERR(b)))
		return PTR_ERR(b);

	--iter->level;
	btree_iter_node_set(iter, b, pos);
	return 0;
}

static void btree_iter_up(struct btree_iter *iter)
{
	btree_node_unlock(iter, iter->level++);
}

static void btree_iter_verify_locking(struct btree_iter *iter)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	struct btree_iter *linked;
	unsigned level;

	/*
	 * Can't hold _any_ read locks (including in linked iterators) when
	 * taking intent locks, that leads to a fun deadlock involving write
	 * locks and journal reservations
	 *
	 * We could conceivably drop read locks, then retake them and if
	 * retaking fails then return -EINTR... but, let's keep things simple
	 * for now:
	 */
	for_each_linked_btree_iter(iter, linked)
		for (level = 0; level < BTREE_MAX_DEPTH; level++)
			BUG_ON(btree_node_read_locked(linked, level));

	/* Lock ordering: */
	for_each_linked_btree_iter(iter, linked)
		BUG_ON(btree_iter_cmp(iter, linked) < 0 &&
		       btree_node_intent_locked(linked, 0));

	/*
	 * Also, we have to take intent locks on interior nodes before leaf
	 * nodes - verify that linked iterators don't have intent locks held at
	 * depths lower than where we're at:
	 */
	for_each_linked_btree_iter(iter, linked)
		BUG_ON(btree_iter_cmp(linked, iter) <= 0 &&
		       linked->locks_want >= 0 &&
		       linked->locks_want < iter->locks_want);
#endif
}

/*
 * This is the main state machine for walking down the btree - walks down to a
 * specified depth
 *
 * Returns 0 on success, -EIO on error (error reading in a btree node).
 *
 * On error, caller (peek_node()/peek_key()) must return NULL; the error is
 * stashed in the iterator and returned from bch_btree_iter_unlock().
 */
static int __must_check __bch_btree_iter_traverse(struct btree_iter *iter,
						  unsigned l, struct bpos pos)
{
	if (!iter->nodes[iter->level])
		return 0;
retry:
	/*
	 * If the current node isn't locked, go up until we have a locked node
	 * or run out of nodes:
	 */
	while (iter->nodes[iter->level] &&
	       !(is_btree_node(iter, iter->level) &&
		 btree_node_relock(iter, iter->level) &&
		 btree_iter_pos_cmp(iter, pos,
				    iter->nodes[iter->level]->key.k.p)))
		btree_iter_up(iter);

	/*
	 * If we've got a btree node locked (i.e. we aren't about to relock the
	 * root) - advance its node iterator if necessary:
	 */
	if (iter->nodes[iter->level]) {
		struct bkey_s_c k;

		while ((k = __btree_iter_peek_all(iter)).k &&
		       !btree_iter_pos_cmp(iter, pos, k.k->p))
			__btree_iter_advance(iter);
	}

	if (iter->locks_want >= 0)
		btree_iter_verify_locking(iter);

	/*
	 * Note: iter->nodes[iter->level] may be temporarily NULL here - that
	 * would indicate to other code that we got to the end of the btree,
	 * here it indicates that relocking the root failed - it's critical that
	 * btree_iter_lock_root() comes next and that it can't fail
	 */
	while (iter->level > l)
		if (iter->nodes[iter->level]) {
			struct closure cl;
			int ret;

			closure_init_stack(&cl);

			ret = btree_iter_down(iter, pos, &cl);
			if (unlikely(ret)) {
				bch_btree_iter_unlock(iter);
				closure_sync(&cl);

				/*
				 * We just dropped all our locks - so if we need
				 * intent locks, make sure to get them again:
				 */
				if (ret == -EAGAIN || ret == -EINTR) {
					bch_btree_iter_upgrade(iter);
					goto retry;
				}

				iter->error = ret;
				iter->level = BTREE_MAX_DEPTH;
				return ret;
			}
		} else {
			btree_iter_lock_root(iter, pos);
		}

	return 0;
}

int __must_check bch_btree_iter_traverse(struct btree_iter *iter)
{
	return __bch_btree_iter_traverse(iter, iter->level, iter->pos);
}

/* Iterate across nodes (leaf and interior nodes) */

struct btree *bch_btree_iter_peek_node(struct btree_iter *iter)
{
	struct btree *b;
	int ret;

	EBUG_ON(iter->is_extents);

	ret = bch_btree_iter_traverse(iter);
	if (ret)
		return NULL;

	b = iter->nodes[iter->level];

	EBUG_ON(bkey_cmp(b->key.k.p, iter->pos) < 0);
	iter->pos = b->key.k.p;

	return b;
}

struct btree *bch_btree_iter_next_node(struct btree_iter *iter)
{
	struct btree *b;
	int ret;

	EBUG_ON(iter->is_extents);

	btree_iter_up(iter);

	if (!iter->nodes[iter->level])
		return NULL;

	/* parent node usually won't be locked: redo traversal if necessary */
	ret = bch_btree_iter_traverse(iter);
	if (ret)
		return NULL;

	b = iter->nodes[iter->level];

	if (bkey_cmp(iter->pos, b->key.k.p) < 0) {
		struct bpos pos = bkey_successor(iter->pos);

		ret = __bch_btree_iter_traverse(iter, 0, pos);
		if (ret)
			return NULL;

		b = iter->nodes[iter->level];
	}

	iter->pos = b->key.k.p;

	return b;
}

/* Iterate across keys (in leaf nodes only) */

void bch_btree_iter_set_pos(struct btree_iter *iter, struct bpos new_pos)
{
	EBUG_ON(bkey_cmp(new_pos, iter->pos) < 0);
	iter->pos = new_pos;
}

void bch_btree_iter_advance_pos(struct btree_iter *iter)
{
	bch_btree_iter_set_pos(iter,
		btree_type_successor(iter->btree_id, iter->k.p));
}

/* XXX: expensive */
void bch_btree_iter_rewind(struct btree_iter *iter, struct bpos pos)
{
	/* incapable of rewinding across nodes: */
	BUG_ON(bkey_cmp(pos, iter->nodes[iter->level]->data->min_key) < 0);

	iter->pos = pos;

	bch_btree_node_iter_init(&iter->node_iters[iter->level],
				 &iter->nodes[iter->level]->keys,
				 pos, iter->is_extents);
}

struct bkey_s_c bch_btree_iter_peek(struct btree_iter *iter)
{
	struct bkey_s_c k;
	struct bpos pos = iter->pos;
	int ret;

	while (1) {
		ret = __bch_btree_iter_traverse(iter, 0, pos);
		if (unlikely(ret))
			return bkey_s_c_null;

		k = __btree_iter_peek(iter);
		if (likely(k.k)) {
			/*
			 * iter->pos should always be equal to the key we just
			 * returned - except extents can straddle iter->pos:
			 */
			if (!iter->is_extents ||
			    bkey_cmp(bkey_start_pos(k.k), iter->pos) > 0)
				bch_btree_iter_set_pos(iter, bkey_start_pos(k.k));
			return k;
		}

		pos = iter->nodes[0]->key.k.p;

		if (!bkey_cmp(pos, POS_MAX))
			return (struct bkey_s_c) { NULL, NULL };

		pos = btree_type_successor(iter->btree_id, pos);
	}
}

struct bkey_s_c bch_btree_iter_peek_with_holes(struct btree_iter *iter)
{
	struct bkey_s_c k;
	struct bkey n;
	int ret;

	while (1) {
		ret = __bch_btree_iter_traverse(iter, 0, iter->pos);
		if (unlikely(ret))
			return bkey_s_c_null;

		k = __btree_iter_peek_all(iter);
recheck:
		if (!k.k || bkey_cmp(bkey_start_pos(k.k), iter->pos) > 0) {
			/* hole */
			bkey_init(&n);
			n.p = iter->pos;

			if (iter->is_extents) {
				if (n.p.offset == KEY_OFFSET_MAX) {
					iter->pos = bkey_successor(iter->pos);
					goto recheck;
				}

				if (!k.k)
					k.k = &iter->nodes[0]->key.k;

				bch_key_resize(&n,
				       min_t(u64, KEY_SIZE_MAX,
					     (k.k->p.inode == n.p.inode
					      ? bkey_start_offset(k.k)
					      : KEY_OFFSET_MAX) -
					     n.p.offset));

				EBUG_ON(!n.size);
			}

			iter->k = n;
			return (struct bkey_s_c) { &iter->k, NULL };
		} else if (!bkey_deleted(k.k)) {
			return k;
		} else {
			__btree_iter_advance(iter);
		}
	}

	EBUG_ON(!iter->error &&
		(iter->btree_id != BTREE_ID_INODES
		 ? bkey_cmp(iter->pos, POS_MAX)
		 : iter->pos.inode != KEY_INODE_MAX));

	return bkey_s_c_null;
}

void __bch_btree_iter_init(struct btree_iter *iter, struct cache_set *c,
			   enum btree_id btree_id, struct bpos pos,
			   int locks_want)
{
	iter->level			= 0;
	iter->is_extents		= btree_id == BTREE_ID_EXTENTS;
	iter->nodes_locked		= 0;
	iter->nodes_intent_locked	= 0;
	iter->locks_want		= locks_want;
	iter->btree_id			= btree_id;
	iter->error			= 0;
	iter->c				= c;
	iter->pos			= pos;
	iter->nodes[iter->level]	= BTREE_ITER_NOT_END;
	iter->nodes[iter->level + 1]	= NULL;
	iter->next			= iter;
}

int bch_btree_iter_unlink(struct btree_iter *iter)
{
	struct btree_iter *linked;
	int ret = bch_btree_iter_unlock(iter);

	for_each_linked_btree_iter(iter, linked)
		if (linked->next == iter) {
			linked->next = iter->next;
			iter->next = iter;
			return ret;
		}

	BUG();
}

void bch_btree_iter_link(struct btree_iter *iter, struct btree_iter *linked)
{
	BUG_ON(linked->next != linked);

	linked->next = iter->next;
	iter->next = linked;
}

void bch_btree_iter_copy(struct btree_iter *dst, struct btree_iter *src)
{
	bch_btree_iter_unlock(dst);

	dst->level	= src->level;
	dst->is_extents	= src->is_extents;
	dst->btree_id	= src->btree_id;
	dst->pos	= src->pos;

	memcpy(dst->lock_seq,
	       src->lock_seq,
	       sizeof(src->lock_seq));
	memcpy(dst->nodes,
	       src->nodes,
	       sizeof(src->nodes));
	memcpy(dst->node_iters,
	       src->node_iters,
	       sizeof(src->node_iters));
}

void bch_btree_iter_init_copy(struct btree_iter *dst, struct btree_iter *src)
{
	*dst = *src;
	dst->next = dst;
	dst->nodes_locked = 0;
	dst->nodes_intent_locked = 0;
	bch_btree_iter_link(src, dst);
}
