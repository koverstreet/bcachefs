
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

bool btree_node_relock(struct btree_iter *iter, unsigned level)
{
	struct btree_iter *linked;
	struct btree *b = iter->nodes[level];
	enum btree_node_locked_type want = btree_lock_want(iter, level);
	enum btree_node_locked_type have = btree_node_locked_type(iter, level);

	if (want == have)
		return true;

	if (!is_btree_node(iter, level))
		return false;

	if (race_fault())
		return false;

	if (have != BTREE_NODE_UNLOCKED
	    ? six_trylock_convert(&b->lock, have, want)
	    : six_relock_type(&b->lock, want, iter->lock_seq[level]))
		goto success;

	for_each_linked_btree_iter(iter, linked)
		if (linked->nodes[level] == b &&
		    btree_node_locked_type(linked, level) == want &&
		    iter->lock_seq[level] == b->lock.state.seq) {
			btree_node_unlock(iter, level);
			six_lock_increment(&b->lock, want);
			goto success;
		}

	return false;
success:
	mark_btree_node_unlocked(iter, level);
	mark_btree_node_locked(iter, level, want);
	return true;
}

/* Slowpath: */
bool __bch_btree_node_lock(struct btree *b, struct bpos pos,
			   unsigned level,
			   struct btree_iter *iter,
			   enum six_lock_type type)
{
	struct btree_iter *linked;

	/* Can't have children locked before ancestors: */
	EBUG_ON(iter->nodes_locked && level > __ffs(iter->nodes_locked));

	/*
	 * Can't hold any read locks while we block taking an intent lock - see
	 * below for reasoning, and we should have already dropped any read
	 * locks in the current iterator
	 */
	EBUG_ON(type == SIX_LOCK_intent &&
		iter->nodes_locked != iter->nodes_intent_locked);

	for_each_linked_btree_iter(iter, linked)
		if (linked->nodes[level] == b &&
		    btree_node_locked_type(linked, level) == type) {
			six_lock_increment(&b->lock, type);
			return true;
		}

	/*
	 * Must lock btree nodes in key order - this case hapens when locking
	 * the prev sibling in btree node merging:
	 */
	if (iter->nodes_locked &&
	    __ffs(iter->nodes_locked) == level &&
	    __btree_iter_cmp(iter->btree_id, pos, iter))
		return false;

	for_each_linked_btree_iter(iter, linked) {
		if (!linked->nodes_locked)
			continue;

		/*
		 * Can't block taking an intent lock if we have _any_ nodes read
		 * locked:
		 *
		 * - Our read lock blocks another thread with an intent lock on
		 *   the same node from getting a write lock, and thus from
		 *   dropping its intent lock
		 *
		 * - And the other thread may have multiple nodes intent locked:
		 *   both the node we want to intent lock, and the node we
		 *   already have read locked - deadlock:
		 */
		if (type == SIX_LOCK_intent &&
		    linked->nodes_locked != linked->nodes_intent_locked) {
			linked->locks_want = max(linked->locks_want,
						 iter->locks_want);
			return false;
		}

		/* We have to lock btree nodes in key order: */
		if (__btree_iter_cmp(iter->btree_id, pos, linked) < 0)
			return false;

		/*
		 * Interior nodes must be locked before their descendants: if
		 * another iterator has possible descendants locked of the node
		 * we're about to lock, it must have the ancestors locked too:
		 */
		if (linked->btree_id == iter->btree_id &&
		    level > __fls(linked->nodes_locked)) {
			linked->locks_want = max(linked->locks_want,
						 iter->locks_want);
			return false;
		}
	}

	six_lock_type(&b->lock, type);
	return true;
}

/* Btree iterator locking: */


static void btree_iter_drop_extra_locks(struct btree_iter *iter)
{
	unsigned l;

	while (iter->nodes_locked &&
	       (l = __fls(iter->nodes_locked)) > iter->locks_want) {
		if (!btree_node_locked(iter, l))
			panic("l %u nodes_locked %u\n", l, iter->nodes_locked);

		if (l > iter->level) {
			btree_node_unlock(iter, l);
		} else if (btree_node_intent_locked(iter, l)) {
			BUG_ON(!six_trylock_convert(&iter->nodes[l]->lock,
						    SIX_LOCK_intent,
						    SIX_LOCK_read));
			iter->nodes_intent_locked ^= 1 << l;
		}
	}
}

bool __bch_btree_iter_set_locks_want(struct btree_iter *iter,
				     unsigned new_locks_want)
{
	struct btree_iter *linked;
	unsigned l;

	/* Drop locks we don't want anymore: */
	if (new_locks_want < iter->locks_want)
		for_each_linked_btree_iter(iter, linked)
			if (linked->locks_want > new_locks_want) {
				linked->locks_want = max_t(unsigned, 1,
							   new_locks_want);
				btree_iter_drop_extra_locks(linked);
			}

	iter->locks_want = new_locks_want;
	btree_iter_drop_extra_locks(iter);

	for (l = iter->level; l < iter->locks_want && iter->nodes[l]; l++)
		if (!btree_node_relock(iter, l))
			goto fail;

	return true;
fail:
	/*
	 * Just an optimization: ancestor nodes must be locked before child
	 * nodes, so set locks_want on iterators that might lock ancestors
	 * before us to avoid getting -EINTR later:
	 */
	for_each_linked_btree_iter(iter, linked)
		if (linked->btree_id == iter->btree_id &&
		    btree_iter_cmp(linked, iter) <= 0)
			linked->locks_want = max_t(unsigned, linked->locks_want,
						   new_locks_want);
	return false;
}

static int __bch_btree_iter_unlock(struct btree_iter *iter)
{
	BUG_ON(iter->error == -EINTR);

	while (iter->nodes_locked)
		btree_node_unlock(iter, __ffs(iter->nodes_locked));

	return iter->error;
}

int bch_btree_iter_unlock(struct btree_iter *iter)
{
	struct btree_iter *linked;

	for_each_linked_btree_iter(iter, linked)
		__bch_btree_iter_unlock(linked);
	return __bch_btree_iter_unlock(iter);
}

/* Btree iterator: */

#ifdef CONFIG_BCACHEFS_DEBUG

static void __bch_btree_iter_verify(struct btree_iter *iter,
				    struct btree *b)
{
	const struct bkey_format *f = &b->keys.format;
	struct btree_node_iter *node_iter = &iter->node_iters[b->level];
	struct btree_node_iter tmp = *node_iter;
	struct bkey_packed *k;

	bch_btree_node_iter_verify(node_iter, &b->keys);

	/*
	 * For interior nodes, the iterator will have skipped past
	 * deleted keys:
	 */
	k = b->level
		? bch_btree_node_iter_prev(&tmp, &b->keys)
		: bch_btree_node_iter_prev_all(&tmp, &b->keys);
	BUG_ON(k && btree_iter_pos_cmp_packed(f, iter->pos, k,
					      iter->is_extents));

	k = bch_btree_node_iter_peek_all(node_iter, &b->keys);
	BUG_ON(k && !btree_iter_pos_cmp_packed(f, iter->pos, k,
					       iter->is_extents));
}

void bch_btree_iter_verify(struct btree_iter *iter, struct btree *b)
{
	struct btree_iter *linked;

	if (iter->nodes[b->level] == b)
		__bch_btree_iter_verify(iter, b);

	for_each_linked_btree_node(iter, b, linked)
		__bch_btree_iter_verify(iter, b);
}

#endif

static void __bch_btree_node_iter_fix(struct btree_iter *iter,
				      struct btree_keys *b,
				      struct btree_node_iter *node_iter,
				      struct bset_tree *t,
				      struct bkey_packed *where,
				      unsigned clobber_u64s,
				      unsigned new_u64s)
{
	struct bkey_format *f = &b->format;
	const struct bkey_packed *end = bset_bkey_last(t->data);
	struct btree_node_iter_set *set;
	unsigned offset = __btree_node_key_to_offset(b, where);
	int shift = new_u64s - clobber_u64s;
	unsigned old_end = (int) __btree_node_key_to_offset(b, end) - shift;

	btree_node_iter_for_each(node_iter, set)
		if (set->end == old_end)
			goto found;

	/* didn't find the bset in the iterator - might have to readd it: */
	if (new_u64s &&
	    btree_iter_pos_cmp_packed(f, iter->pos, where,
				      iter->is_extents))
		bch_btree_node_iter_push(node_iter, b, where, end);
	return;
found:
	set->end = (int) set->end + shift;

	/* Iterator hasn't gotten to the key that changed yet: */
	if (set->k < offset)
		return;

	if (new_u64s &&
	    btree_iter_pos_cmp_packed(f, iter->pos, where,
				      iter->is_extents)) {
		set->k = offset;
		bch_btree_node_iter_sort(node_iter, b);
	} else if (set->k < offset + clobber_u64s) {
		set->k = offset + new_u64s;
		if (set->k == set->end)
			*set = node_iter->data[--node_iter->used];
		bch_btree_node_iter_sort(node_iter, b);
	} else {
		set->k = (int) set->k + shift;
	}
}

void bch_btree_node_iter_fix(struct btree_iter *iter,
			     struct btree *b,
			     struct btree_node_iter *node_iter,
			     struct bset_tree *t,
			     struct bkey_packed *where,
			     unsigned clobber_u64s,
			     unsigned new_u64s)
{
	struct btree_iter *linked;

	if (node_iter != &iter->node_iters[b->level])
		__bch_btree_node_iter_fix(iter, &b->keys, node_iter, t,
					  where, clobber_u64s, new_u64s);

	if (iter->nodes[b->level] == b)
		__bch_btree_node_iter_fix(iter, &b->keys,
					  &iter->node_iters[b->level], t,
					  where, clobber_u64s, new_u64s);

	for_each_linked_btree_node(iter, b, linked)
		__bch_btree_node_iter_fix(linked, &b->keys,
					  &linked->node_iters[b->level], t,
					  where, clobber_u64s, new_u64s);
	bch_btree_iter_verify(iter, b);
}

/* peek_all() doesn't skip deleted keys */
static inline struct bkey_s_c __btree_iter_peek_all(struct btree_iter *iter)
{
	const struct bkey_format *f = &iter->nodes[iter->level]->keys.format;
	struct bkey_packed *k =
		bch_btree_node_iter_peek_all(&iter->node_iters[iter->level],
					     &iter->nodes[iter->level]->keys);
	struct bkey_s_c ret;

	EBUG_ON(!btree_node_locked(iter, iter->level));

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

	EBUG_ON(!btree_node_locked(iter, iter->level));

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

/*
 * Verify that iterator for parent node points to child node:
 */
static void btree_iter_verify_new_node(struct btree_iter *iter, struct btree *b)
{
	bool parent_locked;
	struct bkey_packed *k;

	if (!IS_ENABLED(CONFIG_BCACHEFS_DEBUG) ||
	    !iter->nodes[b->level + 1])
		return;

	parent_locked = btree_node_locked(iter, b->level + 1);

	if (!btree_node_relock(iter, b->level + 1))
		return;

	k = bch_btree_node_iter_peek_all(&iter->node_iters[b->level + 1],
					 &iter->nodes[b->level + 1]->keys);
	BUG_ON(!k ||
	       bkey_cmp_left_packed(&iter->nodes[b->level + 1]->keys.format,
				    k, b->key.k.p));

	if (!parent_locked)
		btree_node_unlock(iter, b->level + 1);
}

static inline void btree_iter_node_set(struct btree_iter *iter,
				       struct btree *b)
{
	btree_iter_verify_new_node(iter, b);

	BUG_ON(b->lock.state.seq & 1);

	iter->lock_seq[b->level] = b->lock.state.seq;
	iter->nodes[b->level] = b;
	bch_btree_node_iter_init(&iter->node_iters[b->level], &b->keys,
				 iter->pos, iter->is_extents);
}

static bool btree_iter_pos_in_node(struct btree_iter *iter, struct btree *b)
{
	return iter->btree_id == b->btree_id &&
		bkey_cmp(iter->pos, b->data->min_key) >= 0 &&
		btree_iter_pos_cmp(iter->pos, &b->key.k, iter->is_extents);
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

			btree_iter_node_set(linked, b);
		}

	if (!btree_iter_pos_in_node(iter, b)) {
		six_unlock_intent(&b->lock);
		return false;
	}

	mark_btree_node_intent_locked(iter, b->level);
	btree_iter_node_set(iter, b);
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

static inline int btree_iter_lock_root(struct btree_iter *iter,
				       unsigned depth_want)
{
	struct cache_set *c = iter->c;
	struct btree *b;
	enum six_lock_type lock_type;
	unsigned i;

	EBUG_ON(iter->nodes_locked);

	while (1) {
		b = READ_ONCE(c->btree_roots[iter->btree_id].b);
		iter->level = READ_ONCE(b->level);

		if (iter->level < depth_want) {
			/*
			 * the root is at a lower depth than the depth we want:
			 * got to the end of the btree, or we're walking nodes
			 * greater than some depth and there are no nodes >=
			 * that depth
			 */
			iter->level = depth_want;
			iter->nodes[iter->level] = NULL;
			return 0;
		}

		lock_type = btree_lock_want(iter, iter->level);
		if (!btree_node_lock(b, POS_MAX, iter->level,
				     iter, lock_type))
			return -EINTR;

		if (b == c->btree_roots[iter->btree_id].b &&
		    b->level == iter->level &&
		    !race_fault()) {
			for (i = 0; i < iter->level; i++)
				iter->nodes[i] = BTREE_ITER_NOT_END;
			iter->nodes[iter->level] = b;

			mark_btree_node_locked(iter, iter->level, lock_type);
			btree_iter_node_set(iter, b);
			return 0;

		}

		six_unlock_type(&b->lock, lock_type);
	}
}

static inline int btree_iter_down(struct btree_iter *iter)
{
	struct btree *b;
	struct bkey_s_c k = __btree_iter_peek(iter);
	unsigned level = iter->level - 1;
	enum six_lock_type lock_type = btree_lock_want(iter, level);
	BKEY_PADDED(k) tmp;

	bkey_reassemble(&tmp.k, k);

	b = bch_btree_node_get(iter, &tmp.k, level, lock_type);
	if (unlikely(IS_ERR(b)))
		return PTR_ERR(b);

	iter->level = level;
	mark_btree_node_locked(iter, level, lock_type);
	btree_iter_node_set(iter, b);
	return 0;
}

static void btree_iter_up(struct btree_iter *iter)
{
	btree_node_unlock(iter, iter->level++);
}

int __must_check __bch_btree_iter_traverse(struct btree_iter *);

static int btree_iter_traverse_error(struct btree_iter *iter, int ret)
{
	struct cache_set *c = iter->c;
	struct btree_iter *linked, *sorted_iters, **i;
retry_all:
	for_each_linked_btree_iter(iter, linked)
		bch_btree_iter_unlock(linked);
	bch_btree_iter_unlock(iter);

	if (ret != -ENOMEM && ret != -EINTR)
		goto io_error;

	if (ret == -ENOMEM) {
		struct closure cl;

		closure_init_stack(&cl);

		do {
			ret = mca_cannibalize_lock(c, &cl);
			closure_sync(&cl);
		} while (ret);
	}

	/*
	 * Linked iters are normally a circular singly linked list - break cycle
	 * while we sort them:
	 */
	linked = iter->next;
	iter->next = NULL;
	sorted_iters = NULL;

	while (linked) {
		iter = linked;
		linked = linked->next;

		i = &sorted_iters;
		while (*i && btree_iter_cmp(iter, *i) > 0)
			i = &(*i)->next;

		iter->next = *i;
		*i = iter;
	}

	/* Make list circular again: */
	iter = sorted_iters;
	while (iter->next)
		iter = iter->next;
	iter->next = sorted_iters;

	/* Now, redo traversals in correct order: */

	iter = sorted_iters;
	do {
retry:
		ret = __bch_btree_iter_traverse(iter);
		if (unlikely(ret)) {
			if (ret == -EINTR)
				goto retry;
			goto retry_all;
		}

		iter = iter->next;
	} while (iter != sorted_iters);

	ret = btree_iter_linked(iter) ? -EINTR : 0;
out:
	mca_cannibalize_unlock(c);
	return ret;
io_error:
	BUG_ON(ret != -EIO);

	iter->error = ret;
	iter->nodes[iter->level] = NULL;
	goto out;
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
int __must_check __bch_btree_iter_traverse(struct btree_iter *iter)
{
	unsigned depth_want = iter->level;

	/* make sure we have all the intent locks we need - ugh */
	if (unlikely(iter->nodes[iter->level] &&
		     iter->level + 1 < iter->locks_want)) {
		unsigned i;

		for (i = iter->level + 1;
		     i < iter->locks_want && iter->nodes[i];
		     i++)
			if (!btree_node_relock(iter, i)) {
				while (iter->nodes[iter->level] &&
				       iter->level + 1 < iter->locks_want)
					btree_iter_up(iter);
				break;
			}
	}

	/*
	 * If the current node isn't locked, go up until we have a locked node
	 * or run out of nodes:
	 */
	while (iter->nodes[iter->level] &&
	       !(is_btree_node(iter, iter->level) &&
		 btree_node_relock(iter, iter->level) &&
		 btree_iter_pos_cmp(iter->pos,
				    &iter->nodes[iter->level]->key.k,
				    iter->is_extents)))
		btree_iter_up(iter);

	/*
	 * If we've got a btree node locked (i.e. we aren't about to relock the
	 * root) - advance its node iterator if necessary:
	 */
	if (iter->nodes[iter->level]) {
		struct bkey_s_c k;

		while ((k = __btree_iter_peek_all(iter)).k &&
		       !btree_iter_pos_cmp(iter->pos, k.k, iter->is_extents))
			__btree_iter_advance(iter);
	}

	/*
	 * Note: iter->nodes[iter->level] may be temporarily NULL here - that
	 * would indicate to other code that we got to the end of the btree,
	 * here it indicates that relocking the root failed - it's critical that
	 * btree_iter_lock_root() comes next and that it can't fail
	 */
	while (iter->level > depth_want) {
		int ret = iter->nodes[iter->level]
			? btree_iter_down(iter)
			: btree_iter_lock_root(iter, depth_want);
		if (unlikely(ret)) {
			iter->level = depth_want;
			return ret;
		}
	}

	return 0;
}

int __must_check bch_btree_iter_traverse(struct btree_iter *iter)
{
	int ret;

	if (unlikely(!iter->nodes[iter->level]))
		return 0;

	iter->at_end_of_leaf = false;

	ret = __bch_btree_iter_traverse(iter);
	if (unlikely(ret))
		ret = btree_iter_traverse_error(iter, ret);

	return ret;
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

	if (b) {
		EBUG_ON(bkey_cmp(b->key.k.p, iter->pos) < 0);
		iter->pos = b->key.k.p;
	}

	return b;
}

struct btree *bch_btree_iter_next_node(struct btree_iter *iter, unsigned depth)
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
	if (!b)
		return b;

	if (bkey_cmp(iter->pos, b->key.k.p) < 0) {
		/* Haven't gotten to the end of the parent node: */
		iter->pos	= bkey_successor(iter->pos);
		iter->level	= depth;

		ret = bch_btree_iter_traverse(iter);
		if (ret)
			return NULL;

		b = iter->nodes[iter->level];
	}

	iter->pos = b->key.k.p;

	return b;
}

/* Iterate across keys (in leaf nodes only) */

void bch_btree_iter_set_pos_same_leaf(struct btree_iter *iter, struct bpos new_pos)
{
	struct btree_keys *b = &iter->nodes[0]->keys;
	struct btree_node_iter *node_iter = &iter->node_iters[0];
	struct bkey_packed *k;

	EBUG_ON(iter->level != 0);
	EBUG_ON(bkey_cmp(new_pos, iter->pos) < 0);
	EBUG_ON(!btree_node_locked(iter, 0));
	EBUG_ON(bkey_cmp(new_pos, iter->nodes[0]->key.k.p) > 0);

	while ((k = bch_btree_node_iter_peek_all(node_iter, b)) &&
	       !btree_iter_pos_cmp_packed(&b->format, new_pos, k,
					  iter->is_extents))
		bch_btree_node_iter_advance(node_iter, b);

	if (!k &&
	    !btree_iter_pos_cmp(new_pos, &iter->nodes[0]->key.k,
				iter->is_extents))
		iter->at_end_of_leaf = true;

	iter->pos = new_pos;
}

void bch_btree_iter_set_pos(struct btree_iter *iter, struct bpos new_pos)
{
	EBUG_ON(bkey_cmp(new_pos, iter->pos) < 0); /* XXX handle this */
	iter->pos = new_pos;
}

void bch_btree_iter_advance_pos(struct btree_iter *iter)
{
	/*
	 * We use iter->k instead of iter->pos for extents: iter->pos will be
	 * equal to the start of the extent we returned, but we need to advance
	 * to the end of the extent we returned.
	 */
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
	int ret;

	while (1) {
		ret = bch_btree_iter_traverse(iter);
		if (unlikely(ret)) {
			iter->k = KEY(iter->pos.inode, iter->pos.offset, 0);
			return bkey_s_c_err(ret);
		}

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

		iter->pos = iter->nodes[0]->key.k.p;

		if (!bkey_cmp(iter->pos, POS_MAX)) {
			iter->k = KEY(iter->pos.inode, iter->pos.offset, 0);
			bch_btree_iter_unlock(iter);
			return bkey_s_c_null;
		}

		iter->pos = btree_type_successor(iter->btree_id, iter->pos);
	}
}

struct bkey_s_c bch_btree_iter_peek_with_holes(struct btree_iter *iter)
{
	struct bkey_s_c k;
	struct bkey n;
	int ret;

	while (1) {
		ret = bch_btree_iter_traverse(iter);
		if (unlikely(ret)) {
			iter->k = KEY(iter->pos.inode, iter->pos.offset, 0);
			return bkey_s_c_err(ret);
		}

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
}

void __bch_btree_iter_init(struct btree_iter *iter, struct cache_set *c,
			   enum btree_id btree_id, struct bpos pos,
			   unsigned locks_want, unsigned depth)
{
	iter->level			= depth;
	iter->is_extents		= btree_id == BTREE_ID_EXTENTS;
	iter->nodes_locked		= 0;
	iter->nodes_intent_locked	= 0;
	iter->locks_want		= min(locks_want, BTREE_MAX_DEPTH);
	iter->btree_id			= btree_id;
	iter->at_end_of_leaf		= 0;
	iter->error			= 0;
	iter->c				= c;
	iter->pos			= pos;
	memset(iter->nodes, 0, sizeof(iter->nodes));
	iter->nodes[iter->level]	= BTREE_ITER_NOT_END;
	iter->next			= iter;
}

void bch_btree_iter_link(struct btree_iter *iter, struct btree_iter *new)
{
	BUG_ON(btree_iter_linked(new));

	new->next = iter->next;
	iter->next = new;

	if (IS_ENABLED(CONFIG_BCACHEFS_DEBUG)) {
		unsigned nr_iters = 1;

		for_each_linked_btree_iter(iter, new)
			nr_iters++;

		BUG_ON(nr_iters > SIX_LOCK_MAX_RECURSE);
	}
}

void bch_btree_iter_copy(struct btree_iter *dst, struct btree_iter *src)
{
	bch_btree_iter_unlock(dst);
	memcpy(dst, src, offsetof(struct btree_iter, next));
	dst->nodes_locked = dst->nodes_intent_locked = 0;
}
