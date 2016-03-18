
#include "bcache.h"
#include "btree_cache.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_locking.h"
#include "debug.h"
#include "extents.h"

#include <trace/events/bcachefs.h>

#define DEF_BTREE_ID(kwd, val, name) name,

const char *bch_btree_id_names[BTREE_ID_NR] = {
	DEFINE_BCH_BTREE_IDS()
};

#undef DEF_BTREE_ID

void bch_recalc_btree_reserve(struct cache_set *c)
{
	unsigned i, reserve = 16;

	if (!c->btree_roots[0].b)
		reserve += 8;

	for (i = 0; i < BTREE_ID_NR; i++)
		if (c->btree_roots[i].b)
			reserve += min_t(unsigned, 1,
					 c->btree_roots[i].b->level) * 8;

	c->btree_cache_reserve = reserve;
}

#define mca_can_free(c)						\
	max_t(int, 0, c->btree_cache_used - c->btree_cache_reserve)

static void __mca_data_free(struct btree *b)
{
	BUG_ON(b->io_mutex.count != 1);

	free_pages((unsigned long) b->data, b->keys.page_order);
	b->data = NULL;
	bch_btree_keys_free(&b->keys);
}

static void mca_data_free(struct cache_set *c, struct btree *b)
{
	__mca_data_free(b);
	c->btree_cache_used--;
	list_move(&b->list, &c->btree_cache_freed);
}

static const struct rhashtable_params bch_btree_cache_params = {
	.head_offset	= offsetof(struct btree, hash),
	.key_offset	= offsetof(struct btree, key.v),
	.key_len	= sizeof(struct bch_extent_ptr),
	.hashfn		= jhash,
};

static void mca_data_alloc(struct cache_set *c, struct btree *b, gfp_t gfp)
{
	unsigned order = ilog2(btree_pages(c));

	b->data = (void *) __get_free_pages(gfp, order);
	if (!b->data)
		goto err;

	if (bch_btree_keys_alloc(&b->keys, order, gfp))
		goto err;

	c->btree_cache_used++;
	list_move(&b->list, &c->btree_cache_freeable);
	return;
err:
	free_pages((unsigned long) b->data, order);
	b->data = NULL;
	list_move(&b->list, &c->btree_cache_freed);
}

static struct btree *mca_bucket_alloc(struct cache_set *c, gfp_t gfp)
{
	struct btree *b = kzalloc(sizeof(struct btree), gfp);
	if (!b)
		return NULL;

	six_lock_init(&b->lock);
	INIT_LIST_HEAD(&b->list);
	INIT_DELAYED_WORK(&b->work, btree_node_write_work);
	b->c = c;
	sema_init(&b->io_mutex, 1);
	INIT_LIST_HEAD(&b->journal_seq_blacklisted);
	b->writes[1].index = 1;
	INIT_LIST_HEAD(&b->write_blocked);

	mca_data_alloc(c, b, gfp);
	return b->data ? b : NULL;
}

/* Btree in memory cache - hash table */

#define PTR_HASH(_k)	(bkey_i_to_extent_c(_k)->v._data[0])

void mca_hash_remove(struct cache_set *c, struct btree *b)
{
	BUG_ON(btree_node_dirty(b));
	BUG_ON(!list_empty_careful(&b->journal_seq_blacklisted));

	b->keys.nsets = 0;
	b->keys.set[0].data = NULL;

	rhashtable_remove_fast(&c->btree_cache_table, &b->hash,
			       bch_btree_cache_params);

	/* Cause future lookups for this node to fail: */
	bkey_i_to_extent(&b->key)->v._data[0] = 0;
}

int mca_hash_insert(struct cache_set *c, struct btree *b,
		    unsigned level, enum btree_id id)
{
	int ret;
	b->level	= level;
	b->btree_id	= id;

	bch_btree_keys_init(&b->keys, b->level
			    ? &bch_btree_interior_node_ops
			    : bch_btree_ops[id],
			    &c->expensive_debug_checks);

	ret = rhashtable_lookup_insert_fast(&c->btree_cache_table, &b->hash,
					    bch_btree_cache_params);
	if (ret)
		return ret;

	mutex_lock(&c->btree_cache_lock);
	list_add(&b->list, &c->btree_cache);
	mutex_unlock(&c->btree_cache_lock);

	return 0;
}

static inline struct btree *mca_find(struct cache_set *c,
				     const struct bkey_i *k)
{
	return rhashtable_lookup_fast(&c->btree_cache_table, &PTR_HASH(k),
				      bch_btree_cache_params);
}

/*
 * this version is for btree nodes that have already been freed (we're not
 * reaping a real btree node)
 */
static int mca_reap_notrace(struct cache_set *c, struct btree *b, bool flush)
{
	struct closure cl;
	struct bset *i;

	closure_init_stack(&cl);
	lockdep_assert_held(&c->btree_cache_lock);

	if (!six_trylock_intent(&b->lock))
		return -ENOMEM;

	if (!six_trylock_write(&b->lock))
		goto out_unlock_intent;

	if (btree_node_write_error(b))
		goto out_unlock;

	if (!list_empty(&b->write_blocked))
		goto out_unlock;

	i = btree_bset_last(b);
	BUG_ON(!i && btree_node_dirty(b));
	BUG_ON(i && i->u64s &&
	       b->io_mutex.count == 1 &&
	       !btree_node_dirty(b) &&
	       (((void *) i - (void *) b->data) >>
		(c->block_bits + 9) >= b->written));

	/* XXX: we need a better solution for this, this will cause deadlocks */
	if (!list_empty_careful(&b->journal_seq_blacklisted))
		goto out_unlock;

	if (!flush) {
		if (btree_node_dirty(b))
			goto out_unlock;

		if (down_trylock(&b->io_mutex))
			goto out_unlock;
		up(&b->io_mutex);
	}

	/*
	 * Using the underscore version because we don't want to compact bsets
	 * after the write, since this node is about to be evicted:
	 */
	if (btree_node_dirty(b))
		__bch_btree_node_write(b, &cl, -1);

	closure_sync(&cl);

	/* wait for any in flight btree write */
	down(&b->io_mutex);
	up(&b->io_mutex);

	return 0;
out_unlock:
	six_unlock_write(&b->lock);
out_unlock_intent:
	six_unlock_intent(&b->lock);
	return -ENOMEM;
}

static int mca_reap(struct cache_set *c, struct btree *b, bool flush)
{
	int ret = mca_reap_notrace(c, b, flush);

	trace_bcache_mca_reap(b, ret);
	return ret;
}

static unsigned long bch_mca_scan(struct shrinker *shrink,
				  struct shrink_control *sc)
{
	struct cache_set *c = container_of(shrink, struct cache_set,
					   btree_cache_shrink);
	struct btree *b, *t;
	unsigned long nr = sc->nr_to_scan;
	unsigned long can_free;
	unsigned long touched = 0;
	unsigned long freed = 0;
	unsigned i;

	u64 start_time = local_clock();

	if (btree_shrinker_disabled(c))
		return SHRINK_STOP;

	if (c->btree_cache_alloc_lock)
		return SHRINK_STOP;

	/* Return -1 if we can't do anything right now */
	if (sc->gfp_mask & __GFP_IO)
		mutex_lock(&c->btree_cache_lock);
	else if (!mutex_trylock(&c->btree_cache_lock))
		return -1;

	/*
	 * It's _really_ critical that we don't free too many btree nodes - we
	 * have to always leave ourselves a reserve. The reserve is how we
	 * guarantee that allocating memory for a new btree node can always
	 * succeed, so that inserting keys into the btree can always succeed and
	 * IO can always make forward progress:
	 */
	nr /= btree_pages(c);
	can_free = mca_can_free(c);
	nr = min_t(unsigned long, nr, can_free);

	i = 0;
	list_for_each_entry_safe(b, t, &c->btree_cache_freeable, list) {
		touched++;

		if (freed >= nr)
			break;

		if (++i > 3 &&
		    !mca_reap_notrace(c, b, false)) {
			mca_data_free(c, b);
			six_unlock_write(&b->lock);
			six_unlock_intent(&b->lock);
			freed++;
		}
	}
restart:
	list_for_each_entry_safe(b, t, &c->btree_cache, list) {
		touched++;

		if (freed >= nr) {
			/* Save position */
			if (&t->list != &c->btree_cache)
				list_move_tail(&c->btree_cache, &t->list);
			break;
		}

		if (!b->accessed &&
		    !mca_reap(c, b, false)) {
			/* can't call mca_hash_remove under btree_cache_lock  */
			freed++;
			if (&t->list != &c->btree_cache)
				list_move_tail(&c->btree_cache, &t->list);

			mca_data_free(c, b);
			mutex_unlock(&c->btree_cache_lock);

			mca_hash_remove(c, b);
			six_unlock_write(&b->lock);
			six_unlock_intent(&b->lock);

			if (freed >= nr)
				goto out;

			if (sc->gfp_mask & __GFP_IO)
				mutex_lock(&c->btree_cache_lock);
			else if (!mutex_trylock(&c->btree_cache_lock))
				goto out;
			goto restart;
		} else
			b->accessed = 0;
	}

	mutex_unlock(&c->btree_cache_lock);
out:
	bch_time_stats_update(&c->mca_scan_time, start_time);

	trace_bcache_mca_scan(c,
			      touched * btree_pages(c),
			      freed * btree_pages(c),
			      can_free * btree_pages(c),
			      sc->nr_to_scan);

	return (unsigned long) freed * btree_pages(c);
}

static unsigned long bch_mca_count(struct shrinker *shrink,
				   struct shrink_control *sc)
{
	struct cache_set *c = container_of(shrink, struct cache_set,
					   btree_cache_shrink);

	if (btree_shrinker_disabled(c))
		return 0;

	if (c->btree_cache_alloc_lock)
		return 0;

	return mca_can_free(c) * btree_pages(c);
}

void bch_btree_cache_free(struct cache_set *c)
{
	struct btree *b;
	unsigned i;

	if (c->btree_cache_shrink.list.next)
		unregister_shrinker(&c->btree_cache_shrink);

	mutex_lock(&c->btree_cache_lock);

#ifdef CONFIG_BCACHEFS_DEBUG
	if (c->verify_data)
		list_move(&c->verify_data->list, &c->btree_cache);

	free_pages((unsigned long) c->verify_ondisk, ilog2(btree_pages(c)));
#endif

	for (i = 0; i < BTREE_ID_NR; i++)
		if (c->btree_roots[i].b)
			list_add(&c->btree_roots[i].b->list, &c->btree_cache);

	list_splice(&c->btree_cache_freeable,
		    &c->btree_cache);

	while (!list_empty(&c->btree_cache)) {
		b = list_first_entry(&c->btree_cache, struct btree, list);

		if (btree_node_dirty(b))
			bch_btree_complete_write(c, b, btree_current_write(b));
		clear_btree_node_dirty(b);

		mca_data_free(c, b);
	}

	while (!list_empty(&c->btree_cache_freed)) {
		b = list_first_entry(&c->btree_cache_freed,
				     struct btree, list);
		list_del(&b->list);
		cancel_delayed_work_sync(&b->work);
		kfree(b);
	}

	mutex_unlock(&c->btree_cache_lock);

	if (c->btree_cache_table_init_done)
		rhashtable_destroy(&c->btree_cache_table);
}

int bch_btree_cache_alloc(struct cache_set *c)
{
	unsigned i;
	int ret;

	ret = rhashtable_init(&c->btree_cache_table, &bch_btree_cache_params);
	if (ret)
		return ret;

	c->btree_cache_table_init_done = true;

	bch_recalc_btree_reserve(c);

	for (i = 0; i < c->btree_cache_reserve; i++)
		if (!mca_bucket_alloc(c, GFP_KERNEL))
			return -ENOMEM;

	list_splice_init(&c->btree_cache,
			 &c->btree_cache_freeable);

#ifdef CONFIG_BCACHEFS_DEBUG
	mutex_init(&c->verify_lock);

	c->verify_ondisk = (void *)
		__get_free_pages(GFP_KERNEL, ilog2(btree_pages(c)));
	if (!c->verify_ondisk)
		return -ENOMEM;

	c->verify_data = mca_bucket_alloc(c, GFP_KERNEL);
	if (!c->verify_data)
		return -ENOMEM;

	list_del_init(&c->verify_data->list);
#endif

	c->btree_cache_shrink.count_objects = bch_mca_count;
	c->btree_cache_shrink.scan_objects = bch_mca_scan;
	c->btree_cache_shrink.seeks = 4;
	c->btree_cache_shrink.batch = btree_pages(c) * 2;
	register_shrinker(&c->btree_cache_shrink);

	return 0;
}

/*
 * We can only have one thread cannibalizing other cached btree nodes at a time,
 * or we'll deadlock. We use an open coded mutex to ensure that, which a
 * cannibalize_bucket() will take. This means every time we unlock the root of
 * the btree, we need to release this lock if we have it held.
 */
void mca_cannibalize_unlock(struct cache_set *c)
{
	if (c->btree_cache_alloc_lock == current) {
		trace_bcache_mca_cannibalize_unlock(c);
		c->btree_cache_alloc_lock = NULL;
		closure_wake_up(&c->mca_wait);
	}
}

int mca_cannibalize_lock(struct cache_set *c, struct closure *cl)
{
	struct task_struct *old;

	old = cmpxchg(&c->btree_cache_alloc_lock, NULL, current);
	if (old == NULL || old == current)
		goto success;

	if (!cl) {
		trace_bcache_mca_cannibalize_lock_fail(c, cl);
		return -EINTR;
	}

	closure_wait(&c->mca_wait, cl);

	/* Try again, after adding ourselves to waitlist */
	old = cmpxchg(&c->btree_cache_alloc_lock, NULL, current);
	if (old == NULL || old == current) {
		/* We raced */
		closure_wake_up(&c->mca_wait);
		goto success;
	}

	trace_bcache_mca_cannibalize_lock_fail(c, cl);
	return -EAGAIN;

success:
	trace_bcache_mca_cannibalize_lock(c, cl);
	return 0;
}

static struct btree *mca_cannibalize(struct cache_set *c)
{
	struct btree *b;

	list_for_each_entry_reverse(b, &c->btree_cache, list)
		if (!mca_reap(c, b, false))
			return b;

	while (1) {
		list_for_each_entry_reverse(b, &c->btree_cache, list)
			if (!mca_reap(c, b, true))
				return b;

		/*
		 * Rare case: all nodes were intent-locked.
		 * Just busy-wait.
		 */
		WARN_ONCE(1, "btree cache cannibalize failed\n");
		cond_resched();
	}
}

struct btree *mca_alloc(struct cache_set *c, struct closure *cl)
{
	struct btree *b;
	int ret;
	u64 start_time = local_clock();

	mutex_lock(&c->btree_cache_lock);

	/*
	 * btree_free() doesn't free memory; it sticks the node on the end of
	 * the list. Check if there's any freed nodes there:
	 */
	list_for_each_entry(b, &c->btree_cache_freeable, list)
		if (!mca_reap_notrace(c, b, false))
			goto out_unlock;

	/*
	 * We never free struct btree itself, just the memory that holds the on
	 * disk node. Check the freed list before allocating a new one:
	 */
	list_for_each_entry(b, &c->btree_cache_freed, list)
		if (!mca_reap_notrace(c, b, false)) {
			mca_data_alloc(c, b, __GFP_NOWARN|GFP_NOIO);
			if (b->data)
				goto out_unlock;

			six_unlock_write(&b->lock);
			six_unlock_intent(&b->lock);
			goto err;
		}

	b = mca_bucket_alloc(c, __GFP_NOWARN|GFP_NOIO);
	if (!b)
		goto err;

	BUG_ON(!six_trylock_intent(&b->lock));
	BUG_ON(!six_trylock_write(&b->lock));
out_unlock:
	BUG_ON(bkey_extent_is_data(&b->key.k) && PTR_HASH(&b->key));
	BUG_ON(b->io_mutex.count != 1);

	list_del_init(&b->list);
	mutex_unlock(&c->btree_cache_lock);
out:
	b->flags	= 0;
	b->written	= 0;
	b->keys.nsets	= 0;
	b->keys.set[0].data = NULL;

	bch_time_stats_update(&c->mca_alloc_time, start_time);

	return b;
err:
	/* Try to cannibalize another cached btree node: */
	ret = mca_cannibalize_lock(c, cl);
	if (ret) {
		mutex_unlock(&c->btree_cache_lock);
		return ERR_PTR(ret);
	}

	b = mca_cannibalize(c);
	list_del_init(&b->list);
	mutex_unlock(&c->btree_cache_lock);

	mca_hash_remove(c, b);

	trace_bcache_mca_cannibalize(c, cl);
	goto out;
}

/* Slowpath, don't want it inlined into btree_iter_traverse() */
static noinline struct btree *bch_btree_node_fill(struct btree_iter *iter,
						  const struct bkey_i *k,
						  int level)
{
	struct cache_set *c = iter->c;
	struct btree *b;

	b = mca_alloc(c, &iter->cl);
	if (IS_ERR(b))
		return b;

	mca_cannibalize_unlock(c);

	bkey_copy(&b->key, k);
	if (mca_hash_insert(c, b, level, iter->btree_id)) {
		/* raced with another fill: */

		/* mark as unhashed... */
		bkey_i_to_extent(&b->key)->v._data[0] = 0;

		mutex_lock(&c->btree_cache_lock);
		list_add(&b->list, &c->btree_cache_freeable);
		mutex_unlock(&c->btree_cache_lock);

		six_unlock_write(&b->lock);
		six_unlock_intent(&b->lock);
		return NULL;
	}

	/*
	 * If the btree node wasn't cached, we can't drop our lock on
	 * the parent until after it's added to the cache - because
	 * otherwise we could race with a btree_split() freeing the node
	 * we're trying to lock.
	 *
	 * But the deadlock described below doesn't exist in this case,
	 * so it's safe to not drop the parent lock until here:
	 */
	if (btree_node_read_locked(iter, level + 1))
		btree_node_unlock(iter, level + 1);

	bch_btree_node_read(c, b);
	six_unlock_write(&b->lock);

	mark_btree_node_locked(iter, level, btree_lock_want(iter, level));

	if (btree_lock_want(iter, level) == SIX_LOCK_read)
		BUG_ON(!six_trylock_convert(&b->lock,
					    SIX_LOCK_intent,
					    SIX_LOCK_read));

	return b;
}

/**
 * bch_btree_node_get - find a btree node in the cache and lock it, reading it
 * in from disk if necessary.
 *
 * If IO is necessary and running under generic_make_request, returns -EAGAIN.
 *
 * The btree node will have either a read or a write lock held, depending on
 * the @write parameter.
 */
struct btree *bch_btree_node_get(struct btree_iter *iter,
				 const struct bkey_i *k, int level)
{
	int i = 0;
	struct btree *b;

	BUG_ON(level < 0);
retry:
	rcu_read_lock();
	b = mca_find(iter->c, k);
	rcu_read_unlock();

	if (unlikely(!b)) {
		b = bch_btree_node_fill(iter, k, level);

		/* We raced and found the btree node in the cache */
		if (!b)
			goto retry;

		if (IS_ERR(b)) {
			BUG_ON(PTR_ERR(b) != -EAGAIN);
			return b;
		}
	} else {
		/*
		 * There's a potential deadlock with splits and insertions into
		 * interior nodes we have to avoid:
		 *
		 * The other thread might be holding an intent lock on the node
		 * we want, and they want to update its parent node so they're
		 * going to upgrade their intent lock on the parent node to a
		 * write lock.
		 *
		 * But if we're holding a read lock on the parent, and we're
		 * trying to get the intent lock they're holding, we deadlock.
		 *
		 * So to avoid this we drop the read locks on parent nodes when
		 * we're starting to take intent locks - and handle the race.
		 *
		 * The race is that they might be about to free the node we
		 * want, and dropping our read lock lets them add the
		 * replacement node's pointer to the parent and then free the
		 * old node (the node we're trying to lock).
		 *
		 * After we take the intent lock on the node we want (which
		 * protects against it being freed), we check if we might have
		 * raced (and the node was freed before we locked it) with a
		 * global sequence number for freed btree nodes.
		 */
		if (btree_node_read_locked(iter, level + 1))
			btree_node_unlock(iter, level + 1);

		if (!btree_node_lock(b, iter, level,
				     PTR_HASH(&b->key) != PTR_HASH(k))) {
			if (!btree_node_relock(iter, level + 1)) {
				trace_bcache_btree_intent_lock_fail(b, iter);
				return ERR_PTR(-EINTR);
			}

			goto retry;
		}

		BUG_ON(b->level != level);
	}

	b->accessed = 1;

	for (; i <= b->keys.nsets; i++) {
		prefetch(b->keys.set[i].tree);
		prefetch(b->keys.set[i].data);
	}

	if (btree_node_read_error(b)) {
		__btree_node_unlock(iter, level, b);
		return ERR_PTR(-EIO);
	}

	BUG_ON(!b->written);

	return b;
}
