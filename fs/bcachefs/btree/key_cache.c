// SPDX-License-Identifier: GPL-2.0

/* DOC(btree-key-cache)
 *
 * Fast single-key lookups for btrees where the same keys are read and updated
 * frequently. The primary user is the alloc btree: extent updates need to
 * update allocation information for the affected buckets, and doing a full
 * btree lookup for each would be expensive. The key cache keeps recently
 * accessed alloc keys in a hash table, allowing updates to be applied directly
 * without a btree traversal. Cached entries are flushed to the btree by
 * journal reclaim.
 */

#include "bcachefs.h"
#include "backpressure.h"

#include "btree/cache.h"
#include "btree/iter.h"
#include "btree/journal_overlay.h"
#include "btree/key_cache.h"
#include "btree/locking.h"
#include "btree/update.h"

#include "init/error.h"

#include "journal/journal.h"
#include "journal/reclaim.h"

#include <linux/sched/mm.h>

static inline bool btree_uses_pcpu_readers(enum btree_id id)
{
	return id == BTREE_ID_subvolumes;
}

/*
 * Recompute backpressure for the key cache from the current dirty/keys
 * counts and publish it; if the level rose, kick journal reclaim so it
 * starts draining. Called from every nr_dirty / nr_keys mutation —
 * cheap on the no-change path (set_fs returns after one cmpxchg miss).
 */
static void key_cache_pressure_update(struct bch_fs *c)
{
	size_t nr_dirty = atomic_long_read(&c->btree.key_cache.nr_dirty);
	size_t nr_keys = atomic_long_read(&c->btree.key_cache.nr_keys);
	enum bch_backpressure_level new_level = nr_keys
		? nr_dirty * BCH_BACKPRESSURE_LEVEL_NR / nr_keys
		: BCH_BACKPRESSURE_LEVEL_none;
	enum bch_backpressure_level old =
		bch2_backpressure_fs_set(c, BCH_BACKPRESSURE_FS_btree_key_cache,
					 new_level);
	if (new_level > old)
		journal_reclaim_kick(&c->journal);
}

static struct kmem_cache *bch2_key_cache;

static int bch2_btree_key_cache_cmp_fn(struct rhashtable_compare_arg *arg,
				       const void *obj)
{
	const struct bkey_cached *ck = obj;
	const struct bkey_cached_key *key = arg->key;

	return ck->key.btree_id != key->btree_id ||
		!bpos_eq(ck->key.pos, key->pos);
}

static const struct rhashtable_params bch2_btree_key_cache_params = {
	.head_offset		= offsetof(struct bkey_cached, hash),
	.key_offset		= offsetof(struct bkey_cached, key),
	.key_len		= sizeof(struct bkey_cached_key),
	.obj_cmpfn		= bch2_btree_key_cache_cmp_fn,
	.automatic_shrinking	= true,
};

static inline void btree_path_cached_set(struct btree_trans *trans, struct btree_path *path,
					 struct bkey_cached *ck,
					 enum btree_node_locked_type lock_held)
{
	path->l[0].lock_seq	= six_lock_seq(&ck->c.lock);
	path->l[0].b		= (void *) ck;
	mark_btree_node_locked(trans, path, 0, lock_held);
}

__flatten
inline struct bkey_cached *
bch2_btree_key_cache_find(struct bch_fs *c, enum btree_id btree_id, struct bpos pos)
{
	struct bkey_cached_key key = {
		.btree_id	= btree_id,
		.pos		= pos,
	};

	return rhashtable_lookup_fast(&c->btree.key_cache.table, &key,
				      bch2_btree_key_cache_params);
}

static bool bkey_cached_lock_for_evict(struct bkey_cached *ck)
{
	if (!six_trylock_intent(&ck->c.lock))
		return false;

	if (atomic64_read(&ck->journal_seq_offset)) {
		six_unlock_intent(&ck->c.lock);
		return false;
	}

	if (!six_trylock_write(&ck->c.lock)) {
		six_unlock_intent(&ck->c.lock);
		return false;
	}

	return true;
}

static bool bkey_cached_evict(struct bch_fs_btree_key_cache *bc,
			      struct bkey_cached *ck)
{
	bool ret = !rhashtable_remove_fast(&bc->table, &ck->hash,
				      bch2_btree_key_cache_params);
	if (ret) {
		memset(&ck->key, ~0, sizeof(ck->key));
		atomic_long_dec(&bc->nr_keys);
		key_cache_pressure_update(container_of(bc, struct bch_fs,
						       btree.key_cache));
	}
	return ret;
}

static void __bkey_cached_free(struct rcu_pending *pending, struct rcu_head *rcu)
{
	struct bch_fs *c = container_of(pending->srcu, struct bch_fs, btree.trans.barrier);
	struct bkey_cached *ck = container_of(rcu, struct bkey_cached, rcu);

	this_cpu_dec(*c->btree.key_cache.nr_pending);
	six_lock_exit(&ck->c.lock);
	kmem_cache_free(bch2_key_cache, ck);
}

static inline void bkey_cached_free_noassert(struct bch_fs_btree_key_cache *bc,
				      struct bkey_cached *ck)
{
	kfree(ck->k);
	ck->k		= NULL;
	ck->u64s	= 0;

	six_unlock_write(&ck->c.lock);
	six_unlock_intent(&ck->c.lock);

	bool pcpu_readers = ck->c.lock.readers != NULL;
	rcu_pending_enqueue(&bc->pending[pcpu_readers], &ck->rcu);
	this_cpu_inc(*bc->nr_pending);
}

static void bkey_cached_free(struct btree_trans *trans,
			     struct bch_fs_btree_key_cache *bc,
			     struct bkey_cached *ck)
{
	/*
	 * we'll hit strange issues in the SRCU code if we aren't holding an
	 * SRCU read lock...
	 */
	EBUG_ON(!trans->srcu_held);

	bkey_cached_free_noassert(bc, ck);
}

static struct bkey_cached *__bkey_cached_alloc(unsigned key_u64s)
{
	gfp_t gfp = GFP_KERNEL|__GFP_ACCOUNT|__GFP_RECLAIMABLE;

	struct bkey_cached *ck = kmem_cache_zalloc(bch2_key_cache, gfp);
	if (unlikely(!ck))
		return NULL;
	ck->k = kmalloc(key_u64s * sizeof(u64), GFP_KERNEL);
	if (unlikely(!ck->k)) {
		kmem_cache_free(bch2_key_cache, ck);
		return NULL;
	}
	ck->u64s = key_u64s;
	return ck;
}

/*
 * Predicate for rcu_pending_dequeue_where: try to claim a pending entry by
 * taking its intent+write locks. Succeeds only if the lock is currently idle
 * (no SRCU readers still using it), so the returned ck can be reused without
 * blocking. Called under p->lock; six_trylock is safe there (atomic ops only).
 */
static bool bkey_cached_try_claim(struct rcu_head *rcu)
{
	struct bkey_cached *ck = container_of(rcu, struct bkey_cached, rcu);

	if (!six_trylock_intent(&ck->c.lock))
		return false;
	if (!six_trylock_write(&ck->c.lock)) {
		six_unlock_intent(&ck->c.lock);
		return false;
	}
	return true;
}

static struct bkey_cached *
bkey_cached_alloc(struct btree_trans *trans, struct btree_path *path, unsigned key_u64s)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_btree_key_cache *bc = &c->btree.key_cache;
	bool pcpu_readers = btree_uses_pcpu_readers(path->btree_id);
	int ret;

	struct bkey_cached *ck = container_of_or_null(
				rcu_pending_dequeue_where(&bc->pending[pcpu_readers],
							  bkey_cached_try_claim),
				struct bkey_cached, rcu);
	if (ck)
		return ck;

	ck = allocate_dropping_locks(trans, ret,
				     __bkey_cached_alloc(key_u64s));
	if (ret) {
		if (ck) {
			kfree(ck->k);
			kmem_cache_free(bch2_key_cache, ck);
		}
		return ERR_PTR(ret);
	}

	if (ck) {
		bch2_btree_lock_init(&ck->c, pcpu_readers ? SIX_LOCK_INIT_PCPU : 0, GFP_KERNEL);
		ck->c.cached = true;
		/* Brand new lock, trylock can't fail. */
		BUG_ON(!six_trylock_intent(&ck->c.lock));
		BUG_ON(!six_trylock_write(&ck->c.lock));
		return ck;
	}

	return container_of_or_null(
			rcu_pending_dequeue_from_all_where(&bc->pending[pcpu_readers],
							   bkey_cached_try_claim),
			struct bkey_cached, rcu);
}

static struct bkey_cached *
bkey_cached_reuse(struct bch_fs_btree_key_cache *c)
{

	guard(rcu)();
	struct bucket_table *tbl = rht_dereference_rcu(c->table.tbl, &c->table);
	struct rhash_head *pos;
	struct bkey_cached *ck;

	for (unsigned i = 0; i < tbl->size; i++)
		rht_for_each_entry_rcu(ck, pos, tbl, i, hash) {
			if (!atomic64_read(&ck->journal_seq_offset) &&
			    bkey_cached_lock_for_evict(ck)) {
				if (bkey_cached_evict(c, ck))
					return ck;
				six_unlock_write(&ck->c.lock);
				six_unlock_intent(&ck->c.lock);
			}
		}
	return NULL;
}

static int btree_key_cache_create(struct btree_trans *trans,
				  struct btree_path *path,
				  struct btree_path *ck_path,
				  struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_btree_key_cache *bc = &c->btree.key_cache;
	int ret = 0;

	/*
	 * bch2_varint_decode can read past the end of the buffer by at
	 * most 7 bytes (it won't be used):
	 */
	unsigned key_u64s = k.k->u64s + 1;

	/*
	 * Allocate some extra space so that the transaction commit path is less
	 * likely to have to reallocate, since that requires a transaction
	 * restart:
	 */
	key_u64s = min(256U, (key_u64s * 3) / 2);
	key_u64s = roundup_pow_of_two(key_u64s);

	struct bkey_cached *ck = errptr_try(bkey_cached_alloc(trans, ck_path, key_u64s));
	if (unlikely(!ck)) {
		ck = bkey_cached_reuse(bc);
		if (unlikely(!ck)) {
			bch_err_ratelimited(c, "error allocating memory for key cache item, btree %s",
				bch2_btree_id_str(ck_path->btree_id));
			return bch_err_throw(c, ENOMEM_btree_key_cache_create);
		}
	}
	/*
	 * Either way, ck is returned with intent+write held: bkey_cached_alloc
	 * claims them via try_claim for reclaimed entries and trylocks the fresh
	 * lock for newly allocated entries; bkey_cached_reuse takes them via
	 * bkey_cached_lock_for_evict.
	 */

	ck->c.level		= 0;
	ck->c.btree_id		= ck_path->btree_id;
	ck->key.btree_id	= ck_path->btree_id;
	ck->key.pos		= ck_path->pos;
	ck->flags		= 1U << BKEY_CACHED_ACCESSED;

	if (unlikely(key_u64s > ck->u64s)) {
		mark_btree_node_locked_noreset(ck_path, 0, BTREE_NODE_UNLOCKED);

		struct bkey_i *new_k = allocate_dropping_locks(trans, ret,
				kmalloc(key_u64s * sizeof(u64), GFP_KERNEL));
		if (unlikely(!new_k && !ret)) {
			bch_err(trans->c, "error allocating memory for key cache key, btree %s u64s %u",
				bch2_btree_id_str(ck->key.btree_id), key_u64s);
			ret = bch_err_throw(c, ENOMEM_btree_key_cache_fill);
		}

				ret = bch_err_throw(c, ENOMEM_btree_key_cache_fill);
				goto err;
			}

			ret = bch2_trans_relock(trans);
			if (unlikely(ret)) {
				kfree(new_k);
				goto err;
			}
		}

		kfree(ck->k);
		ck->k = new_k;
		ck->u64s = key_u64s;
	}

	bkey_reassemble(ck->k, k);

	ret = bch2_btree_node_lock_write(trans, path, &path_l(path)->b->c);
	if (unlikely(ret))
		goto err;

	ret = rhashtable_lookup_insert_fast(&bc->table, &ck->hash, bch2_btree_key_cache_params);

	bch2_btree_node_unlock_write(trans, path, path_l(path)->b);

	if (unlikely(ret)) /* raced with another fill? */
		goto err;

	atomic_long_inc(&bc->nr_keys);
	key_cache_pressure_update(c);
	six_unlock_write(&ck->c.lock);

	enum six_lock_type lock_want = __btree_lock_want(ck_path, 0);
	if (lock_want == SIX_LOCK_read)
		six_lock_downgrade(&ck->c.lock);
	btree_path_cached_set(trans, ck_path, ck, (enum btree_node_locked_type) lock_want);
	ck_path->uptodate = BTREE_ITER_UPTODATE;
	return 0;
err:
	bkey_cached_free(trans, bc, ck);
	mark_btree_node_locked_noreset(ck_path, 0, BTREE_NODE_UNLOCKED);

	return ret;
}

static noinline int btree_key_cache_fill(struct btree_trans *trans,
					 btree_path_idx_t ck_path_idx,
					 unsigned flags)
{
	struct btree_path *ck_path = trans->paths + ck_path_idx;

	if (flags & BTREE_ITER_cached_nofill) {
		ck_path->l[0].b = NULL;
		return 0;
	}

	struct bch_fs *c = trans->c;

	CLASS(btree_iter, iter)(trans, ck_path->btree_id, ck_path->pos,
				BTREE_ITER_intent|
				BTREE_ITER_nofilter_whiteouts|
				BTREE_ITER_key_cache_fill|
				BTREE_ITER_cached_nofill);
	iter.flags &= ~BTREE_ITER_with_journal;
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	bool needs_immediate_flush = bkey_deleted(k.k);

	ck_path = trans->paths + ck_path_idx;

	if (unlikely(trans->journal_replay_not_finished)) {
		size_t idx = 0;
		const struct bkey_i *jk =
			bch2_journal_keys_peek_max(trans->c, ck_path->btree_id, 0,
						   ck_path->pos, ck_path->pos, &idx);
		if (jk) {
			k = bkey_i_to_s_c(jk);
			needs_immediate_flush |= bkey_deleted(k.k);
		}
	}

	/* Recheck after btree lookup, before allocating: */
	int ret = bch2_btree_key_cache_find(c, ck_path->btree_id, ck_path->pos) ? -EEXIST : 0;
	if (unlikely(ret))
		goto out;

	try(btree_key_cache_create(trans, btree_iter_path(trans, &iter), ck_path, k));

	if (unlikely(needs_immediate_flush)) {
		struct bkey_cached *ck = (void *) ck_path->l[0].b;
		set_bit(BKEY_CACHED_IMMEDIATE_FLUSH, &ck->flags);
	}

	event_inc_trace(c, btree_key_cache_fill, buf, ({
		prt_printf(&buf, "%s\n", trans->fn);
		bch2_bkey_val_to_text(&buf, c, k);
	}));
out:
	/* We're not likely to need this iterator again: */
	bch2_set_btree_iter_dontneed(&iter);
	return ret;
}

static inline int btree_path_traverse_cached_fast(struct btree_trans *trans,
						  btree_path_idx_t path_idx)
{
	struct bch_fs *c = trans->c;
	struct bkey_cached *ck;
	struct btree_path *path = trans->paths + path_idx;
retry:
	ck = bch2_btree_key_cache_find(c, path->btree_id, path->pos);
	if (!ck)
		return -ENOENT;

	enum six_lock_type lock_want = __btree_lock_want(path, 0);

	try(btree_node_lock(trans, path, (void *) ck, 0, lock_want, _THIS_IP_));

	if (ck->key.btree_id != path->btree_id ||
	    !bpos_eq(ck->key.pos, path->pos)) {
		six_unlock_type(&ck->c.lock, lock_want);
		goto retry;
	}

	if (!test_bit(BKEY_CACHED_ACCESSED, &ck->flags))
		set_bit(BKEY_CACHED_ACCESSED, &ck->flags);

	btree_path_cached_set(trans, path, ck, (enum btree_node_locked_type) lock_want);
	path->uptodate = BTREE_ITER_UPTODATE;
	return 0;
}

int bch2_btree_path_traverse_cached(struct btree_trans *trans,
				    btree_path_idx_t path_idx,
				    unsigned flags)
{
	EBUG_ON(trans->paths[path_idx].level);

	int ret;
	do {
		ret = btree_path_traverse_cached_fast(trans, path_idx);
		if (unlikely(ret == -ENOENT))
			ret = btree_key_cache_fill(trans, path_idx, flags);
	} while (ret == -EEXIST);

	struct btree_path *path = trans->paths + path_idx;

	if (unlikely(ret)) {
		path->uptodate = BTREE_ITER_NEED_TRAVERSE;
		if (!bch2_err_matches(ret, BCH_ERR_transaction_restart)) {
			btree_node_unlock(trans, path, 0);
			path->l[0].b = ERR_PTR(ret);
		}
	} else if (!(flags & BTREE_ITER_cached_nofill)) {
		BUG_ON(path->uptodate);
		BUG_ON(!path->nodes_locked);
	}

	return ret;
}

bool bch2_btree_insert_key_cached(struct btree_trans *trans,
				  unsigned flags,
				  struct btree_insert_entry *insert_entry)
{
	struct bch_fs *c = trans->c;
	struct bkey_cached *ck = (void *) (trans->paths + insert_entry->path)->l[0].b;
	struct bkey_i *insert = insert_entry->k;

	BUG_ON(insert->k.u64s > ck->u64s);
	BUG_ON(bkey_deleted(&insert->k));
	BUG_ON(!trans->journal_res.seq);

	bkey_copy(ck->k, insert);

	if (!atomic64_xchg(&ck->journal_seq_offset,
			   (trans->journal_res.seq << 32) |
			   ((insert_entry->ip_allocated + 1) & U32_MAX))) {
		atomic_long_inc(&c->btree.key_cache.nr_dirty);
		key_cache_pressure_update(c);
	}

	if (kick_reclaim)
		journal_reclaim_kick(&c->journal);
	return true;
}

void bch2_btree_key_cache_drop(struct btree_trans *trans,
			       struct btree_path *path)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_btree_key_cache *bc = &c->btree.key_cache;
	struct bkey_cached *ck = (void *) path->l[0].b;

	/*
	 * We just did an update to the btree, bypassing the key cache: the key
	 * cache key is now stale and must be dropped, even if dirty:
	 */
	BUG_ON(atomic64_read(&ck->journal_seq_offset));

	bkey_cached_evict(bc, ck);
	bkey_cached_free(trans, bc, ck);

	mark_btree_node_locked(trans, path, 0, BTREE_NODE_UNLOCKED);

	struct btree_path *path2;
	unsigned i;
	trans_for_each_path(trans, path2, i)
		if (path2->l[0].b == (void *) ck) {
			/*
			 * It's safe to clear should_be_locked here because
			 * we're evicting from the key cache, and we still have
			 * the underlying btree locked: filling into the key
			 * cache would require taking a write lock on the btree
			 * node
			 */
			path2->should_be_locked = false;
			__bch2_btree_path_unlock(trans, path2);
			path2->l[0].b = ERR_PTR(-BCH_ERR_no_btree_node_drop);
			btree_path_set_dirty(trans, path2, BTREE_ITER_NEED_TRAVERSE);
		}

	bch2_trans_verify_locks(trans);
}

static unsigned long bch2_btree_key_cache_scan(struct shrinker *shrink,
					   struct shrink_control *sc)
{
	struct bch_fs *c = shrink->private_data;
	struct bch_fs_btree_key_cache *bc = &c->btree.key_cache;
	struct bucket_table *tbl;
	struct bkey_cached *ck;
	size_t scanned = 0, freed = 0, nr = sc->nr_to_scan;
	unsigned iter, start;

	u64 start_time = local_clock();
	guard(srcu)(&c->btree.trans.barrier);
	guard(rcu)();

	tbl = rht_dereference_rcu(bc->table.tbl, &bc->table);

	/*
	 * Scanning is expensive while a rehash is in progress - most elements
	 * will be on the new hashtable, if it's in progress
	 *
	 * A rehash could still start while we're scanning - that's ok, we'll
	 * still see most elements.
	 */
	if (unlikely(tbl->nest))
		return SHRINK_STOP;

	iter = bc->shrink_iter;
	if (iter >= tbl->size)
		iter = 0;
	start = iter;

	do {
		struct rhash_head *pos, *next;

		pos = rht_ptr_rcu(&tbl->buckets[iter]);

		while (!rht_is_a_nulls(pos)) {
			next = rht_dereference_bucket_rcu(pos->next, tbl, iter);
			ck = container_of(pos, struct bkey_cached, hash);

			if (atomic64_read(&ck->journal_seq_offset)) {
				bc->skipped_dirty++;
			} else if (test_bit(BKEY_CACHED_ACCESSED, &ck->flags)) {
				clear_bit(BKEY_CACHED_ACCESSED, &ck->flags);
				bc->skipped_accessed++;
			} else if (!bkey_cached_lock_for_evict(ck)) {
				bc->skipped_lock_fail++;
			} else if (bkey_cached_evict(bc, ck)) {
				bkey_cached_free_noassert(bc, ck);
				bc->freed++;
				freed++;
			} else {
				six_unlock_write(&ck->c.lock);
				six_unlock_intent(&ck->c.lock);
			}

			scanned++;
			if (scanned >= nr)
				goto out;

			pos = next;
		}

		iter++;
		if (iter >= tbl->size)
			iter = 0;
	} while (scanned < nr && iter != start);
out:
	bc->shrink_iter = iter;

	bch2_time_stats_update(&c->times[BCH_TIME_btree_key_cache_scan], start_time);

	return freed;
}

static unsigned long bch2_btree_key_cache_count(struct shrinker *shrink,
					    struct shrink_control *sc)
{
	struct bch_fs *c = shrink->private_data;
	struct bch_fs_btree_key_cache *bc = &c->btree.key_cache;
	long nr = atomic_long_read(&bc->nr_keys) -
		atomic_long_read(&bc->nr_dirty);

	/*
	 * Avoid hammering our shrinker too much if it's nearly empty - the
	 * shrinker code doesn't take into account how big our cache is, if it's
	 * mostly empty but the system is under memory pressure it causes nasty
	 * lock contention:
	 */
	nr -= 128;

	return max(0L, nr);
}

void bch2_fs_btree_key_cache_exit(struct bch_fs_btree_key_cache *bc)
{
	struct bch_fs *c = container_of(bc, struct bch_fs, btree.key_cache);
	struct bucket_table *tbl;
	struct bkey_cached *ck;
	struct rhash_head *pos;
	LIST_HEAD(items);
	unsigned i;

	shrinker_free(bc->shrink);

	/*
	 * The loop is needed to guard against racing with rehash:
	 */
	while (atomic_long_read(&bc->nr_keys)) {
		scoped_guard(rcu) {
			tbl = rht_dereference_rcu(bc->table.tbl, &bc->table);
			if (tbl) {
				if (tbl->nest) {
					/* wait for in progress rehash */
					goto rehash_wait;
				}
				for (i = 0; i < tbl->size; i++)
					while (pos = rht_ptr_rcu(&tbl->buckets[i]), !rht_is_a_nulls(pos)) {
						ck = container_of(pos, struct bkey_cached, hash);
						BUG_ON(atomic64_read(&ck->journal_seq_offset));
						BUG_ON(!bkey_cached_evict(bc, ck));
						kfree(ck->k);
						six_lock_exit(&ck->c.lock);
						kmem_cache_free(bch2_key_cache, ck);
					}
			}
		}
		continue;
rehash_wait:
		mutex_lock(&bc->table.mutex);
		mutex_unlock(&bc->table.mutex);
	}

	if (atomic_long_read(&bc->nr_dirty) &&
	    !bch2_journal_error(&c->journal) &&
	    test_bit(BCH_FS_was_rw, &c->flags))
		panic("btree key cache shutdown error: nr_dirty nonzero (%li)\n",
		      atomic_long_read(&bc->nr_dirty));

	if (atomic_long_read(&bc->nr_keys))
		panic("btree key cache shutdown error: nr_keys nonzero (%li)\n",
		      atomic_long_read(&bc->nr_keys));

	if (bc->table_init_done)
		rhashtable_destroy(&bc->table);

	rcu_pending_exit(&bc->pending[0]);
	rcu_pending_exit(&bc->pending[1]);

	free_percpu(bc->nr_pending);
}

#ifdef HAVE_SHRINKER_TO_TEXT
#include <linux/seq_buf.h>

static void bch2_btree_key_cache_shrinker_to_text(struct seq_buf *s, struct shrinker *shrink)
{
	struct bch_fs *c = shrink->private_data;
	struct bch_fs_btree_key_cache *bc = &c->btree.key_cache;
	char *cbuf;
	size_t buflen = seq_buf_get_buf(s, &cbuf);
	struct printbuf out = PRINTBUF_EXTERN(cbuf, buflen);

	bch2_btree_key_cache_to_text(&out, bc);
	seq_buf_commit(s, out.pos);
}
#endif /* HAVE_SHRINKER_TO_TEXT */

int bch2_fs_btree_key_cache_init(struct bch_fs_btree_key_cache *bc)
{
	struct bch_fs *c = container_of(bc, struct bch_fs, btree.key_cache);
	struct shrinker *shrink;

	bc->nr_pending = alloc_percpu(size_t);
	if (!bc->nr_pending)
		return bch_err_throw(c, ENOMEM_fs_btree_cache_init);

	if (rcu_pending_init(&bc->pending[0], &c->btree.trans.barrier, __bkey_cached_free) ||
	    rcu_pending_init(&bc->pending[1], &c->btree.trans.barrier, __bkey_cached_free))
		return bch_err_throw(c, ENOMEM_fs_btree_cache_init);

	if (rhashtable_init(&bc->table, &bch2_btree_key_cache_params))
		return bch_err_throw(c, ENOMEM_fs_btree_cache_init);

	bc->table_init_done = true;

	shrink = shrinker_alloc(0, "%s-btree_key_cache", c->name);
	if (!shrink)
		return bch_err_throw(c, ENOMEM_fs_btree_cache_init);
	bc->shrink = shrink;
	shrink->count_objects	= bch2_btree_key_cache_count;
	shrink->scan_objects	= bch2_btree_key_cache_scan;
#ifdef HAVE_SHRINKER_TO_TEXT
	shrink->to_text		= bch2_btree_key_cache_shrinker_to_text;
#endif
	shrink->batch		= 1 << 14;
	shrink->seeks		= 0;
	shrink->private_data	= c;
	shrinker_register(shrink);
	return 0;
}

void bch2_btree_key_cache_to_text(struct printbuf *out, struct bch_fs_btree_key_cache *bc)
{
	printbuf_tabstop_push(out, 24);
	printbuf_tabstop_push(out, 12);

	prt_printf(out, "keys:\t%lu\r\n",		atomic_long_read(&bc->nr_keys));
	prt_printf(out, "dirty:\t%lu\r\n",		atomic_long_read(&bc->nr_dirty));
	prt_printf(out, "table size:\t%u\r\n",		bc->table.tbl->size);
	prt_newline(out);
	prt_printf(out, "shrinker:\n");
	prt_printf(out, "requested_to_free:\t%lu\r\n",	bc->requested_to_free);
	prt_printf(out, "freed:\t%lu\r\n",		bc->freed);
	prt_printf(out, "skipped_dirty:\t%lu\r\n",	bc->skipped_dirty);
	prt_printf(out, "skipped_accessed:\t%lu\r\n",	bc->skipped_accessed);
	prt_printf(out, "skipped_lock_fail:\t%lu\r\n",	bc->skipped_lock_fail);
	prt_newline(out);
	prt_printf(out, "pending:\t%zu\r\n",		per_cpu_sum(bc->nr_pending));
}

void bch2_btree_key_cache_exit(void)
{
	kmem_cache_destroy(bch2_key_cache);
}

int __init bch2_btree_key_cache_init(void)
{
	bch2_key_cache = KMEM_CACHE(bkey_cached, SLAB_RECLAIM_ACCOUNT);
	if (!bch2_key_cache)
		return -ENOMEM;

	return 0;
}
