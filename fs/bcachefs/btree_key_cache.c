
#include "bcachefs.h"
#include "btree_cache.h"
#include "btree_iter.h"
#include "btree_key_cache.h"
#include "btree_locking.h"
#include "btree_update.h"
#include "error.h"
#include "journal.h"
#include "journal_reclaim.h"

#include <linux/sched/mm.h>
#include <trace/events/bcachefs.h>

static struct kmem_cache *bch2_key_cache;

static int bch2_btree_key_cache_cmp_fn(struct rhashtable_compare_arg *arg,
				       const void *obj)
{
	const struct bkey_cached *ck = obj;
	const struct bkey_cached_key *key = arg->key;

	return cmp_int(ck->key.btree_id, key->btree_id) ?:
		bpos_cmp(ck->key.pos, key->pos);
}

static const struct rhashtable_params bch2_btree_key_cache_params = {
	.head_offset	= offsetof(struct bkey_cached, hash),
	.key_offset	= offsetof(struct bkey_cached, key),
	.key_len	= sizeof(struct bkey_cached_key),
	.obj_cmpfn	= bch2_btree_key_cache_cmp_fn,
};

__flatten
inline struct bkey_cached *
bch2_btree_key_cache_find(struct bch_fs *c, enum btree_id btree_id, struct bpos pos)
{
	struct bkey_cached_key key = {
		.btree_id	= btree_id,
		.pos		= pos,
	};

	return rhashtable_lookup_fast(&c->btree_key_cache.table, &key,
				      bch2_btree_key_cache_params);
}

static bool bkey_cached_lock_for_evict(struct bkey_cached *ck)
{
	if (!six_trylock_intent(&ck->c.lock))
		return false;

	if (!six_trylock_write(&ck->c.lock)) {
		six_unlock_intent(&ck->c.lock);
		return false;
	}

	if (test_bit(BKEY_CACHED_DIRTY, &ck->flags)) {
		six_unlock_write(&ck->c.lock);
		six_unlock_intent(&ck->c.lock);
		return false;
	}

	return true;
}

static void bkey_cached_evict(struct btree_key_cache *c,
			      struct bkey_cached *ck)
{
	BUG_ON(rhashtable_remove_fast(&c->table, &ck->hash,
				      bch2_btree_key_cache_params));
	memset(&ck->key, ~0, sizeof(ck->key));

	atomic_long_dec(&c->nr_keys);
}

static void bkey_cached_free(struct btree_key_cache *bc,
			     struct bkey_cached *ck)
{
	struct bch_fs *c = container_of(bc, struct bch_fs, btree_key_cache);

	BUG_ON(test_bit(BKEY_CACHED_DIRTY, &ck->flags));

	ck->btree_trans_barrier_seq =
		start_poll_synchronize_srcu(&c->btree_trans_barrier);

	list_move_tail(&ck->list, &bc->freed);
	bc->nr_freed++;

	kfree(ck->k);
	ck->k		= NULL;
	ck->u64s	= 0;

	six_unlock_write(&ck->c.lock);
	six_unlock_intent(&ck->c.lock);
}

static struct bkey_cached *
bkey_cached_alloc(struct btree_key_cache *c)
{
	struct bkey_cached *ck;

	ck = kmem_cache_alloc(bch2_key_cache, GFP_NOFS|__GFP_ZERO);
	if (likely(ck)) {
		INIT_LIST_HEAD(&ck->list);
		six_lock_init(&ck->c.lock);
		BUG_ON(!six_trylock_intent(&ck->c.lock));
		BUG_ON(!six_trylock_write(&ck->c.lock));
		return ck;
	}

	return NULL;
}

static struct bkey_cached *
bkey_cached_reuse(struct btree_key_cache *c)
{
	struct bucket_table *tbl;
	struct rhash_head *pos;
	struct bkey_cached *ck;
	unsigned i;

	mutex_lock(&c->lock);
	list_for_each_entry_reverse(ck, &c->freed, list)
		if (bkey_cached_lock_for_evict(ck)) {
			c->nr_freed--;
			list_del(&ck->list);
			mutex_unlock(&c->lock);
			return ck;
		}
	mutex_unlock(&c->lock);

	rcu_read_lock();
	tbl = rht_dereference_rcu(c->table.tbl, &c->table);
	for (i = 0; i < tbl->size; i++)
		rht_for_each_entry_rcu(ck, pos, tbl, i, hash) {
			if (!test_bit(BKEY_CACHED_DIRTY, &ck->flags) &&
			    bkey_cached_lock_for_evict(ck)) {
				bkey_cached_evict(c, ck);
				rcu_read_unlock();
				return ck;
			}
		}
	rcu_read_unlock();

	return NULL;
}

static struct bkey_cached *
btree_key_cache_create(struct bch_fs *c,
		       enum btree_id btree_id,
		       struct bpos pos)
{
	struct btree_key_cache *bc = &c->btree_key_cache;
	struct bkey_cached *ck;
	bool was_new = true;

	ck = bkey_cached_alloc(bc);

	if (unlikely(!ck)) {
		ck = bkey_cached_reuse(bc);
		if (unlikely(!ck)) {
			bch_err(c, "error allocating memory for key cache item, btree %s",
				bch2_btree_ids[btree_id]);
			return ERR_PTR(-ENOMEM);
		}

		was_new = false;
	}

	if (btree_id == BTREE_ID_subvolumes)
		six_lock_pcpu_alloc(&ck->c.lock);
	else
		six_lock_pcpu_free(&ck->c.lock);

	ck->c.level		= 0;
	ck->c.btree_id		= btree_id;
	ck->key.btree_id	= btree_id;
	ck->key.pos		= pos;
	ck->valid		= false;
	ck->flags		= 1U << BKEY_CACHED_ACCESSED;

	if (unlikely(rhashtable_lookup_insert_fast(&bc->table,
					  &ck->hash,
					  bch2_btree_key_cache_params))) {
		/* We raced with another fill: */

		if (likely(was_new)) {
			six_unlock_write(&ck->c.lock);
			six_unlock_intent(&ck->c.lock);
			kfree(ck);
		} else {
			mutex_lock(&bc->lock);
			bkey_cached_free(bc, ck);
			mutex_unlock(&bc->lock);
		}

		return NULL;
	}

	atomic_long_inc(&bc->nr_keys);

	six_unlock_write(&ck->c.lock);

	return ck;
}

static int btree_key_cache_fill(struct btree_trans *trans,
				struct btree_path *ck_path,
				struct bkey_cached *ck)
{
	struct btree_path *path;
	struct bkey_s_c k;
	unsigned new_u64s = 0;
	struct bkey_i *new_k = NULL;
	struct bkey u;
	int ret;

	path = bch2_path_get(trans, ck->key.btree_id,
			     ck->key.pos, 0, 0, 0, _THIS_IP_);
	ret = bch2_btree_path_traverse(trans, path, 0);
	if (ret)
		goto err;

	k = bch2_btree_path_peek_slot(path, &u);

	if (!bch2_btree_node_relock(trans, ck_path, 0)) {
		trace_trans_restart_relock_key_cache_fill(trans->fn,
				_THIS_IP_, ck_path->btree_id, &ck_path->pos);
		ret = btree_trans_restart(trans);
		goto err;
	}

	/*
	 * bch2_varint_decode can read past the end of the buffer by at
	 * most 7 bytes (it won't be used):
	 */
	new_u64s = k.k->u64s + 1;

	if (new_u64s > ck->u64s) {
		new_u64s = roundup_pow_of_two(new_u64s);
		new_k = kmalloc(new_u64s * sizeof(u64), GFP_NOFS);
		if (!new_k) {
			bch_err(trans->c, "error allocating memory for key cache key, btree %s u64s %u",
				bch2_btree_ids[ck->key.btree_id], new_u64s);
			ret = -ENOMEM;
			goto err;
		}
	}

	/*
	 * XXX: not allowed to be holding read locks when we take a write lock,
	 * currently
	 */
	bch2_btree_node_lock_write(trans, ck_path, ck_path->l[0].b);
	if (new_k) {
		kfree(ck->k);
		ck->u64s = new_u64s;
		ck->k = new_k;
	}

	bkey_reassemble(ck->k, k);
	ck->valid = true;
	bch2_btree_node_unlock_write(trans, ck_path, ck_path->l[0].b);

	/* We're not likely to need this iterator again: */
	path->preserve = false;
err:
	bch2_path_put(trans, path, 0);
	return ret;
}

static int bkey_cached_check_fn(struct six_lock *lock, void *p)
{
	struct bkey_cached *ck = container_of(lock, struct bkey_cached, c.lock);
	const struct btree_path *path = p;

	return ck->key.btree_id == path->btree_id &&
		!bpos_cmp(ck->key.pos, path->pos) ? 0 : -1;
}

__flatten
int bch2_btree_path_traverse_cached(struct btree_trans *trans, struct btree_path *path,
				    unsigned flags)
{
	struct bch_fs *c = trans->c;
	struct bkey_cached *ck;
	int ret = 0;

	BUG_ON(path->level);

	path->l[1].b = NULL;

	if (bch2_btree_node_relock(trans, path, 0)) {
		ck = (void *) path->l[0].b;
		goto fill;
	}
retry:
	ck = bch2_btree_key_cache_find(c, path->btree_id, path->pos);
	if (!ck) {
		if (flags & BTREE_ITER_CACHED_NOCREATE) {
			path->l[0].b = NULL;
			return 0;
		}

		ck = btree_key_cache_create(c, path->btree_id, path->pos);
		ret = PTR_ERR_OR_ZERO(ck);
		if (ret)
			goto err;
		if (!ck)
			goto retry;

		mark_btree_node_locked(path, 0, SIX_LOCK_intent);
		path->locks_want = 1;
	} else {
		enum six_lock_type lock_want = __btree_lock_want(path, 0);

		if (!btree_node_lock(trans, path, (void *) ck, path->pos, 0,
				     lock_want,
				     bkey_cached_check_fn, path, _THIS_IP_)) {
			if (!trans->restarted)
				goto retry;

			ret = -EINTR;
			goto err;
		}

		if (ck->key.btree_id != path->btree_id ||
		    bpos_cmp(ck->key.pos, path->pos)) {
			six_unlock_type(&ck->c.lock, lock_want);
			goto retry;
		}

		mark_btree_node_locked(path, 0, lock_want);
	}

	path->l[0].lock_seq	= ck->c.lock.state.seq;
	path->l[0].b		= (void *) ck;
fill:
	if (!ck->valid && !(flags & BTREE_ITER_CACHED_NOFILL)) {
		if (!path->locks_want &&
		    !__bch2_btree_path_upgrade(trans, path, 1)) {
			trace_transaction_restart_ip(trans->fn, _THIS_IP_);
			ret = btree_trans_restart(trans);
			goto err;
		}

		ret = btree_key_cache_fill(trans, path, ck);
		if (ret)
			goto err;
	}

	if (!test_bit(BKEY_CACHED_ACCESSED, &ck->flags))
		set_bit(BKEY_CACHED_ACCESSED, &ck->flags);

	path->uptodate = BTREE_ITER_UPTODATE;
	BUG_ON(btree_node_locked_type(path, 0) != btree_lock_want(path, 0));

	return ret;
err:
	if (ret != -EINTR) {
		btree_node_unlock(path, 0);
		path->l[0].b = BTREE_ITER_NO_NODE_ERROR;
	}
	return ret;
}

static int btree_key_cache_flush_pos(struct btree_trans *trans,
				     struct bkey_cached_key key,
				     u64 journal_seq,
				     unsigned commit_flags,
				     bool evict)
{
	struct bch_fs *c = trans->c;
	struct journal *j = &c->journal;
	struct btree_iter c_iter, b_iter;
	struct bkey_cached *ck = NULL;
	int ret;

	bch2_trans_iter_init(trans, &b_iter, key.btree_id, key.pos,
			     BTREE_ITER_SLOTS|
			     BTREE_ITER_INTENT|
			     BTREE_ITER_ALL_SNAPSHOTS);
	bch2_trans_iter_init(trans, &c_iter, key.btree_id, key.pos,
			     BTREE_ITER_CACHED|
			     BTREE_ITER_CACHED_NOFILL|
			     BTREE_ITER_CACHED_NOCREATE|
			     BTREE_ITER_INTENT);
	b_iter.flags &= ~BTREE_ITER_WITH_KEY_CACHE;

	ret = bch2_btree_iter_traverse(&c_iter);
	if (ret)
		goto out;

	ck = (void *) c_iter.path->l[0].b;
	if (!ck)
		goto out;

	if (!test_bit(BKEY_CACHED_DIRTY, &ck->flags)) {
		if (evict)
			goto evict;
		goto out;
	}

	BUG_ON(!ck->valid);

	if (journal_seq && ck->journal.seq != journal_seq)
		goto out;

	/*
	 * Since journal reclaim depends on us making progress here, and the
	 * allocator/copygc depend on journal reclaim making progress, we need
	 * to be using alloc reserves:
	 * */
	ret   = bch2_btree_iter_traverse(&b_iter) ?:
		bch2_trans_update(trans, &b_iter, ck->k,
				  BTREE_UPDATE_KEY_CACHE_RECLAIM|
				  BTREE_UPDATE_INTERNAL_SNAPSHOT_NODE|
				  BTREE_TRIGGER_NORUN) ?:
		bch2_trans_commit(trans, NULL, NULL,
				  BTREE_INSERT_NOCHECK_RW|
				  BTREE_INSERT_NOFAIL|
				  BTREE_INSERT_USE_RESERVE|
				  (ck->journal.seq == journal_last_seq(j)
				   ? BTREE_INSERT_JOURNAL_RESERVED
				   : 0)|
				  commit_flags);
	if (ret) {
		bch2_fs_fatal_err_on(ret != -EINTR &&
				     ret != -EAGAIN &&
				     !bch2_journal_error(j), c,
			"error flushing key cache: %i", ret);
		goto out;
	}

	bch2_journal_pin_drop(j, &ck->journal);
	bch2_journal_preres_put(j, &ck->res);

	BUG_ON(!btree_node_locked(c_iter.path, 0));

	if (!evict) {
		if (test_bit(BKEY_CACHED_DIRTY, &ck->flags)) {
			clear_bit(BKEY_CACHED_DIRTY, &ck->flags);
			atomic_long_dec(&c->btree_key_cache.nr_dirty);
		}
	} else {
evict:
		BUG_ON(!btree_node_intent_locked(c_iter.path, 0));

		mark_btree_node_unlocked(c_iter.path, 0);
		c_iter.path->l[0].b = NULL;

		six_lock_write(&ck->c.lock, NULL, NULL);

		if (test_bit(BKEY_CACHED_DIRTY, &ck->flags)) {
			clear_bit(BKEY_CACHED_DIRTY, &ck->flags);
			atomic_long_dec(&c->btree_key_cache.nr_dirty);
		}

		bkey_cached_evict(&c->btree_key_cache, ck);

		mutex_lock(&c->btree_key_cache.lock);
		bkey_cached_free(&c->btree_key_cache, ck);
		mutex_unlock(&c->btree_key_cache.lock);
	}
out:
	bch2_trans_iter_exit(trans, &b_iter);
	bch2_trans_iter_exit(trans, &c_iter);
	return ret;
}

int bch2_btree_key_cache_journal_flush(struct journal *j,
				struct journal_entry_pin *pin, u64 seq)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct bkey_cached *ck =
		container_of(pin, struct bkey_cached, journal);
	struct bkey_cached_key key;
	int ret = 0;

	int srcu_idx = srcu_read_lock(&c->btree_trans_barrier);

	six_lock_read(&ck->c.lock, NULL, NULL);
	key = ck->key;

	if (ck->journal.seq != seq ||
	    !test_bit(BKEY_CACHED_DIRTY, &ck->flags)) {
		six_unlock_read(&ck->c.lock);
		goto unlock;
	}
	six_unlock_read(&ck->c.lock);

	ret = bch2_trans_do(c, NULL, NULL, 0,
		btree_key_cache_flush_pos(&trans, key, seq,
				BTREE_INSERT_JOURNAL_RECLAIM, false));
unlock:
	srcu_read_unlock(&c->btree_trans_barrier, srcu_idx);

	return ret;
}

/*
 * Flush and evict a key from the key cache:
 */
int bch2_btree_key_cache_flush(struct btree_trans *trans,
			       enum btree_id id, struct bpos pos)
{
	struct bch_fs *c = trans->c;
	struct bkey_cached_key key = { id, pos };

	/* Fastpath - assume it won't be found: */
	if (!bch2_btree_key_cache_find(c, id, pos))
		return 0;

	return btree_key_cache_flush_pos(trans, key, 0, 0, true);
}

bool bch2_btree_insert_key_cached(struct btree_trans *trans,
				  struct btree_path *path,
				  struct bkey_i *insert)
{
	struct bch_fs *c = trans->c;
	struct bkey_cached *ck = (void *) path->l[0].b;
	bool kick_reclaim = false;

	BUG_ON(insert->u64s > ck->u64s);

	if (likely(!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY))) {
		int difference;

		BUG_ON(jset_u64s(insert->u64s) > trans->journal_preres.u64s);

		difference = jset_u64s(insert->u64s) - ck->res.u64s;
		if (difference > 0) {
			trans->journal_preres.u64s	-= difference;
			ck->res.u64s			+= difference;
		}
	}

	bkey_copy(ck->k, insert);
	ck->valid = true;

	if (!test_bit(BKEY_CACHED_DIRTY, &ck->flags)) {
		set_bit(BKEY_CACHED_DIRTY, &ck->flags);
		atomic_long_inc(&c->btree_key_cache.nr_dirty);

		if (bch2_nr_btree_keys_need_flush(c))
			kick_reclaim = true;
	}

	bch2_journal_pin_update(&c->journal, trans->journal_res.seq,
				&ck->journal, bch2_btree_key_cache_journal_flush);

	if (kick_reclaim)
		journal_reclaim_kick(&c->journal);
	return true;
}

static unsigned long bch2_btree_key_cache_scan(struct shrinker *shrink,
					   struct shrink_control *sc)
{
	struct bch_fs *c = container_of(shrink, struct bch_fs,
					btree_key_cache.shrink);
	struct btree_key_cache *bc = &c->btree_key_cache;
	struct bucket_table *tbl;
	struct bkey_cached *ck, *t;
	size_t scanned = 0, freed = 0, nr = sc->nr_to_scan;
	unsigned start, flags;
	int srcu_idx;

	/* Return -1 if we can't do anything right now */
	if (sc->gfp_mask & __GFP_FS)
		mutex_lock(&bc->lock);
	else if (!mutex_trylock(&bc->lock))
		return -1;

	srcu_idx = srcu_read_lock(&c->btree_trans_barrier);
	flags = memalloc_nofs_save();

	/*
	 * Newest freed entries are at the end of the list - once we hit one
	 * that's too new to be freed, we can bail out:
	 */
	list_for_each_entry_safe(ck, t, &bc->freed, list) {
		if (!poll_state_synchronize_srcu(&c->btree_trans_barrier,
						 ck->btree_trans_barrier_seq))
			break;

		list_del(&ck->list);
		kmem_cache_free(bch2_key_cache, ck);
		bc->nr_freed--;
		scanned++;
		freed++;
	}

	if (scanned >= nr)
		goto out;

	rcu_read_lock();
	tbl = rht_dereference_rcu(bc->table.tbl, &bc->table);
	if (bc->shrink_iter >= tbl->size)
		bc->shrink_iter = 0;
	start = bc->shrink_iter;

	do {
		struct rhash_head *pos, *next;

		pos = rht_ptr_rcu(rht_bucket(tbl, bc->shrink_iter));

		while (!rht_is_a_nulls(pos)) {
			next = rht_dereference_bucket_rcu(pos->next, tbl, bc->shrink_iter);
			ck = container_of(pos, struct bkey_cached, hash);

			if (test_bit(BKEY_CACHED_DIRTY, &ck->flags))
				goto next;

			if (test_bit(BKEY_CACHED_ACCESSED, &ck->flags))
				clear_bit(BKEY_CACHED_ACCESSED, &ck->flags);
			else if (bkey_cached_lock_for_evict(ck)) {
				bkey_cached_evict(bc, ck);
				bkey_cached_free(bc, ck);
			}

			scanned++;
			if (scanned >= nr)
				break;
next:
			pos = next;
		}

		bc->shrink_iter++;
		if (bc->shrink_iter >= tbl->size)
			bc->shrink_iter = 0;
	} while (scanned < nr && bc->shrink_iter != start);

	rcu_read_unlock();
out:
	memalloc_nofs_restore(flags);
	srcu_read_unlock(&c->btree_trans_barrier, srcu_idx);
	mutex_unlock(&bc->lock);

	return freed;
}

static unsigned long bch2_btree_key_cache_count(struct shrinker *shrink,
					    struct shrink_control *sc)
{
	struct bch_fs *c = container_of(shrink, struct bch_fs,
					btree_key_cache.shrink);
	struct btree_key_cache *bc = &c->btree_key_cache;
	long nr = atomic_long_read(&bc->nr_keys) -
		atomic_long_read(&bc->nr_dirty);

	return max(0L, nr);
}

void bch2_fs_btree_key_cache_exit(struct btree_key_cache *bc)
{
	struct bch_fs *c = container_of(bc, struct bch_fs, btree_key_cache);
	struct bucket_table *tbl;
	struct bkey_cached *ck, *n;
	struct rhash_head *pos;
	unsigned i;

	if (bc->shrink.list.next)
		unregister_shrinker(&bc->shrink);

	mutex_lock(&bc->lock);

	rcu_read_lock();
	tbl = rht_dereference_rcu(bc->table.tbl, &bc->table);
	if (tbl)
		for (i = 0; i < tbl->size; i++)
			rht_for_each_entry_rcu(ck, pos, tbl, i, hash) {
				bkey_cached_evict(bc, ck);
				list_add(&ck->list, &bc->freed);
			}
	rcu_read_unlock();

	list_for_each_entry_safe(ck, n, &bc->freed, list) {
		cond_resched();

		bch2_journal_pin_drop(&c->journal, &ck->journal);
		bch2_journal_preres_put(&c->journal, &ck->res);

		list_del(&ck->list);
		kfree(ck->k);
		kmem_cache_free(bch2_key_cache, ck);
	}

	BUG_ON(atomic_long_read(&bc->nr_dirty) &&
	       !bch2_journal_error(&c->journal) &&
	       test_bit(BCH_FS_WAS_RW, &c->flags));
	BUG_ON(atomic_long_read(&bc->nr_keys));

	mutex_unlock(&bc->lock);

	if (bc->table_init_done)
		rhashtable_destroy(&bc->table);
}

void bch2_fs_btree_key_cache_init_early(struct btree_key_cache *c)
{
	mutex_init(&c->lock);
	INIT_LIST_HEAD(&c->freed);
}

int bch2_fs_btree_key_cache_init(struct btree_key_cache *c)
{
	int ret;

	ret = rhashtable_init(&c->table, &bch2_btree_key_cache_params);
	if (ret)
		return ret;

	c->table_init_done = true;

	c->shrink.seeks			= 1;
	c->shrink.count_objects		= bch2_btree_key_cache_count;
	c->shrink.scan_objects		= bch2_btree_key_cache_scan;
	return register_shrinker(&c->shrink);
}

void bch2_btree_key_cache_to_text(struct printbuf *out, struct btree_key_cache *c)
{
	pr_buf(out, "nr_freed:\t%zu\n",	c->nr_freed);
	pr_buf(out, "nr_keys:\t%zu\n",	atomic_long_read(&c->nr_keys));
	pr_buf(out, "nr_dirty:\t%zu\n",	atomic_long_read(&c->nr_dirty));
}

void bch2_btree_key_cache_exit(void)
{
	if (bch2_key_cache)
		kmem_cache_destroy(bch2_key_cache);
}

int __init bch2_btree_key_cache_init(void)
{
	bch2_key_cache = KMEM_CACHE(bkey_cached, 0);
	if (!bch2_key_cache)
		return -ENOMEM;

	return 0;
}
