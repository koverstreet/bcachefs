// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "bbpos.h"
#include "bkey_buf.h"
#include "btree_cache.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_locking.h"
#include "debug.h"
#include "errcode.h"
#include "error.h"
#include "journal.h"
#include "trace.h"

#include <linux/prefetch.h>
#include <linux/sched/mm.h>
#include <linux/seq_buf.h>
#include <linux/swap.h>

const char * const bch2_btree_node_flags[] = {
	"typebit",
	"typebit",
	"typebit",
#define x(f)	[BTREE_NODE_##f] = #f,
	BTREE_FLAGS()
#undef x
	NULL
};

void bch2_recalc_btree_reserve(struct bch_fs *c)
{
	unsigned reserve = 16;

	if (!c->btree_roots_known[0].b)
		reserve += 8;

	for (unsigned i = 0; i < btree_id_nr_alive(c); i++) {
		struct btree_root *r = bch2_btree_id_root(c, i);

		if (r->b)
			reserve += min_t(unsigned, 1, r->b->c.level) * 8;
	}

	c->btree_cache.nr_reserve = reserve;
}

static inline size_t btree_cache_can_free(struct btree_cache_list *list)
{
	struct btree_cache *bc = container_of(list, struct btree_cache, live[list->idx]);

	size_t can_free = list->nr;
	if (!list->idx)
		can_free = max_t(ssize_t, 0, can_free - bc->nr_reserve);
	return can_free;
}

static void btree_node_to_freedlist(struct btree_cache *bc, struct btree *b)
{
	BUG_ON(!list_empty(&b->list));

	if (b->c.lock.readers)
		list_add(&b->list, &bc->freed_pcpu);
	else
		list_add(&b->list, &bc->freed_nonpcpu);
}

static void __bch2_btree_node_to_freelist(struct btree_cache *bc, struct btree *b)
{
	BUG_ON(!list_empty(&b->list));
	BUG_ON(!b->data);

	bc->nr_freeable++;
	list_add(&b->list, &bc->freeable);
}

void bch2_btree_node_to_freelist(struct bch_fs *c, struct btree *b)
{
	struct btree_cache *bc = &c->btree_cache;

	scoped_guard(mutex, &bc->lock)
		__bch2_btree_node_to_freelist(bc, b);

	six_unlock_write(&b->c.lock);
	six_unlock_intent(&b->c.lock);
}

void __btree_node_data_free(struct btree *b)
{
	BUG_ON(!list_empty(&b->list));
	BUG_ON(btree_node_hashed(b));

	/*
	 * This should really be done in slub/vmalloc, but we're using the
	 * kmalloc_large() path, so we're working around a slub bug by doing
	 * this here:
	 */
	if (b->data)
		mm_account_reclaimed_pages(btree_buf_bytes(b) / PAGE_SIZE);
	if (b->aux_data)
		mm_account_reclaimed_pages(btree_aux_data_bytes(b) / PAGE_SIZE);

	EBUG_ON(btree_node_write_in_flight(b));

	clear_btree_node_just_written(b);

	kvfree(b->data);
	b->data = NULL;
#ifdef __KERNEL__
	kvfree(b->aux_data);
#else
	munmap(b->aux_data, btree_aux_data_bytes(b));
#endif
	b->aux_data = NULL;
}

static void btree_node_data_free(struct btree_cache *bc, struct btree *b)
{
	BUG_ON(list_empty(&b->list));
	list_del_init(&b->list);

	__btree_node_data_free(b);

	--bc->nr_freeable;
	btree_node_to_freedlist(bc, b);
}

static int bch2_btree_cache_cmp_fn(struct rhashtable_compare_arg *arg,
				   const void *obj)
{
	const struct btree *b = obj;
	const u64 *v = arg->key;

	return b->hash_val == *v ? 0 : 1;
}

static const struct rhashtable_params bch_btree_cache_params = {
	.head_offset		= offsetof(struct btree, hash),
	.key_offset		= offsetof(struct btree, hash_val),
	.key_len		= sizeof(u64),
	.obj_cmpfn		= bch2_btree_cache_cmp_fn,
	.automatic_shrinking	= true,
};

static int btree_node_data_alloc(struct bch_fs *c, struct btree *b, gfp_t gfp)
{
	BUG_ON(b->data || b->aux_data);

	gfp |= __GFP_ACCOUNT|__GFP_RECLAIMABLE;

	b->data = kvmalloc(btree_buf_bytes(b), gfp);
	if (!b->data)
		return bch_err_throw(c, ENOMEM_btree_node_mem_alloc);
#ifdef __KERNEL__
	b->aux_data = kvmalloc(btree_aux_data_bytes(b), gfp);
#else
	b->aux_data = mmap(NULL, btree_aux_data_bytes(b),
			   PROT_READ|PROT_WRITE|PROT_EXEC,
			   MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	if (b->aux_data == MAP_FAILED)
		b->aux_data = NULL;
#endif
	if (!b->aux_data) {
		kvfree(b->data);
		b->data = NULL;
		return bch_err_throw(c, ENOMEM_btree_node_mem_alloc);
	}

	return 0;
}

static struct btree *__btree_node_mem_alloc(struct bch_fs *c, gfp_t gfp)
{
	struct btree *b;

	b = kzalloc(sizeof(struct btree), gfp);
	if (!b)
		return NULL;

	bkey_btree_ptr_init(&b->key);
	INIT_LIST_HEAD(&b->list);
	INIT_LIST_HEAD(&b->write_blocked);
	b->byte_order = ilog2(c->opts.btree_node_size);
	return b;
}

struct btree *__bch2_btree_node_mem_alloc(struct bch_fs *c)
{
	struct btree *b = __btree_node_mem_alloc(c, GFP_KERNEL);
	if (!b)
		return NULL;

	if (btree_node_data_alloc(c, b, GFP_KERNEL)) {
		kfree(b);
		return NULL;
	}

	bch2_btree_lock_init(&b->c, 0, GFP_KERNEL);
	return b;
}

static inline bool __btree_node_pinned(struct btree_cache *bc, struct btree *b)
{
	struct bbpos pos = BBPOS(b->c.btree_id, b->key.k.p);

	u64 mask = bc->pinned_nodes_mask[!!b->c.level];

	return ((mask & BIT_ULL(b->c.btree_id)) &&
		bbpos_cmp(bc->pinned_nodes_start, pos) < 0 &&
		bbpos_cmp(bc->pinned_nodes_end, pos) >= 0);
}

void bch2_node_pin(struct bch_fs *c, struct btree *b)
{
	struct btree_cache *bc = &c->btree_cache;

	guard(mutex)(&bc->lock);
	if (!btree_node_is_root(c, b) && !btree_node_pinned(b)) {
		set_btree_node_pinned(b);
		list_move(&b->list, &bc->live[1].list);
		bc->live[0].nr--;
		bc->live[1].nr++;
	}
}

void bch2_btree_cache_unpin(struct bch_fs *c)
{
	struct btree_cache *bc = &c->btree_cache;
	struct btree *b, *n;

	guard(mutex)(&bc->lock);
	c->btree_cache.pinned_nodes_mask[0] = 0;
	c->btree_cache.pinned_nodes_mask[1] = 0;

	list_for_each_entry_safe(b, n, &bc->live[1].list, list) {
		clear_btree_node_pinned(b);
		list_move(&b->list, &bc->live[0].list);
		bc->live[0].nr++;
		bc->live[1].nr--;
	}
}

/* Btree in memory cache - hash table */

void __bch2_btree_node_hash_remove(struct btree_cache *bc, struct btree *b)
{
	lockdep_assert_held(&bc->lock);

	int ret = rhashtable_remove_fast(&bc->table, &b->hash, bch_btree_cache_params);
	BUG_ON(ret);

	/* Cause future lookups for this node to fail: */
	b->hash_val = 0;

	if (b->c.btree_id < BTREE_ID_NR)
		--bc->nr_by_btree[b->c.btree_id];
	--bc->live[btree_node_pinned(b)].nr;
	list_del_init(&b->list);
}

void bch2_btree_node_hash_remove(struct btree_cache *bc, struct btree *b)
{
	__bch2_btree_node_hash_remove(bc, b);
	__bch2_btree_node_to_freelist(bc, b);
}

int __bch2_btree_node_hash_insert(struct btree_cache *bc, struct btree *b)
{
	BUG_ON(!list_empty(&b->list));
	BUG_ON(b->hash_val);

	b->hash_val = btree_ptr_hash_val(&b->key);
	int ret = rhashtable_lookup_insert_fast(&bc->table, &b->hash,
						bch_btree_cache_params);
	if (ret)
		return ret;

	if (b->c.btree_id < BTREE_ID_NR)
		bc->nr_by_btree[b->c.btree_id]++;

	bool p = __btree_node_pinned(bc, b);
	mod_bit(BTREE_NODE_pinned, &b->flags, p);

	list_add_tail(&b->list, &bc->live[p].list);
	bc->live[p].nr++;
	return 0;
}

int bch2_btree_node_hash_insert(struct btree_cache *bc, struct btree *b,
				unsigned level, enum btree_id id)
{
	b->c.level	= level;
	b->c.btree_id	= id;

	guard(mutex)(&bc->lock);
	return __bch2_btree_node_hash_insert(bc, b);
}

void bch2_btree_node_update_key_early(struct btree_trans *trans,
				      enum btree_id btree, unsigned level,
				      struct bkey_s_c old, struct bkey_i *new)
{
	struct bch_fs *c = trans->c;
	struct btree *b;
	struct bkey_buf tmp;
	int ret;

	bch2_bkey_buf_init(&tmp);
	bch2_bkey_buf_reassemble(&tmp, c, old);

	b = bch2_btree_node_get_noiter(trans, tmp.k, btree, level, true);
	if (!IS_ERR_OR_NULL(b)) {
		guard(mutex)(&c->btree_cache.lock);

		__bch2_btree_node_hash_remove(&c->btree_cache, b);

		bkey_copy(&b->key, new);
		ret = __bch2_btree_node_hash_insert(&c->btree_cache, b);
		BUG_ON(ret);

		six_unlock_read(&b->c.lock);
	}

	bch2_bkey_buf_exit(&tmp, c);
}

__flatten
static inline struct btree *btree_cache_find(struct btree_cache *bc,
				     const struct bkey_i *k)
{
	u64 v = btree_ptr_hash_val(k);

	return rhashtable_lookup_fast(&bc->table, &v, bch_btree_cache_params);
}

static int __btree_node_reclaim_checks(struct bch_fs *c, struct btree *b,
				       bool flush, bool locked)
{
	struct btree_cache *bc = &c->btree_cache;

	lockdep_assert_held(&bc->lock);

	if (btree_node_noevict(b)) {
		bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_noevict]++;
		return bch_err_throw(c, ENOMEM_btree_node_reclaim);
	}
	if (btree_node_write_blocked(b)) {
		bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_write_blocked]++;
		return bch_err_throw(c, ENOMEM_btree_node_reclaim);
	}
	if (btree_node_will_make_reachable(b)) {
		bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_will_make_reachable]++;
		return bch_err_throw(c, ENOMEM_btree_node_reclaim);
	}

	if (btree_node_dirty(b)) {
		if (!flush) {
			bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_dirty]++;
			return bch_err_throw(c, ENOMEM_btree_node_reclaim);
		}

		if (locked) {
			/*
			 * Using the underscore version because we don't want to compact
			 * bsets after the write, since this node is about to be evicted
			 * - unless btree verify mode is enabled, since it runs out of
			 * the post write cleanup:
			 */
			if (static_branch_unlikely(&bch2_verify_btree_ondisk))
				bch2_btree_node_write(c, b, SIX_LOCK_intent,
						      BTREE_WRITE_cache_reclaim);
			else
				__bch2_btree_node_write(c, b,
							BTREE_WRITE_cache_reclaim);
		}
	}

	if (b->flags & ((1U << BTREE_NODE_read_in_flight)|
			(1U << BTREE_NODE_write_in_flight))) {
		if (!flush) {
			if (btree_node_read_in_flight(b))
				bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_read_in_flight]++;
			else if (btree_node_write_in_flight(b))
				bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_write_in_flight]++;
			return bch_err_throw(c, ENOMEM_btree_node_reclaim);
		}

		if (locked)
			return -EINTR;

		/* XXX: waiting on IO with btree cache lock held */
		bch2_btree_node_wait_on_read(b);
		bch2_btree_node_wait_on_write(b);
	}

	return 0;
}

/*
 * this version is for btree nodes that have already been freed (we're not
 * reaping a real btree node)
 */
static int __btree_node_reclaim(struct bch_fs *c, struct btree *b, bool flush)
{
	struct btree_cache *bc = &c->btree_cache;
	int ret = 0;

	lockdep_assert_held(&bc->lock);
retry_unlocked:
	ret = __btree_node_reclaim_checks(c, b, flush, false);
	if (ret)
		return ret;

	if (!six_trylock_intent(&b->c.lock)) {
		bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_lock_intent]++;
		return bch_err_throw(c, ENOMEM_btree_node_reclaim);
	}

	if (!six_trylock_write(&b->c.lock)) {
		bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_lock_write]++;
		six_unlock_intent(&b->c.lock);
		return bch_err_throw(c, ENOMEM_btree_node_reclaim);
	}

	/* recheck under lock */
	ret = __btree_node_reclaim_checks(c, b, flush, true);
	if (ret) {
		six_unlock_write(&b->c.lock);
		six_unlock_intent(&b->c.lock);
		if (ret == -EINTR)
			goto retry_unlocked;
		return ret;
	}

	if (b->hash_val && !ret)
		trace_btree_node(c, b, btree_cache_reap);

	return 0;
}

static int btree_node_reclaim(struct bch_fs *c, struct btree *b)
{
	return __btree_node_reclaim(c, b, false);
}

static int btree_node_write_and_reclaim(struct bch_fs *c, struct btree *b)
{
	return __btree_node_reclaim(c, b, true);
}

static unsigned long bch2_btree_cache_scan(struct shrinker *shrink,
					   struct shrink_control *sc)
{
	struct btree_cache_list *list = shrink->private_data;
	struct btree_cache *bc = container_of(list, struct btree_cache, live[list->idx]);
	struct bch_fs *c = container_of(bc, struct bch_fs, btree_cache);
	struct btree *b, *t;
	unsigned long nr = sc->nr_to_scan;
	unsigned long can_free = 0;
	unsigned long freed = 0;
	unsigned long touched = 0;
	unsigned i, flags;
	unsigned long ret = SHRINK_STOP;
	bool trigger_writes = atomic_long_read(&bc->nr_dirty) + nr >= list->nr * 3 / 4;

	if (static_branch_unlikely(&bch2_btree_shrinker_disabled))
		return SHRINK_STOP;

	mutex_lock(&bc->lock);
	flags = memalloc_nofs_save();

	/*
	 * It's _really_ critical that we don't free too many btree nodes - we
	 * have to always leave ourselves a reserve. The reserve is how we
	 * guarantee that allocating memory for a new btree node can always
	 * succeed, so that inserting keys into the btree can always succeed and
	 * IO can always make forward progress:
	 */
	can_free = btree_cache_can_free(list);
	if (nr > can_free) {
		bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_cache_reserve] += nr - can_free;
		nr = can_free;
	}

	i = 0;
	list_for_each_entry_safe(b, t, &bc->freeable, list) {
		/*
		 * Leave a few nodes on the freeable list, so that a btree split
		 * won't have to hit the system allocator:
		 */
		if (++i <= 3)
			continue;

		touched++;

		if (touched >= nr)
			goto out;

		if (!btree_node_reclaim(c, b)) {
			btree_node_data_free(bc, b);
			six_unlock_write(&b->c.lock);
			six_unlock_intent(&b->c.lock);
			freed++;
			bc->nr_freed++;
		}
	}
restart:
	list_for_each_entry_safe(b, t, &list->list, list) {
		touched++;

		if (btree_node_accessed(b)) {
			clear_btree_node_accessed(b);
			bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_access_bit]++;
			--touched;
		} else if (!btree_node_reclaim(c, b)) {
			__bch2_btree_node_hash_remove(bc, b);
			__btree_node_data_free(b);
			btree_node_to_freedlist(bc, b);

			freed++;
			bc->nr_freed++;

			six_unlock_write(&b->c.lock);
			six_unlock_intent(&b->c.lock);

			if (freed == nr)
				goto out_rotate;
		} else if (trigger_writes &&
			   btree_node_dirty(b) &&
			   !btree_node_will_make_reachable(b) &&
			   !btree_node_write_blocked(b) &&
			   six_trylock_read(&b->c.lock)) {
			list_move(&list->list, &b->list);
			mutex_unlock(&bc->lock);
			__bch2_btree_node_write(c, b, BTREE_WRITE_cache_reclaim);
			six_unlock_read(&b->c.lock);
			if (touched >= nr)
				goto out_nounlock;
			mutex_lock(&bc->lock);
			goto restart;
		}

		if (touched >= nr)
			break;
	}
out_rotate:
	if (&t->list != &list->list)
		list_move_tail(&list->list, &t->list);
out:
	mutex_unlock(&bc->lock);
out_nounlock:
	ret = freed;
	memalloc_nofs_restore(flags);
	trace_and_count(c, btree_cache_scan, sc->nr_to_scan, can_free, ret);
	return ret;
}

static unsigned long bch2_btree_cache_count(struct shrinker *shrink,
					    struct shrink_control *sc)
{
	struct btree_cache_list *list = shrink->private_data;

	if (static_branch_unlikely(&bch2_btree_shrinker_disabled))
		return 0;

	return btree_cache_can_free(list);
}

static void bch2_btree_cache_shrinker_to_text(struct seq_buf *s, struct shrinker *shrink)
{
	struct btree_cache_list *list = shrink->private_data;
	struct btree_cache *bc = container_of(list, struct btree_cache, live[list->idx]);

	char *cbuf;
	size_t buflen = seq_buf_get_buf(s, &cbuf);
	struct printbuf out = PRINTBUF_EXTERN(cbuf, buflen);

	bch2_btree_cache_to_text(&out, bc);
	seq_buf_commit(s, out.pos);
}

void bch2_fs_btree_cache_exit(struct bch_fs *c)
{
	struct btree_cache *bc = &c->btree_cache;
	struct btree *b, *t;
	unsigned long flags;

	shrinker_free(bc->live[1].shrink);
	shrinker_free(bc->live[0].shrink);

	/* vfree() can allocate memory: */
	flags = memalloc_nofs_save();
	mutex_lock(&bc->lock);

	if (c->verify_data)
		list_move(&c->verify_data->list, &bc->live[0].list);

	kvfree(c->verify_ondisk);

	for (unsigned i = 0; i < btree_id_nr_alive(c); i++) {
		struct btree_root *r = bch2_btree_id_root(c, i);

		if (r->b)
			list_add(&r->b->list, &bc->live[0].list);
	}

	list_for_each_entry_safe(b, t, &bc->live[1].list, list)
		bch2_btree_node_hash_remove(bc, b);
	list_for_each_entry_safe(b, t, &bc->live[0].list, list)
		bch2_btree_node_hash_remove(bc, b);

	list_for_each_entry_safe(b, t, &bc->freeable, list) {
		BUG_ON(btree_node_read_in_flight(b) ||
		       btree_node_write_in_flight(b));

		btree_node_data_free(bc, b);
		cond_resched();
	}

	BUG_ON(!bch2_journal_error(&c->journal) &&
	       atomic_long_read(&c->btree_cache.nr_dirty));

	list_splice(&bc->freed_pcpu, &bc->freed_nonpcpu);

	list_for_each_entry_safe(b, t, &bc->freed_nonpcpu, list) {
		list_del(&b->list);
		six_lock_exit(&b->c.lock);
		kfree(b);
	}

	mutex_unlock(&bc->lock);
	memalloc_nofs_restore(flags);

	for (unsigned i = 0; i < ARRAY_SIZE(bc->nr_by_btree); i++)
		BUG_ON(bc->nr_by_btree[i]);
	BUG_ON(bc->live[0].nr);
	BUG_ON(bc->live[1].nr);
	BUG_ON(bc->nr_freeable);

	if (bc->table_init_done)
		rhashtable_destroy(&bc->table);
}

int bch2_fs_btree_cache_init(struct bch_fs *c)
{
	struct btree_cache *bc = &c->btree_cache;
	struct shrinker *shrink;
	unsigned i;
	int ret = 0;

	ret = rhashtable_init(&bc->table, &bch_btree_cache_params);
	if (ret)
		goto err;

	bc->table_init_done = true;

	bch2_recalc_btree_reserve(c);

	for (i = 0; i < bc->nr_reserve; i++) {
		struct btree *b = __bch2_btree_node_mem_alloc(c);
		if (!b)
			goto err;
		__bch2_btree_node_to_freelist(bc, b);
	}

	list_splice_init(&bc->live[0].list, &bc->freeable);

	mutex_init(&c->verify_lock);

	shrink = shrinker_alloc(0, "%s-btree_cache", c->name);
	if (!shrink)
		goto err;
	bc->live[0].shrink	= shrink;
	shrink->count_objects	= bch2_btree_cache_count;
	shrink->scan_objects	= bch2_btree_cache_scan;
	shrink->to_text		= bch2_btree_cache_shrinker_to_text;
	shrink->seeks		= 2;
	shrink->private_data	= &bc->live[0];
	shrinker_register(shrink);

	shrink = shrinker_alloc(0, "%s-btree_cache-pinned", c->name);
	if (!shrink)
		goto err;
	bc->live[1].shrink	= shrink;
	shrink->count_objects	= bch2_btree_cache_count;
	shrink->scan_objects	= bch2_btree_cache_scan;
	shrink->to_text		= bch2_btree_cache_shrinker_to_text;
	shrink->seeks		= 8;
	shrink->private_data	= &bc->live[1];
	shrinker_register(shrink);

	return 0;
err:
	return bch_err_throw(c, ENOMEM_fs_btree_cache_init);
}

void bch2_fs_btree_cache_init_early(struct btree_cache *bc)
{
	mutex_init(&bc->lock);
	for (unsigned i = 0; i < ARRAY_SIZE(bc->live); i++) {
		bc->live[i].idx = i;
		INIT_LIST_HEAD(&bc->live[i].list);
	}
	INIT_LIST_HEAD(&bc->freeable);
	INIT_LIST_HEAD(&bc->freed_pcpu);
	INIT_LIST_HEAD(&bc->freed_nonpcpu);
}

/*
 * We can only have one thread cannibalizing other cached btree nodes at a time,
 * or we'll deadlock. We use an open coded mutex to ensure that, which a
 * cannibalize_bucket() will take. This means every time we unlock the root of
 * the btree, we need to release this lock if we have it held.
 */
void bch2_btree_cache_cannibalize_unlock(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	struct btree_cache *bc = &c->btree_cache;

	if (bc->alloc_lock == current) {
		trace_and_count(c, btree_cache_cannibalize_unlock, trans);
		bc->alloc_lock = NULL;
		closure_wake_up(&bc->alloc_wait);
	}
}

int bch2_btree_cache_cannibalize_lock(struct btree_trans *trans, struct closure *cl)
{
	struct bch_fs *c = trans->c;
	struct btree_cache *bc = &c->btree_cache;
	struct task_struct *old;

	old = NULL;
	if (try_cmpxchg(&bc->alloc_lock, &old, current) || old == current)
		goto success;

	if (!cl) {
		trace_and_count(c, btree_cache_cannibalize_lock_fail, trans);
		return bch_err_throw(c, ENOMEM_btree_cache_cannibalize_lock);
	}

	closure_wait(&bc->alloc_wait, cl);

	/* Try again, after adding ourselves to waitlist */
	old = NULL;
	if (try_cmpxchg(&bc->alloc_lock, &old, current) || old == current) {
		/* We raced */
		closure_wake_up(&bc->alloc_wait);
		goto success;
	}

	trace_and_count(c, btree_cache_cannibalize_lock_fail, trans);
	return bch_err_throw(c, btree_cache_cannibalize_lock_blocked);

success:
	trace_and_count(c, btree_cache_cannibalize_lock, trans);
	return 0;
}

static struct btree *btree_node_cannibalize(struct bch_fs *c)
{
	struct btree_cache *bc = &c->btree_cache;
	struct btree *b;

	for (unsigned i = 0; i < ARRAY_SIZE(bc->live); i++)
		list_for_each_entry_reverse(b, &bc->live[i].list, list)
			if (!btree_node_reclaim(c, b))
				return b;

	while (1) {
		for (unsigned i = 0; i < ARRAY_SIZE(bc->live); i++)
			list_for_each_entry_reverse(b, &bc->live[i].list, list)
				if (!btree_node_write_and_reclaim(c, b))
					return b;

		/*
		 * Rare case: all nodes were intent-locked.
		 * Just busy-wait.
		 */
		WARN_ONCE(1, "btree cache cannibalize failed\n");
		cond_resched();
	}
}

struct btree *bch2_btree_node_mem_alloc(struct btree_trans *trans, bool pcpu_read_locks)
{
	struct bch_fs *c = trans->c;
	struct btree_cache *bc = &c->btree_cache;
	struct list_head *freed = pcpu_read_locks
		? &bc->freed_pcpu
		: &bc->freed_nonpcpu;
	struct btree *b, *b2;
	u64 start_time = local_clock();

	mutex_lock(&bc->lock);

	/*
	 * We never free struct btree itself, just the memory that holds the on
	 * disk node. Check the freed list before allocating a new one:
	 */
	list_for_each_entry(b, freed, list)
		if (!btree_node_reclaim(c, b)) {
			list_del_init(&b->list);
			goto got_node;
		}

	b = __btree_node_mem_alloc(c, GFP_NOWAIT);
	if (b) {
		bch2_btree_lock_init(&b->c, pcpu_read_locks ? SIX_LOCK_INIT_PCPU : 0, GFP_NOWAIT);
	} else {
		mutex_unlock(&bc->lock);
		bch2_trans_unlock(trans);
		b = __btree_node_mem_alloc(c, GFP_KERNEL);
		if (!b)
			goto err;
		bch2_btree_lock_init(&b->c, pcpu_read_locks ? SIX_LOCK_INIT_PCPU : 0, GFP_KERNEL);
		mutex_lock(&bc->lock);
	}

	BUG_ON(!six_trylock_intent(&b->c.lock));
	BUG_ON(!six_trylock_write(&b->c.lock));

got_node:
	/*
	 * btree_free() doesn't free memory; it sticks the node on the end of
	 * the list. Check if there's any freed nodes there:
	 */
	list_for_each_entry(b2, &bc->freeable, list)
		if (!btree_node_reclaim(c, b2)) {
			swap(b->data, b2->data);
			swap(b->aux_data, b2->aux_data);

			list_del_init(&b2->list);
			--bc->nr_freeable;
			btree_node_to_freedlist(bc, b2);
			mutex_unlock(&bc->lock);

			six_unlock_write(&b2->c.lock);
			six_unlock_intent(&b2->c.lock);
			goto got_mem;
		}

	mutex_unlock(&bc->lock);

	if (btree_node_data_alloc(c, b, GFP_NOWAIT)) {
		bch2_trans_unlock(trans);
		if (btree_node_data_alloc(c, b, GFP_KERNEL|__GFP_NOWARN))
			goto err;
	}

got_mem:
	BUG_ON(!list_empty(&b->list));
	BUG_ON(btree_node_hashed(b));
	BUG_ON(btree_node_dirty(b));
	BUG_ON(btree_node_write_in_flight(b));
out:
	b->flags		= 0;
	b->written		= 0;
	b->nsets		= 0;
	b->sib_u64s[0]		= 0;
	b->sib_u64s[1]		= 0;
	b->whiteout_u64s	= 0;
	bch2_btree_keys_init(b);

	bch2_time_stats_update(&c->times[BCH_TIME_btree_node_mem_alloc],
			       start_time);

	int ret = bch2_trans_relock(trans);
	if (unlikely(ret)) {
		bch2_btree_node_to_freelist(c, b);
		return ERR_PTR(ret);
	}

	return b;
err:
	mutex_lock(&bc->lock);

	/* Try to cannibalize another cached btree node: */
	if (bc->alloc_lock == current) {
		b2 = btree_node_cannibalize(c);
		clear_btree_node_just_written(b2);
		__bch2_btree_node_hash_remove(bc, b2);

		if (b) {
			swap(b->data, b2->data);
			swap(b->aux_data, b2->aux_data);
			btree_node_to_freedlist(bc, b2);
			six_unlock_write(&b2->c.lock);
			six_unlock_intent(&b2->c.lock);
		} else {
			b = b2;
		}

		BUG_ON(!list_empty(&b->list));
		mutex_unlock(&bc->lock);

		trace_and_count(c, btree_cache_cannibalize, trans);
		goto out;
	}

	mutex_unlock(&bc->lock);
	return ERR_PTR(-BCH_ERR_ENOMEM_btree_node_mem_alloc);
}

/* Slowpath, don't want it inlined into btree_iter_traverse() */
static noinline struct btree *bch2_btree_node_fill(struct btree_trans *trans,
				struct btree_path *path,
				const struct bkey_i *k,
				enum btree_id btree_id,
				unsigned level,
				enum six_lock_type lock_type,
				bool sync)
{
	struct bch_fs *c = trans->c;
	struct btree_cache *bc = &c->btree_cache;
	struct btree *b;

	if (unlikely(level >= BTREE_MAX_DEPTH)) {
		int ret = bch2_fs_topology_error(c, "attempting to get btree node at level %u, >= max depth %u",
						 level, BTREE_MAX_DEPTH);
		return ERR_PTR(ret);
	}

	if (unlikely(!bkey_is_btree_ptr(&k->k))) {
		CLASS(printbuf, buf)();
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(k));

		int ret = bch2_fs_topology_error(c, "attempting to get btree node with non-btree key %s", buf.buf);
		return ERR_PTR(ret);
	}

	if (unlikely(k->k.u64s > BKEY_BTREE_PTR_U64s_MAX)) {
		CLASS(printbuf, buf)();
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(k));

		int ret = bch2_fs_topology_error(c, "attempting to get btree node with too big key %s", buf.buf);
		return ERR_PTR(ret);
	}

	/*
	 * Parent node must be locked, else we could read in a btree node that's
	 * been freed:
	 */
	if (path && !bch2_btree_node_relock(trans, path, level + 1)) {
		trace_and_count(c, trans_restart_relock_parent_for_fill, trans, _THIS_IP_, path);
		return ERR_PTR(btree_trans_restart(trans, BCH_ERR_transaction_restart_fill_relock));
	}

	b = bch2_btree_node_mem_alloc(trans, level != 0);

	if (bch2_err_matches(PTR_ERR_OR_ZERO(b), ENOMEM)) {
		if (!path)
			return b;

		trans->memory_allocation_failure = true;
		trace_and_count(c, trans_restart_memory_allocation_failure, trans, _THIS_IP_, path);
		return ERR_PTR(btree_trans_restart(trans, BCH_ERR_transaction_restart_fill_mem_alloc_fail));
	}

	if (IS_ERR(b))
		return b;

	bkey_copy(&b->key, k);
	if (bch2_btree_node_hash_insert(bc, b, level, btree_id)) {
		/* raced with another fill: */

		/* mark as unhashed... */
		b->hash_val = 0;

		mutex_lock(&bc->lock);
		__bch2_btree_node_to_freelist(bc, b);
		mutex_unlock(&bc->lock);

		six_unlock_write(&b->c.lock);
		six_unlock_intent(&b->c.lock);
		return NULL;
	}

	set_btree_node_read_in_flight(b);
	six_unlock_write(&b->c.lock);

	if (path) {
		u32 seq = six_lock_seq(&b->c.lock);

		/* Unlock before doing IO: */
		six_unlock_intent(&b->c.lock);
		bch2_trans_unlock(trans);

		bch2_btree_node_read(trans, b, sync);

		int ret = bch2_trans_relock(trans);
		if (ret)
			return ERR_PTR(ret);

		if (!sync)
			return NULL;

		if (!six_relock_type(&b->c.lock, lock_type, seq))
			b = NULL;
	} else {
		bch2_btree_node_read(trans, b, sync);
		if (lock_type == SIX_LOCK_read)
			six_lock_downgrade(&b->c.lock);
	}

	return b;
}

static noinline void btree_bad_header(struct bch_fs *c, struct btree *b)
{
	if (c->recovery.pass_done < BCH_RECOVERY_PASS_check_allocations)
		return;

	CLASS(printbuf, buf)();
	prt_printf(&buf,
		   "btree node header doesn't match ptr: ");
	bch2_btree_id_level_to_text(&buf, b->c.btree_id, b->c.level);
	prt_str(&buf, "\nptr: ");
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));

	prt_str(&buf, "\nheader: ");
	bch2_btree_id_level_to_text(&buf, BTREE_NODE_ID(b->data), BTREE_NODE_LEVEL(b->data));
	prt_str(&buf, "\nmin ");
	bch2_bpos_to_text(&buf, b->data->min_key);

	prt_printf(&buf, "\nmax ");
	bch2_bpos_to_text(&buf, b->data->max_key);

	bch2_fs_topology_error(c, "%s", buf.buf);
}

static inline void btree_check_header(struct bch_fs *c, struct btree *b)
{
	if (b->c.btree_id != BTREE_NODE_ID(b->data) ||
	    b->c.level != BTREE_NODE_LEVEL(b->data) ||
	    !bpos_eq(b->data->max_key, b->key.k.p) ||
	    (b->key.k.type == KEY_TYPE_btree_ptr_v2 &&
	     !bpos_eq(b->data->min_key,
		      bkey_i_to_btree_ptr_v2(&b->key)->v.min_key)))
		btree_bad_header(c, b);
}

static struct btree *__bch2_btree_node_get(struct btree_trans *trans, struct btree_path *path,
					   const struct bkey_i *k, unsigned level,
					   enum six_lock_type lock_type,
					   unsigned long trace_ip)
{
	struct bch_fs *c = trans->c;
	struct btree_cache *bc = &c->btree_cache;
	struct btree *b;
	bool need_relock = false;
	int ret;

	EBUG_ON(level >= BTREE_MAX_DEPTH);
retry:
	b = btree_cache_find(bc, k);
	if (unlikely(!b)) {
		/*
		 * We must have the parent locked to call bch2_btree_node_fill(),
		 * else we could read in a btree node from disk that's been
		 * freed:
		 */
		b = bch2_btree_node_fill(trans, path, k, path->btree_id,
					 level, lock_type, true);
		need_relock = true;

		/* We raced and found the btree node in the cache */
		if (!b)
			goto retry;

		if (IS_ERR(b))
			return b;
	} else {
		if (btree_node_read_locked(path, level + 1))
			btree_node_unlock(trans, path, level + 1);

		ret = btree_node_lock(trans, path, &b->c, level, lock_type, trace_ip);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			return ERR_PTR(ret);

		BUG_ON(ret);

		if (unlikely(b->hash_val != btree_ptr_hash_val(k) ||
			     b->c.level != level ||
			     race_fault())) {
			six_unlock_type(&b->c.lock, lock_type);
			if (bch2_btree_node_relock(trans, path, level + 1))
				goto retry;

			trace_and_count(c, trans_restart_btree_node_reused, trans, trace_ip, path);
			return ERR_PTR(btree_trans_restart(trans, BCH_ERR_transaction_restart_lock_node_reused));
		}

		/* avoid atomic set bit if it's not needed: */
		if (!btree_node_accessed(b))
			set_btree_node_accessed(b);
	}

	if (unlikely(btree_node_read_in_flight(b))) {
		u32 seq = six_lock_seq(&b->c.lock);

		six_unlock_type(&b->c.lock, lock_type);
		bch2_trans_unlock(trans);
		need_relock = true;

		bch2_btree_node_wait_on_read(b);

		ret = bch2_trans_relock(trans);
		if (ret)
			return ERR_PTR(ret);

		/*
		 * should_be_locked is not set on this path yet, so we need to
		 * relock it specifically:
		 */
		if (!six_relock_type(&b->c.lock, lock_type, seq))
			goto retry;
	}

	if (unlikely(need_relock)) {
		ret = bch2_trans_relock(trans) ?:
			bch2_btree_path_relock_intent(trans, path);
		if (ret) {
			six_unlock_type(&b->c.lock, lock_type);
			return ERR_PTR(ret);
		}
	}

	prefetch(b->aux_data);

	for_each_bset(b, t) {
		void *p = (u64 *) b->aux_data + t->aux_data_offset;

		prefetch(p + L1_CACHE_BYTES * 0);
		prefetch(p + L1_CACHE_BYTES * 1);
		prefetch(p + L1_CACHE_BYTES * 2);
	}

	if (unlikely(btree_node_read_error(b))) {
		six_unlock_type(&b->c.lock, lock_type);
		return ERR_PTR(-BCH_ERR_btree_node_read_err_cached);
	}

	EBUG_ON(b->c.btree_id != path->btree_id);
	EBUG_ON(BTREE_NODE_LEVEL(b->data) != level);
	btree_check_header(c, b);

	return b;
}

/**
 * bch2_btree_node_get - find a btree node in the cache and lock it, reading it
 * in from disk if necessary.
 *
 * @trans:	btree transaction object
 * @path:	btree_path being traversed
 * @k:		pointer to btree node (generally KEY_TYPE_btree_ptr_v2)
 * @level:	level of btree node being looked up (0 == leaf node)
 * @lock_type:	SIX_LOCK_read or SIX_LOCK_intent
 * @trace_ip:	ip of caller of btree iterator code (i.e. caller of bch2_btree_iter_peek())
 *
 * The btree node will have either a read or a write lock held, depending on
 * the @write parameter.
 *
 * Returns: btree node or ERR_PTR()
 */
struct btree *bch2_btree_node_get(struct btree_trans *trans, struct btree_path *path,
				  const struct bkey_i *k, unsigned level,
				  enum six_lock_type lock_type,
				  unsigned long trace_ip)
{
	struct bch_fs *c = trans->c;
	struct btree *b;
	int ret;

	EBUG_ON(level >= BTREE_MAX_DEPTH);

	b = btree_node_mem_ptr(k);

	/*
	 * Check b->hash_val _before_ calling btree_node_lock() - this might not
	 * be the node we want anymore, and trying to lock the wrong node could
	 * cause an unneccessary transaction restart:
	 */
	if (unlikely(!c->opts.btree_node_mem_ptr_optimization ||
		     !b ||
		     b->hash_val != btree_ptr_hash_val(k)))
		return __bch2_btree_node_get(trans, path, k, level, lock_type, trace_ip);

	if (btree_node_read_locked(path, level + 1))
		btree_node_unlock(trans, path, level + 1);

	ret = btree_node_lock(trans, path, &b->c, level, lock_type, trace_ip);
	if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
		return ERR_PTR(ret);

	BUG_ON(ret);

	if (unlikely(b->hash_val != btree_ptr_hash_val(k) ||
		     b->c.level != level ||
		     race_fault())) {
		six_unlock_type(&b->c.lock, lock_type);
		if (bch2_btree_node_relock(trans, path, level + 1))
			return __bch2_btree_node_get(trans, path, k, level, lock_type, trace_ip);

		trace_and_count(c, trans_restart_btree_node_reused, trans, trace_ip, path);
		return ERR_PTR(btree_trans_restart(trans, BCH_ERR_transaction_restart_lock_node_reused));
	}

	if (unlikely(btree_node_read_in_flight(b))) {
		six_unlock_type(&b->c.lock, lock_type);
		return __bch2_btree_node_get(trans, path, k, level, lock_type, trace_ip);
	}

	prefetch(b->aux_data);

	for_each_bset(b, t) {
		void *p = (u64 *) b->aux_data + t->aux_data_offset;

		prefetch(p + L1_CACHE_BYTES * 0);
		prefetch(p + L1_CACHE_BYTES * 1);
		prefetch(p + L1_CACHE_BYTES * 2);
	}

	/* avoid atomic set bit if it's not needed: */
	if (!btree_node_accessed(b))
		set_btree_node_accessed(b);

	if (unlikely(btree_node_read_error(b))) {
		six_unlock_type(&b->c.lock, lock_type);
		return ERR_PTR(-BCH_ERR_btree_node_read_err_cached);
	}

	EBUG_ON(b->c.btree_id != path->btree_id);
	EBUG_ON(BTREE_NODE_LEVEL(b->data) != level);
	btree_check_header(c, b);

	return b;
}

struct btree *bch2_btree_node_get_noiter(struct btree_trans *trans,
					 const struct bkey_i *k,
					 enum btree_id btree_id,
					 unsigned level,
					 bool nofill)
{
	struct bch_fs *c = trans->c;
	struct btree_cache *bc = &c->btree_cache;
	struct btree *b;
	int ret;

	EBUG_ON(level >= BTREE_MAX_DEPTH);

	if (c->opts.btree_node_mem_ptr_optimization) {
		b = btree_node_mem_ptr(k);
		if (b)
			goto lock_node;
	}
retry:
	b = btree_cache_find(bc, k);
	if (unlikely(!b)) {
		if (nofill)
			goto out;

		b = bch2_btree_node_fill(trans, NULL, k, btree_id,
					 level, SIX_LOCK_read, true);

		/* We raced and found the btree node in the cache */
		if (!b)
			goto retry;

		if (IS_ERR(b) &&
		    !bch2_btree_cache_cannibalize_lock(trans, NULL))
			goto retry;

		if (IS_ERR(b))
			goto out;
	} else {
lock_node:
		ret = btree_node_lock_nopath(trans, &b->c, SIX_LOCK_read, _THIS_IP_);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			return ERR_PTR(ret);

		BUG_ON(ret);

		if (unlikely(b->hash_val != btree_ptr_hash_val(k) ||
			     b->c.btree_id != btree_id ||
			     b->c.level != level)) {
			six_unlock_read(&b->c.lock);
			goto retry;
		}

		/* avoid atomic set bit if it's not needed: */
		if (!btree_node_accessed(b))
			set_btree_node_accessed(b);
	}

	/* XXX: waiting on IO with btree locks held: */
	__bch2_btree_node_wait_on_read(b);

	prefetch(b->aux_data);

	for_each_bset(b, t) {
		void *p = (u64 *) b->aux_data + t->aux_data_offset;

		prefetch(p + L1_CACHE_BYTES * 0);
		prefetch(p + L1_CACHE_BYTES * 1);
		prefetch(p + L1_CACHE_BYTES * 2);
	}

	if (unlikely(btree_node_read_error(b))) {
		six_unlock_read(&b->c.lock);
		b = ERR_PTR(-BCH_ERR_btree_node_read_err_cached);
		goto out;
	}

	EBUG_ON(b->c.btree_id != btree_id);
	EBUG_ON(BTREE_NODE_LEVEL(b->data) != level);
	btree_check_header(c, b);
out:
	bch2_btree_cache_cannibalize_unlock(trans);
	return b;
}

int bch2_btree_node_prefetch(struct btree_trans *trans,
			     struct btree_path *path,
			     const struct bkey_i *k,
			     enum btree_id btree_id, unsigned level)
{
	struct bch_fs *c = trans->c;
	struct btree_cache *bc = &c->btree_cache;

	BUG_ON(path && !btree_node_locked(path, level + 1));
	BUG_ON(level >= BTREE_MAX_DEPTH);

	struct btree *b = btree_cache_find(bc, k);
	if (b)
		return 0;

	b = bch2_btree_node_fill(trans, path, k, btree_id,
				 level, SIX_LOCK_read, false);
	int ret = PTR_ERR_OR_ZERO(b);
	if (ret)
		return ret;
	if (b)
		six_unlock_read(&b->c.lock);
	return 0;
}

void bch2_btree_node_evict(struct btree_trans *trans, const struct bkey_i *k)
{
	struct bch_fs *c = trans->c;
	struct btree_cache *bc = &c->btree_cache;
	struct btree *b;

	b = btree_cache_find(bc, k);
	if (!b)
		return;

	BUG_ON(b == btree_node_root(trans->c, b));
wait_on_io:
	/* not allowed to wait on io with btree locks held: */

	/* XXX we're called from btree_gc which will be holding other btree
	 * nodes locked
	 */
	__bch2_btree_node_wait_on_read(b);
	__bch2_btree_node_wait_on_write(b);

	btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_intent);
	btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_write);
	if (unlikely(b->hash_val != btree_ptr_hash_val(k)))
		goto out;

	if (btree_node_dirty(b)) {
		__bch2_btree_node_write(c, b, BTREE_WRITE_cache_reclaim);
		six_unlock_write(&b->c.lock);
		six_unlock_intent(&b->c.lock);
		goto wait_on_io;
	}

	BUG_ON(btree_node_dirty(b));

	mutex_lock(&bc->lock);
	bch2_btree_node_hash_remove(bc, b);
	btree_node_data_free(bc, b);
	mutex_unlock(&bc->lock);
out:
	six_unlock_write(&b->c.lock);
	six_unlock_intent(&b->c.lock);
}

const char *bch2_btree_id_str(enum btree_id btree)
{
	return btree < BTREE_ID_NR ? __bch2_btree_ids[btree] : "(unknown)";
}

void bch2_btree_id_to_text(struct printbuf *out, enum btree_id btree)
{
	if (btree < BTREE_ID_NR)
		prt_str(out, __bch2_btree_ids[btree]);
	else
		prt_printf(out, "(unknown btree %u)", btree);
}

void bch2_btree_id_level_to_text(struct printbuf *out, enum btree_id btree, unsigned level)
{
	prt_str(out, "btree=");
	bch2_btree_id_to_text(out, btree);
	prt_printf(out, " level=%u", level);
}

void __bch2_btree_pos_to_text(struct printbuf *out, struct bch_fs *c,
			      enum btree_id btree, unsigned level, struct bkey_s_c k)
{
	bch2_btree_id_to_text(out, btree);
	prt_printf(out, " level %u/", level);
	struct btree_root *r = bch2_btree_id_root(c, btree);
	if (r)
		prt_printf(out, "%u", r->level);
	else
		prt_printf(out, "(unknown)");
	prt_newline(out);

	bch2_bkey_val_to_text(out, c, k);
}

void bch2_btree_pos_to_text(struct printbuf *out, struct bch_fs *c, const struct btree *b)
{
	__bch2_btree_pos_to_text(out, c, b->c.btree_id, b->c.level, bkey_i_to_s_c(&b->key));
}

void bch2_btree_node_to_text(struct printbuf *out, struct bch_fs *c, const struct btree *b)
{
	struct bset_stats stats;

	memset(&stats, 0, sizeof(stats));

	bch2_btree_keys_stats(b, &stats);

	prt_printf(out, "l %u ", b->c.level);
	bch2_bpos_to_text(out, b->data->min_key);
	prt_printf(out, " - ");
	bch2_bpos_to_text(out, b->data->max_key);
	prt_printf(out, ":\n"
	       "    ptrs: ");
	bch2_val_to_text(out, c, bkey_i_to_s_c(&b->key));
	prt_newline(out);

	prt_printf(out,
	       "    format: ");
	bch2_bkey_format_to_text(out, &b->format);

	prt_printf(out,
	       "    unpack fn len: %u\n"
	       "    bytes used %zu/%zu (%zu%% full)\n"
	       "    sib u64s: %u, %u (merge threshold %u)\n"
	       "    nr packed keys %u\n"
	       "    nr unpacked keys %u\n"
	       "    floats %zu\n"
	       "    failed unpacked %zu\n",
	       b->unpack_fn_len,
	       b->nr.live_u64s * sizeof(u64),
	       btree_buf_bytes(b) - sizeof(struct btree_node),
	       b->nr.live_u64s * 100 / btree_max_u64s(c),
	       b->sib_u64s[0],
	       b->sib_u64s[1],
	       c->btree_foreground_merge_threshold,
	       b->nr.packed_keys,
	       b->nr.unpacked_keys,
	       stats.floats,
	       stats.failed);
}

static void prt_btree_cache_line(struct printbuf *out, const struct bch_fs *c,
				 const char *label, size_t nr)
{
	prt_printf(out, "%s\t", label);
	prt_human_readable_u64(out, nr * c->opts.btree_node_size);
	prt_printf(out, " (%zu)\n", nr);
}

static const char * const bch2_btree_cache_not_freed_reasons_strs[] = {
#define x(n) #n,
	BCH_BTREE_CACHE_NOT_FREED_REASONS()
#undef x
	NULL
};

void bch2_btree_cache_to_text(struct printbuf *out, const struct btree_cache *bc)
{
	struct bch_fs *c = container_of(bc, struct bch_fs, btree_cache);

	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 32);

	prt_btree_cache_line(out, c, "live:",		bc->live[0].nr);
	prt_btree_cache_line(out, c, "pinned:",		bc->live[1].nr);
	prt_btree_cache_line(out, c, "reserve:",	bc->nr_reserve);
	prt_btree_cache_line(out, c, "freed:",		bc->nr_freeable);
	prt_btree_cache_line(out, c, "dirty:",		atomic_long_read(&bc->nr_dirty));
	prt_printf(out, "cannibalize lock:\t%s\n",	bc->alloc_lock ? "held" : "not held");
	prt_newline(out);

	for (unsigned i = 0; i < ARRAY_SIZE(bc->nr_by_btree); i++) {
		bch2_btree_id_to_text(out, i);
		prt_printf(out, "\t");
		prt_human_readable_u64(out, bc->nr_by_btree[i] * c->opts.btree_node_size);
		prt_printf(out, " (%zu)\n", bc->nr_by_btree[i]);
	}

	prt_newline(out);
	prt_printf(out, "counters since mount:\n");
	prt_printf(out, "freed:\t%zu\n", bc->nr_freed);
	prt_printf(out, "not freed:\n");

	for (unsigned i = 0; i < ARRAY_SIZE(bc->not_freed); i++)
		prt_printf(out, "  %s\t%llu\n",
			   bch2_btree_cache_not_freed_reasons_strs[i], bc->not_freed[i]);
}
