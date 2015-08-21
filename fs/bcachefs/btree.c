/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 *
 * Uses a block device as cache for other block devices; optimized for SSDs.
 * All allocation is done in buckets, which should match the erase block size
 * of the device.
 *
 * Buckets containing cached data are kept on a heap sorted by priority;
 * bucket priority is increased on cache hit, and periodically all the buckets
 * on the heap have their priority scaled down. This currently is just used as
 * an LRU but in the future should allow for more intelligent heuristics.
 *
 * Buckets have an 8 bit counter; freeing is accomplished by incrementing the
 * counter. Garbage collection is used to remove stale pointers.
 *
 * Indexing is done via a btree; nodes are not necessarily fully sorted, rather
 * as keys are inserted we only sort the pages that have not yet been written.
 * When garbage collection is run, we resort the entire node.
 *
 * All configuration is done via sysfs; see Documentation/bcache.txt.
 */

#include "bcache.h"
#include "alloc.h"
#include "btree.h"
#include "buckets.h"
#include "debug.h"
#include "extents.h"
#include "io.h"
#include "keylist.h"
#include "journal.h"
#include "keylist.h"
#include "movinggc.h"
#include "super.h"
#include "writeback.h"

#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/hash.h>
#include <linux/jhash.h>
#include <linux/kthread.h>
#include <linux/prefetch.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <trace/events/bcachefs.h>

/*
 * Todo:
 * Writeback: don't undirty key until after a cache flush
 *
 * Create an iterator for key pointers
 *
 * On btree write error, mark bucket such that it won't be freed from the cache
 *
 * Journalling:
 *   Check for bad keys in replay
 *
 * Garbage collection:
 *   Gc should free old UUIDs, data for invalid UUIDs
 *
 * Provide a way to list backing device UUIDs we have data cached for, and
 * probably how long it's been since we've seen them, and a way to invalidate
 * dirty data for devices that will never be attached again
 *
 * If data write is less than hard sector size of ssd, round up offset in open
 * bucket to the next whole sector
 *
 * IO tracking: Can we track when one process is doing io on behalf of another?
 * IO tracking: Don't use just an average, weigh more recent stuff higher
 *
 * Test module load/unload
 */

static int __bch_btree_insert_node(struct btree *, struct btree_op *,
				   struct keylist *, struct bkey *,
				   struct closure *, struct keylist *,
				   struct closure *);

#define MAX_NEED_GC		64
#define MAX_SAVE_PRIO		72

/*
 * These macros are for recursing down the btree - they handle the details of
 * locking and looking up nodes in the cache for you. They're best treated as
 * mere syntax when reading code that uses them.
 *
 * op->lock determines whether we take a read or a write lock at a given depth.
 * If you've got a read lock and find that you need a write lock (i.e. you're
 * going to have to split), set op->lock and return -EINTR; btree_root() will
 * call you again and you'll have the correct lock.
 */

static inline bool btree_node_read_locked(struct btree_op *op, int level)
{
	return test_bit(level, (void *) &op->locks_read);
}

static inline bool btree_node_intent_locked(struct btree_op *op, int level)
{
	return test_bit(level, (void *) &op->locks_intent);
}

static inline bool btree_node_locked(struct btree_op *op, int level)
{
	return btree_node_read_locked(op, level) ||
		btree_node_intent_locked(op, level);
}

static inline bool btree_want_intent(struct btree_op *op, int level)
{
	return level <= op->locks_want;
}

static void btree_node_unlock(struct btree_op *op, struct btree *b, int level)
{
	if (__test_and_clear_bit(level, (void *) &op->locks_intent))
		six_unlock_intent(&b->lock);
	else if (__test_and_clear_bit(level, (void *) &op->locks_read))
		six_unlock_read(&b->lock);
}

#define __btree_node_lock(b, op, _level, check_if_raced, type)		\
({									\
	bool _raced;							\
									\
	six_lock_##type(&(b)->lock);					\
	if ((_raced = ((check_if_raced) || ((b)->level != _level)))) {	\
		six_unlock_##type(&(b)->lock);				\
	} else {							\
		__set_bit(_level, (void *) &(op)->locks_##type);	\
		(op)->lock_seq[_level] = (b)->lock.state.seq;		\
	}								\
									\
	!_raced;							\
})

#define btree_node_lock(b, op, level, check_if_raced)			\
	(btree_want_intent(op, level)					\
	 ? __btree_node_lock(b, op, level, check_if_raced, intent)	\
	 : __btree_node_lock(b, op, level, check_if_raced, read))

#define __btree_node_relock(b, op, _level, type)			\
({									\
	bool _locked = six_relock_##type(&(b)->lock,			\
					 (op)->lock_seq[_level]);	\
									\
	if (_locked)							\
		__set_bit((_level), (void *) &(op)->locks_##type);	\
									\
	_locked;							\
})

static bool btree_node_relock(struct btree *b, struct btree_op *op,
			      unsigned level)
{
	return btree_node_locked(op, level) ||
		(btree_want_intent(op, level)
		 ? __btree_node_relock(b, op, level, intent)
		 : __btree_node_relock(b, op, level, read));
}

static int btree_lock_upgrade(struct btree *b, struct btree_op *op,
			      unsigned level)
{
	if (btree_node_intent_locked(op, level))
		return 0;

	if (btree_node_read_locked(op, level)
	    ? six_trylock_convert(&b->lock, read, intent)
	    : six_relock_intent(&b->lock, op->lock_seq[level])) {
		__clear_bit(level, (void *) &op->locks_read);
		__set_bit(level, (void *) &op->locks_intent);

		trace_bcache_btree_upgrade_lock(b, op);
		return 0;
	}

	trace_bcache_btree_upgrade_lock_fail(b, op);
	return -EINTR;
}

/**
 * btree - recurse down the btree on a specified key
 * @fn:		function to call, which will be passed the child node
 * @key:	key to recurse on
 * @b:		parent btree node
 * @op:		pointer to struct btree_op
 */
#define btree(fn, key, b, op, ...)					\
({									\
	int _r, l = (b)->level - 1;					\
	struct btree *_child;						\
									\
	_child = bch_btree_node_get((b)->c, op, key, l, b);		\
	if (!IS_ERR(_child)) {						\
		_r = bch_btree_##fn(_child, op, ##__VA_ARGS__);		\
		btree_node_unlock(op, _child, l);			\
	} else								\
		_r = PTR_ERR(_child);					\
	_r;								\
})

/**
 * btree_root - call a function on the root of the btree
 * @fn:		function to call, which will be passed the child node
 * @c:		cache set
 * @op:		pointer to struct btree_op
 * @async:	if true, pass -EAGAIN up to the caller, otherwise wait
 */
#define btree_root(fn, c, op, async, ...)				\
({									\
	int _l, _r = -EINTR;						\
									\
	while (1) {							\
		struct btree *_b;					\
									\
		(op)->locks_intent	= 0;				\
		(op)->locks_read	= 0;				\
		(op)->iterator_invalidated = 0;				\
									\
		_b = (c)->btree_roots[(op)->id];			\
		_l = _b->level;						\
		if (btree_node_lock(_b, (op), _l,			\
				(_b != (c)->btree_roots[(op)->id]))) {	\
			_r = bch_btree_ ## fn(_b, (op), ##__VA_ARGS__);	\
			btree_node_unlock((op), _b, _l);		\
		}							\
		bch_cannibalize_unlock(c);				\
		if (_r == -EINTR)					\
			cond_resched();					\
		else if (!(async) && _r == -EAGAIN)			\
			closure_sync(&(op)->cl);			\
		else							\
			break;						\
	}								\
	if (!(async))							\
		closure_sync(&(op)->cl);				\
	_r;								\
})

static inline struct bset *write_block(struct btree *b)
{
	return ((void *) btree_bset_first(b)) + b->written * block_bytes(b->c);
}

/* Returns true if we sorted (i.e. invalidated iterators */
static bool bch_btree_init_next(struct btree *b)
{
	unsigned nsets = b->keys.nsets;
	bool sorted;

	/* If not a leaf node, always sort */
	if (b->level && b->keys.nsets)
		bch_btree_sort(&b->keys, NULL, &b->c->sort);
	else
		bch_btree_sort_lazy(&b->keys, NULL, &b->c->sort);

	sorted = nsets != b->keys.nsets;

	/*
	 * do verify if there was more than one set initially (i.e. we did a
	 * sort) and we sorted down to a single set:
	 */
	if (nsets && !b->keys.nsets)
		bch_btree_verify(b);

	if (b->written < btree_blocks(b->c)) {
		struct bset *i = write_block(b);

		bch_bset_init_next(&b->keys, i);
		i->magic = bset_magic(&b->c->sb);
	}

	return sorted;
}

/* Btree IO */

static u64 btree_csum_set(struct btree *b, struct bset *i)
{
	u64 crc = b->key.val[0];
	void *data = (void *) i + 8, *end = bset_bkey_last(i);

	crc = bch_checksum_update(BSET_CSUM_TYPE(i), crc, data, end - data);

	return crc ^ 0xffffffffffffffffULL;
}

#define btree_node_error(b, ca, ptr, fmt, ...)			\
	bch_cache_error(ca,					\
		"btree node error at btree %u level %u/%u bucket %zu block %u keys %u: " fmt,\
		(b)->btree_id, (b)->level, btree_node_root(b)	\
			    ? btree_node_root(b)->level : -1,	\
		PTR_BUCKET_NR((b)->c, &(b)->key, ptr),		\
		bset_block_offset(b, i),			\
		i->keys, ##__VA_ARGS__)

void bch_btree_node_read_done(struct btree *b, struct cache *ca, unsigned ptr)
{
	struct cache_set *c = b->c;
	const char *err = "bad btree header";
	struct bset *i = btree_bset_first(b);
	struct btree_node_iter *iter;
	struct bkey *k;

	iter = mempool_alloc(b->c->fill_iter, GFP_NOIO);
	iter->size = btree_blocks(c);
	iter->used = 0;
	iter->is_extents = b->keys.ops->is_extents;

#ifdef CONFIG_BCACHEFS_DEBUG
	iter->b = &b->keys;
#endif

	if (!i->seq)
		goto err;

	for (;
	     b->written < btree_blocks(c) && i->seq == b->keys.set[0].data->seq;
	     i = write_block(b)) {
		b->written += set_blocks(i, block_bytes(c));

		err = "unsupported bset version";
		if (i->version != BCACHE_BSET_VERSION)
			goto err;

		err = "bad magic";
		if (i->magic != bset_magic(&c->sb))
			goto err;

		err = "unknown checksum type";
		if (BSET_CSUM_TYPE(i) >= BCH_CSUM_NR)
			goto err;

		err = "bad btree header";
		if (b->written > btree_blocks(c))
			goto err;

		err = "bad checksum";
		if (i->csum != btree_csum_set(b, i))
			goto err;

		if (i != b->keys.set[0].data && !i->keys)
			btree_node_error(b, ca, ptr, "empty set");

		for (k = i->start;
		     k != bset_bkey_last(i);) {
			if (!KEY_U64s(k)) {
				btree_node_error(b, ca, ptr,
					"KEY_U64s 0: %zu bytes of metadata lost",
					(void *) bset_bkey_last(i) -
					(void *) k);

				i->keys = (u64 *) k - i->d;
				break;
			}

			if (bkey_next(k) > bset_bkey_last(i)) {
				btree_node_error(b, ca, ptr,
					"key extends past end of bset");

				i->keys = (u64 *) k - i->d;
				break;
			}

			if (bkey_invalid(&b->keys, k)) {
				char buf[80];

				bch_bkey_val_to_text(&b->keys, buf,
						     sizeof(buf), k);
				btree_node_error(b, ca, ptr,
						 "invalid bkey %s", buf);

				i->keys -= KEY_U64s(k);
				memmove(k, bkey_next(k),
					(void *) bset_bkey_last(i) -
					(void *) k);
				continue;
			}

			k = bkey_next(k);
		}

		bch_btree_node_iter_push(iter, i->start, bset_bkey_last(i));
	}

	err = "corrupted btree";
	for (i = write_block(b);
	     bset_sector_offset(&b->keys, i) < btree_sectors(c);
	     i = ((void *) i) + block_bytes(c))
		if (i->seq == b->keys.set[0].data->seq)
			goto err;

	bch_btree_sort_and_fix_extents(&b->keys, iter, NULL, &c->sort);

	i = b->keys.set[0].data;
	err = "short btree key";
	if (b->keys.set[0].size &&
	    bkey_cmp(&b->key, &b->keys.set[0].end) < 0)
		goto err;

out:
	mempool_free(iter, c->fill_iter);
	return;
err:
	set_btree_node_io_error(b);
	btree_node_error(b, ca, ptr, "%s", err);
	goto out;
}

static void btree_node_read_endio(struct bio *bio)
{
	bch_bbio_endio(to_bbio(bio), bio->bi_error, "reading btree");
}

static void bch_btree_node_read(struct btree *b)
{
	uint64_t start_time = local_clock();
	struct closure cl;
	struct bbio *bio;
	struct cache *ca;
	unsigned ptr;

	trace_bcache_btree_read(b);

	closure_init_stack(&cl);

	ca = bch_btree_pick_ptr(b->c, &b->key, &ptr);
	if (!ca) {
		set_btree_node_io_error(b);
		goto missing;
	}

	bio = to_bbio(bch_bbio_alloc(b->c));
	bio->bio.bi_iter.bi_size	= btree_bytes(b->c);
	bio->bio.bi_end_io		= btree_node_read_endio;
	bio->bio.bi_private		= &cl;
	bio_set_op_attrs(&bio->bio, REQ_OP_READ, REQ_META|READ_SYNC);

	bch_bio_map(&bio->bio, b->keys.set[0].data);

	bio_get(&bio->bio);
	bch_submit_bbio(bio, ca, &b->key, ptr, true);

	closure_sync(&cl);

	if (bio->bio.bi_error)
		set_btree_node_io_error(b);

	bch_bbio_free(&bio->bio, b->c);

	if (btree_node_io_error(b))
		goto err;

	bch_btree_node_read_done(b, ca, ptr);
	bch_time_stats_update(&b->c->btree_read_time, start_time);

	return;

missing:
	bch_cache_set_error(b->c, "no cache device for btree node");
	return;

err:
	bch_cache_error(ca, "IO error reading bucket %zu",
			PTR_BUCKET_NR(b->c, &b->key, ptr));
}

static void btree_complete_write(struct btree *b, struct btree_write *w)
{
	if (w->journal) {
		atomic_dec_bug(w->journal);
		wake_up(&b->c->journal.wait);
	}

	w->journal	= NULL;
}

static void btree_node_write_unlock(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io);

	up(&b->io_mutex);
}

static void __btree_node_write_done(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io);
	struct btree_write *w = btree_prev_write(b);
	struct cache_set *c = b->c;

	bch_bbio_free(b->bio, c);
	b->bio = NULL;
	btree_complete_write(b, w);

	if (btree_node_dirty(b) && c->btree_flush_delay)
		schedule_delayed_work(&b->work, c->btree_flush_delay * HZ);

	closure_return_with_destructor(cl, btree_node_write_unlock);
}

static void btree_node_write_done(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io);

	bio_free_pages(b->bio);
	__btree_node_write_done(cl);
}

static void btree_node_write_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;
	struct btree *b = container_of(cl, struct btree, io);

	if (bio->bi_error)
		set_btree_node_io_error(b);

	bch_bbio_endio(to_bbio(bio), bio->bi_error, "writing btree");
}

static void do_btree_node_write(struct btree *b)
{
	struct closure *cl = &b->io;
	struct bset *i = btree_bset_last(b);
	BKEY_PADDED(key) k;
	int n;

	i->version	= BCACHE_BSET_VERSION;

	SET_BSET_CSUM_TYPE(i, CACHE_PREFERRED_CSUM_TYPE(&b->c->sb));
	i->csum		= btree_csum_set(b, i);

	BUG_ON(b->bio);
	b->bio = bch_bbio_alloc(b->c);

	/* Take an extra reference so that the bio_put() in
	 * btree_node_write_endio() doesn't call bio_free() */
	bio_get(b->bio);

	b->bio->bi_end_io	= btree_node_write_endio;
	b->bio->bi_private	= cl;
	b->bio->bi_iter.bi_size	= roundup(set_bytes(i), block_bytes(b->c));
	bio_set_op_attrs(b->bio, REQ_OP_WRITE, REQ_META|WRITE_SYNC|REQ_FUA);
	bch_bio_map(b->bio, i);

	/*
	 * If we're appending to a leaf node, we don't technically need FUA -
	 * this write just needs to be persisted before the next journal write,
	 * which will be marked FLUSH|FUA.
	 *
	 * Similarly if we're writing a new btree root - the pointer is going to
	 * be in the next journal entry.
	 *
	 * But if we're writing a new btree node (that isn't a root) or
	 * appending to a non leaf btree node, we need either FUA or a flush
	 * when we write the parent with the new pointer. FUA is cheaper than a
	 * flush, and writes appending to leaf nodes aren't blocking anything so
	 * just make all btree node writes FUA to keep things sane.
	 */

	bkey_copy(&k.key, &b->key);
	for (n = 0; n < bch_extent_ptrs(&b->key); n++)
		SET_PTR_OFFSET(&k.key, n, PTR_OFFSET(&k.key, n) +
			       bset_sector_offset(&b->keys, i));

	if (!bio_alloc_pages(b->bio, __GFP_NOWARN|GFP_NOWAIT)) {
		int j;
		struct bio_vec *bv;
		void *base = (void *) ((unsigned long) i & ~(PAGE_SIZE - 1));

		bio_for_each_segment_all(bv, b->bio, j)
			memcpy(page_address(bv->bv_page),
			       base + j * PAGE_SIZE, PAGE_SIZE);

		bch_submit_bbio_replicas(b->bio, b->c, &k.key, 0, true);
		continue_at(cl, btree_node_write_done, NULL);
	} else {
		trace_bcache_btree_bounce_write_fail(b);

		b->bio->bi_vcnt = 0;
		bch_bio_map(b->bio, i);

		bch_submit_bbio_replicas(b->bio, b->c, &k.key, 0, true);

		closure_sync(cl);
		continue_at_nobarrier(cl, __btree_node_write_done, NULL);
	}
}

static void __bch_btree_node_write(struct btree *b, struct closure *parent)
{
	struct bset *i = btree_bset_last(b);
	size_t blocks_to_write = set_blocks(i, block_bytes(b->c));
	struct cache *ca;
	unsigned ptr;

	if (!test_and_clear_bit(BTREE_NODE_dirty, &b->flags))
		return;

	trace_bcache_btree_write(b);

	BUG_ON(b->written >= btree_blocks(b->c));
	BUG_ON(b->written + blocks_to_write > btree_blocks(b->c));
	BUG_ON(b->written && !i->keys);
	BUG_ON(btree_bset_first(b)->seq != i->seq);
	bch_check_keys(&b->keys, "writing");

	cancel_delayed_work(&b->work);

	/* If caller isn't waiting for write, parent refcount is cache set */
	down(&b->io_mutex);
	closure_init(&b->io, parent ?: &b->c->cl);

	change_bit(BTREE_NODE_write_idx, &b->flags);

	do_btree_node_write(b);

	rcu_read_lock();
	for (ptr = 0; ptr < bch_extent_ptrs(&b->key); ptr++)
		if ((ca = PTR_CACHE(b->c, &b->key, ptr)))
			atomic_long_add(blocks_to_write * b->c->sb.block_size,
					&ca->btree_sectors_written);
	rcu_read_unlock();

	b->written += blocks_to_write;
}

static void bch_btree_node_write(struct btree *b, struct closure *parent)
{
	__bch_btree_node_write(b, parent);

	six_lock_write(&b->lock);
	bch_btree_init_next(b);
	six_unlock_write(&b->lock);
}

static void bch_btree_node_write_sync(struct btree *b)
{
	struct closure cl;

	closure_init_stack(&cl);

	bch_btree_node_write(b, &cl);
	closure_sync(&cl);
}

static void bch_btree_node_write_dirty(struct btree *b, struct closure *parent)
{
	six_lock_read(&b->lock);
	if (btree_node_dirty(b))
		__bch_btree_node_write(b, parent);
	six_unlock_read(&b->lock);
}

static void btree_node_write_work(struct work_struct *w)
{
	struct btree *b = container_of(to_delayed_work(w), struct btree, work);

	bch_btree_node_write_dirty(b, NULL);
}

void bch_btree_write_oldest(struct cache_set *c)
{
	/*
	 * Try to find the btree node with that references the oldest journal
	 * entry, best is our current candidate and is locked if non NULL:
	 */
	struct btree *b, *best;
	struct bucket_table *tbl;
	struct rhash_head *pos;
	unsigned i;
retry:
	cond_resched();
	best = NULL;

	rcu_read_lock();
	for_each_cached_btree(b, c, tbl, i, pos)
		if (btree_current_write(b)->journal) {
			if (!best)
				best = b;
			else if (journal_pin_cmp(c,
					btree_current_write(best)->journal,
					btree_current_write(b)->journal)) {
				best = b;
			}
		}
	rcu_read_unlock();

	b = best;
	if (b) {
		six_lock_read(&b->lock);
		if (!btree_current_write(b)->journal) {
			six_unlock_read(&b->lock);
			/* We raced */
			goto retry;
		}

		__bch_btree_node_write(b, NULL);
		six_unlock_read(&b->lock);
	}
}

/*
 * Write all dirty btree nodes to disk, including roots
 */
void bch_btree_flush(struct cache_set *c)
{
	struct closure cl;
	struct btree *b;
	struct bucket_table *tbl;
	struct rhash_head *pos;
	bool dropped_lock;
	unsigned i;

	closure_init_stack(&cl);

	rcu_read_lock();

	do {
		dropped_lock = false;
		i = 0;
restart:
		tbl = rht_dereference_rcu(c->btree_cache_table.tbl,
					  &c->btree_cache_table);

		for (; i < tbl->size; i++)
			rht_for_each_entry_rcu(b, pos, tbl, i, hash)
				if (btree_node_dirty(b)) {
					rcu_read_unlock();
					bch_btree_node_write_dirty(b, &cl);
					dropped_lock = true;
					rcu_read_lock();
					goto restart;
				}
	} while (dropped_lock);

	rcu_read_unlock();

	closure_sync(&cl);
}

/*
 * Btree in memory cache - allocation/freeing
 * mca -> memory cache
 */

void bch_recalc_btree_reserve(struct cache_set *c)
{
	unsigned i, reserve = 16;

	if (!c->btree_roots[0])
		reserve += 8;

	for (i = 0; i < BTREE_ID_NR; i++)
		if (c->btree_roots[i])
			reserve += min_t(unsigned, 1,
					 c->btree_roots[i]->level) * 8;

	c->btree_cache_reserve = reserve;
}

#define mca_can_free(c)						\
	max_t(int, 0, c->btree_cache_used - c->btree_cache_reserve)

static void mca_data_free(struct btree *b)
{
	BUG_ON(b->io_mutex.count != 1);

	bch_btree_keys_free(&b->keys);

	b->c->btree_cache_used--;
	list_move(&b->list, &b->c->btree_cache_freed);
}

static const struct rhashtable_params bch_btree_cache_params = {
	.head_offset	= offsetof(struct btree, hash),
	.key_offset	= offsetof(struct btree, key.val[0]),
	.key_len	= sizeof(u64),
	.hashfn		= jhash,
};

static void mca_bucket_free(struct btree *b)
{
	BUG_ON(btree_node_dirty(b));

	rhashtable_remove_fast(&b->c->btree_cache_table, &b->hash,
			       bch_btree_cache_params);

	/* Cause future lookups for this node to fail: */
	b->key.val[0] = 0;
	list_move(&b->list, &b->c->btree_cache_freeable);
}

static void mca_data_alloc(struct btree *b, gfp_t gfp)
{
	if (!bch_btree_keys_alloc(&b->keys, ilog2(b->c->btree_pages), gfp)) {
		b->c->btree_cache_used++;
		list_move(&b->list, &b->c->btree_cache);
	} else {
		list_move(&b->list, &b->c->btree_cache_freed);
	}
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

	mca_data_alloc(b, gfp);
	return b;
}

/*
 * this version is for btree nodes that have already been freed (we're not
 * reaping a real btree node)
 */
static int mca_reap_notrace(struct btree *b, bool flush)
{
	struct closure cl;

	closure_init_stack(&cl);
	lockdep_assert_held(&b->c->btree_cache_lock);

	if (!six_trylock_intent(&b->lock))
		return -ENOMEM;

	if (!six_trylock_write(&b->lock))
		goto out_unlock_intent;

	BUG_ON(btree_node_dirty(b) && !b->keys.set[0].data);

	if (!flush) {
		if (btree_node_dirty(b))
			goto out_unlock;

		if (down_trylock(&b->io_mutex))
			goto out_unlock;
		up(&b->io_mutex);
	}

	if (btree_node_dirty(b))
		__bch_btree_node_write(b, &cl);

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

static int mca_reap(struct btree *b, bool flush)
{
	int ret = mca_reap_notrace(b, flush);

	trace_bcache_mca_reap(b, ret);
	return ret;
}

static unsigned long bch_mca_scan(struct shrinker *shrink,
				  struct shrink_control *sc)
{
	struct cache_set *c = container_of(shrink, struct cache_set,
					   btree_cache_shrink);
	struct btree *b, *t;
	unsigned long i, nr = sc->nr_to_scan;
	unsigned long freed = 0;

	if (c->shrinker_disabled)
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
	nr /= c->btree_pages;
	nr = min_t(unsigned long, nr, mca_can_free(c));

	i = 0;
	list_for_each_entry_safe(b, t, &c->btree_cache_freeable, list) {
		if (freed >= nr)
			break;

		if (++i > 3 &&
		    !mca_reap_notrace(b, false)) {
			mca_data_free(b);
			six_unlock_write(&b->lock);
			six_unlock_intent(&b->lock);
			freed++;
		}
	}

	list_for_each_entry_safe(b, t, &c->btree_cache, list) {
		if (freed >= nr) {
			/* Save position */
			if (&t->list != &c->btree_cache)
				list_move_tail(&c->btree_cache, &t->list);
			break;
		}

		if (!b->accessed &&
		    !mca_reap(b, false)) {
			mca_bucket_free(b);
			mca_data_free(b);
			six_unlock_write(&b->lock);
			six_unlock_intent(&b->lock);
			freed++;
		} else
			b->accessed = 0;
	}

	mutex_unlock(&c->btree_cache_lock);
	return freed * c->btree_pages;
}

static unsigned long bch_mca_count(struct shrinker *shrink,
				   struct shrink_control *sc)
{
	struct cache_set *c = container_of(shrink, struct cache_set,
					   btree_cache_shrink);

	if (c->shrinker_disabled)
		return 0;

	if (c->btree_cache_alloc_lock)
		return 0;

	return mca_can_free(c) * c->btree_pages;
}

void bch_btree_cache_free(struct cache_set *c)
{
	struct btree *b;
	struct closure cl;
	unsigned i;

	closure_init_stack(&cl);

	if (c->btree_cache_shrink.list.next)
		unregister_shrinker(&c->btree_cache_shrink);

	mutex_lock(&c->btree_cache_lock);

#ifdef CONFIG_BCACHEFS_DEBUG
	if (c->verify_data)
		list_move(&c->verify_data->list, &c->btree_cache);

	free_pages((unsigned long) c->verify_ondisk, ilog2(bucket_pages(c)));
#endif

	for (i = 0; i < BTREE_ID_NR; i++)
		if (c->btree_roots[i])
			list_add(&c->btree_roots[i]->list, &c->btree_cache);

	list_splice(&c->btree_cache_freeable,
		    &c->btree_cache);

	while (!list_empty(&c->btree_cache)) {
		b = list_first_entry(&c->btree_cache, struct btree, list);

		if (btree_node_dirty(b))
			btree_complete_write(b, btree_current_write(b));
		clear_bit(BTREE_NODE_dirty, &b->flags);

		mca_data_free(b);
	}

	while (!list_empty(&c->btree_cache_freed)) {
		b = list_first_entry(&c->btree_cache_freed,
				     struct btree, list);
		list_del(&b->list);
		cancel_delayed_work_sync(&b->work);
		kfree(b);
	}

	rhashtable_destroy(&c->btree_cache_table);
	mutex_unlock(&c->btree_cache_lock);
}

int bch_btree_cache_alloc(struct cache_set *c)
{
	unsigned i;
	int ret;

	ret = rhashtable_init(&c->btree_cache_table, &bch_btree_cache_params);
	if (ret)
		return ret;

	bch_recalc_btree_reserve(c);

	for (i = 0; i < c->btree_cache_reserve; i++)
		if (!mca_bucket_alloc(c, GFP_KERNEL))
			return -ENOMEM;

	list_splice_init(&c->btree_cache,
			 &c->btree_cache_freeable);

#ifdef CONFIG_BCACHEFS_DEBUG
	mutex_init(&c->verify_lock);

	c->verify_ondisk = (void *)
		__get_free_pages(GFP_KERNEL, ilog2(bucket_pages(c)));

	c->verify_data = mca_bucket_alloc(c, GFP_KERNEL);

	if (c->verify_data &&
	    c->verify_data->keys.set->data)
		list_del_init(&c->verify_data->list);
	else
		c->verify_data = NULL;
#endif

	c->btree_cache_shrink.count_objects = bch_mca_count;
	c->btree_cache_shrink.scan_objects = bch_mca_scan;
	c->btree_cache_shrink.seeks = 4;
	c->btree_cache_shrink.batch = c->btree_pages * 2;
	register_shrinker(&c->btree_cache_shrink);

	return 0;
}

/* Btree in memory cache - hash table */

#define PTR_HASH(_k)	((_k)->val[0])

static struct btree *mca_find(struct cache_set *c, struct bkey *k)
{
	return rhashtable_lookup_fast(&c->btree_cache_table, &PTR_HASH(k),
				      bch_btree_cache_params);
}

static int mca_cannibalize_lock(struct cache_set *c, struct closure *cl)
{
	struct task_struct *old;

	old = cmpxchg(&c->btree_cache_alloc_lock, NULL, current);
	if (old && old != current) {
		trace_bcache_mca_cannibalize_lock_fail(c, cl);
		if (cl) {
			closure_wait(&c->mca_wait, cl);
			return -EAGAIN;
		}

		return -EINTR;
	}

	trace_bcache_mca_cannibalize_lock(c, cl);
	return 0;
}

static struct btree *mca_cannibalize(struct cache_set *c, struct closure *cl)
{
	struct btree *b;
	int ret;

	ret = mca_cannibalize_lock(c, cl);
	if (ret)
		return ERR_PTR(ret);

	trace_bcache_mca_cannibalize(c, cl);

	list_for_each_entry_reverse(b, &c->btree_cache, list)
		if (!mca_reap(b, false))
			goto out;

	list_for_each_entry_reverse(b, &c->btree_cache, list)
		if (!mca_reap(b, true))
			goto out;

	WARN(1, "btree cache cannibalize failed\n");
	return ERR_PTR(-ENOMEM);
out:
	mca_bucket_free(b);
	return b;
}

/*
 * We can only have one thread cannibalizing other cached btree nodes at a time,
 * or we'll deadlock. We use an open coded mutex to ensure that, which a
 * cannibalize_bucket() will take. This means every time we unlock the root of
 * the btree, we need to release this lock if we have it held.
 */
static void bch_cannibalize_unlock(struct cache_set *c)
{
	if (c->btree_cache_alloc_lock == current) {
		trace_bcache_mca_cannibalize_unlock(c);
		c->btree_cache_alloc_lock = NULL;
		closure_wake_up(&c->mca_wait);
	}
}

static struct btree *mca_alloc(struct cache_set *c, struct bkey *k, int level,
			       enum btree_id id, struct closure *cl)
{
	struct btree *b = NULL;

	mutex_lock(&c->btree_cache_lock);

	if (mca_find(c, k))
		goto out_unlock;

	/* btree_free() doesn't free memory; it sticks the node on the end of
	 * the list. Check if there's any freed nodes there:
	 */
	list_for_each_entry(b, &c->btree_cache_freeable, list)
		if (!mca_reap_notrace(b, false))
			goto out;

	/* We never free struct btree itself, just the memory that holds the on
	 * disk node. Check the freed list before allocating a new one:
	 */
	list_for_each_entry(b, &c->btree_cache_freed, list)
		if (!mca_reap_notrace(b, false)) {
			mca_data_alloc(b, __GFP_NOWARN|GFP_NOIO);
			if (!b->keys.set[0].data)
				goto err;
			else
				goto out;
		}

	b = mca_bucket_alloc(c, __GFP_NOWARN|GFP_NOIO);
	if (!b)
		goto err;

	BUG_ON(!six_trylock_intent(&b->lock));
	BUG_ON(!six_trylock_write(&b->lock));
	if (!b->keys.set->data)
		goto err;
out:
	BUG_ON(PTR_HASH(&b->key));
	BUG_ON(b->io_mutex.count != 1);

	bkey_copy(&b->key, k);
	list_move(&b->list, &c->btree_cache);
	BUG_ON(rhashtable_insert_fast(&c->btree_cache_table, &b->hash,
				      bch_btree_cache_params));

	b->parent	= (void *) ~0UL;
	b->flags	= 0;
	b->written	= 0;
	b->level	= level;
	b->btree_id	= id;

	bch_btree_keys_init(&b->keys, b->level
			    ? &bch_btree_interior_node_ops
			    : bch_btree_ops[id],
			    &b->c->expensive_debug_checks);

out_unlock:
	mutex_unlock(&c->btree_cache_lock);
	return b;
err:
	if (b) {
		six_unlock_write(&b->lock);
		six_unlock_intent(&b->lock);
	}

	b = mca_cannibalize(c, cl);
	if (!IS_ERR(b))
		goto out;

	goto out_unlock;
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
static struct btree *bch_btree_node_get(struct cache_set *c,
					struct btree_op *op, struct bkey *k,
					int level, struct btree *parent)
{
	int i = 0;
	struct btree *b;
	bool dropped_locks = false;

	BUG_ON(level < 0);
retry:
	rcu_read_lock();
	b = mca_find(c, k);
	rcu_read_unlock();

	if (unlikely(!b)) {
		b = mca_alloc(c, k, level, op->id, &op->cl);
		if (!b)
			goto retry;
		if (IS_ERR(b))
			return b;

		bch_btree_node_read(b);
		six_unlock_write(&b->lock);

		if (btree_want_intent(op, level)) {
			__set_bit(level, (void *) &op->locks_intent);
		} else {
			__set_bit(level, (void *) &op->locks_read);
			BUG_ON(!six_trylock_convert(&b->lock, intent, read));
		}
	} else {
		BKEY_PADDED(k) tmp;

		/*
		 * k points into the parent which we're about to
		 * unlock, so save us a copy
		 */
		bkey_copy(&tmp.k, k);
		k = &tmp.k;

		if (btree_node_read_locked(op, level + 1)) {
			/*
			 * There's a potential deadlock with splits and
			 * insertions into interior nodes we have to avoid:
			 *
			 * The other thread might be holding an intent lock on
			 * the node we want, and they want to update its parent
			 * node so they're going to upgrade their intent lock on
			 * the parent node to a write lock.
			 *
			 * But if we're holding a read lock on the parent, and
			 * we're trying to get the intent lock they're holding,
			 * we deadlock.
			 *
			 * So to avoid this we drop the read locks on parent
			 * nodes when we're starting to take intent locks - and
			 * handle the race.
			 *
			 * The race is that they might be about to free the node
			 * we want, and dropping our read lock lets them add the
			 * replacement node's pointer to the parent and then
			 * free the old node (the node we're trying to lock).
			 *
			 * After we take the intent lock on the node we want
			 * (which protects against it being freed), we check if
			 * we might have raced (and the node was freed before we
			 * locked it) with a global sequence number for freed
			 * btree nodes.
			 */

			btree_node_unlock(op, parent, level + 1);
			dropped_locks = true;
		}

		if (!btree_node_lock(b, op, level,
				     (PTR_HASH(&b->key) != PTR_HASH(k)))) {
			if (dropped_locks &&
			    !btree_node_relock(parent, op, level + 1)) {
				trace_bcache_btree_intent_lock_fail(b, op);
				return ERR_PTR(-EINTR);
			}

			goto retry;
		}

		BUG_ON(b->level != level);
	}

	/*
	 * Parent can't change without taking a write lock on the parent.
	 * If we don't have the parent locked, it makes no sense to use
	 * b->parent
	 */
	if (!dropped_locks)
		b->parent = parent;
	b->accessed = 1;

	for (; i <= b->keys.nsets && b->keys.set[i].size; i++) {
		prefetch(b->keys.set[i].tree);
		prefetch(b->keys.set[i].data);
	}

	for (; i <= b->keys.nsets; i++)
		prefetch(b->keys.set[i].data);

	if (btree_node_io_error(b)) {
		btree_node_unlock(op, b, level);
		return ERR_PTR(-EIO);
	}

	BUG_ON(!b->written);

	return b;
}

static void btree_node_prefetch(struct btree *parent, struct bkey *k)
{
	struct btree *b;

	b = mca_alloc(parent->c, k, parent->level - 1, parent->btree_id, NULL);
	if (!IS_ERR_OR_NULL(b)) {
		b->parent = parent;
		bch_btree_node_read(b);
		six_unlock_write(&b->lock);
		six_unlock_intent(&b->lock);
	}
}

/* Btree alloc */

static void btree_node_free(struct btree *b)
{
	trace_bcache_btree_node_free(b);

	BUG_ON(b == btree_node_root(b));

	six_lock_write(&b->lock);

	if (btree_node_dirty(b))
		btree_complete_write(b, btree_current_write(b));
	clear_bit(BTREE_NODE_dirty, &b->flags);

	cancel_delayed_work(&b->work);

	bch_bucket_free(b->c, &b->key);

	mutex_lock(&b->c->btree_cache_lock);
	mca_bucket_free(b);
	mutex_unlock(&b->c->btree_cache_lock);

	six_unlock_write(&b->lock);
}

/**
 * bch_btree_set_root - update the root in memory and on disk
 *
 * To ensure forward progress, the current task must not be holding any
 * btree node write locks. However, you must hold an intent lock on the
 * old root.
 *
 * Frees the old root.
 */
static void bch_btree_set_root(struct btree *b)
{
	struct cache_set *c = b->c;
	struct journal_res res;
	struct closure cl;
	struct btree *old;

	memset(&res, 0, sizeof(res));
	closure_init_stack(&cl);

	trace_bcache_btree_set_root(b);
	BUG_ON(!b->written);

	old = btree_node_root(b);
	if (old) {
		bch_journal_res_get(c, &res, 0, 0);
		six_lock_write(&old->lock);
	}

	/* Root nodes cannot be reaped */
	mutex_lock(&c->btree_cache_lock);
	list_del_init(&b->list);
	mutex_unlock(&c->btree_cache_lock);

	spin_lock(&c->btree_root_lock);
	btree_node_root(b) = b;
	spin_unlock(&c->btree_root_lock);

	bch_recalc_btree_reserve(c);

	if (old) {
		bch_journal_res_put(c, &res, &cl);
		closure_sync(&cl);

		six_unlock_write(&old->lock);
		btree_node_free(old);
	}
}

static struct btree *bch_btree_node_alloc(struct cache_set *c,
					  struct btree_op *op,
					  int level, enum btree_id id,
					  struct btree *parent)
{
	BKEY_PADDED(key) k;
	struct btree *b;
	enum alloc_reserve reserve = (op ? op->reserve : id);

	if (bch_bucket_alloc_set(c, reserve, &k.key,
				 CACHE_SET_META_REPLICAS_WANT(&c->sb),
				 &c->cache_all, NULL))
		BUG();

	BUG_ON(KEY_SIZE(&k.key));

	b = mca_alloc(c, &k.key, level, id, NULL);
	BUG_ON(IS_ERR_OR_NULL(b));

	bch_check_mark_super(c, &b->key, true);

	b->accessed = 1;
	b->parent = parent;
	bch_bset_init_next(&b->keys, b->keys.set->data);
	b->keys.set->data->magic = bset_magic(&b->c->sb);
	set_btree_node_dirty(b);

	trace_bcache_btree_node_alloc(b);
	return b;
}

static struct btree *btree_node_alloc_replacement(struct btree *b,
						  struct btree_op *op)
{
	struct btree *n;

	n = bch_btree_node_alloc(b->c, op, b->level, b->btree_id, b->parent);
	bch_btree_sort_into(&n->keys, &b->keys,
			    b->keys.ops->key_normalize,
			    &b->c->sort);

	bkey_copy_key(&n->key, &b->key);
	trace_bcache_btree_node_alloc_replacement(b, n);

	return n;
}

static int __btree_check_reserve(struct cache_set *c,
				 enum alloc_reserve reserve,
				 unsigned required,
				 struct closure *cl)
{
	struct cache *ca;
	unsigned i;
	int ret;

	rcu_read_lock();

	for_each_cache_rcu(ca, c, i) {
		if (CACHE_STATE(&ca->mi) != CACHE_ACTIVE)
			continue;

		spin_lock(&ca->freelist_lock);

		if (fifo_used(&ca->free[reserve]) < required) {
			trace_bcache_btree_check_reserve_fail(ca, reserve,
					fifo_used(&ca->free[reserve]),
					required, cl);

			if (cl) {
				closure_wait(&c->freelist_wait, cl);
				ret = -EAGAIN;
			} else {
				ret = -ENOSPC;
			}

			spin_unlock(&ca->freelist_lock);
			rcu_read_unlock();
			return ret;
		}

		spin_unlock(&ca->freelist_lock);
	}

	rcu_read_unlock();

	return mca_cannibalize_lock(c, cl);
}

static int btree_check_reserve(struct btree *b, struct btree_op *op,
			       unsigned extra_nodes)
{
	unsigned depth = btree_node_root(b)->level - b->level;
	enum alloc_reserve reserve = op ? op->reserve : b->btree_id;

	return __btree_check_reserve(b->c, reserve,
			btree_reserve_required_nodes(depth) + extra_nodes,
			op ? &op->cl : NULL);
}

int bch_btree_root_alloc(struct cache_set *c, enum btree_id id,
			 struct closure *cl)
{
	struct btree_op op;
	struct btree *b;

	bch_btree_op_init(&op, id, S8_MAX);

	while (__btree_check_reserve(c, id, 1, &op.cl))
		closure_sync(&op.cl);

	b = bch_btree_node_alloc(c, NULL, 0, id, NULL);

	bkey_copy_key(&b->key, &MAX_KEY);
	six_unlock_write(&b->lock);

	bch_btree_node_write(b, cl);

	bch_btree_set_root(b);
	six_unlock_intent(&b->lock);

	return 0;
}

int bch_btree_root_read(struct cache_set *c, enum btree_id id,
			struct bkey *k, unsigned level)
{
	struct btree_op op;
	struct btree *b;

	bch_btree_op_init(&op, id, S8_MAX);

	while (IS_ERR(b = bch_btree_node_get(c, &op, k, level, NULL))) {
		if (PTR_ERR(b) == -EAGAIN)
			closure_sync(&op.cl);
		else if (PTR_ERR(b) == -EINTR)
			BUG();
		else
			return PTR_ERR(b);
	}

	list_del_init(&b->list);
	btree_node_unlock(&op, b, b->level);

	c->btree_roots[id] = b;

	return 0;
}

/* Garbage collection */

u8 bch_btree_mark_last_gc(struct cache_set *c, struct bkey *k)
{
	u8 max_stale = 0;
	struct cache *ca;
	unsigned i;

	for (i = 0; i < bch_extent_ptrs(k); i++) {
		if (PTR_DEV(k, i) < MAX_CACHES_PER_SET)
			__set_bit(PTR_DEV(k, i), c->cache_slots_used);

		if ((ca = PTR_CACHE(c, k, i))) {
			struct bucket *g = PTR_BUCKET(c, ca, k, i);

			if (gen_after(g->last_gc, PTR_GEN(k, i)))
				g->last_gc = PTR_GEN(k, i);

			max_stale = max(max_stale, ptr_stale(c, ca, k, i));
		}
	}

	return max_stale;
}

u8 __bch_btree_mark_key(struct cache_set *c, int level, struct bkey *k)
{
	u8 max_stale;
	struct cache *ca;
	unsigned i;

	if (KEY_DELETED(k))
		return 0;

	rcu_read_lock();

	max_stale = bch_btree_mark_last_gc(c, k);

	if (level) {
		for (i = 0; i < bch_extent_ptrs(k); i++)
			if ((ca = PTR_CACHE(c, k, i)))
				bch_mark_metadata_bucket(ca,
					PTR_BUCKET(c, ca, k, i));
	} else {
		__bch_add_sectors(c, k, KEY_START(k), KEY_SIZE(k), false, true);
	}

	rcu_read_unlock();

	return max_stale;
}

static u8 btree_mark_key(struct btree *b, struct bkey *k)
{
	bkey_debugcheck(&b->keys, k);

	return __bch_btree_mark_key(b->c, b->level, k);
}

/* Only the extent btree has leafs whose keys point to data */
static inline bool btree_node_has_ptrs(struct btree *b, unsigned level)
{
	return b->btree_id == BTREE_ID_EXTENTS || level > 0;
}

static bool btree_gc_mark_node(struct btree *b, struct gc_stat *gc)
{
	uint8_t stale = 0;
	unsigned keys = 0, good_keys = 0, u64s;
	struct bkey *k;
	struct btree_node_iter iter;
	struct bset_tree *t;

	gc->nodes++;

	if (!btree_node_has_ptrs(b, b->level))
		return 0;

	for_each_btree_node_key(&b->keys, k, &iter) {
		stale = max(stale, btree_mark_key(b, k));
		keys++;

		u64s = bch_extent_nr_ptrs_after_normalize(b->c, k);
		if (u64s) {
			good_keys++;

			gc->key_bytes += KEY_U64s(k);
			gc->nkeys++;
			gc->data += KEY_SIZE(k);
		}
	}

	for (t = b->keys.set; t <= &b->keys.set[b->keys.nsets]; t++)
		btree_bug_on(t->size &&
			     bset_written(&b->keys, t) &&
			     bkey_cmp(&b->key, &t->end) < 0,
			     b, "found short btree key in gc");

	if (b->c->gc_always_rewrite)
		return true;

	if (stale > 10)
		return true;

	if ((keys - good_keys) * 2 > keys)
		return true;

	return false;
}

struct gc_merge_info {
	struct btree	*b;
};

static int btree_gc_coalesce(struct btree *b, struct btree_op *op,
			     struct gc_stat *gc, struct gc_merge_info *r)
{
	unsigned i, nodes, old_nodes, keys = 0;
	unsigned blocks = btree_blocks(b->c) * 2 / 3;
	struct btree *new_nodes[GC_MERGE_NODES];
	struct keylist keylist;
	struct closure cl;

	bch_keylist_init(&keylist);

	memset(new_nodes, 0, sizeof(new_nodes));
	closure_init_stack(&cl);

	for (nodes = 0;
	     nodes < GC_MERGE_NODES && !IS_ERR_OR_NULL(r[nodes].b);
	     nodes++)
		keys += r[nodes].b->keys.nr_live_keys;

	old_nodes = nodes;

	if (nodes <= 1 ||
	    __set_blocks(b->keys.set[0].data,
			 DIV_ROUND_UP(keys, nodes - 1),
			 block_bytes(b->c)) > blocks)
		return 0;

	if (btree_check_reserve(b, NULL, nodes) ||
	    bch_keylist_realloc(&keylist,
			(BKEY_U64s + BKEY_EXTENT_MAX_U64s) * nodes)) {
		trace_bcache_btree_gc_coalesce_fail(b->c);
		return 0;
	}

	trace_bcache_btree_gc_coalesce(b, nodes);

	for (i = 0; i < nodes; i++) {
		new_nodes[i] = btree_node_alloc_replacement(r[i].b, NULL);
		BUG_ON(!new_nodes[i]);
	}

	/*
	 * Conceptually we concatenate the nodes together and slice them
	 * up at different boundaries.
	 */
	for (i = nodes - 1; i > 0; --i) {
		struct bset *n1 = btree_bset_first(new_nodes[i]);
		struct bset *n2 = btree_bset_first(new_nodes[i - 1]);
		struct bkey *k, *last = NULL;

		keys = 0;

		for (k = n2->start;
		     k < bset_bkey_last(n2) &&
		     __set_blocks(n1, n1->keys + keys + KEY_U64s(k),
				  block_bytes(b->c)) <= blocks;
		     k = bkey_next(k)) {
			last = k;
			keys += KEY_U64s(k);
		}

		if (keys == n2->keys) {
			/* n2 fits entirely in n1 */
			bkey_copy_key(&new_nodes[i]->key,
				      &new_nodes[i - 1]->key);

			memcpy(bset_bkey_last(n1),
			       n2->start,
			       n2->keys * sizeof(u64));
			n1->keys += n2->keys;

			six_unlock_write(&new_nodes[i - 1]->lock);
			btree_node_free(new_nodes[i - 1]);
			six_unlock_intent(&new_nodes[i - 1]->lock);

			memmove(new_nodes + i - 1,
				new_nodes + i,
				sizeof(new_nodes[0]) * (nodes - i));
			--nodes;
		} else if (keys) {
			/* move part of n2 into n1 */
			bkey_copy_key(&new_nodes[i]->key, last);

			memcpy(bset_bkey_last(n1),
			       n2->start,
			       keys * sizeof(u64));
			n1->keys += keys;

			memmove(n2->start,
				bset_bkey_idx(n2, keys),
				(n2->keys - keys) * sizeof(u64));
			n2->keys -= keys;
		}
	}

	for (i = 0; i < nodes; i++) {
		new_nodes[i]->keys.nr_live_keys =
			new_nodes[i]->keys.set[0].data->keys;

		six_unlock_write(&new_nodes[i]->lock);
		bch_btree_node_write(new_nodes[i], &cl);
	}

	/* Wait for all the writes to finish */
	closure_sync(&cl);

	/* The keys for the old nodes get deleted */
	for (i = old_nodes - 1; i > 0; --i) {
		*keylist.top = r[i].b->key;
		bch_set_extent_ptrs(keylist.top, 0);
		SET_KEY_DELETED(keylist.top, 1);

		__bch_keylist_push(&keylist);
	}

	/*
	 * Keys for the new nodes get inserted: bch_btree_insert_keys() only
	 * does the lookup once and thus expects the keys to be in sorted order
	 */
	for (i = 0; i < nodes; i++)
		bch_keylist_add_in_order(&keylist, &new_nodes[i]->key);

	/* Insert the newly coalesced nodes */
	bch_btree_insert_node(b, op, &keylist, NULL, NULL);
	BUG_ON(!bch_keylist_empty(&keylist));

	/* Free the old nodes and update our sliding window */
	for (i = 0; i < old_nodes; i++) {
		btree_node_free(r[i].b);
		six_unlock_intent(&r[i].b->lock);

		r[i].b = ERR_PTR(-EINTR);
	}

	for (i = 0; i < nodes; i++)
		r[i].b = new_nodes[i];

	gc->nodes -= old_nodes - nodes;

	bch_keylist_free(&keylist);

	/* Invalidated our iterator */
	return -EINTR;
}

/**
 * btree_gc_rewrite_node - merge node bsets together and update parent
 */
static int btree_gc_rewrite_node(struct btree *b, struct btree_op *op,
				 struct btree *replace)
{
	struct btree *n;

	if (btree_check_reserve(b, NULL, 1)) {
		trace_bcache_btree_gc_rewrite_node_fail(b);
		return 0;
	}

	n = btree_node_alloc_replacement(replace, NULL);
	six_unlock_write(&n->lock);

	trace_bcache_btree_gc_rewrite_node(b);

	bch_btree_node_write_sync(n);

	bch_btree_insert_node(b, op, &keylist_single(&n->key), NULL, NULL);

	btree_node_free(replace);
	six_unlock_intent(&n->lock);

	/* Invalidated our iterator */
	return -EINTR;
}

/**
 * btree_gc_recurse - tracing garbage collection on a node and children
 *
 * This may bail out early for a variety of reasons. This is allowed
 * because concurrent writes will conservatively mark buckets dirty,
 * ensuring they won't be touched until the next GC pass.
 */
static int btree_gc_recurse(struct btree *b, struct btree_op *op,
			    struct gc_stat *gc)
{
	struct cache_set *c = b->c;

	int ret = 0;
	bool should_rewrite;
	struct bkey *k, tmp;
	struct btree_node_iter iter;

	/* Sliding window of GC_MERGE_NODES adjacent btree nodes */
	struct gc_merge_info r[GC_MERGE_NODES];
	struct gc_merge_info *i, *last = r + ARRAY_SIZE(r) - 1;

	for (i = r; i < r + ARRAY_SIZE(r); i++)
		i->b = ERR_PTR(-EINTR);

	if (kthread_should_stop())
		return -ESHUTDOWN;

	tmp = bkey_successor(&c->gc_cur_key);
	bch_btree_node_iter_init(&b->keys, &iter, &tmp);
	while (1) {
		k = bch_btree_node_iter_next(&iter);
		if (k) {
			r->b = bch_btree_node_get(c, op, k, b->level - 1, b);
			if (IS_ERR(r->b)) {
				/* XXX: handle IO error better */
				ret = PTR_ERR(r->b);
				break;
			}

			verify_nr_live_keys(&r->b->keys);

			/* See if we should coalesce */
			ret = btree_gc_coalesce(b, op, gc, r);
			if (ret)
				break;
		}

		if (!last->b)
			break;

		if (!IS_ERR(last->b)) {
			should_rewrite = btree_gc_mark_node(last->b, gc);

			if (!last->b->level) {
				write_seqlock(&c->gc_cur_lock);
				BUG_ON(bkey_cmp(&c->gc_cur_key,
						&last->b->key) > 0);
				bkey_copy_key(&c->gc_cur_key, &last->b->key);
				write_sequnlock(&c->gc_cur_lock);
			}

			if (should_rewrite) {
				ret = btree_gc_rewrite_node(b, op, last->b);
				if (ret)
					break;
			}

			if (last->b->level) {
				ret = btree_gc_recurse(last->b, op, gc);
				if (ret)
					break;
			}

			six_unlock_intent(&last->b->lock);
		}

		memmove(r + 1, r, sizeof(r[0]) * (GC_MERGE_NODES - 1));
		r->b = NULL;

		if (need_resched() || race_fault()) {
			ret = -ETIMEDOUT;
			break;
		}

		if (op->iterator_invalidated) {
			ret = -EINTR;
			break;
		}
	}

	for (i = r; i < r + ARRAY_SIZE(r); i++)
		if (!IS_ERR_OR_NULL(i->b))
			six_unlock_intent(&i->b->lock);

	if (bkey_cmp(&c->gc_cur_key, &MAX_KEY))
		return ret;

	return 0;
}

static int bch_btree_gc_root(struct btree *b, struct btree_op *op,
			     struct gc_stat *gc)
{
	struct btree *n = NULL;
	int ret = 0;
	bool should_rewrite;

	should_rewrite = btree_gc_mark_node(b, gc);
	if (should_rewrite &&
	    btree_check_reserve(b, NULL, 1)) {
		n = btree_node_alloc_replacement(b, NULL);

		six_unlock_write(&n->lock);
		bch_btree_node_write_sync(n);

		bch_btree_set_root(n);
		six_unlock_intent(&n->lock);

		return -EINTR;
	}

	__bch_btree_mark_key(b->c, b->level + 1, &b->key);

	if (b->level) {
		ret = btree_gc_recurse(b, op, gc);
		if (ret)
			return ret;
	} else {
		write_seqlock(&b->c->gc_cur_lock);
		BUG_ON(bkey_cmp(&b->c->gc_cur_key, &b->key) > 0);
		bkey_copy_key(&b->c->gc_cur_key, &b->key);
		write_sequnlock(&b->c->gc_cur_lock);
	}

	return ret;
}

static void btree_gc_start(struct cache_set *c)
{
	struct cache *ca;
	struct bucket *g;
	unsigned i;

	write_seqlock(&c->gc_cur_lock);
	for_each_cache(ca, c, i)
		ca->bucket_stats_cached = __bucket_stats_read(ca);

	c->gc_cur_btree = 0;
	c->gc_cur_key = ZERO_KEY;
	write_sequnlock(&c->gc_cur_lock);

	memset(c->cache_slots_used, 0, sizeof(c->cache_slots_used));

	for_each_cache(ca, c, i)
		for_each_bucket(g, ca) {
			g->last_gc = ca->bucket_gens[g - ca->buckets];
			bch_mark_free_bucket(ca, g);
		}

	/*
	 * must happen before traversing the btree, as pointers move from open
	 * buckets into the btree - if we race and an open_bucket has been freed
	 * before we marked it, it's in the btree now
	 */
	bch_mark_allocator_buckets(c);
}

static void bch_btree_gc_finish(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;

	bch_mark_writeback_keys(c);
	bch_mark_scan_keylist_keys(c, &c->tiering_keys);

	for_each_cache(ca, c, i) {
		unsigned j;
		uint64_t *i;

		bch_mark_scan_keylist_keys(c, &ca->moving_gc_keys);

		for (j = 0; j < bch_nr_journal_buckets(&ca->sb); j++)
			bch_mark_metadata_bucket(ca,
					&ca->buckets[journal_bucket(ca, j)]);

		spin_lock(&ca->prio_buckets_lock);

		for (i = ca->prio_buckets;
		     i < ca->prio_buckets + prio_buckets(ca) * 2; i++)
			bch_mark_metadata_bucket(ca, &ca->buckets[*i]);

		spin_unlock(&ca->prio_buckets_lock);

		atomic_long_set(&ca->saturated_count, 0);
		ca->inc_gen_needs_gc = 0;
	}

	set_gc_sectors(c);

	write_seqlock(&c->gc_cur_lock);
	c->gc_cur_btree = BTREE_ID_NR + 1;
	write_sequnlock(&c->gc_cur_lock);

	/*
	 * Setting gc_cur_btree marks gc as finished, and the allocator threads
	 * will now see the new buckets_available - wake them up in case they
	 * were waiting on it
	 */

	for_each_cache(ca, c, i)
		bch_wake_allocator(ca);
}

/**
 * bch_btree_gc - find reclaimable buckets and clean up the btree
 *
 * This will find buckets that are completely unreachable, as well as those
 * only containing clean data that can be safely discarded. Also, nodes that
 * contain too many bsets are merged up and re-written, and adjacent nodes
 * with low occupancy are coalesced together.
 */
static void bch_btree_gc(struct cache_set *c)
{
	struct gc_stat stats;
	struct btree_op op;
	uint64_t start_time = local_clock();

	if (test_bit(CACHE_SET_GC_FAILURE, &c->flags))
		return;

	trace_bcache_gc_start(c);

	memset(&stats, 0, sizeof(struct gc_stat));

	down_write(&c->gc_lock);
	btree_gc_start(c);

	while (c->gc_cur_btree < BTREE_ID_NR) {
		enum btree_id id = c->gc_cur_btree;
		int ret = 0;

		/* Write lock all nodes */
		bch_btree_op_init(&op, id, S8_MAX);

		if (c->btree_roots[id])
			ret = btree_root(gc_root, c, &op, false, &stats);

		if (ret == -ETIMEDOUT) {
			schedule();
			continue;
		}

		if (ret == -ESHUTDOWN)
			goto gc_failed;

		if (ret) {
			pr_err("garbage collection failed with %d!", ret);
			goto gc_failed;
		}

		write_seqlock(&c->gc_cur_lock);
		c->gc_cur_btree++;
		c->gc_cur_key = ZERO_KEY;
		write_sequnlock(&c->gc_cur_lock);
	}

	bch_btree_gc_finish(c);
	up_write(&c->gc_lock);

	bch_time_stats_update(&c->btree_gc_time, start_time);

	stats.key_bytes *= sizeof(uint64_t);
	stats.data	<<= 9;
	memcpy(&c->gc_stats, &stats, sizeof(struct gc_stat));

	trace_bcache_gc_end(c);
	return;

gc_failed:
	set_bit(CACHE_SET_GC_FAILURE, &c->flags);
	up_write(&c->gc_lock);
}

static int bch_gc_thread(void *arg)
{
	struct cache_set *c = arg;

	while (1) {
		bch_btree_gc(c);

		/* Set task to interruptible first so that if someone wakes us
		 * up while we're finishing up, we will start another GC pass
		 * immediately */
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;

		try_to_freeze();
		schedule();
	}

	return 0;
}

int bch_gc_thread_start(struct cache_set *c)
{
	c->gc_thread = kthread_create(bch_gc_thread, c, "bcache_gc");
	if (IS_ERR(c->gc_thread))
		return PTR_ERR(c->gc_thread);

	wake_up_process(c->gc_thread);
	return 0;
}

/* Initial partial gc */

static int bch_btree_check_recurse(struct btree *b, struct btree_op *op)
{
	int ret = 0;
	struct bkey *k, *p = NULL;
	struct btree_node_iter iter;

	if (btree_node_has_ptrs(b, b->level))
		for_each_btree_node_key(&b->keys, k, &iter)
			btree_mark_key(b, k);

	__bch_btree_mark_key(b->c, b->level + 1, &b->key);

	if (b->level > 0 && btree_node_has_ptrs(b, b->level - 1)) {
		bch_btree_node_iter_init(&b->keys, &iter, NULL);

		do {
			k = bch_btree_node_iter_next(&iter);
			if (k)
				btree_node_prefetch(b, k);

			if (p)
				ret = btree(check_recurse, p, b, op);

			p = k;
		} while (p && !ret);
	}

	return ret;
}

static int bch_btree_check(struct cache_set *c)
{
	struct btree_op op;
	enum btree_id id;
	int ret;

	for (id = 0; id < BTREE_ID_NR; id++) {
		bch_btree_op_init(&op, id, S8_MAX);

		if (c->btree_roots[id]) {
			ret = btree_root(check_recurse, c, &op, false);
			if (ret)
				return ret;
		}
	}

	return 0;
}

int bch_initial_gc(struct cache_set *c, struct list_head *journal)
{
	if (journal) {
		int ret = bch_btree_check(c);

		if (ret)
			return ret;

		bch_journal_mark(c, journal);
	}

	bch_btree_gc_finish(c);
	return 0;
}

/* Btree insertion */

/**
 * btree_insert_key - insert one key into a btree node, and then journal the key
 * that was inserted.
 *
 * Wrapper around bch_btree_insert_key() which does the real heavy lifting, this
 * function journals the key that bch_btree_insert_key() actually inserted
 * (which may have been different than @k if e.g. @replace was only partially
 * present, or not present).
 */
static bool btree_insert_key(struct btree *b, struct keylist *insert_keys,
			     struct bkey *replace, struct btree_node_iter *iter,
			     struct bkey *where, struct journal_res *res,
			     struct closure *flush_cl)
{
	struct bkey done, *insert = bch_keylist_front(insert_keys);
	struct cache_set *c = b->c;
	BKEY_PADDED(key) temp;
	unsigned status;

	bch_btree_node_iter_verify(&b->keys, iter);
	BUG_ON(write_block(b) != btree_bset_last(b));
	BUG_ON(KEY_DELETED(insert) && bch_val_u64s(insert));

	if (b->keys.ops->is_extents) {
		struct bkey *orig = insert;

		bkey_copy(&temp.key, insert);
		insert = &temp.key;

		if (bkey_cmp(insert, &b->key) > 0)
			bch_cut_back(&b->key, insert);

		status = __bch_btree_insert_key(&b->keys, iter, insert,
						replace, where, &done);

		bch_cut_front(&done, orig);
		if (!KEY_SIZE(orig))
			bch_keylist_pop_front(insert_keys);
	} else {
		BUG_ON(bkey_cmp(insert, &b->key) > 0);

		status = __bch_btree_insert_key(&b->keys, iter, insert,
						replace, where, &done);

		bch_keylist_pop_front(insert_keys);
	}

	if (status == BTREE_INSERT_STATUS_NO_INSERT)
		return false;

	if (!btree_node_dirty(b)) {
		set_btree_node_dirty(b);

		if (c->btree_flush_delay)
			schedule_delayed_work(&b->work,
					      c->btree_flush_delay * HZ);
	}

	if (res->ref &&
	    test_bit(JOURNAL_REPLAY_DONE, &c->journal.flags)) {
		struct btree_write *w = btree_current_write(b);

		if (!w->journal) {
			w->journal = &fifo_back(&c->journal.pin);
			atomic_inc(w->journal);
		}

		bch_journal_add_keys(c, res, b->btree_id, insert,
				     KEY_U64s(insert), b->level,
				     bch_keylist_empty(insert_keys)
				     ? flush_cl : NULL);
	}

	bch_check_keys(&b->keys, "%u for %s", status,
		       replace ? "replace" : "insert");

	trace_bcache_btree_insert_key(b, insert, replace != NULL, status);
	return true;
}

enum btree_insert_status {
	BTREE_INSERT_NO_INSERT,
	BTREE_INSERT_INSERTED,
	BTREE_INSERT_NEED_SPLIT,
};

static bool have_enough_space(struct btree *b, struct keylist *insert_keys)
{
	/*
	 * For updates to interior nodes, everything on the
	 * keylist has to be inserted atomically
	 */
	unsigned u64s = b->level
		? bch_keylist_nkeys(insert_keys)
		: b->keys.ops->is_extents
		? BKEY_EXTENT_MAX_U64s * 2
		: KEY_U64s(bch_keylist_front(insert_keys));

	return u64s <= bch_btree_keys_u64s_remaining(&b->keys);
}

static struct bkey *insert_iter_init(struct btree *b,
				     struct btree_node_iter *iter,
				     struct bkey *k)
{
	return bch_btree_node_iter_init(&b->keys, iter, b->keys.ops->is_extents
				   ? &START_KEY(k) : k);
}

static void verify_keys_sorted(struct keylist *l)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	struct bkey *k;

	for (k = l->bot;
	     k < l->top && bkey_next(k) < l->top;
	     k = bkey_next(k))
		BUG_ON(bkey_cmp(k, bkey_next(k)) > 0);
#endif
}

/**
 * bch_btree_insert_keys - insert keys from @insert_keys into btree node @b,
 * until the node is full.
 *
 * If keys couldn't be inserted because @b was full, the caller must split @b
 * and bch_btree_insert_keys() will be called again from btree_split().
 *
 * Caller must either be holding an intent lock on this node only, or intent
 * locks on all nodes all the way up to the root. Caller must not be holding
 * read locks on any nodes.
 */
static enum btree_insert_status
bch_btree_insert_keys(struct btree *b, struct btree_op *op,
		      struct keylist *insert_keys,
		      struct bkey *replace_key,
		      struct closure *flush_cl)
{
	bool done = false, inserted = false,
	     attempted = false, need_split = false;
	struct journal_res res;
	struct btree_node_iter iter;
	struct bkey *where, *k = bch_keylist_front(insert_keys);

	memset(&res, 0, sizeof(res));

	verify_keys_sorted(insert_keys);

	/* index lookup before locks/journal reservation */
	where = insert_iter_init(b, &iter, k);

	while (!done && !bch_keylist_empty(insert_keys)) {
		unsigned n_min = KEY_U64s(bch_keylist_front(insert_keys));
		if (!b->level)
			bch_journal_res_get(b->c, &res,
					    n_min,
					    bch_keylist_nkeys(insert_keys));

		six_lock_write(&b->lock);

		if (write_block(b) != btree_bset_last(b) &&
		    b->keys.last_set_unwritten) {
			/* just wrote a set */
			if (bch_btree_init_next(b)) {
				where = insert_iter_init(b, &iter, k);
				op->iterator_invalidated = 1;
			} else
				where = btree_bset_last(b)->start;
		}

		while (!bch_keylist_empty(insert_keys)) {
			k = bch_keylist_front(insert_keys);

			/* finished for this node */
			if (b->keys.ops->is_extents
			    ? bkey_cmp(&START_KEY(k), &b->key) >= 0
			    : bkey_cmp(k, &b->key) > 0) {
				done = true;
				break;
			}

			if (!have_enough_space(b, insert_keys)) {
				done = true;
				need_split = true;
				break;
			}

			if (!b->level &&
			    jset_u64s(KEY_U64s(k)) > res.nkeys)
				break;

			attempted = true;
			if (btree_insert_key(b, insert_keys, replace_key,
					     &iter, where, &res,
					     bch_keylist_is_last(insert_keys, k)
					     ? flush_cl : NULL)) {
				op->iterator_invalidated = 1;
				inserted = true;
			}
		}

		six_unlock_write(&b->lock);

		if (res.ref)
			bch_journal_res_put(b->c, &res,
					    bch_keylist_empty(insert_keys)
					    ? flush_cl : NULL);
	}

	if (inserted && b->written) {
		/*
		 * Force write if set is too big (or if it's an interior
		 * node, since those aren't journalled yet)
		 */
		if (b->level)
			bch_btree_node_write_sync(b);
		else {
			unsigned long bytes = set_bytes(btree_bset_last(b));

			if (b->io_mutex.count > 0 &&
			    ((max(roundup(bytes, block_bytes(b->c)),
				  PAGE_SIZE) - bytes < 48) ||
			     bytes > (16 << 10)))
				bch_btree_node_write(b, NULL);
		}
	}

	if (attempted && !inserted)
		op->insert_collision = true;

	BUG_ON(!bch_keylist_empty(insert_keys) && inserted && b->level);

	return need_split ? BTREE_INSERT_NEED_SPLIT :
		 inserted ? BTREE_INSERT_INSERTED : BTREE_INSERT_NO_INSERT;
}

static int btree_split(struct btree *b, struct btree_op *op,
		       struct keylist *insert_keys,
		       struct bkey *replace_key,
		       struct closure *flush_cl,
		       struct keylist *parent_keys,
		       struct closure *stack_cl)
{
	struct btree *n1, *n2 = NULL, *n3 = NULL;
	struct bset *set1, *set2;
	uint64_t start_time = local_clock();
	struct bkey *k;
	enum btree_insert_status status;
	int ret;

	BUG_ON(!btree_node_intent_locked(op, btree_node_root(b)->level));

	/* After this check we cannot return -EAGAIN anymore */
	ret = btree_check_reserve(b, op, 0);
	if (ret) {
		/* If splitting an interior node, we've already split a leaf,
		 * so we should have checked for sufficient reserve. We can't
		 * just restart splitting an interior node since we've already
		 * modified the btree. */
		if (!b->level)
			return ret;
		else
			WARN(1, "insufficient reserve for split\n");
	}

	n1 = btree_node_alloc_replacement(b, op);
	set1 = btree_bset_first(n1);

	/*
	 * For updates to interior nodes, we've got to do the insert before we
	 * split because the stuff we're inserting has to be inserted
	 * atomically. Post split, the keys might have to go in different nodes
	 * and the split would no longer be atomic.
	 *
	 * But for updates to leaf nodes (in the extent btree, anyways) - we
	 * can't update the new replacement node while the old node is still
	 * visible. Reason being as we do the update we're updating garbage
	 * collection information on the fly, possibly causing a bucket to
	 * become unreferenced and available to the allocator to reuse - we
	 * don't want that to happen while other threads can still use the old
	 * version of the btree node.
	 */
	if (b->level) {
		six_unlock_write(&n1->lock);
		status = bch_btree_insert_keys(n1, op, insert_keys,
					       replace_key, flush_cl);
		BUG_ON(status != BTREE_INSERT_INSERTED);
		six_lock_write(&n1->lock);

		/*
		 * There might be duplicate (deleted) keys after the
		 * bch_btree_insert_keys() call - we need to remove them before
		 * we split, as it would be rather bad if we picked a duplicate
		 * for the pivot.
		 *
		 * Additionally, inserting might overwrite a bunch of existing
		 * keys (i.e. a big discard when there were a bunch of small
		 * extents previously) - we might not want to split after the
		 * insert. Splitting a node that's too small to be split would
		 * be bad (if the node had only one key, we wouldn't be able to
		 * assign the new node a key different from the original node)
		 */
		k = set1->start;
		while (k != bset_bkey_last(set1))
			if (bkey_deleted(k)) {
				set1->keys -= KEY_U64s(k);
				memmove(k, bkey_next(k),
					(void *) bset_bkey_last(set1) -
					(void *) k);
			} else
				k = bkey_next(k);
	}

	/*
	 * Note that on recursive parent_keys == insert_keys, so we can't start
	 * adding new keys to parent_keys before emptying it out (by doing the
	 * insert, which we just did above)
	 */

	if (set_blocks(set1, block_bytes(n1->c)) > btree_blocks(b->c) * 3 / 4) {
		trace_bcache_btree_node_split(b, set1->keys);

		n2 = bch_btree_node_alloc(b->c, op, b->level,
					  b->btree_id, b->parent);
		set2 = btree_bset_first(n2);

		if (!b->parent) {
			n3 = bch_btree_node_alloc(b->c, op, b->level + 1,
						  b->btree_id, NULL);

			bkey_copy_key(&n3->key, &MAX_KEY);
			six_unlock_write(&n3->lock);

			n1->parent = n3;
			n2->parent = n3;
		}

		/*
		 * Has to be a linear search because we don't have an auxiliary
		 * search tree yet
		 */
		for (k = set1->start;
		     ((u64 *) k - set1->d) < (set1->keys * 3) / 5;
		     k = bkey_next(k))
			;

		bkey_copy_key(&n1->key, k);

		k = bkey_next(k);

		set2->keys = (u64 *) bset_bkey_last(set1) - (u64 *) k;
		set1->keys -= set2->keys;

		n1->keys.nr_live_keys = set1->keys;
		n2->keys.nr_live_keys = set2->keys;

		BUG_ON(!set1->keys);
		BUG_ON(!set2->keys);

		memcpy(set2->start,
		       bset_bkey_last(set1),
		       set2->keys * sizeof(u64));

		bkey_copy_key(&n2->key, &b->key);

		six_unlock_write(&n1->lock);
		six_unlock_write(&n2->lock);

		bch_keylist_add(parent_keys, &n1->key);
		bch_keylist_add(parent_keys, &n2->key);

		bch_btree_node_write(n2, stack_cl);
	} else {
		trace_bcache_btree_node_compact(b, set1->keys);

		six_unlock_write(&n1->lock);
		bch_keylist_add(parent_keys, &n1->key);
	}

	bch_btree_node_write(n1, stack_cl);

	if (n3) {
		/* Depth increases, make a new root */
		bch_btree_insert_keys(n3, op, parent_keys, NULL, false);
		bch_btree_node_write(n3, stack_cl);

		closure_sync(stack_cl);

		bch_btree_set_root(n3);
		six_unlock_intent(&n3->lock);
	} else if (!b->parent) {
		BUG_ON(parent_keys->start_keys_p
		       != &parent_keys->inline_keys[0]);
		bch_keylist_init(parent_keys);

		/* Root filled up but didn't need to be split */
		closure_sync(stack_cl);

		bch_btree_set_root(n1);
	} else {
		/* Split a non root node */
		closure_sync(stack_cl);

		__bch_btree_insert_node(b->parent, op, parent_keys, NULL,
					NULL, parent_keys, stack_cl);
		BUG_ON(!bch_keylist_empty(parent_keys));

		btree_node_free(b);
	}

	op->iterator_invalidated = 1;

	/* New nodes now visible, can finish insert */
	if (!n1->level) {
		status = bch_btree_insert_keys(n1, op, insert_keys,
					       replace_key, flush_cl);
		if (n2 && status != BTREE_INSERT_NEED_SPLIT)
			bch_btree_insert_keys(n2, op, insert_keys,
					      replace_key, flush_cl);
	}

	if (n2)
		six_unlock_intent(&n2->lock);
	six_unlock_intent(&n1->lock);

	bch_time_stats_update(&b->c->btree_split_time, start_time);

	return 0;
}

static int __bch_btree_insert_node(struct btree *b, struct btree_op *op,
				   struct keylist *insert_keys,
				   struct bkey *replace_key,
				   struct closure *flush_cl,
				   struct keylist *split_keys,
				   struct closure *stack_cl)
{
	if (btree_lock_upgrade(b, op, b->level))
		return -EINTR;

	BUG_ON(b->level && replace_key);
	BUG_ON(!b->written);

	if (bch_btree_insert_keys(b, op, insert_keys, replace_key,
				  flush_cl) == BTREE_INSERT_NEED_SPLIT) {
		struct btree *p;
		int level;

		/*
		 * Check if we have intent locks on all parent nodes, if not
		 * try again
		 */
		for (p = b->parent, level = b->level + 1;
		     p;
		     p = p->parent, level++)
			if (!btree_node_intent_locked(op, level)) {
				op->locks_want = btree_node_root(b)->level + 1;
				return -EINTR;
			}

		return btree_split(b, op, insert_keys, replace_key,
				   flush_cl, split_keys, stack_cl);
	}

	return 0;
}

/**
 * bch_btree_insert_node - insert bkeys into a given btree node
 * @b:			parent btree node
 * @op:			pointer to struct btree_op
 * @insert_keys:	list of keys to insert
 * @replace_key:	old key for compare exchange
 * @flush_cl:		if not null, @flush_cl will wait on journal write
 *
 * This is top level for common btree insertion/index update code. The control
 * flow goes roughly like:
 *
 * bch_btree_insert_node
 *     btree_split
 *   bch_btree_insert_keys
 *     btree_insert_key
 *       bch_btree_insert_key
 *         op->insert_fixup
 *         bch_bset_insert
 *
 * Inserts the keys from @insert_keys that belong in node @b; if there's extra
 * keys that go in different nodes, it's up to the caller to insert the rest of
 * the keys in the correct node (@insert_keys might span multiple btree nodes.
 * It must be in sorted order, lowest keys first).
 *
 * The @flush_cl closure is used to wait on btree node allocation as well as
 * the journal write (if @flush is set). The journal wait will only happen
 * if the full list is inserted.
 *
 * Return values:
 * -EAGAIN: @op->cl was put on a waitlist waiting for btree node allocation.
 * -EINTR: locking changed, this function should be called again.
 */
int bch_btree_insert_node(struct btree *b, struct btree_op *op,
			  struct keylist *insert_keys,
			  struct bkey *replace_key,
			  struct closure *flush_cl)
{
	struct closure stack_cl;
	struct keylist split_keys;

	closure_init_stack(&stack_cl);
	bch_keylist_init(&split_keys);

	return __bch_btree_insert_node(b, op, insert_keys, replace_key,
				       flush_cl, &split_keys, &stack_cl);
}

/**
 * bch_btree_insert_check_key - insert dummy key into btree
 *
 * We insert a random key on a cache miss, then compare exchange on it
 * once the cache promotion or backing device read completes. This
 * ensures that if this key is written to after the read, the read will
 * lose and not overwrite the key with stale data.
 *
 * Return values:
 * -EAGAIN: @op.cl was put on a waitlist waiting for btree node allocation
 * -EINTR: btree node was changed while upgrading to write lock
 */
int bch_btree_insert_check_key(struct btree *b, struct btree_op *op,
			       struct bkey *check_key)
{
	BKEY_PADDED(key) tmp;

	bch_set_extent_ptrs(check_key, 1);
	get_random_bytes(&check_key->val[0], sizeof(u64));

	SET_PTR_DEV(check_key, 0, PTR_CHECK_DEV);
	SET_KEY_CACHED(check_key, 1);

	bkey_copy(&tmp.key, check_key);

	return bch_btree_insert_node(b, op, &keylist_single(&tmp.key),
				     NULL, NULL);
}

struct btree_insert_op {
	struct btree_op	op;
	struct keylist	*keys;
	struct bkey	*replace_key;
};

static int btree_insert_fn(struct btree_op *b_op, struct btree *b)
{
	struct btree_insert_op *op = container_of(b_op,
					struct btree_insert_op, op);

	int ret = bch_btree_insert_node(b, &op->op, op->keys,
					op->replace_key, NULL);
	return bch_keylist_empty(op->keys) ? MAP_DONE : ret;
}

/**
 * bch_btree_insert - insert keys into the extent btree
 * @c:			pointer to struct cache_set
 * @id:			btree to insert into
 * @reserve:		reserve to allocate btree node from
 * @insert_keys:	list of keys to insert
 * @replace_key:	old key for compare exchange
 */
int bch_btree_insert(struct cache_set *c, enum btree_id id,
		     struct keylist *keys, struct bkey *replace_key)
{
	struct btree_insert_op op;
	int ret = 0;

	bch_btree_op_init(&op.op, id, 0);
	op.keys		= keys;
	op.replace_key	= replace_key;

	while (!ret && !bch_keylist_empty(keys)) {
		op.op.locks_want = 0;
		ret = bch_btree_map_nodes(&op.op, c,
			       id == BTREE_ID_EXTENTS
					  ? &START_KEY(bch_keylist_front(keys))
					  : (bch_keylist_front(keys)),
					  btree_insert_fn,
					  0);
	}

	BUG_ON(ret);

	if (op.op.insert_collision)
		return -ESRCH;

	return 0;
}

/* Map across nodes or keys */

static int bch_btree_map_nodes_recurse(struct btree *b, struct btree_op *op,
				       struct bkey *from,
				       btree_map_nodes_fn *fn, int flags)
{
	int ret = MAP_CONTINUE;
	unsigned level = b->level;

	if (level) {
		struct bkey *k;
		struct btree_node_iter iter;

		bch_btree_node_iter_init(&b->keys, &iter, from);

		while ((k = bch_btree_node_iter_next(&iter))) {
			ret = btree(map_nodes_recurse, k, b,
				    op, from, fn, flags);
			from = NULL;

			if (ret != MAP_CONTINUE)
				return ret;

			if (!btree_node_relock(b, op, level))
				return -EINTR;

			if (ret == MAP_CONTINUE && need_resched())
				return -EINTR;
		}
	}

	if (!level) {
		ret = fn(op, b);

		if (ret == MAP_CONTINUE && op->iterator_invalidated)
			ret = -EINTR;
	}

	return ret;
}

int bch_btree_map_nodes(struct btree_op *op, struct cache_set *c,
			struct bkey *_from, btree_map_nodes_fn *fn, int flags)
{
	struct bkey from = _from ? *_from : KEY(0, 0, 0);

	if (op->id == BTREE_ID_EXTENTS)
		from = bkey_successor(&from);

	return btree_root(map_nodes_recurse, c, op, flags & MAP_ASYNC,
			  &from, fn, flags);
}

static int do_map_fn(struct btree *b, struct btree_op *op, struct bkey *from,
		     btree_map_keys_fn *fn, struct bkey *k)
{
	int ret;
	struct bkey next = *k;

	if (b->btree_id == BTREE_ID_INODES)
		SET_KEY_INODE(&next, KEY_INODE(&next) + 1);
	else if (b->btree_id != BTREE_ID_EXTENTS)
		next = bkey_successor(&next);

	ret = fn(op, b, k);

	if (ret == MAP_CONTINUE)
		*from = next;

	if (ret == MAP_CONTINUE && op->iterator_invalidated) {
		trace_bcache_btree_iterator_invalidated(b, op);
		ret = -EINTR;
	}

	if (ret == MAP_CONTINUE && need_resched())
		ret = -EINTR;

	return ret;
}

/**
 * map_hole - handle holes for map_keys()
 *
 * calls the map fn for every key in the interval [from, to)
 */
static int map_hole(struct btree *b, struct btree_op *op,
		    struct bkey *from, struct bkey *to,
		    btree_map_keys_fn *fn)
{
	BUG_ON(b->btree_id != BTREE_ID_EXTENTS &&
	       KEY_SIZE(to));

	while (bkey_cmp(from, &START_KEY(to)) < 0) {
		struct bkey next = *from;
		int ret;

		bch_set_val_u64s(&next, 0);

		if (b->btree_id == BTREE_ID_EXTENTS) {
			unsigned size;

			if (KEY_OFFSET(&next) == KEY_OFFSET_MAX) {
				if (KEY_INODE(&next) == KEY_INODE(to))
					return MAP_CONTINUE;

				SET_KEY_INODE(&next, KEY_INODE(&next + 1));
				SET_KEY_OFFSET(&next, 0);
			}

			size = min_t(u64, KEY_SIZE_MAX,
				     (KEY_INODE(to) == KEY_INODE(&next)
				      ? KEY_START(to) : KEY_OFFSET_MAX) -
				     KEY_OFFSET(&next));

			BUG_ON(!size);

			SET_KEY_SIZE(&next, size);
			SET_KEY_OFFSET(&next, KEY_OFFSET(&next) + size);
		}

		ret = do_map_fn(b, op, from, fn, &next);

		if (ret != MAP_CONTINUE)
			return ret;
	}

	return MAP_CONTINUE;
}

static int bch_btree_map_keys_recurse(struct btree *b, struct btree_op *op,
				      struct bkey *from, btree_map_keys_fn *fn,
				      int flags)
{
	int ret = MAP_CONTINUE;
	struct bkey *k, search = *from;
	struct btree_node_iter iter;
	unsigned level = b->level;

	if (b->btree_id == BTREE_ID_EXTENTS)
		search = bkey_successor(&search);

	bch_btree_node_iter_init(&b->keys, &iter, &search);

	while ((k = bch_btree_node_iter_next(&iter))) {
		BUG_ON(bkey_cmp(k, from) < 0);

		if (!level) {
			if (flags & MAP_HOLES) {
				ret = map_hole(b, op, from, k, fn);

				if (ret != MAP_CONTINUE)
					goto out;
			}

			ret = do_map_fn(b, op, from, fn, k);
		} else {
			ret = btree(map_keys_recurse, k, b,
				    op, from, fn, flags);
		}

		if (ret != MAP_CONTINUE)
			goto out;

		if (!btree_node_relock(b, op, level)) {
			ret = -EINTR;
			goto out;
		}
	}

	/* whatever is left up to the end of the btree node is a hole */
	if (!level) {
		/*
		 * map_hole() expects a half open interval - [from, next)
		 *
		 * the btree node contains keys in the interval (.., * b->key],
		 *
		 * for extents (which are half open intervals) this all works
		 * out magically, but for non extents we need to pass b->key + 1
		 */
		struct bkey next = b->key;

		if (b->btree_id != BTREE_ID_EXTENTS &&
		    bkey_cmp(&b->key, &MAX_KEY))
			next = bkey_successor(&next);

		/* If we're not mapping holes, we need to advance @from to
		 * ensure that we don't re-visit the same leaf node again in
		 * the case where that leaf node has no keys */
		if (flags & MAP_HOLES)
			ret = map_hole(b, op, from, &next, fn);
		else
			*from = next;
	}

out:
	/*
	 * If there's no more work to be done, don't do the lookup again,
	 * we will crash in the bkey_successor() call at the top here
	 */
	if (ret == -EINTR && bkey_cmp(from, &MAX_KEY) == 0)
		ret = 0;
	return ret;
}

/**
 * bch_btree_map_keys - iterate over keys in the b-tree
 * @op:			private to the b-tree code, caller must initialize with
 *			bch_btree_op_init()
 * @c:			cache set to run against
 * @from:		key to start iterating from
 * @fn:			function to apply to each key
 * @flags:		optional arguments
 *
 * Iterates over the b-tree in sorted order (low to high) starting at @from, and
 * applies @fn to each key it finds.
 *
 * @fn should return either MAP_DONE, MAP_CONTINUE, or an error:
 *
 *  - if @fn returns MAP_DONE, bch_btree_map_keys() will return success (0).
 *  - if @fn returns MAP_CONTINUE, bch_btree_map_keys() advances to the next key
 *  - if @fn returns an error, bch_btree_map_keys() will return that error
 *    - unless that error was -EINTR, which means "redo the previous lookup" -
 *      we won't advance to the next key, instead we redo the b-tree traversal
 *      from the root and @fn will be passed the same key again (unless it races
 *      with other threads modifying the b-tree). This is used for e.g.
 *      upgrading to intent locks without deadlocking.
 *
 * If MAP_HOLES is passed in @flags, @fn is also called for holes in the
 * keyspace - it will cover everything in the given range of the keyspace
 * precisely once, and bch_btree_map_keys() will synthesize keys to pass to @fn
 * for the holes. @fn can check whether the key it was passed corresponds to a
 * hole by checking whether bch_val_u64s() is nonzero - a nonempty value
 * indicates a real key.
 */
int bch_btree_map_keys(struct btree_op *op, struct cache_set *c,
		       struct bkey *_from, btree_map_keys_fn *fn,
		       int flags)
{
	struct bkey from;

	bkey_init(&from);

	if (_from) {
		BUG_ON(!bkey_cmp(_from, &MAX_KEY));
		bkey_copy_key(&from, _from);
	}

	return btree_root(map_keys_recurse, c, op, flags & MAP_ASYNC,
			  &from, fn, flags);
}
