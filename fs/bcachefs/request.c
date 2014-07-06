/*
 * Main bcache entry point - handle a read or a write request and decide what to
 * do with it; the make_request functions are called by the block layer.
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "alloc.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"
#include "journal.h"
#include "keybuf.h"
#include "request.h"
#include "writeback.h"
#include "stats.h"

#include <linux/module.h>
#include <linux/hash.h>
#include <linux/random.h>
#include <linux/backing-dev.h>

#include <trace/events/bcachefs.h>

#define CUTOFF_CACHE_ADD	10
#define CUTOFF_CACHE_READA	15

struct kmem_cache *bch_search_cache;

static inline void mark_cache_stats(struct cache_stat_collector *stats,
				    bool hit, bool bypass)
{
	atomic_inc(&stats->cache_hit_array[!bypass][!hit]);
}

static inline void bch_mark_cache_accounting(struct cache_set *c,
					     struct cached_dev *dc,
					     bool hit, bool bypass)
{
	mark_cache_stats(&dc->accounting.collector, hit, bypass);
	mark_cache_stats(&c->accounting.collector, hit, bypass);
}

static inline void bch_mark_sectors_bypassed(struct cache_set *c,
					     struct cached_dev *dc,
					     unsigned sectors)
{
	atomic_add(sectors, &dc->accounting.collector.sectors_bypassed);
	atomic_add(sectors, &c->accounting.collector.sectors_bypassed);
}

static inline void bch_mark_gc_write(struct cache_set *c, int sectors)
{
	atomic_add(sectors, &c->accounting.collector.gc_write_sectors);
}

static inline void bch_mark_foreground_write(struct cache_set *c, int sectors)
{
	atomic_add(sectors, &c->accounting.collector.foreground_write_sectors);
}

static inline void bch_mark_discard(struct cache_set *c, int sectors)
{
	atomic_add(sectors, &c->accounting.collector.discard_sectors);
}

static void bch_data_insert_start(struct closure *);

static void bio_csum(struct bio *bio, struct bkey *k)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	uint64_t csum = 0;

	bio_for_each_segment(bv, bio, iter) {
		void *d = kmap(bv.bv_page) + bv.bv_offset;
		csum = bch_crc64_update(csum, d, bv.bv_len);
		kunmap(bv.bv_page);
	}

	k->val[bch_extent_ptrs(k)] = csum & (~0ULL >> 1);
}

/* Insert data into cache */

static enum alloc_reserve bch_btree_reserve(struct data_insert_op *op)
{
	if (op->moving_gc) {
		/*
		 * free_inc.size buckets are set aside for moving GC
		 * btree node allocations. This means that if moving GC
		 * runs out of new buckets for btree nodes, it will have
		 * put back at least free_inc.size buckets back on
		 * free_inc, preventing a deadlock.
		 *
		 * XXX: figure out a less stupid way of achieving this
		 */
		return RESERVE_MOVINGGC_BTREE;
	} else if (op->tiering) {
		/*
		 * Tiering needs a btree node reserve because of how
		 * btree_check_reserve() works -- if the cache tier is
		 * full, we don't want tiering to block forever.
		 */
		return RESERVE_TIERING_BTREE;
	}

	return BTREE_ID_EXTENTS;
}

static int btree_insert_fn(struct btree_op *b_op, struct btree *b)
{
	struct data_insert_op *op = container_of(b_op,
					struct data_insert_op, op);
	struct bkey *replace_key = op->replace ? &op->replace_key : NULL;

	int ret = bch_btree_insert_node(b, &op->op, &op->insert_keys,
					replace_key, op->flush);
	return bch_keylist_empty(&op->insert_keys) ? MAP_DONE : ret;
}

static void bch_data_insert_keys_done(struct closure *cl)
{
	struct data_insert_op *op = container_of(cl, struct data_insert_op, cl);
	unsigned i;

	if (op->op.insert_collision)
		op->replace_collision = true;

	for (i = 0; i < ARRAY_SIZE(op->open_buckets); i++)
		if (op->open_buckets[i]) {
			bch_open_bucket_put(op->c, op->open_buckets[i]);
			op->open_buckets[i] = NULL;
		}

	if (!op->insert_data_done)
		continue_at(cl, bch_data_insert_start, op->c->wq);

	bch_keylist_free(&op->insert_keys);
	closure_return(cl);
}

static void __bch_data_insert_keys(struct closure *cl)
{
	struct data_insert_op *op = container_of(cl, struct data_insert_op,
					op.cl);
	struct keylist *keys = &op->insert_keys;
	int ret = 0;

	while (!ret && !bch_keylist_empty(keys)) {
		op->op.lock = 0;
		ret = bch_btree_map_nodes(&op->op, op->c,
					  &START_KEY(keys->keys),
					  btree_insert_fn,
					  MAP_ASYNC);
	}

	if (ret == -EAGAIN)
		continue_at(cl, __bch_data_insert_keys, op->c->wq);

	closure_return(cl);
}

/**
 * bch_data_insert_keys - insert extent btree keys for a write
 */
static void bch_data_insert_keys(struct closure *cl)
{
	struct data_insert_op *op = container_of(cl, struct data_insert_op, cl);
	enum btree_id id = BTREE_ID_EXTENTS;
	enum alloc_reserve reserve;

	reserve = bch_btree_reserve(op);
	__bch_btree_op_init(&op->op, id, reserve, 0);

	closure_call(&op->op.cl, __bch_data_insert_keys, NULL, cl);
	continue_at(cl, bch_data_insert_keys_done, op->c->wq);
}

/**
 * bch_data_invalidate - discard range of keys
 *
 * Used to implement discard, and to handle when writethrough write hits
 * a write error on the cache device.
 */
static void bch_data_invalidate(struct closure *cl)
{
	struct data_insert_op *op = container_of(cl, struct data_insert_op, cl);
	struct keylist *keys = &op->insert_keys;
	struct bio *bio = op->bio;

	pr_debug("invalidating %i sectors from %llu",
		 bio_sectors(bio), (uint64_t) bio->bi_iter.bi_sector);

	while (bio_sectors(bio)) {
		unsigned sectors = min(bio_sectors(bio),
				       1U << (KEY_SIZE_BITS - 1));

		if (bch_keylist_realloc(keys, BKEY_U64s))
			goto out;

		bio->bi_iter.bi_sector	+= sectors;
		bio->bi_iter.bi_size	-= sectors << 9;

		*keys->top = KEY(KEY_INODE(&op->insert_key),
				 bio->bi_iter.bi_sector, sectors);
		SET_KEY_DELETED(keys->top, true);

		bch_keylist_push(keys);
	}

	op->insert_data_done = true;
	bio_put(bio);
out:
	continue_at(cl, bch_data_insert_keys, op->c->wq);
}

static void bch_data_insert_error(struct closure *cl)
{
	struct data_insert_op *op = container_of(cl, struct data_insert_op, cl);

	/*
	 * Our data write just errored, which means we've got a bunch of keys to
	 * insert that point to data that wasn't succesfully written.
	 *
	 * We don't have to insert those keys but we still have to invalidate
	 * that region of the cache - so, if we just strip off all the pointers
	 * from the keys we'll accomplish just that.
	 */

	struct bkey *src = op->insert_keys.keys, *dst = op->insert_keys.keys;

	while (src != op->insert_keys.top) {
		struct bkey *n = bkey_next(src);

		bch_set_extent_ptrs(src, 0);
		memmove(dst, src, bkey_bytes(src));

		dst = bkey_next(dst);
		src = n;
	}

	op->insert_keys.top = dst;

	bch_data_insert_keys(cl);
}

static void bch_data_insert_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;
	struct data_insert_op *op = container_of(cl, struct data_insert_op, cl);

	if (bio->bi_error) {
		/* TODO: We could try to recover from this. */
		if (!KEY_CACHED(&op->insert_key))
			op->error = bio->bi_error;
		else if (!op->replace)
			set_closure_fn(cl, bch_data_insert_error,
				       op->c->wq);
		else
			set_closure_fn(cl, NULL, NULL);
	}

	bch_bbio_endio(op->c, bio, bio->bi_error, "writing data to cache");
}

static void bch_data_insert_start(struct closure *cl)
{
	struct data_insert_op *op = container_of(cl, struct data_insert_op, cl);
	unsigned long ptrs_to_write[BITS_TO_LONGS(MAX_CACHES_PER_SET)];
	struct bio *bio = op->bio, *n;
	unsigned open_bucket_nr = 0;
	struct open_bucket *b;

	if (op->discard)
		return bch_data_invalidate(cl);

	/*
	 * Journal writes are marked REQ_PREFLUSH; if the original write was a
	 * flush, it'll wait on the journal write.
	 */
	bio->bi_opf &= ~(REQ_PREFLUSH|REQ_FUA);

	do {
		struct bkey *k;
		struct bio_set *split = op->c->bio_split;

		BUG_ON(bio_sectors(bio) != KEY_SIZE(&op->insert_key));

		if (open_bucket_nr == ARRAY_SIZE(op->open_buckets))
			continue_at(cl, bch_data_insert_keys,
				    op->c->wq);

		/* for the device pointers and 1 for the chksum */
		if (bch_keylist_realloc(&op->insert_keys,
					KEY_U64s(&op->insert_key) +
					BKEY_PAD_PTRS +
					(KEY_CSUM(&op->insert_key) ? 1 : 0)))
			continue_at(cl, bch_data_insert_keys, op->c->wq);

		memset(ptrs_to_write, 0, sizeof(ptrs_to_write));

		k = op->insert_keys.top;
		bkey_copy(k, &op->insert_key);

		b = op->moving_gc
			? bch_gc_alloc_sectors(op->c, k, ptrs_to_write, cl)
			: bch_alloc_sectors(op->c, k, op->write_point, op->tier,
					    ptrs_to_write,
					    op->wait ? cl : NULL);
		BUG_ON(!b);
		if (PTR_ERR(b) == -EAGAIN) {
			/* If we already have some keys, must insert them first
			 * before allocating another open bucket. We only hit
			 * this case if open_bucket_nr > 1. */
			if (bch_keylist_empty(&op->insert_keys))
				continue_at(cl, bch_data_insert_start,
					    op->c->wq);
			else
				continue_at(cl, bch_data_insert_keys,
					    op->c->wq);
		} else if (IS_ERR(b))
			goto err;

		op->open_buckets[open_bucket_nr++] = b;

		bch_cut_front(k, &op->insert_key);

		n = bio_next_split(bio, KEY_SIZE(k), GFP_NOIO, split);
		n->bi_end_io	= bch_data_insert_endio;
		n->bi_private	= cl;

		if (KEY_CSUM(k))
			bio_csum(n, k);

		trace_bcache_cache_insert(k);

		bio_set_op_attrs(n, REQ_OP_WRITE, 0);
		bch_submit_bbio_replicas(n, op->c, k, ptrs_to_write, false);

		bch_extent_normalize(op->c, k);
		bch_keylist_push(&op->insert_keys);
	} while (n != bio);

	op->insert_data_done = true;
	continue_at(cl, bch_data_insert_keys, op->c->wq);
err:
	BUG_ON(op->wait);

	/*
	 * But if it's not a writeback write we'd rather just bail out if
	 * there aren't any buckets ready to write to - it might take awhile and
	 * we might be starving btree writes for gc or something.
	 */

	if (!op->replace) {
		/*
		 * Writethrough write: We can't complete the write until we've
		 * updated the index. But we don't want to delay the write while
		 * we wait for buckets to be freed up, so just invalidate the
		 * rest of the write.
		 */
		op->discard = true;
		return bch_data_invalidate(cl);
	} else {
		/*
		 * From a cache miss, we can just insert the keys for the data
		 * we have written or bail out if we didn't do anything.
		 */
		op->insert_data_done = true;
		bio_put(bio);

		if (!bch_keylist_empty(&op->insert_keys))
			continue_at(cl, bch_data_insert_keys, op->c->wq);
		else
			closure_return(cl);
	}
}

/**
 * bch_data_insert - handle a write to a cache device or flash only volume
 *
 * This is the starting point for any data to end up in a cache device; it could
 * be from a normal write, or a writeback write, or a write to a flash only
 * volume - it's also used by the moving garbage collector to compact data in
 * mostly empty buckets.
 *
 * It first writes the data to the cache, creating a list of keys to be inserted
 * (if the data had to be fragmented there will be multiple keys); after the
 * data is written it calls bch_journal, and after the keys have been added to
 * the next journal write they're inserted into the btree.
 *
 * It inserts the data in s->cache_bio; bi_sector is used for the key offset,
 * and op->inode is used for the key inode.
 *
 * If op->discard is true, instead of inserting the data it invalidates the
 * region of the cache represented by s->cache_bio and op->inode.
 */
void bch_data_insert(struct closure *cl)
{
	struct data_insert_op *op = container_of(cl, struct data_insert_op, cl);
	struct cache_set *c = op->c;
	u64 inode = KEY_INODE(&op->insert_key);

	trace_bcache_write(c, inode, op->bio, !KEY_CACHED(&op->insert_key),
			   op->discard);

	memset(op->open_buckets, 0, sizeof(op->open_buckets));

	if (!bio_sectors(op->bio)) {
		WARN_ONCE(1, "bch_data_insert() called with empty bio");
		closure_return(cl);
	}

	if (!op->discard)
		bch_increment_clock(c, bio_sectors(op->bio), WRITE);

	if (!op->replace) {
		/* XXX: discards may be for more sectors than max key size */

		struct bkey start = KEY(inode, op->bio->bi_iter.bi_sector, 0);
		struct bkey end = KEY(inode, bio_end_sector(op->bio), 0);

		unsigned i;
		struct cache *ca;

		for_each_cache(ca, c, i)
			bch_keybuf_check_overlapping(&ca->moving_gc_keys,
						     &start, &end);

		bch_keybuf_check_overlapping(&c->tiering_keys,
					     &start, &end);
	}

	if (op->moving_gc)
		bch_mark_gc_write(c, bio_sectors(op->bio));
	else if (!op->discard)
		bch_mark_foreground_write(c, bio_sectors(op->bio));
	else
		bch_mark_discard(c, bio_sectors(op->bio));

	if (atomic_sub_return(bio_sectors(op->bio),
			      &c->sectors_until_gc) < 0) {
		set_gc_sectors(c);
		wake_up_gc(c, true);
	}

	SET_KEY_OFFSET(&op->insert_key, bio_end_sector(op->bio));
	SET_KEY_SIZE(&op->insert_key, bio_sectors(op->bio));

	bch_keylist_init(&op->insert_keys);
	bio_get(op->bio);
	continue_at_nobarrier(cl, bch_data_insert_start, NULL);
}

/* Cache promotion on read */

struct cache_promote_op {
	struct closure		cl;
	struct bio		*orig_bio;
	struct data_insert_op	iop;
	bool			stale; /* was the ptr stale after the read? */
	struct bbio		bio; /* must be last */
};

static void cache_promote_done(struct closure *cl)
{
	struct cache_promote_op *op = container_of(cl,
					struct cache_promote_op, cl);
	struct cache_set *c = op->iop.c;

	if (op->iop.replace_collision) {
		trace_bcache_promote_collision(&op->iop.replace_key);
		atomic_inc(&c->accounting.collector.cache_miss_collisions);
	}

	bio_free_pages(op->iop.bio);
	kfree(op);
}

static void cache_promote_write(struct closure *cl)
{
	struct cache_promote_op *op = container_of(cl,
					struct cache_promote_op, cl);
	struct bio *bio = op->iop.bio;

	bio_reset(bio);
	bio->bi_iter.bi_sector	= KEY_START(&op->iop.insert_key);
	bio->bi_iter.bi_size	= KEY_SIZE(&op->iop.insert_key) << 9;
	/* needed to reinit bi_vcnt so pages can be freed later */
	bch_bio_map(bio, NULL);

	bio_copy_data(op->orig_bio, bio);
	op->orig_bio->bi_error = op->iop.error;
	bio_endio(op->orig_bio);

	if (!op->stale &&
	    !op->iop.error &&
	    !test_bit(CACHE_SET_STOPPING, &op->iop.c->flags))
		closure_call(&op->iop.cl, bch_data_insert, NULL, cl);

	closure_return_with_destructor(cl, cache_promote_done);
}

static void cache_promote_endio(struct bio *bio)
{
	struct bbio *b = to_bbio(bio);
	struct cache_promote_op *op = container_of(b,
					struct cache_promote_op, bio);

	/*
	 * If the bucket was reused while our bio was in flight, we might have
	 * read the wrong data. Set s->error but not error so it doesn't get
	 * counted against the cache device, but we'll still reread the data
	 * from the backing device.
	 */

	if (bio->bi_error)
		op->iop.error = bio->bi_error;
	else if (ptr_stale(op->iop.c, &b->key, 0))
		op->stale = 1;

	bch_bbio_endio(op->iop.c, bio, bio->bi_error, "reading from cache");
}

/**
 * __cache_promote -- insert result of read bio into cache
 *
 * @orig_bio must actually be a bbio with a valid key.
 */
static void __cache_promote(struct cache_set *c, struct bbio *orig_bio,
			    struct bkey *replace_key, bio_end_io_t *bi_end_io)
{
	struct cache_promote_op *op;
	struct bio *bio;
	unsigned pages = DIV_ROUND_UP(orig_bio->bio.bi_iter.bi_size, PAGE_SIZE);

	/* XXX: readahead? */

	op = kmalloc(sizeof(*op) + sizeof(struct bio_vec) * pages, GFP_NOIO);
	if (!op)
		goto out_submit;

	bkey_copy(&op->bio.key, &orig_bio->key);
	bio = &op->bio.bio;
	bio_init(bio);
	bio_get(bio);
	bio->bi_bdev		= orig_bio->bio.bi_bdev;
	bio->bi_iter.bi_sector	= orig_bio->bio.bi_iter.bi_sector;
	bio->bi_iter.bi_size	= orig_bio->bio.bi_iter.bi_size;
	bio->bi_end_io		= bi_end_io;
	bio->bi_private		= &op->cl;
	bio->bi_io_vec		= bio->bi_inline_vecs;
	bch_bio_map(bio, NULL);

	if (bio_alloc_pages(bio, __GFP_NOWARN|GFP_NOIO))
		goto out_free;

	closure_init(&op->cl, &c->cl);
	op->orig_bio		= &orig_bio->bio;
	op->stale		= 0;

	bch_data_insert_op_init(&op->iop, c,
				bio,
				hash_long((unsigned long) current, 16),
				false,
				false,
				false,
				replace_key,
				replace_key);

	bch_cut_front(&START_KEY(&orig_bio->key), &op->iop.insert_key);
	bch_cut_back(&orig_bio->key, &op->iop.insert_key);

	trace_bcache_promote(&orig_bio->bio);

	op->bio.submit_time_us = local_clock_us();
	closure_bio_submit(bio, &op->cl);

	continue_at(&op->cl, cache_promote_write, c->wq);
out_free:
	kfree(op);
out_submit:
	generic_make_request(&orig_bio->bio);
}

/**
 * cache_promote - promote data stored in higher tiers
 *
 * @bio must actually be a bbio with valid key.
 */
static bool cache_promote(struct cache_set *c, struct bbio *bio,
			  struct bkey *k, unsigned ptr)
{
	struct cache *ca = PTR_CACHE(c, k, ptr);

	if (!CACHE_TIER(&ca->sb)) {
		generic_make_request(&bio->bio);
		return 0;
	}

	__cache_promote(c, bio, k, cache_promote_endio);
	return 1;
}

/* Congested? */

unsigned bch_get_congested(struct cache_set *c)
{
	int i;
	long rand;

	if (!c->congested_read_threshold_us &&
	    !c->congested_write_threshold_us)
		return 0;

	i = (local_clock_us() - c->congested_last_us) / 1024;
	if (i < 0)
		return 0;

	i += atomic_read(&c->congested);
	if (i >= 0)
		return 0;

	i += CONGESTED_MAX;

	if (i > 0)
		i = fract_exp_two(i, 6);

	rand = get_random_int();
	i -= bitmap_weight(&rand, BITS_PER_LONG);

	return i > 0 ? i : 1;
}

static void add_sequential(struct task_struct *t)
{
	t->sequential_io_avg = ewma_add(t->sequential_io_avg,
					t->sequential_io, 3);
	t->sequential_io = 0;
}

static struct hlist_head *iohash(struct cached_dev *dc, uint64_t k)
{
	return &dc->io_hash[hash_64(k, RECENT_IO_BITS)];
}

static bool check_should_bypass(struct cached_dev *dc, struct bio *bio, int rw)
{
	struct cache_set *c = dc->disk.c;
	unsigned mode = BDEV_CACHE_MODE(&dc->sb);
	unsigned sectors, congested = bch_get_congested(c);
	struct task_struct *task = current;
	struct io *i;
	u64 available = buckets_available(dc->disk.c);

	if (test_bit(BCACHE_DEV_DETACHING, &dc->disk.flags) ||
	    available * 100 < (u64) dc->disk.c->nbuckets * CUTOFF_CACHE_ADD ||
	    (bio_op(bio) == REQ_OP_DISCARD))
		goto skip;

	if (mode == CACHE_MODE_NONE ||
	    (mode == CACHE_MODE_WRITEAROUND &&
	     op_is_write(bio_op(bio))))
		goto skip;

	if (bio->bi_iter.bi_sector & (c->sb.block_size - 1) ||
	    bio_sectors(bio) & (c->sb.block_size - 1)) {
		pr_debug("skipping unaligned io");
		goto skip;
	}

	if (bypass_torture_test(dc)) {
		if ((get_random_int() & 3) == 3)
			goto skip;
		else
			goto rescale;
	}

	if (!congested && !dc->sequential_cutoff)
		goto rescale;

	if (!congested &&
	    mode == CACHE_MODE_WRITEBACK &&
	    op_is_write(bio_op(bio)) &&
	    (bio->bi_opf & REQ_SYNC))
		goto rescale;

	spin_lock(&dc->io_lock);

	hlist_for_each_entry(i, iohash(dc, bio->bi_iter.bi_sector), hash)
		if (i->last == bio->bi_iter.bi_sector &&
		    time_before(jiffies, i->jiffies))
			goto found;

	i = list_first_entry(&dc->io_lru, struct io, lru);

	add_sequential(task);
	i->sequential = 0;
found:
	if (i->sequential + bio->bi_iter.bi_size > i->sequential)
		i->sequential	+= bio->bi_iter.bi_size;

	i->last			 = bio_end_sector(bio);
	i->jiffies		 = jiffies + msecs_to_jiffies(5000);
	task->sequential_io	 = i->sequential;

	hlist_del(&i->hash);
	hlist_add_head(&i->hash, iohash(dc, i->last));
	list_move_tail(&i->lru, &dc->io_lru);

	spin_unlock(&dc->io_lock);

	sectors = max(task->sequential_io,
		      task->sequential_io_avg) >> 9;

	if (dc->sequential_cutoff &&
	    sectors >= dc->sequential_cutoff >> 9) {
		trace_bcache_bypass_sequential(bio);
		goto skip;
	}

	if (congested && sectors >= congested) {
		trace_bcache_bypass_congested(bio);
		goto skip;
	}

rescale:
	return false;
skip:
	bch_mark_sectors_bypassed(c, dc, bio_sectors(bio));
	return true;
}

/* Cache lookup */

/* XXX: consolidate these somehow */

struct bch_read_op {
	struct btree_op		op;
	struct cache_set	*c;
	struct bio		*bio;
	u64			inode;
};

/* XXX: this looks a lot like cache_lookup_fn() */
static int bch_read_fn(struct btree_op *b_op, struct btree *b, struct bkey *k)
{
	struct bch_read_op *op = container_of(b_op,
			struct bch_read_op, op);
	struct bio *n, *bio = op->bio;
	struct bbio *bbio;
	int sectors, ret;
	int ptr = 0;

	if (bkey_cmp(k, &KEY(op->inode, bio->bi_iter.bi_sector, 0)) <= 0)
		return MAP_CONTINUE;

	if (KEY_INODE(k) != op->inode ||
	    KEY_START(k) >= bio_end_sector(bio)) {
		/* Completely missed */
		zero_fill_bio(bio);
		return MAP_DONE;
	}

	if (KEY_START(k) > bio->bi_iter.bi_sector) {
		unsigned bytes = (KEY_START(k) - bio->bi_iter.bi_sector) << 9;

		swap(bytes, bio->bi_iter.bi_size);
		zero_fill_bio(bio);
		swap(bytes, bio->bi_iter.bi_size);

		bio_advance(bio, bytes);
	}

	ptr = bch_extent_pick_ptr(b->c, k);
	if (ptr < 0) /* all stale? */
		return MAP_CONTINUE;

	sectors = min_t(u64, INT_MAX,
			KEY_OFFSET(k) - bio->bi_iter.bi_sector);

	if (sectors >= bio_sectors(bio)) {
		n = bio_clone_fast(bio, GFP_NOIO, b->c->bio_split);
		ret = MAP_DONE;
	} else {
		n = bio_split(bio, sectors, GFP_NOIO, b->c->bio_split);
		ret = MAP_CONTINUE;
	}

	bio_chain(n, bio);

	bbio = to_bbio(n);
	bch_bkey_copy_single_ptr(&bbio->key, k, ptr);

	/* Trim the key to match what we're actually reading */
	bch_cut_front(&KEY(op->inode, n->bi_iter.bi_sector, 0), &bbio->key);
	bch_cut_back(&KEY(op->inode, bio_end_sector(n), 0), &bbio->key);

	__bch_bbio_prep(bbio, b->c);

	cache_promote(b->c, bbio, k, ptr);

	return ret;
}

int bch_read(struct cache_set *c, struct bio *bio, u64 inode)
{
	struct bch_read_op op;
	int ret;

	bch_increment_clock(c, bio_sectors(bio), READ);

	zero_fill_bio(bio);

	bch_btree_op_init(&op.op, BTREE_ID_EXTENTS, -1);
	op.c = c;
	op.bio = bio;
	op.inode = inode;

	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(inode, bio->bi_iter.bi_sector, 0),
				 bch_read_fn, 0);
	return ret < 0 ? ret : 0;
}
EXPORT_SYMBOL(bch_read);

/* struct search based code */

struct search {
	/* Stack frame for bio_complete */
	struct closure		cl;

	struct bbio		bio;
	/* Not modified */
	struct bio		*orig_bio;
	struct bcache_device	*d;

	unsigned		inode;
	unsigned		write:1;

	/* Flags only used for reads */
	unsigned		recoverable:1;
	unsigned		read_dirty_data:1;
	unsigned		cache_miss:1;

	/*
	 * For reads:  bypass read from cache and insertion into cache
	 * For writes: discard key range from cache, sending the write to
	 *             the backing device (if there is a backing device)
	 */
	unsigned		bypass:1;

	unsigned long		start_time;

	/* Only used for reads */
	struct btree_op		op;

	/*
	 * Mostly only used for writes. For reads, we still make use of
	 * some trivial fields:
	 * - c
	 * - error
	 */
	struct data_insert_op	iop;
};

static void bch_cache_read_endio(struct bio *bio)
{
	struct bbio *b = to_bbio(bio);
	struct closure *cl = bio->bi_private;
	struct search *s = container_of(cl, struct search, cl);

	/*
	 * If the bucket was reused while our bio was in flight, we might have
	 * read the wrong data. Set s->error but not error so it doesn't get
	 * counted against the cache device, but we'll still reread the data.
	 */

	if (bio->bi_error)
		s->iop.error = bio->bi_error;
	else if (ptr_stale(s->iop.c, &b->key, 0)) {
		atomic_long_inc(&s->iop.c->cache_read_races);
		s->iop.error = -EINTR;
	}

	bch_bbio_endio(s->iop.c, bio, bio->bi_error, "reading from cache");
}

/*
 * Read from a single key, handling the initial cache miss if the key starts in
 * the middle of the bio
 */
static int cache_lookup_fn(struct btree_op *op, struct btree *b, struct bkey *k)
{
	struct search *s = container_of(op, struct search, op);
	struct bio *n, *bio = &s->bio.bio;
	struct bbio *bbio;
	unsigned sectors;
	int ptr;

	BUG_ON(bkey_cmp(&START_KEY(k),
			&KEY(s->inode, bio->bi_iter.bi_sector, 0)) > 0);

	BUG_ON(bkey_cmp(k, &KEY(s->inode, bio->bi_iter.bi_sector, 0)) <= 0);

	sectors = KEY_OFFSET(k) - bio->bi_iter.bi_sector;

	ptr = bch_extent_pick_ptr(b->c, k);
	if (ptr < 0) /* no pointers (hole), or all stale */
		return s->d->cache_miss(b, s, bio, sectors);

	PTR_BUCKET(b->c, k, ptr)->read_prio = b->c->read_clock.hand;

	if (!KEY_CACHED(k))
		s->read_dirty_data = true;

	n = bio_next_split(bio, sectors, GFP_NOIO, s->d->bio_split);

	bbio = to_bbio(n);
	bch_bkey_copy_single_ptr(&bbio->key, k, ptr);

	/* Trim the key to match what we're actually reading */
	bch_cut_front(&KEY(s->inode, n->bi_iter.bi_sector, 0), &bbio->key);
	bch_cut_back(&KEY(s->inode, bio_end_sector(n), 0), &bbio->key);

	__bch_bbio_prep(bbio, b->c);

	n->bi_end_io		= bch_cache_read_endio;
	n->bi_private		= &s->cl;

	/*
	 * The bucket we're reading from might be reused while our bio
	 * is in flight, and we could then end up reading the wrong
	 * data.
	 *
	 * We guard against this by checking (in cache_read_endio()) if
	 * the pointer is stale again; if so, we treat it as an error
	 * and reread from the backing device (but we don't pass that
	 * error up anywhere).
	 */
	closure_get(&s->cl);
	if (!s->bypass) {
		if (cache_promote(b->c, bbio, k, ptr))
			s->cache_miss = 1;
	} else
		submit_bio(n);

	return n == bio ? MAP_DONE : MAP_CONTINUE;
}

/**
 * cache_lookup - handle a read from a cache or flash only volume
 */
static void cache_lookup(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, op.cl);
	enum btree_id id = BTREE_ID_EXTENTS;
	struct bio *bio = &s->bio.bio;
	int ret;

	__bch_btree_op_init(&s->op, id, id, -1);

	ret = bch_btree_map_keys(&s->op, s->iop.c,
				 &KEY(s->inode, bio->bi_iter.bi_sector, 0),
				 cache_lookup_fn, MAP_HOLES | MAP_ASYNC);
	if (ret == -EAGAIN)
		continue_at(cl, cache_lookup, s->iop.c->wq);
	else if (ret)
		pr_err("error %i", ret);

	closure_return(cl);
}

/* Common code for the make_request functions */

static void request_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;

	if (bio->bi_error) {
		struct search *s = container_of(cl, struct search, cl);
		s->iop.error = bio->bi_error;
		/* Only cache read errors are recoverable */
		s->recoverable = false;
	}

	bio_put(bio);
	closure_put(cl);
}

static void bio_complete(struct search *s)
{
	if (s->orig_bio) {
		generic_end_io_acct(bio_data_dir(s->orig_bio),
				    &s->d->disk->part0, s->start_time);

		trace_bcache_request_end(s->d, s->orig_bio);
		s->orig_bio->bi_error = s->iop.error;
		bio_endio(s->orig_bio);
		s->orig_bio = NULL;
	}
}

static void do_bio_hook(struct search *s, struct bio *orig_bio)
{
	struct bio *bio = &s->bio.bio;

	bio_init(bio);
	__bio_clone_fast(bio, orig_bio);
	bio->bi_end_io		= request_endio;
	bio->bi_private		= &s->cl;

	bio_cnt_set(bio, 3);
}

static void search_free(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	bio_complete(s);

	if (s->iop.bio)
		bio_put(s->iop.bio);

	closure_debug_destroy(cl);
	mempool_free(s, s->d->c->search);
}

static inline struct search *search_alloc(struct bio *bio,
					  struct bcache_device *d)
{
	struct search *s;

	s = mempool_alloc(d->c->search, GFP_NOIO);

	closure_init(&s->cl, NULL);
	do_bio_hook(s, bio);

	s->orig_bio		= bio;
	s->d			= d;
	s->recoverable		= 1;
	s->bypass		= 0;
	s->write		= op_is_write(bio_op(bio));
	s->read_dirty_data	= 0;
	s->cache_miss		= 0;
	s->start_time		= jiffies;
	s->inode		= bcache_dev_inum(d);

	s->iop.c		= d->c;
	s->iop.bio		= NULL;
	s->iop.error		= 0;

	return s;
}

/* Cached devices */

static void cached_dev_bio_complete(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	search_free(cl);
	cached_dev_put(dc);
}

/* Process reads */

static void cached_dev_read_error(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct bio *bio = &s->bio.bio;

	if (s->recoverable) {
		/* Retry from the backing device: */
		trace_bcache_read_retry(s->orig_bio);

		s->iop.error = 0;
		do_bio_hook(s, s->orig_bio);

		/* XXX: invalidate cache, don't count twice */

		closure_bio_submit(bio, cl);
	}

	continue_at(cl, cached_dev_bio_complete, NULL);
}

static void cached_dev_read_done(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	if (dc->verify && s->recoverable && !s->read_dirty_data)
		bch_data_verify(dc, s->orig_bio);

	continue_at_nobarrier(cl, cached_dev_bio_complete, NULL);
}

static void cached_dev_read_done_bh(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	bch_mark_cache_accounting(s->iop.c, dc, !s->cache_miss, s->bypass);
	trace_bcache_read(s->orig_bio, !s->cache_miss, s->bypass);

	if (s->iop.error)
		continue_at_nobarrier(cl, cached_dev_read_error, s->iop.c->wq);
	else if (dc->verify)
		continue_at_nobarrier(cl, cached_dev_read_done, s->iop.c->wq);
	else
		continue_at_nobarrier(cl, cached_dev_bio_complete, NULL);
}

/**
 * cached_dev_cache_miss - populate cache with data from backing device
 *
 * We don't write to the cache if s->bypass is set.
 */
static int cached_dev_cache_miss(struct btree *b, struct search *s,
				 struct bio *bio, unsigned sectors)
{
	int ret;
	unsigned reada = 0;
	struct bio *miss;
	BKEY_PADDED(key) replace;

	if (s->bypass) {
		miss = bio_next_split(bio, sectors, GFP_NOIO, s->d->bio_split);

		miss->bi_end_io		= request_endio;
		miss->bi_private	= &s->cl;
		closure_bio_submit(miss, &s->cl);

		return miss == bio ? MAP_DONE : MAP_CONTINUE;
	}
#if 0
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	/* XXX: broken */
	if (!(bio->bi_opf & REQ_RAHEAD) &&
	    !(bio->bi_opf & REQ_META) &&
	    ((u64) buckets_available(dc->disk.c) * 100 <
	     (u64) b->c->nbuckets * CUTOFF_CACHE_READA))
		reada = min_t(sector_t, dc->readahead >> 9,
			      bdev_sectors(bio->bi_bdev) - bio_end_sector(bio));
#endif
	sectors = min(sectors, bio_sectors(bio) + reada);

	replace.key = KEY(s->inode, bio->bi_iter.bi_sector + sectors, sectors);

	ret = bch_btree_insert_check_key(b, &s->op, &replace.key);
	if (ret)
		return ret;

	s->cache_miss = 1;

	miss = bio_next_split(bio, sectors, GFP_NOIO, s->d->bio_split);

	miss->bi_end_io		= request_endio;
	miss->bi_private	= &s->cl;

	to_bbio(miss)->key = KEY(s->inode,
				 bio_end_sector(miss),
				 bio_sectors(miss));

	closure_get(&s->cl);
	__cache_promote(b->c, to_bbio(miss), &replace.key, request_endio);

	return miss == bio ? MAP_DONE : MAP_CONTINUE;
}

static void cached_dev_read(struct cached_dev *dc, struct search *s)
{
	struct closure *cl = &s->cl;

	bch_increment_clock(s->iop.c, bio_sectors(&s->bio.bio), READ);

	closure_call(&s->op.cl, cache_lookup, NULL, cl);
	continue_at(cl, cached_dev_read_done_bh, NULL);
}

/* Process writes */

static void cached_dev_write_complete(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	up_read_non_owner(&dc->writeback_lock);
	cached_dev_bio_complete(cl);
}

static void cached_dev_write(struct cached_dev *dc, struct search *s)
{
	struct closure *cl = &s->cl;
	struct bio *bio = &s->bio.bio;
	unsigned inode = bcache_dev_inum(&dc->disk);
	struct bkey start = KEY(inode, bio->bi_iter.bi_sector, 0);
	struct bkey end = KEY(inode, bio_end_sector(bio), 0);
	bool writeback = false;
	bool bypass = s->bypass;
	struct bkey insert_key = KEY(s->inode, 0, 0);
	struct bio *insert_bio;

	down_read_non_owner(&dc->writeback_lock);
	if (bch_keybuf_check_overlapping(&dc->writeback_keys, &start, &end)) {
		/*
		 * We overlap with some dirty data undergoing background
		 * writeback, force this write to writeback
		 */
		bypass = false;
		writeback = true;
	}

	/*
	 * Discards aren't _required_ to do anything, so skipping if
	 * check_overlapping returned true is ok
	 *
	 * But check_overlapping drops dirty keys for which io hasn't started,
	 * so we still want to call it.
	 */
	if (bio_op(bio) == REQ_OP_DISCARD)
		bypass = true;

	if (should_writeback(dc, bio, BDEV_CACHE_MODE(&dc->sb),
			     bypass)) {
		bypass = false;
		writeback = true;
	}

	if (bypass) {
		insert_bio = s->orig_bio;
		bio_get(insert_bio);

		/* If this is a bypass-write (as opposed to a discard), send
		 * it down to the backing device. If this is a discard, only
		 * send it to the backing device if the backing device
		 * supports discards. Otherwise, we simply discard the key
		 * range from the cache and don't touch the backing device. */
		if ((bio_op(bio) != REQ_OP_DISCARD) ||
		    blk_queue_discard(bdev_get_queue(dc->bdev)))
			closure_bio_submit(bio, cl);
	} else if (writeback) {
		insert_bio = bio;
		bch_writeback_add(dc);

		if (bio->bi_opf & REQ_PREFLUSH) {
			/* Also need to send a flush to the backing device */
			struct bio *flush = bio_alloc_bioset(GFP_NOIO, 0,
							     dc->disk.bio_split);

			flush->bi_bdev	= bio->bi_bdev;
			flush->bi_end_io = request_endio;
			flush->bi_private = cl;
			bio_set_op_attrs(flush, REQ_OP_WRITE, WRITE_FLUSH);

			closure_bio_submit(flush, cl);
		}
	} else {
		insert_bio = bio_clone_fast(bio, GFP_NOIO, dc->disk.bio_split);
		SET_KEY_CACHED(&insert_key, true);

		closure_bio_submit(bio, cl);
	}

	bch_data_insert_op_init(&s->iop, dc->disk.c, insert_bio,
				hash_long((unsigned long) current, 16),
				!KEY_CACHED(&insert_key), bypass,
				bio->bi_opf & (REQ_PREFLUSH|REQ_FUA),
				&insert_key, NULL);

	closure_call(&s->iop.cl, bch_data_insert, NULL, cl);
	continue_at(cl, cached_dev_write_complete, NULL);
}

static void cached_dev_nodata(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct bio *bio = &s->bio.bio;

	if (s->orig_bio->bi_opf & (REQ_PREFLUSH|REQ_FUA))
		bch_journal_meta(s->iop.c, cl);

	/* If it's a flush, we send the flush to the backing device too */
	closure_bio_submit(bio, cl);

	continue_at(cl, cached_dev_bio_complete, NULL);
}

/* Cached devices - read & write stuff */

static void __cached_dev_make_request(struct request_queue *q, struct bio *bio)
{
	struct search *s;
	struct bcache_device *d = bio->bi_bdev->bd_disk->private_data;
	struct cached_dev *dc = container_of(d, struct cached_dev, disk);
	int rw = bio_data_dir(bio);

	generic_start_io_acct(rw, bio_sectors(bio), &d->disk->part0);

	bio->bi_bdev = dc->bdev;
	bio->bi_iter.bi_sector += dc->sb.data_offset;

	if (cached_dev_get(dc)) {
		s = search_alloc(bio, d);
		trace_bcache_request_start(s->d, bio);

		if (!bio->bi_iter.bi_size) {
			/*
			 * can't call bch_journal_meta from under
			 * generic_make_request
			 */
			continue_at_nobarrier(&s->cl,
					      cached_dev_nodata,
					      d->c->wq);
		} else {
			s->bypass = check_should_bypass(dc, bio, rw);

			if (rw)
				cached_dev_write(dc, s);
			else
				cached_dev_read(dc, s);
		}
	} else {
		if ((bio_op(bio) == REQ_OP_DISCARD) &&
		    !blk_queue_discard(bdev_get_queue(dc->bdev)))
			bio_endio(bio);
		else
			generic_make_request(bio);
	}
}

static blk_qc_t cached_dev_make_request(struct request_queue *q,
					struct bio *bio)
{
	__cached_dev_make_request(q, bio);
	return BLK_QC_T_NONE;
}

static int cached_dev_ioctl(struct bcache_device *d, fmode_t mode,
			    unsigned int cmd, unsigned long arg)
{
	struct cached_dev *dc = container_of(d, struct cached_dev, disk);
	return __blkdev_driver_ioctl(dc->bdev, mode, cmd, arg);
}

static int cached_dev_congested(void *data, int bits)
{
	struct bcache_device *d = data;
	struct cached_dev *dc = container_of(d, struct cached_dev, disk);
	struct request_queue *q = bdev_get_queue(dc->bdev);
	int ret = 0;

	if (bdi_congested(&q->backing_dev_info, bits))
		return 1;

	if (cached_dev_get(dc)) {
		unsigned i;
		struct cache *ca;

		for_each_cache(ca, d->c, i) {
			q = bdev_get_queue(ca->bdev);
			ret |= bdi_congested(&q->backing_dev_info, bits);
		}

		cached_dev_put(dc);
	}

	return ret;
}

void bch_cached_dev_request_init(struct cached_dev *dc)
{
	struct gendisk *g = dc->disk.disk;

	g->queue->make_request_fn		= cached_dev_make_request;
	g->queue->backing_dev_info.congested_fn = cached_dev_congested;
	dc->disk.cache_miss			= cached_dev_cache_miss;
	dc->disk.ioctl				= cached_dev_ioctl;
}

/* Flash backed devices */

/**
 * flash_dev_cache_miss - handle read from a hole in a flash only volume
 */
static int flash_dev_cache_miss(struct btree *b, struct search *s,
				struct bio *bio, unsigned sectors)
{
	unsigned bytes = min(sectors, bio_sectors(bio)) << 9;

	swap(bio->bi_iter.bi_size, bytes);
	zero_fill_bio(bio);
	swap(bio->bi_iter.bi_size, bytes);

	bio_advance(bio, bytes);

	if (!bio->bi_iter.bi_size)
		return MAP_DONE;

	return MAP_CONTINUE;
}

static void flash_dev_nodata(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);

	if (s->orig_bio->bi_opf & (REQ_PREFLUSH|REQ_FUA))
		bch_journal_meta(s->iop.c, cl);

	continue_at(cl, search_free, NULL);
}

static void flash_dev_read_error(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct bio *bio = &s->bio.bio;

	if (s->recoverable) {
		trace_bcache_read_retry(s->orig_bio);

		s->iop.error = 0;
		do_bio_hook(s, s->orig_bio);

		/* XXX: invalidate cache, don't count twice */

		closure_bio_submit(bio, cl);
	}

	continue_at(cl, search_free, NULL);
}

/* XXX: this looks a lot like cached_dev_read_done_bh() */
static void flash_dev_read_done_bh(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);

	if (s->iop.error)
		continue_at_nobarrier(cl, flash_dev_read_error, s->iop.c->wq);
	else if (!s->cache_miss)
		atomic_inc(&s->iop.c->accounting.collector.cache_hits);
	else
		atomic_inc(&s->iop.c->accounting.collector.cache_misses);

	continue_at_nobarrier(cl, search_free, NULL);
}

static void __flash_dev_make_request(struct request_queue *q, struct bio *bio)
{
	struct search *s;
	struct closure *cl;
	struct bcache_device *d = bio->bi_bdev->bd_disk->private_data;
	int rw = bio_data_dir(bio);

	generic_start_io_acct(rw, bio_sectors(bio), &d->disk->part0);

	s = search_alloc(bio, d);
	cl = &s->cl;
	bio = &s->bio.bio;

	trace_bcache_request_start(s->d, bio);

	if (!bio->bi_iter.bi_size) {
		/*
		 * can't call bch_journal_meta from under
		 * generic_make_request
		 */
		continue_at_nobarrier(&s->cl,
				      flash_dev_nodata,
				      d->c->wq);
	}

	if (rw) {
		bch_data_insert_op_init(&s->iop, d->c, bio,
					hash_long((unsigned long) current, 16),
					true,
					bio_op(bio) == REQ_OP_DISCARD,
					bio->bi_opf & (REQ_PREFLUSH|REQ_FUA),
					&KEY(s->inode, 0, 0), NULL);

		closure_call(&s->iop.cl, bch_data_insert, NULL, cl);
		continue_at(cl, search_free, NULL);
	} else {
		bch_increment_clock(d->c, bio_sectors(bio), READ);
		closure_call(&s->op.cl, cache_lookup, NULL, cl);
		continue_at(cl, flash_dev_read_done_bh, NULL);
	}
}

static blk_qc_t flash_dev_make_request(struct request_queue *q, struct bio *bio)
{
	__flash_dev_make_request(q, bio);
	return BLK_QC_T_NONE;
}

static int flash_dev_ioctl(struct bcache_device *d, fmode_t mode,
			   unsigned int cmd, unsigned long arg)
{
	return -ENOTTY;
}

static int flash_dev_congested(void *data, int bits)
{
	struct bcache_device *d = data;
	struct request_queue *q;
	struct cache *ca;
	unsigned i;
	int ret = 0;

	for_each_cache(ca, d->c, i) {
		q = bdev_get_queue(ca->bdev);
		ret |= bdi_congested(&q->backing_dev_info, bits);
	}

	return ret;
}

void bch_flash_dev_request_init(struct bcache_device *d)
{
	struct gendisk *g = d->disk;

	g->queue->make_request_fn		= flash_dev_make_request;
	g->queue->backing_dev_info.congested_fn = flash_dev_congested;
	d->cache_miss				= flash_dev_cache_miss;
	d->ioctl				= flash_dev_ioctl;
}

void bch_request_exit(void)
{
	kmem_cache_destroy(bch_search_cache);
}

int __init bch_request_init(void)
{
	bch_search_cache = KMEM_CACHE(search, 0);
	if (!bch_search_cache)
		return -ENOMEM;

	return 0;
}
