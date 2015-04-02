/*
 * Some low level IO code, and hacks for various block layer limitations
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "alloc.h"
#include "bset.h"
#include "btree.h"
#include "buckets.h"
#include "debug.h"
#include "extents.h"
#include "gc.h"
#include "io.h"
#include "keylist.h"
#include "notify.h"
#include "stats.h"
#include "super.h"

#include <linux/blkdev.h>

#include <trace/events/bcachefs.h>

void bch_generic_make_request(struct bio *bio, struct cache_set *c)
{
	if (current->bio_list) {
		spin_lock(&c->bio_submit_lock);
		bio_list_add(&c->bio_submit_list, bio);
		spin_unlock(&c->bio_submit_lock);
		queue_work(bcache_io_wq, &c->bio_submit_work);
	} else {
		generic_make_request(bio);
	}
}

void bch_bio_submit_work(struct work_struct *work)
{
	struct cache_set *c = container_of(work, struct cache_set,
					   bio_submit_work);
	struct bio *bio;

	while (1) {
		spin_lock(&c->bio_submit_lock);
		bio = bio_list_pop(&c->bio_submit_list);
		spin_unlock(&c->bio_submit_lock);

		if (!bio)
			break;

		bch_generic_make_request(bio, c);
	}
}

/* Bios with headers */

void bch_bbio_free(struct bio *bio, struct cache_set *c)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	mempool_free(b, c->bio_meta);
}

struct bio *bch_bbio_alloc(struct cache_set *c)
{
	struct bbio *b = mempool_alloc(c->bio_meta, GFP_NOIO);
	struct bio *bio = &b->bio;

	bio_init(bio);
	bio->bi_max_vecs	 = c->btree_pages;
	bio->bi_io_vec		 = bio->bi_inline_vecs;

	return bio;
}

void bch_bbio_prep(struct bbio *b, struct cache *ca)
{
	struct bvec_iter *iter = &b->bio.bi_iter;

	b->ca				= ca;
	b->bio.bi_iter.bi_sector	= PTR_OFFSET(&b->ptr);
	b->bio.bi_bdev			= ca ? ca->disk_sb.bdev : NULL;

	b->bi_idx			= iter->bi_idx;
	b->bi_bvec_done			= iter->bi_bvec_done;
}

/* XXX: should be bkey, not bkey_i */
void bch_submit_bbio(struct bbio *b, struct cache *ca, const struct bkey_i *k,
		     const struct bch_extent_ptr *ptr, bool punt)
{
	struct bio *bio = &b->bio;

	b->key = *k;
	b->ptr = *ptr;
	bch_set_extent_ptrs(bkey_i_to_s_extent(&b->key), 1);
	bch_bbio_prep(b, ca);
	b->submit_time_us = local_clock_us();

	if (!ca) {
		bcache_io_error(ca->set, bio, "device has been removed");
	} else if (punt)
		closure_bio_submit_punt(bio, bio->bi_private, ca->set);
	else
		closure_bio_submit(bio, bio->bi_private);
}

void bch_submit_bbio_replicas(struct bio *bio, struct cache_set *c,
			      const struct bkey_i *k, unsigned ptrs_from,
			      bool punt)
{
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
	struct cache *ca;
	unsigned ptr;

	for (ptr = ptrs_from;
	     ptr < bch_extent_ptrs(e);
	     ptr++) {
		rcu_read_lock();
		ca = PTR_CACHE(c, &e.v->ptr[ptr]);
		if (ca)
			percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		if (!ca) {
			bch_submit_bbio(to_bbio(bio), ca, k,
					&e.v->ptr[ptr], punt);
			break;
		}

		if (ptr + 1 < bch_extent_ptrs(e)) {
			struct bio *n = bio_clone_fast(bio, GFP_NOIO,
						       ca->replica_set);
			n->bi_end_io		= bio->bi_end_io;
			n->bi_private		= bio->bi_private;
			bch_submit_bbio(to_bbio(n), ca, k,
					&e.v->ptr[ptr], punt);
		} else {
			bch_submit_bbio(to_bbio(bio), ca, k,
					&e.v->ptr[ptr], punt);
		}
	}
}

static void bch_bbio_reset(struct bbio *b)
{
	struct bvec_iter *iter = &b->bio.bi_iter;

	bio_reset(&b->bio);
	iter->bi_sector		= bkey_start_offset(&b->key.k);
	iter->bi_size		= b->key.k.size << 9;
	iter->bi_idx		= b->bi_idx;
	iter->bi_bvec_done	= b->bi_bvec_done;
}

/* IO errors */

void bch_count_io_errors(struct cache *ca, int error, const char *m)
{
	/*
	 * The halflife of an error is:
	 * log2(1/2)/log2(127/128) * refresh ~= 88 * refresh
	 */

	if (ca->set->error_decay) {
		unsigned count = atomic_inc_return(&ca->io_count);

		while (count > ca->set->error_decay) {
			unsigned errors;
			unsigned old = count;
			unsigned new = count - ca->set->error_decay;

			/*
			 * First we subtract refresh from count; each time we
			 * succesfully do so, we rescale the errors once:
			 */

			count = atomic_cmpxchg(&ca->io_count, old, new);

			if (count == old) {
				count = new;

				errors = atomic_read(&ca->io_errors);
				do {
					old = errors;
					new = ((uint64_t) errors * 127) / 128;
					errors = atomic_cmpxchg(&ca->io_errors,
								old, new);
				} while (old != errors);
			}
		}
	}

	if (error) {
		char buf[BDEVNAME_SIZE];

		atomic_add(1 << IO_ERROR_SHIFT, &ca->io_errors);
		queue_work(system_long_wq, &ca->io_error_work);
		printk_ratelimited(KERN_ERR "%s: IO error on %s",
		       bdevname(ca->disk_sb.bdev, buf), m);
	}
}

void bch_cache_io_error_work(struct work_struct *work)
{
	struct cache *ca = container_of(work, struct cache, io_error_work);
	unsigned errors = atomic_read(&ca->io_errors);
	char buf[BDEVNAME_SIZE];

	if (errors < ca->set->error_limit) {
		bch_notify_cache_error(ca, false);
	} else {
		bch_notify_cache_error(ca, true);
		printk_ratelimited(KERN_ERR "%s: too many IO errors, removing",
		       bdevname(ca->disk_sb.bdev, buf));
		bch_cache_remove(ca, true);
	}
}

void bch_bbio_count_io_errors(struct bbio *bio, int error, const char *m)
{
	struct cache_set *c;
	unsigned threshold;

	if (!bio->ca)
		return;

	c = bio->ca->set;
	threshold = op_is_write(bio_op(&bio->bio))
		? c->congested_write_threshold_us
		: c->congested_read_threshold_us;

	if (threshold && bio->submit_time_us) {
		unsigned t = local_clock_us();

		int us = t - bio->submit_time_us;
		int congested = atomic_read(&c->congested);

		if (us > (int) threshold) {
			int ms = us / 1024;
			c->congested_last_us = t;

			ms = min(ms, CONGESTED_MAX + congested);
			atomic_sub(ms, &c->congested);
		} else if (congested < 0)
			atomic_inc(&c->congested);
	}

	bch_count_io_errors(bio->ca, error, m);
}

void bch_bbio_endio(struct bbio *bio, int error, const char *m)
{
	struct closure *cl = bio->bio.bi_private;
	struct cache *ca = bio->ca;

	bch_bbio_count_io_errors(bio, error, m);
	bio_put(&bio->bio);
	if (ca)
		percpu_ref_put(&ca->ref);
	closure_put(cl);
}

/* Writes */

static inline bool version_stress_test(struct cache_set *c)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	return c->version_stress_test;
#else
	return false;
#endif
}

static void __bch_write(struct closure *);

#if 0
static void bio_csum(struct bio *bio, struct bkey *k)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	u64 crc = 0xffffffffffffffffULL;

	bio_for_each_segment(bv, bio, iter) {
		void *d = kmap(bv.bv_page) + bv.bv_offset;

		crc = bch_checksum_update(KEY_CSUM(k), crc, d, bv.bv_len);
		kunmap(bv.bv_page);
	}

	k->val[bch_extent_ptrs(k)] = crc;
}
#endif

static void bch_write_done(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(op->open_buckets); i++)
		if (op->open_buckets[i]) {
			bch_open_bucket_put(op->c, op->open_buckets[i]);
			op->open_buckets[i] = NULL;
		}

	if (!op->write_done)
		continue_at(cl, __bch_write, op->io_wq);

	percpu_ref_put(&op->c->writes);
	bch_keylist_free(&op->insert_keys);
	closure_return(cl);
}

/**
 * bch_write_index - after a write, update index to point to new data
 */
static void bch_write_index(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);

	int ret = bch_btree_insert(op->c, BTREE_ID_EXTENTS, &op->insert_keys,
				   op->replace ? &op->replace_info : NULL,
				   op->flush ? &op->cl : NULL);
	if (ret) {
		__bcache_io_error(op->c, "btree IO error");
		op->error = ret;
	} else if (op->replace && op->replace_info.successes == 0)
		op->replace_collision = true;

	continue_at(cl, bch_write_done, op->c->wq);
}

/**
 * bch_write_discard - discard range of keys
 *
 * Used to implement discard, and to handle when writethrough write hits
 * a write error on the cache device.
 */
static void bch_write_discard(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bio *bio = op->bio;
	u64 inode = op->insert_key.k.p.inode;

	op->error = bch_discard(op->c,
				POS(inode, bio->bi_iter.bi_sector),
				POS(inode, bio_end_sector(bio)),
				op->insert_key.k.version);
}

static void bch_write_error(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);

	/*
	 * Our data write just errored, which means we've got a bunch of keys to
	 * insert that point to data that wasn't successfully written.
	 *
	 * We don't have to insert those keys but we still have to invalidate
	 * that region of the cache - so, if we just strip off all the pointers
	 * from the keys we'll accomplish just that.
	 */

	struct bkey_i *src = bch_keylist_front(&op->insert_keys);
	struct bkey_i *dst = bch_keylist_front(&op->insert_keys);

	while (src != op->insert_keys.top) {
		struct bkey_i *n = bkey_next(src);

		set_bkey_val_u64s(&src->k, 0);
		src->k.type = KEY_TYPE_DISCARD;
		memmove(dst, src, bkey_bytes(&src->k));

		dst = bkey_next(dst);
		src = n;
	}

	op->insert_keys.top = dst;

	bch_write_index(cl);
}

static void bch_write_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);

	if (bio->bi_error) {
		/* TODO: We could try to recover from this. */
		if (!bkey_extent_cached(bkey_i_to_s_c(&op->insert_key))) {
			__bcache_io_error(op->c, "IO error writing data");
			op->error = bio->bi_error;
		} else if (!op->replace)
			set_closure_fn(cl, bch_write_error, op->c->wq);
		else
			set_closure_fn(cl, NULL, NULL);
	}

	bch_bbio_endio(to_bbio(bio), bio->bi_error, "writing data to cache");
}

static void __bch_write(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bio *bio = op->bio, *n;
	unsigned open_bucket_nr = 0, ptrs_from;
	struct open_bucket *b;

	memset(op->open_buckets, 0, sizeof(op->open_buckets));

	if (op->discard) {
		op->write_done = true;
		bch_write_discard(cl);
		bio_put(bio);
		continue_at(cl, bch_write_done, op->c->wq);
	}

	bch_extent_drop_stale(op->c, bkey_i_to_s(&op->insert_key));
	ptrs_from = bch_extent_ptrs(bkey_i_to_s_extent(&op->insert_key));

	/*
	 * Journal writes are marked REQ_PREFLUSH; if the original write was a
	 * flush, it'll wait on the journal write.
	 */
	bio->bi_opf &= ~(REQ_PREFLUSH|REQ_FUA);

	do {
		struct bkey_i *k;
		struct bio_set *split = op->c->bio_split;

		BUG_ON(bio_sectors(bio) != op->insert_key.k.size);

		if (open_bucket_nr == ARRAY_SIZE(op->open_buckets))
			continue_at(cl, bch_write_index,
				    op->c->wq);

		/* for the device pointers and 1 for the chksum */
		if (bch_keylist_realloc(&op->insert_keys,
					BKEY_EXTENT_MAX_U64s))
			continue_at(cl, bch_write_index, op->c->wq);

		k = op->insert_keys.top;
		bkey_copy(k, &op->insert_key);

		b = bch_alloc_sectors(op->c, op->wp, k,
				      op->check_enospc,
				      op->nowait ? NULL : cl);
		BUG_ON(!b);

		if (PTR_ERR(b) == -EAGAIN) {
			/* If we already have some keys, must insert them first
			 * before allocating another open bucket. We only hit
			 * this case if open_bucket_nr > 1. */
			if (bch_keylist_empty(&op->insert_keys))
				continue_at(cl, __bch_write,
					    op->io_wq);
			else
				continue_at(cl, bch_write_index,
					    op->c->wq);
		} else if (IS_ERR(b))
			goto err;

		op->open_buckets[open_bucket_nr++] = b;

		bch_cut_front(k->k.p, &op->insert_key);

		n = bio_next_split(bio, k->k.size, GFP_NOIO, split);
		n->bi_end_io	= bch_write_endio;
		n->bi_private	= cl;
#if 0
		if (KEY_CSUM(k))
			bio_csum(n, k);
#endif
		trace_bcache_cache_insert(&k->k);

		bio_set_op_attrs(n, REQ_OP_WRITE, 0);
		bch_submit_bbio_replicas(n, op->c, k, ptrs_from, false);

		BUG_ON(bch_extent_normalize(op->c, bkey_i_to_s(k)));
		bch_check_mark_super(op->c, k, false);

		/*
		 * Do this after normalize since EXTENT_CACHED is stored
		 * in the first pointer
		 */
		if (op->cached && k->k.type == BCH_EXTENT)
			SET_EXTENT_CACHED(&bkey_i_to_extent(k)->v, true);

		bch_keylist_enqueue(&op->insert_keys);
	} while (n != bio);

	op->write_done = true;
	continue_at(cl, bch_write_index, op->c->wq);
err:
	if (op->cached) {
		/*
		 * If we were writing cached data, not doing the write is fine
		 * so long as we discard whatever would have been overwritten -
		 * then it's equivalent to doing the write and immediately
		 * reclaiming it.
		 */

		bch_write_discard(cl);
	} else {
		if (!op->replace)
			__bcache_io_error(op->c,
				"out of space for write %li nowait %i",
				PTR_ERR(b), op->nowait);
		op->error = -ENOSPC;
	}

	op->write_done = true;
	bio_put(bio);

	/*
	 * No reason not to insert keys for whatever data was successfully
	 * written (especially for a cmpxchg operation that's moving data
	 * around)
	 */
	continue_at(cl, !bch_keylist_empty(&op->insert_keys)
		    ? bch_write_index
		    : bch_write_done, op->c->wq);
}

void bch_wake_delayed_writes(unsigned long data)
{
	struct cache_set *c = (void *) data;
	struct bch_write_op *op;
	unsigned long flags;

	spin_lock_irqsave(&c->foreground_write_pd_lock, flags);

	while ((op = c->write_wait_head)) {
		if (!test_bit(CACHE_SET_RO, &c->flags) &&
		    !test_bit(CACHE_SET_STOPPING, &c->flags) &&
		    time_after(op->expires, jiffies)) {
			mod_timer(&c->foreground_write_wakeup, op->expires);
			break;
		}

		c->write_wait_head = op->next;
		if (!c->write_wait_head)
			c->write_wait_tail = NULL;

		closure_put(&op->cl);
	}

	spin_unlock_irqrestore(&c->foreground_write_pd_lock, flags);

}

/**
 * bch_write - handle a write to a cache device or flash only volume
 *
 * This is the starting point for any data to end up in a cache device; it could
 * be from a normal write, or a writeback write, or a write to a flash only
 * volume - it's also used by the moving garbage collector to compact data in
 * mostly empty buckets.
 *
 * It first writes the data to the cache, creating a list of keys to be inserted
 * (if the data won't fit in a single open bucket, there will be multiple keys);
 * after the data is written it calls bch_journal, and after the keys have been
 * added to the next journal write they're inserted into the btree.
 *
 * It inserts the data in op->bio; bi_sector is used for the key offset, and
 * op->inode is used for the key inode.
 *
 * If op->discard is true, instead of inserting the data it invalidates the
 * region of the cache represented by op->bio and op->inode.
 */
void bch_write(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct cache_set *c = op->c;
	u64 inode = op->insert_key.k.p.inode;

	trace_bcache_write(c, inode, op->bio,
			   !bkey_extent_cached(bkey_i_to_s_c(&op->insert_key)),
			   op->discard);

	if (!bio_sectors(op->bio)) {
		WARN_ONCE(1, "bch_write() called with empty bio");
		closure_return(cl);
	}

	if (!percpu_ref_tryget(&c->writes)) {
		__bcache_io_error(c, "read only");
		op->error = -EROFS;
		closure_return(cl);
	}

	if (version_stress_test(c))
		op->insert_key.k.version = bch_rand_range(UINT_MAX);

	/*
	 * This ought to be initialized in bch_write_op_init(), but struct
	 * cache_set isn't exported
	 */
	if (!op->io_wq)
		op->io_wq = op->c->wq;

	if (!op->discard)
		bch_increment_clock(c, bio_sectors(op->bio), WRITE);

	if (!op->discard)
		bch_mark_foreground_write(c, bio_sectors(op->bio));
	else
		bch_mark_discard(c, bio_sectors(op->bio));

	if (atomic64_sub_return(bio_sectors(op->bio),
				&c->sectors_until_gc) < 0) {
		trace_bcache_gc_periodic(c);
		set_gc_sectors(c);
		wake_up_process(c->gc_thread);
	}

	op->insert_key.k.p.offset	= bio_end_sector(op->bio);
	op->insert_key.k.size		= bio_sectors(op->bio);

	bch_keylist_init(&op->insert_keys);
	bio_get(op->bio);

	/* Don't call bch_next_delay() if rate is >= 1 GB/sec */

	if (c->foreground_write_pd.rate.rate < (1 << 30) &&
	    !op->discard && op->wp->throttle) {
		unsigned long flags;
		u64 delay;

		spin_lock_irqsave(&c->foreground_write_pd_lock, flags);
		bch_ratelimit_increment(&c->foreground_write_pd.rate,
					op->bio->bi_iter.bi_size);

		delay = bch_ratelimit_delay(&c->foreground_write_pd.rate);

		if (delay >= HZ / 100) {
			trace_bcache_write_throttle(c, inode, op->bio, delay);

			closure_get(&op->cl); /* list takes a ref */

			op->expires = jiffies + delay;
			op->next = NULL;

			if (c->write_wait_tail)
				c->write_wait_tail->next = op;
			else
				c->write_wait_head = op;
			c->write_wait_tail = op;

			if (!timer_pending(&c->foreground_write_wakeup))
				mod_timer(&c->foreground_write_wakeup,
					  op->expires);

			spin_unlock_irqrestore(&c->foreground_write_pd_lock,
					       flags);
			continue_at(cl, __bch_write, op->c->wq);
		}

		spin_unlock_irqrestore(&c->foreground_write_pd_lock, flags);
	}

	continue_at_nobarrier(cl, __bch_write, NULL);
}

void bch_write_op_init(struct bch_write_op *op, struct cache_set *c,
		       struct bio *bio, struct write_point *wp,
		       struct bkey_s_c insert_key,
		       struct bkey_s_c replace_key,
		       unsigned flags)
{
	if (!wp) {
		unsigned wp_idx = hash_long((unsigned long) current,
					    ilog2(ARRAY_SIZE(c->write_points)));

		BUG_ON(wp_idx > ARRAY_SIZE(c->write_points));
		wp = &c->write_points[wp_idx];
	}

	op->c		= c;
	op->io_wq	= NULL;
	op->bio		= bio;
	op->error	= 0;
	op->flags	= 0;
	op->check_enospc = (flags & BCH_WRITE_CHECK_ENOSPC) != 0;
	op->nowait	= (flags & BCH_WRITE_ALLOC_NOWAIT) != 0;
	op->discard	= (flags & BCH_WRITE_DISCARD) != 0;
	op->cached	= (flags & BCH_WRITE_CACHED) != 0;
	op->flush	= (flags & BCH_WRITE_FLUSH) != 0;
	op->wp		= wp;

	bch_keylist_init(&op->insert_keys);
	bkey_reassemble(&op->insert_key, insert_key);

	if (!bkey_val_u64s(&op->insert_key.k)) {
		/*
		 * If the new key has no pointers, we're either doing a
		 * discard or we're writing new data and we're going to
		 * allocate pointers
		 */
		op->insert_key.k.type = op->discard
			? KEY_TYPE_DISCARD
			: BCH_EXTENT;
	}

	if (replace_key.k) {
		op->replace = true;
		/* The caller can overwrite any replace_info fields */
		memset(&op->replace_info, 0, sizeof(op->replace_info));
		bkey_reassemble(&op->replace_info.key, replace_key);
	}
}

/* Discard */

/* bch_discard - discard a range of keys from start_key to end_key.
 * @c		cache set
 * @start_key	pointer to start location
 *		NOTE: discard starts at bkey_start_offset(start_key)
 * @end_key	pointer to end location
 *		NOTE: discard ends at KEY_OFFSET(end_key)
 * @version	version of discard (0ULL if none)
 *
 * Returns:
 *	 0 on success
 *	<0 on error
 *
 * XXX: this needs to be refactored with inode_truncate, or more
 *	appropriately inode_truncate should call this
 */
int bch_discard(struct cache_set *c, struct bpos start,
		struct bpos end, u64 version)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_EXTENTS, start);

	while ((k = bch_btree_iter_peek(&iter)).k) {
		unsigned max_sectors = KEY_SIZE_MAX & (~0 << c->block_bits);
		/* really shouldn't be using a bare, unpadded bkey_i */
		struct bkey_i erase;
		struct bpos n;

		/* create the biggest key we can, to minimize writes */
		bkey_init(&erase.k);
		erase.k.type	= KEY_TYPE_DISCARD;
		erase.k.version	= version;
		erase.k.p	= bkey_cmp(bkey_start_pos(k.k),
					   iter.pos) > 0
			? bkey_start_pos(k.k)
			: iter.pos;

		if (bkey_cmp(erase.k.p, end) >= 0)
			break;

		bch_key_resize(&erase.k, max_sectors);
		bch_cut_back(end, &erase.k);
		n = erase.k.p;

		ret = bch_btree_insert_at(&iter, &keylist_single(&erase),
					  NULL, NULL, 0);
		if (ret)
			break;

		bch_btree_iter_set_pos(&iter, n);
		bch_btree_iter_cond_resched(&iter);
	}
	bch_btree_iter_unlock(&iter);

	return ret;
}

/* Cache promotion on read */

struct cache_promote_op {
	struct closure		cl;
	struct bio		*orig_bio;
	struct bch_write_op	iop;
	bool			stale; /* was the ptr stale after the read? */
	struct bbio		bio; /* must be last */
};

static void cache_promote_done(struct closure *cl)
{
	struct cache_promote_op *op = container_of(cl,
					struct cache_promote_op, cl);
	struct cache_set *c = op->iop.c;

	if (op->iop.replace_collision) {
		trace_bcache_promote_collision(&op->iop.replace_info.key.k);
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
	bio->bi_iter.bi_sector	= bkey_start_offset(&op->iop.insert_key.k);
	bio->bi_iter.bi_size	= op->iop.insert_key.k.size << 9;
	/* needed to reinit bi_vcnt so pages can be freed later */
	bch_bio_map(bio, NULL);

	bio_copy_data(op->orig_bio, bio);
	op->orig_bio->bi_error = op->iop.error;
	bio_endio(op->orig_bio);

	if (!op->stale &&
	    !op->iop.error &&
	    !test_bit(CACHE_SET_RO, &op->iop.c->flags) &&
	    !test_bit(CACHE_SET_STOPPING, &op->iop.c->flags))
		closure_call(&op->iop.cl, bch_write, NULL, cl);

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
	else if (b->ca && ptr_stale(b->ca, &b->ptr))
		op->stale = 1;

	bch_bbio_endio(b, bio->bi_error, "reading from cache");
}

/**
 * __cache_promote -- insert result of read bio into cache
 *
 * Used for backing devices and flash-only volumes.
 *
 * @orig_bio must actually be a bbio with a valid key.
 */
void __cache_promote(struct cache_set *c, struct bbio *orig_bio,
		     struct bkey_s_c old,
		     struct bkey_s_c new,
		     unsigned write_flags)
{
	struct cache_promote_op *op;
	struct bio *bio;
	unsigned pages = DIV_ROUND_UP(orig_bio->bio.bi_iter.bi_size, PAGE_SIZE);

	/* XXX: readahead? */

	op = kmalloc(sizeof(*op) + sizeof(struct bio_vec) * pages, GFP_NOIO);
	if (!op)
		goto out_submit;

	/* clone the bbio */
	memcpy(&op->bio, orig_bio, offsetof(struct bbio, bio));

	bio = &op->bio.bio;
	bio_init(bio);
	bio_get(bio);
	bio->bi_bdev		= orig_bio->bio.bi_bdev;
	bio->bi_iter.bi_sector	= orig_bio->bio.bi_iter.bi_sector;
	bio->bi_iter.bi_size	= orig_bio->bio.bi_iter.bi_size;
	bio->bi_end_io		= cache_promote_endio;
	bio->bi_private		= &op->cl;
	bio->bi_io_vec		= bio->bi_inline_vecs;
	bch_bio_map(bio, NULL);

	if (bio_alloc_pages(bio, __GFP_NOWARN|GFP_NOIO))
		goto out_free;

	orig_bio->ca = NULL;

	closure_init(&op->cl, &c->cl);
	op->orig_bio		= &orig_bio->bio;
	op->stale		= 0;

	bch_write_op_init(&op->iop, c, bio, &c->promote_write_point,
			  new, old, BCH_WRITE_CHECK_ENOSPC|write_flags);

	bch_cut_front(bkey_start_pos(&orig_bio->key.k), &op->iop.insert_key);
	bch_cut_back(orig_bio->key.k.p, &op->iop.insert_key.k);

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
 * Used for flash only volumes.
 *
 * @bio must actually be a bbio with valid key.
 */
bool cache_promote(struct cache_set *c, struct bbio *bio, struct bkey_s_c k)
{
	if (!CACHE_TIER(&bio->ca->mi)) {
		generic_make_request(&bio->bio);
		return 0;
	}

	__cache_promote(c, bio, k, k, BCH_WRITE_ALLOC_NOWAIT);
	return 1;
}

/* Read */

static void bch_read_requeue(struct cache_set *c, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&c->read_race_lock, flags);
	bio_list_add(&c->read_race_list, bio);
	spin_unlock_irqrestore(&c->read_race_lock, flags);
	queue_work(c->wq, &c->read_race_work);
}

static void bch_read_endio(struct bio *bio)
{
	struct bbio *b = to_bbio(bio);
	struct cache *ca = b->ca;
	struct bio *orig = bio->bi_private;

	bch_bbio_count_io_errors(b, bio->bi_error, "reading from cache");

	if (!bio->bi_error && ca &&
	    (race_fault() ||
	     ptr_stale(ca, &b->ptr))) {
		/* Read bucket invalidate race */
		atomic_long_inc(&ca->set->cache_read_races);
		bch_read_requeue(ca->set, bio);
	} else {
		if (bio->bi_error)
			orig->bi_error = bio->bi_error;

		bio_endio(orig);
		bio_put(bio);
	}

	if (ca)
		percpu_ref_put(&ca->ref);
}

static inline void __bio_inc_remaining(struct bio *bio)
{
	bio->bi_flags |= (1 << BIO_CHAIN);
	smp_mb__before_atomic();
	atomic_inc(&bio->__bi_remaining);
}

/* XXX: this looks a lot like cache_lookup_fn() */
int bch_read(struct cache_set *c, struct bio *bio, u64 inode)
{
	struct btree_iter iter;
	struct bkey_s_c k;

	bch_increment_clock(c, bio_sectors(bio), READ);

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_EXTENTS,
				      POS(inode, bio->bi_iter.bi_sector), k) {
		struct bio *n;
		struct bbio *bbio;
		struct cache *ca;
		unsigned sectors;
		const struct bch_extent_ptr *ptr;
		bool done;

		BUG_ON(bkey_cmp(bkey_start_pos(k.k),
				POS(inode, bio->bi_iter.bi_sector)) > 0);

		BUG_ON(bkey_cmp(k.k->p,
				POS(inode, bio->bi_iter.bi_sector)) <= 0);

		sectors = k.k->p.offset - bio->bi_iter.bi_sector;
		done = sectors >= bio_sectors(bio);

		ca = bch_extent_pick_ptr(c, k, &ptr);
		if (IS_ERR(ca)) {
			bcache_io_error(c, bio, "no device to read from");
			bch_btree_iter_unlock(&iter);
			return 0;
		}
		if (ca) {
			struct bkey_s_c_extent e = bkey_s_c_to_extent(k);

			PTR_BUCKET(ca, ptr)->read_prio =
				c->prio_clock[READ].hand;

			n = sectors >= bio_sectors(bio)
				? bio_clone_fast(bio, GFP_NOIO, c->bio_split)
				: bio_split(bio, sectors, GFP_NOIO,
					    c->bio_split);

			n->bi_private		= bio;
			n->bi_end_io		= bch_read_endio;
			__bio_inc_remaining(bio);

			bbio = to_bbio(n);
			bch_bkey_copy_single_ptr(&bbio->key, k,
						 ptr - e.v->ptr);

			/* Trim the key to match what we're actually reading */
			bch_cut_front(POS(inode, n->bi_iter.bi_sector),
				      &bbio->key);
			bch_cut_back(POS(inode, bio_end_sector(n)),
				     &bbio->key.k);
			bch_bbio_prep(bbio, ca);

			cache_promote(c, bbio, k);
		} else {
			unsigned bytes = min_t(unsigned, sectors,
					       bio_sectors(bio)) << 9;

			swap(bio->bi_iter.bi_size, bytes);
			zero_fill_bio(bio);
			swap(bio->bi_iter.bi_size, bytes);

			bio_advance(bio, bytes);
		}

		if (done) {
			bch_btree_iter_unlock(&iter);
			return 0;
		}
	}

	/*
	 * If we get here, it better have been because there was an error
	 * reading a btree node
	 */
	BUG_ON(!bch_btree_iter_unlock(&iter));
	bcache_io_error(c, bio, "btree IO error");

	return 0;
}
EXPORT_SYMBOL(bch_read);

/**
 * bch_read_retry - re-submit a bio originally from bch_read()
 */
static void bch_read_retry(struct bbio *bbio)
{
	struct bio *bio = &bbio->bio;
	struct bio *parent;
	u64 inode;

	trace_bcache_read_retry(bio);

	/*
	 * This used to be a leaf bio from bch_read_fn(), but
	 * since we don't know what happened to the btree in
	 * the meantime, we have to re-submit it via the
	 * top-level bch_read() entry point. Before doing that,
	 * we have to reset the bio, preserving the biovec.
	 *
	 * The inode, offset and size come from the bbio's key,
	 * which was set by bch_read_fn().
	 */
	inode = bbio->key.k.p.inode;
	parent = bio->bi_private;

	bch_bbio_reset(bbio);
	bio_chain(bio, parent);

	bch_read(bbio->ca->set, bio, inode);
	bio_endio(parent);  /* for bio_chain() in bch_read_fn() */
	bio_endio(bio);
}

void bch_read_race_work(struct work_struct *work)
{
	struct cache_set *c = container_of(work, struct cache_set,
					   read_race_work);
	unsigned long flags;
	struct bio *bio;

	while (1) {
		spin_lock_irqsave(&c->read_race_lock, flags);
		bio = bio_list_pop(&c->read_race_list);
		spin_unlock_irqrestore(&c->read_race_lock, flags);

		if (!bio)
			break;

		bch_read_retry(to_bbio(bio));
	}
}
