/*
 * Some low level IO code, and hacks for various block layer limitations
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "alloc.h"
#include "bset.h"
#include "btree_update.h"
#include "buckets.h"
#include "checksum.h"
#include "compress.h"
#include "clock.h"
#include "debug.h"
#include "error.h"
#include "extents.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "notify.h"
#include "stats.h"
#include "super.h"

#include <linux/blkdev.h>
#include <linux/random.h>

#include <trace/events/bcachefs.h>

static inline void __bio_inc_remaining(struct bio *bio)
{
	bio_set_flag(bio, BIO_CHAIN);
	smp_mb__before_atomic();
	atomic_inc(&bio->__bi_remaining);
}

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
	struct bio_list bl;
	struct bio *bio;

	spin_lock(&c->bio_submit_lock);
	bl = c->bio_submit_list;
	bio_list_init(&c->bio_submit_list);
	spin_unlock(&c->bio_submit_lock);

	while ((bio = bio_list_pop(&bl)))
		generic_make_request(bio);
}

/* Allocate, free from mempool: */

void bch_bio_free_pages_pool(struct cache_set *c, struct bio *bio)
{
	struct bio_vec *bv;
	unsigned i;

	bio_for_each_segment_all(bv, bio, i)
		if (bv->bv_page != ZERO_PAGE(0))
			mempool_free(bv->bv_page, &c->bio_bounce_pages);
	bio->bi_vcnt = 0;
}

static void bch_bio_alloc_page_pool(struct cache_set *c, struct bio *bio,
				    bool *using_mempool)
{
	struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt++];

	if (likely(!*using_mempool)) {
		bv->bv_page = alloc_page(GFP_NOIO);
		if (unlikely(!bv->bv_page)) {
			mutex_lock(&c->bio_bounce_pages_lock);
			*using_mempool = true;
			goto pool_alloc;

		}
	} else {
pool_alloc:
		bv->bv_page = mempool_alloc(&c->bio_bounce_pages, GFP_NOIO);
	}

	bv->bv_len = PAGE_SIZE;
	bv->bv_offset = 0;
}

void bch_bio_alloc_pages_pool(struct cache_set *c, struct bio *bio,
			      size_t bytes)
{
	bool using_mempool = false;

	bio->bi_iter.bi_size = bytes;

	while (bio->bi_vcnt < DIV_ROUND_UP(bytes, PAGE_SIZE))
		bch_bio_alloc_page_pool(c, bio, &using_mempool);

	if (using_mempool)
		mutex_unlock(&c->bio_bounce_pages_lock);
}

/* Bios with headers */

static void bch_submit_wbio(struct cache_set *c, struct bch_write_bio *wbio,
			    struct cache *ca, const struct bch_extent_ptr *ptr,
			    bool punt)
{
	wbio->ca		= ca;
	wbio->submit_time_us	= local_clock_us();
	wbio->bio.bi_iter.bi_sector = ptr->offset;
	wbio->bio.bi_bdev	= ca ? ca->disk_sb.bdev : NULL;

	if (!ca)
		bcache_io_error(c, &wbio->bio, "device has been removed");
	else if (punt)
		bch_generic_make_request(&wbio->bio, c);
	else
		generic_make_request(&wbio->bio);
}

void bch_submit_wbio_replicas(struct bch_write_bio *wbio, struct cache_set *c,
			      const struct bkey_i *k, bool punt)
{
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
	const struct bch_extent_ptr *ptr;
	struct bch_write_bio *n;
	struct cache *ca;

	wbio->split = false;
	wbio->c = c;

	extent_for_each_ptr(e, ptr) {
		rcu_read_lock();
		ca = PTR_CACHE(c, ptr);
		if (ca)
			percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		if (!ca) {
			bch_submit_wbio(c, wbio, ca, ptr, punt);
			break;
		}

		if (ptr + 1 < &extent_entry_last(e)->ptr) {
			n = to_wbio(bio_clone_fast(&wbio->bio, GFP_NOIO,
						   &ca->replica_set));

			n->bio.bi_end_io	= wbio->bio.bi_end_io;
			n->bio.bi_private	= wbio->bio.bi_private;
			n->c			= c;
			n->orig			= &wbio->bio;
			n->bounce		= false;
			n->split		= true;
			n->bio.bi_opf		= wbio->bio.bi_opf;
			__bio_inc_remaining(n->orig);
		} else {
			n = wbio;
		}

		if (!journal_flushes_device(ca))
			n->bio.bi_opf |= REQ_FUA;

		bch_submit_wbio(c, n, ca, ptr, punt);
	}
}

/* IO errors */

/* Writes */

static void __bch_write(struct closure *);

static void bch_write_done(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);

	BUG_ON(!(op->flags & BCH_WRITE_DONE));

	if (!op->error && (op->flags & BCH_WRITE_FLUSH))
		op->error = bch_journal_error(&op->c->journal);

	bch_disk_reservation_put(op->c, &op->res);
	percpu_ref_put(&op->c->writes);
	bch_keylist_free(&op->insert_keys, op->inline_keys);
	closure_return(cl);
}

static u64 keylist_sectors(struct keylist *keys)
{
	struct bkey_i *k;
	u64 ret = 0;

	for_each_keylist_key(keys, k)
		ret += k->k.size;

	return ret;
}

static int bch_write_index_default(struct bch_write_op *op)
{
	struct keylist *keys = &op->insert_keys;
	struct btree_iter iter;
	int ret;

	bch_btree_iter_init_intent(&iter, op->c, BTREE_ID_EXTENTS,
		bkey_start_pos(&bch_keylist_front(keys)->k));

	ret = bch_btree_insert_list_at(&iter, keys, &op->res,
				       NULL, op_journal_seq(op),
				       BTREE_INSERT_NOFAIL);
	bch_btree_iter_unlock(&iter);

	return ret;
}

/**
 * bch_write_index - after a write, update index to point to new data
 */
static void bch_write_index(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct cache_set *c = op->c;
	struct keylist *keys = &op->insert_keys;
	unsigned i;

	op->flags |= BCH_WRITE_LOOPED;

	if (!bch_keylist_empty(keys)) {
		u64 sectors_start = keylist_sectors(keys);
		int ret = op->index_update_fn(op);

		BUG_ON(keylist_sectors(keys) && !ret);

		op->written += sectors_start - keylist_sectors(keys);

		if (ret) {
			__bcache_io_error(c, "btree IO error %i", ret);
			op->error = ret;
		}
	}

	for (i = 0; i < ARRAY_SIZE(op->open_buckets); i++)
		if (op->open_buckets[i]) {
			bch_open_bucket_put(c,
					    c->open_buckets +
					    op->open_buckets[i]);
			op->open_buckets[i] = 0;
		}

	if (!(op->flags & BCH_WRITE_DONE))
		continue_at(cl, __bch_write, op->io_wq);

	if (!op->error && (op->flags & BCH_WRITE_FLUSH)) {
		bch_journal_flush_seq_async(&c->journal,
					    *op_journal_seq(op),
					    cl);
		continue_at(cl, bch_write_done, c->wq);
	} else {
		continue_at_nobarrier(cl, bch_write_done, NULL);
	}
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
	struct bio *bio = &op->bio->bio;
	struct bpos end = op->pos;

	end.offset += bio_sectors(bio);

	op->error = bch_discard(op->c, op->pos, end, op->version,
				&op->res, NULL, NULL);
}

/*
 * Convert extents to be inserted to discards after an error:
 */
static void bch_write_io_error(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);

	if (op->flags & BCH_WRITE_DISCARD_ON_ERROR) {
		struct bkey_i *src = bch_keylist_front(&op->insert_keys);
		struct bkey_i *dst = bch_keylist_front(&op->insert_keys);

		/*
		 * Our data write just errored, which means we've got a bunch
		 * of keys to insert that point to data that wasn't
		 * successfully written.
		 *
		 * We don't have to insert those keys but we still have to
		 * invalidate that region of the cache - so, if we just strip
		 * off all the pointers from the keys we'll accomplish just
		 * that.
		 */

		while (src != op->insert_keys.top) {
			struct bkey_i *n = bkey_next(src);

			set_bkey_val_u64s(&src->k, 0);
			src->k.type = KEY_TYPE_DISCARD;
			bkey_copy(dst, src);

			dst = bkey_next(dst);
			src = n;
		}

		op->insert_keys.top = dst;
		op->flags |= BCH_WRITE_DISCARD;
	} else {
		/* TODO: We could try to recover from this. */
		while (!bch_keylist_empty(&op->insert_keys))
			bch_keylist_pop_front(&op->insert_keys);

		op->error = -EIO;
		op->flags |= BCH_WRITE_DONE;
	}

	bch_write_index(cl);
}

static void bch_write_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;
	struct bch_write_bio *wbio = to_wbio(bio);
	struct cache_set *c = wbio->c;
	struct bio *orig = wbio->orig;
	struct cache *ca = wbio->ca;

	if (cache_nonfatal_io_err_on(bio->bi_error, ca,
				     "data write"))
		set_closure_fn(cl, bch_write_io_error, c->wq);

	bch_account_io_completion_time(ca, wbio->submit_time_us,
				       REQ_OP_WRITE);
	if (ca)
		percpu_ref_put(&ca->ref);

	if (bio->bi_error && orig)
		orig->bi_error = bio->bi_error;

	if (wbio->bounce)
		bch_bio_free_pages_pool(c, bio);

	if (wbio->put_bio)
		bio_put(bio);

	if (orig)
		bio_endio(orig);
	else
		closure_put(cl);
}

static int bch_write_extent(struct bch_write_op *op,
			    struct open_bucket *ob,
			    struct bkey_i_extent *e,
			    struct bio *orig)
{
	struct cache_set *c = op->c;
	struct bio *bio;
	struct bch_write_bio *wbio;
	unsigned csum_type = c->opts.data_checksum;
	unsigned compression_type = op->compression_type;
	int ret;

	/* don't refetch csum type/compression type */
	barrier();

	/* Need to decompress data? */
	if ((op->flags & BCH_WRITE_DATA_COMPRESSED) &&
	    (op->crc.uncompressed_size != e->k.size ||
	     op->crc.compressed_size > ob->sectors_free)) {
		int ret;

		ret = bch_bio_uncompress_inplace(c, orig, &e->k, op->crc);
		if (ret)
			return ret;

		op->flags &= ~BCH_WRITE_DATA_COMPRESSED;
	}

	if (op->flags & BCH_WRITE_DATA_COMPRESSED) {
		bch_extent_crc_append(e,
				      op->crc.compressed_size,
				      op->crc.uncompressed_size,
				      op->crc.compression_type,
				      op->crc.csum,
				      op->crc.csum_type);
		bch_alloc_sectors_done(op->c, op->wp,
				       e, op->nr_replicas,
				       ob, bio_sectors(orig));

		bio			= orig;
		wbio			= to_wbio(bio);
		wbio->orig		= NULL;
		wbio->bounce		= false;
		wbio->put_bio		= false;
		ret			= 0;
	} else if (csum_type != BCH_CSUM_NONE ||
		   compression_type != BCH_COMPRESSION_NONE) {
		/* all units here in bytes */
		unsigned output_available, extra_input,
			 orig_input = orig->bi_iter.bi_size;
		u64 csum;

		/* XXX: decide extent size better: */
		output_available = min(e->k.size,
				   min(ob->sectors_free,
				       CRC32_EXTENT_SIZE_MAX)) << 9;

		/*
		 * temporarily set input bio's size to the max we want to
		 * consume from it, in order to avoid overflow in the crc info
		 */
		extra_input = orig->bi_iter.bi_size > CRC32_EXTENT_SIZE_MAX << 9
			? orig->bi_iter.bi_size - (CRC32_EXTENT_SIZE_MAX << 9)
			: 0;
		orig->bi_iter.bi_size -= extra_input;

		bio = bch_bio_compress(c, orig,
				       &compression_type,
				       output_available);
		/* copy WRITE_SYNC flag */
		bio->bi_opf		= orig->bi_opf;

		orig->bi_iter.bi_size += extra_input;

		bio->bi_end_io		= bch_write_endio;
		wbio			= to_wbio(bio);
		wbio->orig		= NULL;
		wbio->bounce		= true;
		wbio->put_bio		= true;

		/*
		 * Set the (uncompressed) size of the key we're creating to the
		 * number of sectors we consumed from orig:
		 */
		bch_key_resize(&e->k, (orig_input - orig->bi_iter.bi_size) >> 9);

		/*
		 * XXX: could move checksumming out from under the open
		 * bucket lock - but compression is also being done
		 * under it
		 */
		csum = bch_checksum_bio(bio, csum_type);
#if 0
		if (compression_type != BCH_COMPRESSION_NONE)
			pr_info("successfully compressed %u -> %u",
				e->k.size, bio_sectors(bio));
#endif
		/*
		 * Add a bch_extent_crc header for the pointers that
		 * bch_alloc_sectors_done() is going to append:
		 */
		bch_extent_crc_append(e, bio_sectors(bio), e->k.size,
				      compression_type,
				      csum, csum_type);
		bch_alloc_sectors_done(op->c, op->wp,
				       e, op->nr_replicas,
				       ob, bio_sectors(bio));

		ret = orig->bi_iter.bi_size != 0;
	} else {
		if (e->k.size > ob->sectors_free)
			bch_key_resize(&e->k, ob->sectors_free);

		BUG_ON(e->k.size > ob->sectors_free);
		/*
		 * We might need a checksum entry, if there's a previous
		 * checksum entry we need to override:
		 */
		bch_extent_crc_append(e, e->k.size, e->k.size,
				      compression_type, 0, csum_type);
		bch_alloc_sectors_done(op->c, op->wp,
				       e, op->nr_replicas,
				       ob, e->k.size);

		bio = bio_next_split(orig, e->k.size, GFP_NOIO,
				     &op->c->bio_write);

		wbio			= to_wbio(bio);
		wbio->orig		= NULL;
		wbio->bounce		= false;
		wbio->put_bio		= bio != orig;

		ret = bio != orig;
	}

	bio->bi_end_io	= bch_write_endio;
	bio->bi_private	= &op->cl;
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	closure_get(bio->bi_private);
	bch_submit_wbio_replicas(wbio, op->c, &e->k_i, false);
	return ret;
}

static void __bch_write(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct cache_set *c = op->c;
	struct bio *bio = &op->bio->bio;
	unsigned open_bucket_nr = 0;
	struct open_bucket *b;
	int ret;

	memset(op->open_buckets, 0, sizeof(op->open_buckets));

	if (op->flags & BCH_WRITE_DISCARD) {
		op->flags |= BCH_WRITE_DONE;
		bch_write_discard(cl);
		bio_put(bio);
		continue_at(cl, bch_write_done, c->wq);
	}

	/*
	 * Journal writes are marked REQ_PREFLUSH; if the original write was a
	 * flush, it'll wait on the journal write.
	 */
	bio->bi_opf &= ~(REQ_PREFLUSH|REQ_FUA);

	do {
		struct bkey_i *k;

		EBUG_ON(bio->bi_iter.bi_sector != op->pos.offset);
		EBUG_ON(!bio_sectors(bio));

		if (open_bucket_nr == ARRAY_SIZE(op->open_buckets))
			continue_at(cl, bch_write_index, c->wq);

		/* for the device pointers and 1 for the chksum */
		if (bch_keylist_realloc(&op->insert_keys,
					op->inline_keys,
					ARRAY_SIZE(op->inline_keys),
					BKEY_EXTENT_U64s_MAX))
			continue_at(cl, bch_write_index, c->wq);

		k = op->insert_keys.top;
		bkey_extent_init(k);
		k->k.p = op->pos;
		bch_key_resize(&k->k,
			       (op->flags & BCH_WRITE_DATA_COMPRESSED)
			       ? op->size
			       : bio_sectors(bio));

		b = bch_alloc_sectors_start(c, op->wp,
			bkey_i_to_extent(k), op->nr_replicas,
			op->alloc_reserve,
			(op->flags & BCH_WRITE_ALLOC_NOWAIT) ? NULL : cl);
		EBUG_ON(!b);

		if (unlikely(IS_ERR(b))) {
			if (unlikely(PTR_ERR(b) != -EAGAIN)) {
				ret = PTR_ERR(b);
				goto err;
			}

			/*
			 * If we already have some keys, must insert them first
			 * before allocating another open bucket. We only hit
			 * this case if open_bucket_nr > 1.
			 */
			if (!bch_keylist_empty(&op->insert_keys))
				continue_at(cl, bch_write_index, c->wq);

			/*
			 * If we've looped, we're running out of a workqueue -
			 * not the bch_write() caller's context - and we don't
			 * want to block the workqueue:
			 */
			if (op->flags & BCH_WRITE_LOOPED)
				continue_at(cl, __bch_write, op->io_wq);

			/*
			 * Otherwise, we do want to block the caller on alloc
			 * failure instead of letting it queue up more and more
			 * writes:
			 * XXX: this technically needs a try_to_freeze() -
			 * except that that's not safe because caller may have
			 * issued other IO... hmm..
			 */
			closure_sync(cl);
			continue;
		}

		BUG_ON(b - c->open_buckets == 0 ||
		       b - c->open_buckets > U8_MAX);
		op->open_buckets[open_bucket_nr++] = b - c->open_buckets;

		ret = bch_write_extent(op, b, bkey_i_to_extent(k), bio);
		if (ret < 0)
			goto err;

		op->pos.offset += k->k.size;

		bkey_extent_set_cached(&k->k, (op->flags & BCH_WRITE_CACHED));

		if (!(op->flags & BCH_WRITE_CACHED))
			bch_check_mark_super(c, k, false);

		bch_keylist_push(&op->insert_keys);

		trace_bcache_cache_insert(&k->k);
	} while (ret);

	op->flags |= BCH_WRITE_DONE;
	continue_at(cl, bch_write_index, c->wq);
err:
	if (op->flags & BCH_WRITE_DISCARD_ON_ERROR) {
		/*
		 * If we were writing cached data, not doing the write is fine
		 * so long as we discard whatever would have been overwritten -
		 * then it's equivalent to doing the write and immediately
		 * reclaiming it.
		 */

		bch_write_discard(cl);
	} else {
		/*
		 * Right now we can only error here if we went RO - the
		 * allocation failed, but we already checked for -ENOSPC when we
		 * got our reservation.
		 *
		 * XXX capacity might have changed, but we don't check for that
		 * yet:
		 */
		op->error = ret;
	}

	op->flags |= BCH_WRITE_DONE;

	/*
	 * No reason not to insert keys for whatever data was successfully
	 * written (especially for a cmpxchg operation that's moving data
	 * around)
	 */
	continue_at(cl, !bch_keylist_empty(&op->insert_keys)
		    ? bch_write_index
		    : bch_write_done, c->wq);
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
	struct bio *bio = &op->bio->bio;
	struct cache_set *c = op->c;
	u64 inode = op->pos.inode;

	trace_bcache_write(c, inode, bio,
			   !(op->flags & BCH_WRITE_CACHED),
			   op->flags & BCH_WRITE_DISCARD);

	if (!percpu_ref_tryget(&c->writes)) {
		__bcache_io_error(c, "read only");
		op->error = -EROFS;
		bch_disk_reservation_put(op->c, &op->res);
		closure_return(cl);
	}

	if (!(op->flags & BCH_WRITE_DISCARD))
		bch_increment_clock(c, bio_sectors(bio), WRITE);

	if (!(op->flags & BCH_WRITE_DISCARD))
		bch_mark_foreground_write(c, bio_sectors(bio));
	else
		bch_mark_discard(c, bio_sectors(bio));

	/* Don't call bch_next_delay() if rate is >= 1 GB/sec */

	if (c->foreground_write_ratelimit_enabled &&
	    c->foreground_write_pd.rate.rate < (1 << 30) &&
	    !(op->flags & BCH_WRITE_DISCARD) && op->wp->throttle) {
		unsigned long flags;
		u64 delay;

		spin_lock_irqsave(&c->foreground_write_pd_lock, flags);
		bch_ratelimit_increment(&c->foreground_write_pd.rate,
					bio->bi_iter.bi_size);

		delay = bch_ratelimit_delay(&c->foreground_write_pd.rate);

		if (delay >= HZ / 100) {
			trace_bcache_write_throttle(c, inode, bio, delay);

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
		       struct bch_write_bio *bio, struct disk_reservation res,
		       struct write_point *wp, struct bpos pos,
		       u64 *journal_seq, unsigned flags)
{
	op->c		= c;
	op->io_wq	= op->c->wq;
	op->bio		= bio;
	op->written	= 0;
	op->error	= 0;
	op->flags	= flags;
	op->compression_type = c->opts.compression;
	op->nr_replicas	= res.nr_replicas;
	op->alloc_reserve = RESERVE_NONE;
	op->pos		= pos;
	op->version	= 0;
	op->res		= res;
	op->wp		= wp;

	if (journal_seq) {
		op->journal_seq_p = journal_seq;
		op->flags |= BCH_WRITE_JOURNAL_SEQ_PTR;
	} else {
		op->journal_seq = 0;
	}

	op->index_update_fn = bch_write_index_default;

	bch_keylist_init(&op->insert_keys,
			 op->inline_keys,
			 ARRAY_SIZE(op->inline_keys));

	if (version_stress_test(c))
		get_random_bytes(&op->version, sizeof(op->version));
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
		struct bpos end, u64 version,
		struct disk_reservation *disk_res,
		struct extent_insert_hook *hook,
		u64 *journal_seq)
{
	return bch_btree_delete_range(c, BTREE_ID_EXTENTS, start, end, version,
				      disk_res, hook, journal_seq);
}

/* Cache promotion on read */

struct cache_promote_op {
	struct closure		cl;
	struct migrate_write	write;
	struct bio_vec		bi_inline_vecs[0]; /* must be last */
};

/* Read */

static int bio_checksum_uncompress(struct cache_set *c,
				   struct bch_read_bio *rbio)
{
	struct bio *src = &rbio->bio;
	struct bio *dst = &bch_rbio_parent(rbio)->bio;
	struct bvec_iter dst_iter = rbio->parent_iter;
	u64 csum;
	int ret = 0;

	/*
	 * reset iterator for checksumming and copying bounced data: here we've
	 * set rbio->compressed_size to the amount of data we actually read,
	 * which was not necessarily the full extent if we were only bouncing
	 * in order to promote
	 */
	if (rbio->bounce) {
		src->bi_iter.bi_size		= rbio->crc.compressed_size << 9;
		src->bi_iter.bi_idx		= 0;
		src->bi_iter.bi_bvec_done	= 0;
	} else {
		src->bi_iter = rbio->parent_iter;
	}

	csum = bch_checksum_bio(src, rbio->crc.csum_type);
	if (cache_nonfatal_io_err_on(rbio->crc.csum != csum, rbio->ca,
			"data checksum error, inode %llu offset %llu: expected %0llx got %0llx (type %u)",
			rbio->inode, (u64) rbio->parent_iter.bi_sector << 9,
			rbio->crc.csum, csum, rbio->crc.csum_type))
		ret = -EIO;

	/*
	 * If there was a checksum error, still copy the data back - unless it
	 * was compressed, we don't want to decompress bad data:
	 */
	if (rbio->crc.compression_type != BCH_COMPRESSION_NONE) {
		if (!ret) {
			ret = bch_bio_uncompress(c, src, dst,
						 dst_iter, rbio->crc);
			if (ret)
				__bcache_io_error(c, "decompression error");
		}
	} else if (rbio->bounce) {
		bio_advance(src, rbio->crc.offset << 9);
		bio_copy_data_iter(dst, dst_iter,
				   src, src->bi_iter);
	}

	return ret;
}

static void bch_rbio_free(struct cache_set *c, struct bch_read_bio *rbio)
{
	struct bio *bio = &rbio->bio;

	BUG_ON(rbio->ca);
	BUG_ON(!rbio->split);

	if (rbio->promote)
		kfree(rbio->promote);
	if (rbio->bounce)
		bch_bio_free_pages_pool(c, bio);

	bio_put(bio);
}

static void bch_rbio_done(struct cache_set *c, struct bch_read_bio *rbio)
{
	struct bio *orig = &bch_rbio_parent(rbio)->bio;

	percpu_ref_put(&rbio->ca->ref);
	rbio->ca = NULL;

	if (rbio->split) {
		if (rbio->bio.bi_error)
			orig->bi_error = rbio->bio.bi_error;

		bio_endio(orig);
		bch_rbio_free(c, rbio);
	} else {
		if (rbio->promote)
			kfree(rbio->promote);

		orig->bi_end_io = rbio->orig_bi_end_io;
		bio_endio_nodec(orig);
	}
}

/*
 * Decide if we want to retry the read - returns true if read is being retried,
 * false if caller should pass error on up
 */
static void bch_read_error_maybe_retry(struct cache_set *c,
				       struct bch_read_bio *rbio,
				       int error)
{
	unsigned long flags;

	if ((error == -EINTR) &&
	    (rbio->flags & BCH_READ_RETRY_IF_STALE)) {
		atomic_long_inc(&c->cache_read_races);
		goto retry;
	}

	if (error == -EIO) {
		/* io error - do we have another replica? */
	}

	bch_rbio_parent(rbio)->bio.bi_error = error;
	bch_rbio_done(c, rbio);
	return;
retry:
	percpu_ref_put(&rbio->ca->ref);
	rbio->ca = NULL;

	spin_lock_irqsave(&c->read_retry_lock, flags);
	bio_list_add(&c->read_retry_list, &rbio->bio);
	spin_unlock_irqrestore(&c->read_retry_lock, flags);
	queue_work(c->wq, &c->read_retry_work);
}

static void cache_promote_done(struct closure *cl)
{
	struct cache_promote_op *op =
		container_of(cl, struct cache_promote_op, cl);

	bch_bio_free_pages_pool(op->write.op.c, &op->write.wbio.bio);
	kfree(op);
}

/* Inner part that may run in process context */
static void __bch_read_endio(struct cache_set *c, struct bch_read_bio *rbio)
{
	int ret;

	ret = bio_checksum_uncompress(c, rbio);
	if (ret) {
		bch_read_error_maybe_retry(c, rbio, ret);
		return;
	}

	if (rbio->promote &&
	    !test_bit(CACHE_SET_RO, &c->flags) &&
	    !test_bit(CACHE_SET_STOPPING, &c->flags)) {
		struct cache_promote_op *promote = rbio->promote;
		struct closure *cl = &promote->cl;

		BUG_ON(!rbio->split || !rbio->bounce);

		/* we now own pages: */
		swap(promote->write.wbio.bio.bi_vcnt, rbio->bio.bi_vcnt);
		rbio->promote = NULL;

		bch_rbio_done(c, rbio);

		closure_init(cl, &c->cl);
		closure_call(&promote->write.op.cl, bch_write, c->wq, cl);
		closure_return_with_destructor(cl, cache_promote_done);
	} else {
		bch_rbio_done(c, rbio);
	}
}

void bch_bio_decompress_work(struct work_struct *work)
{
	struct bio_decompress_worker *d =
		container_of(work, struct bio_decompress_worker, work);
	struct llist_node *list, *next;
	struct bch_read_bio *rbio;

	while ((list = llist_del_all(&d->bio_list)))
		for (list = llist_reverse_order(list);
		     list;
		     list = next) {
			next = llist_next(list);
			rbio = container_of(list, struct bch_read_bio, list);

			__bch_read_endio(d->c, rbio);
		}
}

static void bch_read_endio(struct bio *bio)
{
	struct bch_read_bio *rbio =
		container_of(bio, struct bch_read_bio, bio);
	struct cache_set *c = rbio->ca->set;
	int stale = ((rbio->flags & BCH_READ_RETRY_IF_STALE) && race_fault()) ||
		ptr_stale(rbio->ca, &rbio->ptr) ? -EINTR : 0;
	int error = bio->bi_error ?: stale;

	bch_account_io_completion_time(rbio->ca, rbio->submit_time_us, REQ_OP_READ);

	cache_nonfatal_io_err_on(bio->bi_error, rbio->ca, "data read");

	if (error) {
		bch_read_error_maybe_retry(c, rbio, error);
		return;
	}

	if (rbio->crc.compression_type != BCH_COMPRESSION_NONE) {
		struct bio_decompress_worker *d;

		preempt_disable();
		d = this_cpu_ptr(c->bio_decompress_worker);
		llist_add(&rbio->list, &d->bio_list);
		queue_work(system_unbound_wq, &d->work);
		preempt_enable();
	} else {
		__bch_read_endio(c, rbio);
	}
}

void bch_read_extent_iter(struct cache_set *c, struct bch_read_bio *orig,
			  struct bvec_iter iter, struct bkey_s_c k,
			  struct extent_pick_ptr *pick, unsigned flags)
{
	struct bch_read_bio *rbio;
	struct cache_promote_op *promote_op = NULL;
	unsigned skip = iter.bi_sector - bkey_start_offset(k.k);
	bool bounce = false, split, read_full = false;

	EBUG_ON(bkey_start_offset(k.k) > iter.bi_sector ||
		k.k->p.offset < bvec_iter_end_sector(iter));

	/* only promote if we're not reading from the fastest tier: */

	/*
	 * XXX: multiple promotes can race with each other, wastefully. Keep a
	 * list of outstanding promotes?
	 */
	if ((flags & BCH_READ_PROMOTE) && pick->ca->mi.tier) {
		/*
		 * biovec needs to be big enough to hold decompressed data, if
		 * the bch_write_extent() has to decompress/recompress it:
		 */
		unsigned sectors =
			max_t(unsigned, k.k->size,
			      pick->crc.uncompressed_size);
		unsigned pages = DIV_ROUND_UP(sectors, PAGE_SECTORS);

		promote_op = kmalloc(sizeof(*promote_op) +
				sizeof(struct bio_vec) * pages, GFP_NOIO);
		if (promote_op) {
			struct bio *promote_bio = &promote_op->write.wbio.bio;

			bio_init(promote_bio);
			promote_bio->bi_max_vecs = pages;
			promote_bio->bi_io_vec	= promote_bio->bi_inline_vecs;
			bounce = true;
			/* could also set read_full */
		}
	}

	/*
	 * note: if compression_type and crc_type both == none, then
	 * compressed/uncompressed size is zero
	 */
	if (pick->crc.compression_type != BCH_COMPRESSION_NONE ||
	    (pick->crc.csum_type != BCH_CSUM_NONE &&
	     (bvec_iter_sectors(iter) != pick->crc.uncompressed_size ||
	      (flags & BCH_READ_FORCE_BOUNCE)))) {
		read_full = true;
		bounce = true;
	}

	if (bounce) {
		unsigned sectors = read_full
			? (pick->crc.compressed_size ?: k.k->size)
			: bvec_iter_sectors(iter);

		rbio = container_of(bio_alloc_bioset(GFP_NOIO,
					DIV_ROUND_UP(sectors, PAGE_SECTORS),
					&c->bio_read_split),
				    struct bch_read_bio, bio);

		bch_bio_alloc_pages_pool(c, &rbio->bio, sectors << 9);
		split = true;
	} else if (!(flags & BCH_READ_MAY_REUSE_BIO) ||
		   !(flags & BCH_READ_IS_LAST)) {
		/*
		 * Have to clone if there were any splits, due to error
		 * reporting issues (if a split errored, and retrying didn't
		 * work, when it reports the error to its parent (us) we don't
		 * know if the error was from our bio, and we should retry, or
		 * from the whole bio, in which case we don't want to retry and
		 * lose the error)
		 */
		rbio = container_of(bio_clone_fast(&orig->bio,
					GFP_NOIO, &c->bio_read_split),
				    struct bch_read_bio, bio);
		rbio->bio.bi_iter = iter;
		split = true;
	} else {
		rbio = orig;
		rbio->bio.bi_iter = iter;
		split = false;
		BUG_ON(bio_flagged(&rbio->bio, BIO_CHAIN));
	}

	if (!(flags & BCH_READ_IS_LAST))
		__bio_inc_remaining(&orig->bio);

	if (split)
		rbio->parent	= orig;
	else
		rbio->orig_bi_end_io = orig->bio.bi_end_io;
	rbio->parent_iter	= iter;

	rbio->inode		= k.k->p.inode;
	rbio->flags		= flags;
	rbio->bounce		= bounce;
	rbio->split		= split;
	rbio->crc		= pick->crc;
	/*
	 * crc.compressed_size will be 0 if there wasn't any checksum
	 * information, also we need to stash the original size of the bio if we
	 * bounced (which isn't necessarily the original key size, if we bounced
	 * only for promoting)
	 */
	rbio->crc.compressed_size = bio_sectors(&rbio->bio);
	rbio->ptr		= pick->ptr;
	rbio->ca		= pick->ca;
	rbio->promote		= promote_op;

	rbio->bio.bi_bdev	= pick->ca->disk_sb.bdev;
	rbio->bio.bi_opf	= orig->bio.bi_opf;
	rbio->bio.bi_iter.bi_sector = pick->ptr.offset;
	rbio->bio.bi_end_io	= bch_read_endio;

	if (promote_op) {
		struct bio *promote_bio = &promote_op->write.wbio.bio;

		promote_bio->bi_iter = rbio->bio.bi_iter;
		memcpy(promote_bio->bi_io_vec, rbio->bio.bi_io_vec,
		       sizeof(struct bio_vec) * rbio->bio.bi_vcnt);

		bch_migrate_write_init(c, &promote_op->write,
				       &c->promote_write_point,
				       k, NULL,
				       BCH_WRITE_ALLOC_NOWAIT);
		promote_op->write.promote = true;

		if (rbio->crc.compression_type) {
			promote_op->write.op.flags |= BCH_WRITE_DATA_COMPRESSED;
			promote_op->write.op.crc = rbio->crc;
			promote_op->write.op.size = k.k->size;
		} else if (read_full) {
			/*
			 * Adjust bio to correspond to _live_ portion of @k -
			 * which might be less than what we're actually reading:
			 */
			bio_advance(promote_bio, rbio->crc.offset << 9);
			BUG_ON(bio_sectors(promote_bio) < k.k->size);
			promote_bio->bi_iter.bi_size = k.k->size << 9;
		} else {
			/*
			 * Set insert pos to correspond to what we're actually
			 * reading:
			 */
			promote_op->write.op.pos.offset = iter.bi_sector;
		}

		promote_bio->bi_iter.bi_sector =
			promote_op->write.op.pos.offset;
	}

	/* _after_ promete stuff has looked at rbio->crc.offset */
	if (read_full)
		rbio->crc.offset += skip;
	else
		rbio->bio.bi_iter.bi_sector += skip;

	rbio->submit_time_us = local_clock_us();

	generic_make_request(&rbio->bio);
}

static void bch_read_iter(struct cache_set *c, struct bch_read_bio *rbio,
			  struct bvec_iter bvec_iter, u64 inode,
			  unsigned flags)
{
	struct bio *bio = &rbio->bio;
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_EXTENTS,
				      POS(inode, bvec_iter.bi_sector), k) {
		BKEY_PADDED(k) tmp;
		struct extent_pick_ptr pick;
		unsigned bytes, sectors;
		bool is_last;

		/*
		 * Unlock the iterator while the btree node's lock is still in
		 * cache, before doing the IO:
		 */
		bkey_reassemble(&tmp.k, k);
		k = bkey_i_to_s_c(&tmp.k);
		bch_btree_iter_unlock(&iter);

		bch_extent_pick_ptr(c, k, &pick);
		if (IS_ERR(pick.ca)) {
			bcache_io_error(c, bio, "no device to read from");
			bio_endio(bio);
			return;
		}

		sectors = min_t(u64, k.k->p.offset,
				bvec_iter_end_sector(bvec_iter)) -
			bvec_iter.bi_sector;
		bytes = sectors << 9;
		is_last = bytes == bvec_iter.bi_size;
		swap(bvec_iter.bi_size, bytes);

		if (is_last)
			flags |= BCH_READ_IS_LAST;

		if (pick.ca) {
			PTR_BUCKET(pick.ca, &pick.ptr)->read_prio =
				c->prio_clock[READ].hand;

			bch_read_extent_iter(c, rbio, bvec_iter,
					     k, &pick, flags);

			flags &= ~BCH_READ_MAY_REUSE_BIO;
		} else {
			zero_fill_bio_iter(bio, bvec_iter);

			if (is_last)
				bio_endio(bio);
		}

		if (is_last)
			return;

		swap(bvec_iter.bi_size, bytes);
		bio_advance_iter(bio, &bvec_iter, bytes);
	}

	/*
	 * If we get here, it better have been because there was an error
	 * reading a btree node
	 */
	ret = bch_btree_iter_unlock(&iter);
	BUG_ON(!ret);
	bcache_io_error(c, bio, "btree IO error %i", ret);
	bio_endio(bio);
}

void bch_read(struct cache_set *c, struct bch_read_bio *bio, u64 inode)
{
	bch_increment_clock(c, bio_sectors(&bio->bio), READ);

	bch_read_iter(c, bio, bio->bio.bi_iter, inode,
		      BCH_READ_FORCE_BOUNCE|
		      BCH_READ_RETRY_IF_STALE|
		      BCH_READ_PROMOTE|
		      BCH_READ_MAY_REUSE_BIO);
}
EXPORT_SYMBOL(bch_read);

/**
 * bch_read_retry - re-submit a bio originally from bch_read()
 */
static void bch_read_retry(struct cache_set *c, struct bch_read_bio *rbio)
{
	struct bch_read_bio *parent = bch_rbio_parent(rbio);
	struct bvec_iter iter = rbio->parent_iter;
	u64 inode = rbio->inode;

	trace_bcache_read_retry(&rbio->bio);

	if (rbio->split)
		bch_rbio_free(c, rbio);
	else
		rbio->bio.bi_end_io = rbio->orig_bi_end_io;

	bch_read_iter(c, parent, iter, inode,
		      BCH_READ_FORCE_BOUNCE|
		      BCH_READ_RETRY_IF_STALE|
		      BCH_READ_PROMOTE);
}

void bch_read_retry_work(struct work_struct *work)
{
	struct cache_set *c = container_of(work, struct cache_set,
					   read_retry_work);
	struct bch_read_bio *rbio;
	struct bio *bio;
	unsigned long flags;

	while (1) {
		spin_lock_irqsave(&c->read_retry_lock, flags);
		bio = bio_list_pop(&c->read_retry_list);
		spin_unlock_irqrestore(&c->read_retry_lock, flags);

		if (!bio)
			break;

		rbio = container_of(bio, struct bch_read_bio, bio);
		bch_read_retry(c, rbio);
	}
}
