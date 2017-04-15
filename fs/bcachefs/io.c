/*
 * Some low level IO code, and hacks for various block layer limitations
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcachefs.h"
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
#include "super-io.h"

#include <linux/blkdev.h>
#include <linux/random.h>

#include <trace/events/bcachefs.h>

static inline void __bio_inc_remaining(struct bio *bio)
{
	bio_set_flag(bio, BIO_CHAIN);
	smp_mb__before_atomic();
	atomic_inc(&bio->__bi_remaining);
}

/* Allocate, free from mempool: */

void bch2_bio_free_pages_pool(struct bch_fs *c, struct bio *bio)
{
	struct bio_vec *bv;
	unsigned i;

	bio_for_each_segment_all(bv, bio, i)
		if (bv->bv_page != ZERO_PAGE(0))
			mempool_free(bv->bv_page, &c->bio_bounce_pages);
	bio->bi_vcnt = 0;
}

static void bch2_bio_alloc_page_pool(struct bch_fs *c, struct bio *bio,
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

void bch2_bio_alloc_pages_pool(struct bch_fs *c, struct bio *bio,
			      size_t bytes)
{
	bool using_mempool = false;

	bio->bi_iter.bi_size = bytes;

	while (bio->bi_vcnt < DIV_ROUND_UP(bytes, PAGE_SIZE))
		bch2_bio_alloc_page_pool(c, bio, &using_mempool);

	if (using_mempool)
		mutex_unlock(&c->bio_bounce_pages_lock);
}

/* Bios with headers */

void bch2_submit_wbio_replicas(struct bch_write_bio *wbio, struct bch_fs *c,
			       const struct bkey_i *k)
{
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
	const struct bch_extent_ptr *ptr;
	struct bch_write_bio *n;
	struct bch_dev *ca;

	BUG_ON(c->opts.nochanges);

	wbio->split = false;
	wbio->c = c;

	extent_for_each_ptr(e, ptr) {
		ca = c->devs[ptr->dev];

		if (ptr + 1 < &extent_entry_last(e)->ptr) {
			n = to_wbio(bio_clone_fast(&wbio->bio, GFP_NOIO,
						   &ca->replica_set));

			n->bio.bi_end_io	= wbio->bio.bi_end_io;
			n->bio.bi_private	= wbio->bio.bi_private;
			n->c			= c;
			n->orig			= &wbio->bio;
			n->bounce		= false;
			n->split		= true;
			n->put_bio		= true;
			n->bio.bi_opf		= wbio->bio.bi_opf;
			__bio_inc_remaining(n->orig);
		} else {
			n = wbio;
		}

		if (!journal_flushes_device(ca))
			n->bio.bi_opf |= REQ_FUA;

		n->ca			= ca;
		n->submit_time_us	= local_clock_us();
		n->bio.bi_iter.bi_sector = ptr->offset;

		if (likely(percpu_ref_tryget(&ca->io_ref))) {
			n->have_io_ref		= true;
			n->bio.bi_bdev		= ca->disk_sb.bdev;
			generic_make_request(&n->bio);
		} else {
			n->have_io_ref		= false;
			bcache_io_error(c, &n->bio, "device has been removed");
			bio_endio(&n->bio);
		}
	}
}

/* IO errors */

/* Writes */

static struct workqueue_struct *index_update_wq(struct bch_write_op *op)
{
	return op->alloc_reserve == RESERVE_MOVINGGC
		? op->c->copygc_wq
		: op->c->wq;
}

static void __bch2_write(struct closure *);

static void bch2_write_done(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);

	BUG_ON(!(op->flags & BCH_WRITE_DONE));

	if (!op->error && (op->flags & BCH_WRITE_FLUSH))
		op->error = bch2_journal_error(&op->c->journal);

	bch2_disk_reservation_put(op->c, &op->res);
	percpu_ref_put(&op->c->writes);
	bch2_keylist_free(&op->insert_keys, op->inline_keys);
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

static int bch2_write_index_default(struct bch_write_op *op)
{
	struct keylist *keys = &op->insert_keys;
	struct btree_iter iter;
	int ret;

	bch2_btree_iter_init_intent(&iter, op->c, BTREE_ID_EXTENTS,
		bkey_start_pos(&bch2_keylist_front(keys)->k));

	ret = bch2_btree_insert_list_at(&iter, keys, &op->res,
				       NULL, op_journal_seq(op),
				       BTREE_INSERT_NOFAIL);
	bch2_btree_iter_unlock(&iter);

	return ret;
}

/**
 * bch_write_index - after a write, update index to point to new data
 */
static void bch2_write_index(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bch_fs *c = op->c;
	struct keylist *keys = &op->insert_keys;
	unsigned i;

	op->flags |= BCH_WRITE_LOOPED;

	if (!bch2_keylist_empty(keys)) {
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
			bch2_open_bucket_put(c,
					     c->open_buckets +
					     op->open_buckets[i]);
			op->open_buckets[i] = 0;
		}

	if (!(op->flags & BCH_WRITE_DONE))
		continue_at(cl, __bch2_write, op->io_wq);

	if (!op->error && (op->flags & BCH_WRITE_FLUSH)) {
		bch2_journal_flush_seq_async(&c->journal,
					     *op_journal_seq(op),
					     cl);
		continue_at(cl, bch2_write_done, index_update_wq(op));
	} else {
		continue_at_nobarrier(cl, bch2_write_done, NULL);
	}
}

/**
 * bch_write_discard - discard range of keys
 *
 * Used to implement discard, and to handle when writethrough write hits
 * a write error on the cache device.
 */
static void bch2_write_discard(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bio *bio = &op->bio->bio;
	struct bpos end = op->pos;

	end.offset += bio_sectors(bio);

	op->error = bch2_discard(op->c, op->pos, end, op->version,
				&op->res, NULL, NULL);
}

/*
 * Convert extents to be inserted to discards after an error:
 */
static void bch2_write_io_error(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);

	if (op->flags & BCH_WRITE_DISCARD_ON_ERROR) {
		struct bkey_i *src = bch2_keylist_front(&op->insert_keys);
		struct bkey_i *dst = bch2_keylist_front(&op->insert_keys);

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
		while (!bch2_keylist_empty(&op->insert_keys))
			bch2_keylist_pop_front(&op->insert_keys);

		op->error = -EIO;
		op->flags |= BCH_WRITE_DONE;
	}

	bch2_write_index(cl);
}

static void bch2_write_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bch_write_bio *wbio = to_wbio(bio);
	struct bch_fs *c = wbio->c;
	struct bio *orig = wbio->orig;
	struct bch_dev *ca = wbio->ca;

	if (bch2_dev_nonfatal_io_err_on(bio->bi_error, ca,
				       "data write"))
		set_closure_fn(cl, bch2_write_io_error, index_update_wq(op));

	if (wbio->have_io_ref)
		percpu_ref_put(&ca->io_ref);

	if (bio->bi_error && orig)
		orig->bi_error = bio->bi_error;

	if (wbio->bounce)
		bch2_bio_free_pages_pool(c, bio);

	if (wbio->put_bio)
		bio_put(bio);

	if (orig)
		bio_endio(orig);
	else
		closure_put(cl);
}

static struct nonce extent_nonce(struct bversion version,
				 unsigned nonce,
				 unsigned uncompressed_size,
				 unsigned compression_type)
{
	return (struct nonce) {{
		[0] = cpu_to_le32((nonce		<< 12) |
				  (uncompressed_size	<< 22)),
		[1] = cpu_to_le32(version.lo),
		[2] = cpu_to_le32(version.lo >> 32),
		[3] = cpu_to_le32(version.hi|
				  (compression_type << 24))^BCH_NONCE_EXTENT,
	}};
}

static void init_append_extent(struct bch_write_op *op,
			       unsigned compressed_size,
			       unsigned uncompressed_size,
			       unsigned compression_type,
			       unsigned nonce,
			       struct bch_csum csum, unsigned csum_type,
			       struct open_bucket *ob)
{
	struct bkey_i_extent *e = bkey_extent_init(op->insert_keys.top);

	op->pos.offset += uncompressed_size;
	e->k.p = op->pos;
	e->k.size = uncompressed_size;
	e->k.version = op->version;
	bkey_extent_set_cached(&e->k, op->flags & BCH_WRITE_CACHED);

	bch2_extent_crc_append(e, compressed_size,
			      uncompressed_size,
			      compression_type,
			      nonce, csum, csum_type);

	bch2_alloc_sectors_append_ptrs(op->c, e, op->nr_replicas,
				      ob, compressed_size);

	bkey_extent_set_cached(&e->k, (op->flags & BCH_WRITE_CACHED));
	bch2_keylist_push(&op->insert_keys);
}

static int bch2_write_extent(struct bch_write_op *op,
			    struct open_bucket *ob,
			    struct bio *orig)
{
	struct bch_fs *c = op->c;
	struct bio *bio;
	struct bch_write_bio *wbio;
	unsigned key_to_write_offset = op->insert_keys.top_p -
		op->insert_keys.keys_p;
	struct bkey_i *key_to_write;
	unsigned csum_type = op->csum_type;
	unsigned compression_type = op->compression_type;
	int ret;

	/* don't refetch csum type/compression type */
	barrier();

	/* Need to decompress data? */
	if ((op->flags & BCH_WRITE_DATA_COMPRESSED) &&
	    (crc_uncompressed_size(NULL, &op->crc) != op->size ||
	     crc_compressed_size(NULL, &op->crc) > ob->sectors_free)) {
		int ret;

		ret = bch2_bio_uncompress_inplace(c, orig, op->size, op->crc);
		if (ret)
			return ret;

		op->flags &= ~BCH_WRITE_DATA_COMPRESSED;
	}

	if (op->flags & BCH_WRITE_DATA_COMPRESSED) {
		init_append_extent(op,
				   crc_compressed_size(NULL, &op->crc),
				   crc_uncompressed_size(NULL, &op->crc),
				   op->crc.compression_type,
				   op->crc.nonce,
				   op->crc.csum,
				   op->crc.csum_type,
				   ob);

		bio			= orig;
		wbio			= to_wbio(bio);
		wbio->orig		= NULL;
		wbio->bounce		= false;
		wbio->put_bio		= false;
		ret			= 0;
	} else if (csum_type != BCH_CSUM_NONE ||
		   compression_type != BCH_COMPRESSION_NONE) {
		/* all units here in bytes */
		unsigned total_output = 0, output_available =
			min(ob->sectors_free << 9, orig->bi_iter.bi_size);
		unsigned crc_nonce = bch2_csum_type_is_encryption(csum_type)
			? op->nonce : 0;
		struct bch_csum csum;
		struct nonce nonce;

		bio = bio_alloc_bioset(GFP_NOIO,
				       DIV_ROUND_UP(output_available, PAGE_SIZE),
				       &c->bio_write);
		/*
		 * XXX: can't use mempool for more than
		 * BCH_COMPRESSED_EXTENT_MAX worth of pages
		 */
		bch2_bio_alloc_pages_pool(c, bio, output_available);

		/* copy WRITE_SYNC flag */
		bio->bi_opf		= orig->bi_opf;
		wbio			= to_wbio(bio);
		wbio->orig		= NULL;
		wbio->bounce		= true;
		wbio->put_bio		= true;

		do {
			unsigned fragment_compression_type = compression_type;
			size_t dst_len, src_len;

			bch2_bio_compress(c, bio, &dst_len,
					 orig, &src_len,
					 &fragment_compression_type);

			BUG_ON(!dst_len || dst_len > bio->bi_iter.bi_size);
			BUG_ON(!src_len || src_len > orig->bi_iter.bi_size);
			BUG_ON(dst_len & (block_bytes(c) - 1));
			BUG_ON(src_len & (block_bytes(c) - 1));

			swap(bio->bi_iter.bi_size, dst_len);
			nonce = extent_nonce(op->version,
					     crc_nonce,
					     src_len >> 9,
					     fragment_compression_type),

			bch2_encrypt_bio(c, csum_type, nonce, bio);

			csum = bch2_checksum_bio(c, csum_type, nonce, bio);
			swap(bio->bi_iter.bi_size, dst_len);

			init_append_extent(op,
					   dst_len >> 9, src_len >> 9,
					   fragment_compression_type,
					   crc_nonce, csum, csum_type, ob);

			total_output += dst_len;
			bio_advance(bio, dst_len);
			bio_advance(orig, src_len);
		} while (bio->bi_iter.bi_size &&
			 orig->bi_iter.bi_size &&
			 !bch2_keylist_realloc(&op->insert_keys,
					      op->inline_keys,
					      ARRAY_SIZE(op->inline_keys),
					      BKEY_EXTENT_U64s_MAX));

		BUG_ON(total_output > output_available);

		memset(&bio->bi_iter, 0, sizeof(bio->bi_iter));
		bio->bi_iter.bi_size = total_output;

		/*
		 * Free unneeded pages after compressing:
		 */
		while (bio->bi_vcnt * PAGE_SIZE >
		       round_up(bio->bi_iter.bi_size, PAGE_SIZE))
			mempool_free(bio->bi_io_vec[--bio->bi_vcnt].bv_page,
				     &c->bio_bounce_pages);

		ret = orig->bi_iter.bi_size != 0;
	} else {
		bio = bio_next_split(orig, ob->sectors_free, GFP_NOIO,
				     &c->bio_write);

		wbio			= to_wbio(bio);
		wbio->orig		= NULL;
		wbio->bounce		= false;
		wbio->put_bio		= bio != orig;

		init_append_extent(op, bio_sectors(bio), bio_sectors(bio),
				   compression_type, 0,
				   (struct bch_csum) { 0 }, csum_type, ob);

		ret = bio != orig;
	}

	bio->bi_end_io	= bch2_write_endio;
	bio->bi_private	= &op->cl;
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	closure_get(bio->bi_private);

	/* might have done a realloc... */

	key_to_write = (void *) (op->insert_keys.keys_p + key_to_write_offset);

	bch2_check_mark_super(c, key_to_write, false);

	bch2_submit_wbio_replicas(to_wbio(bio), c, key_to_write);
	return ret;
}

static void __bch2_write(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bch_fs *c = op->c;
	struct bio *bio = &op->bio->bio;
	unsigned open_bucket_nr = 0;
	struct open_bucket *b;
	int ret;

	memset(op->open_buckets, 0, sizeof(op->open_buckets));

	if (op->flags & BCH_WRITE_DISCARD) {
		op->flags |= BCH_WRITE_DONE;
		bch2_write_discard(cl);
		bio_put(bio);
		continue_at(cl, bch2_write_done, index_update_wq(op));
	}

	/*
	 * Journal writes are marked REQ_PREFLUSH; if the original write was a
	 * flush, it'll wait on the journal write.
	 */
	bio->bi_opf &= ~(REQ_PREFLUSH|REQ_FUA);

	do {
		EBUG_ON(bio->bi_iter.bi_sector != op->pos.offset);
		EBUG_ON(!bio_sectors(bio));

		if (open_bucket_nr == ARRAY_SIZE(op->open_buckets))
			continue_at(cl, bch2_write_index, index_update_wq(op));

		/* for the device pointers and 1 for the chksum */
		if (bch2_keylist_realloc(&op->insert_keys,
					op->inline_keys,
					ARRAY_SIZE(op->inline_keys),
					BKEY_EXTENT_U64s_MAX))
			continue_at(cl, bch2_write_index, index_update_wq(op));

		b = bch2_alloc_sectors_start(c, op->wp,
			op->nr_replicas,
			c->opts.data_replicas_required,
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
			if (!bch2_keylist_empty(&op->insert_keys))
				continue_at(cl, bch2_write_index,
					    index_update_wq(op));

			/*
			 * If we've looped, we're running out of a workqueue -
			 * not the bch2_write() caller's context - and we don't
			 * want to block the workqueue:
			 */
			if (op->flags & BCH_WRITE_LOOPED)
				continue_at(cl, __bch2_write, op->io_wq);

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

		ret = bch2_write_extent(op, b, bio);

		bch2_alloc_sectors_done(c, op->wp, b);

		if (ret < 0)
			goto err;
	} while (ret);

	op->flags |= BCH_WRITE_DONE;
	continue_at(cl, bch2_write_index, index_update_wq(op));
err:
	if (op->flags & BCH_WRITE_DISCARD_ON_ERROR) {
		/*
		 * If we were writing cached data, not doing the write is fine
		 * so long as we discard whatever would have been overwritten -
		 * then it's equivalent to doing the write and immediately
		 * reclaiming it.
		 */

		bch2_write_discard(cl);
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
	continue_at(cl, !bch2_keylist_empty(&op->insert_keys)
		    ? bch2_write_index
		    : bch2_write_done, index_update_wq(op));
}

void bch2_wake_delayed_writes(unsigned long data)
{
	struct bch_fs *c = (void *) data;
	struct bch_write_op *op;
	unsigned long flags;

	spin_lock_irqsave(&c->foreground_write_pd_lock, flags);

	while ((op = c->write_wait_head)) {
		if (time_after(op->expires, jiffies)) {
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
void bch2_write(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bio *bio = &op->bio->bio;
	struct bch_fs *c = op->c;
	u64 inode = op->pos.inode;

	if (c->opts.nochanges ||
	    !percpu_ref_tryget(&c->writes)) {
		__bcache_io_error(c, "read only");
		op->error = -EROFS;
		bch2_disk_reservation_put(c, &op->res);
		closure_return(cl);
	}

	if (bversion_zero(op->version) &&
	    bch2_csum_type_is_encryption(op->csum_type))
		op->version.lo =
			atomic64_inc_return(&c->key_version) + 1;

	if (!(op->flags & BCH_WRITE_DISCARD))
		bch2_increment_clock(c, bio_sectors(bio), WRITE);

	/* Don't call bch2_next_delay() if rate is >= 1 GB/sec */

	if (c->foreground_write_ratelimit_enabled &&
	    c->foreground_write_pd.rate.rate < (1 << 30) &&
	    !(op->flags & BCH_WRITE_DISCARD) && op->wp->throttle) {
		unsigned long flags;
		u64 delay;

		spin_lock_irqsave(&c->foreground_write_pd_lock, flags);
		bch2_ratelimit_increment(&c->foreground_write_pd.rate,
					bio->bi_iter.bi_size);

		delay = bch2_ratelimit_delay(&c->foreground_write_pd.rate);

		if (delay >= HZ / 100) {
			trace_write_throttle(c, inode, bio, delay);

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
			continue_at(cl, __bch2_write, index_update_wq(op));
		}

		spin_unlock_irqrestore(&c->foreground_write_pd_lock, flags);
	}

	continue_at_nobarrier(cl, __bch2_write, NULL);
}

void bch2_write_op_init(struct bch_write_op *op, struct bch_fs *c,
		       struct bch_write_bio *bio, struct disk_reservation res,
		       struct write_point *wp, struct bpos pos,
		       u64 *journal_seq, unsigned flags)
{
	EBUG_ON(res.sectors && !res.nr_replicas);

	op->c		= c;
	op->io_wq	= index_update_wq(op);
	op->bio		= bio;
	op->written	= 0;
	op->error	= 0;
	op->flags	= flags;
	op->csum_type	= bch2_data_checksum_type(c);
	op->compression_type = c->opts.compression;
	op->nr_replicas	= res.nr_replicas;
	op->alloc_reserve = RESERVE_NONE;
	op->nonce	= 0;
	op->pos		= pos;
	op->version	= ZERO_VERSION;
	op->res		= res;
	op->wp		= wp;

	if (journal_seq) {
		op->journal_seq_p = journal_seq;
		op->flags |= BCH_WRITE_JOURNAL_SEQ_PTR;
	} else {
		op->journal_seq = 0;
	}

	op->index_update_fn = bch2_write_index_default;

	bch2_keylist_init(&op->insert_keys,
			  op->inline_keys,
			  ARRAY_SIZE(op->inline_keys));

	if (version_stress_test(c))
		get_random_bytes(&op->version, sizeof(op->version));
}

/* Discard */

/* bch_discard - discard a range of keys from start_key to end_key.
 * @c		filesystem
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
int bch2_discard(struct bch_fs *c, struct bpos start,
		 struct bpos end, struct bversion version,
		 struct disk_reservation *disk_res,
		 struct extent_insert_hook *hook,
		 u64 *journal_seq)
{
	return bch2_btree_delete_range(c, BTREE_ID_EXTENTS, start, end, version,
				      disk_res, hook, journal_seq);
}

/* Cache promotion on read */

struct cache_promote_op {
	struct closure		cl;
	struct migrate_write	write;
	struct bio_vec		bi_inline_vecs[0]; /* must be last */
};

/* Read */

static int bio_checksum_uncompress(struct bch_fs *c,
				   struct bch_read_bio *rbio)
{
	struct bio *src = &rbio->bio;
	struct bio *dst = &bch2_rbio_parent(rbio)->bio;
	struct bvec_iter dst_iter = rbio->parent_iter;
	struct nonce nonce = extent_nonce(rbio->version,
				rbio->crc.nonce,
				crc_uncompressed_size(NULL, &rbio->crc),
				rbio->crc.compression_type);
	struct bch_csum csum;
	int ret = 0;

	/*
	 * reset iterator for checksumming and copying bounced data: here we've
	 * set rbio->compressed_size to the amount of data we actually read,
	 * which was not necessarily the full extent if we were only bouncing
	 * in order to promote
	 */
	if (rbio->bounce) {
		src->bi_iter.bi_size	= crc_compressed_size(NULL, &rbio->crc) << 9;
		src->bi_iter.bi_idx	= 0;
		src->bi_iter.bi_bvec_done = 0;
	} else {
		src->bi_iter = rbio->parent_iter;
	}

	csum = bch2_checksum_bio(c, rbio->crc.csum_type, nonce, src);
	if (bch2_dev_nonfatal_io_err_on(bch2_crc_cmp(rbio->crc.csum, csum),
					rbio->ca,
			"data checksum error, inode %llu offset %llu: expected %0llx%0llx got %0llx%0llx (type %u)",
			rbio->inode, (u64) rbio->parent_iter.bi_sector << 9,
			rbio->crc.csum.hi, rbio->crc.csum.lo, csum.hi, csum.lo,
			rbio->crc.csum_type))
		ret = -EIO;

	/*
	 * If there was a checksum error, still copy the data back - unless it
	 * was compressed, we don't want to decompress bad data:
	 */
	if (rbio->crc.compression_type != BCH_COMPRESSION_NONE) {
		if (!ret) {
			bch2_encrypt_bio(c, rbio->crc.csum_type, nonce, src);
			ret = bch2_bio_uncompress(c, src, dst,
						 dst_iter, rbio->crc);
			if (ret)
				__bcache_io_error(c, "decompression error");
		}
	} else if (rbio->bounce) {
		bio_advance(src, rbio->crc.offset << 9);

		/* don't need to decrypt the entire bio: */
		BUG_ON(src->bi_iter.bi_size < dst_iter.bi_size);
		src->bi_iter.bi_size = dst_iter.bi_size;

		nonce = nonce_add(nonce, rbio->crc.offset << 9);

		bch2_encrypt_bio(c, rbio->crc.csum_type,
				nonce, src);

		bio_copy_data_iter(dst, &dst_iter,
				   src, &src->bi_iter);
	} else {
		bch2_encrypt_bio(c, rbio->crc.csum_type, nonce, src);
	}

	return ret;
}

static void bch2_rbio_free(struct bch_read_bio *rbio)
{
	struct bch_fs *c = rbio->c;
	struct bio *bio = &rbio->bio;

	BUG_ON(rbio->ca);
	BUG_ON(!rbio->split);

	if (rbio->promote)
		kfree(rbio->promote);
	if (rbio->bounce)
		bch2_bio_free_pages_pool(c, bio);

	bio_put(bio);
}

static void bch2_rbio_done(struct bch_read_bio *rbio)
{
	struct bio *orig = &bch2_rbio_parent(rbio)->bio;

	percpu_ref_put(&rbio->ca->io_ref);
	rbio->ca = NULL;

	if (rbio->split) {
		if (rbio->bio.bi_error)
			orig->bi_error = rbio->bio.bi_error;

		bio_endio(orig);
		bch2_rbio_free(rbio);
	} else {
		if (rbio->promote)
			kfree(rbio->promote);

		orig->bi_end_io = rbio->orig_bi_end_io;
		bio_endio_nodec(orig);
	}
}

static void bch2_rbio_error(struct bch_read_bio *rbio, int error)
{
	bch2_rbio_parent(rbio)->bio.bi_error = error;
	bch2_rbio_done(rbio);
}

static void bch2_rbio_retry(struct bch_fs *c, struct bch_read_bio *rbio)
{
	unsigned long flags;

	percpu_ref_put(&rbio->ca->io_ref);
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

	bch2_bio_free_pages_pool(op->write.op.c, &op->write.wbio.bio);
	kfree(op);
}

/* Inner part that may run in process context */
static void __bch2_read_endio(struct work_struct *work)
{
	struct bch_read_bio *rbio =
		container_of(work, struct bch_read_bio, work);
	struct bch_fs *c = rbio->c;
	int ret;

	ret = bio_checksum_uncompress(c, rbio);
	if (ret) {
		/*
		 * Checksum error: if the bio wasn't bounced, we may have been
		 * reading into buffers owned by userspace (that userspace can
		 * scribble over) - retry the read, bouncing it this time:
		 */
		if (!rbio->bounce && (rbio->flags & BCH_READ_USER_MAPPED)) {
			rbio->flags |= BCH_READ_FORCE_BOUNCE;
			bch2_rbio_retry(c, rbio);
		} else {
			bch2_rbio_error(rbio, -EIO);
		}
		return;
	}

	if (rbio->promote) {
		struct cache_promote_op *promote = rbio->promote;
		struct closure *cl = &promote->cl;

		BUG_ON(!rbio->split || !rbio->bounce);

		trace_promote(&rbio->bio);

		/* we now own pages: */
		swap(promote->write.wbio.bio.bi_vcnt, rbio->bio.bi_vcnt);
		rbio->promote = NULL;

		bch2_rbio_done(rbio);

		closure_init(cl, &c->cl);
		closure_call(&promote->write.op.cl, bch2_write, c->wq, cl);
		closure_return_with_destructor(cl, cache_promote_done);
	} else {
		bch2_rbio_done(rbio);
	}
}

static void bch2_read_endio(struct bio *bio)
{
	struct bch_read_bio *rbio =
		container_of(bio, struct bch_read_bio, bio);
	struct bch_fs *c = rbio->c;

	if (bch2_dev_nonfatal_io_err_on(bio->bi_error, rbio->ca, "data read")) {
		/* XXX: retry IO errors when we have another replica */
		bch2_rbio_error(rbio, bio->bi_error);
		return;
	}

	if (rbio->ptr.cached &&
	    (((rbio->flags & BCH_READ_RETRY_IF_STALE) && race_fault()) ||
	     ptr_stale(rbio->ca, &rbio->ptr))) {
		atomic_long_inc(&c->read_realloc_races);

		if (rbio->flags & BCH_READ_RETRY_IF_STALE)
			bch2_rbio_retry(c, rbio);
		else
			bch2_rbio_error(rbio, -EINTR);
		return;
	}

	if (rbio->crc.compression_type ||
	    bch2_csum_type_is_encryption(rbio->crc.csum_type))
		queue_work(system_unbound_wq, &rbio->work);
	else if (rbio->crc.csum_type)
		queue_work(system_highpri_wq, &rbio->work);
	else
		__bch2_read_endio(&rbio->work);
}

static bool should_promote(struct bch_fs *c,
			   struct extent_pick_ptr *pick, unsigned flags)
{
	if (!(flags & BCH_READ_PROMOTE))
		return false;

	if (percpu_ref_is_dying(&c->writes))
		return false;

	return c->fastest_tier &&
		c->fastest_tier < c->tiers + pick->ca->mi.tier;
}

void bch2_read_extent_iter(struct bch_fs *c, struct bch_read_bio *orig,
			  struct bvec_iter iter, struct bkey_s_c k,
			  struct extent_pick_ptr *pick, unsigned flags)
{
	struct bch_read_bio *rbio;
	struct cache_promote_op *promote_op = NULL;
	unsigned skip = iter.bi_sector - bkey_start_offset(k.k);
	bool bounce = false, split, read_full = false;

	bch2_increment_clock(c, bio_sectors(&orig->bio), READ);

	EBUG_ON(bkey_start_offset(k.k) > iter.bi_sector ||
		k.k->p.offset < bvec_iter_end_sector(iter));

	/* only promote if we're not reading from the fastest tier: */

	/*
	 * XXX: multiple promotes can race with each other, wastefully. Keep a
	 * list of outstanding promotes?
	 */
	if (should_promote(c, pick, flags)) {
		/*
		 * biovec needs to be big enough to hold decompressed data, if
		 * the bch2_write_extent() has to decompress/recompress it:
		 */
		unsigned sectors =
			max_t(unsigned, k.k->size,
			      crc_uncompressed_size(NULL, &pick->crc));
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
	     (bvec_iter_sectors(iter) != crc_uncompressed_size(NULL, &pick->crc) ||
	      (bch2_csum_type_is_encryption(pick->crc.csum_type) &&
	       (flags & BCH_READ_USER_MAPPED)) ||
	      (flags & BCH_READ_FORCE_BOUNCE)))) {
		read_full = true;
		bounce = true;
	}

	if (bounce) {
		unsigned sectors = read_full
			? (crc_compressed_size(NULL, &pick->crc) ?: k.k->size)
			: bvec_iter_sectors(iter);

		rbio = container_of(bio_alloc_bioset(GFP_NOIO,
					DIV_ROUND_UP(sectors, PAGE_SECTORS),
					&c->bio_read_split),
				    struct bch_read_bio, bio);

		bch2_bio_alloc_pages_pool(c, &rbio->bio, sectors << 9);
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

	rbio->flags		= flags;
	rbio->bounce		= bounce;
	rbio->split		= split;
	rbio->c			= c;
	rbio->ca		= pick->ca;
	rbio->ptr		= pick->ptr;
	rbio->crc		= pick->crc;
	/*
	 * crc.compressed_size will be 0 if there wasn't any checksum
	 * information, also we need to stash the original size of the bio if we
	 * bounced (which isn't necessarily the original key size, if we bounced
	 * only for promoting)
	 */
	rbio->crc._compressed_size = bio_sectors(&rbio->bio) - 1;
	rbio->version		= k.k->version;
	rbio->promote		= promote_op;
	rbio->inode		= k.k->p.inode;
	INIT_WORK(&rbio->work, __bch2_read_endio);

	rbio->bio.bi_bdev	= pick->ca->disk_sb.bdev;
	rbio->bio.bi_opf	= orig->bio.bi_opf;
	rbio->bio.bi_iter.bi_sector = pick->ptr.offset;
	rbio->bio.bi_end_io	= bch2_read_endio;

	if (promote_op) {
		struct bio *promote_bio = &promote_op->write.wbio.bio;

		promote_bio->bi_iter = rbio->bio.bi_iter;
		memcpy(promote_bio->bi_io_vec, rbio->bio.bi_io_vec,
		       sizeof(struct bio_vec) * rbio->bio.bi_vcnt);

		bch2_migrate_write_init(c, &promote_op->write,
				       &c->promote_write_point,
				       k, NULL,
				       BCH_WRITE_ALLOC_NOWAIT|
				       BCH_WRITE_CACHED);
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

	if (bounce)
		trace_read_bounce(&rbio->bio);

	if (!(flags & BCH_READ_IS_LAST))
		trace_read_split(&rbio->bio);

	generic_make_request(&rbio->bio);
}

static void bch2_read_iter(struct bch_fs *c, struct bch_read_bio *rbio,
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
		bch2_btree_iter_unlock(&iter);

		bch2_extent_pick_ptr(c, k, &pick);
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

			bch2_read_extent_iter(c, rbio, bvec_iter,
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
	ret = bch2_btree_iter_unlock(&iter);
	BUG_ON(!ret);
	bcache_io_error(c, bio, "btree IO error %i", ret);
	bio_endio(bio);
}

void bch2_read(struct bch_fs *c, struct bch_read_bio *bio, u64 inode)
{
	bch2_read_iter(c, bio, bio->bio.bi_iter, inode,
		      BCH_READ_RETRY_IF_STALE|
		      BCH_READ_PROMOTE|
		      BCH_READ_MAY_REUSE_BIO|
		      BCH_READ_USER_MAPPED);
}

/**
 * bch_read_retry - re-submit a bio originally from bch2_read()
 */
static void bch2_read_retry(struct bch_fs *c, struct bch_read_bio *rbio)
{
	struct bch_read_bio *parent = bch2_rbio_parent(rbio);
	struct bvec_iter iter = rbio->parent_iter;
	unsigned flags = rbio->flags;
	u64 inode = rbio->inode;

	trace_read_retry(&rbio->bio);

	if (rbio->split)
		bch2_rbio_free(rbio);
	else
		rbio->bio.bi_end_io = rbio->orig_bi_end_io;

	bch2_read_iter(c, parent, iter, inode, flags);
}

void bch2_read_retry_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs,
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
		bch2_read_retry(c, rbio);
	}
}
