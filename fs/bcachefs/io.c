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

/* Allocate, free from mempool: */

void bch2_latency_acct(struct bch_dev *ca, unsigned submit_time_us, int rw)
{
	u64 now = local_clock();
	unsigned io_latency = (now >> 10) - submit_time_us;
	atomic_t *latency = &ca->latency[rw];
	unsigned old, new, v = atomic_read(latency);

	do {
		old = v;

		/*
		 * If the io latency was reasonably close to the current
		 * latency, skip doing the update and atomic operation - most of
		 * the time:
		 */
		if (abs((int) (old - io_latency)) < (old >> 1) &&
		    now & ~(~0 << 5))
			break;

		new = ewma_add((u64) old, io_latency, 6);
	} while ((v = atomic_cmpxchg(latency, old, new)) != old);
}

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
			       enum bch_data_type type,
			       const struct bkey_i *k)
{
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
	const struct bch_extent_ptr *ptr;
	struct bch_write_bio *n;
	struct bch_dev *ca;
	unsigned ptr_idx = 0;

	BUG_ON(c->opts.nochanges);

	extent_for_each_ptr(e, ptr) {
		BUG_ON(ptr->dev >= BCH_SB_MEMBERS_MAX ||
		       !c->devs[ptr->dev]);

		ca = c->devs[ptr->dev];

		if (ptr + 1 < &extent_entry_last(e)->ptr) {
			n = to_wbio(bio_clone_fast(&wbio->bio, GFP_NOIO,
						   &ca->replica_set));

			n->bio.bi_end_io	= wbio->bio.bi_end_io;
			n->bio.bi_private	= wbio->bio.bi_private;
			n->parent		= wbio;
			n->split		= true;
			n->bounce		= false;
			n->put_bio		= true;
			n->bio.bi_opf		= wbio->bio.bi_opf;
			bio_inc_remaining(&wbio->bio);
		} else {
			n = wbio;
			n->split		= false;
		}

		n->c			= c;
		n->ca			= ca;
		n->ptr_idx		= ptr_idx++;
		n->submit_time_us	= local_clock_us();
		n->bio.bi_iter.bi_sector = ptr->offset;

		if (!journal_flushes_device(ca))
			n->bio.bi_opf |= REQ_FUA;

		if (likely(percpu_ref_tryget(&ca->io_ref))) {
			this_cpu_add(ca->io_done->sectors[WRITE][type],
				     bio_sectors(&n->bio));

			n->have_io_ref		= true;
			bio_set_dev(&n->bio, ca->disk_sb.bdev);
			submit_bio(&n->bio);
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

	bch2_btree_iter_init(&iter, op->c, BTREE_ID_EXTENTS,
			     bkey_start_pos(&bch2_keylist_front(keys)->k),
			     BTREE_ITER_INTENT);

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

	if (!(op->flags & BCH_WRITE_DONE)) {
		continue_at(cl, __bch2_write, op->io_wq);
		return;
	}

	if (!op->error && (op->flags & BCH_WRITE_FLUSH)) {
		bch2_journal_flush_seq_async(&c->journal,
					     *op_journal_seq(op),
					     cl);
		continue_at(cl, bch2_write_done, index_update_wq(op));
	} else {
		continue_at_nobarrier(cl, bch2_write_done, NULL);
	}
}

static void bch2_write_io_error(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct keylist *keys = &op->insert_keys;
	struct bch_fs *c = op->c;
	struct bch_extent_ptr *ptr;
	struct bkey_i *k;
	int ret;

	for_each_keylist_key(keys, k) {
		struct bkey_i *n = bkey_next(k);
		struct bkey_s_extent e = bkey_i_to_s_extent(k);

		extent_for_each_ptr_backwards(e, ptr)
			if (test_bit(ptr->dev, op->failed.d))
				bch2_extent_drop_ptr(e, ptr);

		memmove(bkey_next(k), n, (void *) keys->top - (void *) n);
		keys->top_p -= (u64 *) n - (u64 *) bkey_next(k);

		ret = bch2_extent_nr_ptrs(e.c)
			? bch2_check_mark_super(c, e.c, BCH_DATA_USER)
			: -EIO;
		if (ret) {
			keys->top = keys->keys;
			op->error = ret;
			op->flags |= BCH_WRITE_DONE;
			break;
		}
	}

	memset(&op->failed, 0, sizeof(op->failed));

	bch2_write_index(cl);
	return;
}

static void bch2_write_endio(struct bio *bio)
{
	struct closure *cl		= bio->bi_private;
	struct bch_write_op *op		= container_of(cl, struct bch_write_op, cl);
	struct bch_write_bio *wbio	= to_wbio(bio);
	struct bch_write_bio *parent	= wbio->split ? wbio->parent : NULL;
	struct bch_fs *c		= wbio->c;
	struct bch_dev *ca		= wbio->ca;

	bch2_latency_acct(ca, wbio->submit_time_us, WRITE);

	if (bch2_dev_io_err_on(bio->bi_status, ca, "data write")) {
		set_bit(ca->dev_idx, op->failed.d);
		set_closure_fn(cl, bch2_write_io_error, index_update_wq(op));
	}

	if (wbio->have_io_ref)
		percpu_ref_put(&ca->io_ref);

	if (wbio->bounce)
		bch2_bio_free_pages_pool(c, bio);

	if (wbio->put_bio)
		bio_put(bio);

	if (parent)
		bio_endio(&parent->bio);
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

static void __init_append_extent(struct bch_write_op *op,
				 struct bch_extent_crc_unpacked crc,
				 struct open_bucket *ob)
{
	struct bkey_i_extent *e = bkey_extent_init(op->insert_keys.top);

	op->pos.offset += crc.uncompressed_size;
	e->k.p = op->pos;
	e->k.size = crc.uncompressed_size;
	e->k.version = op->version;
	bkey_extent_set_cached(&e->k, op->flags & BCH_WRITE_CACHED);

	bch2_extent_crc_append(e, crc);
	bch2_alloc_sectors_append_ptrs(op->c, e, op->nr_replicas,
				       ob, crc.compressed_size);

	bkey_extent_set_cached(&e->k, (op->flags & BCH_WRITE_CACHED));
	bch2_keylist_push(&op->insert_keys);
}

static void init_append_extent(struct bch_write_op *op,
			       unsigned compressed_size,
			       unsigned uncompressed_size,
			       unsigned compression_type,
			       unsigned nonce,
			       struct bch_csum csum, unsigned csum_type,
			       struct open_bucket *ob)
{
	struct bch_extent_crc_unpacked crc = {
		.csum_type		= csum_type,
		.compression_type	= compression_type,
		.compressed_size	= compressed_size,
		.uncompressed_size	= uncompressed_size,
		.nonce			= nonce,
		.csum			= csum,
	};

	__init_append_extent(op, crc, ob);
}

static int bch2_write_extent(struct bch_write_op *op, struct write_point *wp)
{
	struct bch_fs *c = op->c;
	struct bio *orig = &op->wbio.bio;
	struct bio *bio;
	struct bch_write_bio *wbio;
	unsigned key_to_write_offset = op->insert_keys.top_p -
		op->insert_keys.keys_p;
	struct bkey_i *key_to_write;
	unsigned csum_type = op->csum_type;
	unsigned compression_type = op->compression_type;
	int ret, more;

	/* don't refetch csum type/compression type */
	barrier();

	BUG_ON(!bio_sectors(orig));

	/* Need to decompress data? */
	if ((op->flags & BCH_WRITE_DATA_COMPRESSED) &&
	    (op->crc.uncompressed_size != op->size ||
	     op->crc.compressed_size > wp->sectors_free)) {
		int ret;

		ret = bch2_bio_uncompress_inplace(c, orig, op->size, op->crc);
		if (ret)
			return ret;

		op->flags &= ~BCH_WRITE_DATA_COMPRESSED;
	}

	if (op->flags & BCH_WRITE_DATA_COMPRESSED) {
		__init_append_extent(op,
				     op->crc,
				     wp->ob);

		bio			= orig;
		wbio			= wbio_init(bio);
		more			= 0;
	} else if (csum_type != BCH_CSUM_NONE ||
		   compression_type != BCH_COMPRESSION_NONE) {
		/* all units here in bytes */
		unsigned total_output = 0, output_available =
			min(wp->sectors_free << 9, orig->bi_iter.bi_size);
		unsigned crc_nonce = bch2_csum_type_is_encryption(csum_type)
			? op->nonce : 0;
		struct bch_csum csum;
		struct nonce nonce;

		bio = bio_alloc_bioset(GFP_NOIO,
				       DIV_ROUND_UP(output_available, PAGE_SIZE),
				       &c->bio_write);
		wbio			= wbio_init(bio);
		wbio->bounce		= true;
		wbio->put_bio		= true;
		/* copy WRITE_SYNC flag */
		wbio->bio.bi_opf	= orig->bi_opf;

		/*
		 * XXX: can't use mempool for more than
		 * BCH_COMPRESSED_EXTENT_MAX worth of pages
		 */
		bch2_bio_alloc_pages_pool(c, bio, output_available);

		do {
			unsigned fragment_compression_type = compression_type;
			size_t dst_len, src_len;

			bch2_bio_compress(c, bio, &dst_len,
					 orig, &src_len,
					 &fragment_compression_type);

			nonce = extent_nonce(op->version,
					     crc_nonce,
					     src_len >> 9,
					     fragment_compression_type);

			swap(bio->bi_iter.bi_size, dst_len);
			bch2_encrypt_bio(c, csum_type, nonce, bio);

			csum = bch2_checksum_bio(c, csum_type, nonce, bio);
			swap(bio->bi_iter.bi_size, dst_len);

			init_append_extent(op,
					   dst_len >> 9, src_len >> 9,
					   fragment_compression_type,
					   crc_nonce, csum, csum_type, wp->ob);

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

		more = orig->bi_iter.bi_size != 0;
	} else {
		bio = bio_next_split(orig, wp->sectors_free, GFP_NOIO,
				     &c->bio_write);
		wbio			= wbio_init(bio);
		wbio->put_bio		= bio != orig;

		init_append_extent(op, bio_sectors(bio), bio_sectors(bio),
				   compression_type, 0,
				   (struct bch_csum) { 0 }, csum_type, wp->ob);

		more = bio != orig;
	}

	/* might have done a realloc... */

	key_to_write = (void *) (op->insert_keys.keys_p + key_to_write_offset);

	ret = bch2_check_mark_super(c, bkey_i_to_s_c_extent(key_to_write),
				    BCH_DATA_USER);
	if (ret)
		return ret;

	bio->bi_end_io	= bch2_write_endio;
	bio->bi_private	= &op->cl;
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	closure_get(bio->bi_private);

	bch2_submit_wbio_replicas(to_wbio(bio), c, BCH_DATA_USER,
				  key_to_write);
	return more;
}

static void __bch2_write(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bch_fs *c = op->c;
	unsigned open_bucket_nr = 0;
	struct write_point *wp;
	struct open_bucket *ob;
	int ret;

	do {
		if (open_bucket_nr == ARRAY_SIZE(op->open_buckets)) {
			continue_at(cl, bch2_write_index, index_update_wq(op));
			return;
		}

		/* for the device pointers and 1 for the chksum */
		if (bch2_keylist_realloc(&op->insert_keys,
					op->inline_keys,
					ARRAY_SIZE(op->inline_keys),
					BKEY_EXTENT_U64s_MAX)) {
			continue_at(cl, bch2_write_index, index_update_wq(op));
			return;
		}

		wp = bch2_alloc_sectors_start(c,
			op->devs,
			op->write_point,
			op->nr_replicas,
			c->opts.data_replicas_required,
			op->alloc_reserve,
			op->flags,
			(op->flags & BCH_WRITE_ALLOC_NOWAIT) ? NULL : cl);
		EBUG_ON(!wp);

		if (unlikely(IS_ERR(wp))) {
			if (unlikely(PTR_ERR(wp) != -EAGAIN)) {
				ret = PTR_ERR(wp);
				goto err;
			}

			/*
			 * If we already have some keys, must insert them first
			 * before allocating another open bucket. We only hit
			 * this case if open_bucket_nr > 1.
			 */
			if (!bch2_keylist_empty(&op->insert_keys)) {
				continue_at(cl, bch2_write_index,
					    index_update_wq(op));
				return;
			}

			/*
			 * If we've looped, we're running out of a workqueue -
			 * not the bch2_write() caller's context - and we don't
			 * want to block the workqueue:
			 */
			if (op->flags & BCH_WRITE_LOOPED) {
				continue_at(cl, __bch2_write, op->io_wq);
				return;
			}

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

		ob = wp->ob;

		BUG_ON(ob - c->open_buckets == 0 ||
		       ob - c->open_buckets > U8_MAX);
		op->open_buckets[open_bucket_nr++] = ob - c->open_buckets;

		ret = bch2_write_extent(op, wp);

		bch2_alloc_sectors_done(c, wp);

		if (ret < 0)
			goto err;
	} while (ret);

	op->flags |= BCH_WRITE_DONE;
	continue_at(cl, bch2_write_index, index_update_wq(op));
	return;
err:
	/*
	 * Right now we can only error here if we went RO - the
	 * allocation failed, but we already checked for -ENOSPC when we
	 * got our reservation.
	 *
	 * XXX capacity might have changed, but we don't check for that
	 * yet:
	 */
	op->error = ret;
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

void bch2_wake_delayed_writes(struct timer_list *timer)
{
	struct bch_fs *c =
		container_of(timer, struct bch_fs, foreground_write_wakeup);
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
 * If op->discard is true, instead of inserting the data it invalidates the
 * region of the cache represented by op->bio and op->inode.
 */
void bch2_write(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bio *bio = &op->wbio.bio;
	struct bch_fs *c = op->c;
	u64 inode = op->pos.inode;

	if (c->opts.nochanges ||
	    !percpu_ref_tryget(&c->writes)) {
		__bcache_io_error(c, "read only");
		op->error = -EROFS;
		bch2_disk_reservation_put(c, &op->res);
		closure_return(cl);
		return;
	}

	if (bversion_zero(op->version) &&
	    bch2_csum_type_is_encryption(op->csum_type))
		op->version.lo =
			atomic64_inc_return(&c->key_version) + 1;

	bch2_increment_clock(c, bio_sectors(bio), WRITE);

	/* Don't call bch2_next_delay() if rate is >= 1 GB/sec */

	if ((op->flags & BCH_WRITE_THROTTLE) &&
	    c->foreground_write_ratelimit_enabled &&
	    c->foreground_write_pd.rate.rate < (1 << 30)) {
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
			return;
		}

		spin_unlock_irqrestore(&c->foreground_write_pd_lock, flags);
	}

	continue_at_nobarrier(cl, __bch2_write, NULL);
}

void bch2_write_op_init(struct bch_write_op *op, struct bch_fs *c,
			struct disk_reservation res,
			struct bch_devs_mask *devs,
			struct write_point_specifier write_point,
			struct bpos pos,
			u64 *journal_seq, unsigned flags)
{
	EBUG_ON(res.sectors && !res.nr_replicas);

	op->c		= c;
	op->io_wq	= index_update_wq(op);
	op->written	= 0;
	op->error	= 0;
	op->flags	= flags;
	op->csum_type	= bch2_data_checksum_type(c);
	op->compression_type =
		bch2_compression_opt_to_type(c->opts.compression);
	op->nr_replicas	= res.nr_replicas;
	op->alloc_reserve = RESERVE_NONE;
	op->nonce	= 0;
	op->pos		= pos;
	op->version	= ZERO_VERSION;
	op->res		= res;
	op->devs	= devs;
	op->write_point	= write_point;

	if (journal_seq) {
		op->journal_seq_p = journal_seq;
		op->flags |= BCH_WRITE_JOURNAL_SEQ_PTR;
	} else {
		op->journal_seq = 0;
	}

	op->index_update_fn = bch2_write_index_default;

	memset(op->open_buckets, 0, sizeof(op->open_buckets));
	memset(&op->failed, 0, sizeof(op->failed));

	bch2_keylist_init(&op->insert_keys,
			  op->inline_keys,
			  ARRAY_SIZE(op->inline_keys));

	if (version_stress_test(c))
		get_random_bytes(&op->version, sizeof(op->version));
}

/* Cache promotion on read */

struct promote_op {
	struct closure		cl;
	struct migrate_write	write;
	struct bio_vec		bi_inline_vecs[0]; /* must be last */
};

static void promote_done(struct closure *cl)
{
	struct promote_op *op =
		container_of(cl, struct promote_op, cl);
	struct bch_fs *c = op->write.op.c;

	percpu_ref_put(&c->writes);
	bch2_bio_free_pages_pool(c, &op->write.op.wbio.bio);
	kfree(op);
}

static void promote_start(struct promote_op *op, struct bch_read_bio *rbio)
{
	struct bch_fs *c = rbio->c;
	struct closure *cl = &op->cl;
	struct bio *bio = &op->write.op.wbio.bio;

	BUG_ON(!rbio->split || !rbio->bounce);

	if (!percpu_ref_tryget(&c->writes))
		return;

	trace_promote(&rbio->bio);

	/* we now own pages: */
	swap(bio->bi_vcnt, rbio->bio.bi_vcnt);
	rbio->promote = NULL;

	closure_init(cl, NULL);
	closure_call(&op->write.op.cl, bch2_write, c->wq, cl);
	closure_return_with_destructor(cl, promote_done);
}

/*
 * XXX: multiple promotes can race with each other, wastefully. Keep a list of
 * outstanding promotes?
 */
static struct promote_op *promote_alloc(struct bch_read_bio *rbio,
					struct bkey_s_c k)
{
	struct bch_fs *c = rbio->c;
	struct promote_op *op;
	struct bio *bio;

	op = kmalloc(sizeof(*op) + sizeof(struct bio_vec) * rbio->bio.bi_vcnt,
		     GFP_NOIO);
	if (!op)
		return NULL;

	bio = &op->write.op.wbio.bio;
	bio_init(bio, bio->bi_inline_vecs, rbio->bio.bi_vcnt);

	bio->bi_iter.bi_size = rbio->bio.bi_iter.bi_size;

	memcpy(bio->bi_io_vec, rbio->bio.bi_io_vec,
	       sizeof(struct bio_vec) * rbio->bio.bi_vcnt);

	bch2_migrate_write_init(c, &op->write,
				c->fastest_devs,
				writepoint_hashed((unsigned long) current),
				k, NULL,
				BCH_WRITE_ALLOC_NOWAIT|
				BCH_WRITE_CACHED);
	op->write.promote = true;

	if (rbio->pick.crc.compression_type) {
		op->write.op.flags     |= BCH_WRITE_DATA_COMPRESSED;
		op->write.op.crc	= rbio->pick.crc;
		op->write.op.size	= k.k->size;
	} else if (rbio->read_full) {
		/*
		 * Adjust bio to correspond to _live_ portion of @k -
		 * which might be less than what we're actually reading:
		 */
		bio_advance(bio, rbio->pick.crc.offset << 9);

		BUG_ON(bio_sectors(bio) < k.k->size);
		bio->bi_iter.bi_size = k.k->size << 9;
	} else {
		/*
		 * Set insert pos to correspond to what we're actually
		 * reading:
		 */
		op->write.op.pos.offset = bio->bi_iter.bi_sector;
	}

	return op;
}

/* only promote if we're not reading from the fastest tier: */
static bool should_promote(struct bch_fs *c,
			   struct extent_pick_ptr *pick, unsigned flags)
{
	if (!(flags & BCH_READ_MAY_PROMOTE))
		return false;

	if (percpu_ref_is_dying(&c->writes))
		return false;

	return c->fastest_tier &&
		c->fastest_tier < c->tiers + pick->ca->mi.tier;
}

/* Read */

#define READ_RETRY_AVOID	1
#define READ_RETRY		2
#define READ_ERR		3

enum rbio_context {
	RBIO_CONTEXT_NULL,
	RBIO_CONTEXT_HIGHPRI,
	RBIO_CONTEXT_UNBOUND,
	RBIO_CONTEXT_FS,
};

static inline struct bch_read_bio *
bch2_rbio_parent(struct bch_read_bio *rbio)
{
	return rbio->split ? rbio->parent : rbio;
}

__always_inline
static void bch2_rbio_punt(struct bch_read_bio *rbio, work_func_t fn,
			   enum rbio_context context,
			   struct workqueue_struct *wq)
{
	if (context <= rbio->context) {
		fn(&rbio->work);
	} else {
		rbio->work.func		= fn;
		rbio->context		= context;
		queue_work(wq, &rbio->work);
	}
}

static inline struct bch_read_bio *bch2_rbio_free(struct bch_read_bio *rbio)
{
	struct bch_read_bio *parent = rbio->parent;

	BUG_ON(!rbio->split);

	if (rbio->promote)
		kfree(rbio->promote);
	if (rbio->bounce)
		bch2_bio_free_pages_pool(rbio->c, &rbio->bio);
	bio_put(&rbio->bio);

	return parent;
}

static void bch2_rbio_done(struct bch_read_bio *rbio)
{
	if (rbio->promote)
		kfree(rbio->promote);
	rbio->promote = NULL;

	if (rbio->split)
		rbio = bch2_rbio_free(rbio);
	bio_endio(&rbio->bio);
}

static void bch2_rbio_retry(struct work_struct *work)
{
	struct bch_read_bio *rbio =
		container_of(work, struct bch_read_bio, work);
	struct bch_fs *c		= rbio->c;
	struct bvec_iter iter		= rbio->bvec_iter;
	unsigned flags			= rbio->flags;
	u64 inode			= rbio->pos.inode;
	struct bch_devs_mask avoid;

	trace_read_retry(&rbio->bio);

	memset(&avoid, 0, sizeof(avoid));

	if (rbio->retry == READ_RETRY_AVOID)
		__set_bit(rbio->pick.ca->dev_idx, avoid.d);

	if (rbio->split)
		rbio = bch2_rbio_free(rbio);
	else
		rbio->bio.bi_status = 0;

	flags |= BCH_READ_MUST_CLONE;
	flags |= BCH_READ_IN_RETRY;
	flags &= ~BCH_READ_MAY_PROMOTE;

	__bch2_read(c, rbio, iter, inode, &avoid, flags);
}

static void bch2_rbio_error(struct bch_read_bio *rbio, int retry, int error)
{
	rbio->retry = retry;

	if (rbio->flags & BCH_READ_IN_RETRY)
		return;

	if (retry == READ_ERR) {
		bch2_rbio_parent(rbio)->bio.bi_status = error;
		bch2_rbio_done(rbio);
	} else {
		bch2_rbio_punt(rbio, bch2_rbio_retry,
			       RBIO_CONTEXT_FS, rbio->c->wq);
	}
}

static void bch2_rbio_narrow_crcs(struct bch_read_bio *rbio)
{
	struct bch_fs *c = rbio->c;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_extent e;
	BKEY_PADDED(k) new;
	struct bch_csum csum;
	struct nonce nonce; /* encrypted csums can't be narrowed */
	struct bvec_iter saved_iter = rbio->bio.bi_iter;
	int ret;

	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, rbio->pos,
			     BTREE_ITER_INTENT);
retry:
	k = bch2_btree_iter_peek(&iter);
	if (IS_ERR_OR_NULL(k.k))
		goto out;

	if (!bkey_extent_is_data(k.k))
		goto out;

	bkey_reassemble(&new.k, k);
	e = bkey_i_to_s_extent(&new.k);

	if (!bch2_extent_matches_ptr(c, e,
				     rbio->pick.ptr,
				     rbio->pos.offset -
				     rbio->pick.crc.offset))
		goto out;

	/*
	 * The data we read in is for rbio->pos.offset - rbio->pick.crc.offset,
	 * but the data currently starts at bkey_start_offset(e.k):
	 */
	rbio->bio.bi_iter = saved_iter;
	bio_advance(&rbio->bio,
		    (bkey_start_offset(e.k) -
		     (rbio->pos.offset - rbio->pick.crc.offset)) << 9);

	BUG_ON(rbio->bio.bi_iter.bi_size < e.k->size << 9);
	rbio->bio.bi_iter.bi_size = e.k->size << 9;

	csum = bch2_checksum_bio(c, rbio->pick.crc.csum_type,
				 nonce, &rbio->bio);

	if (!bch2_extent_narrow_crcs(e, rbio->pick.crc.csum_type, csum))
		goto out;

	ret = bch2_btree_insert_at(c, NULL, NULL, NULL,
				   BTREE_INSERT_ATOMIC|
				   BTREE_INSERT_NOFAIL,
				   BTREE_INSERT_ENTRY(&iter, &new.k));
	if (ret == -EINTR)
		goto retry;
out:
	bch2_btree_iter_unlock(&iter);
	rbio->bio.bi_iter = saved_iter;
}

static bool should_narrow_crcs(struct bkey_s_c_extent e,
			       struct extent_pick_ptr *pick,
			       unsigned flags)
{
	struct bch_extent_crc_unpacked crc;
	const union bch_extent_entry *i;

	if (!pick->crc.csum_type)
		return false;

	if (bch2_csum_type_is_encryption(pick->crc.csum_type))
		return false;

	if (flags & BCH_READ_IN_RETRY)
		return false;

	extent_for_each_crc(e, crc, i)
		if (!crc.compression_type &&
		    crc.csum_type &&
		    e.k->size != crc.uncompressed_size)
			return true;

	return false;
}

/* Inner part that may run in process context */
static void __bch2_read_endio(struct work_struct *work)
{
	struct bch_read_bio *rbio =
		container_of(work, struct bch_read_bio, work);
	struct bch_fs *c = rbio->c;
	struct bio *src = &rbio->bio;
	struct bio *dst = &bch2_rbio_parent(rbio)->bio;
	struct bvec_iter dst_iter = rbio->bvec_iter;
	struct nonce nonce = extent_nonce(rbio->version,
				rbio->pick.crc.nonce,
				rbio->pick.crc.uncompressed_size,
				rbio->pick.crc.compression_type);
	unsigned csum_type = rbio->pick.crc.csum_type;
	struct bch_csum csum;
	int ret = 0;

	/* Reset iterator for checksumming and copying bounced data: */
	if (rbio->bounce) {
		rbio->bio.bi_iter.bi_size	= rbio->read_full
			? rbio->pick.crc.compressed_size << 9
			: rbio->bvec_iter.bi_size;
		rbio->bio.bi_iter.bi_idx	= 0;
		rbio->bio.bi_iter.bi_bvec_done	= 0;
	} else {
		rbio->bio.bi_iter		= rbio->bvec_iter;
	}

	csum = bch2_checksum_bio(c, csum_type, nonce, src);
	if (bch2_dev_io_err_on(bch2_crc_cmp(rbio->pick.crc.csum, csum),
			       rbio->pick.ca,
			"data checksum error, inode %llu offset %llu: expected %0llx%0llx got %0llx%0llx (type %u)",
			rbio->pos.inode, (u64) rbio->bvec_iter.bi_sector,
			rbio->pick.crc.csum.hi, rbio->pick.crc.csum.lo,
			csum.hi, csum.lo, csum_type))
		ret = -EIO;

	if (unlikely(rbio->narrow_crcs) && !ret)
		bch2_rbio_narrow_crcs(rbio);

	/*
	 * If we read in all live data, adjust crc.offset to point to the start
	 * of the data we actually want - do this after calling
	 * bch2_rbio_narrow_crcs();
	 */
	if (rbio->read_full)
		rbio->pick.crc.offset +=
			rbio->bvec_iter.bi_sector - rbio->pos.offset;

	/*
	 * If there was a checksum error, still copy the data back - unless it
	 * was compressed, we don't want to decompress bad data:
	 */
	if (rbio->pick.crc.compression_type != BCH_COMPRESSION_NONE) {
		if (!ret) {
			bch2_encrypt_bio(c, csum_type, nonce, src);
			ret = bch2_bio_uncompress(c, src, dst,
						  dst_iter, rbio->pick.crc);
			if (ret)
				__bcache_io_error(c, "decompression error");
		}
	} else {
		bio_advance(src, rbio->pick.crc.offset << 9);

		/* don't need to decrypt the entire bio: */
		BUG_ON(src->bi_iter.bi_size < dst_iter.bi_size);
		src->bi_iter.bi_size = dst_iter.bi_size;

		nonce = nonce_add(nonce, rbio->pick.crc.offset << 9);

		bch2_encrypt_bio(c, csum_type, nonce, src);

		if (rbio->bounce)
			bio_copy_data_iter(dst, &dst_iter, src, &src->bi_iter);
	}

	if (ret) {
		/*
		 * Checksum error: if the bio wasn't bounced, we may have been
		 * reading into buffers owned by userspace (that userspace can
		 * scribble over) - retry the read, bouncing it this time:
		 */
		if (!rbio->bounce && (rbio->flags & BCH_READ_USER_MAPPED)) {
			rbio->flags |= BCH_READ_MUST_BOUNCE;
			bch2_rbio_error(rbio, READ_RETRY, ret);
		} else {
			bch2_rbio_error(rbio, READ_RETRY_AVOID, ret);
		}
		return;
	}

	if (unlikely(rbio->flags & BCH_READ_IN_RETRY))
		return;

	if (rbio->promote)
		promote_start(rbio->promote, rbio);

	bch2_rbio_done(rbio);
}

static void bch2_read_endio(struct bio *bio)
{
	struct bch_read_bio *rbio =
		container_of(bio, struct bch_read_bio, bio);
	struct bch_fs *c = rbio->c;
	struct workqueue_struct *wq = NULL;
	enum rbio_context context = RBIO_CONTEXT_NULL;

	bch2_latency_acct(rbio->pick.ca, rbio->submit_time_us, READ);

	percpu_ref_put(&rbio->pick.ca->io_ref);

	if (!rbio->split)
		rbio->bio.bi_end_io = rbio->end_io;

	if (bch2_dev_io_err_on(bio->bi_status, rbio->pick.ca, "data read")) {
		bch2_rbio_error(rbio, READ_RETRY_AVOID, bio->bi_status);
		return;
	}

	if (rbio->pick.ptr.cached &&
	    (((rbio->flags & BCH_READ_RETRY_IF_STALE) && race_fault()) ||
	     ptr_stale(rbio->pick.ca, &rbio->pick.ptr))) {
		atomic_long_inc(&c->read_realloc_races);

		if (rbio->flags & BCH_READ_RETRY_IF_STALE)
			bch2_rbio_error(rbio, READ_RETRY, BLK_STS_AGAIN);
		else
			bch2_rbio_error(rbio, READ_ERR, BLK_STS_AGAIN);
		return;
	}

	if (rbio->narrow_crcs)
		context = RBIO_CONTEXT_FS,	wq = c->wq;
	else if (rbio->pick.crc.compression_type ||
		 bch2_csum_type_is_encryption(rbio->pick.crc.csum_type))
		context = RBIO_CONTEXT_UNBOUND,	wq = system_unbound_wq;
	else if (rbio->pick.crc.csum_type)
		context = RBIO_CONTEXT_HIGHPRI,	wq = system_highpri_wq;

	bch2_rbio_punt(rbio, __bch2_read_endio, context, wq);
}

int __bch2_read_extent(struct bch_fs *c, struct bch_read_bio *orig,
		       struct bvec_iter iter, struct bkey_s_c k,
		       struct extent_pick_ptr *pick, unsigned flags)
{
	struct bch_read_bio *rbio;
	bool bounce = false, split, read_full = false, narrow_crcs, promote;
	int ret = 0;

	bch2_increment_clock(c, bio_sectors(&orig->bio), READ);
	PTR_BUCKET(pick->ca, &pick->ptr)->prio[READ] = c->prio_clock[READ].hand;

	EBUG_ON(bkey_start_offset(k.k) > iter.bi_sector ||
		k.k->p.offset < bvec_iter_end_sector(iter));

	narrow_crcs = should_narrow_crcs(bkey_s_c_to_extent(k), pick, flags);
	if (narrow_crcs)
		flags |= BCH_READ_MUST_BOUNCE;

	if (pick->crc.compression_type != BCH_COMPRESSION_NONE ||
	    (pick->crc.csum_type != BCH_CSUM_NONE &&
	     (bvec_iter_sectors(iter) != pick->crc.uncompressed_size ||
	      (bch2_csum_type_is_encryption(pick->crc.csum_type) &&
	       (flags & BCH_READ_USER_MAPPED)) ||
	      (flags & BCH_READ_MUST_BOUNCE)))) {
		read_full = true;
		bounce = true;
	}

	promote = should_promote(c, pick, flags);
	/* could also set read_full */
	if (promote)
		bounce = true;

	if (bounce) {
		unsigned sectors = read_full
			? pick->crc.compressed_size
			: bvec_iter_sectors(iter);

		rbio = rbio_init(bio_alloc_bioset(GFP_NOIO,
					DIV_ROUND_UP(sectors, PAGE_SECTORS),
					&c->bio_read_split));

		bch2_bio_alloc_pages_pool(c, &rbio->bio, sectors << 9);
		split = true;
	} else if (flags & BCH_READ_MUST_CLONE) {
		/*
		 * Have to clone if there were any splits, due to error
		 * reporting issues (if a split errored, and retrying didn't
		 * work, when it reports the error to its parent (us) we don't
		 * know if the error was from our bio, and we should retry, or
		 * from the whole bio, in which case we don't want to retry and
		 * lose the error)
		 */
		rbio = rbio_init(bio_clone_fast(&orig->bio,
					      GFP_NOIO, &c->bio_read_split));
		rbio->bio.bi_iter = iter;
		split = true;
	} else {
		rbio = orig;
		rbio->bio.bi_iter = iter;
		split = false;
		BUG_ON(bio_flagged(&rbio->bio, BIO_CHAIN));
	}

	BUG_ON((pick->crc.csum_type ||
		pick->crc.compression_type) &&
	       bio_sectors(&rbio->bio) != pick->crc.compressed_size);

	rbio->c			= c;

	if (split)
		rbio->parent	= orig;
	else
		rbio->end_io	= orig->bio.bi_end_io;

	rbio->bvec_iter		= iter;
	rbio->flags		= flags;
	rbio->read_full		= read_full,
	rbio->bounce		= bounce;
	rbio->split		= split;
	rbio->narrow_crcs	= narrow_crcs;
	rbio->context		= 0;
	rbio->retry		= 0;
	rbio->pick		= *pick;
	rbio->version		= k.k->version;
	rbio->pos		= bkey_start_pos(k.k);
	rbio->promote		= promote ? promote_alloc(rbio, k) : NULL;
	INIT_WORK(&rbio->work, NULL);

	bio_set_dev(&rbio->bio, pick->ca->disk_sb.bdev);
	rbio->bio.bi_opf	= orig->bio.bi_opf;
	rbio->bio.bi_iter.bi_sector = pick->ptr.offset;
	rbio->bio.bi_end_io	= bch2_read_endio;

	if (!read_full)
		rbio->bio.bi_iter.bi_sector +=
			rbio->bvec_iter.bi_sector - rbio->pos.offset;

	rbio->submit_time_us = local_clock_us();

	if (bounce)
		trace_read_bounce(&rbio->bio);

	this_cpu_add(pick->ca->io_done->sectors[READ][BCH_DATA_USER],
		     bio_sectors(&rbio->bio));

	if (likely(!(flags & BCH_READ_IN_RETRY))) {
		submit_bio(&rbio->bio);
	} else {
		submit_bio_wait(&rbio->bio);

		rbio->context = RBIO_CONTEXT_FS;
		bch2_read_endio(&rbio->bio);

		ret = rbio->retry;
		if (!ret)
			bch2_rbio_done(rbio);
	}

	return ret;
}

void __bch2_read(struct bch_fs *c, struct bch_read_bio *rbio,
		 struct bvec_iter bvec_iter, u64 inode,
		 struct bch_devs_mask *avoid, unsigned flags)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;
retry:
	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
			   POS(inode, bvec_iter.bi_sector),
			   BTREE_ITER_WITH_HOLES, k) {
		BKEY_PADDED(k) tmp;
		struct extent_pick_ptr pick;
		struct bvec_iter fragment;

		/*
		 * Unlock the iterator while the btree node's lock is still in
		 * cache, before doing the IO:
		 */
		bkey_reassemble(&tmp.k, k);
		k = bkey_i_to_s_c(&tmp.k);
		bch2_btree_iter_unlock(&iter);

		bch2_extent_pick_ptr(c, k, avoid, &pick);
		if (IS_ERR(pick.ca)) {
			bcache_io_error(c, &rbio->bio, "no device to read from");
			bio_endio(&rbio->bio);
			return;
		}

		fragment = bvec_iter;
		fragment.bi_size = (min_t(u64, k.k->p.offset,
					  bvec_iter_end_sector(bvec_iter)) -
				    bvec_iter.bi_sector) << 9;

		if (pick.ca) {
			if (fragment.bi_size != bvec_iter.bi_size) {
				bio_inc_remaining(&rbio->bio);
				flags |= BCH_READ_MUST_CLONE;
				trace_read_split(&rbio->bio);
			}

			ret = __bch2_read_extent(c, rbio, fragment,
						 k, &pick, flags);
			switch (ret) {
			case READ_RETRY_AVOID:
				__set_bit(pick.ca->dev_idx, avoid->d);
			case READ_RETRY:
				goto retry;
			case READ_ERR:
				bio_endio(&rbio->bio);
				return;
			};
		} else {
			zero_fill_bio_iter(&rbio->bio, fragment);

			if (fragment.bi_size == bvec_iter.bi_size)
				bio_endio(&rbio->bio);
		}

		if (fragment.bi_size == bvec_iter.bi_size)
			return;

		bio_advance_iter(&rbio->bio, &bvec_iter, fragment.bi_size);
	}

	/*
	 * If we get here, it better have been because there was an error
	 * reading a btree node
	 */
	ret = bch2_btree_iter_unlock(&iter);
	BUG_ON(!ret);
	bcache_io_error(c, &rbio->bio, "btree IO error %i", ret);
	bio_endio(&rbio->bio);
}
