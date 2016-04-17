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
#include "clock.h"
#include "debug.h"
#include "error.h"
#include "extents.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "notify.h"
#include "stats.h"
#include "super.h"

#include <linux/blkdev.h>
#include <linux/lz4.h>
#include <linux/zlib.h>

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

/* Allocate, free from mempool: */

static void bch_bio_free_pages_pool(struct cache_set *c, struct bio *bio)
{
	struct bio_vec *bv;
	unsigned i;

	bio_for_each_segment_all(bv, bio, i)
		if (bv->bv_page != ZERO_PAGE(0))
			mempool_free(bv->bv_page, &c->bio_bounce_pages);
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

static void bch_bio_alloc_pages_pool(struct cache_set *c, struct bio *bio,
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

static void bch_bbio_prep(struct bbio *b, struct cache *ca)
{
	b->ca				= ca;
	b->bio.bi_iter.bi_sector	= b->ptr.offset;
	b->bio.bi_bdev			= ca ? ca->disk_sb.bdev : NULL;
}

void bch_submit_bbio(struct bbio *b, struct cache *ca,
		     const struct bch_extent_ptr *ptr, bool punt)
{
	struct bio *bio = &b->bio;

	b->ptr = *ptr;
	bch_bbio_prep(b, ca);
	b->submit_time_us = local_clock_us();

	if (!ca) {
		bcache_io_error(ca->set, bio, "device has been removed");
	} else if (punt)
		closure_bio_submit_punt(bio, bio->bi_private, ca->set);
	else
		closure_bio_submit(bio, bio->bi_private);
}

void bch_submit_bbio_replicas(struct bch_write_bio *bio, struct cache_set *c,
			      const struct bkey_i *k, unsigned ptrs_from,
			      bool punt)
{
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
	const struct bch_extent_ptr *ptr;
	struct cache *ca;
	unsigned ptr_idx = 0;

	BUG_ON(bio->orig);

	extent_for_each_ptr(e, ptr) {
		if (ptr_idx++ < ptrs_from)
			continue;

		rcu_read_lock();
		ca = PTR_CACHE(c, ptr);
		if (ca)
			percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		if (!ca) {
			bch_submit_bbio(&bio->bio, ca, ptr, punt);
			break;
		}

		if (ptr + 1 < &extent_entry_last(e)->ptr) {
			struct bch_write_bio *n =
				to_wbio(bio_clone_fast(&bio->bio.bio, GFP_NOIO,
						       &ca->replica_set));

			n->bio.bio.bi_end_io	= bio->bio.bio.bi_end_io;
			n->bio.bio.bi_private	= bio->bio.bio.bi_private;
			n->orig			= &bio->bio.bio;
			__bio_inc_remaining(n->orig);

			bch_submit_bbio(&n->bio, ca, ptr, punt);
		} else {
			bch_submit_bbio(&bio->bio, ca, ptr, punt);
		}
	}
}

/* IO errors */

void bch_bbio_endio(struct bbio *bio)
{
	struct closure *cl = bio->bio.bi_private;
	struct cache *ca = bio->ca;

	bch_account_io_completion_time(ca, bio->submit_time_us,
				       bio_op(&bio->bio));
	bio_put(&bio->bio);
	if (ca)
		percpu_ref_put(&ca->ref);
	closure_put(cl);
}

/* Writes */

static u32 checksum_bio(struct bio *bio, unsigned type)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	u32 csum = U32_MAX;

	if (type == BCH_CSUM_NONE)
		return 0;

	bio_for_each_segment(bv, bio, iter) {
		void *p = kmap_atomic(bv.bv_page);

		csum = bch_checksum_update(type, csum,
					   p + bv.bv_offset,
					   bv.bv_len);
		kunmap_atomic(p);
	}

	return csum ^= U32_MAX;
}

static void memcpy_to_bio(struct bio *dst, struct bvec_iter dst_iter,
			  void *src)
{
	struct bio_vec bv;
	struct bvec_iter iter;

	__bio_for_each_segment(bv, dst, iter, dst_iter) {
		void *dstp = kmap_atomic(bv.bv_page);
		memcpy(dstp + bv.bv_offset, src, bv.bv_len);
		kunmap_atomic(dstp);

		src += bv.bv_len;
	}
}

static void memcpy_from_bio(void *dst, struct bio *src,
			    struct bvec_iter src_iter)
{
	struct bio_vec bv;
	struct bvec_iter iter;

	__bio_for_each_segment(bv, src, iter, src_iter) {
		void *srcp = kmap_atomic(bv.bv_page);
		memcpy(dst, srcp + bv.bv_offset, bv.bv_len);
		kunmap_atomic(srcp);

		dst += bv.bv_len;
	}
}

static void *__bio_map_or_bounce(struct bio *bio, struct bvec_iter start,
				 unsigned *bounced, bool may_bounce)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	unsigned nr_pages = 0;
	struct page *stack_pages[4];
	struct page **pages = NULL;
	bool first = true;
	unsigned prev_end = PAGE_SIZE;
	void *data;

	*bounced = 0;

	__bio_for_each_segment(bv, bio, iter, start) {
		if ((!first && bv.bv_offset) ||
		    prev_end != PAGE_SIZE)
			goto bounce;

		prev_end = bv.bv_offset + bv.bv_len;
		nr_pages++;
	}

	BUG_ON(DIV_ROUND_UP(start.bi_size, PAGE_SIZE) > nr_pages);

	pages = nr_pages > ARRAY_SIZE(stack_pages)
		? kmalloc_array(nr_pages, sizeof(struct page *), GFP_NOIO)
		: stack_pages;
	if (!pages)
		return NULL;

	nr_pages = 0;
	__bio_for_each_segment(bv, bio, iter, start)
		pages[nr_pages++] = bv.bv_page;

	data = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (pages != stack_pages)
		kfree(pages);

	return data + bio_iter_offset(bio, start);
bounce:
	if (!may_bounce)
		return NULL;

	data = kmalloc(start.bi_size, GFP_NOIO);
	if (!data)
		return NULL;

	*bounced = 1;
	memcpy_from_bio(data, bio, start);

	return data;
}

static void *bio_map_or_bounce(struct bio *bio, unsigned *bounced, bool may_bounce)
{
	return __bio_map_or_bounce(bio, bio->bi_iter, bounced, may_bounce);
}

static void bio_unmap_or_unbounce(void *data, unsigned bounced)
{
	if (!data)
		return;
	else if (bounced)
		kfree(data);
	else
		vunmap((void *) ((unsigned long) data & PAGE_MASK));
}

static struct bio *bio_compress_lz4(struct cache_set *c,
				    struct bio *src,
				    unsigned output_available,
				    int *input_consumed)
{
	struct bio *dst;
	void *src_data = NULL, *dst_data = NULL;
	unsigned src_bounced, dst_bounced;
	struct page *workmem = NULL;
	size_t compressed_size;
	int ret = -1;

	/*
	 * XXX: due to the way the interface to lzo1x_1_compress works, we can't
	 * consume more than output_available bytes of input (even though a lot
	 * more might fit after compressing)
	 */
	dst = bio_alloc_bioset(GFP_NOIO,
		DIV_ROUND_UP(lz4_compressbound(output_available), PAGE_SIZE),
		&c->bio_write);

	bch_bio_alloc_pages_pool(c, dst, lz4_compressbound(output_available));

	src_data = bio_map_or_bounce(src, &src_bounced, true);
	if (!src_data)
		goto err;

	dst_data = bio_map_or_bounce(dst, &dst_bounced, false);
	if (!src_data)
		goto err;

	workmem = mempool_alloc(&c->compression_workspace_pool, GFP_NOIO);

	ret = lz4_compress(src_data, output_available,
			   dst_data, &compressed_size,
			   page_address(workmem));
	if (ret)
		goto err;

	BUG_ON(!compressed_size);

	dst->bi_iter.bi_size = compressed_size;
	*input_consumed = output_available;
out:
	mempool_free(workmem, &c->compression_workspace_pool);
	bio_unmap_or_unbounce(dst_data, dst_bounced);
	bio_unmap_or_unbounce(src_data, src_bounced);

	if (!ret)
		while (dst->bi_vcnt * PAGE_SIZE >
		       round_up(dst->bi_iter.bi_size, PAGE_SIZE))
			mempool_free(dst->bi_io_vec[--dst->bi_vcnt].bv_page,
				     &c->bio_bounce_pages);

	return dst;
err:
	ret = -1;
	*input_consumed = -1;
	goto out;
}

static int bio_compress_gzip(struct cache_set *c, struct bio *dst,
			     struct bio *src, unsigned output_available)
{
	struct bvec_iter src_iter = src->bi_iter;
	z_stream strm;
	struct page *workspace;
	struct page *inp = NULL;
	void *k_in = NULL;
	bool using_mempool = false;
	int ret;

	workspace = mempool_alloc(&c->compression_workspace_pool, GFP_NOIO);
	strm.workspace = page_address(workspace);

	zlib_deflateInit(&strm, 3);
	strm.next_in	= NULL;
	strm.next_out	= NULL;
	strm.avail_out	= 0;
	strm.avail_in	= 0;

	while (1) {
		if (!strm.avail_out) {
			struct bio_vec *bv = &dst->bi_io_vec[dst->bi_vcnt];

			if (!output_available) {
				/*
				 * XXX: this really shouldn't happen, accounting
				 * is screwed up somehow:
				 */
				//pr_err("output_available == 0");
				goto err;
			}

			BUG_ON(dst->bi_vcnt >= dst->bi_max_vecs);

			if (k_in) {
				kunmap_atomic(k_in);

				bch_bio_alloc_page_pool(c, dst, &using_mempool);

				strm.next_in = kmap_atomic(inp) +
					(((unsigned long) strm.next_in) &
					 (PAGE_SIZE - 1));
			} else {
				bch_bio_alloc_page_pool(c, dst, &using_mempool);
			}

			strm.next_out = page_address(bv->bv_page);
			strm.avail_out = min_t(unsigned, PAGE_SIZE,
					       output_available);

			dst->bi_iter.bi_size	+= strm.avail_out;
			output_available	-= strm.avail_out;
		}

		if (!strm.avail_in && src_iter.bi_size &&
		    output_available > PAGE_SIZE * 3 / 2) {
			struct bio_vec bv = bio_iter_iovec(src, src_iter);

			if (k_in)
				kunmap_atomic(k_in);

			strm.avail_in = bv.bv_len;
			inp = bv.bv_page;
			k_in = kmap_atomic(inp);
			strm.next_in = k_in + bv.bv_offset;

			bio_advance_iter(src, &src_iter, strm.avail_in);
		}

		ret = zlib_deflate(&strm, strm.avail_in
				   ? Z_NO_FLUSH : Z_FINISH);
		if (ret == Z_STREAM_END)
			break;

		BUG_ON(ret != Z_OK);
	}

	ret = zlib_deflateEnd(&strm);
	BUG_ON(ret != Z_OK);

	BUG_ON(strm.total_out > dst->bi_iter.bi_size);

	/* caller will pad with 0s to block boundary */
	dst->bi_iter.bi_size = strm.total_out;

	/* return number of bytes consumed */
	ret = src->bi_iter.bi_size - src_iter.bi_size;
out:
	if (k_in)
		kunmap_atomic(k_in);
	if (using_mempool)
		mutex_unlock(&c->bio_bounce_pages_lock);
	mempool_free(workspace, &c->compression_workspace_pool);

	return ret;
err:
	ret = -1;
	goto out;
}

static struct bio *bio_compress(struct cache_set *c, struct bio *src,
				unsigned *compression_type,
				unsigned output_available)
{
	struct bio *dst = NULL;
	int input_consumed;

	/* if it's only one block, don't bother trying to compress: */
	if (bio_sectors(src) <= c->sb.block_size)
		*compression_type = BCH_COMPRESSION_NONE;

	switch (*compression_type) {
	case BCH_COMPRESSION_NONE:
		/* Just bounce it, for stable checksums: */
copy:
		if (!dst)
			dst = bio_alloc_bioset(GFP_NOIO,
				DIV_ROUND_UP(output_available, PAGE_SIZE),
				&c->bio_write);
		bch_bio_alloc_pages_pool(c, dst, output_available);
		bio_copy_data(dst, src);
		input_consumed = output_available;
		goto advance;
	case BCH_COMPRESSION_LZ4:
		dst = bio_compress_lz4(c, src, output_available, &input_consumed);
		break;
	case BCH_COMPRESSION_GZIP:
		dst = bio_alloc_bioset(GFP_NOIO,
			DIV_ROUND_UP(output_available, PAGE_SIZE),
			&c->bio_write);
		input_consumed = bio_compress_gzip(c, dst, src, output_available);
		break;
	default:
		BUG();
	}

	if ((int) round_up(dst->bi_iter.bi_size,
			   block_bytes(c)) >= input_consumed) {
		/* Failed to compress (didn't get smaller): */
		*compression_type = BCH_COMPRESSION_NONE;
		goto copy;
	}

	/* Pad to blocksize, and zero out padding: */
	while (dst->bi_iter.bi_size & (block_bytes(c) - 1)) {
		unsigned idx = dst->bi_iter.bi_size >> PAGE_SHIFT;
		unsigned offset = dst->bi_iter.bi_size & (PAGE_SIZE - 1);
		unsigned bytes = (PAGE_SIZE - offset) & (block_bytes(c) - 1);

		if (idx < dst->bi_vcnt) {
			struct bio_vec *bv = &dst->bi_io_vec[idx];

			memset(page_address(bv->bv_page) + offset, 0, bytes);
		} else {
			dst->bi_io_vec[dst->bi_vcnt++] = (struct bio_vec) {
				.bv_page	= ZERO_PAGE(0),
				.bv_len		= PAGE_SIZE,
				.bv_offset	= 0,
			};
		}

		dst->bi_iter.bi_size += bytes;
	}
advance:
	bio_advance(src, input_consumed);

	return dst;
}

static void __bch_write(struct closure *);

static void bch_write_done(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);

	BUG_ON(!(op->flags & BCH_WRITE_DONE));

	if (!op->error && (op->flags & BCH_WRITE_FLUSH))
		op->error = bch_journal_error(&op->c->journal);

	bch_disk_reservation_put(op->c, &op->res);
	percpu_ref_put(&op->c->writes);
	bch_keylist_free(&op->insert_keys);
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
				       op->insert_hook,
				       op_journal_seq(op),
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
	struct keylist *keys = &op->insert_keys;
	unsigned i;

	op->flags |= BCH_WRITE_LOOPED;

	if (!bch_keylist_empty(keys)) {
		u64 sectors_start = keylist_sectors(keys);
		int ret = op->index_update_fn(op);

		BUG_ON(keylist_sectors(keys) && !ret);

		op->written += sectors_start - keylist_sectors(keys);

		if (ret) {
			__bcache_io_error(op->c, "btree IO error");
			op->error = ret;
		}
	}

	for (i = 0; i < ARRAY_SIZE(op->open_buckets); i++)
		if (op->open_buckets[i]) {
			bch_open_bucket_put(op->c, op->open_buckets[i]);
			op->open_buckets[i] = NULL;
		}

	if (!(op->flags & BCH_WRITE_DONE))
		continue_at(cl, __bch_write, op->io_wq);

	if (!op->error && (op->flags & BCH_WRITE_FLUSH)) {
		bch_journal_flush_seq_async(&op->c->journal,
					    *op_journal_seq(op),
					    cl);
		continue_at(cl, bch_write_done, op->c->wq);
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
	struct bio *bio = &op->bio->bio.bio;
	u64 inode = op->insert_key.k.p.inode;

	op->error = bch_discard(op->c,
				POS(inode, bio->bi_iter.bi_sector),
				POS(inode, bio_end_sector(bio)),
				op->insert_key.k.version,
				NULL, NULL);
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
			memmove(dst, src, bkey_bytes(&src->k));

			dst = bkey_next(dst);
			src = n;
		}

		op->insert_keys.top = dst;
		op->flags |= BCH_WRITE_DISCARD;
	} else {
		/* TODO: We could try to recover from this. */
		while (!bch_keylist_empty(&op->insert_keys))
			bch_keylist_dequeue(&op->insert_keys);

		op->error = -EIO;
		op->flags |= BCH_WRITE_DONE;
	}

	bch_write_index(cl);
}

static void bch_write_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bch_write_bio *wbio = to_wbio(bio);
	struct cache *ca = wbio->bio.ca;

	if (cache_nonfatal_io_err_on(bio->bi_error, ca,
				     "data write"))
		set_closure_fn(cl, bch_write_io_error, op->c->wq);

	if (wbio->orig)
		bio_endio(wbio->orig);
	else if (wbio->bounce)
		bch_bio_free_pages_pool(op->c, bio);

	bch_account_io_completion_time(ca,
				       wbio->bio.submit_time_us,
				       REQ_OP_WRITE);
	if (wbio->split)
		bio_put(&wbio->bio.bio);
	if (ca)
		percpu_ref_put(&ca->ref);
	closure_put(cl);
}

static const unsigned bch_crc_size[] = {
	[BCH_CSUM_NONE]		= 0,
	[BCH_CSUM_CRC32C]	= 4,
	[BCH_CSUM_CRC64]	= 8,
};

/*
 * We're writing another replica for this extent, so while we've got the data in
 * memory we'll be computing a new checksum for the currently live data.
 *
 * If there are other replicas we aren't moving, and they are checksummed but
 * not compressed, we can modify them to point to only the data that is
 * currently live (so that readers won't have to bounce) while we've got the
 * checksum we need:
 *
 * XXX: to guard against data being corrupted while in memory, instead of
 * recomputing the checksum here, it would be better in the read path to instead
 * of computing the checksum of the entire extent:
 *
 * | extent                              |
 *
 * compute the checksums of the live and dead data separately
 * | dead data || live data || dead data |
 *
 * and then verify that crc_dead1 + crc_live + crc_dead2 == orig_crc, and then
 * use crc_live here (that we verified was correct earlier)
 */
static void extent_cleanup_checksums(struct bkey_s_extent e,
				     u64 csum, unsigned csum_type)
{
	union bch_extent_entry *entry;

	extent_for_each_entry(e, entry)
		switch (extent_entry_type(entry)) {
		case BCH_EXTENT_ENTRY_ptr:
			continue;
		case BCH_EXTENT_ENTRY_crc32:
			if (entry->crc32.compression_type != BCH_COMPRESSION_NONE ||
			    bch_crc_size[csum_type] > sizeof(entry->crc32.csum))
				continue;

			extent_adjust_pointers(e, entry);
			entry->crc32.compressed_size	= e.k->size;
			entry->crc32.uncompressed_size	= e.k->size;
			entry->crc32.offset		= 0;
			entry->crc32.csum_type		= csum_type;
			entry->crc32.csum		= csum;
			break;
		case BCH_EXTENT_ENTRY_crc64:
			if (entry->crc64.compression_type != BCH_COMPRESSION_NONE ||
			    bch_crc_size[csum_type] > sizeof(entry->crc64.csum))
				continue;

			extent_adjust_pointers(e, entry);
			entry->crc64.compressed_size	= e.k->size;
			entry->crc64.uncompressed_size	= e.k->size;
			entry->crc64.offset		= 0;
			entry->crc64.csum_type		= csum_type;
			entry->crc64.csum		= csum;
			break;
		}
}

static void extent_checksum_append(struct bkey_i_extent *e,
				   unsigned compressed_size,
				   unsigned uncompressed_size,
				   unsigned compression_type,
				   u64 csum, unsigned csum_type)
{
	struct bch_extent_ptr *ptr;
	union bch_extent_crc *crc;

	BUG_ON(compressed_size > uncompressed_size);
	BUG_ON(uncompressed_size != e->k.size);

	/*
	 * Look up the last crc entry, so we can check if we need to add
	 * another:
	 */
	extent_for_each_ptr_crc(extent_i_to_s(e), ptr, crc)
		;

	switch (bch_extent_crc_type(crc)) {
	case BCH_EXTENT_CRC_NONE:
		if (csum_type == BCH_CSUM_NONE &&
		    compression_type == BCH_COMPRESSION_NONE)
			return;
		break;
	case BCH_EXTENT_CRC32:
		if (crc->crc32.compressed_size	== compressed_size &&
		    crc->crc32.uncompressed_size == uncompressed_size &&
		    crc->crc32.offset		== 0 &&
		    crc->crc32.compression_type	== compression_type &&
		    crc->crc32.csum_type	== csum_type &&
		    crc->crc32.csum		== csum)
			return;
		break;
	case BCH_EXTENT_CRC64:
		if (crc->crc64.compressed_size	== compressed_size &&
		    crc->crc64.uncompressed_size == uncompressed_size &&
		    crc->crc64.offset		== 0 &&
		    crc->crc32.compression_type	== compression_type &&
		    crc->crc64.csum_type	== csum_type &&
		    crc->crc64.csum		== csum)
			return;
		break;
	}

	switch (csum_type) {
	case BCH_CSUM_NONE:
	case BCH_CSUM_CRC32C:
		BUG_ON(compressed_size > CRC32_EXTENT_SIZE_MAX ||
		       uncompressed_size > CRC32_EXTENT_SIZE_MAX);

		extent_crc32_append(e, (struct bch_extent_crc32) {
			.compressed_size	= compressed_size,
			.uncompressed_size	= uncompressed_size,
			.offset			= 0,
			.compression_type	= compression_type,
			.csum_type		= csum_type,
			.csum			= csum,
		});
		break;
	case BCH_CSUM_CRC64:
		BUG_ON(compressed_size > CRC64_EXTENT_SIZE_MAX ||
		       uncompressed_size > CRC64_EXTENT_SIZE_MAX);

		extent_crc64_append(e, (struct bch_extent_crc64) {
			.compressed_size	= compressed_size,
			.uncompressed_size	= uncompressed_size,
			.offset			= 0,
			.compression_type	= compression_type,
			.csum_type		= csum_type,
			.csum			= csum,
		});
		break;
	default:
		BUG();
	}
}

static void bch_write_extent(struct bch_write_op *op,
			     struct open_bucket *ob,
			     struct bkey_i *k, struct bio *orig)
{
	struct cache_set *c = op->c;
	struct bio *bio;
	struct bch_write_bio *wbio;
	struct bkey_i_extent *e = bkey_i_to_extent(k);
	struct bch_extent_ptr *ptr;
	unsigned ptrs_from = 0;
	unsigned csum_type = c->opts.data_checksum;
	unsigned compression_type = op->compression_type;

	/* don't refetch csum type/compression type */
	barrier();

	extent_for_each_ptr(extent_i_to_s(e), ptr)
		ptrs_from++;

	if (csum_type != BCH_CSUM_NONE ||
	    compression_type != BCH_COMPRESSION_NONE) {
		/* all units here in bytes */
		unsigned output_available, extra_input,
			 orig_input = orig->bi_iter.bi_size;
		u64 csum;

		BUG_ON(bio_sectors(orig) != k->k.size);

		/* XXX: decide extent size better: */
		output_available = min(k->k.size,
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

		bio = bio_compress(c, orig,
				   &compression_type,
				   output_available);
		/* copy WRITE_SYNC flag */
		bio->bi_opf		= orig->bi_opf;

		orig->bi_iter.bi_size += extra_input;

		bio->bi_end_io		= bch_write_endio;
		wbio			= to_wbio(bio);
		wbio->orig		= NULL;
		wbio->bounce		= true;
		wbio->split		= true;

		/*
		 * Set the (uncompressed) size of the key we're creating to the
		 * number of sectors we consumed from orig:
		 */
		bch_key_resize(&k->k, (orig_input - orig->bi_iter.bi_size) >> 9);

		/*
		 * XXX: could move checksumming out from under the open
		 * bucket lock - but compression is also being done
		 * under it
		 */
		csum = checksum_bio(bio, csum_type);

		/*
		 * If possible, adjust existing pointers to only point to
		 * currently live data, while we have the checksum for that
		 * data:
		 */
		extent_cleanup_checksums(extent_i_to_s(e), csum, csum_type);

		/*
		 * Add a bch_extent_crc header for the pointers that
		 * bch_alloc_sectors_done() is going to append:
		 */
		extent_checksum_append(e, bio_sectors(bio), e->k.size,
				       compression_type,
				       csum, csum_type);

		bch_alloc_sectors_done(op->c, op->wp,
				       e, op->nr_replicas,
				       ob, bio_sectors(bio));
	} else {
		if (k->k.size > ob->sectors_free)
			bch_key_resize(&k->k, ob->sectors_free);

		/*
		 * We might need a checksum entry, if there's a previous
		 * checksum entry we need to override:
		 */
		extent_checksum_append(e, k->k.size, k->k.size,
				       compression_type, 0, csum_type);

		bch_alloc_sectors_done(op->c, op->wp,
				       e, op->nr_replicas,
				       ob, k->k.size);

		bio = bio_next_split(orig, k->k.size, GFP_NOIO,
				     &op->c->bio_write);

		wbio			= to_wbio(bio);
		wbio->orig		= NULL;
		wbio->bounce		= false;
		wbio->split		= bio != orig;
	}

	bio->bi_end_io	= bch_write_endio;
	bio->bi_private	= &op->cl;
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	bch_submit_bbio_replicas(wbio, op->c, k, ptrs_from, false);
}

static void __bch_write(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bio *bio = &op->bio->bio.bio;
	unsigned open_bucket_nr = 0;
	struct open_bucket *b;

	memset(op->open_buckets, 0, sizeof(op->open_buckets));

	if (op->flags & BCH_WRITE_DISCARD) {
		op->flags |= BCH_WRITE_DONE;
		bch_write_discard(cl);
		bio_put(bio);
		continue_at(cl, bch_write_done, op->c->wq);
	}

	if (bkey_extent_is_data(&op->insert_key.k))
		bch_extent_drop_stale(op->c,
				      bkey_i_to_s_extent(&op->insert_key));

	/*
	 * Journal writes are marked REQ_PREFLUSH; if the original write was a
	 * flush, it'll wait on the journal write.
	 */
	bio->bi_opf &= ~(REQ_PREFLUSH|REQ_FUA);

	do {
		struct bkey_i *k;

		EBUG_ON(bio_sectors(bio)	!= op->insert_key.k.size);
		EBUG_ON(bio_end_sector(bio)	!= op->insert_key.k.p.offset);

		if (open_bucket_nr == ARRAY_SIZE(op->open_buckets))
			continue_at(cl, bch_write_index, op->c->wq);

		/* for the device pointers and 1 for the chksum */
		if (bch_keylist_realloc(&op->insert_keys,
					BKEY_EXTENT_U64s_MAX))
			continue_at(cl, bch_write_index, op->c->wq);

		k = op->insert_keys.top;
		bkey_copy(k, &op->insert_key);

		b = bch_alloc_sectors_start(op->c, op->wp,
			bkey_i_to_extent(k), op->nr_replicas,
			(op->flags & BCH_WRITE_ALLOC_NOWAIT) ? NULL : cl);
		EBUG_ON(!b);

		if (unlikely(IS_ERR(b))) {
			if (unlikely(PTR_ERR(b) != -EAGAIN))
				goto err;

			/*
			 * If we already have some keys, must insert them first
			 * before allocating another open bucket. We only hit
			 * this case if open_bucket_nr > 1.
			 */
			if (!bch_keylist_empty(&op->insert_keys))
				continue_at(cl, bch_write_index, op->c->wq);

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

		op->open_buckets[open_bucket_nr++] = b;

		bch_write_extent(op, b, k, bio);
		bch_cut_front(k->k.p, &op->insert_key);

		EBUG_ON(op->insert_key.k.size &&
			op->insert_key.k.size != bio_sectors(bio));

		bch_extent_normalize(op->c, bkey_i_to_s(k));

		bkey_extent_set_cached(&k->k, (op->flags & BCH_WRITE_CACHED));

		if (!(op->flags & BCH_WRITE_CACHED))
			bch_check_mark_super(op->c, k, false);

		bch_keylist_enqueue(&op->insert_keys);

		trace_bcache_cache_insert(&k->k);
	} while (op->insert_key.k.size);

	op->flags |= BCH_WRITE_DONE;
	continue_at(cl, bch_write_index, op->c->wq);
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
		op->error = -EROFS;
	}

	op->flags |= BCH_WRITE_DONE;

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
	struct bio *bio = &op->bio->bio.bio;
	struct cache_set *c = op->c;
	u64 inode = op->insert_key.k.p.inode;

	trace_bcache_write(c, inode, bio,
			   !bkey_extent_is_cached(&op->insert_key.k),
			   op->flags & BCH_WRITE_DISCARD);

	if (!bio_sectors(bio)) {
		WARN_ONCE(1, "bch_write() called with empty bio");
		bch_disk_reservation_put(op->c, &op->res);
		closure_return(cl);
	}

	if (!percpu_ref_tryget(&c->writes)) {
		__bcache_io_error(c, "read only");
		op->error = -EROFS;
		bch_disk_reservation_put(op->c, &op->res);
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

	if (!(op->flags & BCH_WRITE_DISCARD))
		bch_increment_clock(c, bio_sectors(bio), WRITE);

	if (!(op->flags & BCH_WRITE_DISCARD))
		bch_mark_foreground_write(c, bio_sectors(bio));
	else
		bch_mark_discard(c, bio_sectors(bio));

	op->insert_key.k.p.offset	= bio_end_sector(bio);
	op->insert_key.k.size		= bio_sectors(bio);

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
		       struct write_point *wp, struct bkey_s_c insert_key,
		       struct extent_insert_hook *insert_hook,
		       u64 *journal_seq, unsigned flags)
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
	op->written	= 0;
	op->error	= 0;
	op->flags	= flags;
	op->compression_type = c->opts.compression;
	op->nr_replicas	= c->opts.data_replicas;
	op->res		= res;
	op->wp		= wp;

	if (journal_seq) {
		op->journal_seq_p = journal_seq;
		op->flags |= BCH_WRITE_JOURNAL_SEQ_PTR;
	} else {
		op->journal_seq = 0;
	}

	op->insert_hook = insert_hook;
	op->index_update_fn = bch_write_index_default;

	bch_keylist_init(&op->insert_keys,
			 op->inline_keys,
			 ARRAY_SIZE(op->inline_keys));
	bkey_reassemble(&op->insert_key, insert_key);

	if (!bkey_val_u64s(&op->insert_key.k)) {
		/*
		 * If the new key has no pointers, we're either doing a
		 * discard or we're writing new data and we're going to
		 * allocate pointers
		 */
		op->insert_key.k.type =
			(op->flags & BCH_WRITE_DISCARD) ? KEY_TYPE_DISCARD :
			(op->flags & BCH_WRITE_CACHED) ? BCH_EXTENT_CACHED :
			BCH_EXTENT;
	}
}

void bch_replace_init(struct bch_replace_info *r, struct bkey_s_c old)
{
	memset(r, 0, sizeof(*r));
	r->hook.fn = bch_extent_cmpxchg;
	bkey_reassemble(&r->key, old);
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
		struct extent_insert_hook *hook,
		u64 *journal_seq)
{
	return bch_btree_delete_range(c, BTREE_ID_EXTENTS, start, end,
				      version, hook, journal_seq);
}

/* Cache promotion on read */

struct cache_promote_op {
	struct closure		cl;
	struct bch_read_bio	*orig_bio;
	struct bch_write_op	iop;
	struct bch_write_bio	bio; /* must be last */
};

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
#if 0
	struct cache_promote_op *op;
	struct bio *bio;
	unsigned pages = DIV_ROUND_UP(orig_bio->bio.bi_iter.bi_size, PAGE_SIZE);

	/* XXX: readahead? */

	op = kmalloc(sizeof(*op) + sizeof(struct bio_vec) * pages, GFP_NOIO);
	if (!op)
		goto out_submit;

	/* clone the bbio */
	memcpy(&op->bio, orig_bio, offsetof(struct bbio, bio));

	bio = &op->bio.bio.bio;
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

	bch_write_op_init(&op->iop, c, &op->bio, &c->promote_write_point,
			  new, old,
			  BCH_WRITE_ALLOC_NOWAIT|write_flags);
	op->iop.nr_replicas = 1;

	//bch_cut_front(bkey_start_pos(&orig_bio->key.k), &op->iop.insert_key);
	//bch_cut_back(orig_bio->key.k.p, &op->iop.insert_key.k);

	trace_bcache_promote(&orig_bio->bio);

	op->bio.bio.submit_time_us = local_clock_us();
	closure_bio_submit(bio, &op->cl);

	continue_at(&op->cl, cache_promote_write, c->wq);
out_free:
	kfree(op);
out_submit:
	generic_make_request(&orig_bio->bio);
#endif
}

/* Read */

static int bio_uncompress_lz4(struct cache_set *c,
			      struct bio *dst, struct bvec_iter dst_iter,
			      struct bio *src, struct bvec_iter src_iter,
			      unsigned skip, unsigned uncompressed_size)
{
	void *src_data = NULL, *dst_data = NULL;
	unsigned src_bounced;
	size_t src_len = src_iter.bi_size;
	size_t dst_len = uncompressed_size;
	int ret = -ENOMEM;

	src_data = __bio_map_or_bounce(src, src_iter, &src_bounced, true);
	if (!src_data)
		goto err;

	dst_data = kmalloc(uncompressed_size, GFP_NOIO|__GFP_NOWARN);
	if (!dst_data) {
		dst_data = vmalloc(uncompressed_size);
		if (!dst_data)
			goto err;
	}

	ret = lz4_decompress(src_data, &src_len,
			     dst_data, dst_len);

	if (ret)
		goto err;

	memcpy_to_bio(dst, dst_iter, dst_data + skip);
err:
	kvfree(dst_data);
	bio_unmap_or_unbounce(src_data, src_bounced);
	return ret;
}

static int bio_uncompress_gzip(struct cache_set *c,
			       struct bio *dst, struct bvec_iter dst_iter,
			       struct bio *src, struct bvec_iter src_iter,
			       unsigned skip)
{
	z_stream strm;
	struct page *workspace;
	void *k_out = NULL;
	u8 garbage[128];
	int ret;
	bool decompress_all = true;

	workspace = mempool_alloc(&c->compression_workspace_pool, GFP_NOIO);
	strm.workspace = page_address(workspace);

	zlib_inflateInit(&strm);
	strm.next_in	= NULL;
	strm.next_out	= NULL;
	strm.avail_out	= 0;
	strm.avail_in	= 0;

	do {
		if (strm.avail_out) {
			;
		} else if (skip) {
			strm.avail_out = min_t(unsigned, sizeof(garbage), skip);
			strm.next_out = garbage;

			skip -= strm.avail_out;
		} else if (dst_iter.bi_size) {
			struct bio_vec bv = bio_iter_iovec(dst, dst_iter);

			if (k_out)
				kunmap_atomic(k_out);
			k_out = kmap_atomic(bv.bv_page) + bv.bv_offset;

			strm.avail_out = bv.bv_len;
			strm.next_out = k_out;

			bio_advance_iter(dst, &dst_iter, bv.bv_len);
		} else {
			/* Uncompressed all the data we actually want: */
			if (!decompress_all) {
				ret = Z_STREAM_END;
				break;
			}

			strm.avail_out = sizeof(garbage);
			strm.next_out = garbage;
		}

		if (!strm.avail_in && src_iter.bi_size) {
			struct bio_vec bv = bio_iter_iovec(src, src_iter);

			strm.avail_in = bv.bv_len;
			strm.next_in = page_address(bv.bv_page) + bv.bv_offset;

			bio_advance_iter(src, &src_iter, bv.bv_len);
		}
	} while ((ret = zlib_inflate(&strm, Z_NO_FLUSH)) == Z_OK);

	if (k_out)
		kunmap_atomic(k_out);

	mempool_free(workspace, &c->compression_workspace_pool);

	return ret == Z_STREAM_END ? 0 : -EIO;
}

static int bio_checksum_uncompress(struct cache_set *c,
				   struct bch_read_bio *rbio)
{
	struct bio *src = &rbio->bio;
	struct bio *dst = &bch_rbio_parent(rbio)->bio;
	struct bvec_iter dst_iter = rbio->parent_iter;
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

	if (rbio->crc.csum_type != BCH_CSUM_NONE &&
	    rbio->crc.csum != checksum_bio(src, rbio->crc.csum_type)) {
		cache_nonfatal_io_error(rbio->ca, "checksum error");
		return -EIO;
	}

	switch (rbio->crc.compression_type) {
	case BCH_COMPRESSION_NONE:
		if (rbio->bounce) {
			bio_advance(src, rbio->crc.offset << 9);
			bio_copy_data_iter(dst, dst_iter,
					   src, src->bi_iter);
		}
		break;
	case BCH_COMPRESSION_LZ4:
		ret = bio_uncompress_lz4(c,
					 dst, dst_iter,
					 src, src->bi_iter,
					 rbio->crc.offset << 9,
					 rbio->crc.uncompressed_size << 9);
		break;
	case BCH_COMPRESSION_GZIP:
		ret = bio_uncompress_gzip(c,
					  dst, dst_iter,
					  src, src->bi_iter,
					  rbio->crc.offset << 9);
		break;
	default:
		BUG();
	}

	if (ret)
		__bcache_io_error(c, "decompression error");

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

	bch_rbio_free(op->iop.c, op->orig_bio);
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
		struct closure *cl = &rbio->promote->cl;

		BUG_ON(!rbio->split || !rbio->bounce);

		percpu_ref_put(&rbio->ca->ref);
		rbio->ca = NULL;

		bio_endio(&rbio->parent->bio);
		rbio->parent = NULL;

		closure_init(cl, &c->cl);
		closure_call(&rbio->promote->iop.cl, bch_write, c->wq, cl);
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
	int stale = race_fault() ||
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
			  struct extent_pick_ptr *pick,
			  unsigned skip, unsigned flags)
{
	struct bch_read_bio *rbio;
	struct cache_promote_op *promote_op = NULL;
	unsigned orig_sectors = bio_sectors(&orig->bio);
	bool bounce = false, split, read_full = false;

	/* only promote if we're not reading from the fastest tier: */
	if ((flags & BCH_READ_PROMOTE) && pick->ca->mi.tier) {
		promote_op = kmalloc(sizeof(*promote_op), GFP_NOIO);

		if (promote_op)
			bounce = true;
	}

	/*
	 * note: if compression_type and crc_type both == none, then
	 * compressed/uncompressed size is zero
	 */
	if (pick->crc.compression_type != BCH_COMPRESSION_NONE ||
	    (pick->crc.csum_type != BCH_CSUM_NONE &&
	     (orig_sectors != pick->crc.uncompressed_size ||
	      (flags & BCH_READ_FORCE_BOUNCE)))) {
		read_full = true;
		bounce = true;
	}

	if (bounce) {
		unsigned sectors = read_full
			? (pick->crc.compressed_size ?: k.k->size)
			: orig_sectors;

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

	if (read_full)
		rbio->crc.offset += skip;
	else
		rbio->bio.bi_iter.bi_sector += skip;

	if (promote_op) {
		promote_op->orig_bio = rbio;

		bch_write_op_init(&promote_op->iop, c,
				  &promote_op->bio,
				  (struct disk_reservation) { 0 },
				  &c->promote_write_point,
				  k, NULL, NULL,
				  BCH_WRITE_ALLOC_NOWAIT);

		if (!read_full) {
			bch_cut_front(POS(k.k->p.inode,
					  bkey_start_offset(k.k) + skip),
				      &promote_op->iop.insert_key);
			bch_key_resize(&promote_op->iop.insert_key.k,
				       orig_sectors);
		}

		__bio_clone_fast(&promote_op->bio.bio.bio, &rbio->bio);
	}

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

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_EXTENTS,
				      POS(inode, bvec_iter.bi_sector), k) {
		struct extent_pick_ptr pick;
		unsigned bytes, sectors;
		bool is_last;

		EBUG_ON(bkey_cmp(bkey_start_pos(k.k),
				 POS(inode, bvec_iter.bi_sector)) > 0);

		EBUG_ON(bkey_cmp(k.k->p,
				 POS(inode, bvec_iter.bi_sector)) <= 0);

		bch_extent_pick_ptr(c, k, &pick);

		/*
		 * Unlock the iterator while the btree node's lock is still in
		 * cache, before doing the IO:
		 */
		bch_btree_iter_unlock(&iter);

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

			bch_read_extent_iter(c, rbio, bvec_iter, k, &pick,
					     bvec_iter.bi_sector -
					     bkey_start_offset(k.k), flags);

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
	BUG_ON(!bch_btree_iter_unlock(&iter));
	bcache_io_error(c, bio, "btree IO error");
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
