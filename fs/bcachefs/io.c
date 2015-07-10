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
#include <linux/zlib.h>

#include <trace/events/bcachefs.h>

static inline void __bio_inc_remaining(struct bio *bio)
{
	bio->bi_flags |= (1 << BIO_CHAIN);
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

void bch_bio_free_pages_pool(struct cache_set *c, struct bio *bio)
{
	struct bio_vec *bv;
	unsigned i;

	bio_for_each_segment_all(bv, bio, i)
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

static void bch_bbio_reset(struct bbio *b)
{
	BUG();
#if 0
	struct bvec_iter *iter = &b->bio.bi_iter;

	bio_reset(&b->bio);
	iter->bi_sector		= bkey_start_offset(&b->key.k);
	iter->bi_size		= b->key.k.size << 9;
	iter->bi_idx		= b->bi_idx;
	iter->bi_bvec_done	= b->bi_bvec_done;
#endif
}

/* IO errors */

void bch_bbio_endio(struct bbio *bio)
{
	struct closure *cl = bio->bio.bi_private;
	struct cache *ca = bio->ca;

	bch_account_bbio_completion(bio);

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

	BUG_ON(dst->bi_iter.bi_size);

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

static unsigned bio_compress(struct cache_set *c, struct bio *dst,
			     struct bio *src, unsigned *compression_type,
			     unsigned output_available)
{
	int ret = 0;

	/* if it's only one block, don't bother trying to compress: */
	if (bio_sectors(src) <= c->sb.block_size)
		*compression_type = BCH_COMPRESSION_NONE;

	switch (*compression_type) {
	case BCH_COMPRESSION_NONE:
		/* Just bounce it, for stable checksums: */
copy:
		bch_bio_alloc_pages_pool(c, dst, output_available);
		bio_copy_data(dst, src);
		return output_available;
	case BCH_COMPRESSION_LZO1X:
		BUG();
	case BCH_COMPRESSION_GZIP:
		ret = bio_compress_gzip(c, dst, src, output_available);
		break;
	case BCH_COMPRESSION_XZ:
		BUG();
	default:
		BUG();
	}

	if (ret < 0) {
		/* Failed to compress (didn't get smaller): */
		*compression_type = BCH_COMPRESSION_NONE;
		goto copy;
	}

	BUG_ON(ret & ((1 << (c->block_bits + 9)) - 1));

	if (DIV_ROUND_UP(dst->bi_iter.bi_size, block_bytes(c)) >=
	    ret >> (c->block_bits + 9)) {
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

	return ret;
}

static void __bch_write(struct closure *);

static inline u64 *op_journal_seq(struct bch_write_op *op)
{
	return op->journal_seq_ptr ? op->journal_seq_p : &op->journal_seq;
}

static void bch_write_done(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);

	BUG_ON(!op->write_done);

	if (!op->error && op->flush)
		op->error = bch_journal_error(&op->c->journal);

	if (op->replace_collision) {
		trace_bcache_promote_collision(&op->replace_info.key.k);
		atomic_inc(&op->c->accounting.collector.cache_miss_collisions);
	}

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
	unsigned i;
	int ret;

	ret = bch_btree_insert(op->c, BTREE_ID_EXTENTS, &op->insert_keys,
			       op->replace ? &op->replace_info : NULL,
			       op_journal_seq(op), BTREE_INSERT_NOFAIL);
	if (ret) {
		__bcache_io_error(op->c, "btree IO error");
		op->error = ret;
	} else if (op->replace && op->replace_info.successes == 0)
		op->replace_collision = true;

	for (i = 0; i < ARRAY_SIZE(op->open_buckets); i++)
		if (op->open_buckets[i]) {
			bch_open_bucket_put(op->c, op->open_buckets[i]);
			op->open_buckets[i] = NULL;
		}

	if (!op->write_done)
		continue_at(cl, __bch_write, op->io_wq);

	if (!op->error && op->flush) {
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
				NULL);
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
	struct bch_write_bio *wbio = to_wbio(bio);

	if (cache_nonfatal_io_err_on(bio->bi_error, wbio->bio.ca,
				     "data write")) {
		/* TODO: We could try to recover from this. */
		if (!bkey_extent_is_cached(&op->insert_key.k)) {
			op->error = bio->bi_error;
		} else if (!op->replace)
			set_closure_fn(cl, bch_write_error, op->c->wq);
		else
			set_closure_fn(cl, NULL, NULL);
	}

	if (wbio->orig)
		bio_endio(wbio->orig);
	else if (wbio->bounce)
		bch_bio_free_pages_pool(op->c, bio);

	bch_bbio_endio(&wbio->bio);
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
	unsigned csum_type = c->opts.data_csum_type;
	unsigned compression_type = c->opts.compression_type;

	/* don't refetch csum type/compression type */
	barrier();

	extent_for_each_ptr(extent_i_to_s(e), ptr)
		ptrs_from++;

	if (csum_type != BCH_CSUM_NONE ||
	    compression_type != BCH_COMPRESSION_NONE) {
		/* all units here in bytes */
		unsigned output_available, input_available, input_consumed;
		u64 csum;

		BUG_ON(bio_sectors(orig) != k->k.size);

		/* XXX: decide extent size better: */
		output_available = min(k->k.size,
				   min(ob->sectors_free,
				       CRC32_EXTENT_SIZE_MAX)) << 9;

		input_available = min(orig->bi_iter.bi_size,
				      CRC32_EXTENT_SIZE_MAX << 9);

		/*
		 * temporarily set input bio's size to the max we want to
		 * consume from it, in order to avoid overflow in the crc info
		 */
		swap(orig->bi_iter.bi_size, input_available);

		bio = bio_alloc_bioset(GFP_NOIO,
				DIV_ROUND_UP(output_available, PAGE_SIZE),
				&c->bio_write);
		wbio			= to_wbio(bio);
		wbio->orig		= NULL;
		wbio->bounce		= true;

		input_consumed = bio_compress(c, bio, orig,
					      &compression_type,
					      output_available);

		swap(orig->bi_iter.bi_size, input_available);

		bch_key_resize(&k->k, input_consumed >> 9);
		bio_advance(orig, input_consumed);

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

		bch_alloc_sectors_done(op->c, op->wp, k, ob, bio_sectors(bio));
	} else {
		if (k->k.size > ob->sectors_free)
			bch_key_resize(&k->k, ob->sectors_free);

		/*
		 * We might need a checksum entry, if there's a previous
		 * checksum entry we need to override:
		 */
		extent_checksum_append(e, k->k.size, k->k.size,
				       compression_type, 0, csum_type);

		bch_alloc_sectors_done(op->c, op->wp, k, ob, k->k.size);

		bio = bio_next_split(orig, k->k.size, GFP_NOIO,
				     &op->c->bio_write);
		if (bio == orig)
			bio_get(bio);

		wbio			= to_wbio(bio);
		wbio->orig		= NULL;
		wbio->bounce		= false;
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

	if (op->discard) {
		op->write_done = true;
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

		b = bch_alloc_sectors_start(op->c, op->wp,
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

		/*
		 * XXX: if we compressed, we didn't use all the space we just
		 * allocated
		 */
		bch_write_extent(op, b, k, bio);
		bch_cut_front(k->k.p, &op->insert_key);

		BUG_ON(op->insert_key.k.size &&
		       op->insert_key.k.size != bio_sectors(bio));

		BUG_ON(bch_extent_normalize(op->c, bkey_i_to_s(k)));
		bch_check_mark_super(op->c, k, false);

		bkey_extent_set_cached(&k->k, op->cached);

		bch_keylist_enqueue(&op->insert_keys);

		trace_bcache_cache_insert(&k->k);
	} while (op->insert_key.k.size);

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
		op->error = -ENOSPC;
	}

	op->write_done = true;

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
			   op->discard);

	if (!bio_sectors(bio)) {
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
		bch_increment_clock(c, bio_sectors(bio), WRITE);

	if (!op->discard)
		bch_mark_foreground_write(c, bio_sectors(bio));
	else
		bch_mark_discard(c, bio_sectors(bio));

	op->insert_key.k.p.offset	= bio_end_sector(bio);
	op->insert_key.k.size		= bio_sectors(bio);

	/* Don't call bch_next_delay() if rate is >= 1 GB/sec */

	if (c->foreground_write_ratelimit_enabled &&
	    c->foreground_write_pd.rate.rate < (1 << 30) &&
	    !op->discard && op->wp->throttle) {
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
		       struct bch_write_bio *bio, struct write_point *wp,
		       struct bkey_s_c insert_key,
		       struct bkey_s_c replace_key,
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
	op->error	= 0;
	op->flags	= 0;
	op->check_enospc = (flags & BCH_WRITE_CHECK_ENOSPC) != 0;
	op->nowait	= (flags & BCH_WRITE_ALLOC_NOWAIT) != 0;
	op->discard	= (flags & BCH_WRITE_DISCARD) != 0;
	op->cached	= (flags & BCH_WRITE_CACHED) != 0;
	op->flush	= (flags & BCH_WRITE_FLUSH) != 0;
	op->wp		= wp;
	op->journal_seq_ptr = journal_seq != NULL;

	if (op->journal_seq_ptr)
		op->journal_seq_p = journal_seq;
	else
		op->journal_seq = 0;

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
		op->insert_key.k.type = op->discard ? KEY_TYPE_DISCARD
			: op->cached ? BCH_EXTENT_CACHED
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
		struct bpos end, u64 version, u64 *journal_seq)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_EXTENTS, start);

	while ((k = bch_btree_iter_peek(&iter)).k) {
		unsigned max_sectors = KEY_SIZE_MAX & (~0 << c->block_bits);
		/* really shouldn't be using a bare, unpadded bkey_i */
		struct bkey_i erase;

		if (bkey_cmp(iter.pos, end) >= 0)
			break;

		/* create the biggest key we can, to minimize writes */
		bkey_init(&erase.k);
		erase.k.type	= KEY_TYPE_DISCARD;
		erase.k.version	= version;
		erase.k.p	= iter.pos;

		bch_key_resize(&erase.k, max_sectors);
		bch_cut_back(end, &erase.k);

		ret = bch_btree_insert_at(&iter, &keylist_single(&erase),
					  NULL, journal_seq,
					  BTREE_INSERT_NOFAIL);
		if (ret)
			break;

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
	struct bch_write_bio	bio; /* must be last */
};

static void cache_promote_done(struct closure *cl)
{
	struct cache_promote_op *op =
		container_of(cl, struct cache_promote_op, cl);

	bch_bio_free_pages_pool(op->iop.c, op->orig_bio);
	bio_put(op->orig_bio);
	kfree(op);
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
			  BCH_WRITE_CHECK_ENOSPC|
			  BCH_WRITE_ALLOC_NOWAIT|write_flags);

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

static void bch_read_requeue(struct cache_set *c, struct bio *bio)
{
	unsigned long flags;

	BUG();

	spin_lock_irqsave(&c->read_race_lock, flags);
	bio_list_add(&c->read_race_list, bio);
	spin_unlock_irqrestore(&c->read_race_lock, flags);
	queue_work(c->wq, &c->read_race_work);
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

static int bio_checksum_uncompress(struct bch_read_bio *rbio)
{
	struct bio *bio = &rbio->bio.bio;
	int ret = 0;

	/* reset iterator for checksum */
	bio->bi_iter.bi_size		= rbio->compressed_size << 9;
	bio->bi_iter.bi_idx		= 0;
	bio->bi_iter.bi_bvec_done	= 0;

	if (rbio->csum_type != BCH_CSUM_NONE &&
	    rbio->csum != checksum_bio(bio, rbio->csum_type)) {
		cache_nonfatal_io_error(rbio->bio.ca, "checksum error");
		return -EIO;
	}

	switch (rbio->compression_type) {
	case BCH_COMPRESSION_NONE:
		if (rbio->bounce) {
			bio_advance(bio, rbio->offset << 9);
			bio_copy_data_iter(rbio->parent, rbio->parent_iter,
					   bio, bio->bi_iter);
		}
		break;
	case BCH_COMPRESSION_LZO1X:
		BUG();
	case BCH_COMPRESSION_GZIP:
		ret = bio_uncompress_gzip(rbio->c,
					  rbio->parent,
					  rbio->parent_iter,
					  bio, bio->bi_iter,
					  rbio->offset << 9);
		break;
	case BCH_COMPRESSION_XZ:
		BUG();
	default:
		BUG();
	}

	if (ret)
		__bcache_io_error(rbio->c, "decompression error");

	return ret;
}

/* Inner part that may run in process context */
static void __bch_read_endio(struct bch_read_bio *rbio)
{
	struct bio *bio = &rbio->bio.bio;
	int ret;

	ret = bio_checksum_uncompress(rbio);
	if (ret)
		rbio->parent->bi_error = ret;
	bio_endio(rbio->parent);

	if (!ret && rbio->promote &&
	    !test_bit(CACHE_SET_RO, &rbio->c->flags) &&
	    !test_bit(CACHE_SET_STOPPING, &rbio->c->flags)) {
		struct closure *cl = &rbio->promote->cl;

		closure_init(cl, &rbio->c->cl);
		closure_call(&rbio->promote->iop.cl, bch_write, rbio->c->wq, cl);
		closure_return_with_destructor(cl, cache_promote_done);
	} else {
		if (rbio->promote)
			kfree(rbio->promote);
		if (rbio->bounce)
			bch_bio_free_pages_pool(rbio->c, bio);

		bio_put(bio);
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

			__bch_read_endio(rbio);
		}
}

static void bch_read_endio(struct bio *bio)
{
	struct bch_read_bio *rbio =
		container_of(bio, struct bch_read_bio, bio.bio);
	bool stale = //race_fault() ||
		ptr_stale(rbio->bio.ca, &rbio->bio.ptr);
	int error = bio->bi_error;

	bch_account_bbio_completion(&rbio->bio);

	cache_nonfatal_io_err_on(error, rbio->bio.ca, "data read");

	percpu_ref_put(&rbio->bio.ca->ref);

	if (error)
		goto out;

	if (stale)
		goto stale;

	if (rbio->compression_type != BCH_COMPRESSION_NONE) {
		struct bio_decompress_worker *d;

		preempt_disable();
		d = this_cpu_ptr(rbio->c->bio_decompress_worker);
		llist_add(&rbio->list, &d->bio_list);
		queue_work(system_unbound_wq, &d->work);
		preempt_enable();
	} else {
		__bch_read_endio(rbio);
	}

	return;
stale:
	if (rbio->promote)
		kfree(rbio->promote);
	rbio->promote = NULL;

	/* Raced with the bucket being reused and invalidated: */
	if (rbio->flags & BCH_READ_RETRY_IF_STALE) {
		atomic_long_inc(&rbio->c->cache_read_races);
		bch_read_requeue(rbio->c, bio);
		return;
	}

	error = -EINTR;
out:
	if (rbio->promote)
		kfree(rbio->promote);
	if (error)
		rbio->parent->bi_error = error;
	bio_endio(rbio->parent);
	bio_put(bio);
}

void bch_read_extent(struct cache_set *c, struct bio *orig,
		     struct bkey_s_c k, struct extent_pick_ptr *pick,
		     unsigned skip, unsigned flags)
{
	struct bio *bio;
	struct bch_read_bio *rbio;
	struct cache_promote_op *promote_op = NULL;
	bool bounce = false, read_full = false;

	/* only promote if we're not reading from the fastest tier: */
	if ((flags & BCH_READ_PROMOTE) && CACHE_TIER(&pick->ca->mi)) {
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
	     (bio_sectors(orig) != pick->crc.uncompressed_size ||
	      (flags & BCH_READ_FORCE_BOUNCE)))) {
		read_full = true;
		bounce = true;
	}

	if (bounce) {
		unsigned sectors =
			!read_full ? bio_sectors(orig)
			: pick->crc.compressed_size ?: k.k->size;

		bio = bio_alloc_bioset(GFP_NOIO,
				DIV_ROUND_UP(sectors, PAGE_SECTORS),
				&c->bio_read);
		bch_bio_alloc_pages_pool(c, bio, sectors << 9);
	} else {
		bio = bio_clone_fast(orig, GFP_NOIO, &c->bio_read);
	}

	rbio = container_of(bio, struct bch_read_bio, bio.bio);
	memset(rbio, 0, offsetof(struct bch_read_bio, bio));

	rbio->csum		= pick->crc.csum;
	rbio->compressed_size	= pick->crc.compressed_size;
	rbio->uncompressed_size	= pick->crc.uncompressed_size;
	rbio->offset		= pick->crc.offset;
	rbio->csum_type		= pick->crc.csum_type;
	rbio->compression_type	= pick->crc.compression_type;

	__bio_inc_remaining(orig);
	rbio->parent		= orig;
	rbio->parent_iter	= orig->bi_iter;
	rbio->c			= c;
	rbio->flags		= flags;
	rbio->bounce		= bounce;
	rbio->promote		= promote_op;
	rbio->bio.ptr		= pick->ptr;
	bio->bi_end_io		= bch_read_endio;
	bch_bbio_prep(&rbio->bio, pick->ca);

	if (read_full)
		rbio->offset += skip;
	else
		bio->bi_iter.bi_sector += skip;

	if (promote_op) {
		promote_op->orig_bio = bio;

		bch_write_op_init(&promote_op->iop, c,
				  &promote_op->bio,
				  &c->promote_write_point,
				  k, k, NULL,
				  BCH_WRITE_CHECK_ENOSPC|
				  BCH_WRITE_ALLOC_NOWAIT);

		if (!read_full) {
			bch_cut_front(POS(k.k->p.inode,
					  bkey_start_offset(k.k) + skip),
				      &promote_op->iop.insert_key);
			bch_key_resize(&promote_op->iop.insert_key.k,
				       bio_sectors(orig));
		}

		__bio_clone_fast(&promote_op->bio.bio.bio, bio);
	}

	generic_make_request(bio);
}

/* XXX: this looks a lot like cache_lookup_fn() */
int bch_read(struct cache_set *c, struct bio *bio, u64 inode)
{
	struct btree_iter iter;
	struct bkey_s_c k;

	bch_increment_clock(c, bio_sectors(bio), READ);

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_EXTENTS,
				      POS(inode, bio->bi_iter.bi_sector), k) {
		struct extent_pick_ptr pick;
		unsigned bytes, sectors;
		bool done;

		BUG_ON(bkey_cmp(bkey_start_pos(k.k),
				POS(inode, bio->bi_iter.bi_sector)) > 0);

		BUG_ON(bkey_cmp(k.k->p,
				POS(inode, bio->bi_iter.bi_sector)) <= 0);

		sectors = min_t(u64, k.k->p.offset, bio_end_sector(bio)) -
			bio->bi_iter.bi_sector;
		bytes = sectors << 9;
		done = bytes == bio->bi_iter.bi_size;

		swap(bio->bi_iter.bi_size, bytes);

		pick = bch_extent_pick_ptr(c, k);
		if (IS_ERR(pick.ca)) {
			bcache_io_error(c, bio, "no device to read from");
			bch_btree_iter_unlock(&iter);
			return 0;
		}
		if (pick.ca) {
			PTR_BUCKET(pick.ca, &pick.ptr)->read_prio =
				c->prio_clock[READ].hand;

			bch_read_extent(c, bio, k, &pick,
					bio->bi_iter.bi_sector -
					bkey_start_offset(k.k),
					BCH_READ_FORCE_BOUNCE|
					BCH_READ_RETRY_IF_STALE|
					BCH_READ_PROMOTE);
		} else {
			zero_fill_bio(bio);
		}

		swap(bio->bi_iter.bi_size, bytes);
		bio_advance(bio, bytes);

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
	BUG(); /* currently broken */
	//inode = bbio->key.k.p.inode;
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
