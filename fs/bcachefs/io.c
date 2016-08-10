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

enum bounced {
	BOUNCED_MAPPED,
	BOUNCED_KMALLOCED,
	BOUNCED_VMALLOCED,
	BOUNCED_MEMPOOLED,
};

static void *__bounce_alloc(struct cache_set *c, unsigned size,
			    unsigned *bounced, int direction)
{
	void *data;

	*bounced = BOUNCED_KMALLOCED;
	data = kmalloc(size, GFP_NOIO);
	if (data)
		return data;

	*bounced = BOUNCED_MEMPOOLED;
	data = mempool_alloc(&c->compression_bounce[direction], GFP_NOWAIT);
	if (data)
		return page_address(data);

	*bounced = BOUNCED_VMALLOCED;
	data = vmalloc(size);
	if (data)
		return data;

	*bounced = BOUNCED_MEMPOOLED;
	data = mempool_alloc(&c->compression_bounce[direction], GFP_NOIO);
	return page_address(data);
}

static void *__bio_map_or_bounce(struct cache_set *c,
				 struct bio *bio, struct bvec_iter start,
				 unsigned *bounced, int direction)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	unsigned nr_pages = 0;
	struct page *stack_pages[4];
	struct page **pages = NULL;
	bool first = true;
	unsigned prev_end = PAGE_SIZE;
	void *data;

	BUG_ON(start.bi_size > (BCH_COMPRESSED_EXTENT_MAX << 9));

	*bounced = BOUNCED_MAPPED;

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
		goto bounce;

	nr_pages = 0;
	__bio_for_each_segment(bv, bio, iter, start)
		pages[nr_pages++] = bv.bv_page;

	data = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (pages != stack_pages)
		kfree(pages);

	return data + bio_iter_offset(bio, start);
bounce:
	data = __bounce_alloc(c, start.bi_size, bounced, direction);

	if (direction == READ)
		memcpy_from_bio(data, bio, start);

	return data;
}

static void *bio_map_or_bounce(struct cache_set *c, struct bio *bio,
			       unsigned *bounced, int direction)
{
	return __bio_map_or_bounce(c, bio, bio->bi_iter, bounced, direction);
}

static void bio_unmap_or_unbounce(struct cache_set *c, void *data,
				  unsigned bounced, int direction)
{
	if (!data)
		return;

	switch (bounced) {
	case BOUNCED_MAPPED:
		vunmap((void *) ((unsigned long) data & PAGE_MASK));
		return;
	case BOUNCED_KMALLOCED:
		kfree(data);
		return;
	case BOUNCED_VMALLOCED:
		vfree(data);
		return;
	case BOUNCED_MEMPOOLED:
		mempool_free(virt_to_page(data), &c->compression_bounce[direction]);
		return;
	}
}

static int __bio_uncompress(struct cache_set *c, struct bio *src,
			    void *dst_data, struct bch_extent_crc64 crc)
{
	void *src_data = NULL;
	unsigned src_bounced;
	size_t src_len = src->bi_iter.bi_size;
	size_t dst_len = crc.uncompressed_size << 9;
	int ret;

	src_data = bio_map_or_bounce(c, src, &src_bounced, READ);

	switch (crc.compression_type) {
	case BCH_COMPRESSION_LZ4:
		ret = lz4_decompress(src_data, &src_len,
				     dst_data, dst_len);
		if (ret) {
			ret = -EIO;
			goto err;
		}
		break;
	case BCH_COMPRESSION_GZIP: {
		struct page *workspace;
		z_stream strm;

		workspace = mempool_alloc(&c->compression_workspace_pool,
					  GFP_NOIO);
		strm.workspace	= page_address(workspace);
		strm.next_in	= src_data;
		strm.avail_in	= src_len;
		strm.next_out	= dst_data;
		strm.avail_out	= dst_len;
		zlib_inflateInit2(&strm, -MAX_WBITS);

		ret = zlib_inflate(&strm, Z_FINISH);

		mempool_free(workspace, &c->compression_workspace_pool);

		if (ret != Z_STREAM_END) {
			ret = -EIO;
			goto err;
		}
		break;
	}
	default:
		BUG();
	}
	ret = 0;
err:
	bio_unmap_or_unbounce(c, src_data, src_bounced, READ);
	return ret;
}

static int bio_uncompress_inplace(struct cache_set *c, struct bio *bio,
				  struct bkey *k, struct bch_extent_crc64 crc)
{
	void *dst_data = NULL;
	size_t dst_len = crc.uncompressed_size << 9;
	int ret = -ENOMEM;

	BUG_ON(DIV_ROUND_UP(k->size, PAGE_SECTORS) > bio->bi_max_vecs);

	/* XXX mempoolify */
	dst_data = kmalloc(dst_len, GFP_NOIO|__GFP_NOWARN);
	if (!dst_data) {
		dst_data = vmalloc(dst_len);
		if (!dst_data)
			goto err;
	}

	ret = __bio_uncompress(c, bio, dst_data, crc);
	if (ret)
		goto err;

	while (bio->bi_vcnt < DIV_ROUND_UP(k->size, PAGE_SECTORS)) {
		struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt];

		bv->bv_page = alloc_page(GFP_NOIO);
		if (!bv->bv_page)
			goto use_mempool;

		bv->bv_len = PAGE_SIZE;
		bv->bv_offset = 0;
		bio->bi_vcnt++;
	}

	bio->bi_iter.bi_size = k->size << 9;
copy_data:
	memcpy_to_bio(bio, bio->bi_iter, dst_data + (crc.offset << 9));
err:
	kvfree(dst_data);
	return ret;
use_mempool:
	/*
	 * We already allocated from mempool, we can't allocate from it again
	 * without freeing the pages we already allocated or else we could
	 * deadlock:
	 */

	bch_bio_free_pages_pool(c, bio);
	bch_bio_alloc_pages_pool(c, bio, k->size << 9);
	goto copy_data;
}

static int bio_uncompress(struct cache_set *c, struct bio *src,
			  struct bio *dst, struct bvec_iter dst_iter,
			  struct bch_extent_crc64 crc)
{
	void *dst_data = NULL;
	unsigned dst_bounced;
	size_t dst_len = crc.uncompressed_size << 9;
	int ret = -ENOMEM;

	dst_data = dst_len == dst_iter.bi_size
		? __bio_map_or_bounce(c, dst, dst_iter, &dst_bounced, WRITE)
		: __bounce_alloc(c, dst_len, &dst_bounced, WRITE);

	ret = __bio_uncompress(c, src, dst_data, crc);
	if (ret)
		goto err;

	if (dst_bounced)
		memcpy_to_bio(dst, dst_iter, dst_data + (crc.offset << 9));
err:
	bio_unmap_or_unbounce(c, dst_data, dst_bounced, WRITE);
	return ret;
}

static struct bio *__bio_compress(struct cache_set *c,
				  unsigned compression_type,
				  struct bio *src,
				  unsigned output_available,
				  int *input_consumed)
{
	struct bio *dst;
	void *src_data = NULL, *dst_data = NULL;
	unsigned src_bounced, dst_bounced;
	int ret = -1;

	BUG_ON(output_available > src->bi_iter.bi_size);

	output_available = min_t(unsigned, output_available,
				 BCH_COMPRESSED_EXTENT_MAX << 9);

	dst = bio_alloc_bioset(GFP_NOIO,
		DIV_ROUND_UP(output_available, PAGE_SIZE),
		&c->bio_write);

	bch_bio_alloc_pages_pool(c, dst, output_available);

	dst_data = bio_map_or_bounce(c, dst, &dst_bounced, WRITE);
	src_data = bio_map_or_bounce(c, src, &src_bounced, READ);

	switch (compression_type) {
	case BCH_COMPRESSION_LZ4: {
		struct page *workmem;
		bool used_mempool = false;
		unsigned order = get_order(LZ4_MEM_COMPRESS);
		size_t dst_size = dst->bi_iter.bi_size;

		workmem = alloc_pages(GFP_NOWAIT|__GFP_NOWARN, order);
		if (!workmem) {
			workmem = mempool_alloc(&c->compression_workspace_pool,
						GFP_NOIO);
			used_mempool = true;
		}
		/*
		 * XXX: due to the way the interface to lz4_compress works, we
		 * can't consume more than output_available bytes of input (even
		 * though a lot more might fit after compressing)
		 */
		ret = lz4_compress(src_data, min(output_available,
						 src->bi_iter.bi_size),
				   dst_data, &dst_size,
				   page_address(workmem));

		if (used_mempool)
			mempool_free(workmem, &c->compression_workspace_pool);
		else
			__free_pages(workmem, order);

		if (ret)
			goto err;

		dst->bi_iter.bi_size = dst_size;
		*input_consumed = output_available;
		break;
	}
	case BCH_COMPRESSION_GZIP: {
		struct page *workmem;
		z_stream strm;

		workmem = mempool_alloc(&c->compression_workspace_pool, GFP_NOIO);
		strm.workspace	= page_address(workmem);
		strm.next_in	= src_data;
		strm.avail_in	= output_available;
		strm.next_out	= dst_data;
		strm.avail_out	= output_available;
		zlib_deflateInit2(&strm, Z_DEFAULT_COMPRESSION,
				  Z_DEFLATED, -MAX_WBITS, DEF_MEM_LEVEL,
				  Z_DEFAULT_STRATEGY);

		ret = zlib_deflate(&strm, Z_FINISH);

		mempool_free(workmem, &c->compression_workspace_pool);

		if (ret != Z_STREAM_END) {
			ret = -EIO;
			goto err;
		}

		ret = zlib_deflateEnd(&strm);
		if (ret != Z_OK) {
			ret = -EIO;
			goto err;
		}

		BUG_ON(strm.total_in != output_available);

		dst->bi_iter.bi_size = strm.total_out;
		*input_consumed = strm.total_in;
		break;
	}
	default:
		BUG();
	}

	BUG_ON(!dst->bi_iter.bi_size);

	if (dst_bounced)
		memcpy_to_bio(dst, dst->bi_iter, dst_data);
out:
	bio_unmap_or_unbounce(c, src_data, src_bounced, READ);
	bio_unmap_or_unbounce(c, dst_data, dst_bounced, WRITE);

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
	case BCH_COMPRESSION_GZIP:
		dst = __bio_compress(c, *compression_type, src,
				     output_available, &input_consumed);
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
	union bch_extent_crc *crc;

	extent_for_each_crc(e, crc)
		switch (bch_extent_crc_type(crc)) {
		case BCH_EXTENT_CRC_NONE:
			BUG();
		case BCH_EXTENT_CRC32:
			if (crc->crc32.compression_type != BCH_COMPRESSION_NONE ||
			    bch_crc_size[csum_type] > sizeof(crc->crc32.csum))
				continue;

			extent_adjust_pointers(e, (void *) crc);
			crc->crc32.compressed_size	= e.k->size;
			crc->crc32.uncompressed_size	= e.k->size;
			crc->crc32.offset		= 0;
			crc->crc32.csum_type		= csum_type;
			crc->crc32.csum		= csum;
			break;
		case BCH_EXTENT_CRC64:
			if (crc->crc64.compression_type != BCH_COMPRESSION_NONE ||
			    bch_crc_size[csum_type] > sizeof(crc->crc64.csum))
				continue;

			extent_adjust_pointers(e, (void *) crc);
			crc->crc64.compressed_size	= e.k->size;
			crc->crc64.uncompressed_size	= e.k->size;
			crc->crc64.offset		= 0;
			crc->crc64.csum_type		= csum_type;
			crc->crc64.csum		= csum;
			break;
		}
}

static void extent_checksum_append(struct bkey_i_extent *e,
				   unsigned compressed_size,
				   unsigned uncompressed_size,
				   unsigned compression_type,
				   u64 csum, unsigned csum_type)
{
	union bch_extent_crc *crc;

	BUG_ON(compressed_size > uncompressed_size);
	BUG_ON(uncompressed_size != e->k.size);
	BUG_ON(!compressed_size || !uncompressed_size);

	/*
	 * Look up the last crc entry, so we can check if we need to add
	 * another:
	 */
	extent_for_each_crc(extent_i_to_s(e), crc)
		;

	switch (bch_extent_crc_type(crc)) {
	case BCH_EXTENT_CRC_NONE:
		if (!csum_type && !compression_type)
			return;
		break;
	case BCH_EXTENT_CRC32:
	case BCH_EXTENT_CRC64:
		if (crc_to_64(crc).compressed_size	== compressed_size &&
		    crc_to_64(crc).uncompressed_size	== uncompressed_size &&
		    crc_to_64(crc).offset		== 0 &&
		    crc_to_64(crc).compression_type	== compression_type &&
		    crc_to_64(crc).csum_type		== csum_type &&
		    crc_to_64(crc).csum			== csum)
			return;
		break;
	}

	if (bch_crc_size[csum_type] <= 4 &&
	    uncompressed_size <= CRC32_EXTENT_SIZE_MAX) {
		extent_crc32_append(e, (struct bch_extent_crc32) {
			.compressed_size	= compressed_size,
			.uncompressed_size	= uncompressed_size,
			.offset			= 0,
			.compression_type	= compression_type,
			.csum_type		= csum_type,
			.csum			= csum,
		});
	} else {
		BUG_ON(uncompressed_size > CRC64_EXTENT_SIZE_MAX);

		extent_crc64_append(e, (struct bch_extent_crc64) {
			.compressed_size	= compressed_size,
			.uncompressed_size	= uncompressed_size,
			.offset			= 0,
			.compression_type	= compression_type,
			.csum_type		= csum_type,
			.csum			= csum,
		});
	}
}

static int bch_write_extent(struct bch_write_op *op,
			    struct open_bucket *ob,
			    struct bkey_i_extent *e,
			    struct bio *orig)
{
	struct cache_set *c = op->c;
	struct bio *bio;
	struct bch_write_bio *wbio;
	unsigned ptrs_from = bch_extent_nr_ptrs(extent_i_to_s_c(e));
	unsigned csum_type = c->opts.data_checksum;
	unsigned compression_type = op->compression_type;

	/* don't refetch csum type/compression type */
	barrier();

	/* Need to decompress data? */
	if ((op->flags & BCH_WRITE_DATA_COMPRESSED) &&
	    (op->crc.uncompressed_size != e->k.size ||
	     op->crc.compressed_size > ob->sectors_free)) {
		int ret;

		ret = bio_uncompress_inplace(c, orig, &e->k, op->crc);
		if (ret)
			return ret;

		op->flags &= ~BCH_WRITE_DATA_COMPRESSED;
	}

	if (op->flags & BCH_WRITE_DATA_COMPRESSED) {
		extent_checksum_append(e,
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
		wbio->split		= false;
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
		bch_key_resize(&e->k, (orig_input - orig->bi_iter.bi_size) >> 9);

		/*
		 * XXX: could move checksumming out from under the open
		 * bucket lock - but compression is also being done
		 * under it
		 */
		csum = bch_checksum_bio(bio, csum_type);

		/*
		 * If possible, adjust existing pointers to only point to
		 * currently live data, while we have the checksum for that
		 * data:
		 */
		extent_cleanup_checksums(extent_i_to_s(e), csum, csum_type);
#if 0
		if (compression_type != BCH_COMPRESSION_NONE)
			pr_info("successfully compressed %u -> %u",
				e->k.size, bio_sectors(bio));
#endif
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
		if (e->k.size > ob->sectors_free)
			bch_key_resize(&e->k, ob->sectors_free);

		BUG_ON(e->k.size > ob->sectors_free);
		/*
		 * We might need a checksum entry, if there's a previous
		 * checksum entry we need to override:
		 */
		extent_checksum_append(e, e->k.size, e->k.size,
				       compression_type, 0, csum_type);
		bch_alloc_sectors_done(op->c, op->wp,
				       e, op->nr_replicas,
				       ob, e->k.size);

		bio = bio_next_split(orig, e->k.size, GFP_NOIO,
				     &op->c->bio_write);

		wbio			= to_wbio(bio);
		wbio->orig		= NULL;
		wbio->bounce		= false;
		wbio->split		= bio != orig;
	}

	bio->bi_end_io	= bch_write_endio;
	bio->bi_private	= &op->cl;
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	bch_submit_bbio_replicas(wbio, op->c, &e->k_i, ptrs_from, false);
	return 0;
}

static void __bch_write(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bio *bio = &op->bio->bio.bio;
	unsigned open_bucket_nr = 0;
	struct open_bucket *b;
	int ret;

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

		EBUG_ON(bio->bi_iter.bi_sector !=
			bkey_start_offset(&op->insert_key.k));
		EBUG_ON(bio_sectors(bio) !=
			((op->flags & BCH_WRITE_DATA_COMPRESSED)
			 ? op->crc.compressed_size
			 : op->insert_key.k.size));
		EBUG_ON(!bio_sectors(bio));

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
			if (unlikely(PTR_ERR(b) != -EAGAIN)) {
				ret = -EROFS;
				goto err;
			}

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

		ret = bch_write_extent(op, b, bkey_i_to_extent(k), bio);
		if (ret)
			goto err;

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
	struct bch_replace_info	replace;
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
	    rbio->crc.csum != bch_checksum_bio(src, rbio->crc.csum_type)) {
		cache_nonfatal_io_error(rbio->ca, "checksum error");
		return -EIO;
	}

	if (rbio->crc.compression_type != BCH_COMPRESSION_NONE) {
		ret = bio_uncompress(c, src, dst, dst_iter, rbio->crc);
	} else if (rbio->bounce) {
		bio_advance(src, rbio->crc.offset << 9);
		bio_copy_data_iter(dst, dst_iter,
				   src, src->bi_iter);
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

	bch_bio_free_pages_pool(op->iop.c, &op->bio.bio.bio);
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
		swap(promote->bio.bio.bio.bi_vcnt, rbio->bio.bi_vcnt);
		rbio->promote = NULL;

		bch_rbio_done(c, rbio);

		closure_init(cl, &c->cl);
		closure_call(&promote->iop.cl, bch_write, c->wq, cl);
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
			  struct extent_pick_ptr *pick, unsigned flags)
{
	struct bch_read_bio *rbio;
	struct cache_promote_op *promote_op = NULL;
	unsigned skip = iter.bi_sector - bkey_start_offset(k.k);
	bool bounce = false, split, read_full = false;

	EBUG_ON(bkey_start_offset(k.k) > iter.bi_sector ||
		k.k->p.offset < bvec_iter_end_sector(iter));

	/* only promote if we're not reading from the fastest tier: */
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
			struct bio *promote_bio = &promote_op->bio.bio.bio;

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
		struct bio *promote_bio = &promote_op->bio.bio.bio;

		promote_bio->bi_iter = rbio->bio.bi_iter;
		memcpy(promote_bio->bi_io_vec, rbio->bio.bi_io_vec,
		       sizeof(struct bio_vec) * rbio->bio.bi_vcnt);

		bch_replace_init(&promote_op->replace, k);
		bch_write_op_init(&promote_op->iop, c,
				  &promote_op->bio,
				  (struct disk_reservation) { 0 },
				  &c->promote_write_point, k,
				  &promote_op->replace.hook, NULL,
				  BCH_WRITE_ALLOC_NOWAIT);

		if (rbio->crc.compression_type) {
			promote_op->iop.flags |= BCH_WRITE_DATA_COMPRESSED;
			promote_op->iop.crc = rbio->crc;
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
			 * Adjust insert_key to correspond to what we're
			 * actually reading:
			 */
			bch_cut_front(POS(k.k->p.inode, iter.bi_sector),
				      &promote_op->iop.insert_key);
			bch_key_resize(&promote_op->iop.insert_key.k,
				       bvec_iter_sectors(iter));
		}

		promote_bio->bi_iter.bi_sector =
			bkey_start_offset(&promote_op->iop.insert_key.k);
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
