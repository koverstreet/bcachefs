#include "bcachefs.h"
#include "compress.h"
#include "extents.h"
#include "io.h"
#include "super-io.h"

#include "lz4.h"
#include <linux/lz4.h>
#include <linux/zlib.h>

/* Bounce buffer: */
struct bbuf {
	void		*b;
	enum {
		BB_NONE,
		BB_VMAP,
		BB_KMALLOC,
		BB_VMALLOC,
		BB_MEMPOOL,
	}		type;
	int		rw;
};

static struct bbuf __bounce_alloc(struct bch_fs *c, unsigned size, int rw)
{
	void *b;

	BUG_ON(size > c->sb.encoded_extent_max);

	b = kmalloc(size, GFP_NOIO|__GFP_NOWARN);
	if (b)
		return (struct bbuf) { .b = b, .type = BB_KMALLOC, .rw = rw };

	b = mempool_alloc(&c->compression_bounce[rw], GFP_NOWAIT);
	b = b ? page_address(b) : NULL;
	if (b)
		return (struct bbuf) { .b = b, .type = BB_MEMPOOL, .rw = rw };

	b = vmalloc(size);
	if (b)
		return (struct bbuf) { .b = b, .type = BB_VMALLOC, .rw = rw };

	b = mempool_alloc(&c->compression_bounce[rw], GFP_NOIO);
	b = b ? page_address(b) : NULL;
	if (b)
		return (struct bbuf) { .b = b, .type = BB_MEMPOOL, .rw = rw };

	BUG();
}

static struct bbuf __bio_map_or_bounce(struct bch_fs *c, struct bio *bio,
				       struct bvec_iter start, int rw)
{
	struct bbuf ret;
	struct bio_vec bv;
	struct bvec_iter iter;
	unsigned nr_pages = 0;
	struct page *stack_pages[16];
	struct page **pages = NULL;
	bool first = true;
	unsigned prev_end = PAGE_SIZE;
	void *data;

	BUG_ON(bvec_iter_sectors(start) > c->sb.encoded_extent_max);

#ifndef CONFIG_HIGHMEM
	__bio_for_each_contig_segment(bv, bio, iter, start) {
		if (bv.bv_len == start.bi_size)
			return (struct bbuf) {
				.b = page_address(bv.bv_page) + bv.bv_offset,
				.type = BB_NONE, .rw = rw
			};
	}
#endif
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

	if (data)
		return (struct bbuf) {
			.b = data + bio_iter_offset(bio, start),
			.type = BB_VMAP, .rw = rw
		};
bounce:
	ret = __bounce_alloc(c, start.bi_size, rw);

	if (rw == READ)
		memcpy_from_bio(ret.b, bio, start);

	return ret;
}

static struct bbuf bio_map_or_bounce(struct bch_fs *c, struct bio *bio, int rw)
{
	return __bio_map_or_bounce(c, bio, bio->bi_iter, rw);
}

static void bio_unmap_or_unbounce(struct bch_fs *c, struct bbuf buf)
{
	switch (buf.type) {
	case BB_NONE:
		break;
	case BB_VMAP:
		vunmap((void *) ((unsigned long) buf.b & PAGE_MASK));
		break;
	case BB_KMALLOC:
		kfree(buf.b);
		break;
	case BB_VMALLOC:
		vfree(buf.b);
		break;
	case BB_MEMPOOL:
		mempool_free(virt_to_page(buf.b),
			     &c->compression_bounce[buf.rw]);
		break;
	}
}

static inline void zlib_set_workspace(z_stream *strm, void *workspace)
{
#ifdef __KERNEL__
	strm->workspace = workspace;
#endif
}

static int __bio_uncompress(struct bch_fs *c, struct bio *src,
			    void *dst_data, struct bch_extent_crc128 crc)
{
	struct bbuf src_data = { NULL };
	size_t src_len = src->bi_iter.bi_size;
	size_t dst_len = crc_uncompressed_size(NULL, &crc) << 9;
	int ret;

	src_data = bio_map_or_bounce(c, src, READ);

	switch (crc.compression_type) {
	case BCH_COMPRESSION_LZ4_OLD:
		ret = bch2_lz4_decompress(src_data.b, &src_len,
				     dst_data, dst_len);
		if (ret) {
			ret = -EIO;
			goto err;
		}
		break;
	case BCH_COMPRESSION_LZ4:
		ret = LZ4_decompress_safe(src_data.b, dst_data,
					  src_len, dst_len);
		if (ret != dst_len) {
			ret = -EIO;
			goto err;
		}
		break;
	case BCH_COMPRESSION_GZIP: {
		void *workspace;
		z_stream strm;

		workspace = kmalloc(zlib_inflate_workspacesize(),
				    GFP_NOIO|__GFP_NOWARN);
		if (!workspace) {
			mutex_lock(&c->zlib_workspace_lock);
			workspace = c->zlib_workspace;
		}

		strm.next_in	= src_data.b;
		strm.avail_in	= src_len;
		strm.next_out	= dst_data;
		strm.avail_out	= dst_len;
		zlib_set_workspace(&strm, workspace);
		zlib_inflateInit2(&strm, -MAX_WBITS);

		ret = zlib_inflate(&strm, Z_FINISH);

		if (workspace == c->zlib_workspace)
			mutex_unlock(&c->zlib_workspace_lock);
		else
			kfree(workspace);

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
	bio_unmap_or_unbounce(c, src_data);
	return ret;
}

int bch2_bio_uncompress_inplace(struct bch_fs *c, struct bio *bio,
			       unsigned live_data_sectors,
			       struct bch_extent_crc128 crc)
{
	struct bbuf dst_data = { NULL };
	size_t dst_len = crc_uncompressed_size(NULL, &crc) << 9;
	int ret = -ENOMEM;

	BUG_ON(DIV_ROUND_UP(live_data_sectors, PAGE_SECTORS) > bio->bi_max_vecs);

	if (crc_uncompressed_size(NULL, &crc) > c->sb.encoded_extent_max ||
	    crc_compressed_size(NULL, &crc)   > c->sb.encoded_extent_max)
		return -EIO;

	dst_data = __bounce_alloc(c, dst_len, WRITE);

	ret = __bio_uncompress(c, bio, dst_data.b, crc);
	if (ret)
		goto err;

	while (bio->bi_vcnt < DIV_ROUND_UP(live_data_sectors, PAGE_SECTORS)) {
		struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt];

		bv->bv_page = alloc_page(GFP_NOIO);
		if (!bv->bv_page)
			goto use_mempool;

		bv->bv_len = PAGE_SIZE;
		bv->bv_offset = 0;
		bio->bi_vcnt++;
	}

	bio->bi_iter.bi_size = live_data_sectors << 9;
copy_data:
	memcpy_to_bio(bio, bio->bi_iter, dst_data.b + (crc.offset << 9));
err:
	bio_unmap_or_unbounce(c, dst_data);
	return ret;
use_mempool:
	/*
	 * We already allocated from mempool, we can't allocate from it again
	 * without freeing the pages we already allocated or else we could
	 * deadlock:
	 */

	bch2_bio_free_pages_pool(c, bio);
	bch2_bio_alloc_pages_pool(c, bio, live_data_sectors << 9);
	goto copy_data;
}

int bch2_bio_uncompress(struct bch_fs *c, struct bio *src,
		       struct bio *dst, struct bvec_iter dst_iter,
		       struct bch_extent_crc128 crc)
{
	struct bbuf dst_data = { NULL };
	size_t dst_len = crc_uncompressed_size(NULL, &crc) << 9;
	int ret = -ENOMEM;

	if (crc_uncompressed_size(NULL, &crc) < c->sb.encoded_extent_max)
		return -EIO;

	dst_data = dst_len == dst_iter.bi_size
		? __bio_map_or_bounce(c, dst, dst_iter, WRITE)
		: __bounce_alloc(c, dst_len, WRITE);

	ret = __bio_uncompress(c, src, dst_data.b, crc);
	if (ret)
		goto err;

	if (dst_data.type != BB_NONE)
		memcpy_to_bio(dst, dst_iter, dst_data.b + (crc.offset << 9));
err:
	bio_unmap_or_unbounce(c, dst_data);
	return ret;
}

static int __bio_compress(struct bch_fs *c,
			  struct bio *dst, size_t *dst_len,
			  struct bio *src, size_t *src_len,
			  unsigned *compression_type)
{
	struct bbuf src_data = { NULL }, dst_data = { NULL };
	unsigned pad;
	int ret;

	dst_data = bio_map_or_bounce(c, dst, WRITE);
	src_data = bio_map_or_bounce(c, src, READ);

	switch (*compression_type) {
	case BCH_COMPRESSION_LZ4_OLD:
		*compression_type = BCH_COMPRESSION_LZ4;

	case BCH_COMPRESSION_LZ4: {
		void *workspace;
		int len = src->bi_iter.bi_size;

		ret = 0;

		workspace = mempool_alloc(&c->lz4_workspace_pool, GFP_NOIO);

		while (len > block_bytes(c) &&
		       (!(ret = LZ4_compress_destSize(
					src_data.b,	dst_data.b,
					&len,		dst->bi_iter.bi_size,
					workspace)) ||
			(len & (block_bytes(c) - 1)))) {
			/*
			 * On error, the compressed data was bigger than
			 * dst_len - round down to nearest block and try again:
			 */
			len = round_down(len, block_bytes(c));
		}

		mempool_free(workspace, &c->lz4_workspace_pool);

		if (!ret)
			goto err;

		*src_len = len;
		*dst_len = ret;
		break;
	}
	case BCH_COMPRESSION_GZIP: {
		void *workspace;
		z_stream strm;

		workspace = kmalloc(zlib_deflate_workspacesize(MAX_WBITS,
							       DEF_MEM_LEVEL),
				    GFP_NOIO|__GFP_NOWARN);
		if (!workspace) {
			mutex_lock(&c->zlib_workspace_lock);
			workspace = c->zlib_workspace;
		}

		strm.next_in	= src_data.b;
		strm.avail_in	= min(src->bi_iter.bi_size,
				      dst->bi_iter.bi_size);
		strm.next_out	= dst_data.b;
		strm.avail_out	= dst->bi_iter.bi_size;
		zlib_set_workspace(&strm, workspace);
		zlib_deflateInit2(&strm, Z_DEFAULT_COMPRESSION,
				  Z_DEFLATED, -MAX_WBITS, DEF_MEM_LEVEL,
				  Z_DEFAULT_STRATEGY);

		ret = zlib_deflate(&strm, Z_FINISH);
		if (ret != Z_STREAM_END) {
			ret = -EIO;
			goto zlib_err;
		}

		ret = zlib_deflateEnd(&strm);
		if (ret != Z_OK) {
			ret = -EIO;
			goto zlib_err;
		}

		ret = 0;
zlib_err:
		if (workspace == c->zlib_workspace)
			mutex_unlock(&c->zlib_workspace_lock);
		else
			kfree(workspace);

		if (ret)
			goto err;

		*dst_len = strm.total_out;
		*src_len = strm.total_in;
		break;
	}
	default:
		BUG();
	}

	/* Didn't get smaller: */
	if (round_up(*dst_len, block_bytes(c)) >= *src_len)
		goto err;

	pad = round_up(*dst_len, block_bytes(c)) - *dst_len;

	memset(dst_data.b + *dst_len, 0, pad);
	*dst_len += pad;

	if (dst_data.type != BB_NONE)
		memcpy_to_bio(dst, dst->bi_iter, dst_data.b);
out:
	bio_unmap_or_unbounce(c, src_data);
	bio_unmap_or_unbounce(c, dst_data);
	return ret;
err:
	ret = -1;
	goto out;
}

void bch2_bio_compress(struct bch_fs *c,
		       struct bio *dst, size_t *dst_len,
		       struct bio *src, size_t *src_len,
		       unsigned *compression_type)
{
	unsigned orig_dst = dst->bi_iter.bi_size;
	unsigned orig_src = src->bi_iter.bi_size;

	/* Don't consume more than BCH_ENCODED_EXTENT_MAX from @src: */
	src->bi_iter.bi_size = min_t(unsigned, src->bi_iter.bi_size,
				     c->sb.encoded_extent_max << 9);

	/* Don't generate a bigger output than input: */
	dst->bi_iter.bi_size =
		min(dst->bi_iter.bi_size, src->bi_iter.bi_size);

	/* If it's only one block, don't bother trying to compress: */
	if (*compression_type != BCH_COMPRESSION_NONE &&
	    bio_sectors(src) > c->opts.block_size &&
	    !__bio_compress(c, dst, dst_len, src, src_len, compression_type))
		goto out;

	/* If compressing failed (didn't get smaller), just copy: */
	*compression_type = BCH_COMPRESSION_NONE;
	*dst_len = *src_len = min(dst->bi_iter.bi_size, src->bi_iter.bi_size);
	bio_copy_data(dst, src);
out:
	dst->bi_iter.bi_size = orig_dst;
	src->bi_iter.bi_size = orig_src;

	BUG_ON(!*dst_len || *dst_len > dst->bi_iter.bi_size);
	BUG_ON(!*src_len || *src_len > src->bi_iter.bi_size);
	BUG_ON(*dst_len & (block_bytes(c) - 1));
	BUG_ON(*src_len & (block_bytes(c) - 1));
}

/* doesn't write superblock: */
int bch2_check_set_has_compressed_data(struct bch_fs *c,
				      unsigned compression_type)
{
	switch (compression_type) {
	case BCH_COMPRESSION_OPT_NONE:
		return 0;
	case BCH_COMPRESSION_OPT_LZ4:
		if (bch2_sb_test_feature(c->disk_sb, BCH_FEATURE_LZ4))
			return 0;

		bch2_sb_set_feature(c->disk_sb, BCH_FEATURE_LZ4);
		break;
	case BCH_COMPRESSION_OPT_GZIP:
		if (bch2_sb_test_feature(c->disk_sb, BCH_FEATURE_GZIP))
			return 0;

		bch2_sb_set_feature(c->disk_sb, BCH_FEATURE_GZIP);
		break;
	default:
		BUG();
	}

	return bch2_fs_compress_init(c);
}

void bch2_fs_compress_exit(struct bch_fs *c)
{
	vfree(c->zlib_workspace);
	mempool_exit(&c->lz4_workspace_pool);
	mempool_exit(&c->compression_bounce[WRITE]);
	mempool_exit(&c->compression_bounce[READ]);
}

#define COMPRESSION_WORKSPACE_SIZE					\
	max_t(size_t, zlib_inflate_workspacesize(),			\
	      zlib_deflate_workspacesize(MAX_WBITS, DEF_MEM_LEVEL))

int bch2_fs_compress_init(struct bch_fs *c)
{
	unsigned order = get_order(c->sb.encoded_extent_max << 9);
	int ret;

	if (!bch2_sb_test_feature(c->disk_sb, BCH_FEATURE_LZ4) &&
	    !bch2_sb_test_feature(c->disk_sb, BCH_FEATURE_GZIP))
		return 0;

	if (!mempool_initialized(&c->compression_bounce[READ])) {
		ret = mempool_init_page_pool(&c->compression_bounce[READ],
					     1, order);
		if (ret)
			return ret;
	}

	if (!mempool_initialized(&c->compression_bounce[WRITE])) {
		ret = mempool_init_page_pool(&c->compression_bounce[WRITE],
					     1, order);
		if (ret)
			return ret;
	}

	if (!mempool_initialized(&c->lz4_workspace_pool) &&
	    bch2_sb_test_feature(c->disk_sb, BCH_FEATURE_LZ4)) {
		ret = mempool_init_kmalloc_pool(&c->lz4_workspace_pool,
						1, LZ4_MEM_COMPRESS);
		if (ret)
			return ret;
	}

	if (!c->zlib_workspace &&
	    bch2_sb_test_feature(c->disk_sb, BCH_FEATURE_GZIP)) {
		c->zlib_workspace = vmalloc(COMPRESSION_WORKSPACE_SIZE);
		if (!c->zlib_workspace)
			return -ENOMEM;
	}

	return 0;
}
