// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "data/checksum.h"
#include "data/compress.h"
#include "data/extents.h"
#include "data/write.h"

#include "sb/io.h"

#include "init/error.h"

#include <linux/lz4.h>
#include <linux/zlib.h>
#include <linux/zstd.h>

static inline enum bch_compression_opts bch2_compression_type_to_opt(enum bch_compression_type type)
{
	switch (type) {
	case BCH_COMPRESSION_TYPE_none:
	case BCH_COMPRESSION_TYPE_incompressible:
		return BCH_COMPRESSION_OPT_none;
	case BCH_COMPRESSION_TYPE_lz4_old:
	case BCH_COMPRESSION_TYPE_lz4:
		return BCH_COMPRESSION_OPT_lz4;
	case BCH_COMPRESSION_TYPE_gzip:
		return BCH_COMPRESSION_OPT_gzip;
	case BCH_COMPRESSION_TYPE_zstd:
		return BCH_COMPRESSION_OPT_zstd;
	default:
		BUG();
	}
}

/* Bounce buffer: */
struct bbuf {
	struct bch_fs	*c;
	void		*b;
	enum bbuf_type {
		BB_none,
		BB_vmap,
		BB_kmalloc,
		BB_mempool,
	}		type;
	int		rw;
};

static void bbuf_exit(struct bbuf *buf)
{
	switch (buf->type) {
	case BB_none:
		break;
	case BB_vmap:
		vunmap((void *) ((unsigned long) buf->b & PAGE_MASK));
		break;
	case BB_kmalloc:
		kfree(buf->b);
		break;
	case BB_mempool:
		mempool_free(buf->b, &buf->c->compress.bounce[buf->rw]);
		break;
	}
}

static struct bbuf __bounce_alloc(struct bch_fs *c, unsigned size, int rw)
{
	void *b;

	BUG_ON(size > c->opts.encoded_extent_max);

	b = kmalloc(size, GFP_NOFS|__GFP_NOWARN);
	if (b)
		return (struct bbuf) { .c = c, .b = b, .type = BB_kmalloc, .rw = rw };

	b = mempool_alloc(&c->compress.bounce[rw], GFP_NOFS);
	if (b)
		return (struct bbuf) { .c = c, .b = b, .type = BB_mempool, .rw = rw };

	BUG();
}

static struct bbuf bio_bounce(struct bch_fs *c, struct bio *bio, struct bvec_iter start, int rw)
{
	struct bbuf ret = __bounce_alloc(c, start.bi_size, rw);

	if (rw == READ)
		memcpy_from_bio(ret.b, bio, start);
	return ret;
}

static bool bio_phys_contig(struct bio *bio, struct bvec_iter start)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *expected_start = NULL;

	__bio_for_each_bvec(bv, bio, iter, start) {
		void *bv_addr = bvec_virt(&bv);

		if (expected_start && expected_start != bv_addr)
			return false;

		expected_start = bv_addr + bv.bv_len;
	}

	return true;
}

static struct bbuf __bio_map_or_bounce(struct bch_fs *c, struct bio *bio,
				       struct bvec_iter start, int rw)
{
	BUG_ON(start.bi_size > c->opts.encoded_extent_max);

#ifndef CONFIG_HIGHMEM
	if (bio_phys_contig(bio, start))
		return (struct bbuf) {
			.c	= c,
			.b	= bvec_virt(&bio_iter_iovec(bio, start)),
			.type	= BB_none,
			.rw	= rw
		};
#endif

#ifdef __KERNEL__
	/* check if we can map the pages contiguously: */
	struct bio_vec bv;
	struct bvec_iter iter;
	unsigned nr_pages = 0;

	__bio_for_each_segment(bv, bio, iter, start) {
		BUG_ON(bv.bv_offset + bv.bv_len > PAGE_SIZE);

		if (iter.bi_size != start.bi_size &&
		    bv.bv_offset)
			return bio_bounce(c, bio, start, rw);

		if (bv.bv_len < iter.bi_size &&
		    bv.bv_offset + bv.bv_len < PAGE_SIZE)
			return bio_bounce(c, bio, start, rw);

		nr_pages++;
	}

	BUG_ON(DIV_ROUND_UP(start.bi_size, PAGE_SIZE) > nr_pages);

	struct page *stack_pages[16];
	struct page **pages = nr_pages > ARRAY_SIZE(stack_pages)
		? kmalloc_array(nr_pages, sizeof(struct page *), GFP_NOFS)
		: stack_pages;
	if (!pages)
		return bio_bounce(c, bio, start, rw);

	nr_pages = 0;
	__bio_for_each_segment(bv, bio, iter, start)
		pages[nr_pages++] = bv.bv_page;

	void *data = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (pages != stack_pages)
		kfree(pages);

	if (data)
		return (struct bbuf) {
			c,
			data + bio_iter_offset(bio, start),
			BB_vmap,
			rw
		};
#endif /* __KERNEL__ */

	return bio_bounce(c, bio, start, rw);
}

static struct bbuf bio_map_or_bounce(struct bch_fs *c, struct bio *bio, int rw)
{
	return __bio_map_or_bounce(c, bio, bio->bi_iter, rw);
}

static inline void zlib_set_workspace(z_stream *strm, void *workspace)
{
#ifdef __KERNEL__
	strm->workspace = workspace;
#endif
}

static int __bio_uncompress(struct bch_fs *c, struct bio *src,
			    void *dst_data, struct bch_extent_crc_unpacked crc)
{
	size_t src_len = src->bi_iter.bi_size;
	size_t dst_len = crc.uncompressed_size << 9;
	void *workspace;
	int ret2;

	enum bch_compression_opts opt = bch2_compression_type_to_opt(crc.compression_type);
	mempool_t *workspace_pool = &c->compress.workspace[opt];
	if (unlikely(!mempool_initialized(workspace_pool))) {
		if (ret_fsck_err(c, compression_type_not_marked_in_sb,
			     "compression type %s set but not marked in superblock",
			     __bch2_compression_types[crc.compression_type]))
			try(bch2_check_set_has_compressed_data(c, opt));
		else
			return bch_err_throw(c, compression_workspace_not_initialized);
	}

	struct bbuf src_data __cleanup(bbuf_exit) = bio_map_or_bounce(c, src, READ);

	switch (crc.compression_type) {
	case BCH_COMPRESSION_TYPE_lz4_old:
	case BCH_COMPRESSION_TYPE_lz4:
		ret2 = LZ4_decompress_safe_partial(src_data.b, dst_data,
						   src_len, dst_len, dst_len);
		if (ret2 != dst_len)
			return bch_err_throw(c, decompress_lz4);
		break;
	case BCH_COMPRESSION_TYPE_gzip: {
		z_stream strm = {
			.next_in	= src_data.b,
			.avail_in	= src_len,
			.next_out	= dst_data,
			.avail_out	= dst_len,
		};

		workspace = mempool_alloc(workspace_pool, GFP_NOFS);

		zlib_set_workspace(&strm, workspace);
		zlib_inflateInit2(&strm, -MAX_WBITS);
		ret2 = zlib_inflate(&strm, Z_FINISH);

		mempool_free(workspace, workspace_pool);

		if (ret2 != Z_STREAM_END)
			return bch_err_throw(c, decompress_gzip);
		break;
	}
	case BCH_COMPRESSION_TYPE_zstd: {
		ZSTD_DCtx *ctx;
		size_t real_src_len = le32_to_cpup(src_data.b);

		if (real_src_len > src_len - 4)
			return bch_err_throw(c, decompress_zstd_src_len_bad);

		workspace = mempool_alloc(workspace_pool, GFP_NOFS);
		ctx = zstd_init_dctx(workspace, zstd_dctx_workspace_bound());

		ret2 = zstd_decompress_dctx(ctx,
				dst_data,	dst_len,
				src_data.b + 4, real_src_len);

		mempool_free(workspace, workspace_pool);

		if (ret2 != dst_len)
			return bch_err_throw(c, decompress_zstd);
		break;
	}
	default:
		BUG();
	}

	return 0;
}

int bch2_bio_uncompress_inplace(struct bch_write_op *op,
				struct bio *bio)
{
	struct bch_fs *c = op->c;
	struct bch_extent_crc_unpacked *crc = &op->crc;
	size_t dst_len = crc->uncompressed_size << 9;

	/* bio must own its pages: */
	BUG_ON(!bio->bi_vcnt);
	BUG_ON(DIV_ROUND_UP(crc->live_size, PAGE_SECTORS) > bio->bi_max_vecs);

	if (crc->uncompressed_size << 9	> c->opts.encoded_extent_max) {
		bch2_write_op_error(op, false, op->pos.offset,
				    "extent too big to decompress (%u > %u)",
				    crc->uncompressed_size << 9, c->opts.encoded_extent_max);
		return bch_err_throw(c, decompress_exceeded_max_encoded_extent);
	}

	struct bbuf data __cleanup(bbuf_exit) = __bounce_alloc(c, dst_len, WRITE);

	int ret = __bio_uncompress(c, bio, data.b, *crc);
	if (c->opts.no_data_io)
		ret = 0;
	if (ret) {
		bch2_write_op_error(op, false, op->pos.offset, "%s", bch2_err_str(ret));
		return ret;
	}

	/*
	 * XXX: don't have a good way to assert that the bio was allocated with
	 * enough space, we depend on bch2_move_extent doing the right thing
	 */
	bio->bi_iter.bi_size = crc->live_size << 9;

	memcpy_to_bio(bio, bio->bi_iter, data.b + (crc->offset << 9));

	crc->csum_type		= 0;
	crc->compression_type	= 0;
	crc->compressed_size	= crc->live_size;
	crc->uncompressed_size	= crc->live_size;
	crc->offset		= 0;
	crc->csum		= (struct bch_csum) { 0, 0 };
	return 0;
}

int bch2_bio_uncompress(struct bch_fs *c, struct bio *src,
		       struct bio *dst, struct bvec_iter dst_iter,
		       struct bch_extent_crc_unpacked crc)
{
	size_t dst_len = crc.uncompressed_size << 9;

	if (crc.uncompressed_size << 9	> c->opts.encoded_extent_max ||
	    crc.compressed_size << 9	> c->opts.encoded_extent_max)
		return bch_err_throw(c, decompress_exceeded_max_encoded_extent);

	struct bbuf dst_data __cleanup(bbuf_exit) = dst_len == dst_iter.bi_size
		? __bio_map_or_bounce(c, dst, dst_iter, WRITE)
		: __bounce_alloc(c, dst_len, WRITE);

	try(__bio_uncompress(c, src, dst_data.b, crc));

	if (dst_data.type != BB_none &&
	    dst_data.type != BB_vmap)
		memcpy_to_bio(dst, dst_iter, dst_data.b + (crc.offset << 9));
	return 0;
}

static int attempt_compress(struct bch_fs *c,
			    void *workspace,
			    void *dst, size_t dst_len,
			    void *src, size_t src_len,
			    union bch_compression_opt compression)
{
	enum bch_compression_type compression_type =
		__bch2_compression_opt_to_type[compression.type];

	switch (compression_type) {
	case BCH_COMPRESSION_TYPE_lz4:
		if (compression.level < LZ4HC_MIN_CLEVEL) {
			int len = src_len;
			int ret = LZ4_compress_destSize(
					src,		dst,
					&len,		dst_len,
					workspace);
			if (len < src_len)
				return -len;

			return ret;
		} else {
			int ret = LZ4_compress_HC(
					src,		dst,
					src_len,	dst_len,
					compression.level,
					workspace);

			return ret ?: -1;
		}
	case BCH_COMPRESSION_TYPE_gzip: {
		z_stream strm = {
			.next_in	= src,
			.avail_in	= src_len,
			.next_out	= dst,
			.avail_out	= dst_len,
		};

		zlib_set_workspace(&strm, workspace);
		if (zlib_deflateInit2(&strm,
				  compression.level
				  ? clamp_t(unsigned, compression.level,
					    Z_BEST_SPEED, Z_BEST_COMPRESSION)
				  : Z_DEFAULT_COMPRESSION,
				  Z_DEFLATED, -MAX_WBITS, DEF_MEM_LEVEL,
				  Z_DEFAULT_STRATEGY) != Z_OK)
			return 0;

		if (zlib_deflate(&strm, Z_FINISH) != Z_STREAM_END)
			return 0;

		if (zlib_deflateEnd(&strm) != Z_OK)
			return 0;

		return strm.total_out;
	}
	case BCH_COMPRESSION_TYPE_zstd: {
		/*
		 * rescale:
		 * zstd max compression level is 22, our max level is 15
		 */
		unsigned level = min((compression.level * 3) / 2, zstd_max_clevel());
		ZSTD_parameters params = zstd_get_params(level, c->opts.encoded_extent_max);
		ZSTD_CCtx *ctx = zstd_init_cctx(workspace, c->compress.zstd_workspace_size);

		/*
		 * ZSTD requires that when we decompress we pass in the exact
		 * compressed size - rounding it up to the nearest sector
		 * doesn't work, so we use the first 4 bytes of the buffer for
		 * that.
		 *
		 * Additionally, the ZSTD code seems to have a bug where it will
		 * write just past the end of the buffer - so subtract a fudge
		 * factor (7 bytes) from the dst buffer size to account for
		 * that.
		 */
		size_t len = zstd_compress_cctx(ctx,
				dst + 4,	dst_len - 4 - 7,
				src,		src_len,
				&params);
		if (zstd_is_error(len))
			return 0;

		*((__le32 *) dst) = cpu_to_le32(len);
		return len + 4;
	}
	default:
		BUG();
	}
}

static unsigned __bio_compress(struct bch_fs *c,
			       struct bio *dst, size_t *dst_len,
			       struct bio *src, size_t *src_len,
			       union bch_compression_opt compression)
{
	enum bch_compression_type compression_type =
		__bch2_compression_opt_to_type[compression.type];
	int ret = 0;

	/* bch2_compression_decode catches unknown compression types: */
	BUG_ON(compression.type >= BCH_COMPRESSION_OPT_NR);

	mempool_t *workspace_pool = &c->compress.workspace[compression.type];
	if (unlikely(!mempool_initialized(workspace_pool))) {
		if (ret_fsck_err(c, compression_opt_not_marked_in_sb,
			     "compression opt %s set but not marked in superblock",
			     bch2_compression_opts[compression.type])) {
			ret = bch2_check_set_has_compressed_data(c, compression.type);
			if (ret) /* memory allocation failure, don't compress */
				return 0;
		} else {
			return 0;
		}
	}

	/* If it's only one block, don't bother trying to compress: */
	if (src->bi_iter.bi_size <= c->opts.block_size)
		return BCH_COMPRESSION_TYPE_incompressible;

	struct bbuf dst_data __cleanup(bbuf_exit) = bio_map_or_bounce(c, dst, WRITE);
	struct bbuf src_data __cleanup(bbuf_exit) = bio_map_or_bounce(c, src, READ);

	void *workspace = mempool_alloc(workspace_pool, GFP_NOFS);

	*src_len = src->bi_iter.bi_size;
	*dst_len = dst->bi_iter.bi_size;

	/*
	 * XXX: this algorithm sucks when the compression code doesn't tell us
	 * how much would fit, like LZ4 does:
	 */
	while (1) {
		if (*src_len <= block_bytes(c)) {
			ret = -1;
			break;
		}

		ret = attempt_compress(c, workspace,
				       dst_data.b,	*dst_len,
				       src_data.b,	*src_len,
				       compression);
		if (ret > 0) {
			*dst_len = ret;
			ret = 0;
			break;
		}

		/* Didn't fit: should we retry with a smaller amount?  */
		if (*src_len <= *dst_len) {
			ret = -1;
			break;
		}

		/*
		 * If ret is negative, it's a hint as to how much data would fit
		 */
		BUG_ON(-ret >= *src_len);

		if (ret < 0)
			*src_len = -ret;
		else
			*src_len -= (*src_len - *dst_len) / 2;
		*src_len = round_down(*src_len, block_bytes(c));
	}

	mempool_free(workspace, workspace_pool);

	if (ret)
		return BCH_COMPRESSION_TYPE_incompressible;

	/* Didn't get smaller: */
	if (round_up(*dst_len, block_bytes(c)) >= *src_len)
		return BCH_COMPRESSION_TYPE_incompressible;

	unsigned pad = round_up(*dst_len, block_bytes(c)) - *dst_len;

	memset(dst_data.b + *dst_len, 0, pad);
	*dst_len += pad;

	if (dst_data.type != BB_none &&
	    dst_data.type != BB_vmap)
		memcpy_to_bio(dst, dst->bi_iter, dst_data.b);

	BUG_ON(!*dst_len || *dst_len > dst->bi_iter.bi_size);
	BUG_ON(!*src_len || *src_len > src->bi_iter.bi_size);
	BUG_ON(*dst_len & (block_bytes(c) - 1));
	BUG_ON(*src_len & (block_bytes(c) - 1));
	return compression_type;
}

unsigned bch2_bio_compress(struct bch_fs *c,
			   struct bio *dst, size_t *dst_len,
			   struct bio *src, size_t *src_len,
			   unsigned compression_opt)
{
	unsigned orig_dst = dst->bi_iter.bi_size;
	unsigned orig_src = src->bi_iter.bi_size;
	unsigned compression_type;

	/* Don't consume more than BCH_ENCODED_EXTENT_MAX from @src: */
	src->bi_iter.bi_size = min_t(unsigned, src->bi_iter.bi_size,
				     c->opts.encoded_extent_max);
	/* Don't generate a bigger output than input: */
	dst->bi_iter.bi_size = min(dst->bi_iter.bi_size, src->bi_iter.bi_size);

	compression_type =
		__bio_compress(c, dst, dst_len, src, src_len,
			       (union bch_compression_opt){ .value = compression_opt });

	dst->bi_iter.bi_size = orig_dst;
	src->bi_iter.bi_size = orig_src;
	return compression_type;
}

static int __bch2_fs_compress_init(struct bch_fs *, u64);

#define BCH_FEATURE_none	0

static const unsigned bch2_compression_opt_to_feature[] = {
#define x(t, n) [BCH_COMPRESSION_OPT_##t] = BCH_FEATURE_##t,
	BCH_COMPRESSION_OPTS()
#undef x
};

#undef BCH_FEATURE_none

static int __bch2_check_set_has_compressed_data(struct bch_fs *c, u64 f)
{
	if ((c->sb.features & f) == f)
		return 0;

	guard(mutex)(&c->sb_lock);

	if ((c->sb.features & f) == f)
		return 0;

	try(__bch2_fs_compress_init(c, c->sb.features|f));

	c->disk_sb.sb->features[0] |= cpu_to_le64(f);
	bch2_write_super(c);
	return 0;
}

int bch2_check_set_has_compressed_data(struct bch_fs *c,
				       unsigned compression_opt)
{
	unsigned int compression_type = ((union bch_compression_opt){ .value = compression_opt })
					.type;

	BUG_ON(compression_type >= ARRAY_SIZE(bch2_compression_opt_to_feature));

	return compression_type
		? __bch2_check_set_has_compressed_data(c,
				1ULL << bch2_compression_opt_to_feature[compression_type])
		: 0;
}

void bch2_fs_compress_exit(struct bch_fs *c)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(c->compress.workspace); i++)
		mempool_exit(&c->compress.workspace[i]);
	mempool_exit(&c->compress.bounce[WRITE]);
	mempool_exit(&c->compress.bounce[READ]);
}

static int __bch2_fs_compress_init(struct bch_fs *c, u64 features)
{
	ZSTD_parameters params = zstd_get_params(zstd_max_clevel(),
						 c->opts.encoded_extent_max);

	c->compress.zstd_workspace_size = zstd_cctx_workspace_bound(&params.cParams);

	struct {
		unsigned			feature;
		enum bch_compression_opts	type;
		size_t				compress_workspace;
	} compression_types[] = {
		{ BCH_FEATURE_lz4, BCH_COMPRESSION_OPT_lz4,
			max_t(size_t, LZ4_MEM_COMPRESS, LZ4HC_MEM_COMPRESS) },
		{ BCH_FEATURE_gzip, BCH_COMPRESSION_OPT_gzip,
			max(zlib_deflate_workspacesize(MAX_WBITS, DEF_MEM_LEVEL),
			    zlib_inflate_workspacesize()) },
		{ BCH_FEATURE_zstd, BCH_COMPRESSION_OPT_zstd,
			max(c->compress.zstd_workspace_size,
			    zstd_dctx_workspace_bound()) },
	}, *i;
	bool have_compressed = false;

	for (i = compression_types;
	     i < compression_types + ARRAY_SIZE(compression_types);
	     i++)
		have_compressed |= (features & (1 << i->feature)) != 0;

	if (!have_compressed)
		return 0;

	if (!mempool_initialized(&c->compress.bounce[READ]) &&
	    mempool_init_kvmalloc_pool(&c->compress.bounce[READ],
				       1, c->opts.encoded_extent_max))
		return bch_err_throw(c, ENOMEM_compression_bounce_read_init);

	if (!mempool_initialized(&c->compress.bounce[WRITE]) &&
	    mempool_init_kvmalloc_pool(&c->compress.bounce[WRITE],
				       1, c->opts.encoded_extent_max))
		return bch_err_throw(c, ENOMEM_compression_bounce_write_init);

	for (i = compression_types;
	     i < compression_types + ARRAY_SIZE(compression_types);
	     i++) {
		if (!(features & (1 << i->feature)))
			continue;

		if (mempool_initialized(&c->compress.workspace[i->type]))
			continue;

		if (mempool_init_kvmalloc_pool(
				&c->compress.workspace[i->type],
				1, i->compress_workspace))
			return bch_err_throw(c, ENOMEM_compression_workspace_init);
	}

	return 0;
}

static u64 compression_opt_to_feature(unsigned v)
{
	unsigned int type = ((union bch_compression_opt){ .value = v }).type;

	return BIT_ULL(bch2_compression_opt_to_feature[type]);
}

int bch2_fs_compress_init(struct bch_fs *c)
{
	u64 f = c->sb.features;

	f |= compression_opt_to_feature(c->opts.compression);
	f |= compression_opt_to_feature(c->opts.background_compression);

	return __bch2_fs_compress_init(c, f);
}

int bch2_opt_compression_parse(struct bch_fs *c, const char *_val, u64 *res,
			       struct printbuf *err)
{
	char *val __free(kfree) = kstrdup(_val, GFP_KERNEL);
	char *p = val, *type_str, *level_str;
	union bch_compression_opt opt = { 0 };

	if (!val)
		return -ENOMEM;

	type_str = strsep(&p, ":");
	level_str = p;

	int ret = match_string(bch2_compression_opts, -1, type_str);
	if (ret < 0 && err)
		prt_printf(err, "invalid compression type\n");
	if (ret < 0)
		return ret;

	opt.type = ret;

	if (level_str) {
		unsigned level;

		ret = kstrtouint(level_str, 10, &level);
		if (!ret && !opt.type && level)
			ret = -EINVAL;
		if (!ret && level > 15)
			ret = -EINVAL;
		if (ret < 0 && err)
			prt_printf(err, "invalid compression level\n");
		if (ret < 0)
			return ret;

		opt.level = level;
	}

	*res = opt.value;
	return 0;
}

void bch2_compression_opt_to_text(struct printbuf *out, u64 v)
{
	union bch_compression_opt opt = { .value = v };

	if (opt.type < BCH_COMPRESSION_OPT_NR)
		prt_str(out, bch2_compression_opts[opt.type]);
	else
		prt_printf(out, "(unknown compression opt %u)", opt.type);
	if (opt.level)
		prt_printf(out, ":%u", opt.level);
}

void bch2_opt_compression_to_text(struct printbuf *out,
				  struct bch_fs *c,
				  struct bch_sb *sb,
				  u64 v)
{
	return bch2_compression_opt_to_text(out, v);
}

int bch2_opt_compression_validate(u64 v, struct printbuf *err)
{
	if (!bch2_compression_opt_valid(v)) {
		prt_printf(err, "invalid compression opt %llu", v);
		return -BCH_ERR_invalid_sb_opt_compression;
	}

	return 0;
}
