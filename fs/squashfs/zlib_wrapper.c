// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * zlib_wrapper.c
 */


#include <linux/mutex.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/zlib.h>
#include <linux/vmalloc.h>

#include "squashfs_fs.h"
#include "squashfs_fs_sb.h"
#include "squashfs.h"
#include "decompressor.h"
#include "page_actor.h"

static void *zlib_init(struct squashfs_sb_info *dummy, void *buff)
{
	z_stream *stream = kmalloc(sizeof(z_stream), GFP_KERNEL);
	if (stream == NULL)
		goto failed;
	stream->workspace = vmalloc(zlib_inflate_workspacesize());
	if (stream->workspace == NULL)
		goto failed;

	return stream;

failed:
	ERROR("Failed to allocate zlib workspace\n");
	kfree(stream);
	return ERR_PTR(-ENOMEM);
}


static void zlib_free(void *strm)
{
	z_stream *stream = strm;

	if (stream)
		vfree(stream->workspace);
	kfree(stream);
}


static int zlib_uncompress(struct squashfs_sb_info *msblk, void *strm,
	struct bio *bio, int offset, int length,
	struct squashfs_page_actor *output)
{
	struct bvec_iter_all iter;
	int zlib_init = 0, error = 0;
	z_stream *stream = strm;

	stream->avail_out = PAGE_SIZE;
	stream->next_out = squashfs_first_page(output);
	stream->avail_in = 0;

	if (IS_ERR(stream->next_out)) {
		error = PTR_ERR(stream->next_out);
		goto finish;
	}

	bvec_iter_all_init(&iter);
	bio_iter_all_advance(bio, &iter, offset);

	for (;;) {
		int zlib_err;

		if (stream->avail_in == 0) {
			struct bio_vec bvec = bio_iter_all_peek(bio, &iter);
			int avail;

			if (iter.idx >= bio->bi_vcnt) {
				/* Z_STREAM_END must be reached. */
				error = -EIO;
				break;
			}

			avail = min_t(unsigned, length, bvec.bv_len);
			length -= avail;
			stream->next_in = bvec_virt(&bvec);
			stream->avail_in = avail;

			bio_iter_all_advance(bio, &iter, avail);
		}

		if (stream->avail_out == 0) {
			stream->next_out = squashfs_next_page(output);
			if (IS_ERR(stream->next_out)) {
				error = PTR_ERR(stream->next_out);
				break;
			} else if (stream->next_out != NULL)
				stream->avail_out = PAGE_SIZE;
		}

		if (!zlib_init) {
			zlib_err = zlib_inflateInit(stream);
			if (zlib_err != Z_OK) {
				error = -EIO;
				break;
			}
			zlib_init = 1;
		}

		zlib_err = zlib_inflate(stream, Z_SYNC_FLUSH);
		if (zlib_err == Z_STREAM_END)
			break;
		if (zlib_err != Z_OK) {
			error = -EIO;
			break;
		}
	}

finish:
	squashfs_finish_page(output);

	if (!error)
		if (zlib_inflateEnd(stream) != Z_OK)
			error = -EIO;

	return error ? error : stream->total_out;
}

const struct squashfs_decompressor squashfs_zlib_comp_ops = {
	.init = zlib_init,
	.free = zlib_free,
	.decompress = zlib_uncompress,
	.id = ZLIB_COMPRESSION,
	.name = "zlib",
	.alloc_buffer = 1,
	.supported = 1
};

