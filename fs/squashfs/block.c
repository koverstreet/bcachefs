// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * block.c
 */

/*
 * This file implements the low-level routines to read and decompress
 * datablocks and metadata blocks.
 */

#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/bio.h>

#include "squashfs_fs.h"
#include "squashfs_fs_sb.h"
#include "squashfs.h"
#include "decompressor.h"
#include "page_actor.h"

/*
 * Returns the amount of bytes copied to the page actor.
 */
static int copy_bio_to_actor(struct bio *bio,
			     struct squashfs_page_actor *actor,
			     int offset, int req_length)
{
	void *actor_addr;
	struct bvec_iter_all iter;
	struct bio_vec bvec;
	int copied_bytes = 0;
	int actor_offset = 0;
	int bytes_to_copy;

	squashfs_actor_nobuff(actor);
	actor_addr = squashfs_first_page(actor);

	bvec_iter_all_init(&iter);
	bio_iter_all_advance(bio, &iter, offset);

	while (copied_bytes < req_length &&
	       iter.idx < bio->bi_vcnt) {
		bvec = bio_iter_all_peek(bio, &iter);

		bytes_to_copy = min_t(int, bvec.bv_len,
					  PAGE_SIZE - actor_offset);

		bytes_to_copy = min_t(int, bytes_to_copy,
				      req_length - copied_bytes);
		if (!IS_ERR(actor_addr))
			memcpy(actor_addr + actor_offset, bvec_virt(&bvec),
			       bytes_to_copy);

		actor_offset += bytes_to_copy;
		copied_bytes += bytes_to_copy;

		if (actor_offset >= PAGE_SIZE) {
			actor_addr = squashfs_next_page(actor);
			if (!actor_addr)
				break;
			actor_offset = 0;
		}

		bio_iter_all_advance(bio, &iter, bytes_to_copy);
	}
	squashfs_finish_page(actor);
	return copied_bytes;
}

static int squashfs_bio_read(struct super_block *sb, u64 index, int length,
			     struct bio **biop, int *block_offset)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	const u64 read_start = round_down(index, msblk->devblksize);
	const sector_t block = read_start >> msblk->devblksize_log2;
	const u64 read_end = round_up(index + length, msblk->devblksize);
	const sector_t block_end = read_end >> msblk->devblksize_log2;
	int offset = read_start - round_down(index, PAGE_SIZE);
	int total_len = (block_end - block) << msblk->devblksize_log2;
	const int page_count = DIV_ROUND_UP(total_len + offset, PAGE_SIZE);
	int error, i;
	struct bio *bio;

	bio = bio_kmalloc(page_count, GFP_NOIO);
	if (!bio)
		return -ENOMEM;
	bio_init(bio, sb->s_bdev, bio->bi_inline_vecs, page_count, REQ_OP_READ);
	bio->bi_iter.bi_sector = block * (msblk->devblksize >> SECTOR_SHIFT);

	for (i = 0; i < page_count; ++i) {
		unsigned int len =
			min_t(unsigned int, PAGE_SIZE - offset, total_len);
		struct page *page = alloc_page(GFP_NOIO);

		if (!page) {
			error = -ENOMEM;
			goto out_free_bio;
		}
		if (!bio_add_page(bio, page, len, offset)) {
			error = -EIO;
			goto out_free_bio;
		}
		offset = 0;
		total_len -= len;
	}

	error = submit_bio_wait(bio);
	if (error)
		goto out_free_bio;

	*biop = bio;
	*block_offset = index & ((1 << msblk->devblksize_log2) - 1);
	return 0;

out_free_bio:
	bio_free_pages(bio);
	bio_uninit(bio);
	kfree(bio);
	return error;
}

/*
 * Read and decompress a metadata block or datablock.  Length is non-zero
 * if a datablock is being read (the size is stored elsewhere in the
 * filesystem), otherwise the length is obtained from the first two bytes of
 * the metadata block.  A bit in the length field indicates if the block
 * is stored uncompressed in the filesystem (usually because compression
 * generated a larger block - this does occasionally happen with compression
 * algorithms).
 */
int squashfs_read_data(struct super_block *sb, u64 index, int length,
		       u64 *next_index, struct squashfs_page_actor *output)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	struct bio *bio = NULL;
	int compressed;
	int res;
	int offset;

	if (length) {
		/*
		 * Datablock.
		 */
		compressed = SQUASHFS_COMPRESSED_BLOCK(length);
		length = SQUASHFS_COMPRESSED_SIZE_BLOCK(length);
		TRACE("Block @ 0x%llx, %scompressed size %d, src size %d\n",
			index, compressed ? "" : "un", length, output->length);
	} else {
		/*
		 * Metadata block.
		 */
		const u8 *data;
		struct bvec_iter_all iter;
		struct bio_vec bvec;

		bvec_iter_all_init(&iter);

		if (index + 2 > msblk->bytes_used) {
			res = -EIO;
			goto out;
		}
		res = squashfs_bio_read(sb, index, 2, &bio, &offset);
		if (res)
			goto out;

		bvec = bio_iter_all_peek(bio, &iter);

		if (WARN_ON_ONCE(!bvec.bv_len)) {
			res = -EIO;
			goto out_free_bio;
		}
		/* Extract the length of the metadata block */
		data = bvec_virt(&bvec);
		length = data[offset];
		if (offset < bvec.bv_len - 1) {
			length |= data[offset + 1] << 8;
		} else {
			bio_iter_all_advance(bio, &iter, bvec.bv_len);

			if (WARN_ON_ONCE(!bvec.bv_len)) {
				res = -EIO;
				goto out_free_bio;
			}
			data = bvec_virt(&bvec);
			length |= data[0] << 8;
		}
		bio_free_pages(bio);
		bio_uninit(bio);
		kfree(bio);

		compressed = SQUASHFS_COMPRESSED(length);
		length = SQUASHFS_COMPRESSED_SIZE(length);
		index += 2;

		TRACE("Block @ 0x%llx, %scompressed size %d\n", index - 2,
		      compressed ? "" : "un", length);
	}
	if (length < 0 || length > output->length ||
			(index + length) > msblk->bytes_used) {
		res = -EIO;
		goto out;
	}

	if (next_index)
		*next_index = index + length;

	res = squashfs_bio_read(sb, index, length, &bio, &offset);
	if (res)
		goto out;

	if (compressed) {
		if (!msblk->stream) {
			res = -EIO;
			goto out_free_bio;
		}
		res = msblk->thread_ops->decompress(msblk, bio, offset, length, output);
	} else {
		res = copy_bio_to_actor(bio, output, offset, length);
	}

out_free_bio:
	bio_free_pages(bio);
	bio_uninit(bio);
	kfree(bio);
out:
	if (res < 0) {
		ERROR("Failed to read block 0x%llx: %d\n", index, res);
		if (msblk->panic_on_errors)
			panic("squashfs read failed");
	}

	return res;
}
