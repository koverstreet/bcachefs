// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 */

#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/radix-tree.h>
#include <linux/writeback.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/migrate.h>
#include <linux/ratelimit.h>
#include <linux/uuid.h>
#include <linux/semaphore.h>
#include <linux/error-injection.h>
#include <linux/crc32c.h>
#include <linux/sched/mm.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>
#include "ctree.h"
#include "disk-io.h"
#include "transaction.h"
#include "btrfs_inode.h"
#include "bio.h"
#include "print-tree.h"
#include "locking.h"
#include "tree-log.h"
#include "free-space-cache.h"
#include "free-space-tree.h"
#include "check-integrity.h"
#include "rcu-string.h"
#include "dev-replace.h"
#include "raid56.h"
#include "sysfs.h"
#include "qgroup.h"
#include "compression.h"
#include "tree-checker.h"
#include "ref-verify.h"
#include "block-group.h"
#include "discard.h"
#include "space-info.h"
#include "zoned.h"
#include "subpage.h"
#include "fs.h"
#include "accessors.h"
#include "extent-tree.h"
#include "root-tree.h"
#include "defrag.h"
#include "uuid-tree.h"
#include "relocation.h"
#include "scrub.h"
#include "super.h"

#define BTRFS_SUPER_FLAG_SUPP	(BTRFS_HEADER_FLAG_WRITTEN |\
				 BTRFS_HEADER_FLAG_RELOC |\
				 BTRFS_SUPER_FLAG_ERROR |\
				 BTRFS_SUPER_FLAG_SEEDING |\
				 BTRFS_SUPER_FLAG_METADUMP |\
				 BTRFS_SUPER_FLAG_METADUMP_V2)

static void btrfs_destroy_ordered_extents(struct btrfs_root *root);
static int btrfs_destroy_delayed_refs(struct btrfs_transaction *trans,
				      struct btrfs_fs_info *fs_info);
static void btrfs_destroy_delalloc_inodes(struct btrfs_root *root);
static int btrfs_destroy_marked_extents(struct btrfs_fs_info *fs_info,
					struct extent_io_tree *dirty_pages,
					int mark);
static int btrfs_destroy_pinned_extent(struct btrfs_fs_info *fs_info,
				       struct extent_io_tree *pinned_extents);
static int btrfs_cleanup_transaction(struct btrfs_fs_info *fs_info);
static void btrfs_error_commit_super(struct btrfs_fs_info *fs_info);

static void btrfs_free_csum_hash(struct btrfs_fs_info *fs_info)
{
	if (fs_info->csum_shash)
		crypto_free_shash(fs_info->csum_shash);
}

/*
 * async submit bios are used to offload expensive checksumming
 * onto the worker threads.  They checksum file and metadata bios
 * just before they are sent down the IO stack.
 */
struct async_submit_bio {
	struct btrfs_inode *inode;
	struct bio *bio;
	enum btrfs_wq_submit_cmd submit_cmd;
	int mirror_num;

	/* Optional parameter for used by direct io */
	u64 dio_file_offset;
	struct btrfs_work work;
	blk_status_t status;
};

/*
 * Compute the csum of a btree block and store the result to provided buffer.
 */
static void csum_tree_block(struct extent_buffer *buf, u8 *result)
{
	struct btrfs_fs_info *fs_info = buf->fs_info;
	const int num_pages = num_extent_pages(buf);
	const int first_page_part = min_t(u32, PAGE_SIZE, fs_info->nodesize);
	SHASH_DESC_ON_STACK(shash, fs_info->csum_shash);
	char *kaddr;
	int i;

	shash->tfm = fs_info->csum_shash;
	crypto_shash_init(shash);
	kaddr = page_address(buf->pages[0]) + offset_in_page(buf->start);
	crypto_shash_update(shash, kaddr + BTRFS_CSUM_SIZE,
			    first_page_part - BTRFS_CSUM_SIZE);

	for (i = 1; i < num_pages; i++) {
		kaddr = page_address(buf->pages[i]);
		crypto_shash_update(shash, kaddr, PAGE_SIZE);
	}
	memset(result, 0, BTRFS_CSUM_SIZE);
	crypto_shash_final(shash, result);
}

/*
 * we can't consider a given block up to date unless the transid of the
 * block matches the transid in the parent node's pointer.  This is how we
 * detect blocks that either didn't get written at all or got written
 * in the wrong place.
 */
static int verify_parent_transid(struct extent_io_tree *io_tree,
				 struct extent_buffer *eb, u64 parent_transid,
				 int atomic)
{
	struct extent_state *cached_state = NULL;
	int ret;

	if (!parent_transid || btrfs_header_generation(eb) == parent_transid)
		return 0;

	if (atomic)
		return -EAGAIN;

	lock_extent(io_tree, eb->start, eb->start + eb->len - 1, &cached_state);
	if (extent_buffer_uptodate(eb) &&
	    btrfs_header_generation(eb) == parent_transid) {
		ret = 0;
		goto out;
	}
	btrfs_err_rl(eb->fs_info,
"parent transid verify failed on logical %llu mirror %u wanted %llu found %llu",
			eb->start, eb->read_mirror,
			parent_transid, btrfs_header_generation(eb));
	ret = 1;
	clear_extent_buffer_uptodate(eb);
out:
	unlock_extent(io_tree, eb->start, eb->start + eb->len - 1,
		      &cached_state);
	return ret;
}

static bool btrfs_supported_super_csum(u16 csum_type)
{
	switch (csum_type) {
	case BTRFS_CSUM_TYPE_CRC32:
	case BTRFS_CSUM_TYPE_XXHASH:
	case BTRFS_CSUM_TYPE_SHA256:
	case BTRFS_CSUM_TYPE_BLAKE2:
		return true;
	default:
		return false;
	}
}

/*
 * Return 0 if the superblock checksum type matches the checksum value of that
 * algorithm. Pass the raw disk superblock data.
 */
int btrfs_check_super_csum(struct btrfs_fs_info *fs_info,
			   const struct btrfs_super_block *disk_sb)
{
	char result[BTRFS_CSUM_SIZE];
	SHASH_DESC_ON_STACK(shash, fs_info->csum_shash);

	shash->tfm = fs_info->csum_shash;

	/*
	 * The super_block structure does not span the whole
	 * BTRFS_SUPER_INFO_SIZE range, we expect that the unused space is
	 * filled with zeros and is included in the checksum.
	 */
	crypto_shash_digest(shash, (const u8 *)disk_sb + BTRFS_CSUM_SIZE,
			    BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE, result);

	if (memcmp(disk_sb->csum, result, fs_info->csum_size))
		return 1;

	return 0;
}

int btrfs_verify_level_key(struct extent_buffer *eb, int level,
			   struct btrfs_key *first_key, u64 parent_transid)
{
	struct btrfs_fs_info *fs_info = eb->fs_info;
	int found_level;
	struct btrfs_key found_key;
	int ret;

	found_level = btrfs_header_level(eb);
	if (found_level != level) {
		WARN(IS_ENABLED(CONFIG_BTRFS_DEBUG),
		     KERN_ERR "BTRFS: tree level check failed\n");
		btrfs_err(fs_info,
"tree level mismatch detected, bytenr=%llu level expected=%u has=%u",
			  eb->start, level, found_level);
		return -EIO;
	}

	if (!first_key)
		return 0;

	/*
	 * For live tree block (new tree blocks in current transaction),
	 * we need proper lock context to avoid race, which is impossible here.
	 * So we only checks tree blocks which is read from disk, whose
	 * generation <= fs_info->last_trans_committed.
	 */
	if (btrfs_header_generation(eb) > fs_info->last_trans_committed)
		return 0;

	/* We have @first_key, so this @eb must have at least one item */
	if (btrfs_header_nritems(eb) == 0) {
		btrfs_err(fs_info,
		"invalid tree nritems, bytenr=%llu nritems=0 expect >0",
			  eb->start);
		WARN_ON(IS_ENABLED(CONFIG_BTRFS_DEBUG));
		return -EUCLEAN;
	}

	if (found_level)
		btrfs_node_key_to_cpu(eb, &found_key, 0);
	else
		btrfs_item_key_to_cpu(eb, &found_key, 0);
	ret = btrfs_comp_cpu_keys(first_key, &found_key);

	if (ret) {
		WARN(IS_ENABLED(CONFIG_BTRFS_DEBUG),
		     KERN_ERR "BTRFS: tree first key check failed\n");
		btrfs_err(fs_info,
"tree first key mismatch detected, bytenr=%llu parent_transid=%llu key expected=(%llu,%u,%llu) has=(%llu,%u,%llu)",
			  eb->start, parent_transid, first_key->objectid,
			  first_key->type, first_key->offset,
			  found_key.objectid, found_key.type,
			  found_key.offset);
	}
	return ret;
}

static int btrfs_repair_eb_io_failure(const struct extent_buffer *eb,
				      int mirror_num)
{
	struct btrfs_fs_info *fs_info = eb->fs_info;
	u64 start = eb->start;
	int i, num_pages = num_extent_pages(eb);
	int ret = 0;

	if (sb_rdonly(fs_info->sb))
		return -EROFS;

	for (i = 0; i < num_pages; i++) {
		struct page *p = eb->pages[i];

		ret = btrfs_repair_io_failure(fs_info, 0, start, PAGE_SIZE,
				start, p, start - page_offset(p), mirror_num);
		if (ret)
			break;
		start += PAGE_SIZE;
	}

	return ret;
}

/*
 * helper to read a given tree block, doing retries as required when
 * the checksums don't match and we have alternate mirrors to try.
 *
 * @check:		expected tree parentness check, see the comments of the
 *			structure for details.
 */
int btrfs_read_extent_buffer(struct extent_buffer *eb,
			     struct btrfs_tree_parent_check *check)
{
	struct btrfs_fs_info *fs_info = eb->fs_info;
	int failed = 0;
	int ret;
	int num_copies = 0;
	int mirror_num = 0;
	int failed_mirror = 0;

	ASSERT(check);

	while (1) {
		clear_bit(EXTENT_BUFFER_CORRUPT, &eb->bflags);
		ret = read_extent_buffer_pages(eb, WAIT_COMPLETE, mirror_num, check);
		if (!ret)
			break;

		num_copies = btrfs_num_copies(fs_info,
					      eb->start, eb->len);
		if (num_copies == 1)
			break;

		if (!failed_mirror) {
			failed = 1;
			failed_mirror = eb->read_mirror;
		}

		mirror_num++;
		if (mirror_num == failed_mirror)
			mirror_num++;

		if (mirror_num > num_copies)
			break;
	}

	if (failed && !ret && failed_mirror)
		btrfs_repair_eb_io_failure(eb, failed_mirror);

	return ret;
}

static int csum_one_extent_buffer(struct extent_buffer *eb)
{
	struct btrfs_fs_info *fs_info = eb->fs_info;
	u8 result[BTRFS_CSUM_SIZE];
	int ret;

	ASSERT(memcmp_extent_buffer(eb, fs_info->fs_devices->metadata_uuid,
				    offsetof(struct btrfs_header, fsid),
				    BTRFS_FSID_SIZE) == 0);
	csum_tree_block(eb, result);

	if (btrfs_header_level(eb))
		ret = btrfs_check_node(eb);
	else
		ret = btrfs_check_leaf_full(eb);

	if (ret < 0)
		goto error;

	/*
	 * Also check the generation, the eb reached here must be newer than
	 * last committed. Or something seriously wrong happened.
	 */
	if (unlikely(btrfs_header_generation(eb) <= fs_info->last_trans_committed)) {
		ret = -EUCLEAN;
		btrfs_err(fs_info,
			"block=%llu bad generation, have %llu expect > %llu",
			  eb->start, btrfs_header_generation(eb),
			  fs_info->last_trans_committed);
		goto error;
	}
	write_extent_buffer(eb, result, 0, fs_info->csum_size);

	return 0;

error:
	btrfs_print_tree(eb, 0);
	btrfs_err(fs_info, "block=%llu write time tree block corruption detected",
		  eb->start);
	/*
	 * Be noisy if this is an extent buffer from a log tree. We don't abort
	 * a transaction in case there's a bad log tree extent buffer, we just
	 * fallback to a transaction commit. Still we want to know when there is
	 * a bad log tree extent buffer, as that may signal a bug somewhere.
	 */
	WARN_ON(IS_ENABLED(CONFIG_BTRFS_DEBUG) ||
		btrfs_header_owner(eb) == BTRFS_TREE_LOG_OBJECTID);
	return ret;
}

/* Checksum all dirty extent buffers in one bio_vec */
static int csum_dirty_subpage_buffers(struct btrfs_fs_info *fs_info,
				      struct bio_vec *bvec)
{
	struct page *page = bvec->bv_page;
	u64 bvec_start = page_offset(page) + bvec->bv_offset;
	u64 cur;
	int ret = 0;

	for (cur = bvec_start; cur < bvec_start + bvec->bv_len;
	     cur += fs_info->nodesize) {
		struct extent_buffer *eb;
		bool uptodate;

		eb = find_extent_buffer(fs_info, cur);
		uptodate = btrfs_subpage_test_uptodate(fs_info, page, cur,
						       fs_info->nodesize);

		/* A dirty eb shouldn't disappear from buffer_radix */
		if (WARN_ON(!eb))
			return -EUCLEAN;

		if (WARN_ON(cur != btrfs_header_bytenr(eb))) {
			free_extent_buffer(eb);
			return -EUCLEAN;
		}
		if (WARN_ON(!uptodate)) {
			free_extent_buffer(eb);
			return -EUCLEAN;
		}

		ret = csum_one_extent_buffer(eb);
		free_extent_buffer(eb);
		if (ret < 0)
			return ret;
	}
	return ret;
}

/*
 * Checksum a dirty tree block before IO.  This has extra checks to make sure
 * we only fill in the checksum field in the first page of a multi-page block.
 * For subpage extent buffers we need bvec to also read the offset in the page.
 */
static int csum_dirty_buffer(struct btrfs_fs_info *fs_info, struct bio_vec *bvec)
{
	struct page *page = bvec->bv_page;
	u64 start = page_offset(page);
	u64 found_start;
	struct extent_buffer *eb;

	if (fs_info->nodesize < PAGE_SIZE)
		return csum_dirty_subpage_buffers(fs_info, bvec);

	eb = (struct extent_buffer *)page->private;
	if (page != eb->pages[0])
		return 0;

	found_start = btrfs_header_bytenr(eb);

	if (test_bit(EXTENT_BUFFER_NO_CHECK, &eb->bflags)) {
		WARN_ON(found_start != 0);
		return 0;
	}

	/*
	 * Please do not consolidate these warnings into a single if.
	 * It is useful to know what went wrong.
	 */
	if (WARN_ON(found_start != start))
		return -EUCLEAN;
	if (WARN_ON(!PageUptodate(page)))
		return -EUCLEAN;

	return csum_one_extent_buffer(eb);
}

static int check_tree_block_fsid(struct extent_buffer *eb)
{
	struct btrfs_fs_info *fs_info = eb->fs_info;
	struct btrfs_fs_devices *fs_devices = fs_info->fs_devices, *seed_devs;
	u8 fsid[BTRFS_FSID_SIZE];
	u8 *metadata_uuid;

	read_extent_buffer(eb, fsid, offsetof(struct btrfs_header, fsid),
			   BTRFS_FSID_SIZE);
	/*
	 * Checking the incompat flag is only valid for the current fs. For
	 * seed devices it's forbidden to have their uuid changed so reading
	 * ->fsid in this case is fine
	 */
	if (btrfs_fs_incompat(fs_info, METADATA_UUID))
		metadata_uuid = fs_devices->metadata_uuid;
	else
		metadata_uuid = fs_devices->fsid;

	if (!memcmp(fsid, metadata_uuid, BTRFS_FSID_SIZE))
		return 0;

	list_for_each_entry(seed_devs, &fs_devices->seed_list, seed_list)
		if (!memcmp(fsid, seed_devs->fsid, BTRFS_FSID_SIZE))
			return 0;

	return 1;
}

/* Do basic extent buffer checks at read time */
static int validate_extent_buffer(struct extent_buffer *eb,
				  struct btrfs_tree_parent_check *check)
{
	struct btrfs_fs_info *fs_info = eb->fs_info;
	u64 found_start;
	const u32 csum_size = fs_info->csum_size;
	u8 found_level;
	u8 result[BTRFS_CSUM_SIZE];
	const u8 *header_csum;
	int ret = 0;

	ASSERT(check);

	found_start = btrfs_header_bytenr(eb);
	if (found_start != eb->start) {
		btrfs_err_rl(fs_info,
			"bad tree block start, mirror %u want %llu have %llu",
			     eb->read_mirror, eb->start, found_start);
		ret = -EIO;
		goto out;
	}
	if (check_tree_block_fsid(eb)) {
		btrfs_err_rl(fs_info, "bad fsid on logical %llu mirror %u",
			     eb->start, eb->read_mirror);
		ret = -EIO;
		goto out;
	}
	found_level = btrfs_header_level(eb);
	if (found_level >= BTRFS_MAX_LEVEL) {
		btrfs_err(fs_info,
			"bad tree block level, mirror %u level %d on logical %llu",
			eb->read_mirror, btrfs_header_level(eb), eb->start);
		ret = -EIO;
		goto out;
	}

	csum_tree_block(eb, result);
	header_csum = page_address(eb->pages[0]) +
		get_eb_offset_in_page(eb, offsetof(struct btrfs_header, csum));

	if (memcmp(result, header_csum, csum_size) != 0) {
		btrfs_warn_rl(fs_info,
"checksum verify failed on logical %llu mirror %u wanted " CSUM_FMT " found " CSUM_FMT " level %d",
			      eb->start, eb->read_mirror,
			      CSUM_FMT_VALUE(csum_size, header_csum),
			      CSUM_FMT_VALUE(csum_size, result),
			      btrfs_header_level(eb));
		ret = -EUCLEAN;
		goto out;
	}

	if (found_level != check->level) {
		btrfs_err(fs_info,
		"level verify failed on logical %llu mirror %u wanted %u found %u",
			  eb->start, eb->read_mirror, check->level, found_level);
		ret = -EIO;
		goto out;
	}
	if (unlikely(check->transid &&
		     btrfs_header_generation(eb) != check->transid)) {
		btrfs_err_rl(eb->fs_info,
"parent transid verify failed on logical %llu mirror %u wanted %llu found %llu",
				eb->start, eb->read_mirror, check->transid,
				btrfs_header_generation(eb));
		ret = -EIO;
		goto out;
	}
	if (check->has_first_key) {
		struct btrfs_key *expect_key = &check->first_key;
		struct btrfs_key found_key;

		if (found_level)
			btrfs_node_key_to_cpu(eb, &found_key, 0);
		else
			btrfs_item_key_to_cpu(eb, &found_key, 0);
		if (unlikely(btrfs_comp_cpu_keys(expect_key, &found_key))) {
			btrfs_err(fs_info,
"tree first key mismatch detected, bytenr=%llu parent_transid=%llu key expected=(%llu,%u,%llu) has=(%llu,%u,%llu)",
				  eb->start, check->transid,
				  expect_key->objectid,
				  expect_key->type, expect_key->offset,
				  found_key.objectid, found_key.type,
				  found_key.offset);
			ret = -EUCLEAN;
			goto out;
		}
	}
	if (check->owner_root) {
		ret = btrfs_check_eb_owner(eb, check->owner_root);
		if (ret < 0)
			goto out;
	}

	/*
	 * If this is a leaf block and it is corrupt, set the corrupt bit so
	 * that we don't try and read the other copies of this block, just
	 * return -EIO.
	 */
	if (found_level == 0 && btrfs_check_leaf_full(eb)) {
		set_bit(EXTENT_BUFFER_CORRUPT, &eb->bflags);
		ret = -EIO;
	}

	if (found_level > 0 && btrfs_check_node(eb))
		ret = -EIO;

	if (!ret)
		set_extent_buffer_uptodate(eb);
	else
		btrfs_err(fs_info,
		"read time tree block corruption detected on logical %llu mirror %u",
			  eb->start, eb->read_mirror);
out:
	return ret;
}

static int validate_subpage_buffer(struct page *page, u64 start, u64 end,
				   int mirror, struct btrfs_tree_parent_check *check)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(page->mapping->host->i_sb);
	struct extent_buffer *eb;
	bool reads_done;
	int ret = 0;

	ASSERT(check);

	/*
	 * We don't allow bio merge for subpage metadata read, so we should
	 * only get one eb for each endio hook.
	 */
	ASSERT(end == start + fs_info->nodesize - 1);
	ASSERT(PagePrivate(page));

	eb = find_extent_buffer(fs_info, start);
	/*
	 * When we are reading one tree block, eb must have been inserted into
	 * the radix tree. If not, something is wrong.
	 */
	ASSERT(eb);

	reads_done = atomic_dec_and_test(&eb->io_pages);
	/* Subpage read must finish in page read */
	ASSERT(reads_done);

	eb->read_mirror = mirror;
	if (test_bit(EXTENT_BUFFER_READ_ERR, &eb->bflags)) {
		ret = -EIO;
		goto err;
	}
	ret = validate_extent_buffer(eb, check);
	if (ret < 0)
		goto err;

	set_extent_buffer_uptodate(eb);

	free_extent_buffer(eb);
	return ret;
err:
	/*
	 * end_bio_extent_readpage decrements io_pages in case of error,
	 * make sure it has something to decrement.
	 */
	atomic_inc(&eb->io_pages);
	clear_extent_buffer_uptodate(eb);
	free_extent_buffer(eb);
	return ret;
}

int btrfs_validate_metadata_buffer(struct btrfs_bio *bbio,
				   struct page *page, u64 start, u64 end,
				   int mirror)
{
	struct extent_buffer *eb;
	int ret = 0;
	int reads_done;

	ASSERT(page->private);

	if (btrfs_sb(page->mapping->host->i_sb)->nodesize < PAGE_SIZE)
		return validate_subpage_buffer(page, start, end, mirror,
					       &bbio->parent_check);

	eb = (struct extent_buffer *)page->private;

	/*
	 * The pending IO might have been the only thing that kept this buffer
	 * in memory.  Make sure we have a ref for all this other checks
	 */
	atomic_inc(&eb->refs);

	reads_done = atomic_dec_and_test(&eb->io_pages);
	if (!reads_done)
		goto err;

	eb->read_mirror = mirror;
	if (test_bit(EXTENT_BUFFER_READ_ERR, &eb->bflags)) {
		ret = -EIO;
		goto err;
	}
	ret = validate_extent_buffer(eb, &bbio->parent_check);
err:
	if (ret) {
		/*
		 * our io error hook is going to dec the io pages
		 * again, we have to make sure it has something
		 * to decrement
		 */
		atomic_inc(&eb->io_pages);
		clear_extent_buffer_uptodate(eb);
	}
	free_extent_buffer(eb);

	return ret;
}

static void run_one_async_start(struct btrfs_work *work)
{
	struct async_submit_bio *async;
	blk_status_t ret;

	async = container_of(work, struct  async_submit_bio, work);
	switch (async->submit_cmd) {
	case WQ_SUBMIT_METADATA:
		ret = btree_submit_bio_start(async->bio);
		break;
	case WQ_SUBMIT_DATA:
		ret = btrfs_submit_bio_start(async->inode, async->bio);
		break;
	case WQ_SUBMIT_DATA_DIO:
		ret = btrfs_submit_bio_start_direct_io(async->inode,
				async->bio, async->dio_file_offset);
		break;
	}
	if (ret)
		async->status = ret;
}

/*
 * In order to insert checksums into the metadata in large chunks, we wait
 * until bio submission time.   All the pages in the bio are checksummed and
 * sums are attached onto the ordered extent record.
 *
 * At IO completion time the csums attached on the ordered extent record are
 * inserted into the tree.
 */
static void run_one_async_done(struct btrfs_work *work)
{
	struct async_submit_bio *async =
		container_of(work, struct  async_submit_bio, work);
	struct btrfs_inode *inode = async->inode;
	struct btrfs_bio *bbio = btrfs_bio(async->bio);

	/* If an error occurred we just want to clean up the bio and move on */
	if (async->status) {
		btrfs_bio_end_io(bbio, async->status);
		return;
	}

	/*
	 * All of the bios that pass through here are from async helpers.
	 * Use REQ_CGROUP_PUNT to issue them from the owning cgroup's context.
	 * This changes nothing when cgroups aren't in use.
	 */
	async->bio->bi_opf |= REQ_CGROUP_PUNT;
	btrfs_submit_bio(inode->root->fs_info, async->bio, async->mirror_num);
}

static void run_one_async_free(struct btrfs_work *work)
{
	struct async_submit_bio *async;

	async = container_of(work, struct  async_submit_bio, work);
	kfree(async);
}

/*
 * Submit bio to an async queue.
 *
 * Retrun:
 * - true if the work has been succesfuly submitted
 * - false in case of error
 */
bool btrfs_wq_submit_bio(struct btrfs_inode *inode, struct bio *bio, int mirror_num,
			 u64 dio_file_offset, enum btrfs_wq_submit_cmd cmd)
{
	struct btrfs_fs_info *fs_info = inode->root->fs_info;
	struct async_submit_bio *async;

	async = kmalloc(sizeof(*async), GFP_NOFS);
	if (!async)
		return false;

	async->inode = inode;
	async->bio = bio;
	async->mirror_num = mirror_num;
	async->submit_cmd = cmd;

	btrfs_init_work(&async->work, run_one_async_start, run_one_async_done,
			run_one_async_free);

	async->dio_file_offset = dio_file_offset;

	async->status = 0;

	if (op_is_sync(bio->bi_opf))
		btrfs_queue_work(fs_info->hipri_workers, &async->work);
	else
		btrfs_queue_work(fs_info->workers, &async->work);
	return true;
}

static blk_status_t btree_csum_one_bio(struct bio *bio)
{
	struct bio_vec bvec;
	struct btrfs_root *root;
	int ret = 0;
	struct bvec_iter_all iter_all;

	ASSERT(!bio_flagged(bio, BIO_CLONED));
	bio_for_each_segment_all(bvec, bio, iter_all) {
		root = BTRFS_I(bvec.bv_page->mapping->host)->root;
		ret = csum_dirty_buffer(root->fs_info, &bvec);
		if (ret)
			break;
	}

	return errno_to_blk_status(ret);
}

blk_status_t btree_submit_bio_start(struct bio *bio)
{
	/*
	 * when we're called for a write, we're already in the async
	 * submission context.  Just jump into btrfs_submit_bio.
	 */
	return btree_csum_one_bio(bio);
}

static bool should_async_write(struct btrfs_fs_info *fs_info,
			     struct btrfs_inode *bi)
{
	if (btrfs_is_zoned(fs_info))
		return false;
	if (atomic_read(&bi->sync_writers))
		return false;
	if (test_bit(BTRFS_FS_CSUM_IMPL_FAST, &fs_info->flags))
		return false;
	return true;
}

void btrfs_submit_metadata_bio(struct btrfs_inode *inode, struct bio *bio, int mirror_num)
{
	struct btrfs_fs_info *fs_info = inode->root->fs_info;
	struct btrfs_bio *bbio = btrfs_bio(bio);
	blk_status_t ret;

	bio->bi_opf |= REQ_META;
	bbio->is_metadata = 1;

	if (btrfs_op(bio) != BTRFS_MAP_WRITE) {
		btrfs_submit_bio(fs_info, bio, mirror_num);
		return;
	}

	/*
	 * Kthread helpers are used to submit writes so that checksumming can
	 * happen in parallel across all CPUs.
	 */
	if (should_async_write(fs_info, inode) &&
	    btrfs_wq_submit_bio(inode, bio, mirror_num, 0, WQ_SUBMIT_METADATA))
		return;

	ret = btree_csum_one_bio(bio);
	if (ret) {
		btrfs_bio_end_io(bbio, ret);
		return;
	}

	btrfs_submit_bio(fs_info, bio, mirror_num);
}

#ifdef CONFIG_MIGRATION
static int btree_migrate_folio(struct address_space *mapping,
		struct folio *dst, struct folio *src, enum migrate_mode mode)
{
	/*
	 * we can't safely write a btree page from here,
	 * we haven't done the locking hook
	 */
	if (folio_test_dirty(src))
		return -EAGAIN;
	/*
	 * Buffers may be managed in a filesystem specific way.
	 * We must have no buffers or drop them.
	 */
	if (folio_get_private(src) &&
	    !filemap_release_folio(src, GFP_KERNEL))
		return -EAGAIN;
	return migrate_folio(mapping, dst, src, mode);
}
#else
#define btree_migrate_folio NULL
#endif

static int btree_writepages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	struct btrfs_fs_info *fs_info;
	int ret;

	if (wbc->sync_mode == WB_SYNC_NONE) {

		if (wbc->for_kupdate)
			return 0;

		fs_info = BTRFS_I(mapping->host)->root->fs_info;
		/* this is a bit racy, but that's ok */
		ret = __percpu_counter_compare(&fs_info->dirty_metadata_bytes,
					     BTRFS_DIRTY_METADATA_THRESH,
					     fs_info->dirty_metadata_batch);
		if (ret < 0)
			return 0;
	}
	return btree_write_cache_pages(mapping, wbc);
}

static bool btree_release_folio(struct folio *folio, gfp_t gfp_flags)
{
	if (folio_test_writeback(folio) || folio_test_dirty(folio))
		return false;

	return try_release_extent_buffer(&folio->page);
}

static void btree_invalidate_folio(struct folio *folio, size_t offset,
				 size_t length)
{
	struct extent_io_tree *tree;
	tree = &BTRFS_I(folio->mapping->host)->io_tree;
	extent_invalidate_folio(tree, folio, offset);
	btree_release_folio(folio, GFP_NOFS);
	if (folio_get_private(folio)) {
		btrfs_warn(BTRFS_I(folio->mapping->host)->root->fs_info,
			   "folio private not zero on folio %llu",
			   (unsigned long long)folio_pos(folio));
		folio_detach_private(folio);
	}
}

#ifdef DEBUG
static bool btree_dirty_folio(struct address_space *mapping,
		struct folio *folio)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(mapping->host->i_sb);
	struct btrfs_subpage *subpage;
	struct extent_buffer *eb;
	int cur_bit = 0;
	u64 page_start = folio_pos(folio);

	if (fs_info->sectorsize == PAGE_SIZE) {
		eb = folio_get_private(folio);
		BUG_ON(!eb);
		BUG_ON(!test_bit(EXTENT_BUFFER_DIRTY, &eb->bflags));
		BUG_ON(!atomic_read(&eb->refs));
		btrfs_assert_tree_write_locked(eb);
		return filemap_dirty_folio(mapping, folio);
	}
	subpage = folio_get_private(folio);

	ASSERT(subpage->dirty_bitmap);
	while (cur_bit < BTRFS_SUBPAGE_BITMAP_SIZE) {
		unsigned long flags;
		u64 cur;
		u16 tmp = (1 << cur_bit);

		spin_lock_irqsave(&subpage->lock, flags);
		if (!(tmp & subpage->dirty_bitmap)) {
			spin_unlock_irqrestore(&subpage->lock, flags);
			cur_bit++;
			continue;
		}
		spin_unlock_irqrestore(&subpage->lock, flags);
		cur = page_start + cur_bit * fs_info->sectorsize;

		eb = find_extent_buffer(fs_info, cur);
		ASSERT(eb);
		ASSERT(test_bit(EXTENT_BUFFER_DIRTY, &eb->bflags));
		ASSERT(atomic_read(&eb->refs));
		btrfs_assert_tree_write_locked(eb);
		free_extent_buffer(eb);

		cur_bit += (fs_info->nodesize >> fs_info->sectorsize_bits);
	}
	return filemap_dirty_folio(mapping, folio);
}
#else
#define btree_dirty_folio filemap_dirty_folio
#endif

static const struct address_space_operations btree_aops = {
	.writepages	= btree_writepages,
	.release_folio	= btree_release_folio,
	.invalidate_folio = btree_invalidate_folio,
	.migrate_folio	= btree_migrate_folio,
	.dirty_folio	= btree_dirty_folio,
};

struct extent_buffer *btrfs_find_create_tree_block(
						struct btrfs_fs_info *fs_info,
						u64 bytenr, u64 owner_root,
						int level)
{
	if (btrfs_is_testing(fs_info))
		return alloc_test_extent_buffer(fs_info, bytenr);
	return alloc_extent_buffer(fs_info, bytenr, owner_root, level);
}

/*
 * Read tree block at logical address @bytenr and do variant basic but critical
 * verification.
 *
 * @check:		expected tree parentness check, see comments of the
 *			structure for details.
 */
struct extent_buffer *read_tree_block(struct btrfs_fs_info *fs_info, u64 bytenr,
				      struct btrfs_tree_parent_check *check)
{
	struct extent_buffer *buf = NULL;
	int ret;

	ASSERT(check);

	buf = btrfs_find_create_tree_block(fs_info, bytenr, check->owner_root,
					   check->level);
	if (IS_ERR(buf))
		return buf;

	ret = btrfs_read_extent_buffer(buf, check);
	if (ret) {
		free_extent_buffer_stale(buf);
		return ERR_PTR(ret);
	}
	if (btrfs_check_eb_owner(buf, check->owner_root)) {
		free_extent_buffer_stale(buf);
		return ERR_PTR(-EUCLEAN);
	}
	return buf;

}

void btrfs_clean_tree_block(struct extent_buffer *buf)
{
	struct btrfs_fs_info *fs_info = buf->fs_info;
	if (btrfs_header_generation(buf) ==
	    fs_info->running_transaction->transid) {
		btrfs_assert_tree_write_locked(buf);

		if (test_and_clear_bit(EXTENT_BUFFER_DIRTY, &buf->bflags)) {
			percpu_counter_add_batch(&fs_info->dirty_metadata_bytes,
						 -buf->len,
						 fs_info->dirty_metadata_batch);
			clear_extent_buffer_dirty(buf);
		}
	}
}

static void __setup_root(struct btrfs_root *root, struct btrfs_fs_info *fs_info,
			 u64 objectid)
{
	bool dummy = test_bit(BTRFS_FS_STATE_DUMMY_FS_INFO, &fs_info->fs_state);

	memset(&root->root_key, 0, sizeof(root->root_key));
	memset(&root->root_item, 0, sizeof(root->root_item));
	memset(&root->defrag_progress, 0, sizeof(root->defrag_progress));
	root->fs_info = fs_info;
	root->root_key.objectid = objectid;
	root->node = NULL;
	root->commit_root = NULL;
	root->state = 0;
	RB_CLEAR_NODE(&root->rb_node);

	root->last_trans = 0;
	root->free_objectid = 0;
	root->nr_delalloc_inodes = 0;
	root->nr_ordered_extents = 0;
	root->inode_tree = RB_ROOT;
	INIT_RADIX_TREE(&root->delayed_nodes_tree, GFP_ATOMIC);

	btrfs_init_root_block_rsv(root);

	INIT_LIST_HEAD(&root->dirty_list);
	INIT_LIST_HEAD(&root->root_list);
	INIT_LIST_HEAD(&root->delalloc_inodes);
	INIT_LIST_HEAD(&root->delalloc_root);
	INIT_LIST_HEAD(&root->ordered_extents);
	INIT_LIST_HEAD(&root->ordered_root);
	INIT_LIST_HEAD(&root->reloc_dirty_list);
	INIT_LIST_HEAD(&root->logged_list[0]);
	INIT_LIST_HEAD(&root->logged_list[1]);
	spin_lock_init(&root->inode_lock);
	spin_lock_init(&root->delalloc_lock);
	spin_lock_init(&root->ordered_extent_lock);
	spin_lock_init(&root->accounting_lock);
	spin_lock_init(&root->log_extents_lock[0]);
	spin_lock_init(&root->log_extents_lock[1]);
	spin_lock_init(&root->qgroup_meta_rsv_lock);
	mutex_init(&root->objectid_mutex);
	mutex_init(&root->log_mutex);
	mutex_init(&root->ordered_extent_mutex);
	mutex_init(&root->delalloc_mutex);
	init_waitqueue_head(&root->qgroup_flush_wait);
	init_waitqueue_head(&root->log_writer_wait);
	init_waitqueue_head(&root->log_commit_wait[0]);
	init_waitqueue_head(&root->log_commit_wait[1]);
	INIT_LIST_HEAD(&root->log_ctxs[0]);
	INIT_LIST_HEAD(&root->log_ctxs[1]);
	atomic_set(&root->log_commit[0], 0);
	atomic_set(&root->log_commit[1], 0);
	atomic_set(&root->log_writers, 0);
	atomic_set(&root->log_batch, 0);
	refcount_set(&root->refs, 1);
	atomic_set(&root->snapshot_force_cow, 0);
	atomic_set(&root->nr_swapfiles, 0);
	root->log_transid = 0;
	root->log_transid_committed = -1;
	root->last_log_commit = 0;
	root->anon_dev = 0;
	if (!dummy) {
		extent_io_tree_init(fs_info, &root->dirty_log_pages,
				    IO_TREE_ROOT_DIRTY_LOG_PAGES);
		extent_io_tree_init(fs_info, &root->log_csum_range,
				    IO_TREE_LOG_CSUM_RANGE);
	}

	spin_lock_init(&root->root_item_lock);
	btrfs_qgroup_init_swapped_blocks(&root->swapped_blocks);
#ifdef CONFIG_BTRFS_DEBUG
	INIT_LIST_HEAD(&root->leak_list);
	spin_lock(&fs_info->fs_roots_radix_lock);
	list_add_tail(&root->leak_list, &fs_info->allocated_roots);
	spin_unlock(&fs_info->fs_roots_radix_lock);
#endif
}

static struct btrfs_root *btrfs_alloc_root(struct btrfs_fs_info *fs_info,
					   u64 objectid, gfp_t flags)
{
	struct btrfs_root *root = kzalloc(sizeof(*root), flags);
	if (root)
		__setup_root(root, fs_info, objectid);
	return root;
}

#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
/* Should only be used by the testing infrastructure */
struct btrfs_root *btrfs_alloc_dummy_root(struct btrfs_fs_info *fs_info)
{
	struct btrfs_root *root;

	if (!fs_info)
		return ERR_PTR(-EINVAL);

	root = btrfs_alloc_root(fs_info, BTRFS_ROOT_TREE_OBJECTID, GFP_KERNEL);
	if (!root)
		return ERR_PTR(-ENOMEM);

	/* We don't use the stripesize in selftest, set it as sectorsize */
	root->alloc_bytenr = 0;

	return root;
}
#endif

static int global_root_cmp(struct rb_node *a_node, const struct rb_node *b_node)
{
	const struct btrfs_root *a = rb_entry(a_node, struct btrfs_root, rb_node);
	const struct btrfs_root *b = rb_entry(b_node, struct btrfs_root, rb_node);

	return btrfs_comp_cpu_keys(&a->root_key, &b->root_key);
}

static int global_root_key_cmp(const void *k, const struct rb_node *node)
{
	const struct btrfs_key *key = k;
	const struct btrfs_root *root = rb_entry(node, struct btrfs_root, rb_node);

	return btrfs_comp_cpu_keys(key, &root->root_key);
}

int btrfs_global_root_insert(struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct rb_node *tmp;

	write_lock(&fs_info->global_root_lock);
	tmp = rb_find_add(&root->rb_node, &fs_info->global_root_tree, global_root_cmp);
	write_unlock(&fs_info->global_root_lock);
	ASSERT(!tmp);

	return tmp ? -EEXIST : 0;
}

void btrfs_global_root_delete(struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;

	write_lock(&fs_info->global_root_lock);
	rb_erase(&root->rb_node, &fs_info->global_root_tree);
	write_unlock(&fs_info->global_root_lock);
}

struct btrfs_root *btrfs_global_root(struct btrfs_fs_info *fs_info,
				     struct btrfs_key *key)
{
	struct rb_node *node;
	struct btrfs_root *root = NULL;

	read_lock(&fs_info->global_root_lock);
	node = rb_find(key, &fs_info->global_root_tree, global_root_key_cmp);
	if (node)
		root = container_of(node, struct btrfs_root, rb_node);
	read_unlock(&fs_info->global_root_lock);

	return root;
}

static u64 btrfs_global_root_id(struct btrfs_fs_info *fs_info, u64 bytenr)
{
	struct btrfs_block_group *block_group;
	u64 ret;

	if (!btrfs_fs_incompat(fs_info, EXTENT_TREE_V2))
		return 0;

	if (bytenr)
		block_group = btrfs_lookup_block_group(fs_info, bytenr);
	else
		block_group = btrfs_lookup_first_block_group(fs_info, bytenr);
	ASSERT(block_group);
	if (!block_group)
		return 0;
	ret = block_group->global_root_id;
	btrfs_put_block_group(block_group);

	return ret;
}

struct btrfs_root *btrfs_csum_root(struct btrfs_fs_info *fs_info, u64 bytenr)
{
	struct btrfs_key key = {
		.objectid = BTRFS_CSUM_TREE_OBJECTID,
		.type = BTRFS_ROOT_ITEM_KEY,
		.offset = btrfs_global_root_id(fs_info, bytenr),
	};

	return btrfs_global_root(fs_info, &key);
}

struct btrfs_root *btrfs_extent_root(struct btrfs_fs_info *fs_info, u64 bytenr)
{
	struct btrfs_key key = {
		.objectid = BTRFS_EXTENT_TREE_OBJECTID,
		.type = BTRFS_ROOT_ITEM_KEY,
		.offset = btrfs_global_root_id(fs_info, bytenr),
	};

	return btrfs_global_root(fs_info, &key);
}

struct btrfs_root *btrfs_block_group_root(struct btrfs_fs_info *fs_info)
{
	if (btrfs_fs_compat_ro(fs_info, BLOCK_GROUP_TREE))
		return fs_info->block_group_root;
	return btrfs_extent_root(fs_info, 0);
}

struct btrfs_root *btrfs_create_tree(struct btrfs_trans_handle *trans,
				     u64 objectid)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct extent_buffer *leaf;
	struct btrfs_root *tree_root = fs_info->tree_root;
	struct btrfs_root *root;
	struct btrfs_key key;
	unsigned int nofs_flag;
	int ret = 0;

	/*
	 * We're holding a transaction handle, so use a NOFS memory allocation
	 * context to avoid deadlock if reclaim happens.
	 */
	nofs_flag = memalloc_nofs_save();
	root = btrfs_alloc_root(fs_info, objectid, GFP_KERNEL);
	memalloc_nofs_restore(nofs_flag);
	if (!root)
		return ERR_PTR(-ENOMEM);

	root->root_key.objectid = objectid;
	root->root_key.type = BTRFS_ROOT_ITEM_KEY;
	root->root_key.offset = 0;

	leaf = btrfs_alloc_tree_block(trans, root, 0, objectid, NULL, 0, 0, 0,
				      BTRFS_NESTING_NORMAL);
	if (IS_ERR(leaf)) {
		ret = PTR_ERR(leaf);
		leaf = NULL;
		goto fail;
	}

	root->node = leaf;
	btrfs_mark_buffer_dirty(leaf);

	root->commit_root = btrfs_root_node(root);
	set_bit(BTRFS_ROOT_TRACK_DIRTY, &root->state);

	btrfs_set_root_flags(&root->root_item, 0);
	btrfs_set_root_limit(&root->root_item, 0);
	btrfs_set_root_bytenr(&root->root_item, leaf->start);
	btrfs_set_root_generation(&root->root_item, trans->transid);
	btrfs_set_root_level(&root->root_item, 0);
	btrfs_set_root_refs(&root->root_item, 1);
	btrfs_set_root_used(&root->root_item, leaf->len);
	btrfs_set_root_last_snapshot(&root->root_item, 0);
	btrfs_set_root_dirid(&root->root_item, 0);
	if (is_fstree(objectid))
		generate_random_guid(root->root_item.uuid);
	else
		export_guid(root->root_item.uuid, &guid_null);
	btrfs_set_root_drop_level(&root->root_item, 0);

	btrfs_tree_unlock(leaf);

	key.objectid = objectid;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = 0;
	ret = btrfs_insert_root(trans, tree_root, &key, &root->root_item);
	if (ret)
		goto fail;

	return root;

fail:
	btrfs_put_root(root);

	return ERR_PTR(ret);
}

static struct btrfs_root *alloc_log_tree(struct btrfs_trans_handle *trans,
					 struct btrfs_fs_info *fs_info)
{
	struct btrfs_root *root;

	root = btrfs_alloc_root(fs_info, BTRFS_TREE_LOG_OBJECTID, GFP_NOFS);
	if (!root)
		return ERR_PTR(-ENOMEM);

	root->root_key.objectid = BTRFS_TREE_LOG_OBJECTID;
	root->root_key.type = BTRFS_ROOT_ITEM_KEY;
	root->root_key.offset = BTRFS_TREE_LOG_OBJECTID;

	return root;
}

int btrfs_alloc_log_tree_node(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root)
{
	struct extent_buffer *leaf;

	/*
	 * DON'T set SHAREABLE bit for log trees.
	 *
	 * Log trees are not exposed to user space thus can't be snapshotted,
	 * and they go away before a real commit is actually done.
	 *
	 * They do store pointers to file data extents, and those reference
	 * counts still get updated (along with back refs to the log tree).
	 */

	leaf = btrfs_alloc_tree_block(trans, root, 0, BTRFS_TREE_LOG_OBJECTID,
			NULL, 0, 0, 0, BTRFS_NESTING_NORMAL);
	if (IS_ERR(leaf))
		return PTR_ERR(leaf);

	root->node = leaf;

	btrfs_mark_buffer_dirty(root->node);
	btrfs_tree_unlock(root->node);

	return 0;
}

int btrfs_init_log_root_tree(struct btrfs_trans_handle *trans,
			     struct btrfs_fs_info *fs_info)
{
	struct btrfs_root *log_root;

	log_root = alloc_log_tree(trans, fs_info);
	if (IS_ERR(log_root))
		return PTR_ERR(log_root);

	if (!btrfs_is_zoned(fs_info)) {
		int ret = btrfs_alloc_log_tree_node(trans, log_root);

		if (ret) {
			btrfs_put_root(log_root);
			return ret;
		}
	}

	WARN_ON(fs_info->log_root_tree);
	fs_info->log_root_tree = log_root;
	return 0;
}

int btrfs_add_log_tree(struct btrfs_trans_handle *trans,
		       struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_root *log_root;
	struct btrfs_inode_item *inode_item;
	int ret;

	log_root = alloc_log_tree(trans, fs_info);
	if (IS_ERR(log_root))
		return PTR_ERR(log_root);

	ret = btrfs_alloc_log_tree_node(trans, log_root);
	if (ret) {
		btrfs_put_root(log_root);
		return ret;
	}

	log_root->last_trans = trans->transid;
	log_root->root_key.offset = root->root_key.objectid;

	inode_item = &log_root->root_item.inode;
	btrfs_set_stack_inode_generation(inode_item, 1);
	btrfs_set_stack_inode_size(inode_item, 3);
	btrfs_set_stack_inode_nlink(inode_item, 1);
	btrfs_set_stack_inode_nbytes(inode_item,
				     fs_info->nodesize);
	btrfs_set_stack_inode_mode(inode_item, S_IFDIR | 0755);

	btrfs_set_root_node(&log_root->root_item, log_root->node);

	WARN_ON(root->log_root);
	root->log_root = log_root;
	root->log_transid = 0;
	root->log_transid_committed = -1;
	root->last_log_commit = 0;
	return 0;
}

static struct btrfs_root *read_tree_root_path(struct btrfs_root *tree_root,
					      struct btrfs_path *path,
					      struct btrfs_key *key)
{
	struct btrfs_root *root;
	struct btrfs_tree_parent_check check = { 0 };
	struct btrfs_fs_info *fs_info = tree_root->fs_info;
	u64 generation;
	int ret;
	int level;

	root = btrfs_alloc_root(fs_info, key->objectid, GFP_NOFS);
	if (!root)
		return ERR_PTR(-ENOMEM);

	ret = btrfs_find_root(tree_root, key, path,
			      &root->root_item, &root->root_key);
	if (ret) {
		if (ret > 0)
			ret = -ENOENT;
		goto fail;
	}

	generation = btrfs_root_generation(&root->root_item);
	level = btrfs_root_level(&root->root_item);
	check.level = level;
	check.transid = generation;
	check.owner_root = key->objectid;
	root->node = read_tree_block(fs_info, btrfs_root_bytenr(&root->root_item),
				     &check);
	if (IS_ERR(root->node)) {
		ret = PTR_ERR(root->node);
		root->node = NULL;
		goto fail;
	}
	if (!btrfs_buffer_uptodate(root->node, generation, 0)) {
		ret = -EIO;
		goto fail;
	}

	/*
	 * For real fs, and not log/reloc trees, root owner must
	 * match its root node owner
	 */
	if (!test_bit(BTRFS_FS_STATE_DUMMY_FS_INFO, &fs_info->fs_state) &&
	    root->root_key.objectid != BTRFS_TREE_LOG_OBJECTID &&
	    root->root_key.objectid != BTRFS_TREE_RELOC_OBJECTID &&
	    root->root_key.objectid != btrfs_header_owner(root->node)) {
		btrfs_crit(fs_info,
"root=%llu block=%llu, tree root owner mismatch, have %llu expect %llu",
			   root->root_key.objectid, root->node->start,
			   btrfs_header_owner(root->node),
			   root->root_key.objectid);
		ret = -EUCLEAN;
		goto fail;
	}
	root->commit_root = btrfs_root_node(root);
	return root;
fail:
	btrfs_put_root(root);
	return ERR_PTR(ret);
}

struct btrfs_root *btrfs_read_tree_root(struct btrfs_root *tree_root,
					struct btrfs_key *key)
{
	struct btrfs_root *root;
	struct btrfs_path *path;

	path = btrfs_alloc_path();
	if (!path)
		return ERR_PTR(-ENOMEM);
	root = read_tree_root_path(tree_root, path, key);
	btrfs_free_path(path);

	return root;
}

/*
 * Initialize subvolume root in-memory structure
 *
 * @anon_dev:	anonymous device to attach to the root, if zero, allocate new
 */
static int btrfs_init_fs_root(struct btrfs_root *root, dev_t anon_dev)
{
	int ret;
	unsigned int nofs_flag;

	/*
	 * We might be called under a transaction (e.g. indirect backref
	 * resolution) which could deadlock if it triggers memory reclaim
	 */
	nofs_flag = memalloc_nofs_save();
	ret = btrfs_drew_lock_init(&root->snapshot_lock);
	memalloc_nofs_restore(nofs_flag);
	if (ret)
		goto fail;

	if (root->root_key.objectid != BTRFS_TREE_LOG_OBJECTID &&
	    !btrfs_is_data_reloc_root(root)) {
		set_bit(BTRFS_ROOT_SHAREABLE, &root->state);
		btrfs_check_and_init_root_item(&root->root_item);
	}

	/*
	 * Don't assign anonymous block device to roots that are not exposed to
	 * userspace, the id pool is limited to 1M
	 */
	if (is_fstree(root->root_key.objectid) &&
	    btrfs_root_refs(&root->root_item) > 0) {
		if (!anon_dev) {
			ret = get_anon_bdev(&root->anon_dev);
			if (ret)
				goto fail;
		} else {
			root->anon_dev = anon_dev;
		}
	}

	mutex_lock(&root->objectid_mutex);
	ret = btrfs_init_root_free_objectid(root);
	if (ret) {
		mutex_unlock(&root->objectid_mutex);
		goto fail;
	}

	ASSERT(root->free_objectid <= BTRFS_LAST_FREE_OBJECTID);

	mutex_unlock(&root->objectid_mutex);

	return 0;
fail:
	/* The caller is responsible to call btrfs_free_fs_root */
	return ret;
}

static struct btrfs_root *btrfs_lookup_fs_root(struct btrfs_fs_info *fs_info,
					       u64 root_id)
{
	struct btrfs_root *root;

	spin_lock(&fs_info->fs_roots_radix_lock);
	root = radix_tree_lookup(&fs_info->fs_roots_radix,
				 (unsigned long)root_id);
	if (root)
		root = btrfs_grab_root(root);
	spin_unlock(&fs_info->fs_roots_radix_lock);
	return root;
}

static struct btrfs_root *btrfs_get_global_root(struct btrfs_fs_info *fs_info,
						u64 objectid)
{
	struct btrfs_key key = {
		.objectid = objectid,
		.type = BTRFS_ROOT_ITEM_KEY,
		.offset = 0,
	};

	if (objectid == BTRFS_ROOT_TREE_OBJECTID)
		return btrfs_grab_root(fs_info->tree_root);
	if (objectid == BTRFS_EXTENT_TREE_OBJECTID)
		return btrfs_grab_root(btrfs_global_root(fs_info, &key));
	if (objectid == BTRFS_CHUNK_TREE_OBJECTID)
		return btrfs_grab_root(fs_info->chunk_root);
	if (objectid == BTRFS_DEV_TREE_OBJECTID)
		return btrfs_grab_root(fs_info->dev_root);
	if (objectid == BTRFS_CSUM_TREE_OBJECTID)
		return btrfs_grab_root(btrfs_global_root(fs_info, &key));
	if (objectid == BTRFS_QUOTA_TREE_OBJECTID)
		return btrfs_grab_root(fs_info->quota_root) ?
			fs_info->quota_root : ERR_PTR(-ENOENT);
	if (objectid == BTRFS_UUID_TREE_OBJECTID)
		return btrfs_grab_root(fs_info->uuid_root) ?
			fs_info->uuid_root : ERR_PTR(-ENOENT);
	if (objectid == BTRFS_BLOCK_GROUP_TREE_OBJECTID)
		return btrfs_grab_root(fs_info->block_group_root) ?
			fs_info->block_group_root : ERR_PTR(-ENOENT);
	if (objectid == BTRFS_FREE_SPACE_TREE_OBJECTID) {
		struct btrfs_root *root = btrfs_global_root(fs_info, &key);

		return btrfs_grab_root(root) ? root : ERR_PTR(-ENOENT);
	}
	return NULL;
}

int btrfs_insert_fs_root(struct btrfs_fs_info *fs_info,
			 struct btrfs_root *root)
{
	int ret;

	ret = radix_tree_preload(GFP_NOFS);
	if (ret)
		return ret;

	spin_lock(&fs_info->fs_roots_radix_lock);
	ret = radix_tree_insert(&fs_info->fs_roots_radix,
				(unsigned long)root->root_key.objectid,
				root);
	if (ret == 0) {
		btrfs_grab_root(root);
		set_bit(BTRFS_ROOT_IN_RADIX, &root->state);
	}
	spin_unlock(&fs_info->fs_roots_radix_lock);
	radix_tree_preload_end();

	return ret;
}

void btrfs_check_leaked_roots(struct btrfs_fs_info *fs_info)
{
#ifdef CONFIG_BTRFS_DEBUG
	struct btrfs_root *root;

	while (!list_empty(&fs_info->allocated_roots)) {
		char buf[BTRFS_ROOT_NAME_BUF_LEN];

		root = list_first_entry(&fs_info->allocated_roots,
					struct btrfs_root, leak_list);
		btrfs_err(fs_info, "leaked root %s refcount %d",
			  btrfs_root_name(&root->root_key, buf),
			  refcount_read(&root->refs));
		while (refcount_read(&root->refs) > 1)
			btrfs_put_root(root);
		btrfs_put_root(root);
	}
#endif
}

static void free_global_roots(struct btrfs_fs_info *fs_info)
{
	struct btrfs_root *root;
	struct rb_node *node;

	while ((node = rb_first_postorder(&fs_info->global_root_tree)) != NULL) {
		root = rb_entry(node, struct btrfs_root, rb_node);
		rb_erase(&root->rb_node, &fs_info->global_root_tree);
		btrfs_put_root(root);
	}
}

void btrfs_free_fs_info(struct btrfs_fs_info *fs_info)
{
	percpu_counter_destroy(&fs_info->dirty_metadata_bytes);
	percpu_counter_destroy(&fs_info->delalloc_bytes);
	percpu_counter_destroy(&fs_info->ordered_bytes);
	percpu_counter_destroy(&fs_info->dev_replace.bio_counter);
	btrfs_free_csum_hash(fs_info);
	btrfs_free_stripe_hash_table(fs_info);
	btrfs_free_ref_cache(fs_info);
	kfree(fs_info->balance_ctl);
	kfree(fs_info->delayed_root);
	free_global_roots(fs_info);
	btrfs_put_root(fs_info->tree_root);
	btrfs_put_root(fs_info->chunk_root);
	btrfs_put_root(fs_info->dev_root);
	btrfs_put_root(fs_info->quota_root);
	btrfs_put_root(fs_info->uuid_root);
	btrfs_put_root(fs_info->fs_root);
	btrfs_put_root(fs_info->data_reloc_root);
	btrfs_put_root(fs_info->block_group_root);
	btrfs_check_leaked_roots(fs_info);
	btrfs_extent_buffer_leak_debug_check(fs_info);
	kfree(fs_info->super_copy);
	kfree(fs_info->super_for_commit);
	kfree(fs_info->subpage_info);
	kvfree(fs_info);
}


/*
 * Get an in-memory reference of a root structure.
 *
 * For essential trees like root/extent tree, we grab it from fs_info directly.
 * For subvolume trees, we check the cached filesystem roots first. If not
 * found, then read it from disk and add it to cached fs roots.
 *
 * Caller should release the root by calling btrfs_put_root() after the usage.
 *
 * NOTE: Reloc and log trees can't be read by this function as they share the
 *	 same root objectid.
 *
 * @objectid:	root id
 * @anon_dev:	preallocated anonymous block device number for new roots,
 * 		pass 0 for new allocation.
 * @check_ref:	whether to check root item references, If true, return -ENOENT
 *		for orphan roots
 */
static struct btrfs_root *btrfs_get_root_ref(struct btrfs_fs_info *fs_info,
					     u64 objectid, dev_t anon_dev,
					     bool check_ref)
{
	struct btrfs_root *root;
	struct btrfs_path *path;
	struct btrfs_key key;
	int ret;

	root = btrfs_get_global_root(fs_info, objectid);
	if (root)
		return root;
again:
	root = btrfs_lookup_fs_root(fs_info, objectid);
	if (root) {
		/* Shouldn't get preallocated anon_dev for cached roots */
		ASSERT(!anon_dev);
		if (check_ref && btrfs_root_refs(&root->root_item) == 0) {
			btrfs_put_root(root);
			return ERR_PTR(-ENOENT);
		}
		return root;
	}

	key.objectid = objectid;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;
	root = btrfs_read_tree_root(fs_info->tree_root, &key);
	if (IS_ERR(root))
		return root;

	if (check_ref && btrfs_root_refs(&root->root_item) == 0) {
		ret = -ENOENT;
		goto fail;
	}

	ret = btrfs_init_fs_root(root, anon_dev);
	if (ret)
		goto fail;

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto fail;
	}
	key.objectid = BTRFS_ORPHAN_OBJECTID;
	key.type = BTRFS_ORPHAN_ITEM_KEY;
	key.offset = objectid;

	ret = btrfs_search_slot(NULL, fs_info->tree_root, &key, path, 0, 0);
	btrfs_free_path(path);
	if (ret < 0)
		goto fail;
	if (ret == 0)
		set_bit(BTRFS_ROOT_ORPHAN_ITEM_INSERTED, &root->state);

	ret = btrfs_insert_fs_root(fs_info, root);
	if (ret) {
		if (ret == -EEXIST) {
			btrfs_put_root(root);
			goto again;
		}
		goto fail;
	}
	return root;
fail:
	/*
	 * If our caller provided us an anonymous device, then it's his
	 * responsibility to free it in case we fail. So we have to set our
	 * root's anon_dev to 0 to avoid a double free, once by btrfs_put_root()
	 * and once again by our caller.
	 */
	if (anon_dev)
		root->anon_dev = 0;
	btrfs_put_root(root);
	return ERR_PTR(ret);
}

/*
 * Get in-memory reference of a root structure
 *
 * @objectid:	tree objectid
 * @check_ref:	if set, verify that the tree exists and the item has at least
 *		one reference
 */
struct btrfs_root *btrfs_get_fs_root(struct btrfs_fs_info *fs_info,
				     u64 objectid, bool check_ref)
{
	return btrfs_get_root_ref(fs_info, objectid, 0, check_ref);
}

/*
 * Get in-memory reference of a root structure, created as new, optionally pass
 * the anonymous block device id
 *
 * @objectid:	tree objectid
 * @anon_dev:	if zero, allocate a new anonymous block device or use the
 *		parameter value
 */
struct btrfs_root *btrfs_get_new_fs_root(struct btrfs_fs_info *fs_info,
					 u64 objectid, dev_t anon_dev)
{
	return btrfs_get_root_ref(fs_info, objectid, anon_dev, true);
}

/*
 * btrfs_get_fs_root_commit_root - return a root for the given objectid
 * @fs_info:	the fs_info
 * @objectid:	the objectid we need to lookup
 *
 * This is exclusively used for backref walking, and exists specifically because
 * of how qgroups does lookups.  Qgroups will do a backref lookup at delayed ref
 * creation time, which means we may have to read the tree_root in order to look
 * up a fs root that is not in memory.  If the root is not in memory we will
 * read the tree root commit root and look up the fs root from there.  This is a
 * temporary root, it will not be inserted into the radix tree as it doesn't
 * have the most uptodate information, it'll simply be discarded once the
 * backref code is finished using the root.
 */
struct btrfs_root *btrfs_get_fs_root_commit_root(struct btrfs_fs_info *fs_info,
						 struct btrfs_path *path,
						 u64 objectid)
{
	struct btrfs_root *root;
	struct btrfs_key key;

	ASSERT(path->search_commit_root && path->skip_locking);

	/*
	 * This can return -ENOENT if we ask for a root that doesn't exist, but
	 * since this is called via the backref walking code we won't be looking
	 * up a root that doesn't exist, unless there's corruption.  So if root
	 * != NULL just return it.
	 */
	root = btrfs_get_global_root(fs_info, objectid);
	if (root)
		return root;

	root = btrfs_lookup_fs_root(fs_info, objectid);
	if (root)
		return root;

	key.objectid = objectid;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;
	root = read_tree_root_path(fs_info->tree_root, path, &key);
	btrfs_release_path(path);

	return root;
}

static int cleaner_kthread(void *arg)
{
	struct btrfs_fs_info *fs_info = arg;
	int again;

	while (1) {
		again = 0;

		set_bit(BTRFS_FS_CLEANER_RUNNING, &fs_info->flags);

		/* Make the cleaner go to sleep early. */
		if (btrfs_need_cleaner_sleep(fs_info))
			goto sleep;

		/*
		 * Do not do anything if we might cause open_ctree() to block
		 * before we have finished mounting the filesystem.
		 */
		if (!test_bit(BTRFS_FS_OPEN, &fs_info->flags))
			goto sleep;

		if (!mutex_trylock(&fs_info->cleaner_mutex))
			goto sleep;

		/*
		 * Avoid the problem that we change the status of the fs
		 * during the above check and trylock.
		 */
		if (btrfs_need_cleaner_sleep(fs_info)) {
			mutex_unlock(&fs_info->cleaner_mutex);
			goto sleep;
		}

		btrfs_run_delayed_iputs(fs_info);

		again = btrfs_clean_one_deleted_snapshot(fs_info);
		mutex_unlock(&fs_info->cleaner_mutex);

		/*
		 * The defragger has dealt with the R/O remount and umount,
		 * needn't do anything special here.
		 */
		btrfs_run_defrag_inodes(fs_info);

		/*
		 * Acquires fs_info->reclaim_bgs_lock to avoid racing
		 * with relocation (btrfs_relocate_chunk) and relocation
		 * acquires fs_info->cleaner_mutex (btrfs_relocate_block_group)
		 * after acquiring fs_info->reclaim_bgs_lock. So we
		 * can't hold, nor need to, fs_info->cleaner_mutex when deleting
		 * unused block groups.
		 */
		btrfs_delete_unused_bgs(fs_info);

		/*
		 * Reclaim block groups in the reclaim_bgs list after we deleted
		 * all unused block_groups. This possibly gives us some more free
		 * space.
		 */
		btrfs_reclaim_bgs(fs_info);
sleep:
		clear_and_wake_up_bit(BTRFS_FS_CLEANER_RUNNING, &fs_info->flags);
		if (kthread_should_park())
			kthread_parkme();
		if (kthread_should_stop())
			return 0;
		if (!again) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
			__set_current_state(TASK_RUNNING);
		}
	}
}

static int transaction_kthread(void *arg)
{
	struct btrfs_root *root = arg;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_trans_handle *trans;
	struct btrfs_transaction *cur;
	u64 transid;
	time64_t delta;
	unsigned long delay;
	bool cannot_commit;

	do {
		cannot_commit = false;
		delay = msecs_to_jiffies(fs_info->commit_interval * 1000);
		mutex_lock(&fs_info->transaction_kthread_mutex);

		spin_lock(&fs_info->trans_lock);
		cur = fs_info->running_transaction;
		if (!cur) {
			spin_unlock(&fs_info->trans_lock);
			goto sleep;
		}

		delta = ktime_get_seconds() - cur->start_time;
		if (!test_and_clear_bit(BTRFS_FS_COMMIT_TRANS, &fs_info->flags) &&
		    cur->state < TRANS_STATE_COMMIT_START &&
		    delta < fs_info->commit_interval) {
			spin_unlock(&fs_info->trans_lock);
			delay -= msecs_to_jiffies((delta - 1) * 1000);
			delay = min(delay,
				    msecs_to_jiffies(fs_info->commit_interval * 1000));
			goto sleep;
		}
		transid = cur->transid;
		spin_unlock(&fs_info->trans_lock);

		/* If the file system is aborted, this will always fail. */
		trans = btrfs_attach_transaction(root);
		if (IS_ERR(trans)) {
			if (PTR_ERR(trans) != -ENOENT)
				cannot_commit = true;
			goto sleep;
		}
		if (transid == trans->transid) {
			btrfs_commit_transaction(trans);
		} else {
			btrfs_end_transaction(trans);
		}
sleep:
		wake_up_process(fs_info->cleaner_kthread);
		mutex_unlock(&fs_info->transaction_kthread_mutex);

		if (BTRFS_FS_ERROR(fs_info))
			btrfs_cleanup_transaction(fs_info);
		if (!kthread_should_stop() &&
				(!btrfs_transaction_blocked(fs_info) ||
				 cannot_commit))
			schedule_timeout_interruptible(delay);
	} while (!kthread_should_stop());
	return 0;
}

/*
 * This will find the highest generation in the array of root backups.  The
 * index of the highest array is returned, or -EINVAL if we can't find
 * anything.
 *
 * We check to make sure the array is valid by comparing the
 * generation of the latest  root in the array with the generation
 * in the super block.  If they don't match we pitch it.
 */
static int find_newest_super_backup(struct btrfs_fs_info *info)
{
	const u64 newest_gen = btrfs_super_generation(info->super_copy);
	u64 cur;
	struct btrfs_root_backup *root_backup;
	int i;

	for (i = 0; i < BTRFS_NUM_BACKUP_ROOTS; i++) {
		root_backup = info->super_copy->super_roots + i;
		cur = btrfs_backup_tree_root_gen(root_backup);
		if (cur == newest_gen)
			return i;
	}

	return -EINVAL;
}

/*
 * copy all the root pointers into the super backup array.
 * this will bump the backup pointer by one when it is
 * done
 */
static void backup_super_roots(struct btrfs_fs_info *info)
{
	const int next_backup = info->backup_root_index;
	struct btrfs_root_backup *root_backup;

	root_backup = info->super_for_commit->super_roots + next_backup;

	/*
	 * make sure all of our padding and empty slots get zero filled
	 * regardless of which ones we use today
	 */
	memset(root_backup, 0, sizeof(*root_backup));

	info->backup_root_index = (next_backup + 1) % BTRFS_NUM_BACKUP_ROOTS;

	btrfs_set_backup_tree_root(root_backup, info->tree_root->node->start);
	btrfs_set_backup_tree_root_gen(root_backup,
			       btrfs_header_generation(info->tree_root->node));

	btrfs_set_backup_tree_root_level(root_backup,
			       btrfs_header_level(info->tree_root->node));

	btrfs_set_backup_chunk_root(root_backup, info->chunk_root->node->start);
	btrfs_set_backup_chunk_root_gen(root_backup,
			       btrfs_header_generation(info->chunk_root->node));
	btrfs_set_backup_chunk_root_level(root_backup,
			       btrfs_header_level(info->chunk_root->node));

	if (!btrfs_fs_compat_ro(info, BLOCK_GROUP_TREE)) {
		struct btrfs_root *extent_root = btrfs_extent_root(info, 0);
		struct btrfs_root *csum_root = btrfs_csum_root(info, 0);

		btrfs_set_backup_extent_root(root_backup,
					     extent_root->node->start);
		btrfs_set_backup_extent_root_gen(root_backup,
				btrfs_header_generation(extent_root->node));
		btrfs_set_backup_extent_root_level(root_backup,
					btrfs_header_level(extent_root->node));

		btrfs_set_backup_csum_root(root_backup, csum_root->node->start);
		btrfs_set_backup_csum_root_gen(root_backup,
					       btrfs_header_generation(csum_root->node));
		btrfs_set_backup_csum_root_level(root_backup,
						 btrfs_header_level(csum_root->node));
	}

	/*
	 * we might commit during log recovery, which happens before we set
	 * the fs_root.  Make sure it is valid before we fill it in.
	 */
	if (info->fs_root && info->fs_root->node) {
		btrfs_set_backup_fs_root(root_backup,
					 info->fs_root->node->start);
		btrfs_set_backup_fs_root_gen(root_backup,
			       btrfs_header_generation(info->fs_root->node));
		btrfs_set_backup_fs_root_level(root_backup,
			       btrfs_header_level(info->fs_root->node));
	}

	btrfs_set_backup_dev_root(root_backup, info->dev_root->node->start);
	btrfs_set_backup_dev_root_gen(root_backup,
			       btrfs_header_generation(info->dev_root->node));
	btrfs_set_backup_dev_root_level(root_backup,
				       btrfs_header_level(info->dev_root->node));

	btrfs_set_backup_total_bytes(root_backup,
			     btrfs_super_total_bytes(info->super_copy));
	btrfs_set_backup_bytes_used(root_backup,
			     btrfs_super_bytes_used(info->super_copy));
	btrfs_set_backup_num_devices(root_backup,
			     btrfs_super_num_devices(info->super_copy));

	/*
	 * if we don't copy this out to the super_copy, it won't get remembered
	 * for the next commit
	 */
	memcpy(&info->super_copy->super_roots,
	       &info->super_for_commit->super_roots,
	       sizeof(*root_backup) * BTRFS_NUM_BACKUP_ROOTS);
}

/*
 * read_backup_root - Reads a backup root based on the passed priority. Prio 0
 * is the newest, prio 1/2/3 are 2nd newest/3rd newest/4th (oldest) backup roots
 *
 * fs_info - filesystem whose backup roots need to be read
 * priority - priority of backup root required
 *
 * Returns backup root index on success and -EINVAL otherwise.
 */
static int read_backup_root(struct btrfs_fs_info *fs_info, u8 priority)
{
	int backup_index = find_newest_super_backup(fs_info);
	struct btrfs_super_block *super = fs_info->super_copy;
	struct btrfs_root_backup *root_backup;

	if (priority < BTRFS_NUM_BACKUP_ROOTS && backup_index >= 0) {
		if (priority == 0)
			return backup_index;

		backup_index = backup_index + BTRFS_NUM_BACKUP_ROOTS - priority;
		backup_index %= BTRFS_NUM_BACKUP_ROOTS;
	} else {
		return -EINVAL;
	}

	root_backup = super->super_roots + backup_index;

	btrfs_set_super_generation(super,
				   btrfs_backup_tree_root_gen(root_backup));
	btrfs_set_super_root(super, btrfs_backup_tree_root(root_backup));
	btrfs_set_super_root_level(super,
				   btrfs_backup_tree_root_level(root_backup));
	btrfs_set_super_bytes_used(super, btrfs_backup_bytes_used(root_backup));

	/*
	 * Fixme: the total bytes and num_devices need to match or we should
	 * need a fsck
	 */
	btrfs_set_super_total_bytes(super, btrfs_backup_total_bytes(root_backup));
	btrfs_set_super_num_devices(super, btrfs_backup_num_devices(root_backup));

	return backup_index;
}

/* helper to cleanup workers */
static void btrfs_stop_all_workers(struct btrfs_fs_info *fs_info)
{
	btrfs_destroy_workqueue(fs_info->fixup_workers);
	btrfs_destroy_workqueue(fs_info->delalloc_workers);
	btrfs_destroy_workqueue(fs_info->hipri_workers);
	btrfs_destroy_workqueue(fs_info->workers);
	if (fs_info->endio_workers)
		destroy_workqueue(fs_info->endio_workers);
	if (fs_info->rmw_workers)
		destroy_workqueue(fs_info->rmw_workers);
	if (fs_info->compressed_write_workers)
		destroy_workqueue(fs_info->compressed_write_workers);
	btrfs_destroy_workqueue(fs_info->endio_write_workers);
	btrfs_destroy_workqueue(fs_info->endio_freespace_worker);
	btrfs_destroy_workqueue(fs_info->delayed_workers);
	btrfs_destroy_workqueue(fs_info->caching_workers);
	btrfs_destroy_workqueue(fs_info->flush_workers);
	btrfs_destroy_workqueue(fs_info->qgroup_rescan_workers);
	if (fs_info->discard_ctl.discard_workers)
		destroy_workqueue(fs_info->discard_ctl.discard_workers);
	/*
	 * Now that all other work queues are destroyed, we can safely destroy
	 * the queues used for metadata I/O, since tasks from those other work
	 * queues can do metadata I/O operations.
	 */
	if (fs_info->endio_meta_workers)
		destroy_workqueue(fs_info->endio_meta_workers);
}

static void free_root_extent_buffers(struct btrfs_root *root)
{
	if (root) {
		free_extent_buffer(root->node);
		free_extent_buffer(root->commit_root);
		root->node = NULL;
		root->commit_root = NULL;
	}
}

static void free_global_root_pointers(struct btrfs_fs_info *fs_info)
{
	struct btrfs_root *root, *tmp;

	rbtree_postorder_for_each_entry_safe(root, tmp,
					     &fs_info->global_root_tree,
					     rb_node)
		free_root_extent_buffers(root);
}

/* helper to cleanup tree roots */
static void free_root_pointers(struct btrfs_fs_info *info, bool free_chunk_root)
{
	free_root_extent_buffers(info->tree_root);

	free_global_root_pointers(info);
	free_root_extent_buffers(info->dev_root);
	free_root_extent_buffers(info->quota_root);
	free_root_extent_buffers(info->uuid_root);
	free_root_extent_buffers(info->fs_root);
	free_root_extent_buffers(info->data_reloc_root);
	free_root_extent_buffers(info->block_group_root);
	if (free_chunk_root)
		free_root_extent_buffers(info->chunk_root);
}

void btrfs_put_root(struct btrfs_root *root)
{
	if (!root)
		return;

	if (refcount_dec_and_test(&root->refs)) {
		WARN_ON(!RB_EMPTY_ROOT(&root->inode_tree));
		WARN_ON(test_bit(BTRFS_ROOT_DEAD_RELOC_TREE, &root->state));
		if (root->anon_dev)
			free_anon_bdev(root->anon_dev);
		btrfs_drew_lock_destroy(&root->snapshot_lock);
		free_root_extent_buffers(root);
#ifdef CONFIG_BTRFS_DEBUG
		spin_lock(&root->fs_info->fs_roots_radix_lock);
		list_del_init(&root->leak_list);
		spin_unlock(&root->fs_info->fs_roots_radix_lock);
#endif
		kfree(root);
	}
}

void btrfs_free_fs_roots(struct btrfs_fs_info *fs_info)
{
	int ret;
	struct btrfs_root *gang[8];
	int i;

	while (!list_empty(&fs_info->dead_roots)) {
		gang[0] = list_entry(fs_info->dead_roots.next,
				     struct btrfs_root, root_list);
		list_del(&gang[0]->root_list);

		if (test_bit(BTRFS_ROOT_IN_RADIX, &gang[0]->state))
			btrfs_drop_and_free_fs_root(fs_info, gang[0]);
		btrfs_put_root(gang[0]);
	}

	while (1) {
		ret = radix_tree_gang_lookup(&fs_info->fs_roots_radix,
					     (void **)gang, 0,
					     ARRAY_SIZE(gang));
		if (!ret)
			break;
		for (i = 0; i < ret; i++)
			btrfs_drop_and_free_fs_root(fs_info, gang[i]);
	}
}

static void btrfs_init_scrub(struct btrfs_fs_info *fs_info)
{
	mutex_init(&fs_info->scrub_lock);
	atomic_set(&fs_info->scrubs_running, 0);
	atomic_set(&fs_info->scrub_pause_req, 0);
	atomic_set(&fs_info->scrubs_paused, 0);
	atomic_set(&fs_info->scrub_cancel_req, 0);
	init_waitqueue_head(&fs_info->scrub_pause_wait);
	refcount_set(&fs_info->scrub_workers_refcnt, 0);
}

static void btrfs_init_balance(struct btrfs_fs_info *fs_info)
{
	spin_lock_init(&fs_info->balance_lock);
	mutex_init(&fs_info->balance_mutex);
	atomic_set(&fs_info->balance_pause_req, 0);
	atomic_set(&fs_info->balance_cancel_req, 0);
	fs_info->balance_ctl = NULL;
	init_waitqueue_head(&fs_info->balance_wait_q);
	atomic_set(&fs_info->reloc_cancel_req, 0);
}

static void btrfs_init_btree_inode(struct btrfs_fs_info *fs_info)
{
	struct inode *inode = fs_info->btree_inode;
	unsigned long hash = btrfs_inode_hash(BTRFS_BTREE_INODE_OBJECTID,
					      fs_info->tree_root);

	inode->i_ino = BTRFS_BTREE_INODE_OBJECTID;
	set_nlink(inode, 1);
	/*
	 * we set the i_size on the btree inode to the max possible int.
	 * the real end of the address space is determined by all of
	 * the devices in the system
	 */
	inode->i_size = OFFSET_MAX;
	inode->i_mapping->a_ops = &btree_aops;

	RB_CLEAR_NODE(&BTRFS_I(inode)->rb_node);
	extent_io_tree_init(fs_info, &BTRFS_I(inode)->io_tree,
			    IO_TREE_BTREE_INODE_IO);
	extent_map_tree_init(&BTRFS_I(inode)->extent_tree);

	BTRFS_I(inode)->root = btrfs_grab_root(fs_info->tree_root);
	BTRFS_I(inode)->location.objectid = BTRFS_BTREE_INODE_OBJECTID;
	BTRFS_I(inode)->location.type = 0;
	BTRFS_I(inode)->location.offset = 0;
	set_bit(BTRFS_INODE_DUMMY, &BTRFS_I(inode)->runtime_flags);
	__insert_inode_hash(inode, hash);
}

static void btrfs_init_dev_replace_locks(struct btrfs_fs_info *fs_info)
{
	mutex_init(&fs_info->dev_replace.lock_finishing_cancel_unmount);
	init_rwsem(&fs_info->dev_replace.rwsem);
	init_waitqueue_head(&fs_info->dev_replace.replace_wait);
}

static void btrfs_init_qgroup(struct btrfs_fs_info *fs_info)
{
	spin_lock_init(&fs_info->qgroup_lock);
	mutex_init(&fs_info->qgroup_ioctl_lock);
	fs_info->qgroup_tree = RB_ROOT;
	INIT_LIST_HEAD(&fs_info->dirty_qgroups);
	fs_info->qgroup_seq = 1;
	fs_info->qgroup_ulist = NULL;
	fs_info->qgroup_rescan_running = false;
	fs_info->qgroup_drop_subtree_thres = BTRFS_MAX_LEVEL;
	mutex_init(&fs_info->qgroup_rescan_lock);
}

static int btrfs_init_workqueues(struct btrfs_fs_info *fs_info)
{
	u32 max_active = fs_info->thread_pool_size;
	unsigned int flags = WQ_MEM_RECLAIM | WQ_FREEZABLE | WQ_UNBOUND;

	fs_info->workers =
		btrfs_alloc_workqueue(fs_info, "worker", flags, max_active, 16);
	fs_info->hipri_workers =
		btrfs_alloc_workqueue(fs_info, "worker-high",
				      flags | WQ_HIGHPRI, max_active, 16);

	fs_info->delalloc_workers =
		btrfs_alloc_workqueue(fs_info, "delalloc",
				      flags, max_active, 2);

	fs_info->flush_workers =
		btrfs_alloc_workqueue(fs_info, "flush_delalloc",
				      flags, max_active, 0);

	fs_info->caching_workers =
		btrfs_alloc_workqueue(fs_info, "cache", flags, max_active, 0);

	fs_info->fixup_workers =
		btrfs_alloc_workqueue(fs_info, "fixup", flags, 1, 0);

	fs_info->endio_workers =
		alloc_workqueue("btrfs-endio", flags, max_active);
	fs_info->endio_meta_workers =
		alloc_workqueue("btrfs-endio-meta", flags, max_active);
	fs_info->rmw_workers = alloc_workqueue("btrfs-rmw", flags, max_active);
	fs_info->endio_write_workers =
		btrfs_alloc_workqueue(fs_info, "endio-write", flags,
				      max_active, 2);
	fs_info->compressed_write_workers =
		alloc_workqueue("btrfs-compressed-write", flags, max_active);
	fs_info->endio_freespace_worker =
		btrfs_alloc_workqueue(fs_info, "freespace-write", flags,
				      max_active, 0);
	fs_info->delayed_workers =
		btrfs_alloc_workqueue(fs_info, "delayed-meta", flags,
				      max_active, 0);
	fs_info->qgroup_rescan_workers =
		btrfs_alloc_workqueue(fs_info, "qgroup-rescan", flags, 1, 0);
	fs_info->discard_ctl.discard_workers =
		alloc_workqueue("btrfs_discard", WQ_UNBOUND | WQ_FREEZABLE, 1);

	if (!(fs_info->workers && fs_info->hipri_workers &&
	      fs_info->delalloc_workers && fs_info->flush_workers &&
	      fs_info->endio_workers && fs_info->endio_meta_workers &&
	      fs_info->compressed_write_workers &&
	      fs_info->endio_write_workers &&
	      fs_info->endio_freespace_worker && fs_info->rmw_workers &&
	      fs_info->caching_workers && fs_info->fixup_workers &&
	      fs_info->delayed_workers && fs_info->qgroup_rescan_workers &&
	      fs_info->discard_ctl.discard_workers)) {
		return -ENOMEM;
	}

	return 0;
}

static int btrfs_init_csum_hash(struct btrfs_fs_info *fs_info, u16 csum_type)
{
	struct crypto_shash *csum_shash;
	const char *csum_driver = btrfs_super_csum_driver(csum_type);

	csum_shash = crypto_alloc_shash(csum_driver, 0, 0);

	if (IS_ERR(csum_shash)) {
		btrfs_err(fs_info, "error allocating %s hash for checksum",
			  csum_driver);
		return PTR_ERR(csum_shash);
	}

	fs_info->csum_shash = csum_shash;

	btrfs_info(fs_info, "using %s (%s) checksum algorithm",
			btrfs_super_csum_name(csum_type),
			crypto_shash_driver_name(csum_shash));
	return 0;
}

static int btrfs_replay_log(struct btrfs_fs_info *fs_info,
			    struct btrfs_fs_devices *fs_devices)
{
	int ret;
	struct btrfs_tree_parent_check check = { 0 };
	struct btrfs_root *log_tree_root;
	struct btrfs_super_block *disk_super = fs_info->super_copy;
	u64 bytenr = btrfs_super_log_root(disk_super);
	int level = btrfs_super_log_root_level(disk_super);

	if (fs_devices->rw_devices == 0) {
		btrfs_warn(fs_info, "log replay required on RO media");
		return -EIO;
	}

	log_tree_root = btrfs_alloc_root(fs_info, BTRFS_TREE_LOG_OBJECTID,
					 GFP_KERNEL);
	if (!log_tree_root)
		return -ENOMEM;

	check.level = level;
	check.transid = fs_info->generation + 1;
	check.owner_root = BTRFS_TREE_LOG_OBJECTID;
	log_tree_root->node = read_tree_block(fs_info, bytenr, &check);
	if (IS_ERR(log_tree_root->node)) {
		btrfs_warn(fs_info, "failed to read log tree");
		ret = PTR_ERR(log_tree_root->node);
		log_tree_root->node = NULL;
		btrfs_put_root(log_tree_root);
		return ret;
	}
	if (!extent_buffer_uptodate(log_tree_root->node)) {
		btrfs_err(fs_info, "failed to read log tree");
		btrfs_put_root(log_tree_root);
		return -EIO;
	}

	/* returns with log_tree_root freed on success */
	ret = btrfs_recover_log_trees(log_tree_root);
	if (ret) {
		btrfs_handle_fs_error(fs_info, ret,
				      "Failed to recover log tree");
		btrfs_put_root(log_tree_root);
		return ret;
	}

	if (sb_rdonly(fs_info->sb)) {
		ret = btrfs_commit_super(fs_info);
		if (ret)
			return ret;
	}

	return 0;
}

static int load_global_roots_objectid(struct btrfs_root *tree_root,
				      struct btrfs_path *path, u64 objectid,
				      const char *name)
{
	struct btrfs_fs_info *fs_info = tree_root->fs_info;
	struct btrfs_root *root;
	u64 max_global_id = 0;
	int ret;
	struct btrfs_key key = {
		.objectid = objectid,
		.type = BTRFS_ROOT_ITEM_KEY,
		.offset = 0,
	};
	bool found = false;

	/* If we have IGNOREDATACSUMS skip loading these roots. */
	if (objectid == BTRFS_CSUM_TREE_OBJECTID &&
	    btrfs_test_opt(fs_info, IGNOREDATACSUMS)) {
		set_bit(BTRFS_FS_STATE_NO_CSUMS, &fs_info->fs_state);
		return 0;
	}

	while (1) {
		ret = btrfs_search_slot(NULL, tree_root, &key, path, 0, 0);
		if (ret < 0)
			break;

		if (path->slots[0] >= btrfs_header_nritems(path->nodes[0])) {
			ret = btrfs_next_leaf(tree_root, path);
			if (ret) {
				if (ret > 0)
					ret = 0;
				break;
			}
		}
		ret = 0;

		btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
		if (key.objectid != objectid)
			break;
		btrfs_release_path(path);

		/*
		 * Just worry about this for extent tree, it'll be the same for
		 * everybody.
		 */
		if (objectid == BTRFS_EXTENT_TREE_OBJECTID)
			max_global_id = max(max_global_id, key.offset);

		found = true;
		root = read_tree_root_path(tree_root, path, &key);
		if (IS_ERR(root)) {
			if (!btrfs_test_opt(fs_info, IGNOREBADROOTS))
				ret = PTR_ERR(root);
			break;
		}
		set_bit(BTRFS_ROOT_TRACK_DIRTY, &root->state);
		ret = btrfs_global_root_insert(root);
		if (ret) {
			btrfs_put_root(root);
			break;
		}
		key.offset++;
	}
	btrfs_release_path(path);

	if (objectid == BTRFS_EXTENT_TREE_OBJECTID)
		fs_info->nr_global_roots = max_global_id + 1;

	if (!found || ret) {
		if (objectid == BTRFS_CSUM_TREE_OBJECTID)
			set_bit(BTRFS_FS_STATE_NO_CSUMS, &fs_info->fs_state);

		if (!btrfs_test_opt(fs_info, IGNOREBADROOTS))
			ret = ret ? ret : -ENOENT;
		else
			ret = 0;
		btrfs_err(fs_info, "failed to load root %s", name);
	}
	return ret;
}

static int load_global_roots(struct btrfs_root *tree_root)
{
	struct btrfs_path *path;
	int ret = 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ret = load_global_roots_objectid(tree_root, path,
					 BTRFS_EXTENT_TREE_OBJECTID, "extent");
	if (ret)
		goto out;
	ret = load_global_roots_objectid(tree_root, path,
					 BTRFS_CSUM_TREE_OBJECTID, "csum");
	if (ret)
		goto out;
	if (!btrfs_fs_compat_ro(tree_root->fs_info, FREE_SPACE_TREE))
		goto out;
	ret = load_global_roots_objectid(tree_root, path,
					 BTRFS_FREE_SPACE_TREE_OBJECTID,
					 "free space");
out:
	btrfs_free_path(path);
	return ret;
}

static int btrfs_read_roots(struct btrfs_fs_info *fs_info)
{
	struct btrfs_root *tree_root = fs_info->tree_root;
	struct btrfs_root *root;
	struct btrfs_key location;
	int ret;

	BUG_ON(!fs_info->tree_root);

	ret = load_global_roots(tree_root);
	if (ret)
		return ret;

	location.type = BTRFS_ROOT_ITEM_KEY;
	location.offset = 0;

	if (btrfs_fs_compat_ro(fs_info, BLOCK_GROUP_TREE)) {
		location.objectid = BTRFS_BLOCK_GROUP_TREE_OBJECTID;
		root = btrfs_read_tree_root(tree_root, &location);
		if (IS_ERR(root)) {
			if (!btrfs_test_opt(fs_info, IGNOREBADROOTS)) {
				ret = PTR_ERR(root);
				goto out;
			}
		} else {
			set_bit(BTRFS_ROOT_TRACK_DIRTY, &root->state);
			fs_info->block_group_root = root;
		}
	}

	location.objectid = BTRFS_DEV_TREE_OBJECTID;
	root = btrfs_read_tree_root(tree_root, &location);
	if (IS_ERR(root)) {
		if (!btrfs_test_opt(fs_info, IGNOREBADROOTS)) {
			ret = PTR_ERR(root);
			goto out;
		}
	} else {
		set_bit(BTRFS_ROOT_TRACK_DIRTY, &root->state);
		fs_info->dev_root = root;
	}
	/* Initialize fs_info for all devices in any case */
	ret = btrfs_init_devices_late(fs_info);
	if (ret)
		goto out;

	/*
	 * This tree can share blocks with some other fs tree during relocation
	 * and we need a proper setup by btrfs_get_fs_root
	 */
	root = btrfs_get_fs_root(tree_root->fs_info,
				 BTRFS_DATA_RELOC_TREE_OBJECTID, true);
	if (IS_ERR(root)) {
		if (!btrfs_test_opt(fs_info, IGNOREBADROOTS)) {
			ret = PTR_ERR(root);
			goto out;
		}
	} else {
		set_bit(BTRFS_ROOT_TRACK_DIRTY, &root->state);
		fs_info->data_reloc_root = root;
	}

	location.objectid = BTRFS_QUOTA_TREE_OBJECTID;
	root = btrfs_read_tree_root(tree_root, &location);
	if (!IS_ERR(root)) {
		set_bit(BTRFS_ROOT_TRACK_DIRTY, &root->state);
		set_bit(BTRFS_FS_QUOTA_ENABLED, &fs_info->flags);
		fs_info->quota_root = root;
	}

	location.objectid = BTRFS_UUID_TREE_OBJECTID;
	root = btrfs_read_tree_root(tree_root, &location);
	if (IS_ERR(root)) {
		if (!btrfs_test_opt(fs_info, IGNOREBADROOTS)) {
			ret = PTR_ERR(root);
			if (ret != -ENOENT)
				goto out;
		}
	} else {
		set_bit(BTRFS_ROOT_TRACK_DIRTY, &root->state);
		fs_info->uuid_root = root;
	}

	return 0;
out:
	btrfs_warn(fs_info, "failed to read root (objectid=%llu): %d",
		   location.objectid, ret);
	return ret;
}

/*
 * Real super block validation
 * NOTE: super csum type and incompat features will not be checked here.
 *
 * @sb:		super block to check
 * @mirror_num:	the super block number to check its bytenr:
 * 		0	the primary (1st) sb
 * 		1, 2	2nd and 3rd backup copy
 * 	       -1	skip bytenr check
 */
int btrfs_validate_super(struct btrfs_fs_info *fs_info,
			 struct btrfs_super_block *sb, int mirror_num)
{
	u64 nodesize = btrfs_super_nodesize(sb);
	u64 sectorsize = btrfs_super_sectorsize(sb);
	int ret = 0;

	if (btrfs_super_magic(sb) != BTRFS_MAGIC) {
		btrfs_err(fs_info, "no valid FS found");
		ret = -EINVAL;
	}
	if (btrfs_super_flags(sb) & ~BTRFS_SUPER_FLAG_SUPP) {
		btrfs_err(fs_info, "unrecognized or unsupported super flag: %llu",
				btrfs_super_flags(sb) & ~BTRFS_SUPER_FLAG_SUPP);
		ret = -EINVAL;
	}
	if (btrfs_super_root_level(sb) >= BTRFS_MAX_LEVEL) {
		btrfs_err(fs_info, "tree_root level too big: %d >= %d",
				btrfs_super_root_level(sb), BTRFS_MAX_LEVEL);
		ret = -EINVAL;
	}
	if (btrfs_super_chunk_root_level(sb) >= BTRFS_MAX_LEVEL) {
		btrfs_err(fs_info, "chunk_root level too big: %d >= %d",
				btrfs_super_chunk_root_level(sb), BTRFS_MAX_LEVEL);
		ret = -EINVAL;
	}
	if (btrfs_super_log_root_level(sb) >= BTRFS_MAX_LEVEL) {
		btrfs_err(fs_info, "log_root level too big: %d >= %d",
				btrfs_super_log_root_level(sb), BTRFS_MAX_LEVEL);
		ret = -EINVAL;
	}

	/*
	 * Check sectorsize and nodesize first, other check will need it.
	 * Check all possible sectorsize(4K, 8K, 16K, 32K, 64K) here.
	 */
	if (!is_power_of_2(sectorsize) || sectorsize < 4096 ||
	    sectorsize > BTRFS_MAX_METADATA_BLOCKSIZE) {
		btrfs_err(fs_info, "invalid sectorsize %llu", sectorsize);
		ret = -EINVAL;
	}

	/*
	 * We only support at most two sectorsizes: 4K and PAGE_SIZE.
	 *
	 * We can support 16K sectorsize with 64K page size without problem,
	 * but such sectorsize/pagesize combination doesn't make much sense.
	 * 4K will be our future standard, PAGE_SIZE is supported from the very
	 * beginning.
	 */
	if (sectorsize > PAGE_SIZE || (sectorsize != SZ_4K && sectorsize != PAGE_SIZE)) {
		btrfs_err(fs_info,
			"sectorsize %llu not yet supported for page size %lu",
			sectorsize, PAGE_SIZE);
		ret = -EINVAL;
	}

	if (!is_power_of_2(nodesize) || nodesize < sectorsize ||
	    nodesize > BTRFS_MAX_METADATA_BLOCKSIZE) {
		btrfs_err(fs_info, "invalid nodesize %llu", nodesize);
		ret = -EINVAL;
	}
	if (nodesize != le32_to_cpu(sb->__unused_leafsize)) {
		btrfs_err(fs_info, "invalid leafsize %u, should be %llu",
			  le32_to_cpu(sb->__unused_leafsize), nodesize);
		ret = -EINVAL;
	}

	/* Root alignment check */
	if (!IS_ALIGNED(btrfs_super_root(sb), sectorsize)) {
		btrfs_warn(fs_info, "tree_root block unaligned: %llu",
			   btrfs_super_root(sb));
		ret = -EINVAL;
	}
	if (!IS_ALIGNED(btrfs_super_chunk_root(sb), sectorsize)) {
		btrfs_warn(fs_info, "chunk_root block unaligned: %llu",
			   btrfs_super_chunk_root(sb));
		ret = -EINVAL;
	}
	if (!IS_ALIGNED(btrfs_super_log_root(sb), sectorsize)) {
		btrfs_warn(fs_info, "log_root block unaligned: %llu",
			   btrfs_super_log_root(sb));
		ret = -EINVAL;
	}

	if (memcmp(fs_info->fs_devices->fsid, fs_info->super_copy->fsid,
		   BTRFS_FSID_SIZE)) {
		btrfs_err(fs_info,
		"superblock fsid doesn't match fsid of fs_devices: %pU != %pU",
			fs_info->super_copy->fsid, fs_info->fs_devices->fsid);
		ret = -EINVAL;
	}

	if (btrfs_fs_incompat(fs_info, METADATA_UUID) &&
	    memcmp(fs_info->fs_devices->metadata_uuid,
		   fs_info->super_copy->metadata_uuid, BTRFS_FSID_SIZE)) {
		btrfs_err(fs_info,
"superblock metadata_uuid doesn't match metadata uuid of fs_devices: %pU != %pU",
			fs_info->super_copy->metadata_uuid,
			fs_info->fs_devices->metadata_uuid);
		ret = -EINVAL;
	}

	/*
	 * Artificial requirement for block-group-tree to force newer features
	 * (free-space-tree, no-holes) so the test matrix is smaller.
	 */
	if (btrfs_fs_compat_ro(fs_info, BLOCK_GROUP_TREE) &&
	    (!btrfs_fs_compat_ro(fs_info, FREE_SPACE_TREE_VALID) ||
	     !btrfs_fs_incompat(fs_info, NO_HOLES))) {
		btrfs_err(fs_info,
		"block-group-tree feature requires fres-space-tree and no-holes");
		ret = -EINVAL;
	}

	if (memcmp(fs_info->fs_devices->metadata_uuid, sb->dev_item.fsid,
		   BTRFS_FSID_SIZE) != 0) {
		btrfs_err(fs_info,
			"dev_item UUID does not match metadata fsid: %pU != %pU",
			fs_info->fs_devices->metadata_uuid, sb->dev_item.fsid);
		ret = -EINVAL;
	}

	/*
	 * Hint to catch really bogus numbers, bitflips or so, more exact checks are
	 * done later
	 */
	if (btrfs_super_bytes_used(sb) < 6 * btrfs_super_nodesize(sb)) {
		btrfs_err(fs_info, "bytes_used is too small %llu",
			  btrfs_super_bytes_used(sb));
		ret = -EINVAL;
	}
	if (!is_power_of_2(btrfs_super_stripesize(sb))) {
		btrfs_err(fs_info, "invalid stripesize %u",
			  btrfs_super_stripesize(sb));
		ret = -EINVAL;
	}
	if (btrfs_super_num_devices(sb) > (1UL << 31))
		btrfs_warn(fs_info, "suspicious number of devices: %llu",
			   btrfs_super_num_devices(sb));
	if (btrfs_super_num_devices(sb) == 0) {
		btrfs_err(fs_info, "number of devices is 0");
		ret = -EINVAL;
	}

	if (mirror_num >= 0 &&
	    btrfs_super_bytenr(sb) != btrfs_sb_offset(mirror_num)) {
		btrfs_err(fs_info, "super offset mismatch %llu != %u",
			  btrfs_super_bytenr(sb), BTRFS_SUPER_INFO_OFFSET);
		ret = -EINVAL;
	}

	/*
	 * Obvious sys_chunk_array corruptions, it must hold at least one key
	 * and one chunk
	 */
	if (btrfs_super_sys_array_size(sb) > BTRFS_SYSTEM_CHUNK_ARRAY_SIZE) {
		btrfs_err(fs_info, "system chunk array too big %u > %u",
			  btrfs_super_sys_array_size(sb),
			  BTRFS_SYSTEM_CHUNK_ARRAY_SIZE);
		ret = -EINVAL;
	}
	if (btrfs_super_sys_array_size(sb) < sizeof(struct btrfs_disk_key)
			+ sizeof(struct btrfs_chunk)) {
		btrfs_err(fs_info, "system chunk array too small %u < %zu",
			  btrfs_super_sys_array_size(sb),
			  sizeof(struct btrfs_disk_key)
			  + sizeof(struct btrfs_chunk));
		ret = -EINVAL;
	}

	/*
	 * The generation is a global counter, we'll trust it more than the others
	 * but it's still possible that it's the one that's wrong.
	 */
	if (btrfs_super_generation(sb) < btrfs_super_chunk_root_generation(sb))
		btrfs_warn(fs_info,
			"suspicious: generation < chunk_root_generation: %llu < %llu",
			btrfs_super_generation(sb),
			btrfs_super_chunk_root_generation(sb));
	if (btrfs_super_generation(sb) < btrfs_super_cache_generation(sb)
	    && btrfs_super_cache_generation(sb) != (u64)-1)
		btrfs_warn(fs_info,
			"suspicious: generation < cache_generation: %llu < %llu",
			btrfs_super_generation(sb),
			btrfs_super_cache_generation(sb));

	return ret;
}

/*
 * Validation of super block at mount time.
 * Some checks already done early at mount time, like csum type and incompat
 * flags will be skipped.
 */
static int btrfs_validate_mount_super(struct btrfs_fs_info *fs_info)
{
	return btrfs_validate_super(fs_info, fs_info->super_copy, 0);
}

/*
 * Validation of super block at write time.
 * Some checks like bytenr check will be skipped as their values will be
 * overwritten soon.
 * Extra checks like csum type and incompat flags will be done here.
 */
static int btrfs_validate_write_super(struct btrfs_fs_info *fs_info,
				      struct btrfs_super_block *sb)
{
	int ret;

	ret = btrfs_validate_super(fs_info, sb, -1);
	if (ret < 0)
		goto out;
	if (!btrfs_supported_super_csum(btrfs_super_csum_type(sb))) {
		ret = -EUCLEAN;
		btrfs_err(fs_info, "invalid csum type, has %u want %u",
			  btrfs_super_csum_type(sb), BTRFS_CSUM_TYPE_CRC32);
		goto out;
	}
	if (btrfs_super_incompat_flags(sb) & ~BTRFS_FEATURE_INCOMPAT_SUPP) {
		ret = -EUCLEAN;
		btrfs_err(fs_info,
		"invalid incompat flags, has 0x%llx valid mask 0x%llx",
			  btrfs_super_incompat_flags(sb),
			  (unsigned long long)BTRFS_FEATURE_INCOMPAT_SUPP);
		goto out;
	}
out:
	if (ret < 0)
		btrfs_err(fs_info,
		"super block corruption detected before writing it to disk");
	return ret;
}

static int load_super_root(struct btrfs_root *root, u64 bytenr, u64 gen, int level)
{
	struct btrfs_tree_parent_check check = {
		.level = level,
		.transid = gen,
		.owner_root = root->root_key.objectid
	};
	int ret = 0;

	root->node = read_tree_block(root->fs_info, bytenr, &check);
	if (IS_ERR(root->node)) {
		ret = PTR_ERR(root->node);
		root->node = NULL;
		return ret;
	}
	if (!extent_buffer_uptodate(root->node)) {
		free_extent_buffer(root->node);
		root->node = NULL;
		return -EIO;
	}

	btrfs_set_root_node(&root->root_item, root->node);
	root->commit_root = btrfs_root_node(root);
	btrfs_set_root_refs(&root->root_item, 1);
	return ret;
}

static int load_important_roots(struct btrfs_fs_info *fs_info)
{
	struct btrfs_super_block *sb = fs_info->super_copy;
	u64 gen, bytenr;
	int level, ret;

	bytenr = btrfs_super_root(sb);
	gen = btrfs_super_generation(sb);
	level = btrfs_super_root_level(sb);
	ret = load_super_root(fs_info->tree_root, bytenr, gen, level);
	if (ret) {
		btrfs_warn(fs_info, "couldn't read tree root");
		return ret;
	}
	return 0;
}

static int __cold init_tree_roots(struct btrfs_fs_info *fs_info)
{
	int backup_index = find_newest_super_backup(fs_info);
	struct btrfs_super_block *sb = fs_info->super_copy;
	struct btrfs_root *tree_root = fs_info->tree_root;
	bool handle_error = false;
	int ret = 0;
	int i;

	for (i = 0; i < BTRFS_NUM_BACKUP_ROOTS; i++) {
		if (handle_error) {
			if (!IS_ERR(tree_root->node))
				free_extent_buffer(tree_root->node);
			tree_root->node = NULL;

			if (!btrfs_test_opt(fs_info, USEBACKUPROOT))
				break;

			free_root_pointers(fs_info, 0);

			/*
			 * Don't use the log in recovery mode, it won't be
			 * valid
			 */
			btrfs_set_super_log_root(sb, 0);

			/* We can't trust the free space cache either */
			btrfs_set_opt(fs_info->mount_opt, CLEAR_CACHE);

			ret = read_backup_root(fs_info, i);
			backup_index = ret;
			if (ret < 0)
				return ret;
		}

		ret = load_important_roots(fs_info);
		if (ret) {
			handle_error = true;
			continue;
		}

		/*
		 * No need to hold btrfs_root::objectid_mutex since the fs
		 * hasn't been fully initialised and we are the only user
		 */
		ret = btrfs_init_root_free_objectid(tree_root);
		if (ret < 0) {
			handle_error = true;
			continue;
		}

		ASSERT(tree_root->free_objectid <= BTRFS_LAST_FREE_OBJECTID);

		ret = btrfs_read_roots(fs_info);
		if (ret < 0) {
			handle_error = true;
			continue;
		}

		/* All successful */
		fs_info->generation = btrfs_header_generation(tree_root->node);
		fs_info->last_trans_committed = fs_info->generation;
		fs_info->last_reloc_trans = 0;

		/* Always begin writing backup roots after the one being used */
		if (backup_index < 0) {
			fs_info->backup_root_index = 0;
		} else {
			fs_info->backup_root_index = backup_index + 1;
			fs_info->backup_root_index %= BTRFS_NUM_BACKUP_ROOTS;
		}
		break;
	}

	return ret;
}

void btrfs_init_fs_info(struct btrfs_fs_info *fs_info)
{
	INIT_RADIX_TREE(&fs_info->fs_roots_radix, GFP_ATOMIC);
	INIT_RADIX_TREE(&fs_info->buffer_radix, GFP_ATOMIC);
	INIT_LIST_HEAD(&fs_info->trans_list);
	INIT_LIST_HEAD(&fs_info->dead_roots);
	INIT_LIST_HEAD(&fs_info->delayed_iputs);
	INIT_LIST_HEAD(&fs_info->delalloc_roots);
	INIT_LIST_HEAD(&fs_info->caching_block_groups);
	spin_lock_init(&fs_info->delalloc_root_lock);
	spin_lock_init(&fs_info->trans_lock);
	spin_lock_init(&fs_info->fs_roots_radix_lock);
	spin_lock_init(&fs_info->delayed_iput_lock);
	spin_lock_init(&fs_info->defrag_inodes_lock);
	spin_lock_init(&fs_info->super_lock);
	spin_lock_init(&fs_info->buffer_lock);
	spin_lock_init(&fs_info->unused_bgs_lock);
	spin_lock_init(&fs_info->treelog_bg_lock);
	spin_lock_init(&fs_info->zone_active_bgs_lock);
	spin_lock_init(&fs_info->relocation_bg_lock);
	rwlock_init(&fs_info->tree_mod_log_lock);
	rwlock_init(&fs_info->global_root_lock);
	mutex_init(&fs_info->unused_bg_unpin_mutex);
	mutex_init(&fs_info->reclaim_bgs_lock);
	mutex_init(&fs_info->reloc_mutex);
	mutex_init(&fs_info->delalloc_root_mutex);
	mutex_init(&fs_info->zoned_meta_io_lock);
	mutex_init(&fs_info->zoned_data_reloc_io_lock);
	seqlock_init(&fs_info->profiles_lock);

	btrfs_lockdep_init_map(fs_info, btrfs_trans_num_writers);
	btrfs_lockdep_init_map(fs_info, btrfs_trans_num_extwriters);
	btrfs_lockdep_init_map(fs_info, btrfs_trans_pending_ordered);
	btrfs_lockdep_init_map(fs_info, btrfs_ordered_extent);
	btrfs_state_lockdep_init_map(fs_info, btrfs_trans_commit_start,
				     BTRFS_LOCKDEP_TRANS_COMMIT_START);
	btrfs_state_lockdep_init_map(fs_info, btrfs_trans_unblocked,
				     BTRFS_LOCKDEP_TRANS_UNBLOCKED);
	btrfs_state_lockdep_init_map(fs_info, btrfs_trans_super_committed,
				     BTRFS_LOCKDEP_TRANS_SUPER_COMMITTED);
	btrfs_state_lockdep_init_map(fs_info, btrfs_trans_completed,
				     BTRFS_LOCKDEP_TRANS_COMPLETED);

	INIT_LIST_HEAD(&fs_info->dirty_cowonly_roots);
	INIT_LIST_HEAD(&fs_info->space_info);
	INIT_LIST_HEAD(&fs_info->tree_mod_seq_list);
	INIT_LIST_HEAD(&fs_info->unused_bgs);
	INIT_LIST_HEAD(&fs_info->reclaim_bgs);
	INIT_LIST_HEAD(&fs_info->zone_active_bgs);
#ifdef CONFIG_BTRFS_DEBUG
	INIT_LIST_HEAD(&fs_info->allocated_roots);
	INIT_LIST_HEAD(&fs_info->allocated_ebs);
	spin_lock_init(&fs_info->eb_leak_lock);
#endif
	extent_map_tree_init(&fs_info->mapping_tree);
	btrfs_init_block_rsv(&fs_info->global_block_rsv,
			     BTRFS_BLOCK_RSV_GLOBAL);
	btrfs_init_block_rsv(&fs_info->trans_block_rsv, BTRFS_BLOCK_RSV_TRANS);
	btrfs_init_block_rsv(&fs_info->chunk_block_rsv, BTRFS_BLOCK_RSV_CHUNK);
	btrfs_init_block_rsv(&fs_info->empty_block_rsv, BTRFS_BLOCK_RSV_EMPTY);
	btrfs_init_block_rsv(&fs_info->delayed_block_rsv,
			     BTRFS_BLOCK_RSV_DELOPS);
	btrfs_init_block_rsv(&fs_info->delayed_refs_rsv,
			     BTRFS_BLOCK_RSV_DELREFS);

	atomic_set(&fs_info->async_delalloc_pages, 0);
	atomic_set(&fs_info->defrag_running, 0);
	atomic_set(&fs_info->nr_delayed_iputs, 0);
	atomic64_set(&fs_info->tree_mod_seq, 0);
	fs_info->global_root_tree = RB_ROOT;
	fs_info->max_inline = BTRFS_DEFAULT_MAX_INLINE;
	fs_info->metadata_ratio = 0;
	fs_info->defrag_inodes = RB_ROOT;
	atomic64_set(&fs_info->free_chunk_space, 0);
	fs_info->tree_mod_log = RB_ROOT;
	fs_info->commit_interval = BTRFS_DEFAULT_COMMIT_INTERVAL;
	fs_info->avg_delayed_ref_runtime = NSEC_PER_SEC >> 6; /* div by 64 */
	btrfs_init_ref_verify(fs_info);

	fs_info->thread_pool_size = min_t(unsigned long,
					  num_online_cpus() + 2, 8);

	INIT_LIST_HEAD(&fs_info->ordered_roots);
	spin_lock_init(&fs_info->ordered_root_lock);

	btrfs_init_scrub(fs_info);
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	fs_info->check_integrity_print_mask = 0;
#endif
	btrfs_init_balance(fs_info);
	btrfs_init_async_reclaim_work(fs_info);

	rwlock_init(&fs_info->block_group_cache_lock);
	fs_info->block_group_cache_tree = RB_ROOT_CACHED;

	extent_io_tree_init(fs_info, &fs_info->excluded_extents,
			    IO_TREE_FS_EXCLUDED_EXTENTS);

	mutex_init(&fs_info->ordered_operations_mutex);
	mutex_init(&fs_info->tree_log_mutex);
	mutex_init(&fs_info->chunk_mutex);
	mutex_init(&fs_info->transaction_kthread_mutex);
	mutex_init(&fs_info->cleaner_mutex);
	mutex_init(&fs_info->ro_block_group_mutex);
	init_rwsem(&fs_info->commit_root_sem);
	init_rwsem(&fs_info->cleanup_work_sem);
	init_rwsem(&fs_info->subvol_sem);
	sema_init(&fs_info->uuid_tree_rescan_sem, 1);

	btrfs_init_dev_replace_locks(fs_info);
	btrfs_init_qgroup(fs_info);
	btrfs_discard_init(fs_info);

	btrfs_init_free_cluster(&fs_info->meta_alloc_cluster);
	btrfs_init_free_cluster(&fs_info->data_alloc_cluster);

	init_waitqueue_head(&fs_info->transaction_throttle);
	init_waitqueue_head(&fs_info->transaction_wait);
	init_waitqueue_head(&fs_info->transaction_blocked_wait);
	init_waitqueue_head(&fs_info->async_submit_wait);
	init_waitqueue_head(&fs_info->delayed_iputs_wait);

	/* Usable values until the real ones are cached from the superblock */
	fs_info->nodesize = 4096;
	fs_info->sectorsize = 4096;
	fs_info->sectorsize_bits = ilog2(4096);
	fs_info->stripesize = 4096;

	fs_info->max_extent_size = BTRFS_MAX_EXTENT_SIZE;

	spin_lock_init(&fs_info->swapfile_pins_lock);
	fs_info->swapfile_pins = RB_ROOT;

	fs_info->bg_reclaim_threshold = BTRFS_DEFAULT_RECLAIM_THRESH;
	INIT_WORK(&fs_info->reclaim_bgs_work, btrfs_reclaim_bgs_work);
}

static int init_mount_fs_info(struct btrfs_fs_info *fs_info, struct super_block *sb)
{
	int ret;

	fs_info->sb = sb;
	sb->s_blocksize = BTRFS_BDEV_BLOCKSIZE;
	sb->s_blocksize_bits = blksize_bits(BTRFS_BDEV_BLOCKSIZE);

	ret = percpu_counter_init(&fs_info->ordered_bytes, 0, GFP_KERNEL);
	if (ret)
		return ret;

	ret = percpu_counter_init(&fs_info->dirty_metadata_bytes, 0, GFP_KERNEL);
	if (ret)
		return ret;

	fs_info->dirty_metadata_batch = PAGE_SIZE *
					(1 + ilog2(nr_cpu_ids));

	ret = percpu_counter_init(&fs_info->delalloc_bytes, 0, GFP_KERNEL);
	if (ret)
		return ret;

	ret = percpu_counter_init(&fs_info->dev_replace.bio_counter, 0,
			GFP_KERNEL);
	if (ret)
		return ret;

	fs_info->delayed_root = kmalloc(sizeof(struct btrfs_delayed_root),
					GFP_KERNEL);
	if (!fs_info->delayed_root)
		return -ENOMEM;
	btrfs_init_delayed_root(fs_info->delayed_root);

	if (sb_rdonly(sb))
		set_bit(BTRFS_FS_STATE_RO, &fs_info->fs_state);

	return btrfs_alloc_stripe_hash_table(fs_info);
}

static int btrfs_uuid_rescan_kthread(void *data)
{
	struct btrfs_fs_info *fs_info = data;
	int ret;

	/*
	 * 1st step is to iterate through the existing UUID tree and
	 * to delete all entries that contain outdated data.
	 * 2nd step is to add all missing entries to the UUID tree.
	 */
	ret = btrfs_uuid_tree_iterate(fs_info);
	if (ret < 0) {
		if (ret != -EINTR)
			btrfs_warn(fs_info, "iterating uuid_tree failed %d",
				   ret);
		up(&fs_info->uuid_tree_rescan_sem);
		return ret;
	}
	return btrfs_uuid_scan_kthread(data);
}

static int btrfs_check_uuid_tree(struct btrfs_fs_info *fs_info)
{
	struct task_struct *task;

	down(&fs_info->uuid_tree_rescan_sem);
	task = kthread_run(btrfs_uuid_rescan_kthread, fs_info, "btrfs-uuid");
	if (IS_ERR(task)) {
		/* fs_info->update_uuid_tree_gen remains 0 in all error case */
		btrfs_warn(fs_info, "failed to start uuid_rescan task");
		up(&fs_info->uuid_tree_rescan_sem);
		return PTR_ERR(task);
	}

	return 0;
}

/*
 * Some options only have meaning at mount time and shouldn't persist across
 * remounts, or be displayed. Clear these at the end of mount and remount
 * code paths.
 */
void btrfs_clear_oneshot_options(struct btrfs_fs_info *fs_info)
{
	btrfs_clear_opt(fs_info->mount_opt, USEBACKUPROOT);
	btrfs_clear_opt(fs_info->mount_opt, CLEAR_CACHE);
}

/*
 * Mounting logic specific to read-write file systems. Shared by open_ctree
 * and btrfs_remount when remounting from read-only to read-write.
 */
int btrfs_start_pre_rw_mount(struct btrfs_fs_info *fs_info)
{
	int ret;
	const bool cache_opt = btrfs_test_opt(fs_info, SPACE_CACHE);
	bool clear_free_space_tree = false;

	if (btrfs_test_opt(fs_info, CLEAR_CACHE) &&
	    btrfs_fs_compat_ro(fs_info, FREE_SPACE_TREE)) {
		clear_free_space_tree = true;
	} else if (btrfs_fs_compat_ro(fs_info, FREE_SPACE_TREE) &&
		   !btrfs_fs_compat_ro(fs_info, FREE_SPACE_TREE_VALID)) {
		btrfs_warn(fs_info, "free space tree is invalid");
		clear_free_space_tree = true;
	}

	if (clear_free_space_tree) {
		btrfs_info(fs_info, "clearing free space tree");
		ret = btrfs_clear_free_space_tree(fs_info);
		if (ret) {
			btrfs_warn(fs_info,
				   "failed to clear free space tree: %d", ret);
			goto out;
		}
	}

	/*
	 * btrfs_find_orphan_roots() is responsible for finding all the dead
	 * roots (with 0 refs), flag them with BTRFS_ROOT_DEAD_TREE and load
	 * them into the fs_info->fs_roots_radix tree. This must be done before
	 * calling btrfs_orphan_cleanup() on the tree root. If we don't do it
	 * first, then btrfs_orphan_cleanup() will delete a dead root's orphan
	 * item before the root's tree is deleted - this means that if we unmount
	 * or crash before the deletion completes, on the next mount we will not
	 * delete what remains of the tree because the orphan item does not
	 * exists anymore, which is what tells us we have a pending deletion.
	 */
	ret = btrfs_find_orphan_roots(fs_info);
	if (ret)
		goto out;

	ret = btrfs_cleanup_fs_roots(fs_info);
	if (ret)
		goto out;

	down_read(&fs_info->cleanup_work_sem);
	if ((ret = btrfs_orphan_cleanup(fs_info->fs_root)) ||
	    (ret = btrfs_orphan_cleanup(fs_info->tree_root))) {
		up_read(&fs_info->cleanup_work_sem);
		goto out;
	}
	up_read(&fs_info->cleanup_work_sem);

	mutex_lock(&fs_info->cleaner_mutex);
	ret = btrfs_recover_relocation(fs_info);
	mutex_unlock(&fs_info->cleaner_mutex);
	if (ret < 0) {
		btrfs_warn(fs_info, "failed to recover relocation: %d", ret);
		goto out;
	}

	if (btrfs_test_opt(fs_info, FREE_SPACE_TREE) &&
	    !btrfs_fs_compat_ro(fs_info, FREE_SPACE_TREE)) {
		btrfs_info(fs_info, "creating free space tree");
		ret = btrfs_create_free_space_tree(fs_info);
		if (ret) {
			btrfs_warn(fs_info,
				"failed to create free space tree: %d", ret);
			goto out;
		}
	}

	if (cache_opt != btrfs_free_space_cache_v1_active(fs_info)) {
		ret = btrfs_set_free_space_cache_v1_active(fs_info, cache_opt);
		if (ret)
			goto out;
	}

	ret = btrfs_resume_balance_async(fs_info);
	if (ret)
		goto out;

	ret = btrfs_resume_dev_replace_async(fs_info);
	if (ret) {
		btrfs_warn(fs_info, "failed to resume dev_replace");
		goto out;
	}

	btrfs_qgroup_rescan_resume(fs_info);

	if (!fs_info->uuid_root) {
		btrfs_info(fs_info, "creating UUID tree");
		ret = btrfs_create_uuid_tree(fs_info);
		if (ret) {
			btrfs_warn(fs_info,
				   "failed to create the UUID tree %d", ret);
			goto out;
		}
	}

out:
	return ret;
}

/*
 * Do various sanity and dependency checks of different features.
 *
 * @is_rw_mount:	If the mount is read-write.
 *
 * This is the place for less strict checks (like for subpage or artificial
 * feature dependencies).
 *
 * For strict checks or possible corruption detection, see
 * btrfs_validate_super().
 *
 * This should be called after btrfs_parse_options(), as some mount options
 * (space cache related) can modify on-disk format like free space tree and
 * screw up certain feature dependencies.
 */
int btrfs_check_features(struct btrfs_fs_info *fs_info, bool is_rw_mount)
{
	struct btrfs_super_block *disk_super = fs_info->super_copy;
	u64 incompat = btrfs_super_incompat_flags(disk_super);
	const u64 compat_ro = btrfs_super_compat_ro_flags(disk_super);
	const u64 compat_ro_unsupp = (compat_ro & ~BTRFS_FEATURE_COMPAT_RO_SUPP);

	if (incompat & ~BTRFS_FEATURE_INCOMPAT_SUPP) {
		btrfs_err(fs_info,
		"cannot mount because of unknown incompat features (0x%llx)",
		    incompat);
		return -EINVAL;
	}

	/* Runtime limitation for mixed block groups. */
	if ((incompat & BTRFS_FEATURE_INCOMPAT_MIXED_GROUPS) &&
	    (fs_info->sectorsize != fs_info->nodesize)) {
		btrfs_err(fs_info,
"unequal nodesize/sectorsize (%u != %u) are not allowed for mixed block groups",
			fs_info->nodesize, fs_info->sectorsize);
		return -EINVAL;
	}

	/* Mixed backref is an always-enabled feature. */
	incompat |= BTRFS_FEATURE_INCOMPAT_MIXED_BACKREF;

	/* Set compression related flags just in case. */
	if (fs_info->compress_type == BTRFS_COMPRESS_LZO)
		incompat |= BTRFS_FEATURE_INCOMPAT_COMPRESS_LZO;
	else if (fs_info->compress_type == BTRFS_COMPRESS_ZSTD)
		incompat |= BTRFS_FEATURE_INCOMPAT_COMPRESS_ZSTD;

	/*
	 * An ancient flag, which should really be marked deprecated.
	 * Such runtime limitation doesn't really need a incompat flag.
	 */
	if (btrfs_super_nodesize(disk_super) > PAGE_SIZE)
		incompat |= BTRFS_FEATURE_INCOMPAT_BIG_METADATA;

	if (compat_ro_unsupp && is_rw_mount) {
		btrfs_err(fs_info,
	"cannot mount read-write because of unknown compat_ro features (0x%llx)",
		       compat_ro);
		return -EINVAL;
	}

	/*
	 * We have unsupported RO compat features, although RO mounted, we
	 * should not cause any metadata writes, including log replay.
	 * Or we could screw up whatever the new feature requires.
	 */
	if (compat_ro_unsupp && btrfs_super_log_root(disk_super) &&
	    !btrfs_test_opt(fs_info, NOLOGREPLAY)) {
		btrfs_err(fs_info,
"cannot replay dirty log with unsupported compat_ro features (0x%llx), try rescue=nologreplay",
			  compat_ro);
		return -EINVAL;
	}

	/*
	 * Artificial limitations for block group tree, to force
	 * block-group-tree to rely on no-holes and free-space-tree.
	 */
	if (btrfs_fs_compat_ro(fs_info, BLOCK_GROUP_TREE) &&
	    (!btrfs_fs_incompat(fs_info, NO_HOLES) ||
	     !btrfs_test_opt(fs_info, FREE_SPACE_TREE))) {
		btrfs_err(fs_info,
"block-group-tree feature requires no-holes and free-space-tree features");
		return -EINVAL;
	}

	/*
	 * Subpage runtime limitation on v1 cache.
	 *
	 * V1 space cache still has some hard codeed PAGE_SIZE usage, while
	 * we're already defaulting to v2 cache, no need to bother v1 as it's
	 * going to be deprecated anyway.
	 */
	if (fs_info->sectorsize < PAGE_SIZE && btrfs_test_opt(fs_info, SPACE_CACHE)) {
		btrfs_warn(fs_info,
	"v1 space cache is not supported for page size %lu with sectorsize %u",
			   PAGE_SIZE, fs_info->sectorsize);
		return -EINVAL;
	}

	/* This can be called by remount, we need to protect the super block. */
	spin_lock(&fs_info->super_lock);
	btrfs_set_super_incompat_flags(disk_super, incompat);
	spin_unlock(&fs_info->super_lock);

	return 0;
}

int __cold open_ctree(struct super_block *sb, struct btrfs_fs_devices *fs_devices,
		      char *options)
{
	u32 sectorsize;
	u32 nodesize;
	u32 stripesize;
	u64 generation;
	u64 features;
	u16 csum_type;
	struct btrfs_super_block *disk_super;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	struct btrfs_root *tree_root;
	struct btrfs_root *chunk_root;
	int ret;
	int err = -EINVAL;
	int level;

	ret = init_mount_fs_info(fs_info, sb);
	if (ret) {
		err = ret;
		goto fail;
	}

	/* These need to be init'ed before we start creating inodes and such. */
	tree_root = btrfs_alloc_root(fs_info, BTRFS_ROOT_TREE_OBJECTID,
				     GFP_KERNEL);
	fs_info->tree_root = tree_root;
	chunk_root = btrfs_alloc_root(fs_info, BTRFS_CHUNK_TREE_OBJECTID,
				      GFP_KERNEL);
	fs_info->chunk_root = chunk_root;
	if (!tree_root || !chunk_root) {
		err = -ENOMEM;
		goto fail;
	}

	fs_info->btree_inode = new_inode(sb);
	if (!fs_info->btree_inode) {
		err = -ENOMEM;
		goto fail;
	}
	mapping_set_gfp_mask(fs_info->btree_inode->i_mapping, GFP_NOFS);
	btrfs_init_btree_inode(fs_info);

	invalidate_bdev(fs_devices->latest_dev->bdev);

	/*
	 * Read super block and check the signature bytes only
	 */
	disk_super = btrfs_read_dev_super(fs_devices->latest_dev->bdev);
	if (IS_ERR(disk_super)) {
		err = PTR_ERR(disk_super);
		goto fail_alloc;
	}

	/*
	 * Verify the type first, if that or the checksum value are
	 * corrupted, we'll find out
	 */
	csum_type = btrfs_super_csum_type(disk_super);
	if (!btrfs_supported_super_csum(csum_type)) {
		btrfs_err(fs_info, "unsupported checksum algorithm: %u",
			  csum_type);
		err = -EINVAL;
		btrfs_release_disk_super(disk_super);
		goto fail_alloc;
	}

	fs_info->csum_size = btrfs_super_csum_size(disk_super);

	ret = btrfs_init_csum_hash(fs_info, csum_type);
	if (ret) {
		err = ret;
		btrfs_release_disk_super(disk_super);
		goto fail_alloc;
	}

	/*
	 * We want to check superblock checksum, the type is stored inside.
	 * Pass the whole disk block of size BTRFS_SUPER_INFO_SIZE (4k).
	 */
	if (btrfs_check_super_csum(fs_info, disk_super)) {
		btrfs_err(fs_info, "superblock checksum mismatch");
		err = -EINVAL;
		btrfs_release_disk_super(disk_super);
		goto fail_alloc;
	}

	/*
	 * super_copy is zeroed at allocation time and we never touch the
	 * following bytes up to INFO_SIZE, the checksum is calculated from
	 * the whole block of INFO_SIZE
	 */
	memcpy(fs_info->super_copy, disk_super, sizeof(*fs_info->super_copy));
	btrfs_release_disk_super(disk_super);

	disk_super = fs_info->super_copy;


	features = btrfs_super_flags(disk_super);
	if (features & BTRFS_SUPER_FLAG_CHANGING_FSID_V2) {
		features &= ~BTRFS_SUPER_FLAG_CHANGING_FSID_V2;
		btrfs_set_super_flags(disk_super, features);
		btrfs_info(fs_info,
			"found metadata UUID change in progress flag, clearing");
	}

	memcpy(fs_info->super_for_commit, fs_info->super_copy,
	       sizeof(*fs_info->super_for_commit));

	ret = btrfs_validate_mount_super(fs_info);
	if (ret) {
		btrfs_err(fs_info, "superblock contains fatal errors");
		err = -EINVAL;
		goto fail_alloc;
	}

	if (!btrfs_super_root(disk_super))
		goto fail_alloc;

	/* check FS state, whether FS is broken. */
	if (btrfs_super_flags(disk_super) & BTRFS_SUPER_FLAG_ERROR)
		set_bit(BTRFS_FS_STATE_ERROR, &fs_info->fs_state);

	/*
	 * In the long term, we'll store the compression type in the super
	 * block, and it'll be used for per file compression control.
	 */
	fs_info->compress_type = BTRFS_COMPRESS_ZLIB;


	/* Set up fs_info before parsing mount options */
	nodesize = btrfs_super_nodesize(disk_super);
	sectorsize = btrfs_super_sectorsize(disk_super);
	stripesize = sectorsize;
	fs_info->dirty_metadata_batch = nodesize * (1 + ilog2(nr_cpu_ids));
	fs_info->delalloc_batch = sectorsize * 512 * (1 + ilog2(nr_cpu_ids));

	fs_info->nodesize = nodesize;
	fs_info->sectorsize = sectorsize;
	fs_info->sectorsize_bits = ilog2(sectorsize);
	fs_info->csums_per_leaf = BTRFS_MAX_ITEM_SIZE(fs_info) / fs_info->csum_size;
	fs_info->stripesize = stripesize;

	ret = btrfs_parse_options(fs_info, options, sb->s_flags);
	if (ret) {
		err = ret;
		goto fail_alloc;
	}

	ret = btrfs_check_features(fs_info, !sb_rdonly(sb));
	if (ret < 0) {
		err = ret;
		goto fail_alloc;
	}

	if (sectorsize < PAGE_SIZE) {
		struct btrfs_subpage_info *subpage_info;

		/*
		 * V1 space cache has some hardcoded PAGE_SIZE usage, and is
		 * going to be deprecated.
		 *
		 * Force to use v2 cache for subpage case.
		 */
		btrfs_clear_opt(fs_info->mount_opt, SPACE_CACHE);
		btrfs_set_and_info(fs_info, FREE_SPACE_TREE,
			"forcing free space tree for sector size %u with page size %lu",
			sectorsize, PAGE_SIZE);

		btrfs_warn(fs_info,
		"read-write for sector size %u with page size %lu is experimental",
			   sectorsize, PAGE_SIZE);
		subpage_info = kzalloc(sizeof(*subpage_info), GFP_KERNEL);
		if (!subpage_info)
			goto fail_alloc;
		btrfs_init_subpage_info(subpage_info, sectorsize);
		fs_info->subpage_info = subpage_info;
	}

	ret = btrfs_init_workqueues(fs_info);
	if (ret) {
		err = ret;
		goto fail_sb_buffer;
	}

	sb->s_bdi->ra_pages *= btrfs_super_num_devices(disk_super);
	sb->s_bdi->ra_pages = max(sb->s_bdi->ra_pages, SZ_4M / PAGE_SIZE);

	sb->s_blocksize = sectorsize;
	sb->s_blocksize_bits = blksize_bits(sectorsize);
	memcpy(&sb->s_uuid, fs_info->fs_devices->fsid, BTRFS_FSID_SIZE);

	mutex_lock(&fs_info->chunk_mutex);
	ret = btrfs_read_sys_array(fs_info);
	mutex_unlock(&fs_info->chunk_mutex);
	if (ret) {
		btrfs_err(fs_info, "failed to read the system array: %d", ret);
		goto fail_sb_buffer;
	}

	generation = btrfs_super_chunk_root_generation(disk_super);
	level = btrfs_super_chunk_root_level(disk_super);
	ret = load_super_root(chunk_root, btrfs_super_chunk_root(disk_super),
			      generation, level);
	if (ret) {
		btrfs_err(fs_info, "failed to read chunk root");
		goto fail_tree_roots;
	}

	read_extent_buffer(chunk_root->node, fs_info->chunk_tree_uuid,
			   offsetof(struct btrfs_header, chunk_tree_uuid),
			   BTRFS_UUID_SIZE);

	ret = btrfs_read_chunk_tree(fs_info);
	if (ret) {
		btrfs_err(fs_info, "failed to read chunk tree: %d", ret);
		goto fail_tree_roots;
	}

	/*
	 * At this point we know all the devices that make this filesystem,
	 * including the seed devices but we don't know yet if the replace
	 * target is required. So free devices that are not part of this
	 * filesystem but skip the replace target device which is checked
	 * below in btrfs_init_dev_replace().
	 */
	btrfs_free_extra_devids(fs_devices);
	if (!fs_devices->latest_dev->bdev) {
		btrfs_err(fs_info, "failed to read devices");
		goto fail_tree_roots;
	}

	ret = init_tree_roots(fs_info);
	if (ret)
		goto fail_tree_roots;

	/*
	 * Get zone type information of zoned block devices. This will also
	 * handle emulation of a zoned filesystem if a regular device has the
	 * zoned incompat feature flag set.
	 */
	ret = btrfs_get_dev_zone_info_all_devices(fs_info);
	if (ret) {
		btrfs_err(fs_info,
			  "zoned: failed to read device zone info: %d",
			  ret);
		goto fail_block_groups;
	}

	/*
	 * If we have a uuid root and we're not being told to rescan we need to
	 * check the generation here so we can set the
	 * BTRFS_FS_UPDATE_UUID_TREE_GEN bit.  Otherwise we could commit the
	 * transaction during a balance or the log replay without updating the
	 * uuid generation, and then if we crash we would rescan the uuid tree,
	 * even though it was perfectly fine.
	 */
	if (fs_info->uuid_root && !btrfs_test_opt(fs_info, RESCAN_UUID_TREE) &&
	    fs_info->generation == btrfs_super_uuid_tree_generation(disk_super))
		set_bit(BTRFS_FS_UPDATE_UUID_TREE_GEN, &fs_info->flags);

	ret = btrfs_verify_dev_extents(fs_info);
	if (ret) {
		btrfs_err(fs_info,
			  "failed to verify dev extents against chunks: %d",
			  ret);
		goto fail_block_groups;
	}
	ret = btrfs_recover_balance(fs_info);
	if (ret) {
		btrfs_err(fs_info, "failed to recover balance: %d", ret);
		goto fail_block_groups;
	}

	ret = btrfs_init_dev_stats(fs_info);
	if (ret) {
		btrfs_err(fs_info, "failed to init dev_stats: %d", ret);
		goto fail_block_groups;
	}

	ret = btrfs_init_dev_replace(fs_info);
	if (ret) {
		btrfs_err(fs_info, "failed to init dev_replace: %d", ret);
		goto fail_block_groups;
	}

	ret = btrfs_check_zoned_mode(fs_info);
	if (ret) {
		btrfs_err(fs_info, "failed to initialize zoned mode: %d",
			  ret);
		goto fail_block_groups;
	}

	ret = btrfs_sysfs_add_fsid(fs_devices);
	if (ret) {
		btrfs_err(fs_info, "failed to init sysfs fsid interface: %d",
				ret);
		goto fail_block_groups;
	}

	ret = btrfs_sysfs_add_mounted(fs_info);
	if (ret) {
		btrfs_err(fs_info, "failed to init sysfs interface: %d", ret);
		goto fail_fsdev_sysfs;
	}

	ret = btrfs_init_space_info(fs_info);
	if (ret) {
		btrfs_err(fs_info, "failed to initialize space info: %d", ret);
		goto fail_sysfs;
	}

	ret = btrfs_read_block_groups(fs_info);
	if (ret) {
		btrfs_err(fs_info, "failed to read block groups: %d", ret);
		goto fail_sysfs;
	}

	btrfs_free_zone_cache(fs_info);

	if (!sb_rdonly(sb) && fs_info->fs_devices->missing_devices &&
	    !btrfs_check_rw_degradable(fs_info, NULL)) {
		btrfs_warn(fs_info,
		"writable mount is not allowed due to too many missing devices");
		goto fail_sysfs;
	}

	fs_info->cleaner_kthread = kthread_run(cleaner_kthread, fs_info,
					       "btrfs-cleaner");
	if (IS_ERR(fs_info->cleaner_kthread))
		goto fail_sysfs;

	fs_info->transaction_kthread = kthread_run(transaction_kthread,
						   tree_root,
						   "btrfs-transaction");
	if (IS_ERR(fs_info->transaction_kthread))
		goto fail_cleaner;

	if (!btrfs_test_opt(fs_info, NOSSD) &&
	    !fs_info->fs_devices->rotating) {
		btrfs_set_and_info(fs_info, SSD, "enabling ssd optimizations");
	}

	/*
	 * For devices supporting discard turn on discard=async automatically,
	 * unless it's already set or disabled. This could be turned off by
	 * nodiscard for the same mount.
	 */
	if (!(btrfs_test_opt(fs_info, DISCARD_SYNC) ||
	      btrfs_test_opt(fs_info, DISCARD_ASYNC) ||
	      btrfs_test_opt(fs_info, NODISCARD)) &&
	    fs_info->fs_devices->discardable) {
		btrfs_set_and_info(fs_info, DISCARD_ASYNC,
				   "auto enabling async discard");
		btrfs_clear_opt(fs_info->mount_opt, NODISCARD);
	}

#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	if (btrfs_test_opt(fs_info, CHECK_INTEGRITY)) {
		ret = btrfsic_mount(fs_info, fs_devices,
				    btrfs_test_opt(fs_info,
					CHECK_INTEGRITY_DATA) ? 1 : 0,
				    fs_info->check_integrity_print_mask);
		if (ret)
			btrfs_warn(fs_info,
				"failed to initialize integrity check module: %d",
				ret);
	}
#endif
	ret = btrfs_read_qgroup_config(fs_info);
	if (ret)
		goto fail_trans_kthread;

	if (btrfs_build_ref_tree(fs_info))
		btrfs_err(fs_info, "couldn't build ref tree");

	/* do not make disk changes in broken FS or nologreplay is given */
	if (btrfs_super_log_root(disk_super) != 0 &&
	    !btrfs_test_opt(fs_info, NOLOGREPLAY)) {
		btrfs_info(fs_info, "start tree-log replay");
		ret = btrfs_replay_log(fs_info, fs_devices);
		if (ret) {
			err = ret;
			goto fail_qgroup;
		}
	}

	fs_info->fs_root = btrfs_get_fs_root(fs_info, BTRFS_FS_TREE_OBJECTID, true);
	if (IS_ERR(fs_info->fs_root)) {
		err = PTR_ERR(fs_info->fs_root);
		btrfs_warn(fs_info, "failed to read fs tree: %d", err);
		fs_info->fs_root = NULL;
		goto fail_qgroup;
	}

	if (sb_rdonly(sb))
		goto clear_oneshot;

	ret = btrfs_start_pre_rw_mount(fs_info);
	if (ret) {
		close_ctree(fs_info);
		return ret;
	}
	btrfs_discard_resume(fs_info);

	if (fs_info->uuid_root &&
	    (btrfs_test_opt(fs_info, RESCAN_UUID_TREE) ||
	     fs_info->generation != btrfs_super_uuid_tree_generation(disk_super))) {
		btrfs_info(fs_info, "checking UUID tree");
		ret = btrfs_check_uuid_tree(fs_info);
		if (ret) {
			btrfs_warn(fs_info,
				"failed to check the UUID tree: %d", ret);
			close_ctree(fs_info);
			return ret;
		}
	}

	set_bit(BTRFS_FS_OPEN, &fs_info->flags);

	/* Kick the cleaner thread so it'll start deleting snapshots. */
	if (test_bit(BTRFS_FS_UNFINISHED_DROPS, &fs_info->flags))
		wake_up_process(fs_info->cleaner_kthread);

clear_oneshot:
	btrfs_clear_oneshot_options(fs_info);
	return 0;

fail_qgroup:
	btrfs_free_qgroup_config(fs_info);
fail_trans_kthread:
	kthread_stop(fs_info->transaction_kthread);
	btrfs_cleanup_transaction(fs_info);
	btrfs_free_fs_roots(fs_info);
fail_cleaner:
	kthread_stop(fs_info->cleaner_kthread);

	/*
	 * make sure we're done with the btree inode before we stop our
	 * kthreads
	 */
	filemap_write_and_wait(fs_info->btree_inode->i_mapping);

fail_sysfs:
	btrfs_sysfs_remove_mounted(fs_info);

fail_fsdev_sysfs:
	btrfs_sysfs_remove_fsid(fs_info->fs_devices);

fail_block_groups:
	btrfs_put_block_group_cache(fs_info);

fail_tree_roots:
	if (fs_info->data_reloc_root)
		btrfs_drop_and_free_fs_root(fs_info, fs_info->data_reloc_root);
	free_root_pointers(fs_info, true);
	invalidate_inode_pages2(fs_info->btree_inode->i_mapping);

fail_sb_buffer:
	btrfs_stop_all_workers(fs_info);
	btrfs_free_block_groups(fs_info);
fail_alloc:
	btrfs_mapping_tree_free(&fs_info->mapping_tree);

	iput(fs_info->btree_inode);
fail:
	btrfs_close_devices(fs_info->fs_devices);
	return err;
}
ALLOW_ERROR_INJECTION(open_ctree, ERRNO);

static void btrfs_end_super_write(struct bio *bio)
{
	struct btrfs_device *device = bio->bi_private;
	struct bio_vec bvec;
	struct bvec_iter_all iter_all;
	struct page *page;

	bio_for_each_segment_all(bvec, bio, iter_all) {
		page = bvec.bv_page;

		if (bio->bi_status) {
			btrfs_warn_rl_in_rcu(device->fs_info,
				"lost page write due to IO error on %s (%d)",
				btrfs_dev_name(device),
				blk_status_to_errno(bio->bi_status));
			ClearPageUptodate(page);
			SetPageError(page);
			btrfs_dev_stat_inc_and_print(device,
						     BTRFS_DEV_STAT_WRITE_ERRS);
		} else {
			SetPageUptodate(page);
		}

		put_page(page);
		unlock_page(page);
	}

	bio_put(bio);
}

struct btrfs_super_block *btrfs_read_dev_one_super(struct block_device *bdev,
						   int copy_num, bool drop_cache)
{
	struct btrfs_super_block *super;
	struct page *page;
	u64 bytenr, bytenr_orig;
	struct address_space *mapping = bdev->bd_inode->i_mapping;
	int ret;

	bytenr_orig = btrfs_sb_offset(copy_num);
	ret = btrfs_sb_log_location_bdev(bdev, copy_num, READ, &bytenr);
	if (ret == -ENOENT)
		return ERR_PTR(-EINVAL);
	else if (ret)
		return ERR_PTR(ret);

	if (bytenr + BTRFS_SUPER_INFO_SIZE >= bdev_nr_bytes(bdev))
		return ERR_PTR(-EINVAL);

	if (drop_cache) {
		/* This should only be called with the primary sb. */
		ASSERT(copy_num == 0);

		/*
		 * Drop the page of the primary superblock, so later read will
		 * always read from the device.
		 */
		invalidate_inode_pages2_range(mapping,
				bytenr >> PAGE_SHIFT,
				(bytenr + BTRFS_SUPER_INFO_SIZE) >> PAGE_SHIFT);
	}

	page = read_cache_page_gfp(mapping, bytenr >> PAGE_SHIFT, GFP_NOFS);
	if (IS_ERR(page))
		return ERR_CAST(page);

	super = page_address(page);
	if (btrfs_super_magic(super) != BTRFS_MAGIC) {
		btrfs_release_disk_super(super);
		return ERR_PTR(-ENODATA);
	}

	if (btrfs_super_bytenr(super) != bytenr_orig) {
		btrfs_release_disk_super(super);
		return ERR_PTR(-EINVAL);
	}

	return super;
}


struct btrfs_super_block *btrfs_read_dev_super(struct block_device *bdev)
{
	struct btrfs_super_block *super, *latest = NULL;
	int i;
	u64 transid = 0;

	/* we would like to check all the supers, but that would make
	 * a btrfs mount succeed after a mkfs from a different FS.
	 * So, we need to add a special mount option to scan for
	 * later supers, using BTRFS_SUPER_MIRROR_MAX instead
	 */
	for (i = 0; i < 1; i++) {
		super = btrfs_read_dev_one_super(bdev, i, false);
		if (IS_ERR(super))
			continue;

		if (!latest || btrfs_super_generation(super) > transid) {
			if (latest)
				btrfs_release_disk_super(super);

			latest = super;
			transid = btrfs_super_generation(super);
		}
	}

	return super;
}

/*
 * Write superblock @sb to the @device. Do not wait for completion, all the
 * pages we use for writing are locked.
 *
 * Write @max_mirrors copies of the superblock, where 0 means default that fit
 * the expected device size at commit time. Note that max_mirrors must be
 * same for write and wait phases.
 *
 * Return number of errors when page is not found or submission fails.
 */
static int write_dev_supers(struct btrfs_device *device,
			    struct btrfs_super_block *sb, int max_mirrors)
{
	struct btrfs_fs_info *fs_info = device->fs_info;
	struct address_space *mapping = device->bdev->bd_inode->i_mapping;
	SHASH_DESC_ON_STACK(shash, fs_info->csum_shash);
	int i;
	int errors = 0;
	int ret;
	u64 bytenr, bytenr_orig;

	if (max_mirrors == 0)
		max_mirrors = BTRFS_SUPER_MIRROR_MAX;

	shash->tfm = fs_info->csum_shash;

	for (i = 0; i < max_mirrors; i++) {
		struct page *page;
		struct bio *bio;
		struct btrfs_super_block *disk_super;

		bytenr_orig = btrfs_sb_offset(i);
		ret = btrfs_sb_log_location(device, i, WRITE, &bytenr);
		if (ret == -ENOENT) {
			continue;
		} else if (ret < 0) {
			btrfs_err(device->fs_info,
				"couldn't get super block location for mirror %d",
				i);
			errors++;
			continue;
		}
		if (bytenr + BTRFS_SUPER_INFO_SIZE >=
		    device->commit_total_bytes)
			break;

		btrfs_set_super_bytenr(sb, bytenr_orig);

		crypto_shash_digest(shash, (const char *)sb + BTRFS_CSUM_SIZE,
				    BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE,
				    sb->csum);

		page = find_or_create_page(mapping, bytenr >> PAGE_SHIFT,
					   GFP_NOFS);
		if (!page) {
			btrfs_err(device->fs_info,
			    "couldn't get super block page for bytenr %llu",
			    bytenr);
			errors++;
			continue;
		}

		/* Bump the refcount for wait_dev_supers() */
		get_page(page);

		disk_super = page_address(page);
		memcpy(disk_super, sb, BTRFS_SUPER_INFO_SIZE);

		/*
		 * Directly use bios here instead of relying on the page cache
		 * to do I/O, so we don't lose the ability to do integrity
		 * checking.
		 */
		bio = bio_alloc(device->bdev, 1,
				REQ_OP_WRITE | REQ_SYNC | REQ_META | REQ_PRIO,
				GFP_NOFS);
		bio->bi_iter.bi_sector = bytenr >> SECTOR_SHIFT;
		bio->bi_private = device;
		bio->bi_end_io = btrfs_end_super_write;
		__bio_add_page(bio, page, BTRFS_SUPER_INFO_SIZE,
			       offset_in_page(bytenr));

		/*
		 * We FUA only the first super block.  The others we allow to
		 * go down lazy and there's a short window where the on-disk
		 * copies might still contain the older version.
		 */
		if (i == 0 && !btrfs_test_opt(device->fs_info, NOBARRIER))
			bio->bi_opf |= REQ_FUA;

		btrfsic_check_bio(bio);
		submit_bio(bio);

		if (btrfs_advance_sb_log(device, i))
			errors++;
	}
	return errors < i ? 0 : -1;
}

/*
 * Wait for write completion of superblocks done by write_dev_supers,
 * @max_mirrors same for write and wait phases.
 *
 * Return number of errors when page is not found or not marked up to
 * date.
 */
static int wait_dev_supers(struct btrfs_device *device, int max_mirrors)
{
	int i;
	int errors = 0;
	bool primary_failed = false;
	int ret;
	u64 bytenr;

	if (max_mirrors == 0)
		max_mirrors = BTRFS_SUPER_MIRROR_MAX;

	for (i = 0; i < max_mirrors; i++) {
		struct page *page;

		ret = btrfs_sb_log_location(device, i, READ, &bytenr);
		if (ret == -ENOENT) {
			break;
		} else if (ret < 0) {
			errors++;
			if (i == 0)
				primary_failed = true;
			continue;
		}
		if (bytenr + BTRFS_SUPER_INFO_SIZE >=
		    device->commit_total_bytes)
			break;

		page = find_get_page(device->bdev->bd_inode->i_mapping,
				     bytenr >> PAGE_SHIFT);
		if (!page) {
			errors++;
			if (i == 0)
				primary_failed = true;
			continue;
		}
		/* Page is submitted locked and unlocked once the IO completes */
		wait_on_page_locked(page);
		if (PageError(page)) {
			errors++;
			if (i == 0)
				primary_failed = true;
		}

		/* Drop our reference */
		put_page(page);

		/* Drop the reference from the writing run */
		put_page(page);
	}

	/* log error, force error return */
	if (primary_failed) {
		btrfs_err(device->fs_info, "error writing primary super block to device %llu",
			  device->devid);
		return -1;
	}

	return errors < i ? 0 : -1;
}

/*
 * endio for the write_dev_flush, this will wake anyone waiting
 * for the barrier when it is done
 */
static void btrfs_end_empty_barrier(struct bio *bio)
{
	bio_uninit(bio);
	complete(bio->bi_private);
}

/*
 * Submit a flush request to the device if it supports it. Error handling is
 * done in the waiting counterpart.
 */
static void write_dev_flush(struct btrfs_device *device)
{
	struct bio *bio = &device->flush_bio;

#ifndef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	/*
	 * When a disk has write caching disabled, we skip submission of a bio
	 * with flush and sync requests before writing the superblock, since
	 * it's not needed. However when the integrity checker is enabled, this
	 * results in reports that there are metadata blocks referred by a
	 * superblock that were not properly flushed. So don't skip the bio
	 * submission only when the integrity checker is enabled for the sake
	 * of simplicity, since this is a debug tool and not meant for use in
	 * non-debug builds.
	 */
	if (!bdev_write_cache(device->bdev))
		return;
#endif

	bio_init(bio, device->bdev, NULL, 0,
		 REQ_OP_WRITE | REQ_SYNC | REQ_PREFLUSH);
	bio->bi_end_io = btrfs_end_empty_barrier;
	init_completion(&device->flush_wait);
	bio->bi_private = &device->flush_wait;

	btrfsic_check_bio(bio);
	submit_bio(bio);
	set_bit(BTRFS_DEV_STATE_FLUSH_SENT, &device->dev_state);
}

/*
 * If the flush bio has been submitted by write_dev_flush, wait for it.
 */
static blk_status_t wait_dev_flush(struct btrfs_device *device)
{
	struct bio *bio = &device->flush_bio;

	if (!test_bit(BTRFS_DEV_STATE_FLUSH_SENT, &device->dev_state))
		return BLK_STS_OK;

	clear_bit(BTRFS_DEV_STATE_FLUSH_SENT, &device->dev_state);
	wait_for_completion_io(&device->flush_wait);

	return bio->bi_status;
}

static int check_barrier_error(struct btrfs_fs_info *fs_info)
{
	if (!btrfs_check_rw_degradable(fs_info, NULL))
		return -EIO;
	return 0;
}

/*
 * send an empty flush down to each device in parallel,
 * then wait for them
 */
static int barrier_all_devices(struct btrfs_fs_info *info)
{
	struct list_head *head;
	struct btrfs_device *dev;
	int errors_wait = 0;
	blk_status_t ret;

	lockdep_assert_held(&info->fs_devices->device_list_mutex);
	/* send down all the barriers */
	head = &info->fs_devices->devices;
	list_for_each_entry(dev, head, dev_list) {
		if (test_bit(BTRFS_DEV_STATE_MISSING, &dev->dev_state))
			continue;
		if (!dev->bdev)
			continue;
		if (!test_bit(BTRFS_DEV_STATE_IN_FS_METADATA, &dev->dev_state) ||
		    !test_bit(BTRFS_DEV_STATE_WRITEABLE, &dev->dev_state))
			continue;

		write_dev_flush(dev);
		dev->last_flush_error = BLK_STS_OK;
	}

	/* wait for all the barriers */
	list_for_each_entry(dev, head, dev_list) {
		if (test_bit(BTRFS_DEV_STATE_MISSING, &dev->dev_state))
			continue;
		if (!dev->bdev) {
			errors_wait++;
			continue;
		}
		if (!test_bit(BTRFS_DEV_STATE_IN_FS_METADATA, &dev->dev_state) ||
		    !test_bit(BTRFS_DEV_STATE_WRITEABLE, &dev->dev_state))
			continue;

		ret = wait_dev_flush(dev);
		if (ret) {
			dev->last_flush_error = ret;
			btrfs_dev_stat_inc_and_print(dev,
					BTRFS_DEV_STAT_FLUSH_ERRS);
			errors_wait++;
		}
	}

	if (errors_wait) {
		/*
		 * At some point we need the status of all disks
		 * to arrive at the volume status. So error checking
		 * is being pushed to a separate loop.
		 */
		return check_barrier_error(info);
	}
	return 0;
}

int btrfs_get_num_tolerated_disk_barrier_failures(u64 flags)
{
	int raid_type;
	int min_tolerated = INT_MAX;

	if ((flags & BTRFS_BLOCK_GROUP_PROFILE_MASK) == 0 ||
	    (flags & BTRFS_AVAIL_ALLOC_BIT_SINGLE))
		min_tolerated = min_t(int, min_tolerated,
				    btrfs_raid_array[BTRFS_RAID_SINGLE].
				    tolerated_failures);

	for (raid_type = 0; raid_type < BTRFS_NR_RAID_TYPES; raid_type++) {
		if (raid_type == BTRFS_RAID_SINGLE)
			continue;
		if (!(flags & btrfs_raid_array[raid_type].bg_flag))
			continue;
		min_tolerated = min_t(int, min_tolerated,
				    btrfs_raid_array[raid_type].
				    tolerated_failures);
	}

	if (min_tolerated == INT_MAX) {
		pr_warn("BTRFS: unknown raid flag: %llu", flags);
		min_tolerated = 0;
	}

	return min_tolerated;
}

int write_all_supers(struct btrfs_fs_info *fs_info, int max_mirrors)
{
	struct list_head *head;
	struct btrfs_device *dev;
	struct btrfs_super_block *sb;
	struct btrfs_dev_item *dev_item;
	int ret;
	int do_barriers;
	int max_errors;
	int total_errors = 0;
	u64 flags;

	do_barriers = !btrfs_test_opt(fs_info, NOBARRIER);

	/*
	 * max_mirrors == 0 indicates we're from commit_transaction,
	 * not from fsync where the tree roots in fs_info have not
	 * been consistent on disk.
	 */
	if (max_mirrors == 0)
		backup_super_roots(fs_info);

	sb = fs_info->super_for_commit;
	dev_item = &sb->dev_item;

	mutex_lock(&fs_info->fs_devices->device_list_mutex);
	head = &fs_info->fs_devices->devices;
	max_errors = btrfs_super_num_devices(fs_info->super_copy) - 1;

	if (do_barriers) {
		ret = barrier_all_devices(fs_info);
		if (ret) {
			mutex_unlock(
				&fs_info->fs_devices->device_list_mutex);
			btrfs_handle_fs_error(fs_info, ret,
					      "errors while submitting device barriers.");
			return ret;
		}
	}

	list_for_each_entry(dev, head, dev_list) {
		if (!dev->bdev) {
			total_errors++;
			continue;
		}
		if (!test_bit(BTRFS_DEV_STATE_IN_FS_METADATA, &dev->dev_state) ||
		    !test_bit(BTRFS_DEV_STATE_WRITEABLE, &dev->dev_state))
			continue;

		btrfs_set_stack_device_generation(dev_item, 0);
		btrfs_set_stack_device_type(dev_item, dev->type);
		btrfs_set_stack_device_id(dev_item, dev->devid);
		btrfs_set_stack_device_total_bytes(dev_item,
						   dev->commit_total_bytes);
		btrfs_set_stack_device_bytes_used(dev_item,
						  dev->commit_bytes_used);
		btrfs_set_stack_device_io_align(dev_item, dev->io_align);
		btrfs_set_stack_device_io_width(dev_item, dev->io_width);
		btrfs_set_stack_device_sector_size(dev_item, dev->sector_size);
		memcpy(dev_item->uuid, dev->uuid, BTRFS_UUID_SIZE);
		memcpy(dev_item->fsid, dev->fs_devices->metadata_uuid,
		       BTRFS_FSID_SIZE);

		flags = btrfs_super_flags(sb);
		btrfs_set_super_flags(sb, flags | BTRFS_HEADER_FLAG_WRITTEN);

		ret = btrfs_validate_write_super(fs_info, sb);
		if (ret < 0) {
			mutex_unlock(&fs_info->fs_devices->device_list_mutex);
			btrfs_handle_fs_error(fs_info, -EUCLEAN,
				"unexpected superblock corruption detected");
			return -EUCLEAN;
		}

		ret = write_dev_supers(dev, sb, max_mirrors);
		if (ret)
			total_errors++;
	}
	if (total_errors > max_errors) {
		btrfs_err(fs_info, "%d errors while writing supers",
			  total_errors);
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);

		/* FUA is masked off if unsupported and can't be the reason */
		btrfs_handle_fs_error(fs_info, -EIO,
				      "%d errors while writing supers",
				      total_errors);
		return -EIO;
	}

	total_errors = 0;
	list_for_each_entry(dev, head, dev_list) {
		if (!dev->bdev)
			continue;
		if (!test_bit(BTRFS_DEV_STATE_IN_FS_METADATA, &dev->dev_state) ||
		    !test_bit(BTRFS_DEV_STATE_WRITEABLE, &dev->dev_state))
			continue;

		ret = wait_dev_supers(dev, max_mirrors);
		if (ret)
			total_errors++;
	}
	mutex_unlock(&fs_info->fs_devices->device_list_mutex);
	if (total_errors > max_errors) {
		btrfs_handle_fs_error(fs_info, -EIO,
				      "%d errors while writing supers",
				      total_errors);
		return -EIO;
	}
	return 0;
}

/* Drop a fs root from the radix tree and free it. */
void btrfs_drop_and_free_fs_root(struct btrfs_fs_info *fs_info,
				  struct btrfs_root *root)
{
	bool drop_ref = false;

	spin_lock(&fs_info->fs_roots_radix_lock);
	radix_tree_delete(&fs_info->fs_roots_radix,
			  (unsigned long)root->root_key.objectid);
	if (test_and_clear_bit(BTRFS_ROOT_IN_RADIX, &root->state))
		drop_ref = true;
	spin_unlock(&fs_info->fs_roots_radix_lock);

	if (BTRFS_FS_ERROR(fs_info)) {
		ASSERT(root->log_root == NULL);
		if (root->reloc_root) {
			btrfs_put_root(root->reloc_root);
			root->reloc_root = NULL;
		}
	}

	if (drop_ref)
		btrfs_put_root(root);
}

int btrfs_cleanup_fs_roots(struct btrfs_fs_info *fs_info)
{
	u64 root_objectid = 0;
	struct btrfs_root *gang[8];
	int i = 0;
	int err = 0;
	unsigned int ret = 0;

	while (1) {
		spin_lock(&fs_info->fs_roots_radix_lock);
		ret = radix_tree_gang_lookup(&fs_info->fs_roots_radix,
					     (void **)gang, root_objectid,
					     ARRAY_SIZE(gang));
		if (!ret) {
			spin_unlock(&fs_info->fs_roots_radix_lock);
			break;
		}
		root_objectid = gang[ret - 1]->root_key.objectid + 1;

		for (i = 0; i < ret; i++) {
			/* Avoid to grab roots in dead_roots */
			if (btrfs_root_refs(&gang[i]->root_item) == 0) {
				gang[i] = NULL;
				continue;
			}
			/* grab all the search result for later use */
			gang[i] = btrfs_grab_root(gang[i]);
		}
		spin_unlock(&fs_info->fs_roots_radix_lock);

		for (i = 0; i < ret; i++) {
			if (!gang[i])
				continue;
			root_objectid = gang[i]->root_key.objectid;
			err = btrfs_orphan_cleanup(gang[i]);
			if (err)
				break;
			btrfs_put_root(gang[i]);
		}
		root_objectid++;
	}

	/* release the uncleaned roots due to error */
	for (; i < ret; i++) {
		if (gang[i])
			btrfs_put_root(gang[i]);
	}
	return err;
}

int btrfs_commit_super(struct btrfs_fs_info *fs_info)
{
	struct btrfs_root *root = fs_info->tree_root;
	struct btrfs_trans_handle *trans;

	mutex_lock(&fs_info->cleaner_mutex);
	btrfs_run_delayed_iputs(fs_info);
	mutex_unlock(&fs_info->cleaner_mutex);
	wake_up_process(fs_info->cleaner_kthread);

	/* wait until ongoing cleanup work done */
	down_write(&fs_info->cleanup_work_sem);
	up_write(&fs_info->cleanup_work_sem);

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans))
		return PTR_ERR(trans);
	return btrfs_commit_transaction(trans);
}

static void warn_about_uncommitted_trans(struct btrfs_fs_info *fs_info)
{
	struct btrfs_transaction *trans;
	struct btrfs_transaction *tmp;
	bool found = false;

	if (list_empty(&fs_info->trans_list))
		return;

	/*
	 * This function is only called at the very end of close_ctree(),
	 * thus no other running transaction, no need to take trans_lock.
	 */
	ASSERT(test_bit(BTRFS_FS_CLOSING_DONE, &fs_info->flags));
	list_for_each_entry_safe(trans, tmp, &fs_info->trans_list, list) {
		struct extent_state *cached = NULL;
		u64 dirty_bytes = 0;
		u64 cur = 0;
		u64 found_start;
		u64 found_end;

		found = true;
		while (!find_first_extent_bit(&trans->dirty_pages, cur,
			&found_start, &found_end, EXTENT_DIRTY, &cached)) {
			dirty_bytes += found_end + 1 - found_start;
			cur = found_end + 1;
		}
		btrfs_warn(fs_info,
	"transaction %llu (with %llu dirty metadata bytes) is not committed",
			   trans->transid, dirty_bytes);
		btrfs_cleanup_one_transaction(trans, fs_info);

		if (trans == fs_info->running_transaction)
			fs_info->running_transaction = NULL;
		list_del_init(&trans->list);

		btrfs_put_transaction(trans);
		trace_btrfs_transaction_commit(fs_info);
	}
	ASSERT(!found);
}

void __cold close_ctree(struct btrfs_fs_info *fs_info)
{
	int ret;

	set_bit(BTRFS_FS_CLOSING_START, &fs_info->flags);

	/*
	 * If we had UNFINISHED_DROPS we could still be processing them, so
	 * clear that bit and wake up relocation so it can stop.
	 * We must do this before stopping the block group reclaim task, because
	 * at btrfs_relocate_block_group() we wait for this bit, and after the
	 * wait we stop with -EINTR if btrfs_fs_closing() returns non-zero - we
	 * have just set BTRFS_FS_CLOSING_START, so btrfs_fs_closing() will
	 * return 1.
	 */
	btrfs_wake_unfinished_drop(fs_info);

	/*
	 * We may have the reclaim task running and relocating a data block group,
	 * in which case it may create delayed iputs. So stop it before we park
	 * the cleaner kthread otherwise we can get new delayed iputs after
	 * parking the cleaner, and that can make the async reclaim task to hang
	 * if it's waiting for delayed iputs to complete, since the cleaner is
	 * parked and can not run delayed iputs - this will make us hang when
	 * trying to stop the async reclaim task.
	 */
	cancel_work_sync(&fs_info->reclaim_bgs_work);
	/*
	 * We don't want the cleaner to start new transactions, add more delayed
	 * iputs, etc. while we're closing. We can't use kthread_stop() yet
	 * because that frees the task_struct, and the transaction kthread might
	 * still try to wake up the cleaner.
	 */
	kthread_park(fs_info->cleaner_kthread);

	/* wait for the qgroup rescan worker to stop */
	btrfs_qgroup_wait_for_completion(fs_info, false);

	/* wait for the uuid_scan task to finish */
	down(&fs_info->uuid_tree_rescan_sem);
	/* avoid complains from lockdep et al., set sem back to initial state */
	up(&fs_info->uuid_tree_rescan_sem);

	/* pause restriper - we want to resume on mount */
	btrfs_pause_balance(fs_info);

	btrfs_dev_replace_suspend_for_unmount(fs_info);

	btrfs_scrub_cancel(fs_info);

	/* wait for any defraggers to finish */
	wait_event(fs_info->transaction_wait,
		   (atomic_read(&fs_info->defrag_running) == 0));

	/* clear out the rbtree of defraggable inodes */
	btrfs_cleanup_defrag_inodes(fs_info);

	/*
	 * After we parked the cleaner kthread, ordered extents may have
	 * completed and created new delayed iputs. If one of the async reclaim
	 * tasks is running and in the RUN_DELAYED_IPUTS flush state, then we
	 * can hang forever trying to stop it, because if a delayed iput is
	 * added after it ran btrfs_run_delayed_iputs() and before it called
	 * btrfs_wait_on_delayed_iputs(), it will hang forever since there is
	 * no one else to run iputs.
	 *
	 * So wait for all ongoing ordered extents to complete and then run
	 * delayed iputs. This works because once we reach this point no one
	 * can either create new ordered extents nor create delayed iputs
	 * through some other means.
	 *
	 * Also note that btrfs_wait_ordered_roots() is not safe here, because
	 * it waits for BTRFS_ORDERED_COMPLETE to be set on an ordered extent,
	 * but the delayed iput for the respective inode is made only when doing
	 * the final btrfs_put_ordered_extent() (which must happen at
	 * btrfs_finish_ordered_io() when we are unmounting).
	 */
	btrfs_flush_workqueue(fs_info->endio_write_workers);
	/* Ordered extents for free space inodes. */
	btrfs_flush_workqueue(fs_info->endio_freespace_worker);
	btrfs_run_delayed_iputs(fs_info);

	cancel_work_sync(&fs_info->async_reclaim_work);
	cancel_work_sync(&fs_info->async_data_reclaim_work);
	cancel_work_sync(&fs_info->preempt_reclaim_work);

	/* Cancel or finish ongoing discard work */
	btrfs_discard_cleanup(fs_info);

	if (!sb_rdonly(fs_info->sb)) {
		/*
		 * The cleaner kthread is stopped, so do one final pass over
		 * unused block groups.
		 */
		btrfs_delete_unused_bgs(fs_info);

		/*
		 * There might be existing delayed inode workers still running
		 * and holding an empty delayed inode item. We must wait for
		 * them to complete first because they can create a transaction.
		 * This happens when someone calls btrfs_balance_delayed_items()
		 * and then a transaction commit runs the same delayed nodes
		 * before any delayed worker has done something with the nodes.
		 * We must wait for any worker here and not at transaction
		 * commit time since that could cause a deadlock.
		 * This is a very rare case.
		 */
		btrfs_flush_workqueue(fs_info->delayed_workers);

		ret = btrfs_commit_super(fs_info);
		if (ret)
			btrfs_err(fs_info, "commit super ret %d", ret);
	}

	if (BTRFS_FS_ERROR(fs_info))
		btrfs_error_commit_super(fs_info);

	kthread_stop(fs_info->transaction_kthread);
	kthread_stop(fs_info->cleaner_kthread);

	ASSERT(list_empty(&fs_info->delayed_iputs));
	set_bit(BTRFS_FS_CLOSING_DONE, &fs_info->flags);

	if (btrfs_check_quota_leak(fs_info)) {
		WARN_ON(IS_ENABLED(CONFIG_BTRFS_DEBUG));
		btrfs_err(fs_info, "qgroup reserved space leaked");
	}

	btrfs_free_qgroup_config(fs_info);
	ASSERT(list_empty(&fs_info->delalloc_roots));

	if (percpu_counter_sum(&fs_info->delalloc_bytes)) {
		btrfs_info(fs_info, "at unmount delalloc count %lld",
		       percpu_counter_sum(&fs_info->delalloc_bytes));
	}

	if (percpu_counter_sum(&fs_info->ordered_bytes))
		btrfs_info(fs_info, "at unmount dio bytes count %lld",
			   percpu_counter_sum(&fs_info->ordered_bytes));

	btrfs_sysfs_remove_mounted(fs_info);
	btrfs_sysfs_remove_fsid(fs_info->fs_devices);

	btrfs_put_block_group_cache(fs_info);

	/*
	 * we must make sure there is not any read request to
	 * submit after we stopping all workers.
	 */
	invalidate_inode_pages2(fs_info->btree_inode->i_mapping);
	btrfs_stop_all_workers(fs_info);

	/* We shouldn't have any transaction open at this point */
	warn_about_uncommitted_trans(fs_info);

	clear_bit(BTRFS_FS_OPEN, &fs_info->flags);
	free_root_pointers(fs_info, true);
	btrfs_free_fs_roots(fs_info);

	/*
	 * We must free the block groups after dropping the fs_roots as we could
	 * have had an IO error and have left over tree log blocks that aren't
	 * cleaned up until the fs roots are freed.  This makes the block group
	 * accounting appear to be wrong because there's pending reserved bytes,
	 * so make sure we do the block group cleanup afterwards.
	 */
	btrfs_free_block_groups(fs_info);

	iput(fs_info->btree_inode);

#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	if (btrfs_test_opt(fs_info, CHECK_INTEGRITY))
		btrfsic_unmount(fs_info->fs_devices);
#endif

	btrfs_mapping_tree_free(&fs_info->mapping_tree);
	btrfs_close_devices(fs_info->fs_devices);
}

int btrfs_buffer_uptodate(struct extent_buffer *buf, u64 parent_transid,
			  int atomic)
{
	int ret;
	struct inode *btree_inode = buf->pages[0]->mapping->host;

	ret = extent_buffer_uptodate(buf);
	if (!ret)
		return ret;

	ret = verify_parent_transid(&BTRFS_I(btree_inode)->io_tree, buf,
				    parent_transid, atomic);
	if (ret == -EAGAIN)
		return ret;
	return !ret;
}

void btrfs_mark_buffer_dirty(struct extent_buffer *buf)
{
	struct btrfs_fs_info *fs_info = buf->fs_info;
	u64 transid = btrfs_header_generation(buf);
	int was_dirty;

#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
	/*
	 * This is a fast path so only do this check if we have sanity tests
	 * enabled.  Normal people shouldn't be using unmapped buffers as dirty
	 * outside of the sanity tests.
	 */
	if (unlikely(test_bit(EXTENT_BUFFER_UNMAPPED, &buf->bflags)))
		return;
#endif
	btrfs_assert_tree_write_locked(buf);
	if (transid != fs_info->generation)
		WARN(1, KERN_CRIT "btrfs transid mismatch buffer %llu, found %llu running %llu\n",
			buf->start, transid, fs_info->generation);
	was_dirty = set_extent_buffer_dirty(buf);
	if (!was_dirty)
		percpu_counter_add_batch(&fs_info->dirty_metadata_bytes,
					 buf->len,
					 fs_info->dirty_metadata_batch);
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	/*
	 * Since btrfs_mark_buffer_dirty() can be called with item pointer set
	 * but item data not updated.
	 * So here we should only check item pointers, not item data.
	 */
	if (btrfs_header_level(buf) == 0 &&
	    btrfs_check_leaf_relaxed(buf)) {
		btrfs_print_leaf(buf);
		ASSERT(0);
	}
#endif
}

static void __btrfs_btree_balance_dirty(struct btrfs_fs_info *fs_info,
					int flush_delayed)
{
	/*
	 * looks as though older kernels can get into trouble with
	 * this code, they end up stuck in balance_dirty_pages forever
	 */
	int ret;

	if (current->flags & PF_MEMALLOC)
		return;

	if (flush_delayed)
		btrfs_balance_delayed_items(fs_info);

	ret = __percpu_counter_compare(&fs_info->dirty_metadata_bytes,
				     BTRFS_DIRTY_METADATA_THRESH,
				     fs_info->dirty_metadata_batch);
	if (ret > 0) {
		balance_dirty_pages_ratelimited(fs_info->btree_inode->i_mapping);
	}
}

void btrfs_btree_balance_dirty(struct btrfs_fs_info *fs_info)
{
	__btrfs_btree_balance_dirty(fs_info, 1);
}

void btrfs_btree_balance_dirty_nodelay(struct btrfs_fs_info *fs_info)
{
	__btrfs_btree_balance_dirty(fs_info, 0);
}

static void btrfs_error_commit_super(struct btrfs_fs_info *fs_info)
{
	/* cleanup FS via transaction */
	btrfs_cleanup_transaction(fs_info);

	mutex_lock(&fs_info->cleaner_mutex);
	btrfs_run_delayed_iputs(fs_info);
	mutex_unlock(&fs_info->cleaner_mutex);

	down_write(&fs_info->cleanup_work_sem);
	up_write(&fs_info->cleanup_work_sem);
}

static void btrfs_drop_all_logs(struct btrfs_fs_info *fs_info)
{
	struct btrfs_root *gang[8];
	u64 root_objectid = 0;
	int ret;

	spin_lock(&fs_info->fs_roots_radix_lock);
	while ((ret = radix_tree_gang_lookup(&fs_info->fs_roots_radix,
					     (void **)gang, root_objectid,
					     ARRAY_SIZE(gang))) != 0) {
		int i;

		for (i = 0; i < ret; i++)
			gang[i] = btrfs_grab_root(gang[i]);
		spin_unlock(&fs_info->fs_roots_radix_lock);

		for (i = 0; i < ret; i++) {
			if (!gang[i])
				continue;
			root_objectid = gang[i]->root_key.objectid;
			btrfs_free_log(NULL, gang[i]);
			btrfs_put_root(gang[i]);
		}
		root_objectid++;
		spin_lock(&fs_info->fs_roots_radix_lock);
	}
	spin_unlock(&fs_info->fs_roots_radix_lock);
	btrfs_free_log_root_tree(NULL, fs_info);
}

static void btrfs_destroy_ordered_extents(struct btrfs_root *root)
{
	struct btrfs_ordered_extent *ordered;

	spin_lock(&root->ordered_extent_lock);
	/*
	 * This will just short circuit the ordered completion stuff which will
	 * make sure the ordered extent gets properly cleaned up.
	 */
	list_for_each_entry(ordered, &root->ordered_extents,
			    root_extent_list)
		set_bit(BTRFS_ORDERED_IOERR, &ordered->flags);
	spin_unlock(&root->ordered_extent_lock);
}

static void btrfs_destroy_all_ordered_extents(struct btrfs_fs_info *fs_info)
{
	struct btrfs_root *root;
	struct list_head splice;

	INIT_LIST_HEAD(&splice);

	spin_lock(&fs_info->ordered_root_lock);
	list_splice_init(&fs_info->ordered_roots, &splice);
	while (!list_empty(&splice)) {
		root = list_first_entry(&splice, struct btrfs_root,
					ordered_root);
		list_move_tail(&root->ordered_root,
			       &fs_info->ordered_roots);

		spin_unlock(&fs_info->ordered_root_lock);
		btrfs_destroy_ordered_extents(root);

		cond_resched();
		spin_lock(&fs_info->ordered_root_lock);
	}
	spin_unlock(&fs_info->ordered_root_lock);

	/*
	 * We need this here because if we've been flipped read-only we won't
	 * get sync() from the umount, so we need to make sure any ordered
	 * extents that haven't had their dirty pages IO start writeout yet
	 * actually get run and error out properly.
	 */
	btrfs_wait_ordered_roots(fs_info, U64_MAX, 0, (u64)-1);
}

static int btrfs_destroy_delayed_refs(struct btrfs_transaction *trans,
				      struct btrfs_fs_info *fs_info)
{
	struct rb_node *node;
	struct btrfs_delayed_ref_root *delayed_refs;
	struct btrfs_delayed_ref_node *ref;
	int ret = 0;

	delayed_refs = &trans->delayed_refs;

	spin_lock(&delayed_refs->lock);
	if (atomic_read(&delayed_refs->num_entries) == 0) {
		spin_unlock(&delayed_refs->lock);
		btrfs_debug(fs_info, "delayed_refs has NO entry");
		return ret;
	}

	while ((node = rb_first_cached(&delayed_refs->href_root)) != NULL) {
		struct btrfs_delayed_ref_head *head;
		struct rb_node *n;
		bool pin_bytes = false;

		head = rb_entry(node, struct btrfs_delayed_ref_head,
				href_node);
		if (btrfs_delayed_ref_lock(delayed_refs, head))
			continue;

		spin_lock(&head->lock);
		while ((n = rb_first_cached(&head->ref_tree)) != NULL) {
			ref = rb_entry(n, struct btrfs_delayed_ref_node,
				       ref_node);
			ref->in_tree = 0;
			rb_erase_cached(&ref->ref_node, &head->ref_tree);
			RB_CLEAR_NODE(&ref->ref_node);
			if (!list_empty(&ref->add_list))
				list_del(&ref->add_list);
			atomic_dec(&delayed_refs->num_entries);
			btrfs_put_delayed_ref(ref);
		}
		if (head->must_insert_reserved)
			pin_bytes = true;
		btrfs_free_delayed_extent_op(head->extent_op);
		btrfs_delete_ref_head(delayed_refs, head);
		spin_unlock(&head->lock);
		spin_unlock(&delayed_refs->lock);
		mutex_unlock(&head->mutex);

		if (pin_bytes) {
			struct btrfs_block_group *cache;

			cache = btrfs_lookup_block_group(fs_info, head->bytenr);
			BUG_ON(!cache);

			spin_lock(&cache->space_info->lock);
			spin_lock(&cache->lock);
			cache->pinned += head->num_bytes;
			btrfs_space_info_update_bytes_pinned(fs_info,
				cache->space_info, head->num_bytes);
			cache->reserved -= head->num_bytes;
			cache->space_info->bytes_reserved -= head->num_bytes;
			spin_unlock(&cache->lock);
			spin_unlock(&cache->space_info->lock);

			btrfs_put_block_group(cache);

			btrfs_error_unpin_extent_range(fs_info, head->bytenr,
				head->bytenr + head->num_bytes - 1);
		}
		btrfs_cleanup_ref_head_accounting(fs_info, delayed_refs, head);
		btrfs_put_delayed_ref_head(head);
		cond_resched();
		spin_lock(&delayed_refs->lock);
	}
	btrfs_qgroup_destroy_extent_records(trans);

	spin_unlock(&delayed_refs->lock);

	return ret;
}

static void btrfs_destroy_delalloc_inodes(struct btrfs_root *root)
{
	struct btrfs_inode *btrfs_inode;
	struct list_head splice;

	INIT_LIST_HEAD(&splice);

	spin_lock(&root->delalloc_lock);
	list_splice_init(&root->delalloc_inodes, &splice);

	while (!list_empty(&splice)) {
		struct inode *inode = NULL;
		btrfs_inode = list_first_entry(&splice, struct btrfs_inode,
					       delalloc_inodes);
		__btrfs_del_delalloc_inode(root, btrfs_inode);
		spin_unlock(&root->delalloc_lock);

		/*
		 * Make sure we get a live inode and that it'll not disappear
		 * meanwhile.
		 */
		inode = igrab(&btrfs_inode->vfs_inode);
		if (inode) {
			invalidate_inode_pages2(inode->i_mapping);
			iput(inode);
		}
		spin_lock(&root->delalloc_lock);
	}
	spin_unlock(&root->delalloc_lock);
}

static void btrfs_destroy_all_delalloc_inodes(struct btrfs_fs_info *fs_info)
{
	struct btrfs_root *root;
	struct list_head splice;

	INIT_LIST_HEAD(&splice);

	spin_lock(&fs_info->delalloc_root_lock);
	list_splice_init(&fs_info->delalloc_roots, &splice);
	while (!list_empty(&splice)) {
		root = list_first_entry(&splice, struct btrfs_root,
					 delalloc_root);
		root = btrfs_grab_root(root);
		BUG_ON(!root);
		spin_unlock(&fs_info->delalloc_root_lock);

		btrfs_destroy_delalloc_inodes(root);
		btrfs_put_root(root);

		spin_lock(&fs_info->delalloc_root_lock);
	}
	spin_unlock(&fs_info->delalloc_root_lock);
}

static int btrfs_destroy_marked_extents(struct btrfs_fs_info *fs_info,
					struct extent_io_tree *dirty_pages,
					int mark)
{
	int ret;
	struct extent_buffer *eb;
	u64 start = 0;
	u64 end;

	while (1) {
		ret = find_first_extent_bit(dirty_pages, start, &start, &end,
					    mark, NULL);
		if (ret)
			break;

		clear_extent_bits(dirty_pages, start, end, mark);
		while (start <= end) {
			eb = find_extent_buffer(fs_info, start);
			start += fs_info->nodesize;
			if (!eb)
				continue;
			wait_on_extent_buffer_writeback(eb);

			if (test_and_clear_bit(EXTENT_BUFFER_DIRTY,
					       &eb->bflags))
				clear_extent_buffer_dirty(eb);
			free_extent_buffer_stale(eb);
		}
	}

	return ret;
}

static int btrfs_destroy_pinned_extent(struct btrfs_fs_info *fs_info,
				       struct extent_io_tree *unpin)
{
	u64 start;
	u64 end;
	int ret;

	while (1) {
		struct extent_state *cached_state = NULL;

		/*
		 * The btrfs_finish_extent_commit() may get the same range as
		 * ours between find_first_extent_bit and clear_extent_dirty.
		 * Hence, hold the unused_bg_unpin_mutex to avoid double unpin
		 * the same extent range.
		 */
		mutex_lock(&fs_info->unused_bg_unpin_mutex);
		ret = find_first_extent_bit(unpin, 0, &start, &end,
					    EXTENT_DIRTY, &cached_state);
		if (ret) {
			mutex_unlock(&fs_info->unused_bg_unpin_mutex);
			break;
		}

		clear_extent_dirty(unpin, start, end, &cached_state);
		free_extent_state(cached_state);
		btrfs_error_unpin_extent_range(fs_info, start, end);
		mutex_unlock(&fs_info->unused_bg_unpin_mutex);
		cond_resched();
	}

	return 0;
}

static void btrfs_cleanup_bg_io(struct btrfs_block_group *cache)
{
	struct inode *inode;

	inode = cache->io_ctl.inode;
	if (inode) {
		invalidate_inode_pages2(inode->i_mapping);
		BTRFS_I(inode)->generation = 0;
		cache->io_ctl.inode = NULL;
		iput(inode);
	}
	ASSERT(cache->io_ctl.pages == NULL);
	btrfs_put_block_group(cache);
}

void btrfs_cleanup_dirty_bgs(struct btrfs_transaction *cur_trans,
			     struct btrfs_fs_info *fs_info)
{
	struct btrfs_block_group *cache;

	spin_lock(&cur_trans->dirty_bgs_lock);
	while (!list_empty(&cur_trans->dirty_bgs)) {
		cache = list_first_entry(&cur_trans->dirty_bgs,
					 struct btrfs_block_group,
					 dirty_list);

		if (!list_empty(&cache->io_list)) {
			spin_unlock(&cur_trans->dirty_bgs_lock);
			list_del_init(&cache->io_list);
			btrfs_cleanup_bg_io(cache);
			spin_lock(&cur_trans->dirty_bgs_lock);
		}

		list_del_init(&cache->dirty_list);
		spin_lock(&cache->lock);
		cache->disk_cache_state = BTRFS_DC_ERROR;
		spin_unlock(&cache->lock);

		spin_unlock(&cur_trans->dirty_bgs_lock);
		btrfs_put_block_group(cache);
		btrfs_delayed_refs_rsv_release(fs_info, 1);
		spin_lock(&cur_trans->dirty_bgs_lock);
	}
	spin_unlock(&cur_trans->dirty_bgs_lock);

	/*
	 * Refer to the definition of io_bgs member for details why it's safe
	 * to use it without any locking
	 */
	while (!list_empty(&cur_trans->io_bgs)) {
		cache = list_first_entry(&cur_trans->io_bgs,
					 struct btrfs_block_group,
					 io_list);

		list_del_init(&cache->io_list);
		spin_lock(&cache->lock);
		cache->disk_cache_state = BTRFS_DC_ERROR;
		spin_unlock(&cache->lock);
		btrfs_cleanup_bg_io(cache);
	}
}

void btrfs_cleanup_one_transaction(struct btrfs_transaction *cur_trans,
				   struct btrfs_fs_info *fs_info)
{
	struct btrfs_device *dev, *tmp;

	btrfs_cleanup_dirty_bgs(cur_trans, fs_info);
	ASSERT(list_empty(&cur_trans->dirty_bgs));
	ASSERT(list_empty(&cur_trans->io_bgs));

	list_for_each_entry_safe(dev, tmp, &cur_trans->dev_update_list,
				 post_commit_list) {
		list_del_init(&dev->post_commit_list);
	}

	btrfs_destroy_delayed_refs(cur_trans, fs_info);

	cur_trans->state = TRANS_STATE_COMMIT_START;
	wake_up(&fs_info->transaction_blocked_wait);

	cur_trans->state = TRANS_STATE_UNBLOCKED;
	wake_up(&fs_info->transaction_wait);

	btrfs_destroy_delayed_inodes(fs_info);

	btrfs_destroy_marked_extents(fs_info, &cur_trans->dirty_pages,
				     EXTENT_DIRTY);
	btrfs_destroy_pinned_extent(fs_info, &cur_trans->pinned_extents);

	btrfs_free_redirty_list(cur_trans);

	cur_trans->state =TRANS_STATE_COMPLETED;
	wake_up(&cur_trans->commit_wait);
}

static int btrfs_cleanup_transaction(struct btrfs_fs_info *fs_info)
{
	struct btrfs_transaction *t;

	mutex_lock(&fs_info->transaction_kthread_mutex);

	spin_lock(&fs_info->trans_lock);
	while (!list_empty(&fs_info->trans_list)) {
		t = list_first_entry(&fs_info->trans_list,
				     struct btrfs_transaction, list);
		if (t->state >= TRANS_STATE_COMMIT_START) {
			refcount_inc(&t->use_count);
			spin_unlock(&fs_info->trans_lock);
			btrfs_wait_for_commit(fs_info, t->transid);
			btrfs_put_transaction(t);
			spin_lock(&fs_info->trans_lock);
			continue;
		}
		if (t == fs_info->running_transaction) {
			t->state = TRANS_STATE_COMMIT_DOING;
			spin_unlock(&fs_info->trans_lock);
			/*
			 * We wait for 0 num_writers since we don't hold a trans
			 * handle open currently for this transaction.
			 */
			wait_event(t->writer_wait,
				   atomic_read(&t->num_writers) == 0);
		} else {
			spin_unlock(&fs_info->trans_lock);
		}
		btrfs_cleanup_one_transaction(t, fs_info);

		spin_lock(&fs_info->trans_lock);
		if (t == fs_info->running_transaction)
			fs_info->running_transaction = NULL;
		list_del_init(&t->list);
		spin_unlock(&fs_info->trans_lock);

		btrfs_put_transaction(t);
		trace_btrfs_transaction_commit(fs_info);
		spin_lock(&fs_info->trans_lock);
	}
	spin_unlock(&fs_info->trans_lock);
	btrfs_destroy_all_ordered_extents(fs_info);
	btrfs_destroy_delayed_inodes(fs_info);
	btrfs_assert_delayed_root_empty(fs_info);
	btrfs_destroy_all_delalloc_inodes(fs_info);
	btrfs_drop_all_logs(fs_info);
	mutex_unlock(&fs_info->transaction_kthread_mutex);

	return 0;
}

int btrfs_init_root_free_objectid(struct btrfs_root *root)
{
	struct btrfs_path *path;
	int ret;
	struct extent_buffer *l;
	struct btrfs_key search_key;
	struct btrfs_key found_key;
	int slot;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	search_key.objectid = BTRFS_LAST_FREE_OBJECTID;
	search_key.type = -1;
	search_key.offset = (u64)-1;
	ret = btrfs_search_slot(NULL, root, &search_key, path, 0, 0);
	if (ret < 0)
		goto error;
	BUG_ON(ret == 0); /* Corruption */
	if (path->slots[0] > 0) {
		slot = path->slots[0] - 1;
		l = path->nodes[0];
		btrfs_item_key_to_cpu(l, &found_key, slot);
		root->free_objectid = max_t(u64, found_key.objectid + 1,
					    BTRFS_FIRST_FREE_OBJECTID);
	} else {
		root->free_objectid = BTRFS_FIRST_FREE_OBJECTID;
	}
	ret = 0;
error:
	btrfs_free_path(path);
	return ret;
}

int btrfs_get_free_objectid(struct btrfs_root *root, u64 *objectid)
{
	int ret;
	mutex_lock(&root->objectid_mutex);

	if (unlikely(root->free_objectid >= BTRFS_LAST_FREE_OBJECTID)) {
		btrfs_warn(root->fs_info,
			   "the objectid of root %llu reaches its highest value",
			   root->root_key.objectid);
		ret = -ENOSPC;
		goto out;
	}

	*objectid = root->free_objectid++;
	ret = 0;
out:
	mutex_unlock(&root->objectid_mutex);
	return ret;
}
