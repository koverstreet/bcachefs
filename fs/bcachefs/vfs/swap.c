// SPDX-License-Identifier: GPL-2.0
#ifndef NO_BCACHEFS_FS

#include "bcachefs.h"
#include "alloc/buckets.h"
#include "btree/cache.h"
#include "btree/iter.h"
#include "btree/update.h"
#include "data/extents.h"
#include "data/io_misc.h"
#include "data/write.h"
#include "vfs/fs.h"
#include "vfs/swap.h"
#include "vfs/direct.h"
#include "vfs/buffered.h"

#include <linux/sched/mm.h>
#include <linux/swap.h>
#include <linux/ktime.h>

/*
 * Swap file support for bcachefs.
 *
 * Uses the SWP_FS_OPS path (like NFS) so that bcachefs stays in the I/O
 * loop for swap operations.  This enables checksumming, encryption,
 * replication, and multi-device support for swap data.
 *
 * Key design points:
 * - Btree nodes are pinned (noevict) at swapon to avoid disk reads
 *   during memory reclaim
 * - PF_MEMALLOC is set during swap I/O to prevent reclaim re-entry
 * - BCH_WRITE_swap flag propagates the noreclaim context to the
 *   write index worker thread
 */

/*
 * Feature toggles for A/B testing.  Disable via kernel cmdline:
 *   bcachefs.swap_nopin       - disable btree node pinning
 *   bcachefs.swap_noreclaim   - disable PF_MEMALLOC in swap_rw
 */
static bool bch2_swap_pin_enabled = true;
bool bch2_swap_noreclaim_enabled = true; /* also checked in data/write.c */

static int __init swap_nopin_setup(char *s)
{
	bch2_swap_pin_enabled = false;
	return 1;
}
__setup("bcachefs.swap_nopin", swap_nopin_setup);

static int __init swap_noreclaim_setup(char *s)
{
	bch2_swap_noreclaim_enabled = false;
	return 1;
}
__setup("bcachefs.swap_noreclaim", swap_noreclaim_setup);

/*
 * Swap I/O diagnostics.
 *
 * Track in-flight swap ops and detect when they stall.  Under memory
 * pressure the write path can block indefinitely on allocation —
 * we want to crash early with a useful stack trace rather than
 * silently hang.
 */
static atomic_t bch2_swap_inflight = ATOMIC_INIT(0);
static atomic64_t bch2_swap_completed = ATOMIC64_INIT(0);
static atomic64_t bch2_swap_errors = ATOMIC64_INIT(0);

/* Warn after 2 s, BUG after 10 s */
#define SWAP_IO_WARN_NS		(2ULL * NSEC_PER_SEC)
#define SWAP_IO_BUG_NS		(10ULL * NSEC_PER_SEC)

/* Pin leaf nodes in a btree covering a key range. */
static int bch2_swap_pin_btree_range(struct btree_trans *trans,
				     enum btree_id btree,
				     struct bpos start, struct bpos end,
				     bool pin)
{
	int count = 0;

	int ret = __for_each_btree_node(trans, iter, btree,
			start, 0, 0, BTREE_ITER_prefetch, b, ({
		if (bpos_gt(b->data->min_key, end))
			break;

		if (pin)
			set_btree_node_noevict(b);
		else
			clear_btree_node_noevict(b);
		count++;
		0;
	}));

	return ret < 0 ? ret : count;
}

static int bch2_swap_pin_unpin_nodes(struct bch_fs *c,
				     struct bch_inode_info *inode,
				     bool pin)
{
	int total = 0, ret;

	CLASS(btree_trans, trans)(c);

	u64 inum = inode->ei_inum.inum;

	ret = bch2_swap_pin_btree_range(trans, BTREE_ID_extents,
					POS(inum, 0), POS(inum, U64_MAX), pin);
	if (ret < 0)
		return ret;
	total += ret;

	ret = bch2_swap_pin_btree_range(trans, BTREE_ID_inodes,
					POS(0, inum), POS(0, inum), pin);
	if (ret < 0)
		return ret;
	total += ret;

	ret = bch2_swap_pin_btree_range(trans, BTREE_ID_alloc,
					POS_MIN, SPOS_MAX, pin);
	if (ret < 0)
		return ret;
	total += ret;

	return total;
}

int bch2_swap_activate(struct swap_info_struct *sis,
		       struct file *file, sector_t *span)
{
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;

	if (!S_ISREG(inode->v.i_mode))
		return -EINVAL;

	int pinned = 0;
	if (bch2_swap_pin_enabled) {
		/* Pin after prefragmentation (more nodes to pin now) */
		pinned = bch2_swap_pin_unpin_nodes(c, inode, true);
		if (pinned < 0) {
			bch_err(c, "swap activate: failed to pin btree nodes: %s",
				bch2_err_str(pinned));
			return pinned;
		}
	}

	/*
	 * Reserve disk space for the entire swap file.
	 *
	 * Each COW swap write allocates a new physical block before freeing
	 * the old one.  Without a reservation, ENOSPC during reclaim is
	 * possible if the filesystem is near full — causing swap writes to
	 * fail, which prevents freeing memory, causing an OOM spiral.
	 *
	 * Reserving swap_pages × PAGE_SECTORS at swapon time guarantees
	 * that space can't be taken by other writers while swap is active.
	 */
	u64 swap_sectors = (u64)sis->pages * PAGE_SECTORS;
	struct disk_reservation disk_res =
		bch2_disk_reservation_init(c, c->opts.data_replicas);
	int disk_ret = bch2_disk_reservation_get(c, &disk_res,
						  swap_sectors,
						  c->opts.data_replicas, 0);
	if (disk_ret) {
		bch_err(c, "swap activate: insufficient disk space for reservation (%llu sectors, %d replicas): %s",
			swap_sectors, c->opts.data_replicas,
			bch2_err_str(disk_ret));
		return disk_ret;
	}
	inode->ei_swap_reserved_sectors = disk_res.sectors;

	/*
	 * Pre-allocate btree node buffers on bc->freeable so that btree reads
	 * during swap I/O can steal a pre-allocated buffer rather than hitting
	 * the page allocator under PF_MEMALLOC.
	 *
	 * A single swap write traverses extents + inodes + alloc/freespace
	 * btrees (3 trees × BTREE_MAX_DEPTH levels × 256 KB = 3 MB minimum).
	 * We reserve 16 MB (= 16 MB / btree_node_size nodes) which covers
	 * ~5 concurrent fully-cold traversals with headroom.
	 */
	unsigned swap_reserve = (16 << 20) / c->opts.btree_node_size;
	int reserved = bch2_btree_cache_add_reserve(c, swap_reserve);

	sis->flags |= SWP_FS_OPS;
	*span = sis->pages;

	bch_info(c, "swap activated on inode %lu (%llu pages, %d nodes pinned, %d/%u btree nodes pre-reserved)",
		 inode->v.i_ino, (u64)sis->pages, pinned, reserved, swap_reserve);

	int ret = add_swap_extent(sis, 0, sis->max, 0);
	if (ret < 0) {
		bch2_btree_cache_remove_reserve(c, swap_reserve);
		if (inode->ei_swap_reserved_sectors) {
			struct disk_reservation dr = {
				.sectors = inode->ei_swap_reserved_sectors,
			};
			bch2_disk_reservation_put(c, &dr);
			inode->ei_swap_reserved_sectors = 0;
		}
		if (bch2_swap_pin_enabled)
			bch2_swap_pin_unpin_nodes(c, inode, false);
	}
	return ret;
}

void bch2_swap_deactivate(struct file *file)
{
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;

	if (bch2_swap_pin_enabled)
		bch2_swap_pin_unpin_nodes(c, inode, false);

	unsigned swap_reserve = (16 << 20) / c->opts.btree_node_size;
	bch2_btree_cache_remove_reserve(c, swap_reserve);

	if (inode->ei_swap_reserved_sectors) {
		struct disk_reservation disk_res = {
			.sectors = inode->ei_swap_reserved_sectors,
		};
		bch2_disk_reservation_put(c, &disk_res);
		inode->ei_swap_reserved_sectors = 0;
	}

	bch_info(c, "swap deactivated on inode %lu", inode->v.i_ino);
}

/*
 * Swap I/O callback — called for every swap read/write when SWP_FS_OPS
 * is set.  Returns bytes transferred or -EIOCBQUEUED for async I/O.
 */
int bch2_swap_rw(struct kiocb *iocb, struct iov_iter *iter)
{
	struct bch_fs *c = file_inode(iocb->ki_filp)->i_sb->s_fs_info;
	u64 start_ns = ktime_get_ns();
	int rw = iov_iter_rw(iter);

	atomic_inc(&bch2_swap_inflight);

	iocb->ki_flags |= IOCB_DIRECT;

	/*
	 * Prevent reclaim re-entry for both writes AND reads.
	 *
	 * Writes: swap writeback runs during reclaim, so allocations in
	 * the write path must not trigger reclaim (circular dependency).
	 *
	 * Reads: swap-in happens during page fault.  If a read-path
	 * allocation enters reclaim → reclaim tries to swap out other
	 * pages → those writes compete for the same btree locks as the
	 * read → deadlock.
	 *
	 * PF_MEMALLOC bypasses watermarks and skips direct reclaim.
	 */
	unsigned int noreclaim_flags = 0;
	if (bch2_swap_noreclaim_enabled)
		noreclaim_flags = memalloc_noreclaim_save();

	ssize_t ret;
	if (rw == READ)
		ret = bch2_read_iter(iocb, iter);
	else
		ret = bch2_write_iter(iocb, iter);

	if (bch2_swap_noreclaim_enabled)
		memalloc_noreclaim_restore(noreclaim_flags);

	atomic_dec(&bch2_swap_inflight);

	u64 elapsed_ns = ktime_get_ns() - start_ns;

	if (ret < 0 && ret != -EIOCBQUEUED) {
		atomic64_inc(&bch2_swap_errors);
		bch_err_ratelimited(c, "swap_rw %s error %li at pos %lld "
				    "(inflight=%d completed=%lld errors=%lld)",
				    rw == READ ? "read" : "write",
				    ret, iocb->ki_pos,
				    atomic_read(&bch2_swap_inflight),
				    atomic64_read(&bch2_swap_completed),
				    atomic64_read(&bch2_swap_errors));
	} else {
		atomic64_inc(&bch2_swap_completed);
	}

	/*
	 * Detect stalled swap I/O.  If a single operation takes >2 s,
	 * something is badly wrong (likely PF_MEMALLOC reserves exhausted
	 * or deadlock).  WARN at 2 s; in debug builds, BUG at 10 s to get
	 * a full crash dump with symbolized stacks instead of a silent hang.
	 */
	if (unlikely(elapsed_ns > SWAP_IO_WARN_NS)) {
		bch_err(c, "swap_rw %s STALL: %llu ms at pos %lld "
			"(inflight=%d completed=%lld errors=%lld)",
			rw == READ ? "read" : "write",
			elapsed_ns / NSEC_PER_MSEC, iocb->ki_pos,
			atomic_read(&bch2_swap_inflight),
			atomic64_read(&bch2_swap_completed),
			atomic64_read(&bch2_swap_errors));
		WARN_ON_ONCE(1);
	}
	if (unlikely(elapsed_ns > SWAP_IO_BUG_NS))
		BUG_ON(IS_ENABLED(CONFIG_BCACHEFS_DEBUG));

	return ret;
}

#endif /* NO_BCACHEFS_FS */
