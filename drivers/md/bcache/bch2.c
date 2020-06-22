// SPDX-License-Identifier: GPL-2.0
/*
 * Main bcache entry point - handle a read or a write request and decide what to
 * do with it; the make_request functions are called by the block layer.
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "backingdev.h"
#include "bch2.h"

#include "../../../fs/bcachefs/bcachefs.h"
#include "../../../fs/bcachefs/alloc_foreground.h"
#include "../../../fs/bcachefs/btree_update.h"
#include "../../../fs/bcachefs/buckets.h"
#include "../../../fs/bcachefs/io.h"
#include "../../../fs/bcachefs/fs.h"
#include "../../../fs/bcachefs/fs-common.h"
#include "../../../fs/bcachefs/str_hash.h"

#include "io.h"

#include <linux/kthread.h>
//#include <trace/events/bcache.h>

static unsigned fs_used_percent(struct bch_fs *c)
{
	struct bch_fs_usage_short usage = bch2_fs_usage_read_short(c);

	return div64_u64(usage.used * 100, usage.capacity);
}

static inline bool bch_keybuf_check_overlapping(struct keybuf *buf, struct bkey *start,
						struct bkey *end)
{
	return false;
}

/* Reads: */

struct bch_cached_dev_rbio {
	struct bio		*orig;
	struct cached_dev	*dc;
	struct bch_read_bio	rbio;
};

static void cached_dev_read_endio(struct bio *bio)
{
	struct bch_cached_dev_rbio *c_rbio =
		container_of(bio, struct bch_cached_dev_rbio, rbio.bio);
	struct bio *orig = c_rbio->orig;
	struct cached_dev *dc = c_rbio->dc;

	bio_put(bio);
	cached_dev_put(dc);
	bio_endio(orig);
}

static void cached_dev_read(struct cached_dev *dc, struct bio *bio)
{
	struct bch_fs *c = dc->disk.c2;
	struct bch_read_bio *rbio;
	struct bch_cached_dev_rbio *c_rbio;
	struct bch_io_opts opts = { 0 };
	unsigned flags = BCH_READ_RETRY_IF_STALE|
		  BCH_READ_USER_MAPPED|
		  BCH_READ_PASSTHROUGH_BLOCK_DEV;

	if (!bch_check_should_bypass(dc, bio, c->opts.block_size, 0)) {
		/* XXX: implement promotes from block devices in bch2:
		flags |= BCH_READ_MAY_PROMOTE;
		*/
	}

	/* XXX: plumb through write point for promotes:
	unsigned write_point	= writepoint_hashed((unsigned long) current);
	*/

	rbio = rbio_init(bio_clone_fast(bio, GFP_NOIO, &dc->bch2_bio_read), opts);
	rbio->bio.bi_end_io = cached_dev_read_endio;
	c_rbio		= container_of(rbio, struct bch_cached_dev_rbio, rbio);
	c_rbio->orig	= bio;
	c_rbio->dc	= dc;

	bch2_read(c, rbio, dc->disk.id, flags);
}

/* Writes: */

struct bch_write {
	struct closure		cl;

	struct bcache_device	*d;
	struct bio		*orig_bio;
	struct bio		backingdev_bio;

	blk_status_t		status;
	unsigned long		start_time;

	unsigned int		bypass:1;
	unsigned int		writeback:1;
	struct bch_write_op	op;
};

static void cached_dev_bio_complete(struct closure *cl)
{
	struct bch_write *io = container_of(cl, struct bch_write, cl);
	struct cached_dev *dc = container_of(io->d, struct cached_dev, disk);

	generic_end_io_acct(io->d->disk->queue, bio_op(io->orig_bio),
			    &io->d->disk->part0, io->start_time);

	//trace_bcache_request_end(s->d, s->orig_bio);
	io->orig_bio->bi_status = io->status;
	bio_endio(io->orig_bio);

	closure_debug_destroy(cl);
	mempool_free(io, &dc->bch2_io_write);

	cached_dev_put(dc);
}

static void cached_dev_write_complete(struct closure *cl)
{
	struct bch_write *s = container_of(cl, struct bch_write, cl);
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	up_read_non_owner(&dc->writeback_lock);
	cached_dev_bio_complete(cl);
}

static void backingdev_endio(struct bio *bio)
{
	struct bch_write *io = container_of(bio, struct bch_write, backingdev_bio);
	struct cached_dev *dc = container_of(io->d, struct cached_dev, disk);

	if (bio->bi_status) {
		io->status = bio->bi_status;
		bch_count_backing_io_errors(dc, bio);
	}

	closure_put(&io->cl);
}

static void submit_backingdev_io(struct bch_write *io)
{
	struct cached_dev *dc = container_of(io->d, struct cached_dev, disk);

	/*
	 * If it's a discard and the backing device doesn't support discards, no
	 * need to submit it:
	 */
	if (bio_op(io->orig_bio) == REQ_OP_DISCARD &&
	    !blk_queue_discard(bdev_get_queue(dc->bdev)))
		return;

	bio_init(&io->backingdev_bio, NULL, 0);
	__bio_clone_fast(&io->backingdev_bio, io->orig_bio);
	io->backingdev_bio.bi_end_io = backingdev_endio;

	closure_get(&io->cl);
	generic_make_request(&io->backingdev_bio);
}

static void cached_dev_write(struct cached_dev *dc, struct bio *orig_bio)
{
	struct bch_fs *c = dc->disk.c2;
	struct bch_write *io;
	struct bkey start = KEY(dc->disk.id, orig_bio->bi_iter.bi_sector, 0);
	struct bkey end = KEY(dc->disk.id, bio_end_sector(orig_bio), 0);
	struct bch_io_opts opts = { 0 };
	unsigned in_use = fs_used_percent(c);

	io = mempool_alloc(&dc->bch2_io_write, GFP_NOIO);
	closure_init(&io->cl, NULL);
	io->d		= &dc->disk;
	io->orig_bio	= orig_bio;
	io->status	= 0;
	io->start_time	= jiffies;
	io->bypass	= bch_check_should_bypass(dc, orig_bio,
					c->opts.block_size, in_use);
	io->writeback	= false;

	down_read_non_owner(&dc->writeback_lock);
	if (bch_keybuf_check_overlapping(dc->writeback_keys, &start, &end)) {
		/*
		 * We overlap with some dirty data undergoing background
		 * writeback, force this write to writeback
		 */
		io->bypass = false;
		io->writeback = true;
	}

	/*
	 * Discards aren't _required_ to do anything, so skipping if
	 * check_overlapping returned true is ok
	 *
	 * But check_overlapping drops dirty keys for which io hasn't started,
	 * so we still want to call it.
	 */
	if (bio_op(orig_bio) == REQ_OP_DISCARD) {
		io->bypass = true;
		io->writeback = false;
	}

	if (should_writeback(dc, io->orig_bio, cache_mode(dc),
			     io->bypass, in_use)) {
		io->bypass = false;
		io->writeback = true;
	}

	/*
	 * Submit IO to backing device, if we're not doing a writeback write:
	 *
	 * If it's a discard and the backing device doesn't support discards, no
	 * need to submit to the backing device:
	 */
	if (!io->writeback)
		submit_backingdev_io(io);

	/* If we're bypassing, delete the range we're writing to from the cache: */
	if (io->bypass) {
		u64 journal_seq = 0;

		bch2_btree_delete_range(c, BTREE_ID_EXTENTS,
					POS(dc->disk.id, orig_bio->bi_iter.bi_sector),
					POS(dc->disk.id, bio_end_sector(orig_bio)),
					&journal_seq);

		if ((orig_bio->bi_opf & (REQ_PREFLUSH|REQ_FUA)) &&
		    !(c->opts.journal_flush_disabled))
			bch2_journal_flush_seq_async(&c->journal, journal_seq, &io->cl);
	} else {
		bch2_write_op_init(&io->op, c, opts);
		bio_init(&io->op.wbio.bio, NULL, 0);
		__bio_clone_fast(&io->op.wbio.bio, orig_bio);
		io->op.nr_replicas	= 1;
		io->op.write_point	= writepoint_hashed((unsigned long) current);
		io->op.new_i_size	= U64_MAX;
		io->op.pos		= POS(dc->disk.id, orig_bio->bi_iter.bi_sector);

		if (orig_bio->bi_opf & (REQ_FUA|REQ_PREFLUSH))
			io->op.flags |= BCH_WRITE_FLUSH;

		if (io->writeback) {
			int ret = bch2_disk_reservation_get(c, &io->op.res, bio_sectors(orig_bio),
							    io->op.nr_replicas, 0);
			if (ret) {
				io->status = BLK_STS_RESOURCE;
				goto err;
			}

			/* Mark superblock dirty, if necessary: */
			bch_writeback_add(dc);
		} else {
			io->op.flags |= BCH_WRITE_CACHED;
		}

		closure_call(&io->op.cl, bch2_write, NULL, &io->cl);
	}
err:
	continue_at(&io->cl, cached_dev_write_complete, NULL);
}

static void cached_dev_nodata(struct cached_dev *dc, struct bio *orig_bio)
{
	struct bch_fs *c = dc->disk.c2;
	bool flush_backingdev = cache_mode(dc) != CACHE_MODE_WRITEBACK;
	bool flush_cache = !c->opts.journal_flush_disabled;
	struct bch_write *io;

	if (!(orig_bio->bi_opf & REQ_PREFLUSH)) {
		generic_make_request(orig_bio);
		return;
	}

	if (!flush_backingdev && !flush_cache) {
		bio_endio(orig_bio);
		return;
	}

	if (!flush_cache) {
		generic_make_request(orig_bio);
		return;
	}

	io = mempool_alloc(&dc->bch2_io_write, GFP_NOIO);
	closure_init(&io->cl, NULL);
	io->d		= &dc->disk;
	io->orig_bio	= orig_bio;
	io->status	= 0;
	io->start_time	= jiffies;
	io->bypass	= false;
	io->writeback	= false;

	if (flush_backingdev)
		submit_backingdev_io(io);

	bch2_journal_flush_async(&c->journal, &io->cl);
	continue_at(&io->cl, cached_dev_bio_complete, NULL);
}

void bch2_cached_dev_make_request(struct cached_dev *dc, struct bio *bio)
{
	//trace_bcache_request_start(d, bio);

	if (!bio->bi_iter.bi_size)
		cached_dev_nodata(dc, bio);
	else if (bio_data_dir(bio) == WRITE)
		cached_dev_write(dc, bio);
	else
		cached_dev_read(dc, bio);

}

static int bch2_dev_attach_trans(struct btree_trans *trans,
				 struct qstr *name,
				 u64 *inum,
				 bool must_exist)
{
	struct bch_fs *c = trans->c;
	struct bch_inode_unpacked root_inode;
	struct bch_inode_unpacked dev_inode;
	struct bch_hash_info root_hash_info;
	struct btree_iter *iter;
	int ret;

	ret = bch2_inode_find_by_inum_trans(trans, BCACHEFS_ROOT_INO, &root_inode);
	if (ret)
		return ret;

	root_hash_info = bch2_hash_info_init(c, &root_inode);

	iter = __bch2_dirent_lookup_trans(trans, BCACHEFS_ROOT_INO,
					  &root_hash_info, name, 0);
	ret = PTR_ERR_OR_ZERO(iter);
	if (ret && ret != -ENOENT)
		return ret;

	if (!ret) {
		struct bkey_s_c k = bch2_btree_iter_peek_slot(iter);
		*inum = le64_to_cpu(bkey_s_c_to_dirent(k).v->d_inum);
		return 0;
	}

	if (must_exist)
		return ret;

	/* Doesn't exist, create it: */
	bch2_inode_init_early(c, &dev_inode);

	ret   = bch2_create_trans(trans, BCACHEFS_ROOT_INO,
				  &root_inode, &dev_inode,
				  name, 0, 0, S_IFREG, 0, NULL, NULL) ?:
		bch2_trans_commit(trans, NULL, NULL, 0);
	*inum = dev_inode.bi_inum;
	return ret;
}

static int bch2_cached_dev_attach_one(struct cached_dev *dc, struct bch_fs *c,
				      uint8_t *fs_uuid)
{
	char backingdev_filename[80];
	struct qstr backingdev_qstr;
	struct inode *inode = NULL;
	u64 inum;
	int ret = 0;

	snprintf(backingdev_filename, sizeof(backingdev_filename),
		 "backing-device-%pU", dc->sb.uuid);
	backingdev_qstr = (struct qstr) QSTR_INIT(backingdev_filename,
				    strlen(backingdev_filename));

	if (bcache_dev_is_attached(&dc->disk)) {
		pr_err("Can't attach %s: already attached",
		       dc->backing_dev_name);
		return -EINVAL;
	}
#if 0
	if (test_bit(CACHE_SET_STOPPING, &c->flags)) {
		pr_err("Can't attach %s: shutting down",
		       dc->backing_dev_name);
		return -EINVAL;
	}
#endif
	if (dc->sb.block_size < c->opts.block_size) {
		/* Will die */
		pr_err("Couldn't attach %s: block size less than set's block size",
		       dc->backing_dev_name);
		return -EINVAL;
	}

	ret = bch2_trans_do(c, NULL, NULL, 0,
			bch2_dev_attach_trans(&trans, &backingdev_qstr, &inum,
					      BDEV_STATE(&dc->sb) == BDEV_STATE_DIRTY));
	if (ret) {
		pr_err("Error attaching %s: %i\n",
		       dc->backing_dev_name, ret);
		return ret;
	}

	inode = bch2_vfs_inode_get(c, inum);
	if (IS_ERR(inode)) {
		pr_err("Can't attach %s: error getting inode %li",
		       dc->backing_dev_name, PTR_ERR(inode));
		return PTR_ERR(inode);
	}

	ret = get_write_access(inode);
	if (ret) {
		pr_err("Can't attach %s: error getting inode %i",
		       dc->backing_dev_name, ret);
		iput(inode);
		return ret;
	}

	/* XXX should we be calling __mnt_want_write() too? */

	if (BDEV_STATE(&dc->sb) == BDEV_STATE_STALE) {
		struct closure cl;

		closure_init_stack(&cl);

		ret = bch2_fpunch(c, inum, 0, U64_MAX, NULL, NULL);
		if (ret) {
			pr_err("Error attaching %s: error deleting existing data %i\n",
			       dc->backing_dev_name, ret);
			return ret;
		}

		SET_BDEV_STATE(&dc->sb, BDEV_STATE_CLEAN);
		bch_write_bdev_super(dc, &cl);
		closure_sync(&cl);
	}

	/*
	 * XXX: set inode size
	 */

	dc->disk.id	= inum;
	dc->disk.inode	= inode;
	dc->disk.c2	= c;
#if 0
	bcache_device_attach(&dc->disk, c, inum);
	list_move(&dc->list, &c->cached_devs);
	calc_cached_dev_sectors(c);
#endif
	/*
	 * dc->c must be set before dc->count != 0 - paired with the mb in
	 * cached_dev_get()
	 */
	smp_wmb();
	refcount_set(&dc->count, 1);
#if 0
	/* Block writeback thread, but spawn it */
	down_write(&dc->writeback_lock);
	if (bch_cached_dev_writeback_start(dc)) {
		up_write(&dc->writeback_lock);
		pr_err("Couldn't start writeback facilities for %s",
		       dc->disk.disk->disk_name);
		return -ENOMEM;
	}

	if (BDEV_STATE(&dc->sb) == BDEV_STATE_DIRTY) {
		atomic_set(&dc->has_dirty, 1);
		bch_writeback_queue(dc);
	}

	bch_sectors_dirty_init(&dc->disk);

	ret = bch_cached_dev_run(dc);
	if (ret && (ret != -EBUSY)) {
		up_write(&dc->writeback_lock);
		/*
		 * bch_register_lock is held, bcache_device_stop() is not
		 * able to be directly called. The kthread and kworker
		 * created previously in bch_cached_dev_writeback_start()
		 * have to be stopped manually here.
		 */
		kthread_stop(dc->writeback_thread);
		cancel_writeback_rate_update_dwork(dc);
		pr_err("Couldn't run cached device %s",
		       dc->backing_dev_name);
		return ret;
	}

	/* Allow the writeback thread to proceed */
	up_write(&dc->writeback_lock);
#endif

#if 0
	bcache_device_link(&dc->disk, c, "bdev");
	atomic_inc(&c->attached_dev_nr);
#endif

	pr_info("Caching %s as %s on set %pU",
		dc->backing_dev_name,
		dc->disk.disk->disk_name,
		&dc->disk.c2->sb.uuid);
	return 0;

}

int bch2_cached_dev_attach(struct cached_dev *dc, uint8_t *fs_uuid)
{
	struct bch_fs *c;
	int ret;

	mutex_lock(&bch2_fs_list_lock);
	list_for_each_entry(c, &bch2_fs_list, list) {
		if (fs_uuid
		    ? !memcmp(fs_uuid, &c->sb.user_uuid, 16)
		    : !memcmp(dc->sb.set_uuid, &c->sb.uuid, 16)) {
			closure_get(&c->cl);
			mutex_unlock(&bch2_fs_list_lock);
			goto found;
		}
	}
	mutex_unlock(&bch2_fs_list_lock);
	return -ENOENT;
found:
	ret = bch2_cached_dev_attach_one(dc, c, fs_uuid);
	closure_put(&c->cl);
	return ret;
}

void bch2_request_exit(struct cached_dev *dc)
{
	mempool_exit(&dc->bch2_io_write);
	bioset_exit(&dc->bch2_bio_read);
}

int bch2_request_init(struct cached_dev *dc)
{
	return  bioset_init(&dc->bch2_bio_read, 1,
			    offsetof(struct bch_cached_dev_rbio, rbio.bio),
			    BIOSET_NEED_RESCUER) ?:
		mempool_init_kmalloc_pool(&dc->bch2_io_write, 1, sizeof(struct bch_write));
}
