/*
 * background writeback - scan btree for dirty data and write it to the backing
 * device
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"
#include "io.h"
#include "keybuf.h"
#include "keylist.h"
#include "writeback.h"

#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <trace/events/bcachefs.h>

/* Rate limiting */

static void __update_writeback_rate(struct cached_dev *dc)
{
	struct cache_set *c = dc->disk.c;
	u64 cache_dirty_target =
		div_u64(c->capacity * dc->writeback_percent, 100);
	s64 target = div64_u64(cache_dirty_target * bdev_sectors(dc->bdev),
				   c->cached_dev_sectors);
	s64 dirty = bcache_dev_sectors_dirty(&dc->disk);

	bch_pd_controller_update(&dc->writeback_pd, target << 9,
				 dirty << 9, -1);
}

static void update_writeback_rate(struct work_struct *work)
{
	struct cached_dev *dc = container_of(to_delayed_work(work),
					     struct cached_dev,
					     writeback_pd_update);

	down_read(&dc->writeback_lock);

	if (atomic_read(&dc->has_dirty) &&
	    dc->writeback_percent &&
	    !test_bit(BCACHE_DEV_DETACHING, &dc->disk.flags))
		__update_writeback_rate(dc);
	else
		dc->writeback_pd.rate.rate = UINT_MAX;

	up_read(&dc->writeback_lock);

	schedule_delayed_work(&dc->writeback_pd_update,
			      dc->writeback_pd_update_seconds * HZ);
}

struct dirty_io {
	struct closure		cl;
	BKEY_PADDED(key);
	struct cached_dev	*dc;
	struct cache		*ca;
	struct keybuf_key	*w;
	int			error;
	bool			from_mempool;
	/* Must be last */
	struct bio		bio;
};

#define DIRTY_IO_MEMPOOL_BVECS		64
#define DIRTY_IO_MEMPOOL_SECTORS	(DIRTY_IO_MEMPOOL_BVECS * PAGE_SECTORS)

static void dirty_init(struct dirty_io *io)
{
	struct bio *bio = &io->bio;

	bio_init(bio);
	if (!io->dc->writeback_percent)
		bio_set_prio(bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	bio->bi_iter.bi_size	= KEY_SIZE(&io->key) << 9;
	bio->bi_max_vecs	=
		DIV_ROUND_UP(KEY_SIZE(&io->key), PAGE_SECTORS);
	bio->bi_io_vec		= bio->bi_inline_vecs;
	bch_bio_map(bio, NULL);
}

static void dirty_io_destructor(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);

	if (io->from_mempool)
		mempool_free(io, io->dc->writeback_io_pool);
	else
		kfree(io);
}

static void write_dirty_finish(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);
	struct cached_dev *dc = io->dc;
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, &io->bio, i)
		mempool_free(bv->bv_page, dc->writeback_page_pool);

	if (!io->error) {
		int ret;
		struct keylist keys;

		bch_keylist_init(&keys);

		bkey_copy(keys.top, &io->key);
		SET_KEY_CACHED(keys.top, true);
		bch_keylist_push(&keys);

		ret = bch_btree_insert(dc->disk.c, BTREE_ID_EXTENTS,
				       &keys, &io->key);
		if (ret)
			trace_bcache_writeback_collision(&io->key);

		atomic_long_inc(ret
				? &dc->disk.c->writeback_keys_failed
				: &dc->disk.c->writeback_keys_done);
	}

	bch_keybuf_put(&dc->writeback_keys, io->w);

	closure_return_with_destructor(cl, dirty_io_destructor);
}

static void dirty_endio(struct bio *bio)
{
	struct dirty_io *io = container_of(bio, struct dirty_io, bio);

	if (bio->bi_error) {
		trace_bcache_writeback_error(&io->key,
					     op_is_write(bio_op(&io->bio)),
					     bio->bi_error);
		io->error = bio->bi_error;
	}

	closure_put(&io->cl);
}

static void write_dirty(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);

	if (!io->error) {
		dirty_init(io);
		bio_set_op_attrs(&io->bio, REQ_OP_WRITE, 0);
		io->bio.bi_iter.bi_sector = KEY_START(&io->key);
		io->bio.bi_bdev		= io->dc->bdev;
		io->bio.bi_end_io	= dirty_endio;

		closure_bio_submit(&io->bio, cl);
	}

	continue_at(cl, write_dirty_finish, io->dc->disk.c->wq);
}

static void read_dirty_endio(struct bio *bio)
{
	struct dirty_io *io = container_of(bio, struct dirty_io, bio);
	struct cache_set *c = io->dc->disk.c;

	bch_count_io_errors(io->ca, bio->bi_error,
			    "reading dirty data from cache");
	percpu_ref_put(&io->ca->ref);

	if (ptr_stale(c, io->ca, &io->key, 0))
		bio->bi_error = -EINTR;

	dirty_endio(bio);
}

static void read_dirty_submit(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);

	closure_bio_submit(&io->bio, cl);

	continue_at(cl, write_dirty, system_wq);
}

static void read_dirty(struct cached_dev *dc)
{
	struct keybuf_key *w;
	struct dirty_io *io;
	struct closure cl;
	struct cache *ca;
	unsigned ptr, i;
	struct bio_vec *bv;
	BKEY_PADDED(k) tmp;

	closure_init_stack(&cl);

	while (!bch_ratelimit_wait_freezable_stoppable(&dc->writeback_pd.rate,
						       &cl)) {
		w = bch_keybuf_next(&dc->writeback_keys);
		if (!w)
			break;

		bkey_copy(&tmp.k, &w->key);

		while (KEY_SIZE(&tmp.k)) {
			ca = bch_extent_pick_ptr(dc->disk.c, &tmp.k, &ptr);
			if (!ca)
				break;

			io = kzalloc(sizeof(*io) + sizeof(struct bio_vec) *
				     DIV_ROUND_UP(KEY_SIZE(&tmp.k),
						  PAGE_SECTORS),
				     GFP_KERNEL);
			if (!io) {
				trace_bcache_writeback_alloc_fail(ca->set,
							KEY_SIZE(&tmp.k));
				io = mempool_alloc(dc->writeback_io_pool,
						   GFP_KERNEL);
				memset(io, 0, sizeof(*io) +
				       sizeof(struct bio_vec) *
				       DIRTY_IO_MEMPOOL_BVECS);
				io->from_mempool = true;

				bkey_copy(&io->key, &tmp.k);

				if (DIRTY_IO_MEMPOOL_SECTORS <
				    KEY_SIZE(&io->key))
					bch_key_resize(&io->key,
						DIRTY_IO_MEMPOOL_SECTORS);
			} else {
				bkey_copy(&io->key, &tmp.k);
			}

			io->dc		= dc;
			io->ca		= ca;
			io->w		= w;
			atomic_inc(&w->ref);

			dirty_init(io);
			bio_set_op_attrs(&io->bio, REQ_OP_READ, 0);
			io->bio.bi_iter.bi_sector = PTR_OFFSET(&io->key, ptr);
			io->bio.bi_bdev		= ca->bdev;
			io->bio.bi_end_io	= read_dirty_endio;

			bio_for_each_segment_all(bv, &io->bio, i) {
				bv->bv_page =
					mempool_alloc(dc->writeback_page_pool,
						      i ? GFP_NOWAIT
						      : GFP_KERNEL);
				if (!bv->bv_page) {
					BUG_ON(!i);
					io->bio.bi_vcnt = i;

					io->bio.bi_iter.bi_size =
						io->bio.bi_vcnt * PAGE_SIZE;

					bch_key_resize(&io->key,
						       bio_sectors(&io->bio));
					break;
				}
			}

			bch_cut_front(&io->key, &tmp.k);
			trace_bcache_writeback(&io->key);

			bch_ratelimit_increment(&dc->writeback_pd.rate,
						KEY_SIZE(&io->key) << 9);

			closure_call(&io->cl, read_dirty_submit, NULL, &cl);
		}

		bch_keybuf_put(&dc->writeback_keys, w);
	}

	/*
	 * Wait for outstanding writeback IOs to finish (and keybuf slots to be
	 * freed) before refilling again
	 */
	closure_sync(&cl);
}

/* Scan for dirty data */

static void __bcache_dev_sectors_dirty_add(struct bcache_device *d,
					   u64 offset, int nr_sectors)
{
	unsigned stripe_offset, stripe, sectors_dirty;

	if (!d)
		return;

	if (!d->stripe_sectors_dirty)
		return;

	stripe = offset_to_stripe(d, offset);
	stripe_offset = offset & (d->stripe_size - 1);

	while (nr_sectors) {
		int s = min_t(unsigned, abs(nr_sectors),
			      d->stripe_size - stripe_offset);

		if (nr_sectors < 0)
			s = -s;

		if (stripe >= d->nr_stripes)
			return;

		sectors_dirty = atomic_add_return(s,
					d->stripe_sectors_dirty + stripe);
		if (sectors_dirty == d->stripe_size)
			set_bit(stripe, d->full_dirty_stripes);
		else
			clear_bit(stripe, d->full_dirty_stripes);

		nr_sectors -= s;
		stripe_offset = 0;
		stripe++;
	}
}

void bcache_dev_sectors_dirty_add(struct cache_set *c, unsigned inode,
				  u64 offset, int nr_sectors)
{
	struct bcache_device *d;

	rcu_read_lock();
	d = bch_dev_find(c, inode);
	if (d)
		__bcache_dev_sectors_dirty_add(d, offset, nr_sectors);
	rcu_read_unlock();
}

static bool dirty_pred(struct keybuf *buf, struct bkey *k)
{
	struct cached_dev *dc = container_of(buf, struct cached_dev, writeback_keys);

	BUG_ON(KEY_INODE(k) != bcache_dev_inum(&dc->disk));

	return !KEY_CACHED(k);
}

static void refill_full_stripes(struct cached_dev *dc)
{
	struct keybuf *buf = &dc->writeback_keys;
	unsigned inode = bcache_dev_inum(&dc->disk);
	unsigned start_stripe, stripe, next_stripe;
	bool wrapped = false;

	stripe = offset_to_stripe(&dc->disk, KEY_OFFSET(&buf->last_scanned));

	if (stripe >= dc->disk.nr_stripes)
		stripe = 0;

	start_stripe = stripe;

	while (1) {
		stripe = find_next_bit(dc->disk.full_dirty_stripes,
				       dc->disk.nr_stripes, stripe);

		if (stripe == dc->disk.nr_stripes)
			goto next;

		next_stripe = find_next_zero_bit(dc->disk.full_dirty_stripes,
						 dc->disk.nr_stripes, stripe);

		buf->last_scanned = KEY(inode,
					stripe * dc->disk.stripe_size, 0);

		bch_refill_keybuf(dc->disk.c, buf,
				  &KEY(inode,
				       next_stripe * dc->disk.stripe_size, 0),
				  dirty_pred);

		if (array_freelist_empty(&buf->freelist))
			return;

		stripe = next_stripe;
next:
		if (wrapped && stripe > start_stripe)
			return;

		if (stripe == dc->disk.nr_stripes) {
			stripe = 0;
			wrapped = true;
		}
	}
}

static void bch_writeback(struct cached_dev *dc)
{
	struct keybuf *buf = &dc->writeback_keys;
	unsigned inode = bcache_dev_inum(&dc->disk);
	struct bkey start = KEY(inode, 0, 0);
	struct bkey end = KEY(inode, KEY_OFFSET_MAX, 0);
	struct bkey start_pos;

	buf->last_scanned = KEY(inode, 0, 0);

	while (bkey_cmp(&buf->last_scanned, &end) < 0 &&
	       !kthread_should_stop()) {
		down_write(&dc->writeback_lock);

		if (!atomic_read(&dc->has_dirty)) {
			up_write(&dc->writeback_lock);
			set_current_state(TASK_INTERRUPTIBLE);

			if (kthread_should_stop())
				return;

			try_to_freeze();
			schedule();
			return;
		}

		if (bkey_cmp(&buf->last_scanned, &end) >= 0)
			buf->last_scanned = KEY(inode, 0, 0);

		if (dc->partial_stripes_expensive) {
			refill_full_stripes(dc);
			if (array_freelist_empty(&buf->freelist))
				goto refill_done;
		}

		start_pos = buf->last_scanned;
		bch_refill_keybuf(dc->disk.c, buf, &end, dirty_pred);

		if (bkey_cmp(&buf->last_scanned, &end) >= 0) {
			/*
			 * If we get to the end start scanning again from the
			 * beginning, and only scan up to where we initially
			 * started scanning from:
			 */
			buf->last_scanned = start;
			bch_refill_keybuf(dc->disk.c, buf, &start_pos,
					  dirty_pred);
		}

		if (RB_EMPTY_ROOT(&dc->writeback_keys.keys)) {
			atomic_set(&dc->has_dirty, 0);
			cached_dev_put(dc);
			SET_BDEV_STATE(&dc->sb, BDEV_STATE_CLEAN);
			bch_write_bdev_super(dc, NULL);
		}

refill_done:
		up_write(&dc->writeback_lock);

		bch_ratelimit_reset(&dc->writeback_pd.rate);
		read_dirty(dc);
	}
}

static int bch_writeback_thread(void *arg)
{
	struct cached_dev *dc = arg;
	struct cache_set *c = dc->disk.c;
	unsigned long last = jiffies;

	do {
		if (kthread_wait_freezable(dc->writeback_running ||
				test_bit(BCACHE_DEV_DETACHING,
					 &dc->disk.flags)))
			break;

		bch_writeback(dc);
	} while (!bch_kthread_loop_ratelimit(&last,
				test_bit(BCACHE_DEV_DETACHING, &dc->disk.flags)
				? 0 : c->btree_scan_ratelimit * HZ));

	return 0;
}

void bch_mark_writeback_keys(struct cache_set *c)
{
	struct radix_tree_iter iter;
	void **slot;

	/* don't reclaim buckets to which writeback keys point */
	rcu_read_lock();

	radix_tree_for_each_slot(slot, &c->devices, &iter, 0) {
		struct bcache_device *d;
		struct cached_dev *dc;

		d = radix_tree_deref_slot(slot);

		if (INODE_FLASH_ONLY(&d->inode))
			continue;
		dc = container_of(d, struct cached_dev, disk);

		bch_mark_keybuf_keys(c, &dc->writeback_keys);
	}

	rcu_read_unlock();
}

/* Init */

struct sectors_dirty_init {
	struct btree_op	op;
	unsigned	inode;
	struct		bcache_device *d;
};

static int sectors_dirty_init_fn(struct btree_op *_op, struct btree *b,
				 struct bkey *k)
{
	struct sectors_dirty_init *op = container_of(_op,
						struct sectors_dirty_init, op);
	if (KEY_INODE(k) > op->inode)
		return MAP_DONE;

	if (!KEY_CACHED(k)) {
		/* We have to do this before the disk is added to the
		 * radix tree or we race with moving GC */
		__bcache_dev_sectors_dirty_add(op->d,
					       KEY_START(k), KEY_SIZE(k));
	}

	return MAP_CONTINUE;
}

void bch_sectors_dirty_init(struct cached_dev *dc, struct cache_set *c)
{
	struct bcache_device *d = &dc->disk;
	struct sectors_dirty_init op;

	bch_btree_op_init(&op.op, BTREE_ID_EXTENTS, -1);
	op.inode = bcache_dev_inum(d);
	op.d = d;

	bch_btree_map_keys(&op.op, c,
			   &KEY(op.inode, 0, 0), sectors_dirty_init_fn, 0);

	dc->writeback_pd.last_actual = bcache_dev_sectors_dirty(d);
}

void bch_cached_dev_writeback_stop(struct cached_dev *dc)
{
	cancel_delayed_work_sync(&dc->writeback_pd_update);
	if (!IS_ERR_OR_NULL(dc->writeback_thread)) {
		kthread_stop(dc->writeback_thread);
		dc->writeback_thread = NULL;
	}
}

void bch_cached_dev_writeback_free(struct cached_dev *dc)
{
	struct bcache_device *d = &dc->disk;

	mempool_destroy(dc->writeback_page_pool);
	mempool_destroy(dc->writeback_io_pool);
	kvfree(d->full_dirty_stripes);
	kvfree(d->stripe_sectors_dirty);
}

int bch_cached_dev_writeback_init(struct cached_dev *dc)
{
	struct bcache_device *d = &dc->disk;
	sector_t sectors;
	size_t n;

	sectors = get_capacity(dc->disk.disk);

	if (!d->stripe_size) {
#ifdef CONFIG_BCACHEFS_DEBUG
		d->stripe_size = 1 << 0;
#else
		d->stripe_size = 1 << 31;
#endif
	}

	pr_debug("stripe size: %d sectors", d->stripe_size);
	d->nr_stripes = DIV_ROUND_UP_ULL(sectors, d->stripe_size);

	if (!d->nr_stripes ||
	    d->nr_stripes > INT_MAX ||
	    d->nr_stripes > SIZE_MAX / sizeof(atomic_t)) {
		pr_err("nr_stripes too large or invalid: %u (start sector beyond end of disk?)",
			(unsigned)d->nr_stripes);
		return -ENOMEM;
	}

	n = d->nr_stripes * sizeof(atomic_t);
	d->stripe_sectors_dirty = n < PAGE_SIZE << 6
		? kzalloc(n, GFP_KERNEL)
		: vzalloc(n);
	if (!d->stripe_sectors_dirty) {
		pr_err("cannot allocate stripe_sectors_dirty");
		return -ENOMEM;
	}

	n = BITS_TO_LONGS(d->nr_stripes) * sizeof(unsigned long);
	d->full_dirty_stripes = n < PAGE_SIZE << 6
		? kzalloc(n, GFP_KERNEL)
		: vzalloc(n);
	if (!d->full_dirty_stripes) {
		pr_err("cannot allocate full_dirty_stripes");
		return -ENOMEM;
	}

	dc->writeback_io_pool =
		mempool_create_kmalloc_pool(4, sizeof(struct dirty_io) +
					    sizeof(struct bio_vec) *
					    DIRTY_IO_MEMPOOL_BVECS);
	if (!dc->writeback_io_pool)
		return -ENOMEM;

	dc->writeback_page_pool =
		mempool_create_page_pool((64 << 10) / PAGE_SIZE, 0);
	if (!dc->writeback_page_pool)
		return -ENOMEM;

	init_rwsem(&dc->writeback_lock);
	bch_keybuf_init(&dc->writeback_keys);

	dc->writeback_metadata		= true;
	dc->writeback_running		= true;
	dc->writeback_percent		= 10;
	dc->writeback_pd_update_seconds	= 5;

	bch_pd_controller_init(&dc->writeback_pd);
	INIT_DELAYED_WORK(&dc->writeback_pd_update, update_writeback_rate);

	return 0;
}

int bch_cached_dev_writeback_start(struct cached_dev *dc)
{
	dc->writeback_thread = kthread_create(bch_writeback_thread, dc,
					      "bcache_writeback");
	if (IS_ERR(dc->writeback_thread))
		return PTR_ERR(dc->writeback_thread);

	schedule_delayed_work(&dc->writeback_pd_update,
			      dc->writeback_pd_update_seconds * HZ);

	bch_writeback_queue(dc);

	return 0;
}
