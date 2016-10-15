/*
 * background writeback - scan btree for dirty data and write it to the backing
 * device
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree_update.h"
#include "clock.h"
#include "debug.h"
#include "error.h"
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
	s64 target = div64_u64(cache_dirty_target *
			       bdev_sectors(dc->disk_sb.bdev),
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
	struct bch_replace_info	replace;
	struct cached_dev	*dc;
	struct cache		*ca;
	struct keybuf_key	*w;
	struct bch_extent_ptr	ptr;
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

	bio->bi_iter.bi_size	= io->replace.key.k.size << 9;
	bio->bi_max_vecs	=
		DIV_ROUND_UP(io->replace.key.k.size, PAGE_SECTORS);
	bio->bi_io_vec		= bio->bi_inline_vecs;
	bch_bio_map(bio, NULL);
}

static void dirty_io_destructor(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);

	if (io->from_mempool)
		mempool_free(io, &io->dc->writeback_io_pool);
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
		mempool_free(bv->bv_page, &dc->writeback_page_pool);

	if (!io->error) {
		BKEY_PADDED(k) tmp;
		int ret;

		bkey_copy(&tmp.k, &io->replace.key);
		io->replace.hook.fn = bch_extent_cmpxchg;
		bkey_extent_set_cached(&tmp.k.k, true);

		ret = bch_btree_insert(dc->disk.c, BTREE_ID_EXTENTS, &tmp.k,
				       NULL, &io->replace.hook, NULL, 0);
		if (io->replace.successes == 0)
			trace_bcache_writeback_collision(&io->replace.key.k);

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
		trace_bcache_writeback_error(&io->replace.key.k,
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
		io->bio.bi_iter.bi_sector =
			bkey_start_offset(&io->replace.key.k);
		io->bio.bi_bdev		= io->dc->disk_sb.bdev;
		io->bio.bi_end_io	= dirty_endio;

		closure_bio_submit(&io->bio, cl);
	}

	continue_at(cl, write_dirty_finish, io->dc->disk.c->wq);
}

static void read_dirty_endio(struct bio *bio)
{
	struct dirty_io *io = container_of(bio, struct dirty_io, bio);

	cache_nonfatal_io_err_on(bio->bi_error, io->ca, "writeback read");

	bch_account_io_completion(io->ca);

	if (ptr_stale(io->ca, &io->ptr))
		bio->bi_error = -EINTR;

	dirty_endio(bio);
}

static void read_dirty_submit(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);

	closure_bio_submit(&io->bio, cl);

	continue_at(cl, write_dirty, system_freezable_wq);
}

static u64 read_dirty(struct cached_dev *dc)
{
	struct keybuf_key *w;
	struct dirty_io *io;
	struct closure cl;
	unsigned i;
	struct bio_vec *bv;
	u64 sectors_written = 0;
	BKEY_PADDED(k) tmp;

	closure_init_stack(&cl);

	while (!bch_ratelimit_wait_freezable_stoppable(&dc->writeback_pd.rate)) {
		w = bch_keybuf_next(&dc->writeback_keys);
		if (!w)
			break;

		sectors_written += w->key.k.size;
		bkey_copy(&tmp.k, &w->key);

		while (tmp.k.k.size) {
			struct extent_pick_ptr pick;

			bch_extent_pick_ptr(dc->disk.c,
					    bkey_i_to_s_c(&tmp.k),
					    &pick);
			if (IS_ERR_OR_NULL(pick.ca))
				break;

			io = kzalloc(sizeof(*io) + sizeof(struct bio_vec) *
				     DIV_ROUND_UP(tmp.k.k.size,
						  PAGE_SECTORS),
				     GFP_KERNEL);
			if (!io) {
				trace_bcache_writeback_alloc_fail(pick.ca->set,
								  tmp.k.k.size);
				io = mempool_alloc(&dc->writeback_io_pool,
						   GFP_KERNEL);
				memset(io, 0, sizeof(*io) +
				       sizeof(struct bio_vec) *
				       DIRTY_IO_MEMPOOL_BVECS);
				io->from_mempool = true;

				bkey_copy(&io->replace.key, &tmp.k);

				if (DIRTY_IO_MEMPOOL_SECTORS <
				    io->replace.key.k.size)
					bch_key_resize(&io->replace.key.k,
						DIRTY_IO_MEMPOOL_SECTORS);
			} else {
				bkey_copy(&io->replace.key, &tmp.k);
			}

			io->dc		= dc;
			io->ca		= pick.ca;
			io->w		= w;
			io->ptr		= pick.ptr;
			atomic_inc(&w->ref);

			dirty_init(io);
			bio_set_op_attrs(&io->bio, REQ_OP_READ, 0);
			io->bio.bi_iter.bi_sector = pick.ptr.offset;
			io->bio.bi_bdev		= pick.ca->disk_sb.bdev;
			io->bio.bi_end_io	= read_dirty_endio;

			bio_for_each_segment_all(bv, &io->bio, i) {
				bv->bv_page =
					mempool_alloc(&dc->writeback_page_pool,
						      i ? GFP_NOWAIT
						      : GFP_KERNEL);
				if (!bv->bv_page) {
					BUG_ON(!i);
					io->bio.bi_vcnt = i;

					io->bio.bi_iter.bi_size =
						io->bio.bi_vcnt * PAGE_SIZE;

					bch_key_resize(&io->replace.key.k,
						       bio_sectors(&io->bio));
					break;
				}
			}

			bch_cut_front(io->replace.key.k.p, &tmp.k);
			trace_bcache_writeback(&io->replace.key.k);

			bch_ratelimit_increment(&dc->writeback_pd.rate,
						io->replace.key.k.size << 9);

			closure_call(&io->cl, read_dirty_submit, NULL, &cl);
		}

		bch_keybuf_put(&dc->writeback_keys, w);
	}

	/*
	 * Wait for outstanding writeback IOs to finish (and keybuf slots to be
	 * freed) before refilling again
	 */
	closure_sync(&cl);

	return sectors_written;
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

static bool dirty_pred(struct keybuf *buf, struct bkey_s_c k)
{
	struct cached_dev *dc = container_of(buf, struct cached_dev, writeback_keys);

	BUG_ON(k.k->p.inode != bcache_dev_inum(&dc->disk));

	return bkey_extent_is_data(k.k) &&
		!bkey_extent_is_cached(k.k);
}

static void refill_full_stripes(struct cached_dev *dc)
{
	struct keybuf *buf = &dc->writeback_keys;
	unsigned inode = bcache_dev_inum(&dc->disk);
	unsigned start_stripe, stripe, next_stripe;
	bool wrapped = false;

	stripe = offset_to_stripe(&dc->disk, buf->last_scanned.offset);

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

		buf->last_scanned = POS(inode,
					stripe * dc->disk.stripe_size);

		bch_refill_keybuf(dc->disk.c, buf,
				  POS(inode,
				      next_stripe * dc->disk.stripe_size),
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

static u64 bch_writeback(struct cached_dev *dc)
{
	struct keybuf *buf = &dc->writeback_keys;
	unsigned inode = bcache_dev_inum(&dc->disk);
	struct bpos start = POS(inode, 0);
	struct bpos end = POS(inode, KEY_OFFSET_MAX);
	struct bpos start_pos;
	u64 sectors_written = 0;

	buf->last_scanned = POS(inode, 0);

	while (bkey_cmp(buf->last_scanned, end) < 0 &&
	       !kthread_should_stop()) {
		down_write(&dc->writeback_lock);

		if (!atomic_read(&dc->has_dirty)) {
			up_write(&dc->writeback_lock);
			set_current_state(TASK_INTERRUPTIBLE);

			if (kthread_should_stop())
				return sectors_written;

			schedule();
			try_to_freeze();
			return sectors_written;
		}

		if (bkey_cmp(buf->last_scanned, end) >= 0)
			buf->last_scanned = POS(inode, 0);

		if (dc->partial_stripes_expensive) {
			refill_full_stripes(dc);
			if (array_freelist_empty(&buf->freelist))
				goto refill_done;
		}

		start_pos = buf->last_scanned;
		bch_refill_keybuf(dc->disk.c, buf, end, dirty_pred);

		if (bkey_cmp(buf->last_scanned, end) >= 0) {
			/*
			 * If we get to the end start scanning again from the
			 * beginning, and only scan up to where we initially
			 * started scanning from:
			 */
			buf->last_scanned = start;
			bch_refill_keybuf(dc->disk.c, buf, start_pos,
					  dirty_pred);
		}

		if (RB_EMPTY_ROOT(&dc->writeback_keys.keys)) {
			atomic_set(&dc->has_dirty, 0);
			cached_dev_put(dc);
			SET_BDEV_STATE(dc->disk_sb.sb, BDEV_STATE_CLEAN);
			bch_write_bdev_super(dc, NULL);
		}

refill_done:
		up_write(&dc->writeback_lock);

		bch_ratelimit_reset(&dc->writeback_pd.rate);
		sectors_written += read_dirty(dc);
	}

	return sectors_written;
}

static int bch_writeback_thread(void *arg)
{
	struct cached_dev *dc = arg;
	struct cache_set *c = dc->disk.c;
	struct io_clock *clock = &c->io_clock[WRITE];
	unsigned long last;
	u64 sectors_written;

	set_freezable();

	while (!kthread_should_stop()) {
		if (kthread_wait_freezable(dc->writeback_running ||
				test_bit(BCACHE_DEV_DETACHING,
					 &dc->disk.flags)))
			break;

		last = atomic_long_read(&clock->now);

		sectors_written = bch_writeback(dc);

		if (sectors_written < c->capacity >> 4)
			bch_kthread_io_clock_wait(clock,
					  last + (c->capacity >> 5));
	}

	return 0;
}

/**
 * bch_keylist_recalc_oldest_gens - update oldest_gen pointers from writeback keys
 *
 * This prevents us from wrapping around gens for a bucket only referenced from
 * writeback keybufs. We don't actually care that the data in those buckets is
 * marked live, only that we don't wrap the gens.
 */
void bch_writeback_recalc_oldest_gens(struct cache_set *c)
{
	struct radix_tree_iter iter;
	void **slot;

	rcu_read_lock();

	radix_tree_for_each_slot(slot, &c->devices, &iter, 0) {
		struct bcache_device *d;
		struct cached_dev *dc;

		d = radix_tree_deref_slot(slot);

		if (!CACHED_DEV(&d->inode.v))
			continue;
		dc = container_of(d, struct cached_dev, disk);

		bch_keybuf_recalc_oldest_gens(c, &dc->writeback_keys);
	}

	rcu_read_unlock();
}

/* Init */

void bch_sectors_dirty_init(struct cached_dev *dc, struct cache_set *c)
{
	struct bcache_device *d = &dc->disk;
	struct btree_iter iter;
	struct bkey_s_c k;

	/*
	 * We have to do this before the disk is added to the radix tree or we
	 * race with moving GC
	 */
	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
			   POS(bcache_dev_inum(d), 0), k) {
		if (k.k->p.inode > bcache_dev_inum(d))
			break;

		if (bkey_extent_is_data(k.k) &&
		    !bkey_extent_is_cached(k.k))
			__bcache_dev_sectors_dirty_add(d,
						       bkey_start_offset(k.k),
						       k.k->size);

		bch_btree_iter_cond_resched(&iter);
	}
	bch_btree_iter_unlock(&iter);

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

	mempool_exit(&dc->writeback_page_pool);
	mempool_exit(&dc->writeback_io_pool);
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

	if (mempool_init_kmalloc_pool(&dc->writeback_io_pool, 4,
				      sizeof(struct dirty_io) +
				      sizeof(struct bio_vec) *
				      DIRTY_IO_MEMPOOL_BVECS) ||
	    mempool_init_page_pool(&dc->writeback_page_pool,
				   (64 << 10) / PAGE_SIZE, 0))
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
