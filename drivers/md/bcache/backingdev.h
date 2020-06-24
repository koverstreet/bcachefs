/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHE_BACKINGDEV_H
#define _BCACHE_BACKINGDEV_H

#include <linux/bio.h>
#include <linux/closure.h>
#include <linux/kobject.h>
#include <linux/list.h>

#include <linux/bcache_superblock.h>
#include <linux/bcache/ratelimit.h>

#include "stats.h"
#include "super.h"

struct search;
struct btree;

struct bcache_device {
	struct closure		cl;

	struct kobject		kobj;

	struct cache_set	*c;
	unsigned int		id;
#define BCACHEDEVNAME_SIZE	12
	char			name[BCACHEDEVNAME_SIZE];

	struct gendisk		*disk;

	unsigned long		flags;
#define BCACHE_DEV_CLOSING		0
#define BCACHE_DEV_DETACHING		1
#define BCACHE_DEV_UNLINK_DONE		2
#define BCACHE_DEV_WB_RUNNING		3
#define BCACHE_DEV_RATE_DW_RUNNING	4
	unsigned int		nr_stripes;
	unsigned int		stripe_size;
	atomic_t		*stripe_sectors_dirty;
	unsigned long		*full_dirty_stripes;

	struct bio_set		bio_split;

	unsigned int		data_csum:1;

	int (*cache_miss)(struct btree *b, struct search *s,
			  struct bio *bio, unsigned int sectors);
	int (*ioctl)(struct bcache_device *d, fmode_t mode,
		     unsigned int cmd, unsigned long arg);
};

enum stop_on_failure {
	BCH_CACHED_DEV_STOP_AUTO = 0,
	BCH_CACHED_DEV_STOP_ALWAYS,
	BCH_CACHED_DEV_STOP_MODE_MAX,
};

struct io {
	/* Used to track sequential IO so it can be skipped */
	struct hlist_node	hash;
	struct list_head	lru;

	unsigned long		jiffies;
	unsigned int		sequential;
	sector_t		last;
};

struct cached_dev {
	struct list_head	list;
	struct bcache_device	disk;
	struct block_device	*bdev;

	struct cache_sb		sb;
	struct cache_sb_disk	*sb_disk;
	struct bio		sb_bio;
	struct bio_vec		sb_bv[1];
	struct closure		sb_write;
	struct semaphore	sb_write_mutex;

	/* Refcount on the cache set. Always nonzero when we're caching. */
	refcount_t		count;
	struct work_struct	detach;

	/*
	 * Device might not be running if it's dirty and the cache set hasn't
	 * showed up yet.
	 */
	atomic_t		running;

	/*
	 * Writes take a shared lock from start to finish; scanning for dirty
	 * data to refill the rb tree requires an exclusive lock.
	 */
	struct rw_semaphore	writeback_lock;

	/*
	 * Nonzero, and writeback has a refcount (d->count), iff there is dirty
	 * data in the cache. Protected by writeback_lock; must have an
	 * shared lock to set and exclusive lock to clear.
	 */
	atomic_t		has_dirty;

#define BCH_CACHE_READA_ALL		0
#define BCH_CACHE_READA_META_ONLY	1
	unsigned int		cache_readahead_policy;
	struct bch_ratelimit	writeback_rate;
	struct delayed_work	writeback_rate_update;

	/* Limit number of writeback bios in flight */
	struct semaphore	in_flight;
	struct task_struct	*writeback_thread;
	struct workqueue_struct	*writeback_write_wq;

	struct keybuf		*writeback_keys;

	struct task_struct	*status_update_thread;
	/*
	 * Order the write-half of writeback operations strongly in dispatch
	 * order.  (Maintain LBA order; don't allow reads completing out of
	 * order to re-order the writes...)
	 */
	struct closure_waitlist writeback_ordering_wait;
	atomic_t		writeback_sequence_next;

	/* For tracking sequential IO */
#define RECENT_IO_BITS	7
#define RECENT_IO	(1 << RECENT_IO_BITS)
	struct io		io[RECENT_IO];
	struct hlist_head	io_hash[RECENT_IO + 1];
	struct list_head	io_lru;
	spinlock_t		io_lock;

	struct cache_accounting	accounting;

	/* The rest of this all shows up in sysfs */
	unsigned int		sequential_cutoff;
	unsigned int		readahead;

	unsigned int		io_disable:1;
	unsigned int		verify:1;
	unsigned int		bypass_torture_test:1;

	unsigned int		partial_stripes_expensive:1;
	unsigned int		writeback_metadata:1;
	unsigned int		writeback_running:1;
	unsigned char		writeback_percent;
	unsigned int		writeback_delay;

	uint64_t		writeback_rate_target;
	int64_t			writeback_rate_proportional;
	int64_t			writeback_rate_integral;
	int64_t			writeback_rate_integral_scaled;
	int32_t			writeback_rate_change;

	unsigned int		writeback_rate_update_seconds;
	unsigned int		writeback_rate_i_term_inverse;
	unsigned int		writeback_rate_p_term_inverse;
	unsigned int		writeback_rate_minimum;

	enum stop_on_failure	stop_when_cache_set_failed;
#define DEFAULT_CACHED_DEV_ERROR_LIMIT	64
	atomic_t		io_errors;
	unsigned int		error_limit;
	unsigned int		offline_seconds;

	char			backing_dev_name[BDEVNAME_SIZE];
};

static inline unsigned int cache_mode(struct cached_dev *dc)
{
	return BDEV_CACHE_MODE(&dc->sb);
}

extern unsigned int bch_cutoff_writeback;
extern unsigned int bch_cutoff_writeback_sync;

static inline void cached_dev_put(struct cached_dev *dc)
{
	if (refcount_dec_and_test(&dc->count))
		schedule_work(&dc->detach);
}

static inline bool cached_dev_get(struct cached_dev *dc)
{
	if (!refcount_inc_not_zero(&dc->count))
		return false;

	/* Paired with the mb in cached_dev_attach */
	smp_mb__after_atomic();
	return true;
}

static inline uint64_t bcache_dev_sectors_dirty(struct bcache_device *d)
{
	uint64_t i, ret = 0;

	for (i = 0; i < d->nr_stripes; i++)
		ret += atomic_read(d->stripe_sectors_dirty + i);

	return ret;
}

static inline unsigned int offset_to_stripe(struct bcache_device *d,
					uint64_t offset)
{
	do_div(offset, d->stripe_size);
	return offset;
}

static inline bool bcache_dev_stripe_dirty(struct cached_dev *dc,
					   uint64_t offset,
					   unsigned int nr_sectors)
{
	unsigned int stripe = offset_to_stripe(&dc->disk, offset);

	while (1) {
		if (atomic_read(dc->disk.stripe_sectors_dirty + stripe))
			return true;

		if (nr_sectors <= dc->disk.stripe_size)
			return false;

		nr_sectors -= dc->disk.stripe_size;
		stripe++;
	}
}

static inline void bch_writeback_queue(struct cached_dev *dc)
{
	if (!IS_ERR_OR_NULL(dc->writeback_thread))
		wake_up_process(dc->writeback_thread);
}

static inline void bch_writeback_add(struct cached_dev *dc)
{
	if (!atomic_read(&dc->has_dirty) &&
	    !atomic_xchg(&dc->has_dirty, 1)) {
		if (BDEV_STATE(&dc->sb) != BDEV_STATE_DIRTY) {
			SET_BDEV_STATE(&dc->sb, BDEV_STATE_DIRTY);
			/* XXX: should do this synchronously */
			bch_write_bdev_super(dc, NULL);
		}

		bch_writeback_queue(dc);
	}
}

#define CUTOFF_CACHE_ADD	95
#define CUTOFF_CACHE_READA	90

#endif /* _BCACHE_BACKINGDEV_H */
