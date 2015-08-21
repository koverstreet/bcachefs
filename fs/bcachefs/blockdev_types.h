#ifndef _BCACHE_BLOCKDEV_TYPES_H
#define _BCACHE_BLOCKDEV_TYPES_H

#include "keybuf_types.h"
#include "stats_types.h"
#include "super_types.h"
#include "util.h"

struct bcache_device {
	struct closure		cl;

	struct kobject		kobj;

	struct cache_set	*c;

	struct rb_node		node;
	struct bch_inode_blockdev inode;
	struct mutex		inode_lock;

#define BCACHEDEVNAME_SIZE	12
	char			name[BCACHEDEVNAME_SIZE];

	struct gendisk		*disk;

	unsigned long		flags;
#define BCACHE_DEV_CLOSING	0
#define BCACHE_DEV_DETACHING	1
#define BCACHE_DEV_UNLINK_DONE	2

	unsigned		nr_stripes;
	unsigned		stripe_size;
	atomic_t		*stripe_sectors_dirty;
	unsigned long		*full_dirty_stripes;

	struct bio_set		*bio_split;

	unsigned		data_csum:1;

	int (*ioctl)(struct bcache_device *, fmode_t, unsigned, unsigned long);
};

struct io {
	/* Used to track sequential IO so it can be skipped */
	struct hlist_node	hash;
	struct list_head	lru;

	unsigned long		jiffies;
	unsigned		sequential;
	sector_t		last;
};

struct cached_dev {
	struct list_head	list;
	struct bcache_device	disk;
	struct block_device	*bdev;

	struct cache_sb		sb;
	struct bcache_superblock disk_sb;
	struct closure		sb_write;
	struct semaphore	sb_write_mutex;

	/* Refcount on the cache set. Always nonzero when we're caching. */
	atomic_t		count;
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

	/* for dynamic rate control of writeback */
	struct bch_pd_controller writeback_pd;
	struct delayed_work	writeback_pd_update;
	unsigned		writeback_pd_update_seconds;

	struct task_struct	*writeback_thread;
	struct keybuf		writeback_keys;
	mempool_t		*writeback_io_pool;
	mempool_t		*writeback_page_pool;

	/* For tracking sequential IO */
#define RECENT_IO_BITS	7
#define RECENT_IO	(1 << RECENT_IO_BITS)
	struct io		io[RECENT_IO];
	struct hlist_head	io_hash[RECENT_IO + 1];
	struct list_head	io_lru;
	spinlock_t		io_lock;

	struct cache_accounting	accounting;

	/* The rest of this all shows up in sysfs */
	unsigned		sequential_cutoff;
	unsigned		readahead;

	unsigned		verify:1;
	unsigned		bypass_torture_test:1;

	unsigned		partial_stripes_expensive:1;
	unsigned		writeback_metadata:1;
	unsigned		writeback_running:1;
	unsigned char		writeback_percent;
};

#define CACHE_DEV_REMOVING	0

#endif /* _BCACHE_BLOCKDEV_TYPES_H */
