#ifndef _BCACHE_H
#define _BCACHE_H

/*
 * SOME HIGH LEVEL CODE DOCUMENTATION:
 *
 * Bcache mostly works with cache sets, cache devices, and backing devices.
 *
 * Support for multiple cache devices hasn't quite been finished off yet, but
 * it's about 95% plumbed through. A cache set and its cache devices is sort of
 * like a md raid array and its component devices. Most of the code doesn't care
 * about individual cache devices, the main abstraction is the cache set.
 *
 * Multiple cache devices is intended to give us the ability to mirror dirty
 * cached data and metadata, without mirroring clean cached data.
 *
 * Backing devices are different, in that they have a lifetime independent of a
 * cache set. When you register a newly formatted backing device it'll come up
 * in passthrough mode, and then you can attach and detach a backing device from
 * a cache set at runtime - while it's mounted and in use. Detaching implicitly
 * invalidates any cached data for that backing device.
 *
 * A cache set can have multiple (many) backing devices attached to it.
 *
 * There's also flash only volumes - this is the reason for the distinction
 * between struct cached_dev and struct bcache_device. A flash only volume
 * works much like a bcache device that has a backing device, except the
 * "cached" data is always dirty. The end result is that we get thin
 * provisioning with very little additional code.
 *
 * Flash only volumes work but they're not production ready because the moving
 * garbage collector needs more work. More on that later.
 *
 * BUCKETS/ALLOCATION:
 *
 * Bcache is primarily designed for caching, which means that in normal
 * operation all of our available space will be allocated. Thus, we need an
 * efficient way of deleting things from the cache so we can write new things to
 * it.
 *
 * To do this, we first divide the cache device up into buckets. A bucket is the
 * unit of allocation; they're typically around 1 mb - anywhere from 128k to 2M+
 * works efficiently.
 *
 * Each bucket has a 16 bit priority, and an 8 bit generation associated with
 * it. The gens and priorities for all the buckets are stored contiguously and
 * packed on disk (in a linked list of buckets - aside from the superblock, all
 * of bcache's metadata is stored in buckets).
 *
 * The priority is used to implement an LRU. We reset a bucket's priority when
 * we allocate it or on cache it, and every so often we decrement the priority
 * of each bucket. It could be used to implement something more sophisticated,
 * if anyone ever gets around to it.
 *
 * The generation is used for invalidating buckets. Each pointer also has an 8
 * bit generation embedded in it; for a pointer to be considered valid, its gen
 * must match the gen of the bucket it points into.  Thus, to reuse a bucket all
 * we have to do is increment its gen (and write its new gen to disk; we batch
 * this up).
 *
 * Bcache is entirely COW - we never write twice to a bucket, even buckets that
 * contain metadata (including btree nodes).
 *
 * THE BTREE:
 *
 * Bcache is in large part design around the btree.
 *
 * At a high level, the btree is just an index of key -> ptr tuples.
 *
 * Keys represent extents, and thus have a size field. Keys also have a variable
 * number of pointers attached to them (potentially zero, which is handy for
 * invalidating the cache).
 *
 * The key itself is an inode:offset pair. The inode number corresponds to a
 * backing device or a flash only volume. The offset is the ending offset of the
 * extent within the inode - not the starting offset; this makes lookups
 * slightly more convenient.
 *
 * Pointers contain the cache device id, the offset on that device, and an 8 bit
 * generation number. More on the gen later.
 *
 * Index lookups are not fully abstracted - cache lookups in particular are
 * still somewhat mixed in with the btree code, but things are headed in that
 * direction.
 *
 * Updates are fairly well abstracted, though. There are two different ways of
 * updating the btree; insert and replace.
 *
 * BTREE_INSERT will just take a list of keys and insert them into the btree -
 * overwriting (possibly only partially) any extents they overlap with. This is
 * used to update the index after a write.
 *
 * BTREE_REPLACE is really cmpxchg(); it inserts a key into the btree iff it is
 * overwriting a key that matches another given key. This is used for inserting
 * data into the cache after a cache miss, and for background writeback, and for
 * the moving garbage collector.
 *
 * There is no "delete" operation; deleting things from the index is
 * accomplished by either by invalidating pointers (by incrementing a bucket's
 * gen) or by inserting a key with 0 pointers - which will overwrite anything
 * previously present at that location in the index.
 *
 * This means that there are always stale/invalid keys in the btree. They're
 * filtered out by the code that iterates through a btree node, and removed when
 * a btree node is rewritten.
 *
 * BTREE NODES:
 *
 * Our unit of allocation is a bucket, and we we can't arbitrarily allocate and
 * free smaller than a bucket - so, that's how big our btree nodes are.
 *
 * (If buckets are really big we'll only use part of the bucket for a btree node
 * - no less than 1/4th - but a bucket still contains no more than a single
 * btree node. I'd actually like to change this, but for now we rely on the
 * bucket's gen for deleting btree nodes when we rewrite/split a node.)
 *
 * Anyways, btree nodes are big - big enough to be inefficient with a textbook
 * btree implementation.
 *
 * The way this is solved is that btree nodes are internally log structured; we
 * can append new keys to an existing btree node without rewriting it. This
 * means each set of keys we write is sorted, but the node is not.
 *
 * We maintain this log structure in memory - keeping 1Mb of keys sorted would
 * be expensive, and we have to distinguish between the keys we have written and
 * the keys we haven't. So to do a lookup in a btree node, we have to search
 * each sorted set. But we do merge written sets together lazily, so the cost of
 * these extra searches is quite low (normally most of the keys in a btree node
 * will be in one big set, and then there'll be one or two sets that are much
 * smaller).
 *
 * This log structure makes bcache's btree more of a hybrid between a
 * conventional btree and a compacting data structure, with some of the
 * advantages of both.
 *
 * GARBAGE COLLECTION:
 *
 * We can't just invalidate any bucket - it might contain dirty data or
 * metadata. If it once contained dirty data, other writes might overwrite it
 * later, leaving no valid pointers into that bucket in the index.
 *
 * Thus, the primary purpose of garbage collection is to find buckets to reuse.
 * It also counts how much valid data it each bucket currently contains, so that
 * allocation can reuse buckets sooner when they've been mostly overwritten.
 *
 * It also does some things that are really internal to the btree
 * implementation. If a btree node contains pointers that are stale by more than
 * some threshold, it rewrites the btree node to avoid the bucket's generation
 * wrapping around. It also merges adjacent btree nodes if they're empty enough.
 *
 * THE JOURNAL:
 *
 * Bcache's journal is not necessary for consistency; we always strictly
 * order metadata writes so that the btree and everything else is consistent on
 * disk in the event of an unclean shutdown, and in fact bcache had writeback
 * caching (with recovery from unclean shutdown) before journalling was
 * implemented.
 *
 * Rather, the journal is purely a performance optimization; we can't complete a
 * write until we've updated the index on disk, otherwise the cache would be
 * inconsistent in the event of an unclean shutdown. This means that without the
 * journal, on random write workloads we constantly have to update all the leaf
 * nodes in the btree, and those writes will be mostly empty (appending at most
 * a few keys each) - highly inefficient in terms of amount of metadata writes,
 * and it puts more strain on the various btree resorting/compacting code.
 *
 * The journal is just a log of keys we've inserted; on startup we just reinsert
 * all the keys in the open journal entries. That means that when we're updating
 * a node in the btree, we can wait until a 4k block of keys fills up before
 * writing them out.
 *
 * For simplicity, we only journal updates to leaf nodes; updates to parent
 * nodes are rare enough (since our leaf nodes are huge) that it wasn't worth
 * the complexity to deal with journalling them (in particular, journal replay)
 * - updates to non leaf nodes just happen synchronously (see btree_split()).
 */

#define pr_fmt(fmt) "bcache: %s() " fmt "\n", __func__

#include <linux/bug.h>
#include <linux/bio.h>
#include <linux/closure.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/percpu-refcount.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/rhashtable.h>
#include <linux/rwsem.h>
#include <linux/seqlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "bcachefs_format.h"
#include "bset.h"
#include "fifo.h"
#include "util.h"

#include <linux/dynamic_fault.h>

#define cache_set_init_fault(name)					\
	dynamic_fault("bcache:cache_set_init:" name)
#define bch_meta_read_fault(name)					\
	 dynamic_fault("bcache:meta:read:" name)
#define bch_meta_write_fault(name)					\
	 dynamic_fault("bcache:meta:write:" name)

#define BTREE_SCAN_BATCH	500

#include "alloc_types.h"
#include "bkey_methods.h"
#include "blockdev_types.h"
#include "buckets_types.h"
#include "journal_types.h"
#include "keylist_types.h"
#include "keybuf_types.h"
#include "move_types.h"
#include "stats_types.h"
#include "super_types.h"

/* 256k, in sectors */
#define BTREE_NODE_SIZE_MAX		512

struct btree;
struct cache;

struct cache_group {
	seqcount_t		lock;
	unsigned		nr_devices;
	struct cache __rcu	*devices[MAX_CACHES_PER_SET];
};

struct cache {
	struct percpu_ref	ref;
	struct rcu_head		free_rcu;
	struct work_struct	free_work;
	struct work_struct	remove_work;
	unsigned long		flags;

	struct cache_set	*set;
	struct cache_sb		sb;

	struct cache_group	self;

	/*
	 * Cached version of this device's member info from superblock
	 * Committed by write_super()
	 */
	struct cache_member	mi;

	struct bcache_superblock disk_sb;

	struct kobject		kobj;

	/* biosets used in cloned bios for replicas and moving_gc */
	struct bio_set		*replica_set;

	struct task_struct	*alloc_thread;

	struct prio_set		*disk_buckets;

	/*
	 * When allocating new buckets, prio_write() gets first dibs - since we
	 * may not be allocate at all without writing priorities and gens.
	 * prio_last_buckets[] contains the last buckets we wrote priorities to
	 * (so gc can mark them as metadata).
	 */
	u64			*prio_buckets;
	u64			*prio_last_buckets;
	spinlock_t		prio_buckets_lock;
	struct bio		*bio_prio;

	/*
	 * free: Buckets that are ready to be used
	 *
	 * free_inc: Incoming buckets - these are buckets that currently have
	 * cached data in them, and we can't reuse them until after we write
	 * their new gen to disk. After prio_write() finishes writing the new
	 * gens/prios, they'll be moved to the free list (and possibly discarded
	 * in the process)
	 */
	DECLARE_FIFO(long, free)[RESERVE_NR];
	DECLARE_FIFO(long, free_inc);
	spinlock_t		freelist_lock;

	size_t			reserve_buckets_count;

	size_t			fifo_last_bucket;

	/* Allocation stuff: */
	u8			*bucket_gens;
	struct bucket		*buckets;
	unsigned short		bucket_bits;	/* ilog2(bucket_size) */

	/* last calculated minimum prio */
	u16			min_prio[2];

	/*
	 * Bucket book keeping. The first element is updated by GC, the
	 * second contains a saved copy of the stats from the beginning
	 * of GC.
	 */
	struct bucket_stats __percpu *bucket_stats_percpu;
	struct bucket_stats	bucket_stats_cached;

	atomic_long_t		saturated_count;
	size_t			inc_gen_needs_gc;

	struct mutex		heap_lock;
	DECLARE_HEAP(struct bucket_heap_entry, heap);

	/* Moving GC: */
	struct task_struct	*moving_gc_read;
	struct workqueue_struct	*moving_gc_write;

	struct moving_queue	moving_gc_queue;
	struct bch_pd_controller moving_gc_pd;

	/* Tiering: */
	struct moving_queue	tiering_queue;
	struct write_point	tiering_write_point;
	unsigned		tiering_stripe_size;

	/*
	 * open buckets used in moving garbage collection
	 * NOTE: GC_GEN == 0 signifies no moving gc, so accessing the
	 * gc_buckets array is always GC_GEN-1.
	 */
#define NUM_GC_GENS 8
	struct write_point	gc_buckets[NUM_GC_GENS];

	struct journal_device	journal;

	struct work_struct	io_error_work;

	/* The rest of this all shows up in sysfs */
#define IO_ERROR_SHIFT		20
	atomic_t		io_errors;
	atomic_t		io_count;

	atomic_long_t		meta_sectors_written;
	atomic_long_t		btree_sectors_written;
	atomic_long_t		sectors_written;
};

struct gc_stat {
	size_t			nodes;
	size_t			key_bytes;

	size_t			nkeys;
	uint64_t		data;	/* sectors */
};

/*
 * Flag bits, for how the cache set is shutting down, and what phase it's at:
 *
 * CACHE_SET_UNREGISTERING means we're not just shutting down, we're detaching
 * all the backing devices first (their cached data gets invalidated, and they
 * won't automatically reattach).
 *
 * CACHE_SET_STOPPING always gets set first when we're closing down a cache set;
 * we'll continue to run normally for awhile with CACHE_SET_STOPPING set (i.e.
 * flushing dirty data).
 *
 * CACHE_SET_RUNNING means all cache devices have been registered and journal
 * replay is complete.
 */
#define CACHE_SET_UNREGISTERING		0
#define	CACHE_SET_STOPPING		1
#define	CACHE_SET_RUNNING		2
#define	CACHE_SET_RO			3
#define	CACHE_SET_GC_STOPPING		4
#define	CACHE_SET_GC_FAILURE		5

struct prio_clock {
	/* All fields protected by bucket_lock */
	u16			hand;
	u16			min_prio;
	atomic_long_t		rescale;
	unsigned __percpu	*rescale_percpu;
};

struct cache_member_rcu {
	struct rcu_head		rcu;
	unsigned		nr_in_set;
	struct cache_member	m[];
};

struct btree_debug {
	unsigned		id;
	struct dentry		*btree;
	struct dentry		*btree_format;
};

struct cache_set {
	struct closure		cl;

	struct list_head	list;
	struct kobject		kobj;
	struct kobject		internal;
	unsigned long		flags;

	/* Counts outstanding writes, for clean transition to read-only */
	struct percpu_ref	writes;
	struct completion	write_disable_complete;
	struct work_struct	read_only_work;

	struct cache __rcu	*cache[MAX_CACHES_PER_SET];
	struct cache_member_rcu	*members;
	unsigned long	cache_slots_used[BITS_TO_LONGS(MAX_CACHES_PER_SET)];

	struct cache_sb		sb;
	unsigned short		block_bits;	/* ilog2(block_size) */

	struct closure		sb_write;
	struct semaphore	sb_write_mutex;

	mempool_t		*bio_meta;
	struct bio_set		*bio_split;

	struct bio_list		bio_submit_list;
	struct work_struct	bio_submit_work;
	spinlock_t		bio_submit_lock;

	/* BTREE CACHE */
	/*
	 * Default number of pages for a new btree node - may be less than a
	 * full bucket
	 */
	unsigned		btree_pages;

	spinlock_t		btree_root_lock;
	struct btree		*btree_roots[BTREE_ID_NR];

	struct rhashtable	btree_cache_table;

	/*
	 * We never free a struct btree, except on shutdown - we just put it on
	 * the btree_cache_freed list and reuse it later. This simplifies the
	 * code, and it doesn't cost us much memory as the memory usage is
	 * dominated by buffers that hold the actual btree node data and those
	 * can be freed - and the number of struct btrees allocated is
	 * effectively bounded.
	 *
	 * btree_cache_freeable effectively is a small cache - we use it because
	 * high order page allocations can be rather expensive, and it's quite
	 * common to delete and allocate btree nodes in quick succession. It
	 * should never grow past ~2-3 nodes in practice.
	 */
	struct mutex		btree_cache_lock;
	struct list_head	btree_cache;
	struct list_head	btree_cache_freeable;
	struct list_head	btree_cache_freed;

	/* Number of elements in btree_cache + btree_cache_freeable lists */
	unsigned		btree_cache_used;
	unsigned		btree_cache_reserve;
	struct shrinker		btree_cache_shrink;

	/*
	 * If we need to allocate memory for a new btree node and that
	 * allocation fails, we can cannibalize another node in the btree cache
	 * to satisfy the allocation - lock to guarantee only one thread does
	 * this at a time:
	 */
	struct closure_waitlist	mca_wait;
	struct task_struct	*btree_cache_alloc_lock;

	struct workqueue_struct	*wq;

	/* ALLOCATION */
	struct bch_pd_controller foreground_write_pd;
	struct delayed_work	pd_controllers_update;
	unsigned		pd_controllers_update_seconds;
	spinlock_t		foreground_write_pd_lock;
	struct bch_write_op	*write_wait_head;
	struct bch_write_op	*write_wait_tail;

	struct timer_list	foreground_write_wakeup;

	struct cache_group	cache_all;
	struct cache_group	cache_tiers[CACHE_TIERS];
	u64			capacity; /* sectors */

	struct mutex		bucket_lock;

	struct closure_waitlist	freelist_wait;
	struct closure_waitlist	buckets_available_wait;


	/*
	 * When we invalidate buckets, we use both the priority and the amount
	 * of good data to determine which buckets to reuse first - to weight
	 * those together consistently we keep track of the smallest nonzero
	 * priority of any bucket.
	 */
	struct prio_clock	prio_clock[2];

	/* SECTOR ALLOCATOR */
	struct list_head	open_buckets_open;
	struct list_head	open_buckets_free;
	unsigned		open_buckets_nr_free;
	struct closure_waitlist	open_buckets_wait;
	spinlock_t		open_buckets_lock;
	struct open_bucket	open_buckets[OPEN_BUCKETS_COUNT];

	struct write_point	write_points[WRITE_POINT_COUNT];
	struct write_point	promote_write_point;

	/*
	 * This write point is used for migrating data off a device
	 * and can point to any other device.
	 * We can't use the normal write points because those will
	 * gang up n replicas, and for migration we want only one new
	 * replica.
	 */
	struct write_point	migration_write_point;

	/* GARBAGE COLLECTION */
	struct task_struct	*gc_thread;

	/* This is a list of scan_keylists for btree GC to scan */
	struct list_head	gc_scan_keylists;
	struct mutex		gc_scan_keylist_lock;

	/* Counts how many sectors bch_data_insert has added to the cache */
	atomic64_t		sectors_until_gc;

	/*
	 * Tracks GC's progress - everything in the range [ZERO_KEY..gc_cur_pos]
	 * has been marked by GC.
	 *
	 * (Note that it starts out at ZERO_KEY, but since the extents btree
	 * comes first and an extent equal to ZERO_KEY would have zero size,
	 * gc_cur_pos == ZERO_KEY and gc_cur_btree == BTREE_ID_EXTENTS does
	 * correctly mean nothing has been marked)
	 *
	 * gc_cur_btree > BTREE_ID_NR indicates gc has finished and gc marks are
	 * currently valid (when gc_cur_btree == BTREE_ID_NR gc has only
	 * finished sweeping the btrees, there's still a bit more work to do).
	 *
	 * Protected by gc_cur_lock. Only written to by GC thread, so GC thread
	 * can read without a lock.
	 */
	seqlock_t		gc_cur_lock;
	enum btree_id		gc_cur_btree;
	unsigned		gc_cur_level;
	struct bpos		gc_cur_pos;

	/*
	 * The allocation code needs gc_mark in struct bucket to be correct, but
	 * it's not while a gc is in progress.
	 */
	struct rw_semaphore	gc_lock;
	struct gc_stat		gc_stats;


	/* IO PATH */
	struct bio_list		read_race_list;
	struct work_struct	read_race_work;
	spinlock_t		read_race_lock;

	/* TIERING */
	struct task_struct	*tiering_read;
	struct bch_pd_controller tiering_pd;

	/* NOTIFICATIONS */
	struct mutex		uevent_lock;
	struct kobj_uevent_env	uevent_env;

	/* DEBUG JUNK */
	struct dentry		*debug;
	struct btree_debug	btree_debug[BTREE_ID_NR];
#ifdef CONFIG_BCACHEFS_DEBUG
	struct btree		*verify_data;
	struct bset		*verify_ondisk;
	struct mutex		verify_lock;
#endif

	u64			unused_inode_hint;

	/*
	 * A btree node on disk could have too many bsets for an iterator to fit
	 * on the stack - have to dynamically allocate them
	 */
	mempool_t		*fill_iter;

	struct bset_sort_state	sort;

	struct journal		journal;
	unsigned		btree_flush_delay;

	/* CACHING OTHER BLOCK DEVICES */
	mempool_t		*search;
	struct radix_tree_root	devices;
	struct list_head	cached_devs;
	u64			cached_dev_sectors;
	struct closure		caching;

#define CONGESTED_MAX		1024
	unsigned		congested_last_us;
	atomic_t		congested;

	/* The rest of this all shows up in sysfs */
	unsigned		congested_read_threshold_us;
	unsigned		congested_write_threshold_us;

	struct time_stats	mca_alloc_time;
	struct time_stats	mca_scan_time;
	struct time_stats	btree_gc_time;
	struct time_stats	btree_coalesce_time;
	struct time_stats	btree_split_time;
	struct time_stats	btree_read_time;
	struct time_stats	journal_full_time;

	struct cache_accounting accounting;
	atomic_long_t		cache_read_races;
	atomic_long_t		writeback_keys_done;
	atomic_long_t		writeback_keys_failed;

	unsigned		error_limit;
	unsigned		error_decay;

	bool			expensive_debug_checks;
	unsigned		version_stress_test:1;
	unsigned		verify:1;
	unsigned		key_merging_disabled:1;
	unsigned		gc_always_rewrite:1;
	unsigned		gc_rewrite_disabled:1;
	unsigned		gc_coalesce_disabled:1;
	unsigned		shrinker_disabled:1;
	unsigned		copy_gc_enabled:1;
	unsigned		tiering_enabled:1;
	unsigned		tiering_percent;
	unsigned		btree_scan_ratelimit;

	/*
	 * foreground writes will be throttled when the number of free
	 * buckets is below this percentage
	 */
	unsigned		foreground_target_percent;
	/*
	 * foreground writes will wait when the number of free buckets is
	 * below this percentage
	 */
	unsigned		bucket_reserve_percent;
	/*
	 * foreground writes will fail when the number of free sectors is
	 * below this percentage
	 */
	unsigned		sector_reserve_percent;
};

struct bbio {
	struct cache		*ca;

	unsigned int		bi_idx;		/* current index into bvl_vec */

	unsigned int            bi_bvec_done;	/* number of bytes completed in
						   current bvec */
	unsigned		submit_time_us;
	struct bkey_i		key;
	struct bch_extent_ptr	ptr;
	/* Only ever have a single pointer (the one we're doing io to/from) */
	struct bio		bio;
};

#define to_bbio(_bio)		container_of((_bio), struct bbio, bio)

static inline unsigned bucket_pages(const struct cache *ca)
{
	return ca->mi.bucket_size / PAGE_SECTORS;
}

static inline unsigned bucket_bytes(const struct cache *ca)
{
	return ca->mi.bucket_size << 9;
}

#define block_bytes(c)		((c)->sb.block_size << 9)

#define prios_per_bucket(ca)				\
	((bucket_bytes(ca) - sizeof(struct prio_set)) /	\
	 sizeof(struct bucket_disk))
#define prio_buckets(ca)					\
	DIV_ROUND_UP((size_t) (ca)->mi.nbuckets, prios_per_bucket(ca))

/* Error handling macros */

#define __bch_cache_set_error(c, fmt, ...)				\
	printk(KERN_ERR "bcache: error on %pU: " fmt,			\
	       (c)->sb.set_uuid.b, ##__VA_ARGS__)

#define __bch_cache_error(ca, fmt, ...)					\
do {									\
	char _buf[BDEVNAME_SIZE];					\
	__bch_cache_set_error((ca)->set, "%s: " fmt,			\
			      bdevname((ca)->disk_sb.bdev, _buf),	\
			      ##__VA_ARGS__);				\
} while (0)

#define bch_cache_set_error(c, ...)					\
do {									\
	__bch_cache_set_error(c, __VA_ARGS__);				\
	bch_cache_set_fail(c);						\
} while (0)

#define bch_cache_error(ca, ...)					\
do {									\
	__bch_cache_error(ca, __VA_ARGS__);				\
	bch_cache_set_fail((ca)->set);					\
} while (0)

#define btree_bug(b, ...)						\
do {									\
	__bch_cache_set_error((b)->c, __VA_ARGS__);			\
	BUG();								\
} while (0)

#define cache_set_bug(c, ...)						\
do {									\
	__bch_cache_set_error(c, __VA_ARGS__);				\
	BUG();								\
} while (0)

#define btree_bug_on(cond, b, ...)					\
do {									\
	if (cond)							\
		btree_bug(b, __VA_ARGS__);				\
} while (0)

#define cache_set_bug_on(cond, c, ...)					\
do {									\
	if (cond)							\
		cache_set_bug(c, __VA_ARGS__);				\
} while (0)

#define cache_set_err_on(cond, c, ...)					\
do {									\
	if (cond)							\
		bch_cache_set_error(c, __VA_ARGS__);			\
} while (0)

#define __bcache_io_error(c, fmt, ...)					\
	printk_ratelimited(KERN_ERR "bcache: IO error on %pU: " fmt "\n",\
	       (c)->sb.set_uuid.b, ##__VA_ARGS__)

#define bcache_io_error(c, bio, fmt, ...)				\
do {									\
	__bcache_io_error(c, fmt, ##__VA_ARGS__);			\
	(bio)->bi_error = -EIO;						\
} while (0)

/* Forward declarations */

void bch_debug_exit(void);
int bch_debug_init(void);

#endif /* _BCACHE_H */
