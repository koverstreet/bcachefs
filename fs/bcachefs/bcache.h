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
#include "util.h"

#include <linux/dynamic_fault.h>

#define cache_set_init_fault(name)					\
	dynamic_fault("bcache:cache_set_init:" name)
#define bch_meta_read_fault(name)					\
	 dynamic_fault("bcache:meta:read:" name)
#define bch_meta_write_fault(name)					\
	 dynamic_fault("bcache:meta:write:" name)

struct bucket_mark {
	union {
	struct {
		u32		counter;
	};

	struct {
		unsigned	owned_by_allocator:1;
		unsigned	cached_sectors:15;
		unsigned	is_metadata:1;
		unsigned	dirty_sectors:15;
	};
	};
};

struct bucket {
	union {
		struct {
			u16	read_prio;
			u16	write_prio;
		};
		u16		prio[2];
	};
	struct bucket_mark	mark;
	u8			last_gc; /* Most out of date gen in the btree */

	/* generation copygc is going to move this bucket into */
	u8			copygc_gen;
};

#include "stats.h"
#include "inode.h"
struct search;
struct btree;
struct keybuf;

/*
 * We put two of these in struct journal; we used them for writes to the
 * journal that are being staged or in flight.
 */
struct journal_write {
	struct jset		*data;
#define JSET_BITS		5

	struct cache_set	*c;
	struct closure_waitlist	wait;
};

/* Embedded in struct cache_set */
struct journal {
	unsigned long		flags;
#define JOURNAL_NEED_WRITE	0
#define JOURNAL_DIRTY		1
#define JOURNAL_REPLAY_DONE	2
	atomic_t		in_flight;

	spinlock_t		lock;

	unsigned		u64s_remaining;
	unsigned		res_count;

	/* Number of blocks free in the bucket(s) we're currently writing to */
	unsigned		blocks_free;

	/* used when waiting because the journal was full */
	wait_queue_head_t	wait;
	struct closure		io;
	struct delayed_work	work;

	unsigned		delay_ms;

	u64			seq;
	DECLARE_FIFO(atomic_t, pin);

	BKEY_PADDED(key);

	struct journal_write	w[2], *cur;
};

/*
 * Embedded in struct cache. First three fields refer to the array of journal
 * buckets, in cache_sb.
 */
struct journal_device {
	/*
	 * For each journal bucket, contains the max sequence number of the
	 * journal writes it contains - so we know when a bucket can be reused.
	 */
	u64			seq[SB_JOURNAL_BUCKETS];

	/* Journal bucket we're currently writing to */
	unsigned		cur_idx;

	/* Last journal bucket that still contains an open journal entry */
	unsigned		last_idx;

	/* Next journal bucket to be discarded */
	unsigned		discard_idx;

#define DISCARD_READY		0
#define DISCARD_IN_FLIGHT	1
#define DISCARD_DONE		2
	/* 1 - discard in flight, -1 - discard completed */
	atomic_t		discard_in_flight;

	struct work_struct	discard_work;
	struct bio		discard_bio;
	struct bio_vec		discard_bv;

	/* Bio for journal reads/writes to this device */
	struct bio		bio;
	struct bio_vec		bv[1 << JSET_BITS];
};

struct keybuf_key {
	struct rb_node		node;
	BKEY_PADDED(key);
	void			*private;
};

struct keybuf {
	struct bkey		last_scanned;
	spinlock_t		lock;

	/*
	 * Beginning and end of range in rb tree - so that we can skip taking
	 * lock and checking the rb tree when we need to check for overlapping
	 * keys.
	 */
	struct bkey		start;
	struct bkey		end;

	struct rb_root		keys;

	struct semaphore	in_flight;

#define KEYBUF_NR		500
	DECLARE_ARRAY_ALLOCATOR(struct keybuf_key, freelist, KEYBUF_NR);
};

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

	int (*cache_miss)(struct btree *, struct search *,
			  struct bio *, unsigned);
	int (*ioctl) (struct bcache_device *, fmode_t, unsigned, unsigned long);
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
	struct bio		sb_bio;
	struct bio_vec		sb_bv[1];
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
	struct task_struct	*writeback_thread;
	struct keybuf		writeback_keys;

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

/* There is one reserve for each type of btree, one for prios and gens
 * and one for moving GC */
enum alloc_reserve {
	RESERVE_PRIO	= BTREE_ID_NR,
	RESERVE_MOVINGGC_BTREE,
	RESERVE_TIERING_BTREE,
	RESERVE_METADATA_LAST = RESERVE_TIERING_BTREE,
	RESERVE_MOVINGGC,
	RESERVE_NONE,
	RESERVE_NR,
};

/*
 * The btree node reserve needs to contain enough buckets so that in a tree of
 * depth 2, we can split each level of node, and then allocate a new root.
 * See btree_check_reserve().
 */
#define BTREE_NODE_RESERVE 7

/* Enough for 16 cache devices, 2 tiers and some left over for pipelining */
#define OPEN_BUCKETS_COUNT 256

/* We don't want open bucket allocations from bch_alloc_gc_sectors() to fail */
#define OPEN_BUCKETS_MOVING_GC_RESERVE NUM_GC_GENS

struct open_bucket {
	struct list_head	list;
	atomic_t		pin;
	unsigned		last_write_point;
	unsigned		sectors_free;
	BKEY_PADDED(key);
};

struct bucket_stats {
	atomic_t		buckets_dirty;
	atomic_t		buckets_cached;
	atomic_t		buckets_meta;
	atomic_t		buckets_alloc;

	atomic64_t		sectors_dirty;
	atomic64_t		sectors_cached;
};

struct cache {
	struct percpu_ref	ref;
	struct rcu_head		kill_rcu;
	struct work_struct	kill_work;
	struct work_struct	remove_work;

	struct cache_set	*set;
	/* Cache tier is protected by bucket_lock */
	struct cache_sb		sb;
	struct bio		sb_bio;
	struct bio_vec		sb_bv[1];

	struct kobject		kobj;
	struct block_device	*bdev;

	/* biosets used in cloned bios for replicas and moving_gc */
	struct bio_set		*replica_set;

	struct task_struct	*alloc_thread;

	struct closure		prio;
	struct prio_set		*disk_buckets;

	/*
	 * When allocating new buckets, prio_write() gets first dibs - since we
	 * may not be allocate at all without writing priorities and gens.
	 * prio_last_buckets[] contains the last buckets we wrote priorities to
	 * (so gc can mark them as metadata).
	 */
	u64			*prio_buckets;
	u64			*prio_last_buckets;
	u64			prio_journal_bucket;

	/*
	 * free: Buckets that are ready to be used
	 *
	 * free_inc: Incoming buckets - these are buckets that currently have
	 * cached data in them, and we can't reuse them until after we write
	 * their new gen to disk. After prio_write() finishes writing the new
	 * gens/prios, they'll be moved to the free list (and possibly discarded
	 * in the process)
	 *
	 * Protected by bucket_lock.
	 */
	DECLARE_FIFO(long, free)[RESERVE_NR];
	DECLARE_FIFO(long, free_inc);

	size_t			fifo_last_bucket;

	/* The allocator thread might be waiting to enqueue to these FIFOs */
	wait_queue_head_t	fifo_wait;

	/* Allocation stuff: */
	u8			*bucket_gens;
	struct bucket		*buckets;

	/* last calculated minimum prio */
	u16			min_prio[2];

	/*
	 * Bucket book keeping. The first element is updated by GC, the
	 * second contains a saved copy of the stats from the beginning
	 * of GC.
	 */
	struct bucket_stats	bucket_stats[2];

	struct mutex		heap_lock;
	DECLARE_HEAP(struct bucket *, heap);

	/* Moving GC: */
	struct task_struct	*moving_gc_read;
	struct workqueue_struct	*moving_gc_write;
	struct keybuf		moving_gc_keys;
	struct bch_pd_controller moving_gc_pd;

	/*
	 * open buckets used in moving garbage collection
	 * NOTE: GC_GEN == 0 signifies no moving gc, so accessing the
	 * gc_buckets array is always GC_GEN-1.
	 *
	 * Protected by bucket_lock.
	 */
#define NUM_GC_GENS 7
	struct open_bucket	*gc_buckets[NUM_GC_GENS];

	/*
	 * If set, the allocator thread will issue discard operations to newly
	 * invalidated buckets.
	 */
	bool			discard;

	struct journal_device	journal;

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

#define TIER_OPEN_BUCKETS_COUNT		16

struct cache_tier {
	unsigned		nr_devices;
	struct cache		*devices[MAX_CACHES_PER_SET];
	struct open_bucket	*data_buckets[TIER_OPEN_BUCKETS_COUNT];
};

struct prio_clock {
	/* All fields protected by bucket_lock */
	u16			hand;
	u16			min_prio;
	atomic_long_t		rescale;
	unsigned __percpu	*rescale_percpu;
};

struct cache_set {
	struct closure		cl;

	struct list_head	list;
	struct kobject		kobj;
	struct kobject		internal;
	unsigned long		flags;

	struct cache __rcu	*cache[MAX_CACHES_PER_SET];

	struct cache_sb		sb;
	size_t			nbuckets;
	unsigned short		bucket_bits;	/* ilog2(bucket_size) */
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
	struct cache_tier	cache_by_alloc[CACHE_TIERS];
	struct mutex		bucket_lock;
	/* Protected by bucket_lock */
	struct closure_waitlist	bucket_wait;


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

	/* GARBAGE COLLECTION */
	struct task_struct	*gc_thread;

	/* Counts how many sectors bch_data_insert has added to the cache */
	atomic64_t		sectors_until_gc;

	/*
	 * Tracks GC's progress - everything in the range [ZERO_KEY..gc_cur_key]
	 * has been marked by GC.
	 *
	 * (Note that it starts out at ZERO_KEY, but since the extents btree
	 * comes first and an extent equal to ZERO_KEY would have zero size,
	 * gc_cur_key == ZERO_KEY and gc_cur_btree == BTREE_ID_EXTENTS does
	 * correctly mean nothing has been marked)
	 *
	 * Protected by gc_cur_lock. Only written to by GC thread, so GC thread
	 * can read without a lock.
	 */
	seqlock_t		gc_cur_lock;
	enum btree_id		gc_cur_btree;
	struct bkey		gc_cur_key;

	/*
	 * The allocation code needs gc_mark in struct bucket to be correct, but
	 * it's not while a gc is in progress. Protected by bucket_lock.
	 */
	int			gc_mark_valid;

	/*
	 * Number of GC iterations completed. To wait for the next GC to finish,
	 * add yourself to gc_wait and wait for this to change.
	 */
	atomic_t		gc_count;

	/* Allocator threads might be waiting for GC */
	wait_queue_head_t	gc_wait;
	atomic_t		gc_waiters;

	struct gc_stat		gc_stats;


	/* IO PATH */
	struct bio_list		read_race_list;
	struct work_struct	read_race_work;
	spinlock_t		read_race_lock;

	/* TIERING */
	struct task_struct	*tiering_read;
	struct workqueue_struct	*tiering_write;

	struct keybuf		tiering_keys;
	struct bch_pd_controller tiering_pd;

	/* DEBUG JUNK */
	struct dentry		*debug;
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

	struct time_stats	btree_gc_time;
	struct time_stats	btree_split_time;
	struct time_stats	btree_read_time;

	struct cache_accounting accounting;
	atomic_long_t		cache_read_races;
	atomic_long_t		writeback_keys_done;
	atomic_long_t		writeback_keys_failed;

	enum			{
		ON_ERROR_UNREGISTER,
		ON_ERROR_PANIC,
	}			on_error;
	unsigned		error_limit;
	unsigned		error_decay;

	bool			expensive_debug_checks;
	unsigned		verify:1;
	unsigned		key_merging_disabled:1;
	unsigned		gc_always_rewrite:1;
	unsigned		shrinker_disabled:1;
	unsigned		copy_gc_enabled:1;
	unsigned		tiering_enabled:1;
	unsigned		tiering_percent;
	unsigned		btree_scan_ratelimit;

	/* number of caches to replicate data on */
	unsigned short		meta_replicas;
	unsigned short		data_replicas;
};

struct bbio {
	struct cache		*ca;

	unsigned int		bi_idx;		/* current index into bvl_vec */

	unsigned int            bi_bvec_done;	/* number of bytes completed in
						   current bvec */
	unsigned		submit_time_us;
	struct bkey		key;
	u64			pad;
	/* Only ever have a single pointer (the one we're doing io to/from) */
	struct bio		bio;
};

#define to_bbio(_bio)		container_of((_bio), struct bbio, bio)

#define btree_bytes(c)		((c)->btree_pages * PAGE_SIZE)
#define btree_blocks(b)							\
	((unsigned) (KEY_SIZE(&b->key) >> (b)->c->block_bits))

#define btree_default_blocks(c)						\
	((unsigned) ((PAGE_SECTORS * (c)->btree_pages) >> (c)->block_bits))

#define bucket_pages(c)		((c)->sb.bucket_size / PAGE_SECTORS)
#define bucket_bytes(c)		((c)->sb.bucket_size << 9)
#define block_bytes(c)		((c)->sb.block_size << 9)

#define prios_per_bucket(c)				\
	((bucket_bytes(c) - sizeof(struct prio_set)) /	\
	 sizeof(struct bucket_disk))
#define prio_buckets(c)					\
	DIV_ROUND_UP((size_t) (c)->sb.nbuckets, prios_per_bucket(c))

static inline size_t sector_to_bucket(struct cache_set *c, sector_t s)
{
	return s >> c->bucket_bits;
}

static inline sector_t bucket_to_sector(struct cache_set *c, size_t b)
{
	return ((sector_t) b) << c->bucket_bits;
}

static inline sector_t bucket_remainder(struct cache_set *c, sector_t s)
{
	return s & (c->sb.bucket_size - 1);
}

static inline struct cache *PTR_CACHE(struct cache_set *c,
				      const struct bkey *k,
				      unsigned ptr)
{
	unsigned dev = PTR_DEV(k, ptr);

	return dev < MAX_CACHES_PER_SET
		? rcu_dereference(c->cache[dev])
		: NULL;
}

static inline size_t PTR_BUCKET_NR(struct cache_set *c,
				   const struct bkey *k,
				   unsigned ptr)
{
	return sector_to_bucket(c, PTR_OFFSET(k, ptr));
}

static inline u8 PTR_BUCKET_GEN(struct cache_set *c,
				struct cache *ca,
				const struct bkey *k,
				unsigned ptr)
{
	return ca->bucket_gens[PTR_BUCKET_NR(c, k, ptr)];
}

static inline struct bucket *PTR_BUCKET(struct cache_set *c,
					struct cache *ca,
					const struct bkey *k,
					unsigned ptr)
{
	return ca->buckets + PTR_BUCKET_NR(c, k, ptr);
}

static inline uint8_t gen_after(uint8_t a, uint8_t b)
{
	uint8_t r = a - b;
	return r > 128U ? 0 : r;
}

static inline u8 ptr_stale(struct cache_set *c, struct cache *ca,
			   const struct bkey *k, unsigned ptr)
{
	return gen_after(PTR_BUCKET_GEN(c, ca, k, ptr), PTR_GEN(k, ptr));
}

/* Btree key macros */

/*
 * This is used for various on disk data structures - cache_sb, prio_set, bset,
 * jset: The checksum is _always_ the first 8 bytes of these structs
 */
#define csum_set(i)							\
	bch_crc64(((void *) (i)) + sizeof(uint64_t),			\
		  ((void *) bset_bkey_last(i)) -			\
		  (((void *) (i)) + sizeof(uint64_t)))

/* Error handling macros */

#define btree_bug(b, ...)						\
do {									\
	if (bch_cache_set_error((b)->c, __VA_ARGS__))			\
		dump_stack();						\
} while (0)

#define cache_bug(c, ...)						\
do {									\
	if (bch_cache_set_error(c, __VA_ARGS__))			\
		dump_stack();						\
} while (0)

#define btree_bug_on(cond, b, ...)					\
do {									\
	if (cond)							\
		btree_bug(b, __VA_ARGS__);				\
} while (0)

#define cache_bug_on(cond, c, ...)					\
do {									\
	if (cond)							\
		cache_bug(c, __VA_ARGS__);				\
} while (0)

#define cache_set_err_on(cond, c, ...)					\
do {									\
	if (cond)							\
		bch_cache_set_error(c, __VA_ARGS__);			\
} while (0)

/* Looping macros */

static inline struct cache *bch_next_cache_rcu(struct cache_set *c,
					       unsigned *iter)
{
	struct cache *ret = NULL;

	while (*iter < c->sb.nr_in_set &&
	       !(ret = rcu_dereference(c->cache[*iter])))
		(*iter)++;

	return ret;
}

#define for_each_cache_rcu(ca, c, iter)					\
	for ((iter) = 0; ((ca) = bch_next_cache_rcu((c), &(iter))); (iter)++)

static inline struct cache *bch_get_next_cache(struct cache_set *c,
					       unsigned *iter)
{
	struct cache *ret;

	rcu_read_lock();
	if ((ret = bch_next_cache_rcu(c, iter)))
		percpu_ref_get(&ret->ref);
	rcu_read_unlock();

	return ret;
}

/*
 * If you break early, you must drop your ref on the current cache
 */
#define for_each_cache(ca, c, iter)					\
	for ((iter) = 0;						\
	     (ca = bch_get_next_cache(c, &(iter)));			\
	     percpu_ref_put(&ca->ref), (iter)++)

#define for_each_bucket(b, ca)						\
	for (b = (ca)->buckets + (ca)->sb.first_bucket;			\
	     b < (ca)->buckets + (ca)->sb.nbuckets; b++)

static inline void cached_dev_put(struct cached_dev *dc)
{
	if (atomic_dec_and_test(&dc->count))
		schedule_work(&dc->detach);
}

static inline bool cached_dev_get(struct cached_dev *dc)
{
	if (!atomic_inc_not_zero(&dc->count))
		return false;

	/* Paired with the mb in cached_dev_attach */
	smp_mb__after_atomic();
	return true;
}

static inline u64 bcache_dev_inum(struct bcache_device *d)
{
	return KEY_INODE(&d->inode.i_inode.i_key);
}

static inline struct bcache_device *bch_dev_find(struct cache_set *c, u64 inode)
{
	return radix_tree_lookup(&c->devices, inode);
}

#define kobj_attribute_write(n, fn)					\
	static struct kobj_attribute ksysfs_##n = __ATTR(n, S_IWUSR, NULL, fn)

#define kobj_attribute_rw(n, show, store)				\
	static struct kobj_attribute ksysfs_##n =			\
		__ATTR(n, S_IWUSR|S_IRUSR, show, store)

/* Forward declarations */

void bch_count_io_errors(struct cache *, int, const char *);
void bch_bbio_count_io_errors(struct bbio *, int, const char *);
void bch_bbio_endio(struct bbio *, int, const char *);
void bch_bbio_free(struct bio *, struct cache_set *);
struct bio *bch_bbio_alloc(struct cache_set *);

void bch_generic_make_request(struct bio *, struct cache_set *);
void bch_bio_submit_work(struct work_struct *);
void bch_bbio_prep(struct bbio *, struct cache *);
void bch_submit_bbio(struct bbio *, struct cache *, struct bkey *,
		     unsigned, bool);
void bch_submit_bbio_replicas(struct bio *, struct cache_set *,
			      struct bkey *, unsigned long *, bool);
void bch_bbio_reset(struct bbio *bio);

__printf(2, 3)
bool bch_cache_set_error(struct cache_set *, const char *, ...);

void bch_prio_write(struct cache *);
void bch_write_bdev_super(struct cached_dev *, struct closure *);

struct bcache_device *bch_dev_get_by_inode(struct cache_set *, u64);

extern struct workqueue_struct *bcache_io_wq;
extern const char * const bch_cache_modes[];
extern struct mutex bch_register_lock;
extern struct list_head bch_cache_sets;

extern struct kobj_type bch_cached_dev_ktype;
extern struct kobj_type bch_flash_dev_ktype;
extern struct kobj_type bch_cache_set_ktype;
extern struct kobj_type bch_cache_set_internal_ktype;
extern struct kobj_type bch_cache_ktype;

void bch_cached_dev_release(struct kobject *);
void bch_flash_dev_release(struct kobject *);
void bch_cache_set_release(struct kobject *);
void bch_cache_release(struct kobject *);

void bcache_write_super(struct cache_set *);

int bch_flash_dev_create(struct cache_set *, u64);

int bch_cached_dev_attach(struct cached_dev *, struct cache_set *);
void bch_cached_dev_detach(struct cached_dev *);
void bch_cached_dev_run(struct cached_dev *);
void bcache_device_stop(struct bcache_device *);

void bch_cache_set_unregister(struct cache_set *);
void bch_cache_set_stop(struct cache_set *);

void bch_cache_remove(struct cache *);

struct cache_set *bch_cache_set_alloc(struct cache_sb *);
void bch_btree_cache_free(struct cache_set *);
int bch_btree_cache_alloc(struct cache_set *);
void bch_tiering_init_cache_set(struct cache_set *);
int bch_tiering_thread_start(struct cache_set *c);

void bch_debug_exit(void);
int bch_debug_init(struct kobject *);
void bch_request_exit(void);
int bch_request_init(void);

#endif /* _BCACHE_H */
