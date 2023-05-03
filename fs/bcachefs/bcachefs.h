/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_H
#define _BCACHEFS_H

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

#undef pr_fmt
#define pr_fmt(fmt) "bcachefs: %s() " fmt "\n", __func__

#include <linux/backing-dev-defs.h>
#include <linux/bug.h>
#include <linux/bio.h>
#include <linux/closure.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/math64.h>
#include <linux/mutex.h>
#include <linux/percpu-refcount.h>
#include <linux/percpu-rwsem.h>
#include <linux/rhashtable.h>
#include <linux/rwsem.h>
#include <linux/seqlock.h>
#include <linux/shrinker.h>
#include <linux/srcu.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/zstd.h>

#include "bcachefs_format.h"
#include "fifo.h"
#include "opts.h"
#include "util.h"

#define dynamic_fault(...)		0
#define race_fault(...)			0

#define bch2_fs_init_fault(name)					\
	dynamic_fault("bcachefs:bch_fs_init:" name)
#define bch2_meta_read_fault(name)					\
	 dynamic_fault("bcachefs:meta:read:" name)
#define bch2_meta_write_fault(name)					\
	 dynamic_fault("bcachefs:meta:write:" name)

#ifdef __KERNEL__
#define bch2_fmt(_c, fmt)	"bcachefs (%s): " fmt "\n", ((_c)->name)
#else
#define bch2_fmt(_c, fmt)	fmt "\n"
#endif

#define bch_info(c, fmt, ...) \
	printk(KERN_INFO bch2_fmt(c, fmt), ##__VA_ARGS__)
#define bch_notice(c, fmt, ...) \
	printk(KERN_NOTICE bch2_fmt(c, fmt), ##__VA_ARGS__)
#define bch_warn(c, fmt, ...) \
	printk(KERN_WARNING bch2_fmt(c, fmt), ##__VA_ARGS__)
#define bch_warn_ratelimited(c, fmt, ...) \
	printk_ratelimited(KERN_WARNING bch2_fmt(c, fmt), ##__VA_ARGS__)
#define bch_err(c, fmt, ...) \
	printk(KERN_ERR bch2_fmt(c, fmt), ##__VA_ARGS__)
#define bch_err_ratelimited(c, fmt, ...) \
	printk_ratelimited(KERN_ERR bch2_fmt(c, fmt), ##__VA_ARGS__)

#define bch_verbose(c, fmt, ...)					\
do {									\
	if ((c)->opts.verbose)						\
		bch_info(c, fmt, ##__VA_ARGS__);			\
} while (0)

#define pr_verbose_init(opts, fmt, ...)					\
do {									\
	if (opt_get(opts, verbose))					\
		pr_info(fmt, ##__VA_ARGS__);				\
} while (0)

/* Parameters that are useful for debugging, but should always be compiled in: */
#define BCH_DEBUG_PARAMS_ALWAYS()					\
	BCH_DEBUG_PARAM(key_merging_disabled,				\
		"Disables merging of extents")				\
	BCH_DEBUG_PARAM(btree_gc_always_rewrite,			\
		"Causes mark and sweep to compact and rewrite every "	\
		"btree node it traverses")				\
	BCH_DEBUG_PARAM(btree_gc_rewrite_disabled,			\
		"Disables rewriting of btree nodes during mark and sweep")\
	BCH_DEBUG_PARAM(btree_shrinker_disabled,			\
		"Disables the shrinker callback for the btree node cache")

/* Parameters that should only be compiled in in debug mode: */
#define BCH_DEBUG_PARAMS_DEBUG()					\
	BCH_DEBUG_PARAM(expensive_debug_checks,				\
		"Enables various runtime debugging checks that "	\
		"significantly affect performance")			\
	BCH_DEBUG_PARAM(debug_check_iterators,				\
		"Enables extra verification for btree iterators")	\
	BCH_DEBUG_PARAM(debug_check_bkeys,				\
		"Run bkey_debugcheck (primarily checking GC/allocation "\
		"information) when iterating over keys")		\
	BCH_DEBUG_PARAM(debug_check_btree_accounting,			\
		"Verify btree accounting for keys within a node")	\
	BCH_DEBUG_PARAM(verify_btree_ondisk,				\
		"Reread btree nodes at various points to verify the "	\
		"mergesort in the read path against modifications "	\
		"done in memory")					\
	BCH_DEBUG_PARAM(journal_seq_verify,				\
		"Store the journal sequence number in the version "	\
		"number of every btree key, and verify that btree "	\
		"update ordering is preserved during recovery")		\
	BCH_DEBUG_PARAM(inject_invalid_keys,				\
		"Store the journal sequence number in the version "	\
		"number of every btree key, and verify that btree "	\
		"update ordering is preserved during recovery")		\
	BCH_DEBUG_PARAM(test_alloc_startup,				\
		"Force allocator startup to use the slowpath where it"	\
		"can't find enough free buckets without invalidating"	\
		"cached data")						\
	BCH_DEBUG_PARAM(force_reconstruct_read,				\
		"Force reads to use the reconstruct path, when reading"	\
		"from erasure coded extents")				\
	BCH_DEBUG_PARAM(test_restart_gc,				\
		"Test restarting mark and sweep gc when bucket gens change")

#define BCH_DEBUG_PARAMS_ALL() BCH_DEBUG_PARAMS_ALWAYS() BCH_DEBUG_PARAMS_DEBUG()

#ifdef CONFIG_BCACHEFS_DEBUG
#define BCH_DEBUG_PARAMS() BCH_DEBUG_PARAMS_ALL()
#else
#define BCH_DEBUG_PARAMS() BCH_DEBUG_PARAMS_ALWAYS()
#endif

#define BCH_DEBUG_PARAM(name, description) extern bool bch2_##name;
BCH_DEBUG_PARAMS()
#undef BCH_DEBUG_PARAM

#ifndef CONFIG_BCACHEFS_DEBUG
#define BCH_DEBUG_PARAM(name, description) static const bool bch2_##name;
BCH_DEBUG_PARAMS_DEBUG()
#undef BCH_DEBUG_PARAM
#endif

#define BCH_TIME_STATS()			\
	x(btree_node_mem_alloc)			\
	x(btree_node_split)			\
	x(btree_node_sort)			\
	x(btree_node_read)			\
	x(btree_gc)				\
	x(btree_lock_contended_read)		\
	x(btree_lock_contended_intent)		\
	x(btree_lock_contended_write)		\
	x(data_write)				\
	x(data_read)				\
	x(data_promote)				\
	x(journal_write)			\
	x(journal_delay)			\
	x(journal_flush_seq)			\
	x(blocked_journal)			\
	x(blocked_allocate)			\
	x(blocked_allocate_open_bucket)

enum bch_time_stats {
#define x(name) BCH_TIME_##name,
	BCH_TIME_STATS()
#undef x
	BCH_TIME_STAT_NR
};

#include "alloc_types.h"
#include "btree_types.h"
#include "buckets_types.h"
#include "clock_types.h"
#include "ec_types.h"
#include "journal_types.h"
#include "keylist_types.h"
#include "quota_types.h"
#include "rebalance_types.h"
#include "replicas_types.h"
#include "super_types.h"

/* Number of nodes btree coalesce will try to coalesce at once */
#define GC_MERGE_NODES		4U

/* Maximum number of nodes we might need to allocate atomically: */
#define BTREE_RESERVE_MAX	(BTREE_MAX_DEPTH + (BTREE_MAX_DEPTH - 1))

/* Size of the freelist we allocate btree nodes from: */
#define BTREE_NODE_RESERVE	(BTREE_RESERVE_MAX * 4)

#define BTREE_NODE_OPEN_BUCKET_RESERVE	(BTREE_RESERVE_MAX * BCH_REPLICAS_MAX)

struct btree;

enum gc_phase {
	GC_PHASE_NOT_RUNNING,
	GC_PHASE_START,
	GC_PHASE_SB,

	GC_PHASE_BTREE_EC,
	GC_PHASE_BTREE_EXTENTS,
	GC_PHASE_BTREE_INODES,
	GC_PHASE_BTREE_DIRENTS,
	GC_PHASE_BTREE_XATTRS,
	GC_PHASE_BTREE_ALLOC,
	GC_PHASE_BTREE_QUOTAS,
	GC_PHASE_BTREE_REFLINK,

	GC_PHASE_PENDING_DELETE,
	GC_PHASE_ALLOC,
};

struct gc_pos {
	enum gc_phase		phase;
	struct bpos		pos;
	unsigned		level;
};

struct io_count {
	u64			sectors[2][BCH_DATA_NR];
};

struct bch_dev {
	struct kobject		kobj;
	struct percpu_ref	ref;
	struct completion	ref_completion;
	struct percpu_ref	io_ref;
	struct completion	io_ref_completion;

	struct bch_fs		*fs;

	u8			dev_idx;
	/*
	 * Cached version of this device's member info from superblock
	 * Committed by bch2_write_super() -> bch_fs_mi_update()
	 */
	struct bch_member_cpu	mi;
	uuid_le			uuid;
	char			name[BDEVNAME_SIZE];

	struct bch_sb_handle	disk_sb;
	struct bch_sb		*sb_read_scratch;
	int			sb_write_error;

	struct bch_devs_mask	self;

	/* biosets used in cloned bios for writing multiple replicas */
	struct bio_set		replica_set;

	/*
	 * Buckets:
	 * Per-bucket arrays are protected by c->mark_lock, bucket_lock and
	 * gc_lock, for device resize - holding any is sufficient for access:
	 * Or rcu_read_lock(), but only for ptr_stale():
	 */
	struct bucket_array __rcu *buckets[2];
	unsigned long		*buckets_nouse;
	struct rw_semaphore	bucket_lock;

	struct bch_dev_usage __percpu *usage[2];

	/* Allocator: */
	struct task_struct __rcu *alloc_thread;

	/*
	 * free: Buckets that are ready to be used
	 *
	 * free_inc: Incoming buckets - these are buckets that currently have
	 * cached data in them, and we can't reuse them until after we write
	 * their new gen to disk. After prio_write() finishes writing the new
	 * gens/prios, they'll be moved to the free list (and possibly discarded
	 * in the process)
	 */
	alloc_fifo		free[RESERVE_NR];
	alloc_fifo		free_inc;

	open_bucket_idx_t	open_buckets_partial[OPEN_BUCKETS_COUNT];
	open_bucket_idx_t	open_buckets_partial_nr;

	size_t			fifo_last_bucket;

	/* last calculated minimum prio */
	u16			max_last_bucket_io[2];

	size_t			inc_gen_needs_gc;
	size_t			inc_gen_really_needs_gc;

	/*
	 * XXX: this should be an enum for allocator state, so as to include
	 * error state
	 */
	enum {
		ALLOCATOR_STOPPED,
		ALLOCATOR_RUNNING,
		ALLOCATOR_BLOCKED,
		ALLOCATOR_BLOCKED_FULL,
	}			allocator_state;

	alloc_heap		alloc_heap;

	atomic64_t		rebalance_work;

	struct journal_device	journal;

	struct work_struct	io_error_work;

	/* The rest of this all shows up in sysfs */
	atomic64_t		cur_latency[2];
	struct bch2_time_stats	io_latency[2];

#define CONGESTED_MAX		1024
	atomic_t		congested;
	u64			congested_last;

	struct io_count __percpu *io_done;
};

enum {
	/* startup: */
	BCH_FS_ALLOC_READ_DONE,
	BCH_FS_ALLOC_CLEAN,
	BCH_FS_ALLOCATOR_RUNNING,
	BCH_FS_ALLOCATOR_STOPPING,
	BCH_FS_INITIAL_GC_DONE,
	BCH_FS_BTREE_INTERIOR_REPLAY_DONE,
	BCH_FS_FSCK_DONE,
	BCH_FS_STARTED,
	BCH_FS_RW,

	/* shutdown: */
	BCH_FS_STOPPING,
	BCH_FS_EMERGENCY_RO,
	BCH_FS_WRITE_DISABLE_COMPLETE,

	/* errors: */
	BCH_FS_ERROR,
	BCH_FS_ERRORS_FIXED,

	/* misc: */
	BCH_FS_FIXED_GENS,
	BCH_FS_ALLOC_WRITTEN,
	BCH_FS_REBUILD_REPLICAS,
	BCH_FS_HOLD_BTREE_WRITES,
};

struct btree_debug {
	unsigned		id;
	struct dentry		*btree;
	struct dentry		*btree_format;
	struct dentry		*failed;
};

struct bch_fs_pcpu {
	u64			sectors_available;
};

struct journal_seq_blacklist_table {
	size_t			nr;
	struct journal_seq_blacklist_table_entry {
		u64		start;
		u64		end;
		bool		dirty;
	}			entries[0];
};

struct journal_keys {
	struct journal_key {
		enum btree_id	btree_id:8;
		unsigned	level:8;
		struct bkey_i	*k;
		u32		journal_seq;
		u32		journal_offset;
	}			*d;
	size_t			nr;
	u64			journal_seq_base;
};

struct btree_iter_buf {
	struct btree_iter	*iter;
};

struct bch_fs {
	struct closure		cl;

	struct list_head	list;
	struct kobject		kobj;
	struct kobject		internal;
	struct kobject		opts_dir;
	struct kobject		time_stats;
	unsigned long		flags;

	int			minor;
	struct device		*chardev;
	struct super_block	*vfs_sb;
	char			name[40];

	/* ro/rw, add/remove/resize devices: */
	struct rw_semaphore	state_lock;

	/* Counts outstanding writes, for clean transition to read-only */
	struct percpu_ref	writes;
	struct work_struct	read_only_work;

	struct bch_dev __rcu	*devs[BCH_SB_MEMBERS_MAX];

	struct bch_replicas_cpu replicas;
	struct bch_replicas_cpu replicas_gc;
	struct mutex		replicas_gc_lock;

	struct journal_entry_res replicas_journal_res;

	struct bch_disk_groups_cpu __rcu *disk_groups;

	struct bch_opts		opts;

	/* Updated by bch2_sb_update():*/
	struct {
		uuid_le		uuid;
		uuid_le		user_uuid;

		u16		version;
		u16		encoded_extent_max;

		u8		nr_devices;
		u8		clean;

		u8		encryption_type;

		u64		time_base_lo;
		u32		time_base_hi;
		u32		time_precision;
		u64		features;
		u64		compat;
	}			sb;

	struct bch_sb_handle	disk_sb;

	unsigned short		block_bits;	/* ilog2(block_size) */

	u16			btree_foreground_merge_threshold;

	struct closure		sb_write;
	struct mutex		sb_lock;

	/* BTREE CACHE */
	struct bio_set		btree_bio;

	struct btree_root	btree_roots[BTREE_ID_NR];
	struct mutex		btree_root_lock;

	struct btree_cache	btree_cache;

	/*
	 * Cache of allocated btree nodes - if we allocate a btree node and
	 * don't use it, if we free it that space can't be reused until going
	 * _all_ the way through the allocator (which exposes us to a livelock
	 * when allocating btree reserves fail halfway through) - instead, we
	 * can stick them here:
	 */
	struct btree_alloc	btree_reserve_cache[BTREE_NODE_RESERVE * 2];
	unsigned		btree_reserve_cache_nr;
	struct mutex		btree_reserve_cache_lock;

	mempool_t		btree_interior_update_pool;
	struct list_head	btree_interior_update_list;
	struct list_head	btree_interior_updates_unwritten;
	struct mutex		btree_interior_update_lock;
	struct closure_waitlist	btree_interior_update_wait;

	struct workqueue_struct	*btree_interior_update_worker;
	struct work_struct	btree_interior_update_work;

	/* btree_iter.c: */
	struct mutex		btree_trans_lock;
	struct list_head	btree_trans_list;
	mempool_t		btree_iters_pool;
	struct btree_iter_buf  __percpu	*btree_iters_bufs;

	struct srcu_struct	btree_trans_barrier;

	struct btree_key_cache	btree_key_cache;

	struct workqueue_struct	*wq;
	/* copygc needs its own workqueue for index updates.. */
	struct workqueue_struct	*copygc_wq;

	/* ALLOCATION */
	struct delayed_work	pd_controllers_update;
	unsigned		pd_controllers_update_seconds;

	struct bch_devs_mask	rw_devs[BCH_DATA_NR];

	u64			capacity; /* sectors */

	/*
	 * When capacity _decreases_ (due to a disk being removed), we
	 * increment capacity_gen - this invalidates outstanding reservations
	 * and forces them to be revalidated
	 */
	u32			capacity_gen;
	unsigned		bucket_size_max;

	atomic64_t		sectors_available;
	struct mutex		sectors_available_lock;

	struct bch_fs_pcpu __percpu	*pcpu;

	struct percpu_rw_semaphore	mark_lock;

	seqcount_t			usage_lock;
	struct bch_fs_usage		*usage_base;
	struct bch_fs_usage __percpu	*usage[JOURNAL_BUF_NR];
	struct bch_fs_usage __percpu	*usage_gc;
	u64 __percpu		*online_reserved;

	/* single element mempool: */
	struct mutex		usage_scratch_lock;
	struct bch_fs_usage_online *usage_scratch;

	/*
	 * When we invalidate buckets, we use both the priority and the amount
	 * of good data to determine which buckets to reuse first - to weight
	 * those together consistently we keep track of the smallest nonzero
	 * priority of any bucket.
	 */
	struct bucket_clock	bucket_clock[2];

	struct io_clock		io_clock[2];

	/* JOURNAL SEQ BLACKLIST */
	struct journal_seq_blacklist_table *
				journal_seq_blacklist_table;
	struct work_struct	journal_seq_blacklist_gc_work;

	/* ALLOCATOR */
	spinlock_t		freelist_lock;
	struct closure_waitlist	freelist_wait;
	u64			blocked_allocate;
	u64			blocked_allocate_open_bucket;
	open_bucket_idx_t	open_buckets_freelist;
	open_bucket_idx_t	open_buckets_nr_free;
	struct closure_waitlist	open_buckets_wait;
	struct open_bucket	open_buckets[OPEN_BUCKETS_COUNT];

	struct write_point	btree_write_point;
	struct write_point	rebalance_write_point;

	struct write_point	write_points[WRITE_POINT_MAX];
	struct hlist_head	write_points_hash[WRITE_POINT_HASH_NR];
	struct mutex		write_points_hash_lock;
	unsigned		write_points_nr;

	/* GARBAGE COLLECTION */
	struct task_struct	*gc_thread;
	atomic_t		kick_gc;
	unsigned long		gc_count;

	/*
	 * Tracks GC's progress - everything in the range [ZERO_KEY..gc_cur_pos]
	 * has been marked by GC.
	 *
	 * gc_cur_phase is a superset of btree_ids (BTREE_ID_EXTENTS etc.)
	 *
	 * Protected by gc_pos_lock. Only written to by GC thread, so GC thread
	 * can read without a lock.
	 */
	seqcount_t		gc_pos_lock;
	struct gc_pos		gc_pos;

	/*
	 * The allocation code needs gc_mark in struct bucket to be correct, but
	 * it's not while a gc is in progress.
	 */
	struct rw_semaphore	gc_lock;

	/* IO PATH */
	struct bio_set		bio_read;
	struct bio_set		bio_read_split;
	struct bio_set		bio_write;
	struct mutex		bio_bounce_pages_lock;
mempool_t		bio_bounce_pages;
	struct rhashtable	promote_table;

	mempool_t		compression_bounce[2];
	mempool_t		compress_workspace[BCH_COMPRESSION_TYPE_NR];
	mempool_t		decompress_workspace;
	ZSTD_parameters		zstd_params;

	struct crypto_shash	*sha256;
	struct crypto_sync_skcipher *chacha20;
	struct crypto_shash	*poly1305;

	atomic64_t		key_version;

	mempool_t		large_bkey_pool;

	/* REBALANCE */
	struct bch_fs_rebalance	rebalance;

	/* COPYGC */
	struct task_struct	*copygc_thread;
	copygc_heap		copygc_heap;
	struct bch_pd_controller copygc_pd;
	struct write_point	copygc_write_point;
	u64			copygc_threshold;

	/* STRIPES: */
	GENRADIX(struct stripe) stripes[2];

	ec_stripes_heap		ec_stripes_heap;
	spinlock_t		ec_stripes_heap_lock;

	/* ERASURE CODING */
	struct list_head	ec_stripe_head_list;
	struct mutex		ec_stripe_head_lock;

	struct list_head	ec_stripe_new_list;
	struct mutex		ec_stripe_new_lock;

	struct work_struct	ec_stripe_create_work;
	u64			ec_stripe_hint;

	struct bio_set		ec_bioset;

	struct work_struct	ec_stripe_delete_work;
	struct llist_head	ec_stripe_delete_list;

	/* REFLINK */
	u64			reflink_hint;

	/* VFS IO PATH - fs-io.c */
	struct bio_set		writepage_bioset;
	struct bio_set		dio_write_bioset;
	struct bio_set		dio_read_bioset;

	struct bio_list		btree_write_error_list;
	struct work_struct	btree_write_error_work;
	spinlock_t		btree_write_error_lock;

	/* ERRORS */
	struct list_head	fsck_errors;
	struct mutex		fsck_error_lock;
	bool			fsck_alloc_err;

	/* QUOTAS */
	struct bch_memquota_type quotas[QTYP_NR];

	/* DEBUG JUNK */
	struct dentry		*debug;
	struct btree_debug	btree_debug[BTREE_ID_NR];
#ifdef CONFIG_BCACHEFS_DEBUG
	struct btree		*verify_data;
	struct btree_node	*verify_ondisk;
	struct mutex		verify_lock;
#endif

	u64			*unused_inode_hints;
	unsigned		inode_shard_bits;

	/*
	 * A btree node on disk could have too many bsets for an iterator to fit
	 * on the stack - have to dynamically allocate them
	 */
	mempool_t		fill_iter;

	mempool_t		btree_bounce_pool;

	struct journal		journal;
	struct list_head	journal_entries;
	struct journal_keys	journal_keys;

	u64			last_bucket_seq_cleanup;

	/* The rest of this all shows up in sysfs */
	atomic_long_t		read_realloc_races;
	atomic_long_t		extent_migrate_done;
	atomic_long_t		extent_migrate_raced;

	unsigned		btree_gc_periodic:1;
	unsigned		copy_gc_enabled:1;
	bool			promote_whole_extents;

	struct bch2_time_stats	times[BCH_TIME_STAT_NR];
};

static inline void bch2_set_ra_pages(struct bch_fs *c, unsigned ra_pages)
{
#ifndef NO_BCACHEFS_FS
	if (c->vfs_sb)
		c->vfs_sb->s_bdi->ra_pages = ra_pages;
#endif
}

static inline unsigned bucket_bytes(const struct bch_dev *ca)
{
	return ca->mi.bucket_size << 9;
}

static inline unsigned block_bytes(const struct bch_fs *c)
{
	return c->opts.block_size << 9;
}

static inline struct timespec64 bch2_time_to_timespec(struct bch_fs *c, u64 time)
{
	return ns_to_timespec64(time * c->sb.time_precision + c->sb.time_base_lo);
}

static inline s64 timespec_to_bch2_time(struct bch_fs *c, struct timespec64 ts)
{
	s64 ns = timespec64_to_ns(&ts) - c->sb.time_base_lo;

	if (c->sb.time_precision == 1)
		return ns;

	return div_s64(ns, c->sb.time_precision);
}

static inline s64 bch2_current_time(struct bch_fs *c)
{
	struct timespec64 now;

	ktime_get_coarse_real_ts64(&now);
	return timespec_to_bch2_time(c, now);
}

static inline bool bch2_dev_exists2(const struct bch_fs *c, unsigned dev)
{
	return dev < c->sb.nr_devices && c->devs[dev];
}

#endif /* _BCACHEFS_H */
