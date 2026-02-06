/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_H
#define _BCACHEFS_H

/*
 * bcachefs: a COW filesystem built around a b-tree with snapshot support,
 * multiple devices, checksumming, compression, and encryption.
 *
 * This header defines the core runtime types (struct bch_fs, struct bch_dev)
 * and pulls in subsystem type headers.
 */

#undef pr_fmt
#ifdef __KERNEL__
#define pr_fmt(fmt) "bcachefs: %s() " fmt "\n", __func__
#else
#define pr_fmt(fmt) "%s() " fmt "\n", __func__
#endif

#ifdef CONFIG_BCACHEFS_DEBUG
#define ENUMERATED_REF_DEBUG
#endif

#ifdef __KERNEL__
#ifdef CONFIG_DEBUG_FS
#define CONFIG_BCACHEFS_ASYNC_OBJECT_LISTS
#endif
#endif

#ifndef dynamic_fault
#define dynamic_fault(...)		0
#endif

#define race_fault(...)			dynamic_fault("bcachefs:race")

#include <linux/backing-dev-defs.h>
#include <linux/bug.h>
#include <linux/bio.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/math64.h>
#include <linux/mutex.h>
#include <linux/percpu-refcount.h>
#include <linux/percpu-rwsem.h>
#include <linux/refcount.h>
#include <linux/rhashtable.h>
#include <linux/rwsem.h>
#include <linux/semaphore.h>
#include <linux/seqlock.h>
#include <linux/shrinker.h>
#include <linux/srcu.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/zstd.h>
#include <linux/unicode.h>

#include "bcachefs_format.h"
#include "errcode.h"
#include "opts.h"

#include "closure.h"

#include "util/clock_types.h"
#include "util/enumerated_ref_types.h"
#include "util/fast_list.h"
#include "util/fifo.h"
#include "util/seqmutex.h"
#include "util/time_stats.h"
#include "util/thread_with_file_types.h"
#include "util/util.h"

#include "alloc/accounting_types.h"
#include "alloc/buckets_types.h"
#include "alloc/disk_groups_types.h"
#include "alloc/replicas_types.h"
#include "alloc/types.h"

#include "btree/check_types.h"
#include "btree/journal_overlay_types.h"
#include "btree/types.h"

#include "data/compress_types.h"
#include "data/copygc_types.h"
#include "data/ec/types.h"
#include "data/keylist_types.h"
#include "data/nocow_locking_types.h"
#include "data/reconcile/types.h"

#include "debug/async_objs_types.h"
#include "debug/trace.h"

#include "fs/quota_types.h"

#include "init/error_types.h"
#include "init/passes_types.h"
#include "init/dev_types.h"

#include "journal/types.h"

#include "sb/counters_types.h"
#include "sb/io_types.h"
#include "sb/members_types.h"

#include "snapshots/types.h"

#include "vfs/types.h"

#define bch2_fs_init_fault(name)					\
	dynamic_fault("bcachefs:bch_fs_init:" name)
#define bch2_meta_read_fault(name)					\
	 dynamic_fault("bcachefs:meta:read:" name)
#define bch2_meta_write_fault(name)					\
	 dynamic_fault("bcachefs:meta:write:" name)

#ifdef __KERNEL__
#define BCACHEFS_LOG_PREFIX
#endif

#ifdef BCACHEFS_LOG_PREFIX

#define bch2_log_msg(_c, fmt)			"bcachefs (%s): " fmt, bch2_fs_name(_c)
#define bch2_fmt_dev(_ca, fmt)			"bcachefs (%s): " fmt "\n", bch2_dev_name(_ca)
#define bch2_fmt_dev_offset(_ca, _offset, fmt)	"bcachefs (%s sector %llu): " fmt "\n", ((_ca)->name), (_offset)
#define bch2_fmt_inum(_c, _inum, fmt)		"bcachefs (%s inum %llu): " fmt "\n", ((_c)->name), (_inum)
#define bch2_fmt_inum_offset(_c, _inum, _offset, fmt)			\
	 "bcachefs (%s inum %llu offset %llu): " fmt "\n", ((_c)->name), (_inum), (_offset)

#else

#define bch2_log_msg(_c, fmt)			fmt
#define bch2_fmt_dev(_ca, fmt)			"%s: " fmt "\n", ((_ca)->name)
#define bch2_fmt_dev_offset(_ca, _offset, fmt)	"%s sector %llu: " fmt "\n", ((_ca)->name), (_offset)
#define bch2_fmt_inum(_c, _inum, fmt)		"inum %llu: " fmt "\n", (_inum)
#define bch2_fmt_inum_offset(_c, _inum, _offset, fmt)				\
	 "inum %llu offset %llu: " fmt "\n", (_inum), (_offset)

#endif

#define bch2_fmt(_c, fmt)		bch2_log_msg(_c, fmt "\n")

void bch2_print_str_loglevel(struct bch_fs *, int, const char *);
void bch2_print_str(struct bch_fs *, const char *, const char *);

__printf(2, 3)
void bch2_print_opts(struct bch_opts *, const char *, ...);

__printf(2, 3)
void __bch2_print(struct bch_fs *c, const char *fmt, ...);

#define maybe_dev_to_fs(_c)	_Generic((_c),				\
	struct bch_dev *:	((struct bch_dev *) (_c))->fs,		\
	struct bch_fs *:	(_c))

#define bch2_print(_c, ...) __bch2_print(maybe_dev_to_fs(_c), __VA_ARGS__)

#define __bch2_ratelimit(_c, _rs)					\
	((_c)->opts.ratelimit_errors && !__ratelimit(_rs))

#define bch2_ratelimit(_c)						\
({									\
	static DEFINE_RATELIMIT_STATE(rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
									\
	__bch2_ratelimit(_c, &rs);					\
})

#define bch2_print_ratelimited(_c, ...)					\
do {									\
	if (!bch2_ratelimit(_c))					\
		bch2_print(_c, __VA_ARGS__);				\
} while (0)

#define bch_log(c, loglevel, fmt, ...) \
	bch2_print(c, loglevel bch2_fmt(c, fmt), ##__VA_ARGS__)
#define bch_log_ratelimited(c, loglevel, fmt, ...) \
	bch2_print_ratelimited(c, loglevel bch2_fmt(c, fmt), ##__VA_ARGS__)

#define bch_err(c, ...)			bch_log(c, KERN_ERR, __VA_ARGS__)
#define bch_err_ratelimited(c, ...)	bch_log_ratelimited(c, KERN_ERR, __VA_ARGS__)
#define bch_warn(c, ...)		bch_log(c, KERN_WARNING, __VA_ARGS__)
#define bch_warn_ratelimited(c, ...)	bch_log_ratelimited(c, KERN_WARNING, __VA_ARGS__)
#define bch_notice(c, ...)		bch_log(c, KERN_NOTICE, __VA_ARGS__)
#define bch_info(c, ...)		bch_log(c, KERN_INFO, __VA_ARGS__)
#define bch_info_ratelimited(c, ...)	bch_log_ratelimited(c, KERN_INFO, __VA_ARGS__)
#define bch_verbose(c, ...)		bch_log(c, KERN_DEBUG, __VA_ARGS__)
#define bch_verbose_ratelimited(c, ...)	bch_log_ratelimited(c, KERN_DEBUG, __VA_ARGS__)

#define bch_dev_log(ca, loglevel, fmt, ...) \
	bch2_print(ca->fs, loglevel bch2_fmt_dev(ca, fmt), ##__VA_ARGS__)

#define bch_err_dev(ca, ...)		bch_dev_log(ca, KERN_ERR, __VA_ARGS__)
#define bch_notice_dev(ca, ...)		bch_dev_log(ca, KERN_NOTICE, __VA_ARGS__)
#define bch_info_dev(ca, ...)		bch_dev_log(ca, KERN_INFO, __VA_ARGS__)
#define bch_verbose_dev(ca, ...)	bch_dev_log(ca, KERN_DEBUG, __VA_ARGS__)

#define bch_err_dev_ratelimited(ca, ...)				\
do {									\
	if (!bch2_ratelimit(ca->fs))					\
		bch_err_dev(ca, __VA_ARGS__);				\
} while (0)

static inline bool should_print_err(int err)
{
	return err && !bch2_err_matches(err, BCH_ERR_transaction_restart);
}

#define bch_err_fn(_c, _ret)						\
do {									\
	if (should_print_err(_ret))					\
		bch_err(_c, "%s(): error %s", __func__, bch2_err_str(_ret));\
} while (0)

#define bch_err_fn_ratelimited(_c, _ret)				\
do {									\
	if (should_print_err(_ret))					\
		bch_err_ratelimited(_c, "%s(): error %s", __func__, bch2_err_str(_ret));\
} while (0)

#define bch_err_msg(_c, _ret, _msg, ...)				\
do {									\
	if (should_print_err(_ret))					\
		bch_err(_c, "%s(): error " _msg " %s", __func__,	\
			##__VA_ARGS__, bch2_err_str(_ret));		\
} while (0)

#define bch_err_fn_dev(_ca, _ret)					\
do {									\
	if (should_print_err(_ret))					\
		bch_err_dev(_ca, "%s(): error %s", __func__, bch2_err_str(_ret));\
} while (0)

#define bch_err_msg_dev(_ca, _ret, _msg, ...)				\
do {									\
	if (should_print_err(_ret))					\
		bch_err_dev(_ca, "%s(): error " _msg " %s", __func__,	\
			##__VA_ARGS__, bch2_err_str(_ret));		\
} while (0)

/* Parameters that are useful for debugging, but should always be compiled in: */
#define BCH_DEBUG_PARAMS_ALWAYS()					\
	BCH_DEBUG_PARAM(key_merging_disabled,				\
		"Disables merging of extents")				\
	BCH_DEBUG_PARAM(btree_node_merging_disabled,			\
		"Disables merging of btree nodes")			\
	BCH_DEBUG_PARAM(btree_gc_always_rewrite,			\
		"Causes mark and sweep to compact and rewrite every "	\
		"btree node it traverses")				\
	BCH_DEBUG_PARAM(btree_gc_rewrite_disabled,			\
		"Disables rewriting of btree nodes during mark and sweep")\
	BCH_DEBUG_PARAM(btree_shrinker_disabled,			\
		"Disables the shrinker callback for the btree node cache")\
	BCH_DEBUG_PARAM(verify_btree_ondisk,				\
		"Reread btree nodes at various points to verify the "	\
		"mergesort in the read path against modifications "	\
		"done in memory")					\
	BCH_DEBUG_PARAM(backpointers_no_use_write_buffer,		\
		"Don't use the write buffer for backpointers, enabling "\
		"extra runtime checks")					\
	BCH_DEBUG_PARAM(debug_check_btree_locking,			\
		"Enable additional asserts for btree locking")		\
	BCH_DEBUG_PARAM(debug_check_iterators,				\
		"Enables extra verification for btree iterators")	\
	BCH_DEBUG_PARAM(debug_check_bset_lookups,			\
		"Enables extra verification for bset lookups")		\
	BCH_DEBUG_PARAM(debug_check_btree_accounting,			\
		"Verify btree accounting for keys within a node")	\
	BCH_DEBUG_PARAM(debug_check_bkey_unpack,			\
		"Enables extra verification for bkey unpack")

/* Parameters that should only be compiled in debug mode: */
#define BCH_DEBUG_PARAMS_DEBUG()					\
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

#define BCH_DEBUG_PARAM(name, description) extern struct static_key_false bch2_##name;
BCH_DEBUG_PARAMS_ALL()
#undef BCH_DEBUG_PARAM

#define BCH_TIME_STATS()						\
	x(btree_node_mem_alloc,						\
	  "Allocate memory in the btree node cache "			\
	  "for a new btree node")					\
	x(btree_node_split,						\
	  "Split a full btree node into two new nodes")			\
	x(btree_node_compact,						\
	  "Compact a full btree node on disk")				\
	x(btree_node_merge,						\
	  "Merge two adjacent btree nodes")				\
	x(btree_node_sort,						\
	  "Sort and resort entire btree nodes in memory, "		\
	  "after reading from disk or for compacting")			\
	x(btree_node_read,						\
	  "Read btree nodes from disk")					\
	x(btree_node_read_done,						\
	  "Post-read btree node processing")				\
	x(btree_node_write,						\
	  "Write btree node to disk")					\
	x(btree_interior_update_foreground,				\
	  "Foreground time for topology-changing btree updates "	\
	  "(splits, compactions, merges); roughly corresponds "		\
	  "to lock held time")						\
	x(btree_interior_update_total,					\
	  "Total time for topology-changing btree updates, "		\
	  "including background transaction phase after "		\
	  "new nodes are written")					\
	x(btree_write_buffer_flush,					\
	  "Flush btree write buffer to btree")				\
	x(btree_gc,							\
	  "GC pass recalculating oldest generation numbers")		\
	x(data_write,							\
	  "Core write path: allocate space, compress, "			\
	  "encrypt, checksum, issue writes, "				\
	  "update extents btree")					\
	x(data_read,							\
	  "Core read path: look up extents btree, "			\
	  "issue reads, checksum, decompress, decrypt")			\
	x(data_promote,							\
	  "Promote: write a cached copy of an extent "			\
	  "to promote_target on read")					\
	x(journal_flush_write,						\
	  "Flush journal writes: cache flush to devices "		\
	  "then FUA journal writes")					\
	x(journal_noflush_write,					\
	  "Non-flush journal writes, without cache "			\
	  "flushes or FUA")						\
	x(journal_flush_seq,						\
	  "Flush a journal sequence number to disk "			\
	  "for sync, fsync, and bucket reuse")				\
	x(journal_pin_flush_btree,					\
	  "Flush btree journal pins")					\
	x(journal_pin_flush_key_cache,					\
	  "Flush key cache journal pins")				\
	x(journal_pin_flush_other,					\
	  "Flush other journal pins")					\
	x(blocked_journal_low_on_space,					\
	  "Blocked: journal reclaim not keeping up "			\
	  "with reclaiming space")					\
	x(blocked_journal_low_on_pin,					\
	  "Blocked: journal pins (dirty btree nodes, "			\
	  "key cache entries) not flushed fast enough")			\
	x(blocked_journal_max_in_flight,				\
	  "Blocked: too many journal writes in flight")			\
	x(blocked_journal_max_open,					\
	  "Blocked: too many journal entries open, "			\
	  "not yet closed for writing")					\
	x(blocked_journal_write_buffer_flush,				\
	  "Blocked: waiting for write buffer flush")			\
	x(blocked_key_cache_flush,					\
	  "Blocked: waiting for key cache flush")			\
	x(blocked_allocate,						\
	  "Blocked: bucket allocation waiting, copygc or "		\
	  "allocator thread not keeping up")				\
	x(blocked_allocate_open_bucket,					\
	  "Blocked: all open bucket handles in use")			\
	x(blocked_write_buffer_full,					\
	  "Blocked: write buffer full")					\
	x(blocked_writeback_throttle,					\
	  "Blocked: writeback throttle")				\
	x(nocow_lock_contended,						\
	  "Nocow lock contention")

enum bch_time_stats {
#define x(name, ...) BCH_TIME_##name,
	BCH_TIME_STATS()
#undef x
	BCH_TIME_STAT_NR
};

/* Number of nodes btree coalesce will try to coalesce at once */
#define GC_MERGE_NODES		4U

#define BTREE_NODE_OPEN_BUCKET_RESERVE	(BTREE_RESERVE_MAX * BCH_REPLICAS_MAX)

struct btree;

struct io_count {
	u64			sectors[2][BCH_DATA_NR];
};

#define BCH_DEV_READ_REFS()				\
	x(bch2_online_devs)				\
	x(trans_mark_dev_sbs)				\
	x(read_fua_test)				\
	x(sb_field_resize)				\
	x(write_super)					\
	x(journal_read)					\
	x(fs_journal_alloc)				\
	x(fs_resize_on_mount)				\
	x(sb_journal_sort)				\
	x(btree_node_read)				\
	x(btree_node_read_all_replicas)			\
	x(btree_node_scrub)				\
	x(btree_node_write)				\
	x(btree_node_scan)				\
	x(btree_verify_replicas)			\
	x(btree_node_ondisk_to_text)			\
	x(io_read)					\
	x(check_extent_checksums)			\
	x(ec_block)

enum bch_dev_read_ref {
#define x(n) BCH_DEV_READ_REF_##n,
	BCH_DEV_READ_REFS()
#undef x
	BCH_DEV_READ_REF_NR,
};

#define BCH_DEV_WRITE_REFS()				\
	x(journal_write)				\
	x(journal_discard)				\
	x(dev_do_discards)				\
	x(discard_one_bucket_fast)			\
	x(do_invalidates)				\
	x(stripe_update_extents)			\
	x(nocow_flush)					\
	x(io_write)					\
	x(ec_block)					\
	x(ec_bucket_zero)

enum bch_dev_write_ref {
#define x(n) BCH_DEV_WRITE_REF_##n,
	BCH_DEV_WRITE_REFS()
#undef x
	BCH_DEV_WRITE_REF_NR,
};

struct bucket_bitmap {
	unsigned long		*buckets;
	u64			nr;
	struct mutex		lock;
};

struct bch_dev {
	struct kobject		kobj;
#ifdef CONFIG_BCACHEFS_DEBUG
	atomic_long_t		ref;
	bool			dying;
	unsigned long		last_put;
#else
	struct percpu_ref	ref;
#endif
	struct completion	ref_completion;
	struct enumerated_ref	io_ref[2];

	struct bch_fs		*fs;

	u8			dev_idx;
	/*
	 * Cached version of this device's member info from superblock
	 * Committed by bch2_write_super() -> bch_fs_mi_update()
	 */
	struct bch_member_cpu	mi;
	u64			btree_allocated_bitmap_gc;
	atomic64_t		errors[BCH_MEMBER_ERROR_NR];
	unsigned long		write_errors_start;

	__uuid_t		uuid;
	char			name[BDEVNAME_SIZE];

	struct bch_sb_handle	disk_sb;
	struct bch_sb		*sb_read_scratch;
	int			sb_write_error;
	dev_t			dev;
	atomic_t		flush_seq;

	struct bch_devs_mask	self;

	/*
	 * Buckets:
	 * Per-bucket arrays are protected by either rcu_read_lock or
	 * state_lock, for device resize.
	 */
	GENRADIX(struct bucket)	buckets_gc;
	struct bucket_gens __rcu *bucket_gens;
	u8			*oldest_gen;
	unsigned long		*buckets_nouse;

	struct bucket_bitmap	bucket_backpointer_mismatch;
	struct bucket_bitmap	bucket_backpointer_empty;

	struct bch_dev_usage_full __percpu
				*usage;

	/* Allocator: */
	u64			alloc_cursor[3];

	unsigned		nr_open_buckets;
	unsigned		nr_partial_buckets;
	unsigned		nr_btree_reserve;

	struct work_struct	invalidate_work;

	struct work_struct	discard_work;
	struct work_struct	discard_fast_work;
	struct mutex		discard_lock;
	darray_u64		discard_fast;
	FIFO(struct discard_fifo_entry) discard_fifo;
	bool			discard_buckets_degraded;

	atomic64_t		rebalance_work;

	struct journal_device	journal;
	u64			prev_journal_sector;

	struct work_struct	io_error_work;

	/* The rest of this all shows up in sysfs */
	atomic64_t		cur_latency[2];
	struct bch2_time_stats_quantiles io_latency[2];

#define CONGESTED_MAX		1024
	atomic_t		congested;
	u64			congested_last;

	struct io_count __percpu *io_done;
};

/*
 * initial_gc_unfixed
 * error
 * topology error
 */

#define BCH_FS_FLAGS()			\
	x(new_fs)			\
	x(started)			\
	x(clean_recovery)		\
	x(btree_running)		\
	x(accounting_replay_done)	\
	x(may_go_rw)			\
	x(may_upgrade_downgrade)	\
	x(rw)				\
	x(rw_init_done)			\
	x(was_rw)			\
	x(stopping)			\
	x(emergency_ro)			\
	x(going_ro)			\
	x(write_disable_complete)	\
	x(clean_shutdown)		\
	x(in_recovery)			\
	x(in_fsck)			\
	x(initial_gc_unfixed)		\
	x(need_delete_dead_snapshots)	\
	x(error)			\
	x(topology_error)		\
	x(errors_fixed)			\
	x(errors_fixed_silent)		\
	x(errors_not_fixed)		\
	x(no_invalid_checks)		\
	x(discard_mount_opt_set)	\
	x(sb_dirty)			\

enum bch_fs_flags {
#define x(n)		BCH_FS_##n,
	BCH_FS_FLAGS()
#undef x
};

struct btree_debug {
	unsigned		id;
};

#define BCH_LINK_MAX	U32_MAX

struct journal_seq_blacklist_table {
	size_t			nr;
	struct journal_seq_blacklist_table_entry {
		u64		start;
		u64		end;
		bool		dirty;
	}			entries[];
};

#define BCH_WRITE_REFS()						\
	x(journal)							\
	x(trans)							\
	x(write)							\
	x(promote)							\
	x(node_rewrite)							\
	x(stripe_create)						\
	x(stripe_delete)						\
	x(reflink)							\
	x(fallocate)							\
	x(fsync)							\
	x(dio_write)							\
	x(discard)							\
	x(discard_fast)							\
	x(check_discard_freespace_key)					\
	x(invalidate)							\
	x(delete_dead_snapshots)					\
	x(gc_gens)							\
	x(snapshot_delete_pagecache)					\
	x(sysfs)							\
	x(btree_write_buffer)						\
	x(btree_node_scrub)						\
	x(async_recovery_passes)					\
	x(ioctl_data)

enum bch_write_ref {
#define x(n) BCH_WRITE_REF_##n,
	BCH_WRITE_REFS()
#undef x
	BCH_WRITE_REF_NR,
};

#define BCH_FS_DEFAULT_UTF8_ENCODING UNICODE_AGE(12, 1, 0)

struct bch_fs {
	struct closure		cl;

	struct list_head	list;
	struct kobject		kobj;
	struct kobject		counters_kobj;
	struct kobject		internal;
	struct kobject		opts_dir;
	struct kobject		time_stats;
	struct kobject		time_stats_json;
	unsigned long		flags;

	int			minor;
	struct device		*chardev;
	struct super_block	*vfs_sb;
	dev_t			dev;
	char			name[40];

	struct stdio_redirect	*stdio;
	struct task_struct	*stdio_filter;
	unsigned		loglevel;
	unsigned		prev_loglevel;
	/*
	 * Certain operations are only allowed in single threaded mode, during
	 * recovery, and we want to assert that this is the case:
	 */
	struct task_struct	*recovery_task;

	/* ro/rw, add/remove/resize devices: */
	struct rw_semaphore	state_lock;

	/* Counts outstanding writes, for clean transition to read-only */
	struct enumerated_ref	writes;

	/*
	 * Analagous to c->writes, for asynchronous ops that don't necessarily
	 * need fs to be read-write
	 */
	refcount_t		ro_ref;
	wait_queue_head_t	ro_ref_wait;
	struct work_struct	read_only_work;

	struct bch_dev __rcu	*devs[BCH_SB_MEMBERS_MAX];
	struct bch_devs_mask	devs_online;
	struct bch_devs_mask	devs_removed;
	struct bch_devs_mask	devs_rotational;

	struct bch_opts		opts;
	struct mutex		opt_change_lock;
	u32			opt_change_cookie;
	struct bch_opts_mask	mount_opts;

	struct bch_sb_cpu	sb;
	struct bch_sb_handle	disk_sb;
	struct closure		sb_write;
	struct mutex		sb_lock;
	unsigned long		incompat_versions_requested[BITS_TO_LONGS(BCH_VERSION_MINOR(bcachefs_metadata_version_current))];
	struct unicode_map	*cf_encoding;

	unsigned short		block_bits;	/* ilog2(block_size) */

	struct delayed_work	maybe_schedule_btree_bitmap_gc;

	struct bch_fs_counters	counters;
	struct bch2_time_stats	times[BCH_TIME_STAT_NR];
	struct bch_fs_errors	errors;

#ifdef CONFIG_BCACHEFS_ASYNC_OBJECT_LISTS
	struct async_obj_list	async_objs[BCH_ASYNC_OBJ_NR];
#endif

	struct journal				journal;
	u64					journal_replay_seq_start;
	u64					journal_replay_seq_end;
	GENRADIX(struct journal_replay *)	journal_entries;
	u64					journal_entries_base_seq;
	struct journal_keys			journal_keys;
	struct list_head			journal_iters;
	struct journal_seq_blacklist_table	*journal_seq_blacklist_table;

	struct bch_fs_recovery			recovery;

	struct bch_fs_btree			btree;

	struct bch_fs_gc			gc;
	struct bch_fs_gc_gens			gc_gens;

	struct bch_accounting_mem		accounting;
	struct bch_replicas_cpu			replicas;
	struct bch_disk_groups_cpu __rcu	*disk_groups;
	struct bch_fs_capacity			capacity;
	struct bch_fs_allocator			allocator;

	struct bch_fs_snapshots			snapshots;

	spinlock_t				write_error_lock;
	/*
	 * Use a dedicated wq for write ref holder tasks. Required to avoid
	 * dependency problems with other wq tasks that can block on ref
	 * draining, such as read-only transition.
	 */
	struct workqueue_struct		*write_ref_wq;

	struct workqueue_struct		*promote_wq;
	struct semaphore __percpu	*promote_limit;

	struct io_clock			io_clock[2];
	struct journal_entry_res	clock_journal_res;

	/* IO PATH */
	struct workqueue_struct	*btree_update_wq;
	struct bio_set		bio_read;
	struct bio_set		bio_read_split;
	struct bio_set		bio_write;
	struct bio_set		replica_set;
	struct mutex		bio_bounce_pages_lock;
	mempool_t		bio_bounce_bufs;
	struct bucket_nocow_lock_table
				nocow_locks;
	struct rhltable		update_table;

	struct bch_key		chacha20_key;
	bool			chacha20_key_set;

	atomic64_t		key_version;

	/* MOVE.C */
	struct list_head	moving_context_list;
	struct mutex		moving_context_lock;

	struct bch_fs_compress	compress;
	struct bch_fs_reconcile	reconcile;
	struct bch_fs_copygc	copygc;
	struct bch_fs_ec	ec;

	/* REFLINK */
	reflink_gc_table	reflink_gc_table;
	size_t			reflink_gc_nr;

#ifndef NO_BCACHEFS_FS
	struct bch_fs_vfs	vfs;
#endif

	/* QUOTAS */
	struct bch_memquota_type quotas[QTYP_NR];

	/* DEBUG JUNK */
#ifdef CONFIG_DEBUG_FS
	struct dentry		*fs_debug_dir;
	struct dentry		*btree_debug_dir;
	struct dentry		*async_obj_dir;
	struct btree_debug	btree_debug[BTREE_ID_NR];
#endif
	struct btree		*verify_data;
	struct btree_node	*verify_ondisk;
	struct mutex		verify_lock;
};

/* Error tracking: */

static inline int __bch2_err_throw(struct bch_fs *c, int err)
{
	BUG_ON(err >= 0);
	this_cpu_inc(c->counters.now[BCH_COUNTER_error_throw]);
	trace_error_throw(c, bch2_err_str(err));
	return err;
}

#define bch_err_throw(_c, _err) __bch2_err_throw(_c, -BCH_ERR_##_err)

/* Read-only refs: */

static inline bool bch2_ro_ref_tryget(struct bch_fs *c)
{
	if (test_bit(BCH_FS_stopping, &c->flags))
		return false;

	return refcount_inc_not_zero(&c->ro_ref);
}

static inline void bch2_ro_ref_put(struct bch_fs *c)
{
	if (c && refcount_dec_and_test(&c->ro_ref))
		wake_up(&c->ro_ref_wait);
}

/* Unit conversions: */

static inline unsigned bucket_bytes(const struct bch_dev *ca)
{
	return ca->mi.bucket_size << 9;
}

static inline unsigned block_bytes(const struct bch_fs *c)
{
	return c->opts.block_size;
}

static inline unsigned block_sectors(const struct bch_fs *c)
{
	return c->opts.block_size >> 9;
}

/* Time conversion: */

static inline struct timespec64 bch2_time_to_timespec(const struct bch_fs *c, s64 time)
{
	struct timespec64 t;
	s64 sec;
	s32 rem;

	time += c->sb.time_base_lo;

	sec = div_s64_rem(time, c->sb.time_units_per_sec, &rem);

	set_normalized_timespec64(&t, sec, rem * (s64)c->sb.nsec_per_time_unit);

	return t;
}

static inline s64 timespec_to_bch2_time(const struct bch_fs *c, struct timespec64 ts)
{
	return (ts.tv_sec * c->sb.time_units_per_sec +
		(int) ts.tv_nsec / c->sb.nsec_per_time_unit) - c->sb.time_base_lo;
}

static inline s64 bch2_current_time(const struct bch_fs *c)
{
	struct timespec64 now;

	ktime_get_coarse_real_ts64(&now);
	return timespec_to_bch2_time(c, now);
}

static inline u64 bch2_current_io_time(const struct bch_fs *c, int rw)
{
	return max(1ULL, (u64) atomic64_read(&c->io_clock[rw].now) & LRU_TIME_MAX);
}

/* Filesystem and device helpers: */

static inline void bch2_set_ra_pages(struct bch_fs *c, unsigned ra_pages)
{
#ifndef NO_BCACHEFS_FS
	if (c->vfs_sb)
		c->vfs_sb->s_bdi->ra_pages = ra_pages;
#endif
}

static inline struct stdio_redirect *bch2_fs_stdio_redirect(struct bch_fs *c)
{
	struct stdio_redirect *stdio = c->stdio;

	if (c->stdio_filter && c->stdio_filter != current)
		stdio = NULL;
	return stdio;
}

#define BKEY_PADDED_ONSTACK(key, pad)				\
	struct { struct bkey_i key; __u64 key ## _pad[pad]; }

/*
 * This is needed because discard is both a filesystem option and a device
 * option, and mount options are supposed to apply to that mount and not be
 * persisted, i.e. if it's set as a mount option we can't propagate it to the
 * device.
 */
static inline bool bch2_discard_opt_enabled(struct bch_fs *c, struct bch_dev *ca)
{
	return test_bit(BCH_FS_discard_mount_opt_set, &c->flags)
		? c->opts.discard
		: ca->mi.discard;
}

static inline int bch2_fs_casefold_enabled(struct bch_fs *c)
{
	if (!IS_ENABLED(CONFIG_UNICODE))
		return bch_err_throw(c, no_casefolding_without_utf8);
	if (c->opts.casefold_disabled)
		return bch_err_throw(c, casefolding_disabled);
	return 0;
}

static inline const char *strip_bch2(const char *msg)
{
	if (!strncmp("bch2_", msg, 5))
		return msg + 5;
	return msg;
}

static inline const char *bch2_fs_name(const struct bch_fs *c)
{
	return c->name;
}

static inline const char *bch2_dev_name(const struct bch_dev *ca)
{
	return ca->name;
}

static inline bool bch2_dev_rotational(struct bch_fs *c, unsigned dev)
{
	return dev != BCH_SB_MEMBER_INVALID && test_bit(dev, c->devs_rotational.d);
}

/* Log messages: */

void __bch2_log_msg_start(const char *, struct printbuf *);

static inline void bch2_log_msg_start(struct bch_fs *c, struct printbuf *out)
{
	__bch2_log_msg_start(c->name, out);
}

struct bch_log_msg {
	struct bch_fs	*c;
	u8		loglevel;
	struct printbuf	m;
};

static inline void bch2_log_msg_exit(struct bch_log_msg *msg)
{
	if (!msg->m.suppress)
		bch2_print_str_loglevel(msg->c, msg->loglevel, msg->m.buf);
	printbuf_exit(&msg->m);
}

static inline struct bch_log_msg bch2_log_msg_init(struct bch_fs *c,
						   unsigned loglevel,
						   bool suppress)
{
	struct printbuf buf = PRINTBUF;
	bch2_log_msg_start(c, &buf);
	return (struct bch_log_msg) {
		.c		= c,
		.loglevel	= loglevel,
		.m		= buf,
	};
}

enum kern_loglevels {
	LOGLEVEL_emerg		= 0,
	LOGLEVEL_alert		= 1,
	LOGLEVEL_crit		= 2,
	LOGLEVEL_err		= 3,
	LOGLEVEL_warning	= 4,
	LOGLEVEL_notice		= 5,
	LOGLEVEL_info		= 6,
	LOGLEVEL_debug		= 7,
};

DEFINE_CLASS(bch_log_msg, struct bch_log_msg,
	     bch2_log_msg_exit(&_T),
	     bch2_log_msg_init(c, LOGLEVEL_err, false),
	     struct bch_fs *c)

EXTEND_CLASS(bch_log_msg, _level,
	     bch2_log_msg_init(c, loglevel, false),
	     struct bch_fs *c, unsigned loglevel)

/*
 * Open coded EXTEND_CLASS, because we need the constructor to be a macro for
 * ratelimiting to work correctly
 */

typedef class_bch_log_msg_t class_bch_log_msg_ratelimited_t;

static inline void class_bch_log_msg_ratelimited_destructor(class_bch_log_msg_t *p)
{ bch2_log_msg_exit(p); }
#define class_bch_log_msg_ratelimited_constructor(_c)	bch2_log_msg_init(_c, 3, bch2_ratelimit(_c))

#endif /* _BCACHEFS_H */
