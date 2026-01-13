/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ALLOC_TYPES_H
#define _BCACHEFS_ALLOC_TYPES_H

#include <linux/mutex.h>
#include <linux/spinlock.h>

#include "init/dev_types.h"

#include "util/clock_types.h"
#include "util/fifo.h"

#define BCH_WATERMARKS()		\
	x(stripe)			\
	x(normal)			\
	x(copygc)			\
	x(btree)			\
	x(btree_copygc)			\
	x(reclaim)			\
	x(interior_updates)

enum bch_watermark {
#define x(name)	BCH_WATERMARK_##name,
	BCH_WATERMARKS()
#undef x
	BCH_WATERMARK_NR,
};

#define BCH_WATERMARK_BITS	3
#define BCH_WATERMARK_MASK	~(~0U << BCH_WATERMARK_BITS)

#define OPEN_BUCKETS_COUNT	1024

#define WRITE_POINT_HASH_NR	32
#define WRITE_POINT_MAX		32

/*
 * 0 is never a valid open_bucket_idx_t:
 */
typedef u16			open_bucket_idx_t;

struct open_bucket {
	spinlock_t		lock;
	atomic_t		pin;
	open_bucket_idx_t	freelist;
	open_bucket_idx_t	hash;

	/*
	 * When an open bucket has an ec_stripe attached, this is the index of
	 * the block in the stripe this open_bucket corresponds to:
	 */
	u8			ec_idx;
	enum bch_data_type	data_type:6;
	unsigned		valid:1;
	unsigned		on_partial_list:1;

	u8			dev;
	u8			gen;
	u32			sectors_free;
	u64			bucket;
	struct ec_stripe_new	*ec;
};

struct open_buckets {
	open_bucket_idx_t	nr;
	open_bucket_idx_t	v[BCH_BKEY_PTRS_MAX];
};

struct dev_stripe_state {
	u64			next_alloc[BCH_SB_MEMBERS_MAX];
};

#define WRITE_POINT_STATES()		\
	x(stopped)			\
	x(waiting_io)			\
	x(waiting_work)			\
	x(runnable)			\
	x(running)

enum write_point_state {
#define x(n)	WRITE_POINT_##n,
	WRITE_POINT_STATES()
#undef x
	WRITE_POINT_STATE_NR
};

struct write_point {
	struct {
		struct hlist_node	node;
		struct mutex		lock;
		u64			last_used;
		unsigned long		write_point;
		enum bch_data_type	data_type;

		/* calculated based on how many pointers we're actually going to use: */
		unsigned		sectors_free;
		unsigned		prev_sectors_free;

		struct open_buckets	ptrs;
		struct dev_stripe_state	stripe;

		u64			sectors_allocated;
	} __aligned(SMP_CACHE_BYTES);

	struct {
		struct work_struct	index_update_work;

		struct list_head	writes;
		spinlock_t		writes_lock;

		enum write_point_state	state;
		u64			last_state_change;
		u64			time[WRITE_POINT_STATE_NR];
		u64			last_runtime;
	} __aligned(SMP_CACHE_BYTES);
};

struct write_point_specifier {
	unsigned long		v;
};

struct bch_fs_usage_base;

struct bch_fs_capacity_pcpu {
	u64			sectors_available;
	u64			online_reserved;
};

struct bch_fs_capacity {
	u64			capacity; /* sectors */
	u64			reserved; /* sectors */

	/*
	 * When capacity _decreases_ (due to a disk being removed), we
	 * increment capacity_gen - this invalidates outstanding reservations
	 * and forces them to be revalidated
	 */
	u32			capacity_gen;
	unsigned		bucket_size_max;

	atomic64_t		sectors_available;
	struct mutex		sectors_available_lock;

	struct bch_fs_capacity_pcpu __percpu	*pcpu;

	struct percpu_rw_semaphore	mark_lock;

	seqcount_t			usage_lock;
	struct bch_fs_usage_base __percpu *usage;
};

struct bch_fs_allocator {
	struct bch_devs_mask	rw_devs[BCH_DATA_NR];
	unsigned long		rw_devs_change_count;

	spinlock_t		freelist_lock;
	struct closure_waitlist	freelist_wait;
	unsigned long		last_stuck;

	open_bucket_idx_t	open_buckets_freelist;
	open_bucket_idx_t	open_buckets_nr_free;
	struct closure_waitlist	open_buckets_wait;
	struct open_bucket	open_buckets[OPEN_BUCKETS_COUNT];
	open_bucket_idx_t	open_buckets_hash[OPEN_BUCKETS_COUNT];

	open_bucket_idx_t	open_buckets_partial[OPEN_BUCKETS_COUNT];
	open_bucket_idx_t	open_buckets_partial_nr;

	struct write_point	write_points[WRITE_POINT_MAX];
	struct hlist_head	write_points_hash[WRITE_POINT_HASH_NR];
	struct mutex		write_points_hash_lock;
	unsigned		write_points_nr;

	struct write_point	btree_write_point;
	struct write_point	reconcile_write_point;
};

#endif /* _BCACHEFS_ALLOC_TYPES_H */
