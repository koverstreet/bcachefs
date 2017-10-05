#ifndef _BCACHEFS_ALLOC_TYPES_H
#define _BCACHEFS_ALLOC_TYPES_H

#include <linux/mutex.h>

#include "clock_types.h"

/*
 * There's two of these clocks, one for reads and one for writes:
 *
 * All fields protected by bucket_lock
 */
struct prio_clock {
	/*
	 * "now" in (read/write) IO time - incremented whenever we do X amount
	 * of reads or writes.
	 *
	 * Goes with the bucket read/write prios: when we read or write to a
	 * bucket we reset the bucket's prio to the current hand; thus hand -
	 * prio = time since bucket was last read/written.
	 *
	 * The units are some amount (bytes/sectors) of data read/written, and
	 * the units can change on the fly if we need to rescale to fit
	 * everything in a u16 - your only guarantee is that the units are
	 * consistent.
	 */
	u16			hand;
	u16			min_prio;

	int			rw;

	struct io_timer		rescale;
};

/* There is one reserve for each type of btree, one for prios and gens
 * and one for moving GC */
enum alloc_reserve {
	RESERVE_ALLOC		= -1,
	RESERVE_BTREE		= 0,
	RESERVE_MOVINGGC	= 1,
	RESERVE_NONE		= 2,
	RESERVE_NR		= 3,
};

/* Enough for 16 cache devices, 2 tiers and some left over for pipelining */
#define OPEN_BUCKETS_COUNT	256

#define WRITE_POINT_COUNT	16

struct open_bucket {
	struct list_head	list;
	struct mutex		lock;
	atomic_t		pin;
	bool			has_full_ptrs;
	/*
	 * recalculated every time we allocate from this open_bucket based on
	 * how many pointers we're actually going to use:
	 */
	unsigned		sectors_free;
	unsigned		nr_ptrs;
	struct bch_extent_ptr	ptrs[BCH_REPLICAS_MAX];
	unsigned		ptr_offset[BCH_REPLICAS_MAX];
};

struct write_point {
	struct open_bucket	*b;
	enum bch_data_type	type;

	/*
	 * If not NULL, cache group for tiering, promotion and moving GC -
	 * always allocates a single replica
	 *
	 * Otherwise do a normal replicated bucket allocation that could come
	 * from any device in tier 0 (foreground write)
	 */
	struct bch_devs_mask	*group;

	u64			next_alloc[BCH_SB_MEMBERS_MAX];
};

struct alloc_heap_entry {
	size_t			bucket;
	unsigned long		key;
};

typedef HEAP(struct alloc_heap_entry) alloc_heap;

#endif /* _BCACHEFS_ALLOC_TYPES_H */
