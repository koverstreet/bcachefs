#ifndef _BCACHE_ALLOC_TYPES_H
#define _BCACHE_ALLOC_TYPES_H

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
	RESERVE_PRIO,
	RESERVE_BTREE,
	RESERVE_METADATA_LAST = RESERVE_BTREE,
	RESERVE_MOVINGGC,

	RESERVE_NONE,
	RESERVE_NR,
};

static inline bool allocation_is_metadata(enum alloc_reserve id)
{
	return id <= RESERVE_METADATA_LAST;
}

/* Number of nodes btree coalesce will try to coalesce at once */
#define GC_MERGE_NODES		4U

/*
 * Number of nodes we might have to allocate in a worst case btree split
 * operation - we split all the way up to the root, then allocate a new root.
 */
#define btree_reserve_required_nodes(depth)	(((depth) + 1) * 2 + 1)

/*
 * BTREE_RESERVE_MAX = maximum number of nodes we're allowed to reserve at once
 */
#define BTREE_NODE_RESERVE		(BTREE_RESERVE_MAX * 2)

/* Enough for 16 cache devices, 2 tiers and some left over for pipelining */
#define OPEN_BUCKETS_COUNT	256

#define WRITE_POINT_COUNT	16

struct open_bucket {
	struct list_head	list;
	struct mutex		lock;
	atomic_t		pin;
	unsigned		sectors_free;
	unsigned		nr_ptrs;
	struct bch_extent_ptr	ptrs[BKEY_EXTENT_PTRS_MAX];
};

struct write_point {
	struct open_bucket	*b;

	/*
	 * Throttle writes to this write point if tier 0 is full?
	 */
	bool			throttle;

	/*
	 * If 0, use the desired replica count for the cache set.
	 * Otherwise, this is the number of replicas desired (generally 1).
	 */
	unsigned		nr_replicas;

	/*
	 * Bucket reserve to allocate from.
	 */
	enum alloc_reserve	reserve;

	/*
	 * If not NULL, cache group for tiering, promotion and moving GC -
	 * always allocates a single replica
	 */
	struct cache_group	*group;

	/*
	 * Otherwise do a normal replicated bucket allocation that could come
	 * from any device in tier 0 (foreground write)
	 */
};

#endif /* _BCACHE_ALLOC_TYPES_H */
