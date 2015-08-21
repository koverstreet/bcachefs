#ifndef _BCACHE_ALLOC_TYPES_H
#define _BCACHE_ALLOC_TYPES_H

/* There is one reserve for each type of btree, one for prios and gens
 * and one for moving GC */
enum alloc_reserve {
	RESERVE_PRIO	= BTREE_ID_NR,
	/*
	 * free_inc.size buckets are set aside for moving GC btree node
	 * allocations. This means that if moving GC runs out of new buckets for
	 * btree nodes, it will have put back at least free_inc.size buckets
	 * back on free_inc, preventing a deadlock.
	 *
	 * XXX: figure out a less stupid way of achieving this
	 */
	RESERVE_MOVINGGC_BTREE,
	/*
	 * Tiering needs a btree node reserve because of how
	 * btree_check_reserve() works -- if the cache tier is full, we don't
	 * want tiering to block forever.
	 */
	RESERVE_TIERING_BTREE,
	RESERVE_METADATA_LAST = RESERVE_TIERING_BTREE,
	RESERVE_MOVINGGC,
	RESERVE_NONE,
	RESERVE_NR,
};

/* Number of nodes btree coalesce will try to coalesce at once */
#define GC_MERGE_NODES		4U

/*
 * Number of nodes we might have to allocate in a worst case btree split
 * operation - we split all the way up to the root, then allocate a new root.
 */
#define btree_reserve_required_nodes(depth)	(((depth) + 1) * 2 + 1)

/*
 * Enough for splitting depth 2 btree, or for coalescing nodes (when coalescing
 * we won't be inserting into a leaf)
 */
#define BTREE_NODE_RESERVE						\
	max_t(unsigned,							\
	      btree_reserve_required_nodes(1) + GC_MERGE_NODES,		\
	      btree_reserve_required_nodes(2))

/* Enough for 16 cache devices, 2 tiers and some left over for pipelining */
#define OPEN_BUCKETS_COUNT	256

#define WRITE_POINT_COUNT	16

struct open_bucket {
	struct list_head	list;
	spinlock_t		lock;
	atomic_t		pin;
	unsigned		sectors_free;
	BKEY_PADDED(key);
};

struct write_point {
	struct open_bucket	*b;

	/*
	 * Throttle writes to this write point if tier 0 is full?
	 */
	bool throttle;

	/*
	 * If not NULL, refill from that device (this write point is a member of
	 * that struct cache)
	 *
	 * If NULL, do a normal replicated bucket allocation
	 */
	struct cache		*ca;

	/*
	 * If not NULL, tier specific writepoint used by tiering/promotion -
	 * always allocates a single replica
	 */
	struct cache_group	*tier;

	/*
	 * Otherwise do a normal replicated bucket allocation that could come
	 * from any tier (foreground write)
	 */
};

#endif /* _BCACHE_ALLOC_TYPES_H */
