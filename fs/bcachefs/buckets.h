/*
 * Code for manipulating bucket marks for garbage collection.
 *
 * Copyright 2014 Datera, Inc.
 */

#ifndef _BUCKETS_H
#define _BUCKETS_H

#include "buckets_types.h"
#include "super.h"

#define for_each_bucket(b, ca)					\
	for (b = (ca)->buckets + (ca)->mi.first_bucket;		\
	     b < (ca)->buckets + (ca)->mi.nbuckets; b++)

#define bucket_cmpxchg(g, new, expr)				\
({								\
	u64 _v = READ_ONCE((g)->_mark.counter);			\
	struct bucket_mark _old;				\
								\
	do {							\
		(new).counter = _old.counter = _v;		\
		expr;						\
	} while ((_v = cmpxchg(&(g)->_mark.counter,		\
			       _old.counter,			\
			       (new).counter)) != _old.counter);\
	_old;							\
})

/*
 * bucket_gc_gen() returns the difference between the bucket's current gen and
 * the oldest gen of any pointer into that bucket in the btree.
 */

static inline u8 bucket_gc_gen(struct bch_dev *ca, struct bucket *g)
{
	unsigned long r = g - ca->buckets;
	return g->mark.gen - ca->oldest_gens[r];
}

static inline size_t PTR_BUCKET_NR(const struct bch_dev *ca,
				   const struct bch_extent_ptr *ptr)
{
	return sector_to_bucket(ca, ptr->offset);
}

static inline struct bucket *PTR_BUCKET(const struct bch_dev *ca,
					const struct bch_extent_ptr *ptr)
{
	return ca->buckets + PTR_BUCKET_NR(ca, ptr);
}

static inline int gen_cmp(u8 a, u8 b)
{
	return (s8) (a - b);
}

static inline int gen_after(u8 a, u8 b)
{
	int r = gen_cmp(a, b);

	return r > 0 ? r : 0;
}

/**
 * ptr_stale() - check if a pointer points into a bucket that has been
 * invalidated.
 */
static inline u8 ptr_stale(const struct bch_dev *ca,
			   const struct bch_extent_ptr *ptr)
{
	return gen_after(PTR_BUCKET(ca, ptr)->mark.gen, ptr->gen);
}

/* bucket gc marks */

/* The dirty and cached sector counts saturate. If this occurs,
 * reference counting alone will not free the bucket, and a btree
 * GC must be performed. */
#define GC_MAX_SECTORS_USED ((1U << 15) - 1)

static inline unsigned bucket_sectors_used(struct bucket_mark mark)
{
	return mark.dirty_sectors + mark.cached_sectors;
}

static inline bool bucket_unused(struct bucket_mark mark)
{
	return !mark.owned_by_allocator &&
		!mark.data_type &&
		!bucket_sectors_used(mark);
}

/* Per device stats: */

struct bch_dev_usage __bch2_dev_usage_read(struct bch_dev *);
struct bch_dev_usage bch2_dev_usage_read(struct bch_dev *);

static inline u64 __dev_buckets_available(struct bch_dev *ca,
					  struct bch_dev_usage stats)
{
	return max_t(s64, 0,
		     ca->mi.nbuckets - ca->mi.first_bucket -
		     stats.buckets[S_META] -
		     stats.buckets[S_DIRTY] -
		     stats.buckets_alloc);
}

/*
 * Number of reclaimable buckets - only for use by the allocator thread:
 */
static inline u64 dev_buckets_available(struct bch_dev *ca)
{
	return __dev_buckets_available(ca, bch2_dev_usage_read(ca));
}

static inline u64 __dev_buckets_free(struct bch_dev *ca,
				       struct bch_dev_usage stats)
{
	return __dev_buckets_available(ca, stats) +
		fifo_used(&ca->free[RESERVE_NONE]) +
		fifo_used(&ca->free_inc);
}

static inline u64 dev_buckets_free(struct bch_dev *ca)
{
	return __dev_buckets_free(ca, bch2_dev_usage_read(ca));
}

/* Cache set stats: */

struct bch_fs_usage __bch2_fs_usage_read(struct bch_fs *);
struct bch_fs_usage bch2_fs_usage_read(struct bch_fs *);
void bch2_fs_usage_apply(struct bch_fs *, struct bch_fs_usage *,
			struct disk_reservation *, struct gc_pos);

struct fs_usage_sum {
	u64	data;
	u64	reserved;
};

static inline struct fs_usage_sum __fs_usage_sum(struct bch_fs_usage stats)
{
	struct fs_usage_sum sum = { 0 };
	unsigned i;

	for (i = 0; i < BCH_REPLICAS_MAX; i++) {
		sum.data += (stats.s[i].data[S_META] +
			     stats.s[i].data[S_DIRTY]) * (i + 1);
		sum.reserved += stats.s[i].persistent_reserved * (i + 1);
	}

	sum.reserved += stats.online_reserved;
	return sum;
}

#define RESERVE_FACTOR	6

static u64 reserve_factor(u64 r)
{
	return r + (round_up(r, (1 << RESERVE_FACTOR)) >> RESERVE_FACTOR);
}

static inline u64 __bch2_fs_sectors_used(struct bch_fs *c)
{
	struct fs_usage_sum sum = __fs_usage_sum(__bch2_fs_usage_read(c));

	return sum.data + reserve_factor(sum.reserved);
}

static inline u64 bch2_fs_sectors_used(struct bch_fs *c)
{
	return min(c->capacity, __bch2_fs_sectors_used(c));
}

static inline bool is_available_bucket(struct bucket_mark mark)
{
	return (!mark.owned_by_allocator &&
		mark.data_type == BUCKET_DATA &&
		!mark.dirty_sectors &&
		!mark.nouse);
}

static inline bool bucket_needs_journal_commit(struct bucket_mark m,
					       u16 last_seq_ondisk)
{
	return m.journal_seq_valid &&
		((s16) m.journal_seq - (s16) last_seq_ondisk > 0);
}

void bch2_bucket_seq_cleanup(struct bch_fs *);

bool bch2_invalidate_bucket(struct bch_dev *, struct bucket *,
			    struct bucket_mark *);
bool bch2_mark_alloc_bucket_startup(struct bch_dev *, struct bucket *);
void bch2_mark_free_bucket(struct bch_dev *, struct bucket *);
void bch2_mark_alloc_bucket(struct bch_dev *, struct bucket *, bool);
void bch2_mark_metadata_bucket(struct bch_dev *, struct bucket *,
			       enum bucket_data_type, bool);

#define BCH_BUCKET_MARK_NOATOMIC		(1 << 0)
#define BCH_BUCKET_MARK_GC_WILL_VISIT		(1 << 1)
#define BCH_BUCKET_MARK_MAY_MAKE_UNAVAILABLE	(1 << 2)

void __bch2_mark_key(struct bch_fs *, struct bkey_s_c, s64, bool,
		     struct bch_fs_usage *, u64, unsigned);

void bch2_gc_mark_key(struct bch_fs *, struct bkey_s_c,
		      s64, bool, unsigned);
void bch2_mark_key(struct bch_fs *, struct bkey_s_c, s64, bool,
		  struct gc_pos, struct bch_fs_usage *, u64);

void bch2_recalc_sectors_available(struct bch_fs *);

void __bch2_disk_reservation_put(struct bch_fs *, struct disk_reservation *);

static inline void bch2_disk_reservation_put(struct bch_fs *c,
					     struct disk_reservation *res)
{
	if (res->sectors)
		__bch2_disk_reservation_put(c, res);
}

#define BCH_DISK_RESERVATION_NOFAIL		(1 << 0)
#define BCH_DISK_RESERVATION_METADATA		(1 << 1)
#define BCH_DISK_RESERVATION_GC_LOCK_HELD	(1 << 2)
#define BCH_DISK_RESERVATION_BTREE_LOCKS_HELD	(1 << 3)

int bch2_disk_reservation_add(struct bch_fs *,
			     struct disk_reservation *,
			     unsigned, int);
int bch2_disk_reservation_get(struct bch_fs *,
			     struct disk_reservation *,
			     unsigned, int);

#endif /* _BUCKETS_H */
