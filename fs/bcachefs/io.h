#ifndef _BCACHE_IO_H
#define _BCACHE_IO_H

#include <linux/hash.h>
#include "io_types.h"

#define to_wbio(_bio)			\
	container_of((_bio), struct bch_write_bio, bio)

#define to_rbio(_bio)			\
	container_of((_bio), struct bch_read_bio, bio)

void bch2_bio_free_pages_pool(struct bch_fs *, struct bio *);
void bch2_bio_alloc_pages_pool(struct bch_fs *, struct bio *, size_t);

enum bch_write_flags {
	BCH_WRITE_ALLOC_NOWAIT		= (1 << 0),
	BCH_WRITE_DISCARD		= (1 << 1),
	BCH_WRITE_CACHED		= (1 << 2),
	BCH_WRITE_FLUSH			= (1 << 3),
	BCH_WRITE_DISCARD_ON_ERROR	= (1 << 4),
	BCH_WRITE_DATA_COMPRESSED	= (1 << 5),

	/* Internal: */
	BCH_WRITE_JOURNAL_SEQ_PTR	= (1 << 6),
	BCH_WRITE_DONE			= (1 << 7),
	BCH_WRITE_LOOPED		= (1 << 8),
};

static inline u64 *op_journal_seq(struct bch_write_op *op)
{
	return (op->flags & BCH_WRITE_JOURNAL_SEQ_PTR)
		? op->journal_seq_p : &op->journal_seq;
}

static inline struct write_point *foreground_write_point(struct bch_fs *c,
							 unsigned long v)
{
	return c->write_points +
		hash_long(v, ilog2(ARRAY_SIZE(c->write_points)));
}

void bch2_write_op_init(struct bch_write_op *, struct bch_fs *,
			struct bch_write_bio *,
			struct disk_reservation, struct write_point *,
			struct bpos, u64 *, unsigned);
void bch2_write(struct closure *);

struct cache_promote_op;

struct extent_pick_ptr;

void bch2_read_extent_iter(struct bch_fs *, struct bch_read_bio *,
			   struct bvec_iter, struct bkey_s_c k,
			   struct extent_pick_ptr *, unsigned);

static inline void bch2_read_extent(struct bch_fs *c,
				    struct bch_read_bio *orig,
				    struct bkey_s_c k,
				    struct extent_pick_ptr *pick,
				    unsigned flags)
{
	bch2_read_extent_iter(c, orig, orig->bio.bi_iter,
			     k, pick, flags);
}

enum bch_read_flags {
	BCH_READ_FORCE_BOUNCE		= 1 << 0,
	BCH_READ_RETRY_IF_STALE		= 1 << 1,
	BCH_READ_PROMOTE		= 1 << 2,
	BCH_READ_IS_LAST		= 1 << 3,
	BCH_READ_MAY_REUSE_BIO		= 1 << 4,
	BCH_READ_USER_MAPPED		= 1 << 5,
};

void bch2_read(struct bch_fs *, struct bch_read_bio *, u64);

void bch2_submit_wbio_replicas(struct bch_write_bio *, struct bch_fs *,
			       const struct bkey_i *);

int bch2_discard(struct bch_fs *, struct bpos, struct bpos,
		 struct bversion, struct disk_reservation *,
		 struct extent_insert_hook *, u64 *);

void bch2_read_retry_work(struct work_struct *);
void bch2_wake_delayed_writes(unsigned long data);

#endif /* _BCACHE_IO_H */
