#ifndef _BCACHEFS_IO_H
#define _BCACHEFS_IO_H

#include <linux/hash.h>
#include "io_types.h"

#define to_wbio(_bio)			\
	container_of((_bio), struct bch_write_bio, bio)

#define to_rbio(_bio)			\
	container_of((_bio), struct bch_read_bio, bio)

void bch2_bio_free_pages_pool(struct bch_fs *, struct bio *);
void bch2_bio_alloc_pages_pool(struct bch_fs *, struct bio *, size_t);

void bch2_submit_wbio_replicas(struct bch_write_bio *, struct bch_fs *,
			       enum bch_data_type, const struct bkey_i *);

enum bch_write_flags {
	BCH_WRITE_ALLOC_NOWAIT		= (1 << 0),
	BCH_WRITE_CACHED		= (1 << 1),
	BCH_WRITE_FLUSH			= (1 << 2),
	BCH_WRITE_DATA_COMPRESSED	= (1 << 3),
	BCH_WRITE_THROTTLE		= (1 << 4),
	BCH_WRITE_ONLY_SPECIFIED_DEVS	= (1 << 5),

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

void bch2_write_op_init(struct bch_write_op *, struct bch_fs *,
			struct disk_reservation,
			struct bch_devs_mask *,
			unsigned long,
			struct bpos, u64 *, unsigned);
void bch2_write(struct closure *);

static inline struct bch_write_bio *wbio_init(struct bio *bio)
{
	struct bch_write_bio *wbio = to_wbio(bio);

	memset(wbio, 0, offsetof(struct bch_write_bio, bio));
	return wbio;
}

void bch2_wake_delayed_writes(struct timer_list *);

struct bch_devs_mask;
struct cache_promote_op;
struct extent_pick_ptr;

int __bch2_read_extent(struct bch_fs *, struct bch_read_bio *, struct bvec_iter,
		       struct bkey_s_c k, struct extent_pick_ptr *, unsigned);
void __bch2_read(struct bch_fs *, struct bch_read_bio *, struct bvec_iter,
		 u64, struct bch_devs_mask *, unsigned);

enum bch_read_flags {
	BCH_READ_RETRY_IF_STALE		= 1 << 0,
	BCH_READ_MAY_PROMOTE		= 1 << 1,
	BCH_READ_USER_MAPPED		= 1 << 2,

	/* internal: */
	BCH_READ_MUST_BOUNCE		= 1 << 3,
	BCH_READ_MUST_CLONE		= 1 << 4,
	BCH_READ_IN_RETRY		= 1 << 5,
};

static inline void bch2_read_extent(struct bch_fs *c,
				    struct bch_read_bio *rbio,
				    struct bkey_s_c k,
				    struct extent_pick_ptr *pick,
				    unsigned flags)
{
	rbio->_state = 0;
	__bch2_read_extent(c, rbio, rbio->bio.bi_iter, k, pick, flags);
}

static inline void bch2_read(struct bch_fs *c, struct bch_read_bio *rbio,
			     u64 inode)
{
	rbio->_state = 0;
	__bch2_read(c, rbio, rbio->bio.bi_iter, inode, NULL,
		    BCH_READ_RETRY_IF_STALE|
		    BCH_READ_MAY_PROMOTE|
		    BCH_READ_USER_MAPPED);
}

static inline struct bch_read_bio *rbio_init(struct bio *bio)
{
	struct bch_read_bio *rbio = to_rbio(bio);

	rbio->_state = 0;
	return rbio;
}

#endif /* _BCACHEFS_IO_H */
