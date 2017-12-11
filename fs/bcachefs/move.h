#ifndef _BCACHEFS_MOVE_H
#define _BCACHEFS_MOVE_H

#include "buckets.h"
#include "io_types.h"

struct bch_read_bio;
struct moving_context;

struct migrate_write {
	/* what we read: */
	struct bch_extent_ptr	ptr;
	u64			offset;

	int			move_dev;
	int			btree_insert_flags;
	struct bch_write_op	op;
};

void bch2_migrate_write_init(struct migrate_write *, struct bch_read_bio *);

struct moving_io {
	struct list_head	list;
	struct closure		cl;
	struct moving_context	*ctxt;
	bool			read_completed;
	unsigned		sectors;

	struct bch_read_bio	rbio;

	struct migrate_write	write;
	/* Must be last since it is variable size */
	struct bio_vec		bi_inline_vecs[0];
};

int bch2_data_move(struct bch_fs *, struct moving_context *,
		   struct bch_devs_mask *,
		   struct write_point_specifier,
		   int, int, struct bkey_s_c);

#define SECTORS_IN_FLIGHT_PER_DEVICE	2048

struct moving_context {
	/* Closure for waiting on all reads and writes to complete */
	struct closure		cl;

	/* Key and sector moves issued, updated from submission context */
	u64			keys_moved;
	u64			sectors_moved;

	/* Rate-limiter counting submitted reads */
	struct bch_ratelimit	*rate;

	/* Try to avoid reading the following device */
	struct bch_devs_mask	avoid;

	struct list_head	reads;

	/* Configuration */
	unsigned		max_sectors_in_flight;
	atomic_t		sectors_in_flight;

	wait_queue_head_t	wait;
};

int bch2_move_ctxt_wait(struct moving_context *);
void bch2_move_ctxt_wait_for_io(struct moving_context *);

void bch2_move_ctxt_exit(struct moving_context *);
void bch2_move_ctxt_init(struct moving_context *, struct bch_ratelimit *,
			unsigned);

#endif /* _BCACHEFS_MOVE_H */
