#ifndef _BCACHEFS_MOVE_H
#define _BCACHEFS_MOVE_H

#include "buckets.h"
#include "io_types.h"

enum moving_flag_bitnos {
	MOVING_FLAG_BITNO_READ = 0,
	MOVING_FLAG_BITNO_WRITE,
};

#define MOVING_FLAG_READ	(1U << MOVING_FLAG_BITNO_READ)
#define MOVING_FLAG_WRITE	(1U << MOVING_FLAG_BITNO_WRITE)

struct migrate_write {
	BKEY_PADDED(key);
	bool			promote;
	bool			move;
	struct bch_extent_ptr	move_ptr;
	struct bch_write_op	op;
};

void bch2_migrate_write_init(struct bch_fs *, struct migrate_write *,
			     struct bch_devs_mask *,
			     struct write_point_specifier,
			     struct bkey_s_c,
			     const struct bch_extent_ptr *, unsigned);

#define SECTORS_IN_FLIGHT_PER_DEVICE	2048

struct moving_context {
	/* Closure for waiting on all reads and writes to complete */
	struct closure		cl;

	/* Number and types of errors reported */
	atomic_t		error_count;
	atomic_t		error_flags;

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

struct moving_io {
	struct list_head	list;
	struct rb_node		node;
	struct closure		cl;
	struct moving_context	*ctxt;
	struct migrate_write	write;
	bool			read_completed;

	struct bch_read_bio	rbio;
	/* Must be last since it is variable size */
	struct bio_vec		bi_inline_vecs[0];
};

int bch2_data_move(struct bch_fs *, struct moving_context *,
		   struct bch_devs_mask *,
		   struct write_point_specifier,
		   struct bkey_s_c,
		   const struct bch_extent_ptr *);

int bch2_move_ctxt_wait(struct moving_context *);
void bch2_move_ctxt_wait_for_io(struct moving_context *);

void bch2_move_ctxt_exit(struct moving_context *);
void bch2_move_ctxt_init(struct moving_context *, struct bch_ratelimit *,
			unsigned);

#endif /* _BCACHEFS_MOVE_H */
