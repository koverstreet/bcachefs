#ifndef _BCACHEFS_MOVE_H
#define _BCACHEFS_MOVE_H

#include "btree_iter.h"
#include "buckets.h"
#include "io_types.h"

struct bch_read_bio;
struct moving_context;

struct migrate_write {
	struct moving_context	*ctxt;

	/* what we read: */
	struct bch_extent_ptr	ptr;
	u64			offset;

	int			move_dev;
	int			btree_insert_flags;
	struct bch_write_op	op;
};

void bch2_migrate_write_init(struct migrate_write *, struct bch_read_bio *);

#define SECTORS_IN_FLIGHT_PER_DEVICE	2048

typedef bool (*move_pred_fn)(void *, struct bkey_s_c_extent);

struct bch_move_stats {
	enum bch_data_type	data_type;
	struct btree_iter	iter;

	atomic64_t		keys_moved;
	atomic64_t		sectors_moved;
	atomic64_t		sectors_seen;
	atomic64_t		sectors_raced;
};

int bch2_move_data(struct bch_fs *, struct bch_ratelimit *,
		   unsigned, struct bch_devs_mask *,
		   struct write_point_specifier,
		   int, int, struct bpos, struct bpos,
		   move_pred_fn, void *,
		   struct bch_move_stats *);

int bch2_data_job(struct bch_fs *,
		  struct bch_move_stats *,
		  struct bch_ioctl_data);

#endif /* _BCACHEFS_MOVE_H */
