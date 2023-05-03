/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_MOVE_H
#define _BCACHEFS_MOVE_H

#include "btree_iter.h"
#include "buckets.h"
#include "data_update.h"
#include "move_types.h"

struct bch_read_bio;

struct moving_context {
	struct bch_fs		*c;
	struct bch_ratelimit	*rate;
	struct bch_move_stats	*stats;
	struct write_point_specifier wp;
	bool			wait_on_copygc;
	bool			write_error;

	/* For waiting on outstanding reads and writes: */
	struct closure		cl;
	struct list_head	reads;

	/* in flight sectors: */
	atomic_t		read_sectors;
	atomic_t		write_sectors;

	wait_queue_head_t	wait;
};

typedef bool (*move_pred_fn)(struct bch_fs *, void *, struct bkey_s_c,
			     struct bch_io_opts *, struct data_update_opts *);

void bch2_moving_ctxt_exit(struct moving_context *);
void bch2_moving_ctxt_init(struct moving_context *, struct bch_fs *,
			   struct bch_ratelimit *, struct bch_move_stats *,
			   struct write_point_specifier, bool);

int bch2_scan_old_btree_nodes(struct bch_fs *, struct bch_move_stats *);

int bch2_move_data(struct bch_fs *,
		   enum btree_id, struct bpos,
		   enum btree_id, struct bpos,
		   struct bch_ratelimit *,
		   struct bch_move_stats *,
		   struct write_point_specifier,
		   bool,
		   move_pred_fn, void *);

int __bch2_evacuate_bucket(struct moving_context *,
			   struct bpos, int,
			   struct data_update_opts);
int bch2_evacuate_bucket(struct bch_fs *, struct bpos, int,
			 struct data_update_opts,
			 struct bch_ratelimit *,
			 struct bch_move_stats *,
			 struct write_point_specifier,
			 bool);
int bch2_data_job(struct bch_fs *,
		  struct bch_move_stats *,
		  struct bch_ioctl_data);

void bch2_move_stats_init(struct bch_move_stats *stats, char *name);


#endif /* _BCACHEFS_MOVE_H */
