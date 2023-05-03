/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_IO_TYPES_H
#define _BCACHEFS_IO_TYPES_H

#include "alloc_types.h"
#include "btree_types.h"
#include "buckets_types.h"
#include "extents_types.h"
#include "keylist_types.h"
#include "opts.h"
#include "super_types.h"

#include <linux/llist.h>
#include <linux/workqueue.h>

struct bch_read_bio {
	struct bch_fs		*c;
	u64			start_time;
	u64			submit_time;

	/*
	 * Reads will often have to be split, and if the extent being read from
	 * was checksummed or compressed we'll also have to allocate bounce
	 * buffers and copy the data back into the original bio.
	 *
	 * If we didn't have to split, we have to save and restore the original
	 * bi_end_io - @split below indicates which:
	 */
	union {
	struct bch_read_bio	*parent;
	bio_end_io_t		*end_io;
	};

	/*
	 * Saved copy of bio->bi_iter, from submission time - allows us to
	 * resubmit on IO error, and also to copy data back to the original bio
	 * when we're bouncing:
	 */
	struct bvec_iter	bvec_iter;

	u16			flags;
	union {
	struct {
	u16			bounce:1,
				split:1,
				kmalloc:1,
				have_ioref:1,
				narrow_crcs:1,
				hole:1,
				retry:2,
				context:2;
	};
	u16			_state;
	};

	struct bch_devs_list	devs_have;

	struct extent_pick_ptr	pick;
	/* start pos of data we read (may not be pos of data we want) */
	struct bpos		pos;
	struct bversion		version;

	struct promote_op	*promote;

	struct bch_io_opts	opts;

	struct work_struct	work;

	struct bio		bio;
};

struct bch_write_bio {
	struct_group(wbio,
	struct bch_fs		*c;
	struct bch_write_bio	*parent;

	u64			submit_time;

	struct bch_devs_list	failed;
	u8			order;
	u8			dev;

	unsigned		split:1,
				bounce:1,
				put_bio:1,
				have_ioref:1,
				used_mempool:1;
	);

	struct bio		bio;
};

struct bch_write_op {
	struct closure		cl;
	struct bch_fs		*c;
	struct workqueue_struct	*io_wq;
	u64			start_time;

	unsigned		written; /* sectors */
	u16			flags;
	s16			error; /* dio write path expects it to hold -ERESTARTSYS... */

	unsigned		csum_type:4;
	unsigned		compression_type:4;
	unsigned		nr_replicas:4;
	unsigned		nr_replicas_required:4;
	unsigned		alloc_reserve:4;

	u8			open_buckets_nr;
	struct bch_devs_list	devs_have;
	u16			target;
	u16			nonce;

	struct bch_io_opts	opts;

	struct bpos		pos;
	struct bversion		version;

	/* For BCH_WRITE_DATA_ENCODED: */
	struct bch_extent_crc_unpacked crc;

	struct write_point_specifier write_point;

	struct disk_reservation	res;

	u8			open_buckets[16];

	/*
	 * If caller wants to flush but hasn't passed us a journal_seq ptr, we
	 * still need to stash the journal_seq somewhere:
	 */
	union {
		u64			*journal_seq_p;
		u64			journal_seq;
	};

	int			(*index_update_fn)(struct bch_write_op *);

	struct bch_devs_mask	failed;

	struct keylist		insert_keys;
	u64			inline_keys[BKEY_EXTENT_U64s_MAX * 2];

	/* Must be last: */
	struct bch_write_bio	wbio;
};

#endif /* _BCACHEFS_IO_TYPES_H */
