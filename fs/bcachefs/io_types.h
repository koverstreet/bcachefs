#ifndef _BCACHE_IO_TYPES_H
#define _BCACHE_IO_TYPES_H

#include "btree_types.h"
#include "buckets_types.h"
#include "keylist_types.h"

#include <linux/llist.h>
#include <linux/workqueue.h>

/* XXX kill kill kill */
struct bbio {
	struct cache		*ca;
	struct bch_extent_ptr	ptr;
	unsigned		submit_time_us;
	struct bio		bio;
};

struct bch_read_bio {
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
	bio_end_io_t		*orig_bi_end_io;
	};

	/*
	 * Saved copy of parent->bi_iter, from submission time - allows us to
	 * resubmit on IO error, and also to copy data back to the original bio
	 * when we're bouncing:
	 */
	struct bvec_iter	parent_iter;

	/*
	 * If we have to retry the read (IO error, checksum failure, read stale
	 * data (raced with allocator), we retry the portion of the parent bio
	 * that failed (i.e. this bio's portion, parent_iter).
	 *
	 * But we need to stash the inode somewhere:
	 */
	u64			inode;

	unsigned		submit_time_us;
	u16			flags;
	u8			bounce:1,
				split:1;

	struct bch_extent_crc64	crc;
	struct bch_extent_ptr	ptr;
	struct cache		*ca;

	struct cache_promote_op *promote;

	/* bio_decompress_worker list */
	struct llist_node	list;

	struct bio		bio;
};

static inline struct bch_read_bio *
bch_rbio_parent(struct bch_read_bio *rbio)
{
	return rbio->split ? rbio->parent : rbio;
}

struct bch_write_bio {
	struct bio		*orig;
	unsigned		bounce:1,
				split:1;
	struct bbio		bio;
};

struct bch_replace_info {
	struct extent_insert_hook	hook;
	/* How many insertions succeeded */
	unsigned			successes;
	/* How many insertions failed */
	unsigned			failures;
	BKEY_PADDED(key);
};

struct bch_write_op {
	struct closure		cl;
	struct cache_set	*c;
	struct workqueue_struct	*io_wq;
	struct bch_write_bio	*bio;

	unsigned		written; /* sectors */

	short			error;

	u16			flags;
	unsigned		compression_type:4;
	unsigned		nr_replicas:4;

	struct bpos		pos;
	unsigned		version;

	/* For BCH_WRITE_DATA_COMPRESSED: */
	struct bch_extent_crc64	crc;
	unsigned		size;

	struct disk_reservation	res;

	struct write_point	*wp;

	union {
	struct open_bucket	*open_buckets[2];
	struct {
	struct bch_write_op	*next;
	unsigned long		expires;
	};
	};

	/*
	 * If caller wants to flush but hasn't passed us a journal_seq ptr, we
	 * still need to stash the journal_seq somewhere:
	 */
	union {
		u64			*journal_seq_p;
		u64			journal_seq;
	};

	int			(*index_update_fn)(struct bch_write_op *);

	struct keylist		insert_keys;
	u64			inline_keys[BKEY_EXTENT_U64s_MAX * 2];
};

struct bio_decompress_worker {
	struct cache_set		*c;
	struct work_struct		work;
	struct llist_head		bio_list;
};

#endif /* _BCACHE_IO_TYPES_H */
