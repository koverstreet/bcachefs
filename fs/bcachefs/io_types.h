#ifndef _BCACHE_IO_TYPES_H
#define _BCACHE_IO_TYPES_H

#include "keylist_types.h"

#include <linux/llist.h>
#include <linux/workqueue.h>

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
	 * parent denotes the original bio, and parent_iter is where in parent
	 * we copy the data back to.
	 */
	struct bio		*parent;
	struct bvec_iter	parent_iter;

	/*
	 * If we have to retry the read (IO error, checksum failure, read stale
	 * data (raced with allocator), we retry the portion of the parent bio
	 * that failed (i.e. this bio's portion, parent_iter).
	 *
	 * But we need to stash the inode somewhere:
	 */
	u64			inode;

	struct cache_set	*c;
	unsigned		flags;

	/* fields align with bch_extent_crc64 */
	u64			bounce:3,
				compressed_size:18,
				uncompressed_size:18,
				offset:17,
				csum_type:4,
				compression_type:4;
	u64			csum;

	struct cache_promote_op *promote;

	struct llist_node	list;
	struct bbio		bio;
};

struct bch_write_bio {
	struct bio		*orig;
	unsigned		bounce:1;
	struct bbio		bio;
};

struct bch_replace_info {
	unsigned successes;	/* How many insertions succeeded */
	unsigned failures;	/* How many insertions failed */
	BKEY_PADDED(key);
};

struct bch_write_op {
	struct closure		cl;
	struct cache_set	*c;
	struct workqueue_struct	*io_wq;
	struct bch_write_bio	*bio;

	unsigned		written; /* sectors */

	short			error;

	union {
		u16		flags;

	struct {
		/* Return -ENOSPC if cache set is full? */
		unsigned	check_enospc:1;
		/* Return -ENOSPC if no buckets immediately available? */
		unsigned	nowait:1;
		/* Discard key range? */
		unsigned	discard:1;
		/* Mark data as cached? */
		unsigned	cached:1;
		/* Wait for journal commit? */
		unsigned	flush:1;
		/* Perform a compare-exchange with replace_key? */
		unsigned	replace:1;

		/* Set on completion, if cmpxchg index update failed */
		unsigned	replace_collision:1;
		/* Are we using the prt member of journal_seq union? */
		unsigned	journal_seq_ptr:1;
		/* Internal */
		unsigned	write_done:1;
	};
	};

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

	struct keylist		insert_keys;
	BKEY_PADDED(insert_key);
	struct bch_replace_info replace_info;
	u64			inline_keys[BKEY_EXTENT_U64s_MAX * 2];
};

struct bio_decompress_worker {
	struct work_struct		work;
	struct llist_head		bio_list;
};

#endif /* _BCACHE_IO_TYPES_H */
