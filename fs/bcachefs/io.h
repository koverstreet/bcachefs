#ifndef _BCACHE_IO_H
#define _BCACHE_IO_H

#include <linux/zlib.h>

#define COMPRESSION_WORKSPACE_SIZE					\
	max(zlib_deflate_workspacesize(MAX_WBITS, MAX_MEM_LEVEL),	\
	    zlib_inflate_workspacesize())

struct bbio {
	struct cache		*ca;
	struct bch_extent_ptr	ptr;
	unsigned		submit_time_us;
	struct bio		bio;
};

#define to_bbio(_bio)		container_of((_bio), struct bbio, bio)

struct bch_write_bio {
	struct bio		*orig;
	unsigned		bounce:1;
	struct bbio		bio;
};

#define to_wbio(_bio)			\
	container_of((_bio), struct bch_write_bio, bio.bio)

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
	u64			inline_keys[BKEY_EXTENT_MAX_U64s * 2];
};

enum bch_write_flags {
	BCH_WRITE_CHECK_ENOSPC		= (1 << 0),
	BCH_WRITE_ALLOC_NOWAIT		= (1 << 1),
	BCH_WRITE_DISCARD		= (1 << 2),
	BCH_WRITE_CACHED		= (1 << 3),
	BCH_WRITE_FLUSH			= (1 << 4),
};

void bch_write_op_init(struct bch_write_op *, struct cache_set *,
		       struct bch_write_bio *, struct write_point *,
		       struct bkey_s_c, struct bkey_s_c, u64 *, unsigned);
void bch_write(struct closure *);

struct cache_promote_op;

struct bch_read_bio {
	struct bio		*parent;
	struct bvec_iter	parent_iter;

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

struct extent_pick_ptr;

void bch_read_extent(struct cache_set *, struct bio *, struct bkey_s_c,
		     struct extent_pick_ptr *, unsigned, unsigned);

enum bch_read_flags {
	BCH_READ_FORCE_BOUNCE		= 1 << 0,
	BCH_READ_RETRY_IF_STALE		= 1 << 1,
	BCH_READ_PROMOTE		= 1 << 2,
};

int bch_read(struct cache_set *, struct bio *, u64);

void bch_cache_io_error_work(struct work_struct *);
void bch_count_io_errors(struct cache *, int, const char *);
void bch_bbio_count_io_errors(struct bbio *, int, const char *);
void bch_bbio_endio(struct bbio *, int, const char *);

void bch_generic_make_request(struct bio *, struct cache_set *);
void bch_bio_submit_work(struct work_struct *);
void bch_submit_bbio(struct bbio *, struct cache *,
		     const struct bch_extent_ptr *, bool);
void bch_submit_bbio_replicas(struct bch_write_bio *, struct cache_set *,
			      const struct bkey_i *, unsigned, bool);

int bch_discard(struct cache_set *, struct bpos, struct bpos, u64);

void __cache_promote(struct cache_set *, struct bbio *,
		     struct bkey_s_c, struct bkey_s_c, unsigned);
bool cache_promote(struct cache_set *, struct bbio *, struct bkey_s_c);

void bch_read_race_work(struct work_struct *);
void bch_wake_delayed_writes(unsigned long data);

void bch_bio_decompress_work(struct work_struct *);

extern struct workqueue_struct *bcache_io_wq;

#endif /* _BCACHE_IO_H */
