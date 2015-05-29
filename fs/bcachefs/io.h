#ifndef _BCACHE_IO_H
#define _BCACHE_IO_H

struct bbio {
	struct cache		*ca;

	unsigned int		bi_idx;		/* current index into bvl_vec */

	unsigned int            bi_bvec_done;	/* number of bytes completed in
						   current bvec */
	unsigned		submit_time_us;
	struct bkey_i		key;
	struct bch_extent_ptr	ptr;
	/* Only ever have a single pointer (the one we're doing io to/from) */
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
		u8		flags;

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

	u64			*journal_seq;

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
		       struct bkey_s_c, struct bkey_s_c, unsigned);
void bch_write(struct closure *);

int bch_read(struct cache_set *, struct bio *, u64);

void bch_cache_io_error_work(struct work_struct *);
void bch_count_io_errors(struct cache *, int, const char *);
void bch_bbio_count_io_errors(struct bbio *, int, const char *);
void bch_bbio_endio(struct bbio *, int, const char *);

void bch_generic_make_request(struct bio *, struct cache_set *);
void bch_bio_submit_work(struct work_struct *);
void bch_bbio_prep(struct bbio *, struct cache *);
void bch_submit_bbio(struct bbio *, struct cache *, const struct bkey_i *,
		     const struct bch_extent_ptr *, bool);
void bch_submit_bbio_replicas(struct bch_write_bio *, struct cache_set *,
			      const struct bkey_i *, unsigned, bool);

int bch_discard(struct cache_set *, struct bpos, struct bpos, u64);

void __cache_promote(struct cache_set *, struct bbio *,
		     struct bkey_s_c, struct bkey_s_c, unsigned);
bool cache_promote(struct cache_set *, struct bbio *, struct bkey_s_c);

void bch_read_race_work(struct work_struct *);
void bch_wake_delayed_writes(unsigned long data);

extern struct workqueue_struct *bcache_io_wq;

#endif /* _BCACHE_IO_H */
