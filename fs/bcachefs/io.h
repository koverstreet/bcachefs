#ifndef _BCACHE_IO_H
#define _BCACHE_IO_H

/*
 * Adding a wrapper around the replace_key allows easy addition of
 * statistics and other fields for debugging.
 */

struct bch_replace_info {
	/* Debugging */
	BKEY_PADDED(key);
};

struct bch_write_op {
	struct closure		cl;
	struct cache_set	*c;
	struct workqueue_struct	*io_wq;
	struct bio		*bio;

	/* Used internally, do not touch */
	struct btree_op		op;

	short			error;

	union {
		u8		flags;

	struct {
		/* Wait for data bucket allocation or just
		 * fail when out of space? */
		unsigned	wait:1;
		/* Discard key range? */
		unsigned	discard:1;
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

	u8			btree_alloc_reserve;

	struct write_point	*wp;

	union {
	struct open_bucket	*open_buckets[2];
	struct {
	struct bch_write_op	*next;
	unsigned long		expires;
	};
	};


	struct keylist		insert_keys;
	BKEY_PADDED(insert_key);
	struct bch_replace_info replace_info;
};

void bch_write_op_init(struct bch_write_op *, struct cache_set *,
		       struct bio *, struct write_point *, bool,
		       bool, bool, struct bkey *, struct bkey *);
void bch_write(struct closure *);

int bch_read(struct cache_set *, struct bio *, u64);

void bch_count_io_errors(struct cache *, int, const char *);
void bch_bbio_count_io_errors(struct bbio *, int, const char *);
void bch_bbio_endio(struct bbio *, int, const char *);
void bch_bbio_free(struct bio *, struct cache_set *);
struct bio *bch_bbio_alloc(struct cache_set *);

void bch_generic_make_request(struct bio *, struct cache_set *);
void bch_bio_submit_work(struct work_struct *);
void bch_bbio_prep(struct bbio *, struct cache *);
void bch_submit_bbio(struct bbio *, struct cache *, struct bkey *,
		     unsigned, bool);
void bch_submit_bbio_replicas(struct bio *, struct cache_set *,
			      struct bkey *, unsigned, bool);

int bch_discard(struct cache_set *, struct bkey *, struct bkey *, u64);

void __cache_promote(struct cache_set *, struct bbio *, struct bkey *);
bool cache_promote(struct cache_set *, struct bbio *, struct bkey *, unsigned);

void bch_read_race_work(struct work_struct *);
void bch_wake_delayed_writes(unsigned long data);

extern struct workqueue_struct *bcache_io_wq;

#endif /* _BCACHE_IO_H */
