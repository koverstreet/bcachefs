#ifndef _BCACHE_IO_H
#define _BCACHE_IO_H

struct data_insert_op {
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
		unsigned	insert_data_done:1;
	};
	};

	u8			btree_alloc_reserve;

	struct write_point	*wp;
	struct open_bucket	*open_buckets[2];

	struct keylist		insert_keys;
	BKEY_PADDED(insert_key);
	BKEY_PADDED(replace_key);
};

void bch_data_insert_op_init(struct data_insert_op *, struct cache_set *,
			     struct bio *, struct write_point *, bool,
			     bool, bool, struct bkey *, struct bkey *);
void bch_data_insert(struct closure *cl);

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
void bch_bbio_reset(struct bbio *bio);

void __cache_promote(struct cache_set *, struct bbio *, struct bkey *);
bool cache_promote(struct cache_set *, struct bbio *, struct bkey *, unsigned);

void bch_read_race_work(struct work_struct *work);

#endif /* _BCACHE_IO_H */
