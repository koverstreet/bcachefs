/*
 * Some low level IO code, and hacks for various block layer limitations
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "bset.h"
#include "debug.h"
#include "btree.h"
#include "extents.h"

#include <linux/blkdev.h>

void bch_generic_make_request(struct bio *bio, struct cache_set *c)
{
	if (current->bio_list) {
		spin_lock(&c->bio_submit_lock);
		bio_list_add(&c->bio_submit_list, bio);
		spin_unlock(&c->bio_submit_lock);
		queue_work(bcache_io_wq, &c->bio_submit_work);
	} else {
		generic_make_request(bio);
	}
}

void bch_bio_submit_work(struct work_struct *work)
{
	struct cache_set *c = container_of(work, struct cache_set,
					   bio_submit_work);
	struct bio *bio;

	while (1) {
		spin_lock(&c->bio_submit_lock);
		bio = bio_list_pop(&c->bio_submit_list);
		spin_unlock(&c->bio_submit_lock);

		if (!bio)
			break;

		bch_generic_make_request(bio, c);
	}
}

/* Bios with headers */

void bch_bbio_free(struct bio *bio, struct cache_set *c)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	mempool_free(b, c->bio_meta);
}

struct bio *bch_bbio_alloc(struct cache_set *c)
{
	struct bbio *b = mempool_alloc(c->bio_meta, GFP_NOIO);
	struct bio *bio = &b->bio;

	bio_init(bio);
	bio->bi_max_vecs	 = bucket_pages(c);
	bio->bi_io_vec		 = bio->bi_inline_vecs;

	return bio;
}

void __bch_bbio_prep(struct bio *bio, struct cache_set *c)
{
	struct bbio *b = container_of(bio, struct bbio, bio);

	bio->bi_iter.bi_sector	= PTR_OFFSET(&b->key, 0);
	bio->bi_bdev		= PTR_CACHE(c, &b->key, 0)->bdev;

	b->submit_time_us = local_clock_us();
}

void bch_bbio_prep(struct bio *bio, struct cache_set *c,
		   struct bkey *k, unsigned ptr)
{
	struct bbio *b = container_of(bio, struct bbio, bio);

	bch_bkey_copy_single_ptr(&b->key, k, ptr);
	__bch_bbio_prep(bio, c);
}

void bch_submit_bbio(struct bio *bio, struct cache_set *c,
		     struct bkey *k, unsigned ptr)
{
	bch_bbio_prep(bio, c, k, ptr);
	closure_bio_submit(bio, bio->bi_private);
}

void bch_submit_bbio_replicas(struct bio *bio_src, struct cache_set *c,
			      struct bkey *k, unsigned long *ptrs_to_write)
{
	struct bio *bio;
	unsigned first, i;

	first = find_first_bit(ptrs_to_write, bch_extent_ptrs(k));

	i = first + 1;
	for_each_set_bit_from(i, ptrs_to_write, bch_extent_ptrs(k)) {
		bio = bio_clone_fast(bio_src, GFP_NOIO,
				     PTR_CACHE(c, k, i)->replica_set);
		bio->bi_end_io		= bio_src->bi_end_io;
		bio->bi_private		= bio_src->bi_private;

		bch_bbio_prep(bio, c, k, i);
		closure_bio_submit_punt(bio, bio->bi_private, c);
	}

	bch_bbio_prep(bio_src, c, k, first);
	closure_bio_submit_punt(bio_src, bio_src->bi_private, c);
}

/* IO errors */

void bch_count_io_errors(struct cache *ca, int error, const char *m)
{
	/*
	 * The halflife of an error is:
	 * log2(1/2)/log2(127/128) * refresh ~= 88 * refresh
	 */

	if (ca->set->error_decay) {
		unsigned count = atomic_inc_return(&ca->io_count);

		while (count > ca->set->error_decay) {
			unsigned errors;
			unsigned old = count;
			unsigned new = count - ca->set->error_decay;

			/*
			 * First we subtract refresh from count; each time we
			 * succesfully do so, we rescale the errors once:
			 */

			count = atomic_cmpxchg(&ca->io_count, old, new);

			if (count == old) {
				count = new;

				errors = atomic_read(&ca->io_errors);
				do {
					old = errors;
					new = ((uint64_t) errors * 127) / 128;
					errors = atomic_cmpxchg(&ca->io_errors,
								old, new);
				} while (old != errors);
			}
		}
	}

	if (error) {
		char buf[BDEVNAME_SIZE];
		unsigned errors = atomic_add_return(1 << IO_ERROR_SHIFT,
						    &ca->io_errors);
		errors >>= IO_ERROR_SHIFT;

		if (errors < ca->set->error_limit)
			pr_err("%s: IO error on %s, recovering",
			       bdevname(ca->bdev, buf), m);
		else
			bch_cache_set_error(ca->set,
					    "%s: too many IO errors %s",
					    bdevname(ca->bdev, buf), m);
	}
}

void bch_bbio_count_io_errors(struct cache_set *c, struct bio *bio,
			      int error, const char *m)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	struct cache *ca = PTR_CACHE(c, &b->key, 0);

	unsigned threshold = op_is_write(bio_op(bio))
		? c->congested_write_threshold_us
		: c->congested_read_threshold_us;

	if (threshold && b->submit_time_us) {
		unsigned t = local_clock_us();

		int us = t - b->submit_time_us;
		int congested = atomic_read(&c->congested);

		if (us > (int) threshold) {
			int ms = us / 1024;
			c->congested_last_us = t;

			ms = min(ms, CONGESTED_MAX + congested);
			atomic_sub(ms, &c->congested);
		} else if (congested < 0)
			atomic_inc(&c->congested);
	}

	bch_count_io_errors(ca, error, m);
}

void bch_bbio_endio(struct cache_set *c, struct bio *bio,
		    int error, const char *m)
{
	struct closure *cl = bio->bi_private;

	bch_bbio_count_io_errors(c, bio, error, m);
	bio_put(bio);
	closure_put(cl);
}
