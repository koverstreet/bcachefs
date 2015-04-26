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

void bch_bbio_prep(struct bbio *b, struct cache *ca)
{
	struct bvec_iter *iter = &b->bio.bi_iter;

	b->ca				= ca;
	b->bio.bi_iter.bi_sector	= PTR_OFFSET(&b->key, 0);
	b->bio.bi_bdev			= ca ? ca->bdev : NULL;

	b->bi_idx			= iter->bi_idx;
	b->bi_bvec_done			= iter->bi_bvec_done;
}

void bch_submit_bbio(struct bbio *b, struct cache *ca,
		     struct bkey *k, unsigned ptr, bool punt)
{
	struct bio *bio = &b->bio;

	bch_bkey_copy_single_ptr(&b->key, k, ptr);
	bch_bbio_prep(b, ca);
	b->submit_time_us = local_clock_us();

	if (!ca) {
		closure_get(bio->bi_private);
		bio_io_error(bio);
	} else if (punt)
		closure_bio_submit_punt(bio, bio->bi_private, ca->set);
	else
		closure_bio_submit(bio, bio->bi_private);
}

void bch_submit_bbio_replicas(struct bio *bio, struct cache_set *c,
			      struct bkey *k, unsigned long *ptrs_to_write,
			      bool punt)
{
	struct cache *ca;
	unsigned ptr, next, nr_ptrs = bch_extent_ptrs(k);

	for (ptr = find_first_bit(ptrs_to_write, nr_ptrs);
	     ptr != nr_ptrs;
	     ptr = next) {
		next = find_next_bit(ptrs_to_write, nr_ptrs, ptr + 1);

		rcu_read_lock();
		ca = PTR_CACHE(c, k, ptr);
		if (ca)
			percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		if (!ca) {
			bch_submit_bbio(to_bbio(bio), ca, k, ptr, punt);
			break;
		}

		if (next != nr_ptrs) {
			struct bio *n = bio_clone_fast(bio, GFP_NOIO,
						       ca->replica_set);
			n->bi_end_io		= bio->bi_end_io;
			n->bi_private		= bio->bi_private;
			bch_submit_bbio(to_bbio(n), ca, k, ptr, punt);
		} else {
			bch_submit_bbio(to_bbio(bio), ca, k, ptr, punt);
		}
	}
}

void bch_bbio_reset(struct bbio *b)
{
	struct bvec_iter *iter = &b->bio.bi_iter;

	bio_reset(&b->bio);
	iter->bi_sector		= KEY_START(&b->key);
	iter->bi_size		= KEY_SIZE(&b->key) << 9;
	iter->bi_idx		= b->bi_idx;
	iter->bi_bvec_done	= b->bi_bvec_done;
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

		if (errors < ca->set->error_limit) {
			pr_err("%s: IO error on %s, recovering",
			       bdevname(ca->bdev, buf), m);
		} else {
			pr_err("%s: too many IO errors on %s, removing",
			       bdevname(ca->bdev, buf), m);
			bch_cache_remove(ca);
		}
	}
}

void bch_bbio_count_io_errors(struct bbio *bio, int error, const char *m)
{
	struct cache_set *c;
	unsigned threshold;

	if (!bio->ca)
		return;

	c = bio->ca->set;
	threshold = op_is_write(bio_op(&bio->bio))
		? c->congested_write_threshold_us
		: c->congested_read_threshold_us;

	if (threshold && bio->submit_time_us) {
		unsigned t = local_clock_us();

		int us = t - bio->submit_time_us;
		int congested = atomic_read(&c->congested);

		if (us > (int) threshold) {
			int ms = us / 1024;
			c->congested_last_us = t;

			ms = min(ms, CONGESTED_MAX + congested);
			atomic_sub(ms, &c->congested);
		} else if (congested < 0)
			atomic_inc(&c->congested);
	}

	bch_count_io_errors(bio->ca, error, m);
}

void bch_bbio_endio(struct bbio *bio, int error, const char *m)
{
	struct closure *cl = bio->bio.bi_private;
	struct cache *ca = bio->ca;

	bch_bbio_count_io_errors(bio, error, m);
	bio_put(&bio->bio);
	if (ca)
		percpu_ref_put(&ca->ref);
	closure_put(cl);
}
