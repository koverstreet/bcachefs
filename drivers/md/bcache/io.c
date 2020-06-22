// SPDX-License-Identifier: GPL-2.0
/*
 * Some low level IO code, and hacks for various block layer limitations
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "backingdev.h"
#include "bset.h"
#include "debug.h"

#include <linux/blkdev.h>
#include <linux/random.h>

#include <trace/events/bcache.h>

/*
 * Congested?  Return 0 (not congested) or the limit (in sectors)
 * beyond which we should bypass the cache due to congestion.
 */
unsigned int bch_get_congested(const struct cache_set *c)
{
	int i;

	if (!c->congested_read_threshold_us &&
	    !c->congested_write_threshold_us)
		return 0;

	i = (local_clock_us() - c->congested_last_us) / 1024;
	if (i < 0)
		return 0;

	i += atomic_read(&c->congested);
	if (i >= 0)
		return 0;

	i += CONGESTED_MAX;

	if (i > 0)
		i = fract_exp_two(i, 6);

	i -= hweight32(get_random_u32());

	return i > 0 ? i : 1;
}

static void add_sequential(struct task_struct *t)
{
	ewma_add(t->sequential_io_avg,
		 t->sequential_io, 8, 0);

	t->sequential_io = 0;
}

static struct hlist_head *iohash(struct cached_dev *dc, uint64_t k)
{
	return &dc->io_hash[hash_64(k, RECENT_IO_BITS)];
}

bool bch_check_should_bypass(struct cached_dev *dc, struct bio *bio,
			     unsigned int block_size,
			     unsigned int in_use)
{
	unsigned int mode = cache_mode(dc);
	unsigned int sectors, congested;
	struct task_struct *task = current;
	struct io *i;

	if (test_bit(BCACHE_DEV_DETACHING, &dc->disk.flags) ||
	    in_use > CUTOFF_CACHE_ADD ||
	    (bio_op(bio) == REQ_OP_DISCARD))
		goto skip;

	if (mode == CACHE_MODE_NONE ||
	    (mode == CACHE_MODE_WRITEAROUND &&
	     op_is_write(bio_op(bio))))
		goto skip;

	/*
	 * If the bio is for read-ahead or background IO, bypass it or
	 * not depends on the following situations,
	 * - If the IO is for meta data, always cache it and no bypass
	 * - If the IO is not meta data, check dc->cache_reada_policy,
	 *      BCH_CACHE_READA_ALL: cache it and not bypass
	 *      BCH_CACHE_READA_META_ONLY: not cache it and bypass
	 * That is, read-ahead request for metadata always get cached
	 * (eg, for gfs2 or xfs).
	 */
	if ((bio->bi_opf & (REQ_RAHEAD|REQ_BACKGROUND))) {
		if (!(bio->bi_opf & (REQ_META|REQ_PRIO)) &&
		    (dc->cache_readahead_policy != BCH_CACHE_READA_ALL))
			goto skip;
	}

	if (bio->bi_iter.bi_sector & (block_size - 1) ||
	    bio_sectors(bio) & (block_size - 1)) {
		pr_debug("skipping unaligned io");
		goto skip;
	}

	if (bypass_torture_test(dc)) {
		if ((get_random_int() & 3) == 3)
			goto skip;
		else
			goto rescale;
	}

	if (dc->disk.c) {
		congested = bch_get_congested(dc->disk.c);
	} else {
		/* XXX bcache2: */
		congested = 0;
	}

	if (!congested && !dc->sequential_cutoff)
		goto rescale;

	spin_lock(&dc->io_lock);

	hlist_for_each_entry(i, iohash(dc, bio->bi_iter.bi_sector), hash)
		if (i->last == bio->bi_iter.bi_sector &&
		    time_before(jiffies, i->jiffies))
			goto found;

	i = list_first_entry(&dc->io_lru, struct io, lru);

	add_sequential(task);
	i->sequential = 0;
found:
	if (i->sequential + bio->bi_iter.bi_size > i->sequential)
		i->sequential	+= bio->bi_iter.bi_size;

	i->last			 = bio_end_sector(bio);
	i->jiffies		 = jiffies + msecs_to_jiffies(5000);
	task->sequential_io	 = i->sequential;

	hlist_del(&i->hash);
	hlist_add_head(&i->hash, iohash(dc, i->last));
	list_move_tail(&i->lru, &dc->io_lru);

	spin_unlock(&dc->io_lock);

	sectors = max(task->sequential_io,
		      task->sequential_io_avg) >> 9;

	if (dc->sequential_cutoff &&
	    sectors >= dc->sequential_cutoff >> 9) {
		trace_bcache_bypass_sequential(bio);
		goto skip;
	}

	if (congested && sectors >= congested) {
		trace_bcache_bypass_congested(bio);
		goto skip;
	}

rescale:
	if (dc->disk.c) {
		bch_rescale_priorities(dc->disk.c, bio_sectors(bio));
	} else {
		/* bcache2: */
	}
	return false;
skip:
	if (dc->disk.c) {
		bch_mark_sectors_bypassed(dc->disk.c, dc, bio_sectors(bio));
	} else {
		/* bcache2: */
	}
	return true;
}

/* Bios with headers */

void bch_bbio_free(struct bio *bio, struct cache_set *c)
{
	struct bbio *b = container_of(bio, struct bbio, bio);

	mempool_free(b, &c->bio_meta);
}

struct bio *bch_bbio_alloc(struct cache_set *c)
{
	struct bbio *b = mempool_alloc(&c->bio_meta, GFP_NOIO);
	struct bio *bio = &b->bio;

	bio_init(bio, bio->bi_inline_vecs, bucket_pages(c));

	return bio;
}

void __bch_submit_bbio(struct bio *bio, struct cache_set *c)
{
	struct bbio *b = container_of(bio, struct bbio, bio);

	bio->bi_iter.bi_sector	= PTR_OFFSET(&b->key, 0);
	bio_set_dev(bio, PTR_CACHE(c, &b->key, 0)->bdev);

	b->submit_time_us = local_clock_us();
	closure_bio_submit(c, bio, bio->bi_private);
}

void bch_submit_bbio(struct bio *bio, struct cache_set *c,
		     struct bkey *k, unsigned int ptr)
{
	struct bbio *b = container_of(bio, struct bbio, bio);

	bch_bkey_copy_single_ptr(&b->key, k, ptr);
	__bch_submit_bbio(bio, c);
}

/* IO errors */
void bch_count_backing_io_errors(struct cached_dev *dc, struct bio *bio)
{
	unsigned int errors;

	WARN_ONCE(!dc, "NULL pointer of struct cached_dev");

	/*
	 * Read-ahead requests on a degrading and recovering md raid
	 * (e.g. raid6) device might be failured immediately by md
	 * raid code, which is not a real hardware media failure. So
	 * we shouldn't count failed REQ_RAHEAD bio to dc->io_errors.
	 */
	if (bio->bi_opf & REQ_RAHEAD) {
		pr_warn_ratelimited("%s: Read-ahead I/O failed on backing device, ignore",
				    dc->backing_dev_name);
		return;
	}

	errors = atomic_add_return(1, &dc->io_errors);
	if (errors < dc->error_limit)
		pr_err("%s: IO error on backing device, unrecoverable",
			dc->backing_dev_name);
	else
		bch_cached_dev_error(dc);
}

void bch_count_io_errors(struct cache *ca,
			 blk_status_t error,
			 int is_read,
			 const char *m)
{
	/*
	 * The halflife of an error is:
	 * log2(1/2)/log2(127/128) * refresh ~= 88 * refresh
	 */

	if (ca->set->error_decay) {
		unsigned int count = atomic_inc_return(&ca->io_count);

		while (count > ca->set->error_decay) {
			unsigned int errors;
			unsigned int old = count;
			unsigned int new = count - ca->set->error_decay;

			/*
			 * First we subtract refresh from count; each time we
			 * successfully do so, we rescale the errors once:
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
		unsigned int errors = atomic_add_return(1 << IO_ERROR_SHIFT,
						    &ca->io_errors);
		errors >>= IO_ERROR_SHIFT;

		if (errors < ca->set->error_limit)
			pr_err("%s: IO error on %s%s",
			       ca->cache_dev_name, m,
			       is_read ? ", recovering." : ".");
		else
			bch_cache_set_error(ca->set,
					    "%s: too many IO errors %s",
					    ca->cache_dev_name, m);
	}
}

void bch_bbio_count_io_errors(struct cache_set *c, struct bio *bio,
			      blk_status_t error, const char *m)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	struct cache *ca = PTR_CACHE(c, &b->key, 0);
	int is_read = (bio_data_dir(bio) == READ ? 1 : 0);

	unsigned int threshold = op_is_write(bio_op(bio))
		? c->congested_write_threshold_us
		: c->congested_read_threshold_us;

	if (threshold) {
		unsigned int t = local_clock_us();
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

	bch_count_io_errors(ca, error, is_read, m);
}

void bch_bbio_endio(struct cache_set *c, struct bio *bio,
		    blk_status_t error, const char *m)
{
	struct closure *cl = bio->bi_private;

	bch_bbio_count_io_errors(c, bio, error, m);
	bio_put(bio);
	closure_put(cl);
}
