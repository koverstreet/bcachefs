/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHE_IO_H_
#define _BCACHE_IO_H_

struct cached_dev;
struct cache;
struct cache_set;

unsigned int bch_get_congested(const struct cache_set *c);
bool bch_check_should_bypass(struct cached_dev *dc, struct bio *bio);

void bch_count_backing_io_errors(struct cached_dev *dc, struct bio *bio);
void bch_count_io_errors(struct cache *ca, blk_status_t error,
			 int is_read, const char *m);
void bch_bbio_count_io_errors(struct cache_set *c, struct bio *bio,
			      blk_status_t error, const char *m);
void bch_bbio_endio(struct cache_set *c, struct bio *bio,
		    blk_status_t error, const char *m);
void bch_bbio_free(struct bio *bio, struct cache_set *c);
struct bio *bch_bbio_alloc(struct cache_set *c);

void __bch_submit_bbio(struct bio *bio, struct cache_set *c);
void bch_submit_bbio(struct bio *bio, struct cache_set *c,
		     struct bkey *k, unsigned int ptr);

#endif /* _BCACHE_IO_H_ */
