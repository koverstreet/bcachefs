#ifndef _BCACHE_COMPRESS_H
#define _BCACHE_COMPRESS_H

int bch_bio_uncompress_inplace(struct cache_set *, struct bio *,
			       unsigned, struct bch_extent_crc64);
int bch_bio_uncompress(struct cache_set *, struct bio *, struct bio *,
		       struct bvec_iter, struct bch_extent_crc64);
void bch_bio_compress(struct cache_set *, struct bio *, size_t *,
		      struct bio *, size_t *, unsigned *);

void bch_compress_free(struct cache_set *);
int bch_compress_init(struct cache_set *);

#endif /* _BCACHE_COMPRESS_H */
