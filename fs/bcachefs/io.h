#ifndef _BCACHE_IO_H
#define _BCACHE_IO_H

#include "io_types.h"

#include <linux/zlib.h>

#define COMPRESSION_WORKSPACE_SIZE					\
	max(zlib_deflate_workspacesize(MAX_WBITS, MAX_MEM_LEVEL),	\
	    zlib_inflate_workspacesize())

#define to_bbio(_bio)		container_of((_bio), struct bbio, bio)

#define to_wbio(_bio)			\
	container_of((_bio), struct bch_write_bio, bio.bio)

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

struct extent_pick_ptr;

void bch_read_extent(struct cache_set *, struct bio *, struct bkey_s_c,
		     struct extent_pick_ptr *, unsigned, unsigned);

enum bch_read_flags {
	BCH_READ_FORCE_BOUNCE		= 1 << 0,
	BCH_READ_RETRY_IF_STALE		= 1 << 1,
	BCH_READ_PROMOTE		= 1 << 2,
};

int bch_read(struct cache_set *, struct bio *, u64);

void bch_bbio_endio(struct bbio *);

void bch_generic_make_request(struct bio *, struct cache_set *);
void bch_bio_submit_work(struct work_struct *);
void bch_submit_bbio(struct bbio *, struct cache *,
		     const struct bch_extent_ptr *, bool);
void bch_submit_bbio_replicas(struct bch_write_bio *, struct cache_set *,
			      const struct bkey_i *, unsigned, bool);

int bch_discard(struct cache_set *, struct bpos, struct bpos, u64, u64 *);

void __cache_promote(struct cache_set *, struct bbio *,
		     struct bkey_s_c, struct bkey_s_c, unsigned);
bool cache_promote(struct cache_set *, struct bbio *, struct bkey_s_c);

void bch_read_race_work(struct work_struct *);
void bch_wake_delayed_writes(unsigned long data);

void bch_bio_decompress_work(struct work_struct *);

extern struct workqueue_struct *bcache_io_wq;

#endif /* _BCACHE_IO_H */
