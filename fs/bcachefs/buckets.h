/*
 * Code for manipulating bucket marks for garbage collection.
 *
 * Copyright 2014 Datera, Inc.
 */

#ifndef _BUCKETS_H
#define _BUCKETS_H

#include "bcache.h"

/* The dirty and cached sector counts saturate. If this occurs,
 * reference counting alone will not free the bucket, and a btree
 * GC must be performed. */
#define GC_MAX_SECTORS_USED ((1U << 15) - 1)

static inline bool bucket_unused(struct bucket *b)
{
	return !b->mark.counter;
}

static inline unsigned bucket_sectors_used(struct bucket *b)
{
	return b->mark.dirty_sectors + b->mark.cached_sectors;
}

void bch_mark_free_bucket(struct cache *, struct bucket *);
void bch_mark_alloc_bucket(struct cache *, struct bucket *);
void bch_mark_metadata_bucket(struct cache *, struct bucket *);
void bch_mark_data_bucket(struct cache *, struct bucket *, int, bool);

#endif
