/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ZONE_H
#define _BCACHEFS_ZONE_H

#include "eytzinger.h"

static inline bool blk_zone_writeable(struct blk_zone zone)
{
	return (zone.cond == BLK_ZONE_COND_EMPTY ||
		zone.cond == BLK_ZONE_COND_IMP_OPEN ||
		zone.cond == BLK_ZONE_COND_EXP_OPEN ||
		zone.cond == BLK_ZONE_COND_CLOSED);
}

static inline int bucket_capacity_cmp(const void *_l, const void *_r, size_t size)
{
	const struct bucket_capacity *l = _l;
	const struct bucket_capacity *r = _r;

	return cmp_int(l->start, r->start);
}

static inline unsigned bucket_capacity(struct bch_dev *ca, size_t bucket)
{
	struct bucket_capacities *b = &ca->buckets;
	struct bucket_capacity search = { .start = bucket };
	ssize_t idx;

	if (!ca->zoned)
		return ca->mi.bucket_size;

	idx = eytzinger0_find_le(b->d, b->nr,
				 sizeof(b->d[0]),
				 bucket_capacity_cmp, &search);

	{
		ssize_t j = -1, k;

		for (k = 0; k < b->nr; k++)
			if (b->d[k].start <= bucket &&
			    (j < 0 || b->d[k].start > b->d[j].start))
				j = k;

		BUG_ON(idx != j);
	}

	return b->d[idx].sectors;
}

void bch2_bucket_discard(struct bch_dev *, u64);
void bch2_bucket_finish(struct bch_dev *, u64);
void bch2_dev_zones_exit(struct bch_dev *);
int bch2_dev_zones_init(struct bch_dev *, struct bch_sb_handle *);

#endif /* _BCACHEFS_ZONE_H */
