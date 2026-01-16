/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ALLOC_DISCARD_H
#define _BCACHEFS_ALLOC_DISCARD_H

#include "alloc/buckets.h"

void bch2_discard_one_bucket_fast(struct bch_dev *, u64);

void bch2_dev_do_discards(struct bch_dev *);
void bch2_do_discards_going_ro(struct bch_fs *);
void bch2_do_discards(struct bch_fs *);

static inline u64 should_invalidate_buckets(struct bch_dev *ca,
					    struct bch_dev_usage u)
{
	u64 want_free = ca->mi.nbuckets >> 5;
	u64 free = max_t(s64, 0,
			   u.buckets[BCH_DATA_free]
			 + u.buckets[BCH_DATA_need_discard]
			 - bch2_dev_buckets_reserved(ca, BCH_WATERMARK_stripe));

	return clamp_t(s64, want_free - free, 0, u.buckets[BCH_DATA_cached]);
}

void bch2_dev_do_invalidates(struct bch_dev *);
void bch2_do_invalidates(struct bch_fs *);

void bch2_do_discards_work(struct work_struct *);
void bch2_do_discards_fast_work(struct work_struct *);
void bch2_do_invalidates_work(struct work_struct *);

#endif /* _BCACHEFS_ALLOC_DISCARD_H */
