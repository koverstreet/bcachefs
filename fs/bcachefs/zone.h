/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ZONE_H
#define _BCACHEFS_ZONE_H

static inline bool blk_zone_writeable(struct blk_zone zone)
{
	return (zone.cond == BLK_ZONE_COND_EMPTY ||
		zone.cond == BLK_ZONE_COND_IMP_OPEN ||
		zone.cond == BLK_ZONE_COND_EXP_OPEN ||
		zone.cond == BLK_ZONE_COND_CLOSED);
}

int bch2_zone_report(struct block_device *, sector_t, struct blk_zone *);
void bch2_bucket_discard(struct bch_dev *, u64);
void bch2_bucket_finish(struct bch_dev *, u64);

#endif /* _BCACHEFS_ZONE_H */
