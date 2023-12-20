// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "buckets.h"
#include "zone.h"

#include <linux/blkdev.h>

static int zone_report_cb(struct blk_zone *src, unsigned int idx, void *data)
{
	struct blk_zone *dst = data;

	*dst = *src;
	return 0;
}

int bch2_zone_report(struct block_device *bdev, sector_t sector, struct blk_zone *zone)
{
	int ret = blkdev_report_zones(bdev, sector, 1, zone_report_cb, zone);

	if (ret)
		pr_err("error getting zone %u: %i", 0, ret);
	return ret;
}

void bch2_bucket_discard(struct bch_dev *ca, u64 b)
{
	struct bch_fs *c = ca->fs;

	if (c->opts.nochanges)
		return;

	if (ca->mi.discard &&
	    bdev_max_discard_sectors(ca->disk_sb.bdev))
		blkdev_issue_discard(ca->disk_sb.bdev,
				     bucket_to_sector(ca, b),
				     ca->mi.bucket_size, GFP_NOFS);

	if (ca->zoned)
		blkdev_zone_mgmt(ca->disk_sb.bdev, REQ_OP_ZONE_RESET,
				 bucket_to_sector(ca, b),
				 ca->mi.bucket_size, GFP_NOFS);
}

void bch2_bucket_finish(struct bch_dev *ca, u64 b)
{
	struct bch_fs *c = ca->fs;

	if (c->opts.nochanges || !ca->zoned)
		return;

	blkdev_zone_mgmt(ca->disk_sb.bdev, REQ_OP_ZONE_FINISH,
			 bucket_to_sector(ca, b),
			 ca->mi.bucket_size, GFP_KERNEL);
}
