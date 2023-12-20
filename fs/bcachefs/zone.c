// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "buckets.h"
#include "eytzinger.h"
#include "zone.h"

#include <linux/blkdev.h>

static int zone_report_cb(struct blk_zone *src, unsigned idx, void *data)
{
	struct blk_zone *dst = data;

	*dst = *src;
	return 0;
}

static int bch2_zone_report(struct block_device *bdev, sector_t sector, struct blk_zone *zone)
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

void bch2_dev_zones_exit(struct bch_dev *ca)
{
	kfree(ca->buckets.d);
}

static int zone_report_capacity(struct blk_zone *src, unsigned idx, void *data)
{
	struct bucket_capacities *b = data;

	if (b->nr &&
	    b->d[b->nr - 1].sectors == src->capacity)
		return 0;

	if (b->nr == b->size) {
		size_t new_size = min(b->size * 2, 8U);
		struct bucket_capacity *d =
			krealloc_array(b->d, new_size, sizeof(*d), GFP_KERNEL);
		if (!d)
			return -ENOMEM;

		b->d	= d;
		b->size = new_size;
	}

	b->d[b->nr++] = (struct bucket_capacity) {
		.start		= idx,
		.sectors	= src->capacity,
	};

	return 0;
}

int bch2_dev_zones_init(struct bch_dev *ca, struct bch_sb_handle *sb)
{
	struct bucket_capacities *b = &ca->buckets;
	struct blk_zone zone;
	unsigned i;
	int ret;

	ca->zoned = bdev_nr_zones(sb->bdev) != 0;
	if (!ca->zoned) {
		ca->capacity = ca->mi.bucket_size * ca->mi.nbuckets;
		return 0;
	}

	ret = bch2_zone_report(sb->bdev, 0, &zone);
	if (ret)
		return ret;

	if (zone.len != ca->mi.bucket_size) {
		bch_err(ca, "zone size doesn't match bucket size");
		return -EINVAL;
	}

	if (bdev_nr_zones(sb->bdev) < ca->mi.nbuckets) {
		bch_err(ca, "member info nbuckets (%llu) greater than number of zones (%u)",
			ca->mi.nbuckets,
			bdev_nr_zones(sb->bdev));
		return -EINVAL;
	}

	b->nr = 0;
	ret = blkdev_report_zones(sb->bdev, 0, ca->mi.nbuckets,
				  zone_report_capacity, &ca->buckets);
	if (ret) {
		bch_err(ca, "error getting zone capacities");
		return -EINVAL;
	}

	ca->capacity = 0;
	for (i = 0; i < b->nr; i++) {
		u64 next = i + 1 < b->nr
			? b->d[i + 1].start
			: ca->mi.nbuckets;

		ca->capacity += (next - b->d[i].start) * b->d[i].sectors;
	}

	BUG_ON(ca->capacity > ca->mi.bucket_size * ca->mi.nbuckets);

	eytzinger0_sort(b->d, b->nr, sizeof(*b->d), bucket_capacity_cmp, NULL);

	return 0;
}
