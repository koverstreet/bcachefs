/*
 * bcache setup/teardown code, and some metadata io - read a superblock and
 * figure out what to do with it.
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "blockdev.h"
#include "alloc.h"
#include "btree.h"
#include "debug.h"
#include "inode.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "movinggc.h"
#include "stats.h"
#include "super.h"
#include "tier.h"
#include "writeback.h"

#include <linux/blkdev.h>
#include <linux/crc32c.h>
#include <linux/debugfs.h>
#include <linux/genhd.h>
#include <linux/idr.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/reboot.h>
#include <linux/sysfs.h>

#include <trace/events/bcachefs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kent Overstreet <kent.overstreet@gmail.com>");

static const uuid_le invalid_uuid = {
	.b = {
		0xa0, 0x3e, 0xf8, 0xed, 0x3e, 0xe1, 0xb8, 0x78,
		0xc8, 0x50, 0xfc, 0x5e, 0xcb, 0x16, 0xcd, 0x99
	}
};

static struct kobject *bcache_kobj;
struct mutex bch_register_lock;
LIST_HEAD(bch_cache_sets);

struct workqueue_struct *bcache_io_wq;

static void bch_cache_stop(struct cache *);

u64 bch_checksum_update(unsigned type, u64 crc, const void *data, size_t len)
{
	switch (type) {
	case BCH_CSUM_NONE:
		return 0;
	case BCH_CSUM_CRC32C:
		return crc32c(crc, data, len);
	case BCH_CSUM_CRC64:
		return bch_crc64_update(crc, data, len);
	default:
		BUG();
	}
}

u64 bch_checksum(unsigned type, const void *data, size_t len)
{
	u64 crc = 0xffffffffffffffffULL;

	crc = bch_checksum_update(type, crc, data, len);

	return crc ^ 0xffffffffffffffffULL;
}

static bool bch_is_open_cache(struct block_device *bdev)
{
	struct cache_set *c, *tc;
	struct cache *ca;
	unsigned i;

	rcu_read_lock();
	list_for_each_entry_safe(c, tc, &bch_cache_sets, list)
		for_each_cache_rcu(ca, c, i)
			if (ca->bdev == bdev) {
				rcu_read_unlock();
				return true;
			}
	rcu_read_unlock();
	return false;
}

static bool bch_is_open(struct block_device *bdev)
{
	bool ret;

	mutex_lock(&bch_register_lock);
	ret = bch_is_open_cache(bdev) || bch_is_open_backing(bdev);
	mutex_unlock(&bch_register_lock);

	return ret;
}

static const char *bch_blkdev_open(const char *path, void *holder,
				   struct block_device **ret)
{
	struct block_device *bdev;
	const char *err;

	*ret = NULL;
	bdev = blkdev_get_by_path(path, FMODE_READ|FMODE_WRITE|FMODE_EXCL,
				  holder);

	if (bdev == ERR_PTR(-EBUSY)) {
		bdev = lookup_bdev(path);
		if (IS_ERR(bdev))
			return "device busy";

		err = bch_is_open(bdev)
			? "device already registered"
			: "device busy";

		bdput(bdev);
		return err;
	}

	if (IS_ERR(bdev))
		return "failed to open device";

	*ret = bdev;
	return NULL;
}

/* Superblock */

const char *validate_super(struct bcache_superblock *disk_sb,
			   struct block_device *bdev,
			   struct cache_sb *sb)
{
	const char *err;
	struct cache_sb *s = disk_sb->sb;

	sb->offset		= le64_to_cpu(s->offset);
	sb->version		= le64_to_cpu(s->version);

	sb->magic		= s->magic;
	sb->uuid		= s->uuid;
	sb->set_uuid		= s->set_uuid;
	memcpy(sb->label,	s->label, SB_LABEL_SIZE);

	sb->flags		= le64_to_cpu(s->flags);
	sb->seq			= le64_to_cpu(s->seq);
	sb->block_size		= le16_to_cpu(s->block_size);
	sb->last_mount		= le32_to_cpu(s->last_mount);
	sb->first_bucket	= le16_to_cpu(s->first_bucket);
	sb->keys		= le16_to_cpu(s->keys);

	switch (sb->version) {
	case BCACHE_SB_VERSION_BDEV:
		sb->data_offset	= BDEV_DATA_START_DEFAULT;
		break;
	case BCACHE_SB_VERSION_BDEV_WITH_OFFSET:
		sb->data_offset	= le64_to_cpu(s->data_offset);

		err = "Bad data offset";
		if (sb->data_offset < BDEV_DATA_START_DEFAULT)
			goto err;

		break;
	case BCACHE_SB_VERSION_CDEV_V0:
	case BCACHE_SB_VERSION_CDEV_WITH_UUID:
	case BCACHE_SB_VERSION_CDEV_V2:
	case BCACHE_SB_VERSION_CDEV_V3:
		sb->nbuckets	= le64_to_cpu(s->nbuckets);
		sb->bucket_size	= le16_to_cpu(s->bucket_size);

		sb->nr_in_set	= le16_to_cpu(s->nr_in_set);
		sb->nr_this_dev	= le16_to_cpu(s->nr_this_dev);

		err = "Too many buckets";
		if (sb->nbuckets > LONG_MAX)
			goto err;

		err = "Not enough buckets";
		if (sb->nbuckets < 1 << 8)
			goto err;

		err = "Bad block/bucket size";
		if (!is_power_of_2(sb->block_size) ||
		    sb->block_size > PAGE_SECTORS ||
		    !is_power_of_2(sb->bucket_size) ||
		    sb->bucket_size < PAGE_SECTORS)
			goto err;

		err = "Invalid superblock: device too small";
		if (get_capacity(bdev->bd_disk) < sb->bucket_size * sb->nbuckets)
			goto err;

		err = "Bad UUID";
		if (bch_is_zero(sb->set_uuid.b, sizeof(sb->set_uuid)))
			goto err;

		err = "Bad cache device number in set";
		if (!sb->nr_in_set ||
		    sb->nr_in_set <= sb->nr_this_dev ||
		    sb->nr_in_set > MAX_CACHES_PER_SET)
			goto err;

		err = "Invalid superblock: first bucket comes before end of super";
		if (sb->first_bucket * sb->bucket_size < 16)
			goto err;

		err = "Invalid superblock: member info area missing";
		if (sb->keys < bch_journal_buckets_offset(sb))
			goto err;

		err = "Invalid number of metadata replicas";
		if (!CACHE_SET_META_REPLICAS_WANT(sb) ||
		    CACHE_SET_META_REPLICAS_WANT(sb) >= BKEY_EXTENT_PTRS_MAX)
			goto err;

		err = "Invalid number of data replicas";
		if (!CACHE_SET_DATA_REPLICAS_WANT(sb) ||
		    CACHE_SET_DATA_REPLICAS_WANT(sb) >= BKEY_EXTENT_PTRS_MAX)
			goto err;

		err = "Invalid checksum type";
		if (CACHE_SB_CSUM_TYPE(sb) >= BCH_CSUM_NR)
			goto err;

		err = "Btree node size not set";
		if (!CACHE_BTREE_NODE_SIZE(sb))
			goto err;

		break;
	default:
		err = "Unsupported superblock version";
		goto err;
	}

	sb->last_mount = get_seconds();
	return NULL;
err:
	return err;
}

static void free_super(struct bcache_superblock *sb)
{
	if (sb->bio)
		bio_put(sb->bio);
	sb->bio = NULL;

	free_pages((unsigned long) sb->sb, sb->page_order);
	sb->sb = NULL;
}

static int __bch_super_realloc(struct bcache_superblock *sb, unsigned order)
{
	struct cache_sb *new_sb;
	struct bio *bio;

	if (sb->page_order >= order && sb->sb)
		return 0;

	new_sb = (void *) __get_free_pages(GFP_KERNEL, order);
	if (!new_sb)
		return -ENOMEM;

	bio = bio_kmalloc(GFP_KERNEL, 1 << order);
	if (!bio) {
		free_pages((unsigned long) new_sb, order);
		return -ENOMEM;
	}

	if (sb->sb)
		memcpy(new_sb, sb->sb, PAGE_SIZE << sb->page_order);

	free_pages((unsigned long) sb->sb, sb->page_order);
	sb->sb = new_sb;

	if (sb->bio)
		bio_put(sb->bio);
	sb->bio = bio;

	sb->page_order = order;

	return 0;
}

int bch_super_realloc(struct cache *ca, unsigned keys)
{
	char buf[BDEVNAME_SIZE];
	size_t bytes = __set_bytes((struct cache_sb *) NULL, keys);
	size_t want = bytes + (SB_SECTOR << 9);

	if (want > ca->sb.first_bucket * bucket_bytes(ca)) {
		pr_err("%s: superblock too big: want %zu but have %u",
		       bdevname(ca->bdev, buf), want,
		       ca->sb.first_bucket * bucket_bytes(ca));
		return -ENOSPC;
	}

	return __bch_super_realloc(&ca->disk_sb, get_order(bytes));
}

static const char *read_super(struct block_device *bdev,
			      struct bcache_superblock *sb)
{
	unsigned order = 0;

	memset(sb, 0, sizeof(*sb));
retry:
	if (__bch_super_realloc(sb, order))
		return "cannot allocate memory";

	sb->bio->bi_bdev = bdev;
	sb->bio->bi_iter.bi_sector = SB_SECTOR;
	sb->bio->bi_iter.bi_size = PAGE_SIZE << sb->page_order;
	bio_set_op_attrs(sb->bio, REQ_OP_READ, REQ_SYNC|REQ_META);
	bch_bio_map(sb->bio, sb->sb);

	if (submit_bio_wait(sb->bio))
		return "IO error";

	if (le64_to_cpu(sb->sb->offset) != SB_SECTOR)
		return "Not a bcache superblock";

	if (uuid_le_cmp(sb->sb->magic, BCACHE_MAGIC))
		return "Not a bcache superblock";

	if (bch_is_zero(sb->sb->uuid.b, sizeof(sb->sb->uuid)))
		return "Bad UUID";

	pr_debug("read sb version %llu, flags %llu, seq %llu, journal size %u",
		 le64_to_cpu(sb->sb->version),
		 le64_to_cpu(sb->sb->flags),
		 le64_to_cpu(sb->sb->seq),
		 le16_to_cpu(sb->sb->keys));

	if (le16_to_cpu(sb->sb->block_size) << 9 <
	    bdev_logical_block_size(bdev))
		return "Superblock block size smaller than device block size";

	order = get_order(__set_bytes(sb->sb, le16_to_cpu(sb->sb->keys)));
	if (order > sb->page_order)
		goto retry;

	if (sb->sb->csum != csum_set(sb->sb,
				     le64_to_cpu(sb->sb->version) <
				     BCACHE_SB_VERSION_CDEV_V3
				     ? BCH_CSUM_CRC64
				     : CACHE_SB_CSUM_TYPE(sb->sb)))
		return "Bad checksum";

	if (cache_set_init_fault("read_super"))
		return "dynamic fault";

	return NULL;
}

void __write_super(struct cache_set *c, struct bcache_superblock *disk_sb,
		   struct block_device *bdev, struct cache_sb *sb)
{
	struct cache_sb *out = disk_sb->sb;
	struct bio *bio = disk_sb->bio;

	bio->bi_bdev		= bdev;
	bio->bi_iter.bi_sector	= SB_SECTOR;
	bio->bi_iter.bi_size	= roundup(set_bytes(sb),
					  bdev_logical_block_size(bdev));
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_SYNC|REQ_META);
	bch_bio_map(bio, out);

	out->offset		= cpu_to_le64(sb->offset);
	out->version		= cpu_to_le64(sb->version);

	out->uuid		= sb->uuid;
	out->set_uuid		= sb->set_uuid;
	memcpy(out->label,	sb->label, SB_LABEL_SIZE);

	out->flags		= cpu_to_le64(sb->flags);
	out->seq		= cpu_to_le64(sb->seq);

	out->last_mount		= cpu_to_le32(sb->last_mount);
	out->first_bucket	= cpu_to_le16(sb->first_bucket);
	out->keys		= cpu_to_le16(sb->keys);
	out->csum		=
		csum_set(out, sb->version < BCACHE_SB_VERSION_CDEV_V3
			 ? BCH_CSUM_CRC64
			 : CACHE_SB_CSUM_TYPE(sb));

	pr_debug("ver %llu, flags %llu, seq %llu",
		 sb->version, sb->flags, sb->seq);

	bch_generic_make_request(bio, c);
}

static void write_super_endio(struct bio *bio)
{
	struct cache *ca = bio->bi_private;

	bch_count_io_errors(ca, bio->bi_error, "writing superblock");
	closure_put(&ca->set->sb_write);
	percpu_ref_put(&ca->ref);
}

static void bcache_write_super_unlock(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, sb_write);

	up(&c->sb_write_mutex);
}

static int cache_sb_to_cache_set(struct cache_set *c, struct cache *ca)
{
	struct cache_member_rcu *new, *old = c->members;

	new = kzalloc(sizeof(struct cache_member_rcu) +
		      sizeof(struct cache_member) * ca->sb.nr_in_set,
		      GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	new->nr_in_set = ca->sb.nr_in_set;
	memcpy(&new->m, ca->disk_sb.sb->d,
	       ca->sb.nr_in_set * sizeof(new->m[0]));

	rcu_assign_pointer(c->members, new);
	if (old)
		kfree_rcu(old, rcu);

	c->sb.version		= ca->sb.version;
	c->sb.set_uuid		= ca->sb.set_uuid;
	c->sb.flags		= ca->sb.flags;
	c->sb.seq		= ca->sb.seq;
	c->sb.block_size	= ca->sb.block_size;
	c->sb.bucket_size	= ca->sb.bucket_size;
	c->sb.nr_in_set		= ca->sb.nr_in_set;
	c->sb.last_mount	= ca->sb.last_mount;

	pr_debug("set version = %llu", c->sb.version);
	return 0;
}

static int cache_sb_from_cache_set(struct cache_set *c, struct cache *ca)
{
	struct cache_member_rcu *mi;

	if (ca->sb.nr_in_set != c->sb.nr_in_set) {
		unsigned old_offset = bch_journal_buckets_offset(&ca->sb);
		unsigned keys = bch_journal_buckets_offset(&c->sb)
			+ bch_nr_journal_buckets(&ca->sb);
		int ret = bch_super_realloc(ca, keys);

		if (ret)
			return ret;

		ca->sb.nr_in_set = c->sb.nr_in_set;
		ca->sb.keys = keys;

		memmove(__journal_buckets(ca),
			ca->disk_sb.sb->d + old_offset,
			bch_nr_journal_buckets(&ca->sb) * sizeof(u64));
	}

	mi = cache_member_info_get(c);
	ca->mi = mi->m[ca->sb.nr_this_dev];

	memcpy(ca->disk_sb.sb->d, mi->m, mi->nr_in_set * sizeof(mi->m[0]));
	cache_member_info_put();

	ca->sb.version		= BCACHE_SB_VERSION_CDEV;
	ca->sb.flags		= c->sb.flags;
	ca->sb.seq		= c->sb.seq;
	ca->sb.nr_in_set	= c->sb.nr_in_set;
	ca->sb.last_mount	= c->sb.last_mount;

	return 0;
}

static void __bcache_write_super(struct cache_set *c)
{
	struct closure *cl = &c->sb_write;
	struct cache *ca;
	unsigned i;

	closure_init(cl, &c->cl);

	c->sb.seq++;

	for_each_cache(ca, c, i) {
		struct bio *bio = ca->disk_sb.bio;

		cache_sb_from_cache_set(c, ca);

		SET_CACHE_SB_CSUM_TYPE(&ca->sb,
				       CACHE_PREFERRED_CSUM_TYPE(&c->sb));

		bio_reset(bio);
		bio->bi_bdev	= ca->bdev;
		bio->bi_end_io	= write_super_endio;
		bio->bi_private = ca;

		closure_get(cl);
		percpu_ref_get(&ca->ref);
		__write_super(c, &ca->disk_sb, ca->bdev, &ca->sb);
	}

	closure_return_with_destructor(cl, bcache_write_super_unlock);
}

void bcache_write_super(struct cache_set *c)
{
	down(&c->sb_write_mutex);
	__bcache_write_super(c);
}

void bch_check_mark_super_slowpath(struct cache_set *c, struct bkey *k,
				   bool meta)
{
	unsigned ptr;
	struct cache_member *mi;

	down(&c->sb_write_mutex);

	/* recheck, might have raced */
	if (bch_check_super_marked(c, k, meta)) {
		up(&c->sb_write_mutex);
		return;
	}

	mi = cache_member_info_get(c)->m;

	for (ptr = 0; ptr < bch_extent_ptrs(k); ptr++)
		(meta
		 ? SET_CACHE_HAS_METADATA
		 : SET_CACHE_HAS_DATA)(mi + PTR_DEV(k, ptr), true);

	cache_member_info_put();

	__bcache_write_super(c);
}

/* Cache set */

static void bch_recalc_capacity(struct cache_set *c)
{
	struct cache_group *tier = c->cache_tiers + ARRAY_SIZE(c->cache_tiers);
	u64 capacity = 0;
	unsigned i;

	while (--tier >= c->cache_tiers)
		if (tier->nr_devices) {
			for (i = 0; i < tier->nr_devices; i++) {
				struct cache *ca = tier->devices[i];

				capacity += (ca->sb.nbuckets -
					     ca->sb.first_bucket) <<
					c->bucket_bits;

				ca->reserve_buckets_count =
					div_u64((ca->sb.nbuckets -
						 ca->sb.first_bucket) *
						c->bucket_reserve_percent, 100);

			}

			capacity *= (100 - c->sector_reserve_percent);
			capacity = div64_u64(capacity, 100);
			break;
		}

	c->capacity = capacity;

	/* Wake up case someone was waiting for buckets */
	closure_wake_up(&c->freelist_wait);
	closure_wake_up(&c->buckets_available_wait);
}

static void __bch_cache_read_only(struct cache *ca);

static void bch_cache_set_read_only(struct cache_set *c)
{
	struct cached_dev *dc;
	struct bcache_device *d;
	struct radix_tree_iter iter;
	void **slot;

	struct cache *ca;
	unsigned i;

	lockdep_assert_held(&bch_register_lock);

	if (test_and_set_bit(CACHE_SET_RO, &c->flags))
		return;

	trace_bcache_cache_set_read_only(c);

	bch_wake_delayed_writes((unsigned long) c);
	del_timer_sync(&c->foreground_write_wakeup);
	cancel_delayed_work_sync(&c->pd_controllers_update);

	rcu_read_lock();

	radix_tree_for_each_slot(slot, &c->devices, &iter, 0) {
		d = radix_tree_deref_slot(slot);

		if (!INODE_FLASH_ONLY(&d->inode)) {
			dc = container_of(d, struct cached_dev, disk);
			bch_cached_dev_writeback_stop(dc);
		}
	}

	rcu_read_unlock();

	c->tiering_pd.rate.rate = UINT_MAX;
	bch_ratelimit_reset(&c->tiering_pd.rate);
	bch_tiering_stop(c);

	if (!IS_ERR_OR_NULL(c->gc_thread))
		kthread_stop(c->gc_thread);

	for_each_cache(ca, c, i)
		__bch_cache_read_only(ca);

	/* Should skip this if we're unregistering because of an error */
	bch_btree_flush(c);

	if (c->journal.cur) {
		cancel_delayed_work_sync(&c->journal.work);
		/* flush last journal entry if needed */
		c->journal.work.work.func(&c->journal.work.work);
	}

	trace_bcache_cache_set_read_only_done(c);
}

void bch_cache_set_fail(struct cache_set *c)
{
	switch (CACHE_ERROR_ACTION(&c->sb)) {
	case BCH_ON_ERROR_CONTINUE:
		break;
	case BCH_ON_ERROR_RO:
		pr_err("%pU going read only", c->sb.set_uuid.b);
		bch_cache_set_read_only(c);
		break;
	case BCH_ON_ERROR_PANIC:
		panic("bcache: %pU panic after error\n",
		      c->sb.set_uuid.b);
		break;
	}
}

void bch_cache_set_release(struct kobject *kobj)
{
	struct cache_set *c = container_of(kobj, struct cache_set, kobj);
	kfree(c);
	module_put(THIS_MODULE);
}

static void cache_set_free(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, cl);
	struct cache *ca;
	unsigned i;

	if (!IS_ERR_OR_NULL(c->debug))
		debugfs_remove(c->debug);

	bch_btree_cache_free(c);
	bch_journal_free(c);

	mutex_lock(&bch_register_lock);
	for_each_cache(ca, c, i)
		bch_cache_stop(ca);
	mutex_unlock(&bch_register_lock);

	bch_bset_sort_state_free(&c->sort);

	free_percpu(c->prio_clock[WRITE].rescale_percpu);
	free_percpu(c->prio_clock[READ].rescale_percpu);
	if (c->wq)
		destroy_workqueue(c->wq);
	if (c->bio_split)
		bioset_free(c->bio_split);
	mempool_destroy(c->fill_iter);
	mempool_destroy(c->bio_meta);
	mempool_destroy(c->search);

	mutex_lock(&bch_register_lock);
	list_del(&c->list);
	mutex_unlock(&bch_register_lock);

	pr_info("Cache set %pU unregistered", c->sb.set_uuid.b);

	closure_debug_destroy(&c->cl);
	kobject_put(&c->kobj);
}

static void cache_set_flush(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);

	mutex_lock(&bch_register_lock);
	bch_cache_set_read_only(c);
	mutex_unlock(&bch_register_lock);

	bch_cache_accounting_destroy(&c->accounting);

	kobject_put(&c->internal);
	kobject_del(&c->kobj);

	closure_return(cl);
}

static void __cache_set_unregister(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);
	struct cached_dev *dc;
	struct bcache_device *d;
	struct radix_tree_iter iter;
	void **slot;

	mutex_lock(&bch_register_lock);

	rcu_read_lock();

	radix_tree_for_each_slot(slot, &c->devices, &iter, 0) {
		d = radix_tree_deref_slot(slot);

		if (!INODE_FLASH_ONLY(&d->inode) &&
		    test_bit(CACHE_SET_UNREGISTERING, &c->flags)) {
			dc = container_of(d, struct cached_dev, disk);
			bch_cached_dev_detach(dc);
		} else {
			bcache_device_stop(d);
		}
	}

	rcu_read_unlock();

	mutex_unlock(&bch_register_lock);

	continue_at(cl, cache_set_flush, system_wq);
}

void bch_cache_set_stop(struct cache_set *c)
{
	if (!test_and_set_bit(CACHE_SET_STOPPING, &c->flags))
		closure_queue(&c->caching);
}

void bch_cache_set_unregister(struct cache_set *c)
{
	if (!test_and_set_bit(CACHE_SET_UNREGISTERING, &c->flags))
		bch_cache_set_stop(c);
}

static unsigned cache_set_nr_devices(struct cache_set *c)
{
	unsigned i, nr = 0;
	struct cache_member_rcu *mi = cache_member_info_get(c);

	for (i = 0; i < mi->nr_in_set; i++)
		if (!bch_is_zero(mi->m[i].uuid.b, sizeof(uuid_le)))
			nr++;

	cache_member_info_put();

	return nr;
}

static unsigned cache_set_nr_online_devices(struct cache_set *c)
{
	unsigned i, nr = 0;

	for (i = 0; i < c->sb.nr_in_set; i++)
		if (c->cache[i])
			nr++;

	return nr;
}

#define alloc_bucket_pages(gfp, c)			\
	((void *) __get_free_pages(__GFP_ZERO|gfp, ilog2(bucket_pages(c))))

static struct cache_set *bch_cache_set_alloc(struct cache *ca)
{
	int iter_size;
	struct cache_set *c = kzalloc(sizeof(struct cache_set), GFP_KERNEL);
	if (!c)
		return NULL;

	__module_get(THIS_MODULE);
	closure_init(&c->cl, NULL);
	set_closure_fn(&c->cl, cache_set_free, system_wq);

	closure_init(&c->caching, &c->cl);
	set_closure_fn(&c->caching, __cache_set_unregister, system_wq);

	/* Maybe create continue_at_noreturn() and use it here? */
	closure_set_stopped(&c->cl);
	closure_put(&c->cl);

	kobject_init(&c->kobj, &bch_cache_set_ktype);
	kobject_init(&c->internal, &bch_cache_set_internal_ktype);

	bch_cache_accounting_init(&c->accounting, &c->cl);

	if (cache_sb_to_cache_set(c, ca))
		goto err;

	c->bucket_bits		= ilog2(c->sb.bucket_size);
	c->block_bits		= ilog2(c->sb.block_size);
	c->btree_pages		= CACHE_BTREE_NODE_SIZE(&c->sb) / PAGE_SECTORS;

	sema_init(&c->sb_write_mutex, 1);
	INIT_RADIX_TREE(&c->devices, GFP_KERNEL);
	mutex_init(&c->btree_cache_lock);
	mutex_init(&c->bucket_lock);
	init_rwsem(&c->gc_lock);
	spin_lock_init(&c->btree_root_lock);

	spin_lock_init(&c->btree_gc_time.lock);
	spin_lock_init(&c->btree_split_time.lock);
	spin_lock_init(&c->btree_read_time.lock);

	bch_open_buckets_init(c);
	bch_tiering_init_cache_set(c);

	INIT_LIST_HEAD(&c->list);
	INIT_LIST_HEAD(&c->cached_devs);
	INIT_LIST_HEAD(&c->btree_cache);
	INIT_LIST_HEAD(&c->btree_cache_freeable);
	INIT_LIST_HEAD(&c->btree_cache_freed);

	INIT_WORK(&c->bio_submit_work, bch_bio_submit_work);
	spin_lock_init(&c->bio_submit_lock);

	bio_list_init(&c->read_race_list);
	spin_lock_init(&c->read_race_lock);
	INIT_WORK(&c->read_race_work, bch_read_race_work);

	seqlock_init(&c->gc_cur_lock);
	c->gc_cur_btree = BTREE_ID_NR;

	c->prio_clock[READ].hand = 1;
	c->prio_clock[READ].min_prio = 0;
	c->prio_clock[WRITE].hand = 1;
	c->prio_clock[WRITE].min_prio = 0;

	c->congested_read_threshold_us	= 2000;
	c->congested_write_threshold_us	= 20000;
	c->error_limit	= 16 << IO_ERROR_SHIFT;

	c->btree_flush_delay = 30;

	c->btree_scan_ratelimit = 30;

	c->copy_gc_enabled = 1;
	c->tiering_enabled = 1;
	c->tiering_percent = 10;

	c->foreground_target_percent = 20;
	c->bucket_reserve_percent = 10;
	c->sector_reserve_percent = 20;

	c->search = mempool_create_slab_pool(32, bch_search_cache);
	if (!c->search)
		goto err;

	iter_size = (c->sb.bucket_size / c->sb.block_size + 1) *
		sizeof(struct btree_node_iter_set);

	if (!(c->bio_meta = mempool_create_kmalloc_pool(2,
				sizeof(struct bbio) + sizeof(struct bio_vec) *
				bucket_pages(c))) ||
	    !(c->fill_iter = mempool_create_kmalloc_pool(1, iter_size)) ||
	    !(c->bio_split = bioset_create(4, offsetof(struct bbio, bio))) ||
	    !(c->wq = alloc_workqueue("bcache", WQ_MEM_RECLAIM, 0)) ||
	    !(c->prio_clock[READ].rescale_percpu = alloc_percpu(unsigned)) ||
	    !(c->prio_clock[WRITE].rescale_percpu = alloc_percpu(unsigned)) ||
	    bch_journal_alloc(c) ||
	    bch_btree_cache_alloc(c) ||
	    bch_bset_sort_state_init(&c->sort, ilog2(c->btree_pages)))
		goto err;

	return c;
err:
	bch_cache_set_unregister(c);
	return NULL;
}

static const char *__bch_cache_read_write(struct cache *ca);

static const char *run_cache_set(struct cache_set *c)
{
	const char *err = "cannot allocate memory";
	struct cache_member_rcu *mi;
	struct cached_dev *dc, *t;
	struct cache *ca;
	struct closure cl;
	unsigned i, id;
	int ret;

	BUG_ON(test_bit(CACHE_SET_RUNNING, &c->flags));

	closure_init_stack(&cl);

	/* We don't want bch_cache_set_error() to free underneath us */
	closure_get(&c->caching);

	/*
	 * Make sure that each cache object's mi is up to date before
	 * we start testing it.
	 */

	mi = cache_member_info_get(c);
	for_each_cache(ca, c, i)
		ca->mi = mi->m[ca->sb.nr_this_dev];
	cache_member_info_put();

	/*
	 * CACHE_SYNC is true if the cache set has already been run
	 * and potentially has data.
	 * It is false if it is the first time it is run.
	 */

	if (CACHE_SYNC(&c->sb)) {
		LIST_HEAD(journal);
		struct jset *j;
		struct jset_keys *jk;
		u64 *prio_bucket_ptrs = NULL;

		ret = bch_journal_read(c, &journal);

		err = "cannot allocate memory for journal";
		if (ret == -ENOMEM)
			goto err;

		err = "error reading journal";
		if (ret)
			goto err;

		pr_debug("btree_journal_read() done");

		err = "no journal entries found";
		if (list_empty(&journal))
			goto err;

		j = &list_entry(journal.prev, struct journal_replay, list)->j;

		for_each_jset_jkeys(jk, j)
			if (JKEYS_TYPE(jk) == JKEYS_PRIO_PTRS) {
				prio_bucket_ptrs = jk->d;
				break;
			}

		err = "prio bucket ptrs not found";
		if (!prio_bucket_ptrs)
			goto err;

		err = "error reading priorities";
		for_each_cache(ca, c, i) {
			size_t bucket = prio_bucket_ptrs[ca->sb.nr_this_dev];

			if (bucket && bch_prio_read(ca, bucket)) {
				percpu_ref_put(&ca->ref);
				goto err;
			}
		}

		c->prio_clock[READ].hand = j->read_clock;
		c->prio_clock[WRITE].hand = j->write_clock;

		for_each_cache(ca, c, i) {
			bch_recalc_min_prio(ca, READ);
			bch_recalc_min_prio(ca, WRITE);
		}

		/*
		 * If bch_prio_read() fails it'll call cache_set_error and we'll
		 * tear everything down right away, but if we perhaps checked
		 * sooner we could avoid journal replay.
		 */

		for (id = 0; id < BTREE_ID_NR; id++) {
			unsigned level;
			struct bkey *k;

			err = "bad btree root";
			k = bch_journal_find_btree_root(c, j, id, &level);
			if (!k && id == BTREE_ID_EXTENTS)
				goto err;
			if (!k) {
				pr_debug("missing btree root: %d", id);
				continue;
			}

			err = "error reading btree root";
			if (bch_btree_root_read(c, id, k, level))
				goto err;
		}

		err = "error in recovery";
		if (bch_initial_gc(c, &journal))
			goto err;
		pr_debug("bch_initial_gc() done");

		/*
		 * bcache_journal_next() can't happen sooner, or
		 * btree_gc_finish() will give spurious errors about last_gc >
		 * gc_gen - this is a hack but oh well.
		 */
		bch_journal_next(&c->journal);

		for_each_cache(ca, c, i)
			if (CACHE_STATE(&ca->mi) == CACHE_ACTIVE &&
			    (err = __bch_cache_read_write(ca))) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		bch_journal_replay(c, &journal);
		set_bit(JOURNAL_REPLAY_DONE, &c->journal.flags);
	} else {
		pr_notice("invalidating existing data");

		err = "unable to allocate journal buckets";
		for_each_cache(ca, c, i)
			if (bch_cache_journal_alloc(ca)) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		bch_initial_gc(c, NULL);

		for_each_cache(ca, c, i)
			if (CACHE_STATE(&ca->mi) == CACHE_ACTIVE &&
			    (err = __bch_cache_read_write(ca))) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		err = "cannot allocate new btree root";
		for (id = 0; id < BTREE_ID_NR; id++)
			if (bch_btree_root_alloc(c, id, &cl))
				goto err;

		/*
		 * We don't want to write the first journal entry until
		 * everything is set up - fortunately journal entries won't be
		 * written until the SET_CACHE_SYNC() here:
		 */
		SET_CACHE_SYNC(&c->sb, true);
		set_bit(JOURNAL_REPLAY_DONE, &c->journal.flags);

		bch_journal_next(&c->journal);
		bch_journal_meta(c, &cl);
	}

	err = "error starting btree GC thread";
	if (bch_gc_thread_start(c))
		goto err;

	err = "error starting moving GC threads";
	for_each_cache(ca, c, i)
		if (CACHE_STATE(&ca->mi) == CACHE_ACTIVE &&
		    bch_moving_gc_thread_start(ca)) {
			percpu_ref_put(&ca->ref);
			goto err;
		}

	err = "error starting tiering thread";
	if (bch_tiering_thread_start(c))
		goto err;

	schedule_delayed_work(&c->pd_controllers_update, 5 * HZ);

	closure_sync(&cl);
	c->sb.last_mount = get_seconds();
	bcache_write_super(c);

	flash_devs_run(c);

	bch_debug_init_cache_set(c);

	err = "dynamic fault";
	if (cache_set_init_fault("run_cache_set"))
		goto err;

	set_bit(CACHE_SET_RUNNING, &c->flags);
	list_for_each_entry_safe(dc, t, &uncached_devices, list)
		bch_cached_dev_attach(dc, c);

	closure_put(&c->caching);

	return NULL;
err:
	closure_sync(&cl);
	bch_cache_set_unregister(c);
	closure_put(&c->caching);
	return err;
}

static const char *can_add_cache(struct cache *ca, struct cache_set *c)
{
	if (ca->sb.block_size	!= c->sb.block_size ||
	    ca->sb.bucket_size	!= c->sb.bucket_size ||
	    ca->sb.nr_in_set	!= c->sb.nr_in_set)
		return "cache sb does not match set";

	if (c->cache[ca->sb.nr_this_dev])
		return "duplicate cache set member";

	return NULL;
}

static const char *can_attach_cache(struct cache *ca, struct cache_set *c)
{
	const char *err;
	struct cache_member_rcu *mi;
	bool match;

	err = can_add_cache(ca, c);
	if (err)
		return err;

	/*
	 * When attaching an existing device, the cache set superblock must
	 * already contain member_info with a matching UUID
	 */
	mi = cache_member_info_get(c);

	match = !(ca->sb.seq <= c->sb.seq &&
		  (ca->sb.nr_this_dev >= mi->nr_in_set ||
		   memcmp(&mi->m[ca->sb.nr_this_dev].uuid,
			  &ca->sb.uuid,
			  sizeof(uuid_le))));

	cache_member_info_put();

	if (!match)
		return "cache sb does not match set";

	return NULL;
}

static int cache_set_add_device(struct cache_set *c, struct cache *ca)
{
	char buf[12];
	int ret;

	lockdep_assert_held(&bch_register_lock);

	sprintf(buf, "cache%u", ca->sb.nr_this_dev);
	ret = sysfs_create_link(&ca->kobj, &c->kobj, "set");
	if (ret)
		return ret;

	ret = sysfs_create_link(&c->kobj, &ca->kobj, buf);
	if (ret)
		return ret;

	if (ca->sb.seq > c->sb.seq)
		cache_sb_to_cache_set(c, ca);

	kobject_get(&c->kobj);
	ca->set = c;

	kobject_get(&ca->kobj);
	rcu_assign_pointer(c->cache[ca->sb.nr_this_dev], ca);

	return 0;
}

static const char *register_cache_set(struct cache *ca)
{
	const char *err = "cannot allocate memory";
	struct cache_set *c;

	lockdep_assert_held(&bch_register_lock);

	list_for_each_entry(c, &bch_cache_sets, list)
		if (!memcmp(&c->sb.set_uuid, &ca->sb.set_uuid,
			    sizeof(ca->sb.set_uuid))) {
			err = can_attach_cache(ca, c);
			if (err)
				return err;

			goto found;
		}

	c = bch_cache_set_alloc(ca);
	if (!c)
		return err;

	err = "error creating kobject";
	if (kobject_add(&c->kobj, bcache_kobj, "%pU", c->sb.set_uuid.b) ||
	    kobject_add(&c->internal, &c->kobj, "internal"))
		goto err;

	if (bch_cache_accounting_add_kobjs(&c->accounting, &c->kobj))
		goto err;

	list_add(&c->list, &bch_cache_sets);
found:
	if (cache_set_add_device(c, ca))
		goto err;

	err = NULL;
	if (cache_set_nr_online_devices(c) == cache_set_nr_devices(c))
		err = run_cache_set(c);
	if (err)
		goto err;

	return NULL;
err:
	bch_cache_set_unregister(c);
	return err;
}

/* Cache device */

static void __bch_cache_read_only(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct cache_member_rcu *mi = cache_member_info_get(c);
	struct cache_group *tier = &c->cache_tiers[
		CACHE_TIER(&mi->m[ca->sb.nr_this_dev])];
	struct task_struct *p;
	char buf[BDEVNAME_SIZE];

	cache_member_info_put();

	trace_bcache_cache_read_only(ca);

	bch_moving_gc_stop(ca);

	/*
	 * These remove this cache device from the list from which new
	 * buckets can be allocated.
	 */
	bch_cache_group_remove_cache(tier, ca);
	bch_cache_group_remove_cache(&c->cache_all, ca);

	/*
	 * Stopping the allocator thread stops the writing of any
	 * prio/gen information to the device.
	 */
	p = ca->alloc_thread;
	ca->alloc_thread = NULL;
	smp_wmb(); /* XXX */
	if (p)
		kthread_stop(p);

	bch_recalc_capacity(c);

	/*
	 * This stops new data writes (e.g. to existing open data
	 * buckets) and then waits for all existing writes to
	 * complete.
	 *
	 * The access (read) barrier is in bch_cache_percpu_ref_release.
	 */
	bch_stop_new_data_writes(ca);

	/*
	 * This will suspend the running task until outstanding writes complete.
	 */
	bch_await_scheduled_data_writes(ca);

	/*
	 * Device data write barrier -- no non-meta-data writes should
	 * occur after this point.  However, writes to btree buckets,
	 * journal buckets, and the superblock can still occur.
	 */
	trace_bcache_cache_read_only_done(ca);

	pr_notice("%s read only (data)", bdevname(ca->bdev, buf));
}

static bool bch_last_rw_tier0_device(struct cache *ca)
{
	unsigned i;
	bool ret = true;
	struct cache *ca2;

	rcu_read_lock();

	for_each_cache_rcu(ca2, ca->set, i) {
		if ((CACHE_TIER(&ca2->mi) == 0)
		    && (CACHE_STATE(&ca2->mi) == CACHE_ACTIVE)
		    && (ca2 != ca)) {
			ret = false;
		}
	}

	rcu_read_unlock();
	return ret;
}

/* This does not write the super-block, should it? */

void bch_cache_read_only(struct cache *ca)
{
	unsigned tier;
	bool has_meta, meta_off;
	char buf[BDEVNAME_SIZE];
	struct cache_member *mi;
	struct cache_member_rcu *allmi;

	/*
	 * Stop data writes.
	 */
	__bch_cache_read_only(ca);

	allmi = cache_member_info_get(ca->set);
	mi = &allmi->m[ca->sb.nr_this_dev];
	tier = CACHE_TIER(mi);
	has_meta = CACHE_HAS_METADATA(mi);
	SET_CACHE_STATE(mi, CACHE_RO);
	ca->mi = *mi;		/* Update cache_member cache in struct cache */
	cache_member_info_put();

	meta_off = false;

	/*
	 * The only way to stop meta-data writes is to actually move
	 * the meta-data off!
	 */
	if (has_meta) {
		if ((tier == 0) && (bch_last_rw_tier0_device(ca)))
			pr_err("Tier 0 needs to allow meta-data writes in %pU.",
			       ca->set->sb.set_uuid.b);
		else if (bch_move_meta_data_off_device(ca) != 0)
			pr_err("Unable to stop writing meta-data in %pU.",
			       ca->set->sb.set_uuid.b);
		else
			meta_off = true;
	}

	if (has_meta && meta_off)
		pr_notice("%s read only (meta-data)", bdevname(ca->bdev, buf));
	return;
}

static const char *__bch_cache_read_write(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct cache_member_rcu *mi = cache_member_info_get(c);
	struct cache_group *tier = &c->cache_tiers[
		CACHE_TIER(&mi->m[ca->sb.nr_this_dev])];
	const char *err;

	cache_member_info_put();

	trace_bcache_cache_read_write(ca);

	err = bch_cache_allocator_start(ca);
	if (err)
		return err;

	bch_cache_group_add_cache(tier, ca);
	bch_cache_group_add_cache(&c->cache_all, ca);

	bch_recalc_capacity(c);

	trace_bcache_cache_read_write_done(ca);

	return NULL;
}

/* This does not write the super-block, should it? */

const char *bch_cache_read_write(struct cache *ca)
{
	const char *err = __bch_cache_read_write(ca);

	if (err != NULL)
		return err;

	err = "error starting gc thread";
	if (!bch_moving_gc_thread_start(ca))
		err = NULL;

	return err;
}

void bch_cache_release(struct kobject *kobj)
{
	struct cache *ca = container_of(kobj, struct cache, kobj);
	unsigned i;

	kfree(ca->journal.seq);
	free_percpu(ca->bucket_stats_percpu);

	if (ca->replica_set)
		bioset_free(ca->replica_set);

	free_pages((unsigned long) ca->disk_buckets, ilog2(bucket_pages(ca)));
	kfree(ca->prio_buckets);
	vfree(ca->buckets);
	vfree(ca->bucket_gens);

	free_heap(&ca->heap);
	free_fifo(&ca->free_inc);

	for (i = 0; i < RESERVE_NR; i++)
		free_fifo(&ca->free[i]);

	free_super(&ca->disk_sb);

	percpu_ref_exit(&ca->ref);
	kfree(ca);
	module_put(THIS_MODULE);
	return;
}

/*
 * bch_cache_stop has already returned, so we no longer hold the register
 * lock at the point this is called.
 */

static void bch_cache_kill_work(struct work_struct *work)
{
	struct cache *ca = container_of(work, struct cache, kill_work);
	struct cache_set *c = ca->set;
	char buf[BDEVNAME_SIZE];

	mutex_lock(&bch_register_lock);

	bdevname(ca->bdev, buf);

	if (!IS_ERR_OR_NULL(ca->bdev))
		blkdev_put(ca->bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);

	pr_notice("%s removed", buf);

	if (c->kobj.state_in_sysfs) {
		char buf2[12];

		sprintf(buf2, "cache%u", ca->sb.nr_this_dev);
		sysfs_remove_link(&c->kobj, buf2);
	}

	mutex_unlock(&bch_register_lock);

	kobject_put(&c->kobj);

	/*
	 * This results in bch_cache_release being called which
	 * frees up the storage.
	 */

	kobject_put(&ca->kobj);
	return;
}

static void bch_cache_percpu_ref_release(struct percpu_ref *ref)
{
	/*
	 * Device access barrier -- no non-superblock accesses should occur
	 * after this point.
	 * The write barrier is in bch_cache_read_only.
	 */

	struct cache *ca = container_of(ref, struct cache, ref);

	schedule_work(&ca->kill_work);
}

static void bch_cache_kill_rcu(struct rcu_head *rcu)
{
	struct cache *ca = container_of(rcu, struct cache, kill_rcu);

	/*
	 * This decrements the ref count to ca, and once the ref count
	 * is 0 (outstanding bios to the ca also incremented it and
	 * decrement it on completion/error), bch_cache_percpu_ref_release
	 * is called, and that eventually results in bch_cache_kill_work
	 * being called, which in turn results in bch_cache_release being
	 * called.
	 *
	 * In particular, these functions won't be called until there are no
	 * bios outstanding (the per-cpu ref counts are all 0), so it
	 * is safe to remove the actual sysfs device at that point,
	 * and that can indicate success to the user.
	 */

	percpu_ref_kill(&ca->ref);
}

static void bch_cache_stop(struct cache *ca)
{
	struct cache_set *c = ca->set;

	lockdep_assert_held(&bch_register_lock);

	BUG_ON(rcu_access_pointer(c->cache[ca->sb.nr_this_dev]) != ca);

	rcu_assign_pointer(c->cache[ca->sb.nr_this_dev], NULL);

	call_rcu(&ca->kill_rcu, bch_cache_kill_rcu);
}

static void bch_cache_remove_work(struct work_struct *work)
{
	unsigned tier;
	bool has_data, has_meta, data_off, meta_off;
	struct cache *ca = container_of(work, struct cache, remove_work);
	struct cache_set *c = ca->set;
	struct cache_member_rcu *allmi;
	struct cache_member *mi;
	char buf[BDEVNAME_SIZE];
	bool force = (test_bit(CACHE_DEV_FORCE_REMOVE, &ca->flags));

	mutex_lock(&bch_register_lock);
	allmi = cache_member_info_get(c);
	mi = &allmi->m[ca->sb.nr_this_dev];

	/*
	 * Right now, we can't remove the last device from a tier,
	 * - For tier 0, because all metadata lives in tier 0 and because
	 *   there is no way to have foreground writes go directly to tier 1.
	 * - For tier 1, because the code doesn't completely support an
	 *   empty tier 1.
	 */

	tier = CACHE_TIER(mi);

	if (c->cache_tiers[tier].nr_devices == 1) {
		cache_member_info_put();
		mutex_unlock(&bch_register_lock);
		clear_bit(CACHE_DEV_FORCE_REMOVE, &ca->flags);
		clear_bit(CACHE_DEV_REMOVING, &ca->flags);
		pr_err("Can't remove last device in tier %u of %pU.",
		       tier, c->sb.set_uuid.b);
		return;
	}

	/* CACHE_ACTIVE means Read/Write. */

	if (CACHE_STATE(mi) != CACHE_ACTIVE) {
		has_data = CACHE_HAS_DATA(mi);
		cache_member_info_put();
	} else {
		cache_member_info_put();
		/*
		 * The following quiesces data writes but not meta-data writes.
		 */
		__bch_cache_read_only(ca);

		/* Update the state to read-only */

		allmi = cache_member_info_get(c);
		mi = &allmi->m[ca->sb.nr_this_dev];
		SET_CACHE_STATE(mi, CACHE_RO);
		ca->mi = *mi;	/* Update cache_member cache in struct cache */
		has_data = CACHE_HAS_DATA(mi);
		cache_member_info_put();
		bcache_write_super(c);
	}

	mutex_unlock(&bch_register_lock);

	/*
	 * The call to __bch_cache_read_only above has quiesced all data writes.
	 * Move the data off the device, if there is any.
	 */

	data_off = (!has_data || (bch_move_data_off_device(ca) == 0));

	allmi = cache_member_info_get(c);
	mi = &allmi->m[ca->sb.nr_this_dev];
	if (has_data && data_off) {
		/* We've just moved all the data off! */
		SET_CACHE_HAS_DATA(mi, false);
		/* Update cache_member cache in struct cache */
		ca->mi = *mi;
	}
	has_meta = CACHE_HAS_METADATA(mi);
	cache_member_info_put();

	/*
	 * If there is no meta data, claim it has been moved off.
	 * Else, try to move it off -- this also quiesces meta-data writes.
	 */

	meta_off = (!has_meta || (bch_move_meta_data_off_device(ca) == 0));

	/*
	 * If we successfully moved meta-data off, mark as having none.
	 */

	if (has_meta && meta_off) {
		allmi = cache_member_info_get(c);
		mi = &allmi->m[ca->sb.nr_this_dev];
		/* We've just moved all the meta-data off! */
		SET_CACHE_HAS_METADATA(mi, false);
		/* Update cache_member cache in struct cache */
		ca->mi = *mi;
		cache_member_info_put();
	}

	/* Now, complain as necessary */

	/*
	 * Note: These error messages are messy because pr_err is a macro
	 * that concatenates its first must-be-string argument.
	 */

	if (has_data && !data_off)
		pr_err("%s in %pU%s",
		       (force
			? "Forcing device removal with live data"
			: "Unable to move data off device"),
		       c->sb.set_uuid.b,
		       (force ? "!" : "."));

	if (has_meta && !meta_off)
		pr_err("%s in %pU%s",
		       (force
			? "Forcing device removal with live meta-data"
			: "Unable to move meta-data off device"),
		       c->sb.set_uuid.b,
		       (force ? "!" : "."));

	/* If there is (meta-) data left, and not forcing, abort */

	if ((!data_off || !meta_off) && !force) {
		clear_bit(CACHE_DEV_REMOVING, &ca->flags);
		return;
	}

	if (has_meta && meta_off)
		pr_notice("%s read only (meta-data)", bdevname(ca->bdev, buf));

	/* Update the super block */

	down(&c->sb_write_mutex);

	/* Mark it as failed in the super block */

	if (meta_off) {
		allmi = cache_member_info_get(c);
		mi = &allmi->m[ca->sb.nr_this_dev];
		SET_CACHE_STATE(mi, CACHE_FAILED);
		/* Update cache_member cache in struct cache */
		ca->mi = *mi;
		cache_member_info_put();
	}

	__bcache_write_super(c); /* ups sb_write_mutex */

	/*
	 * Now mark the slot as 0 in memory so that the slot can be reused.
	 * It won't actually be reused until btree_gc makes sure that there
	 * are no pointers to the device at all.
	 */

	if (meta_off) {
		allmi = cache_member_info_get(c);
		mi = &allmi->m[ca->sb.nr_this_dev];
		memset(mi, 0, sizeof(*mi));
		/* No need to copy to struct cache as we are removing */
		cache_member_info_put();
	}

	/*
	 * This completes asynchronously, with bch_cache_stop scheduling
	 * the final teardown when there are no (read) bios outstanding.
	 */

	mutex_lock(&bch_register_lock);
	bch_cache_stop(ca);
	mutex_unlock(&bch_register_lock);
	return;
}

bool bch_cache_remove(struct cache *ca, bool force)
{
	if (test_and_set_bit(CACHE_DEV_REMOVING, &ca->flags))
		return false;

	if (force)
		set_bit(CACHE_DEV_FORCE_REMOVE, &ca->flags);

	queue_work(system_long_wq, &ca->remove_work);
	return true;
}

static int cache_init(struct cache *ca)
{
	size_t reserve_none, movinggc_reserve, free_inc_reserve, total_reserve;
	size_t heap_size;
	unsigned i;

	if (cache_set_init_fault("cache_alloc"))
		return -ENOMEM;

	if (percpu_ref_init(&ca->ref, bch_cache_percpu_ref_release,
			    0, GFP_KERNEL))
		return -ENOMEM;

	INIT_WORK(&ca->kill_work, bch_cache_kill_work);
	INIT_WORK(&ca->remove_work, bch_cache_remove_work);
	bio_init(&ca->journal.bio);
	ca->journal.bio.bi_max_vecs = 8;
	ca->journal.bio.bi_io_vec = ca->journal.bio.bi_inline_vecs;
	spin_lock_init(&ca->freelist_lock);
	spin_lock_init(&ca->prio_buckets_lock);

	/* XXX: tune these */
	movinggc_reserve = max_t(size_t, NUM_GC_GENS * 2,
				 ca->sb.nbuckets >> 7);
	reserve_none = max_t(size_t, 4, ca->sb.nbuckets >> 9);
	free_inc_reserve = reserve_none << 1;
	heap_size = max_t(size_t, free_inc_reserve, movinggc_reserve);

	for (i = 0; i < BTREE_ID_NR; i++)
		if (!init_fifo(&ca->free[i], BTREE_NODE_RESERVE, GFP_KERNEL))
			return -ENOMEM;

	if (!init_fifo(&ca->free[RESERVE_PRIO], prio_buckets(ca), GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_MOVINGGC_BTREE],
		       BTREE_NODE_RESERVE, GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_TIERING_BTREE],
		       BTREE_NODE_RESERVE, GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_MOVINGGC],
		       movinggc_reserve, GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_NONE], reserve_none, GFP_KERNEL) ||
	    !init_fifo(&ca->free_inc,	free_inc_reserve, GFP_KERNEL) ||
	    !init_heap(&ca->heap,	heap_size, GFP_KERNEL) ||
	    !(ca->bucket_gens	= vzalloc(sizeof(u8) *
					  ca->sb.nbuckets)) ||
	    !(ca->buckets	= vzalloc(sizeof(struct bucket) *
					  ca->sb.nbuckets)) ||
	    !(ca->prio_buckets	= kzalloc(sizeof(uint64_t) * prio_buckets(ca) *
					  2, GFP_KERNEL)) ||
	    !(ca->disk_buckets	= alloc_bucket_pages(GFP_KERNEL, ca)) ||
	    !(ca->replica_set = bioset_create(4, offsetof(struct bbio, bio))) ||
	    !(ca->bucket_stats_percpu = alloc_percpu(struct bucket_stats)) ||
	    !(ca->journal.seq	= kcalloc(bch_nr_journal_buckets(&ca->sb),
					  sizeof(u64), GFP_KERNEL)))
		return -ENOMEM;

	ca->prio_last_buckets = ca->prio_buckets + prio_buckets(ca);

	total_reserve = ca->free_inc.size;
	for (i = 0; i < RESERVE_NR; i++)
		total_reserve += ca->free[i].size;
	pr_debug("%zu buckets reserved", total_reserve);

	for (i = 0; i < ARRAY_SIZE(ca->gc_buckets); i++) {
		ca->gc_buckets[i].ca = ca;
		ca->gc_buckets[i].nr_replicas = 1;
	}

	mutex_init(&ca->heap_lock);
	bch_moving_init_cache(ca);

	return 0;
}

static const char *__register_cache(struct bcache_superblock *sb,
				    struct block_device *bdev,
				    struct cache **ret)
{
	const char *err = NULL; /* must be set for any error case */
	struct cache *ca;
	int ret2 = 0;
	unsigned i;

	err = "cannot allocate memory";
	ca = kzalloc(sizeof(*ca), GFP_KERNEL);
	if (!ca) {
		blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
		return err;
	}

	__module_get(THIS_MODULE);
	kobject_init(&ca->kobj, &bch_cache_ktype);

	ca->bdev = bdev;
	ca->bdev->bd_holder = ca;

	ca->disk_sb = *sb;
	memset(sb, 0, sizeof(*sb));

	err = validate_super(&ca->disk_sb, bdev, &ca->sb);
	if (err)
		goto err;

	err = "Unsupported superblock version";
	if (CACHE_SYNC(&ca->sb) &&
	    ca->sb.version != BCACHE_SB_VERSION_CDEV_V3)
		goto err;

	ret2 = cache_init(ca);
	if (ret2 != 0) {
		if (ret2 == -ENOMEM)
			err = "cache_alloc(): -ENOMEM";
		else
			err = "cache_alloc(): unknown error";
		goto err;
	}

	err = "bad journal bucket";
	for (i = 0; i < bch_nr_journal_buckets(&ca->sb); i++)
		if (journal_bucket(ca, i) <  ca->sb.first_bucket ||
		    journal_bucket(ca, i) >= ca->sb.nbuckets)
			goto err;

	err = "error creating kobject";
	if (kobject_add(&ca->kobj, &part_to_dev(bdev->bd_part)->kobj, "bcache"))
		goto err;

	*ret = ca;
	return NULL;
err:
	kobject_put(&ca->kobj);
	return err;
}

static const char *register_cache(struct bcache_superblock *sb,
				  struct block_device *bdev)
{
	char name[BDEVNAME_SIZE];
	const char *err;
	struct cache *ca;

	err = __register_cache(sb, bdev, &ca);
	if (err)
		return err;

	mutex_lock(&bch_register_lock);
	err = register_cache_set(ca);
	mutex_unlock(&bch_register_lock);

	if (err)
		goto err;

	pr_info("registered cache device %s", bdevname(bdev, name));
err:
	kobject_put(&ca->kobj);
	return err;
}

int bch_cache_add(struct cache_set *c, const char *path)
{
	struct bcache_superblock sb;
	struct block_device *bdev;
	const char *err;
	struct cache *ca;
	struct cache_member_rcu *new_mi, *old_mi;
	unsigned i, nr_this_dev, new_size;
	int ret = -EINVAL;
	struct cache_member *mi, orig_mi;

	lockdep_assert_held(&bch_register_lock);

	memset(&sb, 0, sizeof(sb));

	down_read(&c->gc_lock);
	if (test_bit(CACHE_SET_GC_FAILURE, &c->flags))
		goto no_slot;

	for (i = 0; i < MAX_CACHES_PER_SET; i++)
		if (!test_bit(i, c->cache_slots_used) &&
		    (i >= c->sb.nr_in_set ||
		     bch_is_zero(c->members->m[i].uuid.b, sizeof(uuid_le))))
			goto have_slot;
no_slot:
	up_read(&c->gc_lock);

	err = "no slots available in superblock";
	ret = -ENOSPC;
	goto err;

have_slot:
	nr_this_dev = i;
	set_bit(nr_this_dev, c->cache_slots_used);
	up_read(&c->gc_lock);

	err = bch_blkdev_open(path, &sb, &bdev);
	if (err)
		goto err;

	err = read_super(bdev, &sb);
	if (err) {
		blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
		goto err;
	}

	sb.sb->bucket_size	= c->sb.bucket_size;
	sb.sb->block_size	= c->sb.block_size;

	/* Preserve the old cache member information (esp. tier)
	 * before we start bashing the disk stuff.
	 */
	orig_mi = sb.sb->members[le16_to_cpu(sb.sb->nr_this_dev)];

	err = __register_cache(&sb, bdev, &ca);
	if (err)
		goto err;

	ca->sb.nr_this_dev	= nr_this_dev;
	ca->sb.nr_in_set	= c->sb.nr_in_set;
	kobject_get(&c->kobj);
	ca->set			= c;

	err = "journal alloc failed";
	if (bch_cache_journal_alloc(ca))
		goto err_put;

	err = can_add_cache(ca, c);
	if (err)
		goto err_put;

	new_size = max_t(unsigned, nr_this_dev + 1, c->sb.nr_in_set);

	old_mi = c->members;
	new_mi = kzalloc(sizeof(struct cache_member_rcu) +
			 sizeof(struct cache_member) * new_size,
			 GFP_KERNEL);
	if (!new_mi) {
		err = "cannot allocate memory";
		ret = -ENOMEM;
		goto err;
	}

	new_mi->nr_in_set = new_size;
	memcpy(new_mi->m,
	       old_mi->m,
	       c->sb.nr_in_set * sizeof(struct cache_member));

	/* Are there other fields to preserve besides the uuid and tier? */
	mi = &new_mi->m[nr_this_dev];
	mi->uuid = ca->sb.uuid;
	SET_CACHE_TIER(mi, (CACHE_TIER(&orig_mi)));

	/* commit new member info */
	rcu_assign_pointer(c->members, new_mi);
	c->sb.nr_in_set = new_mi->nr_in_set;

	bcache_write_super(c);
	kfree_rcu(old_mi, rcu);

	err = "sysfs error";
	if (cache_set_add_device(c, ca))
		goto err_put;

	err = bch_cache_read_write(ca);
	if (err)
		goto err_put;

	ret = 0;
err_put:
	kobject_put(&ca->kobj);
err:
	free_super(&sb);

	if (ret)
		pr_err("Unable to add device: %s", err);
	return ret;
}

/* Global interfaces/init */

#define kobj_attribute_write(n, fn)					\
	static struct kobj_attribute ksysfs_##n = __ATTR(n, S_IWUSR, NULL, fn)

#define kobj_attribute_rw(n, show, store)				\
	static struct kobj_attribute ksysfs_##n =			\
		__ATTR(n, S_IWUSR|S_IRUSR, show, store)

static ssize_t register_bcache(struct kobject *, struct kobj_attribute *,
			       const char *, size_t);

kobj_attribute_write(register,		register_bcache);
kobj_attribute_write(register_quiet,	register_bcache);

static ssize_t register_bcache(struct kobject *k, struct kobj_attribute *attr,
			       const char *buffer, size_t size)
{
	ssize_t ret = -EINVAL;
	const char *err = "cannot allocate memory";
	char *path = NULL;
	struct block_device *bdev = NULL;
	struct bcache_superblock sb;

	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	if (!(path = kstrndup(skip_spaces(buffer), size, GFP_KERNEL)))
		goto err;

	err = "failed to open device";
	bdev = blkdev_get_by_path(strim(path),
				  FMODE_READ|FMODE_WRITE|FMODE_EXCL,
				  &sb);

	if (IS_ERR(bdev)) {
		if (bdev == ERR_PTR(-EBUSY)) {
			bdev = lookup_bdev(strim(path));
			mutex_lock(&bch_register_lock);
			if (!IS_ERR(bdev) && bch_is_open(bdev))
				err = "device already registered";
			else {
				err = "device busy";
				ret = -EBUSY;
			}
			mutex_unlock(&bch_register_lock);
			if (attr == &ksysfs_register_quiet)
				goto out;
		}
		goto err;
	}

	err = "failed to set blocksize";
	if (set_blocksize(bdev, 4096))
		goto err_close;

	err = read_super(bdev, &sb);
	if (err)
		goto err_close;

	if (__SB_IS_BDEV(le64_to_cpu(sb.sb->version))) {
		mutex_lock(&bch_register_lock);
		err = bch_register_bdev(&sb, bdev);
		mutex_unlock(&bch_register_lock);
	} else {
		err = register_cache(&sb, bdev);
	}
	if (err)
		goto err;

	ret = size;
out:
	kfree(path);
	module_put(THIS_MODULE);
	return ret;

err_close:
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
err:
	pr_err("error opening %s: %s", path, err);
	free_super(&sb);
	goto out;
}

static int bcache_reboot(struct notifier_block *n, unsigned long code, void *x)
{
	if (code == SYS_DOWN ||
	    code == SYS_HALT ||
	    code == SYS_POWER_OFF) {
		struct cache_set *c;

		mutex_lock(&bch_register_lock);

		if (!list_empty(&bch_cache_sets))
			pr_info("Setting all devices read only:");

		list_for_each_entry(c, &bch_cache_sets, list)
			bch_cache_set_read_only(c);

		mutex_unlock(&bch_register_lock);
	}

	return NOTIFY_DONE;
}

static struct notifier_block reboot = {
	.notifier_call	= bcache_reboot,
	.priority	= INT_MAX, /* before any real devices */
};

static ssize_t reboot_test(struct kobject *k, struct kobj_attribute *attr,
			   const char *buffer, size_t size)
{
	bcache_reboot(NULL, SYS_DOWN, NULL);
	return size;
}

kobj_attribute_write(reboot,		reboot_test);

static void bcache_exit(void)
{
	bch_debug_exit();
	bch_blockdev_exit();
	if (bcache_kobj)
		kobject_put(bcache_kobj);
	if (bcache_io_wq)
		destroy_workqueue(bcache_io_wq);
	unregister_reboot_notifier(&reboot);
}

static int __init bcache_init(void)
{
	static const struct attribute *files[] = {
		&ksysfs_register.attr,
		&ksysfs_register_quiet.attr,
		&ksysfs_reboot.attr,
		NULL
	};

	mutex_init(&bch_register_lock);
	register_reboot_notifier(&reboot);

	if (!(bcache_io_wq = alloc_workqueue("bcache_io", WQ_MEM_RECLAIM, 0)) ||
	    !(bcache_kobj = kobject_create_and_add("bcache", fs_kobj)) ||
	    sysfs_create_files(bcache_kobj, files) ||
	    bch_blockdev_init() ||
	    bch_debug_init(bcache_kobj))
		goto err;

	return 0;
err:
	bcache_exit();
	return -ENOMEM;
}

module_exit(bcache_exit);
module_init(bcache_init);
