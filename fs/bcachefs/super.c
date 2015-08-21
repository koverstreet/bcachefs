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
#include "movinggc.h"
#include "stats.h"
#include "super.h"

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

wait_queue_head_t unregister_wait;
struct workqueue_struct *bcache_io_wq;

static void bch_cache_stop(struct cache *);

#define BTREE_MAX_PAGES		(256 * 1024 / PAGE_SIZE)

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
	size_t bytes = __set_bytes((struct cache_sb *) NULL, keys);

	if (bytes + (SB_SECTOR << 9) > ca->sb.first_bucket * bucket_bytes(ca))
		return -ENOSPC;

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
	struct cache_member *m;

	m = kcalloc(ca->sb.nr_in_set, sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	memcpy(m, ca->disk_sb.sb->d,
	       ca->sb.nr_in_set * sizeof(*m));

	kfree(c->members);
	c->members = m;

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

	memcpy(ca->disk_sb.sb->d,
	       c->members,
	       ca->sb.nr_in_set * sizeof(struct cache_member));

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

	for (ptr = 0; ptr < bch_extent_ptrs(k); ptr++) {
		mi = c->members + PTR_DEV(k, ptr);

		(meta
		 ? SET_CACHE_HAS_METADATA
		 : SET_CACHE_HAS_DATA)(mi, true);
	}

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
	closure_wake_up(&c->bucket_wait);
}

__printf(2, 3)
bool bch_cache_set_error(struct cache_set *c, const char *fmt, ...)
{
	va_list args;

	/* XXX: we can be called from atomic context
	acquire_console_sem();
	*/

	printk(KERN_ERR "bcache: error on %pU: ", c->sb.set_uuid.b);

	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);

	switch (CACHE_ERROR_ACTION(&c->sb)) {
	case BCH_ON_ERROR_CONTINUE:
		printk(", continuing\n");
		break;
	case BCH_ON_ERROR_RO:
		printk(", going read only\n");
		set_bit(CACHE_SET_RO, &c->flags);
		break;
	case BCH_ON_ERROR_PANIC:
		panic("panic forced after error\n");
		break;
	}

	return true;
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
	wake_up(&unregister_wait);

	closure_debug_destroy(&c->cl);
	kobject_put(&c->kobj);
}

static void cache_set_flush(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);
	struct cache *ca;
	unsigned i;

	bch_wake_delayed_writes((unsigned long) c);
	del_timer_sync(&c->foreground_write_wakeup);
	cancel_delayed_work_sync(&c->pd_controllers_update);

	c->tiering_pd.rate.rate = UINT_MAX;
	bch_ratelimit_reset(&c->tiering_pd.rate);
	if (!IS_ERR_OR_NULL(c->tiering_read))
		kthread_stop(c->tiering_read);

	if (c->tiering_write)
		destroy_workqueue(c->tiering_write);

	if (!IS_ERR_OR_NULL(c->gc_thread))
		kthread_stop(c->gc_thread);

	mutex_lock(&bch_register_lock);
	for_each_cache(ca, c, i)
		bch_cache_read_only(ca);
	mutex_unlock(&bch_register_lock);

	bch_cache_accounting_destroy(&c->accounting);

	kobject_put(&c->internal);
	kobject_del(&c->kobj);

	/* Should skip this if we're unregistering because of an error */
	bch_btree_flush(c);

	if (c->journal.cur) {
		cancel_delayed_work_sync(&c->journal.work);
		/* flush last journal entry if needed */
		c->journal.work.work.func(&c->journal.work.work);
	}

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

	for (i = 0; i < c->sb.nr_in_set; i++)
		if (!bch_is_zero(c->members[i].uuid.b, sizeof(uuid_le)))
			nr++;
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

	c->btree_pages		= bucket_pages(c);
	if (c->btree_pages > BTREE_MAX_PAGES)
		c->btree_pages = max_t(int, c->btree_pages / 4,
				       BTREE_MAX_PAGES);

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
		sizeof(struct btree_iter_set);

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

static const char *run_cache_set(struct cache_set *c)
{
	const char *err = "cannot allocate memory";
	struct cached_dev *dc, *t;
	struct cache *ca;
	struct closure cl;
	unsigned i, id;
	int ret;

	closure_init_stack(&cl);

	/* We don't want bch_cache_set_error() to free underneath us */
	closure_get(&c->caching);

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

			if (bucket &&
			    (err = bch_prio_read(ca, bucket))) {
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
			if (CACHE_STATE(cache_member_info(ca)) ==
			    CACHE_ACTIVE &&
			    (err = bch_cache_read_write(ca))) {
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
			if (CACHE_STATE(cache_member_info(ca)) ==
			    CACHE_ACTIVE &&
			    (err = bch_cache_read_write(ca))) {
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

	err = "error starting gc thread";
	if (bch_gc_thread_start(c))
		goto err;

	err = "error starting moving GC thread";
	for_each_cache(ca, c, i)
		if (CACHE_STATE(cache_member_info(ca)) == CACHE_ACTIVE &&
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

static const char *can_attach_cache(struct cache *ca, struct cache_set *c)
{
	if (ca->sb.block_size	!= c->sb.block_size ||
	    ca->sb.bucket_size	!= c->sb.bucket_size ||
	    ca->sb.nr_in_set	!= c->sb.nr_in_set)
		return "cache sb does not match set";

	if (ca->sb.seq <= c->sb.seq &&
	    (ca->sb.nr_this_dev >= c->sb.nr_in_set ||
	     memcmp(&c->members[ca->sb.nr_this_dev].uuid,
		    &ca->sb.uuid,
		    sizeof(uuid_le))))
		return "cache sb does not match set";

	if (c->cache[ca->sb.nr_this_dev])
		return "duplicate cache set member";

	return NULL;
}

static int cache_set_add_device(struct cache_set *c, struct cache *ca)
{
	char buf[12];
	int ret;

	lockdep_assert_held(&bch_register_lock);

	sprintf(buf, "cache%i", ca->sb.nr_this_dev);
	ret = sysfs_create_link(&ca->kobj, &c->kobj, "set");
	if (ret)
		return ret;

	ret = sysfs_create_link(&c->kobj, &ca->kobj, buf);
	if (ret)
		return ret;

	if (ca->sb.seq > c->sb.seq)
		cache_sb_to_cache_set(c, ca);

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

void bch_cache_read_only(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct cache_member *mi = cache_member_info(ca);
	struct cache_group *tier = &c->cache_tiers[CACHE_TIER(mi)];
	struct task_struct *p;

	bch_moving_gc_stop(ca);

	bch_cache_group_remove_cache(tier, ca);
	bch_cache_group_remove_cache(&c->cache_all, ca);

	p = ca->alloc_thread;
	ca->alloc_thread = NULL;
	smp_wmb(); /* XXX */
	if (p)
		kthread_stop(p);

	bch_recalc_capacity(c);
}

const char *bch_cache_read_write(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct cache_member *mi = cache_member_info(ca);
	struct cache_group *tier = &c->cache_tiers[CACHE_TIER(mi)];
	const char *err;

	err = bch_cache_allocator_start(ca);
	if (err)
		return err;

	bch_cache_group_add_cache(tier, ca);
	bch_cache_group_add_cache(&c->cache_all, ca);

	bch_recalc_capacity(c);

	return NULL;
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

	if (!IS_ERR_OR_NULL(ca->bdev))
		blkdev_put(ca->bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);

	percpu_ref_exit(&ca->ref);
	kfree(ca);
	module_put(THIS_MODULE);
}

static void bch_cache_kill_work(struct work_struct *work)
{
	struct cache *ca = container_of(work, struct cache, kill_work);

	kobject_put(&ca->kobj);
}

static void bch_cache_percpu_ref_release(struct percpu_ref *ref)
{
	struct cache *ca = container_of(ref, struct cache, ref);

	schedule_work(&ca->kill_work);
}

static void bch_cache_kill_rcu(struct rcu_head *rcu)
{
	struct cache *ca = container_of(rcu, struct cache, kill_rcu);

	percpu_ref_kill(&ca->ref);
}

static void bch_cache_stop(struct cache *ca)
{
	struct cache_set *c = ca->set;

	lockdep_assert_held(&bch_register_lock);

	BUG_ON(rcu_access_pointer(c->cache[ca->sb.nr_this_dev]) != ca);

	if (c->kobj.state_in_sysfs) {
		char buf[12];

		sprintf(buf, "cache%i", ca->sb.nr_this_dev);
		sysfs_remove_link(&c->kobj, buf);
	}

	rcu_assign_pointer(c->cache[ca->sb.nr_this_dev], NULL);

	call_rcu(&ca->kill_rcu, bch_cache_kill_rcu);
}

static void bch_cache_remove_work(struct work_struct *work)
{
	struct cache *ca = container_of(work, struct cache, remove_work);
	struct cache_member *mi = cache_member_info(ca);
	struct cache_set *c = ca->set;

	mutex_lock(&bch_register_lock);

	if (CACHE_STATE(mi) == CACHE_ACTIVE) {
		bch_cache_read_only(ca);

		SET_CACHE_STATE(mi, CACHE_RO);
		bcache_write_super(c);
	}

	down(&c->sb_write_mutex);
	/*
	 * XXX: haven't cleared out open buckets, someone might still mark this
	 * device as having data/metadata
	 */

	if (!CACHE_HAS_METADATA(mi) &&
	    !CACHE_HAS_DATA(mi)) {
		memset(mi, 0, sizeof(*mi));
		__bcache_write_super(c);
	} else {
		up(&c->sb_write_mutex);
	}

	bch_cache_stop(ca);
	mutex_unlock(&bch_register_lock);
}

void bch_cache_remove(struct cache *ca)
{
	if (!test_and_set_bit(CACHE_DEV_REMOVING, &ca->flags))
		queue_work(system_long_wq, &ca->remove_work);
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

	for (i = 0; i < ARRAY_SIZE(ca->gc_buckets); i++)
		ca->gc_buckets[i].ca = ca;

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
	unsigned i, nr_this_dev;
	int ret = -EINVAL;

	lockdep_assert_held(&bch_register_lock);

	memset(&sb, 0, sizeof(sb));

	down_read(&c->gc_lock);

	for (i = 0; i < MAX_CACHES_PER_SET; i++)
		if (!test_bit(i, c->cache_slots_used) &&
		    (i >= c->sb.nr_in_set ||
		     bch_is_zero(c->members[i].uuid.b, sizeof(uuid_le))))
			goto have_slot;

	up_read(&c->gc_lock);

	err = "no slots available in superblock";
	ret = -ENOSPC;
	goto err;

have_slot:
	nr_this_dev = i;
	set_bit(nr_this_dev, c->cache_slots_used);
	up_read(&c->gc_lock);

	if (nr_this_dev >= c->sb.nr_in_set) {
		struct cache_member *p = kcalloc(nr_this_dev + 1,
						 sizeof(struct cache_member),
						 GFP_KERNEL);
		if (!p) {
			err = "cannot allocate memory";
			ret = -ENOMEM;
			goto err;
		}

		memcpy(p, c->members,
		       c->sb.nr_in_set * sizeof(struct cache_member));

		c->members = p;
		c->sb.nr_in_set = nr_this_dev + 1;
	}

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

	err = __register_cache(&sb, bdev, &ca);
	if (err)
		goto err;

	ca->sb.nr_this_dev	= nr_this_dev;
	ca->sb.nr_in_set	= c->sb.nr_in_set;
	ca->set			= c;

	err = "journal alloc failed";
	if (bch_cache_journal_alloc(ca))
		goto err_put;

	c->members[nr_this_dev].uuid = ca->sb.uuid;
	bcache_write_super(c);

	err = can_attach_cache(ca, c);
	if (err)
		goto err_put;

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
		DEFINE_WAIT(wait);
		bool stopped = false;

		struct cache_set *c, *tc;
		struct cached_dev *dc, *tdc;

		unsigned long timeout;

		mutex_lock(&bch_register_lock);

		if (list_empty(&bch_cache_sets) &&
		    list_empty(&uncached_devices))
			goto out;

		pr_info("Stopping all devices:");

		list_for_each_entry_safe(c, tc, &bch_cache_sets, list)
			bch_cache_set_stop(c);

		list_for_each_entry_safe(dc, tdc, &uncached_devices, list)
			bcache_device_stop(&dc->disk);

		/* If we're testing, n == NULL so wait forever */
		if (n)
			timeout = 2 * HZ;
		else
			timeout = MAX_SCHEDULE_TIMEOUT;

		/* What's a condition variable? */
		while (1) {
			stopped = list_empty(&bch_cache_sets) &&
				list_empty(&uncached_devices);

			if (timeout <= 0 || stopped)
				break;

			prepare_to_wait(&unregister_wait, &wait,
					TASK_UNINTERRUPTIBLE);

			mutex_unlock(&bch_register_lock);
			timeout = schedule_timeout(timeout);
			mutex_lock(&bch_register_lock);
		}

		finish_wait(&unregister_wait, &wait);

		if (stopped)
			pr_info("All devices stopped");
		else
			pr_notice("Timeout waiting for devices to be closed");
out:
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
	init_waitqueue_head(&unregister_wait);
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
