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
#include "btree_cache.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "btree_io.h"
#include "checksum.h"
#include "clock.h"
#include "compress.h"
#include "debug.h"
#include "error.h"
#include "fs-gc.h"
#include "inode.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "migrate.h"
#include "movinggc.h"
#include "notify.h"
#include "stats.h"
#include "super.h"
#include "tier.h"
#include "writeback.h"

#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/debugfs.h>
#include <linux/genhd.h>
#include <linux/idr.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/reboot.h>
#include <linux/sysfs.h>
#include <crypto/hash.h>

#include <trace/events/bcachefs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kent Overstreet <kent.overstreet@gmail.com>");

static const uuid_le invalid_uuid = {
	.b = {
		0xa0, 0x3e, 0xf8, 0xed, 0x3e, 0xe1, 0xb8, 0x78,
		0xc8, 0x50, 0xfc, 0x5e, 0xcb, 0x16, 0xcd, 0x99
	}
};

static struct kset *bcache_kset;
struct mutex bch_register_lock;
LIST_HEAD(bch_cache_sets);

static int bch_chardev_major;
static struct class *bch_chardev_class;
static struct device *bch_chardev;
static DEFINE_IDR(bch_chardev_minor);
static DECLARE_WAIT_QUEUE_HEAD(bch_read_only_wait);
struct workqueue_struct *bcache_io_wq;
struct crypto_shash *bch_sha1;

static void bch_cache_stop(struct cache *);
static int bch_cache_online(struct cache *);

static bool bch_is_open_cache(struct block_device *bdev)
{
	struct cache_set *c;
	struct cache *ca;
	unsigned i;

	rcu_read_lock();
	list_for_each_entry(c, &bch_cache_sets, list)
		for_each_cache_rcu(ca, c, i)
			if (ca->disk_sb.bdev == bdev) {
				rcu_read_unlock();
				return true;
			}
	rcu_read_unlock();
	return false;
}

static bool bch_is_open(struct block_device *bdev)
{
	lockdep_assert_held(&bch_register_lock);

	return bch_is_open_cache(bdev) || bch_is_open_backing_dev(bdev);
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

	bdev_get_queue(bdev)->backing_dev_info.capabilities |= BDI_CAP_STABLE_WRITES;

	*ret = bdev;
	return NULL;
}

static int bch_congested_fn(void *data, int bdi_bits)
{
	struct backing_dev_info *bdi;
	struct cache_set *c = data;
	struct cache *ca;
	unsigned i;
	int ret = 0;

	rcu_read_lock();
	if (bdi_bits & (1 << WB_sync_congested)) {
		/* Reads - check all devices: */
		for_each_cache_rcu(ca, c, i) {
			bdi = blk_get_backing_dev_info(ca->disk_sb.bdev);

			if (bdi_congested(bdi, bdi_bits)) {
				ret = 1;
				break;
			}
		}
	} else {
		/* Writes only go to tier 0: */
		group_for_each_cache_rcu(ca, &c->cache_tiers[0], i) {
			bdi = blk_get_backing_dev_info(ca->disk_sb.bdev);

			if (bdi_congested(bdi, bdi_bits)) {
				ret = 1;
				break;
			}
		}
	}
	rcu_read_unlock();

	return ret;
}

/* Superblock */

static struct cache_member_cpu cache_mi_to_cpu_mi(struct cache_member *mi)
{
	return (struct cache_member_cpu) {
		.nbuckets	= le64_to_cpu(mi->nbuckets),
		.first_bucket	= le16_to_cpu(mi->first_bucket),
		.bucket_size	= le16_to_cpu(mi->bucket_size),
		.state		= CACHE_STATE(mi),
		.tier		= CACHE_TIER(mi),
		.replication_set= CACHE_REPLICATION_SET(mi),
		.has_metadata	= CACHE_HAS_METADATA(mi),
		.has_data	= CACHE_HAS_DATA(mi),
		.replacement	= CACHE_REPLACEMENT(mi),
		.discard	= CACHE_DISCARD(mi),
		.valid		= !bch_is_zero(mi->uuid.b, sizeof(uuid_le)),
	};
}

static const char *validate_cache_super(struct bcache_superblock *disk_sb)
{
	struct cache_sb *sb = disk_sb->sb;
	struct cache_member_cpu	mi;
	u16 block_size;
	unsigned i;

	switch (le64_to_cpu(sb->version)) {
	case BCACHE_SB_VERSION_CDEV_V0:
	case BCACHE_SB_VERSION_CDEV_WITH_UUID:
	case BCACHE_SB_VERSION_CDEV_V2:
	case BCACHE_SB_VERSION_CDEV_V3:
		break;
	default:
		return"Unsupported superblock version";
	}

	if (CACHE_SET_SYNC(sb) &&
	    le64_to_cpu(sb->version) != BCACHE_SB_VERSION_CDEV_V3)
		return "Unsupported superblock version";

	block_size = le16_to_cpu(sb->block_size);

	if (!is_power_of_2(block_size) ||
	    block_size > PAGE_SECTORS)
		return "Bad block size";

	if (bch_is_zero(sb->disk_uuid.b, sizeof(uuid_le)))
		return "Bad disk UUID";

	if (bch_is_zero(sb->user_uuid.b, sizeof(uuid_le)))
		return "Bad user UUID";

	if (bch_is_zero(sb->set_uuid.b, sizeof(uuid_le)))
		return "Bad set UUID";

	if (!sb->nr_in_set ||
	    sb->nr_in_set <= sb->nr_this_dev ||
	    sb->nr_in_set > MAX_CACHES_PER_SET)
		return "Bad cache device number in set";

	if (!CACHE_SET_META_REPLICAS_WANT(sb) ||
	    CACHE_SET_META_REPLICAS_WANT(sb) >= BCH_REPLICAS_MAX)
		return "Invalid number of metadata replicas";

	if (!CACHE_SET_META_REPLICAS_HAVE(sb) ||
	    CACHE_SET_META_REPLICAS_HAVE(sb) >
	    CACHE_SET_META_REPLICAS_WANT(sb))
		return "Invalid number of metadata replicas";

	if (!CACHE_SET_DATA_REPLICAS_WANT(sb) ||
	    CACHE_SET_DATA_REPLICAS_WANT(sb) >= BCH_REPLICAS_MAX)
		return "Invalid number of data replicas";

	if (!CACHE_SET_DATA_REPLICAS_HAVE(sb) ||
	    CACHE_SET_DATA_REPLICAS_HAVE(sb) >
	    CACHE_SET_DATA_REPLICAS_WANT(sb))
		return "Invalid number of data replicas";

	if (CACHE_SB_CSUM_TYPE(sb) >= BCH_CSUM_NR)
		return "Invalid checksum type";

	if (!CACHE_SET_BTREE_NODE_SIZE(sb))
		return "Btree node size not set";

	if (!is_power_of_2(CACHE_SET_BTREE_NODE_SIZE(sb)))
		return "Btree node size not a power of two";

	if (CACHE_SET_BTREE_NODE_SIZE(sb) > BTREE_NODE_SIZE_MAX)
		return "Btree node size too large";

	/* Default value, for old filesystems: */
	if (!CACHE_SET_GC_RESERVE(sb))
		SET_CACHE_SET_GC_RESERVE(sb, 10);

	if (CACHE_SET_GC_RESERVE(sb) < 5)
		return "gc reserve percentage too small";

	if (le16_to_cpu(sb->u64s) < bch_journal_buckets_offset(sb))
		return "Invalid superblock: member info area missing";

	mi = cache_mi_to_cpu_mi(sb->members + sb->nr_this_dev);

	if (mi.nbuckets > LONG_MAX)
		return "Too many buckets";

	if (mi.nbuckets < 1 << 8)
		return "Not enough buckets";

	if (!is_power_of_2(mi.bucket_size) ||
	    mi.bucket_size < PAGE_SECTORS ||
	    mi.bucket_size < block_size)
		return "Bad bucket size";

	if (get_capacity(disk_sb->bdev->bd_disk) <
	    mi.bucket_size * mi.nbuckets)
		return "Invalid superblock: device too small";

	if (le64_to_cpu(sb->offset) +
	    (__set_blocks(sb, le16_to_cpu(sb->u64s),
			  block_size << 9) * block_size) >
	    mi.first_bucket * mi.bucket_size)
		return "Invalid superblock: first bucket comes before end of super";

	for (i = 0; i < bch_nr_journal_buckets(sb); i++)
		if (journal_bucket(sb, i) <  mi.first_bucket ||
		    journal_bucket(sb, i) >= mi.nbuckets)
			return "bad journal bucket";

	return NULL;
}

void free_super(struct bcache_superblock *sb)
{
	if (sb->bio)
		bio_put(sb->bio);
	if (!IS_ERR_OR_NULL(sb->bdev))
		blkdev_put(sb->bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);

	free_pages((unsigned long) sb->sb, sb->page_order);
	memset(sb, 0, sizeof(*sb));
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

	bio = (dynamic_fault("bcache:add:super_realloc")
	       ? NULL
	       : bio_kmalloc(GFP_KERNEL, 1 << order));
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

int bch_super_realloc(struct bcache_superblock *sb, unsigned u64s)
{
	struct cache_member *mi = sb->sb->members + sb->sb->nr_this_dev;
	char buf[BDEVNAME_SIZE];
	size_t bytes = __set_bytes((struct cache_sb *) NULL, u64s);
	u64 want = bytes + (SB_SECTOR << 9);

	u64 first_bucket_offset = (u64) le16_to_cpu(mi->first_bucket) *
		((u64) le16_to_cpu(mi->bucket_size) << 9);

	if (want > first_bucket_offset) {
		pr_err("%s: superblock too big: want %llu but have %llu",
		       bdevname(sb->bdev, buf), want, first_bucket_offset);
		return -ENOSPC;
	}

	return __bch_super_realloc(sb, get_order(bytes));
}

static const char *read_super(struct bcache_superblock *sb,
			      const char *path)
{
	const char *err;
	unsigned order = 0;

	lockdep_assert_held(&bch_register_lock);

	memset(sb, 0, sizeof(*sb));

	err = bch_blkdev_open(path, &sb, &sb->bdev);
	if (err)
		return err;
retry:
	err = "cannot allocate memory";
	if (__bch_super_realloc(sb, order))
		goto err;

	err = "dynamic fault";
	if (cache_set_init_fault("read_super"))
		goto err;

	bio_reset(sb->bio);
	sb->bio->bi_bdev = sb->bdev;
	sb->bio->bi_iter.bi_sector = SB_SECTOR;
	sb->bio->bi_iter.bi_size = PAGE_SIZE << sb->page_order;
	bio_set_op_attrs(sb->bio, REQ_OP_READ, REQ_SYNC|REQ_META);
	bch_bio_map(sb->bio, sb->sb);

	err = "IO error";
	if (submit_bio_wait(sb->bio))
		goto err;

	err = "Not a bcache superblock";
	if (uuid_le_cmp(sb->sb->magic, BCACHE_MAGIC))
		goto err;

	err = "Superblock has incorrect offset";
	if (le64_to_cpu(sb->sb->offset) != SB_SECTOR)
		goto err;

	pr_debug("read sb version %llu, flags %llu, seq %llu, journal size %u",
		 le64_to_cpu(sb->sb->version),
		 le64_to_cpu(sb->sb->flags),
		 le64_to_cpu(sb->sb->seq),
		 le16_to_cpu(sb->sb->u64s));

	err = "Superblock block size smaller than device block size";
	if (le16_to_cpu(sb->sb->block_size) << 9 <
	    bdev_logical_block_size(sb->bdev))
		goto err;

	order = get_order(__set_bytes(sb->sb, le16_to_cpu(sb->sb->u64s)));
	if (order > sb->page_order)
		goto retry;

	err = "bad checksum reading superblock";
	if (le64_to_cpu(sb->sb->csum) !=
	    __csum_set(sb->sb, le16_to_cpu(sb->sb->u64s),
		       le64_to_cpu(sb->sb->version) <
		       BCACHE_SB_VERSION_CDEV_V3
		       ? BCH_CSUM_CRC64
		       : CACHE_SB_CSUM_TYPE(sb->sb)))
		goto err;

	return NULL;
err:
	free_super(sb);
	return err;
}

void __write_super(struct cache_set *c, struct bcache_superblock *disk_sb)
{
	struct cache_sb *sb = disk_sb->sb;
	struct bio *bio = disk_sb->bio;

	bio->bi_bdev		= disk_sb->bdev;
	bio->bi_iter.bi_sector	= SB_SECTOR;
	bio->bi_iter.bi_size	=
		roundup(__set_bytes(sb, le16_to_cpu(sb->u64s)),
			bdev_logical_block_size(disk_sb->bdev));
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_SYNC|REQ_META);
	bch_bio_map(bio, sb);

	pr_debug("ver %llu, flags %llu, seq %llu",
		 le64_to_cpu(sb->version),
		 le64_to_cpu(sb->flags),
		 le64_to_cpu(sb->seq));

	bch_generic_make_request(bio, c);
}

static void write_super_endio(struct bio *bio)
{
	struct cache *ca = bio->bi_private;

	/* XXX: return errors directly */

	cache_fatal_io_err_on(bio->bi_error, ca, "superblock write");

	bch_account_io_completion(ca);

	closure_put(&ca->set->sb_write);
	percpu_ref_put(&ca->ref);
}

static void bcache_write_super_unlock(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, sb_write);

	up(&c->sb_write_mutex);
}

/* Update cached mi: */
static int cache_set_mi_update(struct cache_set *c,
			       struct cache_member *mi,
			       unsigned nr_in_set)
{
	struct cache_member_rcu *new, *old;
	struct cache *ca;
	unsigned i;

	mutex_lock(&c->mi_lock);

	new = kzalloc(sizeof(struct cache_member_rcu) +
		      sizeof(struct cache_member_cpu) * nr_in_set,
		      GFP_KERNEL);
	if (!new) {
		mutex_unlock(&c->mi_lock);
		return -ENOMEM;
	}

	new->nr_in_set = nr_in_set;

	for (i = 0; i < nr_in_set; i++)
		new->m[i] = cache_mi_to_cpu_mi(&mi[i]);

	rcu_read_lock();
	for_each_cache(ca, c, i)
		ca->mi = new->m[i];
	rcu_read_unlock();

	old = rcu_dereference_protected(c->members,
				lockdep_is_held(&c->mi_lock));

	rcu_assign_pointer(c->members, new);
	if (old)
		kfree_rcu(old, rcu);

	mutex_unlock(&c->mi_lock);
	return 0;
}

/* doesn't copy member info */
static void __copy_super(struct cache_sb *dst, struct cache_sb *src)
{
	dst->version		= src->version;
	dst->seq		= src->seq;
	dst->user_uuid		= src->user_uuid;
	dst->set_uuid		= src->set_uuid;
	memcpy(dst->label, src->label, SB_LABEL_SIZE);
	dst->flags		= src->flags;
	dst->flags2		= src->flags2;
	dst->nr_in_set		= src->nr_in_set;
	dst->block_size		= src->block_size;
}

static int cache_sb_to_cache_set(struct cache_set *c, struct cache_sb *src)
{
	struct cache_member *new;

	lockdep_assert_held(&bch_register_lock);

	new = kzalloc(sizeof(struct cache_member) * src->nr_in_set,
		      GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	memcpy(new, src->members,
	       src->nr_in_set * sizeof(struct cache_member));

	if (cache_set_mi_update(c, new, src->nr_in_set)) {
		kfree(new);
		return -ENOMEM;
	}

	kfree(c->disk_mi);
	c->disk_mi = new;

	__copy_super(&c->disk_sb, src);

	c->sb.block_size	= le16_to_cpu(src->block_size);
	c->sb.btree_node_size	= CACHE_SET_BTREE_NODE_SIZE(src);
	c->sb.nr_in_set		= src->nr_in_set;
	c->sb.clean		= CACHE_SET_CLEAN(src);
	c->sb.meta_replicas_have= CACHE_SET_META_REPLICAS_HAVE(src);
	c->sb.data_replicas_have= CACHE_SET_DATA_REPLICAS_HAVE(src);
	c->sb.str_hash_type	= CACHE_SET_STR_HASH_TYPE(src);

	return 0;
}

static int cache_sb_from_cache_set(struct cache_set *c, struct cache *ca)
{
	struct cache_sb *src = &c->disk_sb, *dst = ca->disk_sb.sb;

	if (src->nr_in_set != dst->nr_in_set) {
		/*
		 * We have to preserve the list of journal buckets on the
		 * cache's superblock:
		 */
		unsigned old_offset = bch_journal_buckets_offset(dst);
		unsigned u64s = bch_journal_buckets_offset(src)
			+ bch_nr_journal_buckets(dst);
		int ret = bch_super_realloc(&ca->disk_sb, u64s);

		if (ret)
			return ret;

		dst->nr_in_set	= src->nr_in_set;
		dst->u64s	= cpu_to_le16(u64s);

		memmove(dst->_data + bch_journal_buckets_offset(dst),
			dst->_data + old_offset,
			bch_nr_journal_buckets(dst) * sizeof(u64));
	}

	memcpy(dst->_data,
	       c->disk_mi,
	       src->nr_in_set * sizeof(struct cache_member));

	__copy_super(dst, src);

	return 0;
}

static void __bcache_write_super(struct cache_set *c)
{
	struct closure *cl = &c->sb_write;
	struct cache *ca;
	unsigned i;

	cache_set_mi_update(c, c->disk_mi, c->sb.nr_in_set);

	closure_init(cl, &c->cl);

	le64_add_cpu(&c->disk_sb.seq, 1);

	for_each_cache(ca, c, i) {
		struct cache_sb *sb = ca->disk_sb.sb;
		struct bio *bio = ca->disk_sb.bio;

		cache_sb_from_cache_set(c, ca);

		SET_CACHE_SB_CSUM_TYPE(sb, c->opts.metadata_checksum);
		sb->csum = cpu_to_le64(__csum_set(sb,
						  le16_to_cpu(sb->u64s),
						  CACHE_SB_CSUM_TYPE(sb)));

		bio_reset(bio);
		bio->bi_bdev	= ca->disk_sb.bdev;
		bio->bi_end_io	= write_super_endio;
		bio->bi_private = ca;

		closure_get(cl);
		percpu_ref_get(&ca->ref);
		__write_super(c, &ca->disk_sb);
	}

	closure_return_with_destructor(cl, bcache_write_super_unlock);
}

void bcache_write_super(struct cache_set *c)
{
	down(&c->sb_write_mutex);
	__bcache_write_super(c);
}

void bch_check_mark_super_slowpath(struct cache_set *c, const struct bkey_i *k,
				   bool meta)
{
	struct cache_member *mi;
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
	const struct bch_extent_ptr *ptr;

	down(&c->sb_write_mutex);

	/* recheck, might have raced */
	if (bch_check_super_marked(c, k, meta)) {
		up(&c->sb_write_mutex);
		return;
	}

	mi = c->disk_mi;

	extent_for_each_ptr(e, ptr)
		if (bch_extent_ptr_is_dirty(c, e, ptr))
			(meta
			 ? SET_CACHE_HAS_METADATA
			 : SET_CACHE_HAS_DATA)(mi + ptr->dev, true);

	__bcache_write_super(c);
}

/* Cache set RO/RW: */

/*
 * For startup/shutdown of RW stuff, the dependencies are:
 *
 * - foreground writes depend on copygc and tiering (to free up space)
 *
 * - copygc and tiering depend on mark and sweep gc (they actually probably
 *   don't because they either reserve ahead of time or don't block if
 *   allocations fail, but allocations can require mark and sweep gc to run
 *   because of generation number wraparound)
 *
 * - all of the above depends on the allocator threads
 *
 * - allocator depends on the journal (when it rewrites prios and gens)
 */

static void __bch_cache_read_only(struct cache *ca);

static void __bch_cache_set_read_only(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;

	c->tiering_pd.rate.rate = UINT_MAX;
	bch_ratelimit_reset(&c->tiering_pd.rate);
	bch_tiering_read_stop(c);

	for_each_cache(ca, c, i)
		bch_moving_gc_stop(ca);

	bch_gc_thread_stop(c);

	bch_btree_flush(c);

	for_each_cache(ca, c, i)
		bch_cache_allocator_stop(ca);

	/*
	 * Write a journal entry after flushing the btree, so we don't end up
	 * replaying everything we just flushed:
	 */
	if (test_bit(CACHE_SET_INITIAL_GC_DONE, &c->flags))
		bch_journal_meta(&c->journal);

	cancel_delayed_work_sync(&c->journal.write_work);
	cancel_delayed_work_sync(&c->journal.reclaim_work);
}

static void bch_writes_disabled(struct percpu_ref *writes)
{
	struct cache_set *c = container_of(writes, struct cache_set, writes);

	set_bit(CACHE_SET_WRITE_DISABLE_COMPLETE, &c->flags);
	wake_up(&bch_read_only_wait);
}

static void bch_cache_set_read_only_work(struct work_struct *work)
{
	struct cache_set *c =
		container_of(work, struct cache_set, read_only_work);

	percpu_ref_put(&c->writes);

	del_timer_sync(&c->foreground_write_wakeup);
	cancel_delayed_work_sync(&c->pd_controllers_update);

	c->foreground_write_pd.rate.rate = UINT_MAX;
	bch_wake_delayed_writes((unsigned long) c);

	if (!test_bit(CACHE_SET_EMERGENCY_RO, &c->flags)) {
		/*
		 * If we're not doing an emergency shutdown, we want to wait on
		 * outstanding writes to complete so they don't see spurious
		 * errors due to shutting down the allocator:
		 */
		wait_event(bch_read_only_wait,
			   test_bit(CACHE_SET_WRITE_DISABLE_COMPLETE, &c->flags));

		__bch_cache_set_read_only(c);

		if (!bch_journal_error(&c->journal) &&
		    !test_bit(CACHE_SET_ERROR, &c->flags)) {
			SET_CACHE_SET_CLEAN(&c->disk_sb, true);
			bcache_write_super(c);
		}
	} else {
		/*
		 * If we are doing an emergency shutdown outstanding writes may
		 * hang until we shutdown the allocator so we don't want to wait
		 * on outstanding writes before shutting everything down - but
		 * we do need to wait on them before returning and signalling
		 * that going RO is complete:
		 */
		__bch_cache_set_read_only(c);

		wait_event(bch_read_only_wait,
			   test_bit(CACHE_SET_WRITE_DISABLE_COMPLETE, &c->flags));
	}

	bch_notify_cache_set_read_only(c);
	trace_bcache_cache_set_read_only_done(c);

	set_bit(CACHE_SET_RO_COMPLETE, &c->flags);
	wake_up(&bch_read_only_wait);
}

bool bch_cache_set_read_only(struct cache_set *c)
{
	if (test_and_set_bit(CACHE_SET_RO, &c->flags))
		return false;

	trace_bcache_cache_set_read_only(c);

	percpu_ref_get(&c->writes);

	/*
	 * Block new foreground-end write operations from starting - any new
	 * writes will return -EROFS:
	 *
	 * (This is really blocking new _allocations_, writes to previously
	 * allocated space can still happen until stopping the allocator in
	 * bch_cache_allocator_stop()).
	 */
	percpu_ref_kill(&c->writes);

	queue_work(system_freezable_wq, &c->read_only_work);
	return true;
}

bool bch_cache_set_emergency_read_only(struct cache_set *c)
{
	bool ret = !test_and_set_bit(CACHE_SET_EMERGENCY_RO, &c->flags);

	bch_cache_set_read_only(c);
	bch_journal_halt(&c->journal);

	wake_up(&bch_read_only_wait);
	return ret;
}

void bch_cache_set_read_only_sync(struct cache_set *c)
{
	/* so we don't race with bch_cache_set_read_write() */
	lockdep_assert_held(&bch_register_lock);

	bch_cache_set_read_only(c);

	wait_event(bch_read_only_wait,
		   test_bit(CACHE_SET_RO_COMPLETE, &c->flags) &&
		   test_bit(CACHE_SET_WRITE_DISABLE_COMPLETE, &c->flags));
}

static const char *__bch_cache_set_read_write(struct cache_set *c)
{
	struct cache *ca;
	const char *err;
	unsigned i;

	lockdep_assert_held(&bch_register_lock);

	err = "error starting allocator thread";
	for_each_cache(ca, c, i)
		if (ca->mi.state == CACHE_ACTIVE &&
		    bch_cache_allocator_start(ca)) {
			percpu_ref_put(&ca->ref);
			goto err;
		}

	err = "error starting btree GC thread";
	if (bch_gc_thread_start(c))
		goto err;

	for_each_cache(ca, c, i) {
		if (ca->mi.state != CACHE_ACTIVE)
			continue;

		err = "error starting moving GC thread";
		if (bch_moving_gc_thread_start(ca)) {
			percpu_ref_put(&ca->ref);
			goto err;
		}
	}

	err = "error starting tiering thread";
	if (bch_tiering_read_start(c))
		goto err;

	schedule_delayed_work(&c->pd_controllers_update, 5 * HZ);

	return NULL;
err:
	__bch_cache_set_read_only(c);
	return err;
}

const char *bch_cache_set_read_write(struct cache_set *c)
{
	const char *err;

	lockdep_assert_held(&bch_register_lock);

	if (!test_bit(CACHE_SET_RO_COMPLETE, &c->flags))
		return NULL;

	err = __bch_cache_set_read_write(c);
	if (err)
		return err;

	percpu_ref_reinit(&c->writes);

	clear_bit(CACHE_SET_WRITE_DISABLE_COMPLETE, &c->flags);
	clear_bit(CACHE_SET_EMERGENCY_RO, &c->flags);
	clear_bit(CACHE_SET_RO_COMPLETE, &c->flags);
	clear_bit(CACHE_SET_RO, &c->flags);
	return NULL;
}

/* Cache set startup/shutdown: */

static void cache_set_free(struct cache_set *c)
{
	cancel_work_sync(&c->read_only_work);
	cancel_work_sync(&c->bio_submit_work);
	cancel_work_sync(&c->read_retry_work);

	bch_btree_cache_free(c);
	bch_journal_free(&c->journal);
	bch_io_clock_exit(&c->io_clock[WRITE]);
	bch_io_clock_exit(&c->io_clock[READ]);
	bch_compress_free(c);
	bdi_destroy(&c->bdi);
	free_percpu(c->bucket_stats_lock.lock);
	free_percpu(c->bucket_stats_percpu);
	mempool_exit(&c->btree_bounce_pool);
	mempool_exit(&c->bio_bounce_pages);
	bioset_exit(&c->bio_write);
	bioset_exit(&c->bio_read_split);
	bioset_exit(&c->bio_read);
	bioset_exit(&c->btree_read_bio);
	mempool_exit(&c->btree_interior_update_pool);
	mempool_exit(&c->btree_reserve_pool);
	mempool_exit(&c->fill_iter);
	mempool_exit(&c->search);
	percpu_ref_exit(&c->writes);

	if (c->copygc_wq)
		destroy_workqueue(c->copygc_wq);
	if (c->wq)
		destroy_workqueue(c->wq);

	kfree_rcu(rcu_dereference_protected(c->members, 1), rcu); /* shutting down */
	kfree(c->disk_mi);
	kfree(c);
	module_put(THIS_MODULE);
}

/*
 * should be __cache_set_stop4 - block devices are closed, now we can finally
 * free it
 */
void bch_cache_set_release(struct kobject *kobj)
{
	struct cache_set *c = container_of(kobj, struct cache_set, kobj);

	/*
	 * This needs to happen after we've closed the block devices - i.e.
	 * after all the caches have exited, which happens when they all drop
	 * their refs on c->kobj:
	 */
	if (c->stop_completion)
		complete(c->stop_completion);

	bch_notify_cache_set_stopped(c);
	bch_info(c, "stopped");

	cache_set_free(c);
}

/*
 * All activity on the cache_set should have stopped now - close devices:
 */
static void __cache_set_stop3(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, cl);
	struct cache *ca;
	unsigned i;

	mutex_lock(&bch_register_lock);
	for_each_cache(ca, c, i)
		bch_cache_stop(ca);
	mutex_unlock(&bch_register_lock);

	mutex_lock(&bch_register_lock);
	list_del(&c->list);
	if (c->minor >= 0)
		idr_remove(&bch_chardev_minor, c->minor);
	mutex_unlock(&bch_register_lock);

	closure_debug_destroy(&c->cl);
	kobject_put(&c->kobj);
}

/*
 * Openers (i.e. block devices) should have exited, shutdown all userspace
 * interfaces and wait for &c->cl to hit 0
 */
static void __cache_set_stop2(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);

	bch_debug_exit_cache_set(c);

	if (!IS_ERR_OR_NULL(c->chardev))
		device_unregister(c->chardev);

	if (c->kobj.state_in_sysfs)
		kobject_del(&c->kobj);

	bch_cache_accounting_destroy(&c->accounting);

	kobject_put(&c->time_stats);
	kobject_put(&c->opts_dir);
	kobject_put(&c->internal);

	mutex_lock(&bch_register_lock);
	bch_cache_set_read_only_sync(c);
	mutex_unlock(&bch_register_lock);

	closure_return(cl);
}

/*
 * First phase of the shutdown process that's kicked off by cache_set_stop(); we
 * haven't waited for anything to stop yet, we're just punting to process
 * context to shut down block devices:
 */
static void __cache_set_stop1(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);

	bch_blockdevs_stop(c);

	continue_at(cl, __cache_set_stop2, system_wq);
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
	struct cache_member *mi = c->disk_mi;

	lockdep_assert_held(&bch_register_lock);

	for (i = 0; i < c->disk_sb.nr_in_set; i++)
		if (!bch_is_zero(mi[i].uuid.b, sizeof(uuid_le)))
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

#define alloc_bucket_pages(gfp, ca)			\
	((void *) __get_free_pages(__GFP_ZERO|gfp, ilog2(bucket_pages(ca))))

static struct cache_set *bch_cache_set_alloc(struct cache_sb *sb,
					     struct cache_set_opts opts)
{
	struct cache_set *c;
	unsigned iter_size;

	c = kzalloc(sizeof(struct cache_set), GFP_KERNEL);
	if (!c)
		return NULL;

	__module_get(THIS_MODULE);

	c->minor		= -1;

	sema_init(&c->sb_write_mutex, 1);
	INIT_RADIX_TREE(&c->devices, GFP_KERNEL);
	mutex_init(&c->btree_cache_lock);
	lg_lock_init(&c->bucket_stats_lock);
	mutex_init(&c->bucket_lock);
	mutex_init(&c->btree_root_lock);
	INIT_WORK(&c->read_only_work, bch_cache_set_read_only_work);
	mutex_init(&c->mi_lock);

	init_rwsem(&c->gc_lock);

#define BCH_TIME_STAT(name, frequency_units, duration_units)		\
	spin_lock_init(&c->name##_time.lock);
	BCH_TIME_STATS()
#undef BCH_TIME_STAT

	bch_open_buckets_init(c);
	bch_tiering_init_cache_set(c);

	INIT_LIST_HEAD(&c->list);
	INIT_LIST_HEAD(&c->cached_devs);
	INIT_LIST_HEAD(&c->btree_cache);
	INIT_LIST_HEAD(&c->btree_cache_freeable);
	INIT_LIST_HEAD(&c->btree_cache_freed);

	INIT_LIST_HEAD(&c->btree_interior_update_list);
	mutex_init(&c->btree_reserve_cache_lock);
	mutex_init(&c->btree_interior_update_lock);

	mutex_init(&c->bio_bounce_pages_lock);
	INIT_WORK(&c->bio_submit_work, bch_bio_submit_work);
	spin_lock_init(&c->bio_submit_lock);
	bio_list_init(&c->read_retry_list);
	spin_lock_init(&c->read_retry_lock);
	INIT_WORK(&c->read_retry_work, bch_read_retry_work);
	mutex_init(&c->zlib_workspace_lock);

	seqcount_init(&c->gc_pos_lock);

	c->prio_clock[READ].hand = 1;
	c->prio_clock[READ].min_prio = 0;
	c->prio_clock[WRITE].hand = 1;
	c->prio_clock[WRITE].min_prio = 0;

	c->congested_read_threshold_us	= 2000;
	c->congested_write_threshold_us	= 20000;
	c->error_limit	= 16 << IO_ERROR_SHIFT;
	init_waitqueue_head(&c->writeback_wait);

	c->writeback_pages_max = (256 << 10) / PAGE_SIZE;

	c->copy_gc_enabled = 1;
	c->tiering_enabled = 1;
	c->tiering_percent = 10;

	c->foreground_target_percent = 20;

	c->journal.write_time	= &c->journal_write_time;
	c->journal.delay_time	= &c->journal_delay_time;
	c->journal.blocked_time	= &c->journal_blocked_time;
	c->journal.flush_seq_time = &c->journal_flush_seq_time;

	mutex_init(&c->uevent_lock);

	if (cache_sb_to_cache_set(c, sb))
		goto err;

	scnprintf(c->name, sizeof(c->name), "%pU", &c->disk_sb.user_uuid);

	c->opts = cache_superblock_opts(sb);
	cache_set_opts_apply(&c->opts, opts);

	c->block_bits		= ilog2(c->sb.block_size);

	if (cache_set_init_fault("cache_set_alloc"))
		goto err;

	iter_size = (btree_blocks(c) + 1) * 2 *
		sizeof(struct btree_node_iter_set);

	if (!(c->wq = alloc_workqueue("bcache",
				WQ_FREEZABLE|WQ_MEM_RECLAIM|WQ_HIGHPRI, 1)) ||
	    !(c->copygc_wq = alloc_workqueue("bcache_copygc",
				WQ_FREEZABLE|WQ_MEM_RECLAIM|WQ_HIGHPRI, 1)) ||
	    percpu_ref_init(&c->writes, bch_writes_disabled, 0, GFP_KERNEL) ||
	    mempool_init_slab_pool(&c->search, 1, bch_search_cache) ||
	    mempool_init_kmalloc_pool(&c->btree_reserve_pool, 1,
				      sizeof(struct btree_reserve)) ||
	    mempool_init_kmalloc_pool(&c->btree_interior_update_pool, 1,
				      sizeof(struct btree_interior_update)) ||
	    mempool_init_kmalloc_pool(&c->fill_iter, 1, iter_size) ||
	    bioset_init(&c->btree_read_bio, 1, 0) ||
	    bioset_init(&c->bio_read, 1, offsetof(struct bch_read_bio, bio)) ||
	    bioset_init(&c->bio_read_split, 1, offsetof(struct bch_read_bio, bio)) ||
	    bioset_init(&c->bio_write, 1, offsetof(struct bch_write_bio, bio)) ||
	    mempool_init_page_pool(&c->bio_bounce_pages,
				   max_t(unsigned,
					 c->sb.btree_node_size,
					 CRC32_EXTENT_SIZE_MAX) /
				   PAGE_SECTORS, 0) ||
	    !(c->bucket_stats_percpu = alloc_percpu(struct bucket_stats_cache_set)) ||
	    !(c->bucket_stats_lock.lock = alloc_percpu(*c->bucket_stats_lock.lock)) ||
	    mempool_init_page_pool(&c->btree_bounce_pool, 1,
				   ilog2(btree_pages(c))) ||
	    bdi_setup_and_register(&c->bdi, "bcache") ||
	    bch_io_clock_init(&c->io_clock[READ]) ||
	    bch_io_clock_init(&c->io_clock[WRITE]) ||
	    bch_journal_alloc(&c->journal) ||
	    bch_btree_cache_alloc(c) ||
	    bch_compress_init(c))
		goto err;

	c->bdi.ra_pages		= VM_MAX_READAHEAD * 1024 / PAGE_SIZE;
	c->bdi.congested_fn	= bch_congested_fn;
	c->bdi.congested_data	= c;

	/*
	 * Now that all allocations have succeeded, init various refcounty
	 * things that let us shutdown:
	 */
	closure_init(&c->cl, NULL);

	c->kobj.kset = bcache_kset;
	kobject_init(&c->kobj, &bch_cache_set_ktype);
	kobject_init(&c->internal, &bch_cache_set_internal_ktype);
	kobject_init(&c->opts_dir, &bch_cache_set_opts_dir_ktype);
	kobject_init(&c->time_stats, &bch_cache_set_time_stats_ktype);

	bch_cache_accounting_init(&c->accounting, &c->cl);

	closure_init(&c->caching, &c->cl);
	set_closure_fn(&c->caching, __cache_set_stop1, system_wq);

	continue_at_noreturn(&c->cl, __cache_set_stop3, system_wq);
	return c;
err:
	cache_set_free(c);
	return NULL;
}

static int bch_cache_set_online(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;

	lockdep_assert_held(&bch_register_lock);

	if (c->kobj.state_in_sysfs)
		return 0;

	c->minor = idr_alloc(&bch_chardev_minor, c, 0, 0, GFP_KERNEL);
	if (c->minor < 0)
		return c->minor;

	c->chardev = device_create(bch_chardev_class, NULL,
				   MKDEV(bch_chardev_major, c->minor), NULL,
				   "bcache%u-ctl", c->minor);
	if (IS_ERR(c->chardev))
		return PTR_ERR(c->chardev);

	if (kobject_add(&c->kobj, NULL, "%pU", c->disk_sb.user_uuid.b) ||
	    kobject_add(&c->internal, &c->kobj, "internal") ||
	    kobject_add(&c->opts_dir, &c->kobj, "options") ||
	    kobject_add(&c->time_stats, &c->kobj, "time_stats") ||
	    bch_cache_accounting_add_kobjs(&c->accounting, &c->kobj))
		return -1;

	for_each_cache(ca, c, i)
		if (bch_cache_online(ca)) {
			percpu_ref_put(&ca->ref);
			return -1;
		}

	list_add(&c->list, &bch_cache_sets);
	return 0;
}

static const char *run_cache_set(struct cache_set *c)
{
	const char *err = "cannot allocate memory";
	struct cache *ca;
	unsigned i, id;
	time64_t now;
	LIST_HEAD(journal);
	struct jset *j;
	int ret;

	lockdep_assert_held(&bch_register_lock);
	BUG_ON(test_bit(CACHE_SET_RUNNING, &c->flags));

	/* We don't want bch_fatal_error() to free underneath us */
	closure_get(&c->caching);

	/*
	 * Make sure that each cache object's mi is up to date before
	 * we start testing it.
	 */
	for_each_cache(ca, c, i)
		cache_sb_from_cache_set(c, ca);

	/*
	 * CACHE_SET_SYNC is true if the cache set has already been run
	 * and potentially has data.
	 * It is false if it is the first time it is run.
	 */

	if (CACHE_SET_SYNC(&c->disk_sb)) {
		err = bch_journal_read(c, &journal);
		if (err)
			goto err;

		pr_debug("btree_journal_read() done");

		j = &list_entry(journal.prev, struct journal_replay, list)->j;

		err = "error reading priorities";
		for_each_cache(ca, c, i)
			if (bch_prio_read(ca)) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		c->prio_clock[READ].hand = le16_to_cpu(j->read_clock);
		c->prio_clock[WRITE].hand = le16_to_cpu(j->write_clock);

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
			struct bkey_i *k;

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

		bch_verbose(c, "starting mark and sweep:");

		err = "error in recovery";
		if (bch_initial_gc(c, &journal))
			goto err;

		bch_verbose(c, "mark and sweep done");

		/*
		 * bch_journal_start() can't happen sooner, or btree_gc_finish()
		 * will give spurious errors about oldest_gen > bucket_gen -
		 * this is a hack but oh well.
		 */
		bch_journal_start(c);

		for_each_cache(ca, c, i)
			if (ca->mi.state == CACHE_ACTIVE &&
			    (err = bch_cache_allocator_start_once(ca))) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		bch_verbose(c, "starting journal replay:");

		err = "journal replay failed";
		if (bch_journal_replay(c, &journal))
			goto err;

		bch_verbose(c, "journal replay done");

		/*
		 * Write a new journal entry _before_ we start journalling new
		 * data - otherwise, we could end up with btree node bsets with
		 * journal seqs arbitrarily far in the future vs. the most
		 * recently written journal entry on disk, if we crash before
		 * writing the next journal entry:
		 */
		err = "error writing journal entry";
		if (bch_journal_meta(&c->journal))
			goto err;

		bch_verbose(c, "starting fs gc:");
		err = "error in fs gc";
		ret = bch_gc_inode_nlinks(c);
		if (ret)
			goto fsck_err;
		bch_verbose(c, "fs gc done");

		if (!c->opts.nofsck) {
			bch_verbose(c, "starting fsck:");
			err = "error in fsck";
			ret = bch_fsck(c);
			if (ret)
				goto fsck_err;
			bch_verbose(c, "fsck done");
		}
	} else {
		struct bkey_i_inode inode;
		struct closure cl;

		closure_init_stack(&cl);

		bch_notice(c, "initializing new filesystem");

		err = "unable to allocate journal buckets";
		for_each_cache(ca, c, i)
			if (bch_cache_journal_alloc(ca)) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		bch_initial_gc(c, NULL);

		/*
		 * journal_res_get() will crash if called before this has
		 * set up the journal.pin FIFO and journal.cur pointer:
		 */
		bch_journal_start(c);
		bch_journal_set_replay_done(&c->journal);

		for_each_cache(ca, c, i)
			if (ca->mi.state == CACHE_ACTIVE &&
			    (err = bch_cache_allocator_start_once(ca))) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		err = "cannot allocate new btree root";
		for (id = 0; id < BTREE_ID_NR; id++)
			if (bch_btree_root_alloc(c, id, &cl)) {
				closure_sync(&cl);
				goto err;
			}

		/* Wait for new btree roots to be written: */
		closure_sync(&cl);

		bkey_inode_init(&inode.k_i);
		inode.k.p.inode = BCACHE_ROOT_INO;
		inode.v.i_mode = cpu_to_le16(S_IFDIR|S_IRWXU|S_IRUGO|S_IXUGO);
		inode.v.i_nlink = cpu_to_le32(2);
		get_random_bytes(&inode.v.i_hash_seed, sizeof(inode.v.i_hash_seed));
		SET_INODE_STR_HASH_TYPE(&inode.v, c->sb.str_hash_type);

		err = "error creating root directory";
		if (bch_btree_insert(c, BTREE_ID_INODES, &inode.k_i,
				     NULL, NULL, NULL, 0))
			goto err;

		err = "error writing first journal entry";
		if (bch_journal_meta(&c->journal))
			goto err;

		/* Mark cache set as initialized: */
		SET_CACHE_SET_SYNC(&c->disk_sb, true);
	}

	if (c->opts.read_only) {
		bch_cache_set_read_only_sync(c);
	} else {
		err = __bch_cache_set_read_write(c);
		if (err)
			goto err;
	}

	now = ktime_get_seconds();
	rcu_read_lock();
	for_each_cache_rcu(ca, c, i)
		c->disk_mi[ca->sb.nr_this_dev].last_mount = cpu_to_le64(now);
	rcu_read_unlock();

	SET_CACHE_SET_CLEAN(&c->disk_sb, false);
	bcache_write_super(c);

	err = "dynamic fault";
	if (cache_set_init_fault("run_cache_set"))
		goto err;

	err = "error creating kobject";
	if (bch_cache_set_online(c))
		goto err;

	err = "can't bring up blockdev volumes";
	if (bch_blockdev_volumes_start(c))
		goto err;

	bch_debug_init_cache_set(c);
	set_bit(CACHE_SET_RUNNING, &c->flags);
	bch_attach_backing_devs(c);

	closure_put(&c->caching);

	bch_notify_cache_set_read_write(c);

	BUG_ON(!list_empty(&journal));
	return NULL;
err:
	while (!list_empty(&journal)) {
		struct journal_replay *r =
			list_first_entry(&journal, struct journal_replay, list);

		list_del(&r->list);
		kfree(r);
	}

	set_bit(CACHE_SET_ERROR, &c->flags);
	bch_cache_set_unregister(c);
	closure_put(&c->caching);
	return err;
fsck_err:
	switch (ret) {
	case BCH_FSCK_OK:
		break;
	case BCH_FSCK_ERRORS_NOT_FIXED:
		bch_err(c, "filesystem contains errors: please report this to the developers");
		pr_cont("mount with -o fix_errors to repair");
		goto err;
	case BCH_FSCK_REPAIR_UNIMPLEMENTED:
		bch_err(c, "filesystem contains errors: please report this to the developers");
		pr_cont("repair unimplemented: inform the developers so that it can be added");
		goto err;
	default:
		goto err;
	}
	goto err;
}

static const char *can_add_cache(struct cache_sb *sb,
				 struct cache_set *c)
{
	if (le16_to_cpu(sb->block_size) != c->sb.block_size)
		return "mismatched block size";

	if (le16_to_cpu(sb->members[sb->nr_this_dev].bucket_size) <
	    CACHE_SET_BTREE_NODE_SIZE(&c->disk_sb))
		return "new cache bucket_size is too small";

	return NULL;
}

static const char *can_attach_cache(struct cache_sb *sb, struct cache_set *c)
{
	const char *err;
	bool match;

	err = can_add_cache(sb, c);
	if (err)
		return err;

	/*
	 * When attaching an existing device, the cache set superblock must
	 * already contain member_info with a matching UUID
	 */
	match = le64_to_cpu(sb->seq) <= le64_to_cpu(c->disk_sb.seq)
		? (sb->nr_this_dev < c->disk_sb.nr_in_set &&
		   !memcmp(&c->disk_mi[sb->nr_this_dev].uuid,
			   &sb->disk_uuid, sizeof(uuid_le)))
		: (sb->nr_this_dev < sb->nr_in_set &&
		   !memcmp(&sb->members[sb->nr_this_dev].uuid,
			   &sb->disk_uuid, sizeof(uuid_le)));

	if (!match)
		return "cache sb does not match set";

	return NULL;
}

/* Cache device */

static void __bch_cache_read_only(struct cache *ca)
{
	trace_bcache_cache_read_only(ca);

	bch_moving_gc_stop(ca);

	/*
	 * This stops new data writes (e.g. to existing open data
	 * buckets) and then waits for all existing writes to
	 * complete.
	 */
	bch_cache_allocator_stop(ca);

	/*
	 * Device data write barrier -- no non-meta-data writes should
	 * occur after this point.  However, writes to btree buckets,
	 * journal buckets, and the superblock can still occur.
	 */
	trace_bcache_cache_read_only_done(ca);
}

bool bch_cache_read_only(struct cache *ca)
{
	struct cache_set *c = ca->set;
	char buf[BDEVNAME_SIZE];

	bdevname(ca->disk_sb.bdev, buf);

	lockdep_assert_held(&bch_register_lock);

	if (ca->mi.state != CACHE_ACTIVE)
		return false;

	if (!bch_cache_may_remove(ca)) {
		bch_err(c, "required member %s going RO, forcing fs RO", buf);
		bch_cache_set_read_only_sync(c);
	}

	/*
	 * Stop data writes.
	 */
	__bch_cache_read_only(ca);

	bch_notice(c, "%s read only", bdevname(ca->disk_sb.bdev, buf));
	bch_notify_cache_read_only(ca);

	SET_CACHE_STATE(&c->disk_mi[ca->sb.nr_this_dev], CACHE_RO);
	bcache_write_super(c);
	return true;
}

static const char *__bch_cache_read_write(struct cache *ca)
{
	const char *err;

	BUG_ON(ca->mi.state != CACHE_ACTIVE);
	lockdep_assert_held(&bch_register_lock);

	trace_bcache_cache_read_write(ca);

	trace_bcache_cache_read_write_done(ca);

	/* XXX wtf? */
	return NULL;

	err = "error starting moving GC thread";
	if (!bch_moving_gc_thread_start(ca))
		err = NULL;

	wake_up_process(ca->set->tiering_read);

	bch_notify_cache_read_write(ca);

	return err;
}

const char *bch_cache_read_write(struct cache *ca)
{
	struct cache_set *c = ca->set;
	const char *err;

	lockdep_assert_held(&bch_register_lock);

	if (ca->mi.state == CACHE_ACTIVE)
		return NULL;

	if (test_bit(CACHE_DEV_REMOVING, &ca->flags))
		return "removing";

	if (bch_cache_allocator_start(ca))
		return "error starting allocator thread";

	err = __bch_cache_read_write(ca);
	if (err)
		return err;

	SET_CACHE_STATE(&c->disk_mi[ca->sb.nr_this_dev], CACHE_ACTIVE);
	bcache_write_super(c);

	return NULL;
}

/*
 * bch_cache_stop has already returned, so we no longer hold the register
 * lock at the point this is called.
 */

void bch_cache_release(struct kobject *kobj)
{
	struct cache *ca = container_of(kobj, struct cache, kobj);

	percpu_ref_exit(&ca->ref);
	kfree(ca);
}

static void bch_cache_free_work(struct work_struct *work)
{
	struct cache *ca = container_of(work, struct cache, free_work);
	struct cache_set *c = ca->set;
	unsigned i;

	cancel_work_sync(&ca->io_error_work);

	if (c && c->kobj.state_in_sysfs) {
		char buf[12];

		sprintf(buf, "cache%u", ca->sb.nr_this_dev);
		sysfs_remove_link(&c->kobj, buf);
	}

	if (ca->kobj.state_in_sysfs)
		kobject_del(&ca->kobj);

	free_super(&ca->disk_sb);

	if (c)
		kobject_put(&c->kobj);

	/*
	 * bch_cache_stop can be called in the middle of initialization
	 * of the struct cache object.
	 * As such, not all the sub-structures may be initialized.
	 * However, they were zeroed when the object was allocated.
	 */

	free_percpu(ca->sectors_written);
	bioset_exit(&ca->replica_set);
	free_percpu(ca->bucket_stats_percpu);
	kfree(ca->journal.bucket_seq);
	free_pages((unsigned long) ca->disk_buckets, ilog2(bucket_pages(ca)));
	kfree(ca->prio_buckets);
	kfree(ca->bio_prio);
	vfree(ca->buckets);
	vfree(ca->bucket_gens);
	free_heap(&ca->heap);
	free_fifo(&ca->free_inc);

	for (i = 0; i < RESERVE_NR; i++)
		free_fifo(&ca->free[i]);

	kobject_put(&ca->kobj);
}

static void bch_cache_percpu_ref_release(struct percpu_ref *ref)
{
	struct cache *ca = container_of(ref, struct cache, ref);

	schedule_work(&ca->free_work);
}

static void bch_cache_free_rcu(struct rcu_head *rcu)
{
	struct cache *ca = container_of(rcu, struct cache, free_rcu);

	/*
	 * This decrements the ref count to ca, and once the ref count
	 * is 0 (outstanding bios to the ca also incremented it and
	 * decrement it on completion/error), bch_cache_percpu_ref_release
	 * is called, and that eventually results in bch_cache_free_work
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

	if (c) {
		BUG_ON(rcu_access_pointer(c->cache[ca->sb.nr_this_dev]) != ca);
		rcu_assign_pointer(c->cache[ca->sb.nr_this_dev], NULL);
	}

	call_rcu(&ca->free_rcu, bch_cache_free_rcu);
}

static void bch_cache_remove_work(struct work_struct *work)
{
	struct cache *ca = container_of(work, struct cache, remove_work);
	struct cache_set *c = ca->set;
	char name[BDEVNAME_SIZE];
	bool force = test_bit(CACHE_DEV_FORCE_REMOVE, &ca->flags);
	unsigned dev = ca->sb.nr_this_dev;

	bdevname(ca->disk_sb.bdev, name);

	/*
	 * Device should already be RO, now migrate data off:
	 *
	 * XXX: locking is sketchy, bch_cache_read_write() has to check
	 * CACHE_DEV_REMOVING bit
	 */
	if (!ca->mi.has_data) {
		/* Nothing to do: */
	} else if (!bch_move_data_off_device(ca)) {
		lockdep_assert_held(&bch_register_lock);
		SET_CACHE_HAS_DATA(&c->disk_mi[ca->sb.nr_this_dev], false);

		bcache_write_super(c);
	} else if (force) {
		bch_flag_data_bad(ca);

		lockdep_assert_held(&bch_register_lock);
		SET_CACHE_HAS_DATA(&c->disk_mi[ca->sb.nr_this_dev], false);

		bcache_write_super(c);
	} else {
		bch_err(c, "Remove of %s failed, unable to migrate data off",
			name);
		clear_bit(CACHE_DEV_REMOVING, &ca->flags);
		return;
	}

	/* Now metadata: */

	if (!ca->mi.has_metadata) {
		/* Nothing to do: */
	} else if (!bch_move_meta_data_off_device(ca)) {
		lockdep_assert_held(&bch_register_lock);
		SET_CACHE_HAS_METADATA(&c->disk_mi[ca->sb.nr_this_dev], false);

		bcache_write_super(c);
	} else {
		bch_err(c, "Remove of %s failed, unable to migrate metadata off",
			name);
		clear_bit(CACHE_DEV_REMOVING, &ca->flags);
		return;
	}

	/*
	 * Ok, really doing the remove:
	 * Drop device's prio pointer before removing it from superblock:
	 */
	bch_notify_cache_removed(ca);

	spin_lock(&c->journal.lock);
	c->journal.prio_buckets[dev] = 0;
	spin_unlock(&c->journal.lock);

	bch_journal_meta(&c->journal);

	/*
	 * Stop device before removing it from the cache set's list of devices -
	 * and get our own ref on cache set since ca is going away:
	 */
	closure_get(&c->cl);

	mutex_lock(&bch_register_lock);
	bch_cache_stop(ca);

	/*
	 * RCU barrier between dropping between c->cache and dropping from
	 * member info:
	 */
	synchronize_rcu();

	lockdep_assert_held(&bch_register_lock);

	/*
	 * Free this device's slot in the cache_member array - all pointers to
	 * this device must be gone:
	 */
	memset(&c->disk_mi[dev].uuid, 0, sizeof(c->disk_mi[dev].uuid));

	bcache_write_super(c);
	mutex_unlock(&bch_register_lock);

	closure_put(&c->cl);
}

bool bch_cache_remove(struct cache *ca, bool force)
{
	mutex_lock(&bch_register_lock);

	if (test_bit(CACHE_DEV_REMOVING, &ca->flags))
		return false;

	if (!bch_cache_may_remove(ca)) {
		bch_err(ca->set, "Can't remove last device in tier %u",
			ca->mi.tier);
		bch_notify_cache_remove_failed(ca);
		return false;
	}

	/* First, go RO before we try to migrate data off: */
	bch_cache_read_only(ca);

	if (force)
		set_bit(CACHE_DEV_FORCE_REMOVE, &ca->flags);
	set_bit(CACHE_DEV_REMOVING, &ca->flags);
	bch_notify_cache_removing(ca);

	mutex_unlock(&bch_register_lock);

	/* Migrate the data and finish removal asynchronously: */

	queue_work(system_long_wq, &ca->remove_work);
	return true;
}

static int bch_cache_online(struct cache *ca)
{
	char buf[12];

	lockdep_assert_held(&bch_register_lock);

	sprintf(buf, "cache%u", ca->sb.nr_this_dev);

	if (kobject_add(&ca->kobj,
			&part_to_dev(ca->disk_sb.bdev->bd_part)->kobj,
			"bcache") ||
	    sysfs_create_link(&ca->kobj, &ca->set->kobj, "set") ||
	    sysfs_create_link(&ca->set->kobj, &ca->kobj, buf))
		return -1;

	return 0;
}

static const char *cache_alloc(struct bcache_superblock *sb,
			       struct cache_set *c,
			       struct cache **ret)
{
	size_t reserve_none, movinggc_reserve, free_inc_reserve, total_reserve;
	size_t heap_size;
	unsigned i;
	const char *err = "cannot allocate memory";
	struct cache *ca;

	if (c->sb.nr_in_set == 1)
		bdevname(sb->bdev, c->name);

	if (cache_set_init_fault("cache_alloc"))
		return err;

	ca = kzalloc(sizeof(*ca), GFP_KERNEL);
	if (!ca)
		return err;

	if (percpu_ref_init(&ca->ref, bch_cache_percpu_ref_release,
			    0, GFP_KERNEL)) {
		kfree(ca);
		return err;
	}

	kobject_init(&ca->kobj, &bch_cache_ktype);

	spin_lock_init(&ca->self.lock);
	ca->self.nr_devices = 1;
	rcu_assign_pointer(ca->self.d[0].dev, ca);
	ca->sb.nr_this_dev = sb->sb->nr_this_dev;

	INIT_WORK(&ca->free_work, bch_cache_free_work);
	INIT_WORK(&ca->remove_work, bch_cache_remove_work);
	bio_init(&ca->journal.bio);
	ca->journal.bio.bi_max_vecs = 8;
	ca->journal.bio.bi_io_vec = ca->journal.bio.bi_inline_vecs;
	spin_lock_init(&ca->freelist_lock);
	spin_lock_init(&ca->prio_buckets_lock);
	mutex_init(&ca->heap_lock);
	bch_moving_init_cache(ca);

	ca->disk_sb = *sb;
	ca->disk_sb.bdev->bd_holder = ca;
	memset(sb, 0, sizeof(*sb));

	INIT_WORK(&ca->io_error_work, bch_nonfatal_io_error_work);

	err = "dynamic fault";
	if (cache_set_init_fault("cache_alloc"))
		goto err;

	ca->mi = cache_mi_to_cpu_mi(ca->disk_sb.sb->members +
				    ca->disk_sb.sb->nr_this_dev);
	ca->bucket_bits = ilog2(ca->mi.bucket_size);

	/* XXX: tune these */
	movinggc_reserve = max_t(size_t, 16, ca->mi.nbuckets >> 7);
	reserve_none = max_t(size_t, 4, ca->mi.nbuckets >> 9);
	/*
	 * free_inc must be smaller than the copygc reserve: if it was bigger,
	 * one copygc iteration might not make enough buckets available to fill
	 * up free_inc and allow the allocator to make forward progress
	 */
	free_inc_reserve = movinggc_reserve / 2;
	heap_size = movinggc_reserve * 8;

	if (!init_fifo(&ca->free[RESERVE_PRIO], prio_buckets(ca), GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_BTREE], BTREE_NODE_RESERVE, GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_MOVINGGC],
		       movinggc_reserve, GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_NONE], reserve_none, GFP_KERNEL) ||
	    !init_fifo(&ca->free_inc,	free_inc_reserve, GFP_KERNEL) ||
	    !init_heap(&ca->heap,	heap_size, GFP_KERNEL) ||
	    !(ca->bucket_gens	= vzalloc(sizeof(u8) *
					  ca->mi.nbuckets)) ||
	    !(ca->buckets	= vzalloc(sizeof(struct bucket) *
					  ca->mi.nbuckets)) ||
	    !(ca->prio_buckets	= kzalloc(sizeof(uint64_t) * prio_buckets(ca) *
					  2, GFP_KERNEL)) ||
	    !(ca->disk_buckets	= alloc_bucket_pages(GFP_KERNEL, ca)) ||
	    !(ca->bucket_stats_percpu = alloc_percpu(struct bucket_stats_cache)) ||
	    !(ca->journal.bucket_seq = kcalloc(bch_nr_journal_buckets(ca->disk_sb.sb),
					       sizeof(u64), GFP_KERNEL)) ||
	    !(ca->bio_prio = bio_kmalloc(GFP_NOIO, bucket_pages(ca))) ||
	    bioset_init(&ca->replica_set, 4,
			offsetof(struct bch_write_bio, bio)) ||
	    !(ca->sectors_written = alloc_percpu(*ca->sectors_written)))
		goto err;

	ca->prio_last_buckets = ca->prio_buckets + prio_buckets(ca);

	total_reserve = ca->free_inc.size;
	for (i = 0; i < RESERVE_NR; i++)
		total_reserve += ca->free[i].size;
	pr_debug("%zu buckets reserved", total_reserve);

	ca->copygc_write_point.group = &ca->self;
	ca->tiering_write_point.group = &ca->self;

	kobject_get(&c->kobj);
	ca->set = c;

	kobject_get(&ca->kobj);
	rcu_assign_pointer(c->cache[ca->sb.nr_this_dev], ca);

	if (le64_to_cpu(ca->disk_sb.sb->seq) > le64_to_cpu(c->disk_sb.seq))
		cache_sb_to_cache_set(c, ca->disk_sb.sb);

	/*
	 * Increase journal write timeout if flushes to this device are
	 * expensive:
	 */
	if (!blk_queue_nonrot(bdev_get_queue(ca->disk_sb.bdev)) &&
	    journal_flushes_device(ca))
		c->journal.write_delay_ms =
			max(c->journal.write_delay_ms, 1000U);

	err = "error creating kobject";
	if (c->kobj.state_in_sysfs &&
	    bch_cache_online(ca))
		goto err;

	if (ret)
		*ret = ca;
	else
		kobject_put(&ca->kobj);
	return NULL;
err:
	bch_cache_stop(ca);
	return err;
}

static struct cache_set *cache_set_lookup(uuid_le uuid)
{
	struct cache_set *c;

	lockdep_assert_held(&bch_register_lock);

	list_for_each_entry(c, &bch_cache_sets, list)
		if (!memcmp(&c->disk_sb.set_uuid, &uuid, sizeof(uuid_le)))
			return c;

	return NULL;
}

static const char *register_cache(struct bcache_superblock *sb,
				  struct cache_set_opts opts)
{
	char name[BDEVNAME_SIZE];
	const char *err = "cannot allocate memory";
	struct cache_set *c;

	err = validate_cache_super(sb);
	if (err)
		return err;

	bdevname(sb->bdev, name);

	c = cache_set_lookup(sb->sb->set_uuid);
	if (c) {
		if ((err = (can_attach_cache(sb->sb, c) ?:
			    cache_alloc(sb, c, NULL))))
			return err;

		if (cache_set_nr_online_devices(c) == cache_set_nr_devices(c)) {
			err = run_cache_set(c);
			if (err)
				return err;
		}
		goto out;
	}

	c = bch_cache_set_alloc(sb->sb, opts);
	if (!c)
		return err;

	err = cache_alloc(sb, c, NULL);
	if (err)
		goto err_stop;

	if (cache_set_nr_online_devices(c) == cache_set_nr_devices(c)) {
		err = run_cache_set(c);
		if (err)
			goto err_stop;
	}

	err = "error creating kobject";
	if (bch_cache_set_online(c))
		goto err_stop;
out:

	bch_info(c, "started");
	return NULL;
err_stop:
	bch_cache_set_stop(c);
	return err;
}

int bch_cache_set_add_cache(struct cache_set *c, const char *path)
{
	struct bcache_superblock sb;
	const char *err;
	struct cache *ca;
	struct cache_member *new_mi = NULL;
	struct cache_member mi;
	unsigned nr_this_dev, nr_in_set, u64s;
	int ret = -EINVAL;

	mutex_lock(&bch_register_lock);

	err = read_super(&sb, path);
	if (err)
		goto err_unlock;

	err = validate_cache_super(&sb);
	if (err)
		goto err_unlock;

	err = can_add_cache(sb.sb, c);
	if (err)
		goto err_unlock;

	/*
	 * Preserve the old cache member information (esp. tier)
	 * before we start bashing the disk stuff.
	 */
	mi = sb.sb->members[sb.sb->nr_this_dev];
	mi.last_mount = cpu_to_le64(ktime_get_seconds());

	down_read(&c->gc_lock);

	if (dynamic_fault("bcache:add:no_slot"))
		goto no_slot;

	if (test_bit(CACHE_SET_GC_FAILURE, &c->flags))
		goto no_slot;

	for (nr_this_dev = 0; nr_this_dev < MAX_CACHES_PER_SET; nr_this_dev++)
		if (nr_this_dev >= c->sb.nr_in_set ||
		    bch_is_zero(c->disk_mi[nr_this_dev].uuid.b,
				 sizeof(uuid_le)))
			goto have_slot;
no_slot:
	up_read(&c->gc_lock);

	err = "no slots available in superblock";
	ret = -ENOSPC;
	goto err_unlock;

have_slot:
	nr_in_set = max_t(unsigned, nr_this_dev + 1, c->sb.nr_in_set);
	up_read(&c->gc_lock);

	u64s = nr_in_set * (sizeof(struct cache_member) / sizeof(u64));
	err = "no space in superblock for member info";
	if (bch_super_realloc(&sb, u64s))
		goto err_unlock;

	new_mi = dynamic_fault("bcache:add:member_info_realloc")
		? NULL
		: kmalloc(sizeof(struct cache_member) * nr_in_set,
			  GFP_KERNEL);
	if (!new_mi) {
		err = "cannot allocate memory";
		ret = -ENOMEM;
		goto err_unlock;
	}

	memcpy(new_mi, c->disk_mi,
	       sizeof(struct cache_member) * nr_in_set);
	new_mi[nr_this_dev] = mi;

	sb.sb->nr_this_dev	= nr_this_dev;
	sb.sb->nr_in_set	= nr_in_set;
	sb.sb->u64s		= cpu_to_le16(u64s);
	memcpy(sb.sb->members, new_mi,
	       sizeof(struct cache_member) * nr_in_set);

	if (cache_set_mi_update(c, new_mi, nr_in_set)) {
		err = "cannot allocate memory";
		ret = -ENOMEM;
		goto err_unlock;
	}

	/* commit new member info */
	swap(c->disk_mi, new_mi);
	kfree(new_mi);
	new_mi = NULL;
	c->disk_sb.nr_in_set = nr_in_set;
	c->sb.nr_in_set = nr_in_set;

	err = cache_alloc(&sb, c, &ca);
	if (err)
		goto err_unlock;

	bcache_write_super(c);

	err = "journal alloc failed";
	if (bch_cache_journal_alloc(ca))
		goto err_put;

	bch_notify_cache_added(ca);

	if (ca->mi.state == CACHE_ACTIVE) {
		err = bch_cache_allocator_start_once(ca);
		if (err)
			goto err_put;

		err = __bch_cache_read_write(ca);
		if (err)
			goto err_put;
	}

	kobject_put(&ca->kobj);
	mutex_unlock(&bch_register_lock);
	return 0;
err_put:
	bch_cache_stop(ca);
err_unlock:
	kfree(new_mi);
	free_super(&sb);
	mutex_unlock(&bch_register_lock);

	bch_err(c, "Unable to add device: %s", err);
	return ret ?: -EINVAL;
}

const char *bch_register_cache_set(char * const *devices, unsigned nr_devices,
				   struct cache_set_opts opts,
				   struct cache_set **ret)
{
	const char *err;
	struct cache_set *c = NULL;
	struct bcache_superblock *sb;
	uuid_le uuid;
	unsigned i;

	memset(&uuid, 0, sizeof(uuid_le));

	if (!nr_devices)
		return "need at least one device";

	if (!try_module_get(THIS_MODULE))
		return "module unloading";

	err = "cannot allocate memory";
	sb = kcalloc(nr_devices, sizeof(*sb), GFP_KERNEL);
	if (!sb)
		goto err;

	/*
	 * read_super() needs to happen under register_lock, so that the
	 * exclusive open is atomic with adding the new cache set to the list of
	 * cache sets:
	 */
	mutex_lock(&bch_register_lock);

	for (i = 0; i < nr_devices; i++) {
		err = read_super(&sb[i], devices[i]);
		if (err)
			goto err_unlock;

		err = "attempting to register backing device";
		if (__SB_IS_BDEV(le64_to_cpu(sb[i].sb->version)))
			goto err_unlock;

		err = validate_cache_super(&sb[i]);
		if (err)
			goto err_unlock;
	}

	err = "cache set already registered";
	if (cache_set_lookup(sb->sb->set_uuid))
		goto err_unlock;

	err = "cannot allocate memory";
	c = bch_cache_set_alloc(sb[0].sb, opts);
	if (!c)
		goto err_unlock;

	for (i = 0; i < nr_devices; i++) {
		err = cache_alloc(&sb[i], c, NULL);
		if (err)
			goto err_unlock;
	}

	err = "insufficient devices";
	if (cache_set_nr_online_devices(c) != cache_set_nr_devices(c))
		goto err_unlock;

	err = run_cache_set(c);
	if (err)
		goto err_unlock;

	err = "error creating kobject";
	if (bch_cache_set_online(c))
		goto err_unlock;

	if (ret) {
		closure_get(&c->cl);
		*ret = c;
	}

	mutex_unlock(&bch_register_lock);

	err = NULL;
out:
	kfree(sb);
	module_put(THIS_MODULE);
	return err;
err_unlock:
	if (c)
		bch_cache_set_stop(c);
	mutex_unlock(&bch_register_lock);
err:
	for (i = 0; i < nr_devices; i++)
		free_super(&sb[i]);
	goto out;
}

const char *bch_register_one(const char *path)
{
	struct bcache_superblock sb;
	const char *err;

	mutex_lock(&bch_register_lock);

	err = read_super(&sb, path);
	if (err)
		goto err;

	if (__SB_IS_BDEV(le64_to_cpu(sb.sb->version)))
		err = bch_backing_dev_register(&sb);
	else
		err = register_cache(&sb, cache_set_opts_empty());

	free_super(&sb);
err:
	mutex_unlock(&bch_register_lock);
	return err;
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

	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	if (!(path = kstrndup(skip_spaces(buffer), size, GFP_KERNEL)))
		goto err;

	err = bch_register_one(strim(path));
	if (err)
		goto err;

	ret = size;
out:
	kfree(path);
	module_put(THIS_MODULE);
	return ret;
err:
	pr_err("error opening %s: %s", path, err);
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

		list_for_each_entry(c, &bch_cache_sets, list)
			bch_cache_set_read_only_sync(c);

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
	bch_fs_exit();
	bch_blockdev_exit();
	if (bcache_kset)
		kset_unregister(bcache_kset);
	if (bcache_io_wq)
		destroy_workqueue(bcache_io_wq);
	if (!IS_ERR_OR_NULL(bch_chardev_class))
		device_destroy(bch_chardev_class,
			       MKDEV(bch_chardev_major, 0));
	if (!IS_ERR_OR_NULL(bch_chardev_class))
		class_destroy(bch_chardev_class);
	if (bch_chardev_major > 0)
		unregister_chrdev(bch_chardev_major, "bcache");
	if (!IS_ERR_OR_NULL(bch_sha1))
		crypto_free_shash(bch_sha1);
	unregister_reboot_notifier(&reboot);
}

static const struct file_operations bch_chardev_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = bch_chardev_ioctl,
	.open		= nonseekable_open,
};

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
	bkey_pack_test();

	bch_sha1 = crypto_alloc_shash("sha1", 0, 0);
	if (IS_ERR(bch_sha1))
		goto err;

	bch_chardev_major = register_chrdev(0, "bcache-ctl", &bch_chardev_fops);
	if (bch_chardev_major < 0)
		goto err;

	bch_chardev_class = class_create(THIS_MODULE, "bcache");
	if (IS_ERR(bch_chardev_class))
		goto err;

	bch_chardev = device_create(bch_chardev_class, NULL,
				    MKDEV(bch_chardev_major, 255),
				    NULL, "bcache-ctl");
	if (IS_ERR(bch_chardev))
		goto err;

	if (!(bcache_io_wq = create_freezable_workqueue("bcache_io")) ||
	    !(bcache_kset = kset_create_and_add("bcache", NULL, fs_kobj)) ||
	    sysfs_create_files(&bcache_kset->kobj, files) ||
	    bch_blockdev_init() ||
	    bch_fs_init() ||
	    bch_debug_init())
		goto err;

	return 0;
err:
	bcache_exit();
	return -ENOMEM;
}

#define BCH_DEBUG_PARAM(name, description)			\
	bool bch_##name;					\
	module_param_named(name, bch_##name, bool, 0644);	\
	MODULE_PARM_DESC(name, description);
BCH_DEBUG_PARAMS()
#undef BCH_DEBUG_PARAM

module_exit(bcache_exit);
module_init(bcache_init);
