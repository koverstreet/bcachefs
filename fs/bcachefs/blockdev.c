
#include "bcache.h"
#include "blockdev.h"
#include "btree.h"
#include "inode.h"
#include "request.h"
#include "super.h"
#include "writeback.h"

#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/random.h>

static int bch_blockdev_major;
static DEFINE_IDA(bch_blockdev_minor);
LIST_HEAD(uncached_devices);
struct kmem_cache *bch_search_cache;

static void write_bdev_super_endio(struct bio *bio)
{
	struct cached_dev *dc = bio->bi_private;
	/* XXX: error checking */

	closure_put(&dc->sb_write);
}

static void bch_write_bdev_super_unlock(struct closure *cl)
{
	struct cached_dev *dc = container_of(cl, struct cached_dev, sb_write);

	up(&dc->sb_write_mutex);
}

void bch_write_bdev_super(struct cached_dev *dc, struct closure *parent)
{
	struct closure *cl = &dc->sb_write;
	struct bio *bio = dc->disk_sb.bio;

	down(&dc->sb_write_mutex);
	closure_init(cl, parent);

	bio_reset(bio);
	bio->bi_end_io	= write_bdev_super_endio;
	bio->bi_private = dc;

	closure_get(cl);
	__write_super(dc->disk.c, &dc->disk_sb, dc->bdev, &dc->sb);

	closure_return_with_destructor(cl, bch_write_bdev_super_unlock);
}

bool bch_is_open_backing(struct block_device *bdev)
{
	struct cache_set *c, *tc;
	struct cached_dev *dc, *t;

	list_for_each_entry_safe(c, tc, &bch_cache_sets, list)
		list_for_each_entry_safe(dc, t, &c->cached_devs, list)
			if (dc->bdev == bdev)
				return true;
	list_for_each_entry_safe(dc, t, &uncached_devices, list)
		if (dc->bdev == bdev)
			return true;
	return false;
}

static int open_dev(struct block_device *b, fmode_t mode)
{
	struct bcache_device *d = b->bd_disk->private_data;

	if (test_bit(BCACHE_DEV_CLOSING, &d->flags))
		return -ENXIO;

	closure_get(&d->cl);
	return 0;
}

static void release_dev(struct gendisk *b, fmode_t mode)
{
	struct bcache_device *d = b->private_data;

	closure_put(&d->cl);
}

static int ioctl_dev(struct block_device *b, fmode_t mode,
		     unsigned int cmd, unsigned long arg)
{
	struct bcache_device *d = b->bd_disk->private_data;

	return d->ioctl(d, mode, cmd, arg);
}

static const struct block_device_operations bcache_ops = {
	.open		= open_dev,
	.release	= release_dev,
	.ioctl		= ioctl_dev,
	.owner		= THIS_MODULE,
};

void bcache_device_stop(struct bcache_device *d)
{
	if (!test_and_set_bit(BCACHE_DEV_CLOSING, &d->flags))
		closure_queue(&d->cl);
}

static void bcache_device_unlink(struct bcache_device *d)
{
	lockdep_assert_held(&bch_register_lock);

	if (d->c && !test_and_set_bit(BCACHE_DEV_UNLINK_DONE, &d->flags)) {
		sysfs_remove_link(&d->c->kobj, d->name);
		sysfs_remove_link(&d->kobj, "cache");
	}
}

static void bcache_device_link(struct bcache_device *d, struct cache_set *c,
			       const char *name)
{
	snprintf(d->name, BCACHEDEVNAME_SIZE,
		 "%s%llu", name, bcache_dev_inum(d));

	WARN(sysfs_create_link(&d->kobj, &c->kobj, "cache") ||
	     sysfs_create_link(&c->kobj, &d->kobj, d->name),
	     "Couldn't create device <-> cache set symlinks");

	clear_bit(BCACHE_DEV_UNLINK_DONE, &d->flags);
}

static void bcache_device_detach(struct bcache_device *d)
{
	lockdep_assert_held(&bch_register_lock);

	if (test_bit(BCACHE_DEV_DETACHING, &d->flags)) {
		mutex_lock(&d->inode_lock);
		bch_inode_rm(d->c, bcache_dev_inum(d));
		mutex_unlock(&d->inode_lock);
	}

	bcache_device_unlink(d);

	radix_tree_delete(&d->c->devices, bcache_dev_inum(d));

	closure_put(&d->c->caching);
	d->c = NULL;
}

static int bcache_device_attach(struct bcache_device *d, struct cache_set *c)
{
	int ret;

	lockdep_assert_held(&bch_register_lock);

	ret = radix_tree_insert(&c->devices, bcache_dev_inum(d), d);
	if (ret) {
		pr_err("radix_tree_insert() error for inum %llu",
		       bcache_dev_inum(d));
		return ret;
	}

	d->c = c;
	closure_get(&c->caching);

	return ret;
}

static void bcache_device_free(struct bcache_device *d)
{
	lockdep_assert_held(&bch_register_lock);

	pr_info("%s stopped", d->disk->disk_name);

	if (d->c)
		bcache_device_detach(d);
	if (d->disk && d->disk->flags & GENHD_FL_UP)
		del_gendisk(d->disk);
	if (d->disk && d->disk->queue)
		blk_cleanup_queue(d->disk->queue);
	if (d->disk) {
		ida_simple_remove(&bch_blockdev_minor, d->disk->first_minor);
		put_disk(d->disk);
	}

	if (d->bio_split)
		bioset_free(d->bio_split);

	closure_debug_destroy(&d->cl);
}

static int bcache_device_init(struct bcache_device *d, unsigned block_size,
			      sector_t sectors)
{
	struct request_queue *q;
	int minor;

	mutex_init(&d->inode_lock);

	minor = ida_simple_get(&bch_blockdev_minor, 0, MINORMASK + 1, GFP_KERNEL);
	if (minor < 0) {
		pr_err("cannot allocate minor");
		return minor;
	}

	if (!(d->bio_split = bioset_create(4, offsetof(struct bbio, bio))) ||
	    !(d->disk = alloc_disk(1))) {
		pr_err("cannot allocate disk");
		ida_simple_remove(&bch_blockdev_minor, minor);
		return -ENOMEM;
	}

	set_capacity(d->disk, sectors);
	snprintf(d->disk->disk_name, DISK_NAME_LEN, "bcache%i", minor);

	d->disk->major		= bch_blockdev_major;
	d->disk->first_minor	= minor;
	d->disk->fops		= &bcache_ops;
	d->disk->private_data	= d;

	q = blk_alloc_queue(GFP_KERNEL);
	if (!q) {
		pr_err("cannot allocate queue");
		return -ENOMEM;
	}

	blk_queue_make_request(q, NULL);
	d->disk->queue			= q;
	q->queuedata			= d;
	q->backing_dev_info.congested_data = d;
	q->limits.max_hw_sectors	= UINT_MAX;
	q->limits.max_sectors		= UINT_MAX;
	q->limits.max_segment_size	= UINT_MAX;
	q->limits.max_segments		= BIO_MAX_PAGES;
	blk_queue_max_discard_sectors(q, UINT_MAX);
	q->limits.discard_granularity	= 512;
	q->limits.io_min		= block_size;
	q->limits.logical_block_size	= block_size;
	q->limits.physical_block_size	= block_size;
	set_bit(QUEUE_FLAG_NONROT,	&d->disk->queue->queue_flags);
	clear_bit(QUEUE_FLAG_ADD_RANDOM, &d->disk->queue->queue_flags);
	set_bit(QUEUE_FLAG_DISCARD,	&d->disk->queue->queue_flags);

	blk_queue_write_cache(q, true, true);

	return 0;
}

/* Cached device */

static void calc_cached_dev_sectors(struct cache_set *c)
{
	u64 sectors = 0;
	struct cached_dev *dc;

	list_for_each_entry(dc, &c->cached_devs, list)
		sectors += bdev_sectors(dc->bdev);

	c->cached_dev_sectors = sectors;
}

void bch_cached_dev_run(struct cached_dev *dc)
{
	struct bcache_device *d = &dc->disk;
	char buf[SB_LABEL_SIZE + 1];
	char *env[] = {
		"DRIVER=bcache",
		kasprintf(GFP_KERNEL, "CACHED_UUID=%pU", dc->sb.uuid.b),
		NULL,
		NULL,
	};

	memcpy(buf, dc->sb.label, SB_LABEL_SIZE);
	buf[SB_LABEL_SIZE] = '\0';
	env[2] = kasprintf(GFP_KERNEL, "CACHED_LABEL=%s", buf);

	if (atomic_xchg(&dc->running, 1)) {
		kfree(env[1]);
		kfree(env[2]);
		return;
	}

	if (!d->c &&
	    BDEV_STATE(&dc->sb) != BDEV_STATE_NONE) {
		struct closure cl;

		closure_init_stack(&cl);

		SET_BDEV_STATE(&dc->sb, BDEV_STATE_STALE);
		bch_write_bdev_super(dc, &cl);
		closure_sync(&cl);
	}

	add_disk(d->disk);
	bd_link_disk_holder(dc->bdev, dc->disk.disk);
	/* won't show up in the uevent file, use udevadm monitor -e instead
	 * only class / kset properties are persistent */
	kobject_uevent_env(&disk_to_dev(d->disk)->kobj, KOBJ_CHANGE, env);
	kfree(env[1]);
	kfree(env[2]);

	if (sysfs_create_link(&d->kobj, &disk_to_dev(d->disk)->kobj, "dev") ||
	    sysfs_create_link(&disk_to_dev(d->disk)->kobj, &d->kobj, "bcache"))
		pr_debug("error creating sysfs link");
}

static void cached_dev_detach_finish(struct work_struct *w)
{
	struct cached_dev *dc = container_of(w, struct cached_dev, detach);
	char buf[BDEVNAME_SIZE];
	struct closure cl;

	closure_init_stack(&cl);

	BUG_ON(!test_bit(BCACHE_DEV_DETACHING, &dc->disk.flags));
	BUG_ON(atomic_read(&dc->count));

	mutex_lock(&bch_register_lock);

	memset(&dc->sb.set_uuid, 0, 16);
	SET_BDEV_STATE(&dc->sb, BDEV_STATE_NONE);

	bch_write_bdev_super(dc, &cl);
	closure_sync(&cl);

	bcache_device_detach(&dc->disk);
	list_move(&dc->list, &uncached_devices);

	clear_bit(BCACHE_DEV_DETACHING, &dc->disk.flags);
	clear_bit(BCACHE_DEV_UNLINK_DONE, &dc->disk.flags);

	mutex_unlock(&bch_register_lock);

	pr_info("Caching disabled for %s", bdevname(dc->bdev, buf));

	/* Drop ref we took in cached_dev_detach() */
	closure_put(&dc->disk.cl);
}

void bch_cached_dev_detach(struct cached_dev *dc)
{
	lockdep_assert_held(&bch_register_lock);

	if (test_bit(BCACHE_DEV_CLOSING, &dc->disk.flags))
		return;

	if (test_and_set_bit(BCACHE_DEV_DETACHING, &dc->disk.flags))
		return;

	/*
	 * Block the device from being closed and freed until we're finished
	 * detaching
	 */
	closure_get(&dc->disk.cl);

	dc->writeback_pd.rate.rate = UINT_MAX;
	bch_writeback_queue(dc);
	cached_dev_put(dc);
}

int bch_cached_dev_attach(struct cached_dev *dc, struct cache_set *c)
{
	s64 rtime = timekeeping_clocktai_ns();
	char buf[BDEVNAME_SIZE];
	bool found;
	int ret;

	bdevname(dc->bdev, buf);

	if (memcmp(&dc->sb.set_uuid, &c->sb.set_uuid, sizeof(c->sb.set_uuid)))
		return -ENOENT;

	if (dc->disk.c) {
		pr_err("Can't attach %s: already attached", buf);
		return -EINVAL;
	}

	if (!test_bit(CACHE_SET_RUNNING, &c->flags))
		return 0;

	if (test_bit(CACHE_SET_STOPPING, &c->flags)) {
		pr_err("Can't attach %s: shutting down", buf);
		return -EINVAL;
	}

	if (dc->sb.block_size < c->sb.block_size) {
		/* Will die */
		pr_err("Couldn't attach %s: block size less than set's block size",
		       buf);
		return -EINVAL;
	}

	found = !bch_blockdev_inode_find_by_uuid(c, &dc->sb.uuid,
						 &dc->disk.inode);

	if (!found && BDEV_STATE(&dc->sb) == BDEV_STATE_DIRTY) {
		pr_err("Couldn't find uuid for %s in set", buf);
		return -ENOENT;
	}

	if (found &&
	    (BDEV_STATE(&dc->sb) == BDEV_STATE_STALE ||
	     BDEV_STATE(&dc->sb) == BDEV_STATE_NONE)) {
		found = false;
		bch_inode_rm(c, bcache_dev_inum(&dc->disk));
	}

	/* Deadlocks since we're called via sysfs...
	sysfs_remove_file(&dc->kobj, &sysfs_attach);
	 */

	if (!found) {
		struct closure cl;

		closure_init_stack(&cl);

		BCH_INODE_INIT(&dc->disk.inode);
		dc->disk.inode.i_uuid = dc->sb.uuid;
		memcpy(dc->disk.inode.i_label, dc->sb.label, SB_LABEL_SIZE);
		dc->disk.inode.i_inode.i_ctime = rtime;
		dc->disk.inode.i_inode.i_mtime = rtime;

		ret = bch_inode_create(c, &dc->disk.inode.i_inode,
				       0, BLOCKDEV_INODE_MAX,
				       &c->unused_inode_hint);
		if (ret) {
			pr_err("Error %d, not caching %s", ret, buf);
			return ret;
		}

		pr_info("attached inode %llu", bcache_dev_inum(&dc->disk));

		dc->sb.set_uuid = c->sb.set_uuid;
		SET_BDEV_STATE(&dc->sb, BDEV_STATE_CLEAN);

		bch_write_bdev_super(dc, &cl);
		closure_sync(&cl);
	} else {
		dc->disk.inode.i_inode.i_mtime = rtime;
		bch_inode_update(c, &dc->disk.inode.i_inode);
	}

	/* Count dirty sectors before attaching */
	if (BDEV_STATE(&dc->sb) == BDEV_STATE_DIRTY)
		bch_sectors_dirty_init(dc, c);

	ret = bcache_device_attach(&dc->disk, c);
	if (ret)
		return ret;

	list_move(&dc->list, &c->cached_devs);
	calc_cached_dev_sectors(c);

	/*
	 * dc->c must be set before dc->count != 0 - paired with the mb in
	 * cached_dev_get()
	 */
	smp_wmb();
	atomic_set(&dc->count, 1);

	if (bch_cached_dev_writeback_start(dc))
		return -ENOMEM;

	if (BDEV_STATE(&dc->sb) == BDEV_STATE_DIRTY) {
		atomic_set(&dc->has_dirty, 1);
		atomic_inc(&dc->count);
	}

	bch_cached_dev_run(dc);
	bcache_device_link(&dc->disk, c, "bdev");

	pr_info("Caching %s as %s on set %pU",
		bdevname(dc->bdev, buf), dc->disk.disk->disk_name,
		dc->disk.c->sb.set_uuid.b);
	return 0;
}

void bch_cached_dev_release(struct kobject *kobj)
{
	struct cached_dev *dc = container_of(kobj, struct cached_dev,
					     disk.kobj);
	kfree(dc);
	module_put(THIS_MODULE);
}

static void cached_dev_free(struct closure *cl)
{
	struct cached_dev *dc = container_of(cl, struct cached_dev, disk.cl);

	cancel_delayed_work_sync(&dc->writeback_pd.update);
	if (!IS_ERR_OR_NULL(dc->writeback_thread))
		kthread_stop(dc->writeback_thread);

	bch_cached_dev_writeback_free(dc);

	mutex_lock(&bch_register_lock);

	if (atomic_read(&dc->running))
		bd_unlink_disk_holder(dc->bdev, dc->disk.disk);
	bcache_device_free(&dc->disk);
	list_del(&dc->list);

	mutex_unlock(&bch_register_lock);

	if (!IS_ERR_OR_NULL(dc->bdev))
		blkdev_put(dc->bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);

	wake_up(&unregister_wait);

	kobject_put(&dc->disk.kobj);
}

static void cached_dev_flush(struct closure *cl)
{
	struct cached_dev *dc = container_of(cl, struct cached_dev, disk.cl);
	struct bcache_device *d = &dc->disk;

	mutex_lock(&bch_register_lock);
	bcache_device_unlink(d);
	mutex_unlock(&bch_register_lock);

	bch_cache_accounting_destroy(&dc->accounting);
	kobject_del(&d->kobj);

	continue_at(cl, cached_dev_free, system_wq);
}

static int cached_dev_init(struct cached_dev *dc, unsigned block_size)
{
	int ret;
	struct io *io;
	struct request_queue *q = bdev_get_queue(dc->bdev);

	dc->sequential_cutoff		= 4 << 20;

	for (io = dc->io; io < dc->io + RECENT_IO; io++) {
		list_add(&io->lru, &dc->io_lru);
		hlist_add_head(&io->hash, dc->io_hash + RECENT_IO);
	}

	dc->disk.stripe_size = q->limits.io_opt >> 9;

	if (dc->disk.stripe_size)
		dc->partial_stripes_expensive =
			q->limits.raid_partial_stripes_expensive;

	ret = bcache_device_init(&dc->disk, block_size,
			 dc->bdev->bd_part->nr_sects - dc->sb.data_offset);
	if (ret)
		return ret;

	dc->disk.disk->queue->backing_dev_info.ra_pages =
		max(dc->disk.disk->queue->backing_dev_info.ra_pages,
		    q->backing_dev_info.ra_pages);

	bch_cached_dev_request_init(dc);
	ret = bch_cached_dev_writeback_init(dc);
	if (ret)
		return ret;

	return 0;
}

/* Cached device - bcache superblock */

const char *bch_register_bdev(struct bcache_superblock *sb,
			      struct block_device *bdev)
{
	char name[BDEVNAME_SIZE];
	const char *err = "cannot allocate memory";
	struct cache_set *c;
	struct cached_dev *dc;

	dc = kzalloc(sizeof(*dc), GFP_KERNEL);
	if (!dc) {
		blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
		return err;
	}

	__module_get(THIS_MODULE);
	INIT_LIST_HEAD(&dc->list);
	closure_init(&dc->disk.cl, NULL);
	set_closure_fn(&dc->disk.cl, cached_dev_flush, system_wq);
	kobject_init(&dc->disk.kobj, &bch_cached_dev_ktype);
	INIT_WORK(&dc->detach, cached_dev_detach_finish);
	sema_init(&dc->sb_write_mutex, 1);
	INIT_LIST_HEAD(&dc->io_lru);
	spin_lock_init(&dc->io_lock);
	bch_cache_accounting_init(&dc->accounting, &dc->disk.cl);

	dc->bdev = bdev;
	dc->bdev->bd_holder = dc;

	dc->disk_sb = *sb;
	memset(sb, 0, sizeof(*sb));

	err = validate_super(&dc->disk_sb, bdev, &dc->sb);
	if (err)
		goto err;

	if (cached_dev_init(dc, dc->sb.block_size << 9))
		goto err;

	err = "error creating kobject";
	if (kobject_add(&dc->disk.kobj, &part_to_dev(bdev->bd_part)->kobj,
			"bcache"))
		goto err;

	err = "error accounting kobject";
	if (bch_cache_accounting_add_kobjs(&dc->accounting, &dc->disk.kobj))
		goto err;

	pr_info("registered backing device %s", bdevname(bdev, name));

	mutex_lock(&bch_register_lock);

	list_add(&dc->list, &uncached_devices);
	list_for_each_entry(c, &bch_cache_sets, list)
		bch_cached_dev_attach(dc, c);

	if (BDEV_STATE(&dc->sb) == BDEV_STATE_NONE ||
	    BDEV_STATE(&dc->sb) == BDEV_STATE_STALE)
		bch_cached_dev_run(dc);

	mutex_unlock(&bch_register_lock);
	return NULL;
err:
	bcache_device_stop(&dc->disk);
	return err;
}

/* Flash only volumes */

void bch_flash_dev_release(struct kobject *kobj)
{
	struct bcache_device *d = container_of(kobj, struct bcache_device,
					       kobj);
	kfree(d);
}

static void flash_dev_free(struct closure *cl)
{
	struct bcache_device *d = container_of(cl, struct bcache_device, cl);

	mutex_lock(&bch_register_lock);
	bcache_device_free(d);
	mutex_unlock(&bch_register_lock);
	kobject_put(&d->kobj);
}

static void flash_dev_flush(struct closure *cl)
{
	struct bcache_device *d = container_of(cl, struct bcache_device, cl);

	mutex_lock(&bch_register_lock);
	bcache_device_unlink(d);
	mutex_unlock(&bch_register_lock);
	kobject_del(&d->kobj);
	continue_at(cl, flash_dev_free, system_wq);
}

static int flash_dev_run(struct cache_set *c, struct bch_inode_blockdev *inode)
{
	struct bcache_device *d = kzalloc(sizeof(struct bcache_device),
					  GFP_KERNEL);
	int ret = -ENOMEM;

	if (!d)
		return ret;

	d->inode = *inode;

	closure_init(&d->cl, NULL);
	set_closure_fn(&d->cl, flash_dev_flush, system_wq);

	kobject_init(&d->kobj, &bch_flash_dev_ktype);

	ret = bcache_device_init(d, block_bytes(c), inode->i_inode.i_size >> 9);
	if (ret)
		goto err;

	ret = bcache_device_attach(d, c);
	if (ret)
		goto err;

	bch_flash_dev_request_init(d);
	add_disk(d->disk);

	if (kobject_add(&d->kobj, &disk_to_dev(d->disk)->kobj, "bcache"))
		goto err;

	bcache_device_link(d, c, "volume");

	return 0;
err:
	kobject_put(&d->kobj);
	return ret;
}

static int flash_dev_map_fn(struct btree_op *op, struct btree *b,
			    struct bkey *k)
{
	int ret = 0;
	struct bch_inode_blockdev *inode =
		container_of(k, struct bch_inode_blockdev, i_inode.i_key);

	if (KEY_INODE(k) >= BLOCKDEV_INODE_MAX)
		return MAP_DONE;

	if (INODE_FLASH_ONLY(inode))
		ret = flash_dev_run(b->c, inode);

	return ret ? ret : MAP_CONTINUE;
}

int flash_devs_run(struct cache_set *c)
{
	struct btree_op op;
	int ret;

	if (test_bit(CACHE_SET_STOPPING, &c->flags))
		return -EINVAL;

	bch_btree_op_init(&op, BTREE_ID_INODES, -1);

	ret = bch_btree_map_keys(&op, c, NULL, flash_dev_map_fn, 0);
	if (ret < 0)
		bch_cache_set_error(c, "can't bring up flash volumes: %i", ret);

	return 0;
}

int bch_flash_dev_create(struct cache_set *c, u64 size)
{
	s64 rtime = timekeeping_clocktai_ns();
	struct bch_inode_blockdev inode;
	int ret;

	BCH_INODE_INIT(&inode);
	get_random_bytes(&inode.i_uuid, sizeof(inode.i_uuid));
	inode.i_inode.i_ctime = rtime;
	inode.i_inode.i_mtime = rtime;
	inode.i_inode.i_size = size;
	SET_INODE_FLASH_ONLY(&inode, 1);

	ret = bch_inode_create(c, &inode.i_inode, 0, BLOCKDEV_INODE_MAX,
			       &c->unused_inode_hint);
	if (ret) {
		pr_err("Can't create volume: %d", ret);
		return ret;
	}

	return flash_dev_run(c, &inode);
}

void bch_blockdev_exit(void)
{
	kmem_cache_destroy(bch_search_cache);

	if (bch_blockdev_major >= 0)
		unregister_blkdev(bch_blockdev_major, "bcache");
}

int __init bch_blockdev_init(void)
{
	bch_blockdev_major = register_blkdev(0, "bcache");
	if (bch_blockdev_major < 0)
		return bch_blockdev_major;

	bch_search_cache = KMEM_CACHE(search, 0);
	if (!bch_search_cache)
		return -ENOMEM;

	return 0;
}
