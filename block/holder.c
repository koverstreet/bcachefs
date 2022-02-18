// SPDX-License-Identifier: GPL-2.0-only
#include <linux/genhd.h>
#include <linux/slab.h>

struct bd_holder_disk {
	struct list_head	list;
	struct block_device	*bdev;
	int			refcnt;
};

static struct bd_holder_disk *bd_find_holder_disk(struct block_device *bdev,
						  struct gendisk *disk)
{
	struct bd_holder_disk *holder;

	list_for_each_entry(holder, &disk->slave_bdevs, list)
		if (holder->bdev == bdev)
			return holder;
	return NULL;
}

static int add_symlink(struct kobject *from, struct kobject *to)
{
	return sysfs_create_link(from, to, kobject_name(to));
}

static void del_symlink(struct kobject *from, struct kobject *to)
{
	sysfs_remove_link(from, kobject_name(to));
}

static int __link_disk_holder(struct block_device *bdev, struct gendisk *disk)
{
	int ret;

	ret = add_symlink(disk->slave_dir, bdev_kobj(bdev));
	if (ret)
		return ret;
	ret = add_symlink(bdev->bd_holder_dir, &disk_to_dev(disk)->kobj);
	if (ret)
		del_symlink(disk->slave_dir, bdev_kobj(bdev));
	return ret;
}

/**
 * bd_link_disk_holder - create symlinks between holding disk and slave bdev
 * @bdev: the claimed slave bdev
 * @disk: the holding disk
 *
 * DON'T USE THIS UNLESS YOU'RE ALREADY USING IT.
 *
 * This functions creates the following sysfs symlinks.
 *
 * - from "slaves" directory of the holder @disk to the claimed @bdev
 * - from "holders" directory of the @bdev to the holder @disk
 *
 * For example, if /dev/dm-0 maps to /dev/sda and disk for dm-0 is
 * passed to bd_link_disk_holder(), then:
 *
 *   /sys/block/dm-0/slaves/sda --> /sys/block/sda
 *   /sys/block/sda/holders/dm-0 --> /sys/block/dm-0
 *
 * The caller must have claimed @bdev before calling this function and
 * ensure that both @bdev and @disk are valid during the creation and
 * lifetime of these symlinks.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
int bd_link_disk_holder(struct block_device *bdev, struct gendisk *disk)
{
	struct bd_holder_disk *holder;
	int ret = 0;

	mutex_lock(&disk->open_mutex);

	WARN_ON_ONCE(!bdev->bd_holder);

	/* FIXME: remove the following once add_disk() handles errors */
	if (WARN_ON(!bdev->bd_holder_dir))
		goto out_unlock;

	holder = bd_find_holder_disk(bdev, disk);
	if (holder) {
		holder->refcnt++;
		goto out_unlock;
	}

	holder = kzalloc(sizeof(*holder), GFP_KERNEL);
	if (!holder) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	INIT_LIST_HEAD(&holder->list);
	holder->bdev = bdev;
	holder->refcnt = 1;
	if (disk->slave_dir) {
		ret = __link_disk_holder(bdev, disk);
		if (ret) {
			kfree(holder);
			goto out_unlock;
		}
	}

	list_add(&holder->list, &disk->slave_bdevs);
	/*
	 * del_gendisk drops the initial reference to bd_holder_dir, so we need
	 * to keep our own here to allow for cleanup past that point.
	 */
	kobject_get(bdev->bd_holder_dir);

out_unlock:
	mutex_unlock(&disk->open_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(bd_link_disk_holder);

static void __unlink_disk_holder(struct block_device *bdev,
		struct gendisk *disk)
{
	del_symlink(disk->slave_dir, bdev_kobj(bdev));
	del_symlink(bdev->bd_holder_dir, &disk_to_dev(disk)->kobj);
}

/**
 * bd_unlink_disk_holder - destroy symlinks created by bd_link_disk_holder()
 * @bdev: the calimed slave bdev
 * @disk: the holding disk
 *
 * DON'T USE THIS UNLESS YOU'RE ALREADY USING IT.
 *
 * CONTEXT:
 * Might sleep.
 */
void bd_unlink_disk_holder(struct block_device *bdev, struct gendisk *disk)
{
	struct bd_holder_disk *holder;

	mutex_lock(&disk->open_mutex);
	holder = bd_find_holder_disk(bdev, disk);
	if (!WARN_ON_ONCE(holder == NULL) && !--holder->refcnt) {
		if (disk->slave_dir)
			__unlink_disk_holder(bdev, disk);
		kobject_put(bdev->bd_holder_dir);
		list_del_init(&holder->list);
		kfree(holder);
	}
	mutex_unlock(&disk->open_mutex);
}
EXPORT_SYMBOL_GPL(bd_unlink_disk_holder);

int bd_register_pending_holders(struct gendisk *disk)
{
	struct bd_holder_disk *holder;
	int ret;

	mutex_lock(&disk->open_mutex);
	list_for_each_entry(holder, &disk->slave_bdevs, list) {
		ret = __link_disk_holder(holder->bdev, disk);
		if (ret)
			goto out_undo;
	}
	mutex_unlock(&disk->open_mutex);
	return 0;

out_undo:
	list_for_each_entry_continue_reverse(holder, &disk->slave_bdevs, list)
		__unlink_disk_holder(holder->bdev, disk);
	mutex_unlock(&disk->open_mutex);
	return ret;
}
