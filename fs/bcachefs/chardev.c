/*
 * This file adds support for a character device /dev/bcache that is used to
 * atomically register a list of devices, remove a device from a cache_set
 * and add a device to a cache set.
 *
 * Copyright (c) 2014 Datera, Inc.
 *
 */

#include "bcache.h"
#include "bcachefs_ioctl.h"
#include "super.h"
#include "super-io.h"

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

static long bch_ioctl_assemble(struct bch_ioctl_assemble __user *user_arg)
{
	struct bch_ioctl_assemble arg;
	const char *err;
	u64 *user_devs = NULL;
	char **devs = NULL;
	unsigned i;
	int ret = -EFAULT;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	user_devs = kmalloc_array(arg.nr_devs, sizeof(u64), GFP_KERNEL);
	if (!devs)
		return -ENOMEM;

	devs = kcalloc(arg.nr_devs, sizeof(char *), GFP_KERNEL);

	if (copy_from_user(user_devs, user_arg->devs,
			   sizeof(u64) * arg.nr_devs))
		goto err;

	for (i = 0; i < arg.nr_devs; i++) {
		devs[i] = strndup_user((const char __user *)(unsigned long)
				       user_devs[i],
				       PATH_MAX);
		if (!devs[i]) {
			ret = -ENOMEM;
			goto err;
		}
	}

	err = bch_register_cache_set(devs, arg.nr_devs,
				     bch_opts_empty(),
				     NULL);
	if (err) {
		pr_err("Could not register cache set: %s", err);
		ret = -EINVAL;
		goto err;
	}

	ret = 0;
err:
	if (devs)
		for (i = 0; i < arg.nr_devs; i++)
			kfree(devs[i]);
	kfree(devs);
	return ret;
}

static long bch_ioctl_incremental(struct bch_ioctl_incremental __user *user_arg)
{
	struct bch_ioctl_incremental arg;
	const char *err;
	char *path;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	path = strndup_user((const char __user *)(unsigned long) arg.dev, PATH_MAX);
	if (!path)
		return -ENOMEM;

	err = bch_register_one(path);
	kfree(path);

	if (err) {
		pr_err("Could not register bcache devices: %s", err);
		return -EINVAL;
	}

	return 0;
}

static long bch_global_ioctl(unsigned cmd, void __user *arg)
{
	switch (cmd) {
	case BCH_IOCTL_ASSEMBLE:
		return bch_ioctl_assemble(arg);
	case BCH_IOCTL_INCREMENTAL:
		return bch_ioctl_incremental(arg);
	default:
		return -ENOTTY;
	}
}

static long bch_ioctl_stop(struct cache_set *c)
{
	bch_cache_set_stop(c);
	return 0;
}

static long bch_ioctl_disk_add(struct cache_set *c,
			       struct bch_ioctl_disk_add __user *user_arg)
{
	struct bch_ioctl_disk_add arg;
	char *path;
	int ret;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	path = strndup_user((const char __user *)(unsigned long) arg.dev, PATH_MAX);
	if (!path)
		return -ENOMEM;

	ret = bch_cache_set_add_cache(c, path);
	kfree(path);

	return ret;
}

/* returns with ref on ca->ref */
static struct cache *bch_device_lookup(struct cache_set *c,
				       const char __user *dev)
{
	struct block_device *bdev;
	struct cache *ca;
	char *path;
	unsigned i;

	path = strndup_user(dev, PATH_MAX);
	if (!path)
		return ERR_PTR(-ENOMEM);

	bdev = lookup_bdev(strim(path));
	kfree(path);
	if (IS_ERR(bdev))
		return ERR_CAST(bdev);

	for_each_cache(ca, c, i)
		if (ca->disk_sb.bdev == bdev)
			goto found;

	ca = NULL;
found:
	bdput(bdev);
	return ca;
}

static long bch_ioctl_disk_remove(struct cache_set *c,
				  struct bch_ioctl_disk_remove __user *user_arg)
{
	struct bch_ioctl_disk_remove arg;
	struct cache *ca;
	int ret;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	ca = bch_device_lookup(c, (const char __user *)(unsigned long) arg.dev);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	ret = bch_cache_remove(ca, arg.flags & BCH_FORCE_IF_DATA_MISSING)
		? 0 : -EBUSY;

	percpu_ref_put(&ca->ref);
	return ret;
}

static long bch_ioctl_disk_fail(struct cache_set *c,
				struct bch_ioctl_disk_fail __user *user_arg)
{
	struct bch_ioctl_disk_fail arg;
	struct cache *ca;
	int ret;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	ca = bch_device_lookup(c, (const char __user *)(unsigned long) arg.dev);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	/* XXX: failed not actually implemented yet */
	ret = bch_cache_remove(ca, true);

	percpu_ref_put(&ca->ref);
	return ret;
}

static struct bch_member *bch_uuid_lookup(struct cache_set *c, uuid_le uuid)
{
	struct bch_sb_field_members *mi = bch_sb_get_members(c->disk_sb);
	unsigned i;

	lockdep_assert_held(&c->sb_lock);

	for (i = 0; i < c->disk_sb->nr_devices; i++)
		if (!memcmp(&mi->members[i].uuid, &uuid, sizeof(uuid)))
			return &mi->members[i];

	return NULL;
}

static long bch_ioctl_disk_remove_by_uuid(struct cache_set *c,
			struct bch_ioctl_disk_remove_by_uuid __user *user_arg)
{
	struct bch_ioctl_disk_fail_by_uuid arg;
	struct bch_member *m;
	int ret = -ENOENT;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	mutex_lock(&c->sb_lock);
	if ((m = bch_uuid_lookup(c, arg.dev))) {
		/* XXX: */
		SET_BCH_MEMBER_STATE(m, BCH_MEMBER_STATE_FAILED);
		bch_write_super(c);
		ret = 0;
	}
	mutex_unlock(&c->sb_lock);

	return ret;
}

static long bch_ioctl_disk_fail_by_uuid(struct cache_set *c,
			struct bch_ioctl_disk_fail_by_uuid __user *user_arg)
{
	struct bch_ioctl_disk_fail_by_uuid arg;
	struct bch_member *m;
	int ret = -ENOENT;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	mutex_lock(&c->sb_lock);
	if ((m = bch_uuid_lookup(c, arg.dev))) {
		SET_BCH_MEMBER_STATE(m, BCH_MEMBER_STATE_FAILED);
		bch_write_super(c);
		ret = 0;
	}
	mutex_unlock(&c->sb_lock);

	return ret;
}

static long bch_ioctl_query_uuid(struct cache_set *c,
			struct bch_ioctl_query_uuid __user *user_arg)
{
	return copy_to_user(&user_arg->uuid,
			    &c->sb.user_uuid,
			    sizeof(c->sb.user_uuid));
}

long bch_cache_set_ioctl(struct cache_set *c, unsigned cmd, void __user *arg)
{
	/* ioctls that don't require admin cap: */
	switch (cmd) {
	case BCH_IOCTL_QUERY_UUID:
		return bch_ioctl_query_uuid(c, arg);
	}

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* ioctls that do require admin cap: */
	switch (cmd) {
	case BCH_IOCTL_RUN:
		return -ENOTTY;
	case BCH_IOCTL_STOP:
		return bch_ioctl_stop(c);

	case BCH_IOCTL_DISK_ADD:
		return bch_ioctl_disk_add(c, arg);
	case BCH_IOCTL_DISK_REMOVE:
		return bch_ioctl_disk_remove(c, arg);
	case BCH_IOCTL_DISK_FAIL:
		return bch_ioctl_disk_fail(c, arg);

	case BCH_IOCTL_DISK_REMOVE_BY_UUID:
		return bch_ioctl_disk_remove_by_uuid(c, arg);
	case BCH_IOCTL_DISK_FAIL_BY_UUID:
		return bch_ioctl_disk_fail_by_uuid(c, arg);

	default:
		return -ENOTTY;
	}
}

static long bch_chardev_ioctl(struct file *filp, unsigned cmd, unsigned long v)
{
	struct cache_set *c = filp->private_data;
	void __user *arg = (void __user *) v;

	return c
		? bch_cache_set_ioctl(c, cmd, arg)
		: bch_global_ioctl(cmd, arg);
}

const struct file_operations bch_chardev_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = bch_chardev_ioctl,
	.open		= nonseekable_open,
};
