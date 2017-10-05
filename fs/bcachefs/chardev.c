#ifndef NO_BCACHEFS_CHARDEV

#include "bcachefs.h"
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

/* returns with ref on ca->ref */
static struct bch_dev *bch2_device_lookup(struct bch_fs *c, u64 dev,
					  unsigned flags)
{
	struct bch_dev *ca;

	if (flags & BCH_BY_INDEX) {
		if (dev >= c->sb.nr_devices)
			return ERR_PTR(-EINVAL);

		rcu_read_lock();
		ca = c->devs[dev];
		if (ca)
			percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		if (!ca)
			return ERR_PTR(-EINVAL);
	} else {
		struct block_device *bdev;
		char *path;
		unsigned i;

		path = strndup_user((const char __user *)
				    (unsigned long) dev, PATH_MAX);
		if (IS_ERR(path))
			return ERR_CAST(path);

		bdev = lookup_bdev(path);
		kfree(path);
		if (IS_ERR(bdev))
			return ERR_CAST(bdev);

		for_each_member_device(ca, c, i)
			if (ca->disk_sb.bdev == bdev)
				goto found;

		ca = ERR_PTR(-ENOENT);
found:
		bdput(bdev);
	}

	return ca;
}

static long bch2_ioctl_assemble(struct bch_ioctl_assemble __user *user_arg)
{
	struct bch_ioctl_assemble arg;
	const char *err;
	u64 *user_devs = NULL;
	char **devs = NULL;
	unsigned i;
	int ret = -EFAULT;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags || arg.pad)
		return -EINVAL;

	user_devs = kmalloc_array(arg.nr_devs, sizeof(u64), GFP_KERNEL);
	if (!user_devs)
		return -ENOMEM;

	devs = kcalloc(arg.nr_devs, sizeof(char *), GFP_KERNEL);

	if (copy_from_user(user_devs, arg.devs,
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

	err = bch2_fs_open(devs, arg.nr_devs, bch2_opts_empty(), NULL);
	if (err) {
		pr_err("Could not open filesystem: %s", err);
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

static long bch2_ioctl_incremental(struct bch_ioctl_incremental __user *user_arg)
{
	struct bch_ioctl_incremental arg;
	const char *err;
	char *path;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags || arg.pad)
		return -EINVAL;

	path = strndup_user((const char __user *)(unsigned long) arg.dev, PATH_MAX);
	if (!path)
		return -ENOMEM;

	err = bch2_fs_open_incremental(path);
	kfree(path);

	if (err) {
		pr_err("Could not register bcachefs devices: %s", err);
		return -EINVAL;
	}

	return 0;
}

static long bch2_global_ioctl(unsigned cmd, void __user *arg)
{
	switch (cmd) {
	case BCH_IOCTL_ASSEMBLE:
		return bch2_ioctl_assemble(arg);
	case BCH_IOCTL_INCREMENTAL:
		return bch2_ioctl_incremental(arg);
	default:
		return -ENOTTY;
	}
}

static long bch2_ioctl_query_uuid(struct bch_fs *c,
			struct bch_ioctl_query_uuid __user *user_arg)
{
	return copy_to_user(&user_arg->uuid,
			    &c->sb.user_uuid,
			    sizeof(c->sb.user_uuid));
}

static long bch2_ioctl_start(struct bch_fs *c, struct bch_ioctl_start arg)
{
	if (arg.flags || arg.pad)
		return -EINVAL;

	return bch2_fs_start(c) ? -EIO : 0;
}

static long bch2_ioctl_stop(struct bch_fs *c)
{
	bch2_fs_stop(c);
	return 0;
}

static long bch2_ioctl_disk_add(struct bch_fs *c, struct bch_ioctl_disk arg)
{
	char *path;
	int ret;

	if (arg.flags || arg.pad)
		return -EINVAL;

	path = strndup_user((const char __user *)(unsigned long) arg.dev, PATH_MAX);
	if (!path)
		return -ENOMEM;

	ret = bch2_dev_add(c, path);
	kfree(path);

	return ret;
}

static long bch2_ioctl_disk_remove(struct bch_fs *c, struct bch_ioctl_disk arg)
{
	struct bch_dev *ca;

	if ((arg.flags & ~(BCH_FORCE_IF_DATA_LOST|
			   BCH_FORCE_IF_METADATA_LOST|
			   BCH_FORCE_IF_DEGRADED|
			   BCH_BY_INDEX)) ||
	    arg.pad)
		return -EINVAL;

	ca = bch2_device_lookup(c, arg.dev, arg.flags);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	return bch2_dev_remove(c, ca, arg.flags);
}

static long bch2_ioctl_disk_online(struct bch_fs *c, struct bch_ioctl_disk arg)
{
	char *path;
	int ret;

	if (arg.flags || arg.pad)
		return -EINVAL;

	path = strndup_user((const char __user *)(unsigned long) arg.dev, PATH_MAX);
	if (!path)
		return -ENOMEM;

	ret = bch2_dev_online(c, path);
	kfree(path);
	return ret;
}

static long bch2_ioctl_disk_offline(struct bch_fs *c, struct bch_ioctl_disk arg)
{
	struct bch_dev *ca;
	int ret;

	if ((arg.flags & ~(BCH_FORCE_IF_DATA_LOST|
			   BCH_FORCE_IF_METADATA_LOST|
			   BCH_FORCE_IF_DEGRADED|
			   BCH_BY_INDEX)) ||
	    arg.pad)
		return -EINVAL;

	ca = bch2_device_lookup(c, arg.dev, arg.flags);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	ret = bch2_dev_offline(c, ca, arg.flags);
	percpu_ref_put(&ca->ref);
	return ret;
}

static long bch2_ioctl_disk_set_state(struct bch_fs *c,
			struct bch_ioctl_disk_set_state arg)
{
	struct bch_dev *ca;
	int ret;

	if ((arg.flags & ~(BCH_FORCE_IF_DATA_LOST|
			   BCH_FORCE_IF_METADATA_LOST|
			   BCH_FORCE_IF_DEGRADED|
			   BCH_BY_INDEX)) ||
	    arg.pad[0] || arg.pad[1] || arg.pad[2])
		return -EINVAL;

	ca = bch2_device_lookup(c, arg.dev, arg.flags);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	ret = bch2_dev_set_state(c, ca, arg.new_state, arg.flags);

	percpu_ref_put(&ca->ref);
	return ret;
}

static long bch2_ioctl_disk_evacuate(struct bch_fs *c,
				     struct bch_ioctl_disk arg)
{
	struct bch_dev *ca;
	int ret;

	if ((arg.flags & ~BCH_BY_INDEX) ||
	    arg.pad)
		return -EINVAL;

	ca = bch2_device_lookup(c, arg.dev, arg.flags);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	ret = bch2_dev_evacuate(c, ca);

	percpu_ref_put(&ca->ref);
	return ret;
}

#define BCH_IOCTL(_name, _argtype)					\
do {									\
	_argtype i;							\
									\
	if (copy_from_user(&i, arg, sizeof(i)))				\
		return -EFAULT;						\
	return bch2_ioctl_##_name(c, i);				\
} while (0)

long bch2_fs_ioctl(struct bch_fs *c, unsigned cmd, void __user *arg)
{
	/* ioctls that don't require admin cap: */
	switch (cmd) {
	case BCH_IOCTL_QUERY_UUID:
		return bch2_ioctl_query_uuid(c, arg);
	}

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* ioctls that do require admin cap: */
	switch (cmd) {
	case BCH_IOCTL_START:
		BCH_IOCTL(start, struct bch_ioctl_start);
	case BCH_IOCTL_STOP:
		return bch2_ioctl_stop(c);

	case BCH_IOCTL_DISK_ADD:
		BCH_IOCTL(disk_add, struct bch_ioctl_disk);
	case BCH_IOCTL_DISK_REMOVE:
		BCH_IOCTL(disk_remove, struct bch_ioctl_disk);
	case BCH_IOCTL_DISK_ONLINE:
		BCH_IOCTL(disk_online, struct bch_ioctl_disk);
	case BCH_IOCTL_DISK_OFFLINE:
		BCH_IOCTL(disk_offline, struct bch_ioctl_disk);
	case BCH_IOCTL_DISK_SET_STATE:
		BCH_IOCTL(disk_set_state, struct bch_ioctl_disk_set_state);
	case BCH_IOCTL_DISK_EVACUATE:
		BCH_IOCTL(disk_evacuate, struct bch_ioctl_disk);

	default:
		return -ENOTTY;
	}
}

static long bch2_chardev_ioctl(struct file *filp, unsigned cmd, unsigned long v)
{
	struct bch_fs *c = filp->private_data;
	void __user *arg = (void __user *) v;

	return c
		? bch2_fs_ioctl(c, cmd, arg)
		: bch2_global_ioctl(cmd, arg);
}

static const struct file_operations bch_chardev_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = bch2_chardev_ioctl,
	.open		= nonseekable_open,
};

static int bch_chardev_major;
static struct class *bch_chardev_class;
static struct device *bch_chardev;
static DEFINE_IDR(bch_chardev_minor);

void bch2_fs_chardev_exit(struct bch_fs *c)
{
	if (!IS_ERR_OR_NULL(c->chardev))
		device_unregister(c->chardev);
	if (c->minor >= 0)
		idr_remove(&bch_chardev_minor, c->minor);
}

int bch2_fs_chardev_init(struct bch_fs *c)
{
	c->minor = idr_alloc(&bch_chardev_minor, c, 0, 0, GFP_KERNEL);
	if (c->minor < 0)
		return c->minor;

	c->chardev = device_create(bch_chardev_class, NULL,
				   MKDEV(bch_chardev_major, c->minor), NULL,
				   "bcachefs%u-ctl", c->minor);
	if (IS_ERR(c->chardev))
		return PTR_ERR(c->chardev);

	return 0;
}

void bch2_chardev_exit(void)
{
	if (!IS_ERR_OR_NULL(bch_chardev_class))
		device_destroy(bch_chardev_class,
			       MKDEV(bch_chardev_major, 255));
	if (!IS_ERR_OR_NULL(bch_chardev_class))
		class_destroy(bch_chardev_class);
	if (bch_chardev_major > 0)
		unregister_chrdev(bch_chardev_major, "bcachefs");
}

int __init bch2_chardev_init(void)
{
	bch_chardev_major = register_chrdev(0, "bcachefs-ctl", &bch_chardev_fops);
	if (bch_chardev_major < 0)
		return bch_chardev_major;

	bch_chardev_class = class_create(THIS_MODULE, "bcachefs");
	if (IS_ERR(bch_chardev_class))
		return PTR_ERR(bch_chardev_class);

	bch_chardev = device_create(bch_chardev_class, NULL,
				    MKDEV(bch_chardev_major, 255),
				    NULL, "bcachefs-ctl");
	if (IS_ERR(bch_chardev))
		return PTR_ERR(bch_chardev);

	return 0;
}

#endif /* NO_BCACHEFS_CHARDEV */
