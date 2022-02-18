// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2017 Netronome Systems, Inc.
 * Copyright (C) 2019 Mellanox Technologies. All rights reserved
 */

#include <linux/device.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#include "netdevsim.h"

static DEFINE_IDA(nsim_bus_dev_ids);
static LIST_HEAD(nsim_bus_dev_list);
static DEFINE_MUTEX(nsim_bus_dev_list_lock);
static bool nsim_bus_enable;

static struct nsim_bus_dev *to_nsim_bus_dev(struct device *dev)
{
	return container_of(dev, struct nsim_bus_dev, dev);
}

static ssize_t
nsim_bus_dev_numvfs_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	struct nsim_bus_dev *nsim_bus_dev = to_nsim_bus_dev(dev);
	unsigned int num_vfs;
	int ret;

	ret = kstrtouint(buf, 0, &num_vfs);
	if (ret)
		return ret;

	device_lock(dev);
	ret = -ENOENT;
	if (dev_get_drvdata(dev))
		ret = nsim_drv_configure_vfs(nsim_bus_dev, num_vfs);
	device_unlock(dev);

	return ret ? ret : count;
}

static ssize_t
nsim_bus_dev_numvfs_show(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	struct nsim_bus_dev *nsim_bus_dev = to_nsim_bus_dev(dev);

	return sprintf(buf, "%u\n", nsim_bus_dev->num_vfs);
}

static struct device_attribute nsim_bus_dev_numvfs_attr =
	__ATTR(sriov_numvfs, 0664, nsim_bus_dev_numvfs_show,
	       nsim_bus_dev_numvfs_store);

static ssize_t
new_port_store(struct device *dev, struct device_attribute *attr,
	       const char *buf, size_t count)
{
	struct nsim_bus_dev *nsim_bus_dev = to_nsim_bus_dev(dev);
	unsigned int port_index;
	int ret;

	/* Prevent to use nsim_bus_dev before initialization. */
	if (!smp_load_acquire(&nsim_bus_dev->init))
		return -EBUSY;
	ret = kstrtouint(buf, 0, &port_index);
	if (ret)
		return ret;

	if (!mutex_trylock(&nsim_bus_dev->nsim_bus_reload_lock))
		return -EBUSY;

	if (nsim_bus_dev->in_reload) {
		mutex_unlock(&nsim_bus_dev->nsim_bus_reload_lock);
		return -EBUSY;
	}

	ret = nsim_drv_port_add(nsim_bus_dev, NSIM_DEV_PORT_TYPE_PF, port_index);
	mutex_unlock(&nsim_bus_dev->nsim_bus_reload_lock);
	return ret ? ret : count;
}

static struct device_attribute nsim_bus_dev_new_port_attr = __ATTR_WO(new_port);

static ssize_t
del_port_store(struct device *dev, struct device_attribute *attr,
	       const char *buf, size_t count)
{
	struct nsim_bus_dev *nsim_bus_dev = to_nsim_bus_dev(dev);
	unsigned int port_index;
	int ret;

	/* Prevent to use nsim_bus_dev before initialization. */
	if (!smp_load_acquire(&nsim_bus_dev->init))
		return -EBUSY;
	ret = kstrtouint(buf, 0, &port_index);
	if (ret)
		return ret;

	if (!mutex_trylock(&nsim_bus_dev->nsim_bus_reload_lock))
		return -EBUSY;

	if (nsim_bus_dev->in_reload) {
		mutex_unlock(&nsim_bus_dev->nsim_bus_reload_lock);
		return -EBUSY;
	}

	ret = nsim_drv_port_del(nsim_bus_dev, NSIM_DEV_PORT_TYPE_PF, port_index);
	mutex_unlock(&nsim_bus_dev->nsim_bus_reload_lock);
	return ret ? ret : count;
}

static struct device_attribute nsim_bus_dev_del_port_attr = __ATTR_WO(del_port);

static struct attribute *nsim_bus_dev_attrs[] = {
	&nsim_bus_dev_numvfs_attr.attr,
	&nsim_bus_dev_new_port_attr.attr,
	&nsim_bus_dev_del_port_attr.attr,
	NULL,
};

static const struct attribute_group nsim_bus_dev_attr_group = {
	.attrs = nsim_bus_dev_attrs,
};

static const struct attribute_group *nsim_bus_dev_attr_groups[] = {
	&nsim_bus_dev_attr_group,
	NULL,
};

static void nsim_bus_dev_release(struct device *dev)
{
}

static struct device_type nsim_bus_dev_type = {
	.groups = nsim_bus_dev_attr_groups,
	.release = nsim_bus_dev_release,
};

static struct nsim_bus_dev *
nsim_bus_dev_new(unsigned int id, unsigned int port_count, unsigned int num_queues);

static ssize_t
new_device_store(struct bus_type *bus, const char *buf, size_t count)
{
	unsigned int id, port_count, num_queues;
	struct nsim_bus_dev *nsim_bus_dev;
	int err;

	err = sscanf(buf, "%u %u %u", &id, &port_count, &num_queues);
	switch (err) {
	case 1:
		port_count = 1;
		fallthrough;
	case 2:
		num_queues = 1;
		fallthrough;
	case 3:
		if (id > INT_MAX) {
			pr_err("Value of \"id\" is too big.\n");
			return -EINVAL;
		}
		break;
	default:
		pr_err("Format for adding new device is \"id port_count num_queues\" (uint uint unit).\n");
		return -EINVAL;
	}

	mutex_lock(&nsim_bus_dev_list_lock);
	/* Prevent to use resource before initialization. */
	if (!smp_load_acquire(&nsim_bus_enable)) {
		err = -EBUSY;
		goto err;
	}

	nsim_bus_dev = nsim_bus_dev_new(id, port_count, num_queues);
	if (IS_ERR(nsim_bus_dev)) {
		err = PTR_ERR(nsim_bus_dev);
		goto err;
	}

	/* Allow using nsim_bus_dev */
	smp_store_release(&nsim_bus_dev->init, true);

	list_add_tail(&nsim_bus_dev->list, &nsim_bus_dev_list);
	mutex_unlock(&nsim_bus_dev_list_lock);

	return count;
err:
	mutex_unlock(&nsim_bus_dev_list_lock);
	return err;
}
static BUS_ATTR_WO(new_device);

static void nsim_bus_dev_del(struct nsim_bus_dev *nsim_bus_dev);

static ssize_t
del_device_store(struct bus_type *bus, const char *buf, size_t count)
{
	struct nsim_bus_dev *nsim_bus_dev, *tmp;
	unsigned int id;
	int err;

	err = sscanf(buf, "%u", &id);
	switch (err) {
	case 1:
		if (id > INT_MAX) {
			pr_err("Value of \"id\" is too big.\n");
			return -EINVAL;
		}
		break;
	default:
		pr_err("Format for deleting device is \"id\" (uint).\n");
		return -EINVAL;
	}

	err = -ENOENT;
	mutex_lock(&nsim_bus_dev_list_lock);
	/* Prevent to use resource before initialization. */
	if (!smp_load_acquire(&nsim_bus_enable)) {
		mutex_unlock(&nsim_bus_dev_list_lock);
		return -EBUSY;
	}
	list_for_each_entry_safe(nsim_bus_dev, tmp, &nsim_bus_dev_list, list) {
		if (nsim_bus_dev->dev.id != id)
			continue;
		list_del(&nsim_bus_dev->list);
		nsim_bus_dev_del(nsim_bus_dev);
		err = 0;
		break;
	}
	mutex_unlock(&nsim_bus_dev_list_lock);
	return !err ? count : err;
}
static BUS_ATTR_WO(del_device);

static struct attribute *nsim_bus_attrs[] = {
	&bus_attr_new_device.attr,
	&bus_attr_del_device.attr,
	NULL
};
ATTRIBUTE_GROUPS(nsim_bus);

static int nsim_bus_probe(struct device *dev)
{
	struct nsim_bus_dev *nsim_bus_dev = to_nsim_bus_dev(dev);

	return nsim_drv_probe(nsim_bus_dev);
}

static void nsim_bus_remove(struct device *dev)
{
	struct nsim_bus_dev *nsim_bus_dev = to_nsim_bus_dev(dev);

	nsim_drv_remove(nsim_bus_dev);
}

static int nsim_num_vf(struct device *dev)
{
	struct nsim_bus_dev *nsim_bus_dev = to_nsim_bus_dev(dev);

	return nsim_bus_dev->num_vfs;
}

static struct bus_type nsim_bus = {
	.name		= DRV_NAME,
	.dev_name	= DRV_NAME,
	.bus_groups	= nsim_bus_groups,
	.probe		= nsim_bus_probe,
	.remove		= nsim_bus_remove,
	.num_vf		= nsim_num_vf,
};

#define NSIM_BUS_DEV_MAX_VFS 4

static struct nsim_bus_dev *
nsim_bus_dev_new(unsigned int id, unsigned int port_count, unsigned int num_queues)
{
	struct nsim_bus_dev *nsim_bus_dev;
	int err;

	nsim_bus_dev = kzalloc(sizeof(*nsim_bus_dev), GFP_KERNEL);
	if (!nsim_bus_dev)
		return ERR_PTR(-ENOMEM);

	err = ida_alloc_range(&nsim_bus_dev_ids, id, id, GFP_KERNEL);
	if (err < 0)
		goto err_nsim_bus_dev_free;
	nsim_bus_dev->dev.id = err;
	nsim_bus_dev->dev.bus = &nsim_bus;
	nsim_bus_dev->dev.type = &nsim_bus_dev_type;
	nsim_bus_dev->port_count = port_count;
	nsim_bus_dev->num_queues = num_queues;
	nsim_bus_dev->initial_net = current->nsproxy->net_ns;
	nsim_bus_dev->max_vfs = NSIM_BUS_DEV_MAX_VFS;
	mutex_init(&nsim_bus_dev->nsim_bus_reload_lock);
	/* Disallow using nsim_bus_dev */
	smp_store_release(&nsim_bus_dev->init, false);

	err = device_register(&nsim_bus_dev->dev);
	if (err)
		goto err_nsim_bus_dev_id_free;

	return nsim_bus_dev;

err_nsim_bus_dev_id_free:
	ida_free(&nsim_bus_dev_ids, nsim_bus_dev->dev.id);
err_nsim_bus_dev_free:
	kfree(nsim_bus_dev);
	return ERR_PTR(err);
}

static void nsim_bus_dev_del(struct nsim_bus_dev *nsim_bus_dev)
{
	/* Disallow using nsim_bus_dev */
	smp_store_release(&nsim_bus_dev->init, false);
	device_unregister(&nsim_bus_dev->dev);
	ida_free(&nsim_bus_dev_ids, nsim_bus_dev->dev.id);
	kfree(nsim_bus_dev);
}

static struct device_driver nsim_driver = {
	.name		= DRV_NAME,
	.bus		= &nsim_bus,
	.owner		= THIS_MODULE,
};

int nsim_bus_init(void)
{
	int err;

	err = bus_register(&nsim_bus);
	if (err)
		return err;
	err = driver_register(&nsim_driver);
	if (err)
		goto err_bus_unregister;
	/* Allow using resources */
	smp_store_release(&nsim_bus_enable, true);
	return 0;

err_bus_unregister:
	bus_unregister(&nsim_bus);
	return err;
}

void nsim_bus_exit(void)
{
	struct nsim_bus_dev *nsim_bus_dev, *tmp;

	/* Disallow using resources */
	smp_store_release(&nsim_bus_enable, false);

	mutex_lock(&nsim_bus_dev_list_lock);
	list_for_each_entry_safe(nsim_bus_dev, tmp, &nsim_bus_dev_list, list) {
		list_del(&nsim_bus_dev->list);
		nsim_bus_dev_del(nsim_bus_dev);
	}
	mutex_unlock(&nsim_bus_dev_list_lock);

	driver_unregister(&nsim_driver);
	bus_unregister(&nsim_bus);
}
