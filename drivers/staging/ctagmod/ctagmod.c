#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

static int kmalloc_sz;
static void *kmalloc_ptr;
static int pgalloc_sz;
static struct page *pgalloc_ptr;

static ssize_t parse_size(const char *buf)
{
	unsigned long sz;
	int err;

	err = kstrtoul(buf, 0, &sz);
	if (err)
		return err;
	return sz;
}

static ssize_t kmalloc_size_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", kmalloc_sz);
}

static ssize_t kmalloc_size_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	ssize_t sz = parse_size(buf);

	if (sz < 0)
		return sz;

	if (kmalloc_sz)
		kfree(kmalloc_ptr);
	if (sz > 0) {
		kmalloc_ptr = kmalloc(sz, GFP_KERNEL);
		if (unlikely(!kmalloc_ptr)) {
			printk(KERN_ERR "kmalloc failed!\n");
			return -ENOMEM;
		}
	}
	kmalloc_sz = sz;

	return count;
}

static struct kobj_attribute dev_attr_kmalloc_size = __ATTR_RW_MODE(kmalloc_size, 0600);

static ssize_t pgalloc_size_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", pgalloc_sz);
}

static ssize_t pgalloc_size_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	ssize_t sz = parse_size(buf);

	if (sz < 0)
		return sz;

	if (pgalloc_sz)
		free_pages((unsigned long)page_address(pgalloc_ptr), get_order(pgalloc_sz));
	if (sz > 0) {
		pgalloc_ptr = alloc_pages(GFP_KERNEL, get_order(sz));
		if (unlikely(!pgalloc_ptr)) {
			printk(KERN_ERR "alloc_pages failed!\n");
			return -ENOMEM;
		}
	}
	pgalloc_sz = sz;

	return count;
}

static struct kobj_attribute dev_attr_pgalloc_size = __ATTR_RW_MODE(pgalloc_size, 0600);

static struct attribute *ctagmod_attributes[] = {
	&dev_attr_kmalloc_size.attr,
	&dev_attr_pgalloc_size.attr,
	NULL
};

static struct attribute_group ctagmod_attr_group = {
	.name = "ctagmod",
	.attrs = ctagmod_attributes,
};

static int __init ctagmod_start(void)
{
	printk(KERN_INFO "Loading ctagmod module\n");
#ifdef CONFIG_MEM_ALLOC_PROFILING
	if (sysfs_create_group(mm_kobj, &ctagmod_attr_group))
		pr_err("ctagmod: failed to create sysfs group\n");
#else
	printk(KERN_INFO "CONFIG_MEM_ALLOC_PROFILING is undefined\n");
#endif
	return 0;
}

static void __exit ctagmod_end(void)
{
	printk(KERN_INFO "Unloading ctagmod module\n");
#ifdef CONFIG_MEM_ALLOC_PROFILING
	sysfs_remove_group(mm_kobj, &ctagmod_attr_group);
#endif
}

module_init(ctagmod_start);
module_exit(ctagmod_end);
