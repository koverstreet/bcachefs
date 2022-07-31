#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

static struct page *pg_data;
static void *slab_data;

static int __init ctagmod_start(void)
{
#ifdef CONFIG_MEM_ALLOC_PROFILING
	struct page *pg_tmp;
	void *slab_tmp;

	printk(KERN_INFO "Loading ctagmod module...\n");

	pg_data = alloc_pages(GFP_KERNEL, 0);
	if (unlikely(!pg_data)) {
		printk(KERN_ERR "Failed to allocate a page!\n");
		return -ENOMEM;
	}
	pg_tmp = alloc_pages(GFP_KERNEL, 0);
	if (unlikely(!pg_tmp)) {
		printk(KERN_ERR "Failed to allocate a page!\n");
		return -ENOMEM;
	}
	free_pages((unsigned long)page_address(pg_tmp), 0);
	printk(KERN_INFO "Page is allocated\n");

	slab_data = kmalloc(10, GFP_KERNEL);
	if (unlikely(!slab_data)) {
		printk(KERN_ERR "Failed to allocate a slab object!\n");
		return -ENOMEM;
	}
	slab_tmp = kmalloc(10, GFP_KERNEL);
	if (unlikely(!slab_tmp)) {
		printk(KERN_ERR "Failed to allocate a slab object!\n");
		return -ENOMEM;
	}
	kfree(slab_tmp);
	printk(KERN_INFO "Slab object is allocated\n");
#else
	printk(KERN_INFO "CONFIG_MEM_ALLOC_PROFILING is undefined\n");
#endif
	return 0;
}

static void __exit ctagmod_end(void)
{
	if (slab_data)
		kfree(slab_data);
	if (pg_data)
		free_pages((unsigned long)page_address(pg_data), 0);
	printk(KERN_INFO "Unloading ctagmod\n");
}

module_init(ctagmod_start);
module_exit(ctagmod_end);
