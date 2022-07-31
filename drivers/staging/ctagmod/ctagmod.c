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
	printk(KERN_INFO "Loading ctagmod module...\n");

#ifdef CONFIG_PAGE_ALLOC_TAGGING
	pg_data = alloc_pages(GFP_KERNEL, 0);
	if (unlikely(!pg_data)) {
		printk(KERN_ERR "Failed to allocate a page!\n");
		return -ENOMEM;
	}
	printk(KERN_INFO "Page is allocated\n");
#else
	printk(KERN_INFO "CONFIG_PAGE_ALLOC_TAGGING is undefined\n");
#endif

#ifdef CONFIG_SLAB_ALLOC_TAGGING
	slab_data = kmalloc(10, GFP_KERNEL);
	if (unlikely(!slab_data)) {
		printk(KERN_ERR "Failed to allocate a slab object!\n");
		return -ENOMEM;
	}
	printk(KERN_INFO "Slab object is allocated\n");
#else
	printk(KERN_INFO "CONFIG_SLAB_ALLOC_TAGGING is undefined\n");
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
