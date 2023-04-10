// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic show_mem() implementation
 *
 * Copyright (C) 2008 Johannes Weiner <hannes@saeurebad.de>
 */

#include <linux/mm.h>
#include <linux/cma.h>
#include <linux/seq_buf.h>

#include "slab.h"

void __show_mem(unsigned int filter, nodemask_t *nodemask, int max_zone_idx)
{
	unsigned long total = 0, reserved = 0, highmem = 0;
	struct zone *zone;
	char *buf;

	printk("Mem-Info:\n");
	__show_free_areas(filter, nodemask, max_zone_idx);

	for_each_populated_zone(zone) {

		total += zone->present_pages;
		reserved += zone->present_pages - zone_managed_pages(zone);

		if (is_highmem(zone))
			highmem += zone->present_pages;
	}

	printk("%lu pages RAM\n", total);
	printk("%lu pages HighMem/MovableOnly\n", highmem);
	printk("%lu pages reserved\n", reserved);
#ifdef CONFIG_CMA
	printk("%lu pages cma reserved\n", totalcma_pages);
#endif
#ifdef CONFIG_MEMORY_FAILURE
	printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poisoned_pages));
#endif

	buf = kmalloc(4096, GFP_ATOMIC);
	if (buf) {
		struct seq_buf s;

		printk("Unreclaimable slab info:\n");
		seq_buf_init(&s, buf, 4096);
		dump_unreclaimable_slab(&s);
		seq_buf_terminate(&s);
		printk("%s", buf);

		printk("Shrinkers:\n");
		seq_buf_init(&s, buf, 4096);
		shrinkers_to_text(&s);
		seq_buf_terminate(&s);
		printk("%s", buf);

		kfree(buf);
	}
#ifdef CONFIG_MEM_ALLOC_PROFILING
	{
		struct seq_buf s;
		char *buf = kmalloc(4096, GFP_ATOMIC);

		if (buf) {
			printk("Memory allocations:\n");
			seq_buf_init(&s, buf, 4096);
			alloc_tags_show_mem_report(&s);
			printk("%s", buf);
			kfree(buf);
		}
	}
#endif
}
