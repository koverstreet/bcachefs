/* SPDX-License-Identifier: GPL-2.0 */
/*
 * page allocation tagging
 */
#ifndef _LINUX_PGALLOC_TAG_H
#define _LINUX_PGALLOC_TAG_H

#include <linux/alloc_tag.h>
#include <linux/page_ext.h>

extern struct page_ext_operations page_alloc_tagging_ops;
struct page_ext *lookup_page_ext(const struct page *page);

static inline union codetag_ref *get_page_tag_ref(struct page *page)
{
	if (page && mem_alloc_profiling_enabled()) {
		struct page_ext *page_ext = lookup_page_ext(page);

		if (page_ext)
			return (void *)page_ext + page_alloc_tagging_ops.offset;
	}
	return NULL;
}

static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
{
	union codetag_ref *ref = get_page_tag_ref(page);

	if (ref)
		alloc_tag_sub(ref, PAGE_SIZE << order);
}

#endif /* _LINUX_PGALLOC_TAG_H */
