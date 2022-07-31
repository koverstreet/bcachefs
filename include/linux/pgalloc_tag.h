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
	struct page_ext *page_ext = lookup_page_ext(page);

	return page_ext ? (void *)page_ext + page_alloc_tagging_ops.offset
			: NULL;
}

static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
{
	if (page)
		alloc_tag_sub(get_page_tag_ref(page), PAGE_SIZE << order);
}

#endif /* _LINUX_PGALLOC_TAG_H */
