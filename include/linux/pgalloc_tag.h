/* SPDX-License-Identifier: GPL-2.0 */
/*
 * page allocation tagging
 */
#ifndef _LINUX_PGALLOC_TAG_H
#define _LINUX_PGALLOC_TAG_H

#ifdef CONFIG_PAGE_ALLOC_TAGGING

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

/*
 * Redefinitions of the common page allocators/destructors
 */
#define pgtag_alloc_pages(gfp, order)					\
({									\
	struct page *_page = _alloc_pages((gfp), (order));		\
									\
	if (_page)							\
		alloc_tag_add(get_page_tag_ref(_page), PAGE_SIZE << (order));\
	_page;								\
})

#define pgtag_get_free_pages(gfp_mask, order)				\
({									\
	struct page *_page;						\
	unsigned long _res = _get_free_pages((gfp_mask), (order), &_page);\
									\
	if (_res)							\
		alloc_tag_add(get_page_tag_ref(_page), PAGE_SIZE << (order));\
	_res;								\
})

#else /* CONFIG_PAGE_ALLOC_TAGGING */

#define pgtag_alloc_pages(gfp, order) _alloc_pages(gfp, order)

#define pgtag_get_free_pages(gfp_mask, order) \
	_get_free_pages((gfp_mask), (order), NULL)

#define pgalloc_tag_dec(__page, __size)		do {} while (0)

#endif /* CONFIG_PAGE_ALLOC_TAGGING */

#endif /* _LINUX_PGALLOC_TAG_H */
