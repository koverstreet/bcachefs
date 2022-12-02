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
	struct page_ext *page_ext = page ? lookup_page_ext(page) : NULL;

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
	struct page *_page;						\
	DEFINE_ALLOC_TAG(_alloc_tag, _old);				\
									\
	_page = _alloc_pages((gfp), (order));				\
	alloc_tag_add(get_page_tag_ref(_page), &_alloc_tag,		\
		      PAGE_SIZE << (order));				\
	alloc_tag_restore(&_alloc_tag, _old);				\
	_page;								\
})

#define pgtag_get_free_pages(gfp_mask, order)				\
({									\
	struct page *_page;						\
	unsigned long _res;						\
	DEFINE_ALLOC_TAG(_alloc_tag, _old);				\
									\
	_res = _get_free_pages((gfp_mask), (order), &_page);		\
	alloc_tag_add(get_page_tag_ref(_page), &_alloc_tag,		\
		      PAGE_SIZE << (order));				\
	alloc_tag_restore(&_alloc_tag, _old);				\
	_res;								\
})

#else /* CONFIG_PAGE_ALLOC_TAGGING */

#define pgtag_alloc_pages(gfp, order) _alloc_pages(gfp, order)

#define pgtag_get_free_pages(gfp_mask, order) \
	_get_free_pages((gfp_mask), (order), NULL)

#define pgalloc_tag_dec(__page, __size)		do {} while (0)

#endif /* CONFIG_PAGE_ALLOC_TAGGING */

#endif /* _LINUX_PGALLOC_TAG_H */
