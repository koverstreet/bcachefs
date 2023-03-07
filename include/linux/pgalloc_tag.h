/* SPDX-License-Identifier: GPL-2.0 */
/*
 * page allocation tagging
 */
#ifndef _LINUX_PGALLOC_TAG_H
#define _LINUX_PGALLOC_TAG_H

#include <linux/alloc_tag.h>
#include <linux/codetag_ctx.h>

#ifdef CONFIG_MEM_ALLOC_PROFILING

#include <linux/page_ext.h>

extern struct page_ext_operations page_alloc_tagging_ops;
extern struct page_ext *page_ext_get(struct page *page);
extern void page_ext_put(struct page_ext *page_ext);

static inline union codetag_ref *codetag_ref_from_page_ext(struct page_ext *page_ext)
{
	return (void *)page_ext + page_alloc_tagging_ops.offset;
}

static inline struct page_ext *page_ext_from_codetag_ref(union codetag_ref *ref)
{
	return (void *)ref - page_alloc_tagging_ops.offset;
}

static inline union codetag_ref *get_page_tag_ref(struct page *page)
{
	struct page_ext *page_ext = page_ext_get(page);

	return page_ext ? codetag_ref_from_page_ext(page_ext) : NULL;
}

static inline void put_page_tag_ref(union codetag_ref *ref)
{
	if (ref)
		page_ext_put(page_ext_from_codetag_ref(ref));
}

static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
{
	if (page) {
		union codetag_ref *ref = get_page_tag_ref(page);

		alloc_tag_sub(ref, PAGE_SIZE << order);
		put_page_tag_ref(ref);
	}
}

static inline void pgalloc_tag_split(struct page *page, unsigned int nr)
{
	int i;
	struct page_ext *page_ext = page_ext_get(page);
	union codetag_ref *ref;
	struct alloc_tag *tag;

	if (unlikely(!page_ext))
		return;

	ref = codetag_ref_from_page_ext(page_ext);
	if (!ref->ct)
		goto out;

	tag = is_codetag_ctx_ref(ref) ? ctc_to_alloc_tag(ref->ctx->ctc)
				      : ct_to_alloc_tag(ref->ct);
	page_ext = page_ext_next(page_ext);
	for (i = 1; i < nr; i++) {
		/* New reference with 0 bytes accounted */
		alloc_tag_add(codetag_ref_from_page_ext(page_ext), tag, 0);
		page_ext = page_ext_next(page_ext);
	}
out:
	page_ext_put(page_ext);
}

#else /* CONFIG_MEM_ALLOC_PROFILING */

static inline union codetag_ref *get_page_tag_ref(struct page *page) { return NULL; }
static inline void put_page_tag_ref(union codetag_ref *ref) {}
#define pgalloc_tag_dec(__page, __size)		do {} while (0)
static inline void pgalloc_tag_split(struct page *page, unsigned int nr) {}

#endif /* CONFIG_MEM_ALLOC_PROFILING */

#endif /* _LINUX_PGALLOC_TAG_H */
