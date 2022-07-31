/* SPDX-License-Identifier: GPL-2.0 */
/*
 * allocation tagging
 */
#ifndef _LINUX_ALLOC_TAG_H
#define _LINUX_ALLOC_TAG_H

#include <linux/bug.h>
#include <linux/codetag.h>
#include <linux/container_of.h>
#include <linux/lazy-percpu-counter.h>

/*
 * An instance of this structure is created in a special ELF section at every
 * allocation callsite. At runtime, the special section is treated as
 * an array of these. Embedded codetag utilizes codetag framework.
 */
struct alloc_tag {
	struct codetag_with_ctx		ctc;
	unsigned long			last_wrap;
	struct raw_lazy_percpu_counter	call_count;
	struct raw_lazy_percpu_counter	bytes_allocated;
} __aligned(8);

static inline struct alloc_tag *ctc_to_alloc_tag(struct codetag_with_ctx *ctc)
{
	return container_of(ctc, struct alloc_tag, ctc);
}

static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
{
	return container_of(ct_to_ctc(ct), struct alloc_tag, ctc);
}

struct codetag_ctx *alloc_tag_create_ctx(struct alloc_tag *tag, size_t size);
void alloc_tag_free_ctx(struct codetag_ctx *ctx, struct alloc_tag **ptag);
bool alloc_tag_enable_ctx(struct alloc_tag *tag, bool enable);

#define DEFINE_ALLOC_TAG(_alloc_tag)					\
	static struct alloc_tag _alloc_tag __used __aligned(8)		\
	__section("alloc_tags") = { .ctc.ct = CODE_TAG_INIT }

#define alloc_tag_counter_read(counter)					\
	__lazy_percpu_counter_read(counter)

static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes)
{
	struct alloc_tag *tag;

	if (is_codetag_ctx_ref(ref))
		alloc_tag_free_ctx(ref->ctx, &tag);
	else
		tag = ct_to_alloc_tag(ref->ct);

	__lazy_percpu_counter_add(&tag->call_count, &tag->last_wrap, -1);
	__lazy_percpu_counter_add(&tag->bytes_allocated, &tag->last_wrap, -bytes);
	ref->ct = NULL;
}

#define alloc_tag_sub(_ref, _bytes)					\
do {									\
	if ((_ref) && (_ref)->ct)					\
		__alloc_tag_sub(_ref, _bytes);				\
} while (0)

static inline void __alloc_tag_add(struct alloc_tag *tag, union codetag_ref *ref, size_t bytes)
{
	if (codetag_ctx_enabled(&tag->ctc))
		ref->ctx = alloc_tag_create_ctx(tag, bytes);
	else
		ref->ct = &tag->ctc.ct;

	__lazy_percpu_counter_add(&tag->call_count, &tag->last_wrap, 1);
	__lazy_percpu_counter_add(&tag->bytes_allocated, &tag->last_wrap, bytes);
}

#define alloc_tag_add(_ref, _bytes)					\
do {									\
	DEFINE_ALLOC_TAG(_alloc_tag);					\
	if (_ref && !WARN_ONCE(_ref->ct, "alloc_tag was not cleared"))	\
		__alloc_tag_add(&_alloc_tag, _ref, _bytes);		\
} while (0)

#endif /* _LINUX_ALLOC_TAG_H */
