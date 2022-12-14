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
#include <linux/static_key.h>

/*
 * An instance of this structure is created in a special ELF section at every
 * allocation callsite. At runtime, the special section is treated as
 * an array of these. Embedded codetag utilizes codetag framework.
 */
struct alloc_tag {
	struct codetag_with_ctx		ctc;
	struct lazy_percpu_counter	bytes_allocated;
} __aligned(8);

#ifdef CONFIG_ALLOC_TAGGING

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

#define DEFINE_ALLOC_TAG(_alloc_tag, _old)				\
	static struct alloc_tag _alloc_tag __used __aligned(8)		\
	__section("alloc_tags") = { .ctc.ct = CODE_TAG_INIT };		\
	struct alloc_tag * __maybe_unused _old = alloc_tag_save(&_alloc_tag)

extern struct static_key_true alloc_tagging_key;

static inline bool alloc_tagging_enabled(void)
{
	return static_branch_likely(&alloc_tagging_key);
}

#ifdef CONFIG_ALLOC_TAGGING_DEBUG

#define CODETAG_EMPTY	(void*)1

static inline bool is_codetag_empty(union codetag_ref *ref)
{
	return ref->ct == CODETAG_EMPTY;
}

static inline void set_codetag_empty(union codetag_ref *ref)
{
	if (ref)
		ref->ct = CODETAG_EMPTY;
}

#else /* CONFIG_ALLOC_TAGGING_DEBUG */

static inline bool is_codetag_empty(union codetag_ref *ref) { return false; }
static inline void set_codetag_empty(union codetag_ref *ref) {}

#endif /* CONFIG_ALLOC_TAGGING_DEBUG */


static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
{
	struct alloc_tag *tag;

	if (!alloc_tagging_enabled())
		return;

#ifdef CONFIG_ALLOC_TAGGING_DEBUG
	WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
#endif
	if (!ref || !ref->ct)
		return;

	if (is_codetag_empty(ref)) {
		ref->ct = NULL;
		return;
	}

	if (is_codetag_ctx_ref(ref))
		alloc_tag_free_ctx(ref->ctx, &tag);
	else
		tag = ct_to_alloc_tag(ref->ct);
	lazy_percpu_counter_add(&tag->bytes_allocated, -bytes);
	ref->ct = NULL;
}

static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag, size_t bytes)
{
	if (!alloc_tagging_enabled())
		return;

#ifdef CONFIG_ALLOC_TAGGING_DEBUG
	WARN_ONCE(ref && ref->ct,
		  "alloc_tag was not cleared (got tag for %s:%u)\n",\
		  ref->ct->filename, ref->ct->lineno);

	WARN_ONCE(!tag, "current->alloc_tag not set");
#endif
	if (!ref || !tag)
		return;

	if (codetag_ctx_enabled(&tag->ctc))
		ref->ctx = alloc_tag_create_ctx(tag, bytes);
	else
		ref->ct = &tag->ctc.ct;
	lazy_percpu_counter_add(&tag->bytes_allocated, bytes);
}

#else

#define DEFINE_ALLOC_TAG(_alloc_tag, _old)
static inline void set_codetag_empty(union codetag_ref *ref) {}
static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
				 size_t bytes) {}

#endif

#endif /* _LINUX_ALLOC_TAG_H */
