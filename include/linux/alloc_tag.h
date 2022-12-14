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

#ifdef CONFIG_MEM_ALLOC_PROFILING

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

extern struct static_key_true mem_alloc_profiling_key;

static inline bool mem_alloc_profiling_enabled(void)
{
	return static_branch_likely(&mem_alloc_profiling_key);
}

#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG

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

#else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */

static inline bool is_codetag_empty(union codetag_ref *ref) { return false; }
static inline void set_codetag_empty(union codetag_ref *ref) {}

#endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */

static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes,
				   bool may_allocate)
{
	struct alloc_tag *tag;

	if (!mem_alloc_profiling_enabled())
		return;

#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
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

	if (may_allocate)
		lazy_percpu_counter_add(&tag->bytes_allocated, -bytes);
	else
		lazy_percpu_counter_add_noupgrade(&tag->bytes_allocated, -bytes);
	ref->ct = NULL;
}

static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
{
	__alloc_tag_sub(ref, bytes, true);
}

static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes)
{
	__alloc_tag_sub(ref, bytes, false);
}

static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag, size_t bytes)
{
	if (!mem_alloc_profiling_enabled())
		return;

#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
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
static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes) {}
static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
				 size_t bytes) {}

#endif

#define alloc_hooks(_do_alloc, _res_type, _err)			\
({									\
	_res_type _res;							\
	DEFINE_ALLOC_TAG(_alloc_tag, _old);				\
									\
	_res = _do_alloc;						\
	alloc_tag_restore(&_alloc_tag, _old);				\
	_res;								\
})


#endif /* _LINUX_ALLOC_TAG_H */
