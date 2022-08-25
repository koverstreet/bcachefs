/* SPDX-License-Identifier: GPL-2.0 */
/*
 * slab allocation tagging
 */
#ifndef _LINUX_SLAB_ALLOC_TAG_H
#define _LINUX_SLAB_ALLOC_TAG_H

#ifdef CONFIG_SLAB_ALLOC_TAGGING

#include <linux/alloc_tag.h>

union codetag_ref *get_slab_tag_ref(const void *objp);

/* From slab.h, to avoid a circular dependency: */
size_t ksize(const void *objp);

#define ZERO_SIZE_PTR ((void *)16)
#define ZERO_OR_NULL_PTR(x) ((unsigned long)(x) <= \
				(unsigned long)ZERO_SIZE_PTR)

/*
 * Redefinitions of the common slab allocators/destructors
 */
#define krealloc_hooks(_p, _do_alloc)					\
({									\
	void *_res = _do_alloc;						\
	if (!ZERO_OR_NULL_PTR(_res) && _res != _p)			\
		alloc_tag_add(get_slab_tag_ref(_res), ksize(_res));	\
	_res;								\
})

#define kmalloc_hooks(_do_alloc)	krealloc_hooks(NULL, _do_alloc)

static inline void slab_tag_dec(const void *ptr)
{
	if (!ZERO_OR_NULL_PTR(ptr))
		alloc_tag_sub(get_slab_tag_ref(ptr), ksize(ptr));
}

static inline void slab_tag_dec_nowarn(const void *ptr)
{
	if (!ZERO_OR_NULL_PTR(ptr)) {
		union codetag_ref *ref = get_slab_tag_ref(ptr);

		if (ref && ref->ct)
			alloc_tag_sub(ref, ksize(ptr));
	}
}

#else /* CONFIG_SLAB_ALLOC_TAGGING */

#define krealloc_hooks(_p, _do_alloc)	_do_alloc
#define kmalloc_hooks(_do_alloc)	_do_alloc

static inline void slab_tag_dec(const void *ptr) {}
static inline void slab_tag_dec_nowarn(const void *ptr) {}

#endif /* CONFIG_SLAB_ALLOC_TAGGING */

#endif /* _LINUX_SLAB_ALLOC_TAG_H */
