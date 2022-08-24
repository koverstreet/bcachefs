/* SPDX-License-Identifier: GPL-2.0 */
/*
 * slab allocation tagging
 */
#ifndef _LINUX_SLAB_ALLOC_TAG_H
#define _LINUX_SLAB_ALLOC_TAG_H

extern void _kfree(const void *objp);

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
#define slabtag_kmalloc(size, flags)					\
({									\
	void *_res = _kmalloc((size), (flags));				\
	if (!ZERO_OR_NULL_PTR(_res))					\
		alloc_tag_add(get_slab_tag_ref(_res), ksize(_res));	\
	_res;								\
})

static inline void slabtag_kfree(const void *ptr)
{
	if (!ZERO_OR_NULL_PTR(ptr))
		alloc_tag_sub(get_slab_tag_ref(ptr), ksize(ptr));
	_kfree(ptr);
}

#else /* CONFIG_SLAB_ALLOC_TAGGING */

#define slabtag_kmalloc(size, flags) _kmalloc(size, flags)

static inline void slabtag_kfree(const void *objp)
{
	_kfree(objp);
}

#endif /* CONFIG_SLAB_ALLOC_TAGGING */

#endif /* _LINUX_SLAB_ALLOC_TAG_H */
