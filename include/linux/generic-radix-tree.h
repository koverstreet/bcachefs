#ifndef _LINUX_GENERIC_RADIX_TREE_H
#define _LINUX_GENERIC_RADIX_TREE_H

/*
 * Generic radix trees/sparse arrays:
 *
 * A generic radix tree has all nodes of size PAGE_SIZE - both leaves and
 * interior nodes.
 */

#include <asm/page.h>
#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/log2.h>

struct genradix_node;

struct __genradix {
	struct genradix_node		*root;
	size_t				depth;
};

/*
 * NOTE: currently, sizeof(_type) must be a power of two and not larger than
 * PAGE_SIZE:
 */

#define __GENRADIX_INITIALIZER					\
	{							\
		.tree = {					\
			.root = NULL,				\
			.depth = 0,				\
		}						\
	}

/*
 * We use a 0 size array to stash the type we're storing without taking any
 * space at runtime - then the various accessor macros can use typeof() to get
 * to it for casts/sizeof - we also force the alignment so that storing a type
 * with a ridiculous alignment doesn't blow up the alignment or size of the
 * genradix.
 */

#define GENRADIX(_type)						\
struct {							\
	struct __genradix	tree;				\
	_type			type[0] __aligned(1);		\
}

#define DEFINE_GENRADIX(_name, _type)				\
	GENRADIX(_type) _name = __GENRADIX_INITIALIZER

#define genradix_init(_radix)					\
do {								\
	*(_radix) = (typeof(*_radix)) __GENRADIX_INITIALIZER;	\
} while (0)

void __genradix_free(struct __genradix *);

#define genradix_free(_radix)	__genradix_free(&(_radix)->tree)

static inline size_t __idx_to_offset(size_t idx, size_t obj_size)
{
	BUILD_BUG_ON(obj_size > PAGE_SIZE);

	if (!is_power_of_2(obj_size)) {
		size_t objs_per_page = PAGE_SIZE / obj_size;

		return (idx / objs_per_page) * PAGE_SIZE +
			(idx % objs_per_page) * obj_size;
	} else {
		return idx * obj_size;
	}
}

#define __genradix_cast(_radix)		(typeof((_radix)->type[0]) *)
#define __genradix_obj_size(_radix)	sizeof((_radix)->type[0])
#define __genradix_idx_to_offset(_radix, _idx)			\
	__idx_to_offset(_idx, __genradix_obj_size(_radix))

void *__genradix_ptr(struct __genradix *, size_t);

/* Returns a pointer to element at @_idx */
#define genradix_ptr(_radix, _idx)				\
	(__genradix_cast(_radix)				\
	 __genradix_ptr(&(_radix)->tree,			\
			__genradix_idx_to_offset(_radix, _idx)))

void *__genradix_ptr_alloc(struct __genradix *, size_t, gfp_t);

/* Returns a pointer to element at @_idx, allocating it if necessary */
#define genradix_ptr_alloc(_radix, _idx, _gfp)			\
	(__genradix_cast(_radix)				\
	 __genradix_ptr_alloc(&(_radix)->tree,			\
			__genradix_idx_to_offset(_radix, _idx),	\
			_gfp))

struct genradix_iter {
	size_t			offset;
	size_t			pos;
};

#define genradix_iter_init(_radix, _idx)			\
	((struct genradix_iter) {				\
		.pos	= (_idx),				\
		.offset	= __genradix_idx_to_offset((_radix), (_idx)),\
	})

void *__genradix_iter_peek(struct genradix_iter *, struct __genradix *, size_t);

#define genradix_iter_peek(_iter, _radix)			\
	(__genradix_cast(_radix)				\
	 __genradix_iter_peek(_iter, &(_radix)->tree,		\
			      PAGE_SIZE / __genradix_obj_size(_radix)))

static inline void __genradix_iter_advance(struct genradix_iter *iter,
					   size_t obj_size)
{
	iter->offset += obj_size;

	if (!is_power_of_2(obj_size) &&
	    (iter->offset & (PAGE_SIZE - 1)) + obj_size > PAGE_SIZE)
		iter->offset = round_up(iter->offset, PAGE_SIZE);

	iter->pos++;
}

#define genradix_iter_advance(_iter, _radix)			\
	__genradix_iter_advance(_iter, __genradix_obj_size(_radix))

#endif /* _LINUX_GENERIC_RADIX_TREE_H */
