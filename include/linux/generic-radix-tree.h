/*
 * Generic radix trees/sparse arrays:
 *
 * A generic radix tree has all nodes of size PAGE_SIZE - both leaves and
 * interior nodes.
 */

#include <linux/kernel.h>

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

#define DECLARE_GENRADIX_TYPE(_name, _type)			\
struct _name {							\
	struct __genradix	tree;				\
	_type			type[0] __aligned(1);		\
}

#define DECLARE_GENRADIX(_name, _type)				\
struct {							\
	struct __genradix	tree;				\
	_type			type[0] __aligned(1);		\
} _name

#define DEFINE_GENRADIX(_name, _type)				\
	DECLARE_GENRADIX(_name, _type) = __GENRADIX_INITIALIZER

#define genradix_init(_radix)					\
do {								\
	*(_radix) = (typeof(*_radix)) __GENRADIX_INITIALIZER;	\
} while (0)

void __genradix_free(struct __genradix *);

#define genradix_free(_radix)	__genradix_free(&(_radix)->tree)

void *__genradix_ptr(struct __genradix *, size_t);

/* Returns a pointer to element at @_idx */
#define genradix_ptr(_radix, _idx)				\
	((typeof((_radix)->type[0]) *)				\
	 __genradix_ptr(&(_radix)->tree,			\
			(_idx) * sizeof((_radix)->type[0])))

void *__genradix_ptr_alloc(struct __genradix *, size_t, gfp_t);

/* Returns a pointer to element at @_idx, allocating it if necessary */
#define genradix_ptr_alloc(_radix, _idx, _gfp)			\
	((typeof((_radix)->type[0]) *)				\
	 __genradix_ptr_alloc(&(_radix)->tree,			\
			      (_idx) * sizeof((_radix)->type[0]),\
			      _gfp))
