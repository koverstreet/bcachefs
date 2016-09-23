
#include <linux/export.h>
#include <linux/generic-radix-tree.h>
#include <linux/gfp.h>

#define GENRADIX_ARY		(PAGE_SIZE / sizeof(struct genradix_node *))
#define GENRADIX_ARY_SHIFT	ilog2(GENRADIX_ARY)

struct genradix_node {
	union {
		/* Interior node: */
		struct genradix_node	*children[GENRADIX_ARY];

		/* Leaf: */
		u8			data[PAGE_SIZE];
	};
};

static inline unsigned genradix_depth_shift(unsigned depth)
{
	return PAGE_SHIFT + GENRADIX_ARY_SHIFT * depth;
}

/*
 * Returns size (of data, in bytes) that a tree of a given depth holds:
 */
static inline size_t genradix_depth_size(unsigned depth)
{
	return 1UL << genradix_depth_shift(depth);
}

/*
 * Returns pointer to the specified byte @offset within @radix, or NULL if not
 * allocated
 */
void *__genradix_ptr(struct __genradix *radix, size_t offset)
{
	size_t level = radix->depth;
	struct genradix_node *n = radix->root;

	if (offset >= genradix_depth_size(radix->depth))
		return NULL;

	while (1) {
		if (!n)
			return NULL;
		if (!level)
			break;

		level--;

		n = n->children[offset >> genradix_depth_shift(level)];
		offset &= genradix_depth_size(level) - 1;
	}

	return &n->data[offset];
}
EXPORT_SYMBOL(__genradix_ptr);

/*
 * Returns pointer to the specified byte @offset within @radix, allocating it if
 * necessary - newly allocated slots are always zeroed out:
 */
void *__genradix_ptr_alloc(struct __genradix *radix, size_t offset,
			   gfp_t gfp_mask)
{
	struct genradix_node **n;
	size_t level;

	/* Increase tree depth if necessary: */

	while (offset >= genradix_depth_size(radix->depth)) {
		struct genradix_node *new_root =
			(void *) __get_free_page(gfp_mask|__GFP_ZERO);

		if (!new_root)
			return NULL;

		new_root->children[0] = radix->root;
		radix->root = new_root;
		radix->depth++;
	}

	n = &radix->root;
	level = radix->depth;

	while (1) {
		if (!*n) {
			*n = (void *) __get_free_page(gfp_mask|__GFP_ZERO);
			if (!*n)
				return NULL;
		}

		if (!level)
			break;

		level--;

		n = &(*n)->children[offset >> genradix_depth_shift(level)];
		offset &= genradix_depth_size(level) - 1;
	}

	return &(*n)->data[offset];
}
EXPORT_SYMBOL(__genradix_ptr_alloc);

void *__genradix_iter_peek(struct genradix_iter *iter,
			   struct __genradix *radix,
			   size_t objs_per_page)
{
	struct genradix_node *n;
	size_t level, i;

	if (!radix->root)
		return NULL;
restart:
	if (iter->offset >= genradix_depth_size(radix->depth))
		return NULL;

	n	= radix->root;
	level	= radix->depth;

	while (level) {
		level--;

		i = (iter->offset >> genradix_depth_shift(level)) &
			(GENRADIX_ARY - 1);

		while (!n->children[i]) {
			i++;
			iter->offset = round_down(iter->offset +
					   genradix_depth_size(level),
					   genradix_depth_size(level));
			iter->pos = (iter->offset >> PAGE_SHIFT) *
				objs_per_page;
			if (i == GENRADIX_ARY)
				goto restart;
		}

		n = n->children[i];
	}

	return &n->data[iter->offset & (PAGE_SIZE - 1)];
}
EXPORT_SYMBOL(__genradix_iter_peek);

static void genradix_free_recurse(struct genradix_node *n, unsigned level)
{
	if (level) {
		unsigned i;

		for (i = 0; i < GENRADIX_ARY; i++)
			if (n->children[i])
				genradix_free_recurse(n->children[i], level - 1);
	}

	free_page((unsigned long) n);
}

void __genradix_free(struct __genradix *radix)
{
	genradix_free_recurse(radix->root, radix->depth);

	radix->root = NULL;
	radix->depth = 0;
}
EXPORT_SYMBOL(__genradix_free);
