#ifndef _EYTZINGER_H
#define _EYTZINGER_H

#include <linux/bitops.h>
#include <linux/log2.h>

#include "util.h"

/*
 * Traversal for trees in eytzinger layout - a full binary tree layed out in an
 * array
 *
 * We used one based indexing, not zero based: with one based indexing, each
 * level of the tree starts at a power of two - leading to better alignment -
 * and it's what you want for implementing next/prev and to/from inorder.
 *
 * To/from inorder also uses 1 based indexing.
 *
 * Size parameter is treated as if we were using 0 based indexing, however:
 * valid nodes, and inorder indices, are in the range [1..size)
 */

static inline unsigned eytzinger_child(unsigned j, unsigned child)
{
	EBUG_ON(child > 1);

	return (j << 1) + child;
}

static inline unsigned eytzinger_left_child(unsigned j)
{
	return eytzinger_child(j, 0);
}

static inline unsigned eytzinger_right_child(unsigned j)
{
	return eytzinger_child(j, 1);
}

static inline unsigned eytzinger_first(unsigned size)
{
	return rounddown_pow_of_two(size - 1);
}

static inline unsigned eytzinger_last(unsigned size)
{
	return rounddown_pow_of_two(size) - 1;
}

/*
 * eytzinger_next() and eytzinger_prev() have the nice properties that
 *
 * eytzinger_next(0) == eytzinger_first())
 * eytzinger_prev(0) == eytzinger_last())
 *
 * eytzinger_prev(eytzinger_first()) == 0
 * eytzinger_next(eytzinger_last()) == 0
 */

static inline unsigned eytzinger_next(unsigned j, unsigned size)
{
	EBUG_ON(j >= size);

	if (eytzinger_right_child(j) < size) {
		j = eytzinger_right_child(j);

		j <<= __fls(size) - __fls(j);
		j >>= j >= size;
	} else {
		j >>= ffz(j) + 1;
	}

	return j;
}

static inline unsigned eytzinger_prev(unsigned j, unsigned size)
{
	EBUG_ON(j >= size);

	if (eytzinger_left_child(j) < size) {
		j = eytzinger_left_child(j);

		j <<= __fls(size) - __fls(j);
		j -= 1;
		j >>= j >= size;
	} else {
		j >>= __ffs(j) + 1;
	}

	return j;
}

static inline unsigned eytzinger_extra(unsigned size)
{
	return (size - rounddown_pow_of_two(size - 1)) << 1;
}

static inline unsigned __eytzinger_to_inorder(unsigned j, unsigned size,
					      unsigned extra)
{
	unsigned b = __fls(j);
	unsigned shift = __fls(size - 1) - b;
	int s;

	EBUG_ON(!j || j >= size);

	j  ^= 1U << b;
	j <<= 1;
	j  |= 1;
	j <<= shift;

	/*
	 * sign bit trick:
	 *
	 * if (j > extra)
	 *	j -= (j - extra) >> 1;
	 */
	s = extra - j;
	j += (s >> 1) & (s >> 31);

	return j;
}

static inline unsigned __inorder_to_eytzinger(unsigned j, unsigned size,
					      unsigned extra)
{
	unsigned shift;
	int s;

	EBUG_ON(!j || j >= size);

	/*
	 * sign bit trick:
	 *
	 * if (j > extra)
	 *	j += j - extra;
	 */
	s = extra - j;
	j -= s & (s >> 31);

	shift = __ffs(j);

	j >>= shift + 1;
	j  |= 1U << (__fls(size - 1) - shift);

	return j;
}

static inline unsigned eytzinger_to_inorder(unsigned j, unsigned size)
{
	return __eytzinger_to_inorder(j, size, eytzinger_extra(size));
}

static inline unsigned inorder_to_eytzinger(unsigned j, unsigned size)
{
	return __inorder_to_eytzinger(j, size, eytzinger_extra(size));
}

#define eytzinger_for_each(_i, _size)			\
	for ((_i) = eytzinger_first((_size));		\
	     (_i) != 0;					\
	     (_i) = eytzinger_next((_i), (_size)))

#if 0
void eytzinger_test(void)
{
	unsigned i, j, size;

	for (size = 2;
	     size < 65536000;
	     size++) {
		if (!(size % 4096))
			printk(KERN_INFO "tree size %u\n", size);

		assert(eytzinger_prev(0, size) == eytzinger_last(size));
		assert(eytzinger_next(0, size) == eytzinger_first(size));

		assert(eytzinger_prev(eytzinger_first(size), size) == 0);
		assert(eytzinger_next(eytzinger_last(size), size) == 0);

		eytzinger_for_each(j, size) {
			assert(from_inorder(i, size) == j);
			assert(to_inorder(j, size) == i);

			if (j != eytzinger_last(size)) {
				unsigned next = eytzinger_next(j, size);

				assert(eytzinger_prev(next, size) == j);
			}
		}
	}

}
#endif

#endif /* _EYTZINGER_H */
