// SPDX-License-Identifier: GPL-2.0
/*
 * A fast, small, non-recursive O(n log n) sort for the Linux kernel
 *
 * This performs n*log2(n) + 0.37*n + o(n) comparisons on average,
 * and 1.5*n*log2(n) + O(n) in the (very contrived) worst case.
 *
 * Quicksort manages n*log2(n) - 1.26*n for random inputs (1.63*n
 * better) at the expense of stack usage and much larger code to avoid
 * quicksort's O(n^2) worst case.
 */

#include <linux/types.h>
#include <linux/export.h>
#include <linux/sort.h>

/**
 * is_aligned - is this pointer & size okay for word-wide copying?
 * @base: pointer to data
 * @size: size of each element
 * @align: required alignment (typically 4 or 8)
 *
 * Returns true if elements can be copied using word loads and stores.
 * The size must be a multiple of the alignment, and the base address must
 * be if we do not have CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS.
 *
 * For some reason, gcc doesn't know to optimize "if (a & mask || b & mask)"
 * to "if ((a | b) & mask)", so we do that by hand.
 */
__attribute_const__ __always_inline
static bool is_aligned(const void *base, size_t size, unsigned char align)
{
	unsigned char lsbits = (unsigned char)size;

	(void)base;
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	lsbits |= (unsigned char)(uintptr_t)base;
#endif
	return (lsbits & (align - 1)) == 0;
}

/**
 * swap_words_32 - swap two elements in 32-bit chunks
 * @a: pointer to the first element to swap
 * @b: pointer to the second element to swap
 * @n: element size (must be a multiple of 4)
 *
 * Exchange the two objects in memory.  This exploits base+index addressing,
 * which basically all CPUs have, to minimize loop overhead computations.
 *
 * For some reason, on x86 gcc 7.3.0 adds a redundant test of n at the
 * bottom of the loop, even though the zero flag is still valid from the
 * subtract (since the intervening mov instructions don't alter the flags).
 * Gcc 8.1.0 doesn't have that problem.
 */
static void swap_words_32(void *a, void *b, size_t n)
{
	do {
		u32 t = *(u32 *)(a + (n -= 4));
		*(u32 *)(a + n) = *(u32 *)(b + n);
		*(u32 *)(b + n) = t;
	} while (n);
}

/**
 * swap_words_64 - swap two elements in 64-bit chunks
 * @a: pointer to the first element to swap
 * @b: pointer to the second element to swap
 * @n: element size (must be a multiple of 8)
 *
 * Exchange the two objects in memory.  This exploits base+index
 * addressing, which basically all CPUs have, to minimize loop overhead
 * computations.
 *
 * We'd like to use 64-bit loads if possible.  If they're not, emulating
 * one requires base+index+4 addressing which x86 has but most other
 * processors do not.  If CONFIG_64BIT, we definitely have 64-bit loads,
 * but it's possible to have 64-bit loads without 64-bit pointers (e.g.
 * x32 ABI).  Are there any cases the kernel needs to worry about?
 */
static void swap_words_64(void *a, void *b, size_t n)
{
	do {
#ifdef CONFIG_64BIT
		u64 t = *(u64 *)(a + (n -= 8));
		*(u64 *)(a + n) = *(u64 *)(b + n);
		*(u64 *)(b + n) = t;
#else
		/* Use two 32-bit transfers to avoid base+index+4 addressing */
		u32 t = *(u32 *)(a + (n -= 4));
		*(u32 *)(a + n) = *(u32 *)(b + n);
		*(u32 *)(b + n) = t;

		t = *(u32 *)(a + (n -= 4));
		*(u32 *)(a + n) = *(u32 *)(b + n);
		*(u32 *)(b + n) = t;
#endif
	} while (n);
}

/**
 * swap_bytes - swap two elements a byte at a time
 * @a: pointer to the first element to swap
 * @b: pointer to the second element to swap
 * @n: element size
 *
 * This is the fallback if alignment doesn't allow using larger chunks.
 */
static void swap_bytes(void *a, void *b, size_t n)
{
	do {
		char t = ((char *)a)[--n];
		((char *)a)[n] = ((char *)b)[n];
		((char *)b)[n] = t;
	} while (n);
}

/*
 * The values are arbitrary as long as they can't be confused with
 * a pointer, but small integers make for the smallest compare
 * instructions.
 */
#define SWAP_WORDS_64 (swap_r_func_t)0
#define SWAP_WORDS_32 (swap_r_func_t)1
#define SWAP_BYTES    (swap_r_func_t)2
#define SWAP_WRAPPER  (swap_r_func_t)3

struct wrapper {
	cmp_func_t cmp;
	swap_func_t swap;
};

/*
 * The function pointer is last to make tail calls most efficient if the
 * compiler decides not to inline this function.
 */
static void do_swap(void *a, void *b, size_t size, swap_r_func_t swap_func, const void *priv)
{
	if (swap_func == SWAP_WRAPPER) {
		((const struct wrapper *)priv)->swap(a, b, (int)size);
		return;
	}

	if (swap_func == SWAP_WORDS_64)
		swap_words_64(a, b, size);
	else if (swap_func == SWAP_WORDS_32)
		swap_words_32(a, b, size);
	else if (swap_func == SWAP_BYTES)
		swap_bytes(a, b, size);
	else
		swap_func(a, b, (int)size, priv);
}

#define _CMP_WRAPPER ((cmp_r_func_t)0L)

static int do_cmp(const void *a, const void *b, cmp_r_func_t cmp, const void *priv)
{
	if (cmp == _CMP_WRAPPER)
		return ((const struct wrapper *)priv)->cmp(a, b);
	return cmp(a, b, priv);
}

/**
 * parent - given the offset of the child, find the offset of the parent.
 * @i: the offset of the heap element whose parent is sought.  Non-zero.
 * @lsbit: a precomputed 1-bit mask, equal to "size & -size"
 * @size: size of each element
 *
 * In terms of array indexes, the parent of element j = @i/@size is simply
 * (j-1)/2.  But when working in byte offsets, we can't use implicit
 * truncation of integer divides.
 *
 * Fortunately, we only need one bit of the quotient, not the full divide.
 * @size has a least significant bit.  That bit will be clear if @i is
 * an even multiple of @size, and set if it's an odd multiple.
 *
 * Logically, we're doing "if (i & lsbit) i -= size;", but since the
 * branch is unpredictable, it's done with a bit of clever branch-free
 * code instead.
 */
__attribute_const__ __always_inline
static size_t parent(size_t i, unsigned int lsbit, size_t size)
{
	i -= size;
	i -= size & -(i & lsbit);
	return i / 2;
}

#include <linux/sched.h>

static void __sort_r(void *base, size_t num, size_t size,
		     cmp_r_func_t cmp_func,
		     swap_r_func_t swap_func,
		     const void *priv,
		     bool may_schedule)
{
	/* pre-scale counters for performance */
	size_t n = num * size, a = (num/2) * size;
	const unsigned int lsbit = size & -size;  /* Used to find parent */
	size_t shift = 0;

	if (!a)		/* num < 2 || size == 0 */
		return;

	/* called from 'sort' without swap function, let's pick the default */
	if (swap_func == SWAP_WRAPPER && !((struct wrapper *)priv)->swap)
		swap_func = NULL;

	if (!swap_func) {
		if (is_aligned(base, size, 8))
			swap_func = SWAP_WORDS_64;
		else if (is_aligned(base, size, 4))
			swap_func = SWAP_WORDS_32;
		else
			swap_func = SWAP_BYTES;
	}

	/*
	 * Loop invariants:
	 * 1. elements [a,n) satisfy the heap property (compare greater than
	 *    all of their children),
	 * 2. elements [n,num*size) are sorted, and
	 * 3. a <= b <= c <= d <= n (whenever they are valid).
	 */
	for (;;) {
		size_t b, c, d;

		if (a)			/* Building heap: sift down a */
			a -= size << shift;
		else if (n > 3 * size) { /* Sorting: Extract two largest elements */
			n -= size;
			do_swap(base, base + n, size, swap_func, priv);
			shift = do_cmp(base + size, base + 2 * size, cmp_func, priv) <= 0;
			a = size << shift;
			n -= size;
			do_swap(base + a, base + n, size, swap_func, priv);
		} else {		/* Sort complete */
			break;
		}

		/*
		 * Sift element at "a" down into heap.  This is the
		 * "bottom-up" variant, which significantly reduces
		 * calls to cmp_func(): we find the sift-down path all
		 * the way to the leaves (one compare per level), then
		 * backtrack to find where to insert the target element.
		 *
		 * Because elements tend to sift down close to the leaves,
		 * this uses fewer compares than doing two per level
		 * on the way down.  (A bit more than half as many on
		 * average, 3/4 worst-case.)
		 */
		for (b = a; c = 2*b + size, (d = c + size) < n;)
			b = do_cmp(base + c, base + d, cmp_func, priv) > 0 ? c : d;
		if (d == n)	/* Special case last leaf with no sibling */
			b = c;

		/* Now backtrack from "b" to the correct location for "a" */
		while (b != a && do_cmp(base + a, base + b, cmp_func, priv) >= 0)
			b = parent(b, lsbit, size);
		c = b;			/* Where "a" belongs */
		while (b != a) {	/* Shift it into place */
			b = parent(b, lsbit, size);
			do_swap(base + b, base + c, size, swap_func, priv);
		}

		if (may_schedule)
			cond_resched();
	}

	n -= size;
	do_swap(base, base + n, size, swap_func, priv);
	if (n == size * 2 && do_cmp(base, base + size, cmp_func, priv) > 0)
		do_swap(base, base + size, size, swap_func, priv);
}

/**
 * sort_r - sort an array of elements
 * @base: pointer to data to sort
 * @num: number of elements
 * @size: size of each element
 * @cmp_func: pointer to comparison function
 * @swap_func: pointer to swap function or NULL
 * @priv: third argument passed to comparison function
 *
 * This function does a heapsort on the given array.  You may provide
 * a swap_func function if you need to do something more than a memory
 * copy (e.g. fix up pointers or auxiliary data), but the built-in swap
 * avoids a slow retpoline and so is significantly faster.
 *
 * The comparison function must adhere to specific mathematical
 * properties to ensure correct and stable sorting:
 * - Antisymmetry: cmp_func(a, b) must return the opposite sign of
 * cmp_func(b, a).
 * - Transitivity: if cmp_func(a, b) <= 0 and cmp_func(b, c) <= 0, then
 * cmp_func(a, c) <= 0.
 *
 * Sorting time is O(n log n) both on average and worst-case. While
 * quicksort is slightly faster on average, it suffers from exploitable
 * O(n*n) worst-case behavior and extra memory requirements that make
 * it less suitable for kernel use.
 */
void sort_r(void *base, size_t num, size_t size,
	    cmp_r_func_t cmp_func,
	    swap_r_func_t swap_func,
	    const void *priv)
{
	__sort_r(base, num, size, cmp_func, swap_func, priv, false);
}
EXPORT_SYMBOL(sort_r);

/**
 * sort_r_nonatomic - sort an array of elements, with cond_resched
 * @base: pointer to data to sort
 * @num: number of elements
 * @size: size of each element
 * @cmp_func: pointer to comparison function
 * @swap_func: pointer to swap function or NULL
 * @priv: third argument passed to comparison function
 *
 * Same as sort_r, but preferred for larger arrays as it does a periodic
 * cond_resched().
 */
void sort_r_nonatomic(void *base, size_t num, size_t size,
		      cmp_r_func_t cmp_func,
		      swap_r_func_t swap_func,
		      const void *priv)
{
	__sort_r(base, num, size, cmp_func, swap_func, priv, true);
}
EXPORT_SYMBOL(sort_r_nonatomic);

void sort(void *base, size_t num, size_t size,
	  cmp_func_t cmp_func,
	  swap_func_t swap_func)
{
	struct wrapper w = {
		.cmp  = cmp_func,
		.swap = swap_func,
	};

	return __sort_r(base, num, size, _CMP_WRAPPER, SWAP_WRAPPER, &w, false);
}
EXPORT_SYMBOL(sort);

void sort_nonatomic(void *base, size_t num, size_t size,
		    cmp_func_t cmp_func,
		    swap_func_t swap_func)
{
	struct wrapper w = {
		.cmp  = cmp_func,
		.swap = swap_func,
	};

	return __sort_r(base, num, size, _CMP_WRAPPER, SWAP_WRAPPER, &w, true);
}
EXPORT_SYMBOL(sort_nonatomic);

#include <linux/eytzinger.h>

static inline int eytzinger1_do_cmp(void *base1, size_t n, size_t size,
			 cmp_r_func_t cmp_func, const void *priv,
			 size_t l, size_t r)
{
	return do_cmp(base1 + inorder_to_eytzinger1(l, n) * size,
		      base1 + inorder_to_eytzinger1(r, n) * size,
		      cmp_func, priv);
}

static inline void eytzinger1_do_swap(void *base1, size_t n, size_t size,
			   swap_r_func_t swap_func, const void *priv,
			   size_t l, size_t r)
{
	do_swap(base1 + inorder_to_eytzinger1(l, n) * size,
		base1 + inorder_to_eytzinger1(r, n) * size,
		size, swap_func, priv);
}

static void eytzinger1_sort_r(void *base1, size_t n, size_t size,
			      cmp_r_func_t cmp_func,
			      swap_r_func_t swap_func,
			      const void *priv)
{
	unsigned i, j, k;

	/* called from 'sort' without swap function, let's pick the default */
	if (swap_func == SWAP_WRAPPER && !((struct wrapper *)priv)->swap)
		swap_func = NULL;

	if (!swap_func) {
		if (is_aligned(base1, size, 8))
			swap_func = SWAP_WORDS_64;
		else if (is_aligned(base1, size, 4))
			swap_func = SWAP_WORDS_32;
		else
			swap_func = SWAP_BYTES;
	}

	/* heapify */
	for (i = n / 2; i >= 1; --i) {
		/* Find the sift-down path all the way to the leaves. */
		for (j = i; k = j * 2, k < n;)
			j = eytzinger1_do_cmp(base1, n, size, cmp_func, priv, k, k + 1) > 0 ? k : k + 1;

		/* Special case for the last leaf with no sibling. */
		if (j * 2 == n)
			j *= 2;

		/* Backtrack to the correct location. */
		while (j != i && eytzinger1_do_cmp(base1, n, size, cmp_func, priv, i, j) >= 0)
			j /= 2;

		/* Shift the element into its correct place. */
		for (k = j; j != i;) {
			j /= 2;
			eytzinger1_do_swap(base1, n, size, swap_func, priv, j, k);
		}
	}

	/* sort */
	for (i = n; i > 1; --i) {
		eytzinger1_do_swap(base1, n, size, swap_func, priv, 1, i);

		/* Find the sift-down path all the way to the leaves. */
		for (j = 1; k = j * 2, k + 1 < i;)
			j = eytzinger1_do_cmp(base1, n, size, cmp_func, priv, k, k + 1) > 0 ? k : k + 1;

		/* Special case for the last leaf with no sibling. */
		if (j * 2 + 1 == i)
			j *= 2;

		/* Backtrack to the correct location. */
		while (j >= 1 && eytzinger1_do_cmp(base1, n, size, cmp_func, priv, 1, j) >= 0)
			j /= 2;

		/* Shift the element into its correct place. */
		for (k = j; j > 1;) {
			j /= 2;
			eytzinger1_do_swap(base1, n, size, swap_func, priv, j, k);
		}
	}
}

void eytzinger0_sort_r(void *base, size_t n, size_t size,
		       cmp_r_func_t cmp_func,
		       swap_r_func_t swap_func,
		       const void *priv)
{
	void *base1 = base - size;

	return eytzinger1_sort_r(base1, n, size, cmp_func, swap_func, priv);
}
EXPORT_SYMBOL_GPL(eytzinger0_sort_r);

void eytzinger0_sort(void *base, size_t n, size_t size,
		     cmp_func_t cmp_func,
		     swap_func_t swap_func)
{
	struct wrapper w = {
		.cmp  = cmp_func,
		.swap = swap_func,
	};

	return eytzinger0_sort_r(base, n, size, _CMP_WRAPPER, SWAP_WRAPPER, &w);
}
EXPORT_SYMBOL_GPL(eytzinger0_sort);
