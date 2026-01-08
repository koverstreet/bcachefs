// SPDX-License-Identifier: GPL-2.0
#include "min_heap.h"

void __bch2_min_heap_init(min_heap_char *heap, void *data, size_t size)
{
	__min_heap_init_inline(heap, data, size);
}

void *__bch2_min_heap_peek(struct min_heap_char *heap)
{
	return __min_heap_peek_inline(heap);
}

bool __bch2_min_heap_full(min_heap_char *heap)
{
	return __min_heap_full_inline(heap);
}

void __bch2_min_heap_sift_down(min_heap_char *heap, size_t pos, size_t elem_size,
			  const struct min_heap_callbacks *func, void *args)
{
	__min_heap_sift_down_inline(heap, pos, elem_size, func, args);
}

void __bch2_min_heap_sift_up(min_heap_char *heap, size_t elem_size, size_t idx,
			const struct min_heap_callbacks *func, void *args)
{
	__min_heap_sift_up_inline(heap, elem_size, idx, func, args);
}

void __bch2_min_heapify_all(min_heap_char *heap, size_t elem_size,
		       const struct min_heap_callbacks *func, void *args)
{
	__min_heapify_all_inline(heap, elem_size, func, args);
}

bool __bch2_min_heap_pop(min_heap_char *heap, size_t elem_size,
		    const struct min_heap_callbacks *func, void *args)
{
	return __min_heap_pop_inline(heap, elem_size, func, args);
}

void __bch2_min_heap_pop_push(min_heap_char *heap, const void *element, size_t elem_size,
			 const struct min_heap_callbacks *func, void *args)
{
	__min_heap_pop_push_inline(heap, element, elem_size, func, args);
}

bool __bch2_min_heap_push(min_heap_char *heap, const void *element, size_t elem_size,
		     const struct min_heap_callbacks *func, void *args)
{
	return __min_heap_push_inline(heap, element, elem_size, func, args);
}

bool __bch2_min_heap_del(min_heap_char *heap, size_t elem_size, size_t idx,
		    const struct min_heap_callbacks *func, void *args)
{
	return __min_heap_del_inline(heap, elem_size, idx, func, args);
}
