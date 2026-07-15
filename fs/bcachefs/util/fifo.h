/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_FIFO_H
#define _BCACHEFS_FIFO_H

#include "util.h"

#define __FIFO(type, index_type)					\
struct {								\
	index_type front, back, size, mask;				\
	type *data;							\
}

#define FIFO(type)			__FIFO(type, size_t)
#define FIFO_U16_IDX(type)		__FIFO(type, u16)
#define FIFO_U32_IDX(type)		__FIFO(type, u32)
#define FIFO_U64_IDX(type)		__FIFO(type, u64)

#define DECLARE_FIFO(type, name)		FIFO(type) name
#define DECLARE_FIFO_U16_IDX(type, name)	FIFO_U16_IDX(type) name
#define DECLARE_FIFO_U32_IDX(type, name)	FIFO_U32_IDX(type) name
#define DECLARE_FIFO_U64_IDX(type, name)	FIFO_U64_IDX(type) name

#define fifo_buf_size(fifo)						\
	((fifo)->size							\
	 ? roundup_pow_of_two((fifo)->size) * sizeof((fifo)->data[0])	\
	 : 0)

#define init_fifo(fifo, _size, _gfp)					\
({									\
	(fifo)->front	= (fifo)->back = 0;				\
	(fifo)->size	= (_size);					\
	(fifo)->mask	= (fifo)->size					\
		? roundup_pow_of_two((fifo)->size) - 1			\
		: 0;							\
	(fifo)->data	= kvmalloc(fifo_buf_size(fifo), (_gfp));	\
})

#define free_fifo(fifo)							\
do {									\
	kvfree((fifo)->data);						\
	(fifo)->data = NULL;						\
} while (0)

#define fifo_swap(l, r)							\
do {									\
	swap((l)->front, (r)->front);					\
	swap((l)->back, (r)->back);					\
	swap((l)->size, (r)->size);					\
	swap((l)->mask, (r)->mask);					\
	swap((l)->data, (r)->data);					\
} while (0)

#define fifo_move(dest, src)						\
do {									\
	typeof(*((dest)->data)) _t;					\
	while (!fifo_full(dest) &&					\
	       fifo_pop(src, _t))					\
		fifo_push(dest, _t);					\
} while (0)

#define __fifo_grow(fifo, _new_data, _new_size)			\
({								\
	size_t _old_size = fifo_buf_size(fifo);			\
	typeof((fifo)->data) _old_data = (fifo)->data;		\
								\
	memcpy(_new_data,					\
	       _old_data, _old_size);				\
	memcpy(_new_data + (fifo)->mask + 1,			\
	       _old_data, _old_size);				\
	(fifo)->size	= _new_size;				\
	(fifo)->mask	= roundup_pow_of_two(_new_size) - 1;	\
})

/*
 * Double the size of a fifo, preserving front and back indices.
 *
 * The new mask gains one bit. For any absolute index i, i & new_mask is either
 * (i & old_mask) or (i & old_mask) + old_buf_elems, depending on that bit in i.
 * So copying the old buffer into both halves of the new buffer puts every
 * element at the correct position for the new mask.
 */
#define fifo_grow(fifo, _gfp)						\
({									\
	size_t _osize = fifo_buf_size(fifo);				\
	size_t _new_size = (fifo)->size * 2;				\
	typeof((fifo)->data) _new_data =				\
		kvmalloc(_osize * 2, (_gfp));				\
	if (_new_data) {						\
		__fifo_grow(fifo, _new_data, _new_size);		\
		kvfree((fifo)->data);					\
		(fifo)->data = _new_data;				\
	}								\
	_new_data != NULL;						\
})

#define fifo_used(fifo)		((typeof((fifo)->front)) ((fifo)->back - (fifo)->front))
#define fifo_free(fifo)		((fifo)->size - fifo_used(fifo))

#define fifo_empty(fifo)	((fifo)->front == (fifo)->back)
#define fifo_full(fifo)		(fifo_used(fifo) == (fifo)->size)

#define fifo_entry(fifo, idx)	((fifo)->data[(idx) & (fifo)->mask])

#define fifo_peek_front(fifo)	fifo_entry((fifo), (fifo)->front)
#define fifo_peek_back(fifo)	fifo_entry((fifo), (fifo)->back - 1)

#define fifo_entry_idx_abs(fifo, p)					\
	((((p) >= &fifo_peek_front(fifo)				\
	   ? (fifo)->front : (fifo)->back) & ~(fifo)->mask) +		\
	   (((p) - (fifo)->data)))

#define fifo_entry_idx(fifo, p)	(((p) - &fifo_peek_front(fifo)) & (fifo)->mask)
#define fifo_idx_entry(fifo, i)	((fifo)->data[((fifo)->front + (i)) & (fifo)->mask])

#define fifo_push_back_ref(f)						\
	(fifo_full((f)) ? NULL : &(f)->data[(f)->back++ & (f)->mask])

#define fifo_push_front_ref(f)						\
	(fifo_full((f)) ? NULL : &(f)->data[--(f)->front & (f)->mask])

#define fifo_push_back(fifo, new)					\
({									\
	typeof(&(fifo)->data[0]) _r = fifo_push_back_ref(fifo);		\
	if (_r)								\
		*_r = (new);						\
	_r != NULL;							\
})

#define fifo_push_front(fifo, new)					\
({									\
	typeof(&(fifo)->data[0]) _r = fifo_push_front_ref(fifo);	\
	if (_r)								\
		*_r = (new);						\
	_r != NULL;							\
})

#define fifo_pop_front(fifo, i)						\
({									\
	bool _r = !fifo_empty((fifo));					\
	if (_r)								\
		(i) = (fifo)->data[(fifo)->front++ & (fifo)->mask];	\
	_r;								\
})

#define fifo_pop_back(fifo, i)						\
({									\
	bool _r = !fifo_empty((fifo));					\
	if (_r)								\
		(i) = (fifo)->data[--(fifo)->back & (fifo)->mask];	\
	_r;								\
})

#define fifo_push_ref(fifo)	fifo_push_back_ref(fifo)
#define fifo_push(fifo, i)	fifo_push_back(fifo, (i))
#define fifo_pop(fifo, i)	fifo_pop_front(fifo, (i))
#define fifo_peek(fifo)		fifo_peek_front(fifo)

#define fifo_for_each_entry_from(_entry, _fifo, _iter)			\
	for (typecheck(typeof((_fifo)->front), _iter);			\
	     ((_iter != (_fifo)->back) &&				\
	      (_entry = fifo_entry(_fifo, _iter), true));		\
	     (_iter)++)

#define fifo_for_each_entry(_entry, _fifo, _iter)			\
	for (typecheck(typeof((_fifo)->front), _iter),			\
	     (_iter) = (_fifo)->front;					\
	     ((_iter != (_fifo)->back) &&				\
	      (_entry = fifo_entry(_fifo, _iter), true));		\
	     (_iter)++)

#define fifo_for_each_entry_ptr(_ptr, _fifo, _iter)			\
	for (typecheck(typeof((_fifo)->front), _iter),			\
	     (_iter) = (_fifo)->front;					\
	     ((_iter != (_fifo)->back) &&				\
	      (_ptr = &fifo_entry(_fifo, _iter), true));		\
	     (_iter)++)

#define fifo_for_each_entry_ptr_reverse(_ptr, _fifo, _iter)		\
	for (typecheck(typeof((_fifo)->front), _iter),			\
	     (_iter) = (_fifo)->back;					\
	     ((_iter != (_fifo)->front) &&				\
	      (_ptr = &fifo_entry(_fifo, _iter - 1), true));		\
	     (_iter)--)

#endif /* _BCACHEFS_FIFO_H */
