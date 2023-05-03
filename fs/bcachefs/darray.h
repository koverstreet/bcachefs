/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_DARRAY_H
#define _BCACHEFS_DARRAY_H

/*
 * Dynamic arrays:
 *
 * Inspired by CCAN's darray
 */

#include "util.h"
#include <linux/slab.h>

#define DARRAY(type)							\
struct {								\
	size_t nr, size;						\
	type *data;							\
}

typedef DARRAY(void) darray_void;

static inline int __darray_make_room(darray_void *d, size_t t_size, size_t more)
{
	if (d->nr + more > d->size) {
		size_t new_size = roundup_pow_of_two(d->nr + more);
		void *data = krealloc_array(d->data, new_size, t_size, GFP_KERNEL);

		if (!data)
			return -ENOMEM;

		d->data	= data;
		d->size = new_size;
	}

	return 0;
}

#define darray_make_room(_d, _more)					\
	__darray_make_room((darray_void *) (_d), sizeof((_d)->data[0]), (_more))

#define darray_top(_d)		((_d).data[(_d).nr])

#define darray_push(_d, _item)						\
({									\
	int _ret = darray_make_room((_d), 1);				\
									\
	if (!_ret)							\
		(_d)->data[(_d)->nr++] = (_item);			\
	_ret;								\
})

#define darray_insert_item(_d, _pos, _item)				\
({									\
	size_t pos = (_pos);						\
	int _ret = darray_make_room((_d), 1);				\
									\
	if (!_ret)							\
		array_insert_item((_d)->data, (_d)->nr, pos, (_item));	\
	_ret;								\
})

#define darray_for_each(_d, _i)						\
	for (_i = (_d).data; _i < (_d).data + (_d).nr; _i++)

#define darray_init(_d)							\
do {									\
	(_d)->data = NULL;						\
	(_d)->nr = (_d)->size = 0;					\
} while (0)

#define darray_exit(_d)							\
do {									\
	kfree((_d)->data);						\
	darray_init(_d);						\
} while (0)

#endif /* _BCACHEFS_DARRAY_H */
