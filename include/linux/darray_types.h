/* SPDX-License-Identifier: GPL-2.0 */
/*
 * (C) 2022-2024 Kent Overstreet <kent.overstreet@linux.dev>
 */
#ifndef _LINUX_DARRAY_TYPES_H
#define _LINUX_DARRAY_TYPES_H

#include <linux/cleanup.h>
#include <linux/types.h>
#include <linux/slab.h>

#define DARRAY_PREALLOCATED(_type, _nr)					\
struct {								\
	size_t nr, size;						\
	_type *data;							\
	_type preallocated[_nr];					\
}

#define DARRAY(_type) DARRAY_PREALLOCATED(_type, 0)

#define darray_init(_d)							\
do {									\
	(_d)->nr = 0;							\
	(_d)->size = ARRAY_SIZE((_d)->preallocated);			\
	(_d)->data = (_d)->size ? (_d)->preallocated : NULL;		\
} while (0)

#define darray_exit(_d)							\
do {									\
	if (!ARRAY_SIZE((_d)->preallocated) ||				\
	    (_d)->data != (_d)->preallocated)				\
		kvfree((_d)->data);					\
	darray_init(_d);						\
} while (0)

#define darray_exit_free_item(_d, _free)				\
do {									\
	darray_for_each(*(_d), i)					\
		_free(*i);						\
	if (!ARRAY_SIZE((_d)->preallocated) ||				\
	    (_d)->data != (_d)->preallocated)				\
		kvfree((_d)->data);					\
	darray_init(_d);						\
} while (0)

#define __darray_for_each(_d, _i)					\
	for ((_i) = (_d).data; _i < (_d).data + (_d).nr; _i++)

#define darray_for_each_from(_d, _i, _start)					\
	for (typeof(&(_d).data[0]) _i = _start; _i < (_d).data + (_d).nr; _i++)

#define darray_for_each(_d, _i)						\
	darray_for_each_from(_d, _i, (_d).data)

#define DEFINE_DARRAY_CLASS(_type)					\
DEFINE_CLASS(_type, _type, darray_exit(&(_T)), (_type) {}, void)

#define DEFINE_DARRAY_CLASS_FREE_ITEM(_type, _free)		\
DEFINE_CLASS(_type, _type, darray_exit_free_item(&(_T), _free), (_type) {}, void)

#define DEFINE_DARRAY_NAMED(_name, _type)				\
typedef DARRAY(_type)	_name;						\
DEFINE_DARRAY_CLASS(_name)

#define DEFINE_DARRAY(_type)	DEFINE_DARRAY_NAMED(darray_##_type, _type)

#define DEFINE_DARRAY_PREALLOCATED(_type, _nr)				\
typedef DARRAY_PREALLOCATED(_type, _nr)	darray_##_type;			\
DEFINE_DARRAY_CLASS(darray_##_type)

#define DEFINE_DARRAY_NAMED_FREE_ITEM(_name, _type, _free)		\
typedef DARRAY(_type)	_name;						\
DEFINE_DARRAY_CLASS_FREE_ITEM(_name, _free)

DEFINE_DARRAY(char);
DEFINE_DARRAY(u8)
DEFINE_DARRAY(u16)
DEFINE_DARRAY(u32)
DEFINE_DARRAY(u64)

DEFINE_DARRAY(s8)
DEFINE_DARRAY(s16)
DEFINE_DARRAY(s32)
DEFINE_DARRAY(s64)

DEFINE_DARRAY_NAMED_FREE_ITEM(darray_str, char *, kfree);
DEFINE_DARRAY_NAMED_FREE_ITEM(darray_const_str, const char *, kfree);

#endif /* _LINUX_DARRAY_TYPES_H */
