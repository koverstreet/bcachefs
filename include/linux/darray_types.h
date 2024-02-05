/* SPDX-License-Identifier: GPL-2.0 */
/*
 * (C) 2022-2024 Kent Overstreet <kent.overstreet@linux.dev>
 */
#ifndef _LINUX_DARRAY_TYPES_H
#define _LINUX_DARRAY_TYPES_H

#include <linux/types.h>

#define DARRAY_PREALLOCATED(_type, _nr)					\
struct {								\
	size_t nr, size;						\
	_type *data;							\
	_type preallocated[_nr];					\
}

#define DARRAY(_type) DARRAY_PREALLOCATED(_type, 0)

typedef DARRAY(char)	darray_char;
typedef DARRAY(char *)	darray_str;
typedef DARRAY(const char *) darray_const_str;

typedef DARRAY(u8)	darray_u8;
typedef DARRAY(u16)	darray_u16;
typedef DARRAY(u32)	darray_u32;
typedef DARRAY(u64)	darray_u64;

typedef DARRAY(s8)	darray_s8;
typedef DARRAY(s16)	darray_s16;
typedef DARRAY(s32)	darray_s32;
typedef DARRAY(s64)	darray_s64;

#endif /* _LINUX_DARRAY_TYPES_H */
