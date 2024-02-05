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

#endif /* _LINUX_DARRAY_TYPES_H */
