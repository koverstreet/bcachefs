/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_DARRAY_H
#define _BCACHEFS_DARRAY_H

/*
 * Dynamic arrays:
 *
 * Inspired by CCAN's darray
 */

#include <linux/cleanup.h>
#include <linux/slab.h>

#define DARRAY_PREALLOCATED(_type, _nr)					\
struct {								\
	size_t nr, size;						\
	_type *data;							\
	_type preallocated[_nr];					\
}

#define DARRAY(_type) DARRAY_PREALLOCATED(_type, 0)

#define __darray_for_each(_d, _i)					\
	for ((_i) = (_d).data; _i < (_d).data + (_d).nr; _i++)

#define darray_for_each_from(_d, _i, _start)					\
	for (typeof(&(_d).data[0]) _i = _start; _i < (_d).data + (_d).nr; _i++)

#define darray_for_each(_d, _i)						\
	darray_for_each_from(_d, _i, (_d).data)

#define darray_for_each_max(_d, _i, _nr)					\
	for (typeof(&(_d).data[0]) _i = (_d).data; _i < (_d).data + min(_nr, (_d).nr); _i++)

#define darray_for_each_reverse(_d, _i)					\
	for (typeof(&(_d).data[0]) _i = (_d).data + (_d).nr - 1; _i >= (_d).data && (_d).nr; --_i)

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

int __bch2_darray_resize_noprof(darray_char *, size_t, size_t, gfp_t, bool);

#define __bch2_darray_resize(...)	alloc_hooks(__bch2_darray_resize_noprof(__VA_ARGS__))

#define __darray_resize(_d, _element_size, _new_size, _gfp, _rcu)	\
	(unlikely((_new_size) > (_d)->size)				\
	 ? __bch2_darray_resize((_d), (_element_size), (_new_size), (_gfp), _rcu)\
	 : 0)

#define darray_resize_gfp(_d, _new_size, _gfp)				\
	__darray_resize((darray_char *) (_d), sizeof((_d)->data[0]), (_new_size), _gfp, false)

#define darray_resize(_d, _new_size)					\
	darray_resize_gfp(_d, _new_size, GFP_KERNEL)

#define darray_make_room_gfp(_d, _more, _gfp)				\
	darray_resize_gfp((_d), (_d)->nr + (_more), _gfp)

#define darray_make_room(_d, _more)					\
	darray_make_room_gfp(_d, _more, GFP_KERNEL)

#define darray_resize_rcu(_d, _new_size)				\
	__darray_resize((darray_char *) (_d), sizeof((_d)->data[0]), (_new_size), GFP_KERNEL, true)

#define darray_make_room_rcu(_d, _more)				\
	darray_resize_rcu((_d), (_d)->nr + (_more))

#define darray_room(_d)		((_d).size - (_d).nr)

#define darray_top(_d)		((_d).data[(_d).nr])

#define darray_push_gfp(_d, _item, _gfp)				\
({									\
	int _ret = darray_make_room_gfp((_d), 1, _gfp);			\
									\
	if (!_ret)							\
		(_d)->data[(_d)->nr++] = (_item);			\
	_ret;								\
})

#define darray_push(_d, _item)	darray_push_gfp(_d, _item, GFP_KERNEL)

#define darray_pop(_d)		((_d)->data[--(_d)->nr])

#define darray_first(_d)	((_d).data[0])
#define darray_last(_d)		((_d).data[(_d).nr - 1])

#define darray_insert_item(_d, pos, _item)				\
({									\
	size_t _pos = (pos);						\
	int _ret = darray_make_room((_d), 1);				\
									\
	if (!_ret)							\
		array_insert_item((_d)->data, (_d)->nr, _pos, (_item));	\
	_ret;								\
})

#define darray_remove_item(_d, _pos)					\
	array_remove_item((_d)->data, (_d)->nr, (_pos) - (_d)->data)

#define darray_find_p(_d, _i, cond)					\
({									\
	typeof(&(_d).data[0]) _ret = NULL;				\
									\
	darray_for_each(_d, _i)						\
		if (cond) {						\
			_ret = _i;					\
			break;						\
		}							\
	_ret;								\
})

#define darray_find(_d, _item)	darray_find_p(_d, _i, *_i == _item)

#define darray_sort(_d, _cmp)						\
	sort_nonatomic((_d).data, (_d).nr, sizeof((_d).data[0]), _cmp, NULL)

#endif /* _BCACHEFS_DARRAY_H */
