#ifndef _BCACHEFS_EXTENTS_H
#define _BCACHEFS_EXTENTS_H

#include "bcachefs.h"
#include "bkey.h"
#include "io_types.h"

struct bch_fs;
struct journal_res;
struct btree_node_iter;
struct btree_insert;
struct btree_insert_entry;
struct extent_insert_hook;
struct bch_devs_mask;
union bch_extent_crc;

struct btree_nr_keys bch2_key_sort_fix_overlapping(struct bset *,
						  struct btree *,
						  struct btree_node_iter *);
struct btree_nr_keys bch2_extent_sort_fix_overlapping(struct bch_fs *c,
						     struct bset *,
						     struct btree *,
						     struct btree_node_iter *);

extern const struct bkey_ops bch2_bkey_btree_ops;
extern const struct bkey_ops bch2_bkey_extent_ops;

void bch2_get_read_device(struct bch_fs *,
			  const struct bkey *,
			  const struct bch_extent_ptr *,
			  const union bch_extent_crc *,
			  struct bch_devs_mask *,
			  struct extent_pick_ptr *);
struct extent_pick_ptr
bch2_btree_pick_ptr(struct bch_fs *, const struct btree *);

void bch2_extent_pick_ptr(struct bch_fs *, struct bkey_s_c,
			  struct bch_devs_mask *,
			  struct extent_pick_ptr *);

enum btree_insert_ret
bch2_insert_fixup_extent(struct btree_insert *,
			struct btree_insert_entry *);

bool bch2_extent_normalize(struct bch_fs *, struct bkey_s);
void bch2_extent_mark_replicas_cached(struct bch_fs *,
				     struct bkey_s_extent, unsigned);

unsigned bch2_extent_nr_ptrs(struct bkey_s_c_extent);
unsigned bch2_extent_nr_dirty_ptrs(struct bkey_s_c);

static inline bool bkey_extent_is_data(const struct bkey *k)
{
	switch (k->type) {
	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
		return true;
	default:
		return false;
	}
}

static inline bool bkey_extent_is_allocation(const struct bkey *k)
{
	switch (k->type) {
	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
	case BCH_RESERVATION:
		return true;
	default:
		return false;
	}
}

static inline bool bkey_extent_is_cached(const struct bkey *k)
{
	return k->type == BCH_EXTENT_CACHED;
}

static inline void bkey_extent_set_cached(struct bkey *k, bool cached)
{
	EBUG_ON(k->type != BCH_EXTENT &&
		k->type != BCH_EXTENT_CACHED);

	k->type = cached ? BCH_EXTENT_CACHED : BCH_EXTENT;
}

static inline unsigned
__extent_entry_type(const union bch_extent_entry *e)
{
	return e->type ? __ffs(e->type) : BCH_EXTENT_ENTRY_MAX;
}

static inline enum bch_extent_entry_type
extent_entry_type(const union bch_extent_entry *e)
{
	int ret = __ffs(e->type);

	EBUG_ON(ret < 0 || ret >= BCH_EXTENT_ENTRY_MAX);

	return ret;
}

static inline size_t extent_entry_bytes(const union bch_extent_entry *entry)
{
	switch (extent_entry_type(entry)) {
	case BCH_EXTENT_ENTRY_crc32:
		return sizeof(struct bch_extent_crc32);
	case BCH_EXTENT_ENTRY_crc64:
		return sizeof(struct bch_extent_crc64);
	case BCH_EXTENT_ENTRY_crc128:
		return sizeof(struct bch_extent_crc128);
	case BCH_EXTENT_ENTRY_ptr:
		return sizeof(struct bch_extent_ptr);
	default:
		BUG();
	}
}

static inline size_t extent_entry_u64s(const union bch_extent_entry *entry)
{
	return extent_entry_bytes(entry) / sizeof(u64);
}

static inline bool extent_entry_is_ptr(const union bch_extent_entry *e)
{
	return extent_entry_type(e) == BCH_EXTENT_ENTRY_ptr;
}

static inline bool extent_entry_is_crc(const union bch_extent_entry *e)
{
	return !extent_entry_is_ptr(e);
}

union bch_extent_crc {
	u8				type;
	struct bch_extent_crc32		crc32;
	struct bch_extent_crc64		crc64;
	struct bch_extent_crc128	crc128;
};

/* downcast, preserves const */
#define to_entry(_entry)						\
({									\
	BUILD_BUG_ON(!type_is(_entry, union bch_extent_crc *) &&	\
		     !type_is(_entry, struct bch_extent_ptr *));	\
									\
	__builtin_choose_expr(						\
		(type_is_exact(_entry, const union bch_extent_crc *) ||	\
		 type_is_exact(_entry, const struct bch_extent_ptr *)),	\
		(const union bch_extent_entry *) (_entry),		\
		(union bch_extent_entry *) (_entry));			\
})

#define __entry_to_crc(_entry)						\
	__builtin_choose_expr(						\
		type_is_exact(_entry, const union bch_extent_entry *),	\
		(const union bch_extent_crc *) (_entry),		\
		(union bch_extent_crc *) (_entry))

#define entry_to_crc(_entry)						\
({									\
	EBUG_ON((_entry) && !extent_entry_is_crc(_entry));		\
									\
	__entry_to_crc(_entry);						\
})

#define entry_to_ptr(_entry)						\
({									\
	EBUG_ON((_entry) && !extent_entry_is_ptr(_entry));		\
									\
	__builtin_choose_expr(						\
		type_is_exact(_entry, const union bch_extent_entry *),	\
		(const struct bch_extent_ptr *) (_entry),		\
		(struct bch_extent_ptr *) (_entry));			\
})

enum bch_extent_crc_type {
	BCH_EXTENT_CRC_NONE,
	BCH_EXTENT_CRC32,
	BCH_EXTENT_CRC64,
	BCH_EXTENT_CRC128,
};

static inline enum bch_extent_crc_type
__extent_crc_type(const union bch_extent_crc *crc)
{
	if (!crc)
		return BCH_EXTENT_CRC_NONE;

	switch (extent_entry_type(to_entry(crc))) {
	case BCH_EXTENT_ENTRY_crc32:
		return BCH_EXTENT_CRC32;
	case BCH_EXTENT_ENTRY_crc64:
		return BCH_EXTENT_CRC64;
	case BCH_EXTENT_ENTRY_crc128:
		return BCH_EXTENT_CRC128;
	default:
		BUG();
	}
}

#define extent_crc_type(_crc)						\
({									\
	BUILD_BUG_ON(!type_is(_crc, struct bch_extent_crc32 *) &&	\
		     !type_is(_crc, struct bch_extent_crc64 *) &&	\
		     !type_is(_crc, struct bch_extent_crc128 *) &&	\
		     !type_is(_crc, union bch_extent_crc *));		\
									\
	  type_is(_crc, struct bch_extent_crc32 *)  ? BCH_EXTENT_CRC32	\
	: type_is(_crc, struct bch_extent_crc64 *)  ? BCH_EXTENT_CRC64	\
	: type_is(_crc, struct bch_extent_crc128 *) ? BCH_EXTENT_CRC128	\
	: __extent_crc_type((union bch_extent_crc *) _crc);		\
})

#define extent_entry_next(_entry)					\
	((typeof(_entry)) ((void *) (_entry) + extent_entry_bytes(_entry)))

#define extent_entry_last(_e)						\
	vstruct_idx((_e).v, bkey_val_u64s((_e).k))

/* Iterate over all entries: */

#define extent_for_each_entry_from(_e, _entry, _start)			\
	for ((_entry) = _start;						\
	     (_entry) < extent_entry_last(_e);				\
	     (_entry) = extent_entry_next(_entry))

#define extent_for_each_entry(_e, _entry)				\
	extent_for_each_entry_from(_e, _entry, (_e).v->start)

/* Iterate over crcs only: */

#define extent_crc_next(_e, _p)						\
({									\
	typeof(&(_e).v->start[0]) _entry = _p;				\
									\
	while ((_entry) < extent_entry_last(_e) &&			\
	       !extent_entry_is_crc(_entry))				\
		(_entry) = extent_entry_next(_entry);			\
									\
	entry_to_crc(_entry < extent_entry_last(_e) ? _entry : NULL);	\
})

#define extent_for_each_crc(_e, _crc)					\
	for ((_crc) = extent_crc_next(_e, (_e).v->start);		\
	     (_crc);							\
	     (_crc) = extent_crc_next(_e, extent_entry_next(to_entry(_crc))))

/* Iterate over pointers, with crcs: */

#define extent_ptr_crc_next_filter(_e, _crc, _ptr, _filter)		\
({									\
	__label__ out;							\
	typeof(&(_e).v->start[0]) _entry;				\
									\
	extent_for_each_entry_from(_e, _entry, to_entry(_ptr))		\
		if (extent_entry_is_crc(_entry)) {			\
			(_crc) = entry_to_crc(_entry);			\
		} else {						\
			_ptr = entry_to_ptr(_entry);			\
			if (_filter)					\
				goto out;				\
		}							\
									\
	_ptr = NULL;							\
out:									\
	_ptr;								\
})

#define extent_for_each_ptr_crc_filter(_e, _ptr, _crc, _filter)		\
	for ((_crc) = NULL,						\
	     (_ptr) = &(_e).v->start->ptr;				\
	     ((_ptr) = extent_ptr_crc_next_filter(_e, _crc, _ptr, _filter));\
	     (_ptr)++)

#define extent_for_each_ptr_crc(_e, _ptr, _crc)				\
	extent_for_each_ptr_crc_filter(_e, _ptr, _crc, true)

/* Iterate over pointers only, and from a given position: */

#define extent_ptr_next_filter(_e, _ptr, _filter)			\
({									\
	typeof(__entry_to_crc(&(_e).v->start[0])) _crc;			\
									\
	extent_ptr_crc_next_filter(_e, _crc, _ptr, _filter);		\
})

#define extent_ptr_next(_e, _ptr)					\
	extent_ptr_next_filter(_e, _ptr, true)

#define extent_for_each_ptr_filter(_e, _ptr, _filter)			\
	for ((_ptr) = &(_e).v->start->ptr;				\
	     ((_ptr) = extent_ptr_next_filter(_e, _ptr, _filter));	\
	     (_ptr)++)

#define extent_for_each_ptr(_e, _ptr)					\
	extent_for_each_ptr_filter(_e, _ptr, true)

#define extent_ptr_prev(_e, _ptr)					\
({									\
	typeof(&(_e).v->start->ptr) _p;					\
	typeof(&(_e).v->start->ptr) _prev = NULL;			\
									\
	extent_for_each_ptr(_e, _p) {					\
		if (_p == (_ptr))					\
			break;						\
		_prev = _p;						\
	}								\
									\
	_prev;								\
})

/*
 * Use this when you'll be dropping pointers as you iterate. Quadratic,
 * unfortunately:
 */
#define extent_for_each_ptr_backwards(_e, _ptr)				\
	for ((_ptr) = extent_ptr_prev(_e, NULL);			\
	     (_ptr);							\
	     (_ptr) = extent_ptr_prev(_e, _ptr))

void bch2_extent_crc_append(struct bkey_i_extent *, unsigned, unsigned,
			   unsigned, unsigned, struct bch_csum, unsigned);

static inline void __extent_entry_push(struct bkey_i_extent *e)
{
	union bch_extent_entry *entry = extent_entry_last(extent_i_to_s(e));

	EBUG_ON(bkey_val_u64s(&e->k) + extent_entry_u64s(entry) >
		BKEY_EXTENT_VAL_U64s_MAX);

	e->k.u64s += extent_entry_u64s(entry);
}

static inline void extent_ptr_append(struct bkey_i_extent *e,
				     struct bch_extent_ptr ptr)
{
	ptr.type = 1 << BCH_EXTENT_ENTRY_ptr;
	extent_entry_last(extent_i_to_s(e))->ptr = ptr;
	__extent_entry_push(e);
}

static inline struct bch_extent_crc128 crc_to_128(const struct bkey *k,
						  const union bch_extent_crc *crc)
{
	EBUG_ON(!k->size);

	switch (extent_crc_type(crc)) {
	case BCH_EXTENT_CRC_NONE:
		return (struct bch_extent_crc128) {
			._compressed_size	= k->size - 1,
			._uncompressed_size	= k->size - 1,
		};
	case BCH_EXTENT_CRC32:
		return (struct bch_extent_crc128) {
			.type			= 1 << BCH_EXTENT_ENTRY_crc128,
			._compressed_size	= crc->crc32._compressed_size,
			._uncompressed_size	= crc->crc32._uncompressed_size,
			.offset			= crc->crc32.offset,
			.csum_type		= crc->crc32.csum_type,
			.compression_type	= crc->crc32.compression_type,
			.csum.lo		= crc->crc32.csum,
		};
	case BCH_EXTENT_CRC64:
		return (struct bch_extent_crc128) {
			.type			= 1 << BCH_EXTENT_ENTRY_crc128,
			._compressed_size	= crc->crc64._compressed_size,
			._uncompressed_size	= crc->crc64._uncompressed_size,
			.offset			= crc->crc64.offset,
			.nonce			= crc->crc64.nonce,
			.csum_type		= crc->crc64.csum_type,
			.compression_type	= crc->crc64.compression_type,
			.csum.lo		= crc->crc64.csum_lo,
			.csum.hi		= crc->crc64.csum_hi,
		};
	case BCH_EXTENT_CRC128:
		return crc->crc128;
	default:
		BUG();
	}
}

#define crc_compressed_size(_k, _crc)					\
({									\
	unsigned _size = 0;						\
									\
	switch (extent_crc_type(_crc)) {				\
	case BCH_EXTENT_CRC_NONE:					\
		_size = ((const struct bkey *) (_k))->size;		\
		break;							\
	case BCH_EXTENT_CRC32:						\
		_size = ((struct bch_extent_crc32 *) _crc)		\
			->_compressed_size + 1;				\
		break;							\
	case BCH_EXTENT_CRC64:						\
		_size = ((struct bch_extent_crc64 *) _crc)		\
			->_compressed_size + 1;				\
		break;							\
	case BCH_EXTENT_CRC128:						\
		_size = ((struct bch_extent_crc128 *) _crc)		\
			->_compressed_size + 1;				\
		break;							\
	}								\
	_size;								\
})

#define crc_uncompressed_size(_k, _crc)					\
({									\
	unsigned _size = 0;						\
									\
	switch (extent_crc_type(_crc)) {				\
	case BCH_EXTENT_CRC_NONE:					\
		_size = ((const struct bkey *) (_k))->size;		\
		break;							\
	case BCH_EXTENT_CRC32:						\
		_size = ((struct bch_extent_crc32 *) _crc)		\
			->_uncompressed_size + 1;			\
		break;							\
	case BCH_EXTENT_CRC64:						\
		_size = ((struct bch_extent_crc64 *) _crc)		\
			->_uncompressed_size + 1;			\
		break;							\
	case BCH_EXTENT_CRC128:						\
		_size = ((struct bch_extent_crc128 *) _crc)		\
			->_uncompressed_size + 1;			\
		break;							\
	}								\
	_size;								\
})

static inline unsigned crc_offset(const union bch_extent_crc *crc)
{
	switch (extent_crc_type(crc)) {
	case BCH_EXTENT_CRC_NONE:
		return 0;
	case BCH_EXTENT_CRC32:
		return crc->crc32.offset;
	case BCH_EXTENT_CRC64:
		return crc->crc64.offset;
	case BCH_EXTENT_CRC128:
		return crc->crc128.offset;
	default:
		BUG();
	}
}

static inline unsigned crc_nonce(const union bch_extent_crc *crc)
{
	switch (extent_crc_type(crc)) {
	case BCH_EXTENT_CRC_NONE:
	case BCH_EXTENT_CRC32:
		return 0;
	case BCH_EXTENT_CRC64:
		return crc->crc64.nonce;
	case BCH_EXTENT_CRC128:
		return crc->crc128.nonce;
	default:
		BUG();
	}
}

static inline unsigned crc_csum_type(const union bch_extent_crc *crc)
{
	switch (extent_crc_type(crc)) {
	case BCH_EXTENT_CRC_NONE:
		return 0;
	case BCH_EXTENT_CRC32:
		return crc->crc32.csum_type;
	case BCH_EXTENT_CRC64:
		return crc->crc64.csum_type;
	case BCH_EXTENT_CRC128:
		return crc->crc128.csum_type;
	default:
		BUG();
	}
}

static inline unsigned crc_compression_type(const union bch_extent_crc *crc)
{
	switch (extent_crc_type(crc)) {
	case BCH_EXTENT_CRC_NONE:
		return 0;
	case BCH_EXTENT_CRC32:
		return crc->crc32.compression_type;
	case BCH_EXTENT_CRC64:
		return crc->crc64.compression_type;
	case BCH_EXTENT_CRC128:
		return crc->crc128.compression_type;
	default:
		BUG();
	}
}

static inline struct bch_csum crc_csum(const union bch_extent_crc *crc)
{
	switch (extent_crc_type(crc)) {
	case BCH_EXTENT_CRC_NONE:
		return (struct bch_csum) { 0 };
	case BCH_EXTENT_CRC32:
		return (struct bch_csum) { .lo = crc->crc32.csum };
	case BCH_EXTENT_CRC64:
		return (struct bch_csum) {
			.lo = crc->crc64.csum_lo,
			.hi = crc->crc64.csum_hi,
		};
	case BCH_EXTENT_CRC128:
		return crc->crc128.csum;
	default:
		BUG();
	}
}

static inline unsigned bkey_extent_is_compressed(struct bkey_s_c k)
{
	struct bkey_s_c_extent e;
	const struct bch_extent_ptr *ptr;
	const union bch_extent_crc *crc;
	unsigned ret = 0;

	switch (k.k->type) {
	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
		e = bkey_s_c_to_extent(k);

		extent_for_each_ptr_crc(e, ptr, crc)
			if (!ptr->cached &&
			    crc_compression_type(crc) != BCH_COMPRESSION_NONE &&
			    crc_compressed_size(e.k, crc) < k.k->size)
				ret = max_t(unsigned, ret,
					    crc_compressed_size(e.k, crc));
	}

	return ret;
}

static inline unsigned extent_current_nonce(struct bkey_s_c_extent e)
{
	const union bch_extent_crc *crc;

	extent_for_each_crc(e, crc)
		if (bch2_csum_type_is_encryption(crc_csum_type(crc)))
			return crc_offset(crc) + crc_nonce(crc);

	return 0;
}

void bch2_extent_narrow_crcs(struct bkey_s_extent);
void bch2_extent_drop_redundant_crcs(struct bkey_s_extent);

void __bch2_extent_drop_ptr(struct bkey_s_extent, struct bch_extent_ptr *);
void bch2_extent_drop_ptr(struct bkey_s_extent, struct bch_extent_ptr *);
void bch2_extent_drop_ptr_idx(struct bkey_s_extent, unsigned);

const struct bch_extent_ptr *
bch2_extent_has_device(struct bkey_s_c_extent, unsigned);
struct bch_extent_ptr *
bch2_extent_find_ptr(struct bch_fs *, struct bkey_s_extent,
		     struct bch_extent_ptr);
struct bch_extent_ptr *
bch2_extent_find_matching_ptr(struct bch_fs *, struct bkey_s_extent,
			      struct bkey_s_c_extent);

bool bch2_cut_front(struct bpos, struct bkey_i *);
bool bch2_cut_back(struct bpos, struct bkey *);
void bch2_key_resize(struct bkey *, unsigned);

#endif /* _BCACHEFS_EXTENTS_H */
