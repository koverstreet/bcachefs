#ifndef _BCACHE_EXTENTS_H
#define _BCACHE_EXTENTS_H

#include "bkey.h"

struct bch_replace_info;
union bch_extent_crc;
struct btree_iter;
struct btree_insert;
struct btree_insert_entry;

struct btree_nr_keys bch_key_sort_fix_overlapping(struct bset *,
						  struct btree_keys *,
						  struct btree_node_iter *);
struct btree_nr_keys bch_extent_sort_fix_overlapping(struct cache_set *c,
						     struct bset *,
						     struct btree_keys *,
						     struct btree_node_iter *);

enum btree_insert_ret
bch_insert_fixup_key(struct btree_insert *,
		     struct btree_insert_entry *,
		     struct journal_res *);

extern const struct bkey_ops bch_bkey_btree_ops;
extern const struct bkey_ops bch_bkey_extent_ops;

struct cache_set;
struct journal_res;

struct extent_pick_ptr {
	struct bch_extent_crc64		crc;
	struct bch_extent_ptr		ptr;
	struct cache			*ca;
};

struct extent_pick_ptr
bch_btree_pick_ptr(struct cache_set *, const struct btree *);

void bch_extent_pick_ptr_avoiding(struct cache_set *, struct bkey_s_c,
				  struct cache *, struct extent_pick_ptr *);

static inline void
bch_extent_pick_ptr(struct cache_set *c, struct bkey_s_c k,
		    struct extent_pick_ptr *ret)
{
	bch_extent_pick_ptr_avoiding(c, k, NULL, ret);
}

enum extent_insert_hook_ret
bch_extent_cmpxchg(struct extent_insert_hook *, struct bpos, struct bpos,
		   struct bkey_s_c, const struct bkey_i *);

enum btree_insert_ret
bch_insert_fixup_extent(struct btree_insert *,
			struct btree_insert_entry *,
			struct journal_res *);

bool bch_extent_normalize(struct cache_set *, struct bkey_s);

unsigned bch_extent_nr_ptrs_from(struct bkey_s_c_extent,
				 const struct bch_extent_ptr *);
unsigned bch_extent_nr_ptrs(struct bkey_s_c_extent);

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

static inline enum bch_extent_entry_type
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
};

static inline enum bch_extent_crc_type
extent_crc_type(const union bch_extent_crc *crc)
{
	if (!crc)
		return BCH_EXTENT_CRC_NONE;

	switch (extent_entry_type(to_entry(crc))) {
	case BCH_EXTENT_ENTRY_crc32:
		return BCH_EXTENT_CRC32;
	case BCH_EXTENT_ENTRY_crc64:
		return BCH_EXTENT_CRC64;
	default:
		BUG();
	}
}

#define extent_entry_next(_entry)					\
	((typeof(_entry)) ((void *) (_entry) + extent_entry_bytes(_entry)))

#define extent_entry_last(_e)						\
	bkey_idx((_e).v, bkey_val_u64s((_e).k))

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

#define extent_for_each_online_device_crc(_c, _e, _crc, _ptr, _ca)	\
	extent_for_each_ptr_crc_filter(_e, _ptr, _crc,			\
				       ((_ca) = PTR_CACHE(_c, _ptr)))

/* Iterate over pointers only, and from a given position: */

#define extent_ptr_next_filter(_e, _ptr, _filter)			\
({									\
	typeof(__entry_to_crc(&(_e).v->start[0])) _crc;			\
									\
	extent_ptr_crc_next_filter(_e, _crc, _ptr, _filter);		\
})

#define extent_ptr_next(_e, _ptr)					\
	extent_ptr_next_filter(_e, _ptr, true)

#define extent_for_each_ptr_from_filter(_e, _ptr, _start, _filter)	\
	for ((_ptr) = (_start);				\
	     ((_ptr) = extent_ptr_next_filter(_e, _ptr, _filter));	\
	     (_ptr)++)

#define extent_for_each_ptr_from(_e, _ptr, _start)			\
	extent_for_each_ptr_from_filter(_e, _ptr, _start, true)

#define extent_for_each_ptr(_e, _ptr)					\
	extent_for_each_ptr_from_filter(_e, _ptr, &(_e).v->start->ptr, true)

#define extent_for_each_online_device(_c, _e, _ptr, _ca)		\
	extent_for_each_ptr_from_filter(_e, _ptr, &(_e).v->start->ptr,	\
					((_ca) = PTR_CACHE(_c, _ptr)))

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

void bch_extent_entry_append(struct bkey_i_extent *, union bch_extent_entry *);
void bch_extent_crc_append(struct bkey_i_extent *, unsigned, unsigned,
			   unsigned, u64, unsigned);

static inline void extent_ptr_append(struct bkey_i_extent *e,
				     struct bch_extent_ptr ptr)
{
	ptr.type = 1 << BCH_EXTENT_ENTRY_ptr;
	bch_extent_entry_append(e, to_entry(&ptr));
}

/* XXX: inefficient */
static inline bool bch_extent_ptr_is_dirty(const struct cache_set *c,
					   struct bkey_s_c_extent e,
					   const struct bch_extent_ptr *ptr)
{
	if (bkey_extent_is_cached(e.k))
		return false;

	/* Dirty pointers come last */
	return bch_extent_nr_ptrs_from(e, ptr) <= c->opts.data_replicas;
}

extern const unsigned bch_crc_size[];

static inline struct bch_extent_crc64 crc_to_64(const struct bkey *k,
						const union bch_extent_crc *crc)
{
	switch (extent_crc_type(crc)) {
	case BCH_EXTENT_CRC_NONE:
		return (struct bch_extent_crc64) {
			.compressed_size	= k->size,
			.uncompressed_size	= k->size,
		};
	case BCH_EXTENT_CRC32:
		return (struct bch_extent_crc64) {
			.compressed_size	= crc->crc32.compressed_size,
			.uncompressed_size	= crc->crc32.uncompressed_size,
			.offset			= crc->crc32.offset,
			.csum_type		= crc->crc32.csum_type,
			.compression_type	= crc->crc32.compression_type,
			.csum			= crc->crc32.csum,
		};
	case BCH_EXTENT_CRC64:
		return crc->crc64;
	default:
		BUG();
	}
}

static inline unsigned crc_compressed_size(const struct bkey *k,
					   const union bch_extent_crc *crc)
{
	return crc_to_64(k, crc).compressed_size;
}

static inline unsigned crc_uncompressed_size(const struct bkey *k,
					     const union bch_extent_crc *crc)
{
	return crc_to_64(k, crc).uncompressed_size;
}

static inline unsigned crc_offset(const union bch_extent_crc *crc)
{
	switch (extent_crc_type(crc)) {
	case BCH_EXTENT_CRC_NONE:
		return 0;
	case BCH_EXTENT_CRC32:
		return crc->crc32.offset;
	case BCH_EXTENT_CRC64:
		return crc->crc64.offset;
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
	default:
		BUG();
	}
}

static inline u64 crc_csum(const union bch_extent_crc *crc)
{
	switch (extent_crc_type(crc)) {
	case BCH_EXTENT_CRC_NONE:
		return 0;
	case BCH_EXTENT_CRC32:
		return crc->crc32.csum;
	case BCH_EXTENT_CRC64:
		return crc->crc64.csum;
	default:
		BUG();
	}
}

static inline unsigned bkey_extent_is_compressed(struct cache_set *c,
						 struct bkey_s_c k)
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
			if (bch_extent_ptr_is_dirty(c, e, ptr) &&
			    crc_compression_type(crc) != BCH_COMPRESSION_NONE &&
			    crc_compressed_size(e.k, crc) < k.k->size)
				ret = max_t(unsigned, ret,
					    crc_compressed_size(e.k, crc));
	}

	return ret;
}

void bch_extent_narrow_crcs(struct bkey_s_extent);
void bch_extent_drop_redundant_crcs(struct bkey_s_extent);

/* Doesn't cleanup redundant crcs */
static inline void __bch_extent_drop_ptr(struct bkey_s_extent e,
					 struct bch_extent_ptr *ptr)
{
	EBUG_ON(ptr < &e.v->start->ptr ||
		ptr >= &extent_entry_last(e)->ptr);
	EBUG_ON(ptr->type != 1 << BCH_EXTENT_ENTRY_ptr);
	memmove_u64s_down(ptr, ptr + 1,
			  (u64 *) extent_entry_last(e) - (u64 *) (ptr + 1));
	e.k->u64s -= sizeof(*ptr) / sizeof(u64);
}

static inline void bch_extent_drop_ptr(struct bkey_s_extent e,
				       struct bch_extent_ptr *ptr)
{
	__bch_extent_drop_ptr(e, ptr);
	bch_extent_drop_redundant_crcs(e);
}

bool bch_extent_has_device(struct bkey_s_c_extent, unsigned);

bool bch_cut_front(struct bpos, struct bkey_i *);
bool bch_cut_back(struct bpos, struct bkey *);
void bch_key_resize(struct bkey *, unsigned);

#endif /* _BCACHE_EXTENTS_H */
