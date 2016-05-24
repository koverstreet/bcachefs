#ifndef _BCACHE_BKEY_H
#define _BCACHE_BKEY_H

#include <linux/bug.h>
#include "bcachefs_format.h"

#include "util.h"

int bch_bkey_to_text(char *, size_t, const struct bkey *);

/* bkey with split value, const */
struct bkey_s_c {
	const struct bkey	*k;
	const struct bch_val	*v;
};

/* bkey with split value */
struct bkey_s {
	union {
	struct {
		struct bkey	*k;
		struct bch_val	*v;
	};
	struct bkey_s_c		s_c;
	};
};

#define type_is(_val, _type)						\
	(__builtin_types_compatible_p(typeof(_val), _type) ||		\
	 __builtin_types_compatible_p(typeof(_val), const _type))

#define bkey_next(_k)							\
({									\
	BUILD_BUG_ON(!type_is(_k, struct bkey *) &&			\
		     !type_is(_k, struct bkey_i *) &&			\
		     !type_is(_k, struct bkey_packed *));		\
									\
	((typeof(_k)) __bkey_idx(((struct bkey *) (_k)),		\
				 ((struct bkey *) (_k))->u64s));	\
})

static inline unsigned bkey_val_u64s(const struct bkey *k)
{
	return k->u64s - BKEY_U64s;
}

static inline size_t bkey_val_bytes(const struct bkey *k)
{
	return bkey_val_u64s(k) * sizeof(u64);
}

static inline void set_bkey_val_u64s(struct bkey *k, unsigned val_u64s)
{
	k->u64s = BKEY_U64s + val_u64s;
}

static inline void set_bkey_val_bytes(struct bkey *k, unsigned bytes)
{
	k->u64s = BKEY_U64s + DIV_ROUND_UP(bytes, sizeof(u64));
}

/*
 * Mark a key as deleted without changing the size of the value (i.e. modifying
 * keys in the btree in place)
 */
static inline void __set_bkey_deleted(struct bkey *k)
{
	k->type = KEY_TYPE_DELETED;
}

static inline void set_bkey_deleted(struct bkey *k)
{
	__set_bkey_deleted(k);
	set_bkey_val_u64s(k, 0);
}

#define bkey_deleted(_k)	((_k)->type == KEY_TYPE_DELETED)

struct btree_keys;

struct bkey_format_state {
	u64 field_min[BKEY_NR_FIELDS];
	u64 field_max[BKEY_NR_FIELDS];
};

void bch_bkey_format_init(struct bkey_format_state *);
void bch_bkey_format_add_key(struct bkey_format_state *, const struct bkey *);
void bch_bkey_format_add_pos(struct bkey_format_state *, struct bpos);
struct bkey_format bch_bkey_format_done(struct bkey_format_state *);
const char *bch_bkey_format_validate(struct bkey_format *);

unsigned bkey_greatest_differing_bit(const struct bkey_format *,
				     const struct bkey_packed *,
				     const struct bkey_packed *);
unsigned bkey_ffs(const struct bkey_format *, const struct bkey_packed *);

int __bkey_cmp_left_packed(const struct bkey_format *,
			   const struct bkey_packed *,
			   struct bpos);

#define bkey_cmp_left_packed(_format, _l, _r)			\
({								\
	const struct bkey *_l_unpacked;				\
								\
	unlikely(_l_unpacked = packed_to_bkey_c(_l))		\
		? bkey_cmp(_l_unpacked->p, _r)			\
		: __bkey_cmp_left_packed(_format, _l, _r);	\
})

int __bkey_cmp_packed(const struct bkey_format *,
		      const struct bkey_packed *,
		      const struct bkey_packed *);

#if 1
static __always_inline int bkey_cmp(struct bpos l, struct bpos r)
{
	if (l.inode != r.inode)
		return l.inode < r.inode ? -1 : 1;
	if (l.offset != r.offset)
		return l.offset < r.offset ? -1 : 1;
	if (l.snapshot != r.snapshot)
		return l.snapshot < r.snapshot ? -1 : 1;
	return 0;
}
#else
int bkey_cmp(struct bpos l, struct bpos r);
#endif

static inline struct bpos bpos_min(struct bpos l, struct bpos r)
{
	return bkey_cmp(l, r) < 0 ? l : r;
}

void bch_bpos_swab(struct bpos *);
void bch_bkey_swab_key(const struct bkey_format *, struct bkey_packed *);

#define bkey_packed(_k)							\
	({ EBUG_ON((_k)->format > KEY_FORMAT_CURRENT);			\
	 (_k)->format != KEY_FORMAT_CURRENT; })

/*
 * It's safe to treat an unpacked bkey as a packed one, but not the reverse
 */
static inline struct bkey_packed *bkey_to_packed(struct bkey_i *k)
{
	return (struct bkey_packed *) k;
}

static inline const struct bkey_packed *bkey_to_packed_c(const struct bkey_i *k)
{
	return (const struct bkey_packed *) k;
}

static inline struct bkey_i *packed_to_bkey(struct bkey_packed *k)
{
	return bkey_packed(k) ? NULL : (struct bkey_i *) k;
}

static inline const struct bkey *packed_to_bkey_c(const struct bkey_packed *k)
{
	return bkey_packed(k) ? NULL : (const struct bkey *) k;
}

static inline unsigned bkey_format_key_bits(const struct bkey_format *format)
{
	return format->bits_per_field[BKEY_FIELD_INODE] +
		format->bits_per_field[BKEY_FIELD_OFFSET] +
		format->bits_per_field[BKEY_FIELD_SNAPSHOT];
}

#define bkey_packed_typecheck(_k)					\
({									\
	BUILD_BUG_ON(!type_is(_k, struct bkey *) &&			\
		     !type_is(_k, struct bkey_packed *));		\
	type_is(_k, struct bkey_packed *) && bkey_packed(_k);		\
})

/*
 * If @_l and @_r are in the same format, does the comparison without unpacking.
 * Otherwise, unpacks whichever one is packed.
 */
#define bkey_cmp_packed(_f, _l, _r)					\
	((bkey_packed_typecheck(_l) && bkey_packed_typecheck(_r))	\
	 ? __bkey_cmp_packed(_f, (void *) _l, (void *) _r)		\
	 : bkey_packed_typecheck(_l)					\
	 ? __bkey_cmp_left_packed(_f,					\
				  (struct bkey_packed *) _l,		\
				  ((struct bkey *) _r)->p)		\
	 : bkey_packed_typecheck(_r)					\
	 ? -__bkey_cmp_left_packed(_f,					\
				   (struct bkey_packed *) _r,		\
				   ((struct bkey *) _l)->p)		\
	 : bkey_cmp(((struct bkey *) _l)->p,				\
		    ((struct bkey *) _r)->p))

/* packed or unpacked */
static inline int bkey_cmp_p_or_unp(const struct bkey_format *format,
				    const struct bkey_packed *l,
				    const struct bkey_packed *r_packed,
				    struct bpos r)
{
	const struct bkey *l_unpacked;

	EBUG_ON(r_packed && !bkey_packed(r_packed));

	if (unlikely(l_unpacked = packed_to_bkey_c(l)))
		return bkey_cmp(l_unpacked->p, r);

	if (likely(r_packed))
		return __bkey_cmp_packed(format, l, r_packed);

	return __bkey_cmp_left_packed(format, l, r);
}

static inline struct bpos bkey_successor(struct bpos p)
{
	struct bpos ret = p;

	if (!++ret.offset)
		BUG_ON(!++ret.inode);

	return ret;
}

static inline u64 bkey_start_offset(const struct bkey *k)
{
	return k->p.offset - k->size;
}

static inline struct bpos bkey_start_pos(const struct bkey *k)
{
	return (struct bpos) {
		.inode		= k->p.inode,
		.offset		= bkey_start_offset(k),
		.snapshot	= k->p.snapshot,
	};
}

/* Packed helpers */

static inline unsigned bkeyp_key_u64s(const struct bkey_format *format,
				      const struct bkey_packed *k)
{
	unsigned ret = bkey_packed(k) ? format->key_u64s : BKEY_U64s;

	EBUG_ON(k->u64s < ret);
	return ret;
}

static inline unsigned bkeyp_key_bytes(const struct bkey_format *format,
				       const struct bkey_packed *k)
{
	return bkeyp_key_u64s(format, k) * sizeof(u64);
}

static inline unsigned bkeyp_val_u64s(const struct bkey_format *format,
				      const struct bkey_packed *k)
{
	return k->u64s - bkeyp_key_u64s(format, k);
}

static inline size_t bkeyp_val_bytes(const struct bkey_format *format,
				     const struct bkey_packed *k)
{
	return bkeyp_val_u64s(format, k) * sizeof(u64);
}

#define bkeyp_val(_format, _k)						\
	 ((struct bch_val *) ((_k)->_data + bkeyp_key_u64s(_format, _k)))

extern const struct bkey_format bch_bkey_format_current;

bool bch_bkey_transform(const struct bkey_format *,
			struct bkey_packed *,
			const struct bkey_format *,
			const struct bkey_packed *);

struct bkey bkey_unpack_key(const struct bkey_format *,
			    const struct bkey_packed *);
bool bkey_pack_key(struct bkey_packed *, const struct bkey *,
		   const struct bkey_format *);

enum bkey_pack_pos_ret {
	BKEY_PACK_POS_EXACT,
	BKEY_PACK_POS_SMALLER,
	BKEY_PACK_POS_FAIL,
};

enum bkey_pack_pos_ret bkey_pack_pos_lossy(struct bkey_packed *, struct bpos,
					   const struct bkey_format *);

static inline bool bkey_pack_pos(struct bkey_packed *out, struct bpos in,
				 const struct bkey_format *format)
{
	return bkey_pack_pos_lossy(out, in, format) == BKEY_PACK_POS_EXACT;
}

void bkey_unpack(struct bkey_i *, const struct bkey_format *,
		 const struct bkey_packed *);
bool bkey_pack(struct bkey_packed *, const struct bkey_i *,
	       const struct bkey_format *);

/* Disassembled bkeys */

static inline struct bkey_s_c bkey_disassemble(const struct bkey_format *f,
					       const struct bkey_packed *k,
					       struct bkey *u)
{
	*u = bkey_unpack_key(f, k);

	return (struct bkey_s_c) { u, bkeyp_val(f, k), };
}

/* non const version: */
static inline struct bkey_s __bkey_disassemble(const struct bkey_format *f,
					       struct bkey_packed *k,
					       struct bkey *u)
{
	*u = bkey_unpack_key(f, k);

	return (struct bkey_s) { .k = u, .v = bkeyp_val(f, k), };
}

static inline void bkey_reassemble(struct bkey_i *dst,
				   struct bkey_s_c src)
{
	BUG_ON(bkey_packed(src.k));
	dst->k = *src.k;
	memcpy(&dst->v, src.v, bkey_val_bytes(src.k));
}

#define bkey_s_null		((struct bkey_s)   { .k = NULL })
#define bkey_s_c_null		((struct bkey_s_c) { .k = NULL })

#define bkey_s_err(err)		((struct bkey_s)   { .k = ERR_PTR(err) })
#define bkey_s_c_err(err)	((struct bkey_s_c) { .k = ERR_PTR(err) })

static inline struct bkey_s bkey_to_s(struct bkey *k)
{
	return (struct bkey_s) { .k = k, .v = NULL };
}

static inline struct bkey_s_c bkey_to_s_c(const struct bkey *k)
{
	return (struct bkey_s_c) { .k = k, .v = NULL };
}

static inline struct bkey_s bkey_i_to_s(struct bkey_i *k)
{
	return (struct bkey_s) { .k = &k->k, .v = &k->v };
}

static inline struct bkey_s_c bkey_i_to_s_c(const struct bkey_i *k)
{
	return (struct bkey_s_c) { .k = &k->k, .v = &k->v };
}

/*
 * For a given type of value (e.g. struct bch_extent), generates the types for
 * bkey + bch_extent - inline, split, split const - and also all the conversion
 * functions, which also check that the value is of the correct type.
 *
 * We use anonymous unions for upcasting - e.g. converting from e.g. a
 * bkey_i_extent to a bkey_i - since that's always safe, instead of conversion
 * functions.
 */
#define __BKEY_VAL_ACCESSORS(name, nr, _assert)				\
struct bkey_s_c_##name {						\
	union {								\
	struct {							\
		const struct bkey	*k;				\
		const struct bch_##name	*v;				\
	};								\
	struct bkey_s_c			s_c;				\
	};								\
};									\
									\
struct bkey_s_##name {							\
	union {								\
	struct {							\
		struct bkey		*k;				\
		struct bch_##name	*v;				\
	};								\
	struct bkey_s_c_##name		c;				\
	struct bkey_s			s;				\
	struct bkey_s_c			s_c;				\
	};								\
};									\
									\
static inline struct bkey_i_##name *bkey_i_to_##name(struct bkey_i *k)	\
{									\
	_assert(k->k.type, nr);						\
	return container_of(&k->k, struct bkey_i_##name, k);		\
}									\
									\
static inline const struct bkey_i_##name *				\
bkey_i_to_##name##_c(const struct bkey_i *k)				\
{									\
	_assert(k->k.type, nr);						\
	return container_of(&k->k, struct bkey_i_##name, k);		\
}									\
									\
static inline struct bkey_s_##name bkey_s_to_##name(struct bkey_s k)	\
{									\
	_assert(k.k->type, nr);						\
	return (struct bkey_s_##name) {					\
		.k = k.k,						\
		.v = container_of(k.v, struct bch_##name, v),		\
	};								\
}									\
									\
static inline struct bkey_s_c_##name bkey_s_c_to_##name(struct bkey_s_c k)\
{									\
	_assert(k.k->type, nr);						\
	return (struct bkey_s_c_##name) {				\
		.k = k.k,						\
		.v = container_of(k.v, struct bch_##name, v),		\
	};								\
}									\
									\
static inline struct bkey_s_##name name##_i_to_s(struct bkey_i_##name *k)\
{									\
	return (struct bkey_s_##name) {					\
		.k = &k->k,						\
		.v = &k->v,						\
	};								\
}									\
									\
static inline struct bkey_s_c_##name					\
name##_i_to_s_c(const struct bkey_i_##name *k)				\
{									\
	return (struct bkey_s_c_##name) {				\
		.k = &k->k,						\
		.v = &k->v,						\
	};								\
}									\
									\
static inline struct bkey_s_##name bkey_i_to_s_##name(struct bkey_i *k)	\
{									\
	_assert(k->k.type, nr);						\
	return (struct bkey_s_##name) {					\
		.k = &k->k,						\
		.v = container_of(&k->v, struct bch_##name, v),		\
	};								\
}									\
									\
static inline struct bkey_s_c_##name					\
bkey_i_to_s_c_##name(const struct bkey_i *k)				\
{									\
	_assert(k->k.type, nr);						\
	return (struct bkey_s_c_##name) {				\
		.k = &k->k,						\
		.v = container_of(&k->v, struct bch_##name, v),		\
	};								\
}									\
									\
static inline struct bch_##name *					\
bkey_p_##name##_val(const struct bkey_format *f,			\
		    struct bkey_packed *k)				\
{									\
	return container_of(bkeyp_val(f, k), struct bch_##name, v);	\
}									\
									\
static inline const struct bch_##name *					\
bkey_p_c_##name##_val(const struct bkey_format *f,			\
		      const struct bkey_packed *k)			\
{									\
	return container_of(bkeyp_val(f, k), struct bch_##name, v);	\
}									\
									\
static inline struct bkey_i_##name *bkey_##name##_init(struct bkey_i *_k)\
{									\
	struct bkey_i_##name *k =					\
		container_of(&_k->k, struct bkey_i_##name, k);		\
									\
	bkey_init(&k->k);						\
	memset(&k->v, 0, sizeof(k->v));					\
	k->k.type = nr;							\
	set_bkey_val_bytes(&k->k, sizeof(k->v));			\
									\
	return k;							\
}

#define __BKEY_VAL_ASSERT(_type, _nr)	EBUG_ON(_type != _nr)

#define BKEY_VAL_ACCESSORS(name, _nr)					\
	static inline void __bch_##name##_assert(u8 type, u8 nr)	\
	{								\
		EBUG_ON(type != _nr);					\
	}								\
									\
	__BKEY_VAL_ACCESSORS(name, _nr, __bch_##name##_assert)

BKEY_VAL_ACCESSORS(cookie,		KEY_TYPE_COOKIE);

static inline void __bch_extent_assert(u8 type, u8 nr)
{
	EBUG_ON(type != BCH_EXTENT && type != BCH_EXTENT_CACHED);
}

__BKEY_VAL_ACCESSORS(extent,		BCH_EXTENT, __bch_extent_assert);

BKEY_VAL_ACCESSORS(inode,		BCH_INODE_FS);
BKEY_VAL_ACCESSORS(inode_blockdev,	BCH_INODE_BLOCKDEV);

BKEY_VAL_ACCESSORS(dirent,		BCH_DIRENT);

BKEY_VAL_ACCESSORS(xattr,		BCH_XATTR);

/* byte order helpers */

#if !defined(__LITTLE_ENDIAN) && !defined(__BIG_ENDIAN)
#error edit for your odd byteorder.
#endif

#ifdef __LITTLE_ENDIAN

#define high_bit_offset		0
#define __high_word(u64s, k)	((k)->_data + (u64s) - 1)
#define nth_word(p, n)		((p) - (n))

#else

#define high_bit_offset		KEY_PACKED_BITS_START
#define __high_word(u64s, k)	((k)->_data)
#define nth_word(p, n)		((p) + (n))

#endif

#define high_word(format, k)	__high_word((format)->key_u64s, k)
#define next_word(p)		nth_word(p, 1)
#define prev_word(p)		nth_word(p, -1)

#ifdef CONFIG_BCACHEFS_DEBUG
void bkey_pack_test(void);
#else
static inline void bkey_pack_test(void) {}
#endif

#endif /* _BCACHE_BKEY_H */
