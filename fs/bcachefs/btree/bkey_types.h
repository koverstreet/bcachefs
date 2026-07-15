/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BKEY_TYPES_H
#define _BCACHEFS_BKEY_TYPES_H

#include "bcachefs_format.h"

/* DOC_LATEX(bkey-structures)
 *
 * \paragraph{Search keys and bkeys}
 *
 * The btree separates the search key (\texttt{struct bpos}) from the outer
 * container that holds a key and value (\texttt{struct bkey}).
 *
 * \begin{verbatim}
 * struct bpos {
 *     u64  inode;      // high bits of the search key
 *     u64  offset;     // middle bits
 *     u32  snapshot;   // low bits
 * };
 *
 * struct bkey {
 *     u8          u64s;    // size of key + value in u64s
 *     u8          format;  // internal: packed bkey format
 *     u8          type;    // value type (KEY_TYPE_extent, etc.)
 *     u8          pad;
 *     bversion    bversion;
 *     u32         size;    // extent size in sectors (0 for non-extents)
 *     struct bpos p;       // position (for extents: end position)
 * };
 * \end{verbatim}
 *
 * The three fields of \texttt{bpos} form a single large integer for
 * comparison. Not all code uses all fields---the inode field generally
 * corresponds to an inode number, and for extents the offset field
 * is the file offset. The snapshot field enables snapshot-aware lookups.
 *
 * The \texttt{type} field determines how the value is interpreted. Use
 * \texttt{bkey\_val\_u64s()} or \texttt{bkey\_val\_bytes()} to get the value
 * size---the \texttt{u64s} field includes the key header.
 *
 * For extents, \texttt{p.offset} points to the \emph{end} of the extent, not
 * the start. A key with offset 8 and size 8 covers sectors 0--7. This makes
 * ascending iteration over extent ranges more natural.
 *
 * \paragraph{Wrapper types}
 *
 * Values are stored inline with keys on disk, but due to packing they are
 * typically accessed via wrapper types that hold pointers:
 *
 * \begin{description}
 * \item[\texttt{bkey\_i}] Key with inline value (for allocation/insertion)
 * \item[\texttt{bkey\_s}] Key with split value (pointers to key and value)
 * \item[\texttt{bkey\_s\_c}] Constant key with split value (for lookups)
 * \end{description}
 *
 * Each value type generates corresponding typed wrappers. For example,
 * \texttt{struct bch\_xattr} generates:
 *
 * \begin{itemize}
 * \item \texttt{bkey\_i\_xattr} -- inline xattr key
 * \item \texttt{bkey\_s\_xattr} -- split xattr key
 * \item \texttt{bkey\_s\_c\_xattr} -- const split xattr key
 * \end{itemize}
 *
 * To convert from a generic \texttt{bkey\_s\_c} to a typed wrapper, use
 * \texttt{bkey\_s\_c\_to\_xattr(k)}. These accessors assert that the type
 * field matches, so always check \texttt{k.k->type} first:
 *
 * \begin{verbatim}
 * struct bkey_s_c k = bch2_btree_iter_peek(&iter);
 *
 * switch (k.k->type) {
 * case KEY_TYPE_xattr: {
 *     struct bkey_s_c_xattr xattr = bkey_s_c_to_xattr(k);
 *     // access xattr.v->x_name, etc.
 *     break;
 * }
 * }
 * \end{verbatim}
 *
 * See \S\ref{bkey-type-list} for the complete list of key types.
 */

/*
 * bkey_i	- bkey with inline value
 * bkey_s	- bkey with split value
 * bkey_s_c	- bkey with split value, const
 */

#define bkey_p_next(_k)		vstruct_next(_k)

static inline struct bkey_i *bkey_next(struct bkey_i *k)
{
	return (struct bkey_i *) ((u64 *) k->_data + k->k.u64s);
}

#define bkey_val_u64s(_k)	((_k)->u64s - BKEY_U64s)

static inline size_t bkey_val_bytes(const struct bkey *k)
{
	return bkey_val_u64s(k) * sizeof(u64);
}

static inline void set_bkey_val_u64s(struct bkey *k, unsigned val_u64s)
{
	unsigned u64s = BKEY_U64s + val_u64s;

	BUG_ON(u64s > U8_MAX);
	k->u64s = u64s;
}

static inline void set_bkey_val_bytes(struct bkey *k, unsigned bytes)
{
	set_bkey_val_u64s(k, DIV_ROUND_UP(bytes, sizeof(u64)));
}

#define bkey_val_end(_k)	((void *) (((u64 *) (_k).v) + bkey_val_u64s((_k).k)))

#define bkey_deleted(_k)	((_k)->type == KEY_TYPE_deleted)

#define bkey_whiteout(_k)				\
	((_k)->type == KEY_TYPE_deleted || (_k)->type == KEY_TYPE_whiteout)

#define bkey_extent_whiteout(_k)				\
	((_k)->type == KEY_TYPE_deleted ||			\
	 (_k)->type == KEY_TYPE_whiteout ||			\
	 (_k)->type == KEY_TYPE_extent_whiteout)

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
#define x(name, ...)					\
struct bkey_i_##name {							\
	union {								\
		struct bkey		k;				\
		struct bkey_i		k_i;				\
	};								\
	struct bch_##name		v;				\
};									\
									\
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
	BUG_ON(!IS_ERR_OR_NULL(k) && k->k.type != KEY_TYPE_##name);	\
	return container_of(&k->k, struct bkey_i_##name, k);		\
}									\
									\
static inline const struct bkey_i_##name *				\
bkey_i_to_##name##_c(const struct bkey_i *k)				\
{									\
	BUG_ON(!IS_ERR_OR_NULL(k) && k->k.type != KEY_TYPE_##name);	\
	return container_of(&k->k, struct bkey_i_##name, k);		\
}									\
									\
static inline struct bkey_s_##name bkey_s_to_##name(struct bkey_s k)	\
{									\
	BUG_ON(!IS_ERR_OR_NULL(k.k) && k.k->type != KEY_TYPE_##name);	\
	return (struct bkey_s_##name) {					\
		.k = k.k,						\
		.v = container_of(k.v, struct bch_##name, v),		\
	};								\
}									\
									\
static inline struct bkey_s_c_##name bkey_s_c_to_##name(struct bkey_s_c k)\
{									\
	BUG_ON(!IS_ERR_OR_NULL(k.k) && k.k->type != KEY_TYPE_##name);	\
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
	BUG_ON(!IS_ERR_OR_NULL(k) && k->k.type != KEY_TYPE_##name);	\
	return (struct bkey_s_##name) {					\
		.k = &k->k,						\
		.v = container_of(&k->v, struct bch_##name, v),		\
	};								\
}									\
									\
static inline struct bkey_s_c_##name					\
bkey_i_to_s_c_##name(const struct bkey_i *k)				\
{									\
	BUG_ON(!IS_ERR_OR_NULL(k) && k->k.type != KEY_TYPE_##name);	\
	return (struct bkey_s_c_##name) {				\
		.k = &k->k,						\
		.v = container_of(&k->v, struct bch_##name, v),		\
	};								\
}									\
									\
static inline struct bkey_i_##name *bkey_##name##_init(struct bkey_i *_k)\
{									\
	struct bkey_i_##name *k =					\
		container_of(&_k->k, struct bkey_i_##name, k);		\
									\
	bkey_init(&k->k);						\
	memset(&k->v, 0, sizeof(k->v));					\
	k->k.type = KEY_TYPE_##name;					\
	set_bkey_val_bytes(&k->k, sizeof(k->v));			\
									\
	return k;							\
}

BCH_BKEY_TYPES();
#undef x

enum bch_validate_flags {
	BCH_VALIDATE_write		= BIT(0),
	BCH_VALIDATE_commit		= BIT(1),
	BCH_VALIDATE_silent		= BIT(2),
};

#define BKEY_VALIDATE_CONTEXTS()	\
	x(unknown)			\
	x(superblock)			\
	x(journal)			\
	x(btree_root)			\
	x(btree_node)			\
	x(commit)

struct bkey_validate_context {
	enum {
#define x(n)	BKEY_VALIDATE_##n,
	BKEY_VALIDATE_CONTEXTS()
#undef x
	}			from:8;
	enum bch_validate_flags	flags:8;
	u8			level;
	enum btree_id		btree;
	bool			root:1;
	unsigned		journal_offset;
	u64			journal_seq;
};

#endif /* _BCACHEFS_BKEY_TYPES_H */
