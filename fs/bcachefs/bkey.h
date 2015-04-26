#ifndef _BCACHE_BKEY_H
#define _BCACHE_BKEY_H

#include <linux/bug.h>
#include "bcachefs_format.h"

int bch_bkey_to_text(char *, size_t, const struct bkey *);

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

#define BKEY_VAL_ACCESSORS(name, nr)					\
static inline struct bkey_i_##name *bkey_i_to_##name(struct bkey *k)	\
{									\
	BUG_ON(k->type != nr);						\
	return container_of(k, struct bkey_i_##name, k);		\
}									\
									\
static inline const struct bkey_i_##name *				\
bkey_i_to_##name##_c(const struct bkey *k)				\
{									\
	BUG_ON(k->type != nr);						\
	return container_of(k, struct bkey_i_##name, k);		\
}									\
									\
static inline struct bkey_i_##name *bkey_##name##_init(struct bkey *_k)	\
{									\
	struct bkey_i_##name *k = container_of(_k, struct bkey_i_##name, k);\
									\
	bkey_init(&k->k);						\
	memset(&k->v, 0, sizeof(k->v));					\
	k->k.type = nr;							\
	set_bkey_val_bytes(&k->k, sizeof(k->v));			\
									\
	return k;							\
}

BKEY_VAL_ACCESSORS(cookie,		KEY_TYPE_COOKIE);

BKEY_VAL_ACCESSORS(extent,		BCH_EXTENT);

BKEY_VAL_ACCESSORS(inode,		BCH_INODE_FS);
BKEY_VAL_ACCESSORS(inode_blockdev,	BCH_INODE_BLOCKDEV);

#endif /* _BCACHE_BKEY_H */
