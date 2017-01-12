#ifndef _BCACHE_CHECKSUM_H
#define _BCACHE_CHECKSUM_H

#include "btree_types.h"

u64 bch_crc64_update(u64, const void *, size_t);

u64 bch_checksum_update(unsigned, u64, const void *, size_t);
u64 bch_checksum(unsigned, const void *, size_t);
u32 bch_checksum_bio(struct bio *, unsigned);

/*
 * This is used for various on disk data structures - cache_sb, prio_set, bset,
 * jset: The checksum is _always_ the first 8 bytes of these structs
 */
#define __csum_set(i, u64s, type)					\
({									\
	const void *start = ((const void *) (i)) + sizeof(u64);		\
	const void *end = __bkey_idx(i, u64s);				\
									\
	bch_checksum(type, start, end - start);				\
})

#endif /* _BCACHE_CHECKSUM_H */
