#ifndef _BCACHE_CHECKSUM_H
#define _BCACHE_CHECKSUM_H

#include <crypto/chacha20.h>

#include "btree_types.h"

u64 bch_crc64_update(u64, const void *, size_t);

#define BCH_NONCE_EXTENT	cpu_to_le32(1 << 28)
#define BCH_NONCE_BTREE		cpu_to_le32(2 << 28)
#define BCH_NONCE_JOURNAL	cpu_to_le32(3 << 28)
#define BCH_NONCE_PRIO		cpu_to_le32(4 << 28)
#define BCH_NONCE_POLY		cpu_to_le32(1 << 31)

struct bch_csum bch_checksum(struct cache_set *, unsigned, struct nonce,
			     const void *, size_t);

/*
 * This is used for various on disk data structures - cache_sb, prio_set, bset,
 * jset: The checksum is _always_ the first field of these structs
 */
#define csum_set(_c, _type, _nonce, i, u64s)				\
({									\
	const void *start = ((const void *) (i)) + sizeof(i->csum);	\
	const void *end = __bkey_idx(i, u64s);				\
									\
	bch_checksum(_c, _type, _nonce, start, end - start);		\
})

void bch_encrypt(struct cache_set *, unsigned, struct nonce,
		 void *data, size_t);

struct bch_csum bch_checksum_bio(struct cache_set *, unsigned,
				 struct nonce, struct bio *);
void bch_encrypt_bio(struct cache_set *, unsigned,
		    struct nonce, struct bio *);

int bch_disable_encryption(struct cache_set *);
int bch_enable_encryption(struct cache_set *, bool);

void bch_cache_set_encryption_free(struct cache_set *);
int bch_cache_set_encryption_init(struct cache_set *);

static inline unsigned bch_data_checksum_type(struct cache_set *c)
{
	return c->sb.encryption_type
		? BCH_CSUM_CHACHA20_POLY1305
		: c->opts.data_checksum;
}

static inline unsigned bch_meta_checksum_type(struct cache_set *c)
{
	return c->sb.encryption_type
		? BCH_CSUM_CHACHA20_POLY1305
		: c->opts.metadata_checksum;
}

/* for skipping ahead and encrypting/decrypting at an offset: */
static inline struct nonce nonce_add(struct nonce nonce, unsigned offset)
{
	EBUG_ON(offset & (CHACHA20_BLOCK_SIZE - 1));

	le32_add_cpu(&nonce.d[0], offset / CHACHA20_BLOCK_SIZE);
	return nonce;
}

#endif /* _BCACHE_CHECKSUM_H */
