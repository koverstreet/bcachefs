#ifndef _BCACHE_CHECKSUM_H
#define _BCACHE_CHECKSUM_H

#include "bcache.h"
#include "super-io.h"

#include <crypto/chacha20.h>

u64 bch_crc64_update(u64, const void *, size_t);

#define BCH_NONCE_EXTENT	cpu_to_le32(1 << 28)
#define BCH_NONCE_BTREE		cpu_to_le32(2 << 28)
#define BCH_NONCE_JOURNAL	cpu_to_le32(3 << 28)
#define BCH_NONCE_PRIO		cpu_to_le32(4 << 28)
#define BCH_NONCE_POLY		cpu_to_le32(1 << 31)

struct bch_csum bch_checksum(struct cache_set *, unsigned, struct nonce,
			     const void *, size_t);

/*
 * This is used for various on disk data structures - bch_sb, prio_set, bset,
 * jset: The checksum is _always_ the first field of these structs
 */
#define csum_vstruct(_c, _type, _nonce, _i)				\
({									\
	const void *start = ((const void *) (_i)) + sizeof((_i)->csum);	\
	const void *end = vstruct_end(_i);				\
									\
	bch_checksum(_c, _type, _nonce, start, end - start);		\
})

int bch_chacha_encrypt_key(struct bch_key *, struct nonce, void *, size_t);
int bch_request_key(struct bch_sb *, struct bch_key *);

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
	if (c->sb.encryption_type)
		return c->opts.wide_macs
			? BCH_CSUM_CHACHA20_POLY1305_128
			: BCH_CSUM_CHACHA20_POLY1305_80;

	return c->opts.data_checksum;
}

static inline unsigned bch_meta_checksum_type(struct cache_set *c)
{
	return c->sb.encryption_type
		? BCH_CSUM_CHACHA20_POLY1305_128
		: c->opts.metadata_checksum;
}

static inline bool bch_checksum_type_valid(const struct cache_set *c,
					   unsigned type)
{
	if (type >= BCH_CSUM_NR)
		return false;

	if (bch_csum_type_is_encryption(type) && !c->chacha20)
		return false;

	return true;
}

static const unsigned bch_crc_bytes[] = {
	[BCH_CSUM_NONE]				= 0,
	[BCH_CSUM_CRC32C]			= 4,
	[BCH_CSUM_CRC64]			= 8,
	[BCH_CSUM_CHACHA20_POLY1305_80]		= 10,
	[BCH_CSUM_CHACHA20_POLY1305_128]	= 16,
};

static inline bool bch_crc_cmp(struct bch_csum l, struct bch_csum r)
{
	/*
	 * XXX: need some way of preventing the compiler from optimizing this
	 * into a form that isn't constant time..
	 */
	return ((l.lo ^ r.lo) | (l.hi ^ r.hi)) != 0;
}

/* for skipping ahead and encrypting/decrypting at an offset: */
static inline struct nonce nonce_add(struct nonce nonce, unsigned offset)
{
	EBUG_ON(offset & (CHACHA20_BLOCK_SIZE - 1));

	le32_add_cpu(&nonce.d[0], offset / CHACHA20_BLOCK_SIZE);
	return nonce;
}

static inline bool bch_key_is_encrypted(struct bch_encrypted_key *key)
{
	return le64_to_cpu(key->magic) != BCH_KEY_MAGIC;
}

static inline struct nonce __bch_sb_key_nonce(struct bch_sb *sb)
{
	__le64 magic = __bch_sb_magic(sb);

	return (struct nonce) {{
		[0] = 0,
		[1] = 0,
		[2] = ((__le32 *) &magic)[0],
		[3] = ((__le32 *) &magic)[1],
	}};
}

static inline struct nonce bch_sb_key_nonce(struct cache_set *c)
{
	__le64 magic = bch_sb_magic(c);

	return (struct nonce) {{
		[0] = 0,
		[1] = 0,
		[2] = ((__le32 *) &magic)[0],
		[3] = ((__le32 *) &magic)[1],
	}};
}

#endif /* _BCACHE_CHECKSUM_H */
