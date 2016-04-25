
#include "siphash.h"
#include <crypto/sha1_base.h>
#include <linux/crc32c.h>

static const SIPHASH_KEY bch_siphash_key = {
	.k0 = cpu_to_le64(0x5a9585fd80087730ULL),
	.k1 = cpu_to_le64(0xc8de666d50b45664ULL ),
};

struct bch_str_hash_ctx {
	union {
		u32			crc32c;
		u64			crc64;
		SIPHASH_CTX		siphash;
		struct shash_desc	sha1;
	};
};

static inline void bch_str_hash_init(struct bch_str_hash_ctx *ctx,
				     enum bch_str_hash_type type)
{
	switch (type) {
	case BCH_STR_HASH_CRC32C:
		ctx->crc32c = ~0;
		break;
	case BCH_STR_HASH_CRC64:
		ctx->crc64 = ~0;
		break;
	case BCH_STR_HASH_SIPHASH:
		SipHash24_Init(&ctx->siphash, &bch_siphash_key);
		break;
	case BCH_STR_HASH_SHA1:
		sha1_base_init(&ctx->sha1);
		break;
	default:
		BUG();
	}
}

static inline void bch_str_hash_update(struct bch_str_hash_ctx *ctx,
				enum bch_str_hash_type type,
				const void *data, size_t len)
{
	switch (type) {
	case BCH_STR_HASH_CRC32C:
		ctx->crc32c = crc32c(ctx->crc32c, data, len);
		break;
	case BCH_STR_HASH_CRC64:
		ctx->crc64 = bch_crc64_update(ctx->crc64, data, len);
		break;
	case BCH_STR_HASH_SIPHASH:
		SipHash24_Update(&ctx->siphash, data, len);
		break;
	case BCH_STR_HASH_SHA1:
		crypto_sha1_update(&ctx->sha1, data, len);
		break;
	default:
		BUG();
	}
}

static inline u64 bch_str_hash_end(struct bch_str_hash_ctx *ctx,
				   enum bch_str_hash_type type)
{
	switch (type) {
	case BCH_STR_HASH_CRC32C:
		return ctx->crc32c;
	case BCH_STR_HASH_CRC64:
		return ctx->crc64 >> 1;
	case BCH_STR_HASH_SIPHASH:
		return SipHash24_End(&ctx->siphash) >> 1;
	case BCH_STR_HASH_SHA1: {
		u8 out[SHA1_DIGEST_SIZE];
		u64 ret;

		crypto_sha1_finup(&ctx->sha1, NULL, 0, out);
		memcpy(&ret, &out, sizeof(ret));
		return ret >> 1;
	}
	default:
		BUG();
	}
}
