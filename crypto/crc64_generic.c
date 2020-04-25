// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * CRC64 ECMA 182 Checksum
 *
 * Crypto API wrapper for crc64_be
 * 
 * Copyright (c) 2004 Cisco Systems, Inc.	
 * Copyright (c) 2008 Herbert Xu <herbert@gondor.apana.org.au>
 * Copyright (c) 2020 Robbie Litchfield <blam.kiwi@gmail.com>
 */

#include <asm/unaligned.h>
#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crc64.h>

/* 
 * ECMA 182 does not define a byte endianness. 
 * Use host endianness.
 */
#define LOAD(p) get_unaligned((const u64*)p)
#define STORE(v, p) put_unaligned(v, (u64*)p)

struct crc64_csum_ctx {
	u64 key;
};

struct crc64_csum_desc_ctx {
	u64 state;
};

/*
 * Setting the seed allows arbitrary accumulators and flexible XOR policy
 * If your algorithm starts with ~0, then XOR with ~0 before you set
 * the seed.
 */
static int crc64_csum_setkey(struct crypto_shash *tfm, const u8 *key,
			 unsigned int len)
{
	struct crc64_csum_ctx *mctx = crypto_shash_ctx(tfm);

	if (len != sizeof(u64)) {
		crypto_shash_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}

	mctx->key = LOAD(key);

	return 0;
}

static int crc64_csum_update(struct shash_desc *desc, const u8 *data,
			 unsigned int len)
{
	struct crc64_csum_desc_ctx *ctx = shash_desc_ctx(desc);

	ctx->state = crc64_be(ctx->state, data, len);

	return 0;
}

static int crc64_csum_tail(u64 *state, const u8 *data, unsigned int len, u8 *out)
{
	STORE(crc64_be(*state, data, len), out);

	return 0;
}

static int crc64_csum_digest(struct shash_desc *desc, const u8 *data,
			 unsigned int len, u8 *out)
{
	struct crc64_csum_ctx *mctx = crypto_shash_ctx(desc->tfm);

	return crc64_csum_tail(&mctx->key, data, len, out);
}

static int crc64_csum_finup(struct shash_desc *desc, const u8 *data,
			unsigned int len, u8 *out)
{
	struct crc64_csum_desc_ctx *ctx = shash_desc_ctx(desc);

	return crc64_csum_tail(&ctx->state, data, len, out);
}

static int crc64_csum_final(struct shash_desc *desc, u8 *out)
{
	struct crc64_csum_desc_ctx *ctx = shash_desc_ctx(desc);

	STORE(ctx->state, out);

	return 0;
}

static int crc64_csum_init(struct shash_desc *desc)
{
	struct crc64_csum_ctx *mctx = crypto_shash_ctx(desc->tfm);
	struct crc64_csum_desc_ctx *ctx = shash_desc_ctx(desc);

	ctx->state = mctx->key;

	return 0;
}

static int crc64_csum_cra_init(struct crypto_tfm *tfm)
{
	struct crc64_csum_ctx *mctx = crypto_tfm_ctx(tfm);

	mctx->key = 0;
	
	return 0;
}

static struct shash_alg alg = {
	.digestsize		=	sizeof(u64),
	.descsize		=	sizeof(struct crc64_csum_desc_ctx),

	.init			=	crc64_csum_init,
	.setkey			=	crc64_csum_setkey,
	.update			=	crc64_csum_update,
	.digest			=	crc64_csum_digest,
	.final			=	crc64_csum_final,
	.finup			=	crc64_csum_finup,

	.base			=	{
		.cra_name			=	"crc64",
		.cra_driver_name	=	"crc64-generic",
		.cra_priority		=	100,
		.cra_flags			=	CRYPTO_ALG_OPTIONAL_KEY,
		.cra_blocksize		=	sizeof(u8),
		.cra_ctxsize		=	sizeof(struct crc64_csum_ctx),
		.cra_module			=	THIS_MODULE,
		.cra_init			=	crc64_csum_cra_init,
	}
};

static int __init crc64_mod_init(void)
{
	return crypto_register_shash(&alg);
}

static void __exit crc64_mod_exit(void)
{
	crypto_unregister_shash(&alg);
}

module_init(crc64_mod_init);
module_exit(crc64_mod_exit);

MODULE_AUTHOR("Robbie Litchfield <blam.kiwi@gmail.com>");
MODULE_DESCRIPTION("CRC64 wrapper for lib/crc64");
MODULE_LICENSE("GPL");

MODULE_ALIAS_CRYPTO("crc64");
MODULE_ALIAS_CRYPTO("crc64-generic");
MODULE_ALIAS_CRYPTO("crc64-ecma-182");
