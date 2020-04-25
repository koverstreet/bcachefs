// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * CRC64 ECMA 182 Checksum
 *
 * Crypto API wrapper for hardware accelerated functions.
 * This crypto module uses ASM implementations ported from Intel ISA-L. 
 * 
 * Copyright (c) 2004 Cisco Systems, Inc.	
 * Copyright (c) 2008 Herbert Xu <herbert@gondor.apana.org.au>
 * Copyright (c) 2020 Robbie Litchfield <blam.kiwi@gmail.com>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crc64.h>
#include <asm/unaligned.h>
#include <asm/cpufeatures.h>
#include <asm/simd.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>

extern u64 crc64_ecma_norm_by8(u64 crc, const void *data,	size_t len );
extern u64 crc64_ecma_norm_by16_10(u64 crc, const void *data,	size_t len );
static u64 (*impl)(u64, const void *, size_t ) = NULL;

static u64 dispatch_crc64(u64 crc, const void *data, size_t len ) {
	u64 res;
	
	// Kernel FPU has overhead, perform small csums using table based method
	if(len < 256 || !crypto_simd_usable()) {
		res =  crc64_be(crc, data, len);
	} else {
		kernel_fpu_begin();
		res = impl(crc, data, len);
		kernel_fpu_end();
	}

	return res;
}

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

	ctx->state = dispatch_crc64(ctx->state, data, len);

	return 0;
}

static int crc64_csum_tail(u64 *state, const u8 *data, unsigned int len, u8 *out)
{
	STORE(dispatch_crc64(*state, data, len), out);

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
		.cra_driver_name	=	"crc64-pclmul",
		.cra_priority		=	200,
		.cra_flags			=	CRYPTO_ALG_OPTIONAL_KEY,
		.cra_blocksize		=	sizeof(u8),
		.cra_ctxsize		=	sizeof(struct crc64_csum_ctx),
		.cra_module			=	THIS_MODULE,
		.cra_init			=	crc64_csum_cra_init,
	}
};

static int __init crc64_pclmul_mod_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_PCLMULQDQ)) {
		pr_info("PCLMUL instructions are not avaiable");
		return -ENODEV;
	}
		
	#if CONFIG_AS_AVX512
	if (boot_cpu_has(X86_FEATURE_VPCLMULQDQ)) {
		impl = &crc64_ecma_norm_by16_10;
	} else {
		impl = &crc64_ecma_norm_by8;
	}
	#else
		impl = &crc64_ecma_norm_by8;
	#endif

	return crypto_register_shash(&alg);
}

static void __exit crc64_pclmul_mod_exit(void)
{
	crypto_unregister_shash(&alg);
}

module_init(crc64_pclmul_mod_init);
module_exit(crc64_pclmul_mod_exit);

MODULE_AUTHOR("Robbie Litchfield <blam.kiwi@gmail.com>");
MODULE_LICENSE("GPL");

MODULE_ALIAS_CRYPTO("crc64");
MODULE_ALIAS_CRYPTO("crc64-pclmul");
MODULE_ALIAS_CRYPTO("crc64-ecma-182");
