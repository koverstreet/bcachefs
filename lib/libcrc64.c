// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * CRC64 ECMA 182 Checksum
 *
 * Helper function for accessing hardware/SIMD accelerated CRC64 implementations. 
 *
 * Copyright (c) 2004 Cisco Systems, Inc.
 * Copyright (c) 2020 Robbie Litchfield <blam.kiwi@gmail.com>
 */

#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

static struct crypto_shash *tfm;

u64 crc64(u64 crc, const void *data, unsigned int len)
{
	SHASH_DESC_ON_STACK(shash, tfm);
	u64 ret, *ctx = (u64 *)shash_desc_ctx(shash);
	int err;

	shash->tfm = tfm;
	*ctx = crc;

	err = crypto_shash_update(shash, data, len);
	BUG_ON(err);

	ret = *ctx;
	barrier_data(ctx);
	return ret;
}

const char *crc64_impl(void)
{
	return crypto_shash_driver_name(tfm);
}

static int __init libcrc64_mod_init(void)
{
	tfm = crypto_alloc_shash("crc64", 0, 0);

	return PTR_ERR_OR_ZERO(tfm);
}

static void __exit libcrc64_mod_exit(void)
{
	crypto_free_shash(tfm);
}

EXPORT_SYMBOL_GPL(crc64_impl);
EXPORT_SYMBOL_GPL(crc64);

module_init(libcrc64_mod_init);
module_exit(libcrc64_mod_exit);

MODULE_AUTHOR("Robbie Litchfield <blam.kiwi@gmail.com>");
MODULE_DESCRIPTION("CRC64 ECMA 182 checksumming");
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: crc64");

