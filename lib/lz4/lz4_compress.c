/*
 * LZ4 - Fast LZ compression algorithm
 * Copyright (C) 2011-2012, Yann Collet.
 * BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You can contact the author at :
 * - LZ4 homepage : http://fastcompression.blogspot.com/p/lz4.html
 * - LZ4 source repository : http://code.google.com/p/lz4/
 *
 *  Changed for kernel use by:
 *  Chanho Min <chanho.min@lge.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/lz4.h>
#include <asm/unaligned.h>
#include "lz4defs.h"

#define LZ4_HASH_VALUE(p, _table)				\
	__HASH_VALUE(p, MEMORY_USAGE - ilog2(sizeof(_table[0])))

struct lz4_hash_table {
	const u8	*(*add)(const struct lz4_hash_table, const u8 *);
	void		*ctx;
	const u8	*base;
};

#if __SIZEOF_POINTER__ == 4
static inline const u8 *hash_table_add32(const struct lz4_hash_table hash,
					 const u8 *ip)
{
	const u8 **table = hash.ctx;

	swap(table[LZ4_HASH_VALUE(ip, table)], ip);
	return ip;
}
#else
static inline const u8 *hash_table_add32(const struct lz4_hash_table hash,
					 const u8 *ip)
{
	u32 *table = hash.ctx;
	size_t offset = ip - hash.base;

	swap(table[LZ4_HASH_VALUE(ip, table)], offset);
	return hash.base + offset;
}
#endif

static inline const u8 *hash_table_add16(const struct lz4_hash_table hash,
					 const u8 *ip)
{
	u16 *table = hash.ctx;
	size_t offset = ip - hash.base;

	swap(table[LZ4_HASH_VALUE(ip, table)], offset);
	return hash.base + offset;
}

static inline const u8 *try_match(const struct lz4_hash_table hash,
				  const u8 *ip)
{
	const u8 *ref = hash.add(hash, ip);

	return ref >= ip - MAX_DISTANCE &&
		A32(ref) == A32(ip) ? ref : NULL;
}

static inline const u8 *find_match(const struct lz4_hash_table hash,
				   const u8 **ip, const u8 *anchor,
				   const u8 *start, const u8 *end)
{

	int findmatchattempts = (1U << SKIPSTRENGTH) + 3;
	const u8 *next_ip = *ip, *ref;

	do {
		*ip = next_ip;
		next_ip += findmatchattempts++ >> SKIPSTRENGTH;

		if (unlikely(next_ip > end))
			return NULL;
	} while (!(ref = try_match(hash, *ip)));

	/* Catch up */
	while (*ip > anchor &&
	       ref > start &&
	       unlikely((*ip)[-1] == ref[-1])) {
		(*ip)--;
		ref--;
	}

	return ref;
}

/*
 * LZ4_compressCtx :
 * -----------------
 * Compress 'isize' bytes from 'source' into an output buffer 'dest' of
 * maximum size 'maxOutputSize'.  * If it cannot achieve it, compression
 * will stop, and result of the function will be zero.
 * return : the number of bytes written in buffer 'dest', or 0 if the
 * compression fails
 */
static inline int lz4_compressctx(const struct lz4_hash_table hash,
				  const u8 *source,
				  u8 *dest,
				  int isize,
				  int maxoutputsize)
{
	const u8 *ip = source;
	const u8 *anchor = ip, *ref;
	const u8 *const iend = ip + isize;
	const u8 *const mflimit = iend - MFLIMIT;
	const u8 *const matchlimit = iend - LASTLITERALS;
	u8 *op = dest;
	u8 *const oend = op + maxoutputsize;
	int length;
	u8 *token;

	/* Init */
	if (isize < MINLENGTH)
		goto _last_literals;

	memset(hash.ctx, 0, LZ4_MEM_COMPRESS);
	hash.add(hash, ip);

	/* Main Loop */
	while (1) {
		/* Starting a literal: */
		anchor = ip++;
		ref = find_match(hash, &ip, anchor, source, mflimit);
		if (!ref)
			goto _last_literals;

		/*
		 * We found a match; @ip now points to the match and @ref points
		 * to the prior part of the input we matched with. Everything up
		 * to @anchor has been encoded; the range from @anchor to @ip
		 * didn't match and now has to be encoded as a literal:
		 */
		length = ip - anchor;
		token = op++;

		/* check output limit */
		if (unlikely(op + length + (2 + 1 + LASTLITERALS) +
			     (length >> 8) > oend))
			return -1;

		*token = encode_length(&op, length) << ML_BITS;

		/* Copy Literals */
		MEMCPY_ADVANCE_CHUNKED(op, anchor, length);

		/* Encode matches: */
		while (1) {
			/* Match offset: */
			PUT_LE16_ADVANCE(op, ip - ref);

			/* MINMATCH bytes already matched from find_match(): */
			ip += MINMATCH;
			ref += MINMATCH;

			length = common_length(ip, ref, matchlimit);
			ip += length;

			/* Check output limit */
			if (unlikely(op + (1 + LASTLITERALS) +
				     (length >> 8) > oend))
				return -1;

			*token += encode_length(&op, length);

			/* Test end of chunk */
			if (ip > mflimit) {
				anchor = ip;
				break;
			}

			/* Fill table */
			hash.add(hash, ip - 2);

			/* Test next position */
			ref = try_match(hash, ip);
			if (!ref)
				break;

			token = op++;
			*token = 0;
		}
	}

_last_literals:
	/* Encode Last Literals */
	length = iend - anchor;
	if ((op - dest) + length + 1 +
	    ((length + 255 - RUN_MASK) / 255) > (u32)maxoutputsize)
		return -1;

	token = op++;
	*token = encode_length(&op, length) << ML_BITS;
	MEMCPY_ADVANCE(op, anchor, iend - anchor);

	/* End */
	return op - dest;
}

__attribute__((flatten))
int lz4_compress(const unsigned char *src, size_t src_len,
			unsigned char *dst, size_t *dst_len, void *wrkmem)
{
	int out_len = 0;

	if (src_len < LZ4_64KLIMIT) {
		const struct lz4_hash_table hash = {
			.add	= hash_table_add16,
			.ctx	= wrkmem,
			.base	= src,
		};

		out_len = lz4_compressctx(hash, src, dst, src_len, *dst_len);
	} else {
		const struct lz4_hash_table hash = {
			.add	= hash_table_add32,
			.ctx	= wrkmem,
			.base	= src,
		};

		out_len = lz4_compressctx(hash, src, dst, src_len, *dst_len);
	}

	if (out_len < 0)
		return -1;

	*dst_len = out_len;
	return 0;
}
EXPORT_SYMBOL(lz4_compress);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("LZ4 compressor");
