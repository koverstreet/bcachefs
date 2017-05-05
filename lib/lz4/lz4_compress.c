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

static inline const u8 *find_match(const struct lz4_hash_table hash,
				   const u8 **ip, const u8 *anchor,
				   const u8 *start, const u8 *mflimit)
{
	int findmatchattempts = (1U << SKIPSTRENGTH) + 3;

	while (*ip <= mflimit) {
		const u8 *ref = hash.add(hash, *ip);

		if (ref >= *ip - MAX_DISTANCE && A32(ref) == A32(*ip)) {
			/* found match: */
			while (*ip > anchor &&
			       ref > start &&
			       unlikely((*ip)[-1] == ref[-1])) {
				(*ip)--;
				ref--;
			}

			return ref;
		}

		*ip += findmatchattempts++ >> SKIPSTRENGTH;
	}

	return NULL;
}

static inline int length_len(unsigned length)
{
	return length / 255 + 1;
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
				  const u8 *src, size_t src_len,
				  u8 *dst, size_t *dst_len)
{
	const u8 *ip = src, *anchor = ip, *ref;
	const u8 *const iend = ip + src_len;
	const u8 *const mflimit = iend - MFLIMIT;
	const u8 *const matchlimit = iend - LASTLITERALS;
	u8 *op = dst, *token;
	u8 *const oend = op + *dst_len;
	size_t literal_len, match_len, match_offset;

	/* Init */
	memset(hash.ctx, 0, LZ4_MEM_COMPRESS);
	hash.add(hash, ip);

	/* Always start with a literal: */
	ip++;

	while ((ref = find_match(hash, &ip, anchor, src, mflimit))) {
		/*
		 * We found a match; @ip now points to the match and @ref points
		 * to the prior part of the input we matched with. Everything up
		 * to @anchor has been encoded; the range from @anchor to @ip
		 * didn't match and now has to be encoded as a literal:
		 */
		literal_len = ip - anchor;
		match_offset = ip - ref;

		/* MINMATCH bytes already matched from find_match(): */
		ip += MINMATCH;
		ref += MINMATCH;
		match_len = common_length(ip, ref, matchlimit);
		ip += match_len;

		/* check output limit */
		if (unlikely(op +
			     1 + /* token */
			     2 + /* match ofset */
			     literal_len +
			     length_len(literal_len) +
			     length_len(match_len) +
			     LASTLITERALS > oend))
			break;

		token = op++;
		*token = encode_length(&op, literal_len) << ML_BITS;
		MEMCPY_ADVANCE_CHUNKED(op, anchor, literal_len);
		PUT_LE16_ADVANCE(op, match_offset);
		*token += encode_length(&op, match_len);

		anchor = ip;
	}

	/* Encode remaining input as literal: */
	literal_len = iend - anchor;
	if (unlikely(op +
		     1 +
		     literal_len +
		     length_len(literal_len) > oend)) {
		/* Return how much would be able to fit: */
		ssize_t remaining = oend - op;
		ssize_t encoded = anchor - src;

		remaining -= length_len(remaining) + 1;

		return -max(encoded + remaining, 1L);
	}

	token = op++;
	*token = encode_length(&op, literal_len) << ML_BITS;
	MEMCPY_ADVANCE(op, anchor, literal_len);

	/* End */
	BUG_ON(op > oend);
	*dst_len = op - dst;
	return 0;
}

__attribute__((flatten))
int lz4_compress(const unsigned char *src, size_t src_len,
		 unsigned char *dst, size_t *dst_len, void *wrkmem)
{
	if (src_len < LZ4_64KLIMIT) {
		const struct lz4_hash_table hash = {
			.add	= hash_table_add16,
			.ctx	= wrkmem,
			.base	= src,
		};

		return lz4_compressctx(hash, src, src_len, dst, dst_len);
	} else {
		const struct lz4_hash_table hash = {
			.add	= hash_table_add32,
			.ctx	= wrkmem,
			.base	= src,
		};

		return lz4_compressctx(hash, src, src_len, dst, dst_len);
	}
}
EXPORT_SYMBOL(lz4_compress);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("LZ4 compressor");
