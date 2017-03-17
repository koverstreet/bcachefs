/*
 * LZ4 Decompressor for Linux kernel
 *
 * Copyright (C) 2013, LG Electronics, Kyungsik Lee <kyungsik.lee@lge.com>
 *
 * Based on LZ4 implementation by Yann Collet.
 *
 * LZ4 - Fast LZ compression algorithm
 * Copyright (C) 2011-2012, Yann Collet.
 * BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
 *
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
 *  You can contact the author at :
 *  - LZ4 homepage : http://fastcompression.blogspot.com/p/lz4.html
 *  - LZ4 source repository : http://code.google.com/p/lz4/
 */

#ifndef STATIC
#include <linux/module.h>
#include <linux/kernel.h>
#endif

#include "lz4.h"

/*
 * Detects 64 bits mode
 */
#if defined(CONFIG_64BIT)
#define LZ4_ARCH64 1
#else
#define LZ4_ARCH64 0
#endif

#include <asm/unaligned.h>
#include <linux/log2.h>
#include <linux/string.h>

#define A32(_p) get_unaligned((u32 *) (_p))
#define A16(_p) get_unaligned((u16 *) (_p))

#define GET_LE16_ADVANCE(_src)				\
({							\
	u16 _r = get_unaligned_le16(_src);		\
	(_src) += 2;					\
	_r;						\
})

#define PUT_LE16_ADVANCE(_dst, _v)			\
do {							\
	put_unaligned_le16((_v), (_dst));		\
	(_dst) += 2;					\
} while (0)

#define LENGTH_LONG		15
#define COPYLENGTH		8
#define ML_BITS			4
#define ML_MASK			((1U << ML_BITS) - 1)
#define RUN_BITS		(8 - ML_BITS)
#define RUN_MASK		((1U << RUN_BITS) - 1)
#define MEMORY_USAGE		14
#define MINMATCH		4
#define SKIPSTRENGTH		6
#define LASTLITERALS		5
#define MFLIMIT			(COPYLENGTH + MINMATCH)
#define MINLENGTH		(MFLIMIT + 1)
#define MAXD_LOG		16
#define MAXD			(1 << MAXD_LOG)
#define MAXD_MASK		(u32)(MAXD - 1)
#define MAX_DISTANCE		(MAXD - 1)
#define HASH_LOG		(MAXD_LOG - 1)
#define HASHTABLESIZE		(1 << HASH_LOG)
#define MAX_NB_ATTEMPTS		256
#define OPTIMAL_ML		(int)((ML_MASK-1)+MINMATCH)
#define LZ4_64KLIMIT		((1<<16) + (MFLIMIT - 1))

#define __HASH_VALUE(p, bits)				\
	(((A32(p)) * 2654435761U) >> (32 - (bits)))

#define HASH_VALUE(p)		__HASH_VALUE(p, HASH_LOG)

#define MEMCPY_ADVANCE(_dst, _src, length)		\
do {							\
	typeof(length) _length = (length);		\
	memcpy(_dst, _src, _length);			\
	_src += _length;				\
	_dst += _length;				\
} while (0)

#define MEMCPY_ADVANCE_BYTES(_dst, _src, _length)	\
do {							\
	const u8 *_end = (_src) + (_length);		\
	while ((_src) < _end)				\
		*_dst++ = *_src++;			\
} while (0)

#define STEPSIZE		__SIZEOF_LONG__

#define LZ4_COPYPACKET(_src, _dst)			\
do {							\
	MEMCPY_ADVANCE(_dst, _src, STEPSIZE);		\
	MEMCPY_ADVANCE(_dst, _src, COPYLENGTH - STEPSIZE);\
} while (0)

/*
 * Equivalent to MEMCPY_ADVANCE - except may overrun @_dst and @_src by
 * COPYLENGTH:
 *
 * Note: src and dst may overlap (with src < dst) - we must do the copy in
 * STEPSIZE chunks for correctness
 *
 * Note also: length may be negative - we must not call memcpy if length is
 * negative, but still adjust dst and src by length
 */
#define MEMCPY_ADVANCE_CHUNKED(_dst, _src, _length)	\
do {							\
	u8 *_end = (_dst) + (_length);			\
	while ((_dst) < _end)				\
		LZ4_COPYPACKET(_src, _dst);		\
	_src -= (_dst) - _end;				\
	_dst = _end;					\
} while (0)

#define MEMCPY_ADVANCE_CHUNKED_NOFIXUP(_dst, _src, _end)\
do {							\
	while ((_dst) < (_end))				\
		LZ4_COPYPACKET((_src), (_dst));		\
} while (0)

static const int dec32table[8] = {0, 3, 2, 3, 0, 0, 0, 0};
#if LZ4_ARCH64
static const int dec64table[8] = {0, 0, 0, -1, 0, 1, 2, 3};
#else
static const int dec64table[8] = {0, 0, 0, 0, 0, 0, 0, 0};
#endif

static inline size_t get_length(const u8 **ip, size_t length)
{
	if (length == LENGTH_LONG) {
		size_t len;

		do {
			length += (len = *(*ip)++);
		} while (len == 255);
	}

	return length;
}

static int lz4_uncompress(const u8 *source, u8 *dest, int osize)
{
	const u8 *ip = source;
	const u8 *ref;
	u8 *op = dest;
	u8 * const oend = op + osize;
	u8 *cpy;
	unsigned token, offset;
	ssize_t length;

	while (1) {
		/* get runlength */
		token = *ip++;
		length = get_length(&ip, token >> ML_BITS);

		/* copy literals */
		if (unlikely(op + length > oend - COPYLENGTH)) {
			/*
			 * Error: not enough place for another match
			 * (min 4) + 5 literals
			 */
			if (op + length != oend)
				goto _output_error;

			MEMCPY_ADVANCE(op, ip, length);
			break; /* EOF */
		}
		MEMCPY_ADVANCE_CHUNKED(op, ip, length);

		/* get match offset */
		offset = GET_LE16_ADVANCE(ip);
		ref = op - offset;

		/* Error: offset create reference outside destination buffer */
		if (unlikely(ref < (u8 *const) dest))
			goto _output_error;

		/* get match length */
		length = get_length(&ip, token & ML_MASK);
		length += MINMATCH;

		/* copy first STEPSIZE bytes of match: */
		if (unlikely(offset < STEPSIZE)) {
			MEMCPY_ADVANCE_BYTES(op, ref, 4);
			ref -= dec32table[offset];

			memcpy(op, ref, 4);
			op += STEPSIZE - 4;
			ref -= dec64table[offset];
		} else {
			MEMCPY_ADVANCE(op, ref, STEPSIZE);
		}
		length -= STEPSIZE;
		/*
		 * Note - length could have been < STEPSIZE; that's ok, length
		 * will now be negative and we'll just end up rewinding op:
		 */

		/* copy rest of match: */
		cpy = op + length;
		if (cpy > oend - COPYLENGTH) {
			/* Error: request to write beyond destination buffer */
			if (cpy              > oend ||
			    ref + COPYLENGTH > oend)
				goto _output_error;
#if !LZ4_ARCH64
			if (op  + COPYLENGTH > oend)
				goto _output_error;
#endif
			MEMCPY_ADVANCE_CHUNKED_NOFIXUP(op, ref, oend - COPYLENGTH);
			/* op could be > cpy here */
			while (op < cpy)
				*op++ = *ref++;
			op = cpy;
			/*
			 * Check EOF (should never happen, since last 5 bytes
			 * are supposed to be literals)
			 */
			if (op == oend)
				goto _output_error;
		} else {
			MEMCPY_ADVANCE_CHUNKED(op, ref, length);
		}
	}
	/* end of decoding */
	return ip - source;

	/* write overflow error detected */
_output_error:
	return -1;
}

int bch2_lz4_decompress(const unsigned char *src, size_t *src_len,
			unsigned char *dest, size_t actual_dest_len)
{
	int ret = -1;
	int input_len = 0;

	input_len = lz4_uncompress(src, dest, actual_dest_len);
	if (input_len < 0)
		goto exit_0;
	*src_len = input_len;

	return 0;
exit_0:
	return ret;
}
