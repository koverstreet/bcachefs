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
#include <linux/lz4.h>

#include "lz4defs.h"

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

static inline ssize_t get_length_safe(const u8 **ip, ssize_t length)
{
	if (length == 15) {
		size_t len;

		do {
			length += (len = *(*ip)++);
			if (unlikely((ssize_t) length < 0))
				return -1;

			length += len;
		} while (len == 255);
	}

	return length;
}

static int lz4_uncompress_unknownoutputsize(const u8 *source, u8 *dest,
				int isize, size_t maxoutputsize)
{
	const u8 *ip = source;
	const u8 *const iend = ip + isize;
	const u8 *ref;
	u8 *op = dest;
	u8 * const oend = op + maxoutputsize;
	u8 *cpy;
	unsigned token, offset;
	size_t length;

	/* Main Loop */
	while (ip < iend) {
		/* get runlength */
		token = *ip++;
		length = get_length_safe(&ip, token >> ML_BITS);
		if (unlikely((ssize_t) length < 0))
			goto _output_error;

		/* copy literals */
		if ((op + length > oend - COPYLENGTH) ||
		    (ip + length > iend - COPYLENGTH)) {

			if (op + length > oend)
				goto _output_error;/* writes beyond buffer */

			if (ip + length != iend)
				goto _output_error;/*
						    * Error: LZ4 format requires
						    * to consume all input
						    * at this stage
						    */
			MEMCPY_ADVANCE(op, ip, length);
			break;/* Necessarily EOF, due to parsing restrictions */
		}
		MEMCPY_ADVANCE_CHUNKED(op, ip, length);

		/* get match offset */
		offset = GET_LE16_ADVANCE(ip);
		ref = op - offset;

		/* Error: offset create reference outside destination buffer */
		if (ref < (u8 * const) dest)
			goto _output_error;

		/* get match length */
		length = get_length_safe(&ip, token & ML_MASK);
		if (unlikely((ssize_t) length < 0))
			goto _output_error;

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
	return op - dest;

	/* write overflow error detected */
_output_error:
	return -1;
}

int lz4_decompress(const unsigned char *src, size_t *src_len,
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
#ifndef STATIC
EXPORT_SYMBOL(lz4_decompress);
#endif

int lz4_decompress_unknownoutputsize(const unsigned char *src, size_t src_len,
		unsigned char *dest, size_t *dest_len)
{
	int ret = -1;
	int out_len = 0;

	out_len = lz4_uncompress_unknownoutputsize(src, dest, src_len,
					*dest_len);
	if (out_len < 0)
		goto exit_0;
	*dest_len = out_len;

	return 0;
exit_0:
	return ret;
}
#ifndef STATIC
EXPORT_SYMBOL(lz4_decompress_unknownoutputsize);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("LZ4 Decompressor");
#endif
