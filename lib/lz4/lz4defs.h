/*
 * lz4defs.h -- architecture specific defines
 *
 * Copyright (C) 2013, LG Electronics, Kyungsik Lee <kyungsik.lee@lge.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/*
 * Detects 64 bits mode
 */
#if defined(CONFIG_64BIT)
#define LZ4_ARCH64 1
#else
#define LZ4_ARCH64 0
#endif

#include <asm/unaligned.h>

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

struct lz4_hashtable {
#if LZ4_ARCH64
	const u8 * const	base;
	u32			*table;
#else
	const int		base;
	const u8		*table;
#endif
};

#if LZ4_ARCH64
#define HTYPE u32
#else	/* 32-bit */
#define HTYPE const u8*
#endif

#ifdef __BIG_ENDIAN
#define LZ4_NBCOMMONBYTES(val) (__builtin_clzl(val) >> 3)
#else
#define LZ4_NBCOMMONBYTES(val) (__builtin_ctzl(val) >> 3)
#endif

static inline unsigned common_length(const u8 *l, const u8 *r,
				     const u8 *const l_end)
{
	const u8 *l_start = l;

	while (likely(l <= l_end - sizeof(long))) {
		unsigned long diff =
			get_unaligned((unsigned long *) l) ^
			get_unaligned((unsigned long *) r);

		if (diff)
			return l + LZ4_NBCOMMONBYTES(diff) - l_start;

		l += sizeof(long);
		r += sizeof(long);
	}
#if LZ4_ARCH64
	if (l <= l_end - 4 && A32(r) == A32(l)) {
		l += 4;
		r += 4;
	}
#endif
	if (l <= l_end - 2 && A16(r) == A16(l)) {
		l += 2;
		r += 2;
	}
	if (l <= l_end - 1 && *r == *l) {
		l++;
		r++;
	}

	return l - l_start;
}

static inline unsigned encode_length(u8 **op, unsigned length)
{
	if (length >= LENGTH_LONG) {
		length -= LENGTH_LONG;

		for (; length > 254 ; length -= 255)
			*(*op)++ = 255;
		*(*op)++ = length;
		return LENGTH_LONG;
	} else
		return length;
}
