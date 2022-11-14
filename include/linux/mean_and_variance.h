/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MEAN_AND_VARIANCE_H_
#define MEAN_AND_VARIANCE_H_

#include <linux/types.h>
#include <linux/limits.h>
#include <linux/math64.h>
#include <linux/printbuf.h>

#define SQRT_U64_MAX 4294967295ULL


#if defined(CONFIG_ARCH_SUPPORTS_INT128) && defined(__SIZEOF_INT128__)

typedef unsigned __int128 u128;

static inline u128 u64_to_u128(u64 a)
{
	return (u128)a;
}

static inline u64 u128_to_u64(u128 a)
{
	return (u64)a;
}

static inline u64 u128_shr64_to_u64(u128 a)
{
	return (u64)(a >> 64);
}

static inline u128 u128_add(u128 a, u128 b)
{
	return a + b;
}

static inline u128 u128_sub(u128 a, u128 b)
{
	return a - b;
}

static inline u128 u128_shl(u128 i, s8 shift)
{
	return i << shift;
}

static inline u128 u128_shl64_add(u64 a, u64 b)
{
	return ((u128)a << 64) + b;
}

static inline u128 u128_square(u64 i)
{
	return i*i;
}

#else

typedef struct {
	u64 hi, lo;
} u128;

static inline u128 u64_to_u128(u64 a)
{
	return (u128){ .lo = a };
}

static inline u64 u128_to_u64(u128 a)
{
	return a.lo;
}

static inline u64 u128_shr64_to_u64(u128 a)
{
	return a.hi;
}

static inline u128 u128_add(u128 a, u128 b)
{
	u128 c;

	c.lo = a.lo + b.lo;
	c.hi = a.hi + b.hi + (c.lo < a.lo);
	return c;
}

static inline u128 u128_sub(u128 a, u128 b)
{
	u128 c;

	c.lo = a.lo - b.lo;
	c.hi = a.hi - b.hi - (c.lo > a.lo);
	return c;
}

static inline u128 u128_shl(u128 i, s8 shift)
{
	u128 r;

	r.lo = i.lo << shift;
	if (shift < 64)
		r.hi = (i.hi << shift) | (i.lo >> (64 - shift));
	else {
		r.hi = i.lo << (shift - 64);
		r.lo = 0;
	}
	return r;
}

static inline u128 u128_shl64_add(u64 a, u64 b)
{
	return u128_add(u128_shl(u64_to_u128(a), 64), u64_to_u128(b));
}

static inline u128 u128_square(u64 i)
{
	u128 r;
	u64  h = i >> 32, l = i & (u64)U32_MAX;

	r =             u128_shl(u64_to_u128(h*h), 64);
	r = u128_add(r, u128_shl(u64_to_u128(h*l), 32));
	r = u128_add(r, u128_shl(u64_to_u128(l*h), 32));
	r = u128_add(r,          u64_to_u128(l*l));
	return r;
}

#endif

static inline u128 u128_div(u128 n, u64 d)
{
	u128 r;
	u64 rem;
	u64 hi = u128_shr64_to_u64(n);
	u64 lo = u128_to_u64(n);
	u64  h =  hi & ((u64)U32_MAX  << 32);
	u64  l = (hi &  (u64)U32_MAX) << 32;

	r =             u128_shl(u64_to_u128(div64_u64_rem(h,                d, &rem)), 64);
	r = u128_add(r, u128_shl(u64_to_u128(div64_u64_rem(l  + (rem << 32), d, &rem)), 32));
	r = u128_add(r,          u64_to_u128(div64_u64_rem(lo + (rem << 32), d, &rem)));
	return r;
}

struct mean_and_variance {
	s64 n;
	s64 sum;
	u128 sum_squares;
};

/* expontentially weighted variant */
struct mean_and_variance_weighted {
	bool init;
	u8 w;
	s64 mean;
	u64 variance;
};

s64 fast_divpow2(s64 n, u8 d);

struct mean_and_variance mean_and_variance_update(struct mean_and_variance s1, s64 v1);
       s64		 mean_and_variance_get_mean(struct mean_and_variance s);
       u64		 mean_and_variance_get_variance(struct mean_and_variance s1);
       u32		 mean_and_variance_get_stddev(struct mean_and_variance s);

struct mean_and_variance_weighted mean_and_variance_weighted_update(struct mean_and_variance_weighted s1, s64 v1);
       s64			  mean_and_variance_weighted_get_mean(struct mean_and_variance_weighted s);
       u64			  mean_and_variance_weighted_get_variance(struct mean_and_variance_weighted s);
       u32			  mean_and_variance_weighted_get_stddev(struct mean_and_variance_weighted s);

#endif // MEAN_AND_VAIRANCE_H_
