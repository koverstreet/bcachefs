/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MEAN_AND_VARIANCE_H_
#define MEAN_AND_VAIRANCE_H_

#include <linux/types.h>
#include <linux/limits.h>
#include <linux/math64.h>
#include <linux/printbuf.h>

#define SQRT_U64_MAX 4294967295ULL

//#ifdef __SIZEOF_INT128__

//typedef unsigned __int128 u128;

//#else

typedef struct {
	u64 hi;
	u64 lo;
} u128;

static inline u128 u64_to_128(u64 a)
{
	return (u128){ lo = a };
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
	c.hi = a.hi - (b.hi + c.lo > a.lo);
	return c;
}

static inline u128 u128_shl(u128 i, s8 shift)
{
	u128 r;
	if (shift < 64) {
		r.lo = i.lo << s1;
		r.hi = (i.hi << s1) + (i.lo >> (64 - shift));
	} else {
		r.lo = 0;
		r.hi = i.lo << (shift - 64);
	}
	return r;
}

static inline u128 u128_square(u64 x)
{
	u128 r = { 0 };
	u64  x0 = i >> 32, 0 = i & (u64)U32_MAX;

	r = u128_add(r, u128_shl(u64_to_u128(x0 * x0), 0));
	r = u128_add(r, u128_shl(u64_to_u128(x0 * x1), 32));
	r = u128_add(r, u128_shl(u64_to_u128(x0 * x1), 32));
	r = u128_add(r, u128_shl(u64_to_u128(x1 * x1), 64));
	return r;
}

static inline u128 u128_div(u128 n, u64 d) {
	u128 result;
	u64 r;
	u64 rem;
	u64  hh = n.hi & ((u64)U32_MAX << 32), hl = (n.hi & (u64)U32_MAX),
	     lh = n.lo & ((u64)U32_MAX << 32), ll = (n.lo & (u64)U32_MAX);
	printk("divide: %llu::%llu / %llu", n.hi, n.lo, d);
	printk("hi = %llu, hh = %llu, hl = %llu, hh+hl = %llu\n", n.hi, hh, hl, hh+hl);
	r = div64_u64_rem(hh, d, &rem);
	result.hi = r;
	printk("hi = %llu, r = %llu, rem = %llu \n", result.hi, r, rem);
	r = div64_u64_rem(((hl + rem) << 32), d, &rem);
	result.hi += r >> 32;
	printk("hi = %llu, r = %llu, rem = %llu \n", result.hi, r, rem);
	r = div64_u64_rem((n.lo + ((rem) << 32)), d, &rem) + (r << 32);
	result.lo = r;
	printk("lo = %llu, r = %llu, rem = %llu \n", result.hi, r, rem);
	return result;
}
//#endif

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

#ifdef CONFIG_MEAN_AND_VARIANCE_UNIT_TEST
s64 fast_divpow2(s64 n, u8 d);
#endif

struct mean_and_variance mean_and_variance_update(struct mean_and_variance s1, s64 v1);
       s64		 mean_and_variance_get_mean(struct mean_and_variance s);
       u64		 mean_and_variance_get_variance(struct mean_and_variance s1);
       u32		 mean_and_variance_get_stddev(struct mean_and_variance s);

struct mean_and_variance_weighted mean_and_variance_weighted_update(struct mean_and_variance_weighted s1, s64 v1);
       s64			  mean_and_variance_weighted_get_mean(struct mean_and_variance_weighted s);
       u64			  mean_and_variance_weighted_get_variance(struct mean_and_variance_weighted s);
       u32			  mean_and_variance_weighted_get_stddev(struct mean_and_variance_weighted s);



#endif // MEAN_AND_VAIRANCE_H_
