// SPDX-License-Identifier: GPL-2.0
/*
 * Functions for incremental mean and variance.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * Copyright © 2022 Daniel B. Hill
 *
 * Author: Daniel B. Hill <daniel@gluo.nz>
 *
 * Description:
 *
 * This is includes some incremental algorthims for mean and variance calculation
 *
 * Derived from the paper: https://fanf2.user.srcf.net/hermes/doc/antiforgery/stats.pdf
 *
 * Create a struct and if it's the ewm variant set the w field (weight = 2^k).
 *
 * Use mean_and_variance[_ewm]_update() on the struct to update it's state.
 *
 * Use the get_* functions to calculate the mean and variance, some computation
 * is deffered to these functions for peformance reasons.
 *
 * see lib/math/mean_and_variance_test.c for examples of usage.
 *
 * DO NOT access the mean and variance fields of the ewm variants directly.
 * DO NOT change the weight after calling update.
 */

#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/export.h>
#include <linux/limits.h>
#include <linux/math.h>
#include <linux/math64.h>
#include <linux/mean_and_variance.h>
#include <linux/module.h>
#include <linux/printbuf.h>


inline s64 fast_divpow2(s64 n, u8 d)
{
	return (n + ((n < 0) ? ((1 << d) - 1) : 0)) >> d; // + (n < 0 ? 1 : 0);
}

/**
 * mean_and_variance_update() - update a mean_and_variance struct @s1 with a new sample @v1
 * and return it.
 * @s1: the mean_and_variance to update.
 * @v1: the new sample.
 *
 * see linked pdf equation 12.
 **/
inline struct mean_and_variance mean_and_variance_update(struct mean_and_variance s1, s64 v1)
{
	struct mean_and_variance s2;
	u64 v2 = abs(v1);

	if (v2 > SQRT_U64_MAX) {
		v2 = SQRT_U64_MAX;
		WARN(true, "stats overflow! %lld^2 > U64_MAX", v1);
	}

	s2.n           = s1.n + 1;
	s2.sum         = s1.sum + v1;
	s2.sum_squares = s1.sum_squares + v2*v2;
	return s2;
}
EXPORT_SYMBOL_GPL(mean_and_variance_update);

/**
 *  get_mean() - get mean from @s
 */
inline s64 get_mean(struct mean_and_variance s)
{
	return s.sum / s.n;
}
EXPORT_SYMBOL_GPL(get_mean);

/**
 * get_variance() -  get variance from @s1
 *
 * see linked pdf equation 12.
 */
inline u64 get_variance(struct mean_and_variance s1)
{
	u64 s2 = s1.sum_squares / s1.n;
	u64 s3 = abs(get_mean(s1));

	WARN(s3 > SQRT_U64_MAX, "stats overflow %lld ^2 > S64_MAX", s3);
	return s2 - s3*s3;
}
EXPORT_SYMBOL_GPL(get_variance);

/**
 *  get_stddev() - get standard deviation from @s
 */
inline u32 get_stddev(struct mean_and_variance s)
{
	return int_sqrt64(get_variance(s));
}
EXPORT_SYMBOL_GPL(get_stddev);

/**
 * mean_and_variance_evm_update() - expontentially weighted variant of mean_and_variance_update()
 * @s1: ..
 * @s2: ..
 *
 * see linked pdf: function derived from equations 140-143 where alpha = 2^w.
 * values are stored bitshifted for performance and added precision.
 */
inline struct mean_and_variance_ewm mean_and_variance_ewm_update(struct mean_and_variance_ewm s1, s64 v1)
{
	struct mean_and_variance_ewm s2;
	s64 m = s1.mean;
	u64 var = s1.variance;
	u8 w = s2.w = s1.w;
	s64 v2 = v1 << w;
	s64 d1 = (v2 - m);
	s64 d2 = fast_divpow2(d1, w);
	u64 d3 = (d1*d1) >> w;

	if (!s1.init) {
		s2.mean = v2;
		s2.variance = 0;
	} else {
		s2.mean = m + d2;
		s2.variance = var + ((d3 - (d3 >> w) - var) >> w);
	}
	s2.init = true;

	#ifdef CONFIG_STATS_UNIT_TEST
	printk(KERN_DEBUG "v1 = %lld, v2 = %lld, d1 = %lld, d2 = %lld, d3 = %llu, m = %lld, var = %llu",
		   v1, v2, d1, d2, d3, s2.mean, s2.variance);
	#endif
	return s2;
}
EXPORT_SYMBOL_GPL(mean_and_variance_ewm_update);

/**
 *  get_ewm_mean() - get mean from @s
 */
inline s64 get_ewm_mean(struct mean_and_variance_ewm s)
{
	return fast_divpow2(s.mean, s.w);
}
EXPORT_SYMBOL_GPL(get_ewm_mean);

/**
 * get_ewm_variance() -- get variance from @s
 */
inline u64 get_ewm_variance(struct mean_and_variance_ewm s)
{
	// always positive don't need fast divpow2
	return s.variance >> s.w;
}
EXPORT_SYMBOL_GPL(get_ewm_variance);

/**
 * get_ewm_stddev() - get standard deviation from @s
 */
inline u32 get_ewm_stddev(struct mean_and_variance_ewm s)
{
	return int_sqrt64(get_ewm_variance(s));
}
EXPORT_SYMBOL_GPL(get_ewm_stddev);

MODULE_AUTHOR("Daniel B. Hill");
MODULE_LICENSE("GPL");
