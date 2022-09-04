/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STATS_H_
#define STATS_H_

#include <linux/types.h>

#define SQRT_U64_MAX 4294967295ULL

struct mean_and_variance {
	s64 n;
	s64 sum;
	u64 sum_squares;
};

/* expontentially weighted variant */
struct mean_and_variance_ewm {
	bool init;
	u8 w;
	s64 mean;
	u64 variance;
};

#ifdef CONFIG_MEAN_AND_VARIANCE_UNIT_TEST
s64 fast_divpow2(s64 n, u8 d);
#endif

struct mean_and_variance mean_and_variance_update(struct mean_and_variance s1, s64 v1);
       s64		 get_mean(struct mean_and_variance s);
       u64		 get_variance(struct mean_and_variance s1);
       u32		 get_stddev(struct mean_and_variance s);

struct mean_and_variance_ewm mean_and_variance_ewm_update(struct mean_and_variance_ewm s1, s64 v1);
       s64		     get_ewm_mean(struct mean_and_variance_ewm s);
       u64		     get_ewm_variance(struct mean_and_variance_ewm s);
       u32		     get_ewm_stddev(struct mean_and_variance_ewm s);

#endif // STATS_H_
