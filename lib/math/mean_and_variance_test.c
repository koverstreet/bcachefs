// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/stats.h>

#define MAX_SQR (SQRT_U64_MAX*SQRT_U64_MAX)

static void stats_basic_test(struct kunit *test)
{
	struct mean_and_variance s = {};

	s = stats_update(s, 2);
	s = stats_update(s, 2);

	KUNIT_EXPECT_EQ(test, stats_mean(s), 2);
	KUNIT_EXPECT_EQ(test, stats_variance(s), 0);
	KUNIT_EXPECT_EQ(test, s.n, 2);

	s = stats_update(s, 4);
	s = stats_update(s, 4);

	KUNIT_EXPECT_EQ(test, stats_mean(s), 3);
	KUNIT_EXPECT_EQ(test, stats_variance(s), 1);
	KUNIT_EXPECT_EQ(test, s.n, 4);

	/*
	 * Test overflow bounds
	 */
	s = (struct mean_and_variance){};

	s = stats_update(s, SQRT_U64_MAX);

	KUNIT_EXPECT_EQ_MSG(test,
			    s.sum_squares,
			    MAX_SQR,
			    "%llu == %llu, sqrt: %llu == %llu",
			    s.sum_squares,
			    MAX_SQR,
			    int_sqrt64(s.sum_squares),
			    SQRT_U64_MAX);

	s = (struct mean_and_variance){};

	s = stats_update(s, -(s64)SQRT_U64_MAX);

	KUNIT_EXPECT_EQ_MSG(test,
			    s.sum_squares,
			    MAX_SQR,
			    "%llu == %llu, sqrt: %llu == %llu",
			    s.sum_squares,
			    MAX_SQR,
			    int_sqrt64(s.sum_squares),
			    SQRT_U64_MAX);

	s = (struct mean_and_variance){};

	s = stats_update(s, (SQRT_U64_MAX + 1));

	KUNIT_EXPECT_LT(test, s.sum_squares, MAX_SQR);

	s = (struct mean_and_variance){};

	s = stats_update(s, (-(s64)SQRT_U64_MAX) - 1);

	KUNIT_EXPECT_LT(test, s.sum_squares, MAX_SQR);
}

/*
 * Test values computed using a spreadsheet from the psuedocode at the bottom:
 * https://fanf2.user.srcf.net/hermes/doc/antiforgery/stats.pdf
 */

static void stats_ewm_test(struct kunit *test)
{
	struct mean_and_variance_ewm s = {};

	s.w = 2;

	s = stats_ewm_update(s, 10);
	KUNIT_EXPECT_EQ(test, stats_ewm_mean(s), 10);
	KUNIT_EXPECT_EQ(test, stats_ewm_variance(s), 0);

	s = stats_ewm_update(s, 20);
	KUNIT_EXPECT_EQ(test, stats_ewm_mean(s), 12);
	KUNIT_EXPECT_EQ(test, stats_ewm_variance(s), 18);

	s = stats_ewm_update(s, 30);
	KUNIT_EXPECT_EQ(test, stats_ewm_mean(s), 16);
	KUNIT_EXPECT_EQ(test, stats_ewm_variance(s), 71);

	s = (struct mean_and_variance_ewm){};
	s.w = 2;

	s = stats_ewm_update(s, -10);
	KUNIT_EXPECT_EQ(test, stats_ewm_mean(s), -10);
	KUNIT_EXPECT_EQ(test, stats_ewm_variance(s), 0);

	s = stats_ewm_update(s, -20);
	KUNIT_EXPECT_EQ(test, stats_ewm_mean(s), -12);
	KUNIT_EXPECT_EQ(test, stats_ewm_variance(s), 18);

	s = stats_ewm_update(s, -30);
	KUNIT_EXPECT_EQ(test, stats_ewm_mean(s), -16);
	KUNIT_EXPECT_EQ(test, stats_ewm_variance(s), 71);

}

static void stats_ewm_advanced_test(struct kunit *test)
{
	struct mean_and_variance_ewm s = {};
	s64 i;

	s.w = 8;
	for (i = 10; i <= 100; i += 10)
		s = stats_ewm_update(s, i);

	KUNIT_EXPECT_EQ(test, stats_ewm_mean(s), 11);
	KUNIT_EXPECT_EQ(test, stats_ewm_variance(s), 107);

	s = (struct mean_and_variance_ewm){};

	s.w = 8;
	for (i = -10; i >= -100; i -= 10)
		s = stats_ewm_update(s, i);

	KUNIT_EXPECT_EQ(test, stats_ewm_mean(s), -11);
	KUNIT_EXPECT_EQ(test, stats_ewm_variance(s), 107);

}

static void stats_fast_divpow2(struct kunit *test)
{
	s64 i;
	u8 d;

	for (i = 0; i < 100; i++) {
		d = 0;
		KUNIT_EXPECT_EQ(test, fast_divpow2(i, d), div_u64(i, 1LLU << d));
		KUNIT_EXPECT_EQ(test, abs(fast_divpow2(-i, d)), div_u64(i, 1LLU << d));
		for (d = 1; d < 32; d++) {
			KUNIT_EXPECT_EQ_MSG(test, abs(fast_divpow2(i, d)),
					    div_u64(i, 1 << d), "%lld %u", i, d);
			KUNIT_EXPECT_EQ_MSG(test, abs(fast_divpow2(-i, d)),
					    div_u64(i, 1 << d), "%lld %u", -i, d);
		}
	}
}

static struct kunit_case stats_test_cases[] = {
	KUNIT_CASE(stats_basic_test),
	KUNIT_CASE(stats_ewm_test),
	KUNIT_CASE(stats_ewm_advanced_test),
	KUNIT_CASE(stats_fast_divpow2),
	{}
};

static struct kunit_suite stats_test_suite = {
.name = "statistics",
.test_cases = stats_test_cases
};

kunit_test_suite(stats_test_suite);
