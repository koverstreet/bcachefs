// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/mean_and_variance.h>

#define MAX_SQR (SQRT_U64_MAX*SQRT_U64_MAX)

static void mean_and_variance_basic_test(struct kunit *test)
{
	struct mean_and_variance s = {};

	s = mean_and_variance_update(s, 2);
	s = mean_and_variance_update(s, 2);

	KUNIT_EXPECT_EQ(test, mean_and_variance_get_mean(s), 2);
	KUNIT_EXPECT_EQ(test, mean_and_variance_get_variance(s), 0);
	KUNIT_EXPECT_EQ(test, s.n, 2);

	s = mean_and_variance_update(s, 4);
	s = mean_and_variance_update(s, 4);

	KUNIT_EXPECT_EQ(test, mean_and_variance_get_mean(s), 3);
	KUNIT_EXPECT_EQ(test, mean_and_variance_get_variance(s), 1);
	KUNIT_EXPECT_EQ(test, s.n, 4);

	/*
	 * Test overflow bounds
	 */
	s = (struct mean_and_variance){};

	s = mean_and_variance_update(s, SQRT_U64_MAX);

	KUNIT_EXPECT_EQ_MSG(test,
			    s.sum_squares.lo,
			    MAX_SQR,
			    "%llu == %llu, sqrt: %llu == %llu",
			    s.sum_squares.lo,
			    MAX_SQR,
			    int_sqrt64(s.sum_squares.lo),
			    SQRT_U64_MAX);

	s = (struct mean_and_variance){};

	s = mean_and_variance_update(s, -(s64)SQRT_U64_MAX);

	KUNIT_EXPECT_EQ_MSG(test,
			    s.sum_squares.lo,
			    MAX_SQR,
			    "%llu == %llu, sqrt: %llu == %llu",
			    s.sum_squares.lo,
			    MAX_SQR,
			    int_sqrt64(s.sum_squares.lo),
			    SQRT_U64_MAX);

	s = (struct mean_and_variance){};

	s = mean_and_variance_update(s, (SQRT_U64_MAX + 1));

	KUNIT_EXPECT_EQ(test, s.sum_squares.lo, MAX_SQR);

	s = (struct mean_and_variance){};

	s = mean_and_variance_update(s, (-(s64)SQRT_U64_MAX) - 1);

	KUNIT_EXPECT_EQ(test, s.sum_squares.lo, MAX_SQR);
}

/*
 * Test values computed using a spreadsheet from the psuedocode at the bottom:
 * https://fanf2.user.srcf.net/hermes/doc/antiforgery/stats.pdf
 */

static void mean_and_variance_weighted_test(struct kunit *test)
{
	struct mean_and_variance_weighted s = {};

	s.w = 2;

	s = mean_and_variance_weighted_update(s, 10);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_mean(s), 10);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_variance(s), 0);

	s = mean_and_variance_weighted_update(s, 20);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_mean(s), 12);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_variance(s), 18);

	s = mean_and_variance_weighted_update(s, 30);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_mean(s), 16);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_variance(s), 71);

	s = (struct mean_and_variance_weighted){};
	s.w = 2;

	s = mean_and_variance_weighted_update(s, -10);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_mean(s), -10);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_variance(s), 0);

	s = mean_and_variance_weighted_update(s, -20);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_mean(s), -12);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_variance(s), 18);

	s = mean_and_variance_weighted_update(s, -30);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_mean(s), -16);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_variance(s), 71);

}

static void mean_and_variance_weighted_advanced_test(struct kunit *test)
{
	struct mean_and_variance_weighted s = {};
	s64 i;

	s.w = 8;
	for (i = 10; i <= 100; i += 10)
		s = mean_and_variance_weighted_update(s, i);

	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_mean(s), 11);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_variance(s), 107);

	s = (struct mean_and_variance_weighted){};

	s.w = 8;
	for (i = -10; i >= -100; i -= 10)
		s = mean_and_variance_weighted_update(s, i);

	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_mean(s), -11);
	KUNIT_EXPECT_EQ(test, mean_and_variance_weighted_get_variance(s), 107);

}

static void mean_and_variance_fast_divpow2(struct kunit *test)
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

static void mean_and_variance_u128_test(struct kunit *test)
{
	u128 a = u128_init(0, U64_MAX);
	u128 a0 = u128_init(0, 0);
	u128 a1 = u128_init(0, 1);
	u128 a2 = u128_init(0, 2);
	u128 b = u128_init(1, 0);
	u128 c = u128_init(0, 1LLU << 63);

	KUNIT_EXPECT_EQ(test, u128_add(a,a1).hi, 1);
	KUNIT_EXPECT_EQ(test, u128_add(a,a1).lo, 0);
	KUNIT_EXPECT_EQ(test, u128_sub(b,a1).lo, U64_MAX);
	KUNIT_EXPECT_EQ(test, u128_sub(b,a1).hi, 0);

	KUNIT_EXPECT_EQ(test, u128_shl(c, 1).hi, 1 );
	KUNIT_EXPECT_EQ(test, u128_shl(c, 1).lo, 0 );

	KUNIT_EXPECT_EQ(test, u128_square(1).hi, 0);
	KUNIT_EXPECT_EQ(test, u128_square(1).lo, 1);

	KUNIT_EXPECT_EQ(test, u128_square(0).hi, 0);
	KUNIT_EXPECT_EQ(test, u128_square(0).lo, 0);

	KUNIT_EXPECT_EQ(test, u128_square(2).lo, 4);

	KUNIT_EXPECT_EQ(test, u128_square(U64_MAX).hi, U64_MAX);
	KUNIT_EXPECT_EQ(test, u128_square(U64_MAX).lo, 1);


	KUNIT_EXPECT_EQ(test, u128_div(b, 2).lo, 1LLU << 63);
}

static struct kunit_case mean_and_variance_test_cases[] = {
	KUNIT_CASE(mean_and_variance_fast_divpow2),
	KUNIT_CASE(mean_and_variance_u128_test),
	KUNIT_CASE(mean_and_variance_basic_test),
	KUNIT_CASE(mean_and_variance_weighted_test),
	KUNIT_CASE(mean_and_variance_weighted_advanced_test),
	{}
};

static struct kunit_suite mean_and_variance_test_suite = {
.name = "mean and variance tests",
.test_cases = mean_and_variance_test_cases
};

kunit_test_suite(mean_and_variance_test_suite);
