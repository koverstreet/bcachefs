#include <kunit/test.h>
#include "util.h"

static void util_test_basic(struct kunit *test)
{
    u64 mean = 0;
    u64 var  = 0;
    u64 i;
    u64 val;

    for ( i = 100 ; i <= 540 ; i += 20 ) {
	    ewma_cal(&mean, &var, 8, i);
    }
    val = 119;
    KUNIT_EXPECT_GE(test, mean, val - val / 10);
    KUNIT_EXPECT_LE(test, mean, val + val / 10);

    val = 5442;
    KUNIT_EXPECT_GE(test, var, val - val / 10);
    KUNIT_EXPECT_LE(test, var, val + val / 10);

    mean = 0;
    var  = 0;

    for ( i = 1000 ; i <= 5400 ; i += 200 ) {
	    ewma_cal(&mean, &var, 8, i);
    }
    val = 1192;
    KUNIT_EXPECT_GE(test, mean, val - val / 100);
    KUNIT_EXPECT_LE(test, mean, val + val / 100);

    val = 544257;
    KUNIT_EXPECT_GE(test, var, val - val / 100);
    KUNIT_EXPECT_LE(test, var, val + val / 100);

}

static struct kunit_case util_test_cases[] = {
	KUNIT_CASE(util_test_basic),
	{}
};

static struct kunit_suite util_test_suite = {
.name = "util test cases",
.test_cases = util_test_cases
};

kunit_test_suite(util_test_suite);
