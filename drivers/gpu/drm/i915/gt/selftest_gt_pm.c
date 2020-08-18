
/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright © 2019 Intel Corporation
 */

#include "selftest_llc.h"
#include "selftest_rc6.h"
#include "selftest_rps.h"

static int live_gt_resume(void *arg)
{
	struct intel_gt *gt = arg;
	IGT_TIMEOUT(end_time);
	int err;

	/* Do several suspend/resume cycles to check we don't explode! */
	do {
		intel_gt_suspend_prepare(gt);
		intel_gt_suspend_late(gt);

		if (gt->rc6.enabled) {
			pr_err("rc6 still enabled after suspend!\n");
			intel_gt_set_wedged_on_init(gt);
			err = -EINVAL;
			break;
		}

		err = intel_gt_resume(gt);
		if (err)
			break;

		if (gt->rc6.supported && !gt->rc6.enabled) {
			pr_err("rc6 not enabled upon resume!\n");
			intel_gt_set_wedged_on_init(gt);
			err = -EINVAL;
			break;
		}

		err = st_llc_verify(&gt->llc);
		if (err) {
			pr_err("llc state not restored upon resume!\n");
			intel_gt_set_wedged_on_init(gt);
			break;
		}
	} while (!__igt_timeout(end_time, NULL));

	return err;
}

int intel_gt_pm_live_selftests(struct drm_i915_private *i915)
{
	static const struct i915_subtest tests[] = {
		SUBTEST(live_rc6_manual),
		SUBTEST(live_rps_clock_interval),
		SUBTEST(live_rps_control),
		SUBTEST(live_rps_frequency_cs),
		SUBTEST(live_rps_frequency_srm),
		SUBTEST(live_rps_power),
		SUBTEST(live_rps_interrupt),
		SUBTEST(live_rps_dynamic),
		SUBTEST(live_gt_resume),
	};

	if (intel_gt_is_wedged(&i915->gt))
		return 0;

	return intel_gt_live_subtests(tests, &i915->gt);
}

int intel_gt_pm_late_selftests(struct drm_i915_private *i915)
{
	static const struct i915_subtest tests[] = {
		/*
		 * These tests may leave the system in an undesirable state.
		 * They are intended to be run last in CI and the system
		 * rebooted afterwards.
		 */
		SUBTEST(live_rc6_ctx_wa),
	};

	if (intel_gt_is_wedged(&i915->gt))
		return 0;

	return intel_gt_live_subtests(tests, &i915->gt);
}
