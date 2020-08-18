// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2012-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2018-2020 Linaro Ltd.
 */

#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/clk.h>
#include <linux/device.h>
#include <linux/interconnect.h>

#include "ipa.h"
#include "ipa_clock.h"
#include "ipa_modem.h"

/**
 * DOC: IPA Clocking
 *
 * The "IPA Clock" manages both the IPA core clock and the interconnects
 * (buses) the IPA depends on as a single logical entity.  A reference count
 * is incremented by "get" operations and decremented by "put" operations.
 * Transitions of that count from 0 to 1 result in the clock and interconnects
 * being enabled, and transitions of the count from 1 to 0 cause them to be
 * disabled.  We currently operate the core clock at a fixed clock rate, and
 * all buses at a fixed average and peak bandwidth.  As more advanced IPA
 * features are enabled, we can make better use of clock and bus scaling.
 *
 * An IPA clock reference must be held for any access to IPA hardware.
 */

#define	IPA_CORE_CLOCK_RATE		(75UL * 1000 * 1000)	/* Hz */

/* Interconnect path bandwidths (each times 1000 bytes per second) */
#define IPA_MEMORY_AVG			(80 * 1000)	/* 80 MBps */
#define IPA_MEMORY_PEAK			(600 * 1000)

#define IPA_IMEM_AVG			(80 * 1000)
#define IPA_IMEM_PEAK			(350 * 1000)

#define IPA_CONFIG_AVG			(40 * 1000)
#define IPA_CONFIG_PEAK			(40 * 1000)

/**
 * struct ipa_clock - IPA clocking information
 * @count:		Clocking reference count
 * @mutex;		Protects clock enable/disable
 * @core:		IPA core clock
 * @memory_path:	Memory interconnect
 * @imem_path:		Internal memory interconnect
 * @config_path:	Configuration space interconnect
 */
struct ipa_clock {
	atomic_t count;
	struct mutex mutex; /* protects clock enable/disable */
	struct clk *core;
	struct icc_path *memory_path;
	struct icc_path *imem_path;
	struct icc_path *config_path;
};

static struct icc_path *
ipa_interconnect_init_one(struct device *dev, const char *name)
{
	struct icc_path *path;

	path = of_icc_get(dev, name);
	if (IS_ERR(path))
		dev_err(dev, "error %ld getting %s interconnect\n",
			PTR_ERR(path), name);

	return path;
}

/* Initialize interconnects required for IPA operation */
static int ipa_interconnect_init(struct ipa_clock *clock, struct device *dev)
{
	struct icc_path *path;

	path = ipa_interconnect_init_one(dev, "memory");
	if (IS_ERR(path))
		goto err_return;
	clock->memory_path = path;

	path = ipa_interconnect_init_one(dev, "imem");
	if (IS_ERR(path))
		goto err_memory_path_put;
	clock->imem_path = path;

	path = ipa_interconnect_init_one(dev, "config");
	if (IS_ERR(path))
		goto err_imem_path_put;
	clock->config_path = path;

	return 0;

err_imem_path_put:
	icc_put(clock->imem_path);
err_memory_path_put:
	icc_put(clock->memory_path);
err_return:
	return PTR_ERR(path);
}

/* Inverse of ipa_interconnect_init() */
static void ipa_interconnect_exit(struct ipa_clock *clock)
{
	icc_put(clock->config_path);
	icc_put(clock->imem_path);
	icc_put(clock->memory_path);
}

/* Currently we only use one bandwidth level, so just "enable" interconnects */
static int ipa_interconnect_enable(struct ipa *ipa)
{
	struct ipa_clock *clock = ipa->clock;
	int ret;

	ret = icc_set_bw(clock->memory_path, IPA_MEMORY_AVG, IPA_MEMORY_PEAK);
	if (ret)
		return ret;

	ret = icc_set_bw(clock->imem_path, IPA_IMEM_AVG, IPA_IMEM_PEAK);
	if (ret)
		goto err_memory_path_disable;

	ret = icc_set_bw(clock->config_path, IPA_CONFIG_AVG, IPA_CONFIG_PEAK);
	if (ret)
		goto err_imem_path_disable;

	return 0;

err_imem_path_disable:
	(void)icc_set_bw(clock->imem_path, 0, 0);
err_memory_path_disable:
	(void)icc_set_bw(clock->memory_path, 0, 0);

	return ret;
}

/* To disable an interconnect, we just its bandwidth to 0 */
static int ipa_interconnect_disable(struct ipa *ipa)
{
	struct ipa_clock *clock = ipa->clock;
	int ret;

	ret = icc_set_bw(clock->memory_path, 0, 0);
	if (ret)
		return ret;

	ret = icc_set_bw(clock->imem_path, 0, 0);
	if (ret)
		goto err_memory_path_reenable;

	ret = icc_set_bw(clock->config_path, 0, 0);
	if (ret)
		goto err_imem_path_reenable;

	return 0;

err_imem_path_reenable:
	(void)icc_set_bw(clock->imem_path, IPA_IMEM_AVG, IPA_IMEM_PEAK);
err_memory_path_reenable:
	(void)icc_set_bw(clock->memory_path, IPA_MEMORY_AVG, IPA_MEMORY_PEAK);

	return ret;
}

/* Turn on IPA clocks, including interconnects */
static int ipa_clock_enable(struct ipa *ipa)
{
	int ret;

	ret = ipa_interconnect_enable(ipa);
	if (ret)
		return ret;

	ret = clk_prepare_enable(ipa->clock->core);
	if (ret)
		ipa_interconnect_disable(ipa);

	return ret;
}

/* Inverse of ipa_clock_enable() */
static void ipa_clock_disable(struct ipa *ipa)
{
	clk_disable_unprepare(ipa->clock->core);
	(void)ipa_interconnect_disable(ipa);
}

/* Get an IPA clock reference, but only if the reference count is
 * already non-zero.  Returns true if the additional reference was
 * added successfully, or false otherwise.
 */
bool ipa_clock_get_additional(struct ipa *ipa)
{
	return !!atomic_inc_not_zero(&ipa->clock->count);
}

/* Get an IPA clock reference.  If the reference count is non-zero, it is
 * incremented and return is immediate.  Otherwise it is checked again
 * under protection of the mutex, and if appropriate the clock (and
 * interconnects) are enabled suspended endpoints (if any) are resumed
 * before returning.
 *
 * Incrementing the reference count is intentionally deferred until
 * after the clock is running and endpoints are resumed.
 */
void ipa_clock_get(struct ipa *ipa)
{
	struct ipa_clock *clock = ipa->clock;
	int ret;

	/* If the clock is running, just bump the reference count */
	if (ipa_clock_get_additional(ipa))
		return;

	/* Otherwise get the mutex and check again */
	mutex_lock(&clock->mutex);

	/* A reference might have been added before we got the mutex. */
	if (ipa_clock_get_additional(ipa))
		goto out_mutex_unlock;

	ret = ipa_clock_enable(ipa);
	if (ret) {
		dev_err(&ipa->pdev->dev, "error %d enabling IPA clock\n", ret);
		goto out_mutex_unlock;
	}

	ipa_endpoint_resume(ipa);

	atomic_inc(&clock->count);

out_mutex_unlock:
	mutex_unlock(&clock->mutex);
}

/* Attempt to remove an IPA clock reference.  If this represents the last
 * reference, suspend endpoints and disable the clock (and interconnects)
 * under protection of a mutex.
 */
void ipa_clock_put(struct ipa *ipa)
{
	struct ipa_clock *clock = ipa->clock;

	/* If this is not the last reference there's nothing more to do */
	if (!atomic_dec_and_mutex_lock(&clock->count, &clock->mutex))
		return;

	ipa_endpoint_suspend(ipa);

	ipa_clock_disable(ipa);

	mutex_unlock(&clock->mutex);
}

/* Initialize IPA clocking */
struct ipa_clock *ipa_clock_init(struct device *dev)
{
	struct ipa_clock *clock;
	struct clk *clk;
	int ret;

	clk = clk_get(dev, "core");
	if (IS_ERR(clk)) {
		dev_err(dev, "error %ld getting core clock\n", PTR_ERR(clk));
		return ERR_CAST(clk);
	}

	ret = clk_set_rate(clk, IPA_CORE_CLOCK_RATE);
	if (ret) {
		dev_err(dev, "error %d setting core clock rate to %lu\n",
			ret, IPA_CORE_CLOCK_RATE);
		goto err_clk_put;
	}

	clock = kzalloc(sizeof(*clock), GFP_KERNEL);
	if (!clock) {
		ret = -ENOMEM;
		goto err_clk_put;
	}
	clock->core = clk;

	ret = ipa_interconnect_init(clock, dev);
	if (ret)
		goto err_kfree;

	mutex_init(&clock->mutex);
	atomic_set(&clock->count, 0);

	return clock;

err_kfree:
	kfree(clock);
err_clk_put:
	clk_put(clk);

	return ERR_PTR(ret);
}

/* Inverse of ipa_clock_init() */
void ipa_clock_exit(struct ipa_clock *clock)
{
	struct clk *clk = clock->core;

	WARN_ON(atomic_read(&clock->count) != 0);
	mutex_destroy(&clock->mutex);
	ipa_interconnect_exit(clock);
	kfree(clock);
	clk_put(clk);
}
