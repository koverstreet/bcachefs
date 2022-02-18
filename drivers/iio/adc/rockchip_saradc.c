// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Rockchip Successive Approximation Register (SAR) A/D Converter
 * Copyright (C) 2014 ROCKCHIP, Inc.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/reset.h>
#include <linux/regulator/consumer.h>
#include <linux/iio/buffer.h>
#include <linux/iio/iio.h>
#include <linux/iio/trigger_consumer.h>
#include <linux/iio/triggered_buffer.h>

#define SARADC_DATA			0x00

#define SARADC_STAS			0x04
#define SARADC_STAS_BUSY		BIT(0)

#define SARADC_CTRL			0x08
#define SARADC_CTRL_IRQ_STATUS		BIT(6)
#define SARADC_CTRL_IRQ_ENABLE		BIT(5)
#define SARADC_CTRL_POWER_CTRL		BIT(3)
#define SARADC_CTRL_CHN_MASK		0x7

#define SARADC_DLY_PU_SOC		0x0c
#define SARADC_DLY_PU_SOC_MASK		0x3f

#define SARADC_TIMEOUT			msecs_to_jiffies(100)
#define SARADC_MAX_CHANNELS		8

struct rockchip_saradc_data {
	const struct iio_chan_spec	*channels;
	int				num_channels;
	unsigned long			clk_rate;
};

struct rockchip_saradc {
	void __iomem		*regs;
	struct clk		*pclk;
	struct clk		*clk;
	struct completion	completion;
	struct regulator	*vref;
	int			uv_vref;
	struct reset_control	*reset;
	const struct rockchip_saradc_data *data;
	u16			last_val;
	const struct iio_chan_spec *last_chan;
	struct notifier_block nb;
};

static void rockchip_saradc_power_down(struct rockchip_saradc *info)
{
	/* Clear irq & power down adc */
	writel_relaxed(0, info->regs + SARADC_CTRL);
}

static int rockchip_saradc_conversion(struct rockchip_saradc *info,
				   struct iio_chan_spec const *chan)
{
	reinit_completion(&info->completion);

	/* 8 clock periods as delay between power up and start cmd */
	writel_relaxed(8, info->regs + SARADC_DLY_PU_SOC);

	info->last_chan = chan;

	/* Select the channel to be used and trigger conversion */
	writel(SARADC_CTRL_POWER_CTRL
			| (chan->channel & SARADC_CTRL_CHN_MASK)
			| SARADC_CTRL_IRQ_ENABLE,
		   info->regs + SARADC_CTRL);

	if (!wait_for_completion_timeout(&info->completion, SARADC_TIMEOUT))
		return -ETIMEDOUT;

	return 0;
}

static int rockchip_saradc_read_raw(struct iio_dev *indio_dev,
				    struct iio_chan_spec const *chan,
				    int *val, int *val2, long mask)
{
	struct rockchip_saradc *info = iio_priv(indio_dev);
	int ret;

	switch (mask) {
	case IIO_CHAN_INFO_RAW:
		mutex_lock(&indio_dev->mlock);

		ret = rockchip_saradc_conversion(info, chan);
		if (ret) {
			rockchip_saradc_power_down(info);
			mutex_unlock(&indio_dev->mlock);
			return ret;
		}

		*val = info->last_val;
		mutex_unlock(&indio_dev->mlock);
		return IIO_VAL_INT;
	case IIO_CHAN_INFO_SCALE:
		*val = info->uv_vref / 1000;
		*val2 = chan->scan_type.realbits;
		return IIO_VAL_FRACTIONAL_LOG2;
	default:
		return -EINVAL;
	}
}

static irqreturn_t rockchip_saradc_isr(int irq, void *dev_id)
{
	struct rockchip_saradc *info = dev_id;

	/* Read value */
	info->last_val = readl_relaxed(info->regs + SARADC_DATA);
	info->last_val &= GENMASK(info->last_chan->scan_type.realbits - 1, 0);

	rockchip_saradc_power_down(info);

	complete(&info->completion);

	return IRQ_HANDLED;
}

static const struct iio_info rockchip_saradc_iio_info = {
	.read_raw = rockchip_saradc_read_raw,
};

#define SARADC_CHANNEL(_index, _id, _res) {			\
	.type = IIO_VOLTAGE,					\
	.indexed = 1,						\
	.channel = _index,					\
	.info_mask_separate = BIT(IIO_CHAN_INFO_RAW),		\
	.info_mask_shared_by_type = BIT(IIO_CHAN_INFO_SCALE),	\
	.datasheet_name = _id,					\
	.scan_index = _index,					\
	.scan_type = {						\
		.sign = 'u',					\
		.realbits = _res,				\
		.storagebits = 16,				\
		.endianness = IIO_CPU,				\
	},							\
}

static const struct iio_chan_spec rockchip_saradc_iio_channels[] = {
	SARADC_CHANNEL(0, "adc0", 10),
	SARADC_CHANNEL(1, "adc1", 10),
	SARADC_CHANNEL(2, "adc2", 10),
};

static const struct rockchip_saradc_data saradc_data = {
	.channels = rockchip_saradc_iio_channels,
	.num_channels = ARRAY_SIZE(rockchip_saradc_iio_channels),
	.clk_rate = 1000000,
};

static const struct iio_chan_spec rockchip_rk3066_tsadc_iio_channels[] = {
	SARADC_CHANNEL(0, "adc0", 12),
	SARADC_CHANNEL(1, "adc1", 12),
};

static const struct rockchip_saradc_data rk3066_tsadc_data = {
	.channels = rockchip_rk3066_tsadc_iio_channels,
	.num_channels = ARRAY_SIZE(rockchip_rk3066_tsadc_iio_channels),
	.clk_rate = 50000,
};

static const struct iio_chan_spec rockchip_rk3399_saradc_iio_channels[] = {
	SARADC_CHANNEL(0, "adc0", 10),
	SARADC_CHANNEL(1, "adc1", 10),
	SARADC_CHANNEL(2, "adc2", 10),
	SARADC_CHANNEL(3, "adc3", 10),
	SARADC_CHANNEL(4, "adc4", 10),
	SARADC_CHANNEL(5, "adc5", 10),
};

static const struct rockchip_saradc_data rk3399_saradc_data = {
	.channels = rockchip_rk3399_saradc_iio_channels,
	.num_channels = ARRAY_SIZE(rockchip_rk3399_saradc_iio_channels),
	.clk_rate = 1000000,
};

static const struct iio_chan_spec rockchip_rk3568_saradc_iio_channels[] = {
	SARADC_CHANNEL(0, "adc0", 10),
	SARADC_CHANNEL(1, "adc1", 10),
	SARADC_CHANNEL(2, "adc2", 10),
	SARADC_CHANNEL(3, "adc3", 10),
	SARADC_CHANNEL(4, "adc4", 10),
	SARADC_CHANNEL(5, "adc5", 10),
	SARADC_CHANNEL(6, "adc6", 10),
	SARADC_CHANNEL(7, "adc7", 10),
};

static const struct rockchip_saradc_data rk3568_saradc_data = {
	.channels = rockchip_rk3568_saradc_iio_channels,
	.num_channels = ARRAY_SIZE(rockchip_rk3568_saradc_iio_channels),
	.clk_rate = 1000000,
};

static const struct of_device_id rockchip_saradc_match[] = {
	{
		.compatible = "rockchip,saradc",
		.data = &saradc_data,
	}, {
		.compatible = "rockchip,rk3066-tsadc",
		.data = &rk3066_tsadc_data,
	}, {
		.compatible = "rockchip,rk3399-saradc",
		.data = &rk3399_saradc_data,
	}, {
		.compatible = "rockchip,rk3568-saradc",
		.data = &rk3568_saradc_data,
	},
	{},
};
MODULE_DEVICE_TABLE(of, rockchip_saradc_match);

/*
 * Reset SARADC Controller.
 */
static void rockchip_saradc_reset_controller(struct reset_control *reset)
{
	reset_control_assert(reset);
	usleep_range(10, 20);
	reset_control_deassert(reset);
}

static void rockchip_saradc_clk_disable(void *data)
{
	struct rockchip_saradc *info = data;

	clk_disable_unprepare(info->clk);
}

static void rockchip_saradc_pclk_disable(void *data)
{
	struct rockchip_saradc *info = data;

	clk_disable_unprepare(info->pclk);
}

static void rockchip_saradc_regulator_disable(void *data)
{
	struct rockchip_saradc *info = data;

	regulator_disable(info->vref);
}

static irqreturn_t rockchip_saradc_trigger_handler(int irq, void *p)
{
	struct iio_poll_func *pf = p;
	struct iio_dev *i_dev = pf->indio_dev;
	struct rockchip_saradc *info = iio_priv(i_dev);
	/*
	 * @values: each channel takes an u16 value
	 * @timestamp: will be 8-byte aligned automatically
	 */
	struct {
		u16 values[SARADC_MAX_CHANNELS];
		int64_t timestamp;
	} data;
	int ret;
	int i, j = 0;

	mutex_lock(&i_dev->mlock);

	for_each_set_bit(i, i_dev->active_scan_mask, i_dev->masklength) {
		const struct iio_chan_spec *chan = &i_dev->channels[i];

		ret = rockchip_saradc_conversion(info, chan);
		if (ret) {
			rockchip_saradc_power_down(info);
			goto out;
		}

		data.values[j] = info->last_val;
		j++;
	}

	iio_push_to_buffers_with_timestamp(i_dev, &data, iio_get_time_ns(i_dev));
out:
	mutex_unlock(&i_dev->mlock);

	iio_trigger_notify_done(i_dev->trig);

	return IRQ_HANDLED;
}

static int rockchip_saradc_volt_notify(struct notifier_block *nb,
						   unsigned long event,
						   void *data)
{
	struct rockchip_saradc *info =
			container_of(nb, struct rockchip_saradc, nb);

	if (event & REGULATOR_EVENT_VOLTAGE_CHANGE)
		info->uv_vref = (unsigned long)data;

	return NOTIFY_OK;
}

static void rockchip_saradc_regulator_unreg_notifier(void *data)
{
	struct rockchip_saradc *info = data;

	regulator_unregister_notifier(info->vref, &info->nb);
}

static int rockchip_saradc_probe(struct platform_device *pdev)
{
	struct rockchip_saradc *info = NULL;
	struct device_node *np = pdev->dev.of_node;
	struct iio_dev *indio_dev = NULL;
	const struct of_device_id *match;
	int ret;
	int irq;

	if (!np)
		return -ENODEV;

	indio_dev = devm_iio_device_alloc(&pdev->dev, sizeof(*info));
	if (!indio_dev) {
		dev_err(&pdev->dev, "failed allocating iio device\n");
		return -ENOMEM;
	}
	info = iio_priv(indio_dev);

	match = of_match_device(rockchip_saradc_match, &pdev->dev);
	if (!match) {
		dev_err(&pdev->dev, "failed to match device\n");
		return -ENODEV;
	}

	info->data = match->data;

	/* Sanity check for possible later IP variants with more channels */
	if (info->data->num_channels > SARADC_MAX_CHANNELS) {
		dev_err(&pdev->dev, "max channels exceeded");
		return -EINVAL;
	}

	info->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(info->regs))
		return PTR_ERR(info->regs);

	/*
	 * The reset should be an optional property, as it should work
	 * with old devicetrees as well
	 */
	info->reset = devm_reset_control_get_exclusive(&pdev->dev,
						       "saradc-apb");
	if (IS_ERR(info->reset)) {
		ret = PTR_ERR(info->reset);
		if (ret != -ENOENT)
			return dev_err_probe(&pdev->dev, ret,
					     "failed to get saradc-apb\n");

		dev_dbg(&pdev->dev, "no reset control found\n");
		info->reset = NULL;
	}

	init_completion(&info->completion);

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return dev_err_probe(&pdev->dev, irq, "failed to get irq\n");

	ret = devm_request_irq(&pdev->dev, irq, rockchip_saradc_isr,
			       0, dev_name(&pdev->dev), info);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed requesting irq %d\n", irq);
		return ret;
	}

	info->pclk = devm_clk_get(&pdev->dev, "apb_pclk");
	if (IS_ERR(info->pclk))
		return dev_err_probe(&pdev->dev, PTR_ERR(info->pclk),
				     "failed to get pclk\n");

	info->clk = devm_clk_get(&pdev->dev, "saradc");
	if (IS_ERR(info->clk))
		return dev_err_probe(&pdev->dev, PTR_ERR(info->clk),
				     "failed to get adc clock\n");

	info->vref = devm_regulator_get(&pdev->dev, "vref");
	if (IS_ERR(info->vref))
		return dev_err_probe(&pdev->dev, PTR_ERR(info->vref),
				     "failed to get regulator\n");

	if (info->reset)
		rockchip_saradc_reset_controller(info->reset);

	/*
	 * Use a default value for the converter clock.
	 * This may become user-configurable in the future.
	 */
	ret = clk_set_rate(info->clk, info->data->clk_rate);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed to set adc clk rate, %d\n", ret);
		return ret;
	}

	ret = regulator_enable(info->vref);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed to enable vref regulator\n");
		return ret;
	}
	ret = devm_add_action_or_reset(&pdev->dev,
				       rockchip_saradc_regulator_disable, info);
	if (ret) {
		dev_err(&pdev->dev, "failed to register devm action, %d\n",
			ret);
		return ret;
	}

	ret = regulator_get_voltage(info->vref);
	if (ret < 0)
		return ret;

	info->uv_vref = ret;

	ret = clk_prepare_enable(info->pclk);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed to enable pclk\n");
		return ret;
	}
	ret = devm_add_action_or_reset(&pdev->dev,
				       rockchip_saradc_pclk_disable, info);
	if (ret) {
		dev_err(&pdev->dev, "failed to register devm action, %d\n",
			ret);
		return ret;
	}

	ret = clk_prepare_enable(info->clk);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed to enable converter clock\n");
		return ret;
	}
	ret = devm_add_action_or_reset(&pdev->dev,
				       rockchip_saradc_clk_disable, info);
	if (ret) {
		dev_err(&pdev->dev, "failed to register devm action, %d\n",
			ret);
		return ret;
	}

	platform_set_drvdata(pdev, indio_dev);

	indio_dev->name = dev_name(&pdev->dev);
	indio_dev->info = &rockchip_saradc_iio_info;
	indio_dev->modes = INDIO_DIRECT_MODE;

	indio_dev->channels = info->data->channels;
	indio_dev->num_channels = info->data->num_channels;
	ret = devm_iio_triggered_buffer_setup(&indio_dev->dev, indio_dev, NULL,
					      rockchip_saradc_trigger_handler,
					      NULL);
	if (ret)
		return ret;

	info->nb.notifier_call = rockchip_saradc_volt_notify;
	ret = regulator_register_notifier(info->vref, &info->nb);
	if (ret)
		return ret;

	ret = devm_add_action_or_reset(&pdev->dev,
				       rockchip_saradc_regulator_unreg_notifier,
				       info);
	if (ret)
		return ret;

	return devm_iio_device_register(&pdev->dev, indio_dev);
}

#ifdef CONFIG_PM_SLEEP
static int rockchip_saradc_suspend(struct device *dev)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct rockchip_saradc *info = iio_priv(indio_dev);

	clk_disable_unprepare(info->clk);
	clk_disable_unprepare(info->pclk);
	regulator_disable(info->vref);

	return 0;
}

static int rockchip_saradc_resume(struct device *dev)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct rockchip_saradc *info = iio_priv(indio_dev);
	int ret;

	ret = regulator_enable(info->vref);
	if (ret)
		return ret;

	ret = clk_prepare_enable(info->pclk);
	if (ret)
		return ret;

	ret = clk_prepare_enable(info->clk);
	if (ret)
		clk_disable_unprepare(info->pclk);

	return ret;
}
#endif

static SIMPLE_DEV_PM_OPS(rockchip_saradc_pm_ops,
			 rockchip_saradc_suspend, rockchip_saradc_resume);

static struct platform_driver rockchip_saradc_driver = {
	.probe		= rockchip_saradc_probe,
	.driver		= {
		.name	= "rockchip-saradc",
		.of_match_table = rockchip_saradc_match,
		.pm	= &rockchip_saradc_pm_ops,
	},
};

module_platform_driver(rockchip_saradc_driver);

MODULE_AUTHOR("Heiko Stuebner <heiko@sntech.de>");
MODULE_DESCRIPTION("Rockchip SARADC driver");
MODULE_LICENSE("GPL v2");
