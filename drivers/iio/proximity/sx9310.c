// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2018 Google LLC.
 *
 * Driver for Semtech's SX9310/SX9311 capacitive proximity/button solution.
 * Based on SX9500 driver and Semtech driver using the input framework
 * <https://my.syncplicity.com/share/teouwsim8niiaud/
 *          linux-driver-SX9310_NoSmartHSensing>.
 * Reworked April 2019 by Evan Green <evgreen@chromium.org>
 * and January 2020 by Daniel Campello <campello@chromium.org>
 */

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pm.h>
#include <linux/regmap.h>
#include <linux/slab.h>

#include <linux/iio/buffer.h>
#include <linux/iio/events.h>
#include <linux/iio/iio.h>
#include <linux/iio/sysfs.h>
#include <linux/iio/trigger.h>
#include <linux/iio/triggered_buffer.h>
#include <linux/iio/trigger_consumer.h>

/* Register definitions. */
#define SX9310_REG_IRQ_SRC				0x00
#define SX9310_REG_STAT0				0x01
#define SX9310_REG_STAT1				0x02
#define SX9310_REG_IRQ_MSK				0x03
#define   SX9310_CONVDONE_IRQ				BIT(3)
#define   SX9310_FAR_IRQ				BIT(5)
#define   SX9310_CLOSE_IRQ				BIT(6)
#define   SX9310_EVENT_IRQ				(SX9310_FAR_IRQ | \
							 SX9310_CLOSE_IRQ)
#define SX9310_REG_IRQ_FUNC				0x04

#define SX9310_REG_PROX_CTRL0				0x10
#define   SX9310_REG_PROX_CTRL0_PROXSTAT2		0x10
#define   SX9310_REG_PROX_CTRL0_EN_MASK			0x0F
#define SX9310_REG_PROX_CTRL1				0x11
#define SX9310_REG_PROX_CTRL2				0x12
#define   SX9310_REG_PROX_CTRL2_COMBMODE_ALL		0x80
#define   SX9310_REG_PROX_CTRL2_SHIELDEN_DYNAMIC	0x04
#define SX9310_REG_PROX_CTRL3				0x13
#define   SX9310_REG_PROX_CTRL3_GAIN0_X8		0x0c
#define   SX9310_REG_PROX_CTRL3_GAIN12_X4		0x02
#define SX9310_REG_PROX_CTRL4				0x14
#define   SX9310_REG_PROX_CTRL4_RESOLUTION_FINEST	0x07
#define SX9310_REG_PROX_CTRL5				0x15
#define   SX9310_REG_PROX_CTRL5_RANGE_SMALL		0xc0
#define   SX9310_REG_PROX_CTRL5_STARTUPSENS_CS1		0x04
#define   SX9310_REG_PROX_CTRL5_RAWFILT_1P25		0x02
#define SX9310_REG_PROX_CTRL6				0x16
#define   SX9310_REG_PROX_CTRL6_COMP_COMMON		0x20
#define SX9310_REG_PROX_CTRL7				0x17
#define   SX9310_REG_PROX_CTRL7_AVGNEGFILT_2		0x08
#define   SX9310_REG_PROX_CTRL7_AVGPOSFILT_512		0x05
#define SX9310_REG_PROX_CTRL8				0x18
#define SX9310_REG_PROX_CTRL9				0x19
#define   SX9310_REG_PROX_CTRL8_9_PTHRESH12_28		0x40
#define   SX9310_REG_PROX_CTRL8_9_PTHRESH_96		0x88
#define   SX9310_REG_PROX_CTRL8_9_BODYTHRESH_900	0x03
#define   SX9310_REG_PROX_CTRL8_9_BODYTHRESH_1500	0x05
#define SX9310_REG_PROX_CTRL10				0x1a
#define   SX9310_REG_PROX_CTRL10_HYST_6PCT		0x10
#define   SX9310_REG_PROX_CTRL10_CLOSE_DEBOUNCE_8	0x12
#define   SX9310_REG_PROX_CTRL10_FAR_DEBOUNCE_8		0x03
#define SX9310_REG_PROX_CTRL11				0x1b
#define SX9310_REG_PROX_CTRL12				0x1c
#define SX9310_REG_PROX_CTRL13				0x1d
#define SX9310_REG_PROX_CTRL14				0x1e
#define SX9310_REG_PROX_CTRL15				0x1f
#define SX9310_REG_PROX_CTRL16				0x20
#define SX9310_REG_PROX_CTRL17				0x21
#define SX9310_REG_PROX_CTRL18				0x22
#define SX9310_REG_PROX_CTRL19				0x23
#define SX9310_REG_SAR_CTRL0				0x2a
#define   SX9310_REG_SAR_CTRL0_SARDEB_4_SAMPLES		0x40
#define   SX9310_REG_SAR_CTRL0_SARHYST_8		0x10
#define SX9310_REG_SAR_CTRL1				0x2b
/* Each increment of the slope register is 0.0078125. */
#define   SX9310_REG_SAR_CTRL1_SLOPE(_hnslope)		(_hnslope / 78125)
#define SX9310_REG_SAR_CTRL2				0x2c
#define   SX9310_REG_SAR_CTRL2_SAROFFSET_DEFAULT	0x3c

#define SX9310_REG_SENSOR_SEL				0x30

#define SX9310_REG_USE_MSB				0x31
#define SX9310_REG_USE_LSB				0x32

#define SX9310_REG_AVG_MSB				0x33
#define SX9310_REG_AVG_LSB				0x34

#define SX9310_REG_DIFF_MSB				0x35
#define SX9310_REG_DIFF_LSB				0x36

#define SX9310_REG_OFFSET_MSB				0x37
#define SX9310_REG_OFFSET_LSB				0x38

#define SX9310_REG_SAR_MSB				0x39
#define SX9310_REG_SAR_LSB				0x3a

#define SX9310_REG_I2CADDR				0x40
#define SX9310_REG_PAUSE				0x41
#define SX9310_REG_WHOAMI				0x42
#define   SX9310_WHOAMI_VALUE				0x01
#define   SX9311_WHOAMI_VALUE				0x02

#define SX9310_REG_RESET				0x7f
#define   SX9310_SOFT_RESET				0xde

#define SX9310_SCAN_PERIOD_MASK				GENMASK(7, 4)
#define SX9310_SCAN_PERIOD_SHIFT			4

#define SX9310_COMPSTAT_MASK				GENMASK(3, 0)

/* 4 hardware channels, as defined in STAT0: COMB, CS2, CS1 and CS0. */
#define SX9310_NUM_CHANNELS				4
#define SX9310_CHAN_ENABLED_MASK			GENMASK(3, 0)

struct sx9310_data {
	/* Serialize access to registers and channel configuration */
	struct mutex mutex;
	struct i2c_client *client;
	struct iio_trigger *trig;
	struct regmap *regmap;
	/*
	 * Last reading of the proximity status for each channel.
	 * We only send an event to user space when this changes.
	 */
	bool prox_stat[SX9310_NUM_CHANNELS];
	bool trigger_enabled;
	__be16 buffer[SX9310_NUM_CHANNELS +
		      4]; /* 64-bit data + 64-bit timestamp */
	/* Remember enabled channels and sample rate during suspend. */
	unsigned int suspend_ctrl0;
	struct completion completion;
	unsigned int chan_read, chan_event;
	int channel_users[SX9310_NUM_CHANNELS];
	int whoami;
};

static const struct iio_event_spec sx9310_events[] = {
	{
		.type = IIO_EV_TYPE_THRESH,
		.dir = IIO_EV_DIR_EITHER,
		.mask_separate = BIT(IIO_EV_INFO_ENABLE),
	},
};

#define SX9310_NAMED_CHANNEL(idx, name)					 \
	{								 \
		.type = IIO_PROXIMITY,					 \
		.info_mask_separate = BIT(IIO_CHAN_INFO_RAW),		 \
		.info_mask_shared_by_all = BIT(IIO_CHAN_INFO_SAMP_FREQ), \
		.indexed = 1,						 \
		.channel = idx,						 \
		.extend_name = name,					 \
		.address = SX9310_REG_DIFF_MSB,				 \
		.event_spec = sx9310_events,				 \
		.num_event_specs = ARRAY_SIZE(sx9310_events),		 \
		.scan_index = idx,					 \
		.scan_type = {						 \
			.sign = 's',					 \
			.realbits = 12,					 \
			.storagebits = 16,				 \
			.endianness = IIO_BE,				 \
		},							 \
	}
#define SX9310_CHANNEL(idx) SX9310_NAMED_CHANNEL(idx, NULL)

static const struct iio_chan_spec sx9310_channels[] = {
	SX9310_CHANNEL(0),			/* CS0 */
	SX9310_CHANNEL(1),			/* CS1 */
	SX9310_CHANNEL(2),			/* CS2 */
	SX9310_NAMED_CHANNEL(3, "comb"),	/* COMB */

	IIO_CHAN_SOFT_TIMESTAMP(4),
};

/*
 * Each entry contains the integer part (val) and the fractional part, in micro
 * seconds. It conforms to the IIO output IIO_VAL_INT_PLUS_MICRO.
 */
static const struct {
	int val;
	int val2;
} sx9310_samp_freq_table[] = {
	{ 500, 0 }, /* 0000: Min (no idle time) */
	{ 66, 666666 }, /* 0001: 15 ms */
	{ 33, 333333 }, /* 0010: 30 ms (Typ.) */
	{ 22, 222222 }, /* 0011: 45 ms */
	{ 16, 666666 }, /* 0100: 60 ms */
	{ 11, 111111 }, /* 0101: 90 ms */
	{ 8, 333333 }, /* 0110: 120 ms */
	{ 5, 0 }, /* 0111: 200 ms */
	{ 2, 500000 }, /* 1000: 400 ms */
	{ 1, 666666 }, /* 1001: 600 ms */
	{ 1, 250000 }, /* 1010: 800 ms */
	{ 1, 0 }, /* 1011: 1 s */
	{ 0, 500000 }, /* 1100: 2 s */
	{ 0, 333333 }, /* 1101: 3 s */
	{ 0, 250000 }, /* 1110: 4 s */
	{ 0, 200000 }, /* 1111: 5 s */
};
static const unsigned int sx9310_scan_period_table[] = {
	2,   15,  30,  45,   60,   90,	 120,  200,
	400, 600, 800, 1000, 2000, 3000, 4000, 5000,
};

static ssize_t sx9310_show_samp_freq_avail(struct device *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	size_t len = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(sx9310_samp_freq_table); i++)
		len += scnprintf(buf + len, PAGE_SIZE - len, "%d.%d ",
				 sx9310_samp_freq_table[i].val,
				 sx9310_samp_freq_table[i].val2);
	buf[len - 1] = '\n';
	return len;
}
static IIO_DEV_ATTR_SAMP_FREQ_AVAIL(sx9310_show_samp_freq_avail);

static const struct regmap_range sx9310_writable_reg_ranges[] = {
	regmap_reg_range(SX9310_REG_IRQ_MSK, SX9310_REG_IRQ_FUNC),
	regmap_reg_range(SX9310_REG_PROX_CTRL0, SX9310_REG_PROX_CTRL19),
	regmap_reg_range(SX9310_REG_SAR_CTRL0, SX9310_REG_SAR_CTRL2),
	regmap_reg_range(SX9310_REG_SENSOR_SEL, SX9310_REG_SENSOR_SEL),
	regmap_reg_range(SX9310_REG_OFFSET_MSB, SX9310_REG_OFFSET_LSB),
	regmap_reg_range(SX9310_REG_PAUSE, SX9310_REG_PAUSE),
	regmap_reg_range(SX9310_REG_RESET, SX9310_REG_RESET),
};

static const struct regmap_access_table sx9310_writeable_regs = {
	.yes_ranges = sx9310_writable_reg_ranges,
	.n_yes_ranges = ARRAY_SIZE(sx9310_writable_reg_ranges),
};

static const struct regmap_range sx9310_readable_reg_ranges[] = {
	regmap_reg_range(SX9310_REG_IRQ_SRC, SX9310_REG_IRQ_FUNC),
	regmap_reg_range(SX9310_REG_PROX_CTRL0, SX9310_REG_PROX_CTRL19),
	regmap_reg_range(SX9310_REG_SAR_CTRL0, SX9310_REG_SAR_CTRL2),
	regmap_reg_range(SX9310_REG_SENSOR_SEL, SX9310_REG_SAR_LSB),
	regmap_reg_range(SX9310_REG_I2CADDR, SX9310_REG_WHOAMI),
	regmap_reg_range(SX9310_REG_RESET, SX9310_REG_RESET),
};

static const struct regmap_access_table sx9310_readable_regs = {
	.yes_ranges = sx9310_readable_reg_ranges,
	.n_yes_ranges = ARRAY_SIZE(sx9310_readable_reg_ranges),
};

static const struct regmap_range sx9310_volatile_reg_ranges[] = {
	regmap_reg_range(SX9310_REG_IRQ_SRC, SX9310_REG_STAT1),
	regmap_reg_range(SX9310_REG_USE_MSB, SX9310_REG_DIFF_LSB),
	regmap_reg_range(SX9310_REG_SAR_MSB, SX9310_REG_SAR_LSB),
	regmap_reg_range(SX9310_REG_RESET, SX9310_REG_RESET),
};

static const struct regmap_access_table sx9310_volatile_regs = {
	.yes_ranges = sx9310_volatile_reg_ranges,
	.n_yes_ranges = ARRAY_SIZE(sx9310_volatile_reg_ranges),
};

static const struct regmap_config sx9310_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,

	.max_register = SX9310_REG_RESET,
	.cache_type = REGCACHE_RBTREE,

	.wr_table = &sx9310_writeable_regs,
	.rd_table = &sx9310_readable_regs,
	.volatile_table = &sx9310_volatile_regs,
};

static int sx9310_update_chan_en(struct sx9310_data *data,
				 unsigned int chan_read,
				 unsigned int chan_event)
{
	int ret;

	if ((data->chan_read | data->chan_event) != (chan_read | chan_event)) {
		ret = regmap_update_bits(data->regmap, SX9310_REG_PROX_CTRL0,
					 SX9310_CHAN_ENABLED_MASK,
					 chan_read | chan_event);
		if (ret)
			return ret;
	}
	data->chan_read = chan_read;
	data->chan_event = chan_event;
	return 0;
}

static int sx9310_get_read_channel(struct sx9310_data *data, int channel)
{
	return sx9310_update_chan_en(data, data->chan_read | BIT(channel),
				     data->chan_event);
}

static int sx9310_put_read_channel(struct sx9310_data *data, int channel)
{
	return sx9310_update_chan_en(data, data->chan_read & ~BIT(channel),
				     data->chan_event);
}

static int sx9310_get_event_channel(struct sx9310_data *data, int channel)
{
	return sx9310_update_chan_en(data, data->chan_read,
				     data->chan_event | BIT(channel));
}

static int sx9310_put_event_channel(struct sx9310_data *data, int channel)
{
	return sx9310_update_chan_en(data, data->chan_read,
				     data->chan_event & ~BIT(channel));
}

static int sx9310_enable_irq(struct sx9310_data *data, unsigned int irq)
{
	return regmap_update_bits(data->regmap, SX9310_REG_IRQ_MSK, irq, irq);
}

static int sx9310_disable_irq(struct sx9310_data *data, unsigned int irq)
{
	return regmap_update_bits(data->regmap, SX9310_REG_IRQ_MSK, irq, 0);
}

static int sx9310_read_prox_data(struct sx9310_data *data,
				 const struct iio_chan_spec *chan, __be16 *val)
{
	int ret;

	ret = regmap_write(data->regmap, SX9310_REG_SENSOR_SEL, chan->channel);
	if (ret < 0)
		return ret;

	return regmap_bulk_read(data->regmap, chan->address, val, 2);
}

/*
 * If we have no interrupt support, we have to wait for a scan period
 * after enabling a channel to get a result.
 */
static int sx9310_wait_for_sample(struct sx9310_data *data)
{
	int ret;
	unsigned int val;

	ret = regmap_read(data->regmap, SX9310_REG_PROX_CTRL0, &val);
	if (ret < 0)
		return ret;

	val = (val & SX9310_SCAN_PERIOD_MASK) >> SX9310_SCAN_PERIOD_SHIFT;

	msleep(sx9310_scan_period_table[val]);

	return 0;
}

static int sx9310_read_proximity(struct sx9310_data *data,
				 const struct iio_chan_spec *chan, int *val)
{
	int ret = 0;
	__be16 rawval;

	mutex_lock(&data->mutex);

	ret = sx9310_get_read_channel(data, chan->channel);
	if (ret < 0)
		goto out;

	ret = sx9310_enable_irq(data, SX9310_CONVDONE_IRQ);
	if (ret < 0)
		goto out_put_channel;

	mutex_unlock(&data->mutex);

	if (data->client->irq > 0) {
		ret = wait_for_completion_interruptible(&data->completion);
		reinit_completion(&data->completion);
	} else {
		ret = sx9310_wait_for_sample(data);
	}

	mutex_lock(&data->mutex);

	if (ret < 0)
		goto out_disable_irq;

	ret = sx9310_read_prox_data(data, chan, &rawval);
	if (ret < 0)
		goto out_disable_irq;

	*val = sign_extend32(be16_to_cpu(rawval),
			     (chan->address == SX9310_REG_DIFF_MSB ? 11 : 15));

	ret = sx9310_disable_irq(data, SX9310_CONVDONE_IRQ);
	if (ret < 0)
		goto out_put_channel;

	ret = sx9310_put_read_channel(data, chan->channel);
	if (ret < 0)
		goto out;

	mutex_unlock(&data->mutex);

	return IIO_VAL_INT;

out_disable_irq:
	sx9310_disable_irq(data, SX9310_CONVDONE_IRQ);
out_put_channel:
	sx9310_put_read_channel(data, chan->channel);
out:
	mutex_unlock(&data->mutex);

	return ret;
}

static int sx9310_read_samp_freq(struct sx9310_data *data, int *val, int *val2)
{
	unsigned int regval;
	int ret = regmap_read(data->regmap, SX9310_REG_PROX_CTRL0, &regval);

	if (ret < 0)
		return ret;

	regval = (regval & SX9310_SCAN_PERIOD_MASK) >> SX9310_SCAN_PERIOD_SHIFT;
	*val = sx9310_samp_freq_table[regval].val;
	*val2 = sx9310_samp_freq_table[regval].val2;

	return IIO_VAL_INT_PLUS_MICRO;
}

static int sx9310_read_raw(struct iio_dev *indio_dev,
			   const struct iio_chan_spec *chan, int *val,
			   int *val2, long mask)
{
	struct sx9310_data *data = iio_priv(indio_dev);
	int ret;

	if (chan->type != IIO_PROXIMITY)
		return -EINVAL;

	switch (mask) {
	case IIO_CHAN_INFO_RAW:
		ret = iio_device_claim_direct_mode(indio_dev);
		if (ret)
			return ret;

		ret = sx9310_read_proximity(data, chan, val);
		iio_device_release_direct_mode(indio_dev);
		return ret;
	case IIO_CHAN_INFO_SAMP_FREQ:
		return sx9310_read_samp_freq(data, val, val2);
	default:
		return -EINVAL;
	}
}

static int sx9310_set_samp_freq(struct sx9310_data *data, int val, int val2)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(sx9310_samp_freq_table); i++)
		if (val == sx9310_samp_freq_table[i].val &&
		    val2 == sx9310_samp_freq_table[i].val2)
			break;

	if (i == ARRAY_SIZE(sx9310_samp_freq_table))
		return -EINVAL;

	mutex_lock(&data->mutex);

	ret = regmap_update_bits(data->regmap, SX9310_REG_PROX_CTRL0,
				 SX9310_SCAN_PERIOD_MASK,
				 i << SX9310_SCAN_PERIOD_SHIFT);

	mutex_unlock(&data->mutex);

	return ret;
}

static int sx9310_write_raw(struct iio_dev *indio_dev,
			    const struct iio_chan_spec *chan, int val, int val2,
			    long mask)
{
	struct sx9310_data *data = iio_priv(indio_dev);

	if (chan->type != IIO_PROXIMITY)
		return -EINVAL;

	if (mask != IIO_CHAN_INFO_SAMP_FREQ)
		return -EINVAL;

	return sx9310_set_samp_freq(data, val, val2);
}

static irqreturn_t sx9310_irq_handler(int irq, void *private)
{
	struct iio_dev *indio_dev = private;
	struct sx9310_data *data = iio_priv(indio_dev);

	if (data->trigger_enabled)
		iio_trigger_poll(data->trig);

	/*
	 * Even if no event is enabled, we need to wake the thread to
	 * clear the interrupt state by reading SX9310_REG_IRQ_SRC.  It
	 * is not possible to do that here because regmap_read takes a
	 * mutex.
	 */
	return IRQ_WAKE_THREAD;
}

static void sx9310_push_events(struct iio_dev *indio_dev)
{
	int ret;
	unsigned int val, chan;
	struct sx9310_data *data = iio_priv(indio_dev);
	s64 timestamp = iio_get_time_ns(indio_dev);

	/* Read proximity state on all channels */
	ret = regmap_read(data->regmap, SX9310_REG_STAT0, &val);
	if (ret < 0) {
		dev_err(&data->client->dev, "i2c transfer error in irq\n");
		return;
	}

	for (chan = 0; chan < SX9310_NUM_CHANNELS; chan++) {
		int dir;
		u64 ev;
		bool new_prox = val & BIT(chan);

		if (!(data->chan_event & BIT(chan)))
			continue;
		if (new_prox == data->prox_stat[chan])
			/* No change on this channel. */
			continue;

		dir = new_prox ? IIO_EV_DIR_FALLING : IIO_EV_DIR_RISING;
		ev = IIO_UNMOD_EVENT_CODE(IIO_PROXIMITY, chan,
					  IIO_EV_TYPE_THRESH, dir);

		iio_push_event(indio_dev, ev, timestamp);
		data->prox_stat[chan] = new_prox;
	}
}

static irqreturn_t sx9310_irq_thread_handler(int irq, void *private)
{
	struct iio_dev *indio_dev = private;
	struct sx9310_data *data = iio_priv(indio_dev);
	int ret;
	unsigned int val;

	mutex_lock(&data->mutex);

	ret = regmap_read(data->regmap, SX9310_REG_IRQ_SRC, &val);
	if (ret < 0) {
		dev_err(&data->client->dev, "i2c transfer error in irq\n");
		goto out;
	}

	if (val & SX9310_EVENT_IRQ)
		sx9310_push_events(indio_dev);

	if (val & SX9310_CONVDONE_IRQ)
		complete(&data->completion);

out:
	mutex_unlock(&data->mutex);

	return IRQ_HANDLED;
}

static int sx9310_read_event_config(struct iio_dev *indio_dev,
				    const struct iio_chan_spec *chan,
				    enum iio_event_type type,
				    enum iio_event_direction dir)
{
	struct sx9310_data *data = iio_priv(indio_dev);

	return !!(data->chan_event & BIT(chan->channel));
}

static int sx9310_write_event_config(struct iio_dev *indio_dev,
				     const struct iio_chan_spec *chan,
				     enum iio_event_type type,
				     enum iio_event_direction dir, int state)
{
	struct sx9310_data *data = iio_priv(indio_dev);
	int ret;

	/* If the state hasn't changed, there's nothing to do. */
	if (!!(data->chan_event & BIT(chan->channel)) == state)
		return 0;

	mutex_lock(&data->mutex);
	if (state) {
		ret = sx9310_get_event_channel(data, chan->channel);
		if (ret < 0)
			goto out_unlock;
		if (!(data->chan_event & ~BIT(chan->channel))) {
			ret = sx9310_enable_irq(data, SX9310_EVENT_IRQ);
			if (ret < 0)
				sx9310_put_event_channel(data, chan->channel);
		}
	} else {
		ret = sx9310_put_event_channel(data, chan->channel);
		if (ret < 0)
			goto out_unlock;
		if (!data->chan_event) {
			ret = sx9310_disable_irq(data, SX9310_EVENT_IRQ);
			if (ret < 0)
				sx9310_get_event_channel(data, chan->channel);
		}
	}

out_unlock:
	mutex_unlock(&data->mutex);
	return ret;
}

static struct attribute *sx9310_attributes[] = {
	&iio_dev_attr_sampling_frequency_available.dev_attr.attr,
	NULL,
};

static const struct attribute_group sx9310_attribute_group = {
	.attrs = sx9310_attributes,
};

static const struct iio_info sx9310_info = {
	.attrs = &sx9310_attribute_group,
	.read_raw = sx9310_read_raw,
	.write_raw = sx9310_write_raw,
	.read_event_config = sx9310_read_event_config,
	.write_event_config = sx9310_write_event_config,
};

static int sx9310_set_trigger_state(struct iio_trigger *trig, bool state)
{
	struct iio_dev *indio_dev = iio_trigger_get_drvdata(trig);
	struct sx9310_data *data = iio_priv(indio_dev);
	int ret = 0;

	mutex_lock(&data->mutex);

	if (state)
		ret = sx9310_enable_irq(data, SX9310_CONVDONE_IRQ);
	else if (!data->chan_read)
		ret = sx9310_disable_irq(data, SX9310_CONVDONE_IRQ);
	if (ret < 0)
		goto out;

	data->trigger_enabled = state;

out:
	mutex_unlock(&data->mutex);

	return ret;
}

static const struct iio_trigger_ops sx9310_trigger_ops = {
	.set_trigger_state = sx9310_set_trigger_state,
};

static irqreturn_t sx9310_trigger_handler(int irq, void *private)
{
	struct iio_poll_func *pf = private;
	struct iio_dev *indio_dev = pf->indio_dev;
	struct sx9310_data *data = iio_priv(indio_dev);
	__be16 val;
	int bit, ret, i = 0;

	mutex_lock(&data->mutex);

	for_each_set_bit(bit, indio_dev->active_scan_mask,
			 indio_dev->masklength) {
		ret = sx9310_read_prox_data(data, &indio_dev->channels[bit],
					    &val);
		if (ret < 0)
			goto out;

		data->buffer[i++] = val;
	}

	iio_push_to_buffers_with_timestamp(indio_dev, data->buffer,
					   pf->timestamp);

out:
	mutex_unlock(&data->mutex);

	iio_trigger_notify_done(indio_dev->trig);

	return IRQ_HANDLED;
}

static int sx9310_buffer_preenable(struct iio_dev *indio_dev)
{
	struct sx9310_data *data = iio_priv(indio_dev);
	unsigned int channels = 0;
	int bit, ret;

	mutex_lock(&data->mutex);
	for_each_set_bit(bit, indio_dev->active_scan_mask,
			 indio_dev->masklength)
		channels |= BIT(indio_dev->channels[bit].channel);

	ret = sx9310_update_chan_en(data, channels, data->chan_event);
	mutex_unlock(&data->mutex);
	return ret;
}

static int sx9310_buffer_postdisable(struct iio_dev *indio_dev)
{
	struct sx9310_data *data = iio_priv(indio_dev);
	int ret;

	mutex_lock(&data->mutex);
	ret = sx9310_update_chan_en(data, 0, data->chan_event);
	mutex_unlock(&data->mutex);
	return ret;
}

static const struct iio_buffer_setup_ops sx9310_buffer_setup_ops = {
	.preenable = sx9310_buffer_preenable,
	.postenable = iio_triggered_buffer_postenable,
	.predisable = iio_triggered_buffer_predisable,
	.postdisable = sx9310_buffer_postdisable,
};

struct sx9310_reg_default {
	u8 reg;
	u8 def;
};

#define SX_INIT(_reg, _def)			\
	{					\
		.reg = SX9310_REG_##_reg,	\
		.def = _def,			\
	}

static const struct sx9310_reg_default sx9310_default_regs[] = {
	SX_INIT(IRQ_MSK, 0x00),
	SX_INIT(IRQ_FUNC, 0x00),
	/*
	 * The lower 4 bits should not be set as it enable sensors measurements.
	 * Turning the detection on before the configuration values are set to
	 * good values can cause the device to return erroneous readings.
	 */
	SX_INIT(PROX_CTRL0, SX9310_REG_PROX_CTRL0_PROXSTAT2),
	SX_INIT(PROX_CTRL1, 0x00),
	SX_INIT(PROX_CTRL2, SX9310_REG_PROX_CTRL2_COMBMODE_ALL |
			    SX9310_REG_PROX_CTRL2_SHIELDEN_DYNAMIC),
	SX_INIT(PROX_CTRL3, SX9310_REG_PROX_CTRL3_GAIN0_X8 |
			    SX9310_REG_PROX_CTRL3_GAIN12_X4),
	SX_INIT(PROX_CTRL4, SX9310_REG_PROX_CTRL4_RESOLUTION_FINEST),
	SX_INIT(PROX_CTRL5, SX9310_REG_PROX_CTRL5_RANGE_SMALL |
			    SX9310_REG_PROX_CTRL5_STARTUPSENS_CS1 |
			    SX9310_REG_PROX_CTRL5_RAWFILT_1P25),
	SX_INIT(PROX_CTRL6, SX9310_REG_PROX_CTRL6_COMP_COMMON),
	SX_INIT(PROX_CTRL7, SX9310_REG_PROX_CTRL7_AVGNEGFILT_2 |
			    SX9310_REG_PROX_CTRL7_AVGPOSFILT_512),
	SX_INIT(PROX_CTRL8, SX9310_REG_PROX_CTRL8_9_PTHRESH_96 |
			    SX9310_REG_PROX_CTRL8_9_BODYTHRESH_1500),
	SX_INIT(PROX_CTRL9, SX9310_REG_PROX_CTRL8_9_PTHRESH12_28 |
			    SX9310_REG_PROX_CTRL8_9_BODYTHRESH_900),
	SX_INIT(PROX_CTRL10, SX9310_REG_PROX_CTRL10_HYST_6PCT |
			     SX9310_REG_PROX_CTRL10_CLOSE_DEBOUNCE_8 |
			     SX9310_REG_PROX_CTRL10_FAR_DEBOUNCE_8),
	SX_INIT(PROX_CTRL11, 0x00),
	SX_INIT(PROX_CTRL12, 0x00),
	SX_INIT(PROX_CTRL13, 0x00),
	SX_INIT(PROX_CTRL14, 0x00),
	SX_INIT(PROX_CTRL15, 0x00),
	SX_INIT(PROX_CTRL16, 0x00),
	SX_INIT(PROX_CTRL17, 0x00),
	SX_INIT(PROX_CTRL18, 0x00),
	SX_INIT(PROX_CTRL19, 0x00),
	SX_INIT(SAR_CTRL0, SX9310_REG_SAR_CTRL0_SARDEB_4_SAMPLES |
			   SX9310_REG_SAR_CTRL0_SARHYST_8),
	SX_INIT(SAR_CTRL1, SX9310_REG_SAR_CTRL1_SLOPE(10781250)),
	SX_INIT(SAR_CTRL2, SX9310_REG_SAR_CTRL2_SAROFFSET_DEFAULT),
};

/* Activate all channels and perform an initial compensation. */
static int sx9310_init_compensation(struct iio_dev *indio_dev)
{
	struct sx9310_data *data = iio_priv(indio_dev);
	int i, ret;
	unsigned int val;
	unsigned int ctrl0;

	ret = regmap_read(data->regmap, SX9310_REG_PROX_CTRL0, &ctrl0);
	if (ret < 0)
		return ret;

	/* run the compensation phase on all channels */
	ret = regmap_write(data->regmap, SX9310_REG_PROX_CTRL0,
			   ctrl0 | SX9310_REG_PROX_CTRL0_EN_MASK);
	if (ret < 0)
		return ret;

	for (i = 100; i >= 0; i--) {
		msleep(20);
		ret = regmap_read(data->regmap, SX9310_REG_STAT1, &val);
		if (ret < 0)
			goto out;
		if (!(val & SX9310_COMPSTAT_MASK))
			break;
	}

	if (i < 0) {
		dev_err(&data->client->dev,
			"initial compensation timed out: 0x%02x", val);
		ret = -ETIMEDOUT;
	}

out:
	regmap_write(data->regmap, SX9310_REG_PROX_CTRL0, ctrl0);
	return ret;
}

static int sx9310_init_device(struct iio_dev *indio_dev)
{
	struct sx9310_data *data = iio_priv(indio_dev);
	const struct sx9310_reg_default *initval;
	int ret;
	unsigned int i, val;

	ret = regmap_write(data->regmap, SX9310_REG_RESET, SX9310_SOFT_RESET);
	if (ret < 0)
		return ret;

	usleep_range(1000, 2000); /* power-up time is ~1ms. */

	/* Clear reset interrupt state by reading SX9310_REG_IRQ_SRC. */
	ret = regmap_read(data->regmap, SX9310_REG_IRQ_SRC, &val);
	if (ret < 0)
		return ret;

	/* Program some sane defaults. */
	for (i = 0; i < ARRAY_SIZE(sx9310_default_regs); i++) {
		initval = &sx9310_default_regs[i];
		ret = regmap_write(data->regmap, initval->reg, initval->def);
		if (ret < 0)
			return ret;
	}

	return sx9310_init_compensation(indio_dev);
}

static int sx9310_set_indio_dev_name(struct device *dev,
				     struct iio_dev *indio_dev,
				     const struct i2c_device_id *id, int whoami)
{
	const struct acpi_device_id *acpi_id;

	/* id will be NULL when enumerated via ACPI */
	if (id) {
		if (id->driver_data != whoami)
			dev_err(dev, "WHOAMI does not match i2c_device_id: %s",
				id->name);
	} else if (ACPI_HANDLE(dev)) {
		acpi_id = acpi_match_device(dev->driver->acpi_match_table, dev);
		if (!acpi_id)
			return -ENODEV;
		if (acpi_id->driver_data != whoami)
			dev_err(dev, "WHOAMI does not match acpi_device_id: %s",
				acpi_id->id);
	} else
		return -ENODEV;

	switch (whoami) {
	case SX9310_WHOAMI_VALUE:
		indio_dev->name = "sx9310";
		break;
	case SX9311_WHOAMI_VALUE:
		indio_dev->name = "sx9311";
		break;
	default:
		dev_err(dev, "unexpected WHOAMI response: %u", whoami);
		return -ENODEV;
	}

	return 0;
}

static int sx9310_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	int ret;
	struct iio_dev *indio_dev;
	struct sx9310_data *data;

	indio_dev = devm_iio_device_alloc(&client->dev, sizeof(*data));
	if (indio_dev == NULL)
		return -ENOMEM;

	data = iio_priv(indio_dev);
	data->client = client;
	mutex_init(&data->mutex);
	init_completion(&data->completion);

	data->regmap = devm_regmap_init_i2c(client, &sx9310_regmap_config);
	if (IS_ERR(data->regmap))
		return PTR_ERR(data->regmap);

	ret = regmap_read(data->regmap, SX9310_REG_WHOAMI, &data->whoami);
	if (ret < 0) {
		dev_err(&client->dev, "error in reading WHOAMI register: %d",
			ret);
		return ret;
	}

	ret = sx9310_set_indio_dev_name(&client->dev, indio_dev, id,
					data->whoami);
	if (ret < 0)
		return ret;

	ACPI_COMPANION_SET(&indio_dev->dev, ACPI_COMPANION(&client->dev));
	indio_dev->dev.parent = &client->dev;
	indio_dev->channels = sx9310_channels;
	indio_dev->num_channels = ARRAY_SIZE(sx9310_channels);
	indio_dev->info = &sx9310_info;
	indio_dev->modes = INDIO_DIRECT_MODE;
	i2c_set_clientdata(client, indio_dev);

	ret = sx9310_init_device(indio_dev);
	if (ret < 0)
		return ret;

	if (client->irq) {
		ret = devm_request_threaded_irq(&client->dev, client->irq,
						sx9310_irq_handler,
						sx9310_irq_thread_handler,
						IRQF_TRIGGER_LOW | IRQF_ONESHOT,
						"sx9310_event", indio_dev);
		if (ret < 0)
			return ret;

		data->trig =
			devm_iio_trigger_alloc(&client->dev, "%s-dev%d",
					       indio_dev->name, indio_dev->id);
		if (!data->trig)
			return -ENOMEM;

		data->trig->dev.parent = &client->dev;
		data->trig->ops = &sx9310_trigger_ops;
		iio_trigger_set_drvdata(data->trig, indio_dev);

		ret = devm_iio_trigger_register(&client->dev, data->trig);
		if (ret)
			return ret;
	}

	ret = devm_iio_triggered_buffer_setup(&client->dev, indio_dev,
					      iio_pollfunc_store_time,
					      sx9310_trigger_handler,
					      &sx9310_buffer_setup_ops);
	if (ret < 0)
		return ret;

	return devm_iio_device_register(&client->dev, indio_dev);
}

static int __maybe_unused sx9310_suspend(struct device *dev)
{
	struct iio_dev *indio_dev = i2c_get_clientdata(to_i2c_client(dev));
	struct sx9310_data *data = iio_priv(indio_dev);
	u8 ctrl0;
	int ret;

	disable_irq_nosync(data->client->irq);

	mutex_lock(&data->mutex);
	ret = regmap_read(data->regmap, SX9310_REG_PROX_CTRL0,
			  &data->suspend_ctrl0);

	if (ret)
		goto out;

	ctrl0 = data->suspend_ctrl0 & ~SX9310_REG_PROX_CTRL0_EN_MASK;
	ret = regmap_write(data->regmap, SX9310_REG_PROX_CTRL0, ctrl0);
	if (ret)
		goto out;

	ret = regmap_write(data->regmap, SX9310_REG_PAUSE, 0);

out:
	mutex_unlock(&data->mutex);
	return ret;
}

static int __maybe_unused sx9310_resume(struct device *dev)
{
	struct iio_dev *indio_dev = i2c_get_clientdata(to_i2c_client(dev));
	struct sx9310_data *data = iio_priv(indio_dev);
	int ret;

	mutex_lock(&data->mutex);
	ret = regmap_write(data->regmap, SX9310_REG_PAUSE, 1);
	if (ret)
		goto out;

	ret = regmap_write(data->regmap, SX9310_REG_PROX_CTRL0,
			   data->suspend_ctrl0);

out:
	mutex_unlock(&data->mutex);

	enable_irq(data->client->irq);

	return ret;
}

static const struct dev_pm_ops sx9310_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(sx9310_suspend, sx9310_resume)
};

static const struct acpi_device_id sx9310_acpi_match[] = {
	{ "STH9310", SX9310_WHOAMI_VALUE },
	{ "STH9311", SX9311_WHOAMI_VALUE },
	{},
};
MODULE_DEVICE_TABLE(acpi, sx9310_acpi_match);

static const struct of_device_id sx9310_of_match[] = {
	{ .compatible = "semtech,sx9310" },
	{ .compatible = "semtech,sx9311" },
	{},
};
MODULE_DEVICE_TABLE(of, sx9310_of_match);

static const struct i2c_device_id sx9310_id[] = {
	{ "sx9310", SX9310_WHOAMI_VALUE },
	{ "sx9311", SX9311_WHOAMI_VALUE },
	{},
};
MODULE_DEVICE_TABLE(i2c, sx9310_id);

static struct i2c_driver sx9310_driver = {
	.driver = {
		.name	= "sx9310",
		.acpi_match_table = ACPI_PTR(sx9310_acpi_match),
		.of_match_table = of_match_ptr(sx9310_of_match),
		.pm = &sx9310_pm_ops,
	},
	.probe		= sx9310_probe,
	.id_table	= sx9310_id,
};
module_i2c_driver(sx9310_driver);

MODULE_AUTHOR("Gwendal Grignou <gwendal@chromium.org>");
MODULE_AUTHOR("Daniel Campello <campello@chromium.org>");
MODULE_DESCRIPTION("Driver for Semtech SX9310/SX9311 proximity sensor");
MODULE_LICENSE("GPL v2");
