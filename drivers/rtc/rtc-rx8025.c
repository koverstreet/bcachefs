// SPDX-License-Identifier: GPL-2.0-only
/*
 * Driver for Epson's RTC module RX-8025 SA/NB
 *
 * Copyright (C) 2009 Wolfgang Grandegger <wg@grandegger.com>
 *
 * Copyright (C) 2005 by Digi International Inc.
 * All rights reserved.
 *
 * Modified by fengjh at rising.com.cn
 * <lm-sensors@lm-sensors.org>
 * 2006.11
 *
 * Code cleanup by Sergei Poselenov, <sposelenov@emcraft.com>
 * Converted to new style by Wolfgang Grandegger <wg@grandegger.com>
 * Alarm and periodic interrupt added by Dmitry Rakhchev <rda@emcraft.com>
 */
#include <linux/bcd.h>
#include <linux/bitops.h>
#include <linux/i2c.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rtc.h>

/* Register definitions */
#define RX8025_REG_SEC		0x00
#define RX8025_REG_MIN		0x01
#define RX8025_REG_HOUR		0x02
#define RX8025_REG_WDAY		0x03
#define RX8025_REG_MDAY		0x04
#define RX8025_REG_MONTH	0x05
#define RX8025_REG_YEAR		0x06
#define RX8025_REG_DIGOFF	0x07
#define RX8025_REG_ALWMIN	0x08
#define RX8025_REG_ALWHOUR	0x09
#define RX8025_REG_ALWWDAY	0x0a
#define RX8025_REG_ALDMIN	0x0b
#define RX8025_REG_ALDHOUR	0x0c
/* 0x0d is reserved */
#define RX8025_REG_CTRL1	0x0e
#define RX8025_REG_CTRL2	0x0f

#define RX8025_BIT_CTRL1_CT	(7 << 0)
/* 1 Hz periodic level irq */
#define RX8025_BIT_CTRL1_CT_1HZ	4
#define RX8025_BIT_CTRL1_TEST	BIT(3)
#define RX8025_BIT_CTRL1_1224	BIT(5)
#define RX8025_BIT_CTRL1_DALE	BIT(6)
#define RX8025_BIT_CTRL1_WALE	BIT(7)

#define RX8025_BIT_CTRL2_DAFG	BIT(0)
#define RX8025_BIT_CTRL2_WAFG	BIT(1)
#define RX8025_BIT_CTRL2_CTFG	BIT(2)
#define RX8025_BIT_CTRL2_PON	BIT(4)
#define RX8025_BIT_CTRL2_XST	BIT(5)
#define RX8025_BIT_CTRL2_VDET	BIT(6)

/* Clock precision adjustment */
#define RX8025_ADJ_RESOLUTION	3050 /* in ppb */
#define RX8025_ADJ_DATA_MAX	62
#define RX8025_ADJ_DATA_MIN	-62

enum rx_model {
	model_rx_unknown,
	model_rx_8025,
	model_rx_8035,
	model_last
};

static const struct i2c_device_id rx8025_id[] = {
	{ "rx8025", model_rx_8025 },
	{ "rx8035", model_rx_8035 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, rx8025_id);

struct rx8025_data {
	struct rtc_device *rtc;
	enum rx_model model;
	u8 ctrl1;
};

static s32 rx8025_read_reg(const struct i2c_client *client, u8 number)
{
	return i2c_smbus_read_byte_data(client, number << 4);
}

static int rx8025_read_regs(const struct i2c_client *client,
			    u8 number, u8 length, u8 *values)
{
	int ret = i2c_smbus_read_i2c_block_data(client, number << 4, length,
						values);
	if (ret != length)
		return ret < 0 ? ret : -EIO;

	return 0;
}

static s32 rx8025_write_reg(const struct i2c_client *client, u8 number,
			    u8 value)
{
	return i2c_smbus_write_byte_data(client, number << 4, value);
}

static s32 rx8025_write_regs(const struct i2c_client *client,
			     u8 number, u8 length, const u8 *values)
{
	return i2c_smbus_write_i2c_block_data(client, number << 4,
					      length, values);
}

static int rx8025_is_osc_stopped(enum rx_model model, int ctrl2)
{
	int xstp = ctrl2 & RX8025_BIT_CTRL2_XST;
	/* XSTP bit has different polarity on RX-8025 vs RX-8035.
	 * RX-8025: 0 == oscillator stopped
	 * RX-8035: 1 == oscillator stopped
	 */

	if (model == model_rx_8025)
		xstp = !xstp;

	return xstp;
}

static int rx8025_check_validity(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct rx8025_data *drvdata = dev_get_drvdata(dev);
	int ctrl2;
	int xstp;

	ctrl2 = rx8025_read_reg(client, RX8025_REG_CTRL2);
	if (ctrl2 < 0)
		return ctrl2;

	if (ctrl2 & RX8025_BIT_CTRL2_VDET)
		dev_warn(dev, "power voltage drop detected\n");

	if (ctrl2 & RX8025_BIT_CTRL2_PON) {
		dev_warn(dev, "power-on reset detected, date is invalid\n");
		return -EINVAL;
	}

	xstp = rx8025_is_osc_stopped(drvdata->model, ctrl2);
	if (xstp) {
		dev_warn(dev, "crystal stopped, date is invalid\n");
		return -EINVAL;
	}

	return 0;
}

static int rx8025_reset_validity(struct i2c_client *client)
{
	struct rx8025_data *drvdata = i2c_get_clientdata(client);
	int ctrl2 = rx8025_read_reg(client, RX8025_REG_CTRL2);

	if (ctrl2 < 0)
		return ctrl2;

	ctrl2 &= ~(RX8025_BIT_CTRL2_PON | RX8025_BIT_CTRL2_VDET);

	if (drvdata->model == model_rx_8025)
		ctrl2 |= RX8025_BIT_CTRL2_XST;
	else
		ctrl2 &= ~(RX8025_BIT_CTRL2_XST);

	return rx8025_write_reg(client, RX8025_REG_CTRL2,
				ctrl2);
}

static irqreturn_t rx8025_handle_irq(int irq, void *dev_id)
{
	struct i2c_client *client = dev_id;
	struct rx8025_data *rx8025 = i2c_get_clientdata(client);
	int status, xstp;

	rtc_lock(rx8025->rtc);
	status = rx8025_read_reg(client, RX8025_REG_CTRL2);
	if (status < 0)
		goto out;

	xstp = rx8025_is_osc_stopped(rx8025->model, status);
	if (xstp)
		dev_warn(&client->dev, "Oscillation stop was detected,"
			 "you may have to readjust the clock\n");

	if (status & RX8025_BIT_CTRL2_CTFG) {
		/* periodic */
		status &= ~RX8025_BIT_CTRL2_CTFG;
		rtc_update_irq(rx8025->rtc, 1, RTC_PF | RTC_IRQF);
	}

	if (status & RX8025_BIT_CTRL2_DAFG) {
		/* alarm */
		status &= RX8025_BIT_CTRL2_DAFG;
		if (rx8025_write_reg(client, RX8025_REG_CTRL1,
				     rx8025->ctrl1 & ~RX8025_BIT_CTRL1_DALE))
			goto out;
		rtc_update_irq(rx8025->rtc, 1, RTC_AF | RTC_IRQF);
	}

out:
	rtc_unlock(rx8025->rtc);

	return IRQ_HANDLED;
}

static int rx8025_get_time(struct device *dev, struct rtc_time *dt)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct rx8025_data *rx8025 = dev_get_drvdata(dev);
	u8 date[7];
	int err;

	err = rx8025_check_validity(dev);
	if (err)
		return err;

	err = rx8025_read_regs(client, RX8025_REG_SEC, 7, date);
	if (err)
		return err;

	dev_dbg(dev, "%s: read %7ph\n", __func__, date);

	dt->tm_sec = bcd2bin(date[RX8025_REG_SEC] & 0x7f);
	dt->tm_min = bcd2bin(date[RX8025_REG_MIN] & 0x7f);
	if (rx8025->ctrl1 & RX8025_BIT_CTRL1_1224)
		dt->tm_hour = bcd2bin(date[RX8025_REG_HOUR] & 0x3f);
	else
		dt->tm_hour = bcd2bin(date[RX8025_REG_HOUR] & 0x1f) % 12
			+ (date[RX8025_REG_HOUR] & 0x20 ? 12 : 0);

	dt->tm_mday = bcd2bin(date[RX8025_REG_MDAY] & 0x3f);
	dt->tm_mon = bcd2bin(date[RX8025_REG_MONTH] & 0x1f) - 1;
	dt->tm_year = bcd2bin(date[RX8025_REG_YEAR]) + 100;

	dev_dbg(dev, "%s: date %ptRr\n", __func__, dt);

	return 0;
}

static int rx8025_set_time(struct device *dev, struct rtc_time *dt)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct rx8025_data *rx8025 = dev_get_drvdata(dev);
	u8 date[7];
	int ret;

	/*
	 * Here the read-only bits are written as "0".  I'm not sure if that
	 * is sound.
	 */
	date[RX8025_REG_SEC] = bin2bcd(dt->tm_sec);
	date[RX8025_REG_MIN] = bin2bcd(dt->tm_min);
	if (rx8025->ctrl1 & RX8025_BIT_CTRL1_1224)
		date[RX8025_REG_HOUR] = bin2bcd(dt->tm_hour);
	else
		date[RX8025_REG_HOUR] = (dt->tm_hour >= 12 ? 0x20 : 0)
			| bin2bcd((dt->tm_hour + 11) % 12 + 1);

	date[RX8025_REG_WDAY] = bin2bcd(dt->tm_wday);
	date[RX8025_REG_MDAY] = bin2bcd(dt->tm_mday);
	date[RX8025_REG_MONTH] = bin2bcd(dt->tm_mon + 1);
	date[RX8025_REG_YEAR] = bin2bcd(dt->tm_year - 100);

	dev_dbg(dev, "%s: write %7ph\n", __func__, date);

	ret = rx8025_write_regs(client, RX8025_REG_SEC, 7, date);
	if (ret < 0)
		return ret;

	return rx8025_reset_validity(client);
}

static int rx8025_init_client(struct i2c_client *client)
{
	struct rx8025_data *rx8025 = i2c_get_clientdata(client);
	u8 ctrl[2], ctrl2;
	int need_clear = 0;
	int err;

	err = rx8025_read_regs(client, RX8025_REG_CTRL1, 2, ctrl);
	if (err)
		goto out;

	/* Keep test bit zero ! */
	rx8025->ctrl1 = ctrl[0] & ~RX8025_BIT_CTRL1_TEST;

	if (ctrl[1] & (RX8025_BIT_CTRL2_DAFG | RX8025_BIT_CTRL2_WAFG)) {
		dev_warn(&client->dev, "Alarm was detected\n");
		need_clear = 1;
	}

	if (ctrl[1] & RX8025_BIT_CTRL2_CTFG)
		need_clear = 1;

	if (need_clear) {
		ctrl2 = ctrl[1];
		ctrl2 &= ~(RX8025_BIT_CTRL2_CTFG | RX8025_BIT_CTRL2_WAFG |
			   RX8025_BIT_CTRL2_DAFG);

		err = rx8025_write_reg(client, RX8025_REG_CTRL2, ctrl2);
	}
out:
	return err;
}

/* Alarm support */
static int rx8025_read_alarm(struct device *dev, struct rtc_wkalrm *t)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct rx8025_data *rx8025 = dev_get_drvdata(dev);
	u8 ald[2];
	int ctrl2, err;

	err = rx8025_read_regs(client, RX8025_REG_ALDMIN, 2, ald);
	if (err)
		return err;

	ctrl2 = rx8025_read_reg(client, RX8025_REG_CTRL2);
	if (ctrl2 < 0)
		return ctrl2;

	dev_dbg(dev, "%s: read alarm 0x%02x 0x%02x ctrl2 %02x\n",
		__func__, ald[0], ald[1], ctrl2);

	/* Hardware alarms precision is 1 minute! */
	t->time.tm_sec = 0;
	t->time.tm_min = bcd2bin(ald[0] & 0x7f);
	if (rx8025->ctrl1 & RX8025_BIT_CTRL1_1224)
		t->time.tm_hour = bcd2bin(ald[1] & 0x3f);
	else
		t->time.tm_hour = bcd2bin(ald[1] & 0x1f) % 12
			+ (ald[1] & 0x20 ? 12 : 0);

	dev_dbg(dev, "%s: date: %ptRr\n", __func__, &t->time);
	t->enabled = !!(rx8025->ctrl1 & RX8025_BIT_CTRL1_DALE);
	t->pending = (ctrl2 & RX8025_BIT_CTRL2_DAFG) && t->enabled;

	return err;
}

static int rx8025_set_alarm(struct device *dev, struct rtc_wkalrm *t)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct rx8025_data *rx8025 = dev_get_drvdata(dev);
	u8 ald[2];
	int err;

	ald[0] = bin2bcd(t->time.tm_min);
	if (rx8025->ctrl1 & RX8025_BIT_CTRL1_1224)
		ald[1] = bin2bcd(t->time.tm_hour);
	else
		ald[1] = (t->time.tm_hour >= 12 ? 0x20 : 0)
			| bin2bcd((t->time.tm_hour + 11) % 12 + 1);

	dev_dbg(dev, "%s: write 0x%02x 0x%02x\n", __func__, ald[0], ald[1]);

	if (rx8025->ctrl1 & RX8025_BIT_CTRL1_DALE) {
		rx8025->ctrl1 &= ~RX8025_BIT_CTRL1_DALE;
		err = rx8025_write_reg(client, RX8025_REG_CTRL1,
				       rx8025->ctrl1);
		if (err)
			return err;
	}
	err = rx8025_write_regs(client, RX8025_REG_ALDMIN, 2, ald);
	if (err)
		return err;

	if (t->enabled) {
		rx8025->ctrl1 |= RX8025_BIT_CTRL1_DALE;
		err = rx8025_write_reg(client, RX8025_REG_CTRL1,
				       rx8025->ctrl1);
		if (err)
			return err;
	}

	return 0;
}

static int rx8025_alarm_irq_enable(struct device *dev, unsigned int enabled)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct rx8025_data *rx8025 = dev_get_drvdata(dev);
	u8 ctrl1;
	int err;

	ctrl1 = rx8025->ctrl1;
	if (enabled)
		ctrl1 |= RX8025_BIT_CTRL1_DALE;
	else
		ctrl1 &= ~RX8025_BIT_CTRL1_DALE;

	if (ctrl1 != rx8025->ctrl1) {
		rx8025->ctrl1 = ctrl1;
		err = rx8025_write_reg(client, RX8025_REG_CTRL1,
				       rx8025->ctrl1);
		if (err)
			return err;
	}
	return 0;
}

/*
 * According to the RX8025 SA/NB application manual the frequency and
 * temperature characteristics can be approximated using the following
 * equation:
 *
 *   df = a * (ut - t)**2
 *
 *   df: Frequency deviation in any temperature
 *   a : Coefficient = (-35 +-5) * 10**-9
 *   ut: Ultimate temperature in degree = +25 +-5 degree
 *   t : Any temperature in degree
 */
static int rx8025_read_offset(struct device *dev, long *offset)
{
	struct i2c_client *client = to_i2c_client(dev);
	int digoff;

	digoff = rx8025_read_reg(client, RX8025_REG_DIGOFF);
	if (digoff < 0)
		return digoff;

	*offset = digoff >= 64 ? digoff - 128 : digoff;
	if (*offset > 0)
		(*offset)--;
	*offset *= RX8025_ADJ_RESOLUTION;

	return 0;
}

static int rx8025_set_offset(struct device *dev, long offset)
{
	struct i2c_client *client = to_i2c_client(dev);
	u8 digoff;
	int err;

	offset /= RX8025_ADJ_RESOLUTION;
	if (offset > RX8025_ADJ_DATA_MAX)
		offset = RX8025_ADJ_DATA_MAX;
	else if (offset < RX8025_ADJ_DATA_MIN)
		offset = RX8025_ADJ_DATA_MIN;
	else if (offset > 0)
		offset++;
	else if (offset < 0)
		offset += 128;
	digoff = offset;

	err = rx8025_write_reg(client, RX8025_REG_DIGOFF, digoff);
	if (err)
		return err;

	return 0;
}

static const struct rtc_class_ops rx8025_rtc_ops = {
	.read_time = rx8025_get_time,
	.set_time = rx8025_set_time,
	.read_alarm = rx8025_read_alarm,
	.set_alarm = rx8025_set_alarm,
	.alarm_irq_enable = rx8025_alarm_irq_enable,
	.read_offset = rx8025_read_offset,
	.set_offset = rx8025_set_offset,
};

static ssize_t rx8025_sysfs_show_clock_adjust(struct device *dev,
					      struct device_attribute *attr,
					      char *buf)
{
	long adj;
	int err;

	dev_warn_once(dev, "clock_adjust_ppb is deprecated, use offset\n");
	err = rx8025_read_offset(dev, &adj);
	if (err)
		return err;

	return sprintf(buf, "%ld\n", -adj);
}

static ssize_t rx8025_sysfs_store_clock_adjust(struct device *dev,
					       struct device_attribute *attr,
					       const char *buf, size_t count)
{
	long adj;
	int err;

	dev_warn_once(dev, "clock_adjust_ppb is deprecated, use offset\n");
	if (kstrtol(buf, 10, &adj) != 0)
		return -EINVAL;

	err = rx8025_set_offset(dev, -adj);

	return err ? err : count;
}

static DEVICE_ATTR(clock_adjust_ppb, S_IRUGO | S_IWUSR,
		   rx8025_sysfs_show_clock_adjust,
		   rx8025_sysfs_store_clock_adjust);

static struct attribute *rx8025_attrs[] = {
	&dev_attr_clock_adjust_ppb.attr,
	NULL
};

static const struct attribute_group rx8025_attr_group = {
	.attrs	= rx8025_attrs,
};

static int rx8025_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = client->adapter;
	struct rx8025_data *rx8025;
	int err = 0;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA
				     | I2C_FUNC_SMBUS_I2C_BLOCK)) {
		dev_err(&adapter->dev,
			"doesn't support required functionality\n");
		return -EIO;
	}

	rx8025 = devm_kzalloc(&client->dev, sizeof(*rx8025), GFP_KERNEL);
	if (!rx8025)
		return -ENOMEM;

	i2c_set_clientdata(client, rx8025);

	if (id)
		rx8025->model = id->driver_data;

	err = rx8025_init_client(client);
	if (err)
		return err;

	rx8025->rtc = devm_rtc_allocate_device(&client->dev);
	if (IS_ERR(rx8025->rtc))
		return PTR_ERR(rx8025->rtc);

	rx8025->rtc->ops = &rx8025_rtc_ops;
	rx8025->rtc->range_min = RTC_TIMESTAMP_BEGIN_1900;
	rx8025->rtc->range_max = RTC_TIMESTAMP_END_2099;

	if (client->irq > 0) {
		dev_info(&client->dev, "IRQ %d supplied\n", client->irq);
		err = devm_request_threaded_irq(&client->dev, client->irq, NULL,
						rx8025_handle_irq,
						IRQF_ONESHOT,
						"rx8025", client);
		if (err)
			clear_bit(RTC_FEATURE_ALARM, rx8025->rtc->features);
	}

	rx8025->rtc->max_user_freq = 1;

	set_bit(RTC_FEATURE_ALARM_RES_MINUTE, rx8025->rtc->features);
	clear_bit(RTC_FEATURE_UPDATE_INTERRUPT, rx8025->rtc->features);

	err = rtc_add_group(rx8025->rtc, &rx8025_attr_group);
	if (err)
		return err;

	return devm_rtc_register_device(rx8025->rtc);
}

static struct i2c_driver rx8025_driver = {
	.driver = {
		.name = "rtc-rx8025",
	},
	.probe		= rx8025_probe,
	.id_table	= rx8025_id,
};

module_i2c_driver(rx8025_driver);

MODULE_AUTHOR("Wolfgang Grandegger <wg@grandegger.com>");
MODULE_DESCRIPTION("RX-8025 SA/NB RTC driver");
MODULE_LICENSE("GPL");
