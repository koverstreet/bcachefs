/*
 * Copyright (C) 2016 Eurotech S.p.A.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
/*
 * Version History.
 * 2016-10-26	0.6.0	fixed time fields in rtc_read_alarm function
 *
 * 2016-10-03	0.5.0	notify that UIE is not supported by our hw
 *			add mutex lock/unlock to read/set time functions
 *
 * 2016-07-12	0.4-0	Add clock_adj parameter for XT clock calibration
 *
 * 2016-04-20	0.3.0	Add board turn on feature
 *			Feature is enabled as parameter and can be changed
 *			via sysfs
 *			Trickle charger as module parameter
 *
 * 2016-04-01	0.2.0	Add alarm, watchdog functionality
 *			watchdog create a 60ms pulse on sRST pin 3.3V -> 0 -> 3.3V
 *			alarm create a 250ms pulse on nIRQ pin 3.3V -> 0 -> 3.3V
 *
 * 2016-01-22	0.1.0	First Release
 *			date time get/set commands
 *			256 byte get/set via sysfs.
 *			ram_address allows to get/set ram_byte
 *			watchdog
 *
 */

#include <linux/bcd.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rtc.h>
#include <linux/pm.h>
#include <linux/pm_wakeup.h>
#include <linux/watchdog.h>
#include <linux/jiffies.h>

#define DEFAULT_FORCE_SMBUS 0
static bool force_smbus = DEFAULT_FORCE_SMBUS;
module_param(force_smbus, bool, 0444);
MODULE_PARM_DESC(force_smbus, "force smbus protocol (default="
	__MODULE_STRING(DEFAULT_FORCE_SMBUS) ")");

#define DEFAULT_WATCHDOG_TIMEOUT        30
static int timeout = DEFAULT_WATCHDOG_TIMEOUT;
module_param(timeout, int, 0444);
MODULE_PARM_DESC(timeout, "Watchdog timeout in seconds. (1<=timeout<=124, default="
	__MODULE_STRING(DEFAULT_WATCHDOG_TIMEOUT) ")");

static bool nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, bool, 0444);
MODULE_PARM_DESC(nowayout, "Watchdog cannot be stopped once started (default="
	__MODULE_STRING(WATCHDOG_NOWAYOUT) ")");

#define DEFAULT_DISABLE_ON_BOOT 1
static bool disable_on_boot = DEFAULT_DISABLE_ON_BOOT;
module_param(disable_on_boot, bool, 0444);
MODULE_PARM_DESC(disable_on_boot, "Watchdog automatically disabled at boot time (default="
	__MODULE_STRING(DEFAULT_DISABLE_ON_BOOT)")");

/*
 * the following paramweter could be removed since revA board should
 * provide WDT IRQ to cortex via RST pin only
 */
#define DEFAULT_STEERING 1
static bool watchdog_steering = DEFAULT_STEERING;
module_param(watchdog_steering, bool, 0444);
MODULE_PARM_DESC(watchdog_steering, "Watchdog IRQ steering : 0 WIRQ , 1 RST (default="
	__MODULE_STRING(DEFAULT_STEERING)")");

#define DEFAULT_BOARD_TURN_ON 0
static bool board_turn_on = DEFAULT_BOARD_TURN_ON;
module_param(board_turn_on, bool, 0444);
MODULE_PARM_DESC(board_turn_on, "Enable board turn on via alarm route (default="
	__MODULE_STRING(DEFAULT_BOARD_TURN_ON)")");

#define DEFAULT_TRICKLE_REGISTER 0x00
static int trickle_register = DEFAULT_TRICKLE_REGISTER;
module_param(trickle_register, int, 0444);
MODULE_PARM_DESC(trickle_register, "trickle charger register (default="
	__MODULE_STRING(DEFAULT_TRICKLE_REGISTER)")");

#define DEFAULT_XT_CLOCK_ADJ 0
static int xt_clock_adj = DEFAULT_XT_CLOCK_ADJ;
module_param(xt_clock_adj, int, 0444);
MODULE_PARM_DESC(xt_clock_adj, "Adj parameter as per Ambiq micro procedure (default="
	__MODULE_STRING(DEFAULT_XT_CLOCK_ADJ)")");

#define DRIVER_NAME "rtc-am1805"
#define DRIVER_VERSION "0.6.0"

#define AM1805_IDENTITY_CODE	0x18
#define SECONDS_BITS	0x7F
#define MINUTES_BITS	0x7F
#define HOURS_BITS	0x3F
#define DATE_BITS	0x3F
#define MONTHS_BITS	0x1F
#define WEEKDAY_BITS	0x07

#define REG_HUNDREDS_ADDR	0x00	// hundreds of seconds register address
#define REG_SECONDS_ADDR	0x01	// seconds register address
#define REG_MINUTES_ADDR	0x02	// minutes register address
#define REG_HOURS_ADDR		0x03	// hours register address
#define REG_MDAY_ADDR		0x04	// day of the month register address
#define REG_MONTH_ADDR		0x05	// month register address
#define REG_YEAR_ADDR		0x06	// years register address
#define REG_WDAY_ADDR		0x07	// day of the week register address

#define REG_ALM_HUNDREDS_ADDR	0x08	// Alarm hundreds of seconds register address
#define REG_ALM_SECONDS_ADDR	0x09	// Alarm seconds register address
#define REG_ALM_MINUTES_ADDR	0x0A	// Alarm minutes register address
#define REG_ALM_HOURS_ADDR	0x0B	// Alarm hours register address
#define REG_ALM_MDAY_ADDR	0x0C	// Alarm day of the month register address
#define REG_ALM_MONTH_ADDR	0x0D	// Alarm month register address
#define REG_ALM_WDAY_ADDR	0x0E	// Alarm day of the week register address

#define REG_STATUS_ADDR		0x0F	// status register address
#define REG_STATUS_ALM	(1 << 2)	// Alarm function enabled
#define REG_STATUS_WDT	(1 << 5)	// Watchdog expired bit
#define REG_STATUS_CB	(1 << 7)	// Century rollover bit

#define REG_CONTROL1_ADDR	0x10	// control1 register address
#define REG_CONTROL1_WRTC	1	// write enable for counter registers
#define REG_CONTROL1_PWR2	(1 << 1)	// PWR2
#define REG_CONTROL1_ARST	(1 << 2)	// auto reset on read
#define REG_CONTROL1_RSP	(1 << 3)	// nRST polarity 1 high 0 low
#define REG_CONTROL1_OUT	(1 << 4)	// nIRQ pin static value
#define REG_CONTROL1_OUTB	(1 << 5)	// nIRQ2 pin static value
#define REG_CONTROL1_1224	(1 << 6)	// 12/24 format selection 0 = 24h
#define REG_CONTROL1_STOP	(1 << 7)	// stop the clocking system

#define REG_CONTROL2_ADDR	0x11	// control2 register address
#define REG_CONTROL2_OUT2S_BITS 0x1C	// control2 register out2s bits
#define REG_IRQ_MASK_ADDR	0x12	// Interrupt Mask register address
#define REG_IRQ_MASK_AIE	(1 << 2)	// Alarm interrupt enable

#define REG_XT_CALIB_ADDR	0x14	// XT calibration register address
#define REG_XT_CALIB_OFFSETX_MASK	0x7F	// OFFSET X BIT MASK
#define REG_XT_CALIB_CMDX	0x80	// cmdx field


#define REG_TIMER_CTRL_ADDR	0x18	// Countdown timer control register address
#define REG_TIMER_CTRL_RPT_BITS 0x1C	// only the RPT bits

#define REG_WATCHDOG_ADDR	0x1B	// watchdog register address
#define REG_WATCHDOG_WDS	(1 << 7)	// watchodg steering bit
#define WRB_1_SECOND	0x02		//watchdog clock 1Hz
#define WRB_4_SECONDS	0x03		//watchdog clock 1/4 Hz

#define REG_OSC_STATUS_ADDR	0x1D	// oscillator status register address
#define REG_OSC_STATUS_ACAL_MASK 0x60	// ACAL bit field mask
#define REG_OSC_STATUS_ACAL_0	0x00
#define REG_OSC_STATUS_ACAL_1	0x40
#define REG_OSC_STATUS_ACAL_2	0x80
#define REG_OSC_STATUS_ACAL_3	0xC0

#define REG_CONFIGKEY_ADDR	0x1F	// configuration key register address


#define REG_TRICKLE_ADDR	0x20	// trickle charger register

#define REG_IDENTITY_ADDR	0x28	// identity register address must contain 0x18

#define REG_EXTRAM_ADDR		0x3F	// Extension ram register address
#define REG_EXTRAM_XADA		(1 << 2)  //select bank of memory

static struct i2c_driver am1805_driver;

struct am1805_data {
	struct i2c_client   *client;
	struct rtc_device   *rtc;
	struct mutex        mutex;
	int	use_smbus;
	int	watchdog_timeout;
	int	watchdog_disable_on_boot;
	int	watchdog_steering;
	int	watchdog_registered;
	int	watchdog_enabled;
	unsigned char	watchdog_reg;
	unsigned long int	watchdog_start_jiffies;
	int	ram_byte_file_created;
	int	ram_address_file_created;
	unsigned char	ram_address;
	int	board_turn_on;
	int	board_turn_on_file_created;
	unsigned char trickle_register;
};

static int am1805_read(struct am1805_data *amq, u8 *buf, int len)
{
	int err, i;
	u8 base_reg;
	struct i2c_msg	msgs[] = {

		{
			.addr = amq->client->addr,
			.flags = (amq->client->flags & I2C_M_TEN),
			.len = 1,
			.buf = buf,
		},
		{
			.addr = amq->client->addr,
			.flags = (amq->client->flags & I2C_M_TEN) | I2C_M_RD,
			.len = len,
			.buf = buf,
		},
	};
	if (amq->use_smbus) {
		/* use SMBUS transfer protocol */
		base_reg = buf[0];
		for (i = 0; i < len; i++) {
			err = i2c_smbus_read_byte_data(amq->client, base_reg);
			if (err < 0) {
				dev_err(&amq->client->dev,
					"read transfer error reg 0x%02X\n",
					base_reg);
				break;
			}
			buf[i] = (u8)err;
			base_reg++;
			err = 0;
		}
	} else {
		/* use I2C transfer protocol */
		err = i2c_transfer(amq->client->adapter, msgs, 2);

		if (err != 2) {
			dev_err(&amq->client->dev, "I2C read transfer error\n");
			err = -EIO;
		} else {
			err = 0;
		}
	}
	return err;
}

static int am1805_write(struct am1805_data *amq, u8 *buf, int len)
{
	int err = 0, i;
	u8 base_reg;
	struct i2c_msg msgs[] = {
		{
		 .addr = amq->client->addr,
			.flags = (amq->client->flags & I2C_M_TEN),
		 .len = len + 1,
		 .buf = buf,
		 },
	};

	if (amq->use_smbus) {
		/* use SMBUS transfer protocol */
		base_reg = buf[0];
		for (i = 1; i <= len; i++) {
			err = i2c_smbus_write_byte_data(amq->client, base_reg,
							buf[i]);
			if (err < 0) {
				dev_err(&amq->client->dev,
					"write transfer error reg 0x%02X\n",
					base_reg);
				break;
			}
			base_reg++;
		}
	} else {
		/* use I2C transfer protocol */
		err = i2c_transfer(amq->client->adapter, msgs, 1);
		if (err != 1) {
			dev_err(&amq->client->dev, "I2C write transfer error\n");
			err = -EIO;
		} else {
			err = 0;
		}
	}
	return err;
}


static int am1805_stop_rtc(struct am1805_data *amq)
{
	u8 regs[2];
	int err;

	regs[0] = REG_CONTROL1_ADDR;

	err = am1805_read(amq, regs, 1);
	if (err < 0)
		return err;
	regs[1] = regs[0];
	regs[0] = REG_CONTROL1_ADDR;


	regs[1] |= (REG_CONTROL1_STOP|REG_CONTROL1_WRTC);

	err = am1805_write(amq, regs, 1);
	if (err < 0)
		return err;

	return 0;
}


static int am1805_start_rtc(struct am1805_data *amq)
{
	u8 regs[2];
	int err;

	regs[0] = REG_CONTROL1_ADDR;

	err = am1805_read(amq, regs, 1);
	if (err < 0)
		return err;
	regs[1] = regs[0];
	regs[0] = REG_CONTROL1_ADDR;

	regs[1] &= (~(REG_CONTROL1_STOP|REG_CONTROL1_WRTC));

	err = am1805_write(amq, regs, 1);
	if (err < 0)
		return err;

	return 0;
}

static int am1805_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct am1805_data *amq;
	u8 regs[8];
	int err;

	amq = i2c_get_clientdata(client);
	mutex_lock(&amq->mutex);

	regs[0] = REG_SECONDS_ADDR;
	err = am1805_read(amq, regs, 7);
	if (err)
		goto exit;

	/* read the status register */
	regs[7] = REG_STATUS_ADDR;
	err = am1805_read(amq, &regs[7], 1);
	if (err)
		goto exit;
	regs[0] &= SECONDS_BITS;
	regs[1] &= MINUTES_BITS;
	regs[2] &= HOURS_BITS;
	regs[3] &= DATE_BITS;
	regs[4] &= MONTHS_BITS;
	regs[6] &= WEEKDAY_BITS;

	tm->tm_sec = bcd2bin(regs[0]);
	tm->tm_min = bcd2bin(regs[1]);
	tm->tm_hour = bcd2bin(regs[2]);
	tm->tm_mday = bcd2bin(regs[3]);
	tm->tm_mon = bcd2bin(regs[4]);
	tm->tm_mon--;
	tm->tm_year = bcd2bin(regs[5])+100;

	if (regs[7] & REG_STATUS_CB)
		tm->tm_year += 100;
	tm->tm_wday = regs[6];

	err = rtc_valid_tm(tm);
exit:
	mutex_unlock(&amq->mutex);
	return err;
}


static int am1805_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct am1805_data *amq;
	u8 regs[10];
	int err;

	amq = i2c_get_clientdata(client);

	mutex_lock(&amq->mutex);

	err = am1805_stop_rtc(amq);
	if (err < 0)
		goto exit;
	regs[0] = REG_HUNDREDS_ADDR;
	regs[1] = bin2bcd(0);
	regs[2] = bin2bcd(tm->tm_sec);
	regs[3] = bin2bcd(tm->tm_min);
	regs[4] = bin2bcd(tm->tm_hour);
	regs[5] = bin2bcd(tm->tm_mday);
	regs[6] = bin2bcd(tm->tm_mon+1);
	regs[7] = bin2bcd(tm->tm_year - 100);
	regs[8] = tm->tm_wday;


	err = am1805_write(amq, regs, 8);
	if (am1805_start_rtc(amq))
		err =  -1;
exit:
	mutex_unlock(&amq->mutex);
	return err;
}

/*******************************************************************************
 * RAM byte
 * 256 bytes available
 * read return the byte pointed by ram_address
 * write store the values in ram_address
 */

static ssize_t am1805_ram_byte_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	int err;
	unsigned char ram_byte;
	struct i2c_client *client;
	struct am1805_data *amq;

	client = to_i2c_client(dev);
	amq = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s]\n", __func__);

	mutex_lock(&amq->mutex);
	ram_byte = amq->ram_address;
	ram_byte |= 0x80;
	err = am1805_read(amq, &ram_byte, 1);
	mutex_unlock(&amq->mutex);

	if (err == 0)
		err = sprintf(buf, "%02X\n", ram_byte);
	return err;
}

static ssize_t am1805_ram_byte_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	int err;
	unsigned char reg[2];
	struct i2c_client *client;
	struct am1805_data *amq;

	client = to_i2c_client(dev);
	amq = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s]\n", __func__);
	mutex_lock(&amq->mutex);

	err = kstrtou8(buf, 10, &reg[1]);
	if (err == 0) {
		reg[0] = amq->ram_address;
		reg[0] |= 0x80;
		err = am1805_write(amq, reg, 1);
	}

	mutex_unlock(&amq->mutex);
	if (err)
		return err;
	return count;
}

static const struct device_attribute am1805_ram_byte_device_attribute = {
	.attr.name  = "ram_byte",
	.attr.mode  = 0600,
	.show       = am1805_ram_byte_show,
	.store      = am1805_ram_byte_store,
};
/****** END RAM BYTE ATTIBUTES  ********/

/*******************************************************************************
 * RAM Address
 * 256 bytes available
 * read return current ram_address
 * write store the values in ram_address and set Extension Ram register
 */

static ssize_t am1805_ram_address_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	int err;
	struct i2c_client *client;
	struct am1805_data *amq;

	client = to_i2c_client(dev);
	amq = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s]\n", __func__);

	mutex_lock(&amq->mutex);
	err = sprintf(buf, "%02X\n", amq->ram_address);
	mutex_unlock(&amq->mutex);
	return err;
}

static ssize_t am1805_ram_address_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	int err;
	unsigned char reg[2], ram_addr;
	struct i2c_client *client;
	struct am1805_data *amq;

	client = to_i2c_client(dev);
	amq = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s]\n", __func__);
	mutex_lock(&amq->mutex);

	err = kstrtou8(buf, 10, &ram_addr);
	if (err == 0) {
		reg[0] = (unsigned char)(ram_addr ^ amq->ram_address);
		reg[0] &= 0x80;
		if (reg[0] == 0) {
			/* no changes , same bank of memory) */
			amq->ram_address = ram_addr;
		} else {
			reg[0] = REG_EXTRAM_ADDR;
			err = am1805_read(amq, reg, 1);
			if (err == 0) {
				reg[1] = reg[0];
				reg[0] = REG_EXTRAM_ADDR;
				if (ram_addr & 0x80)
					reg[1] |= REG_EXTRAM_XADA;
				else
					reg[1] &=  ~REG_EXTRAM_XADA;
				err = am1805_write(amq, reg, 1);
				if (err == 0)
					amq->ram_address = ram_addr;
			}
		}
	}

	mutex_unlock(&amq->mutex);
	if (err)
		return err;
	return count;
}

static const struct device_attribute am1805_ram_address_device_attribute = {
	.attr.name  = "ram_address",
	.attr.mode  = 0600,
	.show       = am1805_ram_address_show,
	.store      = am1805_ram_address_store,
};
/****** END RAM ADDRESS ATTIBUTES  ********/


/*******************************************************************************
 * WATCHDOG
 * gettimeleft function is implemented via jiffies since hw doesn't support
 * this capability
 */

static int am1805_watchdog_compute_seconds(int *seconds,
					    unsigned char *wdt_reg, int steer)
{
	int err = 0;
	unsigned char reg_value = 0x00;

	/* WatchDog-duration = BMB x stepsize */
	if (*seconds > 120) {
		*seconds = 124;
		reg_value = 31;
		reg_value <<= 2;
		reg_value |= WRB_4_SECONDS;
	} else if (*seconds > 31) {
		reg_value = (unsigned char)(*seconds);
		reg_value >>= 2;
		if (((int)reg_value * 4) != *seconds)
			reg_value++;
		*seconds = reg_value;
		*seconds <<= 2;
		reg_value <<= 2;
		reg_value |= WRB_4_SECONDS;
	} else if (*seconds >= 0) {
		reg_value = (unsigned char)*seconds;
		reg_value <<= 2;
		reg_value |= WRB_1_SECOND;
	} else {
		err =  -EINVAL;
	}
	if (steer)
		reg_value |= REG_WATCHDOG_WDS;
	if (wdt_reg != NULL)
		*wdt_reg = reg_value;
	return err;
}

static int am1805_watchdog_disable(struct am1805_data *am_data)
{
	int err;
	unsigned char regs[2];

	/* disable wdt */
	regs[0] = REG_WATCHDOG_ADDR;
	if (am_data->watchdog_steering)
		regs[1] = (unsigned char)REG_WATCHDOG_WDS;
	else
		regs[1] = 0x00;
	err = am1805_write(am_data, regs, 1);
	if (err) {
		dev_err(&am_data->client->dev,
			"[%s] write watchdog reg ERROR\n", __func__);
		return err;
	}
	regs[0] = REG_STATUS_ADDR;
	err = am1805_read(am_data, regs, 1);
	if (err) {
		dev_err(&am_data->client->dev,
			"[%s] read status reg ERROR\n", __func__);
		return err;
	}
	regs[1] = regs[0];
	regs[0] = REG_STATUS_ADDR;
	regs[1] &=  ~REG_STATUS_WDT;
	err = am1805_write(am_data, regs, 1);
	if (err)
		dev_err(&am_data->client->dev,
			"[%s] write status reg ERROR\n", __func__);
	am_data->watchdog_enabled = 0;
	return err;
}

static int am1805_watchdog_enable(struct am1805_data *am_data)
{
	int err;
	unsigned char regs[2];

	err = am1805_watchdog_disable(am_data);
	if (err)
		return err;
	/* CALCULATE THE REFRESH VALUE */
	err = am1805_watchdog_compute_seconds(&am_data->watchdog_timeout,
					      &am_data->watchdog_reg,
					      am_data->watchdog_steering);
	if (err) {
		dev_err(&am_data->client->dev,
			"[%s] problems while computing actual timeout\n",
			__func__);
		return err;
	}

	regs[0] = REG_WATCHDOG_ADDR;
	regs[1] = am_data->watchdog_reg;
	err = am1805_write(am_data, regs, 1);
	if (err) {
		dev_err(&am_data->client->dev,
			"[%s] write watchdog reg ERROR\n", __func__);
		return err;
	}
	am_data->watchdog_start_jiffies = jiffies;
	am_data->watchdog_enabled = 1;
	return 0;
}

static int am1805_watchdog_start_op(struct watchdog_device *device)
{
	int err;
	struct i2c_client *client;
	struct am1805_data *amq;

	client = watchdog_get_drvdata(device);
	amq = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s]\n", __func__);

	mutex_lock(&amq->mutex);
	/* disable wdt */
	//err=am1805_watchdog_disable(amq);
	//if (err==0) {
		err = am1805_watchdog_enable(amq);
		if (err == 0)
			dev_dbg(&client->dev,
				"[%s] watchdog enabled, seconds = %d\n",
				__func__, amq->watchdog_timeout);
	//}
	mutex_unlock(&amq->mutex);
	return err;
}

static int am1805_watchdog_stop_op(struct watchdog_device *device)
{
	int err;
	struct i2c_client *client;
	struct am1805_data *amq;

	client = watchdog_get_drvdata(device);
	amq = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s]\n", __func__);

	mutex_lock(&amq->mutex);
	err = am1805_watchdog_disable(amq);
	if (err == 0)
		dev_dbg(&client->dev, "[%s] watchdog disabled\n", __func__);
	mutex_unlock(&amq->mutex);
	return err;
}

static int am1805_watchdog_ping_op(struct watchdog_device *device)
{
	unsigned char regs[2];
	int err;
	struct i2c_client *client;
	struct am1805_data *amq;

	client = watchdog_get_drvdata(device);
	amq = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s]\n", __func__);

	mutex_lock(&amq->mutex);
	if (amq->watchdog_enabled) {
		regs[0] = REG_WATCHDOG_ADDR;
		regs[1] = amq->watchdog_reg;
		err = am1805_write(amq, regs, 1);
		if (err)
			dev_err(&amq->client->dev,
				"[%s] write watchdog reg ERROR\n", __func__);
	} else {
		err = 0;
		dev_dbg(&client->dev, "[%s] can not ping disabled watchdog\n",
			__func__);
	}
	mutex_unlock(&amq->mutex);
	return err;
}

static int am1805_watchdog_set_timeout_op(struct watchdog_device *device,
					   unsigned int timeout)
{
	int err;
	unsigned int seconds;
	struct i2c_client *client;
	struct am1805_data *amq;
	unsigned char reg_data;

	client = watchdog_get_drvdata(device);
	amq = i2c_get_clientdata(client);

	dev_dbg(&client->dev, "[%s]\n", __func__);
	seconds = (int)timeout;
	mutex_lock(&amq->mutex);
	err = am1805_watchdog_compute_seconds((int *)&seconds, &reg_data,
					      amq->watchdog_steering);
	if (err == 0) {
		device->timeout = (unsigned int)seconds;
		amq->watchdog_timeout = seconds;
		amq->watchdog_reg = reg_data;
	} else
		dev_err(&client->dev,
			"[%s] problems while computing actual timeout\n",
			__func__);

	mutex_unlock(&amq->mutex);
	return 0;
}

static unsigned int am1805_watchdog_get_timeleft_op(struct watchdog_device
						     *device)
{
	unsigned int time_left;
	struct i2c_client *client;
	struct am1805_data *amq;

	client = watchdog_get_drvdata(device);
	amq = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s]\n", __func__);
	mutex_lock(&amq->mutex);
	time_left = jiffies;
	time_left -= amq->watchdog_start_jiffies;
	time_left = (unsigned int)(time_left/HZ);
	mutex_unlock(&amq->mutex);
	return time_left;
}

static struct watchdog_info am1805_watchdog_info = {
	.options	= WDIOF_SETTIMEOUT | WDIOF_KEEPALIVEPING
			  | WDIOF_MAGICCLOSE,
	.firmware_version = 0x00000100,
	.identity       = "AM1805 Watchdog",
};

static struct watchdog_ops am1805_watchdog_ops = {
	.owner          = THIS_MODULE,
	.start          = am1805_watchdog_start_op,
	.stop           = am1805_watchdog_stop_op,
	.ping           = am1805_watchdog_ping_op,
	.set_timeout    = am1805_watchdog_set_timeout_op,
	.get_timeleft   = am1805_watchdog_get_timeleft_op,
};

static struct watchdog_device am1805_watchdog_device = {
	.info           = &am1805_watchdog_info,
	.ops            = &am1805_watchdog_ops,
	.timeout        = DEFAULT_WATCHDOG_TIMEOUT,
	.min_timeout    = 1,
	.max_timeout    = 124,
};

/****** END Watchdog FUNCTIONS  ********/

/****** START ALARM FUNCTIONS   ********/

static int am1805_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *alarm)
{
	int err;
	unsigned char regs[7];
	struct i2c_client *client;
	struct am1805_data *amq;

	client = to_i2c_client(dev);
	amq = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s]\n", __func__);
	mutex_lock(&amq->mutex);
	regs[0] = REG_ALM_SECONDS_ADDR;
	err = am1805_read(amq, regs, 6);
	if (err) {
		dev_err(&client->dev, "[%s] read %02X 6 register\n", __func__,
			REG_ALM_SECONDS_ADDR);
		goto exit;
	}
	regs[0] &= SECONDS_BITS;
	regs[1] &= MINUTES_BITS;
	regs[2] &= HOURS_BITS;
	regs[3] &= DATE_BITS;
	regs[4] &= MONTHS_BITS;
	regs[5] &= WEEKDAY_BITS;

	alarm->time.tm_sec  = bcd2bin(regs[0]);
	alarm->time.tm_min  = bcd2bin(regs[1]);
	alarm->time.tm_hour = bcd2bin(regs[2]);
	alarm->time.tm_mday = bcd2bin(regs[3]);
	alarm->time.tm_mon  = bcd2bin(regs[4]);
	if (alarm->time.tm_mon > 0)
		alarm->time.tm_mon--;
	alarm->time.tm_wday = regs[5];

	alarm->time.tm_year = -1;
	alarm->time.tm_yday = -1;
	alarm->time.tm_isdst = -1;

	regs[0] = REG_IRQ_MASK_ADDR;
	err = am1805_read(amq, regs, 1);
	if (err) {
		dev_err(&client->dev, "[%s] read %02X 1 register\n", __func__,
			REG_IRQ_MASK_ADDR);
		goto exit;
	}
	alarm->enabled = (regs[0] & REG_IRQ_MASK_AIE) ? 1 : 0;

	regs[0] = REG_STATUS_ADDR;
	err = am1805_read(amq, regs, 1);
	if (err) {
		dev_err(&client->dev, "[%s] read %02X 1 register\n",
			__func__, REG_STATUS_ADDR);
		goto exit;
	}
	alarm->pending = (regs[0] & REG_STATUS_ALM) ? 1 : 0;
exit:
	mutex_unlock(&amq->mutex);
	return err;
}


static int am1805_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *alarm)
{
	int err;
	unsigned char regs[8];
	unsigned char timer_ctrl_reg, irq_mask_reg;
	struct i2c_client *client;
	struct am1805_data *amq;

	client = to_i2c_client(dev);
	amq = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s]\n", __func__);
	/* Disable alarm */
	mutex_lock(&amq->mutex);
	regs[0] = REG_TIMER_CTRL_ADDR;
	err = am1805_read(amq, regs, 1);
	if (err) {
		dev_err(&client->dev, "[%s] read %02X 1 register\n",
			__func__, REG_TIMER_CTRL_ADDR);
		err = -EIO;
		goto exit;
	}
	regs[1] = regs[0];
	regs[0] = REG_TIMER_CTRL_ADDR;
	regs[1] &= (unsigned char)(~REG_TIMER_CTRL_RPT_BITS);
	timer_ctrl_reg = regs[1];
	err = am1805_write(amq, regs, 1);
	if (err) {
		dev_err(&client->dev, "[%s] write %02X 1 register\n",
			__func__, REG_TIMER_CTRL_ADDR);
		err = -EIO;
		goto exit;
	}

	regs[0] = REG_IRQ_MASK_ADDR;
	err = am1805_read(amq, regs, 1);
	if (err) {
		dev_err(&client->dev, "[%s] read %02X 1 register\n",
			__func__, REG_IRQ_MASK_ADDR);
		err = -EIO;
		goto exit;
	}
	regs[1] = regs[0];
	regs[0] = REG_IRQ_MASK_ADDR;
	regs[1] &= (unsigned char)(~REG_IRQ_MASK_AIE);
	irq_mask_reg = regs[1];
	err = am1805_write(amq, regs, 1);
	if (err) {
		dev_err(&client->dev, "[%s] write %02X 1 register\n",
			__func__, REG_IRQ_MASK_ADDR);
		err = -EIO;
		goto exit;
	}
	regs[0] = REG_STATUS_ADDR;
	err = am1805_read(amq, regs, 1);
	if (err) {
		dev_err(&client->dev, "[%s] read %02X 1 register\n",
			__func__, REG_STATUS_ADDR);
		err = -EIO;
		goto exit;
	}
	regs[1] = regs[0];
	regs[0] = REG_STATUS_ADDR;
	regs[1] &= (unsigned char)(~REG_STATUS_ALM);
	err = am1805_write(amq, regs, 1);
	if (err) {
		dev_err(&client->dev, "[%s] write %02X 1 register\n",
			__func__, REG_STATUS_ADDR);
		err = -EIO;
		goto exit;
	}
	if (alarm->enabled) {
		regs[0] = REG_ALM_HUNDREDS_ADDR;
		regs[1] = bin2bcd(0);	/* hundreds of seconds */
		regs[2] = bin2bcd(alarm->time.tm_sec);
		regs[3] = bin2bcd(alarm->time.tm_min);
		regs[4] = bin2bcd(alarm->time.tm_hour);
		regs[5] = bin2bcd(alarm->time.tm_mday);
		regs[6] = bin2bcd(alarm->time.tm_mon + 1);
		regs[7] = (unsigned char)(alarm->time.tm_wday & 0x07);
		err = am1805_write(amq, regs, 7);
		if (err) {
			dev_err(&client->dev, "[%s] write %02X 7 register\n",
				__func__, REG_ALM_HUNDREDS_ADDR);
			err = -EIO;
			goto exit;
		}
		regs[0] = REG_IRQ_MASK_ADDR;
		regs[1] = irq_mask_reg;
		regs[1] |= REG_IRQ_MASK_AIE;
		err = am1805_write(amq, regs, 1);
		if (err) {
			dev_err(&client->dev, "[%s] write %02X 1 register\n",
				__func__, REG_IRQ_MASK_ADDR);
			err = -EIO;
			goto exit;
		}
		regs[0] = REG_TIMER_CTRL_ADDR;
		regs[1] = timer_ctrl_reg;
		regs[1] |= (unsigned char)(1 << 2);
		err = am1805_write(amq, regs, 1);
		if (err) {
			dev_err(&client->dev,
				"[%s] write %02X 1 register\n", __func__,
				REG_TIMER_CTRL_ADDR);
			err = -EIO;
		}
	}
exit:
	mutex_unlock(&amq->mutex);
	return err;
}

static ssize_t am1805_board_turn_on_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	int err;
	struct i2c_client *client;
	struct am1805_data *amq;

	client = to_i2c_client(dev);
	amq = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s]\n", __func__);
	if (amq->board_turn_on)
		err = sprintf(buf, "1\n");
	else
		err = sprintf(buf, "0\n");
	return err;
}

static ssize_t am1805_board_turn_on_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	int err, value;
	struct i2c_client *client;
	struct am1805_data *amq;
	unsigned char regs[4];

	client = to_i2c_client(dev);
	amq = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s]\n", __func__);
	mutex_lock(&amq->mutex);

	err = kstrtos32(buf, 10, &value);
	if (err == 0) {
		regs[0] = REG_CONTROL1_ADDR;
		err = am1805_read(amq, regs, 2);
		if (err) {
			dev_err(&client->dev,
				"[%s] read %02X register , count=2\n",
				__func__, REG_CONTROL1_ADDR);
			err = -EIO;
			goto exit;
		}
		regs[2] = regs[1];
		regs[1] = regs[0];
		regs[0] = REG_CONTROL1_ADDR;
		regs[1] |= REG_CONTROL1_OUTB;
		regs[2] &= (unsigned char)(~REG_CONTROL2_OUT2S_BITS);
		if (value == 0) {
			regs[2] |= (unsigned char)(7 << 2);
			amq->board_turn_on = 0;
		} else {
			regs[2] |= (unsigned char)(3 << 2);
			amq->board_turn_on = 1;
		}
		err = am1805_write(amq, regs, 2);
		if (err) {
			dev_err(&client->dev,
				"[%s] write %02X register , count=2\n",
				__func__, REG_CONTROL1_ADDR);
			err = -EIO;
			goto exit;
		} else
			err = count;
	}
exit:
	mutex_unlock(&amq->mutex);
	return err;
}

static const struct device_attribute am1805_board_turn_on_device_attribute = {
	.attr.name  = "board_turn_on",
	.attr.mode  = 0600,
	.show       = am1805_board_turn_on_show,
	.store      = am1805_board_turn_on_store,
};

/****** END ALARM FUNCTIONS     ********/

static const struct rtc_class_ops am1805_rtc_ops = {
	.read_time	= am1805_rtc_read_time,
	.set_time	= am1805_rtc_set_time,
	.set_alarm	= am1805_rtc_set_alarm,
	.read_alarm	= am1805_rtc_read_alarm,
};

static void am1805_unload(struct i2c_client *client)
{
	struct am1805_data *amq;

	dev_dbg(&client->dev, "[%s]\n", __func__);

	amq = i2c_get_clientdata(client);
	if (amq->ram_byte_file_created) {
		sysfs_remove_file(&client->dev.kobj,
				  &am1805_ram_byte_device_attribute.attr);
	}
	if (amq->ram_address_file_created) {
		sysfs_remove_file(&client->dev.kobj,
				  &am1805_ram_address_device_attribute.attr);
	}
	if (amq->board_turn_on_file_created) {
		sysfs_remove_file(&client->dev.kobj,
				  &am1805_board_turn_on_device_attribute.attr);
	}

	if (amq->watchdog_registered) {
		device_wakeup_disable(&client->dev);
		watchdog_unregister_device(&am1805_watchdog_device);
	}
	devm_kfree(&client->dev, amq);
}

static int am1805_probe(struct i2c_client *client,
			 const struct i2c_device_id *id)
{
	struct am1805_data *amq;
	int err;
	u8 regs[2];
	u8 xt_calib_value = 0;
	u32 smbus_func = (I2C_FUNC_SMBUS_BYTE_DATA | I2C_FUNC_SMBUS_WORD_DATA
			  | I2C_FUNC_SMBUS_I2C_BLOCK);

	dev_info(&client->dev, "probe_start, driver version %s\n",
		 DRIVER_VERSION);

	amq = devm_kzalloc(&client->dev, sizeof(struct am1805_data),
			   GFP_KERNEL);
	if (amq == NULL) {
		err = -ENOMEM;
		dev_err(&client->dev,
			"failed to allocate memory for module data: %d\n", err);
		goto exit;
	}
	amq->ram_byte_file_created = 0;
	amq->ram_address_file_created = 0;
	amq->watchdog_timeout = timeout;
	amq->watchdog_disable_on_boot = disable_on_boot;
	amq->watchdog_steering = watchdog_steering;
	amq->watchdog_enabled = 0;
	amq->board_turn_on = board_turn_on;
	amq->board_turn_on_file_created = 0;
	amq->trickle_register = (unsigned char)trickle_register;
	if (amq->watchdog_steering)
		amq->watchdog_reg = REG_WATCHDOG_WDS;
	else
		amq->watchdog_reg = 0;
	amq->watchdog_start_jiffies = 0;
	amq->watchdog_registered = 0;
	if ((i2c_check_functionality(client->adapter, I2C_FUNC_I2C))
	    && (force_smbus == 0)) {
		amq->use_smbus = 0;
	} else {
		dev_warn(&client->dev, "client not i2c capable\n");
		if (i2c_check_functionality(client->adapter, smbus_func)) {
			amq->use_smbus = 1;
			dev_warn(&client->dev, "client smbus capable\n");
		} else {
			err = -ENODEV;
			dev_err(&client->dev, "client not SMBUS capable\n");
			goto exit;
		}
	}

	mutex_init(&amq->mutex);

	amq->client = client;
	i2c_set_clientdata(client, amq);

	/* check identity register */
	regs[0] = REG_IDENTITY_ADDR;
	if (am1805_read(amq, regs, 1)) {
		err = -ENODEV;
		dev_err(&client->dev,
			"fail to fetch identity register 0x%02X\n",
			REG_IDENTITY_ADDR);
		goto exit;
	}

	if (regs[0] != AM1805_IDENTITY_CODE) {
		err = -ENODEV;
		dev_err(&client->dev,
			"chip not found,invalid identity code 0x%02X\n",
			regs[0]);
		goto exit;

	}

	/* set the trickle_register */
	regs[0] = REG_CONFIGKEY_ADDR;
	regs[1] = 0x9D;
	if (am1805_write(amq, regs, 1)) {
		err = -ENODEV;
		dev_err(&client->dev,
			"fail to set configuration key register\n");
		goto exit;
	}
	regs[0] = REG_TRICKLE_ADDR;
	regs[1] = amq->trickle_register;
	if (am1805_write(amq, regs, 1)) {
		err = -ENODEV;
		dev_err(&client->dev, "fail to set trickle register\n");
		goto exit;
	}

	/* set extended ram register to default value */
	amq->ram_address = 0x00;
	regs[0] = REG_EXTRAM_ADDR;

	if (am1805_read(amq, regs, 1)) {
		err = -ENODEV;
		dev_err(&client->dev, "fail to fetch extension ram register\n");
		goto exit;
	}
	regs[1] = regs[0];
	regs[0] = REG_EXTRAM_ADDR;
	regs[1] &= ~REG_EXTRAM_XADA;

	if (am1805_write(amq, regs, 1)) {
		err = -ENODEV;
		dev_err(&client->dev, "fail to set extension ram register\n");
		goto exit;
	}

	/* ulock LKO2 in oscillator status register in order to drive OUTB */
	/*
	 * Bit_6-7 xtcal = 0
	 * Bit_5 LKO2 = 0
	 * Bit_4 OMODE = 0
	 * Bit_2-3 RESERVED = 0
	 * Bit_1 OF = 1
	 * Bit_0 ACF = 0
	 */
	/* calibrate the XT oscillator */
	regs[1] = 0x02;
	xt_calib_value = 0x00;
	if (xt_clock_adj <  -320)
		dev_warn(&client->dev,
			 "XT frequency too high to be calibrated adj = %d\n",
			 xt_clock_adj);
	else if (xt_clock_adj <  -256) {
		/* XTCAL=3 CMDX=1 OFFSETX=(adj+192)/2 */
		regs[1] |= REG_OSC_STATUS_ACAL_3;
		xt_calib_value = (unsigned char)((int)(xt_clock_adj+192)>>1);
		xt_calib_value &= REG_XT_CALIB_OFFSETX_MASK;
		xt_calib_value |= REG_XT_CALIB_CMDX;
	} else if (xt_clock_adj <  -192) {
		/* XTCAL=3 CMDX=0 OFFSETX=(adj+192) */
		regs[1] |= REG_OSC_STATUS_ACAL_3;
		xt_calib_value = (unsigned char)((int)(xt_clock_adj+192));
		xt_calib_value &= REG_XT_CALIB_OFFSETX_MASK;
	} else if (xt_clock_adj <  -128) {
		/* XTCAL=2 CMDX=0 OFFSETX=(adj+128) */
		regs[1] |= REG_OSC_STATUS_ACAL_2;
		xt_calib_value = (unsigned char)((int)(xt_clock_adj+128));
		xt_calib_value &= REG_XT_CALIB_OFFSETX_MASK;
	} else if (xt_clock_adj <  -64) {
		/* XTCAL=1 CMDX=0 OFFSETX=(adj+64) */
		regs[1] |= REG_OSC_STATUS_ACAL_1;
		xt_calib_value = (unsigned char)((int)(xt_clock_adj+64));
		xt_calib_value &= REG_XT_CALIB_OFFSETX_MASK;
	} else if (xt_clock_adj < 64) {
		/* XTCAL=0 CMDX=0 OFFSETX=(adj) */
		regs[1] |= REG_OSC_STATUS_ACAL_0;
		xt_calib_value = (unsigned char)(xt_clock_adj);
		xt_calib_value &= REG_XT_CALIB_OFFSETX_MASK;
	} else if (xt_clock_adj < 128) {
		/* XTCAL=0 CMDX=1 OFFSETX=(adj)/2 */
		regs[1] |= REG_OSC_STATUS_ACAL_0;
		xt_calib_value = (unsigned char)((int)(xt_clock_adj>>1));
		xt_calib_value &= REG_XT_CALIB_OFFSETX_MASK;
		xt_calib_value |= REG_XT_CALIB_CMDX;
	} else
		dev_warn(&client->dev,
			 "XT frequency too low to be calibrated adj = %d\n",
			 xt_clock_adj);

	regs[0] = REG_OSC_STATUS_ADDR;
	if (am1805_write(amq, regs, 1)) {
		err = -ENODEV;
		dev_err(&client->dev,
			"fail to set oscillator status register\n");
		goto exit;
	}

	/* Calibration XT Register */
	regs[0] = REG_XT_CALIB_ADDR;
	regs[1] = xt_calib_value;
	if (am1805_write(amq, regs, 1)) {
		err = -ENODEV;
		dev_err(&client->dev, "fail to set XT calibration register\n");
		goto exit;
	}

	/*
	 * CONTROL1 register
	 * STOP = 0	12/24 = 0
	 * OUTB = 1 remove power latch due to rtc , OUT = 1
	 * RSP = 0 due to watchdog  active low
	 * ARST = 0	PWR2 = 1 WRTC = 1
	 */
	regs[0] = REG_CONTROL1_ADDR;
	regs[1] = (REG_CONTROL1_OUTB|REG_CONTROL1_OUT | REG_CONTROL1_PWR2
		   | REG_CONTROL1_WRTC);
	if (am1805_write(amq, regs, 1)) {
		err = -ENODEV;
		dev_err(&client->dev, "fail to set control1 register\n");
		goto exit;
	}

	/*
	 * CONTROL2 register
	 * Bit_6-7 reseved = 0
	 * Bit_5   RS1E	= 0 due to watchdog
	 * Bit_2-4 OUT2S = 7 (board_turn_on =0) ; (3 board turn on =1)
	 * Bit_0-1 OUT1S = 3 due to alarm
	 */
	regs[0] = REG_CONTROL2_ADDR;
	regs[1] = 0;
	if (amq->board_turn_on)
		regs[1] |= 0x03;
	else
		regs[1] |= 0x07;
	regs[1] <<= 2;
	regs[1] |= 0x03;

	if (am1805_write(amq, regs, 1)) {
		err = -ENODEV;
		dev_err(&client->dev, "fail to set control2 register\n");
		goto exit;
	}

	/*
	 * alarm IRQ must be on level
	 * Bit_7   CEB = 1
	 * Bit_5-6 IM = 3 ALARM IRQ 1/4 sec
	 * Bit_4 BLIE = 0
	 * Bit_3 TIE = 0
	 * Bit_2 AIE = 0
	 * Bit_1 EX2E = 0
	 * Bit_0 EX1E = 0
	 */
	regs[0] = REG_IRQ_MASK_ADDR;
	regs[1] = 0xE0;	/* set im field to 0 */
	if (am1805_write(amq, regs, 1)) {
		err = -ENODEV;
		dev_err(&client->dev, "fail to set interrupt mask register\n");
		goto exit;
	}
	/*
	 * Disable alarm interrupt
	 * Bit_7 TE = 0
	 * Bit_6 TM = 0
	 * Bit_5 TRPT = 1
	 * Bit_2-4 RPT=0	ALARM DISABLE
	 * Bit_0-1 TFS=3
	 */
	regs[0] = REG_TIMER_CTRL_ADDR;
	regs[1] = 0x23;
	if (am1805_write(amq, regs, 1)) {
		err = -ENODEV;
		dev_err(&client->dev,
			"fail to set countdown timer control register\n");
		goto exit;
	}


	/* clear the status register */
	regs[0] = REG_STATUS_ADDR;
	regs[1] = 0x00;
	if (am1805_write(amq, regs, 1)) {
		err = -ENODEV;
		dev_err(&client->dev, "fail to clear status register\n");
		goto exit;
	}

	amq->rtc = devm_rtc_device_register(&client->dev,
					    am1805_driver.driver.name,
					    &am1805_rtc_ops, THIS_MODULE);

	if (IS_ERR(amq->rtc)) {
		dev_err(&client->dev, "fail to register rtc device\n");
		err = PTR_ERR(amq->rtc);
		goto exit;
	}
	amq->rtc->uie_unsupported = 1;


	/* RAM byte initialization */
	err = sysfs_create_file(&client->dev.kobj,
				&am1805_ram_byte_device_attribute.attr);
	if (err) {
		dev_err(&client->dev, "fail to create sysfs file \"%s\"\n",
			am1805_ram_byte_device_attribute.attr.name);
		goto exit;
	}
	amq->ram_byte_file_created = 1;

	/* RAM address initialization */
	err = sysfs_create_file(&client->dev.kobj,
				&am1805_ram_address_device_attribute.attr);
	if (err) {
		dev_err(&client->dev, "fail to create sysfs file \"%s\"\n",
			am1805_ram_address_device_attribute.attr.name);
		goto exit;
	}
	amq->ram_address_file_created = 1;

	/* board turn on initialization */
	err = sysfs_create_file(&client->dev.kobj,
				&am1805_board_turn_on_device_attribute.attr);
	if (err) {
		dev_err(&client->dev, "fail to create sysfs file \"%s\"\n",
			am1805_board_turn_on_device_attribute.attr.name);
		goto exit;
	}
	amq->board_turn_on_file_created = 1;

	/* Watchdog driver registration */
	watchdog_set_drvdata(&am1805_watchdog_device, client);
	watchdog_init_timeout(&am1805_watchdog_device, amq->watchdog_timeout,
			      NULL);
	watchdog_set_nowayout(&am1805_watchdog_device, nowayout);
	err = watchdog_register_device(&am1805_watchdog_device);
	if (err) {
		dev_err(&client->dev,
			"ERROR, FAIL to register watchdog device\n");
		goto exit;
	}
	amq->watchdog_registered = 1;
	dev_info(&client->dev, "registered %s as watchdog%d\n",
		 am1805_driver.driver.name, am1805_watchdog_device.id);

	if (amq->watchdog_disable_on_boot) {
		dev_info(&client->dev, "watchdog timer disabled at boot\n");
		err = am1805_watchdog_disable(amq);
		if (err)
			goto exit;
	} else {
		dev_info(&client->dev,
			 "watchdog timer enabled at boot, %d s\n",
			 amq->watchdog_timeout);
		err = am1805_watchdog_enable(amq);
		if (err)
			goto exit;
	}
	err = device_init_wakeup(&client->dev, true);
	if (err)
		dev_err(&client->dev, "dev_init_wakeup [%d] FAIL\n", err);
	dev_info(&client->dev, "probe_end, init OK\n");
	return 0;
exit:
	dev_info(&client->dev, "probe_end, init FAIL\n");
	am1805_unload(client);
	return err;
}

static int am1805_remove(struct i2c_client *client)
{
	dev_dbg(&client->dev, "[%s]\n", __func__);
	am1805_unload(client);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int am1805_resume(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct am1805_data *amq;
	unsigned char regs[2];
	int err;

	amq = i2c_get_clientdata(client);

	dev_dbg(&client->dev, "[%s]\n", __func__);
	mutex_lock(&amq->mutex);
	/* is alarm expired? */
	regs[0] = REG_STATUS_ADDR;
	err = am1805_read(amq, regs, 1);
	if (err) {
		dev_err(&client->dev, "[%s] read %02X 1 register\n",
			__func__, REG_STATUS_ADDR);
		err = -EIO;
		goto exit;
	}

	if (regs[0] & REG_STATUS_ALM) {
		/* Disable alarm */
		regs[0] = REG_TIMER_CTRL_ADDR;
		err = am1805_read(amq, regs, 1);
		if (err) {
			dev_err(&client->dev, "[%s] read %02X 1 register\n",
				__func__, REG_TIMER_CTRL_ADDR);
			err = -EIO;
			goto exit;
		}
		regs[1] = regs[0];
		regs[0] = REG_TIMER_CTRL_ADDR;
		regs[1] &= (unsigned char)(~REG_TIMER_CTRL_RPT_BITS);
		err = am1805_write(amq, regs, 1);
		if (err) {
			dev_err(&client->dev, "[%s] write %02X 1 register\n",
				__func__, REG_TIMER_CTRL_ADDR);
			err = -EIO;
			goto exit;
		}

		regs[0] = REG_IRQ_MASK_ADDR;
		err = am1805_read(amq, regs, 1);
		if (err) {
			dev_err(&client->dev, "[%s] read %02X 1 register\n",
				__func__, REG_IRQ_MASK_ADDR);
			err = -EIO;
			goto exit;
		}
		regs[1] = regs[0];
		regs[0] = REG_IRQ_MASK_ADDR;
		regs[1] &= (unsigned char)(~REG_IRQ_MASK_AIE);
		err = am1805_write(amq, regs, 1);
		if (err) {
			dev_err(&client->dev, "[%s] write %02X 1 register\n",
				__func__, REG_IRQ_MASK_ADDR);
			err = -EIO;
			goto exit;
		}
		regs[0] = REG_STATUS_ADDR;
		err = am1805_read(amq, regs, 1);
		if (err) {
			dev_err(&client->dev, "[%s] read %02X 1 register\n",
				__func__, REG_STATUS_ADDR);
			err = -EIO;
			goto exit;
		}
		regs[1] = regs[0];
		regs[0] = REG_STATUS_ADDR;
		regs[1] &= (unsigned char)(~REG_STATUS_ALM);
		err = am1805_write(amq, regs, 1);
		if (err) {
			dev_err(&client->dev, "[%s] write %02X 1 register\n",
				__func__, REG_STATUS_ADDR);
			err = -EIO;
			goto exit;
		}
	}

exit:
	mutex_unlock(&amq->mutex);
	return err;
}

static int am1805_suspend(struct device *dev)
{
	/* nothing to do at the moment */
	return 0;
}
#else
#define am1805_suspend	NULL
#define am1805_resume	NULL
#endif /* CONFIG_PM_SLEEP */

static SIMPLE_DEV_PM_OPS(am1805_pm, am1805_suspend, am1805_resume);

static const struct i2c_device_id am1805_id[] = {
	{ "am1805", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, am1805_id);

static struct i2c_driver am1805_driver = {
	.driver = {
		.name = DRIVER_NAME,
		.owner = THIS_MODULE,
		.pm    = &am1805_pm,
	},
	.probe = am1805_probe,
	.remove = am1805_remove,
	.id_table = am1805_id,
};
module_i2c_driver(am1805_driver);

MODULE_AUTHOR("Pierluigi Driusso <pierluigi.driusso@eurotech.com>");
MODULE_DESCRIPTION("Ambiq micro AM1805 RTC driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRIVER_VERSION);
