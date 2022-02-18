// SPDX-License-Identifier: GPL-2.0
//
// cs35l41-spi.c -- CS35l41 SPI driver
//
// Copyright 2017-2021 Cirrus Logic, Inc.
//
// Author: David Rhodes	<david.rhodes@cirrus.com>

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>

#include <sound/cs35l41.h>
#include "cs35l41.h"

static struct regmap_config cs35l41_regmap_spi = {
	.reg_bits = 32,
	.val_bits = 32,
	.pad_bits = 16,
	.reg_stride = CS35L41_REGSTRIDE,
	.reg_format_endian = REGMAP_ENDIAN_BIG,
	.val_format_endian = REGMAP_ENDIAN_BIG,
	.max_register = CS35L41_LASTREG,
	.reg_defaults = cs35l41_reg,
	.num_reg_defaults = ARRAY_SIZE(cs35l41_reg),
	.volatile_reg = cs35l41_volatile_reg,
	.readable_reg = cs35l41_readable_reg,
	.precious_reg = cs35l41_precious_reg,
	.cache_type = REGCACHE_RBTREE,
};

static const struct spi_device_id cs35l41_id_spi[] = {
	{ "cs35l40", 0 },
	{ "cs35l41", 0 },
	{}
};

MODULE_DEVICE_TABLE(spi, cs35l41_id_spi);

static int cs35l41_spi_probe(struct spi_device *spi)
{
	const struct regmap_config *regmap_config = &cs35l41_regmap_spi;
	struct cs35l41_platform_data *pdata = dev_get_platdata(&spi->dev);
	struct cs35l41_private *cs35l41;
	int ret;

	cs35l41 = devm_kzalloc(&spi->dev, sizeof(struct cs35l41_private), GFP_KERNEL);
	if (!cs35l41)
		return -ENOMEM;

	spi->max_speed_hz = CS35L41_SPI_MAX_FREQ;
	spi_setup(spi);

	spi_set_drvdata(spi, cs35l41);
	cs35l41->regmap = devm_regmap_init_spi(spi, regmap_config);
	if (IS_ERR(cs35l41->regmap)) {
		ret = PTR_ERR(cs35l41->regmap);
		dev_err(&spi->dev, "Failed to allocate register map: %d\n", ret);
		return ret;
	}

	cs35l41->dev = &spi->dev;
	cs35l41->irq = spi->irq;

	return cs35l41_probe(cs35l41, pdata);
}

static int cs35l41_spi_remove(struct spi_device *spi)
{
	struct cs35l41_private *cs35l41 = spi_get_drvdata(spi);

	cs35l41_remove(cs35l41);

	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id cs35l41_of_match[] = {
	{ .compatible = "cirrus,cs35l40" },
	{ .compatible = "cirrus,cs35l41" },
	{},
};
MODULE_DEVICE_TABLE(of, cs35l41_of_match);
#endif

#ifdef CONFIG_ACPI
static const struct acpi_device_id cs35l41_acpi_match[] = {
	{ "CSC3541", 0 }, /* Cirrus Logic PnP ID + part ID */
	{},
};
MODULE_DEVICE_TABLE(acpi, cs35l41_acpi_match);
#endif

static struct spi_driver cs35l41_spi_driver = {
	.driver = {
		.name		= "cs35l41",
		.of_match_table = of_match_ptr(cs35l41_of_match),
		.acpi_match_table = ACPI_PTR(cs35l41_acpi_match),
	},
	.id_table	= cs35l41_id_spi,
	.probe		= cs35l41_spi_probe,
	.remove		= cs35l41_spi_remove,
};

module_spi_driver(cs35l41_spi_driver);

MODULE_DESCRIPTION("SPI CS35L41 driver");
MODULE_AUTHOR("David Rhodes, Cirrus Logic Inc, <david.rhodes@cirrus.com>");
MODULE_LICENSE("GPL");
