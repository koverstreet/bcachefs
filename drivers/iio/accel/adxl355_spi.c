// SPDX-License-Identifier: GPL-2.0-only
/*
 * ADXL355 3-Axis Digital Accelerometer SPI driver
 *
 * Copyright (c) 2021 Puranjay Mohan <puranjay12@gmail.com>
 */

#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/regmap.h>
#include <linux/spi/spi.h>

#include "adxl355.h"

static const struct regmap_config adxl355_spi_regmap_config = {
	.reg_bits = 7,
	.pad_bits = 1,
	.val_bits = 8,
	.read_flag_mask = BIT(0),
	.max_register = 0x2F,
	.rd_table = &adxl355_readable_regs_tbl,
	.wr_table = &adxl355_writeable_regs_tbl,
};

static int adxl355_spi_probe(struct spi_device *spi)
{
	const struct spi_device_id *id = spi_get_device_id(spi);
	struct regmap *regmap;

	regmap = devm_regmap_init_spi(spi, &adxl355_spi_regmap_config);
	if (IS_ERR(regmap)) {
		dev_err(&spi->dev, "Error initializing spi regmap: %ld\n",
			PTR_ERR(regmap));

		return PTR_ERR(regmap);
	}

	return adxl355_core_probe(&spi->dev, regmap, id->name);
}

static const struct spi_device_id adxl355_spi_id[] = {
	{ "adxl355", 0 },
	{ }
};
MODULE_DEVICE_TABLE(spi, adxl355_spi_id);

static const struct of_device_id adxl355_of_match[] = {
	{ .compatible = "adi,adxl355" },
	{ }
};
MODULE_DEVICE_TABLE(of, adxl355_of_match);

static struct spi_driver adxl355_spi_driver = {
	.driver = {
		.name	= "adxl355_spi",
		.of_match_table = adxl355_of_match,
	},
	.probe		= adxl355_spi_probe,
	.id_table	= adxl355_spi_id,
};
module_spi_driver(adxl355_spi_driver);

MODULE_AUTHOR("Puranjay Mohan <puranjay12@gmail.com>");
MODULE_DESCRIPTION("ADXL355 3-Axis Digital Accelerometer SPI driver");
MODULE_LICENSE("GPL v2");
