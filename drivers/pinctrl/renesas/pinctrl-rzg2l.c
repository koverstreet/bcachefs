// SPDX-License-Identifier: GPL-2.0
/*
 * Renesas RZ/G2L Pin Control and GPIO driver core
 *
 * Copyright (C) 2021 Renesas Electronics Corporation.
 */

#include <linux/bitops.h>
#include <linux/clk.h>
#include <linux/gpio/driver.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/pinctrl/pinconf-generic.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/spinlock.h>

#include <dt-bindings/pinctrl/rzg2l-pinctrl.h>

#include "../core.h"
#include "../pinconf.h"
#include "../pinmux.h"

#define DRV_NAME	"pinctrl-rzg2l"

/*
 * Use 16 lower bits [15:0] for pin identifier
 * Use 16 higher bits [31:16] for pin mux function
 */
#define MUX_PIN_ID_MASK		GENMASK(15, 0)
#define MUX_FUNC_MASK		GENMASK(31, 16)
#define MUX_FUNC_OFFS		16
#define MUX_FUNC(pinconf)	(((pinconf) & MUX_FUNC_MASK) >> MUX_FUNC_OFFS)

/* PIN capabilities */
#define PIN_CFG_IOLH			BIT(0)
#define PIN_CFG_SR			BIT(1)
#define PIN_CFG_IEN			BIT(2)
#define PIN_CFG_PUPD			BIT(3)
#define PIN_CFG_IOLH_SD0		BIT(4)
#define PIN_CFG_IOLH_SD1		BIT(5)
#define PIN_CFG_IOLH_QSPI		BIT(6)
#define PIN_CFG_IOLH_ETH0		BIT(7)
#define PIN_CFG_IOLH_ETH1		BIT(8)
#define PIN_CFG_FILONOFF		BIT(9)
#define PIN_CFG_FILNUM			BIT(10)
#define PIN_CFG_FILCLKSEL		BIT(11)

#define RZG2L_MPXED_PIN_FUNCS		(PIN_CFG_IOLH | \
					 PIN_CFG_SR | \
					 PIN_CFG_PUPD | \
					 PIN_CFG_FILONOFF | \
					 PIN_CFG_FILNUM | \
					 PIN_CFG_FILCLKSEL)

#define RZG2L_MPXED_ETH_PIN_FUNCS(x)	((x) | \
					 PIN_CFG_FILONOFF | \
					 PIN_CFG_FILNUM | \
					 PIN_CFG_FILCLKSEL)

/*
 * n indicates number of pins in the port, a is the register index
 * and f is pin configuration capabilities supported.
 */
#define RZG2L_GPIO_PORT_PACK(n, a, f)	(((n) << 28) | ((a) << 20) | (f))
#define RZG2L_GPIO_PORT_GET_PINCNT(x)	(((x) & GENMASK(30, 28)) >> 28)
#define RZG2L_GPIO_PORT_GET_INDEX(x)	(((x) & GENMASK(26, 20)) >> 20)
#define RZG2L_GPIO_PORT_GET_CFGS(x)	((x) & GENMASK(19, 0))

/*
 * BIT(31) indicates dedicated pin, p is the register index while
 * referencing to SR/IEN/IOLH/FILxx registers, b is the register bits
 * (b * 8) and f is the pin configuration capabilities supported.
 */
#define RZG2L_SINGLE_PIN		BIT(31)
#define RZG2L_SINGLE_PIN_PACK(p, b, f)	(RZG2L_SINGLE_PIN | \
					 ((p) << 24) | ((b) << 20) | (f))
#define RZG2L_SINGLE_PIN_GET_PORT(x)	(((x) & GENMASK(30, 24)) >> 24)
#define RZG2L_SINGLE_PIN_GET_BIT(x)	(((x) & GENMASK(22, 20)) >> 20)
#define RZG2L_SINGLE_PIN_GET_CFGS(x)	((x) & GENMASK(19, 0))

#define P(n)			(0x0000 + 0x10 + (n))
#define PM(n)			(0x0100 + 0x20 + (n) * 2)
#define PMC(n)			(0x0200 + 0x10 + (n))
#define PFC(n)			(0x0400 + 0x40 + (n) * 4)
#define PIN(n)			(0x0800 + 0x10 + (n))
#define IEN(n)			(0x1800 + (n) * 8)
#define PWPR			(0x3014)
#define SD_CH(n)		(0x3000 + (n) * 4)
#define QSPI			(0x3008)

#define PVDD_1800		1	/* I/O domain voltage <= 1.8V */
#define PVDD_3300		0	/* I/O domain voltage >= 3.3V */

#define PWPR_B0WI		BIT(7)	/* Bit Write Disable */
#define PWPR_PFCWE		BIT(6)	/* PFC Register Write Enable */

#define PM_MASK			0x03
#define PVDD_MASK		0x01
#define PFC_MASK		0x07
#define IEN_MASK		0x01

#define PM_INPUT		0x1
#define PM_OUTPUT		0x2

#define RZG2L_PIN_ID_TO_PORT(id)	((id) / RZG2L_PINS_PER_PORT)
#define RZG2L_PIN_ID_TO_PIN(id)		((id) % RZG2L_PINS_PER_PORT)

struct rzg2l_dedicated_configs {
	const char *name;
	u32 config;
};

struct rzg2l_pinctrl_data {
	const char * const *port_pins;
	const u32 *port_pin_configs;
	struct rzg2l_dedicated_configs *dedicated_pins;
	unsigned int n_port_pins;
	unsigned int n_dedicated_pins;
};

struct rzg2l_pinctrl {
	struct pinctrl_dev		*pctl;
	struct pinctrl_desc		desc;
	struct pinctrl_pin_desc		*pins;

	const struct rzg2l_pinctrl_data	*data;
	void __iomem			*base;
	struct device			*dev;
	struct clk			*clk;

	struct gpio_chip		gpio_chip;
	struct pinctrl_gpio_range	gpio_range;

	spinlock_t			lock;
};

static void rzg2l_pinctrl_set_pfc_mode(struct rzg2l_pinctrl *pctrl,
				       u8 port, u8 pin, u8 func)
{
	unsigned long flags;
	u32 reg;

	spin_lock_irqsave(&pctrl->lock, flags);

	/* Set pin to 'Non-use (Hi-Z input protection)'  */
	reg = readw(pctrl->base + PM(port));
	reg &= ~(PM_MASK << (pin * 2));
	writew(reg, pctrl->base + PM(port));

	/* Temporarily switch to GPIO mode with PMC register */
	reg = readb(pctrl->base + PMC(port));
	writeb(reg & ~BIT(pin), pctrl->base + PMC(port));

	/* Set the PWPR register to allow PFC register to write */
	writel(0x0, pctrl->base + PWPR);        /* B0WI=0, PFCWE=0 */
	writel(PWPR_PFCWE, pctrl->base + PWPR);  /* B0WI=0, PFCWE=1 */

	/* Select Pin function mode with PFC register */
	reg = readl(pctrl->base + PFC(port));
	reg &= ~(PFC_MASK << (pin * 4));
	writel(reg | (func << (pin * 4)), pctrl->base + PFC(port));

	/* Set the PWPR register to be write-protected */
	writel(0x0, pctrl->base + PWPR);        /* B0WI=0, PFCWE=0 */
	writel(PWPR_B0WI, pctrl->base + PWPR);  /* B0WI=1, PFCWE=0 */

	/* Switch to Peripheral pin function with PMC register */
	reg = readb(pctrl->base + PMC(port));
	writeb(reg | BIT(pin), pctrl->base + PMC(port));

	spin_unlock_irqrestore(&pctrl->lock, flags);
};

static int rzg2l_pinctrl_set_mux(struct pinctrl_dev *pctldev,
				 unsigned int func_selector,
				 unsigned int group_selector)
{
	struct rzg2l_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	struct function_desc *func;
	unsigned int i, *psel_val;
	struct group_desc *group;
	int *pins;

	func = pinmux_generic_get_function(pctldev, func_selector);
	if (!func)
		return -EINVAL;
	group = pinctrl_generic_get_group(pctldev, group_selector);
	if (!group)
		return -EINVAL;

	psel_val = func->data;
	pins = group->pins;

	for (i = 0; i < group->num_pins; i++) {
		dev_dbg(pctrl->dev, "port:%u pin: %u PSEL:%u\n",
			RZG2L_PIN_ID_TO_PORT(pins[i]), RZG2L_PIN_ID_TO_PIN(pins[i]),
			psel_val[i]);
		rzg2l_pinctrl_set_pfc_mode(pctrl, RZG2L_PIN_ID_TO_PORT(pins[i]),
					   RZG2L_PIN_ID_TO_PIN(pins[i]), psel_val[i]);
	}

	return 0;
};

static int rzg2l_map_add_config(struct pinctrl_map *map,
				const char *group_or_pin,
				enum pinctrl_map_type type,
				unsigned long *configs,
				unsigned int num_configs)
{
	unsigned long *cfgs;

	cfgs = kmemdup(configs, num_configs * sizeof(*cfgs),
		       GFP_KERNEL);
	if (!cfgs)
		return -ENOMEM;

	map->type = type;
	map->data.configs.group_or_pin = group_or_pin;
	map->data.configs.configs = cfgs;
	map->data.configs.num_configs = num_configs;

	return 0;
}

static int rzg2l_dt_subnode_to_map(struct pinctrl_dev *pctldev,
				   struct device_node *np,
				   struct pinctrl_map **map,
				   unsigned int *num_maps,
				   unsigned int *index)
{
	struct rzg2l_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	struct pinctrl_map *maps = *map;
	unsigned int nmaps = *num_maps;
	unsigned long *configs = NULL;
	unsigned int *pins, *psel_val;
	unsigned int num_pinmux = 0;
	unsigned int idx = *index;
	unsigned int num_pins, i;
	unsigned int num_configs;
	struct property *pinmux;
	struct property *prop;
	int ret, gsel, fsel;
	const char **pin_fn;
	const char *pin;

	pinmux = of_find_property(np, "pinmux", NULL);
	if (pinmux)
		num_pinmux = pinmux->length / sizeof(u32);

	ret = of_property_count_strings(np, "pins");
	if (ret == -EINVAL) {
		num_pins = 0;
	} else if (ret < 0) {
		dev_err(pctrl->dev, "Invalid pins list in DT\n");
		return ret;
	} else {
		num_pins = ret;
	}

	if (!num_pinmux && !num_pins)
		return 0;

	if (num_pinmux && num_pins) {
		dev_err(pctrl->dev,
			"DT node must contain either a pinmux or pins and not both\n");
		return -EINVAL;
	}

	ret = pinconf_generic_parse_dt_config(np, NULL, &configs, &num_configs);
	if (ret < 0)
		return ret;

	if (num_pins && !num_configs) {
		dev_err(pctrl->dev, "DT node must contain a config\n");
		ret = -ENODEV;
		goto done;
	}

	if (num_pinmux)
		nmaps += 1;

	if (num_pins)
		nmaps += num_pins;

	maps = krealloc_array(maps, nmaps, sizeof(*maps), GFP_KERNEL);
	if (!maps) {
		ret = -ENOMEM;
		goto done;
	}

	*map = maps;
	*num_maps = nmaps;
	if (num_pins) {
		of_property_for_each_string(np, "pins", prop, pin) {
			ret = rzg2l_map_add_config(&maps[idx], pin,
						   PIN_MAP_TYPE_CONFIGS_PIN,
						   configs, num_configs);
			if (ret < 0)
				goto done;

			idx++;
		}
		ret = 0;
		goto done;
	}

	pins = devm_kcalloc(pctrl->dev, num_pinmux, sizeof(*pins), GFP_KERNEL);
	psel_val = devm_kcalloc(pctrl->dev, num_pinmux, sizeof(*psel_val),
				GFP_KERNEL);
	pin_fn = devm_kzalloc(pctrl->dev, sizeof(*pin_fn), GFP_KERNEL);
	if (!pins || !psel_val || !pin_fn) {
		ret = -ENOMEM;
		goto done;
	}

	/* Collect pin locations and mux settings from DT properties */
	for (i = 0; i < num_pinmux; ++i) {
		u32 value;

		ret = of_property_read_u32_index(np, "pinmux", i, &value);
		if (ret)
			goto done;
		pins[i] = value & MUX_PIN_ID_MASK;
		psel_val[i] = MUX_FUNC(value);
	}

	/* Register a single pin group listing all the pins we read from DT */
	gsel = pinctrl_generic_add_group(pctldev, np->name, pins, num_pinmux, NULL);
	if (gsel < 0) {
		ret = gsel;
		goto done;
	}

	/*
	 * Register a single group function where the 'data' is an array PSEL
	 * register values read from DT.
	 */
	pin_fn[0] = np->name;
	fsel = pinmux_generic_add_function(pctldev, np->name, pin_fn, 1,
					   psel_val);
	if (fsel < 0) {
		ret = fsel;
		goto remove_group;
	}

	maps[idx].type = PIN_MAP_TYPE_MUX_GROUP;
	maps[idx].data.mux.group = np->name;
	maps[idx].data.mux.function = np->name;
	idx++;

	dev_dbg(pctrl->dev, "Parsed %pOF with %d pins\n", np, num_pinmux);
	ret = 0;
	goto done;

remove_group:
	pinctrl_generic_remove_group(pctldev, gsel);
done:
	*index = idx;
	kfree(configs);
	return ret;
}

static void rzg2l_dt_free_map(struct pinctrl_dev *pctldev,
			      struct pinctrl_map *map,
			      unsigned int num_maps)
{
	unsigned int i;

	if (!map)
		return;

	for (i = 0; i < num_maps; ++i) {
		if (map[i].type == PIN_MAP_TYPE_CONFIGS_GROUP ||
		    map[i].type == PIN_MAP_TYPE_CONFIGS_PIN)
			kfree(map[i].data.configs.configs);
	}
	kfree(map);
}

static int rzg2l_dt_node_to_map(struct pinctrl_dev *pctldev,
				struct device_node *np,
				struct pinctrl_map **map,
				unsigned int *num_maps)
{
	struct rzg2l_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	struct device_node *child;
	unsigned int index;
	int ret;

	*map = NULL;
	*num_maps = 0;
	index = 0;

	for_each_child_of_node(np, child) {
		ret = rzg2l_dt_subnode_to_map(pctldev, child, map,
					      num_maps, &index);
		if (ret < 0) {
			of_node_put(child);
			goto done;
		}
	}

	if (*num_maps == 0) {
		ret = rzg2l_dt_subnode_to_map(pctldev, np, map,
					      num_maps, &index);
		if (ret < 0)
			goto done;
	}

	if (*num_maps)
		return 0;

	dev_err(pctrl->dev, "no mapping found in node %pOF\n", np);
	ret = -EINVAL;

done:
	if (ret < 0)
		rzg2l_dt_free_map(pctldev, *map, *num_maps);

	return ret;
}

static int rzg2l_pinctrl_pinconf_get(struct pinctrl_dev *pctldev,
				     unsigned int _pin,
				     unsigned long *config)
{
	struct rzg2l_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	enum pin_config_param param = pinconf_to_config_param(*config);
	const struct pinctrl_pin_desc *pin = &pctrl->desc.pins[_pin];
	unsigned int *pin_data = pin->drv_data;
	unsigned int arg = 0;
	unsigned long flags;
	void __iomem *addr;
	u32 port = 0, reg;
	u32 cfg = 0;
	u8 bit = 0;

	if (!pin_data)
		return -EINVAL;

	if (*pin_data & RZG2L_SINGLE_PIN) {
		port = RZG2L_SINGLE_PIN_GET_PORT(*pin_data);
		cfg = RZG2L_SINGLE_PIN_GET_CFGS(*pin_data);
		bit = RZG2L_SINGLE_PIN_GET_BIT(*pin_data);
	}

	switch (param) {
	case PIN_CONFIG_INPUT_ENABLE:
		if (!(cfg & PIN_CFG_IEN))
			return -EINVAL;
		spin_lock_irqsave(&pctrl->lock, flags);
		/* handle _L/_H for 32-bit register read/write */
		addr = pctrl->base + IEN(port);
		if (bit >= 4) {
			bit -= 4;
			addr += 4;
		}

		reg = readl(addr) & (IEN_MASK << (bit * 8));
		arg = (reg >> (bit * 8)) & 0x1;
		spin_unlock_irqrestore(&pctrl->lock, flags);
		break;

	case PIN_CONFIG_POWER_SOURCE: {
		u32 pwr_reg = 0x0;

		if (cfg & PIN_CFG_IOLH_SD0)
			pwr_reg = SD_CH(0);
		else if (cfg & PIN_CFG_IOLH_SD1)
			pwr_reg = SD_CH(1);
		else if (cfg & PIN_CFG_IOLH_QSPI)
			pwr_reg = QSPI;
		else
			return -EINVAL;

		spin_lock_irqsave(&pctrl->lock, flags);
		addr = pctrl->base + pwr_reg;
		arg = (readl(addr) & PVDD_MASK) ? 1800 : 3300;
		spin_unlock_irqrestore(&pctrl->lock, flags);
		break;
	}

	default:
		return -ENOTSUPP;
	}

	*config = pinconf_to_config_packed(param, arg);

	return 0;
};

static int rzg2l_pinctrl_pinconf_set(struct pinctrl_dev *pctldev,
				     unsigned int _pin,
				     unsigned long *_configs,
				     unsigned int num_configs)
{
	struct rzg2l_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	const struct pinctrl_pin_desc *pin = &pctrl->desc.pins[_pin];
	unsigned int *pin_data = pin->drv_data;
	enum pin_config_param param;
	unsigned long flags;
	void __iomem *addr;
	u32 port = 0, reg;
	unsigned int i;
	u32 cfg = 0;
	u8 bit = 0;

	if (!pin_data)
		return -EINVAL;

	if (*pin_data & RZG2L_SINGLE_PIN) {
		port = RZG2L_SINGLE_PIN_GET_PORT(*pin_data);
		cfg = RZG2L_SINGLE_PIN_GET_CFGS(*pin_data);
		bit = RZG2L_SINGLE_PIN_GET_BIT(*pin_data);
	}

	for (i = 0; i < num_configs; i++) {
		param = pinconf_to_config_param(_configs[i]);
		switch (param) {
		case PIN_CONFIG_INPUT_ENABLE: {
			unsigned int arg =
					pinconf_to_config_argument(_configs[i]);

			if (!(cfg & PIN_CFG_IEN))
				return -EINVAL;

			/* handle _L/_H for 32-bit register read/write */
			addr = pctrl->base + IEN(port);
			if (bit >= 4) {
				bit -= 4;
				addr += 4;
			}

			spin_lock_irqsave(&pctrl->lock, flags);
			reg = readl(addr) & ~(IEN_MASK << (bit * 8));
			writel(reg | (arg << (bit * 8)), addr);
			spin_unlock_irqrestore(&pctrl->lock, flags);
			break;
		}

		case PIN_CONFIG_POWER_SOURCE: {
			unsigned int mV = pinconf_to_config_argument(_configs[i]);
			u32 pwr_reg = 0x0;

			if (mV != 1800 && mV != 3300)
				return -EINVAL;

			if (cfg & PIN_CFG_IOLH_SD0)
				pwr_reg = SD_CH(0);
			else if (cfg & PIN_CFG_IOLH_SD1)
				pwr_reg = SD_CH(1);
			else if (cfg & PIN_CFG_IOLH_QSPI)
				pwr_reg = QSPI;
			else
				return -EINVAL;

			addr = pctrl->base + pwr_reg;
			spin_lock_irqsave(&pctrl->lock, flags);
			writel((mV == 1800) ? PVDD_1800 : PVDD_3300, addr);
			spin_unlock_irqrestore(&pctrl->lock, flags);
			break;
		}
		default:
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

static int rzg2l_pinctrl_pinconf_group_set(struct pinctrl_dev *pctldev,
					   unsigned int group,
					   unsigned long *configs,
					   unsigned int num_configs)
{
	const unsigned int *pins;
	unsigned int i, npins;
	int ret;

	ret = pinctrl_generic_get_group_pins(pctldev, group, &pins, &npins);
	if (ret)
		return ret;

	for (i = 0; i < npins; i++) {
		ret = rzg2l_pinctrl_pinconf_set(pctldev, pins[i], configs,
						num_configs);
		if (ret)
			return ret;
	}

	return 0;
};

static int rzg2l_pinctrl_pinconf_group_get(struct pinctrl_dev *pctldev,
					   unsigned int group,
					   unsigned long *config)
{
	const unsigned int *pins;
	unsigned int i, npins, prev_config = 0;
	int ret;

	ret = pinctrl_generic_get_group_pins(pctldev, group, &pins, &npins);
	if (ret)
		return ret;

	for (i = 0; i < npins; i++) {
		ret = rzg2l_pinctrl_pinconf_get(pctldev, pins[i], config);
		if (ret)
			return ret;

		/* Check config matching between to pin  */
		if (i && prev_config != *config)
			return -EOPNOTSUPP;

		prev_config = *config;
	}

	return 0;
};

static const struct pinctrl_ops rzg2l_pinctrl_pctlops = {
	.get_groups_count = pinctrl_generic_get_group_count,
	.get_group_name = pinctrl_generic_get_group_name,
	.get_group_pins = pinctrl_generic_get_group_pins,
	.dt_node_to_map = rzg2l_dt_node_to_map,
	.dt_free_map = rzg2l_dt_free_map,
};

static const struct pinmux_ops rzg2l_pinctrl_pmxops = {
	.get_functions_count = pinmux_generic_get_function_count,
	.get_function_name = pinmux_generic_get_function_name,
	.get_function_groups = pinmux_generic_get_function_groups,
	.set_mux = rzg2l_pinctrl_set_mux,
	.strict = true,
};

static const struct pinconf_ops rzg2l_pinctrl_confops = {
	.is_generic = true,
	.pin_config_get = rzg2l_pinctrl_pinconf_get,
	.pin_config_set = rzg2l_pinctrl_pinconf_set,
	.pin_config_group_set = rzg2l_pinctrl_pinconf_group_set,
	.pin_config_group_get = rzg2l_pinctrl_pinconf_group_get,
	.pin_config_config_dbg_show = pinconf_generic_dump_config,
};

static int rzg2l_gpio_request(struct gpio_chip *chip, unsigned int offset)
{
	struct rzg2l_pinctrl *pctrl = gpiochip_get_data(chip);
	u32 port = RZG2L_PIN_ID_TO_PORT(offset);
	u8 bit = RZG2L_PIN_ID_TO_PIN(offset);
	unsigned long flags;
	u8 reg8;
	int ret;

	ret = pinctrl_gpio_request(chip->base + offset);
	if (ret)
		return ret;

	spin_lock_irqsave(&pctrl->lock, flags);

	/* Select GPIO mode in PMC Register */
	reg8 = readb(pctrl->base + PMC(port));
	reg8 &= ~BIT(bit);
	writeb(reg8, pctrl->base + PMC(port));

	spin_unlock_irqrestore(&pctrl->lock, flags);

	return 0;
}

static void rzg2l_gpio_set_direction(struct rzg2l_pinctrl *pctrl, u32 port,
				     u8 bit, bool output)
{
	unsigned long flags;
	u16 reg16;

	spin_lock_irqsave(&pctrl->lock, flags);

	reg16 = readw(pctrl->base + PM(port));
	reg16 &= ~(PM_MASK << (bit * 2));

	reg16 |= (output ? PM_OUTPUT : PM_INPUT) << (bit * 2);
	writew(reg16, pctrl->base + PM(port));

	spin_unlock_irqrestore(&pctrl->lock, flags);
}

static int rzg2l_gpio_get_direction(struct gpio_chip *chip, unsigned int offset)
{
	struct rzg2l_pinctrl *pctrl = gpiochip_get_data(chip);
	u32 port = RZG2L_PIN_ID_TO_PORT(offset);
	u8 bit = RZG2L_PIN_ID_TO_PIN(offset);

	if (!(readb(pctrl->base + PMC(port)) & BIT(bit))) {
		u16 reg16;

		reg16 = readw(pctrl->base + PM(port));
		reg16 = (reg16 >> (bit * 2)) & PM_MASK;
		if (reg16 == PM_OUTPUT)
			return GPIO_LINE_DIRECTION_OUT;
	}

	return GPIO_LINE_DIRECTION_IN;
}

static int rzg2l_gpio_direction_input(struct gpio_chip *chip,
				      unsigned int offset)
{
	struct rzg2l_pinctrl *pctrl = gpiochip_get_data(chip);
	u32 port = RZG2L_PIN_ID_TO_PORT(offset);
	u8 bit = RZG2L_PIN_ID_TO_PIN(offset);

	rzg2l_gpio_set_direction(pctrl, port, bit, false);

	return 0;
}

static void rzg2l_gpio_set(struct gpio_chip *chip, unsigned int offset,
			   int value)
{
	struct rzg2l_pinctrl *pctrl = gpiochip_get_data(chip);
	u32 port = RZG2L_PIN_ID_TO_PORT(offset);
	u8 bit = RZG2L_PIN_ID_TO_PIN(offset);
	unsigned long flags;
	u8 reg8;

	spin_lock_irqsave(&pctrl->lock, flags);

	reg8 = readb(pctrl->base + P(port));

	if (value)
		writeb(reg8 | BIT(bit), pctrl->base + P(port));
	else
		writeb(reg8 & ~BIT(bit), pctrl->base + P(port));

	spin_unlock_irqrestore(&pctrl->lock, flags);
}

static int rzg2l_gpio_direction_output(struct gpio_chip *chip,
				       unsigned int offset, int value)
{
	struct rzg2l_pinctrl *pctrl = gpiochip_get_data(chip);
	u32 port = RZG2L_PIN_ID_TO_PORT(offset);
	u8 bit = RZG2L_PIN_ID_TO_PIN(offset);

	rzg2l_gpio_set(chip, offset, value);
	rzg2l_gpio_set_direction(pctrl, port, bit, true);

	return 0;
}

static int rzg2l_gpio_get(struct gpio_chip *chip, unsigned int offset)
{
	struct rzg2l_pinctrl *pctrl = gpiochip_get_data(chip);
	u32 port = RZG2L_PIN_ID_TO_PORT(offset);
	u8 bit = RZG2L_PIN_ID_TO_PIN(offset);
	u16 reg16;

	reg16 = readw(pctrl->base + PM(port));
	reg16 = (reg16 >> (bit * 2)) & PM_MASK;

	if (reg16 == PM_INPUT)
		return !!(readb(pctrl->base + PIN(port)) & BIT(bit));
	else if (reg16 == PM_OUTPUT)
		return !!(readb(pctrl->base + P(port)) & BIT(bit));
	else
		return -EINVAL;
}

static void rzg2l_gpio_free(struct gpio_chip *chip, unsigned int offset)
{
	pinctrl_gpio_free(chip->base + offset);

	/*
	 * Set the GPIO as an input to ensure that the next GPIO request won't
	 * drive the GPIO pin as an output.
	 */
	rzg2l_gpio_direction_input(chip, offset);
}

static const char * const rzg2l_gpio_names[] = {
	"P0_0", "P0_1", "P0_2", "P0_3", "P0_4", "P0_5", "P0_6", "P0_7",
	"P1_0", "P1_1", "P1_2", "P1_3", "P1_4", "P1_5", "P1_6", "P1_7",
	"P2_0", "P2_1", "P2_2", "P2_3", "P2_4", "P2_5", "P2_6", "P2_7",
	"P3_0", "P3_1", "P3_2", "P3_3", "P3_4", "P3_5", "P3_6", "P3_7",
	"P4_0", "P4_1", "P4_2", "P4_3", "P4_4", "P4_5", "P4_6", "P4_7",
	"P5_0", "P5_1", "P5_2", "P5_3", "P5_4", "P5_5", "P5_6", "P5_7",
	"P6_0", "P6_1", "P6_2", "P6_3", "P6_4", "P6_5", "P6_6", "P6_7",
	"P7_0", "P7_1", "P7_2", "P7_3", "P7_4", "P7_5", "P7_6", "P7_7",
	"P8_0", "P8_1", "P8_2", "P8_3", "P8_4", "P8_5", "P8_6", "P8_7",
	"P9_0", "P9_1", "P9_2", "P9_3", "P9_4", "P9_5", "P9_6", "P9_7",
	"P10_0", "P10_1", "P10_2", "P10_3", "P10_4", "P10_5", "P10_6", "P10_7",
	"P11_0", "P11_1", "P11_2", "P11_3", "P11_4", "P11_5", "P11_6", "P11_7",
	"P12_0", "P12_1", "P12_2", "P12_3", "P12_4", "P12_5", "P12_6", "P12_7",
	"P13_0", "P13_1", "P13_2", "P13_3", "P13_4", "P13_5", "P13_6", "P13_7",
	"P14_0", "P14_1", "P14_2", "P14_3", "P14_4", "P14_5", "P14_6", "P14_7",
	"P15_0", "P15_1", "P15_2", "P15_3", "P15_4", "P15_5", "P15_6", "P15_7",
	"P16_0", "P16_1", "P16_2", "P16_3", "P16_4", "P16_5", "P16_6", "P16_7",
	"P17_0", "P17_1", "P17_2", "P17_3", "P17_4", "P17_5", "P17_6", "P17_7",
	"P18_0", "P18_1", "P18_2", "P18_3", "P18_4", "P18_5", "P18_6", "P18_7",
	"P19_0", "P19_1", "P19_2", "P19_3", "P19_4", "P19_5", "P19_6", "P19_7",
	"P20_0", "P20_1", "P20_2", "P20_3", "P20_4", "P20_5", "P20_6", "P20_7",
	"P21_0", "P21_1", "P21_2", "P21_3", "P21_4", "P21_5", "P21_6", "P21_7",
	"P22_0", "P22_1", "P22_2", "P22_3", "P22_4", "P22_5", "P22_6", "P22_7",
	"P23_0", "P23_1", "P23_2", "P23_3", "P23_4", "P23_5", "P23_6", "P23_7",
	"P24_0", "P24_1", "P24_2", "P24_3", "P24_4", "P24_5", "P24_6", "P24_7",
	"P25_0", "P25_1", "P25_2", "P25_3", "P25_4", "P25_5", "P25_6", "P25_7",
	"P26_0", "P26_1", "P26_2", "P26_3", "P26_4", "P26_5", "P26_6", "P26_7",
	"P27_0", "P27_1", "P27_2", "P27_3", "P27_4", "P27_5", "P27_6", "P27_7",
	"P28_0", "P28_1", "P28_2", "P28_3", "P28_4", "P28_5", "P28_6", "P28_7",
	"P29_0", "P29_1", "P29_2", "P29_3", "P29_4", "P29_5", "P29_6", "P29_7",
	"P30_0", "P30_1", "P30_2", "P30_3", "P30_4", "P30_5", "P30_6", "P30_7",
	"P31_0", "P31_1", "P31_2", "P31_3", "P31_4", "P31_5", "P31_6", "P31_7",
	"P32_0", "P32_1", "P32_2", "P32_3", "P32_4", "P32_5", "P32_6", "P32_7",
	"P33_0", "P33_1", "P33_2", "P33_3", "P33_4", "P33_5", "P33_6", "P33_7",
	"P34_0", "P34_1", "P34_2", "P34_3", "P34_4", "P34_5", "P34_6", "P34_7",
	"P35_0", "P35_1", "P35_2", "P35_3", "P35_4", "P35_5", "P35_6", "P35_7",
	"P36_0", "P36_1", "P36_2", "P36_3", "P36_4", "P36_5", "P36_6", "P36_7",
	"P37_0", "P37_1", "P37_2", "P37_3", "P37_4", "P37_5", "P37_6", "P37_7",
	"P38_0", "P38_1", "P38_2", "P38_3", "P38_4", "P38_5", "P38_6", "P38_7",
	"P39_0", "P39_1", "P39_2", "P39_3", "P39_4", "P39_5", "P39_6", "P39_7",
	"P40_0", "P40_1", "P40_2", "P40_3", "P40_4", "P40_5", "P40_6", "P40_7",
	"P41_0", "P41_1", "P41_2", "P41_3", "P41_4", "P41_5", "P41_6", "P41_7",
	"P42_0", "P42_1", "P42_2", "P42_3", "P42_4", "P42_5", "P42_6", "P42_7",
	"P43_0", "P43_1", "P43_2", "P43_3", "P43_4", "P43_5", "P43_6", "P43_7",
	"P44_0", "P44_1", "P44_2", "P44_3", "P44_4", "P44_5", "P44_6", "P44_7",
	"P45_0", "P45_1", "P45_2", "P45_3", "P45_4", "P45_5", "P45_6", "P45_7",
	"P46_0", "P46_1", "P46_2", "P46_3", "P46_4", "P46_5", "P46_6", "P46_7",
	"P47_0", "P47_1", "P47_2", "P47_3", "P47_4", "P47_5", "P47_6", "P47_7",
	"P48_0", "P48_1", "P48_2", "P48_3", "P48_4", "P48_5", "P48_6", "P48_7",
};

static const u32 rzg2l_gpio_configs[] = {
	RZG2L_GPIO_PORT_PACK(2, 0x10, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x11, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x12, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x13, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x14, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(3, 0x15, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x16, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(3, 0x17, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(3, 0x18, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x19, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x1a, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x1b, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x1c, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(3, 0x1d, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x1e, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x1f, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x20, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(3, 0x21, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x22, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x23, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(3, 0x24, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH0)),
	RZG2L_GPIO_PORT_PACK(2, 0x25, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH0)),
	RZG2L_GPIO_PORT_PACK(2, 0x26, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH0)),
	RZG2L_GPIO_PORT_PACK(2, 0x27, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH0)),
	RZG2L_GPIO_PORT_PACK(2, 0x28, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH0)),
	RZG2L_GPIO_PORT_PACK(2, 0x29, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH0)),
	RZG2L_GPIO_PORT_PACK(2, 0x2a, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH0)),
	RZG2L_GPIO_PORT_PACK(2, 0x2b, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH0)),
	RZG2L_GPIO_PORT_PACK(2, 0x2c, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH0)),
	RZG2L_GPIO_PORT_PACK(2, 0x2d, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH1)),
	RZG2L_GPIO_PORT_PACK(2, 0x2e, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH1)),
	RZG2L_GPIO_PORT_PACK(2, 0x2f, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH1)),
	RZG2L_GPIO_PORT_PACK(2, 0x30, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH1)),
	RZG2L_GPIO_PORT_PACK(2, 0x31, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH1)),
	RZG2L_GPIO_PORT_PACK(2, 0x32, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH1)),
	RZG2L_GPIO_PORT_PACK(2, 0x33, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH1)),
	RZG2L_GPIO_PORT_PACK(2, 0x34, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH1)),
	RZG2L_GPIO_PORT_PACK(3, 0x35, RZG2L_MPXED_ETH_PIN_FUNCS(PIN_CFG_IOLH_ETH1)),
	RZG2L_GPIO_PORT_PACK(2, 0x36, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(3, 0x37, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(3, 0x38, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(2, 0x39, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(5, 0x3a, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(4, 0x3b, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(4, 0x3c, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(4, 0x3d, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(4, 0x3e, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(4, 0x3f, RZG2L_MPXED_PIN_FUNCS),
	RZG2L_GPIO_PORT_PACK(5, 0x40, RZG2L_MPXED_PIN_FUNCS),
};

static  struct rzg2l_dedicated_configs rzg2l_dedicated_pins[] = {
	{ "NMI", RZG2L_SINGLE_PIN_PACK(0x1, 0,
	 (PIN_CFG_FILONOFF | PIN_CFG_FILNUM | PIN_CFG_FILCLKSEL)) },
	{ "TMS/SWDIO", RZG2L_SINGLE_PIN_PACK(0x2, 0,
	 (PIN_CFG_SR | PIN_CFG_IOLH | PIN_CFG_IEN)) },
	{ "TDO", RZG2L_SINGLE_PIN_PACK(0x3, 0,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN)) },
	{ "AUDIO_CLK1", RZG2L_SINGLE_PIN_PACK(0x4, 0, PIN_CFG_IEN) },
	{ "AUDIO_CLK2", RZG2L_SINGLE_PIN_PACK(0x4, 1, PIN_CFG_IEN) },
	{ "SD0_CLK", RZG2L_SINGLE_PIN_PACK(0x6, 0,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_SD0)) },
	{ "SD0_CMD", RZG2L_SINGLE_PIN_PACK(0x6, 1,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD0)) },
	{ "SD0_RST#", RZG2L_SINGLE_PIN_PACK(0x6, 2,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_SD0)) },
	{ "SD0_DATA0", RZG2L_SINGLE_PIN_PACK(0x7, 0,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD0)) },
	{ "SD0_DATA1", RZG2L_SINGLE_PIN_PACK(0x7, 1,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD0)) },
	{ "SD0_DATA2", RZG2L_SINGLE_PIN_PACK(0x7, 2,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD0)) },
	{ "SD0_DATA3", RZG2L_SINGLE_PIN_PACK(0x7, 3,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD0)) },
	{ "SD0_DATA4", RZG2L_SINGLE_PIN_PACK(0x7, 4,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD0)) },
	{ "SD0_DATA5", RZG2L_SINGLE_PIN_PACK(0x7, 5,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD0)) },
	{ "SD0_DATA6", RZG2L_SINGLE_PIN_PACK(0x7, 6,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD0)) },
	{ "SD0_DATA7", RZG2L_SINGLE_PIN_PACK(0x7, 7,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD0)) },
	{ "SD1_CLK", RZG2L_SINGLE_PIN_PACK(0x8, 0,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_SD1))},
	{ "SD1_CMD", RZG2L_SINGLE_PIN_PACK(0x8, 1,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD1)) },
	{ "SD1_DATA0", RZG2L_SINGLE_PIN_PACK(0x9, 0,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD1)) },
	{ "SD1_DATA1", RZG2L_SINGLE_PIN_PACK(0x9, 1,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD1)) },
	{ "SD1_DATA2", RZG2L_SINGLE_PIN_PACK(0x9, 2,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD1)) },
	{ "SD1_DATA3", RZG2L_SINGLE_PIN_PACK(0x9, 3,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IEN | PIN_CFG_IOLH_SD1)) },
	{ "QSPI0_SPCLK", RZG2L_SINGLE_PIN_PACK(0xa, 0,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI0_IO0", RZG2L_SINGLE_PIN_PACK(0xa, 1,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI0_IO1", RZG2L_SINGLE_PIN_PACK(0xa, 2,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI0_IO2", RZG2L_SINGLE_PIN_PACK(0xa, 3,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI0_IO3", RZG2L_SINGLE_PIN_PACK(0xa, 4,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI0_SSL", RZG2L_SINGLE_PIN_PACK(0xa, 5,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI1_SPCLK", RZG2L_SINGLE_PIN_PACK(0xb, 0,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI1_IO0", RZG2L_SINGLE_PIN_PACK(0xb, 1,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI1_IO1", RZG2L_SINGLE_PIN_PACK(0xb, 2,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI1_IO2", RZG2L_SINGLE_PIN_PACK(0xb, 3,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI1_IO3", RZG2L_SINGLE_PIN_PACK(0xb, 4,
	 (PIN_CFG_IOLH | PIN_CFG_SR  | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI1_SSL", RZG2L_SINGLE_PIN_PACK(0xb, 5,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI_RESET#", RZG2L_SINGLE_PIN_PACK(0xc, 0,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI_WP#", RZG2L_SINGLE_PIN_PACK(0xc, 1,
	 (PIN_CFG_IOLH | PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "QSPI_INT#", RZG2L_SINGLE_PIN_PACK(0xc, 2, (PIN_CFG_SR | PIN_CFG_IOLH_QSPI)) },
	{ "WDTOVF_PERROUT#", RZG2L_SINGLE_PIN_PACK(0xd, 0, (PIN_CFG_IOLH | PIN_CFG_SR)) },
	{ "RIIC0_SDA", RZG2L_SINGLE_PIN_PACK(0xe, 0, PIN_CFG_IEN) },
	{ "RIIC0_SCL", RZG2L_SINGLE_PIN_PACK(0xe, 1, PIN_CFG_IEN) },
	{ "RIIC1_SDA", RZG2L_SINGLE_PIN_PACK(0xe, 2, PIN_CFG_IEN) },
	{ "RIIC1_SCL", RZG2L_SINGLE_PIN_PACK(0xe, 3, PIN_CFG_IEN) },
};

static int rzg2l_gpio_register(struct rzg2l_pinctrl *pctrl)
{
	struct device_node *np = pctrl->dev->of_node;
	struct gpio_chip *chip = &pctrl->gpio_chip;
	const char *name = dev_name(pctrl->dev);
	struct of_phandle_args of_args;
	int ret;

	ret = of_parse_phandle_with_fixed_args(np, "gpio-ranges", 3, 0, &of_args);
	if (ret) {
		dev_err(pctrl->dev, "Unable to parse gpio-ranges\n");
		return ret;
	}

	if (of_args.args[0] != 0 || of_args.args[1] != 0 ||
	    of_args.args[2] != ARRAY_SIZE(rzg2l_gpio_names)) {
		dev_err(pctrl->dev, "gpio-ranges does not match selected SOC\n");
		return -EINVAL;
	}

	chip->names = rzg2l_gpio_names;
	chip->request = rzg2l_gpio_request;
	chip->free = rzg2l_gpio_free;
	chip->get_direction = rzg2l_gpio_get_direction;
	chip->direction_input = rzg2l_gpio_direction_input;
	chip->direction_output = rzg2l_gpio_direction_output;
	chip->get = rzg2l_gpio_get;
	chip->set = rzg2l_gpio_set;
	chip->label = name;
	chip->parent = pctrl->dev;
	chip->owner = THIS_MODULE;
	chip->base = -1;
	chip->ngpio = of_args.args[2];

	pctrl->gpio_range.id = 0;
	pctrl->gpio_range.pin_base = 0;
	pctrl->gpio_range.base = 0;
	pctrl->gpio_range.npins = chip->ngpio;
	pctrl->gpio_range.name = chip->label;
	pctrl->gpio_range.gc = chip;
	ret = devm_gpiochip_add_data(pctrl->dev, chip, pctrl);
	if (ret) {
		dev_err(pctrl->dev, "failed to add GPIO controller\n");
		return ret;
	}

	dev_dbg(pctrl->dev, "Registered gpio controller\n");

	return 0;
}

static int rzg2l_pinctrl_register(struct rzg2l_pinctrl *pctrl)
{
	struct pinctrl_pin_desc *pins;
	unsigned int i, j;
	u32 *pin_data;
	int ret;

	pctrl->desc.name = DRV_NAME;
	pctrl->desc.npins = pctrl->data->n_port_pins + pctrl->data->n_dedicated_pins;
	pctrl->desc.pctlops = &rzg2l_pinctrl_pctlops;
	pctrl->desc.pmxops = &rzg2l_pinctrl_pmxops;
	pctrl->desc.confops = &rzg2l_pinctrl_confops;
	pctrl->desc.owner = THIS_MODULE;

	pins = devm_kcalloc(pctrl->dev, pctrl->desc.npins, sizeof(*pins), GFP_KERNEL);
	if (!pins)
		return -ENOMEM;

	pin_data = devm_kcalloc(pctrl->dev, pctrl->desc.npins,
				sizeof(*pin_data), GFP_KERNEL);
	if (!pin_data)
		return -ENOMEM;

	pctrl->pins = pins;
	pctrl->desc.pins = pins;

	for (i = 0, j = 0; i < pctrl->data->n_port_pins; i++) {
		pins[i].number = i;
		pins[i].name = pctrl->data->port_pins[i];
		if (i && !(i % RZG2L_PINS_PER_PORT))
			j++;
		pin_data[i] = pctrl->data->port_pin_configs[j];
		pins[i].drv_data = &pin_data[i];
	}

	for (i = 0; i < pctrl->data->n_dedicated_pins; i++) {
		unsigned int index = pctrl->data->n_port_pins + i;

		pins[index].number = index;
		pins[index].name = pctrl->data->dedicated_pins[i].name;
		pin_data[index] = pctrl->data->dedicated_pins[i].config;
		pins[index].drv_data = &pin_data[index];
	}

	ret = devm_pinctrl_register_and_init(pctrl->dev, &pctrl->desc, pctrl,
					     &pctrl->pctl);
	if (ret) {
		dev_err(pctrl->dev, "pinctrl registration failed\n");
		return ret;
	}

	ret = pinctrl_enable(pctrl->pctl);
	if (ret) {
		dev_err(pctrl->dev, "pinctrl enable failed\n");
		return ret;
	}

	ret = rzg2l_gpio_register(pctrl);
	if (ret) {
		dev_err(pctrl->dev, "failed to add GPIO chip: %i\n", ret);
		return ret;
	}

	return 0;
}

static void rzg2l_pinctrl_clk_disable(void *data)
{
	clk_disable_unprepare(data);
}

static int rzg2l_pinctrl_probe(struct platform_device *pdev)
{
	struct rzg2l_pinctrl *pctrl;
	int ret;

	pctrl = devm_kzalloc(&pdev->dev, sizeof(*pctrl), GFP_KERNEL);
	if (!pctrl)
		return -ENOMEM;

	pctrl->dev = &pdev->dev;

	pctrl->data = of_device_get_match_data(&pdev->dev);
	if (!pctrl->data)
		return -EINVAL;

	pctrl->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(pctrl->base))
		return PTR_ERR(pctrl->base);

	pctrl->clk = devm_clk_get(pctrl->dev, NULL);
	if (IS_ERR(pctrl->clk)) {
		ret = PTR_ERR(pctrl->clk);
		dev_err(pctrl->dev, "failed to get GPIO clk : %i\n", ret);
		return ret;
	}

	spin_lock_init(&pctrl->lock);

	platform_set_drvdata(pdev, pctrl);

	ret = clk_prepare_enable(pctrl->clk);
	if (ret) {
		dev_err(pctrl->dev, "failed to enable GPIO clk: %i\n", ret);
		return ret;
	}

	ret = devm_add_action_or_reset(&pdev->dev, rzg2l_pinctrl_clk_disable,
				       pctrl->clk);
	if (ret) {
		dev_err(pctrl->dev,
			"failed to register GPIO clk disable action, %i\n",
			ret);
		return ret;
	}

	ret = rzg2l_pinctrl_register(pctrl);
	if (ret)
		return ret;

	dev_info(pctrl->dev, "%s support registered\n", DRV_NAME);
	return 0;
}

static struct rzg2l_pinctrl_data r9a07g044_data = {
	.port_pins = rzg2l_gpio_names,
	.port_pin_configs = rzg2l_gpio_configs,
	.dedicated_pins = rzg2l_dedicated_pins,
	.n_port_pins = ARRAY_SIZE(rzg2l_gpio_names),
	.n_dedicated_pins = ARRAY_SIZE(rzg2l_dedicated_pins),
};

static const struct of_device_id rzg2l_pinctrl_of_table[] = {
	{
		.compatible = "renesas,r9a07g044-pinctrl",
		.data = &r9a07g044_data,
	},
	{ /* sentinel */ }
};

static struct platform_driver rzg2l_pinctrl_driver = {
	.driver = {
		.name = DRV_NAME,
		.of_match_table = of_match_ptr(rzg2l_pinctrl_of_table),
	},
	.probe = rzg2l_pinctrl_probe,
};

static int __init rzg2l_pinctrl_init(void)
{
	return platform_driver_register(&rzg2l_pinctrl_driver);
}
core_initcall(rzg2l_pinctrl_init);

MODULE_AUTHOR("Lad Prabhakar <prabhakar.mahadev-lad.rj@bp.renesas.com>");
MODULE_DESCRIPTION("Pin and gpio controller driver for RZ/G2L family");
MODULE_LICENSE("GPL v2");
