// SPDX-License-Identifier: GPL-2.0
/*
 * RZ/G2L Clock Pulse Generator
 *
 * Copyright (C) 2021 Renesas Electronics Corp.
 *
 * Based on renesas-cpg-mssr.c
 *
 * Copyright (C) 2015 Glider bvba
 * Copyright (C) 2013 Ideas On Board SPRL
 * Copyright (C) 2015 Renesas Electronics Corp.
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/clk/renesas.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/iopoll.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/pm_clock.h>
#include <linux/pm_domain.h>
#include <linux/reset-controller.h>
#include <linux/slab.h>

#include <dt-bindings/clock/renesas-cpg-mssr.h>

#include "rzg2l-cpg.h"

#ifdef DEBUG
#define WARN_DEBUG(x)	WARN_ON(x)
#else
#define WARN_DEBUG(x)	do { } while (0)
#endif

#define DIV_RSMASK(v, s, m)	((v >> s) & m)
#define GET_SHIFT(val)		((val >> 12) & 0xff)
#define GET_WIDTH(val)		((val >> 8) & 0xf)

#define KDIV(val)		DIV_RSMASK(val, 16, 0xffff)
#define MDIV(val)		DIV_RSMASK(val, 6, 0x3ff)
#define PDIV(val)		DIV_RSMASK(val, 0, 0x3f)
#define SDIV(val)		DIV_RSMASK(val, 0, 0x7)

#define CLK_ON_R(reg)		(reg)
#define CLK_MON_R(reg)		(0x180 + (reg))
#define CLK_RST_R(reg)		(reg)
#define CLK_MRST_R(reg)		(0x180 + (reg))

#define GET_REG_OFFSET(val)		((val >> 20) & 0xfff)
#define GET_REG_SAMPLL_CLK1(val)	((val >> 22) & 0xfff)
#define GET_REG_SAMPLL_CLK2(val)	((val >> 12) & 0xfff)

struct sd_hw_data {
	struct clk_hw hw;
	u32 conf;
	struct rzg2l_cpg_priv *priv;
};

#define to_sd_hw_data(_hw)	container_of(_hw, struct sd_hw_data, hw)

/**
 * struct rzg2l_cpg_priv - Clock Pulse Generator Private Data
 *
 * @rcdev: Reset controller entity
 * @dev: CPG device
 * @base: CPG register block base address
 * @rmw_lock: protects register accesses
 * @clks: Array containing all Core and Module Clocks
 * @num_core_clks: Number of Core Clocks in clks[]
 * @num_mod_clks: Number of Module Clocks in clks[]
 * @last_dt_core_clk: ID of the last Core Clock exported to DT
 * @notifiers: Notifier chain to save/restore clock state for system resume
 * @info: Pointer to platform data
 */
struct rzg2l_cpg_priv {
	struct reset_controller_dev rcdev;
	struct device *dev;
	void __iomem *base;
	spinlock_t rmw_lock;

	struct clk **clks;
	unsigned int num_core_clks;
	unsigned int num_mod_clks;
	unsigned int num_resets;
	unsigned int last_dt_core_clk;

	struct raw_notifier_head notifiers;
	const struct rzg2l_cpg_info *info;
};

static void rzg2l_cpg_del_clk_provider(void *data)
{
	of_clk_del_provider(data);
}

static struct clk * __init
rzg2l_cpg_div_clk_register(const struct cpg_core_clk *core,
			   struct clk **clks,
			   void __iomem *base,
			   struct rzg2l_cpg_priv *priv)
{
	struct device *dev = priv->dev;
	const struct clk *parent;
	const char *parent_name;
	struct clk_hw *clk_hw;

	parent = clks[core->parent & 0xffff];
	if (IS_ERR(parent))
		return ERR_CAST(parent);

	parent_name = __clk_get_name(parent);

	if (core->dtable)
		clk_hw = clk_hw_register_divider_table(dev, core->name,
						       parent_name, 0,
						       base + GET_REG_OFFSET(core->conf),
						       GET_SHIFT(core->conf),
						       GET_WIDTH(core->conf),
						       core->flag,
						       core->dtable,
						       &priv->rmw_lock);
	else
		clk_hw = clk_hw_register_divider(dev, core->name,
						 parent_name, 0,
						 base + GET_REG_OFFSET(core->conf),
						 GET_SHIFT(core->conf),
						 GET_WIDTH(core->conf),
						 core->flag, &priv->rmw_lock);

	if (IS_ERR(clk_hw))
		return ERR_CAST(clk_hw);

	return clk_hw->clk;
}

static struct clk * __init
rzg2l_cpg_mux_clk_register(const struct cpg_core_clk *core,
			   void __iomem *base,
			   struct rzg2l_cpg_priv *priv)
{
	const struct clk_hw *clk_hw;

	clk_hw = devm_clk_hw_register_mux(priv->dev, core->name,
					  core->parent_names, core->num_parents,
					  core->flag,
					  base + GET_REG_OFFSET(core->conf),
					  GET_SHIFT(core->conf),
					  GET_WIDTH(core->conf),
					  core->mux_flags, &priv->rmw_lock);
	if (IS_ERR(clk_hw))
		return ERR_CAST(clk_hw);

	return clk_hw->clk;
}

static int rzg2l_cpg_sd_clk_mux_determine_rate(struct clk_hw *hw,
					       struct clk_rate_request *req)
{
	return clk_mux_determine_rate_flags(hw, req, 0);
}

static int rzg2l_cpg_sd_clk_mux_set_parent(struct clk_hw *hw, u8 index)
{
	struct sd_hw_data *hwdata = to_sd_hw_data(hw);
	struct rzg2l_cpg_priv *priv = hwdata->priv;
	u32 off = GET_REG_OFFSET(hwdata->conf);
	u32 shift = GET_SHIFT(hwdata->conf);
	const u32 clk_src_266 = 2;
	u32 bitmask;

	/*
	 * As per the HW manual, we should not directly switch from 533 MHz to
	 * 400 MHz and vice versa. To change the setting from 2’b01 (533 MHz)
	 * to 2’b10 (400 MHz) or vice versa, Switch to 2’b11 (266 MHz) first,
	 * and then switch to the target setting (2’b01 (533 MHz) or 2’b10
	 * (400 MHz)).
	 * Setting a value of '0' to the SEL_SDHI0_SET or SEL_SDHI1_SET clock
	 * switching register is prohibited.
	 * The clock mux has 3 input clocks(533 MHz, 400 MHz, and 266 MHz), and
	 * the index to value mapping is done by adding 1 to the index.
	 */
	bitmask = (GENMASK(GET_WIDTH(hwdata->conf) - 1, 0) << shift) << 16;
	if (index != clk_src_266) {
		u32 msk, val;
		int ret;

		writel(bitmask | ((clk_src_266 + 1) << shift), priv->base + off);

		msk = off ? CPG_CLKSTATUS_SELSDHI1_STS : CPG_CLKSTATUS_SELSDHI0_STS;

		ret = readl_poll_timeout(priv->base + CPG_CLKSTATUS, val,
					 !(val & msk), 100,
					 CPG_SDHI_CLK_SWITCH_STATUS_TIMEOUT_US);
		if (ret) {
			dev_err(priv->dev, "failed to switch clk source\n");
			return ret;
		}
	}

	writel(bitmask | ((index + 1) << shift), priv->base + off);

	return 0;
}

static u8 rzg2l_cpg_sd_clk_mux_get_parent(struct clk_hw *hw)
{
	struct sd_hw_data *hwdata = to_sd_hw_data(hw);
	struct rzg2l_cpg_priv *priv = hwdata->priv;
	u32 val = readl(priv->base + GET_REG_OFFSET(hwdata->conf));

	val >>= GET_SHIFT(hwdata->conf);
	val &= GENMASK(GET_WIDTH(hwdata->conf) - 1, 0);
	if (val) {
		val--;
	} else {
		/* Prohibited clk source, change it to 533 MHz(reset value) */
		rzg2l_cpg_sd_clk_mux_set_parent(hw, 0);
	}

	return val;
}

static const struct clk_ops rzg2l_cpg_sd_clk_mux_ops = {
	.determine_rate = rzg2l_cpg_sd_clk_mux_determine_rate,
	.set_parent	= rzg2l_cpg_sd_clk_mux_set_parent,
	.get_parent	= rzg2l_cpg_sd_clk_mux_get_parent,
};

static struct clk * __init
rzg2l_cpg_sd_mux_clk_register(const struct cpg_core_clk *core,
			      void __iomem *base,
			      struct rzg2l_cpg_priv *priv)
{
	struct sd_hw_data *clk_hw_data;
	struct clk_init_data init;
	struct clk_hw *clk_hw;
	int ret;

	clk_hw_data = devm_kzalloc(priv->dev, sizeof(*clk_hw_data), GFP_KERNEL);
	if (!clk_hw_data)
		return ERR_PTR(-ENOMEM);

	clk_hw_data->priv = priv;
	clk_hw_data->conf = core->conf;

	init.name = GET_SHIFT(core->conf) ? "sd1" : "sd0";
	init.ops = &rzg2l_cpg_sd_clk_mux_ops;
	init.flags = 0;
	init.num_parents = core->num_parents;
	init.parent_names = core->parent_names;

	clk_hw = &clk_hw_data->hw;
	clk_hw->init = &init;

	ret = devm_clk_hw_register(priv->dev, clk_hw);
	if (ret)
		return ERR_PTR(ret);

	return clk_hw->clk;
}

struct pll_clk {
	struct clk_hw hw;
	unsigned int conf;
	unsigned int type;
	void __iomem *base;
	struct rzg2l_cpg_priv *priv;
};

#define to_pll(_hw)	container_of(_hw, struct pll_clk, hw)

static unsigned long rzg2l_cpg_pll_clk_recalc_rate(struct clk_hw *hw,
						   unsigned long parent_rate)
{
	struct pll_clk *pll_clk = to_pll(hw);
	struct rzg2l_cpg_priv *priv = pll_clk->priv;
	unsigned int val1, val2;
	unsigned int mult = 1;
	unsigned int div = 1;

	if (pll_clk->type != CLK_TYPE_SAM_PLL)
		return parent_rate;

	val1 = readl(priv->base + GET_REG_SAMPLL_CLK1(pll_clk->conf));
	val2 = readl(priv->base + GET_REG_SAMPLL_CLK2(pll_clk->conf));
	mult = MDIV(val1) + KDIV(val1) / 65536;
	div = PDIV(val1) * (1 << SDIV(val2));

	return DIV_ROUND_CLOSEST_ULL((u64)parent_rate * mult, div);
}

static const struct clk_ops rzg2l_cpg_pll_ops = {
	.recalc_rate = rzg2l_cpg_pll_clk_recalc_rate,
};

static struct clk * __init
rzg2l_cpg_pll_clk_register(const struct cpg_core_clk *core,
			   struct clk **clks,
			   void __iomem *base,
			   struct rzg2l_cpg_priv *priv)
{
	struct device *dev = priv->dev;
	const struct clk *parent;
	struct clk_init_data init;
	const char *parent_name;
	struct pll_clk *pll_clk;

	parent = clks[core->parent & 0xffff];
	if (IS_ERR(parent))
		return ERR_CAST(parent);

	pll_clk = devm_kzalloc(dev, sizeof(*pll_clk), GFP_KERNEL);
	if (!pll_clk)
		return ERR_PTR(-ENOMEM);

	parent_name = __clk_get_name(parent);
	init.name = core->name;
	init.ops = &rzg2l_cpg_pll_ops;
	init.flags = 0;
	init.parent_names = &parent_name;
	init.num_parents = 1;

	pll_clk->hw.init = &init;
	pll_clk->conf = core->conf;
	pll_clk->base = base;
	pll_clk->priv = priv;
	pll_clk->type = core->type;

	return clk_register(NULL, &pll_clk->hw);
}

static struct clk
*rzg2l_cpg_clk_src_twocell_get(struct of_phandle_args *clkspec,
			       void *data)
{
	unsigned int clkidx = clkspec->args[1];
	struct rzg2l_cpg_priv *priv = data;
	struct device *dev = priv->dev;
	const char *type;
	struct clk *clk;

	switch (clkspec->args[0]) {
	case CPG_CORE:
		type = "core";
		if (clkidx > priv->last_dt_core_clk) {
			dev_err(dev, "Invalid %s clock index %u\n", type, clkidx);
			return ERR_PTR(-EINVAL);
		}
		clk = priv->clks[clkidx];
		break;

	case CPG_MOD:
		type = "module";
		if (clkidx >= priv->num_mod_clks) {
			dev_err(dev, "Invalid %s clock index %u\n", type,
				clkidx);
			return ERR_PTR(-EINVAL);
		}
		clk = priv->clks[priv->num_core_clks + clkidx];
		break;

	default:
		dev_err(dev, "Invalid CPG clock type %u\n", clkspec->args[0]);
		return ERR_PTR(-EINVAL);
	}

	if (IS_ERR(clk))
		dev_err(dev, "Cannot get %s clock %u: %ld", type, clkidx,
			PTR_ERR(clk));
	else
		dev_dbg(dev, "clock (%u, %u) is %pC at %lu Hz\n",
			clkspec->args[0], clkspec->args[1], clk,
			clk_get_rate(clk));
	return clk;
}

static void __init
rzg2l_cpg_register_core_clk(const struct cpg_core_clk *core,
			    const struct rzg2l_cpg_info *info,
			    struct rzg2l_cpg_priv *priv)
{
	struct clk *clk = ERR_PTR(-EOPNOTSUPP), *parent;
	struct device *dev = priv->dev;
	unsigned int id = core->id, div = core->div;
	const char *parent_name;

	WARN_DEBUG(id >= priv->num_core_clks);
	WARN_DEBUG(PTR_ERR(priv->clks[id]) != -ENOENT);

	if (!core->name) {
		/* Skip NULLified clock */
		return;
	}

	switch (core->type) {
	case CLK_TYPE_IN:
		clk = of_clk_get_by_name(priv->dev->of_node, core->name);
		break;
	case CLK_TYPE_FF:
		WARN_DEBUG(core->parent >= priv->num_core_clks);
		parent = priv->clks[core->parent];
		if (IS_ERR(parent)) {
			clk = parent;
			goto fail;
		}

		parent_name = __clk_get_name(parent);
		clk = clk_register_fixed_factor(NULL, core->name,
						parent_name, CLK_SET_RATE_PARENT,
						core->mult, div);
		break;
	case CLK_TYPE_SAM_PLL:
		clk = rzg2l_cpg_pll_clk_register(core, priv->clks,
						 priv->base, priv);
		break;
	case CLK_TYPE_DIV:
		clk = rzg2l_cpg_div_clk_register(core, priv->clks,
						 priv->base, priv);
		break;
	case CLK_TYPE_MUX:
		clk = rzg2l_cpg_mux_clk_register(core, priv->base, priv);
		break;
	case CLK_TYPE_SD_MUX:
		clk = rzg2l_cpg_sd_mux_clk_register(core, priv->base, priv);
		break;
	default:
		goto fail;
	}

	if (IS_ERR_OR_NULL(clk))
		goto fail;

	dev_dbg(dev, "Core clock %pC at %lu Hz\n", clk, clk_get_rate(clk));
	priv->clks[id] = clk;
	return;

fail:
	dev_err(dev, "Failed to register %s clock %s: %ld\n", "core",
		core->name, PTR_ERR(clk));
}

/**
 * struct mstp_clock - MSTP gating clock
 *
 * @hw: handle between common and hardware-specific interfaces
 * @off: register offset
 * @bit: ON/MON bit
 * @enabled: soft state of the clock, if it is coupled with another clock
 * @priv: CPG/MSTP private data
 * @sibling: pointer to the other coupled clock
 */
struct mstp_clock {
	struct clk_hw hw;
	u16 off;
	u8 bit;
	bool enabled;
	struct rzg2l_cpg_priv *priv;
	struct mstp_clock *sibling;
};

#define to_mod_clock(_hw) container_of(_hw, struct mstp_clock, hw)

static int rzg2l_mod_clock_endisable(struct clk_hw *hw, bool enable)
{
	struct mstp_clock *clock = to_mod_clock(hw);
	struct rzg2l_cpg_priv *priv = clock->priv;
	unsigned int reg = clock->off;
	struct device *dev = priv->dev;
	unsigned long flags;
	unsigned int i;
	u32 bitmask = BIT(clock->bit);
	u32 value;

	if (!clock->off) {
		dev_dbg(dev, "%pC does not support ON/OFF\n",  hw->clk);
		return 0;
	}

	dev_dbg(dev, "CLK_ON %u/%pC %s\n", CLK_ON_R(reg), hw->clk,
		enable ? "ON" : "OFF");
	spin_lock_irqsave(&priv->rmw_lock, flags);

	if (enable)
		value = (bitmask << 16) | bitmask;
	else
		value = bitmask << 16;
	writel(value, priv->base + CLK_ON_R(reg));

	spin_unlock_irqrestore(&priv->rmw_lock, flags);

	if (!enable)
		return 0;

	for (i = 1000; i > 0; --i) {
		if (((readl(priv->base + CLK_MON_R(reg))) & bitmask))
			break;
		cpu_relax();
	}

	if (!i) {
		dev_err(dev, "Failed to enable CLK_ON %p\n",
			priv->base + CLK_ON_R(reg));
		return -ETIMEDOUT;
	}

	return 0;
}

static int rzg2l_mod_clock_enable(struct clk_hw *hw)
{
	struct mstp_clock *clock = to_mod_clock(hw);

	if (clock->sibling) {
		struct rzg2l_cpg_priv *priv = clock->priv;
		unsigned long flags;
		bool enabled;

		spin_lock_irqsave(&priv->rmw_lock, flags);
		enabled = clock->sibling->enabled;
		clock->enabled = true;
		spin_unlock_irqrestore(&priv->rmw_lock, flags);
		if (enabled)
			return 0;
	}

	return rzg2l_mod_clock_endisable(hw, true);
}

static void rzg2l_mod_clock_disable(struct clk_hw *hw)
{
	struct mstp_clock *clock = to_mod_clock(hw);

	if (clock->sibling) {
		struct rzg2l_cpg_priv *priv = clock->priv;
		unsigned long flags;
		bool enabled;

		spin_lock_irqsave(&priv->rmw_lock, flags);
		enabled = clock->sibling->enabled;
		clock->enabled = false;
		spin_unlock_irqrestore(&priv->rmw_lock, flags);
		if (enabled)
			return;
	}

	rzg2l_mod_clock_endisable(hw, false);
}

static int rzg2l_mod_clock_is_enabled(struct clk_hw *hw)
{
	struct mstp_clock *clock = to_mod_clock(hw);
	struct rzg2l_cpg_priv *priv = clock->priv;
	u32 bitmask = BIT(clock->bit);
	u32 value;

	if (!clock->off) {
		dev_dbg(priv->dev, "%pC does not support ON/OFF\n",  hw->clk);
		return 1;
	}

	if (clock->sibling)
		return clock->enabled;

	value = readl(priv->base + CLK_MON_R(clock->off));

	return value & bitmask;
}

static const struct clk_ops rzg2l_mod_clock_ops = {
	.enable = rzg2l_mod_clock_enable,
	.disable = rzg2l_mod_clock_disable,
	.is_enabled = rzg2l_mod_clock_is_enabled,
};

static struct mstp_clock
*rzg2l_mod_clock__get_sibling(struct mstp_clock *clock,
			      struct rzg2l_cpg_priv *priv)
{
	struct clk_hw *hw;
	unsigned int i;

	for (i = 0; i < priv->num_mod_clks; i++) {
		struct mstp_clock *clk;

		if (priv->clks[priv->num_core_clks + i] == ERR_PTR(-ENOENT))
			continue;

		hw = __clk_get_hw(priv->clks[priv->num_core_clks + i]);
		clk = to_mod_clock(hw);
		if (clock->off == clk->off && clock->bit == clk->bit)
			return clk;
	}

	return NULL;
}

static void __init
rzg2l_cpg_register_mod_clk(const struct rzg2l_mod_clk *mod,
			   const struct rzg2l_cpg_info *info,
			   struct rzg2l_cpg_priv *priv)
{
	struct mstp_clock *clock = NULL;
	struct device *dev = priv->dev;
	unsigned int id = mod->id;
	struct clk_init_data init;
	struct clk *parent, *clk;
	const char *parent_name;
	unsigned int i;

	WARN_DEBUG(id < priv->num_core_clks);
	WARN_DEBUG(id >= priv->num_core_clks + priv->num_mod_clks);
	WARN_DEBUG(mod->parent >= priv->num_core_clks + priv->num_mod_clks);
	WARN_DEBUG(PTR_ERR(priv->clks[id]) != -ENOENT);

	if (!mod->name) {
		/* Skip NULLified clock */
		return;
	}

	parent = priv->clks[mod->parent];
	if (IS_ERR(parent)) {
		clk = parent;
		goto fail;
	}

	clock = devm_kzalloc(dev, sizeof(*clock), GFP_KERNEL);
	if (!clock) {
		clk = ERR_PTR(-ENOMEM);
		goto fail;
	}

	init.name = mod->name;
	init.ops = &rzg2l_mod_clock_ops;
	init.flags = CLK_SET_RATE_PARENT;
	for (i = 0; i < info->num_crit_mod_clks; i++)
		if (id == info->crit_mod_clks[i]) {
			dev_dbg(dev, "CPG %s setting CLK_IS_CRITICAL\n",
				mod->name);
			init.flags |= CLK_IS_CRITICAL;
			break;
		}

	parent_name = __clk_get_name(parent);
	init.parent_names = &parent_name;
	init.num_parents = 1;

	clock->off = mod->off;
	clock->bit = mod->bit;
	clock->priv = priv;
	clock->hw.init = &init;

	clk = clk_register(NULL, &clock->hw);
	if (IS_ERR(clk))
		goto fail;

	dev_dbg(dev, "Module clock %pC at %lu Hz\n", clk, clk_get_rate(clk));
	priv->clks[id] = clk;

	if (mod->is_coupled) {
		struct mstp_clock *sibling;

		clock->enabled = rzg2l_mod_clock_is_enabled(&clock->hw);
		sibling = rzg2l_mod_clock__get_sibling(clock, priv);
		if (sibling) {
			clock->sibling = sibling;
			sibling->sibling = clock;
		}
	}

	return;

fail:
	dev_err(dev, "Failed to register %s clock %s: %ld\n", "module",
		mod->name, PTR_ERR(clk));
}

#define rcdev_to_priv(x)	container_of(x, struct rzg2l_cpg_priv, rcdev)

static int rzg2l_cpg_reset(struct reset_controller_dev *rcdev,
			   unsigned long id)
{
	struct rzg2l_cpg_priv *priv = rcdev_to_priv(rcdev);
	const struct rzg2l_cpg_info *info = priv->info;
	unsigned int reg = info->resets[id].off;
	u32 dis = BIT(info->resets[id].bit);
	u32 we = dis << 16;

	dev_dbg(rcdev->dev, "reset id:%ld offset:0x%x\n", id, CLK_RST_R(reg));

	/* Reset module */
	writel(we, priv->base + CLK_RST_R(reg));

	/* Wait for at least one cycle of the RCLK clock (@ ca. 32 kHz) */
	udelay(35);

	/* Release module from reset state */
	writel(we | dis, priv->base + CLK_RST_R(reg));

	return 0;
}

static int rzg2l_cpg_assert(struct reset_controller_dev *rcdev,
			    unsigned long id)
{
	struct rzg2l_cpg_priv *priv = rcdev_to_priv(rcdev);
	const struct rzg2l_cpg_info *info = priv->info;
	unsigned int reg = info->resets[id].off;
	u32 value = BIT(info->resets[id].bit) << 16;

	dev_dbg(rcdev->dev, "assert id:%ld offset:0x%x\n", id, CLK_RST_R(reg));

	writel(value, priv->base + CLK_RST_R(reg));
	return 0;
}

static int rzg2l_cpg_deassert(struct reset_controller_dev *rcdev,
			      unsigned long id)
{
	struct rzg2l_cpg_priv *priv = rcdev_to_priv(rcdev);
	const struct rzg2l_cpg_info *info = priv->info;
	unsigned int reg = info->resets[id].off;
	u32 dis = BIT(info->resets[id].bit);
	u32 value = (dis << 16) | dis;

	dev_dbg(rcdev->dev, "deassert id:%ld offset:0x%x\n", id,
		CLK_RST_R(reg));

	writel(value, priv->base + CLK_RST_R(reg));
	return 0;
}

static int rzg2l_cpg_status(struct reset_controller_dev *rcdev,
			    unsigned long id)
{
	struct rzg2l_cpg_priv *priv = rcdev_to_priv(rcdev);
	const struct rzg2l_cpg_info *info = priv->info;
	unsigned int reg = info->resets[id].off;
	u32 bitmask = BIT(info->resets[id].bit);

	return !(readl(priv->base + CLK_MRST_R(reg)) & bitmask);
}

static const struct reset_control_ops rzg2l_cpg_reset_ops = {
	.reset = rzg2l_cpg_reset,
	.assert = rzg2l_cpg_assert,
	.deassert = rzg2l_cpg_deassert,
	.status = rzg2l_cpg_status,
};

static int rzg2l_cpg_reset_xlate(struct reset_controller_dev *rcdev,
				 const struct of_phandle_args *reset_spec)
{
	struct rzg2l_cpg_priv *priv = rcdev_to_priv(rcdev);
	const struct rzg2l_cpg_info *info = priv->info;
	unsigned int id = reset_spec->args[0];

	if (id >= rcdev->nr_resets || !info->resets[id].off) {
		dev_err(rcdev->dev, "Invalid reset index %u\n", id);
		return -EINVAL;
	}

	return id;
}

static int rzg2l_cpg_reset_controller_register(struct rzg2l_cpg_priv *priv)
{
	priv->rcdev.ops = &rzg2l_cpg_reset_ops;
	priv->rcdev.of_node = priv->dev->of_node;
	priv->rcdev.dev = priv->dev;
	priv->rcdev.of_reset_n_cells = 1;
	priv->rcdev.of_xlate = rzg2l_cpg_reset_xlate;
	priv->rcdev.nr_resets = priv->num_resets;

	return devm_reset_controller_register(priv->dev, &priv->rcdev);
}

static bool rzg2l_cpg_is_pm_clk(const struct of_phandle_args *clkspec)
{
	if (clkspec->args_count != 2)
		return false;

	switch (clkspec->args[0]) {
	case CPG_MOD:
		return true;

	default:
		return false;
	}
}

static int rzg2l_cpg_attach_dev(struct generic_pm_domain *unused, struct device *dev)
{
	struct device_node *np = dev->of_node;
	struct of_phandle_args clkspec;
	bool once = true;
	struct clk *clk;
	int error;
	int i = 0;

	while (!of_parse_phandle_with_args(np, "clocks", "#clock-cells", i,
					   &clkspec)) {
		if (rzg2l_cpg_is_pm_clk(&clkspec)) {
			if (once) {
				once = false;
				error = pm_clk_create(dev);
				if (error) {
					of_node_put(clkspec.np);
					goto err;
				}
			}
			clk = of_clk_get_from_provider(&clkspec);
			of_node_put(clkspec.np);
			if (IS_ERR(clk)) {
				error = PTR_ERR(clk);
				goto fail_destroy;
			}

			error = pm_clk_add_clk(dev, clk);
			if (error) {
				dev_err(dev, "pm_clk_add_clk failed %d\n",
					error);
				goto fail_put;
			}
		} else {
			of_node_put(clkspec.np);
		}
		i++;
	}

	return 0;

fail_put:
	clk_put(clk);

fail_destroy:
	pm_clk_destroy(dev);
err:
	return error;
}

static void rzg2l_cpg_detach_dev(struct generic_pm_domain *unused, struct device *dev)
{
	if (!pm_clk_no_clocks(dev))
		pm_clk_destroy(dev);
}

static void rzg2l_cpg_genpd_remove(void *data)
{
	pm_genpd_remove(data);
}

static int __init rzg2l_cpg_add_clk_domain(struct device *dev)
{
	struct device_node *np = dev->of_node;
	struct generic_pm_domain *genpd;
	int ret;

	genpd = devm_kzalloc(dev, sizeof(*genpd), GFP_KERNEL);
	if (!genpd)
		return -ENOMEM;

	genpd->name = np->name;
	genpd->flags = GENPD_FLAG_PM_CLK | GENPD_FLAG_ALWAYS_ON |
		       GENPD_FLAG_ACTIVE_WAKEUP;
	genpd->attach_dev = rzg2l_cpg_attach_dev;
	genpd->detach_dev = rzg2l_cpg_detach_dev;
	ret = pm_genpd_init(genpd, &pm_domain_always_on_gov, false);
	if (ret)
		return ret;

	ret = devm_add_action_or_reset(dev, rzg2l_cpg_genpd_remove, genpd);
	if (ret)
		return ret;

	return of_genpd_add_provider_simple(np, genpd);
}

static int __init rzg2l_cpg_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	const struct rzg2l_cpg_info *info;
	struct rzg2l_cpg_priv *priv;
	unsigned int nclks, i;
	struct clk **clks;
	int error;

	info = of_device_get_match_data(dev);

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->dev = dev;
	priv->info = info;
	spin_lock_init(&priv->rmw_lock);

	priv->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->base))
		return PTR_ERR(priv->base);

	nclks = info->num_total_core_clks + info->num_hw_mod_clks;
	clks = devm_kmalloc_array(dev, nclks, sizeof(*clks), GFP_KERNEL);
	if (!clks)
		return -ENOMEM;

	dev_set_drvdata(dev, priv);
	priv->clks = clks;
	priv->num_core_clks = info->num_total_core_clks;
	priv->num_mod_clks = info->num_hw_mod_clks;
	priv->num_resets = info->num_resets;
	priv->last_dt_core_clk = info->last_dt_core_clk;

	for (i = 0; i < nclks; i++)
		clks[i] = ERR_PTR(-ENOENT);

	for (i = 0; i < info->num_core_clks; i++)
		rzg2l_cpg_register_core_clk(&info->core_clks[i], info, priv);

	for (i = 0; i < info->num_mod_clks; i++)
		rzg2l_cpg_register_mod_clk(&info->mod_clks[i], info, priv);

	error = of_clk_add_provider(np, rzg2l_cpg_clk_src_twocell_get, priv);
	if (error)
		return error;

	error = devm_add_action_or_reset(dev, rzg2l_cpg_del_clk_provider, np);
	if (error)
		return error;

	error = rzg2l_cpg_add_clk_domain(dev);
	if (error)
		return error;

	error = rzg2l_cpg_reset_controller_register(priv);
	if (error)
		return error;

	return 0;
}

static const struct of_device_id rzg2l_cpg_match[] = {
#ifdef CONFIG_CLK_R9A07G044
	{
		.compatible = "renesas,r9a07g044-cpg",
		.data = &r9a07g044_cpg_info,
	},
#endif
	{ /* sentinel */ }
};

static struct platform_driver rzg2l_cpg_driver = {
	.driver		= {
		.name	= "rzg2l-cpg",
		.of_match_table = rzg2l_cpg_match,
	},
};

static int __init rzg2l_cpg_init(void)
{
	return platform_driver_probe(&rzg2l_cpg_driver, rzg2l_cpg_probe);
}

subsys_initcall(rzg2l_cpg_init);

MODULE_DESCRIPTION("Renesas RZ/G2L CPG Driver");
MODULE_LICENSE("GPL v2");
