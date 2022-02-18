// SPDX-License-Identifier: GPL-2.0+

/*
 * Copyright 2021 Pengutronix, Lucas Stach <kernel@pengutronix.de>
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/pm_domain.h>
#include <linux/pm_runtime.h>
#include <linux/regmap.h>
#include <linux/clk.h>

#include <dt-bindings/power/imx8mm-power.h>

#define BLK_SFT_RSTN	0x0
#define BLK_CLK_EN	0x4
#define BLK_MIPI_RESET_DIV	0x8 /* Mini/Nano DISPLAY_BLK_CTRL only */

struct imx8m_blk_ctrl_domain;

struct imx8m_blk_ctrl {
	struct device *dev;
	struct notifier_block power_nb;
	struct device *bus_power_dev;
	struct regmap *regmap;
	struct imx8m_blk_ctrl_domain *domains;
	struct genpd_onecell_data onecell_data;
};

struct imx8m_blk_ctrl_domain_data {
	const char *name;
	const char * const *clk_names;
	int num_clks;
	const char *gpc_name;
	u32 rst_mask;
	u32 clk_mask;

	/*
	 * i.MX8M Mini and Nano have a third DISPLAY_BLK_CTRL register
	 * which is used to control the reset for the MIPI Phy.
	 * Since it's only present in certain circumstances,
	 * an if-statement should be used before setting and clearing this
	 * register.
	 */
	u32 mipi_phy_rst_mask;
};

#define DOMAIN_MAX_CLKS 3

struct imx8m_blk_ctrl_domain {
	struct generic_pm_domain genpd;
	const struct imx8m_blk_ctrl_domain_data *data;
	struct clk_bulk_data clks[DOMAIN_MAX_CLKS];
	struct device *power_dev;
	struct imx8m_blk_ctrl *bc;
};

struct imx8m_blk_ctrl_data {
	int max_reg;
	notifier_fn_t power_notifier_fn;
	const struct imx8m_blk_ctrl_domain_data *domains;
	int num_domains;
};

static inline struct imx8m_blk_ctrl_domain *
to_imx8m_blk_ctrl_domain(struct generic_pm_domain *genpd)
{
	return container_of(genpd, struct imx8m_blk_ctrl_domain, genpd);
}

static int imx8m_blk_ctrl_power_on(struct generic_pm_domain *genpd)
{
	struct imx8m_blk_ctrl_domain *domain = to_imx8m_blk_ctrl_domain(genpd);
	const struct imx8m_blk_ctrl_domain_data *data = domain->data;
	struct imx8m_blk_ctrl *bc = domain->bc;
	int ret;

	/* make sure bus domain is awake */
	ret = pm_runtime_get_sync(bc->bus_power_dev);
	if (ret < 0) {
		pm_runtime_put_noidle(bc->bus_power_dev);
		dev_err(bc->dev, "failed to power up bus domain\n");
		return ret;
	}

	/* put devices into reset */
	regmap_clear_bits(bc->regmap, BLK_SFT_RSTN, data->rst_mask);
	if (data->mipi_phy_rst_mask)
		regmap_clear_bits(bc->regmap, BLK_MIPI_RESET_DIV, data->mipi_phy_rst_mask);

	/* enable upstream and blk-ctrl clocks to allow reset to propagate */
	ret = clk_bulk_prepare_enable(data->num_clks, domain->clks);
	if (ret) {
		dev_err(bc->dev, "failed to enable clocks\n");
		goto bus_put;
	}
	regmap_set_bits(bc->regmap, BLK_CLK_EN, data->clk_mask);

	/* power up upstream GPC domain */
	ret = pm_runtime_get_sync(domain->power_dev);
	if (ret < 0) {
		dev_err(bc->dev, "failed to power up peripheral domain\n");
		goto clk_disable;
	}

	/* wait for reset to propagate */
	udelay(5);

	/* release reset */
	regmap_set_bits(bc->regmap, BLK_SFT_RSTN, data->rst_mask);
	if (data->mipi_phy_rst_mask)
		regmap_set_bits(bc->regmap, BLK_MIPI_RESET_DIV, data->mipi_phy_rst_mask);

	/* disable upstream clocks */
	clk_bulk_disable_unprepare(data->num_clks, domain->clks);

	return 0;

clk_disable:
	clk_bulk_disable_unprepare(data->num_clks, domain->clks);
bus_put:
	pm_runtime_put(bc->bus_power_dev);

	return ret;
}

static int imx8m_blk_ctrl_power_off(struct generic_pm_domain *genpd)
{
	struct imx8m_blk_ctrl_domain *domain = to_imx8m_blk_ctrl_domain(genpd);
	const struct imx8m_blk_ctrl_domain_data *data = domain->data;
	struct imx8m_blk_ctrl *bc = domain->bc;

	/* put devices into reset and disable clocks */
	if (data->mipi_phy_rst_mask)
		regmap_clear_bits(bc->regmap, BLK_MIPI_RESET_DIV, data->mipi_phy_rst_mask);

	regmap_clear_bits(bc->regmap, BLK_SFT_RSTN, data->rst_mask);
	regmap_clear_bits(bc->regmap, BLK_CLK_EN, data->clk_mask);

	/* power down upstream GPC domain */
	pm_runtime_put(domain->power_dev);

	/* allow bus domain to suspend */
	pm_runtime_put(bc->bus_power_dev);

	return 0;
}

static struct generic_pm_domain *
imx8m_blk_ctrl_xlate(struct of_phandle_args *args, void *data)
{
	struct genpd_onecell_data *onecell_data = data;
	unsigned int index = args->args[0];

	if (args->args_count != 1 ||
	    index >= onecell_data->num_domains)
		return ERR_PTR(-EINVAL);

	return onecell_data->domains[index];
}

static struct lock_class_key blk_ctrl_genpd_lock_class;

static int imx8m_blk_ctrl_probe(struct platform_device *pdev)
{
	const struct imx8m_blk_ctrl_data *bc_data;
	struct device *dev = &pdev->dev;
	struct imx8m_blk_ctrl *bc;
	void __iomem *base;
	int i, ret;

	struct regmap_config regmap_config = {
		.reg_bits	= 32,
		.val_bits	= 32,
		.reg_stride	= 4,
	};

	bc = devm_kzalloc(dev, sizeof(*bc), GFP_KERNEL);
	if (!bc)
		return -ENOMEM;

	bc->dev = dev;

	bc_data = of_device_get_match_data(dev);

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return PTR_ERR(base);

	regmap_config.max_register = bc_data->max_reg;
	bc->regmap = devm_regmap_init_mmio(dev, base, &regmap_config);
	if (IS_ERR(bc->regmap))
		return dev_err_probe(dev, PTR_ERR(bc->regmap),
				     "failed to init regmap\n");

	bc->domains = devm_kcalloc(dev, bc_data->num_domains,
				   sizeof(struct imx8m_blk_ctrl_domain),
				   GFP_KERNEL);
	if (!bc->domains)
		return -ENOMEM;

	bc->onecell_data.num_domains = bc_data->num_domains;
	bc->onecell_data.xlate = imx8m_blk_ctrl_xlate;
	bc->onecell_data.domains =
		devm_kcalloc(dev, bc_data->num_domains,
			     sizeof(struct generic_pm_domain *), GFP_KERNEL);
	if (!bc->onecell_data.domains)
		return -ENOMEM;

	bc->bus_power_dev = genpd_dev_pm_attach_by_name(dev, "bus");
	if (IS_ERR(bc->bus_power_dev))
		return dev_err_probe(dev, PTR_ERR(bc->bus_power_dev),
				     "failed to attach power domain\n");

	for (i = 0; i < bc_data->num_domains; i++) {
		const struct imx8m_blk_ctrl_domain_data *data = &bc_data->domains[i];
		struct imx8m_blk_ctrl_domain *domain = &bc->domains[i];
		int j;

		domain->data = data;

		for (j = 0; j < data->num_clks; j++)
			domain->clks[j].id = data->clk_names[j];

		ret = devm_clk_bulk_get(dev, data->num_clks, domain->clks);
		if (ret) {
			dev_err_probe(dev, ret, "failed to get clock\n");
			goto cleanup_pds;
		}

		domain->power_dev =
			dev_pm_domain_attach_by_name(dev, data->gpc_name);
		if (IS_ERR(domain->power_dev)) {
			dev_err_probe(dev, PTR_ERR(domain->power_dev),
				      "failed to attach power domain\n");
			ret = PTR_ERR(domain->power_dev);
			goto cleanup_pds;
		}

		domain->genpd.name = data->name;
		domain->genpd.power_on = imx8m_blk_ctrl_power_on;
		domain->genpd.power_off = imx8m_blk_ctrl_power_off;
		domain->bc = bc;

		ret = pm_genpd_init(&domain->genpd, NULL, true);
		if (ret) {
			dev_err_probe(dev, ret, "failed to init power domain\n");
			dev_pm_domain_detach(domain->power_dev, true);
			goto cleanup_pds;
		}

		/*
		 * We use runtime PM to trigger power on/off of the upstream GPC
		 * domain, as a strict hierarchical parent/child power domain
		 * setup doesn't allow us to meet the sequencing requirements.
		 * This means we have nested locking of genpd locks, without the
		 * nesting being visible at the genpd level, so we need a
		 * separate lock class to make lockdep aware of the fact that
		 * this are separate domain locks that can be nested without a
		 * self-deadlock.
		 */
		lockdep_set_class(&domain->genpd.mlock,
				  &blk_ctrl_genpd_lock_class);

		bc->onecell_data.domains[i] = &domain->genpd;
	}

	ret = of_genpd_add_provider_onecell(dev->of_node, &bc->onecell_data);
	if (ret) {
		dev_err_probe(dev, ret, "failed to add power domain provider\n");
		goto cleanup_pds;
	}

	bc->power_nb.notifier_call = bc_data->power_notifier_fn;
	ret = dev_pm_genpd_add_notifier(bc->bus_power_dev, &bc->power_nb);
	if (ret) {
		dev_err_probe(dev, ret, "failed to add power notifier\n");
		goto cleanup_provider;
	}

	dev_set_drvdata(dev, bc);

	return 0;

cleanup_provider:
	of_genpd_del_provider(dev->of_node);
cleanup_pds:
	for (i--; i >= 0; i--) {
		pm_genpd_remove(&bc->domains[i].genpd);
		dev_pm_domain_detach(bc->domains[i].power_dev, true);
	}

	dev_pm_domain_detach(bc->bus_power_dev, true);

	return ret;
}

static int imx8m_blk_ctrl_remove(struct platform_device *pdev)
{
	struct imx8m_blk_ctrl *bc = dev_get_drvdata(&pdev->dev);
	int i;

	of_genpd_del_provider(pdev->dev.of_node);

	for (i = 0; bc->onecell_data.num_domains; i++) {
		struct imx8m_blk_ctrl_domain *domain = &bc->domains[i];

		pm_genpd_remove(&domain->genpd);
		dev_pm_domain_detach(domain->power_dev, true);
	}

	dev_pm_genpd_remove_notifier(bc->bus_power_dev);

	dev_pm_domain_detach(bc->bus_power_dev, true);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int imx8m_blk_ctrl_suspend(struct device *dev)
{
	struct imx8m_blk_ctrl *bc = dev_get_drvdata(dev);
	int ret, i;

	/*
	 * This may look strange, but is done so the generic PM_SLEEP code
	 * can power down our domains and more importantly power them up again
	 * after resume, without tripping over our usage of runtime PM to
	 * control the upstream GPC domains. Things happen in the right order
	 * in the system suspend/resume paths due to the device parent/child
	 * hierarchy.
	 */
	ret = pm_runtime_get_sync(bc->bus_power_dev);
	if (ret < 0) {
		pm_runtime_put_noidle(bc->bus_power_dev);
		return ret;
	}

	for (i = 0; i < bc->onecell_data.num_domains; i++) {
		struct imx8m_blk_ctrl_domain *domain = &bc->domains[i];

		ret = pm_runtime_get_sync(domain->power_dev);
		if (ret < 0) {
			pm_runtime_put_noidle(domain->power_dev);
			goto out_fail;
		}
	}

	return 0;

out_fail:
	for (i--; i >= 0; i--)
		pm_runtime_put(bc->domains[i].power_dev);

	pm_runtime_put(bc->bus_power_dev);

	return ret;
}

static int imx8m_blk_ctrl_resume(struct device *dev)
{
	struct imx8m_blk_ctrl *bc = dev_get_drvdata(dev);
	int i;

	for (i = 0; i < bc->onecell_data.num_domains; i++)
		pm_runtime_put(bc->domains[i].power_dev);

	pm_runtime_put(bc->bus_power_dev);

	return 0;
}
#endif

static const struct dev_pm_ops imx8m_blk_ctrl_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(imx8m_blk_ctrl_suspend, imx8m_blk_ctrl_resume)
};

static int imx8mm_vpu_power_notifier(struct notifier_block *nb,
				     unsigned long action, void *data)
{
	struct imx8m_blk_ctrl *bc = container_of(nb, struct imx8m_blk_ctrl,
						 power_nb);

	if (action != GENPD_NOTIFY_ON && action != GENPD_NOTIFY_PRE_OFF)
		return NOTIFY_OK;

	/*
	 * The ADB in the VPUMIX domain has no separate reset and clock
	 * enable bits, but is ungated together with the VPU clocks. To
	 * allow the handshake with the GPC to progress we put the VPUs
	 * in reset and ungate the clocks.
	 */
	regmap_clear_bits(bc->regmap, BLK_SFT_RSTN, BIT(0) | BIT(1) | BIT(2));
	regmap_set_bits(bc->regmap, BLK_CLK_EN, BIT(0) | BIT(1) | BIT(2));

	if (action == GENPD_NOTIFY_ON) {
		/*
		 * On power up we have no software backchannel to the GPC to
		 * wait for the ADB handshake to happen, so we just delay for a
		 * bit. On power down the GPC driver waits for the handshake.
		 */
		udelay(5);

		/* set "fuse" bits to enable the VPUs */
		regmap_set_bits(bc->regmap, 0x8, 0xffffffff);
		regmap_set_bits(bc->regmap, 0xc, 0xffffffff);
		regmap_set_bits(bc->regmap, 0x10, 0xffffffff);
		regmap_set_bits(bc->regmap, 0x14, 0xffffffff);
	}

	return NOTIFY_OK;
}

static const struct imx8m_blk_ctrl_domain_data imx8mm_vpu_blk_ctl_domain_data[] = {
	[IMX8MM_VPUBLK_PD_G1] = {
		.name = "vpublk-g1",
		.clk_names = (const char *[]){ "g1", },
		.num_clks = 1,
		.gpc_name = "g1",
		.rst_mask = BIT(1),
		.clk_mask = BIT(1),
	},
	[IMX8MM_VPUBLK_PD_G2] = {
		.name = "vpublk-g2",
		.clk_names = (const char *[]){ "g2", },
		.num_clks = 1,
		.gpc_name = "g2",
		.rst_mask = BIT(0),
		.clk_mask = BIT(0),
	},
	[IMX8MM_VPUBLK_PD_H1] = {
		.name = "vpublk-h1",
		.clk_names = (const char *[]){ "h1", },
		.num_clks = 1,
		.gpc_name = "h1",
		.rst_mask = BIT(2),
		.clk_mask = BIT(2),
	},
};

static const struct imx8m_blk_ctrl_data imx8mm_vpu_blk_ctl_dev_data = {
	.max_reg = 0x18,
	.power_notifier_fn = imx8mm_vpu_power_notifier,
	.domains = imx8mm_vpu_blk_ctl_domain_data,
	.num_domains = ARRAY_SIZE(imx8mm_vpu_blk_ctl_domain_data),
};

static int imx8mm_disp_power_notifier(struct notifier_block *nb,
				      unsigned long action, void *data)
{
	struct imx8m_blk_ctrl *bc = container_of(nb, struct imx8m_blk_ctrl,
						 power_nb);

	if (action != GENPD_NOTIFY_ON && action != GENPD_NOTIFY_PRE_OFF)
		return NOTIFY_OK;

	/* Enable bus clock and deassert bus reset */
	regmap_set_bits(bc->regmap, BLK_CLK_EN, BIT(12));
	regmap_set_bits(bc->regmap, BLK_SFT_RSTN, BIT(6));

	/*
	 * On power up we have no software backchannel to the GPC to
	 * wait for the ADB handshake to happen, so we just delay for a
	 * bit. On power down the GPC driver waits for the handshake.
	 */
	if (action == GENPD_NOTIFY_ON)
		udelay(5);


	return NOTIFY_OK;
}

static const struct imx8m_blk_ctrl_domain_data imx8mm_disp_blk_ctl_domain_data[] = {
	[IMX8MM_DISPBLK_PD_CSI_BRIDGE] = {
		.name = "dispblk-csi-bridge",
		.clk_names = (const char *[]){ "csi-bridge-axi", "csi-bridge-apb",
					       "csi-bridge-core", },
		.num_clks = 3,
		.gpc_name = "csi-bridge",
		.rst_mask = BIT(0) | BIT(1) | BIT(2),
		.clk_mask = BIT(0) | BIT(1) | BIT(2) | BIT(3) | BIT(4) | BIT(5),
	},
	[IMX8MM_DISPBLK_PD_LCDIF] = {
		.name = "dispblk-lcdif",
		.clk_names = (const char *[]){ "lcdif-axi", "lcdif-apb", "lcdif-pix", },
		.num_clks = 3,
		.gpc_name = "lcdif",
		.clk_mask = BIT(6) | BIT(7),
	},
	[IMX8MM_DISPBLK_PD_MIPI_DSI] = {
		.name = "dispblk-mipi-dsi",
		.clk_names = (const char *[]){ "dsi-pclk", "dsi-ref", },
		.num_clks = 2,
		.gpc_name = "mipi-dsi",
		.rst_mask = BIT(5),
		.clk_mask = BIT(8) | BIT(9),
		.mipi_phy_rst_mask = BIT(17),
	},
	[IMX8MM_DISPBLK_PD_MIPI_CSI] = {
		.name = "dispblk-mipi-csi",
		.clk_names = (const char *[]){ "csi-aclk", "csi-pclk" },
		.num_clks = 2,
		.gpc_name = "mipi-csi",
		.rst_mask = BIT(3) | BIT(4),
		.clk_mask = BIT(10) | BIT(11),
		.mipi_phy_rst_mask = BIT(16),
	},
};

static const struct imx8m_blk_ctrl_data imx8mm_disp_blk_ctl_dev_data = {
	.max_reg = 0x2c,
	.power_notifier_fn = imx8mm_disp_power_notifier,
	.domains = imx8mm_disp_blk_ctl_domain_data,
	.num_domains = ARRAY_SIZE(imx8mm_disp_blk_ctl_domain_data),
};

static const struct of_device_id imx8m_blk_ctrl_of_match[] = {
	{
		.compatible = "fsl,imx8mm-vpu-blk-ctrl",
		.data = &imx8mm_vpu_blk_ctl_dev_data
	}, {
		.compatible = "fsl,imx8mm-disp-blk-ctrl",
		.data = &imx8mm_disp_blk_ctl_dev_data
	} ,{
		/* Sentinel */
	}
};
MODULE_DEVICE_TABLE(of, imx8m_blk_ctrl_of_match);

static struct platform_driver imx8m_blk_ctrl_driver = {
	.probe = imx8m_blk_ctrl_probe,
	.remove = imx8m_blk_ctrl_remove,
	.driver = {
		.name = "imx8m-blk-ctrl",
		.pm = &imx8m_blk_ctrl_pm_ops,
		.of_match_table = imx8m_blk_ctrl_of_match,
	},
};
module_platform_driver(imx8m_blk_ctrl_driver);
