// SPDX-License-Identifier: GPL-2.0
/*
 * Qualcomm PCIe Endpoint controller driver
 *
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 * Author: Siddartha Mohanadoss <smohanad@codeaurora.org
 *
 * Copyright (c) 2021, Linaro Ltd.
 * Author: Manivannan Sadhasivam <manivannan.sadhasivam@linaro.org
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/mfd/syscon.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/pm_domain.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <linux/module.h>

#include "pcie-designware.h"

/* PARF registers */
#define PARF_SYS_CTRL				0x00
#define PARF_DB_CTRL				0x10
#define PARF_PM_CTRL				0x20
#define PARF_MHI_BASE_ADDR_LOWER		0x178
#define PARF_MHI_BASE_ADDR_UPPER		0x17c
#define PARF_DEBUG_INT_EN			0x190
#define PARF_AXI_MSTR_RD_HALT_NO_WRITES		0x1a4
#define PARF_AXI_MSTR_WR_ADDR_HALT		0x1a8
#define PARF_Q2A_FLUSH				0x1ac
#define PARF_LTSSM				0x1b0
#define PARF_CFG_BITS				0x210
#define PARF_INT_ALL_STATUS			0x224
#define PARF_INT_ALL_CLEAR			0x228
#define PARF_INT_ALL_MASK			0x22c
#define PARF_SLV_ADDR_MSB_CTRL			0x2c0
#define PARF_DBI_BASE_ADDR			0x350
#define PARF_DBI_BASE_ADDR_HI			0x354
#define PARF_SLV_ADDR_SPACE_SIZE		0x358
#define PARF_SLV_ADDR_SPACE_SIZE_HI		0x35c
#define PARF_ATU_BASE_ADDR			0x634
#define PARF_ATU_BASE_ADDR_HI			0x638
#define PARF_SRIS_MODE				0x644
#define PARF_DEVICE_TYPE			0x1000
#define PARF_BDF_TO_SID_CFG			0x2c00

/* PARF_INT_ALL_{STATUS/CLEAR/MASK} register fields */
#define PARF_INT_ALL_LINK_DOWN			BIT(1)
#define PARF_INT_ALL_BME			BIT(2)
#define PARF_INT_ALL_PM_TURNOFF			BIT(3)
#define PARF_INT_ALL_DEBUG			BIT(4)
#define PARF_INT_ALL_LTR			BIT(5)
#define PARF_INT_ALL_MHI_Q6			BIT(6)
#define PARF_INT_ALL_MHI_A7			BIT(7)
#define PARF_INT_ALL_DSTATE_CHANGE		BIT(8)
#define PARF_INT_ALL_L1SUB_TIMEOUT		BIT(9)
#define PARF_INT_ALL_MMIO_WRITE			BIT(10)
#define PARF_INT_ALL_CFG_WRITE			BIT(11)
#define PARF_INT_ALL_BRIDGE_FLUSH_N		BIT(12)
#define PARF_INT_ALL_LINK_UP			BIT(13)
#define PARF_INT_ALL_AER_LEGACY			BIT(14)
#define PARF_INT_ALL_PLS_ERR			BIT(15)
#define PARF_INT_ALL_PME_LEGACY			BIT(16)
#define PARF_INT_ALL_PLS_PME			BIT(17)

/* PARF_BDF_TO_SID_CFG register fields */
#define PARF_BDF_TO_SID_BYPASS			BIT(0)

/* PARF_DEBUG_INT_EN register fields */
#define PARF_DEBUG_INT_PM_DSTATE_CHANGE		BIT(1)
#define PARF_DEBUG_INT_CFG_BUS_MASTER_EN	BIT(2)
#define PARF_DEBUG_INT_RADM_PM_TURNOFF		BIT(3)

/* PARF_DEVICE_TYPE register fields */
#define PARF_DEVICE_TYPE_EP			0x0

/* PARF_PM_CTRL register fields */
#define PARF_PM_CTRL_REQ_EXIT_L1		BIT(1)
#define PARF_PM_CTRL_READY_ENTR_L23		BIT(2)
#define PARF_PM_CTRL_REQ_NOT_ENTR_L1		BIT(5)

/* PARF_AXI_MSTR_RD_HALT_NO_WRITES register fields */
#define PARF_AXI_MSTR_RD_HALT_NO_WRITE_EN	BIT(0)

/* PARF_AXI_MSTR_WR_ADDR_HALT register fields */
#define PARF_AXI_MSTR_WR_ADDR_HALT_EN		BIT(31)

/* PARF_Q2A_FLUSH register fields */
#define PARF_Q2A_FLUSH_EN			BIT(16)

/* PARF_SYS_CTRL register fields */
#define PARF_SYS_CTRL_AUX_PWR_DET		BIT(4)
#define PARF_SYS_CTRL_CORE_CLK_CGC_DIS		BIT(6)
#define PARF_SYS_CTRL_SLV_DBI_WAKE_DISABLE	BIT(11)

/* PARF_DB_CTRL register fields */
#define PARF_DB_CTRL_INSR_DBNCR_BLOCK		BIT(0)
#define PARF_DB_CTRL_RMVL_DBNCR_BLOCK		BIT(1)
#define PARF_DB_CTRL_DBI_WKP_BLOCK		BIT(4)
#define PARF_DB_CTRL_SLV_WKP_BLOCK		BIT(5)
#define PARF_DB_CTRL_MST_WKP_BLOCK		BIT(6)

/* PARF_CFG_BITS register fields */
#define PARF_CFG_BITS_REQ_EXIT_L1SS_MSI_LTR_EN	BIT(1)

/* ELBI registers */
#define ELBI_SYS_STTS				0x08

/* DBI registers */
#define DBI_CON_STATUS				0x44

/* DBI register fields */
#define DBI_CON_STATUS_POWER_STATE_MASK		GENMASK(1, 0)

#define XMLH_LINK_UP				0x400
#define CORE_RESET_TIME_US_MIN			1000
#define CORE_RESET_TIME_US_MAX			1005
#define WAKE_DELAY_US				2000 /* 2 ms */

#define to_pcie_ep(x)				dev_get_drvdata((x)->dev)

enum qcom_pcie_ep_link_status {
	QCOM_PCIE_EP_LINK_DISABLED,
	QCOM_PCIE_EP_LINK_ENABLED,
	QCOM_PCIE_EP_LINK_UP,
	QCOM_PCIE_EP_LINK_DOWN,
};

static struct clk_bulk_data qcom_pcie_ep_clks[] = {
	{ .id = "cfg" },
	{ .id = "aux" },
	{ .id = "bus_master" },
	{ .id = "bus_slave" },
	{ .id = "ref" },
	{ .id = "sleep" },
	{ .id = "slave_q2a" },
};

struct qcom_pcie_ep {
	struct dw_pcie pci;

	void __iomem *parf;
	void __iomem *elbi;
	struct regmap *perst_map;
	struct resource *mmio_res;

	struct reset_control *core_reset;
	struct gpio_desc *reset;
	struct gpio_desc *wake;
	struct phy *phy;

	u32 perst_en;
	u32 perst_sep_en;

	enum qcom_pcie_ep_link_status link_status;
	int global_irq;
	int perst_irq;
};

static int qcom_pcie_ep_core_reset(struct qcom_pcie_ep *pcie_ep)
{
	struct dw_pcie *pci = &pcie_ep->pci;
	struct device *dev = pci->dev;
	int ret;

	ret = reset_control_assert(pcie_ep->core_reset);
	if (ret) {
		dev_err(dev, "Cannot assert core reset\n");
		return ret;
	}

	usleep_range(CORE_RESET_TIME_US_MIN, CORE_RESET_TIME_US_MAX);

	ret = reset_control_deassert(pcie_ep->core_reset);
	if (ret) {
		dev_err(dev, "Cannot de-assert core reset\n");
		return ret;
	}

	usleep_range(CORE_RESET_TIME_US_MIN, CORE_RESET_TIME_US_MAX);

	return 0;
}

/*
 * Delatch PERST_EN and PERST_SEPARATION_ENABLE with TCSR to avoid
 * device reset during host reboot and hibernation. The driver is
 * expected to handle this situation.
 */
static void qcom_pcie_ep_configure_tcsr(struct qcom_pcie_ep *pcie_ep)
{
	regmap_write(pcie_ep->perst_map, pcie_ep->perst_en, 0);
	regmap_write(pcie_ep->perst_map, pcie_ep->perst_sep_en, 0);
}

static int qcom_pcie_dw_link_up(struct dw_pcie *pci)
{
	struct qcom_pcie_ep *pcie_ep = to_pcie_ep(pci);
	u32 reg;

	reg = readl_relaxed(pcie_ep->elbi + ELBI_SYS_STTS);

	return reg & XMLH_LINK_UP;
}

static int qcom_pcie_dw_start_link(struct dw_pcie *pci)
{
	struct qcom_pcie_ep *pcie_ep = to_pcie_ep(pci);

	enable_irq(pcie_ep->perst_irq);

	return 0;
}

static void qcom_pcie_dw_stop_link(struct dw_pcie *pci)
{
	struct qcom_pcie_ep *pcie_ep = to_pcie_ep(pci);

	disable_irq(pcie_ep->perst_irq);
}

static int qcom_pcie_perst_deassert(struct dw_pcie *pci)
{
	struct qcom_pcie_ep *pcie_ep = to_pcie_ep(pci);
	struct device *dev = pci->dev;
	u32 val, offset;
	int ret;

	ret = clk_bulk_prepare_enable(ARRAY_SIZE(qcom_pcie_ep_clks),
				      qcom_pcie_ep_clks);
	if (ret)
		return ret;

	ret = qcom_pcie_ep_core_reset(pcie_ep);
	if (ret)
		goto err_disable_clk;

	ret = phy_init(pcie_ep->phy);
	if (ret)
		goto err_disable_clk;

	ret = phy_power_on(pcie_ep->phy);
	if (ret)
		goto err_phy_exit;

	/* Assert WAKE# to RC to indicate device is ready */
	gpiod_set_value_cansleep(pcie_ep->wake, 1);
	usleep_range(WAKE_DELAY_US, WAKE_DELAY_US + 500);
	gpiod_set_value_cansleep(pcie_ep->wake, 0);

	qcom_pcie_ep_configure_tcsr(pcie_ep);

	/* Disable BDF to SID mapping */
	val = readl_relaxed(pcie_ep->parf + PARF_BDF_TO_SID_CFG);
	val |= PARF_BDF_TO_SID_BYPASS;
	writel_relaxed(val, pcie_ep->parf + PARF_BDF_TO_SID_CFG);

	/* Enable debug IRQ */
	val = readl_relaxed(pcie_ep->parf + PARF_DEBUG_INT_EN);
	val |= PARF_DEBUG_INT_RADM_PM_TURNOFF |
	       PARF_DEBUG_INT_CFG_BUS_MASTER_EN |
	       PARF_DEBUG_INT_PM_DSTATE_CHANGE;
	writel_relaxed(val, pcie_ep->parf + PARF_DEBUG_INT_EN);

	/* Configure PCIe to endpoint mode */
	writel_relaxed(PARF_DEVICE_TYPE_EP, pcie_ep->parf + PARF_DEVICE_TYPE);

	/* Allow entering L1 state */
	val = readl_relaxed(pcie_ep->parf + PARF_PM_CTRL);
	val &= ~PARF_PM_CTRL_REQ_NOT_ENTR_L1;
	writel_relaxed(val, pcie_ep->parf + PARF_PM_CTRL);

	/* Read halts write */
	val = readl_relaxed(pcie_ep->parf + PARF_AXI_MSTR_RD_HALT_NO_WRITES);
	val &= ~PARF_AXI_MSTR_RD_HALT_NO_WRITE_EN;
	writel_relaxed(val, pcie_ep->parf + PARF_AXI_MSTR_RD_HALT_NO_WRITES);

	/* Write after write halt */
	val = readl_relaxed(pcie_ep->parf + PARF_AXI_MSTR_WR_ADDR_HALT);
	val |= PARF_AXI_MSTR_WR_ADDR_HALT_EN;
	writel_relaxed(val, pcie_ep->parf + PARF_AXI_MSTR_WR_ADDR_HALT);

	/* Q2A flush disable */
	val = readl_relaxed(pcie_ep->parf + PARF_Q2A_FLUSH);
	val &= ~PARF_Q2A_FLUSH_EN;
	writel_relaxed(val, pcie_ep->parf + PARF_Q2A_FLUSH);

	/* Disable DBI Wakeup, core clock CGC and enable AUX power */
	val = readl_relaxed(pcie_ep->parf + PARF_SYS_CTRL);
	val |= PARF_SYS_CTRL_SLV_DBI_WAKE_DISABLE |
	       PARF_SYS_CTRL_CORE_CLK_CGC_DIS |
	       PARF_SYS_CTRL_AUX_PWR_DET;
	writel_relaxed(val, pcie_ep->parf + PARF_SYS_CTRL);

	/* Disable the debouncers */
	val = readl_relaxed(pcie_ep->parf + PARF_DB_CTRL);
	val |= PARF_DB_CTRL_INSR_DBNCR_BLOCK | PARF_DB_CTRL_RMVL_DBNCR_BLOCK |
	       PARF_DB_CTRL_DBI_WKP_BLOCK | PARF_DB_CTRL_SLV_WKP_BLOCK |
	       PARF_DB_CTRL_MST_WKP_BLOCK;
	writel_relaxed(val, pcie_ep->parf + PARF_DB_CTRL);

	/* Request to exit from L1SS for MSI and LTR MSG */
	val = readl_relaxed(pcie_ep->parf + PARF_CFG_BITS);
	val |= PARF_CFG_BITS_REQ_EXIT_L1SS_MSI_LTR_EN;
	writel_relaxed(val, pcie_ep->parf + PARF_CFG_BITS);

	dw_pcie_dbi_ro_wr_en(pci);

	/* Set the L0s Exit Latency to 2us-4us = 0x6 */
	offset = dw_pcie_find_capability(pci, PCI_CAP_ID_EXP);
	val = dw_pcie_readl_dbi(pci, offset + PCI_EXP_LNKCAP);
	val &= ~PCI_EXP_LNKCAP_L0SEL;
	val |= FIELD_PREP(PCI_EXP_LNKCAP_L0SEL, 0x6);
	dw_pcie_writel_dbi(pci, offset + PCI_EXP_LNKCAP, val);

	/* Set the L1 Exit Latency to be 32us-64 us = 0x6 */
	offset = dw_pcie_find_capability(pci, PCI_CAP_ID_EXP);
	val = dw_pcie_readl_dbi(pci, offset + PCI_EXP_LNKCAP);
	val &= ~PCI_EXP_LNKCAP_L1EL;
	val |= FIELD_PREP(PCI_EXP_LNKCAP_L1EL, 0x6);
	dw_pcie_writel_dbi(pci, offset + PCI_EXP_LNKCAP, val);

	dw_pcie_dbi_ro_wr_dis(pci);

	writel_relaxed(0, pcie_ep->parf + PARF_INT_ALL_MASK);
	val = PARF_INT_ALL_LINK_DOWN | PARF_INT_ALL_BME |
	      PARF_INT_ALL_PM_TURNOFF | PARF_INT_ALL_DSTATE_CHANGE |
	      PARF_INT_ALL_LINK_UP;
	writel_relaxed(val, pcie_ep->parf + PARF_INT_ALL_MASK);

	ret = dw_pcie_ep_init_complete(&pcie_ep->pci.ep);
	if (ret) {
		dev_err(dev, "Failed to complete initialization: %d\n", ret);
		goto err_phy_power_off;
	}

	/*
	 * The physical address of the MMIO region which is exposed as the BAR
	 * should be written to MHI BASE registers.
	 */
	writel_relaxed(pcie_ep->mmio_res->start,
		       pcie_ep->parf + PARF_MHI_BASE_ADDR_LOWER);
	writel_relaxed(0, pcie_ep->parf + PARF_MHI_BASE_ADDR_UPPER);

	dw_pcie_ep_init_notify(&pcie_ep->pci.ep);

	/* Enable LTSSM */
	val = readl_relaxed(pcie_ep->parf + PARF_LTSSM);
	val |= BIT(8);
	writel_relaxed(val, pcie_ep->parf + PARF_LTSSM);

	return 0;

err_phy_power_off:
	phy_power_off(pcie_ep->phy);
err_phy_exit:
	phy_exit(pcie_ep->phy);
err_disable_clk:
	clk_bulk_disable_unprepare(ARRAY_SIZE(qcom_pcie_ep_clks),
				   qcom_pcie_ep_clks);

	return ret;
}

static void qcom_pcie_perst_assert(struct dw_pcie *pci)
{
	struct qcom_pcie_ep *pcie_ep = to_pcie_ep(pci);
	struct device *dev = pci->dev;

	if (pcie_ep->link_status == QCOM_PCIE_EP_LINK_DISABLED) {
		dev_dbg(dev, "Link is already disabled\n");
		return;
	}

	phy_power_off(pcie_ep->phy);
	phy_exit(pcie_ep->phy);
	clk_bulk_disable_unprepare(ARRAY_SIZE(qcom_pcie_ep_clks),
				   qcom_pcie_ep_clks);
	pcie_ep->link_status = QCOM_PCIE_EP_LINK_DISABLED;
}

/* Common DWC controller ops */
static const struct dw_pcie_ops pci_ops = {
	.link_up = qcom_pcie_dw_link_up,
	.start_link = qcom_pcie_dw_start_link,
	.stop_link = qcom_pcie_dw_stop_link,
};

static int qcom_pcie_ep_get_io_resources(struct platform_device *pdev,
					 struct qcom_pcie_ep *pcie_ep)
{
	struct device *dev = &pdev->dev;
	struct dw_pcie *pci = &pcie_ep->pci;
	struct device_node *syscon;
	struct resource *res;
	int ret;

	pcie_ep->parf = devm_platform_ioremap_resource_byname(pdev, "parf");
	if (IS_ERR(pcie_ep->parf))
		return PTR_ERR(pcie_ep->parf);

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "dbi");
	pci->dbi_base = devm_pci_remap_cfg_resource(dev, res);
	if (IS_ERR(pci->dbi_base))
		return PTR_ERR(pci->dbi_base);
	pci->dbi_base2 = pci->dbi_base;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "elbi");
	pcie_ep->elbi = devm_pci_remap_cfg_resource(dev, res);
	if (IS_ERR(pcie_ep->elbi))
		return PTR_ERR(pcie_ep->elbi);

	pcie_ep->mmio_res = platform_get_resource_byname(pdev, IORESOURCE_MEM,
							 "mmio");

	syscon = of_parse_phandle(dev->of_node, "qcom,perst-regs", 0);
	if (!syscon) {
		dev_err(dev, "Failed to parse qcom,perst-regs\n");
		return -EINVAL;
	}

	pcie_ep->perst_map = syscon_node_to_regmap(syscon);
	of_node_put(syscon);
	if (IS_ERR(pcie_ep->perst_map))
		return PTR_ERR(pcie_ep->perst_map);

	ret = of_property_read_u32_index(dev->of_node, "qcom,perst-regs",
					 1, &pcie_ep->perst_en);
	if (ret < 0) {
		dev_err(dev, "No Perst Enable offset in syscon\n");
		return ret;
	}

	ret = of_property_read_u32_index(dev->of_node, "qcom,perst-regs",
					 2, &pcie_ep->perst_sep_en);
	if (ret < 0) {
		dev_err(dev, "No Perst Separation Enable offset in syscon\n");
		return ret;
	}

	return 0;
}

static int qcom_pcie_ep_get_resources(struct platform_device *pdev,
				      struct qcom_pcie_ep *pcie_ep)
{
	struct device *dev = &pdev->dev;
	int ret;

	ret = qcom_pcie_ep_get_io_resources(pdev, pcie_ep);
	if (ret) {
		dev_err(&pdev->dev, "Failed to get io resources %d\n", ret);
		return ret;
	}

	ret = devm_clk_bulk_get(dev, ARRAY_SIZE(qcom_pcie_ep_clks),
				qcom_pcie_ep_clks);
	if (ret)
		return ret;

	pcie_ep->core_reset = devm_reset_control_get_exclusive(dev, "core");
	if (IS_ERR(pcie_ep->core_reset))
		return PTR_ERR(pcie_ep->core_reset);

	pcie_ep->reset = devm_gpiod_get(dev, "reset", GPIOD_IN);
	if (IS_ERR(pcie_ep->reset))
		return PTR_ERR(pcie_ep->reset);

	pcie_ep->wake = devm_gpiod_get_optional(dev, "wake", GPIOD_OUT_LOW);
	if (IS_ERR(pcie_ep->wake))
		return PTR_ERR(pcie_ep->wake);

	pcie_ep->phy = devm_phy_optional_get(&pdev->dev, "pciephy");
	if (IS_ERR(pcie_ep->phy))
		ret = PTR_ERR(pcie_ep->phy);

	return ret;
}

/* TODO: Notify clients about PCIe state change */
static irqreturn_t qcom_pcie_ep_global_irq_thread(int irq, void *data)
{
	struct qcom_pcie_ep *pcie_ep = data;
	struct dw_pcie *pci = &pcie_ep->pci;
	struct device *dev = pci->dev;
	u32 status = readl_relaxed(pcie_ep->parf + PARF_INT_ALL_STATUS);
	u32 mask = readl_relaxed(pcie_ep->parf + PARF_INT_ALL_MASK);
	u32 dstate, val;

	writel_relaxed(status, pcie_ep->parf + PARF_INT_ALL_CLEAR);
	status &= mask;

	if (FIELD_GET(PARF_INT_ALL_LINK_DOWN, status)) {
		dev_dbg(dev, "Received Linkdown event\n");
		pcie_ep->link_status = QCOM_PCIE_EP_LINK_DOWN;
	} else if (FIELD_GET(PARF_INT_ALL_BME, status)) {
		dev_dbg(dev, "Received BME event. Link is enabled!\n");
		pcie_ep->link_status = QCOM_PCIE_EP_LINK_ENABLED;
	} else if (FIELD_GET(PARF_INT_ALL_PM_TURNOFF, status)) {
		dev_dbg(dev, "Received PM Turn-off event! Entering L23\n");
		val = readl_relaxed(pcie_ep->parf + PARF_PM_CTRL);
		val |= PARF_PM_CTRL_READY_ENTR_L23;
		writel_relaxed(val, pcie_ep->parf + PARF_PM_CTRL);
	} else if (FIELD_GET(PARF_INT_ALL_DSTATE_CHANGE, status)) {
		dstate = dw_pcie_readl_dbi(pci, DBI_CON_STATUS) &
					   DBI_CON_STATUS_POWER_STATE_MASK;
		dev_dbg(dev, "Received D%d state event\n", dstate);
		if (dstate == 3) {
			val = readl_relaxed(pcie_ep->parf + PARF_PM_CTRL);
			val |= PARF_PM_CTRL_REQ_EXIT_L1;
			writel_relaxed(val, pcie_ep->parf + PARF_PM_CTRL);
		}
	} else if (FIELD_GET(PARF_INT_ALL_LINK_UP, status)) {
		dev_dbg(dev, "Received Linkup event. Enumeration complete!\n");
		dw_pcie_ep_linkup(&pci->ep);
		pcie_ep->link_status = QCOM_PCIE_EP_LINK_UP;
	} else {
		dev_dbg(dev, "Received unknown event: %d\n", status);
	}

	return IRQ_HANDLED;
}

static irqreturn_t qcom_pcie_ep_perst_irq_thread(int irq, void *data)
{
	struct qcom_pcie_ep *pcie_ep = data;
	struct dw_pcie *pci = &pcie_ep->pci;
	struct device *dev = pci->dev;
	u32 perst;

	perst = gpiod_get_value(pcie_ep->reset);
	if (perst) {
		dev_dbg(dev, "PERST asserted by host. Shutting down the PCIe link!\n");
		qcom_pcie_perst_assert(pci);
	} else {
		dev_dbg(dev, "PERST de-asserted by host. Starting link training!\n");
		qcom_pcie_perst_deassert(pci);
	}

	irq_set_irq_type(gpiod_to_irq(pcie_ep->reset),
			 (perst ? IRQF_TRIGGER_HIGH : IRQF_TRIGGER_LOW));

	return IRQ_HANDLED;
}

static int qcom_pcie_ep_enable_irq_resources(struct platform_device *pdev,
					     struct qcom_pcie_ep *pcie_ep)
{
	int irq, ret;

	irq = platform_get_irq_byname(pdev, "global");
	if (irq < 0) {
		dev_err(&pdev->dev, "Failed to get Global IRQ\n");
		return irq;
	}

	ret = devm_request_threaded_irq(&pdev->dev, irq, NULL,
					qcom_pcie_ep_global_irq_thread,
					IRQF_ONESHOT,
					"global_irq", pcie_ep);
	if (ret) {
		dev_err(&pdev->dev, "Failed to request Global IRQ\n");
		return ret;
	}

	pcie_ep->perst_irq = gpiod_to_irq(pcie_ep->reset);
	irq_set_status_flags(pcie_ep->perst_irq, IRQ_NOAUTOEN);
	ret = devm_request_threaded_irq(&pdev->dev, pcie_ep->perst_irq, NULL,
					qcom_pcie_ep_perst_irq_thread,
					IRQF_TRIGGER_HIGH | IRQF_ONESHOT,
					"perst_irq", pcie_ep);
	if (ret) {
		dev_err(&pdev->dev, "Failed to request PERST IRQ\n");
		disable_irq(irq);
		return ret;
	}

	return 0;
}

static int qcom_pcie_ep_raise_irq(struct dw_pcie_ep *ep, u8 func_no,
				  enum pci_epc_irq_type type, u16 interrupt_num)
{
	struct dw_pcie *pci = to_dw_pcie_from_ep(ep);

	switch (type) {
	case PCI_EPC_IRQ_LEGACY:
		return dw_pcie_ep_raise_legacy_irq(ep, func_no);
	case PCI_EPC_IRQ_MSI:
		return dw_pcie_ep_raise_msi_irq(ep, func_no, interrupt_num);
	default:
		dev_err(pci->dev, "Unknown IRQ type\n");
		return -EINVAL;
	}
}

static const struct pci_epc_features qcom_pcie_epc_features = {
	.linkup_notifier = true,
	.core_init_notifier = true,
	.msi_capable = true,
	.msix_capable = false,
};

static const struct pci_epc_features *
qcom_pcie_epc_get_features(struct dw_pcie_ep *pci_ep)
{
	return &qcom_pcie_epc_features;
}

static void qcom_pcie_ep_init(struct dw_pcie_ep *ep)
{
	struct dw_pcie *pci = to_dw_pcie_from_ep(ep);
	enum pci_barno bar;

	for (bar = BAR_0; bar <= BAR_5; bar++)
		dw_pcie_ep_reset_bar(pci, bar);
}

static struct dw_pcie_ep_ops pci_ep_ops = {
	.ep_init = qcom_pcie_ep_init,
	.raise_irq = qcom_pcie_ep_raise_irq,
	.get_features = qcom_pcie_epc_get_features,
};

static int qcom_pcie_ep_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct qcom_pcie_ep *pcie_ep;
	int ret;

	pcie_ep = devm_kzalloc(dev, sizeof(*pcie_ep), GFP_KERNEL);
	if (!pcie_ep)
		return -ENOMEM;

	pcie_ep->pci.dev = dev;
	pcie_ep->pci.ops = &pci_ops;
	pcie_ep->pci.ep.ops = &pci_ep_ops;
	platform_set_drvdata(pdev, pcie_ep);

	ret = qcom_pcie_ep_get_resources(pdev, pcie_ep);
	if (ret)
		return ret;

	ret = clk_bulk_prepare_enable(ARRAY_SIZE(qcom_pcie_ep_clks),
				      qcom_pcie_ep_clks);
	if (ret)
		return ret;

	ret = qcom_pcie_ep_core_reset(pcie_ep);
	if (ret)
		goto err_disable_clk;

	ret = phy_init(pcie_ep->phy);
	if (ret)
		goto err_disable_clk;

	/* PHY needs to be powered on for dw_pcie_ep_init() */
	ret = phy_power_on(pcie_ep->phy);
	if (ret)
		goto err_phy_exit;

	ret = dw_pcie_ep_init(&pcie_ep->pci.ep);
	if (ret) {
		dev_err(dev, "Failed to initialize endpoint: %d\n", ret);
		goto err_phy_power_off;
	}

	ret = qcom_pcie_ep_enable_irq_resources(pdev, pcie_ep);
	if (ret)
		goto err_phy_power_off;

	return 0;

err_phy_power_off:
	phy_power_off(pcie_ep->phy);
err_phy_exit:
	phy_exit(pcie_ep->phy);
err_disable_clk:
	clk_bulk_disable_unprepare(ARRAY_SIZE(qcom_pcie_ep_clks),
				   qcom_pcie_ep_clks);

	return ret;
}

static int qcom_pcie_ep_remove(struct platform_device *pdev)
{
	struct qcom_pcie_ep *pcie_ep = platform_get_drvdata(pdev);

	if (pcie_ep->link_status == QCOM_PCIE_EP_LINK_DISABLED)
		return 0;

	phy_power_off(pcie_ep->phy);
	phy_exit(pcie_ep->phy);
	clk_bulk_disable_unprepare(ARRAY_SIZE(qcom_pcie_ep_clks),
				   qcom_pcie_ep_clks);

	return 0;
}

static const struct of_device_id qcom_pcie_ep_match[] = {
	{ .compatible = "qcom,sdx55-pcie-ep", },
	{ }
};

static struct platform_driver qcom_pcie_ep_driver = {
	.probe	= qcom_pcie_ep_probe,
	.remove = qcom_pcie_ep_remove,
	.driver	= {
		.name = "qcom-pcie-ep",
		.of_match_table	= qcom_pcie_ep_match,
	},
};
builtin_platform_driver(qcom_pcie_ep_driver);

MODULE_AUTHOR("Siddartha Mohanadoss <smohanad@codeaurora.org>");
MODULE_AUTHOR("Manivannan Sadhasivam <manivannan.sadhasivam@linaro.org>");
MODULE_DESCRIPTION("Qualcomm PCIe Endpoint controller driver");
MODULE_LICENSE("GPL v2");
