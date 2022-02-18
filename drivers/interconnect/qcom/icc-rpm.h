/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Linaro Ltd
 */

#ifndef __DRIVERS_INTERCONNECT_QCOM_ICC_RPM_H
#define __DRIVERS_INTERCONNECT_QCOM_ICC_RPM_H

#define RPM_BUS_MASTER_REQ	0x73616d62
#define RPM_BUS_SLAVE_REQ	0x766c7362

#define to_qcom_provider(_provider) \
	container_of(_provider, struct qcom_icc_provider, provider)

/**
 * struct qcom_icc_provider - Qualcomm specific interconnect provider
 * @provider: generic interconnect provider
 * @bus_clks: the clk_bulk_data table of bus clocks
 * @num_clks: the total number of clk_bulk_data entries
 * @is_bimc_node: indicates whether to use bimc specific setting
 * @qos_offset: offset to QoS registers
 * @regmap: regmap for QoS registers read/write access
 */
struct qcom_icc_provider {
	struct icc_provider provider;
	int num_clks;
	bool is_bimc_node;
	struct regmap *regmap;
	unsigned int qos_offset;
	struct clk_bulk_data bus_clks[];
};

/**
 * struct qcom_icc_qos - Qualcomm specific interconnect QoS parameters
 * @areq_prio: node requests priority
 * @prio_level: priority level for bus communication
 * @limit_commands: activate/deactivate limiter mode during runtime
 * @ap_owned: indicates if the node is owned by the AP or by the RPM
 * @qos_mode: default qos mode for this node
 * @qos_port: qos port number for finding qos registers of this node
 */
struct qcom_icc_qos {
	u32 areq_prio;
	u32 prio_level;
	bool limit_commands;
	bool ap_owned;
	int qos_mode;
	int qos_port;
};

/**
 * struct qcom_icc_node - Qualcomm specific interconnect nodes
 * @name: the node name used in debugfs
 * @id: a unique node identifier
 * @links: an array of nodes where we can go next while traversing
 * @num_links: the total number of @links
 * @buswidth: width of the interconnect between a node and the bus (bytes)
 * @mas_rpm_id:	RPM id for devices that are bus masters
 * @slv_rpm_id:	RPM id for devices that are bus slaves
 * @qos: NoC QoS setting parameters
 * @rate: current bus clock rate in Hz
 */
struct qcom_icc_node {
	unsigned char *name;
	u16 id;
	const u16 *links;
	u16 num_links;
	u16 buswidth;
	int mas_rpm_id;
	int slv_rpm_id;
	struct qcom_icc_qos qos;
	u64 rate;
};

struct qcom_icc_desc {
	struct qcom_icc_node **nodes;
	size_t num_nodes;
	const char * const *clocks;
	size_t num_clocks;
	bool is_bimc_node;
	const struct regmap_config *regmap_cfg;
	unsigned int qos_offset;
};

/* Valid for both NoC and BIMC */
#define NOC_QOS_MODE_INVALID		-1
#define NOC_QOS_MODE_FIXED		0x0
#define NOC_QOS_MODE_BYPASS		0x2

int qnoc_probe(struct platform_device *pdev);
int qnoc_remove(struct platform_device *pdev);

#endif
