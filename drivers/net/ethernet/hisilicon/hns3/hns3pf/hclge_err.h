/* SPDX-License-Identifier: GPL-2.0+ */
/*  Copyright (c) 2016-2017 Hisilicon Limited. */

#ifndef __HCLGE_ERR_H
#define __HCLGE_ERR_H

#include "hclge_main.h"
#include "hnae3.h"

#define HCLGE_MPF_RAS_INT_MIN_BD_NUM	10
#define HCLGE_PF_RAS_INT_MIN_BD_NUM	4
#define HCLGE_MPF_MSIX_INT_MIN_BD_NUM	10
#define HCLGE_PF_MSIX_INT_MIN_BD_NUM	4

#define HCLGE_RAS_PF_OTHER_INT_STS_REG   0x20B00
#define HCLGE_RAS_REG_NFE_MASK   0xFF00
#define HCLGE_RAS_REG_ROCEE_ERR_MASK   0x3000000
#define HCLGE_RAS_REG_ERR_MASK \
	(HCLGE_RAS_REG_NFE_MASK | HCLGE_RAS_REG_ROCEE_ERR_MASK)

#define HCLGE_VECTOR0_REG_MSIX_MASK   0x1FF00

#define HCLGE_IMP_TCM_ECC_ERR_INT_EN	0xFFFF0000
#define HCLGE_IMP_TCM_ECC_ERR_INT_EN_MASK	0xFFFF0000
#define HCLGE_IMP_ITCM4_ECC_ERR_INT_EN	0x300
#define HCLGE_IMP_ITCM4_ECC_ERR_INT_EN_MASK	0x300
#define HCLGE_CMDQ_NIC_ECC_ERR_INT_EN	0xFFFF
#define HCLGE_CMDQ_NIC_ECC_ERR_INT_EN_MASK	0xFFFF
#define HCLGE_CMDQ_ROCEE_ECC_ERR_INT_EN	0xFFFF0000
#define HCLGE_CMDQ_ROCEE_ECC_ERR_INT_EN_MASK	0xFFFF0000
#define HCLGE_IMP_RD_POISON_ERR_INT_EN	0x0100
#define HCLGE_IMP_RD_POISON_ERR_INT_EN_MASK	0x0100
#define HCLGE_TQP_ECC_ERR_INT_EN	0x0FFF
#define HCLGE_TQP_ECC_ERR_INT_EN_MASK	0x0FFF
#define HCLGE_MSIX_SRAM_ECC_ERR_INT_EN_MASK	0x0F000000
#define HCLGE_MSIX_SRAM_ECC_ERR_INT_EN	0x0F000000
#define HCLGE_IGU_ERR_INT_EN	0x0000000F
#define HCLGE_IGU_ERR_INT_TYPE	0x00000660
#define HCLGE_IGU_ERR_INT_EN_MASK	0x000F
#define HCLGE_IGU_TNL_ERR_INT_EN    0x0002AABF
#define HCLGE_IGU_TNL_ERR_INT_EN_MASK  0x003F
#define HCLGE_PPP_MPF_ECC_ERR_INT0_EN	0xFFFFFFFF
#define HCLGE_PPP_MPF_ECC_ERR_INT0_EN_MASK	0xFFFFFFFF
#define HCLGE_PPP_MPF_ECC_ERR_INT1_EN	0xFFFFFFFF
#define HCLGE_PPP_MPF_ECC_ERR_INT1_EN_MASK	0xFFFFFFFF
#define HCLGE_PPP_PF_ERR_INT_EN	0x0003
#define HCLGE_PPP_PF_ERR_INT_EN_MASK	0x0003
#define HCLGE_PPP_MPF_ECC_ERR_INT2_EN	0x003F
#define HCLGE_PPP_MPF_ECC_ERR_INT2_EN_MASK	0x003F
#define HCLGE_PPP_MPF_ECC_ERR_INT3_EN	0x003F
#define HCLGE_PPP_MPF_ECC_ERR_INT3_EN_MASK	0x003F
#define HCLGE_TM_SCH_ECC_ERR_INT_EN	0x3
#define HCLGE_TM_QCN_ERR_INT_TYPE	0x29
#define HCLGE_TM_QCN_FIFO_INT_EN	0xFFFF00
#define HCLGE_TM_QCN_MEM_ERR_INT_EN	0xFFFFFF
#define HCLGE_NCSI_ERR_INT_EN	0x3
#define HCLGE_NCSI_ERR_INT_TYPE	0x9
#define HCLGE_MAC_COMMON_ERR_INT_EN		0x107FF
#define HCLGE_MAC_COMMON_ERR_INT_EN_MASK	0x107FF
#define HCLGE_MAC_TNL_INT_EN			GENMASK(9, 0)
#define HCLGE_MAC_TNL_INT_EN_MASK		GENMASK(9, 0)
#define HCLGE_MAC_TNL_INT_CLR			GENMASK(9, 0)
#define HCLGE_PPU_MPF_ABNORMAL_INT0_EN		GENMASK(31, 0)
#define HCLGE_PPU_MPF_ABNORMAL_INT0_EN_MASK	GENMASK(31, 0)
#define HCLGE_PPU_MPF_ABNORMAL_INT1_EN		GENMASK(31, 0)
#define HCLGE_PPU_MPF_ABNORMAL_INT1_EN_MASK	GENMASK(31, 0)
#define HCLGE_PPU_MPF_ABNORMAL_INT2_EN		0x3FFF3FFF
#define HCLGE_PPU_MPF_ABNORMAL_INT2_EN_MASK	0x3FFF3FFF
#define HCLGE_PPU_MPF_ABNORMAL_INT2_EN2		0xB
#define HCLGE_PPU_MPF_ABNORMAL_INT2_EN2_MASK	0xB
#define HCLGE_PPU_MPF_ABNORMAL_INT3_EN		GENMASK(7, 0)
#define HCLGE_PPU_MPF_ABNORMAL_INT3_EN_MASK	GENMASK(23, 16)
#define HCLGE_PPU_PF_ABNORMAL_INT_EN		GENMASK(5, 0)
#define HCLGE_PPU_PF_ABNORMAL_INT_EN_MASK	GENMASK(5, 0)
#define HCLGE_SSU_1BIT_ECC_ERR_INT_EN		GENMASK(31, 0)
#define HCLGE_SSU_1BIT_ECC_ERR_INT_EN_MASK	GENMASK(31, 0)
#define HCLGE_SSU_MULTI_BIT_ECC_ERR_INT_EN	GENMASK(31, 0)
#define HCLGE_SSU_MULTI_BIT_ECC_ERR_INT_EN_MASK	GENMASK(31, 0)
#define HCLGE_SSU_BIT32_ECC_ERR_INT_EN		0x0101
#define HCLGE_SSU_BIT32_ECC_ERR_INT_EN_MASK	0x0101
#define HCLGE_SSU_COMMON_INT_EN			GENMASK(9, 0)
#define HCLGE_SSU_COMMON_INT_EN_MASK		GENMASK(9, 0)
#define HCLGE_SSU_PORT_BASED_ERR_INT_EN		0x0BFF
#define HCLGE_SSU_PORT_BASED_ERR_INT_EN_MASK	0x0BFF0000
#define HCLGE_SSU_FIFO_OVERFLOW_ERR_INT_EN	GENMASK(23, 0)
#define HCLGE_SSU_FIFO_OVERFLOW_ERR_INT_EN_MASK	GENMASK(23, 0)

#define HCLGE_SSU_COMMON_ERR_INT_MASK	GENMASK(9, 0)
#define HCLGE_SSU_PORT_INT_MSIX_MASK	0x7BFF
#define HCLGE_IGU_INT_MASK		GENMASK(3, 0)
#define HCLGE_IGU_EGU_TNL_INT_MASK	GENMASK(5, 0)
#define HCLGE_PPP_MPF_INT_ST3_MASK	GENMASK(5, 0)
#define HCLGE_PPU_MPF_INT_ST3_MASK	GENMASK(7, 0)
#define HCLGE_PPU_MPF_INT_ST2_MSIX_MASK	BIT(29)
#define HCLGE_PPU_PF_INT_RAS_MASK	0x18
#define HCLGE_PPU_PF_INT_MSIX_MASK	0x26
#define HCLGE_PPU_PF_OVER_8BD_ERR_MASK	0x01
#define HCLGE_QCN_FIFO_INT_MASK		GENMASK(17, 0)
#define HCLGE_QCN_ECC_INT_MASK		GENMASK(21, 0)
#define HCLGE_NCSI_ECC_INT_MASK		GENMASK(1, 0)

#define HCLGE_ROCEE_RAS_NFE_INT_EN		0xF
#define HCLGE_ROCEE_RAS_CE_INT_EN		0x1
#define HCLGE_ROCEE_RAS_NFE_INT_EN_MASK		0xF
#define HCLGE_ROCEE_RAS_CE_INT_EN_MASK		0x1
#define HCLGE_ROCEE_RERR_INT_MASK		BIT(0)
#define HCLGE_ROCEE_BERR_INT_MASK		BIT(1)
#define HCLGE_ROCEE_AXI_ERR_INT_MASK		GENMASK(1, 0)
#define HCLGE_ROCEE_ECC_INT_MASK		BIT(2)
#define HCLGE_ROCEE_OVF_INT_MASK		BIT(3)
#define HCLGE_ROCEE_OVF_ERR_INT_MASK		0x10000
#define HCLGE_ROCEE_OVF_ERR_TYPE_MASK		0x3F

#define HCLGE_DESC_DATA_MAX			8
#define HCLGE_REG_NUM_MAX			256
#define HCLGE_DESC_NO_DATA_LEN			8

enum hclge_err_int_type {
	HCLGE_ERR_INT_MSIX = 0,
	HCLGE_ERR_INT_RAS_CE = 1,
	HCLGE_ERR_INT_RAS_NFE = 2,
	HCLGE_ERR_INT_RAS_FE = 3,
};

enum hclge_mod_name_list {
	MODULE_NONE		= 0,
	MODULE_BIOS_COMMON	= 1,
	MODULE_GE		= 2,
	MODULE_IGU_EGU		= 3,
	MODULE_LGE		= 4,
	MODULE_NCSI		= 5,
	MODULE_PPP		= 6,
	MODULE_QCN		= 7,
	MODULE_RCB_RX		= 8,
	MODULE_RTC		= 9,
	MODULE_SSU		= 10,
	MODULE_TM		= 11,
	MODULE_RCB_TX		= 12,
	MODULE_TXDMA		= 13,
	MODULE_MASTER		= 14,
	MODULE_HIMAC		= 15,
	/* add new MODULE NAME for NIC here in order */
	MODULE_ROCEE_TOP	= 40,
	MODULE_ROCEE_TIMER	= 41,
	MODULE_ROCEE_MDB	= 42,
	MODULE_ROCEE_TSP	= 43,
	MODULE_ROCEE_TRP	= 44,
	MODULE_ROCEE_SCC	= 45,
	MODULE_ROCEE_CAEP	= 46,
	MODULE_ROCEE_GEN_AC	= 47,
	MODULE_ROCEE_QMM	= 48,
	MODULE_ROCEE_LSAN	= 49,
	/* add new MODULE NAME for RoCEE here in order */
};

enum hclge_err_type_list {
	NONE_ERROR		= 0,
	FIFO_ERROR		= 1,
	MEMORY_ERROR		= 2,
	POISON_ERROR		= 3,
	MSIX_ECC_ERROR		= 4,
	TQP_INT_ECC_ERROR	= 5,
	PF_ABNORMAL_INT_ERROR	= 6,
	MPF_ABNORMAL_INT_ERROR	= 7,
	COMMON_ERROR		= 8,
	PORT_ERROR		= 9,
	ETS_ERROR		= 10,
	NCSI_ERROR		= 11,
	GLB_ERROR		= 12,
	LINK_ERROR		= 13,
	PTP_ERROR		= 14,
	/* add new ERROR TYPE for NIC here in order */
	ROCEE_NORMAL_ERR	= 40,
	ROCEE_OVF_ERR		= 41,
	ROCEE_BUS_ERR		= 42,
	/* add new ERROR TYPE for ROCEE here in order */
};

struct hclge_hw_blk {
	u32 msk;
	const char *name;
	int (*config_err_int)(struct hclge_dev *hdev, bool en);
};

struct hclge_hw_error {
	u32 int_msk;
	const char *msg;
	enum hnae3_reset_type reset_level;
};

struct hclge_hw_module_id {
	enum hclge_mod_name_list module_id;
	const char *msg;
};

struct hclge_hw_type_id {
	enum hclge_err_type_list type_id;
	const char *msg;
};

struct hclge_sum_err_info {
	u8 reset_type;
	u8 mod_num;
	u8 rsv[2];
};

struct hclge_mod_err_info {
	u8 mod_id;
	u8 err_num;
	u8 rsv[2];
};

struct hclge_type_reg_err_info {
	u8 type_id;
	u8 reg_num;
	u8 rsv[2];
	u32 hclge_reg[HCLGE_REG_NUM_MAX];
};

int hclge_config_mac_tnl_int(struct hclge_dev *hdev, bool en);
int hclge_config_nic_hw_error(struct hclge_dev *hdev, bool state);
int hclge_config_rocee_ras_interrupt(struct hclge_dev *hdev, bool en);
void hclge_handle_all_hns_hw_errors(struct hnae3_ae_dev *ae_dev);
bool hclge_find_error_source(struct hclge_dev *hdev);
void hclge_handle_occurred_error(struct hclge_dev *hdev);
pci_ers_result_t hclge_handle_hw_ras_error(struct hnae3_ae_dev *ae_dev);
int hclge_handle_hw_msix_error(struct hclge_dev *hdev,
			       unsigned long *reset_requests);
int hclge_handle_error_info_log(struct hnae3_ae_dev *ae_dev);
int hclge_handle_mac_tnl(struct hclge_dev *hdev);
#endif
