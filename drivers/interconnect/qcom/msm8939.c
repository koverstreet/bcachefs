// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Linaro Ltd
 * Author: Jun Nie <jun.nie@linaro.org>
 * With reference of msm8916 interconnect driver of Georgi Djakov.
 */

#include <linux/clk.h>
#include <linux/device.h>
#include <linux/interconnect-provider.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/of_device.h>

#include <dt-bindings/interconnect/qcom,msm8939.h>

#include "smd-rpm.h"
#include "icc-rpm.h"

enum {
	MSM8939_BIMC_SNOC_MAS = 1,
	MSM8939_BIMC_SNOC_SLV,
	MSM8939_MASTER_AMPSS_M0,
	MSM8939_MASTER_LPASS,
	MSM8939_MASTER_BLSP_1,
	MSM8939_MASTER_DEHR,
	MSM8939_MASTER_GRAPHICS_3D,
	MSM8939_MASTER_JPEG,
	MSM8939_MASTER_MDP_PORT0,
	MSM8939_MASTER_MDP_PORT1,
	MSM8939_MASTER_CPP,
	MSM8939_MASTER_CRYPTO_CORE0,
	MSM8939_MASTER_SDCC_1,
	MSM8939_MASTER_SDCC_2,
	MSM8939_MASTER_QDSS_BAM,
	MSM8939_MASTER_QDSS_ETR,
	MSM8939_MASTER_SNOC_CFG,
	MSM8939_MASTER_SPDM,
	MSM8939_MASTER_TCU0,
	MSM8939_MASTER_USB_HS1,
	MSM8939_MASTER_USB_HS2,
	MSM8939_MASTER_VFE,
	MSM8939_MASTER_VIDEO_P0,
	MSM8939_SNOC_MM_INT_0,
	MSM8939_SNOC_MM_INT_1,
	MSM8939_SNOC_MM_INT_2,
	MSM8939_PNOC_INT_0,
	MSM8939_PNOC_INT_1,
	MSM8939_PNOC_MAS_0,
	MSM8939_PNOC_MAS_1,
	MSM8939_PNOC_SLV_0,
	MSM8939_PNOC_SLV_1,
	MSM8939_PNOC_SLV_2,
	MSM8939_PNOC_SLV_3,
	MSM8939_PNOC_SLV_4,
	MSM8939_PNOC_SLV_8,
	MSM8939_PNOC_SLV_9,
	MSM8939_PNOC_SNOC_MAS,
	MSM8939_PNOC_SNOC_SLV,
	MSM8939_SNOC_QDSS_INT,
	MSM8939_SLAVE_AMPSS_L2,
	MSM8939_SLAVE_APSS,
	MSM8939_SLAVE_LPASS,
	MSM8939_SLAVE_BIMC_CFG,
	MSM8939_SLAVE_BLSP_1,
	MSM8939_SLAVE_BOOT_ROM,
	MSM8939_SLAVE_CAMERA_CFG,
	MSM8939_SLAVE_CATS_128,
	MSM8939_SLAVE_OCMEM_64,
	MSM8939_SLAVE_CLK_CTL,
	MSM8939_SLAVE_CRYPTO_0_CFG,
	MSM8939_SLAVE_DEHR_CFG,
	MSM8939_SLAVE_DISPLAY_CFG,
	MSM8939_SLAVE_EBI_CH0,
	MSM8939_SLAVE_GRAPHICS_3D_CFG,
	MSM8939_SLAVE_IMEM_CFG,
	MSM8939_SLAVE_IMEM,
	MSM8939_SLAVE_MPM,
	MSM8939_SLAVE_MSG_RAM,
	MSM8939_SLAVE_MSS,
	MSM8939_SLAVE_PDM,
	MSM8939_SLAVE_PMIC_ARB,
	MSM8939_SLAVE_PNOC_CFG,
	MSM8939_SLAVE_PRNG,
	MSM8939_SLAVE_QDSS_CFG,
	MSM8939_SLAVE_QDSS_STM,
	MSM8939_SLAVE_RBCPR_CFG,
	MSM8939_SLAVE_SDCC_1,
	MSM8939_SLAVE_SDCC_2,
	MSM8939_SLAVE_SECURITY,
	MSM8939_SLAVE_SNOC_CFG,
	MSM8939_SLAVE_SPDM,
	MSM8939_SLAVE_SRVC_SNOC,
	MSM8939_SLAVE_TCSR,
	MSM8939_SLAVE_TLMM,
	MSM8939_SLAVE_USB_HS1,
	MSM8939_SLAVE_USB_HS2,
	MSM8939_SLAVE_VENUS_CFG,
	MSM8939_SNOC_BIMC_0_MAS,
	MSM8939_SNOC_BIMC_0_SLV,
	MSM8939_SNOC_BIMC_1_MAS,
	MSM8939_SNOC_BIMC_1_SLV,
	MSM8939_SNOC_BIMC_2_MAS,
	MSM8939_SNOC_BIMC_2_SLV,
	MSM8939_SNOC_INT_0,
	MSM8939_SNOC_INT_1,
	MSM8939_SNOC_INT_BIMC,
	MSM8939_SNOC_PNOC_MAS,
	MSM8939_SNOC_PNOC_SLV,
};

static const u16 bimc_snoc_mas_links[] = {
	MSM8939_BIMC_SNOC_SLV
};

static struct qcom_icc_node bimc_snoc_mas = {
	.name = "bimc_snoc_mas",
	.id = MSM8939_BIMC_SNOC_MAS,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_INVALID,
	.num_links = ARRAY_SIZE(bimc_snoc_mas_links),
	.links = bimc_snoc_mas_links,
};

static const u16 bimc_snoc_slv_links[] = {
	MSM8939_SNOC_INT_0,
	MSM8939_SNOC_INT_1
};

static struct qcom_icc_node bimc_snoc_slv = {
	.name = "bimc_snoc_slv",
	.id = MSM8939_BIMC_SNOC_SLV,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = 2,
	.num_links = ARRAY_SIZE(bimc_snoc_slv_links),
	.links = bimc_snoc_slv_links,
};

static const u16 mas_apss_links[] = {
	MSM8939_SLAVE_EBI_CH0,
	MSM8939_BIMC_SNOC_MAS,
	MSM8939_SLAVE_AMPSS_L2
};

static struct qcom_icc_node mas_apss = {
	.name = "mas_apss",
	.id = MSM8939_MASTER_AMPSS_M0,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_FIXED,
	.qos.areq_prio = 0,
	.qos.prio_level = 0,
	.qos.qos_port = 0,
	.num_links = ARRAY_SIZE(mas_apss_links),
	.links = mas_apss_links,
};

static const u16 mas_audio_links[] = {
	MSM8939_PNOC_MAS_0
};

static struct qcom_icc_node mas_audio = {
	.name = "mas_audio",
	.id = MSM8939_MASTER_LPASS,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(mas_audio_links),
	.links = mas_audio_links,
};

static const u16 mas_blsp_1_links[] = {
	MSM8939_PNOC_MAS_1
};

static struct qcom_icc_node mas_blsp_1 = {
	.name = "mas_blsp_1",
	.id = MSM8939_MASTER_BLSP_1,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(mas_blsp_1_links),
	.links = mas_blsp_1_links,
};

static const u16 mas_dehr_links[] = {
	MSM8939_PNOC_MAS_0
};

static struct qcom_icc_node mas_dehr = {
	.name = "mas_dehr",
	.id = MSM8939_MASTER_DEHR,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(mas_dehr_links),
	.links = mas_dehr_links,
};

static const u16 mas_gfx_links[] = {
	MSM8939_SLAVE_EBI_CH0,
	MSM8939_BIMC_SNOC_MAS,
	MSM8939_SLAVE_AMPSS_L2
};

static struct qcom_icc_node mas_gfx = {
	.name = "mas_gfx",
	.id = MSM8939_MASTER_GRAPHICS_3D,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_FIXED,
	.qos.areq_prio = 0,
	.qos.prio_level = 0,
	.qos.qos_port = 2,
	.num_links = ARRAY_SIZE(mas_gfx_links),
	.links = mas_gfx_links,
};

static const u16 mas_jpeg_links[] = {
	MSM8939_SNOC_MM_INT_0,
	MSM8939_SNOC_MM_INT_2
};

static struct qcom_icc_node mas_jpeg = {
	.name = "mas_jpeg",
	.id = MSM8939_MASTER_JPEG,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_BYPASS,
	.qos.areq_prio = 0,
	.qos.prio_level = 0,
	.qos.qos_port = 6,
	.num_links = ARRAY_SIZE(mas_jpeg_links),
	.links = mas_jpeg_links,
};

static const u16 mas_mdp0_links[] = {
	MSM8939_SNOC_MM_INT_1,
	MSM8939_SNOC_MM_INT_2
};

static struct qcom_icc_node mas_mdp0 = {
	.name = "mas_mdp0",
	.id = MSM8939_MASTER_MDP_PORT0,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_BYPASS,
	.qos.areq_prio = 0,
	.qos.prio_level = 0,
	.qos.qos_port = 7,
	.num_links = ARRAY_SIZE(mas_mdp0_links),
	.links = mas_mdp0_links,
};

static const u16 mas_mdp1_links[] = {
	MSM8939_SNOC_MM_INT_0,
	MSM8939_SNOC_MM_INT_2
};

static struct qcom_icc_node mas_mdp1 = {
	.name = "mas_mdp1",
	.id = MSM8939_MASTER_MDP_PORT1,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_BYPASS,
	.qos.areq_prio = 0,
	.qos.prio_level = 0,
	.qos.qos_port = 13,
	.num_links = ARRAY_SIZE(mas_mdp1_links),
	.links = mas_mdp1_links,
};

static const u16 mas_cpp_links[] = {
	MSM8939_SNOC_MM_INT_0,
	MSM8939_SNOC_MM_INT_2
};

static struct qcom_icc_node mas_cpp = {
	.name = "mas_cpp",
	.id = MSM8939_MASTER_CPP,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_BYPASS,
	.qos.areq_prio = 0,
	.qos.prio_level = 0,
	.qos.qos_port = 12,
	.num_links = ARRAY_SIZE(mas_cpp_links),
	.links = mas_cpp_links,
};

static const u16 mas_pcnoc_crypto_0_links[] = {
	MSM8939_PNOC_INT_1
};

static struct qcom_icc_node mas_pcnoc_crypto_0 = {
	.name = "mas_pcnoc_crypto_0",
	.id = MSM8939_MASTER_CRYPTO_CORE0,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(mas_pcnoc_crypto_0_links),
	.links = mas_pcnoc_crypto_0_links,
};

static const u16 mas_pcnoc_sdcc_1_links[] = {
	MSM8939_PNOC_INT_1
};

static struct qcom_icc_node mas_pcnoc_sdcc_1 = {
	.name = "mas_pcnoc_sdcc_1",
	.id = MSM8939_MASTER_SDCC_1,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(mas_pcnoc_sdcc_1_links),
	.links = mas_pcnoc_sdcc_1_links,
};

static const u16 mas_pcnoc_sdcc_2_links[] = {
	MSM8939_PNOC_INT_1
};

static struct qcom_icc_node mas_pcnoc_sdcc_2 = {
	.name = "mas_pcnoc_sdcc_2",
	.id = MSM8939_MASTER_SDCC_2,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(mas_pcnoc_sdcc_2_links),
	.links = mas_pcnoc_sdcc_2_links,
};

static const u16 mas_qdss_bam_links[] = {
	MSM8939_SNOC_QDSS_INT
};

static struct qcom_icc_node mas_qdss_bam = {
	.name = "mas_qdss_bam",
	.id = MSM8939_MASTER_QDSS_BAM,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_FIXED,
	.qos.areq_prio = 1,
	.qos.prio_level = 1,
	.qos.qos_port = 11,
	.num_links = ARRAY_SIZE(mas_qdss_bam_links),
	.links = mas_qdss_bam_links,
};

static const u16 mas_qdss_etr_links[] = {
	MSM8939_SNOC_QDSS_INT
};

static struct qcom_icc_node mas_qdss_etr = {
	.name = "mas_qdss_etr",
	.id = MSM8939_MASTER_QDSS_ETR,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_FIXED,
	.qos.areq_prio = 1,
	.qos.prio_level = 1,
	.qos.qos_port = 10,
	.num_links = ARRAY_SIZE(mas_qdss_etr_links),
	.links = mas_qdss_etr_links,
};

static const u16 mas_snoc_cfg_links[] = {
	MSM8939_SLAVE_SRVC_SNOC
};

static struct qcom_icc_node mas_snoc_cfg = {
	.name = "mas_snoc_cfg",
	.id = MSM8939_MASTER_SNOC_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(mas_snoc_cfg_links),
	.links = mas_snoc_cfg_links,
};

static const u16 mas_spdm_links[] = {
	MSM8939_PNOC_MAS_0
};

static struct qcom_icc_node mas_spdm = {
	.name = "mas_spdm",
	.id = MSM8939_MASTER_SPDM,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(mas_spdm_links),
	.links = mas_spdm_links,
};

static const u16 mas_tcu0_links[] = {
	MSM8939_SLAVE_EBI_CH0,
	MSM8939_BIMC_SNOC_MAS,
	MSM8939_SLAVE_AMPSS_L2
};

static struct qcom_icc_node mas_tcu0 = {
	.name = "mas_tcu0",
	.id = MSM8939_MASTER_TCU0,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_FIXED,
	.qos.areq_prio = 2,
	.qos.prio_level = 2,
	.qos.qos_port = 6,
	.num_links = ARRAY_SIZE(mas_tcu0_links),
	.links = mas_tcu0_links,
};

static const u16 mas_usb_hs1_links[] = {
	MSM8939_PNOC_MAS_1
};

static struct qcom_icc_node mas_usb_hs1 = {
	.name = "mas_usb_hs1",
	.id = MSM8939_MASTER_USB_HS1,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(mas_usb_hs1_links),
	.links = mas_usb_hs1_links,
};

static const u16 mas_usb_hs2_links[] = {
	MSM8939_PNOC_MAS_1
};

static struct qcom_icc_node mas_usb_hs2 = {
	.name = "mas_usb_hs2",
	.id = MSM8939_MASTER_USB_HS2,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(mas_usb_hs2_links),
	.links = mas_usb_hs2_links,
};

static const u16 mas_vfe_links[] = {
	MSM8939_SNOC_MM_INT_1,
	MSM8939_SNOC_MM_INT_2
};

static struct qcom_icc_node mas_vfe = {
	.name = "mas_vfe",
	.id = MSM8939_MASTER_VFE,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_BYPASS,
	.qos.areq_prio = 0,
	.qos.prio_level = 0,
	.qos.qos_port = 9,
	.num_links = ARRAY_SIZE(mas_vfe_links),
	.links = mas_vfe_links,
};

static const u16 mas_video_links[] = {
	MSM8939_SNOC_MM_INT_0,
	MSM8939_SNOC_MM_INT_2
};

static struct qcom_icc_node mas_video = {
	.name = "mas_video",
	.id = MSM8939_MASTER_VIDEO_P0,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_BYPASS,
	.qos.areq_prio = 0,
	.qos.prio_level = 0,
	.qos.qos_port = 8,
	.num_links = ARRAY_SIZE(mas_video_links),
	.links = mas_video_links,
};

static const u16 mm_int_0_links[] = {
	MSM8939_SNOC_BIMC_2_MAS
};

static struct qcom_icc_node mm_int_0 = {
	.name = "mm_int_0",
	.id = MSM8939_SNOC_MM_INT_0,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_INVALID,
	.num_links = ARRAY_SIZE(mm_int_0_links),
	.links = mm_int_0_links,
};

static const u16 mm_int_1_links[] = {
	MSM8939_SNOC_BIMC_1_MAS
};

static struct qcom_icc_node mm_int_1 = {
	.name = "mm_int_1",
	.id = MSM8939_SNOC_MM_INT_1,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_INVALID,
	.num_links = ARRAY_SIZE(mm_int_1_links),
	.links = mm_int_1_links,
};

static const u16 mm_int_2_links[] = {
	MSM8939_SNOC_INT_0
};

static struct qcom_icc_node mm_int_2 = {
	.name = "mm_int_2",
	.id = MSM8939_SNOC_MM_INT_2,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_INVALID,
	.num_links = ARRAY_SIZE(mm_int_2_links),
	.links = mm_int_2_links,
};

static const u16 pcnoc_int_0_links[] = {
	MSM8939_PNOC_SNOC_MAS,
	MSM8939_PNOC_SLV_0,
	MSM8939_PNOC_SLV_1,
	MSM8939_PNOC_SLV_2,
	MSM8939_PNOC_SLV_3,
	MSM8939_PNOC_SLV_4,
	MSM8939_PNOC_SLV_8,
	MSM8939_PNOC_SLV_9
};

static struct qcom_icc_node pcnoc_int_0 = {
	.name = "pcnoc_int_0",
	.id = MSM8939_PNOC_INT_0,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(pcnoc_int_0_links),
	.links = pcnoc_int_0_links,
};

static const u16 pcnoc_int_1_links[] = {
	MSM8939_PNOC_SNOC_MAS
};

static struct qcom_icc_node pcnoc_int_1 = {
	.name = "pcnoc_int_1",
	.id = MSM8939_PNOC_INT_1,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(pcnoc_int_1_links),
	.links = pcnoc_int_1_links,
};

static const u16 pcnoc_m_0_links[] = {
	MSM8939_PNOC_INT_0
};

static struct qcom_icc_node pcnoc_m_0 = {
	.name = "pcnoc_m_0",
	.id = MSM8939_PNOC_MAS_0,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(pcnoc_m_0_links),
	.links = pcnoc_m_0_links,
};

static const u16 pcnoc_m_1_links[] = {
	MSM8939_PNOC_SNOC_MAS
};

static struct qcom_icc_node pcnoc_m_1 = {
	.name = "pcnoc_m_1",
	.id = MSM8939_PNOC_MAS_1,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(pcnoc_m_1_links),
	.links = pcnoc_m_1_links,
};

static const u16 pcnoc_s_0_links[] = {
	MSM8939_SLAVE_CLK_CTL,
	MSM8939_SLAVE_TLMM,
	MSM8939_SLAVE_TCSR,
	MSM8939_SLAVE_SECURITY,
	MSM8939_SLAVE_MSS
};

static struct qcom_icc_node pcnoc_s_0 = {
	.name = "pcnoc_s_0",
	.id = MSM8939_PNOC_SLV_0,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(pcnoc_s_0_links),
	.links = pcnoc_s_0_links,
};

static const u16 pcnoc_s_1_links[] = {
	MSM8939_SLAVE_IMEM_CFG,
	MSM8939_SLAVE_CRYPTO_0_CFG,
	MSM8939_SLAVE_MSG_RAM,
	MSM8939_SLAVE_PDM,
	MSM8939_SLAVE_PRNG
};

static struct qcom_icc_node pcnoc_s_1 = {
	.name = "pcnoc_s_1",
	.id = MSM8939_PNOC_SLV_1,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(pcnoc_s_1_links),
	.links = pcnoc_s_1_links,
};

static const u16 pcnoc_s_2_links[] = {
	MSM8939_SLAVE_SPDM,
	MSM8939_SLAVE_BOOT_ROM,
	MSM8939_SLAVE_BIMC_CFG,
	MSM8939_SLAVE_PNOC_CFG,
	MSM8939_SLAVE_PMIC_ARB
};

static struct qcom_icc_node pcnoc_s_2 = {
	.name = "pcnoc_s_2",
	.id = MSM8939_PNOC_SLV_2,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(pcnoc_s_2_links),
	.links = pcnoc_s_2_links,
};

static const u16 pcnoc_s_3_links[] = {
	MSM8939_SLAVE_MPM,
	MSM8939_SLAVE_SNOC_CFG,
	MSM8939_SLAVE_RBCPR_CFG,
	MSM8939_SLAVE_QDSS_CFG,
	MSM8939_SLAVE_DEHR_CFG
};

static struct qcom_icc_node pcnoc_s_3 = {
	.name = "pcnoc_s_3",
	.id = MSM8939_PNOC_SLV_3,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(pcnoc_s_3_links),
	.links = pcnoc_s_3_links,
};

static const u16 pcnoc_s_4_links[] = {
	MSM8939_SLAVE_VENUS_CFG,
	MSM8939_SLAVE_CAMERA_CFG,
	MSM8939_SLAVE_DISPLAY_CFG
};

static struct qcom_icc_node pcnoc_s_4 = {
	.name = "pcnoc_s_4",
	.id = MSM8939_PNOC_SLV_4,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(pcnoc_s_4_links),
	.links = pcnoc_s_4_links,
};

static const u16 pcnoc_s_8_links[] = {
	MSM8939_SLAVE_USB_HS1,
	MSM8939_SLAVE_SDCC_1,
	MSM8939_SLAVE_BLSP_1
};

static struct qcom_icc_node pcnoc_s_8 = {
	.name = "pcnoc_s_8",
	.id = MSM8939_PNOC_SLV_8,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(pcnoc_s_8_links),
	.links = pcnoc_s_8_links,
};

static const u16 pcnoc_s_9_links[] = {
	MSM8939_SLAVE_SDCC_2,
	MSM8939_SLAVE_LPASS,
	MSM8939_SLAVE_USB_HS2
};

static struct qcom_icc_node pcnoc_s_9 = {
	.name = "pcnoc_s_9",
	.id = MSM8939_PNOC_SLV_9,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(pcnoc_s_9_links),
	.links = pcnoc_s_9_links,
};

static const u16 pcnoc_snoc_mas_links[] = {
	MSM8939_PNOC_SNOC_SLV
};

static struct qcom_icc_node pcnoc_snoc_mas = {
	.name = "pcnoc_snoc_mas",
	.id = MSM8939_PNOC_SNOC_MAS,
	.buswidth = 8,
	.mas_rpm_id = 29,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(pcnoc_snoc_mas_links),
	.links = pcnoc_snoc_mas_links,
};

static const u16 pcnoc_snoc_slv_links[] = {
	MSM8939_SNOC_INT_0,
	MSM8939_SNOC_INT_BIMC,
	MSM8939_SNOC_INT_1
};

static struct qcom_icc_node pcnoc_snoc_slv = {
	.name = "pcnoc_snoc_slv",
	.id = MSM8939_PNOC_SNOC_SLV,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = 45,
	.num_links = ARRAY_SIZE(pcnoc_snoc_slv_links),
	.links = pcnoc_snoc_slv_links,
};

static const u16 qdss_int_links[] = {
	MSM8939_SNOC_INT_0,
	MSM8939_SNOC_INT_BIMC
};

static struct qcom_icc_node qdss_int = {
	.name = "qdss_int",
	.id = MSM8939_SNOC_QDSS_INT,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_INVALID,
	.num_links = ARRAY_SIZE(qdss_int_links),
	.links = qdss_int_links,
};

static struct qcom_icc_node slv_apps_l2 = {
	.name = "slv_apps_l2",
	.id = MSM8939_SLAVE_AMPSS_L2,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_apss = {
	.name = "slv_apss",
	.id = MSM8939_SLAVE_APSS,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_audio = {
	.name = "slv_audio",
	.id = MSM8939_SLAVE_LPASS,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_bimc_cfg = {
	.name = "slv_bimc_cfg",
	.id = MSM8939_SLAVE_BIMC_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_blsp_1 = {
	.name = "slv_blsp_1",
	.id = MSM8939_SLAVE_BLSP_1,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_boot_rom = {
	.name = "slv_boot_rom",
	.id = MSM8939_SLAVE_BOOT_ROM,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_camera_cfg = {
	.name = "slv_camera_cfg",
	.id = MSM8939_SLAVE_CAMERA_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_cats_0 = {
	.name = "slv_cats_0",
	.id = MSM8939_SLAVE_CATS_128,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_cats_1 = {
	.name = "slv_cats_1",
	.id = MSM8939_SLAVE_OCMEM_64,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_clk_ctl = {
	.name = "slv_clk_ctl",
	.id = MSM8939_SLAVE_CLK_CTL,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_crypto_0_cfg = {
	.name = "slv_crypto_0_cfg",
	.id = MSM8939_SLAVE_CRYPTO_0_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_dehr_cfg = {
	.name = "slv_dehr_cfg",
	.id = MSM8939_SLAVE_DEHR_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_display_cfg = {
	.name = "slv_display_cfg",
	.id = MSM8939_SLAVE_DISPLAY_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_ebi_ch0 = {
	.name = "slv_ebi_ch0",
	.id = MSM8939_SLAVE_EBI_CH0,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = 0,
};

static struct qcom_icc_node slv_gfx_cfg = {
	.name = "slv_gfx_cfg",
	.id = MSM8939_SLAVE_GRAPHICS_3D_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_imem_cfg = {
	.name = "slv_imem_cfg",
	.id = MSM8939_SLAVE_IMEM_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_imem = {
	.name = "slv_imem",
	.id = MSM8939_SLAVE_IMEM,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = 26,
};

static struct qcom_icc_node slv_mpm = {
	.name = "slv_mpm",
	.id = MSM8939_SLAVE_MPM,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_msg_ram = {
	.name = "slv_msg_ram",
	.id = MSM8939_SLAVE_MSG_RAM,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_mss = {
	.name = "slv_mss",
	.id = MSM8939_SLAVE_MSS,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_pdm = {
	.name = "slv_pdm",
	.id = MSM8939_SLAVE_PDM,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_pmic_arb = {
	.name = "slv_pmic_arb",
	.id = MSM8939_SLAVE_PMIC_ARB,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_pcnoc_cfg = {
	.name = "slv_pcnoc_cfg",
	.id = MSM8939_SLAVE_PNOC_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_prng = {
	.name = "slv_prng",
	.id = MSM8939_SLAVE_PRNG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_qdss_cfg = {
	.name = "slv_qdss_cfg",
	.id = MSM8939_SLAVE_QDSS_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_qdss_stm = {
	.name = "slv_qdss_stm",
	.id = MSM8939_SLAVE_QDSS_STM,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = 30,
};

static struct qcom_icc_node slv_rbcpr_cfg = {
	.name = "slv_rbcpr_cfg",
	.id = MSM8939_SLAVE_RBCPR_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_sdcc_1 = {
	.name = "slv_sdcc_1",
	.id = MSM8939_SLAVE_SDCC_1,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_sdcc_2 = {
	.name = "slv_sdcc_2",
	.id = MSM8939_SLAVE_SDCC_2,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_security = {
	.name = "slv_security",
	.id = MSM8939_SLAVE_SECURITY,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_snoc_cfg = {
	.name = "slv_snoc_cfg",
	.id = MSM8939_SLAVE_SNOC_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_spdm = {
	.name = "slv_spdm",
	.id = MSM8939_SLAVE_SPDM,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_srvc_snoc = {
	.name = "slv_srvc_snoc",
	.id = MSM8939_SLAVE_SRVC_SNOC,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_tcsr = {
	.name = "slv_tcsr",
	.id = MSM8939_SLAVE_TCSR,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_tlmm = {
	.name = "slv_tlmm",
	.id = MSM8939_SLAVE_TLMM,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_usb_hs1 = {
	.name = "slv_usb_hs1",
	.id = MSM8939_SLAVE_USB_HS1,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_usb_hs2 = {
	.name = "slv_usb_hs2",
	.id = MSM8939_SLAVE_USB_HS2,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static struct qcom_icc_node slv_venus_cfg = {
	.name = "slv_venus_cfg",
	.id = MSM8939_SLAVE_VENUS_CFG,
	.buswidth = 4,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
};

static const u16 snoc_bimc_0_mas_links[] = {
	MSM8939_SNOC_BIMC_0_SLV
};

static struct qcom_icc_node snoc_bimc_0_mas = {
	.name = "snoc_bimc_0_mas",
	.id = MSM8939_SNOC_BIMC_0_MAS,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_INVALID,
	.num_links = ARRAY_SIZE(snoc_bimc_0_mas_links),
	.links = snoc_bimc_0_mas_links,
};

static const u16 snoc_bimc_0_slv_links[] = {
	MSM8939_SLAVE_EBI_CH0
};

static struct qcom_icc_node snoc_bimc_0_slv = {
	.name = "snoc_bimc_0_slv",
	.id = MSM8939_SNOC_BIMC_0_SLV,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_INVALID,
	.num_links = ARRAY_SIZE(snoc_bimc_0_slv_links),
	.links = snoc_bimc_0_slv_links,
};

static const u16 snoc_bimc_1_mas_links[] = {
	MSM8939_SNOC_BIMC_1_SLV
};

static struct qcom_icc_node snoc_bimc_1_mas = {
	.name = "snoc_bimc_1_mas",
	.id = MSM8939_SNOC_BIMC_1_MAS,
	.buswidth = 16,
	.mas_rpm_id = 76,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(snoc_bimc_1_mas_links),
	.links = snoc_bimc_1_mas_links,
};

static const u16 snoc_bimc_1_slv_links[] = {
	MSM8939_SLAVE_EBI_CH0
};

static struct qcom_icc_node snoc_bimc_1_slv = {
	.name = "snoc_bimc_1_slv",
	.id = MSM8939_SNOC_BIMC_1_SLV,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = 104,
	.num_links = ARRAY_SIZE(snoc_bimc_1_slv_links),
	.links = snoc_bimc_1_slv_links,
};

static const u16 snoc_bimc_2_mas_links[] = {
	MSM8939_SNOC_BIMC_2_SLV
};

static struct qcom_icc_node snoc_bimc_2_mas = {
	.name = "snoc_bimc_2_mas",
	.id = MSM8939_SNOC_BIMC_2_MAS,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_INVALID,
	.num_links = ARRAY_SIZE(snoc_bimc_2_mas_links),
	.links = snoc_bimc_2_mas_links,
};

static const u16 snoc_bimc_2_slv_links[] = {
	MSM8939_SLAVE_EBI_CH0
};

static struct qcom_icc_node snoc_bimc_2_slv = {
	.name = "snoc_bimc_2_slv",
	.id = MSM8939_SNOC_BIMC_2_SLV,
	.buswidth = 16,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.qos.ap_owned = true,
	.qos.qos_mode = NOC_QOS_MODE_INVALID,
	.num_links = ARRAY_SIZE(snoc_bimc_2_slv_links),
	.links = snoc_bimc_2_slv_links,
};

static const u16 snoc_int_0_links[] = {
	MSM8939_SLAVE_QDSS_STM,
	MSM8939_SLAVE_IMEM,
	MSM8939_SNOC_PNOC_MAS
};

static struct qcom_icc_node snoc_int_0 = {
	.name = "snoc_int_0",
	.id = MSM8939_SNOC_INT_0,
	.buswidth = 8,
	.mas_rpm_id = 99,
	.slv_rpm_id = 130,
	.num_links = ARRAY_SIZE(snoc_int_0_links),
	.links = snoc_int_0_links,
};

static const u16 snoc_int_1_links[] = {
	MSM8939_SLAVE_APSS,
	MSM8939_SLAVE_CATS_128,
	MSM8939_SLAVE_OCMEM_64
};

static struct qcom_icc_node snoc_int_1 = {
	.name = "snoc_int_1",
	.id = MSM8939_SNOC_INT_1,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(snoc_int_1_links),
	.links = snoc_int_1_links,
};

static const u16 snoc_int_bimc_links[] = {
	MSM8939_SNOC_BIMC_1_MAS
};

static struct qcom_icc_node snoc_int_bimc = {
	.name = "snoc_int_bimc",
	.id = MSM8939_SNOC_INT_BIMC,
	.buswidth = 8,
	.mas_rpm_id = 101,
	.slv_rpm_id = 132,
	.num_links = ARRAY_SIZE(snoc_int_bimc_links),
	.links = snoc_int_bimc_links,
};

static const u16 snoc_pcnoc_mas_links[] = {
	MSM8939_SNOC_PNOC_SLV
};

static struct qcom_icc_node snoc_pcnoc_mas = {
	.name = "snoc_pcnoc_mas",
	.id = MSM8939_SNOC_PNOC_MAS,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(snoc_pcnoc_mas_links),
	.links = snoc_pcnoc_mas_links,
};

static const u16 snoc_pcnoc_slv_links[] = {
	MSM8939_PNOC_INT_0
};

static struct qcom_icc_node snoc_pcnoc_slv = {
	.name = "snoc_pcnoc_slv",
	.id = MSM8939_SNOC_PNOC_SLV,
	.buswidth = 8,
	.mas_rpm_id = -1,
	.slv_rpm_id = -1,
	.num_links = ARRAY_SIZE(snoc_pcnoc_slv_links),
	.links = snoc_pcnoc_slv_links,
};

static struct qcom_icc_node *msm8939_snoc_nodes[] = {
	[BIMC_SNOC_SLV] = &bimc_snoc_slv,
	[MASTER_QDSS_BAM] = &mas_qdss_bam,
	[MASTER_QDSS_ETR] = &mas_qdss_etr,
	[MASTER_SNOC_CFG] = &mas_snoc_cfg,
	[PCNOC_SNOC_SLV] = &pcnoc_snoc_slv,
	[SLAVE_APSS] = &slv_apss,
	[SLAVE_CATS_128] = &slv_cats_0,
	[SLAVE_OCMEM_64] = &slv_cats_1,
	[SLAVE_IMEM] = &slv_imem,
	[SLAVE_QDSS_STM] = &slv_qdss_stm,
	[SLAVE_SRVC_SNOC] = &slv_srvc_snoc,
	[SNOC_BIMC_0_MAS] = &snoc_bimc_0_mas,
	[SNOC_BIMC_1_MAS] = &snoc_bimc_1_mas,
	[SNOC_BIMC_2_MAS] = &snoc_bimc_2_mas,
	[SNOC_INT_0] = &snoc_int_0,
	[SNOC_INT_1] = &snoc_int_1,
	[SNOC_INT_BIMC] = &snoc_int_bimc,
	[SNOC_PCNOC_MAS] = &snoc_pcnoc_mas,
	[SNOC_QDSS_INT] = &qdss_int,
};

static const struct regmap_config msm8939_snoc_regmap_config = {
	.reg_bits	= 32,
	.reg_stride	= 4,
	.val_bits	= 32,
	.max_register	= 0x14080,
	.fast_io	= true,
};

static struct qcom_icc_desc msm8939_snoc = {
	.nodes = msm8939_snoc_nodes,
	.num_nodes = ARRAY_SIZE(msm8939_snoc_nodes),
	.regmap_cfg = &msm8939_snoc_regmap_config,
	.qos_offset = 0x7000,
};

static struct qcom_icc_node *msm8939_snoc_mm_nodes[] = {
	[MASTER_VIDEO_P0] = &mas_video,
	[MASTER_JPEG] = &mas_jpeg,
	[MASTER_VFE] = &mas_vfe,
	[MASTER_MDP_PORT0] = &mas_mdp0,
	[MASTER_MDP_PORT1] = &mas_mdp1,
	[MASTER_CPP] = &mas_cpp,
	[SNOC_MM_INT_0] = &mm_int_0,
	[SNOC_MM_INT_1] = &mm_int_1,
	[SNOC_MM_INT_2] = &mm_int_2,
};

static const struct regmap_config msm8939_snoc_mm_regmap_config = {
	.reg_bits	= 32,
	.reg_stride	= 4,
	.val_bits	= 32,
	.max_register	= 0x14080,
	.fast_io	= true,
};

static struct qcom_icc_desc msm8939_snoc_mm = {
	.nodes = msm8939_snoc_mm_nodes,
	.num_nodes = ARRAY_SIZE(msm8939_snoc_mm_nodes),
	.regmap_cfg = &msm8939_snoc_mm_regmap_config,
	.qos_offset = 0x7000,
};

static struct qcom_icc_node *msm8939_bimc_nodes[] = {
	[BIMC_SNOC_MAS] = &bimc_snoc_mas,
	[MASTER_AMPSS_M0] = &mas_apss,
	[MASTER_GRAPHICS_3D] = &mas_gfx,
	[MASTER_TCU0] = &mas_tcu0,
	[SLAVE_AMPSS_L2] = &slv_apps_l2,
	[SLAVE_EBI_CH0] = &slv_ebi_ch0,
	[SNOC_BIMC_0_SLV] = &snoc_bimc_0_slv,
	[SNOC_BIMC_1_SLV] = &snoc_bimc_1_slv,
	[SNOC_BIMC_2_SLV] = &snoc_bimc_2_slv,
};

static const struct regmap_config msm8939_bimc_regmap_config = {
	.reg_bits	= 32,
	.reg_stride	= 4,
	.val_bits	= 32,
	.max_register	= 0x62000,
	.fast_io	= true,
};

static struct qcom_icc_desc msm8939_bimc = {
	.nodes = msm8939_bimc_nodes,
	.num_nodes = ARRAY_SIZE(msm8939_bimc_nodes),
	.is_bimc_node = true,
	.regmap_cfg = &msm8939_bimc_regmap_config,
	.qos_offset = 0x8000,
};

static struct qcom_icc_node *msm8939_pcnoc_nodes[] = {
	[MASTER_BLSP_1] = &mas_blsp_1,
	[MASTER_DEHR] = &mas_dehr,
	[MASTER_LPASS] = &mas_audio,
	[MASTER_CRYPTO_CORE0] = &mas_pcnoc_crypto_0,
	[MASTER_SDCC_1] = &mas_pcnoc_sdcc_1,
	[MASTER_SDCC_2] = &mas_pcnoc_sdcc_2,
	[MASTER_SPDM] = &mas_spdm,
	[MASTER_USB_HS1] = &mas_usb_hs1,
	[MASTER_USB_HS2] = &mas_usb_hs2,
	[PCNOC_INT_0] = &pcnoc_int_0,
	[PCNOC_INT_1] = &pcnoc_int_1,
	[PCNOC_MAS_0] = &pcnoc_m_0,
	[PCNOC_MAS_1] = &pcnoc_m_1,
	[PCNOC_SLV_0] = &pcnoc_s_0,
	[PCNOC_SLV_1] = &pcnoc_s_1,
	[PCNOC_SLV_2] = &pcnoc_s_2,
	[PCNOC_SLV_3] = &pcnoc_s_3,
	[PCNOC_SLV_4] = &pcnoc_s_4,
	[PCNOC_SLV_8] = &pcnoc_s_8,
	[PCNOC_SLV_9] = &pcnoc_s_9,
	[PCNOC_SNOC_MAS] = &pcnoc_snoc_mas,
	[SLAVE_BIMC_CFG] = &slv_bimc_cfg,
	[SLAVE_BLSP_1] = &slv_blsp_1,
	[SLAVE_BOOT_ROM] = &slv_boot_rom,
	[SLAVE_CAMERA_CFG] = &slv_camera_cfg,
	[SLAVE_CLK_CTL] = &slv_clk_ctl,
	[SLAVE_CRYPTO_0_CFG] = &slv_crypto_0_cfg,
	[SLAVE_DEHR_CFG] = &slv_dehr_cfg,
	[SLAVE_DISPLAY_CFG] = &slv_display_cfg,
	[SLAVE_GRAPHICS_3D_CFG] = &slv_gfx_cfg,
	[SLAVE_IMEM_CFG] = &slv_imem_cfg,
	[SLAVE_LPASS] = &slv_audio,
	[SLAVE_MPM] = &slv_mpm,
	[SLAVE_MSG_RAM] = &slv_msg_ram,
	[SLAVE_MSS] = &slv_mss,
	[SLAVE_PDM] = &slv_pdm,
	[SLAVE_PMIC_ARB] = &slv_pmic_arb,
	[SLAVE_PCNOC_CFG] = &slv_pcnoc_cfg,
	[SLAVE_PRNG] = &slv_prng,
	[SLAVE_QDSS_CFG] = &slv_qdss_cfg,
	[SLAVE_RBCPR_CFG] = &slv_rbcpr_cfg,
	[SLAVE_SDCC_1] = &slv_sdcc_1,
	[SLAVE_SDCC_2] = &slv_sdcc_2,
	[SLAVE_SECURITY] = &slv_security,
	[SLAVE_SNOC_CFG] = &slv_snoc_cfg,
	[SLAVE_SPDM] = &slv_spdm,
	[SLAVE_TCSR] = &slv_tcsr,
	[SLAVE_TLMM] = &slv_tlmm,
	[SLAVE_USB_HS1] = &slv_usb_hs1,
	[SLAVE_USB_HS2] = &slv_usb_hs2,
	[SLAVE_VENUS_CFG] = &slv_venus_cfg,
	[SNOC_PCNOC_SLV] = &snoc_pcnoc_slv,
};

static const struct regmap_config msm8939_pcnoc_regmap_config = {
	.reg_bits	= 32,
	.reg_stride	= 4,
	.val_bits	= 32,
	.max_register	= 0x11000,
	.fast_io	= true,
};

static struct qcom_icc_desc msm8939_pcnoc = {
	.nodes = msm8939_pcnoc_nodes,
	.num_nodes = ARRAY_SIZE(msm8939_pcnoc_nodes),
	.regmap_cfg = &msm8939_pcnoc_regmap_config,
	.qos_offset = 0x7000,
};

static const struct of_device_id msm8939_noc_of_match[] = {
	{ .compatible = "qcom,msm8939-bimc", .data = &msm8939_bimc },
	{ .compatible = "qcom,msm8939-pcnoc", .data = &msm8939_pcnoc },
	{ .compatible = "qcom,msm8939-snoc", .data = &msm8939_snoc },
	{ .compatible = "qcom,msm8939-snoc-mm", .data = &msm8939_snoc_mm },
	{ }
};
MODULE_DEVICE_TABLE(of, msm8939_noc_of_match);

static struct platform_driver msm8939_noc_driver = {
	.probe = qnoc_probe,
	.remove = qnoc_remove,
	.driver = {
		.name = "qnoc-msm8939",
		.of_match_table = msm8939_noc_of_match,
	},
};
module_platform_driver(msm8939_noc_driver);
MODULE_AUTHOR("Jun Nie <jun.nie@linaro.org>");
MODULE_DESCRIPTION("Qualcomm MSM8939 NoC driver");
MODULE_LICENSE("GPL v2");
