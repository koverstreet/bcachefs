/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * This file is provided under a dual BSD/GPLv2 license. When using or
 * redistributing this file, you may do so under either license.
 *
 * Copyright(c) 2021 Advanced Micro Devices, Inc. All rights reserved.
 *
 * Author: Ajit Kumar Pandey <AjitKumar.Pandey@amd.com>
 */

#ifndef _ACP_IP_OFFSET_HEADER
#define _ACP_IP_OFFSET_HEADER

#define ACPAXI2AXI_ATU_CTRL                           0xC40
#define ACPAXI2AXI_ATU_PAGE_SIZE_GRP_5                0xC20
#define ACPAXI2AXI_ATU_BASE_ADDR_GRP_5                0xC24
#define ACP_EXTERNAL_INTR_ENB                         0x1800
#define ACP_EXTERNAL_INTR_CNTL                        0x1804
#define ACP_EXTERNAL_INTR_STAT                        0x1808
#define ACP_I2S_PIN_CONFIG                            0x1400
#define ACP_SCRATCH_REG_0                             0x12800

/* Registers from ACP_AUDIO_BUFFERS block */

#define ACP_I2S_RX_RINGBUFADDR                        0x2000
#define ACP_I2S_RX_RINGBUFSIZE                        0x2004
#define ACP_I2S_RX_LINKPOSITIONCNTR                   0x2008
#define ACP_I2S_RX_FIFOADDR                           0x200C
#define ACP_I2S_RX_FIFOSIZE                           0x2010
#define ACP_I2S_RX_DMA_SIZE                           0x2014
#define ACP_I2S_RX_LINEARPOSITIONCNTR_HIGH            0x2018
#define ACP_I2S_RX_LINEARPOSITIONCNTR_LOW             0x201C
#define ACP_I2S_RX_INTR_WATERMARK_SIZE                0x2020
#define ACP_I2S_TX_RINGBUFADDR                        0x2024
#define ACP_I2S_TX_RINGBUFSIZE                        0x2028
#define ACP_I2S_TX_LINKPOSITIONCNTR                   0x202C
#define ACP_I2S_TX_FIFOADDR                           0x2030
#define ACP_I2S_TX_FIFOSIZE                           0x2034
#define ACP_I2S_TX_DMA_SIZE                           0x2038
#define ACP_I2S_TX_LINEARPOSITIONCNTR_HIGH            0x203C
#define ACP_I2S_TX_LINEARPOSITIONCNTR_LOW             0x2040
#define ACP_I2S_TX_INTR_WATERMARK_SIZE                0x2044
#define ACP_BT_RX_RINGBUFADDR                         0x2048
#define ACP_BT_RX_RINGBUFSIZE                         0x204C
#define ACP_BT_RX_LINKPOSITIONCNTR                    0x2050
#define ACP_BT_RX_FIFOADDR                            0x2054
#define ACP_BT_RX_FIFOSIZE                            0x2058
#define ACP_BT_RX_DMA_SIZE                            0x205C
#define ACP_BT_RX_LINEARPOSITIONCNTR_HIGH             0x2060
#define ACP_BT_RX_LINEARPOSITIONCNTR_LOW              0x2064
#define ACP_BT_RX_INTR_WATERMARK_SIZE                 0x2068
#define ACP_BT_TX_RINGBUFADDR                         0x206C
#define ACP_BT_TX_RINGBUFSIZE                         0x2070
#define ACP_BT_TX_LINKPOSITIONCNTR                    0x2074
#define ACP_BT_TX_FIFOADDR                            0x2078
#define ACP_BT_TX_FIFOSIZE                            0x207C
#define ACP_BT_TX_DMA_SIZE                            0x2080
#define ACP_BT_TX_LINEARPOSITIONCNTR_HIGH             0x2084
#define ACP_BT_TX_LINEARPOSITIONCNTR_LOW              0x2088
#define ACP_BT_TX_INTR_WATERMARK_SIZE                 0x208C

#define ACP_I2STDM_IER                                0x2400
#define ACP_I2STDM_IRER                               0x2404
#define ACP_I2STDM_RXFRMT                             0x2408
#define ACP_I2STDM_ITER                               0x240C
#define ACP_I2STDM_TXFRMT                             0x2410

/* Registers from ACP_BT_TDM block */

#define ACP_BTTDM_IER                                 0x2800
#define ACP_BTTDM_IRER                                0x2804
#define ACP_BTTDM_RXFRMT                              0x2808
#define ACP_BTTDM_ITER                                0x280C
#define ACP_BTTDM_TXFRMT                              0x2810

#endif
