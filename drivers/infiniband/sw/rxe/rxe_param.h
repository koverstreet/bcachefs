/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef RXE_PARAM_H
#define RXE_PARAM_H

#include <uapi/rdma/rdma_user_rxe.h>

#define DEFAULT_MAX_VALUE (1 << 20)

static inline enum ib_mtu rxe_mtu_int_to_enum(int mtu)
{
	if (mtu < 256)
		return 0;
	else if (mtu < 512)
		return IB_MTU_256;
	else if (mtu < 1024)
		return IB_MTU_512;
	else if (mtu < 2048)
		return IB_MTU_1024;
	else if (mtu < 4096)
		return IB_MTU_2048;
	else
		return IB_MTU_4096;
}

/* Find the IB mtu for a given network MTU. */
static inline enum ib_mtu eth_mtu_int_to_enum(int mtu)
{
	mtu -= RXE_MAX_HDR_LENGTH;

	return rxe_mtu_int_to_enum(mtu);
}

/* default/initial rxe device parameter settings */
enum rxe_device_param {
	RXE_MAX_MR_SIZE			= -1ull,
	RXE_PAGE_SIZE_CAP		= 0xfffff000,
	RXE_MAX_QP_WR			= DEFAULT_MAX_VALUE,
	RXE_DEVICE_CAP_FLAGS		= IB_DEVICE_BAD_PKEY_CNTR
					| IB_DEVICE_BAD_QKEY_CNTR
					| IB_DEVICE_AUTO_PATH_MIG
					| IB_DEVICE_CHANGE_PHY_PORT
					| IB_DEVICE_UD_AV_PORT_ENFORCE
					| IB_DEVICE_PORT_ACTIVE_EVENT
					| IB_DEVICE_SYS_IMAGE_GUID
					| IB_DEVICE_RC_RNR_NAK_GEN
					| IB_DEVICE_SRQ_RESIZE
					| IB_DEVICE_MEM_MGT_EXTENSIONS
					| IB_DEVICE_ALLOW_USER_UNREG
					| IB_DEVICE_MEM_WINDOW
					| IB_DEVICE_MEM_WINDOW_TYPE_2A
					| IB_DEVICE_MEM_WINDOW_TYPE_2B,
	RXE_MAX_SGE			= 32,
	RXE_MAX_WQE_SIZE		= sizeof(struct rxe_send_wqe) +
					  sizeof(struct ib_sge) * RXE_MAX_SGE,
	RXE_MAX_INLINE_DATA		= RXE_MAX_WQE_SIZE -
					  sizeof(struct rxe_send_wqe),
	RXE_MAX_SGE_RD			= 32,
	RXE_MAX_CQ			= DEFAULT_MAX_VALUE,
	RXE_MAX_LOG_CQE			= 15,
	RXE_MAX_PD			= DEFAULT_MAX_VALUE,
	RXE_MAX_QP_RD_ATOM		= 128,
	RXE_MAX_RES_RD_ATOM		= 0x3f000,
	RXE_MAX_QP_INIT_RD_ATOM		= 128,
	RXE_MAX_MCAST_GRP		= 8192,
	RXE_MAX_MCAST_QP_ATTACH		= 56,
	RXE_MAX_TOT_MCAST_QP_ATTACH	= 0x70000,
	RXE_MAX_AH			= (1<<15) - 1,	/* 32Ki - 1 */
	RXE_MIN_AH_INDEX		= 1,
	RXE_MAX_AH_INDEX		= RXE_MAX_AH,
	RXE_MAX_SRQ_WR			= DEFAULT_MAX_VALUE,
	RXE_MIN_SRQ_WR			= 1,
	RXE_MAX_SRQ_SGE			= 27,
	RXE_MIN_SRQ_SGE			= 1,
	RXE_MAX_FMR_PAGE_LIST_LEN	= 512,
	RXE_MAX_PKEYS			= 64,
	RXE_LOCAL_CA_ACK_DELAY		= 15,

	RXE_MAX_UCONTEXT		= DEFAULT_MAX_VALUE,

	RXE_NUM_PORT			= 1,

	RXE_MIN_QP_INDEX		= 16,
	RXE_MAX_QP_INDEX		= DEFAULT_MAX_VALUE,
	RXE_MAX_QP			= DEFAULT_MAX_VALUE - RXE_MIN_QP_INDEX,

	RXE_MIN_SRQ_INDEX		= 0x00020001,
	RXE_MAX_SRQ_INDEX		= DEFAULT_MAX_VALUE,
	RXE_MAX_SRQ			= DEFAULT_MAX_VALUE - RXE_MIN_SRQ_INDEX,

	RXE_MIN_MR_INDEX		= 0x00000001,
	RXE_MAX_MR_INDEX		= DEFAULT_MAX_VALUE,
	RXE_MAX_MR			= DEFAULT_MAX_VALUE - RXE_MIN_MR_INDEX,
	RXE_MIN_MW_INDEX		= 0x00010001,
	RXE_MAX_MW_INDEX		= 0x00020000,
	RXE_MAX_MW			= 0x00001000,

	RXE_MAX_PKT_PER_ACK		= 64,

	RXE_MAX_UNACKED_PSNS		= 128,

	/* Max inflight SKBs per queue pair */
	RXE_INFLIGHT_SKBS_PER_QP_HIGH	= 64,
	RXE_INFLIGHT_SKBS_PER_QP_LOW	= 16,

	/* Delay before calling arbiter timer */
	RXE_NSEC_ARB_TIMER_DELAY	= 200,

	/* IBTA v1.4 A3.3.1 VENDOR INFORMATION section */
	RXE_VENDOR_ID			= 0XFFFFFF,
};

/* default/initial rxe port parameters */
enum rxe_port_param {
	RXE_PORT_GID_TBL_LEN		= 1024,
	RXE_PORT_PORT_CAP_FLAGS		= IB_PORT_CM_SUP,
	RXE_PORT_MAX_MSG_SZ		= 0x800000,
	RXE_PORT_BAD_PKEY_CNTR		= 0,
	RXE_PORT_QKEY_VIOL_CNTR		= 0,
	RXE_PORT_LID			= 0,
	RXE_PORT_SM_LID			= 0,
	RXE_PORT_SM_SL			= 0,
	RXE_PORT_LMC			= 0,
	RXE_PORT_MAX_VL_NUM		= 1,
	RXE_PORT_SUBNET_TIMEOUT		= 0,
	RXE_PORT_INIT_TYPE_REPLY	= 0,
	RXE_PORT_ACTIVE_WIDTH		= IB_WIDTH_1X,
	RXE_PORT_ACTIVE_SPEED		= 1,
	RXE_PORT_PKEY_TBL_LEN		= 1,
	RXE_PORT_PHYS_STATE		= IB_PORT_PHYS_STATE_POLLING,
	RXE_PORT_SUBNET_PREFIX		= 0xfe80000000000000ULL,
};

/* default/initial port info parameters */
enum rxe_port_info_param {
	RXE_PORT_INFO_VL_CAP		= 4,	/* 1-8 */
	RXE_PORT_INFO_MTU_CAP		= 5,	/* 4096 */
	RXE_PORT_INFO_OPER_VL		= 1,	/* 1 */
};

#endif /* RXE_PARAM_H */
