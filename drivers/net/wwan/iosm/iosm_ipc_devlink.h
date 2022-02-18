/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2020-2021 Intel Corporation.
 */

#ifndef _IOSM_IPC_DEVLINK_H_
#define _IOSM_IPC_DEVLINK_H_

#include <net/devlink.h>

#include "iosm_ipc_imem.h"
#include "iosm_ipc_imem_ops.h"
#include "iosm_ipc_pcie.h"

/* Image ext max len */
#define IOSM_DEVLINK_MAX_IMG_LEN 3
/* Magic Header */
#define IOSM_DEVLINK_MAGIC_HEADER "IOSM_DEVLINK_HEADER"
/* Magic Header len */
#define IOSM_DEVLINK_MAGIC_HEADER_LEN 20
/* Devlink image type */
#define IOSM_DEVLINK_IMG_TYPE 4
/* Reserve header size */
#define IOSM_DEVLINK_RESERVED 34
/* Devlink Image Header size */
#define IOSM_DEVLINK_HDR_SIZE sizeof(struct iosm_devlink_image)
/* MAX file name length */
#define IOSM_MAX_FILENAME_LEN 32
/* EBL response size */
#define IOSM_EBL_RSP_SIZE 76
/* MAX number of regions supported */
#define IOSM_NOF_CD_REGION 6
/* MAX number of SNAPSHOTS supported */
#define MAX_SNAPSHOTS 1
/* Default Coredump file size */
#define REPORT_JSON_SIZE 0x800
#define COREDUMP_FCD_SIZE 0x10E00000
#define CDD_LOG_SIZE 0x30000
#define EEPROM_BIN_SIZE 0x10000
#define BOOTCORE_TRC_BIN_SIZE 0x8000
#define BOOTCORE_PREV_TRC_BIN_SIZE 0x20000

/**
 * enum iosm_devlink_param_id - Enum type to different devlink params
 * @IOSM_DEVLINK_PARAM_ID_BASE:			Devlink param base ID
 * @IOSM_DEVLINK_PARAM_ID_ERASE_FULL_FLASH:     Set if full erase required
 */

enum iosm_devlink_param_id {
	IOSM_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	IOSM_DEVLINK_PARAM_ID_ERASE_FULL_FLASH,
};

/**
 * enum iosm_rpsi_cmd_code - Enum type for RPSI command list
 * @rpsi_cmd_code_ebl:		Command to load ebl
 * @rpsi_cmd_coredump_start:    Command to get list of files and
 *				file size info from PSI
 * @rpsi_cmd_coredump_get:      Command to get the coredump data
 * @rpsi_cmd_coredump_end:      Command to stop receiving the coredump
 */
enum iosm_rpsi_cmd_code {
	rpsi_cmd_code_ebl = 0x02,
	rpsi_cmd_coredump_start = 0x10,
	rpsi_cmd_coredump_get   = 0x11,
	rpsi_cmd_coredump_end   = 0x12,
};

/**
 * enum iosm_flash_comp_type - Enum for different flash component types
 * @FLASH_COMP_TYPE_PSI:	PSI flash comp type
 * @FLASH_COMP_TYPE_EBL:	EBL flash comp type
 * @FLASH_COMP_TYPE_FLS:	FLS flash comp type
 * @FLASH_COMP_TYPE_INVAL:	Invalid flash comp type
 */
enum iosm_flash_comp_type {
	FLASH_COMP_TYPE_PSI,
	FLASH_COMP_TYPE_EBL,
	FLASH_COMP_TYPE_FLS,
	FLASH_COMP_TYPE_INVAL,
};

/**
 * struct iosm_devlink_sio - SIO instance
 * @rx_list:	Downlink skbuf list received from CP
 * @read_sem:	Needed for the blocking read or downlink transfer
 * @channel_id: Reserved channel id for flashing/CD collection to RAM
 * @channel:	Channel instance for flashing and coredump
 * @devlink_read_pend: Check if read is pending
 */
struct iosm_devlink_sio {
	struct sk_buff_head rx_list;
	struct completion read_sem;
	int channel_id;
	struct ipc_mem_channel *channel;
	u32 devlink_read_pend;
};

/**
 * struct iosm_flash_params - List of flash params required for flashing
 * @erase_full_flash:   To set the flashing mode
 *                      erase_full_flash = 1; full erase
 *                      erase_full_flash = 0; no erase
 * @erase_full_flash_done: Flag to check if it is a full erase
 */
struct iosm_flash_params {
	u8 erase_full_flash;
	u8 erase_full_flash_done;
};

/**
 * struct iosm_devlink_image - Structure with Fls file header info
 * @magic_header:	Header of the firmware image
 * @image_type:		Firmware image type
 * @region_address:	Address of the region to be flashed
 * @download_region:	Field to identify if it is a region
 * @last_region:	Field to identify if it is last region
 * @reserved:		Reserved field
 */
struct iosm_devlink_image {
	char magic_header[IOSM_DEVLINK_MAGIC_HEADER_LEN];
	char image_type[IOSM_DEVLINK_IMG_TYPE];
	__le32 region_address;
	u8 download_region;
	u8 last_region;
	u8 reserved[IOSM_DEVLINK_RESERVED];
} __packed;

/**
 * struct iosm_ebl_ctx_data -  EBL ctx data used during flashing
 * @ebl_sw_info_version: SWID version info obtained from EBL
 * @m_ebl_resp:         Buffer used to read and write the ebl data
 */
struct iosm_ebl_ctx_data {
	u8 ebl_sw_info_version;
	u8 m_ebl_resp[IOSM_EBL_RSP_SIZE];
};

/**
 * struct iosm_coredump_file_info -  Coredump file info
 * @filename:		Name of coredump file
 * @default_size:	Default size of coredump file
 * @actual_size:	Actual size of coredump file
 * @entry:		Index of the coredump file
 */
struct iosm_coredump_file_info {
	char filename[IOSM_MAX_FILENAME_LEN];
	u32 default_size;
	u32 actual_size;
	u32 entry;
};

/**
 * struct iosm_devlink - IOSM Devlink structure
 * @devlink_sio:        SIO instance for read/write functionality
 * @pcie:               Pointer to PCIe component
 * @dev:                Pointer to device struct
 * @devlink_ctx:	Pointer to devlink context
 * @param:		Params required for flashing
 * @ebl_ctx:		Data to be read and written to Modem
 * @cd_file_info:	coredump file info
 * @iosm_devlink_mdm_coredump:	region ops for coredump collection
 * @cd_regions:		coredump regions
 */
struct iosm_devlink {
	struct iosm_devlink_sio devlink_sio;
	struct iosm_pcie *pcie;
	struct device *dev;
	struct devlink *devlink_ctx;
	struct iosm_flash_params param;
	struct iosm_ebl_ctx_data ebl_ctx;
	struct iosm_coredump_file_info *cd_file_info;
	struct devlink_region_ops iosm_devlink_mdm_coredump[IOSM_NOF_CD_REGION];
	struct devlink_region *cd_regions[IOSM_NOF_CD_REGION];
};

/**
 * union iosm_rpsi_param_u - RPSI cmd param for CRC calculation
 * @word:	Words member used in CRC calculation
 * @dword:	Actual data
 */
union iosm_rpsi_param_u {
	__le16 word[2];
	__le32 dword;
};

/**
 * struct iosm_rpsi_cmd - Structure for RPSI Command
 * @param:      Used to calculate CRC
 * @cmd:        Stores the RPSI command
 * @crc:        Stores the CRC value
 */
struct iosm_rpsi_cmd {
	union iosm_rpsi_param_u param;
	__le16	cmd;
	__le16	crc;
};

struct iosm_devlink *ipc_devlink_init(struct iosm_imem *ipc_imem);

void ipc_devlink_deinit(struct iosm_devlink *ipc_devlink);

int ipc_devlink_send_cmd(struct iosm_devlink *ipc_devlink, u16 cmd, u32 entry);

#endif /* _IOSM_IPC_DEVLINK_H */
