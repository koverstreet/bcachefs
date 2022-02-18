// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2018-2019 Hisilicon Limited. */

#include <linux/device.h>

#include "hclge_debugfs.h"
#include "hclge_err.h"
#include "hclge_main.h"
#include "hclge_tm.h"
#include "hnae3.h"

static const char * const state_str[] = { "off", "on" };
static const char * const hclge_mac_state_str[] = {
	"TO_ADD", "TO_DEL", "ACTIVE"
};

static const struct hclge_dbg_reg_type_info hclge_dbg_reg_info[] = {
	{ .cmd = HNAE3_DBG_CMD_REG_BIOS_COMMON,
	  .dfx_msg = &hclge_dbg_bios_common_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_bios_common_reg),
		       .offset = HCLGE_DBG_DFX_BIOS_OFFSET,
		       .cmd = HCLGE_OPC_DFX_BIOS_COMMON_REG } },
	{ .cmd = HNAE3_DBG_CMD_REG_SSU,
	  .dfx_msg = &hclge_dbg_ssu_reg_0[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_ssu_reg_0),
		       .offset = HCLGE_DBG_DFX_SSU_0_OFFSET,
		       .cmd = HCLGE_OPC_DFX_SSU_REG_0 } },
	{ .cmd = HNAE3_DBG_CMD_REG_SSU,
	  .dfx_msg = &hclge_dbg_ssu_reg_1[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_ssu_reg_1),
		       .offset = HCLGE_DBG_DFX_SSU_1_OFFSET,
		       .cmd = HCLGE_OPC_DFX_SSU_REG_1 } },
	{ .cmd = HNAE3_DBG_CMD_REG_SSU,
	  .dfx_msg = &hclge_dbg_ssu_reg_2[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_ssu_reg_2),
		       .offset = HCLGE_DBG_DFX_SSU_2_OFFSET,
		       .cmd = HCLGE_OPC_DFX_SSU_REG_2 } },
	{ .cmd = HNAE3_DBG_CMD_REG_IGU_EGU,
	  .dfx_msg = &hclge_dbg_igu_egu_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_igu_egu_reg),
		       .offset = HCLGE_DBG_DFX_IGU_OFFSET,
		       .cmd = HCLGE_OPC_DFX_IGU_EGU_REG } },
	{ .cmd = HNAE3_DBG_CMD_REG_RPU,
	  .dfx_msg = &hclge_dbg_rpu_reg_0[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_rpu_reg_0),
		       .offset = HCLGE_DBG_DFX_RPU_0_OFFSET,
		       .cmd = HCLGE_OPC_DFX_RPU_REG_0 } },
	{ .cmd = HNAE3_DBG_CMD_REG_RPU,
	  .dfx_msg = &hclge_dbg_rpu_reg_1[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_rpu_reg_1),
		       .offset = HCLGE_DBG_DFX_RPU_1_OFFSET,
		       .cmd = HCLGE_OPC_DFX_RPU_REG_1 } },
	{ .cmd = HNAE3_DBG_CMD_REG_NCSI,
	  .dfx_msg = &hclge_dbg_ncsi_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_ncsi_reg),
		       .offset = HCLGE_DBG_DFX_NCSI_OFFSET,
		       .cmd = HCLGE_OPC_DFX_NCSI_REG } },
	{ .cmd = HNAE3_DBG_CMD_REG_RTC,
	  .dfx_msg = &hclge_dbg_rtc_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_rtc_reg),
		       .offset = HCLGE_DBG_DFX_RTC_OFFSET,
		       .cmd = HCLGE_OPC_DFX_RTC_REG } },
	{ .cmd = HNAE3_DBG_CMD_REG_PPP,
	  .dfx_msg = &hclge_dbg_ppp_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_ppp_reg),
		       .offset = HCLGE_DBG_DFX_PPP_OFFSET,
		       .cmd = HCLGE_OPC_DFX_PPP_REG } },
	{ .cmd = HNAE3_DBG_CMD_REG_RCB,
	  .dfx_msg = &hclge_dbg_rcb_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_rcb_reg),
		       .offset = HCLGE_DBG_DFX_RCB_OFFSET,
		       .cmd = HCLGE_OPC_DFX_RCB_REG } },
	{ .cmd = HNAE3_DBG_CMD_REG_TQP,
	  .dfx_msg = &hclge_dbg_tqp_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_tqp_reg),
		       .offset = HCLGE_DBG_DFX_TQP_OFFSET,
		       .cmd = HCLGE_OPC_DFX_TQP_REG } },
};

static void hclge_dbg_fill_content(char *content, u16 len,
				   const struct hclge_dbg_item *items,
				   const char **result, u16 size)
{
	char *pos = content;
	u16 i;

	memset(content, ' ', len);
	for (i = 0; i < size; i++) {
		if (result)
			strncpy(pos, result[i], strlen(result[i]));
		else
			strncpy(pos, items[i].name, strlen(items[i].name));
		pos += strlen(items[i].name) + items[i].interval;
	}
	*pos++ = '\n';
	*pos++ = '\0';
}

static char *hclge_dbg_get_func_id_str(char *buf, u8 id)
{
	if (id)
		sprintf(buf, "vf%u", id - 1);
	else
		sprintf(buf, "pf");

	return buf;
}

static int hclge_dbg_get_dfx_bd_num(struct hclge_dev *hdev, int offset,
				    u32 *bd_num)
{
	struct hclge_desc desc[HCLGE_GET_DFX_REG_TYPE_CNT];
	int entries_per_desc;
	int index;
	int ret;

	ret = hclge_query_bd_num_cmd_send(hdev, desc);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to get dfx bd_num, offset = %d, ret = %d\n",
			offset, ret);
		return ret;
	}

	entries_per_desc = ARRAY_SIZE(desc[0].data);
	index = offset % entries_per_desc;

	*bd_num = le32_to_cpu(desc[offset / entries_per_desc].data[index]);
	if (!(*bd_num)) {
		dev_err(&hdev->pdev->dev, "The value of dfx bd_num is 0!\n");
		return -EINVAL;
	}

	return 0;
}

static int hclge_dbg_cmd_send(struct hclge_dev *hdev,
			      struct hclge_desc *desc_src,
			      int index, int bd_num,
			      enum hclge_opcode_type cmd)
{
	struct hclge_desc *desc = desc_src;
	int ret, i;

	hclge_cmd_setup_basic_desc(desc, cmd, true);
	desc->data[0] = cpu_to_le32(index);

	for (i = 1; i < bd_num; i++) {
		desc->flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
		desc++;
		hclge_cmd_setup_basic_desc(desc, cmd, true);
	}

	ret = hclge_cmd_send(&hdev->hw, desc_src, bd_num);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"cmd(0x%x) send fail, ret = %d\n", cmd, ret);
	return ret;
}

static int
hclge_dbg_dump_reg_tqp(struct hclge_dev *hdev,
		       const struct hclge_dbg_reg_type_info *reg_info,
		       char *buf, int len, int *pos)
{
	const struct hclge_dbg_dfx_message *dfx_message = reg_info->dfx_msg;
	const struct hclge_dbg_reg_common_msg *reg_msg = &reg_info->reg_msg;
	struct hclge_desc *desc_src;
	u32 index, entry, i, cnt;
	int bd_num, min_num, ret;
	struct hclge_desc *desc;

	ret = hclge_dbg_get_dfx_bd_num(hdev, reg_msg->offset, &bd_num);
	if (ret)
		return ret;

	desc_src = kcalloc(bd_num, sizeof(struct hclge_desc), GFP_KERNEL);
	if (!desc_src)
		return -ENOMEM;

	min_num = min_t(int, bd_num * HCLGE_DESC_DATA_LEN, reg_msg->msg_num);

	for (i = 0, cnt = 0; i < min_num; i++, dfx_message++)
		*pos += scnprintf(buf + *pos, len - *pos, "item%u = %s\n",
				  cnt++, dfx_message->message);

	for (i = 0; i < cnt; i++)
		*pos += scnprintf(buf + *pos, len - *pos, "item%u\t", i);

	*pos += scnprintf(buf + *pos, len - *pos, "\n");

	for (index = 0; index < hdev->vport[0].alloc_tqps; index++) {
		dfx_message = reg_info->dfx_msg;
		desc = desc_src;
		ret = hclge_dbg_cmd_send(hdev, desc, index, bd_num,
					 reg_msg->cmd);
		if (ret)
			break;

		for (i = 0; i < min_num; i++, dfx_message++) {
			entry = i % HCLGE_DESC_DATA_LEN;
			if (i > 0 && !entry)
				desc++;

			*pos += scnprintf(buf + *pos, len - *pos, "%#x\t",
					  le32_to_cpu(desc->data[entry]));
		}
		*pos += scnprintf(buf + *pos, len - *pos, "\n");
	}

	kfree(desc_src);
	return ret;
}

static int
hclge_dbg_dump_reg_common(struct hclge_dev *hdev,
			  const struct hclge_dbg_reg_type_info *reg_info,
			  char *buf, int len, int *pos)
{
	const struct hclge_dbg_reg_common_msg *reg_msg = &reg_info->reg_msg;
	const struct hclge_dbg_dfx_message *dfx_message = reg_info->dfx_msg;
	struct hclge_desc *desc_src;
	int bd_num, min_num, ret;
	struct hclge_desc *desc;
	u32 entry, i;

	ret = hclge_dbg_get_dfx_bd_num(hdev, reg_msg->offset, &bd_num);
	if (ret)
		return ret;

	desc_src = kcalloc(bd_num, sizeof(struct hclge_desc), GFP_KERNEL);
	if (!desc_src)
		return -ENOMEM;

	desc = desc_src;

	ret = hclge_dbg_cmd_send(hdev, desc, 0, bd_num, reg_msg->cmd);
	if (ret) {
		kfree(desc);
		return ret;
	}

	min_num = min_t(int, bd_num * HCLGE_DESC_DATA_LEN, reg_msg->msg_num);

	for (i = 0; i < min_num; i++, dfx_message++) {
		entry = i % HCLGE_DESC_DATA_LEN;
		if (i > 0 && !entry)
			desc++;
		if (!dfx_message->flag)
			continue;

		*pos += scnprintf(buf + *pos, len - *pos, "%s: %#x\n",
				  dfx_message->message,
				  le32_to_cpu(desc->data[entry]));
	}

	kfree(desc_src);
	return 0;
}

static int  hclge_dbg_dump_mac_enable_status(struct hclge_dev *hdev, char *buf,
					     int len, int *pos)
{
	struct hclge_config_mac_mode_cmd *req;
	struct hclge_desc desc;
	u32 loop_en;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CONFIG_MAC_MODE, true);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump mac enable status, ret = %d\n", ret);
		return ret;
	}

	req = (struct hclge_config_mac_mode_cmd *)desc.data;
	loop_en = le32_to_cpu(req->txrx_pad_fcs_loop_en);

	*pos += scnprintf(buf + *pos, len - *pos, "mac_trans_en: %#x\n",
			  hnae3_get_bit(loop_en, HCLGE_MAC_TX_EN_B));
	*pos += scnprintf(buf + *pos, len - *pos, "mac_rcv_en: %#x\n",
			  hnae3_get_bit(loop_en, HCLGE_MAC_RX_EN_B));
	*pos += scnprintf(buf + *pos, len - *pos, "pad_trans_en: %#x\n",
			  hnae3_get_bit(loop_en, HCLGE_MAC_PAD_TX_B));
	*pos += scnprintf(buf + *pos, len - *pos, "pad_rcv_en: %#x\n",
			  hnae3_get_bit(loop_en, HCLGE_MAC_PAD_RX_B));
	*pos += scnprintf(buf + *pos, len - *pos, "1588_trans_en: %#x\n",
			  hnae3_get_bit(loop_en, HCLGE_MAC_1588_TX_B));
	*pos += scnprintf(buf + *pos, len - *pos, "1588_rcv_en: %#x\n",
			  hnae3_get_bit(loop_en, HCLGE_MAC_1588_RX_B));
	*pos += scnprintf(buf + *pos, len - *pos, "mac_app_loop_en: %#x\n",
			  hnae3_get_bit(loop_en, HCLGE_MAC_APP_LP_B));
	*pos += scnprintf(buf + *pos, len - *pos, "mac_line_loop_en: %#x\n",
			  hnae3_get_bit(loop_en, HCLGE_MAC_LINE_LP_B));
	*pos += scnprintf(buf + *pos, len - *pos, "mac_fcs_tx_en: %#x\n",
			  hnae3_get_bit(loop_en, HCLGE_MAC_FCS_TX_B));
	*pos += scnprintf(buf + *pos, len - *pos,
			  "mac_rx_oversize_truncate_en: %#x\n",
			  hnae3_get_bit(loop_en,
					HCLGE_MAC_RX_OVERSIZE_TRUNCATE_B));
	*pos += scnprintf(buf + *pos, len - *pos, "mac_rx_fcs_strip_en: %#x\n",
			  hnae3_get_bit(loop_en, HCLGE_MAC_RX_FCS_STRIP_B));
	*pos += scnprintf(buf + *pos, len - *pos, "mac_rx_fcs_en: %#x\n",
			  hnae3_get_bit(loop_en, HCLGE_MAC_RX_FCS_B));
	*pos += scnprintf(buf + *pos, len - *pos,
			  "mac_tx_under_min_err_en: %#x\n",
			  hnae3_get_bit(loop_en, HCLGE_MAC_TX_UNDER_MIN_ERR_B));
	*pos += scnprintf(buf + *pos, len - *pos,
			  "mac_tx_oversize_truncate_en: %#x\n",
			  hnae3_get_bit(loop_en,
					HCLGE_MAC_TX_OVERSIZE_TRUNCATE_B));

	return 0;
}

static int hclge_dbg_dump_mac_frame_size(struct hclge_dev *hdev, char *buf,
					 int len, int *pos)
{
	struct hclge_config_max_frm_size_cmd *req;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CONFIG_MAX_FRM_SIZE, true);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump mac frame size, ret = %d\n", ret);
		return ret;
	}

	req = (struct hclge_config_max_frm_size_cmd *)desc.data;

	*pos += scnprintf(buf + *pos, len - *pos, "max_frame_size: %u\n",
			  le16_to_cpu(req->max_frm_size));
	*pos += scnprintf(buf + *pos, len - *pos, "min_frame_size: %u\n",
			  req->min_frm_size);

	return 0;
}

static int hclge_dbg_dump_mac_speed_duplex(struct hclge_dev *hdev, char *buf,
					   int len, int *pos)
{
#define HCLGE_MAC_SPEED_SHIFT	0
#define HCLGE_MAC_SPEED_MASK	GENMASK(5, 0)
#define HCLGE_MAC_DUPLEX_SHIFT	7

	struct hclge_config_mac_speed_dup_cmd *req;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CONFIG_SPEED_DUP, true);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump mac speed duplex, ret = %d\n", ret);
		return ret;
	}

	req = (struct hclge_config_mac_speed_dup_cmd *)desc.data;

	*pos += scnprintf(buf + *pos, len - *pos, "speed: %#lx\n",
			  hnae3_get_field(req->speed_dup, HCLGE_MAC_SPEED_MASK,
					  HCLGE_MAC_SPEED_SHIFT));
	*pos += scnprintf(buf + *pos, len - *pos, "duplex: %#x\n",
			  hnae3_get_bit(req->speed_dup,
					HCLGE_MAC_DUPLEX_SHIFT));
	return 0;
}

static int hclge_dbg_dump_mac(struct hclge_dev *hdev, char *buf, int len)
{
	int pos = 0;
	int ret;

	ret = hclge_dbg_dump_mac_enable_status(hdev, buf, len, &pos);
	if (ret)
		return ret;

	ret = hclge_dbg_dump_mac_frame_size(hdev, buf, len, &pos);
	if (ret)
		return ret;

	return hclge_dbg_dump_mac_speed_duplex(hdev, buf, len, &pos);
}

static int hclge_dbg_dump_dcb_qset(struct hclge_dev *hdev, char *buf, int len,
				   int *pos)
{
	struct hclge_dbg_bitmap_cmd req;
	struct hclge_desc desc;
	u16 qset_id, qset_num;
	int ret;

	ret = hclge_tm_get_qset_num(hdev, &qset_num);
	if (ret)
		return ret;

	*pos += scnprintf(buf + *pos, len - *pos,
			  "qset_id  roce_qset_mask  nic_qset_mask  qset_shaping_pass  qset_bp_status\n");
	for (qset_id = 0; qset_id < qset_num; qset_id++) {
		ret = hclge_dbg_cmd_send(hdev, &desc, qset_id, 1,
					 HCLGE_OPC_QSET_DFX_STS);
		if (ret)
			return ret;

		req.bitmap = (u8)le32_to_cpu(desc.data[1]);

		*pos += scnprintf(buf + *pos, len - *pos,
				  "%04u           %#x            %#x             %#x               %#x\n",
				  qset_id, req.bit0, req.bit1, req.bit2,
				  req.bit3);
	}

	return 0;
}

static int hclge_dbg_dump_dcb_pri(struct hclge_dev *hdev, char *buf, int len,
				  int *pos)
{
	struct hclge_dbg_bitmap_cmd req;
	struct hclge_desc desc;
	u8 pri_id, pri_num;
	int ret;

	ret = hclge_tm_get_pri_num(hdev, &pri_num);
	if (ret)
		return ret;

	*pos += scnprintf(buf + *pos, len - *pos,
			  "pri_id  pri_mask  pri_cshaping_pass  pri_pshaping_pass\n");
	for (pri_id = 0; pri_id < pri_num; pri_id++) {
		ret = hclge_dbg_cmd_send(hdev, &desc, pri_id, 1,
					 HCLGE_OPC_PRI_DFX_STS);
		if (ret)
			return ret;

		req.bitmap = (u8)le32_to_cpu(desc.data[1]);

		*pos += scnprintf(buf + *pos, len - *pos,
				  "%03u       %#x           %#x                %#x\n",
				  pri_id, req.bit0, req.bit1, req.bit2);
	}

	return 0;
}

static int hclge_dbg_dump_dcb_pg(struct hclge_dev *hdev, char *buf, int len,
				 int *pos)
{
	struct hclge_dbg_bitmap_cmd req;
	struct hclge_desc desc;
	u8 pg_id;
	int ret;

	*pos += scnprintf(buf + *pos, len - *pos,
			  "pg_id  pg_mask  pg_cshaping_pass  pg_pshaping_pass\n");
	for (pg_id = 0; pg_id < hdev->tm_info.num_pg; pg_id++) {
		ret = hclge_dbg_cmd_send(hdev, &desc, pg_id, 1,
					 HCLGE_OPC_PG_DFX_STS);
		if (ret)
			return ret;

		req.bitmap = (u8)le32_to_cpu(desc.data[1]);

		*pos += scnprintf(buf + *pos, len - *pos,
				  "%03u      %#x           %#x               %#x\n",
				  pg_id, req.bit0, req.bit1, req.bit2);
	}

	return 0;
}

static int hclge_dbg_dump_dcb_queue(struct hclge_dev *hdev, char *buf, int len,
				    int *pos)
{
	struct hclge_desc desc;
	u16 nq_id;
	int ret;

	*pos += scnprintf(buf + *pos, len - *pos,
			  "nq_id  sch_nic_queue_cnt  sch_roce_queue_cnt\n");
	for (nq_id = 0; nq_id < hdev->num_tqps; nq_id++) {
		ret = hclge_dbg_cmd_send(hdev, &desc, nq_id, 1,
					 HCLGE_OPC_SCH_NQ_CNT);
		if (ret)
			return ret;

		*pos += scnprintf(buf + *pos, len - *pos, "%04u           %#x",
				  nq_id, le32_to_cpu(desc.data[1]));

		ret = hclge_dbg_cmd_send(hdev, &desc, nq_id, 1,
					 HCLGE_OPC_SCH_RQ_CNT);
		if (ret)
			return ret;

		*pos += scnprintf(buf + *pos, len - *pos,
				  "               %#x\n",
				  le32_to_cpu(desc.data[1]));
	}

	return 0;
}

static int hclge_dbg_dump_dcb_port(struct hclge_dev *hdev, char *buf, int len,
				   int *pos)
{
	struct hclge_dbg_bitmap_cmd req;
	struct hclge_desc desc;
	u8 port_id = 0;
	int ret;

	ret = hclge_dbg_cmd_send(hdev, &desc, port_id, 1,
				 HCLGE_OPC_PORT_DFX_STS);
	if (ret)
		return ret;

	req.bitmap = (u8)le32_to_cpu(desc.data[1]);

	*pos += scnprintf(buf + *pos, len - *pos, "port_mask: %#x\n",
			 req.bit0);
	*pos += scnprintf(buf + *pos, len - *pos, "port_shaping_pass: %#x\n",
			 req.bit1);

	return 0;
}

static int hclge_dbg_dump_dcb_tm(struct hclge_dev *hdev, char *buf, int len,
				 int *pos)
{
	struct hclge_desc desc[2];
	u8 port_id = 0;
	int ret;

	ret = hclge_dbg_cmd_send(hdev, desc, port_id, 1,
				 HCLGE_OPC_TM_INTERNAL_CNT);
	if (ret)
		return ret;

	*pos += scnprintf(buf + *pos, len - *pos, "SCH_NIC_NUM: %#x\n",
			  le32_to_cpu(desc[0].data[1]));
	*pos += scnprintf(buf + *pos, len - *pos, "SCH_ROCE_NUM: %#x\n",
			  le32_to_cpu(desc[0].data[2]));

	ret = hclge_dbg_cmd_send(hdev, desc, port_id, 2,
				 HCLGE_OPC_TM_INTERNAL_STS);
	if (ret)
		return ret;

	*pos += scnprintf(buf + *pos, len - *pos, "pri_bp: %#x\n",
			  le32_to_cpu(desc[0].data[1]));
	*pos += scnprintf(buf + *pos, len - *pos, "fifo_dfx_info: %#x\n",
			  le32_to_cpu(desc[0].data[2]));
	*pos += scnprintf(buf + *pos, len - *pos,
			  "sch_roce_fifo_afull_gap: %#x\n",
			  le32_to_cpu(desc[0].data[3]));
	*pos += scnprintf(buf + *pos, len - *pos,
			  "tx_private_waterline: %#x\n",
			  le32_to_cpu(desc[0].data[4]));
	*pos += scnprintf(buf + *pos, len - *pos, "tm_bypass_en: %#x\n",
			  le32_to_cpu(desc[0].data[5]));
	*pos += scnprintf(buf + *pos, len - *pos, "SSU_TM_BYPASS_EN: %#x\n",
			  le32_to_cpu(desc[1].data[0]));
	*pos += scnprintf(buf + *pos, len - *pos, "SSU_RESERVE_CFG: %#x\n",
			  le32_to_cpu(desc[1].data[1]));

	if (hdev->hw.mac.media_type == HNAE3_MEDIA_TYPE_COPPER)
		return 0;

	ret = hclge_dbg_cmd_send(hdev, desc, port_id, 1,
				 HCLGE_OPC_TM_INTERNAL_STS_1);
	if (ret)
		return ret;

	*pos += scnprintf(buf + *pos, len - *pos, "TC_MAP_SEL: %#x\n",
			  le32_to_cpu(desc[0].data[1]));
	*pos += scnprintf(buf + *pos, len - *pos, "IGU_PFC_PRI_EN: %#x\n",
			  le32_to_cpu(desc[0].data[2]));
	*pos += scnprintf(buf + *pos, len - *pos, "MAC_PFC_PRI_EN: %#x\n",
			  le32_to_cpu(desc[0].data[3]));
	*pos += scnprintf(buf + *pos, len - *pos, "IGU_PRI_MAP_TC_CFG: %#x\n",
			  le32_to_cpu(desc[0].data[4]));
	*pos += scnprintf(buf + *pos, len - *pos,
			  "IGU_TX_PRI_MAP_TC_CFG: %#x\n",
			  le32_to_cpu(desc[0].data[5]));

	return 0;
}

static int hclge_dbg_dump_dcb(struct hclge_dev *hdev, char *buf, int len)
{
	int pos = 0;
	int ret;

	ret = hclge_dbg_dump_dcb_qset(hdev, buf, len, &pos);
	if (ret)
		return ret;

	ret = hclge_dbg_dump_dcb_pri(hdev, buf, len, &pos);
	if (ret)
		return ret;

	ret = hclge_dbg_dump_dcb_pg(hdev, buf, len, &pos);
	if (ret)
		return ret;

	ret = hclge_dbg_dump_dcb_queue(hdev, buf, len, &pos);
	if (ret)
		return ret;

	ret = hclge_dbg_dump_dcb_port(hdev, buf, len, &pos);
	if (ret)
		return ret;

	return hclge_dbg_dump_dcb_tm(hdev, buf, len, &pos);
}

static int hclge_dbg_dump_reg_cmd(struct hclge_dev *hdev,
				  enum hnae3_dbg_cmd cmd, char *buf, int len)
{
	const struct hclge_dbg_reg_type_info *reg_info;
	int pos = 0, ret = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(hclge_dbg_reg_info); i++) {
		reg_info = &hclge_dbg_reg_info[i];
		if (cmd == reg_info->cmd) {
			if (cmd == HNAE3_DBG_CMD_REG_TQP)
				return hclge_dbg_dump_reg_tqp(hdev, reg_info,
							      buf, len, &pos);

			ret = hclge_dbg_dump_reg_common(hdev, reg_info, buf,
							len, &pos);
			if (ret)
				break;
		}
	}

	return ret;
}

static int hclge_dbg_dump_tc(struct hclge_dev *hdev, char *buf, int len)
{
	struct hclge_ets_tc_weight_cmd *ets_weight;
	struct hclge_desc desc;
	char *sch_mode_str;
	int pos = 0;
	int ret;
	u8 i;

	if (!hnae3_dev_dcb_supported(hdev)) {
		dev_err(&hdev->pdev->dev,
			"Only DCB-supported dev supports tc\n");
		return -EOPNOTSUPP;
	}

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_ETS_TC_WEIGHT, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "failed to get tc weight, ret = %d\n",
			ret);
		return ret;
	}

	ets_weight = (struct hclge_ets_tc_weight_cmd *)desc.data;

	pos += scnprintf(buf + pos, len - pos, "enabled tc number: %u\n",
			 hdev->tm_info.num_tc);
	pos += scnprintf(buf + pos, len - pos, "weight_offset: %u\n",
			 ets_weight->weight_offset);

	pos += scnprintf(buf + pos, len - pos, "TC    MODE  WEIGHT\n");
	for (i = 0; i < HNAE3_MAX_TC; i++) {
		sch_mode_str = ets_weight->tc_weight[i] ? "dwrr" : "sp";
		pos += scnprintf(buf + pos, len - pos, "%u     %4s    %3u\n",
				 i, sch_mode_str,
				 hdev->tm_info.pg_info[0].tc_dwrr[i]);
	}

	return 0;
}

static const struct hclge_dbg_item tm_pg_items[] = {
	{ "ID", 2 },
	{ "PRI_MAP", 2 },
	{ "MODE", 2 },
	{ "DWRR", 2 },
	{ "C_IR_B", 2 },
	{ "C_IR_U", 2 },
	{ "C_IR_S", 2 },
	{ "C_BS_B", 2 },
	{ "C_BS_S", 2 },
	{ "C_FLAG", 2 },
	{ "C_RATE(Mbps)", 2 },
	{ "P_IR_B", 2 },
	{ "P_IR_U", 2 },
	{ "P_IR_S", 2 },
	{ "P_BS_B", 2 },
	{ "P_BS_S", 2 },
	{ "P_FLAG", 2 },
	{ "P_RATE(Mbps)", 0 }
};

static void hclge_dbg_fill_shaper_content(struct hclge_tm_shaper_para *para,
					  char **result, u8 *index)
{
	sprintf(result[(*index)++], "%3u", para->ir_b);
	sprintf(result[(*index)++], "%3u", para->ir_u);
	sprintf(result[(*index)++], "%3u", para->ir_s);
	sprintf(result[(*index)++], "%3u", para->bs_b);
	sprintf(result[(*index)++], "%3u", para->bs_s);
	sprintf(result[(*index)++], "%3u", para->flag);
	sprintf(result[(*index)++], "%6u", para->rate);
}

static int __hclge_dbg_dump_tm_pg(struct hclge_dev *hdev, char *data_str,
				  char *buf, int len)
{
	struct hclge_tm_shaper_para c_shaper_para, p_shaper_para;
	char *result[ARRAY_SIZE(tm_pg_items)], *sch_mode_str;
	u8 pg_id, sch_mode, weight, pri_bit_map, i, j;
	char content[HCLGE_DBG_TM_INFO_LEN];
	int pos = 0;
	int ret;

	for (i = 0; i < ARRAY_SIZE(tm_pg_items); i++) {
		result[i] = data_str;
		data_str += HCLGE_DBG_DATA_STR_LEN;
	}

	hclge_dbg_fill_content(content, sizeof(content), tm_pg_items,
			       NULL, ARRAY_SIZE(tm_pg_items));
	pos += scnprintf(buf + pos, len - pos, "%s", content);

	for (pg_id = 0; pg_id < hdev->tm_info.num_pg; pg_id++) {
		ret = hclge_tm_get_pg_to_pri_map(hdev, pg_id, &pri_bit_map);
		if (ret)
			return ret;

		ret = hclge_tm_get_pg_sch_mode(hdev, pg_id, &sch_mode);
		if (ret)
			return ret;

		ret = hclge_tm_get_pg_weight(hdev, pg_id, &weight);
		if (ret)
			return ret;

		ret = hclge_tm_get_pg_shaper(hdev, pg_id,
					     HCLGE_OPC_TM_PG_C_SHAPPING,
					     &c_shaper_para);
		if (ret)
			return ret;

		ret = hclge_tm_get_pg_shaper(hdev, pg_id,
					     HCLGE_OPC_TM_PG_P_SHAPPING,
					     &p_shaper_para);
		if (ret)
			return ret;

		sch_mode_str = sch_mode & HCLGE_TM_TX_SCHD_DWRR_MSK ? "dwrr" :
				       "sp";

		j = 0;
		sprintf(result[j++], "%02u", pg_id);
		sprintf(result[j++], "0x%02x", pri_bit_map);
		sprintf(result[j++], "%4s", sch_mode_str);
		sprintf(result[j++], "%3u", weight);
		hclge_dbg_fill_shaper_content(&c_shaper_para, result, &j);
		hclge_dbg_fill_shaper_content(&p_shaper_para, result, &j);

		hclge_dbg_fill_content(content, sizeof(content), tm_pg_items,
				       (const char **)result,
				       ARRAY_SIZE(tm_pg_items));
		pos += scnprintf(buf + pos, len - pos, "%s", content);
	}

	return 0;
}

static int hclge_dbg_dump_tm_pg(struct hclge_dev *hdev, char *buf, int len)
{
	char *data_str;
	int ret;

	data_str = kcalloc(ARRAY_SIZE(tm_pg_items),
			   HCLGE_DBG_DATA_STR_LEN, GFP_KERNEL);

	if (!data_str)
		return -ENOMEM;

	ret = __hclge_dbg_dump_tm_pg(hdev, data_str, buf, len);

	kfree(data_str);

	return ret;
}

static int hclge_dbg_dump_tm_port(struct hclge_dev *hdev,  char *buf, int len)
{
	struct hclge_tm_shaper_para shaper_para;
	int pos = 0;
	int ret;

	ret = hclge_tm_get_port_shaper(hdev, &shaper_para);
	if (ret)
		return ret;

	pos += scnprintf(buf + pos, len - pos,
			 "IR_B  IR_U  IR_S  BS_B  BS_S  FLAG  RATE(Mbps)\n");
	pos += scnprintf(buf + pos, len - pos,
			 "%3u   %3u   %3u   %3u   %3u     %1u   %6u\n",
			 shaper_para.ir_b, shaper_para.ir_u, shaper_para.ir_s,
			 shaper_para.bs_b, shaper_para.bs_s, shaper_para.flag,
			 shaper_para.rate);

	return 0;
}

static int hclge_dbg_dump_tm_bp_qset_map(struct hclge_dev *hdev, u8 tc_id,
					 char *buf, int len)
{
	u32 qset_mapping[HCLGE_BP_EXT_GRP_NUM];
	struct hclge_bp_to_qs_map_cmd *map;
	struct hclge_desc desc;
	int pos = 0;
	u8 group_id;
	u8 grp_num;
	u16 i = 0;
	int ret;

	grp_num = hdev->num_tqps <= HCLGE_TQP_MAX_SIZE_DEV_V2 ?
		  HCLGE_BP_GRP_NUM : HCLGE_BP_EXT_GRP_NUM;
	map = (struct hclge_bp_to_qs_map_cmd *)desc.data;
	for (group_id = 0; group_id < grp_num; group_id++) {
		hclge_cmd_setup_basic_desc(&desc,
					   HCLGE_OPC_TM_BP_TO_QSET_MAPPING,
					   true);
		map->tc_id = tc_id;
		map->qs_group_id = group_id;
		ret = hclge_cmd_send(&hdev->hw, &desc, 1);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"failed to get bp to qset map, ret = %d\n",
				ret);
			return ret;
		}

		qset_mapping[group_id] = le32_to_cpu(map->qs_bit_map);
	}

	pos += scnprintf(buf + pos, len - pos, "INDEX | TM BP QSET MAPPING:\n");
	for (group_id = 0; group_id < grp_num / 8; group_id++) {
		pos += scnprintf(buf + pos, len - pos,
			 "%04d  | %08x:%08x:%08x:%08x:%08x:%08x:%08x:%08x\n",
			 group_id * 256, qset_mapping[i + 7],
			 qset_mapping[i + 6], qset_mapping[i + 5],
			 qset_mapping[i + 4], qset_mapping[i + 3],
			 qset_mapping[i + 2], qset_mapping[i + 1],
			 qset_mapping[i]);
		i += 8;
	}

	return pos;
}

static int hclge_dbg_dump_tm_map(struct hclge_dev *hdev, char *buf, int len)
{
	u16 queue_id;
	u16 qset_id;
	u8 link_vld;
	int pos = 0;
	u8 pri_id;
	u8 tc_id;
	int ret;

	for (queue_id = 0; queue_id < hdev->num_tqps; queue_id++) {
		ret = hclge_tm_get_q_to_qs_map(hdev, queue_id, &qset_id);
		if (ret)
			return ret;

		ret = hclge_tm_get_qset_map_pri(hdev, qset_id, &pri_id,
						&link_vld);
		if (ret)
			return ret;

		ret = hclge_tm_get_q_to_tc(hdev, queue_id, &tc_id);
		if (ret)
			return ret;

		pos += scnprintf(buf + pos, len - pos,
				 "QUEUE_ID   QSET_ID   PRI_ID   TC_ID\n");
		pos += scnprintf(buf + pos, len - pos,
				 "%04u        %4u       %3u      %2u\n",
				 queue_id, qset_id, pri_id, tc_id);

		if (!hnae3_dev_dcb_supported(hdev))
			continue;

		ret = hclge_dbg_dump_tm_bp_qset_map(hdev, tc_id, buf + pos,
						    len - pos);
		if (ret < 0)
			return ret;
		pos += ret;

		pos += scnprintf(buf + pos, len - pos, "\n");
	}

	return 0;
}

static int hclge_dbg_dump_tm_nodes(struct hclge_dev *hdev, char *buf, int len)
{
	struct hclge_tm_nodes_cmd *nodes;
	struct hclge_desc desc;
	int pos = 0;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_NODES, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump tm nodes, ret = %d\n", ret);
		return ret;
	}

	nodes = (struct hclge_tm_nodes_cmd *)desc.data;

	pos += scnprintf(buf + pos, len - pos, "       BASE_ID  MAX_NUM\n");
	pos += scnprintf(buf + pos, len - pos, "PG      %4u      %4u\n",
			 nodes->pg_base_id, nodes->pg_num);
	pos += scnprintf(buf + pos, len - pos, "PRI     %4u      %4u\n",
			 nodes->pri_base_id, nodes->pri_num);
	pos += scnprintf(buf + pos, len - pos, "QSET    %4u      %4u\n",
			 le16_to_cpu(nodes->qset_base_id),
			 le16_to_cpu(nodes->qset_num));
	pos += scnprintf(buf + pos, len - pos, "QUEUE   %4u      %4u\n",
			 le16_to_cpu(nodes->queue_base_id),
			 le16_to_cpu(nodes->queue_num));

	return 0;
}

static const struct hclge_dbg_item tm_pri_items[] = {
	{ "ID", 4 },
	{ "MODE", 2 },
	{ "DWRR", 2 },
	{ "C_IR_B", 2 },
	{ "C_IR_U", 2 },
	{ "C_IR_S", 2 },
	{ "C_BS_B", 2 },
	{ "C_BS_S", 2 },
	{ "C_FLAG", 2 },
	{ "C_RATE(Mbps)", 2 },
	{ "P_IR_B", 2 },
	{ "P_IR_U", 2 },
	{ "P_IR_S", 2 },
	{ "P_BS_B", 2 },
	{ "P_BS_S", 2 },
	{ "P_FLAG", 2 },
	{ "P_RATE(Mbps)", 0 }
};

static int hclge_dbg_dump_tm_pri(struct hclge_dev *hdev, char *buf, int len)
{
	char data_str[ARRAY_SIZE(tm_pri_items)][HCLGE_DBG_DATA_STR_LEN];
	struct hclge_tm_shaper_para c_shaper_para, p_shaper_para;
	char *result[ARRAY_SIZE(tm_pri_items)], *sch_mode_str;
	char content[HCLGE_DBG_TM_INFO_LEN];
	u8 pri_num, sch_mode, weight, i, j;
	int pos, ret;

	ret = hclge_tm_get_pri_num(hdev, &pri_num);
	if (ret)
		return ret;

	for (i = 0; i < ARRAY_SIZE(tm_pri_items); i++)
		result[i] = &data_str[i][0];

	hclge_dbg_fill_content(content, sizeof(content), tm_pri_items,
			       NULL, ARRAY_SIZE(tm_pri_items));
	pos = scnprintf(buf, len, "%s", content);

	for (i = 0; i < pri_num; i++) {
		ret = hclge_tm_get_pri_sch_mode(hdev, i, &sch_mode);
		if (ret)
			return ret;

		ret = hclge_tm_get_pri_weight(hdev, i, &weight);
		if (ret)
			return ret;

		ret = hclge_tm_get_pri_shaper(hdev, i,
					      HCLGE_OPC_TM_PRI_C_SHAPPING,
					      &c_shaper_para);
		if (ret)
			return ret;

		ret = hclge_tm_get_pri_shaper(hdev, i,
					      HCLGE_OPC_TM_PRI_P_SHAPPING,
					      &p_shaper_para);
		if (ret)
			return ret;

		sch_mode_str = sch_mode & HCLGE_TM_TX_SCHD_DWRR_MSK ? "dwrr" :
			       "sp";

		j = 0;
		sprintf(result[j++], "%04u", i);
		sprintf(result[j++], "%4s", sch_mode_str);
		sprintf(result[j++], "%3u", weight);
		hclge_dbg_fill_shaper_content(&c_shaper_para, result, &j);
		hclge_dbg_fill_shaper_content(&p_shaper_para, result, &j);
		hclge_dbg_fill_content(content, sizeof(content), tm_pri_items,
				       (const char **)result,
				       ARRAY_SIZE(tm_pri_items));
		pos += scnprintf(buf + pos, len - pos, "%s", content);
	}

	return 0;
}

static const struct hclge_dbg_item tm_qset_items[] = {
	{ "ID", 4 },
	{ "MAP_PRI", 2 },
	{ "LINK_VLD", 2 },
	{ "MODE", 2 },
	{ "DWRR", 2 },
	{ "IR_B", 2 },
	{ "IR_U", 2 },
	{ "IR_S", 2 },
	{ "BS_B", 2 },
	{ "BS_S", 2 },
	{ "FLAG", 2 },
	{ "RATE(Mbps)", 0 }
};

static int hclge_dbg_dump_tm_qset(struct hclge_dev *hdev, char *buf, int len)
{
	char data_str[ARRAY_SIZE(tm_qset_items)][HCLGE_DBG_DATA_STR_LEN];
	char *result[ARRAY_SIZE(tm_qset_items)], *sch_mode_str;
	u8 priority, link_vld, sch_mode, weight;
	struct hclge_tm_shaper_para shaper_para;
	char content[HCLGE_DBG_TM_INFO_LEN];
	u16 qset_num, i;
	int ret, pos;
	u8 j;

	ret = hclge_tm_get_qset_num(hdev, &qset_num);
	if (ret)
		return ret;

	for (i = 0; i < ARRAY_SIZE(tm_qset_items); i++)
		result[i] = &data_str[i][0];

	hclge_dbg_fill_content(content, sizeof(content), tm_qset_items,
			       NULL, ARRAY_SIZE(tm_qset_items));
	pos = scnprintf(buf, len, "%s", content);

	for (i = 0; i < qset_num; i++) {
		ret = hclge_tm_get_qset_map_pri(hdev, i, &priority, &link_vld);
		if (ret)
			return ret;

		ret = hclge_tm_get_qset_sch_mode(hdev, i, &sch_mode);
		if (ret)
			return ret;

		ret = hclge_tm_get_qset_weight(hdev, i, &weight);
		if (ret)
			return ret;

		ret = hclge_tm_get_qset_shaper(hdev, i, &shaper_para);
		if (ret)
			return ret;

		sch_mode_str = sch_mode & HCLGE_TM_TX_SCHD_DWRR_MSK ? "dwrr" :
			       "sp";

		j = 0;
		sprintf(result[j++], "%04u", i);
		sprintf(result[j++], "%4u", priority);
		sprintf(result[j++], "%4u", link_vld);
		sprintf(result[j++], "%4s", sch_mode_str);
		sprintf(result[j++], "%3u", weight);
		hclge_dbg_fill_shaper_content(&shaper_para, result, &j);

		hclge_dbg_fill_content(content, sizeof(content), tm_qset_items,
				       (const char **)result,
				       ARRAY_SIZE(tm_qset_items));
		pos += scnprintf(buf + pos, len - pos, "%s", content);
	}

	return 0;
}

static int hclge_dbg_dump_qos_pause_cfg(struct hclge_dev *hdev, char *buf,
					int len)
{
	struct hclge_cfg_pause_param_cmd *pause_param;
	struct hclge_desc desc;
	int pos = 0;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CFG_MAC_PARA, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump qos pause, ret = %d\n", ret);
		return ret;
	}

	pause_param = (struct hclge_cfg_pause_param_cmd *)desc.data;

	pos += scnprintf(buf + pos, len - pos, "pause_trans_gap: 0x%x\n",
			 pause_param->pause_trans_gap);
	pos += scnprintf(buf + pos, len - pos, "pause_trans_time: 0x%x\n",
			 le16_to_cpu(pause_param->pause_trans_time));
	return 0;
}

static int hclge_dbg_dump_qos_pri_map(struct hclge_dev *hdev, char *buf,
				      int len)
{
#define HCLGE_DBG_TC_MASK		0x0F
#define HCLGE_DBG_TC_BIT_WIDTH		4

	struct hclge_qos_pri_map_cmd *pri_map;
	struct hclge_desc desc;
	int pos = 0;
	u8 *pri_tc;
	u8 tc, i;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_PRI_TO_TC_MAPPING, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump qos pri map, ret = %d\n", ret);
		return ret;
	}

	pri_map = (struct hclge_qos_pri_map_cmd *)desc.data;

	pos += scnprintf(buf + pos, len - pos, "vlan_to_pri: 0x%x\n",
			 pri_map->vlan_pri);
	pos += scnprintf(buf + pos, len - pos, "PRI  TC\n");

	pri_tc = (u8 *)pri_map;
	for (i = 0; i < HNAE3_MAX_TC; i++) {
		tc = pri_tc[i >> 1] >> ((i & 1) * HCLGE_DBG_TC_BIT_WIDTH);
		tc &= HCLGE_DBG_TC_MASK;
		pos += scnprintf(buf + pos, len - pos, "%u     %u\n", i, tc);
	}

	return 0;
}

static int hclge_dbg_dump_tx_buf_cfg(struct hclge_dev *hdev, char *buf, int len)
{
	struct hclge_tx_buff_alloc_cmd *tx_buf_cmd;
	struct hclge_desc desc;
	int pos = 0;
	int i, ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TX_BUFF_ALLOC, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump tx buf, ret = %d\n", ret);
		return ret;
	}

	tx_buf_cmd = (struct hclge_tx_buff_alloc_cmd *)desc.data;
	for (i = 0; i < HCLGE_MAX_TC_NUM; i++)
		pos += scnprintf(buf + pos, len - pos,
				 "tx_packet_buf_tc_%d: 0x%x\n", i,
				 le16_to_cpu(tx_buf_cmd->tx_pkt_buff[i]));

	return pos;
}

static int hclge_dbg_dump_rx_priv_buf_cfg(struct hclge_dev *hdev, char *buf,
					  int len)
{
	struct hclge_rx_priv_buff_cmd *rx_buf_cmd;
	struct hclge_desc desc;
	int pos = 0;
	int i, ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_RX_PRIV_BUFF_ALLOC, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump rx priv buf, ret = %d\n", ret);
		return ret;
	}

	pos += scnprintf(buf + pos, len - pos, "\n");

	rx_buf_cmd = (struct hclge_rx_priv_buff_cmd *)desc.data;
	for (i = 0; i < HCLGE_MAX_TC_NUM; i++)
		pos += scnprintf(buf + pos, len - pos,
				 "rx_packet_buf_tc_%d: 0x%x\n", i,
				 le16_to_cpu(rx_buf_cmd->buf_num[i]));

	pos += scnprintf(buf + pos, len - pos, "rx_share_buf: 0x%x\n",
			 le16_to_cpu(rx_buf_cmd->shared_buf));

	return pos;
}

static int hclge_dbg_dump_rx_common_wl_cfg(struct hclge_dev *hdev, char *buf,
					   int len)
{
	struct hclge_rx_com_wl *rx_com_wl;
	struct hclge_desc desc;
	int pos = 0;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_RX_COM_WL_ALLOC, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump rx common wl, ret = %d\n", ret);
		return ret;
	}

	rx_com_wl = (struct hclge_rx_com_wl *)desc.data;
	pos += scnprintf(buf + pos, len - pos, "\n");
	pos += scnprintf(buf + pos, len - pos,
			 "rx_com_wl: high: 0x%x, low: 0x%x\n",
			 le16_to_cpu(rx_com_wl->com_wl.high),
			 le16_to_cpu(rx_com_wl->com_wl.low));

	return pos;
}

static int hclge_dbg_dump_rx_global_pkt_cnt(struct hclge_dev *hdev, char *buf,
					    int len)
{
	struct hclge_rx_com_wl *rx_packet_cnt;
	struct hclge_desc desc;
	int pos = 0;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_RX_GBL_PKT_CNT, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump rx global pkt cnt, ret = %d\n", ret);
		return ret;
	}

	rx_packet_cnt = (struct hclge_rx_com_wl *)desc.data;
	pos += scnprintf(buf + pos, len - pos,
			 "rx_global_packet_cnt: high: 0x%x, low: 0x%x\n",
			 le16_to_cpu(rx_packet_cnt->com_wl.high),
			 le16_to_cpu(rx_packet_cnt->com_wl.low));

	return pos;
}

static int hclge_dbg_dump_rx_priv_wl_buf_cfg(struct hclge_dev *hdev, char *buf,
					     int len)
{
	struct hclge_rx_priv_wl_buf *rx_priv_wl;
	struct hclge_desc desc[2];
	int pos = 0;
	int i, ret;

	hclge_cmd_setup_basic_desc(&desc[0], HCLGE_OPC_RX_PRIV_WL_ALLOC, true);
	desc[0].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
	hclge_cmd_setup_basic_desc(&desc[1], HCLGE_OPC_RX_PRIV_WL_ALLOC, true);
	ret = hclge_cmd_send(&hdev->hw, desc, 2);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump rx priv wl buf, ret = %d\n", ret);
		return ret;
	}

	rx_priv_wl = (struct hclge_rx_priv_wl_buf *)desc[0].data;
	for (i = 0; i < HCLGE_TC_NUM_ONE_DESC; i++)
		pos += scnprintf(buf + pos, len - pos,
			 "rx_priv_wl_tc_%d: high: 0x%x, low: 0x%x\n", i,
			 le16_to_cpu(rx_priv_wl->tc_wl[i].high),
			 le16_to_cpu(rx_priv_wl->tc_wl[i].low));

	rx_priv_wl = (struct hclge_rx_priv_wl_buf *)desc[1].data;
	for (i = 0; i < HCLGE_TC_NUM_ONE_DESC; i++)
		pos += scnprintf(buf + pos, len - pos,
			 "rx_priv_wl_tc_%d: high: 0x%x, low: 0x%x\n",
			 i + HCLGE_TC_NUM_ONE_DESC,
			 le16_to_cpu(rx_priv_wl->tc_wl[i].high),
			 le16_to_cpu(rx_priv_wl->tc_wl[i].low));

	return pos;
}

static int hclge_dbg_dump_rx_common_threshold_cfg(struct hclge_dev *hdev,
						  char *buf, int len)
{
	struct hclge_rx_com_thrd *rx_com_thrd;
	struct hclge_desc desc[2];
	int pos = 0;
	int i, ret;

	hclge_cmd_setup_basic_desc(&desc[0], HCLGE_OPC_RX_COM_THRD_ALLOC, true);
	desc[0].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
	hclge_cmd_setup_basic_desc(&desc[1], HCLGE_OPC_RX_COM_THRD_ALLOC, true);
	ret = hclge_cmd_send(&hdev->hw, desc, 2);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump rx common threshold, ret = %d\n", ret);
		return ret;
	}

	pos += scnprintf(buf + pos, len - pos, "\n");
	rx_com_thrd = (struct hclge_rx_com_thrd *)desc[0].data;
	for (i = 0; i < HCLGE_TC_NUM_ONE_DESC; i++)
		pos += scnprintf(buf + pos, len - pos,
			 "rx_com_thrd_tc_%d: high: 0x%x, low: 0x%x\n", i,
			 le16_to_cpu(rx_com_thrd->com_thrd[i].high),
			 le16_to_cpu(rx_com_thrd->com_thrd[i].low));

	rx_com_thrd = (struct hclge_rx_com_thrd *)desc[1].data;
	for (i = 0; i < HCLGE_TC_NUM_ONE_DESC; i++)
		pos += scnprintf(buf + pos, len - pos,
			 "rx_com_thrd_tc_%d: high: 0x%x, low: 0x%x\n",
			 i + HCLGE_TC_NUM_ONE_DESC,
			 le16_to_cpu(rx_com_thrd->com_thrd[i].high),
			 le16_to_cpu(rx_com_thrd->com_thrd[i].low));

	return pos;
}

static int hclge_dbg_dump_qos_buf_cfg(struct hclge_dev *hdev, char *buf,
				      int len)
{
	int pos = 0;
	int ret;

	ret = hclge_dbg_dump_tx_buf_cfg(hdev, buf + pos, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	ret = hclge_dbg_dump_rx_priv_buf_cfg(hdev, buf + pos, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	ret = hclge_dbg_dump_rx_common_wl_cfg(hdev, buf + pos, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	ret = hclge_dbg_dump_rx_global_pkt_cnt(hdev, buf + pos, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	pos += scnprintf(buf + pos, len - pos, "\n");
	if (!hnae3_dev_dcb_supported(hdev))
		return 0;

	ret = hclge_dbg_dump_rx_priv_wl_buf_cfg(hdev, buf + pos, len - pos);
	if (ret < 0)
		return ret;
	pos += ret;

	ret = hclge_dbg_dump_rx_common_threshold_cfg(hdev, buf + pos,
						     len - pos);
	if (ret < 0)
		return ret;

	return 0;
}

static int hclge_dbg_dump_mng_table(struct hclge_dev *hdev, char *buf, int len)
{
	struct hclge_mac_ethertype_idx_rd_cmd *req0;
	struct hclge_desc desc;
	u32 msg_egress_port;
	int pos = 0;
	int ret, i;

	pos += scnprintf(buf + pos, len - pos,
			 "entry  mac_addr          mask  ether  ");
	pos += scnprintf(buf + pos, len - pos,
			 "mask  vlan  mask  i_map  i_dir  e_type  ");
	pos += scnprintf(buf + pos, len - pos, "pf_id  vf_id  q_id  drop\n");

	for (i = 0; i < HCLGE_DBG_MNG_TBL_MAX; i++) {
		hclge_cmd_setup_basic_desc(&desc, HCLGE_MAC_ETHERTYPE_IDX_RD,
					   true);
		req0 = (struct hclge_mac_ethertype_idx_rd_cmd *)&desc.data;
		req0->index = cpu_to_le16(i);

		ret = hclge_cmd_send(&hdev->hw, &desc, 1);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"failed to dump manage table, ret = %d\n", ret);
			return ret;
		}

		if (!req0->resp_code)
			continue;

		pos += scnprintf(buf + pos, len - pos, "%02u     %pM ",
				 le16_to_cpu(req0->index), req0->mac_addr);

		pos += scnprintf(buf + pos, len - pos,
				 "%x     %04x   %x     %04x  ",
				 !!(req0->flags & HCLGE_DBG_MNG_MAC_MASK_B),
				 le16_to_cpu(req0->ethter_type),
				 !!(req0->flags & HCLGE_DBG_MNG_ETHER_MASK_B),
				 le16_to_cpu(req0->vlan_tag) &
				 HCLGE_DBG_MNG_VLAN_TAG);

		pos += scnprintf(buf + pos, len - pos,
				 "%x     %02x     %02x     ",
				 !!(req0->flags & HCLGE_DBG_MNG_VLAN_MASK_B),
				 req0->i_port_bitmap, req0->i_port_direction);

		msg_egress_port = le16_to_cpu(req0->egress_port);
		pos += scnprintf(buf + pos, len - pos,
				 "%x       %x      %02x     %04x  %x\n",
				 !!(msg_egress_port & HCLGE_DBG_MNG_E_TYPE_B),
				 msg_egress_port & HCLGE_DBG_MNG_PF_ID,
				 (msg_egress_port >> 3) & HCLGE_DBG_MNG_VF_ID,
				 le16_to_cpu(req0->egress_queue),
				 !!(msg_egress_port & HCLGE_DBG_MNG_DROP_B));
	}

	return 0;
}

#define HCLGE_DBG_TCAM_BUF_SIZE 256

static int hclge_dbg_fd_tcam_read(struct hclge_dev *hdev, bool sel_x,
				  char *tcam_buf,
				  struct hclge_dbg_tcam_msg tcam_msg)
{
	struct hclge_fd_tcam_config_1_cmd *req1;
	struct hclge_fd_tcam_config_2_cmd *req2;
	struct hclge_fd_tcam_config_3_cmd *req3;
	struct hclge_desc desc[3];
	int pos = 0;
	int ret, i;
	u32 *req;

	hclge_cmd_setup_basic_desc(&desc[0], HCLGE_OPC_FD_TCAM_OP, true);
	desc[0].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
	hclge_cmd_setup_basic_desc(&desc[1], HCLGE_OPC_FD_TCAM_OP, true);
	desc[1].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
	hclge_cmd_setup_basic_desc(&desc[2], HCLGE_OPC_FD_TCAM_OP, true);

	req1 = (struct hclge_fd_tcam_config_1_cmd *)desc[0].data;
	req2 = (struct hclge_fd_tcam_config_2_cmd *)desc[1].data;
	req3 = (struct hclge_fd_tcam_config_3_cmd *)desc[2].data;

	req1->stage  = tcam_msg.stage;
	req1->xy_sel = sel_x ? 1 : 0;
	req1->index  = cpu_to_le32(tcam_msg.loc);

	ret = hclge_cmd_send(&hdev->hw, desc, 3);
	if (ret)
		return ret;

	pos += scnprintf(tcam_buf + pos, HCLGE_DBG_TCAM_BUF_SIZE - pos,
			 "read result tcam key %s(%u):\n", sel_x ? "x" : "y",
			 tcam_msg.loc);

	/* tcam_data0 ~ tcam_data1 */
	req = (u32 *)req1->tcam_data;
	for (i = 0; i < 2; i++)
		pos += scnprintf(tcam_buf + pos, HCLGE_DBG_TCAM_BUF_SIZE - pos,
				 "%08x\n", *req++);

	/* tcam_data2 ~ tcam_data7 */
	req = (u32 *)req2->tcam_data;
	for (i = 0; i < 6; i++)
		pos += scnprintf(tcam_buf + pos, HCLGE_DBG_TCAM_BUF_SIZE - pos,
				 "%08x\n", *req++);

	/* tcam_data8 ~ tcam_data12 */
	req = (u32 *)req3->tcam_data;
	for (i = 0; i < 5; i++)
		pos += scnprintf(tcam_buf + pos, HCLGE_DBG_TCAM_BUF_SIZE - pos,
				 "%08x\n", *req++);

	return ret;
}

static int hclge_dbg_get_rules_location(struct hclge_dev *hdev, u16 *rule_locs)
{
	struct hclge_fd_rule *rule;
	struct hlist_node *node;
	int cnt = 0;

	spin_lock_bh(&hdev->fd_rule_lock);
	hlist_for_each_entry_safe(rule, node, &hdev->fd_rule_list, rule_node) {
		rule_locs[cnt] = rule->location;
		cnt++;
	}
	spin_unlock_bh(&hdev->fd_rule_lock);

	if (cnt != hdev->hclge_fd_rule_num || cnt == 0)
		return -EINVAL;

	return cnt;
}

static int hclge_dbg_dump_fd_tcam(struct hclge_dev *hdev, char *buf, int len)
{
	u32 rule_num = hdev->fd_cfg.rule_num[HCLGE_FD_STAGE_1];
	struct hclge_dbg_tcam_msg tcam_msg;
	int i, ret, rule_cnt;
	u16 *rule_locs;
	char *tcam_buf;
	int pos = 0;

	if (!hnae3_dev_fd_supported(hdev)) {
		dev_err(&hdev->pdev->dev,
			"Only FD-supported dev supports dump fd tcam\n");
		return -EOPNOTSUPP;
	}

	if (!hdev->hclge_fd_rule_num || !rule_num)
		return 0;

	rule_locs = kcalloc(rule_num, sizeof(u16), GFP_KERNEL);
	if (!rule_locs)
		return -ENOMEM;

	tcam_buf = kzalloc(HCLGE_DBG_TCAM_BUF_SIZE, GFP_KERNEL);
	if (!tcam_buf) {
		kfree(rule_locs);
		return -ENOMEM;
	}

	rule_cnt = hclge_dbg_get_rules_location(hdev, rule_locs);
	if (rule_cnt < 0) {
		ret = rule_cnt;
		dev_err(&hdev->pdev->dev,
			"failed to get rule number, ret = %d\n", ret);
		goto out;
	}

	ret = 0;
	for (i = 0; i < rule_cnt; i++) {
		tcam_msg.stage = HCLGE_FD_STAGE_1;
		tcam_msg.loc = rule_locs[i];

		ret = hclge_dbg_fd_tcam_read(hdev, true, tcam_buf, tcam_msg);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"failed to get fd tcam key x, ret = %d\n", ret);
			goto out;
		}

		pos += scnprintf(buf + pos, len - pos, "%s", tcam_buf);

		ret = hclge_dbg_fd_tcam_read(hdev, false, tcam_buf, tcam_msg);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"failed to get fd tcam key y, ret = %d\n", ret);
			goto out;
		}

		pos += scnprintf(buf + pos, len - pos, "%s", tcam_buf);
	}

out:
	kfree(tcam_buf);
	kfree(rule_locs);
	return ret;
}

static int hclge_dbg_dump_fd_counter(struct hclge_dev *hdev, char *buf, int len)
{
	u8 func_num = pci_num_vf(hdev->pdev) + 1; /* pf and enabled vf num */
	struct hclge_fd_ad_cnt_read_cmd *req;
	char str_id[HCLGE_DBG_ID_LEN];
	struct hclge_desc desc;
	int pos = 0;
	int ret;
	u64 cnt;
	u8 i;

	pos += scnprintf(buf + pos, len - pos,
			 "func_id\thit_times\n");

	for (i = 0; i < func_num; i++) {
		hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_FD_CNT_OP, true);
		req = (struct hclge_fd_ad_cnt_read_cmd *)desc.data;
		req->index = cpu_to_le16(i);
		ret = hclge_cmd_send(&hdev->hw, &desc, 1);
		if (ret) {
			dev_err(&hdev->pdev->dev, "failed to get fd counter, ret = %d\n",
				ret);
			return ret;
		}
		cnt = le64_to_cpu(req->cnt);
		hclge_dbg_get_func_id_str(str_id, i);
		pos += scnprintf(buf + pos, len - pos,
				 "%s\t%llu\n", str_id, cnt);
	}

	return 0;
}

int hclge_dbg_dump_rst_info(struct hclge_dev *hdev, char *buf, int len)
{
	int pos = 0;

	pos += scnprintf(buf + pos, len - pos, "PF reset count: %u\n",
			 hdev->rst_stats.pf_rst_cnt);
	pos += scnprintf(buf + pos, len - pos, "FLR reset count: %u\n",
			 hdev->rst_stats.flr_rst_cnt);
	pos += scnprintf(buf + pos, len - pos, "GLOBAL reset count: %u\n",
			 hdev->rst_stats.global_rst_cnt);
	pos += scnprintf(buf + pos, len - pos, "IMP reset count: %u\n",
			 hdev->rst_stats.imp_rst_cnt);
	pos += scnprintf(buf + pos, len - pos, "reset done count: %u\n",
			 hdev->rst_stats.reset_done_cnt);
	pos += scnprintf(buf + pos, len - pos, "HW reset done count: %u\n",
			 hdev->rst_stats.hw_reset_done_cnt);
	pos += scnprintf(buf + pos, len - pos, "reset count: %u\n",
			 hdev->rst_stats.reset_cnt);
	pos += scnprintf(buf + pos, len - pos, "reset fail count: %u\n",
			 hdev->rst_stats.reset_fail_cnt);
	pos += scnprintf(buf + pos, len - pos,
			 "vector0 interrupt enable status: 0x%x\n",
			 hclge_read_dev(&hdev->hw, HCLGE_MISC_VECTOR_REG_BASE));
	pos += scnprintf(buf + pos, len - pos, "reset interrupt source: 0x%x\n",
			 hclge_read_dev(&hdev->hw, HCLGE_MISC_RESET_STS_REG));
	pos += scnprintf(buf + pos, len - pos, "reset interrupt status: 0x%x\n",
			 hclge_read_dev(&hdev->hw, HCLGE_MISC_VECTOR_INT_STS));
	pos += scnprintf(buf + pos, len - pos, "RAS interrupt status: 0x%x\n",
			 hclge_read_dev(&hdev->hw,
					HCLGE_RAS_PF_OTHER_INT_STS_REG));
	pos += scnprintf(buf + pos, len - pos, "hardware reset status: 0x%x\n",
			 hclge_read_dev(&hdev->hw, HCLGE_GLOBAL_RESET_REG));
	pos += scnprintf(buf + pos, len - pos, "handshake status: 0x%x\n",
			 hclge_read_dev(&hdev->hw, HCLGE_NIC_CSQ_DEPTH_REG));
	pos += scnprintf(buf + pos, len - pos, "function reset status: 0x%x\n",
			 hclge_read_dev(&hdev->hw, HCLGE_FUN_RST_ING));
	pos += scnprintf(buf + pos, len - pos, "hdev state: 0x%lx\n",
			 hdev->state);

	return 0;
}

static int hclge_dbg_dump_serv_info(struct hclge_dev *hdev, char *buf, int len)
{
	unsigned long rem_nsec;
	int pos = 0;
	u64 lc;

	lc = local_clock();
	rem_nsec = do_div(lc, HCLGE_BILLION_NANO_SECONDS);

	pos += scnprintf(buf + pos, len - pos, "local_clock: [%5lu.%06lu]\n",
			 (unsigned long)lc, rem_nsec / 1000);
	pos += scnprintf(buf + pos, len - pos, "delta: %u(ms)\n",
			 jiffies_to_msecs(jiffies - hdev->last_serv_processed));
	pos += scnprintf(buf + pos, len - pos,
			 "last_service_task_processed: %lu(jiffies)\n",
			 hdev->last_serv_processed);
	pos += scnprintf(buf + pos, len - pos, "last_service_task_cnt: %lu\n",
			 hdev->serv_processed_cnt);

	return 0;
}

static int hclge_dbg_dump_interrupt(struct hclge_dev *hdev, char *buf, int len)
{
	int pos = 0;

	pos += scnprintf(buf + pos, len - pos, "num_nic_msi: %u\n",
			 hdev->num_nic_msi);
	pos += scnprintf(buf + pos, len - pos, "num_roce_msi: %u\n",
			 hdev->num_roce_msi);
	pos += scnprintf(buf + pos, len - pos, "num_msi_used: %u\n",
			 hdev->num_msi_used);
	pos += scnprintf(buf + pos, len - pos, "num_msi_left: %u\n",
			 hdev->num_msi_left);

	return 0;
}

static void hclge_dbg_imp_info_data_print(struct hclge_desc *desc_src,
					  char *buf, int len, u32 bd_num)
{
#define HCLGE_DBG_IMP_INFO_PRINT_OFFSET 0x2

	struct hclge_desc *desc_index = desc_src;
	u32 offset = 0;
	int pos = 0;
	u32 i, j;

	pos += scnprintf(buf + pos, len - pos, "offset | data\n");

	for (i = 0; i < bd_num; i++) {
		j = 0;
		while (j < HCLGE_DESC_DATA_LEN - 1) {
			pos += scnprintf(buf + pos, len - pos, "0x%04x | ",
					 offset);
			pos += scnprintf(buf + pos, len - pos, "0x%08x  ",
					 le32_to_cpu(desc_index->data[j++]));
			pos += scnprintf(buf + pos, len - pos, "0x%08x\n",
					 le32_to_cpu(desc_index->data[j++]));
			offset += sizeof(u32) * HCLGE_DBG_IMP_INFO_PRINT_OFFSET;
		}
		desc_index++;
	}
}

static int
hclge_dbg_get_imp_stats_info(struct hclge_dev *hdev, char *buf, int len)
{
	struct hclge_get_imp_bd_cmd *req;
	struct hclge_desc *desc_src;
	struct hclge_desc desc;
	u32 bd_num;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_IMP_STATS_BD, true);

	req = (struct hclge_get_imp_bd_cmd *)desc.data;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to get imp statistics bd number, ret = %d\n",
			ret);
		return ret;
	}

	bd_num = le32_to_cpu(req->bd_num);
	if (!bd_num) {
		dev_err(&hdev->pdev->dev, "imp statistics bd number is 0!\n");
		return -EINVAL;
	}

	desc_src = kcalloc(bd_num, sizeof(struct hclge_desc), GFP_KERNEL);
	if (!desc_src)
		return -ENOMEM;

	ret  = hclge_dbg_cmd_send(hdev, desc_src, 0, bd_num,
				  HCLGE_OPC_IMP_STATS_INFO);
	if (ret) {
		kfree(desc_src);
		dev_err(&hdev->pdev->dev,
			"failed to get imp statistics, ret = %d\n", ret);
		return ret;
	}

	hclge_dbg_imp_info_data_print(desc_src, buf, len, bd_num);

	kfree(desc_src);

	return 0;
}

#define HCLGE_CMD_NCL_CONFIG_BD_NUM	5
#define HCLGE_MAX_NCL_CONFIG_LENGTH	16384

static void hclge_ncl_config_data_print(struct hclge_desc *desc, int *index,
					char *buf, int *len, int *pos)
{
#define HCLGE_CMD_DATA_NUM		6

	int offset = HCLGE_MAX_NCL_CONFIG_LENGTH - *index;
	int i, j;

	for (i = 0; i < HCLGE_CMD_NCL_CONFIG_BD_NUM; i++) {
		for (j = 0; j < HCLGE_CMD_DATA_NUM; j++) {
			if (i == 0 && j == 0)
				continue;

			*pos += scnprintf(buf + *pos, *len - *pos,
					  "0x%04x | 0x%08x\n", offset,
					  le32_to_cpu(desc[i].data[j]));

			offset += sizeof(u32);
			*index -= sizeof(u32);

			if (*index <= 0)
				return;
		}
	}
}

static int
hclge_dbg_dump_ncl_config(struct hclge_dev *hdev, char *buf, int len)
{
#define HCLGE_NCL_CONFIG_LENGTH_IN_EACH_CMD	(20 + 24 * 4)

	struct hclge_desc desc[HCLGE_CMD_NCL_CONFIG_BD_NUM];
	int bd_num = HCLGE_CMD_NCL_CONFIG_BD_NUM;
	int index = HCLGE_MAX_NCL_CONFIG_LENGTH;
	int pos = 0;
	u32 data0;
	int ret;

	pos += scnprintf(buf + pos, len - pos, "offset | data\n");

	while (index > 0) {
		data0 = HCLGE_MAX_NCL_CONFIG_LENGTH - index;
		if (index >= HCLGE_NCL_CONFIG_LENGTH_IN_EACH_CMD)
			data0 |= HCLGE_NCL_CONFIG_LENGTH_IN_EACH_CMD << 16;
		else
			data0 |= (u32)index << 16;
		ret = hclge_dbg_cmd_send(hdev, desc, data0, bd_num,
					 HCLGE_OPC_QUERY_NCL_CONFIG);
		if (ret)
			return ret;

		hclge_ncl_config_data_print(desc, &index, buf, &len, &pos);
	}

	return 0;
}

static int hclge_dbg_dump_loopback(struct hclge_dev *hdev, char *buf, int len)
{
	struct phy_device *phydev = hdev->hw.mac.phydev;
	struct hclge_config_mac_mode_cmd *req_app;
	struct hclge_common_lb_cmd *req_common;
	struct hclge_desc desc;
	u8 loopback_en;
	int pos = 0;
	int ret;

	req_app = (struct hclge_config_mac_mode_cmd *)desc.data;
	req_common = (struct hclge_common_lb_cmd *)desc.data;

	pos += scnprintf(buf + pos, len - pos, "mac id: %u\n",
			 hdev->hw.mac.mac_id);

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CONFIG_MAC_MODE, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump app loopback status, ret = %d\n", ret);
		return ret;
	}

	loopback_en = hnae3_get_bit(le32_to_cpu(req_app->txrx_pad_fcs_loop_en),
				    HCLGE_MAC_APP_LP_B);
	pos += scnprintf(buf + pos, len - pos, "app loopback: %s\n",
			 state_str[loopback_en]);

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_COMMON_LOOPBACK, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump common loopback status, ret = %d\n",
			ret);
		return ret;
	}

	loopback_en = req_common->enable & HCLGE_CMD_SERDES_SERIAL_INNER_LOOP_B;
	pos += scnprintf(buf + pos, len - pos, "serdes serial loopback: %s\n",
			 state_str[loopback_en]);

	loopback_en = req_common->enable &
			HCLGE_CMD_SERDES_PARALLEL_INNER_LOOP_B ? 1 : 0;
	pos += scnprintf(buf + pos, len - pos, "serdes parallel loopback: %s\n",
			 state_str[loopback_en]);

	if (phydev) {
		loopback_en = phydev->loopback_enabled;
		pos += scnprintf(buf + pos, len - pos, "phy loopback: %s\n",
				 state_str[loopback_en]);
	} else if (hnae3_dev_phy_imp_supported(hdev)) {
		loopback_en = req_common->enable &
			      HCLGE_CMD_GE_PHY_INNER_LOOP_B;
		pos += scnprintf(buf + pos, len - pos, "phy loopback: %s\n",
				 state_str[loopback_en]);
	}

	return 0;
}

/* hclge_dbg_dump_mac_tnl_status: print message about mac tnl interrupt
 * @hdev: pointer to struct hclge_dev
 */
static int
hclge_dbg_dump_mac_tnl_status(struct hclge_dev *hdev, char *buf, int len)
{
	struct hclge_mac_tnl_stats stats;
	unsigned long rem_nsec;
	int pos = 0;

	pos += scnprintf(buf + pos, len - pos,
			 "Recently generated mac tnl interruption:\n");

	while (kfifo_get(&hdev->mac_tnl_log, &stats)) {
		rem_nsec = do_div(stats.time, HCLGE_BILLION_NANO_SECONDS);

		pos += scnprintf(buf + pos, len - pos,
				 "[%07lu.%03lu] status = 0x%x\n",
				 (unsigned long)stats.time, rem_nsec / 1000,
				 stats.status);
	}

	return 0;
}


static const struct hclge_dbg_item mac_list_items[] = {
	{ "FUNC_ID", 2 },
	{ "MAC_ADDR", 12 },
	{ "STATE", 2 },
};

static void hclge_dbg_dump_mac_list(struct hclge_dev *hdev, char *buf, int len,
				    bool is_unicast)
{
	char data_str[ARRAY_SIZE(mac_list_items)][HCLGE_DBG_DATA_STR_LEN];
	char content[HCLGE_DBG_INFO_LEN], str_id[HCLGE_DBG_ID_LEN];
	char *result[ARRAY_SIZE(mac_list_items)];
	struct hclge_mac_node *mac_node, *tmp;
	struct hclge_vport *vport;
	struct list_head *list;
	u32 func_id;
	int pos = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(mac_list_items); i++)
		result[i] = &data_str[i][0];

	pos += scnprintf(buf + pos, len - pos, "%s MAC_LIST:\n",
			 is_unicast ? "UC" : "MC");
	hclge_dbg_fill_content(content, sizeof(content), mac_list_items,
			       NULL, ARRAY_SIZE(mac_list_items));
	pos += scnprintf(buf + pos, len - pos, "%s", content);

	for (func_id = 0; func_id < hdev->num_alloc_vport; func_id++) {
		vport = &hdev->vport[func_id];
		list = is_unicast ? &vport->uc_mac_list : &vport->mc_mac_list;
		spin_lock_bh(&vport->mac_list_lock);
		list_for_each_entry_safe(mac_node, tmp, list, node) {
			i = 0;
			result[i++] = hclge_dbg_get_func_id_str(str_id,
								func_id);
			sprintf(result[i++], "%pM", mac_node->mac_addr);
			sprintf(result[i++], "%5s",
				hclge_mac_state_str[mac_node->state]);
			hclge_dbg_fill_content(content, sizeof(content),
					       mac_list_items,
					       (const char **)result,
					       ARRAY_SIZE(mac_list_items));
			pos += scnprintf(buf + pos, len - pos, "%s", content);
		}
		spin_unlock_bh(&vport->mac_list_lock);
	}
}

static int hclge_dbg_dump_umv_info(struct hclge_dev *hdev, char *buf, int len)
{
	u8 func_num = pci_num_vf(hdev->pdev) + 1;
	struct hclge_vport *vport;
	int pos = 0;
	u8 i;

	pos += scnprintf(buf, len, "num_alloc_vport   : %u\n",
			  hdev->num_alloc_vport);
	pos += scnprintf(buf + pos, len - pos, "max_umv_size     : %u\n",
			 hdev->max_umv_size);
	pos += scnprintf(buf + pos, len - pos, "wanted_umv_size  : %u\n",
			 hdev->wanted_umv_size);
	pos += scnprintf(buf + pos, len - pos, "priv_umv_size    : %u\n",
			 hdev->priv_umv_size);

	mutex_lock(&hdev->vport_lock);
	pos += scnprintf(buf + pos, len - pos, "share_umv_size   : %u\n",
			 hdev->share_umv_size);
	for (i = 0; i < func_num; i++) {
		vport = &hdev->vport[i];
		pos += scnprintf(buf + pos, len - pos,
				 "vport(%u) used_umv_num : %u\n",
				 i, vport->used_umv_num);
	}
	mutex_unlock(&hdev->vport_lock);

	pos += scnprintf(buf + pos, len - pos, "used_mc_mac_num  : %u\n",
			 hdev->used_mc_mac_num);

	return 0;
}

static int hclge_get_vlan_rx_offload_cfg(struct hclge_dev *hdev, u8 vf_id,
					 struct hclge_dbg_vlan_cfg *vlan_cfg)
{
	struct hclge_vport_vtag_rx_cfg_cmd *req;
	struct hclge_desc desc;
	u16 bmap_index;
	u8 rx_cfg;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_VLAN_PORT_RX_CFG, true);

	req = (struct hclge_vport_vtag_rx_cfg_cmd *)desc.data;
	req->vf_offset = vf_id / HCLGE_VF_NUM_PER_CMD;
	bmap_index = vf_id % HCLGE_VF_NUM_PER_CMD / HCLGE_VF_NUM_PER_BYTE;
	req->vf_bitmap[bmap_index] = 1U << (vf_id % HCLGE_VF_NUM_PER_BYTE);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to get vport%u rxvlan cfg, ret = %d\n",
			vf_id, ret);
		return ret;
	}

	rx_cfg = req->vport_vlan_cfg;
	vlan_cfg->strip_tag1 = hnae3_get_bit(rx_cfg, HCLGE_REM_TAG1_EN_B);
	vlan_cfg->strip_tag2 = hnae3_get_bit(rx_cfg, HCLGE_REM_TAG2_EN_B);
	vlan_cfg->drop_tag1 = hnae3_get_bit(rx_cfg, HCLGE_DISCARD_TAG1_EN_B);
	vlan_cfg->drop_tag2 = hnae3_get_bit(rx_cfg, HCLGE_DISCARD_TAG2_EN_B);
	vlan_cfg->pri_only1 = hnae3_get_bit(rx_cfg, HCLGE_SHOW_TAG1_EN_B);
	vlan_cfg->pri_only2 = hnae3_get_bit(rx_cfg, HCLGE_SHOW_TAG2_EN_B);

	return 0;
}

static int hclge_get_vlan_tx_offload_cfg(struct hclge_dev *hdev, u8 vf_id,
					 struct hclge_dbg_vlan_cfg *vlan_cfg)
{
	struct hclge_vport_vtag_tx_cfg_cmd *req;
	struct hclge_desc desc;
	u16 bmap_index;
	u8 tx_cfg;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_VLAN_PORT_TX_CFG, true);
	req = (struct hclge_vport_vtag_tx_cfg_cmd *)desc.data;
	req->vf_offset = vf_id / HCLGE_VF_NUM_PER_CMD;
	bmap_index = vf_id % HCLGE_VF_NUM_PER_CMD / HCLGE_VF_NUM_PER_BYTE;
	req->vf_bitmap[bmap_index] = 1U << (vf_id % HCLGE_VF_NUM_PER_BYTE);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to get vport%u txvlan cfg, ret = %d\n",
			vf_id, ret);
		return ret;
	}

	tx_cfg = req->vport_vlan_cfg;
	vlan_cfg->pvid = le16_to_cpu(req->def_vlan_tag1);

	vlan_cfg->accept_tag1 = hnae3_get_bit(tx_cfg, HCLGE_ACCEPT_TAG1_B);
	vlan_cfg->accept_tag2 = hnae3_get_bit(tx_cfg, HCLGE_ACCEPT_TAG2_B);
	vlan_cfg->accept_untag1 = hnae3_get_bit(tx_cfg, HCLGE_ACCEPT_UNTAG1_B);
	vlan_cfg->accept_untag2 = hnae3_get_bit(tx_cfg, HCLGE_ACCEPT_UNTAG2_B);
	vlan_cfg->insert_tag1 = hnae3_get_bit(tx_cfg, HCLGE_PORT_INS_TAG1_EN_B);
	vlan_cfg->insert_tag2 = hnae3_get_bit(tx_cfg, HCLGE_PORT_INS_TAG2_EN_B);
	vlan_cfg->shift_tag = hnae3_get_bit(tx_cfg, HCLGE_TAG_SHIFT_MODE_EN_B);

	return 0;
}

static int hclge_get_vlan_filter_config_cmd(struct hclge_dev *hdev,
					    u8 vlan_type, u8 vf_id,
					    struct hclge_desc *desc)
{
	struct hclge_vlan_filter_ctrl_cmd *req;
	int ret;

	hclge_cmd_setup_basic_desc(desc, HCLGE_OPC_VLAN_FILTER_CTRL, true);
	req = (struct hclge_vlan_filter_ctrl_cmd *)desc->data;
	req->vlan_type = vlan_type;
	req->vf_id = vf_id;

	ret = hclge_cmd_send(&hdev->hw, desc, 1);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"failed to get vport%u vlan filter config, ret = %d.\n",
			vf_id, ret);

	return ret;
}

static int hclge_get_vlan_filter_state(struct hclge_dev *hdev, u8 vlan_type,
				       u8 vf_id, u8 *vlan_fe)
{
	struct hclge_vlan_filter_ctrl_cmd *req;
	struct hclge_desc desc;
	int ret;

	ret = hclge_get_vlan_filter_config_cmd(hdev, vlan_type, vf_id, &desc);
	if (ret)
		return ret;

	req = (struct hclge_vlan_filter_ctrl_cmd *)desc.data;
	*vlan_fe = req->vlan_fe;

	return 0;
}

static int hclge_get_port_vlan_filter_bypass_state(struct hclge_dev *hdev,
						   u8 vf_id, u8 *bypass_en)
{
	struct hclge_port_vlan_filter_bypass_cmd *req;
	struct hclge_desc desc;
	int ret;

	if (!test_bit(HNAE3_DEV_SUPPORT_PORT_VLAN_BYPASS_B, hdev->ae_dev->caps))
		return 0;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_PORT_VLAN_BYPASS, true);
	req = (struct hclge_port_vlan_filter_bypass_cmd *)desc.data;
	req->vf_id = vf_id;

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to get vport%u port vlan filter bypass state, ret = %d.\n",
			vf_id, ret);
		return ret;
	}

	*bypass_en = hnae3_get_bit(req->bypass_state, HCLGE_INGRESS_BYPASS_B);

	return 0;
}

static const struct hclge_dbg_item vlan_filter_items[] = {
	{ "FUNC_ID", 2 },
	{ "I_VF_VLAN_FILTER", 2 },
	{ "E_VF_VLAN_FILTER", 2 },
	{ "PORT_VLAN_FILTER_BYPASS", 0 }
};

static const struct hclge_dbg_item vlan_offload_items[] = {
	{ "FUNC_ID", 2 },
	{ "PVID", 4 },
	{ "ACCEPT_TAG1", 2 },
	{ "ACCEPT_TAG2", 2 },
	{ "ACCEPT_UNTAG1", 2 },
	{ "ACCEPT_UNTAG2", 2 },
	{ "INSERT_TAG1", 2 },
	{ "INSERT_TAG2", 2 },
	{ "SHIFT_TAG", 2 },
	{ "STRIP_TAG1", 2 },
	{ "STRIP_TAG2", 2 },
	{ "DROP_TAG1", 2 },
	{ "DROP_TAG2", 2 },
	{ "PRI_ONLY_TAG1", 2 },
	{ "PRI_ONLY_TAG2", 0 }
};

static int hclge_dbg_dump_vlan_filter_config(struct hclge_dev *hdev, char *buf,
					     int len, int *pos)
{
	char content[HCLGE_DBG_VLAN_FLTR_INFO_LEN], str_id[HCLGE_DBG_ID_LEN];
	const char *result[ARRAY_SIZE(vlan_filter_items)];
	u8 i, j, vlan_fe, bypass, ingress, egress;
	u8 func_num = pci_num_vf(hdev->pdev) + 1; /* pf and enabled vf num */
	int ret;

	ret = hclge_get_vlan_filter_state(hdev, HCLGE_FILTER_TYPE_PORT, 0,
					  &vlan_fe);
	if (ret)
		return ret;
	ingress = vlan_fe & HCLGE_FILTER_FE_NIC_INGRESS_B;
	egress = vlan_fe & HCLGE_FILTER_FE_NIC_EGRESS_B ? 1 : 0;

	*pos += scnprintf(buf, len, "I_PORT_VLAN_FILTER: %s\n",
			  state_str[ingress]);
	*pos += scnprintf(buf + *pos, len - *pos, "E_PORT_VLAN_FILTER: %s\n",
			  state_str[egress]);

	hclge_dbg_fill_content(content, sizeof(content), vlan_filter_items,
			       NULL, ARRAY_SIZE(vlan_filter_items));
	*pos += scnprintf(buf + *pos, len - *pos, "%s", content);

	for (i = 0; i < func_num; i++) {
		ret = hclge_get_vlan_filter_state(hdev, HCLGE_FILTER_TYPE_VF, i,
						  &vlan_fe);
		if (ret)
			return ret;

		ingress = vlan_fe & HCLGE_FILTER_FE_NIC_INGRESS_B;
		egress = vlan_fe & HCLGE_FILTER_FE_NIC_EGRESS_B ? 1 : 0;
		ret = hclge_get_port_vlan_filter_bypass_state(hdev, i, &bypass);
		if (ret)
			return ret;
		j = 0;
		result[j++] = hclge_dbg_get_func_id_str(str_id, i);
		result[j++] = state_str[ingress];
		result[j++] = state_str[egress];
		result[j++] =
			test_bit(HNAE3_DEV_SUPPORT_PORT_VLAN_BYPASS_B,
				 hdev->ae_dev->caps) ? state_str[bypass] : "NA";
		hclge_dbg_fill_content(content, sizeof(content),
				       vlan_filter_items, result,
				       ARRAY_SIZE(vlan_filter_items));
		*pos += scnprintf(buf + *pos, len - *pos, "%s", content);
	}
	*pos += scnprintf(buf + *pos, len - *pos, "\n");

	return 0;
}

static int hclge_dbg_dump_vlan_offload_config(struct hclge_dev *hdev, char *buf,
					      int len, int *pos)
{
	char str_id[HCLGE_DBG_ID_LEN], str_pvid[HCLGE_DBG_ID_LEN];
	const char *result[ARRAY_SIZE(vlan_offload_items)];
	char content[HCLGE_DBG_VLAN_OFFLOAD_INFO_LEN];
	u8 func_num = pci_num_vf(hdev->pdev) + 1; /* pf and enabled vf num */
	struct hclge_dbg_vlan_cfg vlan_cfg;
	int ret;
	u8 i, j;

	hclge_dbg_fill_content(content, sizeof(content), vlan_offload_items,
			       NULL, ARRAY_SIZE(vlan_offload_items));
	*pos += scnprintf(buf + *pos, len - *pos, "%s", content);

	for (i = 0; i < func_num; i++) {
		ret = hclge_get_vlan_tx_offload_cfg(hdev, i, &vlan_cfg);
		if (ret)
			return ret;

		ret = hclge_get_vlan_rx_offload_cfg(hdev, i, &vlan_cfg);
		if (ret)
			return ret;

		sprintf(str_pvid, "%u", vlan_cfg.pvid);
		j = 0;
		result[j++] = hclge_dbg_get_func_id_str(str_id, i);
		result[j++] = str_pvid;
		result[j++] = state_str[vlan_cfg.accept_tag1];
		result[j++] = state_str[vlan_cfg.accept_tag2];
		result[j++] = state_str[vlan_cfg.accept_untag1];
		result[j++] = state_str[vlan_cfg.accept_untag2];
		result[j++] = state_str[vlan_cfg.insert_tag1];
		result[j++] = state_str[vlan_cfg.insert_tag2];
		result[j++] = state_str[vlan_cfg.shift_tag];
		result[j++] = state_str[vlan_cfg.strip_tag1];
		result[j++] = state_str[vlan_cfg.strip_tag2];
		result[j++] = state_str[vlan_cfg.drop_tag1];
		result[j++] = state_str[vlan_cfg.drop_tag2];
		result[j++] = state_str[vlan_cfg.pri_only1];
		result[j++] = state_str[vlan_cfg.pri_only2];

		hclge_dbg_fill_content(content, sizeof(content),
				       vlan_offload_items, result,
				       ARRAY_SIZE(vlan_offload_items));
		*pos += scnprintf(buf + *pos, len - *pos, "%s", content);
	}

	return 0;
}

static int hclge_dbg_dump_vlan_config(struct hclge_dev *hdev, char *buf,
				      int len)
{
	int pos = 0;
	int ret;

	ret = hclge_dbg_dump_vlan_filter_config(hdev, buf, len, &pos);
	if (ret)
		return ret;

	return hclge_dbg_dump_vlan_offload_config(hdev, buf, len, &pos);
}

static int hclge_dbg_dump_ptp_info(struct hclge_dev *hdev, char *buf, int len)
{
	struct hclge_ptp *ptp = hdev->ptp;
	u32 sw_cfg = ptp->ptp_cfg;
	unsigned int tx_start;
	unsigned int last_rx;
	int pos = 0;
	u32 hw_cfg;
	int ret;

	pos += scnprintf(buf + pos, len - pos, "phc %s's debug info:\n",
			 ptp->info.name);
	pos += scnprintf(buf + pos, len - pos, "ptp enable: %s\n",
			 test_bit(HCLGE_PTP_FLAG_EN, &ptp->flags) ?
			 "yes" : "no");
	pos += scnprintf(buf + pos, len - pos, "ptp tx enable: %s\n",
			 test_bit(HCLGE_PTP_FLAG_TX_EN, &ptp->flags) ?
			 "yes" : "no");
	pos += scnprintf(buf + pos, len - pos, "ptp rx enable: %s\n",
			 test_bit(HCLGE_PTP_FLAG_RX_EN, &ptp->flags) ?
			 "yes" : "no");

	last_rx = jiffies_to_msecs(ptp->last_rx);
	pos += scnprintf(buf + pos, len - pos, "last rx time: %lu.%lu\n",
			 last_rx / MSEC_PER_SEC, last_rx % MSEC_PER_SEC);
	pos += scnprintf(buf + pos, len - pos, "rx count: %lu\n", ptp->rx_cnt);

	tx_start = jiffies_to_msecs(ptp->tx_start);
	pos += scnprintf(buf + pos, len - pos, "last tx start time: %lu.%lu\n",
			 tx_start / MSEC_PER_SEC, tx_start % MSEC_PER_SEC);
	pos += scnprintf(buf + pos, len - pos, "tx count: %lu\n", ptp->tx_cnt);
	pos += scnprintf(buf + pos, len - pos, "tx skipped count: %lu\n",
			 ptp->tx_skipped);
	pos += scnprintf(buf + pos, len - pos, "tx timeout count: %lu\n",
			 ptp->tx_timeout);
	pos += scnprintf(buf + pos, len - pos, "last tx seqid: %u\n",
			 ptp->last_tx_seqid);

	ret = hclge_ptp_cfg_qry(hdev, &hw_cfg);
	if (ret)
		return ret;

	pos += scnprintf(buf + pos, len - pos, "sw_cfg: %#x, hw_cfg: %#x\n",
			 sw_cfg, hw_cfg);

	pos += scnprintf(buf + pos, len - pos, "tx type: %d, rx filter: %d\n",
			 ptp->ts_cfg.tx_type, ptp->ts_cfg.rx_filter);

	return 0;
}

static int hclge_dbg_dump_mac_uc(struct hclge_dev *hdev, char *buf, int len)
{
	hclge_dbg_dump_mac_list(hdev, buf, len, true);

	return 0;
}

static int hclge_dbg_dump_mac_mc(struct hclge_dev *hdev, char *buf, int len)
{
	hclge_dbg_dump_mac_list(hdev, buf, len, false);

	return 0;
}

static const struct hclge_dbg_func hclge_dbg_cmd_func[] = {
	{
		.cmd = HNAE3_DBG_CMD_TM_NODES,
		.dbg_dump = hclge_dbg_dump_tm_nodes,
	},
	{
		.cmd = HNAE3_DBG_CMD_TM_PRI,
		.dbg_dump = hclge_dbg_dump_tm_pri,
	},
	{
		.cmd = HNAE3_DBG_CMD_TM_QSET,
		.dbg_dump = hclge_dbg_dump_tm_qset,
	},
	{
		.cmd = HNAE3_DBG_CMD_TM_MAP,
		.dbg_dump = hclge_dbg_dump_tm_map,
	},
	{
		.cmd = HNAE3_DBG_CMD_TM_PG,
		.dbg_dump = hclge_dbg_dump_tm_pg,
	},
	{
		.cmd = HNAE3_DBG_CMD_TM_PORT,
		.dbg_dump = hclge_dbg_dump_tm_port,
	},
	{
		.cmd = HNAE3_DBG_CMD_TC_SCH_INFO,
		.dbg_dump = hclge_dbg_dump_tc,
	},
	{
		.cmd = HNAE3_DBG_CMD_QOS_PAUSE_CFG,
		.dbg_dump = hclge_dbg_dump_qos_pause_cfg,
	},
	{
		.cmd = HNAE3_DBG_CMD_QOS_PRI_MAP,
		.dbg_dump = hclge_dbg_dump_qos_pri_map,
	},
	{
		.cmd = HNAE3_DBG_CMD_QOS_BUF_CFG,
		.dbg_dump = hclge_dbg_dump_qos_buf_cfg,
	},
	{
		.cmd = HNAE3_DBG_CMD_MAC_UC,
		.dbg_dump = hclge_dbg_dump_mac_uc,
	},
	{
		.cmd = HNAE3_DBG_CMD_MAC_MC,
		.dbg_dump = hclge_dbg_dump_mac_mc,
	},
	{
		.cmd = HNAE3_DBG_CMD_MNG_TBL,
		.dbg_dump = hclge_dbg_dump_mng_table,
	},
	{
		.cmd = HNAE3_DBG_CMD_LOOPBACK,
		.dbg_dump = hclge_dbg_dump_loopback,
	},
	{
		.cmd = HNAE3_DBG_CMD_PTP_INFO,
		.dbg_dump = hclge_dbg_dump_ptp_info,
	},
	{
		.cmd = HNAE3_DBG_CMD_INTERRUPT_INFO,
		.dbg_dump = hclge_dbg_dump_interrupt,
	},
	{
		.cmd = HNAE3_DBG_CMD_RESET_INFO,
		.dbg_dump = hclge_dbg_dump_rst_info,
	},
	{
		.cmd = HNAE3_DBG_CMD_IMP_INFO,
		.dbg_dump = hclge_dbg_get_imp_stats_info,
	},
	{
		.cmd = HNAE3_DBG_CMD_NCL_CONFIG,
		.dbg_dump = hclge_dbg_dump_ncl_config,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_BIOS_COMMON,
		.dbg_dump_reg = hclge_dbg_dump_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_SSU,
		.dbg_dump_reg = hclge_dbg_dump_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_IGU_EGU,
		.dbg_dump_reg = hclge_dbg_dump_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_RPU,
		.dbg_dump_reg = hclge_dbg_dump_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_NCSI,
		.dbg_dump_reg = hclge_dbg_dump_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_RTC,
		.dbg_dump_reg = hclge_dbg_dump_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_PPP,
		.dbg_dump_reg = hclge_dbg_dump_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_RCB,
		.dbg_dump_reg = hclge_dbg_dump_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_TQP,
		.dbg_dump_reg = hclge_dbg_dump_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_MAC,
		.dbg_dump = hclge_dbg_dump_mac,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_DCB,
		.dbg_dump = hclge_dbg_dump_dcb,
	},
	{
		.cmd = HNAE3_DBG_CMD_FD_TCAM,
		.dbg_dump = hclge_dbg_dump_fd_tcam,
	},
	{
		.cmd = HNAE3_DBG_CMD_MAC_TNL_STATUS,
		.dbg_dump = hclge_dbg_dump_mac_tnl_status,
	},
	{
		.cmd = HNAE3_DBG_CMD_SERV_INFO,
		.dbg_dump = hclge_dbg_dump_serv_info,
	},
	{
		.cmd = HNAE3_DBG_CMD_VLAN_CONFIG,
		.dbg_dump = hclge_dbg_dump_vlan_config,
	},
	{
		.cmd = HNAE3_DBG_CMD_FD_COUNTER,
		.dbg_dump = hclge_dbg_dump_fd_counter,
	},
	{
		.cmd = HNAE3_DBG_CMD_UMV_INFO,
		.dbg_dump = hclge_dbg_dump_umv_info,
	},
};

int hclge_dbg_read_cmd(struct hnae3_handle *handle, enum hnae3_dbg_cmd cmd,
		       char *buf, int len)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	const struct hclge_dbg_func *cmd_func;
	struct hclge_dev *hdev = vport->back;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(hclge_dbg_cmd_func); i++) {
		if (cmd == hclge_dbg_cmd_func[i].cmd) {
			cmd_func = &hclge_dbg_cmd_func[i];
			if (cmd_func->dbg_dump)
				return cmd_func->dbg_dump(hdev, buf, len);
			else
				return cmd_func->dbg_dump_reg(hdev, cmd, buf,
							      len);
		}
	}

	dev_err(&hdev->pdev->dev, "invalid command(%d)\n", cmd);
	return -EINVAL;
}
