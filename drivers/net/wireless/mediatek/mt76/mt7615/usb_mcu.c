// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 MediaTek Inc.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Sean Wang <sean.wang@mediatek.com>
 */
#include <linux/kernel.h>
#include <linux/module.h>

#include "mt7615.h"
#include "mac.h"
#include "mcu.h"
#include "regs.h"

static int
mt7663u_mcu_send_message(struct mt76_dev *mdev, struct sk_buff *skb,
			 int cmd, bool wait_resp)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	int ret, seq, ep;

	mutex_lock(&mdev->mcu.mutex);

	mt7615_mcu_fill_msg(dev, skb, cmd, &seq);
	if (cmd != MCU_CMD_FW_SCATTER)
		ep = MT_EP_OUT_INBAND_CMD;
	else
		ep = MT_EP_OUT_AC_BE;

	ret = mt76u_skb_dma_info(skb, skb->len);
	if (ret < 0)
		goto out;

	ret = mt76u_bulk_msg(&dev->mt76, skb->data, skb->len, NULL,
			     1000, ep);
	dev_kfree_skb(skb);
	if (ret < 0)
		goto out;

	if (wait_resp)
		ret = mt7615_mcu_wait_response(dev, cmd, seq);

out:
	mutex_unlock(&mdev->mcu.mutex);

	return ret;
}

int mt7663u_mcu_init(struct mt7615_dev *dev)
{
	static const struct mt76_mcu_ops mt7663u_mcu_ops = {
		.headroom = MT_USB_HDR_SIZE + sizeof(struct mt7615_mcu_txd),
		.tailroom = MT_USB_TAIL_SIZE,
		.mcu_skb_send_msg = mt7663u_mcu_send_message,
		.mcu_send_msg = mt7615_mcu_msg_send,
		.mcu_restart = mt7615_mcu_restart,
	};
	int ret;

	dev->mt76.mcu_ops = &mt7663u_mcu_ops,

	mt76_set(dev, MT_UDMA_TX_QSEL, MT_FW_DL_EN);

	if (test_and_clear_bit(MT76_STATE_POWER_OFF, &dev->mphy.state)) {
		mt7615_mcu_restart(&dev->mt76);
		if (!mt76_poll_msec(dev, MT_CONN_ON_MISC,
				    MT_TOP_MISC2_FW_PWR_ON, 0, 500))
			return -EIO;

		ret = mt76u_vendor_request(&dev->mt76, MT_VEND_POWER_ON,
					   USB_DIR_OUT | USB_TYPE_VENDOR,
					   0x0, 0x1, NULL, 0);
		if (ret)
			return ret;

		if (!mt76_poll_msec(dev, MT_CONN_ON_MISC,
				    MT_TOP_MISC2_FW_PWR_ON,
				    FW_STATE_PWR_ON << 1, 500)) {
			dev_err(dev->mt76.dev, "Timeout for power on\n");
			return -EIO;
		}
	}

	ret = __mt7663_load_firmware(dev);
	if (ret)
		return ret;

	mt76_clear(dev, MT_UDMA_TX_QSEL, MT_FW_DL_EN);
	set_bit(MT76_STATE_MCU_RUNNING, &dev->mphy.state);

	return 0;
}
