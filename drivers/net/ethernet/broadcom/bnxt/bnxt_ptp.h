/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2021 Broadcom Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#ifndef BNXT_PTP_H
#define BNXT_PTP_H

#include <linux/ptp_clock_kernel.h>
#include <linux/timecounter.h>

#define BNXT_PTP_GRC_WIN	6
#define BNXT_PTP_GRC_WIN_BASE	0x6000

#define BNXT_MAX_PHC_DRIFT	31000000
#define BNXT_LO_TIMER_MASK	0x0000ffffffffUL
#define BNXT_HI_TIMER_MASK	0xffff00000000UL

#define BNXT_PTP_QTS_TIMEOUT	1000
#define BNXT_PTP_QTS_TX_ENABLES	(PORT_TS_QUERY_REQ_ENABLES_PTP_SEQ_ID |	\
				 PORT_TS_QUERY_REQ_ENABLES_TS_REQ_TIMEOUT | \
				 PORT_TS_QUERY_REQ_ENABLES_PTP_HDR_OFFSET)

struct pps_pin {
	u8 event;
	u8 usage;
	u8 state;
};

#define TSIO_PIN_VALID(pin) ((pin) < (BNXT_MAX_TSIO_PINS))

#define EVENT_DATA2_PPS_EVENT_TYPE(data2)				\
	((data2) & ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA2_EVENT_TYPE)

#define EVENT_DATA2_PPS_PIN_NUM(data2)					\
	(((data2) &							\
	  ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA2_PIN_NUMBER_MASK) >>\
	 ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA2_PIN_NUMBER_SFT)

#define BNXT_DATA2_UPPER_MSK						\
	ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA2_PPS_TIMESTAMP_UPPER_MASK

#define BNXT_DATA2_UPPER_SFT						\
	(32 -								\
	 ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA2_PPS_TIMESTAMP_UPPER_SFT)

#define BNXT_DATA1_LOWER_MSK						\
	ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA1_PPS_TIMESTAMP_LOWER_MASK

#define BNXT_DATA1_LOWER_SFT						\
	  ASYNC_EVENT_CMPL_PPS_TIMESTAMP_EVENT_DATA1_PPS_TIMESTAMP_LOWER_SFT

#define EVENT_PPS_TS(data2, data1)					\
	(((u64)((data2) & BNXT_DATA2_UPPER_MSK) << BNXT_DATA2_UPPER_SFT) |\
	 (((data1) & BNXT_DATA1_LOWER_MSK) >> BNXT_DATA1_LOWER_SFT))

#define BNXT_PPS_PIN_DISABLE	0
#define BNXT_PPS_PIN_ENABLE	1
#define BNXT_PPS_PIN_NONE	0
#define BNXT_PPS_PIN_PPS_IN	1
#define BNXT_PPS_PIN_PPS_OUT	2
#define BNXT_PPS_PIN_SYNC_IN	3
#define BNXT_PPS_PIN_SYNC_OUT	4

#define BNXT_PPS_EVENT_INTERNAL	1
#define BNXT_PPS_EVENT_EXTERNAL	2

struct bnxt_pps {
	u8 num_pins;
#define BNXT_MAX_TSIO_PINS	4
	struct pps_pin pins[BNXT_MAX_TSIO_PINS];
};

struct bnxt_ptp_cfg {
	struct ptp_clock_info	ptp_info;
	struct ptp_clock	*ptp_clock;
	struct cyclecounter	cc;
	struct timecounter	tc;
	struct bnxt_pps		pps_info;
	/* serialize timecounter access */
	spinlock_t		ptp_lock;
	struct sk_buff		*tx_skb;
	u64			current_time;
	u64			old_time;
	unsigned long		next_period;
	unsigned long		next_overflow_check;
	/* 48-bit PHC overflows in 78 hours.  Check overflow every 19 hours. */
	#define BNXT_PHC_OVERFLOW_PERIOD	(19 * 3600 * HZ)

	u16			tx_seqid;
	u16			tx_hdr_off;
	struct bnxt		*bp;
	atomic_t		tx_avail;
#define BNXT_MAX_TX_TS	1
	u16			rxctl;
#define BNXT_PTP_MSG_SYNC			(1 << 0)
#define BNXT_PTP_MSG_DELAY_REQ			(1 << 1)
#define BNXT_PTP_MSG_PDELAY_REQ			(1 << 2)
#define BNXT_PTP_MSG_PDELAY_RESP		(1 << 3)
#define BNXT_PTP_MSG_FOLLOW_UP			(1 << 8)
#define BNXT_PTP_MSG_DELAY_RESP			(1 << 9)
#define BNXT_PTP_MSG_PDELAY_RESP_FOLLOW_UP	(1 << 10)
#define BNXT_PTP_MSG_ANNOUNCE			(1 << 11)
#define BNXT_PTP_MSG_SIGNALING			(1 << 12)
#define BNXT_PTP_MSG_MANAGEMENT			(1 << 13)
#define BNXT_PTP_MSG_EVENTS		(BNXT_PTP_MSG_SYNC |		\
					 BNXT_PTP_MSG_DELAY_REQ |	\
					 BNXT_PTP_MSG_PDELAY_REQ |	\
					 BNXT_PTP_MSG_PDELAY_RESP)
	u8			tx_tstamp_en:1;
	int			rx_filter;

	u32			refclk_regs[2];
	u32			refclk_mapped_regs[2];
};

#if BITS_PER_LONG == 32
#define BNXT_READ_TIME64(ptp, dst, src)		\
do {						\
	spin_lock_bh(&(ptp)->ptp_lock);		\
	(dst) = (src);				\
	spin_unlock_bh(&(ptp)->ptp_lock);	\
} while (0)
#else
#define BNXT_READ_TIME64(ptp, dst, src)		\
	((dst) = READ_ONCE(src))
#endif

int bnxt_ptp_parse(struct sk_buff *skb, u16 *seq_id, u16 *hdr_off);
void bnxt_ptp_pps_event(struct bnxt *bp, u32 data1, u32 data2);
void bnxt_ptp_reapply_pps(struct bnxt *bp);
int bnxt_hwtstamp_set(struct net_device *dev, struct ifreq *ifr);
int bnxt_hwtstamp_get(struct net_device *dev, struct ifreq *ifr);
int bnxt_get_tx_ts_p5(struct bnxt *bp, struct sk_buff *skb);
int bnxt_get_rx_ts_p5(struct bnxt *bp, u64 *ts, u32 pkt_ts);
int bnxt_ptp_init(struct bnxt *bp);
void bnxt_ptp_clear(struct bnxt *bp);
#endif
