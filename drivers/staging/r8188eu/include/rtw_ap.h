/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2007 - 2012 Realtek Corporation. */

#ifndef __RTW_AP_H_
#define __RTW_AP_H_

#include "osdep_service.h"
#include "drv_types.h"

/* external function */
void rtw_indicate_sta_assoc_event(struct adapter *padapter,
				  struct sta_info *psta);
void rtw_indicate_sta_disassoc_event(struct adapter *padapter,
				     struct sta_info *psta);
void init_mlme_ap_info(struct adapter *padapter);
void free_mlme_ap_info(struct adapter *padapter);
void update_beacon(struct adapter *padapter, u8 ie_id,
		   u8 *oui, u8 tx);
void add_RATid(struct adapter *padapter, struct sta_info *psta,
	       u8 rssi_level);
void expire_timeout_chk(struct adapter *padapter);
void update_sta_info_apmode(struct adapter *padapter, struct sta_info *psta);
void rtw_ap_restore_network(struct adapter *padapter);

void associated_clients_update(struct adapter *padapter, u8 updated);
void bss_cap_update_on_sta_join(struct adapter *padapter, struct sta_info *psta);
u8 bss_cap_update_on_sta_leave(struct adapter *padapter, struct sta_info *psta);
void sta_info_update(struct adapter *padapter, struct sta_info *psta);
u8 ap_free_sta(struct adapter *padapter, struct sta_info *psta,
	       bool active, u16 reason);
int rtw_sta_flush(struct adapter *padapter);
void start_ap_mode(struct adapter *padapter);
void stop_ap_mode(struct adapter *padapter);
void update_bmc_sta(struct adapter *padapter);

#endif
