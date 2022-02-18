/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2007 - 2012 Realtek Corporation. */

#ifndef __RTW_PWRCTRL_H_
#define __RTW_PWRCTRL_H_

#include "osdep_service.h"
#include "drv_types.h"

#define XMIT_ALIVE	BIT(0)
#define RECV_ALIVE	BIT(1)
#define CMD_ALIVE	BIT(2)
#define EVT_ALIVE	BIT(3)

enum power_mgnt {
	PS_MODE_ACTIVE = 0,
	PS_MODE_MIN,
	PS_MODE_MAX,
	PS_MODE_DTIM,
	PS_MODE_VOIP,
	PS_MODE_UAPSD_WMM,
	PS_MODE_UAPSD,
	PS_MODE_IBSS,
	PS_MODE_WWLAN,
	PM_Radio_Off,
	PM_Card_Disable,
	PS_MODE_NUM
};

#define LPS_DELAY_TIME	1*HZ /*  1 sec */

/*  RF state. */
enum rt_rf_power_state {
	rf_on,		/*  RF is on after RFSleep or RFOff */
	rf_sleep,	/*  802.11 Power Save mode */
	rf_off,		/*  HW/SW Radio OFF or Inactive Power Save */
	/* Add the new RF state above this line===== */
	rf_max
};

enum { /*  for ips_mode */
	IPS_NONE = 0,
	IPS_NORMAL,
	IPS_LEVEL_2,
};

struct pwrctrl_priv {
	struct mutex lock; /* Mutex used to protect struct pwrctrl_priv */

	u8	pwr_mode;
	u8	smart_ps;
	u8	bcn_ant_mode;

	u32	alives;
	struct work_struct cpwm_event;
	u8	bpower_saving;

	u8	reg_rfoff;
	u8	reg_pdnmode; /* powerdown mode */
	u32	rfoff_reason;

	/* RF OFF Level */
	u32	cur_ps_level;
	u32	reg_rfps_level;
	uint	ips_enter_cnts;
	uint	ips_leave_cnts;

	u8	ips_mode;
	u8	ips_mode_req;	/*  used to accept the mode setting request,
				 *  will update to ipsmode later */
	uint bips_processing;
	u32 ips_deny_time; /* will deny IPS when system time less than this */
	u8 ps_processing; /* temp used to mark whether in rtw_ps_processor */

	u8	bLeisurePs;
	u8	LpsIdleCount;
	u8	power_mgnt;
	u8	bFwCurrentInPSMode;
	u32	DelayLPSLastTimeStamp;
	s32		pnp_current_pwr_state;
	u8		pnp_bstop_trx;

	u8		bInternalAutoSuspend;
	u8		bInSuspend;
	u8		bSupportRemoteWakeup;
	struct timer_list pwr_state_check_timer;
	int		pwr_state_check_interval;
	u8		pwr_state_check_cnts;

	int		ps_flag;

	enum rt_rf_power_state	rf_pwrstate;/* cur power state */
	enum rt_rf_power_state	change_rfpwrstate;

	u8		wepkeymask;
	u8		bHWPowerdown;/* if support hw power down */
	u8		bkeepfwalive;
};

#define rtw_get_ips_mode_req(pwrctrlpriv) \
	(pwrctrlpriv)->ips_mode_req

#define rtw_ips_mode_req(pwrctrlpriv, ips_mode) \
	((pwrctrlpriv)->ips_mode_req = (ips_mode))

#define RTW_PWR_STATE_CHK_INTERVAL 2000

#define _rtw_set_pwr_state_check_timer(pwrctrlpriv, ms) \
	do { \
		_set_timer(&(pwrctrlpriv)->pwr_state_check_timer, (ms)); \
	} while (0)

#define rtw_set_pwr_state_check_timer(pwrctrl)			\
	_rtw_set_pwr_state_check_timer((pwrctrl),		\
				       (pwrctrl)->pwr_state_check_interval)

void rtw_init_pwrctrl_priv(struct adapter *adapter);

void rtw_set_ps_mode(struct adapter *adapter, u8 ps_mode, u8 smart_ps,
		     u8 bcn_ant_mode);
void LeaveAllPowerSaveMode(struct adapter *adapter);
void ips_enter(struct adapter *padapter);
int ips_leave(struct adapter *padapter);

void rtw_ps_processor(struct adapter *padapter);

s32 LPS_RF_ON_check(struct adapter *adapter, u32 delay_ms);
void LPS_Enter(struct adapter *adapter);
void LPS_Leave(struct adapter *adapter);

int _rtw_pwr_wakeup(struct adapter *adapter, u32 ips_defer_ms,
		    const char *caller);
#define rtw_pwr_wakeup(adapter)						\
	 _rtw_pwr_wakeup(adapter, RTW_PWR_STATE_CHK_INTERVAL, __func__)
int rtw_pm_set_ips(struct adapter *adapter, u8 mode);
int rtw_pm_set_lps(struct adapter *adapter, u8 mode);

#endif  /* __RTL871X_PWRCTRL_H_ */
