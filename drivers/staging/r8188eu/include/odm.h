/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2007 - 2011 Realtek Corporation. */

#ifndef	__HALDMOUTSRC_H__
#define __HALDMOUTSRC_H__

/*  Add for AP/ADSLpseudo DM structuer requirement. */
/*  We need to remove to other position??? */
struct rtl8192cd_priv {
	u8		temp;
};

struct rtw_dig {
	u8		Dig_Enable_Flag;
	u8		Dig_Ext_Port_Stage;

	int		RssiLowThresh;
	int		RssiHighThresh;

	u32		FALowThresh;
	u32		FAHighThresh;

	u8		CurSTAConnectState;
	u8		PreSTAConnectState;
	u8		CurMultiSTAConnectState;

	u8		PreIGValue;
	u8		CurIGValue;
	u8		BackupIGValue;

	s8		BackoffVal;
	s8		BackoffVal_range_max;
	s8		BackoffVal_range_min;
	u8		rx_gain_range_max;
	u8		rx_gain_range_min;
	u8		Rssi_val_min;

	u8		PreCCK_CCAThres;
	u8		CurCCK_CCAThres;
	u8		PreCCKPDState;
	u8		CurCCKPDState;

	u8		LargeFAHit;
	u8		ForbiddenIGI;
	u32		Recover_cnt;

	u8		DIG_Dynamic_MIN_0;
	u8		DIG_Dynamic_MIN_1;
	bool		bMediaConnect_0;
	bool		bMediaConnect_1;

	u32		AntDiv_RSSI_max;
	u32		RSSI_max;
};

struct rtl_ps {
	u8		pre_cca_state;
	u8		cur_cca_state;

	u8		pre_rf_state;
	u8		cur_rf_state;

	int		rssi_val_min;

	u8		initialize;
	u32		reg_874;
	u32		reg_c70;
	u32		reg_85c;
	u32		reg_a74;

};

struct false_alarm_stats {
	u32	Cnt_Parity_Fail;
	u32	Cnt_Rate_Illegal;
	u32	Cnt_Crc8_fail;
	u32	Cnt_Mcs_fail;
	u32	Cnt_Ofdm_fail;
	u32	Cnt_Cck_fail;
	u32	Cnt_all;
	u32	Cnt_Fast_Fsync;
	u32	Cnt_SB_Search_fail;
	u32	Cnt_OFDM_CCA;
	u32	Cnt_CCK_CCA;
	u32	Cnt_CCA_all;
	u32	Cnt_BW_USC;	/* Gary */
	u32	Cnt_BW_LSC;	/* Gary */
};

struct dyn_primary_cca {
	u8		pri_cca_flag;
	u8		intf_flag;
	u8		intf_type;
	u8		dup_rts_flag;
	u8		monitor_flag;
};

struct rx_hpc {
	u8		RXHP_flag;
	u8		PSD_func_trigger;
	u8		PSD_bitmap_RXHP[80];
	u8		Pre_IGI;
	u8		Cur_IGI;
	u8		Pre_pw_th;
	u8		Cur_pw_th;
	bool		First_time_enter;
	bool		RXHP_enable;
	u8		TP_Mode;
	struct timer_list PSDTimer;
};

#define ODM_ASSOCIATE_ENTRY_NUM	32 /*  Max size of AsocEntry[]. */

struct sw_ant_switch {
	u8	try_flag;
	s32	PreRSSI;
	u8	CurAntenna;
	u8	PreAntenna;
	u8	RSSI_Trying;
	u8	TestMode;
	u8	bTriggerAntennaSwitch;
	u8	SelectAntennaMap;
	u8	RSSI_target;

	/*  Before link Antenna Switch check */
	u8	SWAS_NoLink_State;
	u32	SWAS_NoLink_BK_Reg860;

	s32	RSSI_sum_A;
	s32	RSSI_sum_B;
	s32	RSSI_cnt_A;
	s32	RSSI_cnt_B;
	u64	lastTxOkCnt;
	u64	lastRxOkCnt;
	u64	TXByteCnt_A;
	u64	TXByteCnt_B;
	u64	RXByteCnt_A;
	u64	RXByteCnt_B;
	u8	TrafficLoad;
	struct timer_list SwAntennaSwitchTimer;
	u8	TxAnt[ODM_ASSOCIATE_ENTRY_NUM];
	u8	TargetSTA;
	u8	RxIdleAnt;
};

struct edca_turbo {
	bool bCurrentTurboEDCA;
	bool bIsCurRDLState;
	u32	prv_traffic_idx; /*  edca turbo */
};

struct odm_rate_adapt {
	u8	HighRSSIThresh;	/*  if RSSI > HighRSSIThresh	=> RATRState is DM_RATR_STA_HIGH */
	u8	LowRSSIThresh;	/*  if RSSI <= LowRSSIThresh	=> RATRState is DM_RATR_STA_LOW */
	u8	RATRState;	/*  Current RSSI level, DM_RATR_STA_HIGH/DM_RATR_STA_MIDDLE/DM_RATR_STA_LOW */
	u32	LastRATR;	/*  RATR Register Content */
};

#define IQK_MAC_REG_NUM		4
#define IQK_ADDA_REG_NUM	16
#define IQK_BB_REG_NUM		9
#define HP_THERMAL_NUM		8

#define AVG_THERMAL_NUM		8
#define IQK_Matrix_REG_NUM	8

struct odm_phy_dbg_info {
	/* ODM Write,debug info */
	s8	RxSNRdB[MAX_PATH_NUM_92CS];
	u64	NumQryPhyStatus;
	u64	NumQryPhyStatusCCK;
	u64	NumQryPhyStatusOFDM;
	/* Others */
	s32	RxEVM[MAX_PATH_NUM_92CS];
};

struct odm_per_pkt_info {
	s8	Rate;
	u8	StationID;
	bool	bPacketMatchBSSID;
	bool	bPacketToSelf;
	bool	bPacketBeacon;
};

struct odm_mac_status_info {
	u8	test;
};

enum odm_ability {
	/*  BB Team */
	ODM_DIG			= 0x00000001,
	ODM_HIGH_POWER		= 0x00000002,
	ODM_CCK_CCA_TH		= 0x00000004,
	ODM_FA_STATISTICS	= 0x00000008,
	ODM_RAMASK		= 0x00000010,
	ODM_RSSI_MONITOR	= 0x00000020,
	ODM_SW_ANTDIV		= 0x00000040,
	ODM_HW_ANTDIV		= 0x00000080,
	ODM_BB_PWRSV		= 0x00000100,
	ODM_2TPATHDIV		= 0x00000200,
	ODM_1TPATHDIV		= 0x00000400,
	ODM_PSD2AFH		= 0x00000800
};

/*  2011/20/20 MH For MP driver RT_WLAN_STA =  struct sta_info */
/*  Please declare below ODM relative info in your STA info structure. */

struct odm_sta_info {
	/*  Driver Write */
	bool	bUsed;		/*  record the sta status link or not? */
	u8	IOTPeer;	/*  Enum value.	HT_IOT_PEER_E */

	/*  ODM Write */
	/* 1 PHY_STATUS_INFO */
	u8	RSSI_Path[4];		/*  */
	u8	RSSI_Ave;
	u8	RXEVM[4];
	u8	RXSNR[4];
};

/*  2011/10/20 MH Define Common info enum for all team. */

enum odm_common_info_def {
	/*  Fixed value: */

	/* HOOK BEFORE REG INIT----------- */
	ODM_CMNINFO_ABILITY,		/* ODM_ABILITY_E */
	ODM_CMNINFO_MP_TEST_CHIP,
	/* HOOK BEFORE REG INIT-----------  */

	/*  Dynamic value: */
/*  POINTER REFERENCE-----------  */
	ODM_CMNINFO_TX_UNI,
	ODM_CMNINFO_RX_UNI,
	ODM_CMNINFO_WM_MODE,		/*  ODM_WIRELESS_MODE_E */
	ODM_CMNINFO_SEC_CHNL_OFFSET,	/*  ODM_SEC_CHNL_OFFSET_E */
	ODM_CMNINFO_SEC_MODE,		/*  ODM_SECURITY_E */
	ODM_CMNINFO_BW,			/*  ODM_BW_E */
	ODM_CMNINFO_CHNL,

	ODM_CMNINFO_SCAN,
	ODM_CMNINFO_POWER_SAVING,
	ODM_CMNINFO_NET_CLOSED,
/*  POINTER REFERENCE----------- */

/* CALL BY VALUE------------- */
	ODM_CMNINFO_WIFI_DIRECT,
	ODM_CMNINFO_WIFI_DISPLAY,
	ODM_CMNINFO_LINK,
	ODM_CMNINFO_RSSI_MIN,
	ODM_CMNINFO_RF_ANTENNA_TYPE,		/*  u8 */
/* CALL BY VALUE-------------*/
};

/*  2011/10/20 MH Define ODM support ability.  ODM_CMNINFO_ABILITY */

enum odm_ability_def {
	/*  BB ODM section BIT 0-15 */
	ODM_BB_DIG			= BIT(0),
	ODM_BB_RA_MASK			= BIT(1),
	ODM_BB_DYNAMIC_TXPWR		= BIT(2),
	ODM_BB_FA_CNT			= BIT(3),
	ODM_BB_RSSI_MONITOR		= BIT(4),
	ODM_BB_CCK_PD			= BIT(5),
	ODM_BB_ANT_DIV			= BIT(6),
	ODM_BB_PWR_SAVE			= BIT(7),
	ODM_BB_PWR_TRA			= BIT(8),
	ODM_BB_RATE_ADAPTIVE		= BIT(9),
	ODM_BB_PATH_DIV			= BIT(10),
	ODM_BB_PSD			= BIT(11),
	ODM_BB_RXHP			= BIT(12),

	/*  MAC DM section BIT 16-23 */
	ODM_MAC_EDCA_TURBO		= BIT(16),
	ODM_MAC_EARLY_MODE		= BIT(17),

	/*  RF ODM section BIT 24-31 */
	ODM_RF_TX_PWR_TRACK		= BIT(24),
	ODM_RF_RX_GAIN_TRACK		= BIT(25),
	ODM_RF_CALIBRATION		= BIT(26),
};

# define ODM_ITRF_USB 0x2

/*  ODM_CMNINFO_OP_MODE */
enum odm_operation_mode {
	ODM_NO_LINK		= BIT(0),
	ODM_LINK		= BIT(1),
	ODM_SCAN		= BIT(2),
	ODM_POWERSAVE		= BIT(3),
	ODM_AP_MODE		= BIT(4),
	ODM_CLIENT_MODE		= BIT(5),
	ODM_AD_HOC		= BIT(6),
	ODM_WIFI_DIRECT		= BIT(7),
	ODM_WIFI_DISPLAY	= BIT(8),
};

/*  ODM_CMNINFO_WM_MODE */
enum odm_wireless_mode {
	ODM_WM_UNKNOW	= 0x0,
	ODM_WM_B	= BIT(0),
	ODM_WM_G	= BIT(1),
	ODM_WM_N24G	= BIT(3),
	ODM_WM_AUTO	= BIT(5),
};

/*  ODM_CMNINFO_BW */
enum odm_bw {
	ODM_BW20M		= 0,
	ODM_BW40M		= 1,
};

struct odm_ra_info {
	u8 RateID;
	u32 RateMask;
	u32 RAUseRate;
	u8 RateSGI;
	u8 RssiStaRA;
	u8 PreRssiStaRA;
	u8 SGIEnable;
	u8 DecisionRate;
	u8 PreRate;
	u8 HighestRate;
	u8 LowestRate;
	u32 NscUp;
	u32 NscDown;
	u16 RTY[5];
	u32 TOTAL;
	u16 DROP;
	u8 Active;
	u16 RptTime;
	u8 RAWaitingCounter;
	u8 RAPendingCounter;
	u8 PTActive;	/*  on or off */
	u8 PTTryState;	/*  0 trying state, 1 for decision state */
	u8 PTStage;	/*  0~6 */
	u8 PTStopCount;	/* Stop PT counter */
	u8 PTPreRate;	/*  if rate change do PT */
	u8 PTPreRssi;	/*  if RSSI change 5% do PT */
	u8 PTModeSS;	/*  decide whitch rate should do PT */
	u8 RAstage;	/*  StageRA, decide how many times RA will be done
			 * between PT */
	u8 PTSmoothFactor;
};

struct ijk_matrix_regs_set {
	bool	bIQKDone;
	s32	Value[1][IQK_Matrix_REG_NUM];
};

struct odm_rf_cal {
	/* for tx power tracking */
	u32	RegA24; /*  for TempCCK */
	s32	RegE94;
	s32	RegE9C;
	s32	RegEB4;
	s32	RegEBC;

	u8	TXPowercount;
	bool	bTXPowerTrackingInit;
	bool	bTXPowerTracking;
	u8	TxPowerTrackControl; /* for mp mode, turn off txpwrtracking
				      * as default */
	u8	TM_Trigger;
	u8	InternalPA5G[2];	/* pathA / pathB */

	u8	ThermalMeter[2];    /* ThermalMeter, index 0 for RFIC0,
				     * and 1 for RFIC1 */
	u8	ThermalValue;
	u8	ThermalValue_LCK;
	u8	ThermalValue_IQK;
	u8	ThermalValue_DPK;
	u8	ThermalValue_AVG[AVG_THERMAL_NUM];
	u8	ThermalValue_AVG_index;
	u8	ThermalValue_RxGain;
	u8	ThermalValue_Crystal;
	u8	ThermalValue_DPKstore;
	u8	ThermalValue_DPKtrack;
	bool	TxPowerTrackingInProgress;
	bool	bDPKenable;

	bool	bReloadtxpowerindex;
	u8	bRfPiEnable;
	u32	TXPowerTrackingCallbackCnt; /* cosa add for debug */

	u8	bCCKinCH14;
	u8	CCK_index;
	u8	OFDM_index[2];
	bool bDoneTxpower;

	u8	ThermalValue_HP[HP_THERMAL_NUM];
	u8	ThermalValue_HP_index;
	struct ijk_matrix_regs_set IQKMatrixRegSetting;

	u8	Delta_IQK;
	u8	Delta_LCK;

	/* for IQK */
	u32	RegC04;
	u32	Reg874;
	u32	RegC08;
	u32	RegB68;
	u32	RegB6C;
	u32	Reg870;
	u32	Reg860;
	u32	Reg864;

	bool	bIQKInitialized;
	bool	bAntennaDetected;
	u32	ADDA_backup[IQK_ADDA_REG_NUM];
	u32	IQK_MAC_backup[IQK_MAC_REG_NUM];
	u32	IQK_BB_backup_recover[9];
	u32	IQK_BB_backup[IQK_BB_REG_NUM];

	/* for APK */
	u32	APKoutput[2][2]; /* path A/B; output1_1a/output1_2a */
	u8	bAPKdone;
	u8	bAPKThermalMeterIgnore;
	u8	bDPdone;
	u8	bDPPathAOK;
	u8	bDPPathBOK;
};

/*  ODM Dynamic common info value definition */

struct fast_ant_train {
	u8	Bssid[6];
	u8	antsel_rx_keep_0;
	u8	antsel_rx_keep_1;
	u8	antsel_rx_keep_2;
	u32	antSumRSSI[7];
	u32	antRSSIcnt[7];
	u32	antAveRSSI[7];
	u8	FAT_State;
	u32	TrainIdx;
	u8	antsel_a[ODM_ASSOCIATE_ENTRY_NUM];
	u8	antsel_b[ODM_ASSOCIATE_ENTRY_NUM];
	u8	antsel_c[ODM_ASSOCIATE_ENTRY_NUM];
	u32	MainAnt_Sum[ODM_ASSOCIATE_ENTRY_NUM];
	u32	AuxAnt_Sum[ODM_ASSOCIATE_ENTRY_NUM];
	u32	MainAnt_Cnt[ODM_ASSOCIATE_ENTRY_NUM];
	u32	AuxAnt_Cnt[ODM_ASSOCIATE_ENTRY_NUM];
	u8	RxIdleAnt;
	bool	bBecomeLinked;
};

enum fat_state {
	FAT_NORMAL_STATE		= 0,
	FAT_TRAINING_STATE		= 1,
};

enum ant_div_type {
	NO_ANTDIV			= 0xFF,
	CG_TRX_HW_ANTDIV		= 0x01,
	CGCS_RX_HW_ANTDIV		= 0x02,
	FIXED_HW_ANTDIV			= 0x03,
	CG_TRX_SMART_ANTDIV		= 0x04,
};

/* Copy from SD4 defined structure. We use to support PHY DM integration. */
struct odm_dm_struct {
	/* 	Add for different team use temporarily */
	struct adapter *Adapter;	/*  For CE/NIC team */
	struct rtl8192cd_priv *priv;	/*  For AP/ADSL team */
	/*  WHen you use above pointers, they must be initialized. */
	bool	odm_ready;

	struct rtl8192cd_priv *fake_priv;

/*  ODM HANDLE, DRIVER NEEDS NOT TO HOOK------ */
	bool	bCckHighPower;
	u8	RFPathRxEnable;		/*  ODM_CMNINFO_RFPATH_ENABLE */
	u8	ControlChannel;
/*  ODM HANDLE, DRIVER NEEDS NOT TO HOOK------ */

/* 1  COMMON INFORMATION */
	/*  Init Value */
/* HOOK BEFORE REG INIT----------- */
	/*  ODM Support Ability DIG/RATR/TX_PWR_TRACK/ �K�K = 1/2/3/�K */
	u32	SupportAbility;

	u32	BK_SupportAbility;
	u8	AntDivType;
/* HOOK BEFORE REG INIT----------- */

	/*  Dynamic Value */
/*  POINTER REFERENCE----------- */

	u8	u8_temp;
	bool	bool_temp;
	struct adapter *adapter_temp;

	/* TX Unicast byte count */
	u64	*pNumTxBytesUnicast;
	/* RX Unicast byte count */
	u64	*pNumRxBytesUnicast;
	/*  Wireless mode B/G/A/N = BIT(0)/BIT(1)/BIT(2)/BIT(3) */
	u8	*pWirelessMode; /* ODM_WIRELESS_MODE_E */
	/*  Secondary channel offset don't_care/below/above = 0/1/2 */
	u8	*pSecChOffset;
	/*  Security mode Open/WEP/AES/TKIP = 0/1/2/3 */
	u8	*pSecurity;
	/*  BW info 20M/40M/80M = 0/1/2 */
	u8	*pBandWidth;
	/*  Central channel location Ch1/Ch2/.... */
	u8	*pChannel;	/* central channel number */
	/*  Common info for 92D DMSP */

	bool	*pbGetValueFromOtherMac;
	struct adapter **pBuddyAdapter;
	bool	*pbMasterOfDMSP; /* MAC0: master, MAC1: slave */
	/*  Common info for Status */
	bool	*pbScanInProcess;
	bool	*pbPowerSaving;
	/*  CCA Path 2-path/path-A/path-B = 0/1/2; using ODM_CCA_PATH_E. */
	u8	*pOnePathCCA;
	/* pMgntInfo->AntennaTest */
	u8	*pAntennaTest;
	bool	*pbNet_closed;
/*  POINTER REFERENCE----------- */
	/*  */
/* CALL BY VALUE------------- */
	bool	bWIFI_Direct;
	bool	bWIFI_Display;
	bool	bLinked;
	u8	RSSI_Min;
	u8	InterfaceIndex; /*  Add for 92D  dual MAC: 0--Mac0 1--Mac1 */
	bool	bIsMPChip;
	bool	bOneEntryOnly;
	/*  Common info for BTDM */
	bool	bBtDisabled;	/*  BT is disabled */
	bool	bBtHsOperation;	/*  BT HS mode is under progress */
	u8	btHsDigVal;	/*  use BT rssi to decide the DIG value */
	bool	bBtDisableEdcaTurbo;/* Under some condition, don't enable the
				     * EDCA Turbo */
	bool	bBtBusy;			/*  BT is busy. */
/* CALL BY VALUE------------- */

	/* 2 Define STA info. */
	/*  _ODM_STA_INFO */
	/*  For MP, we need to reduce one array pointer for default port.?? */
	struct sta_info *pODM_StaInfo[ODM_ASSOCIATE_ENTRY_NUM];

	u16	CurrminRptTime;
	struct odm_ra_info RAInfo[ODM_ASSOCIATE_ENTRY_NUM]; /* Use MacID as
			* array index. STA MacID=0,
			* VWiFi Client MacID={1, ODM_ASSOCIATE_ENTRY_NUM-1} */

	/*  Latest packet phy info (ODM write) */
	struct odm_phy_dbg_info PhyDbgInfo;

	/*  Latest packet phy info (ODM write) */
	struct odm_mac_status_info *pMacInfo;

	/*  Different Team independt structure?? */

	/* ODM Structure */
	struct fast_ant_train DM_FatTable;
	struct rtw_dig	DM_DigTable;
	struct rtl_ps	DM_PSTable;
	struct dyn_primary_cca DM_PriCCA;
	struct rx_hpc	DM_RXHP_Table;
	struct false_alarm_stats FalseAlmCnt;
	struct false_alarm_stats FlaseAlmCntBuddyAdapter;
	struct sw_ant_switch DM_SWAT_Table;
	bool		RSSI_test;

	struct edca_turbo DM_EDCA_Table;
	u32		WMMEDCA_BE;
	/*  Copy from SD4 structure */
	/*  */
	/*  ================================================== */
	/*  */

	bool	*pbDriverStopped;
	bool	*pbDriverIsGoingToPnpSetPowerSleep;
	bool	*pinit_adpt_in_progress;

	/* PSD */
	bool	bUserAssignLevel;
	struct timer_list PSDTimer;
	u8	RSSI_BT;			/* come from BT */
	bool	bPSDinProcess;
	bool	bDMInitialGainEnable;

	struct odm_rate_adapt RateAdaptive;

	struct odm_rf_cal RFCalibrateInfo;

	/*  TX power tracking */
	u8	BbSwingIdxOfdm;
	u8	BbSwingIdxOfdmCurrent;
	u8	BbSwingIdxOfdmBase;
	bool	BbSwingFlagOfdm;
	u8	BbSwingIdxCck;
	u8	BbSwingIdxCckCurrent;
	u8	BbSwingIdxCckBase;
	bool	BbSwingFlagCck;
	/*  ODM system resource. */

	/*  ODM relative time. */
	struct timer_list PathDivSwitchTimer;
	/* 2011.09.27 add for Path Diversity */
	struct timer_list CCKPathDiversityTimer;
	struct timer_list FastAntTrainingTimer;
};		/*  DM_Dynamic_Mechanism_Structure */

enum odm_bb_config_type {
    CONFIG_BB_PHY_REG,
    CONFIG_BB_AGC_TAB,
    CONFIG_BB_AGC_TAB_2G,
    CONFIG_BB_PHY_REG_PG,
};

#define		DM_DIG_THRESH_HIGH	40
#define		DM_DIG_THRESH_LOW	35

#define		DM_false_ALARM_THRESH_LOW	400
#define		DM_false_ALARM_THRESH_HIGH	1000

#define		DM_DIG_MAX_NIC			0x4e
#define		DM_DIG_MIN_NIC			0x1e /* 0x22/0x1c */

#define		DM_DIG_MAX_AP			0x32

/* vivi 92c&92d has different definition, 20110504 */
/* this is for 92c */
#define		DM_DIG_FA_TH0			0x200/* 0x20 */
#define		DM_DIG_FA_TH1			0x300/* 0x100 */
#define		DM_DIG_FA_TH2			0x400/* 0x200 */

#define		DM_DIG_BACKOFF_MAX		12
#define		DM_DIG_BACKOFF_MIN		-4
#define		DM_DIG_BACKOFF_DEFAULT		10

/* 3=========================================================== */
/* 3 Rate Adaptive */
/* 3=========================================================== */
#define		DM_RATR_STA_INIT		0
#define		DM_RATR_STA_HIGH		1
#define		DM_RATR_STA_MIDDLE		2
#define		DM_RATR_STA_LOW			3

/* 3=========================================================== */
/* 3 BB Power Save */
/* 3=========================================================== */

enum dm_1r_cca {
	CCA_1R = 0,
	CCA_2R = 1,
	CCA_MAX = 2,
};

enum dm_rf {
	RF_Save = 0,
	RF_Normal = 1,
	RF_MAX = 2,
};

/* 3=========================================================== */
/* 3 Antenna Diversity */
/* 3=========================================================== */
enum dm_swas {
	Antenna_A = 1,
	Antenna_B = 2,
	Antenna_MAX = 3,
};

/*  Extern Global Variables. */
#define	OFDM_TABLE_SIZE_92D	43
#define	CCK_TABLE_SIZE		33

extern	u32 OFDMSwingTable[OFDM_TABLE_SIZE_92D];
extern	u8 CCKSwingTable_Ch1_Ch13[CCK_TABLE_SIZE][8];
extern	u8 CCKSwingTable_Ch14 [CCK_TABLE_SIZE][8];

/*  check Sta pointer valid or not */
#define IS_STA_VALID(pSta)		(pSta)

void ODM_Write_DIG(struct odm_dm_struct *pDM_Odm, u8 CurrentIGI);
void ODM_Write_CCK_CCA_Thres(struct odm_dm_struct *pDM_Odm, u8 CurCCK_CCAThres);

void ODM_SetAntenna(struct odm_dm_struct *pDM_Odm, u8 Antenna);

void ODM_RF_Saving(struct odm_dm_struct *pDM_Odm, u8 bForceInNormal);

void ODM_TXPowerTrackingCheck(struct odm_dm_struct *pDM_Odm);

bool ODM_RAStateCheck(struct odm_dm_struct *pDM_Odm, s32 RSSI,
		      bool bForceUpdate, u8 *pRATRState);

u32 ODM_Get_Rate_Bitmap(struct odm_dm_struct *pDM_Odm, u32 macid,
			u32 ra_mask, u8 rssi_level);

void ODM_DMInit(struct odm_dm_struct *pDM_Odm);

void ODM_DMWatchdog(struct odm_dm_struct *pDM_Odm);

void ODM_CmnInfoInit(struct odm_dm_struct *pDM_Odm,
		     enum odm_common_info_def CmnInfo, u32 Value);

void ODM_CmnInfoHook(struct odm_dm_struct *pDM_Odm,
		     enum odm_common_info_def CmnInfo, void *pValue);

void ODM_CmnInfoUpdate(struct odm_dm_struct *pDM_Odm, u32 CmnInfo, u64 Value);

#endif
