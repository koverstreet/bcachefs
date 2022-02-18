// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019-2020, The Linux Foundation. All rights reserved.
 */

#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pinctrl/pinctrl.h>

#include "pinctrl-msm.h"

#define FUNCTION(fname)					\
	[msm_mux_##fname] = {				\
		.name = #fname,				\
		.groups = fname##_groups,		\
		.ngroups = ARRAY_SIZE(fname##_groups),	\
	}

#define REG_SIZE 0x1000

#define PINGROUP(id, f1, f2, f3, f4, f5, f6, f7, f8, f9)	\
	{						\
		.name = "gpio" #id,			\
		.pins = gpio##id##_pins,		\
		.npins = (unsigned int)ARRAY_SIZE(gpio##id##_pins),	\
		.funcs = (int[]){			\
			msm_mux_gpio, /* gpio mode */	\
			msm_mux_##f1,			\
			msm_mux_##f2,			\
			msm_mux_##f3,			\
			msm_mux_##f4,			\
			msm_mux_##f5,			\
			msm_mux_##f6,			\
			msm_mux_##f7,			\
			msm_mux_##f8,			\
			msm_mux_##f9			\
		},					\
		.nfuncs = 10,				\
		.ctl_reg = REG_SIZE * id,		\
		.io_reg = 0x4 + REG_SIZE * id,		\
		.intr_cfg_reg = 0x8 + REG_SIZE * id,	\
		.intr_status_reg = 0xc + REG_SIZE * id,	\
		.intr_target_reg = 0x8 + REG_SIZE * id,	\
		.mux_bit = 2,			\
		.pull_bit = 0,			\
		.drv_bit = 6,			\
		.oe_bit = 9,			\
		.in_bit = 0,			\
		.out_bit = 1,			\
		.intr_enable_bit = 0,		\
		.intr_status_bit = 0,		\
		.intr_target_bit = 5,		\
		.intr_target_kpss_val = 3,	\
		.intr_raw_status_bit = 4,	\
		.intr_polarity_bit = 1,		\
		.intr_detection_bit = 2,	\
		.intr_detection_width = 2,	\
	}

#define SDC_QDSD_PINGROUP(pg_name, ctl, pull, drv)	\
	{					        \
		.name = #pg_name,			\
		.pins = pg_name##_pins,			\
		.npins = (unsigned int)ARRAY_SIZE(pg_name##_pins),	\
		.ctl_reg = ctl,				\
		.io_reg = 0,				\
		.intr_cfg_reg = 0,			\
		.intr_status_reg = 0,			\
		.intr_target_reg = 0,			\
		.mux_bit = -1,				\
		.pull_bit = pull,			\
		.drv_bit = drv,				\
		.oe_bit = -1,				\
		.in_bit = -1,				\
		.out_bit = -1,				\
		.intr_enable_bit = -1,			\
		.intr_status_bit = -1,			\
		.intr_target_bit = -1,			\
		.intr_raw_status_bit = -1,		\
		.intr_polarity_bit = -1,		\
		.intr_detection_bit = -1,		\
		.intr_detection_width = -1,		\
	}

#define UFS_RESET(pg_name, offset)				\
	{					        \
		.name = #pg_name,			\
		.pins = pg_name##_pins,			\
		.npins = (unsigned int)ARRAY_SIZE(pg_name##_pins),	\
		.ctl_reg = offset,			\
		.io_reg = offset + 0x4,			\
		.intr_cfg_reg = 0,			\
		.intr_status_reg = 0,			\
		.intr_target_reg = 0,			\
		.mux_bit = -1,				\
		.pull_bit = 3,				\
		.drv_bit = 0,				\
		.oe_bit = -1,				\
		.in_bit = -1,				\
		.out_bit = 0,				\
		.intr_enable_bit = -1,			\
		.intr_status_bit = -1,			\
		.intr_target_bit = -1,			\
		.intr_raw_status_bit = -1,		\
		.intr_polarity_bit = -1,		\
		.intr_detection_bit = -1,		\
		.intr_detection_width = -1,		\
	}
static const struct pinctrl_pin_desc qcm2290_pins[] = {
	PINCTRL_PIN(0, "GPIO_0"),
	PINCTRL_PIN(1, "GPIO_1"),
	PINCTRL_PIN(2, "GPIO_2"),
	PINCTRL_PIN(3, "GPIO_3"),
	PINCTRL_PIN(4, "GPIO_4"),
	PINCTRL_PIN(5, "GPIO_5"),
	PINCTRL_PIN(6, "GPIO_6"),
	PINCTRL_PIN(7, "GPIO_7"),
	PINCTRL_PIN(8, "GPIO_8"),
	PINCTRL_PIN(9, "GPIO_9"),
	PINCTRL_PIN(10, "GPIO_10"),
	PINCTRL_PIN(11, "GPIO_11"),
	PINCTRL_PIN(12, "GPIO_12"),
	PINCTRL_PIN(13, "GPIO_13"),
	PINCTRL_PIN(14, "GPIO_14"),
	PINCTRL_PIN(15, "GPIO_15"),
	PINCTRL_PIN(16, "GPIO_16"),
	PINCTRL_PIN(17, "GPIO_17"),
	PINCTRL_PIN(18, "GPIO_18"),
	PINCTRL_PIN(19, "GPIO_19"),
	PINCTRL_PIN(20, "GPIO_20"),
	PINCTRL_PIN(21, "GPIO_21"),
	PINCTRL_PIN(22, "GPIO_22"),
	PINCTRL_PIN(23, "GPIO_23"),
	PINCTRL_PIN(24, "GPIO_24"),
	PINCTRL_PIN(25, "GPIO_25"),
	PINCTRL_PIN(26, "GPIO_26"),
	PINCTRL_PIN(27, "GPIO_27"),
	PINCTRL_PIN(28, "GPIO_28"),
	PINCTRL_PIN(29, "GPIO_29"),
	PINCTRL_PIN(30, "GPIO_30"),
	PINCTRL_PIN(31, "GPIO_31"),
	PINCTRL_PIN(32, "GPIO_32"),
	PINCTRL_PIN(33, "GPIO_33"),
	PINCTRL_PIN(34, "GPIO_34"),
	PINCTRL_PIN(35, "GPIO_35"),
	PINCTRL_PIN(36, "GPIO_36"),
	PINCTRL_PIN(37, "GPIO_37"),
	PINCTRL_PIN(38, "GPIO_38"),
	PINCTRL_PIN(39, "GPIO_39"),
	PINCTRL_PIN(40, "GPIO_40"),
	PINCTRL_PIN(41, "GPIO_41"),
	PINCTRL_PIN(42, "GPIO_42"),
	PINCTRL_PIN(43, "GPIO_43"),
	PINCTRL_PIN(44, "GPIO_44"),
	PINCTRL_PIN(45, "GPIO_45"),
	PINCTRL_PIN(46, "GPIO_46"),
	PINCTRL_PIN(47, "GPIO_47"),
	PINCTRL_PIN(48, "GPIO_48"),
	PINCTRL_PIN(49, "GPIO_49"),
	PINCTRL_PIN(50, "GPIO_50"),
	PINCTRL_PIN(51, "GPIO_51"),
	PINCTRL_PIN(52, "GPIO_52"),
	PINCTRL_PIN(53, "GPIO_53"),
	PINCTRL_PIN(54, "GPIO_54"),
	PINCTRL_PIN(55, "GPIO_55"),
	PINCTRL_PIN(56, "GPIO_56"),
	PINCTRL_PIN(57, "GPIO_57"),
	PINCTRL_PIN(58, "GPIO_58"),
	PINCTRL_PIN(59, "GPIO_59"),
	PINCTRL_PIN(60, "GPIO_60"),
	PINCTRL_PIN(61, "GPIO_61"),
	PINCTRL_PIN(62, "GPIO_62"),
	PINCTRL_PIN(63, "GPIO_63"),
	PINCTRL_PIN(64, "GPIO_64"),
	PINCTRL_PIN(69, "GPIO_69"),
	PINCTRL_PIN(70, "GPIO_70"),
	PINCTRL_PIN(71, "GPIO_71"),
	PINCTRL_PIN(72, "GPIO_72"),
	PINCTRL_PIN(73, "GPIO_73"),
	PINCTRL_PIN(74, "GPIO_74"),
	PINCTRL_PIN(75, "GPIO_75"),
	PINCTRL_PIN(76, "GPIO_76"),
	PINCTRL_PIN(77, "GPIO_77"),
	PINCTRL_PIN(78, "GPIO_78"),
	PINCTRL_PIN(79, "GPIO_79"),
	PINCTRL_PIN(80, "GPIO_80"),
	PINCTRL_PIN(81, "GPIO_81"),
	PINCTRL_PIN(82, "GPIO_82"),
	PINCTRL_PIN(86, "GPIO_86"),
	PINCTRL_PIN(87, "GPIO_87"),
	PINCTRL_PIN(88, "GPIO_88"),
	PINCTRL_PIN(89, "GPIO_89"),
	PINCTRL_PIN(90, "GPIO_90"),
	PINCTRL_PIN(91, "GPIO_91"),
	PINCTRL_PIN(94, "GPIO_94"),
	PINCTRL_PIN(95, "GPIO_95"),
	PINCTRL_PIN(96, "GPIO_96"),
	PINCTRL_PIN(97, "GPIO_97"),
	PINCTRL_PIN(98, "GPIO_98"),
	PINCTRL_PIN(99, "GPIO_99"),
	PINCTRL_PIN(100, "GPIO_100"),
	PINCTRL_PIN(101, "GPIO_101"),
	PINCTRL_PIN(102, "GPIO_102"),
	PINCTRL_PIN(103, "GPIO_103"),
	PINCTRL_PIN(104, "GPIO_104"),
	PINCTRL_PIN(105, "GPIO_105"),
	PINCTRL_PIN(106, "GPIO_106"),
	PINCTRL_PIN(107, "GPIO_107"),
	PINCTRL_PIN(108, "GPIO_108"),
	PINCTRL_PIN(109, "GPIO_109"),
	PINCTRL_PIN(110, "GPIO_110"),
	PINCTRL_PIN(111, "GPIO_111"),
	PINCTRL_PIN(112, "GPIO_112"),
	PINCTRL_PIN(113, "GPIO_113"),
	PINCTRL_PIN(114, "GPIO_114"),
	PINCTRL_PIN(115, "GPIO_115"),
	PINCTRL_PIN(116, "GPIO_116"),
	PINCTRL_PIN(117, "GPIO_117"),
	PINCTRL_PIN(118, "GPIO_118"),
	PINCTRL_PIN(119, "GPIO_119"),
	PINCTRL_PIN(120, "GPIO_120"),
	PINCTRL_PIN(121, "GPIO_121"),
	PINCTRL_PIN(122, "GPIO_122"),
	PINCTRL_PIN(123, "GPIO_123"),
	PINCTRL_PIN(124, "GPIO_124"),
	PINCTRL_PIN(125, "GPIO_125"),
	PINCTRL_PIN(126, "GPIO_126"),
	PINCTRL_PIN(127, "SDC1_RCLK"),
	PINCTRL_PIN(128, "SDC1_CLK"),
	PINCTRL_PIN(129, "SDC1_CMD"),
	PINCTRL_PIN(130, "SDC1_DATA"),
	PINCTRL_PIN(131, "SDC2_CLK"),
	PINCTRL_PIN(132, "SDC2_CMD"),
	PINCTRL_PIN(133, "SDC2_DATA"),
};

#define DECLARE_MSM_GPIO_PINS(pin) \
	static const unsigned int gpio##pin##_pins[] = { pin }
DECLARE_MSM_GPIO_PINS(0);
DECLARE_MSM_GPIO_PINS(1);
DECLARE_MSM_GPIO_PINS(2);
DECLARE_MSM_GPIO_PINS(3);
DECLARE_MSM_GPIO_PINS(4);
DECLARE_MSM_GPIO_PINS(5);
DECLARE_MSM_GPIO_PINS(6);
DECLARE_MSM_GPIO_PINS(7);
DECLARE_MSM_GPIO_PINS(8);
DECLARE_MSM_GPIO_PINS(9);
DECLARE_MSM_GPIO_PINS(10);
DECLARE_MSM_GPIO_PINS(11);
DECLARE_MSM_GPIO_PINS(12);
DECLARE_MSM_GPIO_PINS(13);
DECLARE_MSM_GPIO_PINS(14);
DECLARE_MSM_GPIO_PINS(15);
DECLARE_MSM_GPIO_PINS(16);
DECLARE_MSM_GPIO_PINS(17);
DECLARE_MSM_GPIO_PINS(18);
DECLARE_MSM_GPIO_PINS(19);
DECLARE_MSM_GPIO_PINS(20);
DECLARE_MSM_GPIO_PINS(21);
DECLARE_MSM_GPIO_PINS(22);
DECLARE_MSM_GPIO_PINS(23);
DECLARE_MSM_GPIO_PINS(24);
DECLARE_MSM_GPIO_PINS(25);
DECLARE_MSM_GPIO_PINS(26);
DECLARE_MSM_GPIO_PINS(27);
DECLARE_MSM_GPIO_PINS(28);
DECLARE_MSM_GPIO_PINS(29);
DECLARE_MSM_GPIO_PINS(30);
DECLARE_MSM_GPIO_PINS(31);
DECLARE_MSM_GPIO_PINS(32);
DECLARE_MSM_GPIO_PINS(33);
DECLARE_MSM_GPIO_PINS(34);
DECLARE_MSM_GPIO_PINS(35);
DECLARE_MSM_GPIO_PINS(36);
DECLARE_MSM_GPIO_PINS(37);
DECLARE_MSM_GPIO_PINS(38);
DECLARE_MSM_GPIO_PINS(39);
DECLARE_MSM_GPIO_PINS(40);
DECLARE_MSM_GPIO_PINS(41);
DECLARE_MSM_GPIO_PINS(42);
DECLARE_MSM_GPIO_PINS(43);
DECLARE_MSM_GPIO_PINS(44);
DECLARE_MSM_GPIO_PINS(45);
DECLARE_MSM_GPIO_PINS(46);
DECLARE_MSM_GPIO_PINS(47);
DECLARE_MSM_GPIO_PINS(48);
DECLARE_MSM_GPIO_PINS(49);
DECLARE_MSM_GPIO_PINS(50);
DECLARE_MSM_GPIO_PINS(51);
DECLARE_MSM_GPIO_PINS(52);
DECLARE_MSM_GPIO_PINS(53);
DECLARE_MSM_GPIO_PINS(54);
DECLARE_MSM_GPIO_PINS(55);
DECLARE_MSM_GPIO_PINS(56);
DECLARE_MSM_GPIO_PINS(57);
DECLARE_MSM_GPIO_PINS(58);
DECLARE_MSM_GPIO_PINS(59);
DECLARE_MSM_GPIO_PINS(60);
DECLARE_MSM_GPIO_PINS(61);
DECLARE_MSM_GPIO_PINS(62);
DECLARE_MSM_GPIO_PINS(63);
DECLARE_MSM_GPIO_PINS(64);
DECLARE_MSM_GPIO_PINS(65);
DECLARE_MSM_GPIO_PINS(66);
DECLARE_MSM_GPIO_PINS(67);
DECLARE_MSM_GPIO_PINS(68);
DECLARE_MSM_GPIO_PINS(69);
DECLARE_MSM_GPIO_PINS(70);
DECLARE_MSM_GPIO_PINS(71);
DECLARE_MSM_GPIO_PINS(72);
DECLARE_MSM_GPIO_PINS(73);
DECLARE_MSM_GPIO_PINS(74);
DECLARE_MSM_GPIO_PINS(75);
DECLARE_MSM_GPIO_PINS(76);
DECLARE_MSM_GPIO_PINS(77);
DECLARE_MSM_GPIO_PINS(78);
DECLARE_MSM_GPIO_PINS(79);
DECLARE_MSM_GPIO_PINS(80);
DECLARE_MSM_GPIO_PINS(81);
DECLARE_MSM_GPIO_PINS(82);
DECLARE_MSM_GPIO_PINS(83);
DECLARE_MSM_GPIO_PINS(84);
DECLARE_MSM_GPIO_PINS(85);
DECLARE_MSM_GPIO_PINS(86);
DECLARE_MSM_GPIO_PINS(87);
DECLARE_MSM_GPIO_PINS(88);
DECLARE_MSM_GPIO_PINS(89);
DECLARE_MSM_GPIO_PINS(90);
DECLARE_MSM_GPIO_PINS(91);
DECLARE_MSM_GPIO_PINS(92);
DECLARE_MSM_GPIO_PINS(93);
DECLARE_MSM_GPIO_PINS(94);
DECLARE_MSM_GPIO_PINS(95);
DECLARE_MSM_GPIO_PINS(96);
DECLARE_MSM_GPIO_PINS(97);
DECLARE_MSM_GPIO_PINS(98);
DECLARE_MSM_GPIO_PINS(99);
DECLARE_MSM_GPIO_PINS(100);
DECLARE_MSM_GPIO_PINS(101);
DECLARE_MSM_GPIO_PINS(102);
DECLARE_MSM_GPIO_PINS(103);
DECLARE_MSM_GPIO_PINS(104);
DECLARE_MSM_GPIO_PINS(105);
DECLARE_MSM_GPIO_PINS(106);
DECLARE_MSM_GPIO_PINS(107);
DECLARE_MSM_GPIO_PINS(108);
DECLARE_MSM_GPIO_PINS(109);
DECLARE_MSM_GPIO_PINS(110);
DECLARE_MSM_GPIO_PINS(111);
DECLARE_MSM_GPIO_PINS(112);
DECLARE_MSM_GPIO_PINS(113);
DECLARE_MSM_GPIO_PINS(114);
DECLARE_MSM_GPIO_PINS(115);
DECLARE_MSM_GPIO_PINS(116);
DECLARE_MSM_GPIO_PINS(117);
DECLARE_MSM_GPIO_PINS(118);
DECLARE_MSM_GPIO_PINS(119);
DECLARE_MSM_GPIO_PINS(120);
DECLARE_MSM_GPIO_PINS(121);
DECLARE_MSM_GPIO_PINS(122);
DECLARE_MSM_GPIO_PINS(123);
DECLARE_MSM_GPIO_PINS(124);
DECLARE_MSM_GPIO_PINS(125);
DECLARE_MSM_GPIO_PINS(126);

static const unsigned int sdc1_rclk_pins[] = { 127 };
static const unsigned int sdc1_clk_pins[] = { 128 };
static const unsigned int sdc1_cmd_pins[] = { 129 };
static const unsigned int sdc1_data_pins[] = { 130 };
static const unsigned int sdc2_clk_pins[] = { 131 };
static const unsigned int sdc2_cmd_pins[] = { 132 };
static const unsigned int sdc2_data_pins[] = { 133 };

enum qcm2290_functions {
	msm_mux_adsp_ext,
	msm_mux_agera_pll,
	msm_mux_atest,
	msm_mux_cam_mclk,
	msm_mux_cci_async,
	msm_mux_cci_i2c,
	msm_mux_cci_timer0,
	msm_mux_cci_timer1,
	msm_mux_cci_timer2,
	msm_mux_cci_timer3,
	msm_mux_char_exec,
	msm_mux_cri_trng,
	msm_mux_cri_trng0,
	msm_mux_cri_trng1,
	msm_mux_dac_calib,
	msm_mux_dbg_out,
	msm_mux_ddr_bist,
	msm_mux_ddr_pxi0,
	msm_mux_ddr_pxi1,
	msm_mux_ddr_pxi2,
	msm_mux_ddr_pxi3,
	msm_mux_gcc_gp1,
	msm_mux_gcc_gp2,
	msm_mux_gcc_gp3,
	msm_mux_gpio,
	msm_mux_gp_pdm0,
	msm_mux_gp_pdm1,
	msm_mux_gp_pdm2,
	msm_mux_gsm0_tx,
	msm_mux_gsm1_tx,
	msm_mux_jitter_bist,
	msm_mux_mdp_vsync,
	msm_mux_mdp_vsync_out_0,
	msm_mux_mdp_vsync_out_1,
	msm_mux_mpm_pwr,
	msm_mux_mss_lte,
	msm_mux_m_voc,
	msm_mux_nav_gpio,
	msm_mux_pa_indicator,
	msm_mux_pbs0,
	msm_mux_pbs1,
	msm_mux_pbs2,
	msm_mux_pbs3,
	msm_mux_pbs4,
	msm_mux_pbs5,
	msm_mux_pbs6,
	msm_mux_pbs7,
	msm_mux_pbs8,
	msm_mux_pbs9,
	msm_mux_pbs10,
	msm_mux_pbs11,
	msm_mux_pbs12,
	msm_mux_pbs13,
	msm_mux_pbs14,
	msm_mux_pbs15,
	msm_mux_pbs_out,
	msm_mux_phase_flag,
	msm_mux_pll_bist,
	msm_mux_pll_bypassnl,
	msm_mux_pll_reset,
	msm_mux_prng_rosc,
	msm_mux_pwm_0,
	msm_mux_pwm_1,
	msm_mux_pwm_2,
	msm_mux_pwm_3,
	msm_mux_pwm_4,
	msm_mux_pwm_5,
	msm_mux_pwm_6,
	msm_mux_pwm_7,
	msm_mux_pwm_8,
	msm_mux_pwm_9,
	msm_mux_qdss_cti,
	msm_mux_qdss_gpio,
	msm_mux_qup0,
	msm_mux_qup1,
	msm_mux_qup2,
	msm_mux_qup3,
	msm_mux_qup4,
	msm_mux_qup5,
	msm_mux_sdc1_tb,
	msm_mux_sdc2_tb,
	msm_mux_sd_write,
	msm_mux_ssbi_wtr1,
	msm_mux_tgu_ch0,
	msm_mux_tgu_ch1,
	msm_mux_tgu_ch2,
	msm_mux_tgu_ch3,
	msm_mux_tsense_pwm,
	msm_mux_uim1_clk,
	msm_mux_uim1_data,
	msm_mux_uim1_present,
	msm_mux_uim1_reset,
	msm_mux_uim2_clk,
	msm_mux_uim2_data,
	msm_mux_uim2_present,
	msm_mux_uim2_reset,
	msm_mux_usb_phy,
	msm_mux_vfr_1,
	msm_mux_vsense_trigger,
	msm_mux_wlan1_adc0,
	msm_mux_wlan1_adc1,
	msm_mux__,
};

static const char * const qup0_groups[] = {
	"gpio0", "gpio1", "gpio2", "gpio3", "gpio82", "gpio86",
};
static const char * const gpio_groups[] = {
	"gpio0", "gpio1", "gpio2", "gpio3", "gpio4", "gpio5", "gpio6", "gpio7",
	"gpio8", "gpio9", "gpio10", "gpio11", "gpio12", "gpio13", "gpio14",
	"gpio15", "gpio16", "gpio17", "gpio18", "gpio19", "gpio20", "gpio21",
	"gpio22", "gpio23", "gpio24", "gpio25", "gpio26", "gpio27", "gpio28",
	"gpio29", "gpio30", "gpio31", "gpio32", "gpio33", "gpio34", "gpio35",
	"gpio36", "gpio37", "gpio38", "gpio39", "gpio40", "gpio41", "gpio42",
	"gpio43", "gpio44", "gpio45", "gpio46", "gpio47", "gpio48", "gpio49",
	"gpio50", "gpio51", "gpio52", "gpio53", "gpio54", "gpio55", "gpio56",
	"gpio57", "gpio58", "gpio59", "gpio60", "gpio61", "gpio62", "gpio63",
	"gpio64", "gpio65", "gpio66", "gpio67", "gpio68", "gpio69", "gpio70",
	"gpio71", "gpio72", "gpio73", "gpio74", "gpio75", "gpio76", "gpio77",
	"gpio78", "gpio79", "gpio80", "gpio81", "gpio82", "gpio83", "gpio84",
	"gpio85", "gpio86", "gpio87", "gpio88", "gpio89", "gpio90", "gpio91",
	"gpio92", "gpio93", "gpio94", "gpio95", "gpio96", "gpio97", "gpio98",
	"gpio99", "gpio100", "gpio101", "gpio102", "gpio103", "gpio104",
	"gpio105", "gpio106", "gpio107", "gpio108", "gpio109", "gpio110",
	"gpio111", "gpio112", "gpio113", "gpio114", "gpio115", "gpio116",
	"gpio117", "gpio118", "gpio119", "gpio120", "gpio121", "gpio122",
	"gpio123", "gpio124", "gpio125", "gpio126",
};
static const char * const ddr_bist_groups[] = {
	"gpio0", "gpio1", "gpio2", "gpio3",
};
static const char * const phase_flag_groups[] = {
	"gpio0", "gpio1", "gpio2", "gpio3", "gpio4", "gpio5", "gpio6",
	"gpio14", "gpio15", "gpio16", "gpio17", "gpio22", "gpio23", "gpio24",
	"gpio25", "gpio26", "gpio29", "gpio30", "gpio31", "gpio32", "gpio33",
	"gpio35", "gpio36", "gpio43", "gpio44", "gpio45", "gpio63", "gpio64",
	"gpio102", "gpio103", "gpio104", "gpio105",
};
static const char * const qdss_gpio_groups[] = {
	"gpio0", "gpio1", "gpio2", "gpio3", "gpio8", "gpio9", "gpio10",
	"gpio11", "gpio14", "gpio15", "gpio16", "gpio17", "gpio18", "gpio19",
	"gpio20", "gpio21", "gpio22", "gpio23", "gpio24", "gpio25", "gpio26",
	"gpio47", "gpio48", "gpio69", "gpio70", "gpio87", "gpio90", "gpio91",
	"gpio94", "gpio95", "gpio104", "gpio105", "gpio106", "gpio107",
	"gpio109", "gpio110",
};
static const char * const atest_groups[] = {
	"gpio0", "gpio1", "gpio2", "gpio3", "gpio4", "gpio5", "gpio6",
	"gpio22", "gpio23", "gpio24", "gpio25", "gpio26", "gpio29", "gpio30",
	"gpio31", "gpio32", "gpio33", "gpio86", "gpio89", "gpio100", "gpio101",
};
static const char * const mpm_pwr_groups[] = {
	"gpio1",
};
static const char * const m_voc_groups[] = {
	"gpio0",
};
static const char * const dac_calib_groups[] = {
	"gpio2",
	"gpio3",
	"gpio4",
	"gpio5",
	"gpio6",
	"gpio14",
	"gpio15",
	"gpio16",
	"gpio17",
	"gpio22",
	"gpio23",
	"gpio24",
	"gpio25",
	"gpio26",
	"gpio29",
	"gpio30",
	"gpio31",
	"gpio32",
	"gpio33",
	"gpio80",
	"gpio81",
	"gpio82",
	"gpio102",
	"gpio103",
	"gpio104",
	"gpio105",
};
static const char * const qup1_groups[] = {
	"gpio4", "gpio5", "gpio69", "gpio70",
};
static const char * const cri_trng0_groups[] = {
	"gpio4",
};
static const char * const cri_trng1_groups[] = {
	"gpio5",
};
static const char * const qup2_groups[] = {
	"gpio6", "gpio7", "gpio71", "gpio80",
};
static const char * const qup3_groups[] = {
	"gpio8", "gpio9", "gpio10", "gpio11",
};
static const char * const pbs_out_groups[] = {
	"gpio8", "gpio9", "gpio52",
};
static const char * const pll_bist_groups[] = {
	"gpio8", "gpio9",
};
static const char * const tsense_pwm_groups[] = {
	"gpio8",
};
static const char * const agera_pll_groups[] = {
	"gpio10", "gpio11",
};
static const char * const pbs0_groups[] = {
	"gpio10",
};
static const char * const pbs1_groups[] = {
	"gpio11",
};
static const char * const qup4_groups[] = {
	"gpio12", "gpio13", "gpio96", "gpio97",
};
static const char * const tgu_ch0_groups[] = {
	"gpio12",
};
static const char * const tgu_ch1_groups[] = {
	"gpio13",
};
static const char * const qup5_groups[] = {
	"gpio14", "gpio15", "gpio16", "gpio17",
};
static const char * const tgu_ch2_groups[] = {
	"gpio14",
};
static const char * const tgu_ch3_groups[] = {
	"gpio15",
};
static const char * const sdc2_tb_groups[] = {
	"gpio18",
};
static const char * const cri_trng_groups[] = {
	"gpio18",
};
static const char * const pbs2_groups[] = {
	"gpio18",
};
static const char * const pwm_0_groups[] = {
	"gpio18",
};
static const char * const sdc1_tb_groups[] = {
	"gpio19",
};
static const char * const pbs3_groups[] = {
	"gpio19",
};
static const char * const cam_mclk_groups[] = {
	"gpio20", "gpio21", "gpio27", "gpio28",
};
static const char * const pbs4_groups[] = {
	"gpio20",
};
static const char * const adsp_ext_groups[] = {
	"gpio21",
};
static const char * const pbs5_groups[] = {
	"gpio21",
};
static const char * const cci_i2c_groups[] = {
	"gpio22", "gpio23", "gpio29", "gpio30",
};
static const char * const prng_rosc_groups[] = {
	"gpio22", "gpio23",
};
static const char * const pbs6_groups[] = {
	"gpio22",
};
static const char * const pbs7_groups[] = {
	"gpio23",
};
static const char * const cci_timer1_groups[] = {
	"gpio24",
};
static const char * const gcc_gp1_groups[] = {
	"gpio24", "gpio86",
};
static const char * const pbs8_groups[] = {
	"gpio24",
};
static const char * const cci_async_groups[] = {
	"gpio25",
};
static const char * const cci_timer0_groups[] = {
	"gpio25",
};
static const char * const pbs9_groups[] = {
	"gpio25",
};
static const char * const pbs10_groups[] = {
	"gpio26",
};
static const char * const vsense_trigger_groups[] = {
	"gpio26",
};
static const char * const qdss_cti_groups[] = {
	"gpio27", "gpio28", "gpio72", "gpio73", "gpio96", "gpio97",
};
static const char * const cci_timer2_groups[] = {
	"gpio28",
};
static const char * const pwm_1_groups[] = {
	"gpio28",
};
static const char * const gp_pdm0_groups[] = {
	"gpio31", "gpio95",
};
static const char * const cci_timer3_groups[] = {
	"gpio32",
};
static const char * const gp_pdm1_groups[] = {
	"gpio32", "gpio96",
};
static const char * const gp_pdm2_groups[] = {
	"gpio33", "gpio97",
};
static const char * const char_exec_groups[] = {
	"gpio37", "gpio38",
};
static const char * const nav_gpio_groups[] = {
	"gpio42", "gpio47", "gpio52", "gpio95", "gpio96", "gpio97", "gpio106",
	"gpio107", "gpio108",
};
static const char * const pbs14_groups[] = {
	"gpio47",
};
static const char * const vfr_1_groups[] = {
	"gpio48",
};
static const char * const pbs15_groups[] = {
	"gpio48",
};
static const char * const pa_indicator_groups[] = {
	"gpio49",
};
static const char * const pwm_2_groups[] = {
	"gpio51",
};
static const char * const gsm1_tx_groups[] = {
	"gpio53",
};
static const char * const ssbi_wtr1_groups[] = {
	"gpio59", "gpio60",
};
static const char * const pll_bypassnl_groups[] = {
	"gpio62",
};
static const char * const pll_reset_groups[] = {
	"gpio63",
};
static const char * const ddr_pxi0_groups[] = {
	"gpio63", "gpio64",
};
static const char * const gsm0_tx_groups[] = {
	"gpio64",
};
static const char * const gcc_gp2_groups[] = {
	"gpio69", "gpio107",
};
static const char * const ddr_pxi1_groups[] = {
	"gpio69", "gpio70",
};
static const char * const gcc_gp3_groups[] = {
	"gpio70", "gpio106",
};
static const char * const dbg_out_groups[] = {
	"gpio71",
};
static const char * const uim2_data_groups[] = {
	"gpio72",
};
static const char * const pwm_3_groups[] = {
	"gpio72",
};
static const char * const uim2_clk_groups[] = {
	"gpio73",
};
static const char * const uim2_reset_groups[] = {
	"gpio74",
};
static const char * const pwm_4_groups[] = {
	"gpio74",
};
static const char * const uim2_present_groups[] = {
	"gpio75",
};
static const char * const pwm_5_groups[] = {
	"gpio75",
};
static const char * const uim1_data_groups[] = {
	"gpio76",
};
static const char * const uim1_clk_groups[] = {
	"gpio77",
};
static const char * const uim1_reset_groups[] = {
	"gpio78",
};
static const char * const uim1_present_groups[] = {
	"gpio79",
};
static const char * const mdp_vsync_groups[] = {
	"gpio81", "gpio96", "gpio97",
};
static const char * const mdp_vsync_out_0_groups[] = {
	"gpio81",
};
static const char * const mdp_vsync_out_1_groups[] = {
	"gpio81",
};
static const char * const pwm_6_groups[] = {
	"gpio82",
};
static const char * const pbs11_groups[] = {
	"gpio87",
};
static const char * const usb_phy_groups[] = {
	"gpio89",
};
static const char * const pwm_7_groups[] = {
	"gpio89",
};
static const char * const mss_lte_groups[] = {
	"gpio90", "gpio91",
};
static const char * const pbs12_groups[] = {
	"gpio90",
};
static const char * const pbs13_groups[] = {
	"gpio91",
};
static const char * const wlan1_adc0_groups[] = {
	"gpio94",
};
static const char * const wlan1_adc1_groups[] = {
	"gpio95",
};
static const char * const sd_write_groups[] = {
	"gpio96",
};
static const char * const jitter_bist_groups[] = {
	"gpio96", "gpio97",
};
static const char * const ddr_pxi2_groups[] = {
	"gpio102", "gpio103",
};
static const char * const ddr_pxi3_groups[] = {
	"gpio104", "gpio105",
};
static const char * const pwm_8_groups[] = {
	"gpio104",
};
static const char * const pwm_9_groups[] = {
	"gpio115",
};

static const struct msm_function qcm2290_functions[] = {
	FUNCTION(adsp_ext),
	FUNCTION(agera_pll),
	FUNCTION(atest),
	FUNCTION(cam_mclk),
	FUNCTION(cci_async),
	FUNCTION(cci_i2c),
	FUNCTION(cci_timer0),
	FUNCTION(cci_timer1),
	FUNCTION(cci_timer2),
	FUNCTION(cci_timer3),
	FUNCTION(char_exec),
	FUNCTION(cri_trng),
	FUNCTION(cri_trng0),
	FUNCTION(cri_trng1),
	FUNCTION(dac_calib),
	FUNCTION(dbg_out),
	FUNCTION(ddr_bist),
	FUNCTION(ddr_pxi0),
	FUNCTION(ddr_pxi1),
	FUNCTION(ddr_pxi2),
	FUNCTION(ddr_pxi3),
	FUNCTION(gcc_gp1),
	FUNCTION(gcc_gp2),
	FUNCTION(gcc_gp3),
	FUNCTION(gpio),
	FUNCTION(gp_pdm0),
	FUNCTION(gp_pdm1),
	FUNCTION(gp_pdm2),
	FUNCTION(gsm0_tx),
	FUNCTION(gsm1_tx),
	FUNCTION(jitter_bist),
	FUNCTION(mdp_vsync),
	FUNCTION(mdp_vsync_out_0),
	FUNCTION(mdp_vsync_out_1),
	FUNCTION(mpm_pwr),
	FUNCTION(mss_lte),
	FUNCTION(m_voc),
	FUNCTION(nav_gpio),
	FUNCTION(pa_indicator),
	FUNCTION(pbs0),
	FUNCTION(pbs1),
	FUNCTION(pbs2),
	FUNCTION(pbs3),
	FUNCTION(pbs4),
	FUNCTION(pbs5),
	FUNCTION(pbs6),
	FUNCTION(pbs7),
	FUNCTION(pbs8),
	FUNCTION(pbs9),
	FUNCTION(pbs10),
	FUNCTION(pbs11),
	FUNCTION(pbs12),
	FUNCTION(pbs13),
	FUNCTION(pbs14),
	FUNCTION(pbs15),
	FUNCTION(pbs_out),
	FUNCTION(phase_flag),
	FUNCTION(pll_bist),
	FUNCTION(pll_bypassnl),
	FUNCTION(pll_reset),
	FUNCTION(prng_rosc),
	FUNCTION(pwm_0),
	FUNCTION(pwm_1),
	FUNCTION(pwm_2),
	FUNCTION(pwm_3),
	FUNCTION(pwm_4),
	FUNCTION(pwm_5),
	FUNCTION(pwm_6),
	FUNCTION(pwm_7),
	FUNCTION(pwm_8),
	FUNCTION(pwm_9),
	FUNCTION(qdss_cti),
	FUNCTION(qdss_gpio),
	FUNCTION(qup0),
	FUNCTION(qup1),
	FUNCTION(qup2),
	FUNCTION(qup3),
	FUNCTION(qup4),
	FUNCTION(qup5),
	FUNCTION(sdc1_tb),
	FUNCTION(sdc2_tb),
	FUNCTION(sd_write),
	FUNCTION(ssbi_wtr1),
	FUNCTION(tgu_ch0),
	FUNCTION(tgu_ch1),
	FUNCTION(tgu_ch2),
	FUNCTION(tgu_ch3),
	FUNCTION(tsense_pwm),
	FUNCTION(uim1_clk),
	FUNCTION(uim1_data),
	FUNCTION(uim1_present),
	FUNCTION(uim1_reset),
	FUNCTION(uim2_clk),
	FUNCTION(uim2_data),
	FUNCTION(uim2_present),
	FUNCTION(uim2_reset),
	FUNCTION(usb_phy),
	FUNCTION(vfr_1),
	FUNCTION(vsense_trigger),
	FUNCTION(wlan1_adc0),
	FUNCTION(wlan1_adc1),
};

/* Every pin is maintained as a single group, and missing or non-existing pin
 * would be maintained as dummy group to synchronize pin group index with
 * pin descriptor registered with pinctrl core.
 * Clients would not be able to request these dummy pin groups.
 */
static const struct msm_pingroup qcm2290_groups[] = {
	[0] = PINGROUP(0, qup0, m_voc, ddr_bist, _, phase_flag, qdss_gpio, atest, _, _),
	[1] = PINGROUP(1, qup0, mpm_pwr, ddr_bist, _, phase_flag, qdss_gpio, atest, _, _),
	[2] = PINGROUP(2, qup0, ddr_bist, _, phase_flag, qdss_gpio, dac_calib, atest, _, _),
	[3] = PINGROUP(3, qup0, ddr_bist, _, phase_flag, qdss_gpio, dac_calib, atest, _, _),
	[4] = PINGROUP(4, qup1, cri_trng0, _, phase_flag, dac_calib, atest, _, _, _),
	[5] = PINGROUP(5, qup1, cri_trng1, _, phase_flag, dac_calib, atest, _, _, _),
	[6] = PINGROUP(6, qup2, _, phase_flag, dac_calib, atest, _, _, _, _),
	[7] = PINGROUP(7, qup2, _, _, _, _, _, _, _, _),
	[8] = PINGROUP(8, qup3, pbs_out, pll_bist, _, qdss_gpio, _, tsense_pwm, _, _),
	[9] = PINGROUP(9, qup3, pbs_out, pll_bist, _, qdss_gpio, _, _, _, _),
	[10] = PINGROUP(10, qup3, agera_pll, _, pbs0, qdss_gpio, _, _, _, _),
	[11] = PINGROUP(11, qup3, agera_pll, _, pbs1, qdss_gpio, _, _, _, _),
	[12] = PINGROUP(12, qup4, tgu_ch0, _, _, _, _, _, _, _),
	[13] = PINGROUP(13, qup4, tgu_ch1, _, _, _, _, _, _, _),
	[14] = PINGROUP(14, qup5, tgu_ch2, _, phase_flag, qdss_gpio, dac_calib, _, _, _),
	[15] = PINGROUP(15, qup5, tgu_ch3, _, phase_flag, qdss_gpio, dac_calib, _, _, _),
	[16] = PINGROUP(16, qup5, _, phase_flag, qdss_gpio, dac_calib, _, _, _, _),
	[17] = PINGROUP(17, qup5, _, phase_flag, qdss_gpio, dac_calib, _, _, _, _),
	[18] = PINGROUP(18, sdc2_tb, cri_trng, pbs2, qdss_gpio, _, pwm_0, _, _, _),
	[19] = PINGROUP(19, sdc1_tb, pbs3, qdss_gpio, _, _, _, _, _, _),
	[20] = PINGROUP(20, cam_mclk, pbs4, qdss_gpio, _, _, _, _, _, _),
	[21] = PINGROUP(21, cam_mclk, adsp_ext, pbs5, qdss_gpio, _, _, _, _, _),
	[22] = PINGROUP(22, cci_i2c, prng_rosc, _, pbs6, phase_flag, qdss_gpio, dac_calib, atest, _),
	[23] = PINGROUP(23, cci_i2c, prng_rosc, _, pbs7, phase_flag, qdss_gpio, dac_calib, atest, _),
	[24] = PINGROUP(24, cci_timer1, gcc_gp1, _, pbs8, phase_flag, qdss_gpio, dac_calib, atest, _),
	[25] = PINGROUP(25, cci_async, cci_timer0, _, pbs9, phase_flag, qdss_gpio, dac_calib, atest, _),
	[26] = PINGROUP(26, _, pbs10, phase_flag, qdss_gpio, dac_calib, atest, vsense_trigger, _, _),
	[27] = PINGROUP(27, cam_mclk, qdss_cti, _, _, _, _, _, _, _),
	[28] = PINGROUP(28, cam_mclk, cci_timer2, qdss_cti, _, pwm_1, _, _, _, _),
	[29] = PINGROUP(29, cci_i2c, _, phase_flag, dac_calib, atest, _, _, _, _),
	[30] = PINGROUP(30, cci_i2c, _, phase_flag, dac_calib, atest, _, _, _, _),
	[31] = PINGROUP(31, gp_pdm0, _, phase_flag, dac_calib, atest, _, _, _, _),
	[32] = PINGROUP(32, cci_timer3, gp_pdm1, _, phase_flag, dac_calib, atest, _, _, _),
	[33] = PINGROUP(33, gp_pdm2, _, phase_flag, dac_calib, atest, _, _, _, _),
	[34] = PINGROUP(34, _, _, _, _, _, _, _, _, _),
	[35] = PINGROUP(35, _, phase_flag, _, _, _, _, _, _, _),
	[36] = PINGROUP(36, _, phase_flag, _, _, _, _, _, _, _),
	[37] = PINGROUP(37, _, _, char_exec, _, _, _, _, _, _),
	[38] = PINGROUP(38, _, _, _, char_exec, _, _, _, _, _),
	[39] = PINGROUP(39, _, _, _, _, _, _, _, _, _),
	[40] = PINGROUP(40, _, _, _, _, _, _, _, _, _),
	[41] = PINGROUP(41, _, _, _, _, _, _, _, _, _),
	[42] = PINGROUP(42, _, nav_gpio, _, _, _, _, _, _, _),
	[43] = PINGROUP(43, _, _, phase_flag, _, _, _, _, _, _),
	[44] = PINGROUP(44, _, _, phase_flag, _, _, _, _, _, _),
	[45] = PINGROUP(45, _, _, phase_flag, _, _, _, _, _, _),
	[46] = PINGROUP(46, _, _, _, _, _, _, _, _, _),
	[47] = PINGROUP(47, _, nav_gpio, pbs14, qdss_gpio, _, _, _, _, _),
	[48] = PINGROUP(48, _, vfr_1, _, pbs15, qdss_gpio, _, _, _, _),
	[49] = PINGROUP(49, _, pa_indicator, _, _, _, _, _, _, _),
	[50] = PINGROUP(50, _, _, _, _, _, _, _, _, _),
	[51] = PINGROUP(51, _, _, _, pwm_2, _, _, _, _, _),
	[52] = PINGROUP(52, _, nav_gpio, pbs_out, _, _, _, _, _, _),
	[53] = PINGROUP(53, _, gsm1_tx, _, _, _, _, _, _, _),
	[54] = PINGROUP(54, _, _, _, _, _, _, _, _, _),
	[55] = PINGROUP(55, _, _, _, _, _, _, _, _, _),
	[56] = PINGROUP(56, _, _, _, _, _, _, _, _, _),
	[57] = PINGROUP(57, _, _, _, _, _, _, _, _, _),
	[58] = PINGROUP(58, _, _, _, _, _, _, _, _, _),
	[59] = PINGROUP(59, _, ssbi_wtr1, _, _, _, _, _, _, _),
	[60] = PINGROUP(60, _, ssbi_wtr1, _, _, _, _, _, _, _),
	[61] = PINGROUP(61, _, _, _, _, _, _, _, _, _),
	[62] = PINGROUP(62, _, pll_bypassnl, _, _, _, _, _, _, _),
	[63] = PINGROUP(63, pll_reset, _, phase_flag, ddr_pxi0, _, _, _, _, _),
	[64] = PINGROUP(64, gsm0_tx, _, phase_flag, ddr_pxi0, _, _, _, _, _),
	[65] = PINGROUP(65, _, _, _, _, _, _, _, _, _),
	[66] = PINGROUP(66, _, _, _, _, _, _, _, _, _),
	[67] = PINGROUP(67, _, _, _, _, _, _, _, _, _),
	[68] = PINGROUP(68, _, _, _, _, _, _, _, _, _),
	[69] = PINGROUP(69, qup1, gcc_gp2, qdss_gpio, ddr_pxi1, _, _, _, _, _),
	[70] = PINGROUP(70, qup1, gcc_gp3, qdss_gpio, ddr_pxi1, _, _, _, _, _),
	[71] = PINGROUP(71, qup2, dbg_out, _, _, _, _, _, _, _),
	[72] = PINGROUP(72, uim2_data, qdss_cti, _, pwm_3, _, _, _, _, _),
	[73] = PINGROUP(73, uim2_clk, _, qdss_cti, _, _, _, _, _, _),
	[74] = PINGROUP(74, uim2_reset, _, _, pwm_4, _, _, _, _, _),
	[75] = PINGROUP(75, uim2_present, _, _, pwm_5, _, _, _, _, _),
	[76] = PINGROUP(76, uim1_data, _, _, _, _, _, _, _, _),
	[77] = PINGROUP(77, uim1_clk, _, _, _, _, _, _, _, _),
	[78] = PINGROUP(78, uim1_reset, _, _, _, _, _, _, _, _),
	[79] = PINGROUP(79, uim1_present, _, _, _, _, _, _, _, _),
	[80] = PINGROUP(80, qup2, dac_calib, _, _, _, _, _, _, _),
	[81] = PINGROUP(81, mdp_vsync_out_0, mdp_vsync_out_1, mdp_vsync, dac_calib, _, _, _, _, _),
	[82] = PINGROUP(82, qup0, dac_calib, _, pwm_6, _, _, _, _, _),
	[83] = PINGROUP(83, _, _, _, _, _, _, _, _, _),
	[84] = PINGROUP(84, _, _, _, _, _, _, _, _, _),
	[85] = PINGROUP(85, _, _, _, _, _, _, _, _, _),
	[86] = PINGROUP(86, qup0, gcc_gp1, atest, _, _, _, _, _, _),
	[87] = PINGROUP(87, pbs11, qdss_gpio, _, _, _, _, _, _, _),
	[88] = PINGROUP(88, _, _, _, _, _, _, _, _, _),
	[89] = PINGROUP(89, usb_phy, atest, _, pwm_7, _, _, _, _, _),
	[90] = PINGROUP(90, mss_lte, pbs12, qdss_gpio, _, _, _, _, _, _),
	[91] = PINGROUP(91, mss_lte, pbs13, qdss_gpio, _, _, _, _, _, _),
	[92] = PINGROUP(92, _, _, _, _, _, _, _, _, _),
	[93] = PINGROUP(93, _, _, _, _, _, _, _, _, _),
	[94] = PINGROUP(94, _, qdss_gpio, wlan1_adc0, _, _, _, _, _, _),
	[95] = PINGROUP(95, nav_gpio, gp_pdm0, qdss_gpio, wlan1_adc1, _, _, _, _, _),
	[96] = PINGROUP(96, qup4, nav_gpio, mdp_vsync, gp_pdm1, sd_write, jitter_bist, qdss_cti, qdss_cti, _),
	[97] = PINGROUP(97, qup4, nav_gpio, mdp_vsync, gp_pdm2, jitter_bist, qdss_cti, qdss_cti, _, _),
	[98] = PINGROUP(98, _, _, _, _, _, _, _, _, _),
	[99] = PINGROUP(99, _, _, _, _, _, _, _, _, _),
	[100] = PINGROUP(100, atest, _, _, _, _, _, _, _, _),
	[101] = PINGROUP(101, atest, _, _, _, _, _, _, _, _),
	[102] = PINGROUP(102, _, phase_flag, dac_calib, ddr_pxi2, _, _, _, _, _),
	[103] = PINGROUP(103, _, phase_flag, dac_calib, ddr_pxi2, _, _, _, _, _),
	[104] = PINGROUP(104, _, phase_flag, qdss_gpio, dac_calib, ddr_pxi3, _, pwm_8, _, _),
	[105] = PINGROUP(105, _, phase_flag, qdss_gpio, dac_calib, ddr_pxi3, _, _, _, _),
	[106] = PINGROUP(106, nav_gpio, gcc_gp3, qdss_gpio, _, _, _, _, _, _),
	[107] = PINGROUP(107, nav_gpio, gcc_gp2, qdss_gpio, _, _, _, _, _, _),
	[108] = PINGROUP(108, nav_gpio, _, _, _, _, _, _, _, _),
	[109] = PINGROUP(109, _, qdss_gpio, _, _, _, _, _, _, _),
	[110] = PINGROUP(110, _, qdss_gpio, _, _, _, _, _, _, _),
	[111] = PINGROUP(111, _, _, _, _, _, _, _, _, _),
	[112] = PINGROUP(112, _, _, _, _, _, _, _, _, _),
	[113] = PINGROUP(113, _, _, _, _, _, _, _, _, _),
	[114] = PINGROUP(114, _, _, _, _, _, _, _, _, _),
	[115] = PINGROUP(115, _, pwm_9, _, _, _, _, _, _, _),
	[116] = PINGROUP(116, _, _, _, _, _, _, _, _, _),
	[117] = PINGROUP(117, _, _, _, _, _, _, _, _, _),
	[118] = PINGROUP(118, _, _, _, _, _, _, _, _, _),
	[119] = PINGROUP(119, _, _, _, _, _, _, _, _, _),
	[120] = PINGROUP(120, _, _, _, _, _, _, _, _, _),
	[121] = PINGROUP(121, _, _, _, _, _, _, _, _, _),
	[122] = PINGROUP(122, _, _, _, _, _, _, _, _, _),
	[123] = PINGROUP(123, _, _, _, _, _, _, _, _, _),
	[124] = PINGROUP(124, _, _, _, _, _, _, _, _, _),
	[125] = PINGROUP(125, _, _, _, _, _, _, _, _, _),
	[126] = PINGROUP(126, _, _, _, _, _, _, _, _, _),
	[127] = SDC_QDSD_PINGROUP(sdc1_rclk, 0x84004, 0, 0),
	[128] = SDC_QDSD_PINGROUP(sdc1_clk, 0x84000, 13, 6),
	[129] = SDC_QDSD_PINGROUP(sdc1_cmd, 0x84000, 11, 3),
	[130] = SDC_QDSD_PINGROUP(sdc1_data, 0x84000, 9, 0),
	[131] = SDC_QDSD_PINGROUP(sdc2_clk, 0x86000, 14, 6),
	[132] = SDC_QDSD_PINGROUP(sdc2_cmd, 0x86000, 11, 3),
	[133] = SDC_QDSD_PINGROUP(sdc2_data, 0x86000, 9, 0),
};

static const struct msm_pinctrl_soc_data qcm2290_pinctrl = {
	.pins = qcm2290_pins,
	.npins = ARRAY_SIZE(qcm2290_pins),
	.functions = qcm2290_functions,
	.nfunctions = ARRAY_SIZE(qcm2290_functions),
	.groups = qcm2290_groups,
	.ngroups = ARRAY_SIZE(qcm2290_groups),
	.ngpios = 127,
};

static int qcm2290_pinctrl_probe(struct platform_device *pdev)
{
	return msm_pinctrl_probe(pdev, &qcm2290_pinctrl);
}

static const struct of_device_id qcm2290_pinctrl_of_match[] = {
	{ .compatible = "qcom,qcm2290-tlmm", },
	{ },
};

static struct platform_driver qcm2290_pinctrl_driver = {
	.driver = {
		.name = "qcm2290-pinctrl",
		.of_match_table = qcm2290_pinctrl_of_match,
	},
	.probe = qcm2290_pinctrl_probe,
	.remove = msm_pinctrl_remove,
};

static int __init qcm2290_pinctrl_init(void)
{
	return platform_driver_register(&qcm2290_pinctrl_driver);
}
arch_initcall(qcm2290_pinctrl_init);

static void __exit qcm2290_pinctrl_exit(void)
{
	platform_driver_unregister(&qcm2290_pinctrl_driver);
}
module_exit(qcm2290_pinctrl_exit);

MODULE_DESCRIPTION("QTI QCM2290 pinctrl driver");
MODULE_LICENSE("GPL v2");
MODULE_DEVICE_TABLE(of, qcm2290_pinctrl_of_match);
