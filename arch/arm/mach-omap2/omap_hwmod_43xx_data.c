/*
 * Copyright (C) 2013 Texas Instruments Incorporated
 *
 * Hwmod present only in AM43x and those that differ other than register
 * offsets as compared to AM335x.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "omap_hwmod.h"
#include "omap_hwmod_33xx_43xx_common_data.h"
#include "prcm43xx.h"
#include "omap_hwmod_common_data.h"

/* IP blocks */
static struct omap_hwmod am43xx_emif_hwmod = {
	.name		= "emif",
	.class		= &am33xx_emif_hwmod_class,
	.clkdm_name	= "emif_clkdm",
	.flags		= HWMOD_INIT_NO_IDLE,
	.main_clk	= "dpll_ddr_m2_ck",
	.prcm		= {
		.omap4	= {
			.clkctrl_offs	= AM43XX_CM_PER_EMIF_CLKCTRL_OFFSET,
			.modulemode	= MODULEMODE_SWCTRL,
		},
	},
};

static struct omap_hwmod am43xx_l4_hs_hwmod = {
	.name		= "l4_hs",
	.class		= &am33xx_l4_hwmod_class,
	.clkdm_name	= "l3_clkdm",
	.flags		= HWMOD_INIT_NO_IDLE,
	.main_clk	= "l4hs_gclk",
	.prcm		= {
		.omap4	= {
			.clkctrl_offs	= AM43XX_CM_PER_L4HS_CLKCTRL_OFFSET,
			.modulemode	= MODULEMODE_SWCTRL,
		},
	},
};

static struct omap_hwmod_rst_info am33xx_wkup_m3_resets[] = {
	{ .name = "wkup_m3", .rst_shift = 3, .st_shift = 5 },
};

static struct omap_hwmod am43xx_wkup_m3_hwmod = {
	.name		= "wkup_m3",
	.class		= &am33xx_wkup_m3_hwmod_class,
	.clkdm_name	= "l4_wkup_aon_clkdm",
	/* Keep hardreset asserted */
	.flags		= HWMOD_INIT_NO_RESET | HWMOD_NO_IDLEST,
	.main_clk	= "sys_clkin_ck",
	.prcm		= {
		.omap4	= {
			.clkctrl_offs	= AM43XX_CM_WKUP_WKUP_M3_CLKCTRL_OFFSET,
			.rstctrl_offs	= AM43XX_RM_WKUP_RSTCTRL_OFFSET,
			.rstst_offs	= AM43XX_RM_WKUP_RSTST_OFFSET,
			.modulemode	= MODULEMODE_SWCTRL,
		},
	},
	.rst_lines	= am33xx_wkup_m3_resets,
	.rst_lines_cnt	= ARRAY_SIZE(am33xx_wkup_m3_resets),
};

static struct omap_hwmod am43xx_control_hwmod = {
	.name		= "control",
	.class		= &am33xx_control_hwmod_class,
	.clkdm_name	= "l4_wkup_clkdm",
	.flags		= HWMOD_INIT_NO_IDLE,
	.main_clk	= "sys_clkin_ck",
	.prcm		= {
		.omap4	= {
			.clkctrl_offs	= AM43XX_CM_WKUP_CONTROL_CLKCTRL_OFFSET,
			.modulemode	= MODULEMODE_SWCTRL,
		},
	},
};

static struct omap_hwmod_class_sysconfig am43xx_usb_otg_ss_sysc = {
	.rev_offs	= 0x0000,
	.sysc_offs	= 0x0010,
	.sysc_flags	= (SYSC_HAS_DMADISABLE | SYSC_HAS_MIDLEMODE |
				SYSC_HAS_SIDLEMODE),
	.idlemodes	= (SIDLE_FORCE | SIDLE_NO | SIDLE_SMART |
				SIDLE_SMART_WKUP | MSTANDBY_FORCE |
				MSTANDBY_NO | MSTANDBY_SMART |
				MSTANDBY_SMART_WKUP),
	.sysc_fields	= &omap_hwmod_sysc_type2,
};

static struct omap_hwmod_class am43xx_usb_otg_ss_hwmod_class = {
	.name	= "usb_otg_ss",
	.sysc	= &am43xx_usb_otg_ss_sysc,
};

static struct omap_hwmod am43xx_usb_otg_ss0_hwmod = {
	.name		= "usb_otg_ss0",
	.class		= &am43xx_usb_otg_ss_hwmod_class,
	.clkdm_name	= "l3s_clkdm",
	.main_clk	= "l3s_gclk",
	.prcm = {
		.omap4 = {
			.clkctrl_offs	= AM43XX_CM_PER_USB_OTG_SS0_CLKCTRL_OFFSET,
			.modulemode	= MODULEMODE_SWCTRL,
		},
	},
};

static struct omap_hwmod am43xx_usb_otg_ss1_hwmod = {
	.name		= "usb_otg_ss1",
	.class		= &am43xx_usb_otg_ss_hwmod_class,
	.clkdm_name	= "l3s_clkdm",
	.main_clk	= "l3s_gclk",
	.prcm = {
		.omap4 = {
			.clkctrl_offs	= AM43XX_CM_PER_USB_OTG_SS1_CLKCTRL_OFFSET,
			.modulemode	= MODULEMODE_SWCTRL,
		},
	},
};

/* Interfaces */
static struct omap_hwmod_ocp_if am43xx_l3_main__emif = {
	.master		= &am33xx_l3_main_hwmod,
	.slave		= &am43xx_emif_hwmod,
	.clk		= "dpll_core_m4_ck",
	.user		= OCP_USER_MPU | OCP_USER_SDMA,
};

static struct omap_hwmod_ocp_if am43xx_l3_main__l4_hs = {
	.master		= &am33xx_l3_main_hwmod,
	.slave		= &am43xx_l4_hs_hwmod,
	.clk		= "l3s_gclk",
	.user		= OCP_USER_MPU | OCP_USER_SDMA,
};

static struct omap_hwmod_ocp_if am43xx_wkup_m3__l4_wkup = {
	.master		= &am43xx_wkup_m3_hwmod,
	.slave		= &am33xx_l4_wkup_hwmod,
	.clk		= "sys_clkin_ck",
	.user		= OCP_USER_MPU | OCP_USER_SDMA,
};

static struct omap_hwmod_ocp_if am43xx_l4_wkup__wkup_m3 = {
	.master		= &am33xx_l4_wkup_hwmod,
	.slave		= &am43xx_wkup_m3_hwmod,
	.clk		= "sys_clkin_ck",
	.user		= OCP_USER_MPU | OCP_USER_SDMA,
};

static struct omap_hwmod_ocp_if am43xx_l4_wkup__smartreflex0 = {
	.master		= &am33xx_l4_wkup_hwmod,
	.slave		= &am33xx_smartreflex0_hwmod,
	.clk		= "sys_clkin_ck",
	.user		= OCP_USER_MPU,
};

static struct omap_hwmod_ocp_if am43xx_l4_wkup__smartreflex1 = {
	.master		= &am33xx_l4_wkup_hwmod,
	.slave		= &am33xx_smartreflex1_hwmod,
	.clk		= "sys_clkin_ck",
	.user		= OCP_USER_MPU,
};

static struct omap_hwmod_ocp_if am43xx_l4_wkup__control = {
	.master		= &am33xx_l4_wkup_hwmod,
	.slave		= &am43xx_control_hwmod,
	.clk		= "sys_clkin_ck",
	.user		= OCP_USER_MPU,
};

static struct omap_hwmod_ocp_if am43xx_l3_s__usbotgss0 = {
	.master         = &am33xx_l3_s_hwmod,
	.slave          = &am43xx_usb_otg_ss0_hwmod,
	.clk            = "l3s_gclk",
	.user           = OCP_USER_MPU | OCP_USER_SDMA,
};

static struct omap_hwmod_ocp_if am43xx_l3_s__usbotgss1 = {
	.master         = &am33xx_l3_s_hwmod,
	.slave          = &am43xx_usb_otg_ss1_hwmod,
	.clk            = "l3s_gclk",
	.user           = OCP_USER_MPU | OCP_USER_SDMA,
};

static struct omap_hwmod_ocp_if *am43xx_hwmod_ocp_ifs[] __initdata = {
	&am33xx_mpu__l3_main,
	&am33xx_mpu__prcm,
	&am33xx_l3_s__l4_ls,
	&am33xx_l3_s__l4_wkup,
	&am43xx_l3_main__l4_hs,
	&am33xx_l3_main__l3_s,
	&am33xx_l3_main__l3_instr,
	&am33xx_l3_main__gfx,
	&am33xx_l3_s__l3_main,
	&am43xx_l3_main__emif,
	&am43xx_wkup_m3__l4_wkup,
	&am33xx_gfx__l3_main,
	&am43xx_l4_wkup__wkup_m3,
	&am43xx_l4_wkup__control,
	&am43xx_l4_wkup__smartreflex0,
	&am43xx_l4_wkup__smartreflex1,
	&am33xx_l3_s__gpmc,
	&am33xx_l3_main__ocmc,
	&am43xx_l3_s__usbotgss0,
	&am43xx_l3_s__usbotgss1,
	NULL,
};

static struct omap_hwmod_ocp_if *am43xx_rtc_hwmod_ocp_ifs[] __initdata = {
	&am33xx_l4_wkup__rtc,
	NULL,
};

int __init am43xx_hwmod_init(void)
{
	int ret;

	omap_hwmod_am43xx_reg();
	omap_hwmod_init();
	ret = omap_hwmod_register_links(am43xx_hwmod_ocp_ifs);

	if (!ret && of_machine_is_compatible("ti,am4372"))
		ret = omap_hwmod_register_links(am43xx_rtc_hwmod_ocp_ifs);

	return ret;
}
