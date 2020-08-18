// SPDX-License-Identifier: GPL-2.0-only
/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2009-2013 Solarflare Communications Inc.
 */

/*
 * Driver for PHY related operations via MCDI.
 */

#include <linux/slab.h>
#include "efx.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "nic.h"
#include "selftest.h"
#include "mcdi_port_common.h"

static int efx_mcdi_mdio_read(struct net_device *net_dev,
			      int prtad, int devad, u16 addr)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MDIO_READ_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MDIO_READ_OUT_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MDIO_READ_IN_BUS, efx->mdio_bus);
	MCDI_SET_DWORD(inbuf, MDIO_READ_IN_PRTAD, prtad);
	MCDI_SET_DWORD(inbuf, MDIO_READ_IN_DEVAD, devad);
	MCDI_SET_DWORD(inbuf, MDIO_READ_IN_ADDR, addr);

	rc = efx_mcdi_rpc(efx, MC_CMD_MDIO_READ, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;

	if (MCDI_DWORD(outbuf, MDIO_READ_OUT_STATUS) !=
	    MC_CMD_MDIO_STATUS_GOOD)
		return -EIO;

	return (u16)MCDI_DWORD(outbuf, MDIO_READ_OUT_VALUE);
}

static int efx_mcdi_mdio_write(struct net_device *net_dev,
			       int prtad, int devad, u16 addr, u16 value)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MDIO_WRITE_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MDIO_WRITE_OUT_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MDIO_WRITE_IN_BUS, efx->mdio_bus);
	MCDI_SET_DWORD(inbuf, MDIO_WRITE_IN_PRTAD, prtad);
	MCDI_SET_DWORD(inbuf, MDIO_WRITE_IN_DEVAD, devad);
	MCDI_SET_DWORD(inbuf, MDIO_WRITE_IN_ADDR, addr);
	MCDI_SET_DWORD(inbuf, MDIO_WRITE_IN_VALUE, value);

	rc = efx_mcdi_rpc(efx, MC_CMD_MDIO_WRITE, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;

	if (MCDI_DWORD(outbuf, MDIO_WRITE_OUT_STATUS) !=
	    MC_CMD_MDIO_STATUS_GOOD)
		return -EIO;

	return 0;
}

static int efx_mcdi_phy_probe(struct efx_nic *efx)
{
	struct efx_mcdi_phy_data *phy_data;
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_LINK_OUT_LEN);
	u32 caps;
	int rc;

	/* Initialise and populate phy_data */
	phy_data = kzalloc(sizeof(*phy_data), GFP_KERNEL);
	if (phy_data == NULL)
		return -ENOMEM;

	rc = efx_mcdi_get_phy_cfg(efx, phy_data);
	if (rc != 0)
		goto fail;

	/* Read initial link advertisement */
	BUILD_BUG_ON(MC_CMD_GET_LINK_IN_LEN != 0);
	rc = efx_mcdi_rpc(efx, MC_CMD_GET_LINK, NULL, 0,
			  outbuf, sizeof(outbuf), NULL);
	if (rc)
		goto fail;

	/* Fill out nic state */
	efx->phy_data = phy_data;
	efx->phy_type = phy_data->type;

	efx->mdio_bus = phy_data->channel;
	efx->mdio.prtad = phy_data->port;
	efx->mdio.mmds = phy_data->mmd_mask & ~(1 << MC_CMD_MMD_CLAUSE22);
	efx->mdio.mode_support = 0;
	if (phy_data->mmd_mask & (1 << MC_CMD_MMD_CLAUSE22))
		efx->mdio.mode_support |= MDIO_SUPPORTS_C22;
	if (phy_data->mmd_mask & ~(1 << MC_CMD_MMD_CLAUSE22))
		efx->mdio.mode_support |= MDIO_SUPPORTS_C45 | MDIO_EMULATE_C22;

	caps = MCDI_DWORD(outbuf, GET_LINK_OUT_CAP);
	if (caps & (1 << MC_CMD_PHY_CAP_AN_LBN))
		mcdi_to_ethtool_linkset(phy_data->media, caps,
					efx->link_advertising);
	else
		phy_data->forced_cap = caps;

	/* Assert that we can map efx -> mcdi loopback modes */
	BUILD_BUG_ON(LOOPBACK_NONE != MC_CMD_LOOPBACK_NONE);
	BUILD_BUG_ON(LOOPBACK_DATA != MC_CMD_LOOPBACK_DATA);
	BUILD_BUG_ON(LOOPBACK_GMAC != MC_CMD_LOOPBACK_GMAC);
	BUILD_BUG_ON(LOOPBACK_XGMII != MC_CMD_LOOPBACK_XGMII);
	BUILD_BUG_ON(LOOPBACK_XGXS != MC_CMD_LOOPBACK_XGXS);
	BUILD_BUG_ON(LOOPBACK_XAUI != MC_CMD_LOOPBACK_XAUI);
	BUILD_BUG_ON(LOOPBACK_GMII != MC_CMD_LOOPBACK_GMII);
	BUILD_BUG_ON(LOOPBACK_SGMII != MC_CMD_LOOPBACK_SGMII);
	BUILD_BUG_ON(LOOPBACK_XGBR != MC_CMD_LOOPBACK_XGBR);
	BUILD_BUG_ON(LOOPBACK_XFI != MC_CMD_LOOPBACK_XFI);
	BUILD_BUG_ON(LOOPBACK_XAUI_FAR != MC_CMD_LOOPBACK_XAUI_FAR);
	BUILD_BUG_ON(LOOPBACK_GMII_FAR != MC_CMD_LOOPBACK_GMII_FAR);
	BUILD_BUG_ON(LOOPBACK_SGMII_FAR != MC_CMD_LOOPBACK_SGMII_FAR);
	BUILD_BUG_ON(LOOPBACK_XFI_FAR != MC_CMD_LOOPBACK_XFI_FAR);
	BUILD_BUG_ON(LOOPBACK_GPHY != MC_CMD_LOOPBACK_GPHY);
	BUILD_BUG_ON(LOOPBACK_PHYXS != MC_CMD_LOOPBACK_PHYXS);
	BUILD_BUG_ON(LOOPBACK_PCS != MC_CMD_LOOPBACK_PCS);
	BUILD_BUG_ON(LOOPBACK_PMAPMD != MC_CMD_LOOPBACK_PMAPMD);
	BUILD_BUG_ON(LOOPBACK_XPORT != MC_CMD_LOOPBACK_XPORT);
	BUILD_BUG_ON(LOOPBACK_XGMII_WS != MC_CMD_LOOPBACK_XGMII_WS);
	BUILD_BUG_ON(LOOPBACK_XAUI_WS != MC_CMD_LOOPBACK_XAUI_WS);
	BUILD_BUG_ON(LOOPBACK_XAUI_WS_FAR != MC_CMD_LOOPBACK_XAUI_WS_FAR);
	BUILD_BUG_ON(LOOPBACK_XAUI_WS_NEAR != MC_CMD_LOOPBACK_XAUI_WS_NEAR);
	BUILD_BUG_ON(LOOPBACK_GMII_WS != MC_CMD_LOOPBACK_GMII_WS);
	BUILD_BUG_ON(LOOPBACK_XFI_WS != MC_CMD_LOOPBACK_XFI_WS);
	BUILD_BUG_ON(LOOPBACK_XFI_WS_FAR != MC_CMD_LOOPBACK_XFI_WS_FAR);
	BUILD_BUG_ON(LOOPBACK_PHYXS_WS != MC_CMD_LOOPBACK_PHYXS_WS);

	rc = efx_mcdi_loopback_modes(efx, &efx->loopback_modes);
	if (rc != 0)
		goto fail;
	/* The MC indicates that LOOPBACK_NONE is a valid loopback mode,
	 * but by convention we don't */
	efx->loopback_modes &= ~(1 << LOOPBACK_NONE);

	/* Set the initial link mode */
	efx_mcdi_phy_decode_link(
		efx, &efx->link_state,
		MCDI_DWORD(outbuf, GET_LINK_OUT_LINK_SPEED),
		MCDI_DWORD(outbuf, GET_LINK_OUT_FLAGS),
		MCDI_DWORD(outbuf, GET_LINK_OUT_FCNTL));

	/* Record the initial FEC configuration (or nearest approximation
	 * representable in the ethtool configuration space)
	 */
	efx->fec_config = mcdi_fec_caps_to_ethtool(caps,
						   efx->link_state.speed == 25000 ||
						   efx->link_state.speed == 50000);

	/* Default to Autonegotiated flow control if the PHY supports it */
	efx->wanted_fc = EFX_FC_RX | EFX_FC_TX;
	if (phy_data->supported_cap & (1 << MC_CMD_PHY_CAP_AN_LBN))
		efx->wanted_fc |= EFX_FC_AUTO;
	efx_link_set_wanted_fc(efx, efx->wanted_fc);

	return 0;

fail:
	kfree(phy_data);
	return rc;
}

int efx_mcdi_port_reconfigure(struct efx_nic *efx)
{
	struct efx_mcdi_phy_data *phy_cfg = efx->phy_data;
	u32 caps = (efx->link_advertising[0] ?
		    ethtool_linkset_to_mcdi_cap(efx->link_advertising) :
		    phy_cfg->forced_cap);

	caps |= ethtool_fec_caps_to_mcdi(efx->fec_config);

	return efx_mcdi_set_link(efx, caps, efx_get_mcdi_phy_flags(efx),
				 efx->loopback_mode, 0);
}

static void efx_mcdi_phy_remove(struct efx_nic *efx)
{
	struct efx_mcdi_phy_data *phy_data = efx->phy_data;

	efx->phy_data = NULL;
	kfree(phy_data);
}

static void efx_mcdi_phy_get_link_ksettings(struct efx_nic *efx,
					    struct ethtool_link_ksettings *cmd)
{
	struct efx_mcdi_phy_data *phy_cfg = efx->phy_data;
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_LINK_OUT_LEN);
	int rc;

	cmd->base.speed = efx->link_state.speed;
	cmd->base.duplex = efx->link_state.fd;
	cmd->base.port = mcdi_to_ethtool_media(phy_cfg->media);
	cmd->base.phy_address = phy_cfg->port;
	cmd->base.autoneg = !!(efx->link_advertising[0] & ADVERTISED_Autoneg);
	cmd->base.mdio_support = (efx->mdio.mode_support &
			      (MDIO_SUPPORTS_C45 | MDIO_SUPPORTS_C22));

	mcdi_to_ethtool_linkset(phy_cfg->media, phy_cfg->supported_cap,
				cmd->link_modes.supported);
	memcpy(cmd->link_modes.advertising, efx->link_advertising,
	       sizeof(__ETHTOOL_DECLARE_LINK_MODE_MASK()));

	BUILD_BUG_ON(MC_CMD_GET_LINK_IN_LEN != 0);
	rc = efx_mcdi_rpc(efx, MC_CMD_GET_LINK, NULL, 0,
			  outbuf, sizeof(outbuf), NULL);
	if (rc)
		return;
	mcdi_to_ethtool_linkset(phy_cfg->media,
				MCDI_DWORD(outbuf, GET_LINK_OUT_LP_CAP),
				cmd->link_modes.lp_advertising);
}

static int
efx_mcdi_phy_set_link_ksettings(struct efx_nic *efx,
				const struct ethtool_link_ksettings *cmd)
{
	struct efx_mcdi_phy_data *phy_cfg = efx->phy_data;
	u32 caps;
	int rc;

	if (cmd->base.autoneg) {
		caps = (ethtool_linkset_to_mcdi_cap(cmd->link_modes.advertising) |
			1 << MC_CMD_PHY_CAP_AN_LBN);
	} else if (cmd->base.duplex) {
		switch (cmd->base.speed) {
		case 10:     caps = 1 << MC_CMD_PHY_CAP_10FDX_LBN;     break;
		case 100:    caps = 1 << MC_CMD_PHY_CAP_100FDX_LBN;    break;
		case 1000:   caps = 1 << MC_CMD_PHY_CAP_1000FDX_LBN;   break;
		case 10000:  caps = 1 << MC_CMD_PHY_CAP_10000FDX_LBN;  break;
		case 40000:  caps = 1 << MC_CMD_PHY_CAP_40000FDX_LBN;  break;
		case 100000: caps = 1 << MC_CMD_PHY_CAP_100000FDX_LBN; break;
		case 25000:  caps = 1 << MC_CMD_PHY_CAP_25000FDX_LBN;  break;
		case 50000:  caps = 1 << MC_CMD_PHY_CAP_50000FDX_LBN;  break;
		default:     return -EINVAL;
		}
	} else {
		switch (cmd->base.speed) {
		case 10:     caps = 1 << MC_CMD_PHY_CAP_10HDX_LBN;     break;
		case 100:    caps = 1 << MC_CMD_PHY_CAP_100HDX_LBN;    break;
		case 1000:   caps = 1 << MC_CMD_PHY_CAP_1000HDX_LBN;   break;
		default:     return -EINVAL;
		}
	}

	caps |= ethtool_fec_caps_to_mcdi(efx->fec_config);

	rc = efx_mcdi_set_link(efx, caps, efx_get_mcdi_phy_flags(efx),
			       efx->loopback_mode, 0);
	if (rc)
		return rc;

	if (cmd->base.autoneg) {
		efx_link_set_advertising(efx, cmd->link_modes.advertising);
		phy_cfg->forced_cap = 0;
	} else {
		efx_link_clear_advertising(efx);
		phy_cfg->forced_cap = caps;
	}
	return 0;
}

static int efx_mcdi_phy_set_fecparam(struct efx_nic *efx,
				     const struct ethtool_fecparam *fec)
{
	struct efx_mcdi_phy_data *phy_cfg = efx->phy_data;
	u32 caps;
	int rc;

	/* Work out what efx_mcdi_phy_set_link_ksettings() would produce from
	 * saved advertising bits
	 */
	if (test_bit(ETHTOOL_LINK_MODE_Autoneg_BIT, efx->link_advertising))
		caps = (ethtool_linkset_to_mcdi_cap(efx->link_advertising) |
			1 << MC_CMD_PHY_CAP_AN_LBN);
	else
		caps = phy_cfg->forced_cap;

	caps |= ethtool_fec_caps_to_mcdi(fec->fec);
	rc = efx_mcdi_set_link(efx, caps, efx_get_mcdi_phy_flags(efx),
			       efx->loopback_mode, 0);
	if (rc)
		return rc;

	/* Record the new FEC setting for subsequent set_link calls */
	efx->fec_config = fec->fec;
	return 0;
}

static const char *const mcdi_sft9001_cable_diag_names[] = {
	"cable.pairA.length",
	"cable.pairB.length",
	"cable.pairC.length",
	"cable.pairD.length",
	"cable.pairA.status",
	"cable.pairB.status",
	"cable.pairC.status",
	"cable.pairD.status",
};

static int efx_mcdi_bist(struct efx_nic *efx, unsigned int bist_mode,
			 int *results)
{
	unsigned int retry, i, count = 0;
	size_t outlen;
	u32 status;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_START_BIST_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_POLL_BIST_OUT_SFT9001_LEN);
	u8 *ptr;
	int rc;

	BUILD_BUG_ON(MC_CMD_START_BIST_OUT_LEN != 0);
	MCDI_SET_DWORD(inbuf, START_BIST_IN_TYPE, bist_mode);
	rc = efx_mcdi_rpc(efx, MC_CMD_START_BIST,
			  inbuf, MC_CMD_START_BIST_IN_LEN, NULL, 0, NULL);
	if (rc)
		goto out;

	/* Wait up to 10s for BIST to finish */
	for (retry = 0; retry < 100; ++retry) {
		BUILD_BUG_ON(MC_CMD_POLL_BIST_IN_LEN != 0);
		rc = efx_mcdi_rpc(efx, MC_CMD_POLL_BIST, NULL, 0,
				  outbuf, sizeof(outbuf), &outlen);
		if (rc)
			goto out;

		status = MCDI_DWORD(outbuf, POLL_BIST_OUT_RESULT);
		if (status != MC_CMD_POLL_BIST_RUNNING)
			goto finished;

		msleep(100);
	}

	rc = -ETIMEDOUT;
	goto out;

finished:
	results[count++] = (status == MC_CMD_POLL_BIST_PASSED) ? 1 : -1;

	/* SFT9001 specific cable diagnostics output */
	if (efx->phy_type == PHY_TYPE_SFT9001B &&
	    (bist_mode == MC_CMD_PHY_BIST_CABLE_SHORT ||
	     bist_mode == MC_CMD_PHY_BIST_CABLE_LONG)) {
		ptr = MCDI_PTR(outbuf, POLL_BIST_OUT_SFT9001_CABLE_LENGTH_A);
		if (status == MC_CMD_POLL_BIST_PASSED &&
		    outlen >= MC_CMD_POLL_BIST_OUT_SFT9001_LEN) {
			for (i = 0; i < 8; i++) {
				results[count + i] =
					EFX_DWORD_FIELD(((efx_dword_t *)ptr)[i],
							EFX_DWORD_0);
			}
		}
		count += 8;
	}
	rc = count;

out:
	return rc;
}

static int efx_mcdi_phy_run_tests(struct efx_nic *efx, int *results,
				  unsigned flags)
{
	struct efx_mcdi_phy_data *phy_cfg = efx->phy_data;
	u32 mode;
	int rc;

	if (phy_cfg->flags & (1 << MC_CMD_GET_PHY_CFG_OUT_BIST_LBN)) {
		rc = efx_mcdi_bist(efx, MC_CMD_PHY_BIST, results);
		if (rc < 0)
			return rc;

		results += rc;
	}

	/* If we support both LONG and SHORT, then run each in response to
	 * break or not. Otherwise, run the one we support */
	mode = 0;
	if (phy_cfg->flags & (1 << MC_CMD_GET_PHY_CFG_OUT_BIST_CABLE_SHORT_LBN)) {
		if ((flags & ETH_TEST_FL_OFFLINE) &&
		    (phy_cfg->flags &
		     (1 << MC_CMD_GET_PHY_CFG_OUT_BIST_CABLE_LONG_LBN)))
			mode = MC_CMD_PHY_BIST_CABLE_LONG;
		else
			mode = MC_CMD_PHY_BIST_CABLE_SHORT;
	} else if (phy_cfg->flags &
		   (1 << MC_CMD_GET_PHY_CFG_OUT_BIST_CABLE_LONG_LBN))
		mode = MC_CMD_PHY_BIST_CABLE_LONG;

	if (mode != 0) {
		rc = efx_mcdi_bist(efx, mode, results);
		if (rc < 0)
			return rc;
		results += rc;
	}

	return 0;
}

static const char *efx_mcdi_phy_test_name(struct efx_nic *efx,
					  unsigned int index)
{
	struct efx_mcdi_phy_data *phy_cfg = efx->phy_data;

	if (phy_cfg->flags & (1 << MC_CMD_GET_PHY_CFG_OUT_BIST_LBN)) {
		if (index == 0)
			return "bist";
		--index;
	}

	if (phy_cfg->flags & ((1 << MC_CMD_GET_PHY_CFG_OUT_BIST_CABLE_SHORT_LBN) |
			      (1 << MC_CMD_GET_PHY_CFG_OUT_BIST_CABLE_LONG_LBN))) {
		if (index == 0)
			return "cable";
		--index;

		if (efx->phy_type == PHY_TYPE_SFT9001B) {
			if (index < ARRAY_SIZE(mcdi_sft9001_cable_diag_names))
				return mcdi_sft9001_cable_diag_names[index];
			index -= ARRAY_SIZE(mcdi_sft9001_cable_diag_names);
		}
	}

	return NULL;
}

#define SFP_PAGE_SIZE		128
#define SFF_DIAG_TYPE_OFFSET	92
#define SFF_DIAG_ADDR_CHANGE	BIT(2)
#define SFF_8079_NUM_PAGES	2
#define SFF_8472_NUM_PAGES	4
#define SFF_8436_NUM_PAGES	5
#define SFF_DMT_LEVEL_OFFSET	94

/** efx_mcdi_phy_get_module_eeprom_page() - Get a single page of module eeprom
 * @efx:	NIC context
 * @page:	EEPROM page number
 * @data:	Destination data pointer
 * @offset:	Offset in page to copy from in to data
 * @space:	Space available in data
 *
 * Return:
 *   >=0 - amount of data copied
 *   <0  - error
 */
static int efx_mcdi_phy_get_module_eeprom_page(struct efx_nic *efx,
					       unsigned int page,
					       u8 *data, ssize_t offset,
					       ssize_t space)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_PHY_MEDIA_INFO_OUT_LENMAX);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_PHY_MEDIA_INFO_IN_LEN);
	size_t outlen;
	unsigned int payload_len;
	unsigned int to_copy;
	int rc;

	if (offset > SFP_PAGE_SIZE)
		return -EINVAL;

	to_copy = min(space, SFP_PAGE_SIZE - offset);

	MCDI_SET_DWORD(inbuf, GET_PHY_MEDIA_INFO_IN_PAGE, page);
	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_GET_PHY_MEDIA_INFO,
				inbuf, sizeof(inbuf),
				outbuf, sizeof(outbuf),
				&outlen);

	if (rc)
		return rc;

	if (outlen < (MC_CMD_GET_PHY_MEDIA_INFO_OUT_DATA_OFST +
			SFP_PAGE_SIZE))
		return -EIO;

	payload_len = MCDI_DWORD(outbuf, GET_PHY_MEDIA_INFO_OUT_DATALEN);
	if (payload_len != SFP_PAGE_SIZE)
		return -EIO;

	memcpy(data, MCDI_PTR(outbuf, GET_PHY_MEDIA_INFO_OUT_DATA) + offset,
	       to_copy);

	return to_copy;
}

static int efx_mcdi_phy_get_module_eeprom_byte(struct efx_nic *efx,
					       unsigned int page,
					       u8 byte)
{
	int rc;
	u8 data;

	rc = efx_mcdi_phy_get_module_eeprom_page(efx, page, &data, byte, 1);
	if (rc == 1)
		return data;

	return rc;
}

static int efx_mcdi_phy_diag_type(struct efx_nic *efx)
{
	/* Page zero of the EEPROM includes the diagnostic type at byte 92. */
	return efx_mcdi_phy_get_module_eeprom_byte(efx, 0,
						   SFF_DIAG_TYPE_OFFSET);
}

static int efx_mcdi_phy_sff_8472_level(struct efx_nic *efx)
{
	/* Page zero of the EEPROM includes the DMT level at byte 94. */
	return efx_mcdi_phy_get_module_eeprom_byte(efx, 0,
						   SFF_DMT_LEVEL_OFFSET);
}

static u32 efx_mcdi_phy_module_type(struct efx_nic *efx)
{
	struct efx_mcdi_phy_data *phy_data = efx->phy_data;

	if (phy_data->media != MC_CMD_MEDIA_QSFP_PLUS)
		return phy_data->media;

	/* A QSFP+ NIC may actually have an SFP+ module attached.
	 * The ID is page 0, byte 0.
	 */
	switch (efx_mcdi_phy_get_module_eeprom_byte(efx, 0, 0)) {
	case 0x3:
		return MC_CMD_MEDIA_SFP_PLUS;
	case 0xc:
	case 0xd:
		return MC_CMD_MEDIA_QSFP_PLUS;
	default:
		return 0;
	}
}

static int efx_mcdi_phy_get_module_eeprom(struct efx_nic *efx,
					  struct ethtool_eeprom *ee, u8 *data)
{
	int rc;
	ssize_t space_remaining = ee->len;
	unsigned int page_off;
	bool ignore_missing;
	int num_pages;
	int page;

	switch (efx_mcdi_phy_module_type(efx)) {
	case MC_CMD_MEDIA_SFP_PLUS:
		num_pages = efx_mcdi_phy_sff_8472_level(efx) > 0 ?
				SFF_8472_NUM_PAGES : SFF_8079_NUM_PAGES;
		page = 0;
		ignore_missing = false;
		break;
	case MC_CMD_MEDIA_QSFP_PLUS:
		num_pages = SFF_8436_NUM_PAGES;
		page = -1; /* We obtain the lower page by asking for -1. */
		ignore_missing = true; /* Ignore missing pages after page 0. */
		break;
	default:
		return -EOPNOTSUPP;
	}

	page_off = ee->offset % SFP_PAGE_SIZE;
	page += ee->offset / SFP_PAGE_SIZE;

	while (space_remaining && (page < num_pages)) {
		rc = efx_mcdi_phy_get_module_eeprom_page(efx, page,
							 data, page_off,
							 space_remaining);

		if (rc > 0) {
			space_remaining -= rc;
			data += rc;
			page_off = 0;
			page++;
		} else if (rc == 0) {
			space_remaining = 0;
		} else if (ignore_missing && (page > 0)) {
			int intended_size = SFP_PAGE_SIZE - page_off;

			space_remaining -= intended_size;
			if (space_remaining < 0) {
				space_remaining = 0;
			} else {
				memset(data, 0, intended_size);
				data += intended_size;
				page_off = 0;
				page++;
				rc = 0;
			}
		} else {
			return rc;
		}
	}

	return 0;
}

static int efx_mcdi_phy_get_module_info(struct efx_nic *efx,
					struct ethtool_modinfo *modinfo)
{
	int sff_8472_level;
	int diag_type;

	switch (efx_mcdi_phy_module_type(efx)) {
	case MC_CMD_MEDIA_SFP_PLUS:
		sff_8472_level = efx_mcdi_phy_sff_8472_level(efx);

		/* If we can't read the diagnostics level we have none. */
		if (sff_8472_level < 0)
			return -EOPNOTSUPP;

		/* Check if this module requires the (unsupported) address
		 * change operation.
		 */
		diag_type = efx_mcdi_phy_diag_type(efx);

		if ((sff_8472_level == 0) ||
		    (diag_type & SFF_DIAG_ADDR_CHANGE)) {
			modinfo->type = ETH_MODULE_SFF_8079;
			modinfo->eeprom_len = ETH_MODULE_SFF_8079_LEN;
		} else {
			modinfo->type = ETH_MODULE_SFF_8472;
			modinfo->eeprom_len = ETH_MODULE_SFF_8472_LEN;
		}
		break;

	case MC_CMD_MEDIA_QSFP_PLUS:
		modinfo->type = ETH_MODULE_SFF_8436;
		modinfo->eeprom_len = ETH_MODULE_SFF_8436_LEN;
		break;

	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static const struct efx_phy_operations efx_mcdi_phy_ops = {
	.probe		= efx_mcdi_phy_probe,
	.init		= efx_port_dummy_op_int,
	.reconfigure	= efx_mcdi_port_reconfigure,
	.poll		= efx_mcdi_phy_poll,
	.fini		= efx_port_dummy_op_void,
	.remove		= efx_mcdi_phy_remove,
	.get_link_ksettings = efx_mcdi_phy_get_link_ksettings,
	.set_link_ksettings = efx_mcdi_phy_set_link_ksettings,
	.get_fecparam	= efx_mcdi_phy_get_fecparam,
	.set_fecparam	= efx_mcdi_phy_set_fecparam,
	.test_alive	= efx_mcdi_phy_test_alive,
	.run_tests	= efx_mcdi_phy_run_tests,
	.test_name	= efx_mcdi_phy_test_name,
	.get_module_eeprom = efx_mcdi_phy_get_module_eeprom,
	.get_module_info = efx_mcdi_phy_get_module_info,
};

u32 efx_mcdi_phy_get_caps(struct efx_nic *efx)
{
	struct efx_mcdi_phy_data *phy_data = efx->phy_data;

	return phy_data->supported_cap;
}

bool efx_mcdi_mac_check_fault(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_LINK_OUT_LEN);
	size_t outlength;
	int rc;

	BUILD_BUG_ON(MC_CMD_GET_LINK_IN_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_LINK, NULL, 0,
			  outbuf, sizeof(outbuf), &outlength);
	if (rc)
		return true;

	return MCDI_DWORD(outbuf, GET_LINK_OUT_MAC_FAULT) != 0;
}

enum efx_stats_action {
	EFX_STATS_ENABLE,
	EFX_STATS_DISABLE,
	EFX_STATS_PULL,
};

static int efx_mcdi_mac_stats(struct efx_nic *efx,
			      enum efx_stats_action action, int clear)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAC_STATS_IN_LEN);
	int rc;
	int change = action == EFX_STATS_PULL ? 0 : 1;
	int enable = action == EFX_STATS_ENABLE ? 1 : 0;
	int period = action == EFX_STATS_ENABLE ? 1000 : 0;
	dma_addr_t dma_addr = efx->stats_buffer.dma_addr;
	u32 dma_len = action != EFX_STATS_DISABLE ?
		efx->num_mac_stats * sizeof(u64) : 0;

	BUILD_BUG_ON(MC_CMD_MAC_STATS_OUT_DMA_LEN != 0);

	MCDI_SET_QWORD(inbuf, MAC_STATS_IN_DMA_ADDR, dma_addr);
	MCDI_POPULATE_DWORD_7(inbuf, MAC_STATS_IN_CMD,
			      MAC_STATS_IN_DMA, !!enable,
			      MAC_STATS_IN_CLEAR, clear,
			      MAC_STATS_IN_PERIODIC_CHANGE, change,
			      MAC_STATS_IN_PERIODIC_ENABLE, enable,
			      MAC_STATS_IN_PERIODIC_CLEAR, 0,
			      MAC_STATS_IN_PERIODIC_NOEVENT, 1,
			      MAC_STATS_IN_PERIOD_MS, period);
	MCDI_SET_DWORD(inbuf, MAC_STATS_IN_DMA_LEN, dma_len);

	if (efx_nic_rev(efx) >= EFX_REV_HUNT_A0)
		MCDI_SET_DWORD(inbuf, MAC_STATS_IN_PORT_ID, efx->vport_id);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_MAC_STATS, inbuf, sizeof(inbuf),
				NULL, 0, NULL);
	/* Expect ENOENT if DMA queues have not been set up */
	if (rc && (rc != -ENOENT || atomic_read(&efx->active_queues)))
		efx_mcdi_display_error(efx, MC_CMD_MAC_STATS, sizeof(inbuf),
				       NULL, 0, rc);
	return rc;
}

void efx_mcdi_mac_start_stats(struct efx_nic *efx)
{
	__le64 *dma_stats = efx->stats_buffer.addr;

	dma_stats[efx->num_mac_stats - 1] = EFX_MC_STATS_GENERATION_INVALID;

	efx_mcdi_mac_stats(efx, EFX_STATS_ENABLE, 0);
}

void efx_mcdi_mac_stop_stats(struct efx_nic *efx)
{
	efx_mcdi_mac_stats(efx, EFX_STATS_DISABLE, 0);
}

#define EFX_MAC_STATS_WAIT_US 100
#define EFX_MAC_STATS_WAIT_ATTEMPTS 10

void efx_mcdi_mac_pull_stats(struct efx_nic *efx)
{
	__le64 *dma_stats = efx->stats_buffer.addr;
	int attempts = EFX_MAC_STATS_WAIT_ATTEMPTS;

	dma_stats[efx->num_mac_stats - 1] = EFX_MC_STATS_GENERATION_INVALID;
	efx_mcdi_mac_stats(efx, EFX_STATS_PULL, 0);

	while (dma_stats[efx->num_mac_stats - 1] ==
				EFX_MC_STATS_GENERATION_INVALID &&
			attempts-- != 0)
		udelay(EFX_MAC_STATS_WAIT_US);
}

int efx_mcdi_port_probe(struct efx_nic *efx)
{
	int rc;

	/* Hook in PHY operations table */
	efx->phy_op = &efx_mcdi_phy_ops;

	/* Set up MDIO structure for PHY */
	efx->mdio.mode_support = MDIO_SUPPORTS_C45 | MDIO_EMULATE_C22;
	efx->mdio.mdio_read = efx_mcdi_mdio_read;
	efx->mdio.mdio_write = efx_mcdi_mdio_write;

	/* Fill out MDIO structure, loopback modes, and initial link state */
	rc = efx->phy_op->probe(efx);
	if (rc != 0)
		return rc;

	/* Allocate buffer for stats */
	rc = efx_nic_alloc_buffer(efx, &efx->stats_buffer,
				  efx->num_mac_stats * sizeof(u64), GFP_KERNEL);
	if (rc)
		return rc;
	netif_dbg(efx, probe, efx->net_dev,
		  "stats buffer at %llx (virt %p phys %llx)\n",
		  (u64)efx->stats_buffer.dma_addr,
		  efx->stats_buffer.addr,
		  (u64)virt_to_phys(efx->stats_buffer.addr));

	efx_mcdi_mac_stats(efx, EFX_STATS_DISABLE, 1);

	return 0;
}

void efx_mcdi_port_remove(struct efx_nic *efx)
{
	efx->phy_op->remove(efx);
	efx_nic_free_buffer(efx, &efx->stats_buffer);
}
