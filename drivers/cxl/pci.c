// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2020 Intel Corporation. All rights reserved. */
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/io.h>
#include "cxlmem.h"
#include "pci.h"
#include "cxl.h"

/**
 * DOC: cxl pci
 *
 * This implements the PCI exclusive functionality for a CXL device as it is
 * defined by the Compute Express Link specification. CXL devices may surface
 * certain functionality even if it isn't CXL enabled. While this driver is
 * focused around the PCI specific aspects of a CXL device, it binds to the
 * specific CXL memory device class code, and therefore the implementation of
 * cxl_pci is focused around CXL memory devices.
 *
 * The driver has several responsibilities, mainly:
 *  - Create the memX device and register on the CXL bus.
 *  - Enumerate device's register interface and map them.
 *  - Registers nvdimm bridge device with cxl_core.
 *  - Registers a CXL mailbox with cxl_core.
 */

#define cxl_doorbell_busy(cxlm)                                                \
	(readl((cxlm)->regs.mbox + CXLDEV_MBOX_CTRL_OFFSET) &                  \
	 CXLDEV_MBOX_CTRL_DOORBELL)

/* CXL 2.0 - 8.2.8.4 */
#define CXL_MAILBOX_TIMEOUT_MS (2 * HZ)

static int cxl_pci_mbox_wait_for_doorbell(struct cxl_mem *cxlm)
{
	const unsigned long start = jiffies;
	unsigned long end = start;

	while (cxl_doorbell_busy(cxlm)) {
		end = jiffies;

		if (time_after(end, start + CXL_MAILBOX_TIMEOUT_MS)) {
			/* Check again in case preempted before timeout test */
			if (!cxl_doorbell_busy(cxlm))
				break;
			return -ETIMEDOUT;
		}
		cpu_relax();
	}

	dev_dbg(cxlm->dev, "Doorbell wait took %dms",
		jiffies_to_msecs(end) - jiffies_to_msecs(start));
	return 0;
}

static void cxl_pci_mbox_timeout(struct cxl_mem *cxlm,
				 struct cxl_mbox_cmd *mbox_cmd)
{
	struct device *dev = cxlm->dev;

	dev_dbg(dev, "Mailbox command (opcode: %#x size: %zub) timed out\n",
		mbox_cmd->opcode, mbox_cmd->size_in);
}

/**
 * __cxl_pci_mbox_send_cmd() - Execute a mailbox command
 * @cxlm: The CXL memory device to communicate with.
 * @mbox_cmd: Command to send to the memory device.
 *
 * Context: Any context. Expects mbox_mutex to be held.
 * Return: -ETIMEDOUT if timeout occurred waiting for completion. 0 on success.
 *         Caller should check the return code in @mbox_cmd to make sure it
 *         succeeded.
 *
 * This is a generic form of the CXL mailbox send command thus only using the
 * registers defined by the mailbox capability ID - CXL 2.0 8.2.8.4. Memory
 * devices, and perhaps other types of CXL devices may have further information
 * available upon error conditions. Driver facilities wishing to send mailbox
 * commands should use the wrapper command.
 *
 * The CXL spec allows for up to two mailboxes. The intention is for the primary
 * mailbox to be OS controlled and the secondary mailbox to be used by system
 * firmware. This allows the OS and firmware to communicate with the device and
 * not need to coordinate with each other. The driver only uses the primary
 * mailbox.
 */
static int __cxl_pci_mbox_send_cmd(struct cxl_mem *cxlm,
				   struct cxl_mbox_cmd *mbox_cmd)
{
	void __iomem *payload = cxlm->regs.mbox + CXLDEV_MBOX_PAYLOAD_OFFSET;
	struct device *dev = cxlm->dev;
	u64 cmd_reg, status_reg;
	size_t out_len;
	int rc;

	lockdep_assert_held(&cxlm->mbox_mutex);

	/*
	 * Here are the steps from 8.2.8.4 of the CXL 2.0 spec.
	 *   1. Caller reads MB Control Register to verify doorbell is clear
	 *   2. Caller writes Command Register
	 *   3. Caller writes Command Payload Registers if input payload is non-empty
	 *   4. Caller writes MB Control Register to set doorbell
	 *   5. Caller either polls for doorbell to be clear or waits for interrupt if configured
	 *   6. Caller reads MB Status Register to fetch Return code
	 *   7. If command successful, Caller reads Command Register to get Payload Length
	 *   8. If output payload is non-empty, host reads Command Payload Registers
	 *
	 * Hardware is free to do whatever it wants before the doorbell is rung,
	 * and isn't allowed to change anything after it clears the doorbell. As
	 * such, steps 2 and 3 can happen in any order, and steps 6, 7, 8 can
	 * also happen in any order (though some orders might not make sense).
	 */

	/* #1 */
	if (cxl_doorbell_busy(cxlm)) {
		dev_err_ratelimited(dev, "Mailbox re-busy after acquiring\n");
		return -EBUSY;
	}

	cmd_reg = FIELD_PREP(CXLDEV_MBOX_CMD_COMMAND_OPCODE_MASK,
			     mbox_cmd->opcode);
	if (mbox_cmd->size_in) {
		if (WARN_ON(!mbox_cmd->payload_in))
			return -EINVAL;

		cmd_reg |= FIELD_PREP(CXLDEV_MBOX_CMD_PAYLOAD_LENGTH_MASK,
				      mbox_cmd->size_in);
		memcpy_toio(payload, mbox_cmd->payload_in, mbox_cmd->size_in);
	}

	/* #2, #3 */
	writeq(cmd_reg, cxlm->regs.mbox + CXLDEV_MBOX_CMD_OFFSET);

	/* #4 */
	dev_dbg(dev, "Sending command\n");
	writel(CXLDEV_MBOX_CTRL_DOORBELL,
	       cxlm->regs.mbox + CXLDEV_MBOX_CTRL_OFFSET);

	/* #5 */
	rc = cxl_pci_mbox_wait_for_doorbell(cxlm);
	if (rc == -ETIMEDOUT) {
		cxl_pci_mbox_timeout(cxlm, mbox_cmd);
		return rc;
	}

	/* #6 */
	status_reg = readq(cxlm->regs.mbox + CXLDEV_MBOX_STATUS_OFFSET);
	mbox_cmd->return_code =
		FIELD_GET(CXLDEV_MBOX_STATUS_RET_CODE_MASK, status_reg);

	if (mbox_cmd->return_code != 0) {
		dev_dbg(dev, "Mailbox operation had an error\n");
		return 0;
	}

	/* #7 */
	cmd_reg = readq(cxlm->regs.mbox + CXLDEV_MBOX_CMD_OFFSET);
	out_len = FIELD_GET(CXLDEV_MBOX_CMD_PAYLOAD_LENGTH_MASK, cmd_reg);

	/* #8 */
	if (out_len && mbox_cmd->payload_out) {
		/*
		 * Sanitize the copy. If hardware misbehaves, out_len per the
		 * spec can actually be greater than the max allowed size (21
		 * bits available but spec defined 1M max). The caller also may
		 * have requested less data than the hardware supplied even
		 * within spec.
		 */
		size_t n = min3(mbox_cmd->size_out, cxlm->payload_size, out_len);

		memcpy_fromio(mbox_cmd->payload_out, payload, n);
		mbox_cmd->size_out = n;
	} else {
		mbox_cmd->size_out = 0;
	}

	return 0;
}

/**
 * cxl_pci_mbox_get() - Acquire exclusive access to the mailbox.
 * @cxlm: The memory device to gain access to.
 *
 * Context: Any context. Takes the mbox_mutex.
 * Return: 0 if exclusive access was acquired.
 */
static int cxl_pci_mbox_get(struct cxl_mem *cxlm)
{
	struct device *dev = cxlm->dev;
	u64 md_status;
	int rc;

	mutex_lock_io(&cxlm->mbox_mutex);

	/*
	 * XXX: There is some amount of ambiguity in the 2.0 version of the spec
	 * around the mailbox interface ready (8.2.8.5.1.1).  The purpose of the
	 * bit is to allow firmware running on the device to notify the driver
	 * that it's ready to receive commands. It is unclear if the bit needs
	 * to be read for each transaction mailbox, ie. the firmware can switch
	 * it on and off as needed. Second, there is no defined timeout for
	 * mailbox ready, like there is for the doorbell interface.
	 *
	 * Assumptions:
	 * 1. The firmware might toggle the Mailbox Interface Ready bit, check
	 *    it for every command.
	 *
	 * 2. If the doorbell is clear, the firmware should have first set the
	 *    Mailbox Interface Ready bit. Therefore, waiting for the doorbell
	 *    to be ready is sufficient.
	 */
	rc = cxl_pci_mbox_wait_for_doorbell(cxlm);
	if (rc) {
		dev_warn(dev, "Mailbox interface not ready\n");
		goto out;
	}

	md_status = readq(cxlm->regs.memdev + CXLMDEV_STATUS_OFFSET);
	if (!(md_status & CXLMDEV_MBOX_IF_READY && CXLMDEV_READY(md_status))) {
		dev_err(dev, "mbox: reported doorbell ready, but not mbox ready\n");
		rc = -EBUSY;
		goto out;
	}

	/*
	 * Hardware shouldn't allow a ready status but also have failure bits
	 * set. Spit out an error, this should be a bug report
	 */
	rc = -EFAULT;
	if (md_status & CXLMDEV_DEV_FATAL) {
		dev_err(dev, "mbox: reported ready, but fatal\n");
		goto out;
	}
	if (md_status & CXLMDEV_FW_HALT) {
		dev_err(dev, "mbox: reported ready, but halted\n");
		goto out;
	}
	if (CXLMDEV_RESET_NEEDED(md_status)) {
		dev_err(dev, "mbox: reported ready, but reset needed\n");
		goto out;
	}

	/* with lock held */
	return 0;

out:
	mutex_unlock(&cxlm->mbox_mutex);
	return rc;
}

/**
 * cxl_pci_mbox_put() - Release exclusive access to the mailbox.
 * @cxlm: The CXL memory device to communicate with.
 *
 * Context: Any context. Expects mbox_mutex to be held.
 */
static void cxl_pci_mbox_put(struct cxl_mem *cxlm)
{
	mutex_unlock(&cxlm->mbox_mutex);
}

static int cxl_pci_mbox_send(struct cxl_mem *cxlm, struct cxl_mbox_cmd *cmd)
{
	int rc;

	rc = cxl_pci_mbox_get(cxlm);
	if (rc)
		return rc;

	rc = __cxl_pci_mbox_send_cmd(cxlm, cmd);
	cxl_pci_mbox_put(cxlm);

	return rc;
}

static int cxl_pci_setup_mailbox(struct cxl_mem *cxlm)
{
	const int cap = readl(cxlm->regs.mbox + CXLDEV_MBOX_CAPS_OFFSET);

	cxlm->mbox_send = cxl_pci_mbox_send;
	cxlm->payload_size =
		1 << FIELD_GET(CXLDEV_MBOX_CAP_PAYLOAD_SIZE_MASK, cap);

	/*
	 * CXL 2.0 8.2.8.4.3 Mailbox Capabilities Register
	 *
	 * If the size is too small, mandatory commands will not work and so
	 * there's no point in going forward. If the size is too large, there's
	 * no harm is soft limiting it.
	 */
	cxlm->payload_size = min_t(size_t, cxlm->payload_size, SZ_1M);
	if (cxlm->payload_size < 256) {
		dev_err(cxlm->dev, "Mailbox is too small (%zub)",
			cxlm->payload_size);
		return -ENXIO;
	}

	dev_dbg(cxlm->dev, "Mailbox payload sized %zu",
		cxlm->payload_size);

	return 0;
}

static int cxl_map_regblock(struct pci_dev *pdev, struct cxl_register_map *map)
{
	void __iomem *addr;
	int bar = map->barno;
	struct device *dev = &pdev->dev;
	resource_size_t offset = map->block_offset;

	/* Basic sanity check that BAR is big enough */
	if (pci_resource_len(pdev, bar) < offset) {
		dev_err(dev, "BAR%d: %pr: too small (offset: %pa)\n", bar,
			&pdev->resource[bar], &offset);
		return -ENXIO;
	}

	addr = pci_iomap(pdev, bar, 0);
	if (!addr) {
		dev_err(dev, "failed to map registers\n");
		return -ENOMEM;
	}

	dev_dbg(dev, "Mapped CXL Memory Device resource bar %u @ %pa\n",
		bar, &offset);

	map->base = addr + map->block_offset;
	return 0;
}

static void cxl_unmap_regblock(struct pci_dev *pdev,
			       struct cxl_register_map *map)
{
	pci_iounmap(pdev, map->base - map->block_offset);
	map->base = NULL;
}

static int cxl_probe_regs(struct pci_dev *pdev, struct cxl_register_map *map)
{
	struct cxl_component_reg_map *comp_map;
	struct cxl_device_reg_map *dev_map;
	struct device *dev = &pdev->dev;
	void __iomem *base = map->base;

	switch (map->reg_type) {
	case CXL_REGLOC_RBI_COMPONENT:
		comp_map = &map->component_map;
		cxl_probe_component_regs(dev, base, comp_map);
		if (!comp_map->hdm_decoder.valid) {
			dev_err(dev, "HDM decoder registers not found\n");
			return -ENXIO;
		}

		dev_dbg(dev, "Set up component registers\n");
		break;
	case CXL_REGLOC_RBI_MEMDEV:
		dev_map = &map->device_map;
		cxl_probe_device_regs(dev, base, dev_map);
		if (!dev_map->status.valid || !dev_map->mbox.valid ||
		    !dev_map->memdev.valid) {
			dev_err(dev, "registers not found: %s%s%s\n",
				!dev_map->status.valid ? "status " : "",
				!dev_map->mbox.valid ? "mbox " : "",
				!dev_map->memdev.valid ? "memdev " : "");
			return -ENXIO;
		}

		dev_dbg(dev, "Probing device registers...\n");
		break;
	default:
		break;
	}

	return 0;
}

static int cxl_map_regs(struct cxl_mem *cxlm, struct cxl_register_map *map)
{
	struct device *dev = cxlm->dev;
	struct pci_dev *pdev = to_pci_dev(dev);

	switch (map->reg_type) {
	case CXL_REGLOC_RBI_COMPONENT:
		cxl_map_component_regs(pdev, &cxlm->regs.component, map);
		dev_dbg(dev, "Mapping component registers...\n");
		break;
	case CXL_REGLOC_RBI_MEMDEV:
		cxl_map_device_regs(pdev, &cxlm->regs.device_regs, map);
		dev_dbg(dev, "Probing device registers...\n");
		break;
	default:
		break;
	}

	return 0;
}

static void cxl_decode_regblock(u32 reg_lo, u32 reg_hi,
				struct cxl_register_map *map)
{
	map->block_offset =
		((u64)reg_hi << 32) | (reg_lo & CXL_REGLOC_ADDR_MASK);
	map->barno = FIELD_GET(CXL_REGLOC_BIR_MASK, reg_lo);
	map->reg_type = FIELD_GET(CXL_REGLOC_RBI_MASK, reg_lo);
}

/**
 * cxl_find_regblock() - Locate register blocks by type
 * @pdev: The CXL PCI device to enumerate.
 * @type: Register Block Indicator id
 * @map: Enumeration output, clobbered on error
 *
 * Return: 0 if register block enumerated, negative error code otherwise
 *
 * A CXL DVSEC may point to one or more register blocks, search for them
 * by @type.
 */
static int cxl_find_regblock(struct pci_dev *pdev, enum cxl_regloc_type type,
			     struct cxl_register_map *map)
{
	u32 regloc_size, regblocks;
	int regloc, i;

	regloc = pci_find_dvsec_capability(pdev, PCI_DVSEC_VENDOR_ID_CXL,
					   PCI_DVSEC_ID_CXL_REGLOC_DVSEC_ID);
	if (!regloc)
		return -ENXIO;

	pci_read_config_dword(pdev, regloc + PCI_DVSEC_HEADER1, &regloc_size);
	regloc_size = FIELD_GET(PCI_DVSEC_HEADER1_LENGTH_MASK, regloc_size);

	regloc += PCI_DVSEC_ID_CXL_REGLOC_BLOCK1_OFFSET;
	regblocks = (regloc_size - PCI_DVSEC_ID_CXL_REGLOC_BLOCK1_OFFSET) / 8;

	for (i = 0; i < regblocks; i++, regloc += 8) {
		u32 reg_lo, reg_hi;

		pci_read_config_dword(pdev, regloc, &reg_lo);
		pci_read_config_dword(pdev, regloc + 4, &reg_hi);

		cxl_decode_regblock(reg_lo, reg_hi, map);

		if (map->reg_type == type)
			return 0;
	}

	return -ENODEV;
}

static int cxl_setup_regs(struct pci_dev *pdev, enum cxl_regloc_type type,
			  struct cxl_register_map *map)
{
	int rc;

	rc = cxl_find_regblock(pdev, type, map);
	if (rc)
		return rc;

	rc = cxl_map_regblock(pdev, map);
	if (rc)
		return rc;

	rc = cxl_probe_regs(pdev, map);
	cxl_unmap_regblock(pdev, map);

	return rc;
}

static int cxl_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct cxl_register_map map;
	struct cxl_memdev *cxlmd;
	struct cxl_mem *cxlm;
	int rc;

	/*
	 * Double check the anonymous union trickery in struct cxl_regs
	 * FIXME switch to struct_group()
	 */
	BUILD_BUG_ON(offsetof(struct cxl_regs, memdev) !=
		     offsetof(struct cxl_regs, device_regs.memdev));

	rc = pcim_enable_device(pdev);
	if (rc)
		return rc;

	cxlm = cxl_mem_create(&pdev->dev);
	if (IS_ERR(cxlm))
		return PTR_ERR(cxlm);

	rc = cxl_setup_regs(pdev, CXL_REGLOC_RBI_MEMDEV, &map);
	if (rc)
		return rc;

	rc = cxl_map_regs(cxlm, &map);
	if (rc)
		return rc;

	rc = cxl_pci_setup_mailbox(cxlm);
	if (rc)
		return rc;

	rc = cxl_mem_enumerate_cmds(cxlm);
	if (rc)
		return rc;

	rc = cxl_mem_identify(cxlm);
	if (rc)
		return rc;

	rc = cxl_mem_create_range_info(cxlm);
	if (rc)
		return rc;

	cxlmd = devm_cxl_add_memdev(cxlm);
	if (IS_ERR(cxlmd))
		return PTR_ERR(cxlmd);

	if (range_len(&cxlm->pmem_range) && IS_ENABLED(CONFIG_CXL_PMEM))
		rc = devm_cxl_add_nvdimm(&pdev->dev, cxlmd);

	return rc;
}

static const struct pci_device_id cxl_mem_pci_tbl[] = {
	/* PCI class code for CXL.mem Type-3 Devices */
	{ PCI_DEVICE_CLASS((PCI_CLASS_MEMORY_CXL << 8 | CXL_MEMORY_PROGIF), ~0)},
	{ /* terminate list */ },
};
MODULE_DEVICE_TABLE(pci, cxl_mem_pci_tbl);

static struct pci_driver cxl_pci_driver = {
	.name			= KBUILD_MODNAME,
	.id_table		= cxl_mem_pci_tbl,
	.probe			= cxl_pci_probe,
	.driver	= {
		.probe_type	= PROBE_PREFER_ASYNCHRONOUS,
	},
};

MODULE_LICENSE("GPL v2");
module_pci_driver(cxl_pci_driver);
MODULE_IMPORT_NS(CXL);
