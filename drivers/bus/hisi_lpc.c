// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Hisilicon Limited, All Rights Reserved.
 * Author: Zhichang Yuan <yuanzhichang@hisilicon.com>
 * Author: Zou Rongrong <zourongrong@huawei.com>
 * Author: John Garry <john.garry@huawei.com>
 *
 */

#include <linux/acpi.h>
#include <linux/console.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/logic_pio.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/slab.h>

#define DRV_NAME "hisi-lpc"

/*
 * Setting this bit means each IO operation will target to a
 * different port address:
 * 0 means repeatedly IO operations will stick on the same port,
 * such as BT;
 */
#define FG_INCRADDR_LPC		0x02

struct lpc_cycle_para {
	unsigned int opflags;
	unsigned int csize; /* the data length of each operation */
};

struct hisi_lpc_dev {
	spinlock_t cycle_lock;
	void __iomem  *membase;
	struct logic_pio_hwaddr *io_host;
};

/* The maximum continuous cycles per burst */
#define LPC_MAX_BURST	16
/* The IO cycle counts supported is four per operation at maximum */
#define LPC_MAX_DULEN	4
#if LPC_MAX_DULEN > LPC_MAX_BURST
#error "LPC.. MAX_DULEN must be not bigger than MAX_OPCNT!"
#endif

#if LPC_MAX_BURST % LPC_MAX_DULEN
#error "LPC.. LPC_MAX_BURST must be multiple of LPC_MAX_DULEN!"
#endif

#define LPC_REG_START		0x00 /* start a new LPC cycle */
#define LPC_REG_OP_STATUS	0x04 /* the current LPC status */
#define LPC_REG_IRQ_ST		0x08 /* interrupt enable&status */
#define LPC_REG_OP_LEN		0x10 /* how many LPC cycles each start */
#define LPC_REG_CMD		0x14 /* command for the required LPC cycle */
#define LPC_REG_ADDR		0x20 /* LPC target address */
#define LPC_REG_WDATA		0x24 /* data to be written */
#define LPC_REG_RDATA		0x28 /* data coming from peer */


/* The command register fields */
#define LPC_CMD_SAMEADDR	0x08
#define LPC_CMD_TYPE_IO		0x00
#define LPC_CMD_WRITE		0x01
#define LPC_CMD_READ		0x00
/* the bit attribute is W1C. 1 represents OK. */
#define LPC_STAT_BYIRQ		0x02

#define LPC_STATUS_IDLE		0x01
#define LPC_OP_FINISHED		0x02

#define LPC_START_WORK		0x01

/* The minimal nanosecond interval for each query on LPC cycle status. */
#define LPC_NSEC_PERWAIT	100

/*
 * The maximum waiting time is about 128us.
 * It is specific for stream I/O, such as ins.
 * The fastest IO cycle time is about 390ns, but the worst case will wait
 * for extra 256 lpc clocks, so (256 + 13) * 30ns = 8 us. The maximum
 * burst cycles is 16. So, the maximum waiting time is about 128us under
 * worst case.
 * choose 1300 as the maximum.
 */
#define LPC_MAX_WAITCNT		1300
/* About 10us. This is specific for single IO operation, such as inb. */
#define LPC_PEROP_WAITCNT	100

static inline int wait_lpc_idle(unsigned char *mbase,
				unsigned int waitcnt) {
	u32 opstatus;

	while (waitcnt--) {
		ndelay(LPC_NSEC_PERWAIT);
		opstatus = readl(mbase + LPC_REG_OP_STATUS);
		if (opstatus & LPC_STATUS_IDLE)
			return (opstatus & LPC_OP_FINISHED) ? 0 : (-EIO);
	}
	return -ETIME;
}

/*
 * hisi_lpc_target_in - trigger a series of LPC cycles for read operation
 * @lpcdev: pointer to hisi lpc device
 * @para: some parameters used to control the lpc I/O operations
 * @addr: the lpc I/O target port address
 * @buf: where the read back data is stored
 * @opcnt: how many I/O operations required, i.e. data width
 *
 * Returns 0 on success, non-zero on fail.
 */
static int
hisi_lpc_target_in(struct hisi_lpc_dev *lpcdev, struct lpc_cycle_para *para,
		  unsigned long addr, unsigned char *buf,
		  unsigned long opcnt)
{
	unsigned int cmd_word;
	unsigned int waitcnt;
	unsigned long flags;
	int ret;

	if (!buf || !opcnt || !para || !para->csize || !lpcdev)
		return -EINVAL;

	cmd_word = LPC_CMD_TYPE_IO | LPC_CMD_READ;
	waitcnt = LPC_PEROP_WAITCNT;
	if (!(para->opflags & FG_INCRADDR_LPC)) {
		cmd_word |= LPC_CMD_SAMEADDR;
		waitcnt = LPC_MAX_WAITCNT;
	}

	ret = 0;

	/* whole operation must be atomic */
	spin_lock_irqsave(&lpcdev->cycle_lock, flags);

	writel_relaxed(opcnt, lpcdev->membase + LPC_REG_OP_LEN);

	writel_relaxed(cmd_word, lpcdev->membase + LPC_REG_CMD);

	writel_relaxed(addr, lpcdev->membase + LPC_REG_ADDR);

	writel(LPC_START_WORK, lpcdev->membase + LPC_REG_START);

	/* whether the operation is finished */
	ret = wait_lpc_idle(lpcdev->membase, waitcnt);
	if (!ret) {
		for (; opcnt; opcnt--, buf++)
			*buf = readb(lpcdev->membase + LPC_REG_RDATA);
	}

	spin_unlock_irqrestore(&lpcdev->cycle_lock, flags);

	return ret;
}

/*
 * hisi_lpc_target_out - trigger a series of LPC cycles for write operation
 * @lpcdev: pointer to hisi lpc device
 * @para: some parameters used to control the lpc I/O operations
 * @addr: the lpc I/O target port address
 * @buf: where the data to be written is stored
 * @opcnt: how many I/O operations required, i.e. data width
 *
 * Returns 0 on success, non-zero on fail.
 */
static int
hisi_lpc_target_out(struct hisi_lpc_dev *lpcdev, struct lpc_cycle_para *para,
		    unsigned long addr, const unsigned char *buf,
		    unsigned long opcnt)
{
	unsigned int cmd_word;
	unsigned int waitcnt;
	unsigned long flags;
	int ret;

	if (!buf || !opcnt || !para || !lpcdev)
		return -EINVAL;

	/* default is increasing address */
	cmd_word = LPC_CMD_TYPE_IO | LPC_CMD_WRITE;
	waitcnt = LPC_PEROP_WAITCNT;
	if (!(para->opflags & FG_INCRADDR_LPC)) {
		cmd_word |= LPC_CMD_SAMEADDR;
		waitcnt = LPC_MAX_WAITCNT;
	}

	spin_lock_irqsave(&lpcdev->cycle_lock, flags);

	writel_relaxed(opcnt, lpcdev->membase + LPC_REG_OP_LEN);
	writel_relaxed(cmd_word, lpcdev->membase + LPC_REG_CMD);
	writel_relaxed(addr, lpcdev->membase + LPC_REG_ADDR);

	for (; opcnt; buf++, opcnt--)
		writeb(*buf, lpcdev->membase + LPC_REG_WDATA);

	writel(LPC_START_WORK, lpcdev->membase + LPC_REG_START);

	/* whether the operation is finished */
	ret = wait_lpc_idle(lpcdev->membase, waitcnt);

	spin_unlock_irqrestore(&lpcdev->cycle_lock, flags);

	return ret;
}

static inline unsigned long
hisi_lpc_pio_to_addr(struct hisi_lpc_dev *lpcdev, unsigned long pio)
{
	return pio - lpcdev->io_host->io_start +
		lpcdev->io_host->hw_start;
}

/*
 * hisi_lpc_comm_in - input the data in a single operation
 * @hostdata: pointer to the device information relevant to LPC controller.
 * @pio: the target I/O port address.
 * @dwidth: the data length required to read from the target I/O port.
 *
 * When success, data is returned. Otherwise, -1 is returned.
 */
static u32 hisi_lpc_comm_in(void *hostdata, unsigned long pio, size_t dwidth)
{
	struct hisi_lpc_dev *lpcdev = hostdata;
	struct lpc_cycle_para iopara;
	u32 rd_data = 0;
	unsigned long addr;
	int ret = 0;

	if (!lpcdev || !dwidth || dwidth > LPC_MAX_DULEN)
		return -1;

	addr = hisi_lpc_pio_to_addr(lpcdev, pio);

	iopara.opflags = FG_INCRADDR_LPC;
	iopara.csize = dwidth;

	ret = hisi_lpc_target_in(lpcdev, &iopara, addr,
				 (unsigned char *)&rd_data, dwidth);
	if (ret)
		return -1;

	return le32_to_cpu(rd_data);
}

/*
 * hisi_lpc_comm_out - output the data in a single operation
 * @hostdata: pointer to the device information relevant to LPC controller.
 * @pio: the target I/O port address.
 * @val: a value to be outputted from caller, maximum is four bytes.
 * @dwidth: the data width required writing to the target I/O port.
 *
 * This function is corresponding to out(b,w,l) only
 *
 */
static void hisi_lpc_comm_out(void *hostdata, unsigned long pio,
			     u32 val, size_t dwidth)
{
	struct hisi_lpc_dev *lpcdev = hostdata;
	struct lpc_cycle_para iopara;
	const unsigned char *buf;
	unsigned long addr;

	if (!lpcdev || !dwidth || dwidth > LPC_MAX_DULEN)
		return;

	val = cpu_to_le32(val);

	buf = (const unsigned char *)&val;
	addr = hisi_lpc_pio_to_addr(lpcdev, pio);

	iopara.opflags = FG_INCRADDR_LPC;
	iopara.csize = dwidth;

	hisi_lpc_target_out(lpcdev, &iopara, addr, buf, dwidth);
}

/*
 * hisi_lpc_comm_ins - input the data in the buffer in multiple operations
 * @hostdata: pointer to the device information relevant to LPC controller.
 * @pio: the target I/O port address.
 * @buffer: a buffer where read/input data bytes are stored.
 * @dwidth: the data width required writing to the target I/O port.
 * @count: how many data units whose length is dwidth will be read.
 *
 * When success, the data read back is stored in buffer pointed by buffer.
 * Returns 0 on success, -errno otherwise
 *
 */
static u32
hisi_lpc_comm_ins(void *hostdata, unsigned long pio, void *buffer,
		  size_t dwidth, unsigned int count)
{
	struct hisi_lpc_dev *lpcdev = hostdata;
	unsigned char *buf = buffer;
	struct lpc_cycle_para iopara;
	unsigned long addr;

	if (!lpcdev || !buf || !count || !dwidth || dwidth > LPC_MAX_DULEN)
		return -EINVAL;

	iopara.opflags = 0;
	if (dwidth > 1)
		iopara.opflags |= FG_INCRADDR_LPC;
	iopara.csize = dwidth;

	addr = hisi_lpc_pio_to_addr(lpcdev, pio);

	do {
		int ret;

		ret = hisi_lpc_target_in(lpcdev, &iopara, addr,
					buf, dwidth);
		if (ret)
			return ret;
		buf += dwidth;
		count--;
	} while (count);

	return 0;
}

/*
 * hisi_lpc_comm_outs - output the data in the buffer in multiple operations
 * @hostdata: pointer to the device information relevant to LPC controller.
 * @pio: the target I/O port address.
 * @buffer: a buffer where write/output data bytes are stored.
 * @dwidth: the data width required writing to the target I/O port .
 * @count: how many data units whose length is dwidth will be written.
 *
 */
static void
hisi_lpc_comm_outs(void *hostdata, unsigned long pio, const void *buffer,
		   size_t dwidth, unsigned int count)
{
	struct hisi_lpc_dev *lpcdev = hostdata;
	struct lpc_cycle_para iopara;
	const unsigned char *buf = buffer;
	unsigned long addr;

	if (!lpcdev || !buf || !count || !dwidth || dwidth > LPC_MAX_DULEN)
		return;

	iopara.opflags = 0;
	if (dwidth > 1)
		iopara.opflags |= FG_INCRADDR_LPC;
	iopara.csize = dwidth;

	addr = hisi_lpc_pio_to_addr(lpcdev, pio);
	do {
		if (hisi_lpc_target_out(lpcdev, &iopara, addr, buf,
						dwidth))
			break;
		buf += dwidth;
		count--;
	} while (count);
}

static const struct logic_pio_host_ops hisi_lpc_ops = {
	.in = hisi_lpc_comm_in,
	.out = hisi_lpc_comm_out,
	.ins = hisi_lpc_comm_ins,
	.outs = hisi_lpc_comm_outs,
};

/*
 * hisi_lpc_probe - the probe callback function for hisi lpc host,
 *		   will finish all the initialization.
 * @pdev: the platform device corresponding to hisi lpc host
 *
 * Returns 0 on success, non-zero on fail.
 */
static int hisi_lpc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct acpi_device *acpi_device = ACPI_COMPANION(dev);
	struct logic_pio_hwaddr *range;
	struct hisi_lpc_dev *lpcdev;
	struct resource *res;
	int ret = 0;

	lpcdev = devm_kzalloc(dev, sizeof(struct hisi_lpc_dev), GFP_KERNEL);
	if (!lpcdev)
		return -ENOMEM;

	spin_lock_init(&lpcdev->cycle_lock);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;

	lpcdev->membase = devm_ioremap_resource(dev, res);
	if (IS_ERR(lpcdev->membase)) {
		dev_err(dev, "remap failed\n");
		return PTR_ERR(lpcdev->membase);
	}

	range = devm_kzalloc(dev, sizeof(*range), GFP_KERNEL);
	if (!range)
		return -ENOMEM;
	range->fwnode = dev->fwnode;
	range->flags = PIO_INDIRECT;
	range->size = PIO_INDIRECT_SIZE;

	ret = logic_pio_register_range(range);
	if (ret) {
		dev_err(dev, "register IO range failed (%d)!\n", ret);
		return ret;
	}
	lpcdev->io_host = range;

	/* register the LPC host PIO resources */
	if (!acpi_device)
		ret = of_platform_populate(dev->of_node, NULL, NULL, dev);
	if (ret) {
		dev_err(dev, "populate children failed (%d)\n", ret);
		return ret;
	}

	lpcdev->io_host->hostdata = lpcdev;
	lpcdev->io_host->ops = &hisi_lpc_ops;

	dev_info(dev, "registered range[%pa - sz:%pa]\n",
		 &lpcdev->io_host->io_start,
		 &lpcdev->io_host->size);

	return ret;
}

static const struct of_device_id hisi_lpc_of_match[] = {
	{ .compatible = "hisilicon,hip06-lpc", },
	{ .compatible = "hisilicon,hip07-lpc", },
	{}
};

static struct platform_driver hisi_lpc_driver = {
	.driver = {
		.name           = DRV_NAME,
		.of_match_table = hisi_lpc_of_match,
	},
	.probe = hisi_lpc_probe,
};

builtin_platform_driver(hisi_lpc_driver);
