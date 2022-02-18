/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Private data and functions for adjunct processor VFIO matrix driver.
 *
 * Author(s): Tony Krowiak <akrowiak@linux.ibm.com>
 *	      Halil Pasic <pasic@linux.ibm.com>
 *	      Pierre Morel <pmorel@linux.ibm.com>
 *
 * Copyright IBM Corp. 2018
 */

#ifndef _VFIO_AP_PRIVATE_H_
#define _VFIO_AP_PRIVATE_H_

#include <linux/types.h>
#include <linux/device.h>
#include <linux/mdev.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/kvm_host.h>
#include <linux/vfio.h>

#include "ap_bus.h"

#define VFIO_AP_MODULE_NAME "vfio_ap"
#define VFIO_AP_DRV_NAME "vfio_ap"

/**
 * struct ap_matrix_dev - Contains the data for the matrix device.
 *
 * @device:	generic device structure associated with the AP matrix device
 * @available_instances: number of mediated matrix devices that can be created
 * @info:	the struct containing the output from the PQAP(QCI) instruction
 * @mdev_list:	the list of mediated matrix devices created
 * @lock:	mutex for locking the AP matrix device. This lock will be
 *		taken every time we fiddle with state managed by the vfio_ap
 *		driver, be it using @mdev_list or writing the state of a
 *		single ap_matrix_mdev device. It's quite coarse but we don't
 *		expect much contention.
 * @vfio_ap_drv: the vfio_ap device driver
 */
struct ap_matrix_dev {
	struct device device;
	atomic_t available_instances;
	struct ap_config_info info;
	struct list_head mdev_list;
	struct mutex lock;
	struct ap_driver  *vfio_ap_drv;
};

extern struct ap_matrix_dev *matrix_dev;

/**
 * struct ap_matrix - matrix of adapters, domains and control domains
 *
 * @apm_max: max adapter number in @apm
 * @apm: identifies the AP adapters in the matrix
 * @aqm_max: max domain number in @aqm
 * @aqm: identifies the AP queues (domains) in the matrix
 * @adm_max: max domain number in @adm
 * @adm: identifies the AP control domains in the matrix
 *
 * The AP matrix is comprised of three bit masks identifying the adapters,
 * queues (domains) and control domains that belong to an AP matrix. The bits in
 * each mask, from left to right, correspond to IDs 0 to 255. When a bit is set
 * the corresponding ID belongs to the matrix.
 */
struct ap_matrix {
	unsigned long apm_max;
	DECLARE_BITMAP(apm, 256);
	unsigned long aqm_max;
	DECLARE_BITMAP(aqm, 256);
	unsigned long adm_max;
	DECLARE_BITMAP(adm, 256);
};

/**
 * struct ap_matrix_mdev - Contains the data associated with a matrix mediated
 *			   device.
 * @vdev:	the vfio device
 * @node:	allows the ap_matrix_mdev struct to be added to a list
 * @matrix:	the adapters, usage domains and control domains assigned to the
 *		mediated matrix device.
 * @group_notifier: notifier block used for specifying callback function for
 *		    handling the VFIO_GROUP_NOTIFY_SET_KVM event
 * @iommu_notifier: notifier block used for specifying callback function for
 *		    handling the VFIO_IOMMU_NOTIFY_DMA_UNMAP even
 * @kvm:	the struct holding guest's state
 * @pqap_hook:	the function pointer to the interception handler for the
 *		PQAP(AQIC) instruction.
 * @mdev:	the mediated device
 */
struct ap_matrix_mdev {
	struct vfio_device vdev;
	struct list_head node;
	struct ap_matrix matrix;
	struct notifier_block group_notifier;
	struct notifier_block iommu_notifier;
	struct kvm *kvm;
	crypto_hook pqap_hook;
	struct mdev_device *mdev;
};

/**
 * struct vfio_ap_queue - contains the data associated with a queue bound to the
 *			  vfio_ap device driver
 * @matrix_mdev: the matrix mediated device
 * @saved_pfn: the guest PFN pinned for the guest
 * @apqn: the APQN of the AP queue device
 * @saved_isc: the guest ISC registered with the GIB interface
 */
struct vfio_ap_queue {
	struct ap_matrix_mdev *matrix_mdev;
	unsigned long saved_pfn;
	int	apqn;
#define VFIO_AP_ISC_INVALID 0xff
	unsigned char saved_isc;
};

int vfio_ap_mdev_register(void);
void vfio_ap_mdev_unregister(void);
int vfio_ap_mdev_reset_queue(struct vfio_ap_queue *q,
			     unsigned int retry);

#endif /* _VFIO_AP_PRIVATE_H_ */
