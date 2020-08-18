// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright © 2015 Intel Corporation.
 *
 * Authors: David Woodhouse <dwmw2@infradead.org>
 */

#include <linux/intel-iommu.h>
#include <linux/mmu_notifier.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/intel-svm.h>
#include <linux/rculist.h>
#include <linux/pci.h>
#include <linux/pci-ats.h>
#include <linux/dmar.h>
#include <linux/interrupt.h>
#include <linux/mm_types.h>
#include <linux/ioasid.h>
#include <asm/page.h>

#include "intel-pasid.h"

static irqreturn_t prq_event_thread(int irq, void *d);
static void intel_svm_drain_prq(struct device *dev, int pasid);

#define PRQ_ORDER 0

int intel_svm_enable_prq(struct intel_iommu *iommu)
{
	struct page *pages;
	int irq, ret;

	pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, PRQ_ORDER);
	if (!pages) {
		pr_warn("IOMMU: %s: Failed to allocate page request queue\n",
			iommu->name);
		return -ENOMEM;
	}
	iommu->prq = page_address(pages);

	irq = dmar_alloc_hwirq(DMAR_UNITS_SUPPORTED + iommu->seq_id, iommu->node, iommu);
	if (irq <= 0) {
		pr_err("IOMMU: %s: Failed to create IRQ vector for page request queue\n",
		       iommu->name);
		ret = -EINVAL;
	err:
		free_pages((unsigned long)iommu->prq, PRQ_ORDER);
		iommu->prq = NULL;
		return ret;
	}
	iommu->pr_irq = irq;

	snprintf(iommu->prq_name, sizeof(iommu->prq_name), "dmar%d-prq", iommu->seq_id);

	ret = request_threaded_irq(irq, NULL, prq_event_thread, IRQF_ONESHOT,
				   iommu->prq_name, iommu);
	if (ret) {
		pr_err("IOMMU: %s: Failed to request IRQ for page request queue\n",
		       iommu->name);
		dmar_free_hwirq(irq);
		iommu->pr_irq = 0;
		goto err;
	}
	dmar_writeq(iommu->reg + DMAR_PQH_REG, 0ULL);
	dmar_writeq(iommu->reg + DMAR_PQT_REG, 0ULL);
	dmar_writeq(iommu->reg + DMAR_PQA_REG, virt_to_phys(iommu->prq) | PRQ_ORDER);

	init_completion(&iommu->prq_complete);

	return 0;
}

int intel_svm_finish_prq(struct intel_iommu *iommu)
{
	dmar_writeq(iommu->reg + DMAR_PQH_REG, 0ULL);
	dmar_writeq(iommu->reg + DMAR_PQT_REG, 0ULL);
	dmar_writeq(iommu->reg + DMAR_PQA_REG, 0ULL);

	if (iommu->pr_irq) {
		free_irq(iommu->pr_irq, iommu);
		dmar_free_hwirq(iommu->pr_irq);
		iommu->pr_irq = 0;
	}

	free_pages((unsigned long)iommu->prq, PRQ_ORDER);
	iommu->prq = NULL;

	return 0;
}

static inline bool intel_svm_capable(struct intel_iommu *iommu)
{
	return iommu->flags & VTD_FLAG_SVM_CAPABLE;
}

void intel_svm_check(struct intel_iommu *iommu)
{
	if (!pasid_supported(iommu))
		return;

	if (cpu_feature_enabled(X86_FEATURE_GBPAGES) &&
	    !cap_fl1gp_support(iommu->cap)) {
		pr_err("%s SVM disabled, incompatible 1GB page capability\n",
		       iommu->name);
		return;
	}

	if (cpu_feature_enabled(X86_FEATURE_LA57) &&
	    !cap_5lp_support(iommu->cap)) {
		pr_err("%s SVM disabled, incompatible paging mode\n",
		       iommu->name);
		return;
	}

	iommu->flags |= VTD_FLAG_SVM_CAPABLE;
}

static void intel_flush_svm_range_dev (struct intel_svm *svm, struct intel_svm_dev *sdev,
				unsigned long address, unsigned long pages, int ih)
{
	struct qi_desc desc;

	if (pages == -1) {
		desc.qw0 = QI_EIOTLB_PASID(svm->pasid) |
			QI_EIOTLB_DID(sdev->did) |
			QI_EIOTLB_GRAN(QI_GRAN_NONG_PASID) |
			QI_EIOTLB_TYPE;
		desc.qw1 = 0;
	} else {
		int mask = ilog2(__roundup_pow_of_two(pages));

		desc.qw0 = QI_EIOTLB_PASID(svm->pasid) |
				QI_EIOTLB_DID(sdev->did) |
				QI_EIOTLB_GRAN(QI_GRAN_PSI_PASID) |
				QI_EIOTLB_TYPE;
		desc.qw1 = QI_EIOTLB_ADDR(address) |
				QI_EIOTLB_IH(ih) |
				QI_EIOTLB_AM(mask);
	}
	desc.qw2 = 0;
	desc.qw3 = 0;
	qi_submit_sync(svm->iommu, &desc, 1, 0);

	if (sdev->dev_iotlb) {
		desc.qw0 = QI_DEV_EIOTLB_PASID(svm->pasid) |
				QI_DEV_EIOTLB_SID(sdev->sid) |
				QI_DEV_EIOTLB_QDEP(sdev->qdep) |
				QI_DEIOTLB_TYPE;
		if (pages == -1) {
			desc.qw1 = QI_DEV_EIOTLB_ADDR(-1ULL >> 1) |
					QI_DEV_EIOTLB_SIZE;
		} else if (pages > 1) {
			/* The least significant zero bit indicates the size. So,
			 * for example, an "address" value of 0x12345f000 will
			 * flush from 0x123440000 to 0x12347ffff (256KiB). */
			unsigned long last = address + ((unsigned long)(pages - 1) << VTD_PAGE_SHIFT);
			unsigned long mask = __rounddown_pow_of_two(address ^ last);

			desc.qw1 = QI_DEV_EIOTLB_ADDR((address & ~mask) |
					(mask - 1)) | QI_DEV_EIOTLB_SIZE;
		} else {
			desc.qw1 = QI_DEV_EIOTLB_ADDR(address);
		}
		desc.qw2 = 0;
		desc.qw3 = 0;
		qi_submit_sync(svm->iommu, &desc, 1, 0);
	}
}

static void intel_flush_svm_range(struct intel_svm *svm, unsigned long address,
				unsigned long pages, int ih)
{
	struct intel_svm_dev *sdev;

	rcu_read_lock();
	list_for_each_entry_rcu(sdev, &svm->devs, list)
		intel_flush_svm_range_dev(svm, sdev, address, pages, ih);
	rcu_read_unlock();
}

/* Pages have been freed at this point */
static void intel_invalidate_range(struct mmu_notifier *mn,
				   struct mm_struct *mm,
				   unsigned long start, unsigned long end)
{
	struct intel_svm *svm = container_of(mn, struct intel_svm, notifier);

	intel_flush_svm_range(svm, start,
			      (end - start + PAGE_SIZE - 1) >> VTD_PAGE_SHIFT, 0);
}

static void intel_mm_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct intel_svm *svm = container_of(mn, struct intel_svm, notifier);
	struct intel_svm_dev *sdev;

	/* This might end up being called from exit_mmap(), *before* the page
	 * tables are cleared. And __mmu_notifier_release() will delete us from
	 * the list of notifiers so that our invalidate_range() callback doesn't
	 * get called when the page tables are cleared. So we need to protect
	 * against hardware accessing those page tables.
	 *
	 * We do it by clearing the entry in the PASID table and then flushing
	 * the IOTLB and the PASID table caches. This might upset hardware;
	 * perhaps we'll want to point the PASID to a dummy PGD (like the zero
	 * page) so that we end up taking a fault that the hardware really
	 * *has* to handle gracefully without affecting other processes.
	 */
	rcu_read_lock();
	list_for_each_entry_rcu(sdev, &svm->devs, list)
		intel_pasid_tear_down_entry(svm->iommu, sdev->dev,
					    svm->pasid, true);
	rcu_read_unlock();

}

static const struct mmu_notifier_ops intel_mmuops = {
	.release = intel_mm_release,
	.invalidate_range = intel_invalidate_range,
};

static DEFINE_MUTEX(pasid_mutex);
static LIST_HEAD(global_svm_list);

#define for_each_svm_dev(sdev, svm, d)			\
	list_for_each_entry((sdev), &(svm)->devs, list)	\
		if ((d) != (sdev)->dev) {} else

int intel_svm_bind_gpasid(struct iommu_domain *domain, struct device *dev,
			  struct iommu_gpasid_bind_data *data)
{
	struct intel_iommu *iommu = intel_svm_device_to_iommu(dev);
	struct dmar_domain *dmar_domain;
	struct intel_svm_dev *sdev;
	struct intel_svm *svm;
	int ret = 0;

	if (WARN_ON(!iommu) || !data)
		return -EINVAL;

	if (data->version != IOMMU_GPASID_BIND_VERSION_1 ||
	    data->format != IOMMU_PASID_FORMAT_INTEL_VTD)
		return -EINVAL;

	if (!dev_is_pci(dev))
		return -ENOTSUPP;

	/* VT-d supports devices with full 20 bit PASIDs only */
	if (pci_max_pasids(to_pci_dev(dev)) != PASID_MAX)
		return -EINVAL;

	/*
	 * We only check host PASID range, we have no knowledge to check
	 * guest PASID range.
	 */
	if (data->hpasid <= 0 || data->hpasid >= PASID_MAX)
		return -EINVAL;

	dmar_domain = to_dmar_domain(domain);

	mutex_lock(&pasid_mutex);
	svm = ioasid_find(NULL, data->hpasid, NULL);
	if (IS_ERR(svm)) {
		ret = PTR_ERR(svm);
		goto out;
	}

	if (svm) {
		/*
		 * If we found svm for the PASID, there must be at
		 * least one device bond, otherwise svm should be freed.
		 */
		if (WARN_ON(list_empty(&svm->devs))) {
			ret = -EINVAL;
			goto out;
		}

		for_each_svm_dev(sdev, svm, dev) {
			/*
			 * For devices with aux domains, we should allow
			 * multiple bind calls with the same PASID and pdev.
			 */
			if (iommu_dev_feature_enabled(dev,
						      IOMMU_DEV_FEAT_AUX)) {
				sdev->users++;
			} else {
				dev_warn_ratelimited(dev,
						     "Already bound with PASID %u\n",
						     svm->pasid);
				ret = -EBUSY;
			}
			goto out;
		}
	} else {
		/* We come here when PASID has never been bond to a device. */
		svm = kzalloc(sizeof(*svm), GFP_KERNEL);
		if (!svm) {
			ret = -ENOMEM;
			goto out;
		}
		/* REVISIT: upper layer/VFIO can track host process that bind
		 * the PASID. ioasid_set = mm might be sufficient for vfio to
		 * check pasid VMM ownership. We can drop the following line
		 * once VFIO and IOASID set check is in place.
		 */
		svm->mm = get_task_mm(current);
		svm->pasid = data->hpasid;
		if (data->flags & IOMMU_SVA_GPASID_VAL) {
			svm->gpasid = data->gpasid;
			svm->flags |= SVM_FLAG_GUEST_PASID;
		}
		ioasid_set_data(data->hpasid, svm);
		INIT_LIST_HEAD_RCU(&svm->devs);
		mmput(svm->mm);
	}
	sdev = kzalloc(sizeof(*sdev), GFP_KERNEL);
	if (!sdev) {
		ret = -ENOMEM;
		goto out;
	}
	sdev->dev = dev;

	/* Only count users if device has aux domains */
	if (iommu_dev_feature_enabled(dev, IOMMU_DEV_FEAT_AUX))
		sdev->users = 1;

	/* Set up device context entry for PASID if not enabled already */
	ret = intel_iommu_enable_pasid(iommu, sdev->dev);
	if (ret) {
		dev_err_ratelimited(dev, "Failed to enable PASID capability\n");
		kfree(sdev);
		goto out;
	}

	/*
	 * PASID table is per device for better security. Therefore, for
	 * each bind of a new device even with an existing PASID, we need to
	 * call the nested mode setup function here.
	 */
	spin_lock(&iommu->lock);
	ret = intel_pasid_setup_nested(iommu, dev,
				       (pgd_t *)(uintptr_t)data->gpgd,
				       data->hpasid, &data->vtd, dmar_domain,
				       data->addr_width);
	spin_unlock(&iommu->lock);
	if (ret) {
		dev_err_ratelimited(dev, "Failed to set up PASID %llu in nested mode, Err %d\n",
				    data->hpasid, ret);
		/*
		 * PASID entry should be in cleared state if nested mode
		 * set up failed. So we only need to clear IOASID tracking
		 * data such that free call will succeed.
		 */
		kfree(sdev);
		goto out;
	}

	svm->flags |= SVM_FLAG_GUEST_MODE;

	init_rcu_head(&sdev->rcu);
	list_add_rcu(&sdev->list, &svm->devs);
 out:
	if (!IS_ERR_OR_NULL(svm) && list_empty(&svm->devs)) {
		ioasid_set_data(data->hpasid, NULL);
		kfree(svm);
	}

	mutex_unlock(&pasid_mutex);
	return ret;
}

int intel_svm_unbind_gpasid(struct device *dev, int pasid)
{
	struct intel_iommu *iommu = intel_svm_device_to_iommu(dev);
	struct intel_svm_dev *sdev;
	struct intel_svm *svm;
	int ret = -EINVAL;

	if (WARN_ON(!iommu))
		return -EINVAL;

	mutex_lock(&pasid_mutex);
	svm = ioasid_find(NULL, pasid, NULL);
	if (!svm) {
		ret = -EINVAL;
		goto out;
	}

	if (IS_ERR(svm)) {
		ret = PTR_ERR(svm);
		goto out;
	}

	for_each_svm_dev(sdev, svm, dev) {
		ret = 0;
		if (iommu_dev_feature_enabled(dev, IOMMU_DEV_FEAT_AUX))
			sdev->users--;
		if (!sdev->users) {
			list_del_rcu(&sdev->list);
			intel_pasid_tear_down_entry(iommu, dev,
						    svm->pasid, false);
			intel_svm_drain_prq(dev, svm->pasid);
			kfree_rcu(sdev, rcu);

			if (list_empty(&svm->devs)) {
				/*
				 * We do not free the IOASID here in that
				 * IOMMU driver did not allocate it.
				 * Unlike native SVM, IOASID for guest use was
				 * allocated prior to the bind call.
				 * In any case, if the free call comes before
				 * the unbind, IOMMU driver will get notified
				 * and perform cleanup.
				 */
				ioasid_set_data(pasid, NULL);
				kfree(svm);
			}
		}
		break;
	}
out:
	mutex_unlock(&pasid_mutex);
	return ret;
}

/* Caller must hold pasid_mutex, mm reference */
static int
intel_svm_bind_mm(struct device *dev, int flags, struct svm_dev_ops *ops,
		  struct mm_struct *mm, struct intel_svm_dev **sd)
{
	struct intel_iommu *iommu = intel_svm_device_to_iommu(dev);
	struct device_domain_info *info;
	struct intel_svm_dev *sdev;
	struct intel_svm *svm = NULL;
	int pasid_max;
	int ret;

	if (!iommu || dmar_disabled)
		return -EINVAL;

	if (!intel_svm_capable(iommu))
		return -ENOTSUPP;

	if (dev_is_pci(dev)) {
		pasid_max = pci_max_pasids(to_pci_dev(dev));
		if (pasid_max < 0)
			return -EINVAL;
	} else
		pasid_max = 1 << 20;

	/* Bind supervisor PASID shuld have mm = NULL */
	if (flags & SVM_FLAG_SUPERVISOR_MODE) {
		if (!ecap_srs(iommu->ecap) || mm) {
			pr_err("Supervisor PASID with user provided mm.\n");
			return -EINVAL;
		}
	}

	if (!(flags & SVM_FLAG_PRIVATE_PASID)) {
		struct intel_svm *t;

		list_for_each_entry(t, &global_svm_list, list) {
			if (t->mm != mm || (t->flags & SVM_FLAG_PRIVATE_PASID))
				continue;

			svm = t;
			if (svm->pasid >= pasid_max) {
				dev_warn(dev,
					 "Limited PASID width. Cannot use existing PASID %d\n",
					 svm->pasid);
				ret = -ENOSPC;
				goto out;
			}

			/* Find the matching device in svm list */
			for_each_svm_dev(sdev, svm, dev) {
				if (sdev->ops != ops) {
					ret = -EBUSY;
					goto out;
				}
				sdev->users++;
				goto success;
			}

			break;
		}
	}

	sdev = kzalloc(sizeof(*sdev), GFP_KERNEL);
	if (!sdev) {
		ret = -ENOMEM;
		goto out;
	}
	sdev->dev = dev;

	ret = intel_iommu_enable_pasid(iommu, dev);
	if (ret) {
		kfree(sdev);
		goto out;
	}

	info = get_domain_info(dev);
	sdev->did = FLPT_DEFAULT_DID;
	sdev->sid = PCI_DEVID(info->bus, info->devfn);
	if (info->ats_enabled) {
		sdev->dev_iotlb = 1;
		sdev->qdep = info->ats_qdep;
		if (sdev->qdep >= QI_DEV_EIOTLB_MAX_INVS)
			sdev->qdep = 0;
	}

	/* Finish the setup now we know we're keeping it */
	sdev->users = 1;
	sdev->ops = ops;
	init_rcu_head(&sdev->rcu);

	if (!svm) {
		svm = kzalloc(sizeof(*svm), GFP_KERNEL);
		if (!svm) {
			ret = -ENOMEM;
			kfree(sdev);
			goto out;
		}
		svm->iommu = iommu;

		if (pasid_max > intel_pasid_max_id)
			pasid_max = intel_pasid_max_id;

		/* Do not use PASID 0, reserved for RID to PASID */
		svm->pasid = ioasid_alloc(NULL, PASID_MIN,
					  pasid_max - 1, svm);
		if (svm->pasid == INVALID_IOASID) {
			kfree(svm);
			kfree(sdev);
			ret = -ENOSPC;
			goto out;
		}
		svm->notifier.ops = &intel_mmuops;
		svm->mm = mm;
		svm->flags = flags;
		INIT_LIST_HEAD_RCU(&svm->devs);
		INIT_LIST_HEAD(&svm->list);
		ret = -ENOMEM;
		if (mm) {
			ret = mmu_notifier_register(&svm->notifier, mm);
			if (ret) {
				ioasid_free(svm->pasid);
				kfree(svm);
				kfree(sdev);
				goto out;
			}
		}

		spin_lock(&iommu->lock);
		ret = intel_pasid_setup_first_level(iommu, dev,
				mm ? mm->pgd : init_mm.pgd,
				svm->pasid, FLPT_DEFAULT_DID,
				(mm ? 0 : PASID_FLAG_SUPERVISOR_MODE) |
				(cpu_feature_enabled(X86_FEATURE_LA57) ?
				 PASID_FLAG_FL5LP : 0));
		spin_unlock(&iommu->lock);
		if (ret) {
			if (mm)
				mmu_notifier_unregister(&svm->notifier, mm);
			ioasid_free(svm->pasid);
			kfree(svm);
			kfree(sdev);
			goto out;
		}

		list_add_tail(&svm->list, &global_svm_list);
	} else {
		/*
		 * Binding a new device with existing PASID, need to setup
		 * the PASID entry.
		 */
		spin_lock(&iommu->lock);
		ret = intel_pasid_setup_first_level(iommu, dev,
						mm ? mm->pgd : init_mm.pgd,
						svm->pasid, FLPT_DEFAULT_DID,
						(mm ? 0 : PASID_FLAG_SUPERVISOR_MODE) |
						(cpu_feature_enabled(X86_FEATURE_LA57) ?
						PASID_FLAG_FL5LP : 0));
		spin_unlock(&iommu->lock);
		if (ret) {
			kfree(sdev);
			goto out;
		}
	}
	list_add_rcu(&sdev->list, &svm->devs);
success:
	sdev->pasid = svm->pasid;
	sdev->sva.dev = dev;
	if (sd)
		*sd = sdev;
	ret = 0;
 out:
	return ret;
}

/* Caller must hold pasid_mutex */
static int intel_svm_unbind_mm(struct device *dev, int pasid)
{
	struct intel_svm_dev *sdev;
	struct intel_iommu *iommu;
	struct intel_svm *svm;
	int ret = -EINVAL;

	iommu = intel_svm_device_to_iommu(dev);
	if (!iommu)
		goto out;

	svm = ioasid_find(NULL, pasid, NULL);
	if (!svm)
		goto out;

	if (IS_ERR(svm)) {
		ret = PTR_ERR(svm);
		goto out;
	}

	for_each_svm_dev(sdev, svm, dev) {
		ret = 0;
		sdev->users--;
		if (!sdev->users) {
			list_del_rcu(&sdev->list);
			/* Flush the PASID cache and IOTLB for this device.
			 * Note that we do depend on the hardware *not* using
			 * the PASID any more. Just as we depend on other
			 * devices never using PASIDs that they have no right
			 * to use. We have a *shared* PASID table, because it's
			 * large and has to be physically contiguous. So it's
			 * hard to be as defensive as we might like. */
			intel_pasid_tear_down_entry(iommu, dev,
						    svm->pasid, false);
			intel_svm_drain_prq(dev, svm->pasid);
			kfree_rcu(sdev, rcu);

			if (list_empty(&svm->devs)) {
				ioasid_free(svm->pasid);
				if (svm->mm)
					mmu_notifier_unregister(&svm->notifier, svm->mm);
				list_del(&svm->list);
				/* We mandate that no page faults may be outstanding
				 * for the PASID when intel_svm_unbind_mm() is called.
				 * If that is not obeyed, subtle errors will happen.
				 * Let's make them less subtle... */
				memset(svm, 0x6b, sizeof(*svm));
				kfree(svm);
			}
		}
		break;
	}
 out:

	return ret;
}

/* Page request queue descriptor */
struct page_req_dsc {
	union {
		struct {
			u64 type:8;
			u64 pasid_present:1;
			u64 priv_data_present:1;
			u64 rsvd:6;
			u64 rid:16;
			u64 pasid:20;
			u64 exe_req:1;
			u64 pm_req:1;
			u64 rsvd2:10;
		};
		u64 qw_0;
	};
	union {
		struct {
			u64 rd_req:1;
			u64 wr_req:1;
			u64 lpig:1;
			u64 prg_index:9;
			u64 addr:52;
		};
		u64 qw_1;
	};
	u64 priv_data[2];
};

#define PRQ_RING_MASK	((0x1000 << PRQ_ORDER) - 0x20)

static bool access_error(struct vm_area_struct *vma, struct page_req_dsc *req)
{
	unsigned long requested = 0;

	if (req->exe_req)
		requested |= VM_EXEC;

	if (req->rd_req)
		requested |= VM_READ;

	if (req->wr_req)
		requested |= VM_WRITE;

	return (requested & ~vma->vm_flags) != 0;
}

static bool is_canonical_address(u64 addr)
{
	int shift = 64 - (__VIRTUAL_MASK_SHIFT + 1);
	long saddr = (long) addr;

	return (((saddr << shift) >> shift) == saddr);
}

/**
 * intel_svm_drain_prq - Drain page requests and responses for a pasid
 * @dev: target device
 * @pasid: pasid for draining
 *
 * Drain all pending page requests and responses related to @pasid in both
 * software and hardware. This is supposed to be called after the device
 * driver has stopped DMA, the pasid entry has been cleared, and both IOTLB
 * and DevTLB have been invalidated.
 *
 * It waits until all pending page requests for @pasid in the page fault
 * queue are completed by the prq handling thread. Then follow the steps
 * described in VT-d spec CH7.10 to drain all page requests and page
 * responses pending in the hardware.
 */
static void intel_svm_drain_prq(struct device *dev, int pasid)
{
	struct device_domain_info *info;
	struct dmar_domain *domain;
	struct intel_iommu *iommu;
	struct qi_desc desc[3];
	struct pci_dev *pdev;
	int head, tail;
	u16 sid, did;
	int qdep;

	info = get_domain_info(dev);
	if (WARN_ON(!info || !dev_is_pci(dev)))
		return;

	if (!info->pri_enabled)
		return;

	iommu = info->iommu;
	domain = info->domain;
	pdev = to_pci_dev(dev);
	sid = PCI_DEVID(info->bus, info->devfn);
	did = domain->iommu_did[iommu->seq_id];
	qdep = pci_ats_queue_depth(pdev);

	/*
	 * Check and wait until all pending page requests in the queue are
	 * handled by the prq handling thread.
	 */
prq_retry:
	reinit_completion(&iommu->prq_complete);
	tail = dmar_readq(iommu->reg + DMAR_PQT_REG) & PRQ_RING_MASK;
	head = dmar_readq(iommu->reg + DMAR_PQH_REG) & PRQ_RING_MASK;
	while (head != tail) {
		struct page_req_dsc *req;

		req = &iommu->prq[head / sizeof(*req)];
		if (!req->pasid_present || req->pasid != pasid) {
			head = (head + sizeof(*req)) & PRQ_RING_MASK;
			continue;
		}

		wait_for_completion(&iommu->prq_complete);
		goto prq_retry;
	}

	/*
	 * Perform steps described in VT-d spec CH7.10 to drain page
	 * requests and responses in hardware.
	 */
	memset(desc, 0, sizeof(desc));
	desc[0].qw0 = QI_IWD_STATUS_DATA(QI_DONE) |
			QI_IWD_FENCE |
			QI_IWD_TYPE;
	desc[1].qw0 = QI_EIOTLB_PASID(pasid) |
			QI_EIOTLB_DID(did) |
			QI_EIOTLB_GRAN(QI_GRAN_NONG_PASID) |
			QI_EIOTLB_TYPE;
	desc[2].qw0 = QI_DEV_EIOTLB_PASID(pasid) |
			QI_DEV_EIOTLB_SID(sid) |
			QI_DEV_EIOTLB_QDEP(qdep) |
			QI_DEIOTLB_TYPE |
			QI_DEV_IOTLB_PFSID(info->pfsid);
qi_retry:
	reinit_completion(&iommu->prq_complete);
	qi_submit_sync(iommu, desc, 3, QI_OPT_WAIT_DRAIN);
	if (readl(iommu->reg + DMAR_PRS_REG) & DMA_PRS_PRO) {
		wait_for_completion(&iommu->prq_complete);
		goto qi_retry;
	}
}

static irqreturn_t prq_event_thread(int irq, void *d)
{
	struct intel_iommu *iommu = d;
	struct intel_svm *svm = NULL;
	int head, tail, handled = 0;

	/* Clear PPR bit before reading head/tail registers, to
	 * ensure that we get a new interrupt if needed. */
	writel(DMA_PRS_PPR, iommu->reg + DMAR_PRS_REG);

	tail = dmar_readq(iommu->reg + DMAR_PQT_REG) & PRQ_RING_MASK;
	head = dmar_readq(iommu->reg + DMAR_PQH_REG) & PRQ_RING_MASK;
	while (head != tail) {
		struct intel_svm_dev *sdev;
		struct vm_area_struct *vma;
		struct page_req_dsc *req;
		struct qi_desc resp;
		int result;
		vm_fault_t ret;
		u64 address;

		handled = 1;

		req = &iommu->prq[head / sizeof(*req)];

		result = QI_RESP_FAILURE;
		address = (u64)req->addr << VTD_PAGE_SHIFT;
		if (!req->pasid_present) {
			pr_err("%s: Page request without PASID: %08llx %08llx\n",
			       iommu->name, ((unsigned long long *)req)[0],
			       ((unsigned long long *)req)[1]);
			goto no_pasid;
		}

		if (!svm || svm->pasid != req->pasid) {
			rcu_read_lock();
			svm = ioasid_find(NULL, req->pasid, NULL);
			/* It *can't* go away, because the driver is not permitted
			 * to unbind the mm while any page faults are outstanding.
			 * So we only need RCU to protect the internal idr code. */
			rcu_read_unlock();
			if (IS_ERR_OR_NULL(svm)) {
				pr_err("%s: Page request for invalid PASID %d: %08llx %08llx\n",
				       iommu->name, req->pasid, ((unsigned long long *)req)[0],
				       ((unsigned long long *)req)[1]);
				goto no_pasid;
			}
		}

		result = QI_RESP_INVALID;
		/* Since we're using init_mm.pgd directly, we should never take
		 * any faults on kernel addresses. */
		if (!svm->mm)
			goto bad_req;

		/* If address is not canonical, return invalid response */
		if (!is_canonical_address(address))
			goto bad_req;

		/* If the mm is already defunct, don't handle faults. */
		if (!mmget_not_zero(svm->mm))
			goto bad_req;

		mmap_read_lock(svm->mm);
		vma = find_extend_vma(svm->mm, address);
		if (!vma || address < vma->vm_start)
			goto invalid;

		if (access_error(vma, req))
			goto invalid;

		ret = handle_mm_fault(vma, address,
				      req->wr_req ? FAULT_FLAG_WRITE : 0);
		if (ret & VM_FAULT_ERROR)
			goto invalid;

		result = QI_RESP_SUCCESS;
	invalid:
		mmap_read_unlock(svm->mm);
		mmput(svm->mm);
	bad_req:
		/* Accounting for major/minor faults? */
		rcu_read_lock();
		list_for_each_entry_rcu(sdev, &svm->devs, list) {
			if (sdev->sid == req->rid)
				break;
		}
		/* Other devices can go away, but the drivers are not permitted
		 * to unbind while any page faults might be in flight. So it's
		 * OK to drop the 'lock' here now we have it. */
		rcu_read_unlock();

		if (WARN_ON(&sdev->list == &svm->devs))
			sdev = NULL;

		if (sdev && sdev->ops && sdev->ops->fault_cb) {
			int rwxp = (req->rd_req << 3) | (req->wr_req << 2) |
				(req->exe_req << 1) | (req->pm_req);
			sdev->ops->fault_cb(sdev->dev, req->pasid, req->addr,
					    req->priv_data, rwxp, result);
		}
		/* We get here in the error case where the PASID lookup failed,
		   and these can be NULL. Do not use them below this point! */
		sdev = NULL;
		svm = NULL;
	no_pasid:
		if (req->lpig || req->priv_data_present) {
			/*
			 * Per VT-d spec. v3.0 ch7.7, system software must
			 * respond with page group response if private data
			 * is present (PDP) or last page in group (LPIG) bit
			 * is set. This is an additional VT-d feature beyond
			 * PCI ATS spec.
			 */
			resp.qw0 = QI_PGRP_PASID(req->pasid) |
				QI_PGRP_DID(req->rid) |
				QI_PGRP_PASID_P(req->pasid_present) |
				QI_PGRP_PDP(req->pasid_present) |
				QI_PGRP_RESP_CODE(result) |
				QI_PGRP_RESP_TYPE;
			resp.qw1 = QI_PGRP_IDX(req->prg_index) |
				QI_PGRP_LPIG(req->lpig);

			if (req->priv_data_present)
				memcpy(&resp.qw2, req->priv_data,
				       sizeof(req->priv_data));
			resp.qw2 = 0;
			resp.qw3 = 0;
			qi_submit_sync(iommu, &resp, 1, 0);
		}
		head = (head + sizeof(*req)) & PRQ_RING_MASK;
	}

	dmar_writeq(iommu->reg + DMAR_PQH_REG, tail);

	/*
	 * Clear the page request overflow bit and wake up all threads that
	 * are waiting for the completion of this handling.
	 */
	if (readl(iommu->reg + DMAR_PRS_REG) & DMA_PRS_PRO)
		writel(DMA_PRS_PRO, iommu->reg + DMAR_PRS_REG);

	if (!completion_done(&iommu->prq_complete))
		complete(&iommu->prq_complete);

	return IRQ_RETVAL(handled);
}

#define to_intel_svm_dev(handle) container_of(handle, struct intel_svm_dev, sva)
struct iommu_sva *
intel_svm_bind(struct device *dev, struct mm_struct *mm, void *drvdata)
{
	struct iommu_sva *sva = ERR_PTR(-EINVAL);
	struct intel_svm_dev *sdev = NULL;
	int flags = 0;
	int ret;

	/*
	 * TODO: Consolidate with generic iommu-sva bind after it is merged.
	 * It will require shared SVM data structures, i.e. combine io_mm
	 * and intel_svm etc.
	 */
	if (drvdata)
		flags = *(int *)drvdata;
	mutex_lock(&pasid_mutex);
	ret = intel_svm_bind_mm(dev, flags, NULL, mm, &sdev);
	if (ret)
		sva = ERR_PTR(ret);
	else if (sdev)
		sva = &sdev->sva;
	else
		WARN(!sdev, "SVM bind succeeded with no sdev!\n");

	mutex_unlock(&pasid_mutex);

	return sva;
}

void intel_svm_unbind(struct iommu_sva *sva)
{
	struct intel_svm_dev *sdev;

	mutex_lock(&pasid_mutex);
	sdev = to_intel_svm_dev(sva);
	intel_svm_unbind_mm(sdev->dev, sdev->pasid);
	mutex_unlock(&pasid_mutex);
}

int intel_svm_get_pasid(struct iommu_sva *sva)
{
	struct intel_svm_dev *sdev;
	int pasid;

	mutex_lock(&pasid_mutex);
	sdev = to_intel_svm_dev(sva);
	pasid = sdev->pasid;
	mutex_unlock(&pasid_mutex);

	return pasid;
}
