/*
 * Copyright 2016 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <linux/module.h>

#include <drm/drm_drv.h>

#include "amdgpu.h"

bool amdgpu_virt_mmio_blocked(struct amdgpu_device *adev)
{
	/* By now all MMIO pages except mailbox are blocked */
	/* if blocking is enabled in hypervisor. Choose the */
	/* SCRATCH_REG0 to test. */
	return RREG32_NO_KIQ(0xc040) == 0xffffffff;
}

void amdgpu_virt_init_setting(struct amdgpu_device *adev)
{
	/* enable virtual display */
	if (adev->mode_info.num_crtc == 0)
		adev->mode_info.num_crtc = 1;
	adev->enable_virtual_display = true;
	adev->ddev->driver->driver_features &= ~DRIVER_ATOMIC;
	adev->cg_flags = 0;
	adev->pg_flags = 0;
}

void amdgpu_virt_kiq_reg_write_reg_wait(struct amdgpu_device *adev,
					uint32_t reg0, uint32_t reg1,
					uint32_t ref, uint32_t mask)
{
	struct amdgpu_kiq *kiq = &adev->gfx.kiq;
	struct amdgpu_ring *ring = &kiq->ring;
	signed long r, cnt = 0;
	unsigned long flags;
	uint32_t seq;

	spin_lock_irqsave(&kiq->ring_lock, flags);
	amdgpu_ring_alloc(ring, 32);
	amdgpu_ring_emit_reg_write_reg_wait(ring, reg0, reg1,
					    ref, mask);
	r = amdgpu_fence_emit_polling(ring, &seq, MAX_KIQ_REG_WAIT);
	if (r)
		goto failed_undo;

	amdgpu_ring_commit(ring);
	spin_unlock_irqrestore(&kiq->ring_lock, flags);

	r = amdgpu_fence_wait_polling(ring, seq, MAX_KIQ_REG_WAIT);

	/* don't wait anymore for IRQ context */
	if (r < 1 && in_interrupt())
		goto failed_kiq;

	might_sleep();
	while (r < 1 && cnt++ < MAX_KIQ_REG_TRY) {

		msleep(MAX_KIQ_REG_BAILOUT_INTERVAL);
		r = amdgpu_fence_wait_polling(ring, seq, MAX_KIQ_REG_WAIT);
	}

	if (cnt > MAX_KIQ_REG_TRY)
		goto failed_kiq;

	return;

failed_undo:
	amdgpu_ring_undo(ring);
	spin_unlock_irqrestore(&kiq->ring_lock, flags);
failed_kiq:
	pr_err("failed to write reg %x wait reg %x\n", reg0, reg1);
}

/**
 * amdgpu_virt_request_full_gpu() - request full gpu access
 * @amdgpu:	amdgpu device.
 * @init:	is driver init time.
 * When start to init/fini driver, first need to request full gpu access.
 * Return: Zero if request success, otherwise will return error.
 */
int amdgpu_virt_request_full_gpu(struct amdgpu_device *adev, bool init)
{
	struct amdgpu_virt *virt = &adev->virt;
	int r;

	if (virt->ops && virt->ops->req_full_gpu) {
		r = virt->ops->req_full_gpu(adev, init);
		if (r)
			return r;

		adev->virt.caps &= ~AMDGPU_SRIOV_CAPS_RUNTIME;
	}

	return 0;
}

/**
 * amdgpu_virt_release_full_gpu() - release full gpu access
 * @amdgpu:	amdgpu device.
 * @init:	is driver init time.
 * When finishing driver init/fini, need to release full gpu access.
 * Return: Zero if release success, otherwise will returen error.
 */
int amdgpu_virt_release_full_gpu(struct amdgpu_device *adev, bool init)
{
	struct amdgpu_virt *virt = &adev->virt;
	int r;

	if (virt->ops && virt->ops->rel_full_gpu) {
		r = virt->ops->rel_full_gpu(adev, init);
		if (r)
			return r;

		adev->virt.caps |= AMDGPU_SRIOV_CAPS_RUNTIME;
	}
	return 0;
}

/**
 * amdgpu_virt_reset_gpu() - reset gpu
 * @amdgpu:	amdgpu device.
 * Send reset command to GPU hypervisor to reset GPU that VM is using
 * Return: Zero if reset success, otherwise will return error.
 */
int amdgpu_virt_reset_gpu(struct amdgpu_device *adev)
{
	struct amdgpu_virt *virt = &adev->virt;
	int r;

	if (virt->ops && virt->ops->reset_gpu) {
		r = virt->ops->reset_gpu(adev);
		if (r)
			return r;

		adev->virt.caps &= ~AMDGPU_SRIOV_CAPS_RUNTIME;
	}

	return 0;
}

void amdgpu_virt_request_init_data(struct amdgpu_device *adev)
{
	struct amdgpu_virt *virt = &adev->virt;

	if (virt->ops && virt->ops->req_init_data)
		virt->ops->req_init_data(adev);

	if (adev->virt.req_init_data_ver > 0)
		DRM_INFO("host supports REQ_INIT_DATA handshake\n");
	else
		DRM_WARN("host doesn't support REQ_INIT_DATA handshake\n");
}

/**
 * amdgpu_virt_wait_reset() - wait for reset gpu completed
 * @amdgpu:	amdgpu device.
 * Wait for GPU reset completed.
 * Return: Zero if reset success, otherwise will return error.
 */
int amdgpu_virt_wait_reset(struct amdgpu_device *adev)
{
	struct amdgpu_virt *virt = &adev->virt;

	if (!virt->ops || !virt->ops->wait_reset)
		return -EINVAL;

	return virt->ops->wait_reset(adev);
}

/**
 * amdgpu_virt_alloc_mm_table() - alloc memory for mm table
 * @amdgpu:	amdgpu device.
 * MM table is used by UVD and VCE for its initialization
 * Return: Zero if allocate success.
 */
int amdgpu_virt_alloc_mm_table(struct amdgpu_device *adev)
{
	int r;

	if (!amdgpu_sriov_vf(adev) || adev->virt.mm_table.gpu_addr)
		return 0;

	r = amdgpu_bo_create_kernel(adev, PAGE_SIZE, PAGE_SIZE,
				    AMDGPU_GEM_DOMAIN_VRAM,
				    &adev->virt.mm_table.bo,
				    &adev->virt.mm_table.gpu_addr,
				    (void *)&adev->virt.mm_table.cpu_addr);
	if (r) {
		DRM_ERROR("failed to alloc mm table and error = %d.\n", r);
		return r;
	}

	memset((void *)adev->virt.mm_table.cpu_addr, 0, PAGE_SIZE);
	DRM_INFO("MM table gpu addr = 0x%llx, cpu addr = %p.\n",
		 adev->virt.mm_table.gpu_addr,
		 adev->virt.mm_table.cpu_addr);
	return 0;
}

/**
 * amdgpu_virt_free_mm_table() - free mm table memory
 * @amdgpu:	amdgpu device.
 * Free MM table memory
 */
void amdgpu_virt_free_mm_table(struct amdgpu_device *adev)
{
	if (!amdgpu_sriov_vf(adev) || !adev->virt.mm_table.gpu_addr)
		return;

	amdgpu_bo_free_kernel(&adev->virt.mm_table.bo,
			      &adev->virt.mm_table.gpu_addr,
			      (void *)&adev->virt.mm_table.cpu_addr);
	adev->virt.mm_table.gpu_addr = 0;
}


int amdgpu_virt_fw_reserve_get_checksum(void *obj,
					unsigned long obj_size,
					unsigned int key,
					unsigned int chksum)
{
	unsigned int ret = key;
	unsigned long i = 0;
	unsigned char *pos;

	pos = (char *)obj;
	/* calculate checksum */
	for (i = 0; i < obj_size; ++i)
		ret += *(pos + i);
	/* minus the chksum itself */
	pos = (char *)&chksum;
	for (i = 0; i < sizeof(chksum); ++i)
		ret -= *(pos + i);
	return ret;
}

void amdgpu_virt_init_data_exchange(struct amdgpu_device *adev)
{
	uint32_t pf2vf_size = 0;
	uint32_t checksum = 0;
	uint32_t checkval;
	char *str;

	adev->virt.fw_reserve.p_pf2vf = NULL;
	adev->virt.fw_reserve.p_vf2pf = NULL;

	if (adev->fw_vram_usage.va != NULL) {
		adev->virt.fw_reserve.p_pf2vf =
			(struct amd_sriov_msg_pf2vf_info_header *)(
			adev->fw_vram_usage.va + AMDGIM_DATAEXCHANGE_OFFSET);
		AMDGPU_FW_VRAM_PF2VF_READ(adev, header.size, &pf2vf_size);
		AMDGPU_FW_VRAM_PF2VF_READ(adev, checksum, &checksum);
		AMDGPU_FW_VRAM_PF2VF_READ(adev, feature_flags, &adev->virt.gim_feature);

		/* pf2vf message must be in 4K */
		if (pf2vf_size > 0 && pf2vf_size < 4096) {
			checkval = amdgpu_virt_fw_reserve_get_checksum(
				adev->virt.fw_reserve.p_pf2vf, pf2vf_size,
				adev->virt.fw_reserve.checksum_key, checksum);
			if (checkval == checksum) {
				adev->virt.fw_reserve.p_vf2pf =
					((void *)adev->virt.fw_reserve.p_pf2vf +
					pf2vf_size);
				memset((void *)adev->virt.fw_reserve.p_vf2pf, 0,
					sizeof(amdgim_vf2pf_info));
				AMDGPU_FW_VRAM_VF2PF_WRITE(adev, header.version,
					AMDGPU_FW_VRAM_VF2PF_VER);
				AMDGPU_FW_VRAM_VF2PF_WRITE(adev, header.size,
					sizeof(amdgim_vf2pf_info));
				AMDGPU_FW_VRAM_VF2PF_READ(adev, driver_version,
					&str);
#ifdef MODULE
				if (THIS_MODULE->version != NULL)
					strcpy(str, THIS_MODULE->version);
				else
#endif
					strcpy(str, "N/A");
				AMDGPU_FW_VRAM_VF2PF_WRITE(adev, driver_cert,
					0);
				AMDGPU_FW_VRAM_VF2PF_WRITE(adev, checksum,
					amdgpu_virt_fw_reserve_get_checksum(
					adev->virt.fw_reserve.p_vf2pf,
					pf2vf_size,
					adev->virt.fw_reserve.checksum_key, 0));
			}
		}
	}
}

void amdgpu_detect_virtualization(struct amdgpu_device *adev)
{
	uint32_t reg;

	switch (adev->asic_type) {
	case CHIP_TONGA:
	case CHIP_FIJI:
		reg = RREG32(mmBIF_IOV_FUNC_IDENTIFIER);
		break;
	case CHIP_VEGA10:
	case CHIP_VEGA20:
	case CHIP_NAVI10:
	case CHIP_NAVI12:
	case CHIP_ARCTURUS:
		reg = RREG32(mmRCC_IOV_FUNC_IDENTIFIER);
		break;
	default: /* other chip doesn't support SRIOV */
		reg = 0;
		break;
	}

	if (reg & 1)
		adev->virt.caps |= AMDGPU_SRIOV_CAPS_IS_VF;

	if (reg & 0x80000000)
		adev->virt.caps |= AMDGPU_SRIOV_CAPS_ENABLE_IOV;

	if (!reg) {
		if (is_virtual_machine())	/* passthrough mode exclus sriov mod */
			adev->virt.caps |= AMDGPU_PASSTHROUGH_MODE;
	}
}

bool amdgpu_virt_access_debugfs_is_mmio(struct amdgpu_device *adev)
{
	return amdgpu_sriov_is_debug(adev) ? true : false;
}

bool amdgpu_virt_access_debugfs_is_kiq(struct amdgpu_device *adev)
{
	return amdgpu_sriov_is_normal(adev) ? true : false;
}

int amdgpu_virt_enable_access_debugfs(struct amdgpu_device *adev)
{
	if (!amdgpu_sriov_vf(adev) ||
	    amdgpu_virt_access_debugfs_is_kiq(adev))
		return 0;

	if (amdgpu_virt_access_debugfs_is_mmio(adev))
		adev->virt.caps &= ~AMDGPU_SRIOV_CAPS_RUNTIME;
	else
		return -EPERM;

	return 0;
}

void amdgpu_virt_disable_access_debugfs(struct amdgpu_device *adev)
{
	if (amdgpu_sriov_vf(adev))
		adev->virt.caps |= AMDGPU_SRIOV_CAPS_RUNTIME;
}

enum amdgpu_sriov_vf_mode amdgpu_virt_get_sriov_vf_mode(struct amdgpu_device *adev)
{
	enum amdgpu_sriov_vf_mode mode;

	if (amdgpu_sriov_vf(adev)) {
		if (amdgpu_sriov_is_pp_one_vf(adev))
			mode = SRIOV_VF_MODE_ONE_VF;
		else
			mode = SRIOV_VF_MODE_MULTI_VF;
	} else {
		mode = SRIOV_VF_MODE_BARE_METAL;
	}

	return mode;
}
