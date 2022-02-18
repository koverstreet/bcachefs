/*
 * Copyright 2018 Advanced Micro Devices, Inc.
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

#include <linux/firmware.h>

#include "amdgpu.h"
#include "amdgpu_discovery.h"
#include "soc15_hw_ip.h"
#include "discovery.h"

#include "soc15.h"
#include "gfx_v9_0.h"
#include "gmc_v9_0.h"
#include "df_v1_7.h"
#include "df_v3_6.h"
#include "nbio_v6_1.h"
#include "nbio_v7_0.h"
#include "nbio_v7_4.h"
#include "hdp_v4_0.h"
#include "vega10_ih.h"
#include "vega20_ih.h"
#include "sdma_v4_0.h"
#include "uvd_v7_0.h"
#include "vce_v4_0.h"
#include "vcn_v1_0.h"
#include "vcn_v2_5.h"
#include "jpeg_v2_5.h"
#include "smuio_v9_0.h"
#include "gmc_v10_0.h"
#include "gfxhub_v2_0.h"
#include "mmhub_v2_0.h"
#include "nbio_v2_3.h"
#include "nbio_v7_2.h"
#include "hdp_v5_0.h"
#include "nv.h"
#include "navi10_ih.h"
#include "gfx_v10_0.h"
#include "sdma_v5_0.h"
#include "sdma_v5_2.h"
#include "vcn_v2_0.h"
#include "jpeg_v2_0.h"
#include "vcn_v3_0.h"
#include "jpeg_v3_0.h"
#include "amdgpu_vkms.h"
#include "mes_v10_1.h"
#include "smuio_v11_0.h"
#include "smuio_v11_0_6.h"
#include "smuio_v13_0.h"

MODULE_FIRMWARE("amdgpu/ip_discovery.bin");

#define mmRCC_CONFIG_MEMSIZE	0xde3
#define mmMM_INDEX		0x0
#define mmMM_INDEX_HI		0x6
#define mmMM_DATA		0x1

static const char *hw_id_names[HW_ID_MAX] = {
	[MP1_HWID]		= "MP1",
	[MP2_HWID]		= "MP2",
	[THM_HWID]		= "THM",
	[SMUIO_HWID]		= "SMUIO",
	[FUSE_HWID]		= "FUSE",
	[CLKA_HWID]		= "CLKA",
	[PWR_HWID]		= "PWR",
	[GC_HWID]		= "GC",
	[UVD_HWID]		= "UVD",
	[AUDIO_AZ_HWID]		= "AUDIO_AZ",
	[ACP_HWID]		= "ACP",
	[DCI_HWID]		= "DCI",
	[DMU_HWID]		= "DMU",
	[DCO_HWID]		= "DCO",
	[DIO_HWID]		= "DIO",
	[XDMA_HWID]		= "XDMA",
	[DCEAZ_HWID]		= "DCEAZ",
	[DAZ_HWID]		= "DAZ",
	[SDPMUX_HWID]		= "SDPMUX",
	[NTB_HWID]		= "NTB",
	[IOHC_HWID]		= "IOHC",
	[L2IMU_HWID]		= "L2IMU",
	[VCE_HWID]		= "VCE",
	[MMHUB_HWID]		= "MMHUB",
	[ATHUB_HWID]		= "ATHUB",
	[DBGU_NBIO_HWID]	= "DBGU_NBIO",
	[DFX_HWID]		= "DFX",
	[DBGU0_HWID]		= "DBGU0",
	[DBGU1_HWID]		= "DBGU1",
	[OSSSYS_HWID]		= "OSSSYS",
	[HDP_HWID]		= "HDP",
	[SDMA0_HWID]		= "SDMA0",
	[SDMA1_HWID]		= "SDMA1",
	[SDMA2_HWID]		= "SDMA2",
	[SDMA3_HWID]		= "SDMA3",
	[ISP_HWID]		= "ISP",
	[DBGU_IO_HWID]		= "DBGU_IO",
	[DF_HWID]		= "DF",
	[CLKB_HWID]		= "CLKB",
	[FCH_HWID]		= "FCH",
	[DFX_DAP_HWID]		= "DFX_DAP",
	[L1IMU_PCIE_HWID]	= "L1IMU_PCIE",
	[L1IMU_NBIF_HWID]	= "L1IMU_NBIF",
	[L1IMU_IOAGR_HWID]	= "L1IMU_IOAGR",
	[L1IMU3_HWID]		= "L1IMU3",
	[L1IMU4_HWID]		= "L1IMU4",
	[L1IMU5_HWID]		= "L1IMU5",
	[L1IMU6_HWID]		= "L1IMU6",
	[L1IMU7_HWID]		= "L1IMU7",
	[L1IMU8_HWID]		= "L1IMU8",
	[L1IMU9_HWID]		= "L1IMU9",
	[L1IMU10_HWID]		= "L1IMU10",
	[L1IMU11_HWID]		= "L1IMU11",
	[L1IMU12_HWID]		= "L1IMU12",
	[L1IMU13_HWID]		= "L1IMU13",
	[L1IMU14_HWID]		= "L1IMU14",
	[L1IMU15_HWID]		= "L1IMU15",
	[WAFLC_HWID]		= "WAFLC",
	[FCH_USB_PD_HWID]	= "FCH_USB_PD",
	[PCIE_HWID]		= "PCIE",
	[PCS_HWID]		= "PCS",
	[DDCL_HWID]		= "DDCL",
	[SST_HWID]		= "SST",
	[IOAGR_HWID]		= "IOAGR",
	[NBIF_HWID]		= "NBIF",
	[IOAPIC_HWID]		= "IOAPIC",
	[SYSTEMHUB_HWID]	= "SYSTEMHUB",
	[NTBCCP_HWID]		= "NTBCCP",
	[UMC_HWID]		= "UMC",
	[SATA_HWID]		= "SATA",
	[USB_HWID]		= "USB",
	[CCXSEC_HWID]		= "CCXSEC",
	[XGMI_HWID]		= "XGMI",
	[XGBE_HWID]		= "XGBE",
	[MP0_HWID]		= "MP0",
};

static int hw_id_map[MAX_HWIP] = {
	[GC_HWIP]	= GC_HWID,
	[HDP_HWIP]	= HDP_HWID,
	[SDMA0_HWIP]	= SDMA0_HWID,
	[SDMA1_HWIP]	= SDMA1_HWID,
	[SDMA2_HWIP]    = SDMA2_HWID,
	[SDMA3_HWIP]    = SDMA3_HWID,
	[MMHUB_HWIP]	= MMHUB_HWID,
	[ATHUB_HWIP]	= ATHUB_HWID,
	[NBIO_HWIP]	= NBIF_HWID,
	[MP0_HWIP]	= MP0_HWID,
	[MP1_HWIP]	= MP1_HWID,
	[UVD_HWIP]	= UVD_HWID,
	[VCE_HWIP]	= VCE_HWID,
	[DF_HWIP]	= DF_HWID,
	[DCE_HWIP]	= DMU_HWID,
	[OSSSYS_HWIP]	= OSSSYS_HWID,
	[SMUIO_HWIP]	= SMUIO_HWID,
	[PWR_HWIP]	= PWR_HWID,
	[NBIF_HWIP]	= NBIF_HWID,
	[THM_HWIP]	= THM_HWID,
	[CLK_HWIP]	= CLKA_HWID,
	[UMC_HWIP]	= UMC_HWID,
	[XGMI_HWIP]	= XGMI_HWID,
	[DCI_HWIP]	= DCI_HWID,
};

static int amdgpu_discovery_read_binary(struct amdgpu_device *adev, uint8_t *binary)
{
	uint64_t vram_size = (uint64_t)RREG32(mmRCC_CONFIG_MEMSIZE) << 20;
	uint64_t pos = vram_size - DISCOVERY_TMR_OFFSET;

	amdgpu_device_vram_access(adev, pos, (uint32_t *)binary,
				  adev->mman.discovery_tmr_size, false);
	return 0;
}

static uint16_t amdgpu_discovery_calculate_checksum(uint8_t *data, uint32_t size)
{
	uint16_t checksum = 0;
	int i;

	for (i = 0; i < size; i++)
		checksum += data[i];

	return checksum;
}

static inline bool amdgpu_discovery_verify_checksum(uint8_t *data, uint32_t size,
						    uint16_t expected)
{
	return !!(amdgpu_discovery_calculate_checksum(data, size) == expected);
}

static int amdgpu_discovery_init(struct amdgpu_device *adev)
{
	struct table_info *info;
	struct binary_header *bhdr;
	struct ip_discovery_header *ihdr;
	struct gpu_info_header *ghdr;
	const struct firmware *fw;
	uint16_t offset;
	uint16_t size;
	uint16_t checksum;
	int r;

	adev->mman.discovery_tmr_size = DISCOVERY_TMR_SIZE;
	adev->mman.discovery_bin = kzalloc(adev->mman.discovery_tmr_size, GFP_KERNEL);
	if (!adev->mman.discovery_bin)
		return -ENOMEM;

	if (amdgpu_discovery == 2) {
		r = request_firmware(&fw, "amdgpu/ip_discovery.bin", adev->dev);
		if (r)
			goto get_from_vram;
		dev_info(adev->dev, "Using IP discovery from file\n");
		memcpy((u8 *)adev->mman.discovery_bin, (u8 *)fw->data,
		       adev->mman.discovery_tmr_size);
		release_firmware(fw);
	} else {
get_from_vram:
		r = amdgpu_discovery_read_binary(adev, adev->mman.discovery_bin);
		if (r) {
			DRM_ERROR("failed to read ip discovery binary\n");
			goto out;
		}
	}

	bhdr = (struct binary_header *)adev->mman.discovery_bin;

	if (le32_to_cpu(bhdr->binary_signature) != BINARY_SIGNATURE) {
		DRM_ERROR("invalid ip discovery binary signature\n");
		r = -EINVAL;
		goto out;
	}

	offset = offsetof(struct binary_header, binary_checksum) +
		sizeof(bhdr->binary_checksum);
	size = le16_to_cpu(bhdr->binary_size) - offset;
	checksum = le16_to_cpu(bhdr->binary_checksum);

	if (!amdgpu_discovery_verify_checksum(adev->mman.discovery_bin + offset,
					      size, checksum)) {
		DRM_ERROR("invalid ip discovery binary checksum\n");
		r = -EINVAL;
		goto out;
	}

	info = &bhdr->table_list[IP_DISCOVERY];
	offset = le16_to_cpu(info->offset);
	checksum = le16_to_cpu(info->checksum);
	ihdr = (struct ip_discovery_header *)(adev->mman.discovery_bin + offset);

	if (le32_to_cpu(ihdr->signature) != DISCOVERY_TABLE_SIGNATURE) {
		DRM_ERROR("invalid ip discovery data table signature\n");
		r = -EINVAL;
		goto out;
	}

	if (!amdgpu_discovery_verify_checksum(adev->mman.discovery_bin + offset,
					      le16_to_cpu(ihdr->size), checksum)) {
		DRM_ERROR("invalid ip discovery data table checksum\n");
		r = -EINVAL;
		goto out;
	}

	info = &bhdr->table_list[GC];
	offset = le16_to_cpu(info->offset);
	checksum = le16_to_cpu(info->checksum);
	ghdr = (struct gpu_info_header *)(adev->mman.discovery_bin + offset);

	if (!amdgpu_discovery_verify_checksum(adev->mman.discovery_bin + offset,
				              le32_to_cpu(ghdr->size), checksum)) {
		DRM_ERROR("invalid gc data table checksum\n");
		r = -EINVAL;
		goto out;
	}

	return 0;

out:
	kfree(adev->mman.discovery_bin);
	adev->mman.discovery_bin = NULL;

	return r;
}

void amdgpu_discovery_fini(struct amdgpu_device *adev)
{
	kfree(adev->mman.discovery_bin);
	adev->mman.discovery_bin = NULL;
}

static int amdgpu_discovery_validate_ip(const struct ip *ip)
{
	if (ip->number_instance >= HWIP_MAX_INSTANCE) {
		DRM_ERROR("Unexpected number_instance (%d) from ip discovery blob\n",
			  ip->number_instance);
		return -EINVAL;
	}
	if (le16_to_cpu(ip->hw_id) >= HW_ID_MAX) {
		DRM_ERROR("Unexpected hw_id (%d) from ip discovery blob\n",
			  le16_to_cpu(ip->hw_id));
		return -EINVAL;
	}

	return 0;
}

int amdgpu_discovery_reg_base_init(struct amdgpu_device *adev)
{
	struct binary_header *bhdr;
	struct ip_discovery_header *ihdr;
	struct die_header *dhdr;
	struct ip *ip;
	uint16_t die_offset;
	uint16_t ip_offset;
	uint16_t num_dies;
	uint16_t num_ips;
	uint8_t num_base_address;
	int hw_ip;
	int i, j, k;
	int r;

	r = amdgpu_discovery_init(adev);
	if (r) {
		DRM_ERROR("amdgpu_discovery_init failed\n");
		return r;
	}

	bhdr = (struct binary_header *)adev->mman.discovery_bin;
	ihdr = (struct ip_discovery_header *)(adev->mman.discovery_bin +
			le16_to_cpu(bhdr->table_list[IP_DISCOVERY].offset));
	num_dies = le16_to_cpu(ihdr->num_dies);

	DRM_DEBUG("number of dies: %d\n", num_dies);

	for (i = 0; i < num_dies; i++) {
		die_offset = le16_to_cpu(ihdr->die_info[i].die_offset);
		dhdr = (struct die_header *)(adev->mman.discovery_bin + die_offset);
		num_ips = le16_to_cpu(dhdr->num_ips);
		ip_offset = die_offset + sizeof(*dhdr);

		if (le16_to_cpu(dhdr->die_id) != i) {
			DRM_ERROR("invalid die id %d, expected %d\n",
					le16_to_cpu(dhdr->die_id), i);
			return -EINVAL;
		}

		DRM_DEBUG("number of hardware IPs on die%d: %d\n",
				le16_to_cpu(dhdr->die_id), num_ips);

		for (j = 0; j < num_ips; j++) {
			ip = (struct ip *)(adev->mman.discovery_bin + ip_offset);

			if (amdgpu_discovery_validate_ip(ip))
				goto next_ip;

			num_base_address = ip->num_base_address;

			DRM_DEBUG("%s(%d) #%d v%d.%d.%d:\n",
				  hw_id_names[le16_to_cpu(ip->hw_id)],
				  le16_to_cpu(ip->hw_id),
				  ip->number_instance,
				  ip->major, ip->minor,
				  ip->revision);

			if (le16_to_cpu(ip->hw_id) == VCN_HWID)
				adev->vcn.num_vcn_inst++;
			if (le16_to_cpu(ip->hw_id) == SDMA0_HWID ||
			    le16_to_cpu(ip->hw_id) == SDMA1_HWID ||
			    le16_to_cpu(ip->hw_id) == SDMA2_HWID ||
			    le16_to_cpu(ip->hw_id) == SDMA3_HWID)
				adev->sdma.num_instances++;

			for (k = 0; k < num_base_address; k++) {
				/*
				 * convert the endianness of base addresses in place,
				 * so that we don't need to convert them when accessing adev->reg_offset.
				 */
				ip->base_address[k] = le32_to_cpu(ip->base_address[k]);
				DRM_DEBUG("\t0x%08x\n", ip->base_address[k]);
			}

			for (hw_ip = 0; hw_ip < MAX_HWIP; hw_ip++) {
				if (hw_id_map[hw_ip] == le16_to_cpu(ip->hw_id)) {
					DRM_DEBUG("set register base offset for %s\n",
							hw_id_names[le16_to_cpu(ip->hw_id)]);
					adev->reg_offset[hw_ip][ip->number_instance] =
						ip->base_address;
					/* Instance support is somewhat inconsistent.
					 * SDMA is a good example.  Sienna cichlid has 4 total
					 * SDMA instances, each enumerated separately (HWIDs
					 * 42, 43, 68, 69).  Arcturus has 8 total SDMA instances,
					 * but they are enumerated as multiple instances of the
					 * same HWIDs (4x HWID 42, 4x HWID 43).  UMC is another
					 * example.  On most chips there are multiple instances
					 * with the same HWID.
					 */
					adev->ip_versions[hw_ip][ip->number_instance] =
						IP_VERSION(ip->major, ip->minor, ip->revision);
				}
			}

next_ip:
			ip_offset += sizeof(*ip) + 4 * (ip->num_base_address - 1);
		}
	}

	return 0;
}

int amdgpu_discovery_get_ip_version(struct amdgpu_device *adev, int hw_id, int number_instance,
				    int *major, int *minor, int *revision)
{
	struct binary_header *bhdr;
	struct ip_discovery_header *ihdr;
	struct die_header *dhdr;
	struct ip *ip;
	uint16_t die_offset;
	uint16_t ip_offset;
	uint16_t num_dies;
	uint16_t num_ips;
	int i, j;

	if (!adev->mman.discovery_bin) {
		DRM_ERROR("ip discovery uninitialized\n");
		return -EINVAL;
	}

	bhdr = (struct binary_header *)adev->mman.discovery_bin;
	ihdr = (struct ip_discovery_header *)(adev->mman.discovery_bin +
			le16_to_cpu(bhdr->table_list[IP_DISCOVERY].offset));
	num_dies = le16_to_cpu(ihdr->num_dies);

	for (i = 0; i < num_dies; i++) {
		die_offset = le16_to_cpu(ihdr->die_info[i].die_offset);
		dhdr = (struct die_header *)(adev->mman.discovery_bin + die_offset);
		num_ips = le16_to_cpu(dhdr->num_ips);
		ip_offset = die_offset + sizeof(*dhdr);

		for (j = 0; j < num_ips; j++) {
			ip = (struct ip *)(adev->mman.discovery_bin + ip_offset);

			if ((le16_to_cpu(ip->hw_id) == hw_id) && (ip->number_instance == number_instance)) {
				if (major)
					*major = ip->major;
				if (minor)
					*minor = ip->minor;
				if (revision)
					*revision = ip->revision;
				return 0;
			}
			ip_offset += sizeof(*ip) + 4 * (ip->num_base_address - 1);
		}
	}

	return -EINVAL;
}


int amdgpu_discovery_get_vcn_version(struct amdgpu_device *adev, int vcn_instance,
				     int *major, int *minor, int *revision)
{
	return amdgpu_discovery_get_ip_version(adev, VCN_HWID,
					       vcn_instance, major, minor, revision);
}

void amdgpu_discovery_harvest_ip(struct amdgpu_device *adev)
{
	struct binary_header *bhdr;
	struct harvest_table *harvest_info;
	int i, vcn_harvest_count = 0;

	bhdr = (struct binary_header *)adev->mman.discovery_bin;
	harvest_info = (struct harvest_table *)(adev->mman.discovery_bin +
			le16_to_cpu(bhdr->table_list[HARVEST_INFO].offset));

	for (i = 0; i < 32; i++) {
		if (le16_to_cpu(harvest_info->list[i].hw_id) == 0)
			break;

		switch (le16_to_cpu(harvest_info->list[i].hw_id)) {
		case VCN_HWID:
			vcn_harvest_count++;
			if (harvest_info->list[i].number_instance == 0)
				adev->vcn.harvest_config |= AMDGPU_VCN_HARVEST_VCN0;
			else
				adev->vcn.harvest_config |= AMDGPU_VCN_HARVEST_VCN1;
			break;
		case DMU_HWID:
			adev->harvest_ip_mask |= AMD_HARVEST_IP_DMU_MASK;
			break;
		default:
			break;
		}
	}
	/* some IP discovery tables on Navy Flounder don't have this set correctly */
	if ((adev->ip_versions[UVD_HWIP][1] == IP_VERSION(3, 0, 1)) &&
	    (adev->ip_versions[GC_HWIP][0] == IP_VERSION(10, 3, 2)))
		adev->vcn.harvest_config |= AMDGPU_VCN_HARVEST_VCN1;
	if (vcn_harvest_count == adev->vcn.num_vcn_inst) {
		adev->harvest_ip_mask |= AMD_HARVEST_IP_VCN_MASK;
		adev->harvest_ip_mask |= AMD_HARVEST_IP_JPEG_MASK;
	}
	if ((adev->pdev->device == 0x731E &&
	     (adev->pdev->revision == 0xC6 || adev->pdev->revision == 0xC7)) ||
	    (adev->pdev->device == 0x7340 && adev->pdev->revision == 0xC9)  ||
	    (adev->pdev->device == 0x7360 && adev->pdev->revision == 0xC7)) {
		adev->harvest_ip_mask |= AMD_HARVEST_IP_VCN_MASK;
		adev->harvest_ip_mask |= AMD_HARVEST_IP_JPEG_MASK;
	}
}

union gc_info {
	struct gc_info_v1_0 v1;
	struct gc_info_v2_0 v2;
};

int amdgpu_discovery_get_gfx_info(struct amdgpu_device *adev)
{
	struct binary_header *bhdr;
	union gc_info *gc_info;

	if (!adev->mman.discovery_bin) {
		DRM_ERROR("ip discovery uninitialized\n");
		return -EINVAL;
	}

	bhdr = (struct binary_header *)adev->mman.discovery_bin;
	gc_info = (union gc_info *)(adev->mman.discovery_bin +
			le16_to_cpu(bhdr->table_list[GC].offset));
	switch (gc_info->v1.header.version_major) {
	case 1:
		adev->gfx.config.max_shader_engines = le32_to_cpu(gc_info->v1.gc_num_se);
		adev->gfx.config.max_cu_per_sh = 2 * (le32_to_cpu(gc_info->v1.gc_num_wgp0_per_sa) +
						      le32_to_cpu(gc_info->v1.gc_num_wgp1_per_sa));
		adev->gfx.config.max_sh_per_se = le32_to_cpu(gc_info->v1.gc_num_sa_per_se);
		adev->gfx.config.max_backends_per_se = le32_to_cpu(gc_info->v1.gc_num_rb_per_se);
		adev->gfx.config.max_texture_channel_caches = le32_to_cpu(gc_info->v1.gc_num_gl2c);
		adev->gfx.config.max_gprs = le32_to_cpu(gc_info->v1.gc_num_gprs);
		adev->gfx.config.max_gs_threads = le32_to_cpu(gc_info->v1.gc_num_max_gs_thds);
		adev->gfx.config.gs_vgt_table_depth = le32_to_cpu(gc_info->v1.gc_gs_table_depth);
		adev->gfx.config.gs_prim_buffer_depth = le32_to_cpu(gc_info->v1.gc_gsprim_buff_depth);
		adev->gfx.config.double_offchip_lds_buf = le32_to_cpu(gc_info->v1.gc_double_offchip_lds_buffer);
		adev->gfx.cu_info.wave_front_size = le32_to_cpu(gc_info->v1.gc_wave_size);
		adev->gfx.cu_info.max_waves_per_simd = le32_to_cpu(gc_info->v1.gc_max_waves_per_simd);
		adev->gfx.cu_info.max_scratch_slots_per_cu = le32_to_cpu(gc_info->v1.gc_max_scratch_slots_per_cu);
		adev->gfx.cu_info.lds_size = le32_to_cpu(gc_info->v1.gc_lds_size);
		adev->gfx.config.num_sc_per_sh = le32_to_cpu(gc_info->v1.gc_num_sc_per_se) /
			le32_to_cpu(gc_info->v1.gc_num_sa_per_se);
		adev->gfx.config.num_packer_per_sc = le32_to_cpu(gc_info->v1.gc_num_packer_per_sc);
		break;
	case 2:
		adev->gfx.config.max_shader_engines = le32_to_cpu(gc_info->v2.gc_num_se);
		adev->gfx.config.max_cu_per_sh = le32_to_cpu(gc_info->v2.gc_num_cu_per_sh);
		adev->gfx.config.max_sh_per_se = le32_to_cpu(gc_info->v2.gc_num_sh_per_se);
		adev->gfx.config.max_backends_per_se = le32_to_cpu(gc_info->v2.gc_num_rb_per_se);
		adev->gfx.config.max_texture_channel_caches = le32_to_cpu(gc_info->v2.gc_num_tccs);
		adev->gfx.config.max_gprs = le32_to_cpu(gc_info->v2.gc_num_gprs);
		adev->gfx.config.max_gs_threads = le32_to_cpu(gc_info->v2.gc_num_max_gs_thds);
		adev->gfx.config.gs_vgt_table_depth = le32_to_cpu(gc_info->v2.gc_gs_table_depth);
		adev->gfx.config.gs_prim_buffer_depth = le32_to_cpu(gc_info->v2.gc_gsprim_buff_depth);
		adev->gfx.config.double_offchip_lds_buf = le32_to_cpu(gc_info->v2.gc_double_offchip_lds_buffer);
		adev->gfx.cu_info.wave_front_size = le32_to_cpu(gc_info->v2.gc_wave_size);
		adev->gfx.cu_info.max_waves_per_simd = le32_to_cpu(gc_info->v2.gc_max_waves_per_simd);
		adev->gfx.cu_info.max_scratch_slots_per_cu = le32_to_cpu(gc_info->v2.gc_max_scratch_slots_per_cu);
		adev->gfx.cu_info.lds_size = le32_to_cpu(gc_info->v2.gc_lds_size);
		adev->gfx.config.num_sc_per_sh = le32_to_cpu(gc_info->v2.gc_num_sc_per_se) /
			le32_to_cpu(gc_info->v2.gc_num_sh_per_se);
		adev->gfx.config.num_packer_per_sc = le32_to_cpu(gc_info->v2.gc_num_packer_per_sc);
		break;
	default:
		dev_err(adev->dev,
			"Unhandled GC info table %d.%d\n",
			gc_info->v1.header.version_major,
			gc_info->v1.header.version_minor);
		return -EINVAL;
	}
	return 0;
}

static int amdgpu_discovery_set_common_ip_blocks(struct amdgpu_device *adev)
{
	/* what IP to use for this? */
	switch (adev->ip_versions[GC_HWIP][0]) {
	case IP_VERSION(9, 0, 1):
	case IP_VERSION(9, 1, 0):
	case IP_VERSION(9, 2, 1):
	case IP_VERSION(9, 2, 2):
	case IP_VERSION(9, 3, 0):
	case IP_VERSION(9, 4, 0):
	case IP_VERSION(9, 4, 1):
	case IP_VERSION(9, 4, 2):
		amdgpu_device_ip_block_add(adev, &vega10_common_ip_block);
		break;
	case IP_VERSION(10, 1, 10):
	case IP_VERSION(10, 1, 1):
	case IP_VERSION(10, 1, 2):
	case IP_VERSION(10, 1, 3):
	case IP_VERSION(10, 3, 0):
	case IP_VERSION(10, 3, 1):
	case IP_VERSION(10, 3, 2):
	case IP_VERSION(10, 3, 3):
	case IP_VERSION(10, 3, 4):
	case IP_VERSION(10, 3, 5):
		amdgpu_device_ip_block_add(adev, &nv_common_ip_block);
		break;
	default:
		dev_err(adev->dev,
			"Failed to add common ip block(GC_HWIP:0x%x)\n",
			adev->ip_versions[GC_HWIP][0]);
		return -EINVAL;
	}
	return 0;
}

static int amdgpu_discovery_set_gmc_ip_blocks(struct amdgpu_device *adev)
{
	/* use GC or MMHUB IP version */
	switch (adev->ip_versions[GC_HWIP][0]) {
	case IP_VERSION(9, 0, 1):
	case IP_VERSION(9, 1, 0):
	case IP_VERSION(9, 2, 1):
	case IP_VERSION(9, 2, 2):
	case IP_VERSION(9, 3, 0):
	case IP_VERSION(9, 4, 0):
	case IP_VERSION(9, 4, 1):
	case IP_VERSION(9, 4, 2):
		amdgpu_device_ip_block_add(adev, &gmc_v9_0_ip_block);
		break;
	case IP_VERSION(10, 1, 10):
	case IP_VERSION(10, 1, 1):
	case IP_VERSION(10, 1, 2):
	case IP_VERSION(10, 1, 3):
	case IP_VERSION(10, 3, 0):
	case IP_VERSION(10, 3, 1):
	case IP_VERSION(10, 3, 2):
	case IP_VERSION(10, 3, 3):
	case IP_VERSION(10, 3, 4):
	case IP_VERSION(10, 3, 5):
		amdgpu_device_ip_block_add(adev, &gmc_v10_0_ip_block);
		break;
	default:
		dev_err(adev->dev,
			"Failed to add gmc ip block(GC_HWIP:0x%x)\n",
			adev->ip_versions[GC_HWIP][0]);
		return -EINVAL;
	}
	return 0;
}

static int amdgpu_discovery_set_ih_ip_blocks(struct amdgpu_device *adev)
{
	switch (adev->ip_versions[OSSSYS_HWIP][0]) {
	case IP_VERSION(4, 0, 0):
	case IP_VERSION(4, 0, 1):
	case IP_VERSION(4, 1, 0):
	case IP_VERSION(4, 1, 1):
	case IP_VERSION(4, 3, 0):
		amdgpu_device_ip_block_add(adev, &vega10_ih_ip_block);
		break;
	case IP_VERSION(4, 2, 0):
	case IP_VERSION(4, 2, 1):
	case IP_VERSION(4, 4, 0):
		amdgpu_device_ip_block_add(adev, &vega20_ih_ip_block);
		break;
	case IP_VERSION(5, 0, 0):
	case IP_VERSION(5, 0, 1):
	case IP_VERSION(5, 0, 2):
	case IP_VERSION(5, 0, 3):
	case IP_VERSION(5, 2, 0):
	case IP_VERSION(5, 2, 1):
		amdgpu_device_ip_block_add(adev, &navi10_ih_ip_block);
		break;
	default:
		dev_err(adev->dev,
			"Failed to add ih ip block(OSSSYS_HWIP:0x%x)\n",
			adev->ip_versions[OSSSYS_HWIP][0]);
		return -EINVAL;
	}
	return 0;
}

static int amdgpu_discovery_set_psp_ip_blocks(struct amdgpu_device *adev)
{
	switch (adev->ip_versions[MP0_HWIP][0]) {
	case IP_VERSION(9, 0, 0):
		amdgpu_device_ip_block_add(adev, &psp_v3_1_ip_block);
		break;
	case IP_VERSION(10, 0, 0):
	case IP_VERSION(10, 0, 1):
		amdgpu_device_ip_block_add(adev, &psp_v10_0_ip_block);
		break;
	case IP_VERSION(11, 0, 0):
	case IP_VERSION(11, 0, 2):
	case IP_VERSION(11, 0, 4):
	case IP_VERSION(11, 0, 5):
	case IP_VERSION(11, 0, 9):
	case IP_VERSION(11, 0, 7):
	case IP_VERSION(11, 0, 11):
	case IP_VERSION(11, 0, 12):
	case IP_VERSION(11, 0, 13):
	case IP_VERSION(11, 5, 0):
		amdgpu_device_ip_block_add(adev, &psp_v11_0_ip_block);
		break;
	case IP_VERSION(11, 0, 8):
		amdgpu_device_ip_block_add(adev, &psp_v11_0_8_ip_block);
		break;
	case IP_VERSION(11, 0, 3):
	case IP_VERSION(12, 0, 1):
		amdgpu_device_ip_block_add(adev, &psp_v12_0_ip_block);
		break;
	case IP_VERSION(13, 0, 1):
	case IP_VERSION(13, 0, 2):
	case IP_VERSION(13, 0, 3):
		amdgpu_device_ip_block_add(adev, &psp_v13_0_ip_block);
		break;
	default:
		dev_err(adev->dev,
			"Failed to add psp ip block(MP0_HWIP:0x%x)\n",
			adev->ip_versions[MP0_HWIP][0]);
		return -EINVAL;
	}
	return 0;
}

static int amdgpu_discovery_set_smu_ip_blocks(struct amdgpu_device *adev)
{
	switch (adev->ip_versions[MP1_HWIP][0]) {
	case IP_VERSION(9, 0, 0):
	case IP_VERSION(10, 0, 0):
	case IP_VERSION(10, 0, 1):
	case IP_VERSION(11, 0, 2):
		if (adev->asic_type == CHIP_ARCTURUS)
			amdgpu_device_ip_block_add(adev, &smu_v11_0_ip_block);
		else
			amdgpu_device_ip_block_add(adev, &pp_smu_ip_block);
		break;
	case IP_VERSION(11, 0, 0):
	case IP_VERSION(11, 0, 5):
	case IP_VERSION(11, 0, 9):
	case IP_VERSION(11, 0, 7):
	case IP_VERSION(11, 0, 8):
	case IP_VERSION(11, 0, 11):
	case IP_VERSION(11, 0, 12):
	case IP_VERSION(11, 0, 13):
	case IP_VERSION(11, 5, 0):
		amdgpu_device_ip_block_add(adev, &smu_v11_0_ip_block);
		break;
	case IP_VERSION(12, 0, 0):
	case IP_VERSION(12, 0, 1):
		amdgpu_device_ip_block_add(adev, &smu_v12_0_ip_block);
		break;
	case IP_VERSION(13, 0, 1):
	case IP_VERSION(13, 0, 2):
	case IP_VERSION(13, 0, 3):
		amdgpu_device_ip_block_add(adev, &smu_v13_0_ip_block);
		break;
	default:
		dev_err(adev->dev,
			"Failed to add smu ip block(MP1_HWIP:0x%x)\n",
			adev->ip_versions[MP1_HWIP][0]);
		return -EINVAL;
	}
	return 0;
}

static int amdgpu_discovery_set_display_ip_blocks(struct amdgpu_device *adev)
{
	if (adev->enable_virtual_display || amdgpu_sriov_vf(adev)) {
		amdgpu_device_ip_block_add(adev, &amdgpu_vkms_ip_block);
#if defined(CONFIG_DRM_AMD_DC)
	} else if (adev->ip_versions[DCE_HWIP][0]) {
		switch (adev->ip_versions[DCE_HWIP][0]) {
		case IP_VERSION(1, 0, 0):
		case IP_VERSION(1, 0, 1):
		case IP_VERSION(2, 0, 2):
		case IP_VERSION(2, 0, 0):
		case IP_VERSION(2, 0, 3):
		case IP_VERSION(2, 1, 0):
		case IP_VERSION(3, 0, 0):
		case IP_VERSION(3, 0, 2):
		case IP_VERSION(3, 0, 3):
		case IP_VERSION(3, 0, 1):
		case IP_VERSION(3, 1, 2):
		case IP_VERSION(3, 1, 3):
			amdgpu_device_ip_block_add(adev, &dm_ip_block);
			break;
		default:
			dev_err(adev->dev,
				"Failed to add dm ip block(DCE_HWIP:0x%x)\n",
				adev->ip_versions[DCE_HWIP][0]);
			return -EINVAL;
		}
	} else if (adev->ip_versions[DCI_HWIP][0]) {
		switch (adev->ip_versions[DCI_HWIP][0]) {
		case IP_VERSION(12, 0, 0):
		case IP_VERSION(12, 0, 1):
		case IP_VERSION(12, 1, 0):
			amdgpu_device_ip_block_add(adev, &dm_ip_block);
			break;
		default:
			dev_err(adev->dev,
				"Failed to add dm ip block(DCI_HWIP:0x%x)\n",
				adev->ip_versions[DCI_HWIP][0]);
			return -EINVAL;
		}
#endif
	}
	return 0;
}

static int amdgpu_discovery_set_gc_ip_blocks(struct amdgpu_device *adev)
{
	switch (adev->ip_versions[GC_HWIP][0]) {
	case IP_VERSION(9, 0, 1):
	case IP_VERSION(9, 1, 0):
	case IP_VERSION(9, 2, 1):
	case IP_VERSION(9, 2, 2):
	case IP_VERSION(9, 3, 0):
	case IP_VERSION(9, 4, 0):
	case IP_VERSION(9, 4, 1):
	case IP_VERSION(9, 4, 2):
		amdgpu_device_ip_block_add(adev, &gfx_v9_0_ip_block);
		break;
	case IP_VERSION(10, 1, 10):
	case IP_VERSION(10, 1, 2):
	case IP_VERSION(10, 1, 1):
	case IP_VERSION(10, 1, 3):
	case IP_VERSION(10, 3, 0):
	case IP_VERSION(10, 3, 2):
	case IP_VERSION(10, 3, 1):
	case IP_VERSION(10, 3, 4):
	case IP_VERSION(10, 3, 5):
	case IP_VERSION(10, 3, 3):
		amdgpu_device_ip_block_add(adev, &gfx_v10_0_ip_block);
		break;
	default:
		dev_err(adev->dev,
			"Failed to add gfx ip block(GC_HWIP:0x%x)\n",
			adev->ip_versions[GC_HWIP][0]);
		return -EINVAL;
	}
	return 0;
}

static int amdgpu_discovery_set_sdma_ip_blocks(struct amdgpu_device *adev)
{
	switch (adev->ip_versions[SDMA0_HWIP][0]) {
	case IP_VERSION(4, 0, 0):
	case IP_VERSION(4, 0, 1):
	case IP_VERSION(4, 1, 0):
	case IP_VERSION(4, 1, 1):
	case IP_VERSION(4, 1, 2):
	case IP_VERSION(4, 2, 0):
	case IP_VERSION(4, 2, 2):
	case IP_VERSION(4, 4, 0):
		amdgpu_device_ip_block_add(adev, &sdma_v4_0_ip_block);
		break;
	case IP_VERSION(5, 0, 0):
	case IP_VERSION(5, 0, 1):
	case IP_VERSION(5, 0, 2):
	case IP_VERSION(5, 0, 5):
		amdgpu_device_ip_block_add(adev, &sdma_v5_0_ip_block);
		break;
	case IP_VERSION(5, 2, 0):
	case IP_VERSION(5, 2, 2):
	case IP_VERSION(5, 2, 4):
	case IP_VERSION(5, 2, 5):
	case IP_VERSION(5, 2, 3):
	case IP_VERSION(5, 2, 1):
		amdgpu_device_ip_block_add(adev, &sdma_v5_2_ip_block);
		break;
	default:
		dev_err(adev->dev,
			"Failed to add sdma ip block(SDMA0_HWIP:0x%x)\n",
			adev->ip_versions[SDMA0_HWIP][0]);
		return -EINVAL;
	}
	return 0;
}

static int amdgpu_discovery_set_mm_ip_blocks(struct amdgpu_device *adev)
{
	if (adev->ip_versions[VCE_HWIP][0]) {
		switch (adev->ip_versions[UVD_HWIP][0]) {
		case IP_VERSION(7, 0, 0):
		case IP_VERSION(7, 2, 0):
			/* UVD is not supported on vega20 SR-IOV */
			if (!(adev->asic_type == CHIP_VEGA20 && amdgpu_sriov_vf(adev)))
				amdgpu_device_ip_block_add(adev, &uvd_v7_0_ip_block);
			break;
		default:
			dev_err(adev->dev,
				"Failed to add uvd v7 ip block(UVD_HWIP:0x%x)\n",
				adev->ip_versions[UVD_HWIP][0]);
			return -EINVAL;
		}
		switch (adev->ip_versions[VCE_HWIP][0]) {
		case IP_VERSION(4, 0, 0):
		case IP_VERSION(4, 1, 0):
			/* VCE is not supported on vega20 SR-IOV */
			if (!(adev->asic_type == CHIP_VEGA20 && amdgpu_sriov_vf(adev)))
				amdgpu_device_ip_block_add(adev, &vce_v4_0_ip_block);
			break;
		default:
			dev_err(adev->dev,
				"Failed to add VCE v4 ip block(VCE_HWIP:0x%x)\n",
				adev->ip_versions[VCE_HWIP][0]);
			return -EINVAL;
		}
	} else {
		switch (adev->ip_versions[UVD_HWIP][0]) {
		case IP_VERSION(1, 0, 0):
		case IP_VERSION(1, 0, 1):
			amdgpu_device_ip_block_add(adev, &vcn_v1_0_ip_block);
			break;
		case IP_VERSION(2, 0, 0):
		case IP_VERSION(2, 0, 2):
		case IP_VERSION(2, 2, 0):
			amdgpu_device_ip_block_add(adev, &vcn_v2_0_ip_block);
			if (!amdgpu_sriov_vf(adev))
				amdgpu_device_ip_block_add(adev, &jpeg_v2_0_ip_block);
			break;
		case IP_VERSION(2, 0, 3):
			break;
		case IP_VERSION(2, 5, 0):
			amdgpu_device_ip_block_add(adev, &vcn_v2_5_ip_block);
			amdgpu_device_ip_block_add(adev, &jpeg_v2_5_ip_block);
			break;
		case IP_VERSION(2, 6, 0):
			amdgpu_device_ip_block_add(adev, &vcn_v2_6_ip_block);
			amdgpu_device_ip_block_add(adev, &jpeg_v2_6_ip_block);
			break;
		case IP_VERSION(3, 0, 0):
		case IP_VERSION(3, 0, 16):
		case IP_VERSION(3, 0, 64):
		case IP_VERSION(3, 1, 1):
		case IP_VERSION(3, 0, 2):
		case IP_VERSION(3, 0, 192):
			amdgpu_device_ip_block_add(adev, &vcn_v3_0_ip_block);
			if (!amdgpu_sriov_vf(adev))
				amdgpu_device_ip_block_add(adev, &jpeg_v3_0_ip_block);
			break;
		case IP_VERSION(3, 0, 33):
			amdgpu_device_ip_block_add(adev, &vcn_v3_0_ip_block);
			break;
		default:
			dev_err(adev->dev,
				"Failed to add vcn/jpeg ip block(UVD_HWIP:0x%x)\n",
				adev->ip_versions[UVD_HWIP][0]);
			return -EINVAL;
		}
	}
	return 0;
}

static int amdgpu_discovery_set_mes_ip_blocks(struct amdgpu_device *adev)
{
	switch (adev->ip_versions[GC_HWIP][0]) {
	case IP_VERSION(10, 1, 10):
	case IP_VERSION(10, 1, 1):
	case IP_VERSION(10, 1, 2):
	case IP_VERSION(10, 1, 3):
	case IP_VERSION(10, 3, 0):
	case IP_VERSION(10, 3, 1):
	case IP_VERSION(10, 3, 2):
	case IP_VERSION(10, 3, 3):
	case IP_VERSION(10, 3, 4):
	case IP_VERSION(10, 3, 5):
		amdgpu_device_ip_block_add(adev, &mes_v10_1_ip_block);
		break;
	default:
		break;;
	}
	return 0;
}

int amdgpu_discovery_set_ip_blocks(struct amdgpu_device *adev)
{
	int r;

	switch (adev->asic_type) {
	case CHIP_VEGA10:
		vega10_reg_base_init(adev);
		adev->sdma.num_instances = 2;
		adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 0, 0);
		adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 0, 0);
		adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 0, 0);
		adev->ip_versions[SDMA1_HWIP][0] = IP_VERSION(4, 0, 0);
		adev->ip_versions[DF_HWIP][0] = IP_VERSION(2, 1, 0);
		adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(6, 1, 0);
		adev->ip_versions[UMC_HWIP][0] = IP_VERSION(6, 0, 0);
		adev->ip_versions[MP0_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[MP1_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[THM_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 0, 1);
		adev->ip_versions[UVD_HWIP][0] = IP_VERSION(7, 0, 0);
		adev->ip_versions[VCE_HWIP][0] = IP_VERSION(4, 0, 0);
		adev->ip_versions[DCI_HWIP][0] = IP_VERSION(12, 0, 0);
		break;
	case CHIP_VEGA12:
		vega10_reg_base_init(adev);
		adev->sdma.num_instances = 2;
		adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 3, 0);
		adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 3, 0);
		adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 0, 1);
		adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 0, 1);
		adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 0, 1);
		adev->ip_versions[SDMA1_HWIP][0] = IP_VERSION(4, 0, 1);
		adev->ip_versions[DF_HWIP][0] = IP_VERSION(2, 5, 0);
		adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(6, 2, 0);
		adev->ip_versions[UMC_HWIP][0] = IP_VERSION(6, 1, 0);
		adev->ip_versions[MP0_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[MP1_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[THM_HWIP][0] = IP_VERSION(9, 0, 0);
		adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(9, 0, 1);
		adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 2, 1);
		adev->ip_versions[UVD_HWIP][0] = IP_VERSION(7, 0, 0);
		adev->ip_versions[VCE_HWIP][0] = IP_VERSION(4, 0, 0);
		adev->ip_versions[DCI_HWIP][0] = IP_VERSION(12, 0, 1);
		break;
	case CHIP_RAVEN:
		vega10_reg_base_init(adev);
		adev->sdma.num_instances = 1;
		adev->vcn.num_vcn_inst = 1;
		if (adev->apu_flags & AMD_APU_IS_RAVEN2) {
			adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 2, 0);
			adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 2, 0);
			adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 1, 1);
			adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 1, 1);
			adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 1, 1);
			adev->ip_versions[DF_HWIP][0] = IP_VERSION(2, 1, 1);
			adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(7, 0, 1);
			adev->ip_versions[UMC_HWIP][0] = IP_VERSION(7, 5, 0);
			adev->ip_versions[MP0_HWIP][0] = IP_VERSION(10, 0, 1);
			adev->ip_versions[MP1_HWIP][0] = IP_VERSION(10, 0, 1);
			adev->ip_versions[THM_HWIP][0] = IP_VERSION(10, 1, 0);
			adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(10, 0, 1);
			adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 2, 2);
			adev->ip_versions[UVD_HWIP][0] = IP_VERSION(1, 0, 1);
			adev->ip_versions[DCE_HWIP][0] = IP_VERSION(1, 0, 1);
		} else {
			adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 1, 0);
			adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 1, 0);
			adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 1, 0);
			adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 1, 0);
			adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 1, 0);
			adev->ip_versions[DF_HWIP][0] = IP_VERSION(2, 1, 0);
			adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(7, 0, 0);
			adev->ip_versions[UMC_HWIP][0] = IP_VERSION(7, 0, 0);
			adev->ip_versions[MP0_HWIP][0] = IP_VERSION(10, 0, 0);
			adev->ip_versions[MP1_HWIP][0] = IP_VERSION(10, 0, 0);
			adev->ip_versions[THM_HWIP][0] = IP_VERSION(10, 0, 0);
			adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(10, 0, 0);
			adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 1, 0);
			adev->ip_versions[UVD_HWIP][0] = IP_VERSION(1, 0, 0);
			adev->ip_versions[DCE_HWIP][0] = IP_VERSION(1, 0, 0);
		}
		break;
	case CHIP_VEGA20:
		vega20_reg_base_init(adev);
		adev->sdma.num_instances = 2;
		adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 4, 0);
		adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 4, 0);
		adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 2, 0);
		adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 2, 0);
		adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 2, 0);
		adev->ip_versions[SDMA1_HWIP][0] = IP_VERSION(4, 2, 0);
		adev->ip_versions[DF_HWIP][0] = IP_VERSION(3, 6, 0);
		adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(7, 4, 0);
		adev->ip_versions[UMC_HWIP][0] = IP_VERSION(6, 1, 1);
		adev->ip_versions[MP0_HWIP][0] = IP_VERSION(11, 0, 2);
		adev->ip_versions[MP1_HWIP][0] = IP_VERSION(11, 0, 2);
		adev->ip_versions[THM_HWIP][0] = IP_VERSION(11, 0, 2);
		adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(11, 0, 2);
		adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 4, 0);
		adev->ip_versions[UVD_HWIP][0] = IP_VERSION(7, 2, 0);
		adev->ip_versions[UVD_HWIP][1] = IP_VERSION(7, 2, 0);
		adev->ip_versions[VCE_HWIP][0] = IP_VERSION(4, 1, 0);
		adev->ip_versions[DCI_HWIP][0] = IP_VERSION(12, 1, 0);
		break;
	case CHIP_ARCTURUS:
		arct_reg_base_init(adev);
		adev->sdma.num_instances = 8;
		adev->vcn.num_vcn_inst = 2;
		adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 4, 1);
		adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 4, 1);
		adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 2, 1);
		adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 2, 1);
		adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][0] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][1] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][2] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][3] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][4] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][5] = IP_VERSION(4, 2, 2);
		adev->ip_versions[SDMA1_HWIP][6] = IP_VERSION(4, 2, 2);
		adev->ip_versions[DF_HWIP][0] = IP_VERSION(3, 6, 1);
		adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(7, 4, 1);
		adev->ip_versions[UMC_HWIP][0] = IP_VERSION(6, 1, 2);
		adev->ip_versions[MP0_HWIP][0] = IP_VERSION(11, 0, 4);
		adev->ip_versions[MP1_HWIP][0] = IP_VERSION(11, 0, 2);
		adev->ip_versions[THM_HWIP][0] = IP_VERSION(11, 0, 3);
		adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(11, 0, 3);
		adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 4, 1);
		adev->ip_versions[UVD_HWIP][0] = IP_VERSION(2, 5, 0);
		adev->ip_versions[UVD_HWIP][1] = IP_VERSION(2, 5, 0);
		break;
	case CHIP_ALDEBARAN:
		aldebaran_reg_base_init(adev);
		adev->sdma.num_instances = 5;
		adev->vcn.num_vcn_inst = 2;
		adev->ip_versions[MMHUB_HWIP][0] = IP_VERSION(9, 4, 2);
		adev->ip_versions[ATHUB_HWIP][0] = IP_VERSION(9, 4, 2);
		adev->ip_versions[OSSSYS_HWIP][0] = IP_VERSION(4, 4, 0);
		adev->ip_versions[HDP_HWIP][0] = IP_VERSION(4, 4, 0);
		adev->ip_versions[SDMA0_HWIP][0] = IP_VERSION(4, 4, 0);
		adev->ip_versions[SDMA0_HWIP][1] = IP_VERSION(4, 4, 0);
		adev->ip_versions[SDMA0_HWIP][2] = IP_VERSION(4, 4, 0);
		adev->ip_versions[SDMA0_HWIP][3] = IP_VERSION(4, 4, 0);
		adev->ip_versions[SDMA0_HWIP][4] = IP_VERSION(4, 4, 0);
		adev->ip_versions[DF_HWIP][0] = IP_VERSION(3, 6, 2);
		adev->ip_versions[NBIO_HWIP][0] = IP_VERSION(7, 4, 4);
		adev->ip_versions[UMC_HWIP][0] = IP_VERSION(6, 7, 0);
		adev->ip_versions[MP0_HWIP][0] = IP_VERSION(13, 0, 2);
		adev->ip_versions[MP1_HWIP][0] = IP_VERSION(13, 0, 2);
		adev->ip_versions[THM_HWIP][0] = IP_VERSION(13, 0, 2);
		adev->ip_versions[SMUIO_HWIP][0] = IP_VERSION(13, 0, 2);
		adev->ip_versions[GC_HWIP][0] = IP_VERSION(9, 4, 2);
		adev->ip_versions[UVD_HWIP][0] = IP_VERSION(2, 6, 0);
		adev->ip_versions[UVD_HWIP][1] = IP_VERSION(2, 6, 0);
		adev->ip_versions[XGMI_HWIP][0] = IP_VERSION(6, 1, 0);
		break;
	default:
		r = amdgpu_discovery_reg_base_init(adev);
		if (r)
			return -EINVAL;

		amdgpu_discovery_harvest_ip(adev);

		if (!adev->mman.discovery_bin) {
			DRM_ERROR("ip discovery uninitialized\n");
			return -EINVAL;
		}
		break;
	}

	switch (adev->ip_versions[GC_HWIP][0]) {
	case IP_VERSION(9, 0, 1):
	case IP_VERSION(9, 2, 1):
	case IP_VERSION(9, 4, 0):
	case IP_VERSION(9, 4, 1):
	case IP_VERSION(9, 4, 2):
		adev->family = AMDGPU_FAMILY_AI;
		break;
	case IP_VERSION(9, 1, 0):
	case IP_VERSION(9, 2, 2):
	case IP_VERSION(9, 3, 0):
		adev->family = AMDGPU_FAMILY_RV;
		break;
	case IP_VERSION(10, 1, 10):
	case IP_VERSION(10, 1, 1):
	case IP_VERSION(10, 1, 2):
	case IP_VERSION(10, 1, 3):
	case IP_VERSION(10, 3, 0):
	case IP_VERSION(10, 3, 2):
	case IP_VERSION(10, 3, 4):
	case IP_VERSION(10, 3, 5):
		adev->family = AMDGPU_FAMILY_NV;
		break;
	case IP_VERSION(10, 3, 1):
		adev->family = AMDGPU_FAMILY_VGH;
		break;
	case IP_VERSION(10, 3, 3):
		adev->family = AMDGPU_FAMILY_YC;
		break;
	default:
		return -EINVAL;
	}

	if (adev->ip_versions[XGMI_HWIP][0] == IP_VERSION(4, 8, 0))
		adev->gmc.xgmi.supported = true;

	/* set NBIO version */
	switch (adev->ip_versions[NBIO_HWIP][0]) {
	case IP_VERSION(6, 1, 0):
	case IP_VERSION(6, 2, 0):
		adev->nbio.funcs = &nbio_v6_1_funcs;
		adev->nbio.hdp_flush_reg = &nbio_v6_1_hdp_flush_reg;
		break;
	case IP_VERSION(7, 0, 0):
	case IP_VERSION(7, 0, 1):
	case IP_VERSION(2, 5, 0):
		adev->nbio.funcs = &nbio_v7_0_funcs;
		adev->nbio.hdp_flush_reg = &nbio_v7_0_hdp_flush_reg;
		break;
	case IP_VERSION(7, 4, 0):
	case IP_VERSION(7, 4, 1):
		adev->nbio.funcs = &nbio_v7_4_funcs;
		adev->nbio.hdp_flush_reg = &nbio_v7_4_hdp_flush_reg;
		break;
	case IP_VERSION(7, 4, 4):
		adev->nbio.funcs = &nbio_v7_4_funcs;
		adev->nbio.hdp_flush_reg = &nbio_v7_4_hdp_flush_reg_ald;
		break;
	case IP_VERSION(7, 2, 0):
	case IP_VERSION(7, 2, 1):
	case IP_VERSION(7, 5, 0):
		adev->nbio.funcs = &nbio_v7_2_funcs;
		adev->nbio.hdp_flush_reg = &nbio_v7_2_hdp_flush_reg;
		break;
	case IP_VERSION(2, 1, 1):
	case IP_VERSION(2, 3, 0):
	case IP_VERSION(2, 3, 1):
	case IP_VERSION(2, 3, 2):
		adev->nbio.funcs = &nbio_v2_3_funcs;
		adev->nbio.hdp_flush_reg = &nbio_v2_3_hdp_flush_reg;
		break;
	case IP_VERSION(3, 3, 0):
	case IP_VERSION(3, 3, 1):
	case IP_VERSION(3, 3, 2):
	case IP_VERSION(3, 3, 3):
		adev->nbio.funcs = &nbio_v2_3_funcs;
		adev->nbio.hdp_flush_reg = &nbio_v2_3_hdp_flush_reg_sc;
		break;
	default:
		break;
	}

	switch (adev->ip_versions[HDP_HWIP][0]) {
	case IP_VERSION(4, 0, 0):
	case IP_VERSION(4, 0, 1):
	case IP_VERSION(4, 1, 0):
	case IP_VERSION(4, 1, 1):
	case IP_VERSION(4, 1, 2):
	case IP_VERSION(4, 2, 0):
	case IP_VERSION(4, 2, 1):
	case IP_VERSION(4, 4, 0):
		adev->hdp.funcs = &hdp_v4_0_funcs;
		break;
	case IP_VERSION(5, 0, 0):
	case IP_VERSION(5, 0, 1):
	case IP_VERSION(5, 0, 2):
	case IP_VERSION(5, 0, 3):
	case IP_VERSION(5, 0, 4):
	case IP_VERSION(5, 2, 0):
		adev->hdp.funcs = &hdp_v5_0_funcs;
		break;
	default:
		break;
	}

	switch (adev->ip_versions[DF_HWIP][0]) {
	case IP_VERSION(3, 6, 0):
	case IP_VERSION(3, 6, 1):
	case IP_VERSION(3, 6, 2):
		adev->df.funcs = &df_v3_6_funcs;
		break;
	case IP_VERSION(2, 1, 0):
	case IP_VERSION(2, 1, 1):
	case IP_VERSION(2, 5, 0):
	case IP_VERSION(3, 5, 1):
	case IP_VERSION(3, 5, 2):
		adev->df.funcs = &df_v1_7_funcs;
		break;
	default:
		break;
	}

	switch (adev->ip_versions[SMUIO_HWIP][0]) {
	case IP_VERSION(9, 0, 0):
	case IP_VERSION(9, 0, 1):
	case IP_VERSION(10, 0, 0):
	case IP_VERSION(10, 0, 1):
	case IP_VERSION(10, 0, 2):
		adev->smuio.funcs = &smuio_v9_0_funcs;
		break;
	case IP_VERSION(11, 0, 0):
	case IP_VERSION(11, 0, 2):
	case IP_VERSION(11, 0, 3):
	case IP_VERSION(11, 0, 4):
	case IP_VERSION(11, 0, 7):
	case IP_VERSION(11, 0, 8):
		adev->smuio.funcs = &smuio_v11_0_funcs;
		break;
	case IP_VERSION(11, 0, 6):
	case IP_VERSION(11, 0, 10):
	case IP_VERSION(11, 0, 11):
	case IP_VERSION(11, 5, 0):
	case IP_VERSION(13, 0, 1):
		adev->smuio.funcs = &smuio_v11_0_6_funcs;
		break;
	case IP_VERSION(13, 0, 2):
		adev->smuio.funcs = &smuio_v13_0_funcs;
		break;
	default:
		break;
	}

	r = amdgpu_discovery_set_common_ip_blocks(adev);
	if (r)
		return r;

	r = amdgpu_discovery_set_gmc_ip_blocks(adev);
	if (r)
		return r;

	/* For SR-IOV, PSP needs to be initialized before IH */
	if (amdgpu_sriov_vf(adev)) {
		r = amdgpu_discovery_set_psp_ip_blocks(adev);
		if (r)
			return r;
		r = amdgpu_discovery_set_ih_ip_blocks(adev);
		if (r)
			return r;
	} else {
		r = amdgpu_discovery_set_ih_ip_blocks(adev);
		if (r)
			return r;

		if (likely(adev->firmware.load_type == AMDGPU_FW_LOAD_PSP)) {
			r = amdgpu_discovery_set_psp_ip_blocks(adev);
			if (r)
				return r;
		}
	}

	if (likely(adev->firmware.load_type == AMDGPU_FW_LOAD_PSP)) {
		r = amdgpu_discovery_set_smu_ip_blocks(adev);
		if (r)
			return r;
	}

	r = amdgpu_discovery_set_display_ip_blocks(adev);
	if (r)
		return r;

	r = amdgpu_discovery_set_gc_ip_blocks(adev);
	if (r)
		return r;

	r = amdgpu_discovery_set_sdma_ip_blocks(adev);
	if (r)
		return r;

	if (adev->firmware.load_type == AMDGPU_FW_LOAD_DIRECT &&
	    !amdgpu_sriov_vf(adev)) {
		r = amdgpu_discovery_set_smu_ip_blocks(adev);
		if (r)
			return r;
	}

	r = amdgpu_discovery_set_mm_ip_blocks(adev);
	if (r)
		return r;

	if (adev->enable_mes) {
		r = amdgpu_discovery_set_mes_ip_blocks(adev);
		if (r)
			return r;
	}

	return 0;
}

