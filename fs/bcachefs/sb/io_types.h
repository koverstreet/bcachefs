/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_SB_IO_TYPES_H
#define _BCACHEFS_SB_IO_TYPES_H

/* Updated by bch2_sb_update():*/
struct bch_sb_cpu {
	__uuid_t	uuid;
	__uuid_t	user_uuid;

	u16		version;
	u16		version_incompat;
	u16		version_incompat_allowed;
	u16		version_min;
	u16		version_upgrade_complete;

	u8		nr_devices;
	u8		clean;
	bool		multi_device; /* true if we've ever had more than one device */

	u8		encryption_type;

	u64		time_base_lo;
	u32		time_base_hi;
	unsigned	time_units_per_sec;
	unsigned	nsec_per_time_unit;
	u64		features;
	u64		compat;
	u64		recovery_passes_required;
	unsigned long	errors_silent[BITS_TO_LONGS(BCH_FSCK_ERR_MAX)];
	u64		btrees_lost_data;
};

#endif /* _BCACHEFS_SB_IO_TYPES_H */
