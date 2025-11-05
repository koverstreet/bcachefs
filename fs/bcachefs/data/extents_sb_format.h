/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_EXTENTS_SB_FORMAT_H
#define _BCACHEFS_EXTENTS_SB_FORMAT_H

struct bch_sb_field_extent_type_u64s {
	struct bch_sb_field	field;
	u8			d[];
};

#endif /* _BCACHEFS_EXTENTS_SB_FORMAT_H */
