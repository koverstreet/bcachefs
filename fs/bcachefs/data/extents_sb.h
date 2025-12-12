/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_EXTENTS_SB_H
#define _BCACHEFS_EXTENTS_SB_H

void bch2_sb_extent_type_u64s_to_cpu(struct bch_fs *);
int bch2_sb_extent_type_u64s_from_cpu(struct bch_fs *);

extern const struct bch_sb_field_ops bch_sb_field_ops_extent_type_u64s;

#endif /* _BCACHEFS_EXTENTS_SB_H */
