/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_SB_MEMBERS_TYPES_H
#define _BCACHEFS_SB_MEMBERS_TYPES_H

struct bch_member_cpu {
	u64			nbuckets;	/* device size */
	u64			nbuckets_minus_first;
	u16			first_bucket;   /* index of first bucket used */
	u16			bucket_size;	/* sectors */
	u16			group;
	u8			state;
	u8			discard;
	u8			data_allowed;
	u8			durability;
	u8			freespace_initialized;
	u8			valid;
};

#endif /* _BCACHEFS_SB_MEMBERS_H */
