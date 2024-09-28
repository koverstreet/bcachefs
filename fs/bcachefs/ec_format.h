/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_EC_FORMAT_H
#define _BCACHEFS_EC_FORMAT_H

struct bch_stripe {
	struct bch_val		v;
	__le16			sectors;
	__u8			algorithm;
	__u8			nr_blocks;
	__u8			nr_redundant;

	__u8			csum_granularity_bits;
	__u8			csum_type;

	/*
	 * XXX: targets should be 16 bits - fix this if we ever do a stripe_v2
	 *
	 * we can manage with this because this only needs to point to a
	 * disk label, not a target:
	 */
	__u8			disk_label;

	struct bch_extent_ptr	ptrs[];
} __packed __aligned(8);

#endif /* _BCACHEFS_EC_FORMAT_H */
