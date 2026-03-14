/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_EXTENTS_TYPES_H
#define _BCACHEFS_EXTENTS_TYPES_H

#include "bcachefs_format.h"

struct bch_extent_crc_unpacked {
	u32			compressed_size;
	u32			uncompressed_size;
	u32			live_size;

	u8			csum_type;
	u8			compression_type;

	u16			offset;

	u16			nonce;

	struct bch_csum		csum;
};

struct extent_ptr_decoded {
	bool				has_ec;
	bool				do_ec_reconstruct;
	u8				crc_retry_nr;
	struct bch_extent_crc_unpacked	crc;
	struct bch_extent_ptr		ptr;
	struct bch_extent_stripe_ptr	ec;
};

struct bch_io_failures {
	u8			nr;
	struct bch_dev_io_failures {
		u8		dev;
		unsigned	csum_nr:7;
		s16		ec_errcode;
		s16		errcode;
	}			data[BCH_REPLICAS_MAX + 1];
};

#define BCH_READ_FLAGS()		\
	x(retry_if_stale)		\
	x(may_promote)			\
	x(user_mapped)			\
	x(soft_require_read_device)	\
	x(hard_require_read_device)	\
	x(last_fragment)		\
	x(must_bounce)			\
	x(must_clone)			\
	x(in_retry)

enum __bch_read_flags {
#define x(n)	__BCH_READ_##n,
	BCH_READ_FLAGS()
#undef x
};

enum bch_read_flags {
#define x(n)	BCH_READ_##n = BIT(__BCH_READ_##n),
	BCH_READ_FLAGS()
#undef x
};

#endif /* _BCACHEFS_EXTENTS_TYPES_H */
