#ifndef _BCACHEFS_EXTENTS_TYPES_H
#define _BCACHEFS_EXTENTS_TYPES_H

#include "bcachefs_format.h"

struct bch_extent_crc_unpacked {
	__u64			csum_type:4,
				compression_type:4,
				compressed_size:14,
				uncompressed_size:14,
				offset:14,
				nonce:14;

	struct bch_csum		csum;
};

struct extent_pick_ptr {
	struct bch_extent_ptr		ptr;
	struct bch_extent_crc_unpacked	crc;
	struct bch_dev			*ca;
};

#endif /* _BCACHEFS_EXTENTS_TYPES_H */
