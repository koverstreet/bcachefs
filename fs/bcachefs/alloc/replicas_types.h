/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_REPLICAS_TYPES_H
#define _BCACHEFS_REPLICAS_TYPES_H

/* unsized - bch_replicas_entry_v1 is variable length */
struct bch_replicas_entry_cpu {
	atomic_t			ref;
	struct bch_replicas_entry_v1	e;
};

struct bch_replicas_cpu {
	unsigned			nr;
	unsigned			entry_size;
	struct bch_replicas_entry_cpu	*entries;
};

union bch_replicas_padded {
	u8				bytes[struct_size_t(struct bch_replicas_entry_v1,
							    devs, BCH_BKEY_PTRS_MAX)];
	struct bch_replicas_entry_v1	e;
};

#endif /* _BCACHEFS_REPLICAS_TYPES_H */
