/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_NODE_SCAN_TYPES_H
#define _BCACHEFS_BTREE_NODE_SCAN_TYPES_H

#include "util/darray.h"

typedef struct found_btree_node {
	bool			range_updated:1;
	u8			btree_id;
	u8			level;
	unsigned		sectors_written;
	u32			seq;
	u64			journal_seq;
	u64			cookie;

	struct bpos		min_key;
	struct bpos		max_key;

	unsigned		nr_ptrs;
	struct bch_extent_ptr	ptrs[BCH_REPLICAS_MAX];
} found_btree_node;

DEFINE_DARRAY(found_btree_node);

struct find_btree_nodes {
	int			ret;
	struct mutex		lock;
	darray_found_btree_node	nodes;
};

#endif /* _BCACHEFS_BTREE_NODE_SCAN_TYPES_H */
