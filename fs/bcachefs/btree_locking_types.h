/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_LOCKING_TYPES_H
#define _BCACHEFS_BTREE_LOCKING_TYPES_H

#include "six.h"

/* State used for the cycle detector */

/*
 * @trans wants to lock @b with type @type
 */
struct trans_waiting_for_lock {
	struct btree_trans		*trans;
	struct btree_bkey_cached_common	*node_want;
	enum six_lock_type		lock_want;

	/* for iterating over held locks :*/
	u8				path_idx;
	u8				level;
	u64				lock_start_time;
};

struct lock_graph {
	struct trans_waiting_for_lock	g[6];
	unsigned			nr;
};

#endif /* _BCACHEFS_BTREE_LOCKING_TYPES_H */
