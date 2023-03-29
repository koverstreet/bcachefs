/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_SUBVOLUME_TYPES_H
#define _BCACHEFS_SUBVOLUME_TYPES_H

#include "darray.h"

typedef DARRAY(u32) snapshot_id_list;

struct snapshot_t {
	u32			parent;
	u32			children[2];
	u32			subvol; /* Nonzero only if a subvolume points to this node: */
	u32			equiv;
};

typedef struct {
	u32		subvol;
	u64		inum;
} subvol_inum;

#endif /* _BCACHEFS_SUBVOLUME_TYPES_H */
