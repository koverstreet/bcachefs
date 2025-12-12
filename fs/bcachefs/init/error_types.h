/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_INIT_ERROR_TYPES_H
#define _BCACHEFS_INIT_ERROR_TYPES_H

#include "sb/errors_types.h"

struct bch_fs_errors {
	struct list_head	msgs;
	struct mutex		msgs_lock;
	bool			msgs_alloc_err;

	bch_sb_errors_cpu	counts;
	struct mutex		counts_lock;
};

#endif /* _BCACHEFS_INIT_ERROR_TYPES_H */
