/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_VFS_TYPES_H
#define _BCACHEFS_VFS_TYPES_H

#include <linux/mempool.h>

#include "util/fast_list.h"

struct bch_fs_vfs {
	struct fast_list	inodes;
	struct rhashtable	inodes_table;
	struct rhltable		inodes_by_inum_table;

	struct bio_set		writepage_bioset;
	struct bio_set		dio_write_bioset;
	struct bio_set		dio_read_bioset;
	struct bio_set		nocow_flush_bioset;
	mempool_t		writepage_buf_pool;
	struct workqueue_struct	*writeback_wq;
};

#endif /* _BCACHEFS_VFS_TYPES_H */
