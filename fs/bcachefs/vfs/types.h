/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_VFS_TYPES_H
#define _BCACHEFS_VFS_TYPES_H

struct bch_fs_vfs {
#ifndef NO_BCACHEFS_FS
	struct list_head	inodes_list;
	struct mutex		inodes_lock;
	struct rhashtable	inodes_table;
	struct rhltable		inodes_by_inum_table;

	struct bio_set		writepage_bioset;
	struct bio_set		dio_write_bioset;
	struct bio_set		dio_read_bioset;
	struct bio_set		nocow_flush_bioset;
	struct workqueue_struct	*writeback_wq;
#endif
};

#endif /* _BCACHEFS_VFS_TYPES_H */
