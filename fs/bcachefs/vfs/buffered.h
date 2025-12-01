/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_FS_IO_BUFFERED_H
#define _BCACHEFS_FS_IO_BUFFERED_H

#ifndef NO_BCACHEFS_FS

#include <linux/version.h>

#include "data/write_types.h"

struct bch_writepage_io {
	struct bch_inode_info		*inode;

	/* must be last: */
	struct bch_write_op		op;
};

int bch2_read_single_folio(struct folio *, struct address_space *);
int bch2_read_folio(struct file *, struct folio *);

int bch2_writepages(struct address_space *, struct writeback_control *);
void bch2_readahead(struct readahead_control *);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)
int bch2_write_begin(const struct kiocb *, struct address_space *, loff_t pos,
		     unsigned len, struct folio **, void **);
int bch2_write_end(const struct kiocb *, struct address_space *, loff_t,
		   unsigned len, unsigned copied, struct folio *, void *);
#else
int bch2_write_begin(struct file *, struct address_space *, loff_t pos,
		     unsigned len, struct folio **, void **);
int bch2_write_end(struct file *, struct address_space *, loff_t,
		   unsigned len, unsigned copied, struct folio *, void *);
#endif

ssize_t bch2_write_iter(struct kiocb *, struct iov_iter *);
#endif

#endif /* _BCACHEFS_FS_IO_BUFFERED_H */
