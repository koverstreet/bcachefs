/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_FS_IO_DIRECT_H
#define _BCACHEFS_FS_IO_DIRECT_H

#ifndef NO_BCACHEFS_FS
#include "data/read.h"
#include "vfs/io.h"

struct dio_read {
	struct closure			cl;
	struct kiocb			*req;
	long				ret;
	bool				should_dirty;
	struct bch_read_bio		rbio;
};

struct dio_write {
	struct kiocb			*req;
	struct address_space		*mapping;
	struct bch_inode_info		*inode;
	struct mm_struct		*mm;
	const struct iovec		*iov;
	unsigned			loop:1,
					extending:1,
					sync:1,
					flush:1;
	struct quota_res		quota_res;
	u64				written;

	struct iov_iter			iter;
	struct iovec			inline_vecs[2];

	/* must be last: */
	struct bch_write_op		op;
};

ssize_t bch2_direct_write(struct kiocb *, struct iov_iter *);
ssize_t bch2_read_iter(struct kiocb *, struct iov_iter *);
#endif

#endif /* _BCACHEFS_FS_IO_DIRECT_H */
