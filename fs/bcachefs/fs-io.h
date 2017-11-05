#ifndef _BCACHEFS_FS_IO_H
#define _BCACHEFS_FS_IO_H

#include "buckets.h"
#include <linux/uio.h>

int bch2_set_page_dirty(struct page *);

int bch2_writepage(struct page *, struct writeback_control *);
int bch2_readpage(struct file *, struct page *);

int bch2_writepages(struct address_space *, struct writeback_control *);
int bch2_readpages(struct file *, struct address_space *,
		   struct list_head *, unsigned);

int bch2_write_begin(struct file *, struct address_space *, loff_t,
		     unsigned, unsigned, struct page **, void **);
int bch2_write_end(struct file *, struct address_space *, loff_t,
		   unsigned, unsigned, struct page *, void *);

ssize_t bch2_direct_IO(struct kiocb *, struct iov_iter *);

ssize_t bch2_write_iter(struct kiocb *, struct iov_iter *);

int bch2_fsync(struct file *, loff_t, loff_t, int);

int bch2_truncate(struct bch_inode_info *, struct iattr *);
long bch2_fallocate_dispatch(struct file *, int, loff_t, loff_t);

loff_t bch2_llseek(struct file *, loff_t, int);

int bch2_page_mkwrite(struct vm_fault *);
void bch2_invalidatepage(struct page *, unsigned int, unsigned int);
int bch2_releasepage(struct page *, gfp_t);
int bch2_migrate_page(struct address_space *, struct page *,
		      struct page *, enum migrate_mode);

struct i_sectors_hook {
	struct extent_insert_hook	hook;
	s64				sectors;
	struct bch_inode_info		*inode;
};

struct bchfs_write_op {
	struct bch_inode_info		*inode;
	s64				sectors_added;
	bool				is_dio;
	u64				new_i_size;

	/* must be last: */
	struct bch_write_op		op;
};

struct bch_writepage_io {
	struct closure			cl;

	/* must be last: */
	struct bchfs_write_op		op;
};

extern struct bio_set *bch2_writepage_bioset;

struct dio_write {
	struct closure			cl;
	struct kiocb			*req;
	struct bch_fs			*c;
	long				written;
	long				error;
	loff_t				offset;

	struct disk_reservation		res;

	struct iovec			*iovec;
	struct iovec			inline_vecs[UIO_FASTIOV];
	struct iov_iter			iter;

	struct mm_struct		*mm;

	/* must be last: */
	struct bchfs_write_op		iop;
};

extern struct bio_set *bch2_dio_write_bioset;

struct dio_read {
	struct closure			cl;
	struct kiocb			*req;
	long				ret;
	struct bch_read_bio		rbio;
};

extern struct bio_set *bch2_dio_read_bioset;

#endif /* _BCACHEFS_FS_IO_H */
