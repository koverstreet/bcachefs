#ifndef _BCACHE_FS_IO_H
#define _BCACHE_FS_IO_H

#include "buckets.h"
#include <linux/uio.h>

int bch_set_page_dirty(struct page *);

int bch_writepage(struct page *, struct writeback_control *);
int bch_readpage(struct file *, struct page *);

int bch_writepages(struct address_space *, struct writeback_control *);
int bch_readpages(struct file *, struct address_space *,
		  struct list_head *, unsigned);

int bch_write_begin(struct file *, struct address_space *, loff_t,
		    unsigned, unsigned, struct page **, void **);
int bch_write_end(struct file *, struct address_space *, loff_t,
		  unsigned, unsigned, struct page *, void *);

ssize_t bch_direct_IO(struct kiocb *, struct iov_iter *);

ssize_t bch_write_iter(struct kiocb *, struct iov_iter *);

int bch_fsync(struct file *, loff_t, loff_t, int);

int bch_truncate(struct inode *, struct iattr *);
long bch_fallocate_dispatch(struct file *, int, loff_t, loff_t);

loff_t bch_llseek(struct file *, loff_t, int);

int bch_page_mkwrite(struct vm_area_struct *, struct vm_fault *);
void bch_invalidatepage(struct page *, unsigned int, unsigned int);
int bch_releasepage(struct page *, gfp_t);
int bch_migrate_page(struct address_space *, struct page *,
		     struct page *, enum migrate_mode);

struct i_sectors_hook {
	struct btree_insert_hook	hook;
	s64				sectors;
#ifdef CONFIG_BCACHEFS_DEBUG
	struct bch_inode_info		*ei;
#endif
};

struct bch_writepage_io {
	struct closure		cl;

	struct bch_inode_info	*ei;
	unsigned long		i_size_update_count[I_SIZE_UPDATE_ENTRIES];

	struct bch_write_op	op;
	struct i_sectors_hook	i_sectors_hook;

	/* must come last: */
	struct bch_write_bio	bio;
};

extern struct bio_set *bch_writepage_bioset;

struct dio_write {
	struct closure		cl;
	struct kiocb		*req;
	long			written;
	long			error;
	loff_t			offset;
	bool			append;

	struct disk_reservation	res;

	struct iovec		*iovec;
	struct iovec		inline_vecs[UIO_FASTIOV];
	struct iov_iter		iter;

	struct mm_struct	*mm;

	struct bch_write_op	iop;
	struct i_sectors_hook	i_sectors_hook;

	/* must be last: */
	struct bch_write_bio	bio;
};

extern struct bio_set *bch_dio_write_bioset;

struct dio_read {
	struct closure		cl;
	struct kiocb		*req;
	long			ret;
	struct bio		bio;
};

extern struct bio_set *bch_dio_read_bioset;

#endif /* _BCACHE_FS_IO_H */
