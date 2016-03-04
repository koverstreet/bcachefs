
#include "bcache.h"
#include "btree_update.h"
#include "buckets.h"
#include "clock.h"
#include "error.h"
#include "fs.h"
#include "fs-io.h"
#include "inode.h"
#include "journal.h"
#include "io.h"
#include "keylist.h"

#include <linux/aio.h>
#include <linux/backing-dev.h>
#include <linux/falloc.h>
#include <linux/migrate.h>
#include <linux/mmu_context.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/uio.h>
#include <linux/writeback.h>

struct bio_set *bch_writepage_bioset;
struct bio_set *bch_dio_read_bioset;
struct bio_set *bch_dio_write_bioset;

/* i_size updates: */

/*
 * In memory i_size should never be < on disk i_size:
 */
static void bch_i_size_write(struct inode *inode, loff_t new_i_size)
{
	struct bch_inode_info *ei = to_bch_ei(inode);

	EBUG_ON(new_i_size < ei->i_size);
	i_size_write(inode, new_i_size);
}

static int inode_set_size(struct bch_inode_info *ei, struct bch_inode *bi,
			  void *p)
{
	loff_t *new_i_size = p;
	unsigned i_flags = le32_to_cpu(bi->i_flags);

	lockdep_assert_held(&ei->update_lock);

	bi->i_size = cpu_to_le64(*new_i_size);

	if (atomic_long_read(&ei->i_size_dirty_count))
		i_flags |= BCH_INODE_I_SIZE_DIRTY;
	else
		i_flags &= ~BCH_INODE_I_SIZE_DIRTY;

	bi->i_flags = cpu_to_le32(i_flags);;

	return 0;
}

static int __must_check bch_write_inode_size(struct cache_set *c,
					     struct bch_inode_info *ei,
					     loff_t new_size)
{
	return __bch_write_inode(c, ei, inode_set_size, &new_size);
}

static int inode_set_dirty(struct bch_inode_info *ei,
			   struct bch_inode *bi, void *p)
{
	bi->i_flags = cpu_to_le32(le32_to_cpu(bi->i_flags)|
				  BCH_INODE_I_SIZE_DIRTY);
	return 0;
}

static int check_make_i_size_dirty(struct bch_inode_info *ei, loff_t offset)
{
	bool need_set_dirty;
	unsigned seq;
	int ret = 0;

	do {
		seq = read_seqcount_begin(&ei->shadow_i_size_lock);
		need_set_dirty = offset > ei->i_size &&
			!(ei->i_flags & BCH_INODE_I_SIZE_DIRTY);
	} while (read_seqcount_retry(&ei->shadow_i_size_lock, seq));

	if (!need_set_dirty)
		return 0;

	mutex_lock(&ei->update_lock);

	/* recheck under lock.. */

	if (offset > ei->i_size &&
	    !(ei->i_flags & BCH_INODE_I_SIZE_DIRTY)) {
		struct cache_set *c = ei->vfs_inode.i_sb->s_fs_info;

		ret = __bch_write_inode(c, ei, inode_set_dirty, NULL);
	}

	mutex_unlock(&ei->update_lock);

	return ret;
}

static inline void i_size_dirty_put(struct bch_inode_info *ei)
{
	atomic_long_dec_bug(&ei->i_size_dirty_count);
}

static inline void i_size_dirty_get(struct bch_inode_info *ei)
{
	lockdep_assert_held(&ei->vfs_inode.i_rwsem);

	atomic_long_inc(&ei->i_size_dirty_count);
}

static void i_size_update_put(struct cache_set *c, struct bch_inode_info *ei,
			      unsigned idx, unsigned long count)
{
	struct i_size_update *u = &ei->i_size_updates.data[idx];
	loff_t new_i_size = -1;
	long r;

	if (!count)
		return;

	r = atomic_long_sub_return(count, &u->count);
	BUG_ON(r < 0);

	if (r)
		return;

	/*
	 * Flush i_size_updates entries in order - from the end of the fifo -
	 * if the entry at the end is finished (refcount has gone to 0):
	 */

	mutex_lock(&ei->update_lock);

	while (!fifo_empty(&ei->i_size_updates) &&
	       !atomic_long_read(&(u = &fifo_front(&ei->i_size_updates))->count)) {
		struct i_size_update t;

		i_size_dirty_put(ei);

		if (u->new_i_size != -1) {
			BUG_ON(u->new_i_size < ei->i_size);
			new_i_size = u->new_i_size;
		}

		fifo_pop(&ei->i_size_updates, t);
	}

	if (new_i_size != -1) {
		int ret = bch_write_inode_size(c, ei, new_i_size);

		ret = ret;
		/*
		 * XXX: need to pin the inode in memory if the inode update
		 * fails
		 */
	}

	mutex_unlock(&ei->update_lock);
}

static struct i_size_update *i_size_update_new(struct bch_inode_info *ei,
					       loff_t new_size)
{
	struct i_size_update *u;

	lockdep_assert_held(&ei->update_lock);

	if (fifo_empty(&ei->i_size_updates) ||
	    (test_bit(BCH_INODE_WANT_NEW_APPEND, &ei->flags) &&
	     !fifo_full(&ei->i_size_updates))) {
		clear_bit(BCH_INODE_WANT_NEW_APPEND, &ei->flags);
		fifo_push(&ei->i_size_updates,
			  (struct i_size_update) { 0 });

		u = &fifo_back(&ei->i_size_updates);
		atomic_long_set(&u->count, 0);
		i_size_dirty_get(ei);
	}

	u = &fifo_back(&ei->i_size_updates);
	u->new_i_size = new_size;

	return u;
}

/* page state: */

/* stored in page->private: */
struct bch_page_state {
	u8			idx;
};

#define SECTORS_CACHE	1024

static int reserve_sectors(struct cache_set *c, unsigned sectors)
{
	u64 sectors_to_get = SECTORS_CACHE + sectors;

	if (likely(atomic64_sub_return(sectors,
				       &c->sectors_reserved_cache) >= 0))
		return 0;

	atomic64_add(sectors_to_get, &c->sectors_reserved);

	if (likely(!cache_set_full(c))) {
		atomic64_add(sectors_to_get, &c->sectors_reserved_cache);
		return 0;
	}

	atomic64_sub_bug(sectors_to_get, &c->sectors_reserved);
	atomic64_add(sectors, &c->sectors_reserved_cache);
	return -ENOSPC;
}

/*
 * our page flags:
 *
 * allocated - page has space on disk reserved for it (c->sectors_reserved) -
 * -ENOSPC was checked then, shouldn't be checked later
 *
 * append - page is dirty from an append write, new i_size can't be written
 * until after page is written; ref held on ei->i_size_dirty_count
 */

#define PF_ANY(page, enforce)	page
PAGEFLAG(Allocated, private, PF_ANY)
TESTSCFLAG(Allocated, private, PF_ANY)

PAGEFLAG(Append, private_2, PF_ANY)
TESTSCFLAG(Append, private_2, PF_ANY)
#undef PF_ANY

static void bch_clear_page_bits(struct cache_set *c, struct bch_inode_info *ei,
				struct page *page)
{
	EBUG_ON(!PageLocked(page));

	if (PageAllocated(page)) {
		atomic64_sub_bug(PAGE_SECTORS, &c->sectors_reserved);
		ClearPageAllocated(page);
	}

	if (PageAppend(page)) {
		struct bch_page_state *s = (void *) &page->private;

		i_size_update_put(c, ei, s->idx, 1);
		ClearPageAppend(page);
	}
}

/* readpages/writepages: */

static int bch_bio_add_page(struct bio *bio, struct page *page)
{
	sector_t offset = (sector_t) page->index << (PAGE_SHIFT - 9);

	BUG_ON(!bio->bi_max_vecs);

	if (!bio->bi_vcnt)
		bio->bi_iter.bi_sector = offset;
	else if (bio_end_sector(bio) != offset ||
		 bio->bi_vcnt == bio->bi_max_vecs)
		return -1;

	bio->bi_io_vec[bio->bi_vcnt++] = (struct bio_vec) {
		.bv_page = page,
		.bv_len = PAGE_SIZE,
		.bv_offset = 0,
	};

	bio->bi_iter.bi_size += PAGE_SIZE;

	return 0;
}

static void bch_readpages_end_io(struct bio *bio)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;

		if (!bio->bi_error) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	}

	bio_put(bio);
}

static inline struct page *__readpage_next_page(struct address_space *mapping,
						struct list_head *pages,
						unsigned *nr_pages)
{
	struct page *page;
	int ret;

	while (*nr_pages) {
		page = list_entry(pages->prev, struct page, lru);
		prefetchw(&page->flags);
		list_del(&page->lru);

		ret = add_to_page_cache_lru(page, mapping, page->index, GFP_NOFS);

		/* if add_to_page_cache_lru() succeeded, page is locked: */
		put_page(page);

		if (!ret)
			return page;

		(*nr_pages)--;
	}

	return NULL;
}

#define for_each_readpage_page(_mapping, _pages, _nr_pages, _page)	\
	for (;								\
	     ((_page) = __readpage_next_page(_mapping, _pages, &(_nr_pages)));\
	     (_nr_pages)--)

int bch_readpages(struct file *file, struct address_space *mapping,
		  struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio = NULL;
	struct page *page;

	pr_debug("reading %u pages", nr_pages);

	for_each_readpage_page(mapping, pages, nr_pages, page) {
again:
		if (!bio) {
			bio = bio_alloc(GFP_NOFS,
					min_t(unsigned, nr_pages,
					      BIO_MAX_PAGES));

			bio->bi_end_io = bch_readpages_end_io;
		}

		if (bch_bio_add_page(bio, page)) {
			bch_read(c, bio, inode->i_ino);
			bio = NULL;
			goto again;
		}
	}

	if (bio)
		bch_read(c, bio, inode->i_ino);

	pr_debug("success");
	return 0;
}

int bch_readpage(struct file *file, struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio;

	bio = bio_alloc(GFP_NOFS, 1);
	bio_set_op_attrs(bio, REQ_OP_READ, REQ_SYNC);
	bio->bi_end_io = bch_readpages_end_io;

	bch_bio_add_page(bio, page);
	bch_read(c, bio, inode->i_ino);

	return 0;
}

struct bch_writepage {
	struct cache_set	*c;
	u64			inum;
	struct bch_writepage_io	*io;
};

static void bch_writepage_io_free(struct closure *cl)
{
	struct bch_writepage_io *io = container_of(cl,
					struct bch_writepage_io, cl);
	struct bio *bio = &io->bio.bio.bio;

	bio_put(bio);
}

static void bch_writepage_io_done(struct closure *cl)
{
	struct bch_writepage_io *io = container_of(cl,
					struct bch_writepage_io, cl);
	struct cache_set *c = io->op.c;
	struct bio *bio = &io->bio.bio.bio;
	struct bch_inode_info *ei = io->ei;
	struct bio_vec *bvec;
	unsigned i;

	atomic64_sub_bug(io->sectors_reserved, &c->sectors_reserved);

	for (i = 0; i < ARRAY_SIZE(io->i_size_update_count); i++)
		i_size_update_put(c, ei, i, io->i_size_update_count[i]);

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		BUG_ON(!PageWriteback(page));

		if (io->bio.bio.bio.bi_error) {
			SetPageError(page);
			if (page->mapping)
				set_bit(AS_EIO, &page->mapping->flags);
		}

		end_page_writeback(page);
	}

	closure_return_with_destructor(&io->cl, bch_writepage_io_free);
}

static void bch_writepage_do_io(struct bch_writepage_io *io)
{
	pr_debug("writing %u sectors to %llu:%llu",
		 bio_sectors(&io->bio.bio.bio),
		 io->op.insert_key.k.p.inode,
		 (u64) io->bio.bio.bio.bi_iter.bi_sector);

	closure_call(&io->op.cl, bch_write, NULL, &io->cl);
	continue_at(&io->cl, bch_writepage_io_done, io->op.c->wq);
}

/*
 * Get a bch_writepage_io and add @page to it - appending to an existing one if
 * possible, else allocating a new one:
 */
static void bch_writepage_io_alloc(struct bch_writepage *w,
				   struct bch_inode_info *ei,
				   struct page *page)
{
alloc_io:
	if (!w->io) {
		struct bio *bio = bio_alloc_bioset(GFP_NOFS, BIO_MAX_PAGES,
						   bch_writepage_bioset);
		w->io = container_of(bio, struct bch_writepage_io, bio.bio.bio);

		closure_init(&w->io->cl, NULL);
		w->io->ei		= ei;
		memset(w->io->i_size_update_count, 0,
		       sizeof(w->io->i_size_update_count));
		w->io->sectors_reserved	= 0;

		bch_write_op_init(&w->io->op, w->c, &w->io->bio, NULL,
				  bkey_to_s_c(&KEY(w->inum, 0, 0)),
				  NULL,
				  &ei->journal_seq, 0);
	}

	if (bch_bio_add_page(&w->io->bio.bio.bio, page)) {
		bch_writepage_do_io(w->io);
		w->io = NULL;
		goto alloc_io;
	}

	/*
	 * We shouldn't ever be handed pages for multiple inodes in a single
	 * pass - right?
	 */
	BUG_ON(ei != w->io->ei);
}

static int __bch_writepage(struct page *page, struct writeback_control *wbc,
			   void *data)
{
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct bch_writepage *w = data;
	unsigned offset;
	loff_t i_size = i_size_read(inode);
	pgoff_t end_index = i_size >> PAGE_SHIFT;

	/* Is the page fully inside i_size? */
	if (page->index < end_index)
		goto do_io;

	/* Is the page fully outside i_size? (truncate in progress) */
	offset = i_size & (PAGE_SIZE - 1);
	if (page->index > end_index || !offset) {
		unlock_page(page);
		return 0;
	}

	/*
	 * The page straddles i_size.  It must be zeroed out on each and every
	 * writepage invocation because it may be mmapped.  "A file is mapped
	 * in multiples of the page size.  For a file that is not a multiple of
	 * the  page size, the remaining memory is zeroed when mapped, and
	 * writes to that region are not written out to the file."
	 */
	zero_user_segment(page, offset, PAGE_SIZE);
do_io:
	if (check_make_i_size_dirty(ei, page_offset(page) + PAGE_SIZE)) {
		redirty_page_for_writepage(wbc, page);
		unlock_page(page);
		return 0;
	}

	bch_writepage_io_alloc(w, ei, page);

	if (wbc->sync_mode == WB_SYNC_ALL)
		w->io->bio.bio.bio.bi_opf |= WRITE_SYNC;

	/*
	 * Before unlocking the page, transfer refcounts to w->io:
	 */
	if (PageAppend(page)) {
		struct bch_page_state *s = (void *) &page->private;

		/*
		 * i_size won't get updated and this write's data made visible
		 * until the i_size_update this page points to completes - so
		 * tell the write path to start a new one:
		 */
		if (&ei->i_size_updates.data[s->idx] ==
		    &fifo_back(&ei->i_size_updates))
			set_bit(BCH_INODE_WANT_NEW_APPEND, &ei->flags);

		w->io->i_size_update_count[s->idx]++;
		ClearPageAppend(page);
	}

	if (PageAllocated(page)) {
		w->io->sectors_reserved += PAGE_SECTORS;
		ClearPageAllocated(page);
	}

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);

	return 0;
}

int bch_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	int ret;
	struct bch_writepage w = {
		.c	= mapping->host->i_sb->s_fs_info,
		.inum	= mapping->host->i_ino,
		.io	= NULL,
	};

	ret = write_cache_pages(mapping, wbc, __bch_writepage, &w);

	if (w.io)
		bch_writepage_do_io(w.io);

	return ret;
}

int bch_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	int ret;
	struct bch_writepage w = {
		.c = inode->i_sb->s_fs_info,
		.inum = inode->i_ino,
		.io = NULL,
	};

	ret = __bch_writepage(page, wbc, &w);
	if (ret)
		return ret;

	if (w.io)
		bch_writepage_do_io(w.io);

	return 0;
}

static void bch_read_single_page_end_io(struct bio *bio)
{
	complete(bio->bi_private);
}

static int bch_read_single_page(struct page *page,
				struct address_space *mapping)
{
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio;
	int ret = 0;
	DECLARE_COMPLETION_ONSTACK(done);

	bio = bio_alloc(GFP_NOFS, 1);
	bio_set_op_attrs(bio, REQ_OP_READ, REQ_SYNC);
	bio->bi_private = &done;
	bio->bi_end_io = bch_read_single_page_end_io;
	bch_bio_add_page(bio, page);

	bch_read(c, bio, inode->i_ino);
	wait_for_completion(&done);

	if (!ret)
		ret = bio->bi_error;
	bio_put(bio);

	if (ret < 0)
		return ret;

	SetPageUptodate(page);

	return 0;
}

int bch_write_begin(struct file *file, struct address_space *mapping,
		    loff_t pos, unsigned len, unsigned flags,
		    struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	pgoff_t index = pos >> PAGE_SHIFT;
	unsigned offset = pos & (PAGE_SIZE - 1);
	struct page *page;
	int ret = 0;

	BUG_ON(inode_unhashed(mapping->host));

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	if (!PageAllocated(page)) {
		if (reserve_sectors(c, PAGE_SECTORS)) {
			ret = -ENOSPC;
			goto err;
		}

		SetPageAllocated(page);
	}

	if (PageUptodate(page))
		goto out;

	/* If we're writing entire page, don't need to read it in first: */
	if (len == PAGE_SIZE)
		goto out;

	if (!offset && pos + len >= inode->i_size) {
		zero_user_segment(page, len, PAGE_SIZE);
		flush_dcache_page(page);
		goto out;
	}

	if (index > inode->i_size >> PAGE_SHIFT) {
		zero_user_segments(page, 0, offset, offset + len, PAGE_SIZE);
		flush_dcache_page(page);
		goto out;
	}

	ret = bch_read_single_page(page, mapping);
	if (ret)
		goto err;
out:
	*pagep = page;
	return ret;
err:
	unlock_page(page);
	put_page(page);
	page = NULL;
	goto out;
}

int bch_write_end(struct file *filp, struct address_space *mapping,
		  loff_t pos, unsigned len, unsigned copied,
		  struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;

	lockdep_assert_held(&inode->i_rwsem);

	if (unlikely(copied < len && !PageUptodate(page))) {
		/*
		 * The page needs to be read in, but that would destroy
		 * our partial write - simplest thing is to just force
		 * userspace to redo the write:
		 *
		 * userspace doesn't _have_ to redo the write, so clear
		 * PageAllocated:
		 */
		copied = 0;
		zero_user(page, 0, PAGE_SIZE);
		flush_dcache_page(page);
		bch_clear_page_bits(c, ei, page);
		goto out;
	}

	if (!PageUptodate(page))
		SetPageUptodate(page);
	if (!PageDirty(page))
		set_page_dirty(page);

	if (pos + copied > inode->i_size) {
		struct i_size_update *u;

		/*
		 * if page already has a ref on a i_size_update, even if it's an
		 * older one, leave it - they have to be flushed in order so
		 * that's just as good as taking a ref on a newer one, if we're
		 * adding a newer one now
		 *
		 * - if there's no current i_size_update, or if we want to
		 *   create a new one and there's room for a new one, create it
		 *
		 * - set current i_size_update's i_size to new i_size
		 *
		 * - if !PageAppend, take a ref on the current i_size_update
		 */

		/* XXX: locking */
		mutex_lock(&ei->update_lock);
		u = i_size_update_new(ei, pos + copied);

		if (!PageAppend(page)) {
			struct bch_page_state *s = (void *) &page->private;

			s->idx = u - ei->i_size_updates.data;
			atomic_long_inc(&u->count);

			SetPageAppend(page);
		}

		bch_i_size_write(inode, pos + copied);
		mutex_unlock(&ei->update_lock);
	}
out:
	unlock_page(page);
	put_page(page);

	return copied;
}

/* O_DIRECT */

static void bch_dio_read_complete(struct closure *cl)
{
	struct dio_read *dio = container_of(cl, struct dio_read, cl);

	dio->req->ki_complete(dio->req, dio->ret, 0);
	bio_put(&dio->bio);
}

static void bch_direct_IO_read_endio(struct bio *bio)
{
	struct dio_read *dio = bio->bi_private;

	if (bio->bi_error)
		dio->ret = bio->bi_error;

	closure_put(&dio->cl);
	bio_check_pages_dirty(bio);	/* transfers ownership */
}

static int bch_direct_IO_read(struct cache_set *c, struct kiocb *req,
			      struct file *file, struct inode *inode,
			      struct iov_iter *iter, loff_t offset)
{
	struct dio_read *dio;
	struct bio *bio;
	unsigned long inum = inode->i_ino;
	ssize_t ret = 0;
	size_t pages = iov_iter_npages(iter, BIO_MAX_PAGES);
	bool sync = is_sync_kiocb(req);
	loff_t i_size;

	bio = bio_alloc_bioset(GFP_KERNEL, pages, bch_dio_read_bioset);
	bio_get(bio);

	dio = container_of(bio, struct dio_read, bio);
	closure_init(&dio->cl, NULL);

	/*
	 * this is a _really_ horrible hack just to avoid an atomic sub at the
	 * end:
	 */
	if (!sync) {
		set_closure_fn(&dio->cl, bch_dio_read_complete, NULL);
		atomic_set(&dio->cl.remaining,
			   CLOSURE_REMAINING_INITIALIZER -
			   CLOSURE_RUNNING +
			   CLOSURE_DESTRUCTOR);
	} else {
		atomic_set(&dio->cl.remaining,
			   CLOSURE_REMAINING_INITIALIZER + 1);
	}

	dio->req	= req;
	dio->ret	= iter->count;

	i_size = i_size_read(inode);
	if (offset + dio->ret > i_size) {
		dio->ret = max_t(loff_t, 0, i_size - offset);
		iter->count = round_up(dio->ret, PAGE_SIZE);
	}

	if (!dio->ret) {
		closure_put(&dio->cl);
		goto out;
	}

	goto start;
	while (iter->count) {
		pages = iov_iter_npages(iter, BIO_MAX_PAGES);
		bio = bio_alloc(GFP_KERNEL, pages);
start:
		bio->bi_iter.bi_sector	= offset >> 9;
		bio->bi_end_io		= bch_direct_IO_read_endio;
		bio->bi_private		= dio;

		ret = bio_get_user_pages(bio, iter, 1);
		if (ret < 0) {
			/* XXX: fault inject this path */
			bio->bi_error = ret;
			bio_endio(bio);
			break;
		}

		offset += bio->bi_iter.bi_size;
		bio_set_pages_dirty(bio);

		if (iter->count)
			closure_get(&dio->cl);

		bch_read(c, bio, inum);
	}
out:
	if (sync) {
		closure_sync(&dio->cl);
		closure_debug_destroy(&dio->cl);
		ret = dio->ret;
		bio_put(&dio->bio);
		return ret;
	} else {
		return -EIOCBQUEUED;
	}
}

static void __bch_dio_write_complete(struct dio_write *dio)
{
	inode_dio_end(dio->req->ki_filp->f_inode);

	if (dio->iovec && dio->iovec != dio->inline_vecs)
		kfree(dio->iovec);

	bio_put(&dio->bio.bio.bio);
}

static void bch_dio_write_complete(struct closure *cl)
{
	struct dio_write *dio = container_of(cl, struct dio_write, cl);
	struct kiocb *req = dio->req;
	long ret = dio->written ?: dio->error;

	__bch_dio_write_complete(dio);
	req->ki_complete(req, ret, 0);
}

static void bch_dio_write_done(struct dio_write *dio)
{
	struct bio_vec *bv;
	int i;

	dio->written += dio->iop.written << 9;

	if (dio->iop.error)
		dio->error = dio->iop.error;

	bio_for_each_segment_all(bv, &dio->bio.bio.bio, i)
		put_page(bv->bv_page);

	if (dio->iter.count)
		bio_reset(&dio->bio.bio.bio);
}

static void bch_do_direct_IO_write(struct dio_write *dio, bool sync)
{
	struct file *file = dio->req->ki_filp;
	struct inode *inode = file->f_inode;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio = &dio->bio.bio.bio;
	unsigned flags = BCH_WRITE_CHECK_ENOSPC;
	int ret;

	if (file->f_flags & O_DSYNC || IS_SYNC(file->f_mapping->host))
		flags |= BCH_WRITE_FLUSH;

	while (dio->iter.count) {
		bio->bi_iter.bi_sector = (dio->offset + dio->written) >> 9;

		ret = bio_get_user_pages(bio, &dio->iter, 0);
		if (ret < 0) {
			dio->error = ret;
			break;
		}

		bch_write_op_init(&dio->iop, c, &dio->bio, NULL,
				  bkey_to_s_c(&KEY(inode->i_ino,
						   bio_end_sector(bio),
						   bio_sectors(bio))),
				  NULL,
				  &ei->journal_seq, flags);

		task_io_account_write(bio->bi_iter.bi_size);

		closure_call(&dio->iop.cl, bch_write, NULL, &dio->cl);

		if (!sync)
			break;

		closure_sync(&dio->cl);
		bch_dio_write_done(dio);
	}
}

static void bch_dio_write_loop_async(struct closure *cl)
{
	struct dio_write *dio =
		container_of(cl, struct dio_write, cl);

	bch_dio_write_done(dio);

	if (dio->iter.count && !dio->error) {
		use_mm(dio->mm);
		bch_do_direct_IO_write(dio, false);
		unuse_mm(dio->mm);

		continue_at(&dio->cl,
			    bch_dio_write_loop_async,
			    dio->iter.count ? system_wq : NULL);
	} else {
#if 0
		closure_return_with_destructor(cl, bch_dio_write_complete);
#else
		closure_debug_destroy(cl);
		bch_dio_write_complete(cl);
#endif
	}
}

static int bch_direct_IO_write(struct cache_set *c, struct kiocb *req,
			       struct file *file, struct inode *inode,
			       struct iov_iter *iter, loff_t offset)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct dio_write *dio;
	struct bio *bio;
	size_t pages = iov_iter_npages(iter, BIO_MAX_PAGES);
	ssize_t ret;
	bool sync;

	lockdep_assert_held(&inode->i_rwsem);

	bio = bio_alloc_bioset(GFP_KERNEL, pages, bch_dio_write_bioset);

	dio = container_of(bio, struct dio_write, bio.bio.bio);
	dio->req	= req;
	dio->written	= 0;
	dio->error	= 0;
	dio->offset	= offset;
	dio->append	= false;
	dio->iovec	= NULL;
	dio->iter	= *iter;
	dio->mm		= current->mm;

	if (offset + iter->count > inode->i_size) {
		/*
		 * XXX: try and convert this to i_size_update_new(), and maybe
		 * make async O_DIRECT appends work
		 */

		dio->append = true;
		i_size_dirty_get(ei);
	}

	ret = check_make_i_size_dirty(ei, offset + iter->count);
	if (ret) {
		if (dio->append)
			i_size_dirty_put(ei);
		bio_put(bio);
		return ret;
	}

	closure_init(&dio->cl, NULL);

	inode_dio_begin(inode);

	/*
	 * appends are sync in order to do the i_size update under
	 * i_rwsem, after we know the write has completed successfully
	 */
	sync = is_sync_kiocb(req) || dio->append;

	bch_do_direct_IO_write(dio, sync);

	if (sync) {
		closure_debug_destroy(&dio->cl);
		ret = dio->written ?: dio->error;

		if (dio->append) {
			loff_t new_i_size = offset + dio->written;
			int ret2 = 0;

			if (dio->written &&
			    new_i_size > inode->i_size) {
				struct i_size_update *u;
				unsigned idx;

				mutex_lock(&ei->update_lock);

				bch_i_size_write(inode, new_i_size);

				fifo_for_each_entry_ptr(u, &ei->i_size_updates, idx) {
					if (u->new_i_size < new_i_size)
						u->new_i_size = -1;
					else
						BUG();
				}

				i_size_dirty_put(ei);
				ret2 = bch_write_inode_size(c, ei, new_i_size);

				mutex_unlock(&ei->update_lock);
			} else {
				i_size_dirty_put(ei);
			}
		}

		__bch_dio_write_complete(dio);
		return ret;
	} else {
		if (dio->iter.count) {
			if (dio->iter.nr_segs > ARRAY_SIZE(dio->inline_vecs)) {
				dio->iovec = kmalloc(dio->iter.nr_segs *
						     sizeof(struct iovec),
						     GFP_KERNEL);
				if (!dio->iovec)
					dio->error = -ENOMEM;
			} else {
				dio->iovec = dio->inline_vecs;
			}

			memcpy(dio->iovec,
			       dio->iter.iov,
			       dio->iter.nr_segs * sizeof(struct iovec));
			dio->iter.iov = dio->iovec;
		}

		continue_at_noreturn(&dio->cl,
				     bch_dio_write_loop_async,
				     dio->iter.count ? system_wq : NULL);
		return -EIOCBQUEUED;
	}
}

ssize_t bch_direct_IO(struct kiocb *req, struct iov_iter *iter)
{
	struct file *file = req->ki_filp;
	struct inode *inode = file->f_inode;
	struct cache_set *c = inode->i_sb->s_fs_info;

	if ((req->ki_pos|iter->count) & (block_bytes(c) - 1))
		return -EINVAL;

	return ((iov_iter_rw(iter) == WRITE)
		? bch_direct_IO_write
		: bch_direct_IO_read)(c, req, file, inode, iter, req->ki_pos);
}

static ssize_t
bch_direct_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct file	*file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	loff_t		pos = iocb->ki_pos;
	ssize_t		written;
	size_t		write_len;
	pgoff_t		end;

	write_len = iov_iter_count(from);
	end = (pos + write_len - 1) >> PAGE_SHIFT;

	written = filemap_write_and_wait_range(mapping, pos, pos + write_len - 1);
	if (written)
		goto out;

	/*
	 * After a write we want buffered reads to be sure to go to disk to get
	 * the new data.  We invalidate clean cached page from the region we're
	 * about to write.  We do this *before* the write so that we can return
	 * without clobbering -EIOCBQUEUED from ->direct_IO().
	 */
	if (mapping->nrpages) {
		written = invalidate_inode_pages2_range(mapping,
					pos >> PAGE_SHIFT, end);
		/*
		 * If a page can not be invalidated, return 0 to fall back
		 * to buffered write.
		 */
		if (written) {
			if (written == -EBUSY)
				return 0;
			goto out;
		}
	}

	written = mapping->a_ops->direct_IO(iocb, from);

	/*
	 * Finally, try again to invalidate clean pages which might have been
	 * cached by non-direct readahead, or faulted in by get_user_pages()
	 * if the source of the write was an mmap'ed region of the file
	 * we're writing.  Either one is a pretty crazy thing to do,
	 * so we don't support it 100%.  If this invalidation
	 * fails, tough, the write still worked...
	 *
	 * Augh: this makes no sense for async writes - the second invalidate
	 * has to come after the new data is visible. But, we can't just move it
	 * to the end of the dio write path - for async writes we don't have
	 * i_mutex held anymore, 
	 */
	if (mapping->nrpages) {
		invalidate_inode_pages2_range(mapping,
					      pos >> PAGE_SHIFT, end);
	}
out:
	return written;
}

static ssize_t __bch_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	struct inode	*inode = mapping->host;
	ssize_t	ret;

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);
	ret = file_remove_privs(file);
	if (ret)
		goto out;

	ret = file_update_time(file);
	if (ret)
		goto out;

	ret = iocb->ki_flags & IOCB_DIRECT
		? bch_direct_write(iocb, from)
		: generic_perform_write(file, from, iocb->ki_pos);

	if (likely(ret > 0))
		iocb->ki_pos += ret;
out:
	current->backing_dev_info = NULL;
	return ret;
}

ssize_t bch_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret > 0)
		ret = __bch_write_iter(iocb, from);
	inode_unlock(inode);

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);

	return ret;
}

int bch_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	struct address_space *mapping = inode->i_mapping;
	struct cache_set *c = inode->i_sb->s_fs_info;
	int ret = VM_FAULT_LOCKED;

	sb_start_pagefault(inode->i_sb);
	file_update_time(vma->vm_file);

	/*
	 * i_mutex is required for synchronizing with fcollapse(), O_DIRECT
	 * writes
	 */
	inode_lock(inode);

	lock_page(page);
	if (page->mapping != mapping ||
	    page_offset(page) > i_size_read(inode)) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}

	if (!PageAllocated(page)) {
		if (reserve_sectors(c, PAGE_SECTORS)) {
			unlock_page(page);
			ret = VM_FAULT_SIGBUS;
			goto out;
		}

		SetPageAllocated(page);
	}

	set_page_dirty(page);
	wait_for_stable_page(page);
out:
	inode_unlock(inode);
	sb_end_pagefault(inode->i_sb);
	return ret;
}

void bch_invalidatepage(struct page *page, unsigned int offset,
			unsigned int length)
{
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;

	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));

	if (offset || length < PAGE_SIZE)
		return;

	bch_clear_page_bits(c, ei, page);
}

int bch_releasepage(struct page *page, gfp_t gfp_mask)
{
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;

	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));

	bch_clear_page_bits(c, ei, page);

	if (PageDirty(page)) {
		ClearPageDirty(page);
		cancel_dirty_page(page);
	}

	return 1;
}

#ifdef CONFIG_MIGRATION
int bch_migrate_page(struct address_space *mapping, struct page *newpage,
		     struct page *page, enum migrate_mode mode)
{
	int ret;

	ret = migrate_page_move_mapping(mapping, newpage, page, NULL, mode, 0);
	if (ret != MIGRATEPAGE_SUCCESS)
		return ret;

	if (PageAllocated(page)) {
		ClearPageAllocated(page);
		SetPageAllocated(newpage);
	}

	if (PageAppend(page)) {
		ClearPageAppend(page);
		SetPageAppend(newpage);
	}

	migrate_page_copy(newpage, page);
	return MIGRATEPAGE_SUCCESS;
}
#endif

int bch_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	int ret;

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		return ret;

	inode_lock(inode);
	if (datasync && end <= ei->i_size)
		goto out;

	/*
	 * If there's still outstanding appends, we may have not yet written an
	 * i_size that exposes the data we just fsynced - however, we can
	 * advance the i_size on disk up to the end of what we just explicitly
	 * wrote:
	 */

	mutex_lock(&ei->update_lock);

	if (end > ei->i_size &&
	    ei->i_size < inode->i_size) {
		struct i_size_update *u;
		unsigned idx;
		loff_t new_i_size = min_t(u64, inode->i_size,
					  roundup(end, PAGE_SIZE));

		BUG_ON(fifo_empty(&ei->i_size_updates));
		BUG_ON(new_i_size < ei->i_size);

		/*
		 * There can still be a pending i_size update < the size we're
		 * writing, because it may have been shared with pages > the
		 * size we fsynced to:
		 */
		fifo_for_each_entry_ptr(u, &ei->i_size_updates, idx)
			if (u->new_i_size < new_i_size)
				u->new_i_size = -1;

		ret = bch_write_inode_size(c, ei, new_i_size);
	}

	mutex_unlock(&ei->update_lock);
out:
	inode_unlock(inode);

	if (ret)
		return ret;

	if (c->opts.journal_flush_disabled)
		return 0;

	return bch_journal_flush_seq(&c->journal, ei->journal_seq);
}

static int __bch_truncate_page(struct address_space *mapping,
			       pgoff_t index, loff_t start, loff_t end)
{
	struct inode *inode = mapping->host;
	unsigned start_offset = start & (PAGE_SIZE - 1);
	unsigned end_offset = ((end - 1) & (PAGE_SIZE - 1)) + 1;
	struct page *page;
	int ret = 0;

	/* Page boundary? Nothing to do */
	if (!((index == start >> PAGE_SHIFT && start_offset) ||
	      (index == end >> PAGE_SHIFT && end_offset != PAGE_SIZE)))
		return 0;

	/* Above i_size? */
	if (index << PAGE_SHIFT >= inode->i_size)
		return 0;

	page = find_lock_page(mapping, index);
	if (!page) {
		struct inode *inode = mapping->host;
		struct cache_set *c = inode->i_sb->s_fs_info;
		struct btree_iter iter;
		struct bkey_s_c k;

		/*
		 * XXX: we're doing two index lookups when we end up reading the
		 * page
		 */
		bch_btree_iter_init(&iter, c, BTREE_ID_EXTENTS,
				    POS(inode->i_ino,
					index << (PAGE_SHIFT - 9)));
		k = bch_btree_iter_peek(&iter);
		bch_btree_iter_unlock(&iter);

		if (!k.k ||
		    bkey_cmp(bkey_start_pos(k.k),
			     POS(inode->i_ino,
				 (index + 1) << (PAGE_SHIFT - 9))) >= 0)
			return 0;

		page = find_or_create_page(mapping,
					   index,
					   GFP_KERNEL);
		if (unlikely(!page)) {
			ret = -ENOMEM;
			goto out;
		}
	}

	if (!PageUptodate(page))
		if (bch_read_single_page(page, mapping)) {
			ret = -EIO;
			goto unlock;
		}

	if (index == start >> PAGE_SHIFT &&
	    index == end >> PAGE_SHIFT)
		zero_user_segment(page, start_offset, end_offset);
	else if (index == start >> PAGE_SHIFT)
		zero_user_segment(page, start_offset, PAGE_SIZE);
	else if (index == end >> PAGE_SHIFT)
		zero_user_segment(page, 0, end_offset);

	set_page_dirty(page);
unlock:
	unlock_page(page);
	put_page(page);
out:
	return ret;
}

static int bch_truncate_page(struct address_space *mapping, loff_t from)
{
	return __bch_truncate_page(mapping, from >> PAGE_SHIFT,
				   from, from + PAGE_SIZE);
}

int bch_truncate(struct inode *inode, struct iattr *iattr)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct i_size_update *u;
	bool shrink = iattr->ia_size <= inode->i_size;
	unsigned idx;
	int ret = 0;

	inode_dio_wait(inode);

	mutex_lock(&ei->update_lock);

	/*
	 * The new i_size could be bigger or smaller than the current on
	 * disk size (ei->i_size):
	 *
	 * If it's smaller (i.e. we actually are truncating), then in
	 * order to make the truncate appear atomic we have to write out
	 * the new i_size before discarding the data to be truncated.
	 *
	 * However, if the new i_size is bigger than the on disk i_size,
	 * then we _don't_ want to write the new i_size here - because
	 * if there are appends in flight, that would cause us to expose
	 * the range between the old and the new i_size before those
	 * appends have completed.
	 */

	/*
	 * First, cancel i_size_updates that extend past the new
	 * i_size, so the i_size we write here doesn't get
	 * stomped on:
	 */
	fifo_for_each_entry_ptr(u, &ei->i_size_updates, idx)
		if (u->new_i_size > iattr->ia_size)
			u->new_i_size = -1;

	set_bit(BCH_INODE_WANT_NEW_APPEND, &ei->flags);
	u = i_size_update_new(ei, iattr->ia_size);

	atomic_long_inc(&u->count);
	idx = u - ei->i_size_updates.data;

	if (iattr->ia_size < ei->i_size)
		ret = bch_write_inode_size(c, ei, iattr->ia_size);

	mutex_unlock(&ei->update_lock);

	/*
	 * XXX: if we error, we leak i_size_dirty count - and we can't
	 * just put it, because it actually is still dirty
	 */
	if (unlikely(ret))
		return ret;

	/*
	 * truncate_setsize() does the i_size_write(), can't use
	 * bch_i_size_write()
	 */
	EBUG_ON(iattr->ia_size < ei->i_size);
	truncate_setsize(inode, iattr->ia_size);

	/*
	 * There might be persistent reservations (from fallocate())
	 * above i_size, which bch_inode_truncate() will discard - we're
	 * only supposed to discard them if we're doing a real truncate
	 * here (new i_size < current i_size):
	 */
	if (shrink) {
		ret = bch_truncate_page(inode->i_mapping, iattr->ia_size);
		if (unlikely(ret))
			return ret;

		ret = bch_inode_truncate(c, inode->i_ino,
					 round_up(iattr->ia_size, PAGE_SIZE) >> 9,
					 NULL,
					 &ei->journal_seq);
		if (unlikely(ret))
			return ret;
	}

	setattr_copy(inode, iattr);

	inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	i_size_update_put(c, ei, idx, 1);
	return 0;
}

static long bch_fpunch(struct inode *inode, loff_t offset, loff_t len)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	u64 ino = inode->i_ino;
	u64 discard_start = round_up(offset, PAGE_SIZE) >> 9;
	u64 discard_end = round_down(offset + len, PAGE_SIZE) >> 9;
	int ret = 0;

	inode_lock(inode);
	ret = __bch_truncate_page(inode->i_mapping,
				  offset >> PAGE_SHIFT,
				  offset, offset + len);
	if (unlikely(ret))
		goto out;

	if (offset >> PAGE_SHIFT !=
	    (offset + len) >> PAGE_SHIFT) {
		ret = __bch_truncate_page(inode->i_mapping,
					  (offset + len) >> PAGE_SHIFT,
					  offset, offset + len);
		if (unlikely(ret))
			goto out;
	}

	truncate_pagecache_range(inode, offset, offset + len - 1);

	if (discard_start < discard_end)
		ret = bch_discard(c,
				  POS(ino, discard_start),
				  POS(ino, discard_end),
				  0, NULL, &ei->journal_seq);
out:
	inode_unlock(inode);

	return ret;
}

static long bch_fcollapse(struct inode *inode, loff_t offset, loff_t len)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct btree_iter src;
	struct btree_iter dst;
	BKEY_PADDED(k) copy;
	struct bkey_s_c k;
	struct i_size_update *u;
	loff_t new_size;
	unsigned idx;
	int ret;

	if ((offset | len) & (PAGE_SIZE - 1))
		return -EINVAL;

	bch_btree_iter_init_intent(&dst, c, BTREE_ID_EXTENTS,
				   POS(inode->i_ino, offset >> 9));
	/* position will be set from dst iter's position: */
	bch_btree_iter_init(&src, c, BTREE_ID_EXTENTS, POS_MIN);
	bch_btree_iter_link(&src, &dst);

	/*
	 * We need i_mutex to keep the page cache consistent with the extents
	 * btree, and the btree consistent with i_size - we don't need outside
	 * locking for the extents btree itself, because we're using linked
	 * iterators
	 *
	 * XXX: hmm, need to prevent reads adding things to the pagecache until
	 * we're done?
	 */
	inode_lock(inode);

	ret = -EINVAL;
	if (offset + len >= inode->i_size)
		goto err;

	if (inode->i_size < len)
		goto err;

	new_size = inode->i_size - len;

	inode_dio_wait(inode);

	do {
		ret = filemap_write_and_wait_range(inode->i_mapping,
						   offset, LLONG_MAX);
		if (ret)
			goto err;

		ret = invalidate_inode_pages2_range(inode->i_mapping,
					offset >> PAGE_SHIFT,
					ULONG_MAX);
	} while (ret == -EBUSY);

	if (ret)
		goto err;

	while (bkey_cmp(dst.pos,
			POS(inode->i_ino,
			    round_up(new_size, PAGE_SIZE) >> 9)) < 0) {
		bch_btree_iter_set_pos(&src,
			POS(dst.pos.inode, dst.pos.offset + (len >> 9)));

		/* Have to take intent locks before read locks: */
		ret = bch_btree_iter_traverse(&dst);
		if (ret)
			goto err_unwind;

		k = bch_btree_iter_peek_with_holes(&src);
		if (!k.k) {
			ret = -EIO;
			goto err_unwind;
		}

		bkey_reassemble(&copy.k, k);

		if (bkey_deleted(&copy.k.k))
			copy.k.k.type = KEY_TYPE_DISCARD;

		bch_cut_front(src.pos, &copy.k);
		copy.k.k.p.offset -= len >> 9;

		BUG_ON(bkey_cmp(dst.pos, bkey_start_pos(&copy.k.k)));

		ret = bch_btree_insert_at(&dst,
					  &keylist_single(&copy.k),
					  NULL, &ei->journal_seq,
					  BTREE_INSERT_ATOMIC|
					  BTREE_INSERT_NOFAIL);
		if (ret < 0 && ret != -EINTR)
			goto err_unwind;

		bch_btree_iter_unlock(&src);
	}

	bch_btree_iter_unlock(&src);
	bch_btree_iter_unlock(&dst);

	ret = bch_inode_truncate(c, inode->i_ino,
				 round_up(new_size, PAGE_SIZE) >> 9,
				 NULL, &ei->journal_seq);
	if (ret)
		goto err_unwind;

	mutex_lock(&ei->update_lock);

	/*
	 * Cancel i_size updates > new_size:
	 *
	 * Note: we're also cancelling i_size updates for appends < new_size, and
	 * writing the new i_size before they finish - would be better to use an
	 * i_size_update here like truncate, so we can sequence our i_size
	 * updates with outstanding appends and not have to cancel them:
	 */
	fifo_for_each_entry_ptr(u, &ei->i_size_updates, idx)
		u->new_i_size = -1;

	ret = bch_write_inode_size(c, ei, new_size);
	bch_i_size_write(inode, new_size);

	truncate_pagecache(inode, offset);

	mutex_unlock(&ei->update_lock);

	inode_unlock(inode);

	return ret;
err_unwind:
	BUG();
err:
	bch_btree_iter_unlock(&src);
	bch_btree_iter_unlock(&dst);
	inode_unlock(inode);
	return ret;
}

static long bch_fallocate(struct inode *inode, int mode,
				    loff_t offset, loff_t len)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct btree_iter iter;
	struct bkey_i reservation;
	struct bkey_s_c k;
	struct bpos end;
	loff_t block_start, block_end;
	loff_t new_size = offset + len;
	unsigned sectors;
	int ret;

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_EXTENTS, POS_MIN);

	inode_lock(inode);

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    new_size > inode->i_size) {
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			goto err;
	}

	if (mode & FALLOC_FL_ZERO_RANGE) {
		/* just for __bch_truncate_page(): */
		inode_dio_wait(inode);

		ret = __bch_truncate_page(inode->i_mapping,
					  offset >> PAGE_SHIFT,
					  offset, offset + len);

		if (!ret &&
		    offset >> PAGE_SHIFT !=
		    (offset + len) >> PAGE_SHIFT)
			ret = __bch_truncate_page(inode->i_mapping,
						  (offset + len) >> PAGE_SHIFT,
						  offset, offset + len);

		if (unlikely(ret))
			goto err;

		truncate_pagecache_range(inode, offset, offset + len - 1);

		block_start	= round_up(offset, PAGE_SIZE);
		block_end	= round_down(offset + len, PAGE_SIZE);
	} else {
		block_start	= round_down(offset, PAGE_SIZE);
		block_end	= round_up(offset + len, PAGE_SIZE);
	}

	bch_btree_iter_set_pos(&iter, POS(inode->i_ino, block_start >> 9));
	end = POS(inode->i_ino, block_end >> 9);

	while (bkey_cmp(iter.pos, end) < 0) {
		unsigned flags = 0;

		k = bch_btree_iter_peek_with_holes(&iter);
		if (!k.k) {
			ret = bch_btree_iter_unlock(&iter) ?: -EIO;
			goto err;
		}

		/* already reserved */
		if (k.k->type == BCH_RESERVATION) {
			bch_btree_iter_advance_pos(&iter);
			continue;
		}

		if (bkey_extent_is_data(k.k)) {
			if (!(mode & FALLOC_FL_ZERO_RANGE)) {
				bch_btree_iter_advance_pos(&iter);
				continue;
			}

			/* don't check for -ENOSPC if we're deleting data: */
			flags |= BTREE_INSERT_NOFAIL;
		}

		bkey_init(&reservation.k);
		reservation.k.type	= BCH_RESERVATION;
		reservation.k.p		= k.k->p;
		reservation.k.size	= k.k->size;

		bch_cut_front(iter.pos, &reservation);
		bch_cut_back(end, &reservation.k);

		sectors = reservation.k.size;

		ret = reserve_sectors(c, sectors);
		if (ret)
			goto err;

		ret = bch_btree_insert_at(&iter,
					  &keylist_single(&reservation),
					  NULL, &ei->journal_seq,
					  BTREE_INSERT_ATOMIC|flags);

		atomic64_sub_bug(sectors, &c->sectors_reserved);

		if (ret < 0 && ret != -EINTR)
			goto err;

	}
	bch_btree_iter_unlock(&iter);

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    new_size > inode->i_size) {
		struct i_size_update *u;
		unsigned idx;

		mutex_lock(&ei->update_lock);
		bch_i_size_write(inode, new_size);

		u = i_size_update_new(ei, new_size);
		idx = u - ei->i_size_updates.data;
		atomic_long_inc(&u->count);
		mutex_unlock(&ei->update_lock);

		i_size_update_put(c, ei, idx, 1);
	}

	inode_unlock(inode);

	return 0;
err:
	bch_btree_iter_unlock(&iter);
	inode_unlock(inode);
	return ret;
}

long bch_fallocate_dispatch(struct file *file, int mode,
			    loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);

	if (!(mode & ~(FALLOC_FL_KEEP_SIZE|FALLOC_FL_ZERO_RANGE)))
		return bch_fallocate(inode, mode, offset, len);

	if (mode == (FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE))
		return bch_fpunch(inode, offset, len);

	if (mode == FALLOC_FL_COLLAPSE_RANGE)
		return bch_fcollapse(inode, offset, len);

	return -EOPNOTSUPP;
}
