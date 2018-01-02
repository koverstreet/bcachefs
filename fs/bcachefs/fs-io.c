#ifndef NO_BCACHEFS_FS

#include "bcachefs.h"
#include "btree_update.h"
#include "buckets.h"
#include "clock.h"
#include "error.h"
#include "fs.h"
#include "fs-io.h"
#include "fsck.h"
#include "inode.h"
#include "journal.h"
#include "io.h"
#include "keylist.h"

#include <linux/aio.h>
#include <linux/backing-dev.h>
#include <linux/falloc.h>
#include <linux/migrate.h>
#include <linux/mmu_context.h>
#include <linux/pagevec.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/uio.h>
#include <linux/writeback.h>

#include <trace/events/bcachefs.h>
#include <trace/events/writeback.h>

struct i_sectors_hook {
	struct extent_insert_hook	hook;
	struct bch_inode_info		*inode;
	s64				sectors;
	u64				new_i_size;
	unsigned			flags;
	unsigned			appending:1;
};

struct bchfs_write_op {
	struct bch_inode_info		*inode;
	s64				sectors_added;
	bool				is_dio;
	bool				unalloc;
	u64				new_i_size;

	/* must be last: */
	struct bch_write_op		op;
};

struct bch_writepage_io {
	struct closure			cl;

	/* must be last: */
	struct bchfs_write_op		op;
};

struct dio_write {
	struct closure			cl;
	struct kiocb			*req;
	struct bch_fs			*c;
	loff_t				offset;

	struct iovec			*iovec;
	struct iovec			inline_vecs[UIO_FASTIOV];
	struct iov_iter			iter;

	struct task_struct		*task;

	/* must be last: */
	struct bchfs_write_op		iop;
};

struct dio_read {
	struct closure			cl;
	struct kiocb			*req;
	long				ret;
	struct bch_read_bio		rbio;
};

/* pagecache_block must be held */
static int write_invalidate_inode_pages_range(struct address_space *mapping,
					      loff_t start, loff_t end)
{
	int ret;

	/*
	 * XXX: the way this is currently implemented, we can spin if a process
	 * is continually redirtying a specific page
	 */
	do {
		if (!mapping->nrpages &&
		    !mapping->nrexceptional)
			return 0;

		ret = filemap_write_and_wait_range(mapping, start, end);
		if (ret)
			break;

		if (!mapping->nrpages)
			return 0;

		ret = invalidate_inode_pages2_range(mapping,
				start >> PAGE_SHIFT,
				end >> PAGE_SHIFT);
	} while (ret == -EBUSY);

	return ret;
}

/* i_size updates: */

static int inode_set_size(struct bch_inode_info *inode,
			  struct bch_inode_unpacked *bi,
			  void *p)
{
	loff_t *new_i_size = p;

	lockdep_assert_held(&inode->ei_update_lock);

	bi->bi_size = *new_i_size;
	return 0;
}

static int __must_check bch2_write_inode_size(struct bch_fs *c,
					      struct bch_inode_info *inode,
					      loff_t new_size)
{
	return __bch2_write_inode(c, inode, inode_set_size, &new_size);
}

static void __i_sectors_acct(struct bch_fs *c, struct bch_inode_info *inode, int sectors)
{
	inode->v.i_blocks += sectors;
}

static void i_sectors_acct(struct bch_fs *c, struct bch_inode_info *inode, int sectors)
{
	mutex_lock(&inode->ei_update_lock);
	__i_sectors_acct(c, inode, sectors);
	mutex_unlock(&inode->ei_update_lock);
}

/* i_sectors accounting: */

static enum btree_insert_ret
i_sectors_hook_fn(struct extent_insert_hook *hook,
		  struct bpos committed_pos,
		  struct bpos next_pos,
		  struct bkey_s_c k,
		  const struct bkey_i *insert)
{
	struct i_sectors_hook *h = container_of(hook,
				struct i_sectors_hook, hook);
	s64 sectors = next_pos.offset - committed_pos.offset;
	int sign = bkey_extent_is_allocation(&insert->k) -
		(k.k && bkey_extent_is_allocation(k.k));

	EBUG_ON(!(h->inode->ei_inode.bi_flags & BCH_INODE_I_SECTORS_DIRTY));

	h->sectors += sectors * sign;

	return BTREE_INSERT_OK;
}

static int i_sectors_dirty_finish_fn(struct bch_inode_info *inode,
				     struct bch_inode_unpacked *bi,
				     void *p)
{
	struct i_sectors_hook *h = p;

	if (h->new_i_size != U64_MAX &&
	    (!h->appending ||
	     h->new_i_size > bi->bi_size))
		bi->bi_size = h->new_i_size;
	bi->bi_sectors	+= h->sectors;
	bi->bi_flags	&= ~h->flags;
	return 0;
}

static int i_sectors_dirty_finish(struct bch_fs *c, struct i_sectors_hook *h)
{
	int ret;

	mutex_lock(&h->inode->ei_update_lock);
	if (h->new_i_size != U64_MAX)
		i_size_write(&h->inode->v, h->new_i_size);

	__i_sectors_acct(c, h->inode, h->sectors);

	ret = __bch2_write_inode(c, h->inode, i_sectors_dirty_finish_fn, h);
	mutex_unlock(&h->inode->ei_update_lock);

	h->sectors = 0;

	return ret;
}

static int i_sectors_dirty_start_fn(struct bch_inode_info *inode,
				    struct bch_inode_unpacked *bi, void *p)
{
	struct i_sectors_hook *h = p;

	if (h->flags & BCH_INODE_I_SIZE_DIRTY)
		bi->bi_size = h->new_i_size;

	bi->bi_flags |= h->flags;
	return 0;
}

static int i_sectors_dirty_start(struct bch_fs *c, struct i_sectors_hook *h)
{
	int ret;

	mutex_lock(&h->inode->ei_update_lock);
	ret = __bch2_write_inode(c, h->inode, i_sectors_dirty_start_fn, h);
	mutex_unlock(&h->inode->ei_update_lock);

	return ret;
}

static inline struct i_sectors_hook
i_sectors_hook_init(struct bch_inode_info *inode, unsigned flags)
{
	return (struct i_sectors_hook) {
		.hook.fn	= i_sectors_hook_fn,
		.inode		= inode,
		.sectors	= 0,
		.new_i_size	= U64_MAX,
		.flags		= flags|BCH_INODE_I_SECTORS_DIRTY,
	};
}

/* normal i_size/i_sectors update machinery: */

struct bchfs_extent_trans_hook {
	struct bchfs_write_op		*op;
	struct extent_insert_hook	hook;

	struct bch_inode_unpacked	inode_u;
	struct bkey_inode_buf		inode_p;

	bool				need_inode_update;
};

static enum btree_insert_ret
bchfs_extent_update_hook(struct extent_insert_hook *hook,
			 struct bpos committed_pos,
			 struct bpos next_pos,
			 struct bkey_s_c k,
			 const struct bkey_i *insert)
{
	struct bchfs_extent_trans_hook *h = container_of(hook,
				struct bchfs_extent_trans_hook, hook);
	struct bch_inode_info *inode = h->op->inode;
	int sign = bkey_extent_is_allocation(&insert->k) -
		(k.k && bkey_extent_is_allocation(k.k));
	s64 sectors = (s64) (next_pos.offset - committed_pos.offset) * sign;
	u64 offset = min(next_pos.offset << 9, h->op->new_i_size);
	bool do_pack = false;

	if (h->op->unalloc &&
	    !bch2_extent_is_fully_allocated(k))
		return BTREE_INSERT_ENOSPC;

	BUG_ON((next_pos.offset << 9) > round_up(offset, PAGE_SIZE));

	/* XXX: inode->i_size locking */
	if (offset > inode->ei_inode.bi_size) {
		if (!h->need_inode_update) {
			h->need_inode_update = true;
			return BTREE_INSERT_NEED_TRAVERSE;
		}

		BUG_ON(h->inode_u.bi_flags & BCH_INODE_I_SIZE_DIRTY);

		h->inode_u.bi_size = offset;
		do_pack = true;

		inode->ei_inode.bi_size = offset;

		if (h->op->is_dio)
			i_size_write(&inode->v, offset);
	}

	if (sectors) {
		if (!h->need_inode_update) {
			h->need_inode_update = true;
			return BTREE_INSERT_NEED_TRAVERSE;
		}

		h->inode_u.bi_sectors += sectors;
		do_pack = true;

		h->op->sectors_added += sectors;
	}

	if (do_pack)
		bch2_inode_pack(&h->inode_p, &h->inode_u);

	return BTREE_INSERT_OK;
}

static int bchfs_write_index_update(struct bch_write_op *wop)
{
	struct bchfs_write_op *op = container_of(wop,
				struct bchfs_write_op, op);
	struct keylist *keys = &op->op.insert_keys;
	struct btree_iter extent_iter, inode_iter;
	struct bchfs_extent_trans_hook hook;
	struct bkey_i *k = bch2_keylist_front(keys);
	s64 orig_sectors_added = op->sectors_added;
	int ret;

	BUG_ON(k->k.p.inode != op->inode->v.i_ino);

	bch2_btree_iter_init(&extent_iter, wop->c, BTREE_ID_EXTENTS,
			     bkey_start_pos(&bch2_keylist_front(keys)->k),
			     BTREE_ITER_INTENT);
	bch2_btree_iter_init(&inode_iter, wop->c, BTREE_ID_INODES,
			     POS(extent_iter.pos.inode, 0),
			     BTREE_ITER_INTENT);

	hook.op			= op;
	hook.hook.fn		= bchfs_extent_update_hook;
	hook.need_inode_update	= false;

	do {
		ret = bch2_btree_iter_traverse(&extent_iter);
		if (ret)
			goto err;

		/* XXX: inode->i_size locking */
		k = bch2_keylist_front(keys);
		if (min(k->k.p.offset << 9, op->new_i_size) >
		    op->inode->ei_inode.bi_size)
			hook.need_inode_update = true;

		if (hook.need_inode_update) {
			struct bkey_s_c inode;

			if (!btree_iter_linked(&inode_iter))
				bch2_btree_iter_link(&extent_iter, &inode_iter);

			inode = bch2_btree_iter_peek_with_holes(&inode_iter);
			if ((ret = btree_iter_err(inode)))
				goto err;

			if (WARN_ONCE(inode.k->type != BCH_INODE_FS,
				      "inode %llu not found when updating",
				      extent_iter.pos.inode)) {
				ret = -ENOENT;
				break;
			}

			if (WARN_ONCE(bkey_bytes(inode.k) >
				      sizeof(hook.inode_p),
				      "inode %llu too big (%zu bytes, buf %zu)",
				      extent_iter.pos.inode,
				      bkey_bytes(inode.k),
				      sizeof(hook.inode_p))) {
				ret = -ENOENT;
				break;
			}

			bkey_reassemble(&hook.inode_p.inode.k_i, inode);
			ret = bch2_inode_unpack(bkey_s_c_to_inode(inode),
					       &hook.inode_u);
			if (WARN_ONCE(ret,
				      "error %i unpacking inode %llu",
				      ret, extent_iter.pos.inode)) {
				ret = -ENOENT;
				break;
			}

			ret = bch2_btree_insert_at(wop->c, &wop->res,
					&hook.hook, op_journal_seq(wop),
					BTREE_INSERT_NOFAIL|BTREE_INSERT_ATOMIC,
					BTREE_INSERT_ENTRY(&extent_iter, k),
					BTREE_INSERT_ENTRY_EXTRA_RES(&inode_iter,
							&hook.inode_p.inode.k_i, 2));
		} else {
			ret = bch2_btree_insert_at(wop->c, &wop->res,
					&hook.hook, op_journal_seq(wop),
					BTREE_INSERT_NOFAIL|BTREE_INSERT_ATOMIC,
					BTREE_INSERT_ENTRY(&extent_iter, k));
		}

		BUG_ON(bkey_cmp(extent_iter.pos, bkey_start_pos(&k->k)));
		BUG_ON(!ret != !k->k.size);
err:
		if (ret == -EINTR)
			continue;
		if (ret)
			break;

		BUG_ON(bkey_cmp(extent_iter.pos, k->k.p) < 0);
		bch2_keylist_pop_front(keys);
	} while (!bch2_keylist_empty(keys));

	bch2_btree_iter_unlock(&extent_iter);
	bch2_btree_iter_unlock(&inode_iter);

	if (op->is_dio)
		i_sectors_acct(wop->c, op->inode,
			       op->sectors_added - orig_sectors_added);

	return ret;
}

static inline void bch2_fswrite_op_init(struct bchfs_write_op *op,
					struct bch_fs *c,
					struct bch_inode_info *inode,
					struct bch_io_opts opts,
					bool is_dio)
{
	op->inode		= inode;
	op->sectors_added	= 0;
	op->is_dio		= is_dio;
	op->unalloc		= false;
	op->new_i_size		= U64_MAX;

	bch2_write_op_init(&op->op, c);
	op->op.csum_type	= bch2_data_checksum_type(c, opts.data_checksum);
	op->op.compression_type	= bch2_compression_opt_to_type(opts.compression);
	op->op.devs		= c->fastest_devs;
	op->op.index_update_fn	= bchfs_write_index_update;
	op_journal_seq_set(&op->op, &inode->ei_journal_seq);
}

static inline struct bch_io_opts io_opts(struct bch_fs *c, struct bch_inode_info *inode)
{
	struct bch_io_opts opts = bch2_opts_to_inode_opts(c->opts);

	bch2_io_opts_apply(&opts, bch2_inode_opts_get(&inode->ei_inode));
	return opts;
}

/* page state: */

/* stored in page->private: */

/*
 * bch_page_state has to (unfortunately) be manipulated with cmpxchg - we could
 * almost protected it with the page lock, except that bch2_writepage_io_done has
 * to update the sector counts (and from interrupt/bottom half context).
 */
struct bch_page_state {
union { struct {
	/*
	 * page is _fully_ written on disk, and not compressed - which means to
	 * write this page we don't have to reserve space (the new write will
	 * never take up more space on disk than what it's overwriting)
	 */
	unsigned allocated:1;

	/* Owns PAGE_SECTORS sized reservation: */
	unsigned		reserved:1;
	unsigned		nr_replicas:4;

	/*
	 * Number of sectors on disk - for i_blocks
	 * Uncompressed size, not compressed size:
	 */
	u8			sectors;
	u8			dirty_sectors;
};
	/* for cmpxchg: */
	unsigned long		v;
};
};

#define page_state_cmpxchg(_ptr, _new, _expr)				\
({									\
	unsigned long _v = READ_ONCE((_ptr)->v);			\
	struct bch_page_state _old;					\
									\
	do {								\
		_old.v = _new.v = _v;					\
		_expr;							\
									\
		EBUG_ON(_new.sectors + _new.dirty_sectors > PAGE_SECTORS);\
	} while (_old.v != _new.v &&					\
		 (_v = cmpxchg(&(_ptr)->v, _old.v, _new.v)) != _old.v);	\
									\
	_old;								\
})

static inline struct bch_page_state *page_state(struct page *page)
{
	struct bch_page_state *s = (void *) &page->private;

	BUILD_BUG_ON(sizeof(*s) > sizeof(page->private));

	if (!PagePrivate(page))
		SetPagePrivate(page);

	return s;
}

static void bch2_put_page_reservation(struct bch_fs *c, struct page *page)
{
	struct disk_reservation res = { .sectors = PAGE_SECTORS };
	struct bch_page_state s;

	s = page_state_cmpxchg(page_state(page), s, {
		if (!s.reserved)
			return;
		s.reserved = 0;
	});

	bch2_disk_reservation_put(c, &res);
}

static int bch2_get_page_reservation(struct bch_fs *c, struct page *page,
				    bool check_enospc)
{
	struct bch_page_state *s = page_state(page), new;
	struct disk_reservation res;
	int ret = 0;

	BUG_ON(s->allocated && s->sectors != PAGE_SECTORS);

	if (s->allocated || s->reserved)
		return 0;

	ret = bch2_disk_reservation_get(c, &res, PAGE_SECTORS, !check_enospc
				       ? BCH_DISK_RESERVATION_NOFAIL : 0);
	if (ret)
		return ret;

	page_state_cmpxchg(s, new, {
		if (new.reserved) {
			bch2_disk_reservation_put(c, &res);
			return 0;
		}
		new.reserved	= 1;
		new.nr_replicas	= res.nr_replicas;
	});

	return 0;
}

static void bch2_clear_page_bits(struct page *page)
{
	struct bch_inode_info *inode = to_bch_ei(page->mapping->host);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct disk_reservation res = { .sectors = PAGE_SECTORS };
	struct bch_page_state s;

	if (!PagePrivate(page))
		return;

	s = xchg(page_state(page), (struct bch_page_state) { .v = 0 });
	ClearPagePrivate(page);

	if (s.dirty_sectors)
		i_sectors_acct(c, inode, -s.dirty_sectors);

	if (s.reserved)
		bch2_disk_reservation_put(c, &res);
}

int bch2_set_page_dirty(struct page *page)
{
	struct bch_inode_info *inode = to_bch_ei(page->mapping->host);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct bch_page_state old, new;

	old = page_state_cmpxchg(page_state(page), new,
		new.dirty_sectors = PAGE_SECTORS - new.sectors;
	);

	if (old.dirty_sectors != new.dirty_sectors)
		i_sectors_acct(c, inode, new.dirty_sectors - old.dirty_sectors);

	return __set_page_dirty_nobuffers(page);
}

/* readpages/writepages: */

static bool bio_can_add_page_contig(struct bio *bio, struct page *page)
{
	sector_t offset = (sector_t) page->index << PAGE_SECTOR_SHIFT;

	return bio->bi_vcnt < bio->bi_max_vecs &&
		bio_end_sector(bio) == offset;
}

static void __bio_add_page(struct bio *bio, struct page *page)
{
	bio->bi_io_vec[bio->bi_vcnt++] = (struct bio_vec) {
		.bv_page = page,
		.bv_len = PAGE_SIZE,
		.bv_offset = 0,
	};

	bio->bi_iter.bi_size += PAGE_SIZE;
}

static int bio_add_page_contig(struct bio *bio, struct page *page)
{
	sector_t offset = (sector_t) page->index << PAGE_SECTOR_SHIFT;

	BUG_ON(!bio->bi_max_vecs);

	if (!bio->bi_vcnt)
		bio->bi_iter.bi_sector = offset;
	else if (!bio_can_add_page_contig(bio, page))
		return -1;

	__bio_add_page(bio, page);
	return 0;
}

static void bch2_readpages_end_io(struct bio *bio)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;

		if (!bio->bi_status) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	}

	bio_put(bio);
}

struct readpages_iter {
	struct address_space	*mapping;
	struct list_head	pages;
	unsigned		nr_pages;
};

static int readpage_add_page(struct readpages_iter *iter, struct page *page)
{
	struct bch_page_state *s = page_state(page);
	int ret;

	BUG_ON(s->reserved);
	s->allocated = 1;
	s->sectors = 0;

	prefetchw(&page->flags);
	ret = add_to_page_cache_lru(page, iter->mapping,
				    page->index, GFP_NOFS);
	put_page(page);
	return ret;
}

static inline struct page *readpage_iter_next(struct readpages_iter *iter)
{
	while (iter->nr_pages) {
		struct page *page =
			list_last_entry(&iter->pages, struct page, lru);

		prefetchw(&page->flags);
		list_del(&page->lru);
		iter->nr_pages--;

		if (!readpage_add_page(iter, page))
			return page;
	}

	return NULL;
}

#define for_each_readpage_page(_iter, _page)				\
	for (;								\
	     ((_page) = __readpage_next_page(&(_iter)));)		\

static void bch2_mark_pages_unalloc(struct bio *bio)
{
	struct bvec_iter iter;
	struct bio_vec bv;

	bio_for_each_segment(bv, bio, iter)
		page_state(bv.bv_page)->allocated = 0;
}

static void bch2_add_page_sectors(struct bio *bio, struct bkey_s_c k)
{
	struct bvec_iter iter;
	struct bio_vec bv;

	bio_for_each_segment(bv, bio, iter) {
		struct bch_page_state *s = page_state(bv.bv_page);

		/* sectors in @k from the start of this page: */
		unsigned k_sectors = k.k->size - (iter.bi_sector - k.k->p.offset);

		unsigned page_sectors = min(bv.bv_len >> 9, k_sectors);

		if (!s->sectors)
			s->nr_replicas = bch2_extent_nr_dirty_ptrs(k);
		else
			s->nr_replicas = min_t(unsigned, s->nr_replicas,
					       bch2_extent_nr_dirty_ptrs(k));

		BUG_ON(s->sectors + page_sectors > PAGE_SECTORS);
		s->sectors += page_sectors;
	}
}

static void readpage_bio_extend(struct readpages_iter *iter,
				struct bio *bio, u64 offset,
				bool get_more)
{
	struct page *page;
	pgoff_t page_offset;
	int ret;

	while (bio_end_sector(bio) < offset &&
	       bio->bi_vcnt < bio->bi_max_vecs) {
		page_offset = bio_end_sector(bio) >> PAGE_SECTOR_SHIFT;

		if (iter->nr_pages) {
			page = list_last_entry(&iter->pages, struct page, lru);
			if (page->index != page_offset)
				break;

			list_del(&page->lru);
			iter->nr_pages--;
		} else if (get_more) {
			rcu_read_lock();
			page = radix_tree_lookup(&iter->mapping->page_tree, page_offset);
			rcu_read_unlock();

			if (page && !radix_tree_exceptional_entry(page))
				break;

			page = __page_cache_alloc(readahead_gfp_mask(iter->mapping));
			if (!page)
				break;

			page->index = page_offset;
			ClearPageReadahead(bio->bi_io_vec[bio->bi_vcnt - 1].bv_page);
		} else {
			break;
		}

		ret = readpage_add_page(iter, page);
		if (ret)
			break;

		__bio_add_page(bio, page);
	}

	if (!iter->nr_pages)
		SetPageReadahead(bio->bi_io_vec[bio->bi_vcnt - 1].bv_page);
}

static void bchfs_read(struct bch_fs *c, struct btree_iter *iter,
		       struct bch_read_bio *rbio, u64 inum,
		       struct readpages_iter *readpages_iter)
{
	struct bio *bio = &rbio->bio;
	int flags = BCH_READ_RETRY_IF_STALE|
		BCH_READ_MAY_PROMOTE;

	while (1) {
		struct extent_pick_ptr pick;
		BKEY_PADDED(k) tmp;
		struct bkey_s_c k;
		unsigned bytes;
		bool is_last;

		bch2_btree_iter_set_pos(iter, POS(inum, bio->bi_iter.bi_sector));

		k = bch2_btree_iter_peek_with_holes(iter);
		BUG_ON(!k.k);

		if (IS_ERR(k.k)) {
			int ret = bch2_btree_iter_unlock(iter);
			BUG_ON(!ret);
			bcache_io_error(c, bio, "btree IO error %i", ret);
			bio_endio(bio);
			return;
		}

		bkey_reassemble(&tmp.k, k);
		bch2_btree_iter_unlock(iter);
		k = bkey_i_to_s_c(&tmp.k);

		bch2_extent_pick_ptr(c, k, NULL, &pick);
		if (IS_ERR(pick.ca)) {
			bcache_io_error(c, bio, "no device to read from");
			bio_endio(bio);
			return;
		}

		if (readpages_iter)
			readpage_bio_extend(readpages_iter,
					    bio, k.k->p.offset,
					    pick.ca &&
					    (pick.crc.csum_type ||
					     pick.crc.compression_type));

		bytes = (min_t(u64, k.k->p.offset, bio_end_sector(bio)) -
			 bio->bi_iter.bi_sector) << 9;
		is_last = bytes == bio->bi_iter.bi_size;
		swap(bio->bi_iter.bi_size, bytes);

		if (bkey_extent_is_allocation(k.k))
			bch2_add_page_sectors(bio, k);

		if (!bch2_extent_is_fully_allocated(k))
			bch2_mark_pages_unalloc(bio);

		if (pick.ca) {
			if (!is_last) {
				bio_inc_remaining(&rbio->bio);
				flags |= BCH_READ_MUST_CLONE;
				trace_read_split(&rbio->bio);
			}

			bch2_read_extent(c, rbio, bkey_s_c_to_extent(k),
					 &pick, flags);
		} else {
			zero_fill_bio(bio);

			if (is_last)
				bio_endio(bio);
		}

		if (is_last)
			return;

		swap(bio->bi_iter.bi_size, bytes);
		bio_advance(bio, bytes);
	}
}

int bch2_readpages(struct file *file, struct address_space *mapping,
		   struct list_head *pages, unsigned nr_pages)
{
	struct bch_inode_info *inode = to_bch_ei(mapping->host);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct bch_io_opts opts = io_opts(c, inode);
	struct btree_iter iter;
	struct page *page;
	struct readpages_iter readpages_iter = {
		.mapping = mapping, .nr_pages = nr_pages
	};

	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN, 0);

	INIT_LIST_HEAD(&readpages_iter.pages);
	list_add(&readpages_iter.pages, pages);
	list_del_init(pages);

	if (current->pagecache_lock != &mapping->add_lock)
		pagecache_add_get(&mapping->add_lock);

	while ((page = readpage_iter_next(&readpages_iter))) {
		unsigned n = max_t(unsigned,
				   min_t(unsigned, readpages_iter.nr_pages + 1,
					 BIO_MAX_PAGES),
				   c->sb.encoded_extent_max >> PAGE_SECTOR_SHIFT);

		struct bch_read_bio *rbio =
			rbio_init(bio_alloc_bioset(GFP_NOFS, n, &c->bio_read),
				  opts);

		rbio->bio.bi_end_io = bch2_readpages_end_io;
		bio_add_page_contig(&rbio->bio, page);
		bchfs_read(c, &iter, rbio, inode->v.i_ino, &readpages_iter);
	}

	if (current->pagecache_lock != &mapping->add_lock)
		pagecache_add_put(&mapping->add_lock);

	return 0;
}

static void __bchfs_readpage(struct bch_fs *c, struct bch_read_bio *rbio,
			     u64 inum, struct page *page)
{
	struct btree_iter iter;

	/*
	 * Initialize page state:
	 * If a page is partly allocated and partly a hole, we want it to be
	 * marked BCH_PAGE_UNALLOCATED - so we initially mark all pages
	 * allocated and then mark them unallocated as we find holes:
	 *
	 * Note that the bio hasn't been split yet - it's the only bio that
	 * points to these pages. As we walk extents and split @bio, that
	 * necessarily be true, the splits won't necessarily be on page
	 * boundaries:
	 */
	struct bch_page_state *s = page_state(page);

	EBUG_ON(s->reserved);
	s->allocated = 1;
	s->sectors = 0;

	bio_set_op_attrs(&rbio->bio, REQ_OP_READ, REQ_SYNC);
	bio_add_page_contig(&rbio->bio, page);

	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN, 0);
	bchfs_read(c, &iter, rbio, inum, NULL);
}

int bch2_readpage(struct file *file, struct page *page)
{
	struct bch_inode_info *inode = to_bch_ei(page->mapping->host);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct bch_io_opts opts = io_opts(c, inode);
	struct bch_read_bio *rbio;

	rbio = rbio_init(bio_alloc_bioset(GFP_NOFS, 1, &c->bio_read), opts);
	rbio->bio.bi_end_io = bch2_readpages_end_io;

	__bchfs_readpage(c, rbio, inode->v.i_ino, page);
	return 0;
}

struct bch_writepage_state {
	struct bch_writepage_io	*io;
	struct bch_io_opts	opts;
};

static inline struct bch_writepage_state bch_writepage_state_init(struct bch_fs *c,
								  struct bch_inode_info *inode)
{
	return (struct bch_writepage_state) { .opts = io_opts(c, inode) };
}

static void bch2_writepage_io_free(struct closure *cl)
{
	struct bch_writepage_io *io = container_of(cl,
					struct bch_writepage_io, cl);

	bio_put(&io->op.op.wbio.bio);
}

static void bch2_writepage_io_done(struct closure *cl)
{
	struct bch_writepage_io *io = container_of(cl,
					struct bch_writepage_io, cl);
	struct bch_fs *c = io->op.op.c;
	struct bio *bio = &io->op.op.wbio.bio;
	struct bio_vec *bvec;
	unsigned i;

	atomic_sub(bio->bi_vcnt, &c->writeback_pages);
	wake_up(&c->writeback_wait);

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		if (io->op.op.error) {
			SetPageError(page);
			if (page->mapping)
				set_bit(AS_EIO, &page->mapping->flags);
		}

		if (io->op.op.written >= PAGE_SECTORS) {
			struct bch_page_state old, new;

			old = page_state_cmpxchg(page_state(page), new, {
				new.sectors = PAGE_SECTORS;
				new.dirty_sectors = 0;
			});

			io->op.sectors_added -= old.dirty_sectors;
			io->op.op.written -= PAGE_SECTORS;
		}
	}

	/*
	 * racing with fallocate can cause us to add fewer sectors than
	 * expected - but we shouldn't add more sectors than expected:
	 *
	 * (error (due to going RO) halfway through a page can screw that up
	 * slightly)
	 */
	BUG_ON(io->op.sectors_added >= (s64) PAGE_SECTORS);

	/*
	 * PageWriteback is effectively our ref on the inode - fixup i_blocks
	 * before calling end_page_writeback:
	 */
	if (io->op.sectors_added)
		i_sectors_acct(c, io->op.inode, io->op.sectors_added);

	bio_for_each_segment_all(bvec, bio, i)
		end_page_writeback(bvec->bv_page);

	closure_return_with_destructor(&io->cl, bch2_writepage_io_free);
}

static void bch2_writepage_do_io(struct bch_writepage_state *w)
{
	struct bch_writepage_io *io = w->io;
	struct bio *bio = &io->op.op.wbio.bio;

	w->io = NULL;
	atomic_add(bio->bi_vcnt, &io->op.op.c->writeback_pages);

	closure_call(&io->op.op.cl, bch2_write, NULL, &io->cl);
	continue_at(&io->cl, bch2_writepage_io_done, NULL);
}

/*
 * Get a bch_writepage_io and add @page to it - appending to an existing one if
 * possible, else allocating a new one:
 */
static void bch2_writepage_io_alloc(struct bch_fs *c,
				    struct bch_writepage_state *w,
				    struct bch_inode_info *inode,
				    struct page *page,
				    struct bch_page_state s)
{
	struct bch_write_op *op;
	u64 offset = (u64) page->index << PAGE_SECTOR_SHIFT;

	w->io = container_of(bio_alloc_bioset(GFP_NOFS,
					      BIO_MAX_PAGES,
					      &c->writepage_bioset),
			     struct bch_writepage_io, op.op.wbio.bio);
	op = &w->io->op.op;

	closure_init(&w->io->cl, NULL);

	bch2_fswrite_op_init(&w->io->op, c, inode, w->opts, false);
	op->nr_replicas		= s.nr_replicas;
	op->res.nr_replicas	= s.nr_replicas;
	op->write_point		= writepoint_hashed(inode->ei_last_dirtied);
	op->pos			= POS(inode->v.i_ino, offset);
	op->wbio.bio.bi_iter.bi_sector = offset;
}

static int __bch2_writepage(struct bch_fs *c, struct page *page,
			    struct writeback_control *wbc,
			    struct bch_writepage_state *w)
{
	struct bch_inode_info *inode = to_bch_ei(page->mapping->host);
	struct bch_page_state new, old;
	unsigned offset;
	loff_t i_size = i_size_read(&inode->v);
	pgoff_t end_index = i_size >> PAGE_SHIFT;

	EBUG_ON(!PageUptodate(page));

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
	/* Before unlocking the page, transfer reservation to w->io: */
	old = page_state_cmpxchg(page_state(page), new, {
		EBUG_ON(!new.reserved &&
			(new.sectors != PAGE_SECTORS ||
			!new.allocated));

		if (new.allocated && w->opts.compression)
			new.allocated = 0;
		else if (!new.reserved)
			break;
		new.reserved = 0;
	});

	if (w->io &&
	    (w->io->op.op.res.nr_replicas != old.nr_replicas ||
	     !bio_can_add_page_contig(&w->io->op.op.wbio.bio, page)))
		bch2_writepage_do_io(w);

	if (!w->io)
		bch2_writepage_io_alloc(c, w, inode, page, old);

	BUG_ON(inode != w->io->op.inode);
	BUG_ON(bio_add_page_contig(&w->io->op.op.wbio.bio, page));

	if (old.reserved)
		w->io->op.op.res.sectors += old.nr_replicas * PAGE_SECTORS;

	/* while page is locked: */
	w->io->op.new_i_size = i_size;

	if (wbc->sync_mode == WB_SYNC_ALL)
		w->io->op.op.wbio.bio.bi_opf |= REQ_SYNC;

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);

	return 0;
}

int bch2_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	struct bch_fs *c = mapping->host->i_sb->s_fs_info;
	struct bch_writepage_state w =
		bch_writepage_state_init(c, to_bch_ei(mapping->host));
	struct pagecache_iter iter;
	struct page *page;
	int ret = 0;
	int done = 0;
	pgoff_t uninitialized_var(writeback_index);
	pgoff_t index;
	pgoff_t end;		/* Inclusive */
	pgoff_t done_index;
	int cycled;
	int range_whole = 0;
	int tag;

	if (wbc->range_cyclic) {
		writeback_index = mapping->writeback_index; /* prev offset */
		index = writeback_index;
		if (index == 0)
			cycled = 1;
		else
			cycled = 0;
		end = -1;
	} else {
		index = wbc->range_start >> PAGE_SHIFT;
		end = wbc->range_end >> PAGE_SHIFT;
		if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
			range_whole = 1;
		cycled = 1; /* ignore range_cyclic tests */
	}
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag = PAGECACHE_TAG_TOWRITE;
	else
		tag = PAGECACHE_TAG_DIRTY;
retry:
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag_pages_for_writeback(mapping, index, end);

	done_index = index;
get_pages:
	for_each_pagecache_tag(&iter, mapping, tag, index, end, page) {
		done_index = page->index;

		if (w.io &&
		    !bio_can_add_page_contig(&w.io->op.op.wbio.bio, page))
			bch2_writepage_do_io(&w);

		if (!w.io &&
		    atomic_read(&c->writeback_pages) >=
		    c->writeback_pages_max) {
			/* don't sleep with pages pinned: */
			pagecache_iter_release(&iter);

			__wait_event(c->writeback_wait,
				     atomic_read(&c->writeback_pages) <
				     c->writeback_pages_max);
			goto get_pages;
		}

		lock_page(page);

		/*
		 * Page truncated or invalidated. We can freely skip it
		 * then, even for data integrity operations: the page
		 * has disappeared concurrently, so there could be no
		 * real expectation of this data interity operation
		 * even if there is now a new, dirty page at the same
		 * pagecache address.
		 */
		if (unlikely(page->mapping != mapping)) {
continue_unlock:
			unlock_page(page);
			continue;
		}

		if (!PageDirty(page)) {
			/* someone wrote it for us */
			goto continue_unlock;
		}

		if (PageWriteback(page)) {
			if (wbc->sync_mode != WB_SYNC_NONE)
				wait_on_page_writeback(page);
			else
				goto continue_unlock;
		}

		BUG_ON(PageWriteback(page));
		if (!clear_page_dirty_for_io(page))
			goto continue_unlock;

		trace_wbc_writepage(wbc, inode_to_bdi(mapping->host));
		ret = __bch2_writepage(c, page, wbc, &w);
		if (unlikely(ret)) {
			if (ret == AOP_WRITEPAGE_ACTIVATE) {
				unlock_page(page);
				ret = 0;
			} else {
				/*
				 * done_index is set past this page,
				 * so media errors will not choke
				 * background writeout for the entire
				 * file. This has consequences for
				 * range_cyclic semantics (ie. it may
				 * not be suitable for data integrity
				 * writeout).
				 */
				done_index = page->index + 1;
				done = 1;
				break;
			}
		}

		/*
		 * We stop writing back only if we are not doing
		 * integrity sync. In case of integrity sync we have to
		 * keep going until we have written all the pages
		 * we tagged for writeback prior to entering this loop.
		 */
		if (--wbc->nr_to_write <= 0 &&
		    wbc->sync_mode == WB_SYNC_NONE) {
			done = 1;
			break;
		}
	}
	pagecache_iter_release(&iter);

	if (w.io)
		bch2_writepage_do_io(&w);

	if (!cycled && !done) {
		/*
		 * range_cyclic:
		 * We hit the last page and there is more work to be done: wrap
		 * back to the start of the file
		 */
		cycled = 1;
		index = 0;
		end = writeback_index - 1;
		goto retry;
	}
	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		mapping->writeback_index = done_index;

	return ret;
}

int bch2_writepage(struct page *page, struct writeback_control *wbc)
{
	struct bch_fs *c = page->mapping->host->i_sb->s_fs_info;
	struct bch_writepage_state w =
		bch_writepage_state_init(c, to_bch_ei(page->mapping->host));
	int ret;

	ret = __bch2_writepage(c, page, wbc, &w);
	if (w.io)
		bch2_writepage_do_io(&w);

	return ret;
}

static void bch2_read_single_page_end_io(struct bio *bio)
{
	complete(bio->bi_private);
}

static int bch2_read_single_page(struct page *page,
				 struct address_space *mapping)
{
	struct bch_inode_info *inode = to_bch_ei(mapping->host);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct bch_read_bio *rbio;
	int ret;
	DECLARE_COMPLETION_ONSTACK(done);

	rbio = rbio_init(bio_alloc_bioset(GFP_NOFS, 1, &c->bio_read),
			 io_opts(c, inode));
	rbio->bio.bi_private = &done;
	rbio->bio.bi_end_io = bch2_read_single_page_end_io;

	__bchfs_readpage(c, rbio, inode->v.i_ino, page);
	wait_for_completion(&done);

	ret = blk_status_to_errno(rbio->bio.bi_status);
	bio_put(&rbio->bio);

	if (ret < 0)
		return ret;

	SetPageUptodate(page);
	return 0;
}

int bch2_write_begin(struct file *file, struct address_space *mapping,
		     loff_t pos, unsigned len, unsigned flags,
		     struct page **pagep, void **fsdata)
{
	struct bch_inode_info *inode = to_bch_ei(mapping->host);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	pgoff_t index = pos >> PAGE_SHIFT;
	unsigned offset = pos & (PAGE_SIZE - 1);
	struct page *page;
	int ret = -ENOMEM;

	BUG_ON(inode_unhashed(&inode->v));

	/* Not strictly necessary - same reason as mkwrite(): */
	pagecache_add_get(&mapping->add_lock);

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		goto err_unlock;

	if (PageUptodate(page))
		goto out;

	/* If we're writing entire page, don't need to read it in first: */
	if (len == PAGE_SIZE)
		goto out;

	if (!offset && pos + len >= inode->v.i_size) {
		zero_user_segment(page, len, PAGE_SIZE);
		flush_dcache_page(page);
		goto out;
	}

	if (index > inode->v.i_size >> PAGE_SHIFT) {
		zero_user_segments(page, 0, offset, offset + len, PAGE_SIZE);
		flush_dcache_page(page);
		goto out;
	}
readpage:
	ret = bch2_read_single_page(page, mapping);
	if (ret)
		goto err;
out:
	ret = bch2_get_page_reservation(c, page, true);
	if (ret) {
		if (!PageUptodate(page)) {
			/*
			 * If the page hasn't been read in, we won't know if we
			 * actually need a reservation - we don't actually need
			 * to read here, we just need to check if the page is
			 * fully backed by uncompressed data:
			 */
			goto readpage;
		}

		goto err;
	}

	*pagep = page;
	return 0;
err:
	unlock_page(page);
	put_page(page);
	*pagep = NULL;
err_unlock:
	pagecache_add_put(&mapping->add_lock);
	return ret;
}

int bch2_write_end(struct file *filp, struct address_space *mapping,
		   loff_t pos, unsigned len, unsigned copied,
		   struct page *page, void *fsdata)
{
	struct bch_inode_info *inode = to_bch_ei(page->mapping->host);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;

	lockdep_assert_held(&inode->v.i_rwsem);

	if (unlikely(copied < len && !PageUptodate(page))) {
		/*
		 * The page needs to be read in, but that would destroy
		 * our partial write - simplest thing is to just force
		 * userspace to redo the write:
		 */
		zero_user(page, 0, PAGE_SIZE);
		flush_dcache_page(page);
		copied = 0;
	}

	if (pos + copied > inode->v.i_size)
		i_size_write(&inode->v, pos + copied);

	if (copied) {
		if (!PageUptodate(page))
			SetPageUptodate(page);
		if (!PageDirty(page))
			set_page_dirty(page);

		inode->ei_last_dirtied = (unsigned long) current;
	} else {
		bch2_put_page_reservation(c, page);
	}

	unlock_page(page);
	put_page(page);
	pagecache_add_put(&mapping->add_lock);

	return copied;
}

/* O_DIRECT */

static void bch2_dio_read_complete(struct closure *cl)
{
	struct dio_read *dio = container_of(cl, struct dio_read, cl);

	dio->req->ki_complete(dio->req, dio->ret, 0);
	bio_check_pages_dirty(&dio->rbio.bio);	/* transfers ownership */
}

static void bch2_direct_IO_read_endio(struct bio *bio)
{
	struct dio_read *dio = bio->bi_private;

	if (bio->bi_status)
		dio->ret = blk_status_to_errno(bio->bi_status);

	closure_put(&dio->cl);
}

static void bch2_direct_IO_read_split_endio(struct bio *bio)
{
	bch2_direct_IO_read_endio(bio);
	bio_check_pages_dirty(bio);	/* transfers ownership */
}

static int bch2_direct_IO_read(struct bch_fs *c, struct kiocb *req,
			       struct file *file, struct bch_inode_info *inode,
			       struct iov_iter *iter, loff_t offset)
{
	struct bch_io_opts opts = io_opts(c, inode);
	struct dio_read *dio;
	struct bio *bio;
	bool sync = is_sync_kiocb(req);
	ssize_t ret;

	if ((offset|iter->count) & (block_bytes(c) - 1))
		return -EINVAL;

	ret = min_t(loff_t, iter->count,
		    max_t(loff_t, 0, i_size_read(&inode->v) - offset));
	iov_iter_truncate(iter, round_up(ret, block_bytes(c)));

	if (!ret)
		return ret;

	bio = bio_alloc_bioset(GFP_KERNEL,
			       iov_iter_npages(iter, BIO_MAX_PAGES),
			       &c->dio_read_bioset);

	bio->bi_end_io = bch2_direct_IO_read_endio;

	dio = container_of(bio, struct dio_read, rbio.bio);
	closure_init(&dio->cl, NULL);

	/*
	 * this is a _really_ horrible hack just to avoid an atomic sub at the
	 * end:
	 */
	if (!sync) {
		set_closure_fn(&dio->cl, bch2_dio_read_complete, NULL);
		atomic_set(&dio->cl.remaining,
			   CLOSURE_REMAINING_INITIALIZER -
			   CLOSURE_RUNNING +
			   CLOSURE_DESTRUCTOR);
	} else {
		atomic_set(&dio->cl.remaining,
			   CLOSURE_REMAINING_INITIALIZER + 1);
	}

	dio->req	= req;
	dio->ret	= ret;

	goto start;
	while (iter->count) {
		bio = bio_alloc_bioset(GFP_KERNEL,
				       iov_iter_npages(iter, BIO_MAX_PAGES),
				       &c->bio_read);
		bio->bi_end_io		= bch2_direct_IO_read_split_endio;
start:
		bio_set_op_attrs(bio, REQ_OP_READ, REQ_SYNC);
		bio->bi_iter.bi_sector	= offset >> 9;
		bio->bi_private		= dio;

		ret = bio_iov_iter_get_pages(bio, iter);
		if (ret < 0) {
			/* XXX: fault inject this path */
			bio->bi_status = BLK_STS_RESOURCE;
			bio_endio(bio);
			break;
		}

		offset += bio->bi_iter.bi_size;
		bio_set_pages_dirty(bio);

		if (iter->count)
			closure_get(&dio->cl);

		bch2_read(c, rbio_init(bio, opts), inode->v.i_ino);
	}

	if (sync) {
		closure_sync(&dio->cl);
		closure_debug_destroy(&dio->cl);
		ret = dio->ret;
		bio_check_pages_dirty(&dio->rbio.bio); /* transfers ownership */
		return ret;
	} else {
		return -EIOCBQUEUED;
	}
}

static long __bch2_dio_write_complete(struct dio_write *dio)
{
	struct file *file = dio->req->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct bch_inode_info *inode = file_bch_inode(file);
	long ret = dio->iop.op.error ?: ((long) dio->iop.op.written << 9);

	bch2_disk_reservation_put(dio->c, &dio->iop.op.res);

	__pagecache_block_put(&mapping->add_lock);
	inode_dio_end(&inode->v);

	if (dio->iovec && dio->iovec != dio->inline_vecs)
		kfree(dio->iovec);

	bio_put(&dio->iop.op.wbio.bio);
	return ret;
}

static void bch2_dio_write_complete(struct closure *cl)
{
	struct dio_write *dio = container_of(cl, struct dio_write, cl);
	struct kiocb *req = dio->req;

	req->ki_complete(req, __bch2_dio_write_complete(dio), 0);
}

static void bch2_dio_write_done(struct dio_write *dio)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, &dio->iop.op.wbio.bio, i)
		put_page(bv->bv_page);

	if (dio->iter.count)
		bio_reset(&dio->iop.op.wbio.bio);
}

static void bch2_do_direct_IO_write(struct dio_write *dio)
{
	struct file *file = dio->req->ki_filp;
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bio *bio = &dio->iop.op.wbio.bio;
	int ret;

	ret = bio_iov_iter_get_pages(bio, &dio->iter);
	if (ret < 0) {
		dio->iop.op.error = ret;
		return;
	}

	dio->iop.op.pos = POS(inode->v.i_ino, (dio->offset >> 9) + dio->iop.op.written);

	task_io_account_write(bio->bi_iter.bi_size);

	closure_call(&dio->iop.op.cl, bch2_write, NULL, &dio->cl);
}

static void bch2_dio_write_loop_async(struct closure *cl)
{
	struct dio_write *dio =
		container_of(cl, struct dio_write, cl);
	struct address_space *mapping = dio->req->ki_filp->f_mapping;

	bch2_dio_write_done(dio);

	if (dio->iter.count && !dio->iop.op.error) {
		use_mm(dio->task->mm);
		pagecache_block_get(&mapping->add_lock);

		bch2_do_direct_IO_write(dio);

		pagecache_block_put(&mapping->add_lock);
		unuse_mm(dio->task->mm);

		continue_at(&dio->cl, bch2_dio_write_loop_async, NULL);
	} else {
#if 0
		closure_return_with_destructor(cl, bch2_dio_write_complete);
#else
		closure_debug_destroy(cl);
		bch2_dio_write_complete(cl);
#endif
	}
}

static int bch2_direct_IO_write(struct bch_fs *c,
				struct kiocb *req, struct file *file,
				struct bch_inode_info *inode,
				struct iov_iter *iter, loff_t offset)
{
	struct address_space *mapping = file->f_mapping;
	struct dio_write *dio;
	struct bio *bio;
	ssize_t ret;
	bool sync = is_sync_kiocb(req);

	lockdep_assert_held(&inode->v.i_rwsem);

	if (unlikely(!iter->count))
		return 0;

	if (unlikely((offset|iter->count) & (block_bytes(c) - 1)))
		return -EINVAL;

	bio = bio_alloc_bioset(GFP_KERNEL,
			       iov_iter_npages(iter, BIO_MAX_PAGES),
			       &c->dio_write_bioset);
	dio = container_of(bio, struct dio_write, iop.op.wbio.bio);
	closure_init(&dio->cl, NULL);
	dio->req		= req;
	dio->c			= c;
	dio->offset		= offset;
	dio->iovec		= NULL;
	dio->iter		= *iter;
	dio->task		= current;
	bch2_fswrite_op_init(&dio->iop, c, inode, io_opts(c, inode), true);
	dio->iop.op.write_point	= writepoint_hashed((unsigned long) dio->task);
	dio->iop.op.flags |= BCH_WRITE_NOPUT_RESERVATION;

	if ((dio->req->ki_flags & IOCB_DSYNC) &&
	    !c->opts.journal_flush_disabled)
		dio->iop.op.flags |= BCH_WRITE_FLUSH;

	if (offset + iter->count > inode->v.i_size)
		sync = true;

	/*
	 * XXX: we shouldn't return -ENOSPC if we're overwriting existing data -
	 * if getting a reservation fails we should check if we are doing an
	 * overwrite.
	 *
	 * Have to then guard against racing with truncate (deleting data that
	 * we would have been overwriting)
	 */
	ret = bch2_disk_reservation_get(c, &dio->iop.op.res, iter->count >> 9, 0);
	if (unlikely(ret)) {
		if (bch2_check_range_allocated(c, POS(inode->v.i_ino,
						      offset >> 9),
					       iter->count >> 9)) {
			closure_debug_destroy(&dio->cl);
			bio_put(bio);
			return ret;
		}

		dio->iop.unalloc = true;
	}

	dio->iop.op.nr_replicas	= dio->iop.op.res.nr_replicas;

	inode_dio_begin(&inode->v);
	__pagecache_block_get(&mapping->add_lock);

	if (sync) {
		do {
			bch2_do_direct_IO_write(dio);

			closure_sync(&dio->cl);
			bch2_dio_write_done(dio);
		} while (dio->iter.count && !dio->iop.op.error);

		closure_debug_destroy(&dio->cl);
		return __bch2_dio_write_complete(dio);
	} else {
		bch2_do_direct_IO_write(dio);

		if (dio->iter.count && !dio->iop.op.error) {
			if (dio->iter.nr_segs > ARRAY_SIZE(dio->inline_vecs)) {
				dio->iovec = kmalloc(dio->iter.nr_segs *
						     sizeof(struct iovec),
						     GFP_KERNEL);
				if (!dio->iovec)
					dio->iop.op.error = -ENOMEM;
			} else {
				dio->iovec = dio->inline_vecs;
			}

			memcpy(dio->iovec,
			       dio->iter.iov,
			       dio->iter.nr_segs * sizeof(struct iovec));
			dio->iter.iov = dio->iovec;
		}

		continue_at(&dio->cl, bch2_dio_write_loop_async, NULL);
		return -EIOCBQUEUED;
	}
}

ssize_t bch2_direct_IO(struct kiocb *req, struct iov_iter *iter)
{
	struct file *file = req->ki_filp;
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct blk_plug plug;
	ssize_t ret;

	blk_start_plug(&plug);
	ret = ((iov_iter_rw(iter) == WRITE)
		? bch2_direct_IO_write
		: bch2_direct_IO_read)(c, req, file, inode, iter, req->ki_pos);
	blk_finish_plug(&plug);

	return ret;
}

static ssize_t
bch2_direct_write(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct address_space *mapping = file->f_mapping;
	loff_t pos = iocb->ki_pos;
	ssize_t	ret;

	pagecache_block_get(&mapping->add_lock);

	/* Write and invalidate pagecache range that we're writing to: */
	ret = write_invalidate_inode_pages_range(file->f_mapping, pos,
					pos + iov_iter_count(iter) - 1);
	if (unlikely(ret))
		goto err;

	ret = bch2_direct_IO_write(c, iocb, file, inode, iter, pos);
err:
	pagecache_block_put(&mapping->add_lock);

	return ret;
}

static ssize_t __bch2_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct bch_inode_info *inode = file_bch_inode(file);
	ssize_t	ret;

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(&inode->v);
	ret = file_remove_privs(file);
	if (ret)
		goto out;

	ret = file_update_time(file);
	if (ret)
		goto out;

	ret = iocb->ki_flags & IOCB_DIRECT
		? bch2_direct_write(iocb, from)
		: generic_perform_write(file, from, iocb->ki_pos);

	if (likely(ret > 0))
		iocb->ki_pos += ret;
out:
	current->backing_dev_info = NULL;
	return ret;
}

ssize_t bch2_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct bch_inode_info *inode = file_bch_inode(iocb->ki_filp);
	bool direct = iocb->ki_flags & IOCB_DIRECT;
	ssize_t ret;

	inode_lock(&inode->v);
	ret = generic_write_checks(iocb, from);
	if (ret > 0)
		ret = __bch2_write_iter(iocb, from);
	inode_unlock(&inode->v);

	if (ret > 0 && !direct)
		ret = generic_write_sync(iocb, ret);

	return ret;
}

int bch2_page_mkwrite(struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct file *file = vmf->vma->vm_file;
	struct bch_inode_info *inode = file_bch_inode(file);
	struct address_space *mapping = inode->v.i_mapping;
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	int ret = VM_FAULT_LOCKED;

	sb_start_pagefault(inode->v.i_sb);
	file_update_time(file);

	/*
	 * Not strictly necessary, but helps avoid dio writes livelocking in
	 * write_invalidate_inode_pages_range() - can drop this if/when we get
	 * a write_invalidate_inode_pages_range() that works without dropping
	 * page lock before invalidating page
	 */
	if (current->pagecache_lock != &mapping->add_lock)
		pagecache_add_get(&mapping->add_lock);

	lock_page(page);
	if (page->mapping != mapping ||
	    page_offset(page) > i_size_read(&inode->v)) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}

	if (bch2_get_page_reservation(c, page, true)) {
		unlock_page(page);
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	if (!PageDirty(page))
		set_page_dirty(page);
	wait_for_stable_page(page);
out:
	if (current->pagecache_lock != &mapping->add_lock)
		pagecache_add_put(&mapping->add_lock);
	sb_end_pagefault(inode->v.i_sb);
	return ret;
}

void bch2_invalidatepage(struct page *page, unsigned int offset,
			 unsigned int length)
{
	EBUG_ON(!PageLocked(page));
	EBUG_ON(PageWriteback(page));

	if (offset || length < PAGE_SIZE)
		return;

	bch2_clear_page_bits(page);
}

int bch2_releasepage(struct page *page, gfp_t gfp_mask)
{
	EBUG_ON(!PageLocked(page));
	EBUG_ON(PageWriteback(page));

	if (PageDirty(page))
		return 0;

	bch2_clear_page_bits(page);
	return 1;
}

#ifdef CONFIG_MIGRATION
int bch2_migrate_page(struct address_space *mapping, struct page *newpage,
		      struct page *page, enum migrate_mode mode)
{
	int ret;

	ret = migrate_page_move_mapping(mapping, newpage, page, NULL, mode, 0);
	if (ret != MIGRATEPAGE_SUCCESS)
		return ret;

	if (PagePrivate(page)) {
		*page_state(newpage) = *page_state(page);
		ClearPagePrivate(page);
	}

	migrate_page_copy(newpage, page);
	return MIGRATEPAGE_SUCCESS;
}
#endif

int bch2_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	int ret;

	ret = filemap_write_and_wait_range(inode->v.i_mapping, start, end);
	if (ret)
		return ret;

	if (c->opts.journal_flush_disabled)
		return 0;

	return bch2_journal_flush_seq(&c->journal, inode->ei_journal_seq);
}

static int __bch2_truncate_page(struct bch_inode_info *inode,
				pgoff_t index, loff_t start, loff_t end)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct address_space *mapping = inode->v.i_mapping;
	unsigned start_offset = start & (PAGE_SIZE - 1);
	unsigned end_offset = ((end - 1) & (PAGE_SIZE - 1)) + 1;
	struct page *page;
	int ret = 0;

	/* Page boundary? Nothing to do */
	if (!((index == start >> PAGE_SHIFT && start_offset) ||
	      (index == end >> PAGE_SHIFT && end_offset != PAGE_SIZE)))
		return 0;

	/* Above i_size? */
	if (index << PAGE_SHIFT >= inode->v.i_size)
		return 0;

	page = find_lock_page(mapping, index);
	if (!page) {
		struct btree_iter iter;
		struct bkey_s_c k = bkey_s_c_null;

		/*
		 * XXX: we're doing two index lookups when we end up reading the
		 * page
		 */
		for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
				   POS(inode->v.i_ino,
				       index << PAGE_SECTOR_SHIFT), 0, k) {
			if (bkey_cmp(bkey_start_pos(k.k),
				     POS(inode->v.i_ino,
					 (index + 1) << PAGE_SECTOR_SHIFT)) >= 0)
				break;

			if (k.k->type != KEY_TYPE_DISCARD &&
			    k.k->type != BCH_RESERVATION) {
				bch2_btree_iter_unlock(&iter);
				goto create;
			}
		}
		bch2_btree_iter_unlock(&iter);
		return 0;
create:
		page = find_or_create_page(mapping, index, GFP_KERNEL);
		if (unlikely(!page)) {
			ret = -ENOMEM;
			goto out;
		}
	}

	if (!PageUptodate(page)) {
		ret = bch2_read_single_page(page, mapping);
		if (ret)
			goto unlock;
	}

	/*
	 * Bit of a hack - we don't want truncate to fail due to -ENOSPC.
	 *
	 * XXX: because we aren't currently tracking whether the page has actual
	 * data in it (vs. just 0s, or only partially written) this wrong. ick.
	 */
	ret = bch2_get_page_reservation(c, page, false);
	BUG_ON(ret);

	if (index == start >> PAGE_SHIFT &&
	    index == end >> PAGE_SHIFT)
		zero_user_segment(page, start_offset, end_offset);
	else if (index == start >> PAGE_SHIFT)
		zero_user_segment(page, start_offset, PAGE_SIZE);
	else if (index == end >> PAGE_SHIFT)
		zero_user_segment(page, 0, end_offset);

	if (!PageDirty(page))
		set_page_dirty(page);
unlock:
	unlock_page(page);
	put_page(page);
out:
	return ret;
}

static int bch2_truncate_page(struct bch_inode_info *inode, loff_t from)
{
	return __bch2_truncate_page(inode, from >> PAGE_SHIFT,
				    from, from + PAGE_SIZE);
}

int bch2_truncate(struct bch_inode_info *inode, struct iattr *iattr)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct address_space *mapping = inode->v.i_mapping;
	bool shrink = iattr->ia_size <= inode->v.i_size;
	struct i_sectors_hook i_sectors_hook =
		i_sectors_hook_init(inode, BCH_INODE_I_SIZE_DIRTY);
	int ret = 0;

	inode_dio_wait(&inode->v);
	pagecache_block_get(&mapping->add_lock);

	truncate_setsize(&inode->v, iattr->ia_size);

	/* sync appends.. */
	/* XXX what protects inode->i_size? */
	if (iattr->ia_size > inode->ei_inode.bi_size)
		ret = filemap_write_and_wait_range(mapping,
						   inode->ei_inode.bi_size, S64_MAX);
	if (ret)
		goto err_put_pagecache;

	i_sectors_hook.new_i_size = iattr->ia_size;

	ret = i_sectors_dirty_start(c, &i_sectors_hook);
	if (unlikely(ret))
		goto err;

	/*
	 * There might be persistent reservations (from fallocate())
	 * above i_size, which bch2_inode_truncate() will discard - we're
	 * only supposed to discard them if we're doing a real truncate
	 * here (new i_size < current i_size):
	 */
	if (shrink) {
		ret = bch2_truncate_page(inode, iattr->ia_size);
		if (unlikely(ret))
			goto err;

		ret = bch2_inode_truncate(c, inode->v.i_ino,
					  round_up(iattr->ia_size, PAGE_SIZE) >> 9,
					  &i_sectors_hook.hook,
					  &inode->ei_journal_seq);
		if (unlikely(ret))
			goto err;
	}

	setattr_copy(&inode->v, iattr);
	inode->v.i_mtime = inode->v.i_ctime = current_time(&inode->v);
err:
	/*
	 * On error - in particular, bch2_truncate_page() error - don't clear
	 * I_SIZE_DIRTY, as we've left data above i_size!:
	 */
	if (ret)
		i_sectors_hook.flags &= ~BCH_INODE_I_SIZE_DIRTY;

	ret = i_sectors_dirty_finish(c, &i_sectors_hook) ?: ret;
err_put_pagecache:
	pagecache_block_put(&mapping->add_lock);
	return ret;
}

static long bch2_fpunch(struct bch_inode_info *inode, loff_t offset, loff_t len)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct address_space *mapping = inode->v.i_mapping;
	u64 ino = inode->v.i_ino;
	u64 discard_start = round_up(offset, PAGE_SIZE) >> 9;
	u64 discard_end = round_down(offset + len, PAGE_SIZE) >> 9;
	int ret = 0;

	inode_lock(&inode->v);
	inode_dio_wait(&inode->v);
	pagecache_block_get(&mapping->add_lock);

	ret = __bch2_truncate_page(inode,
				   offset >> PAGE_SHIFT,
				   offset, offset + len);
	if (unlikely(ret))
		goto err;

	if (offset >> PAGE_SHIFT !=
	    (offset + len) >> PAGE_SHIFT) {
		ret = __bch2_truncate_page(inode,
					   (offset + len) >> PAGE_SHIFT,
					   offset, offset + len);
		if (unlikely(ret))
			goto err;
	}

	truncate_pagecache_range(&inode->v, offset, offset + len - 1);

	if (discard_start < discard_end) {
		struct disk_reservation disk_res;
		struct i_sectors_hook i_sectors_hook =
			i_sectors_hook_init(inode, 0);
		int ret;

		ret = i_sectors_dirty_start(c, &i_sectors_hook);
		if (unlikely(ret))
			goto err;

		/*
		 * We need to pass in a disk reservation here because we might
		 * be splitting a compressed extent into two. This isn't a
		 * problem with truncate because truncate will never split an
		 * extent, only truncate it...
		 */
		ret = bch2_disk_reservation_get(c, &disk_res, 0, 0);
		BUG_ON(ret);

		ret = bch2_btree_delete_range(c,
				BTREE_ID_EXTENTS,
				POS(ino, discard_start),
				POS(ino, discard_end),
				ZERO_VERSION,
				&disk_res,
				&i_sectors_hook.hook,
				&inode->ei_journal_seq);
		bch2_disk_reservation_put(c, &disk_res);

		ret = i_sectors_dirty_finish(c, &i_sectors_hook) ?: ret;
	}
err:
	pagecache_block_put(&mapping->add_lock);
	inode_unlock(&inode->v);

	return ret;
}

static long bch2_fcollapse(struct bch_inode_info *inode,
			   loff_t offset, loff_t len)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct address_space *mapping = inode->v.i_mapping;
	struct btree_iter src;
	struct btree_iter dst;
	BKEY_PADDED(k) copy;
	struct bkey_s_c k;
	struct i_sectors_hook i_sectors_hook = i_sectors_hook_init(inode, 0);
	loff_t new_size;
	int ret;

	if ((offset | len) & (PAGE_SIZE - 1))
		return -EINVAL;

	bch2_btree_iter_init(&dst, c, BTREE_ID_EXTENTS,
			     POS(inode->v.i_ino, offset >> 9),
			     BTREE_ITER_INTENT);
	/* position will be set from dst iter's position: */
	bch2_btree_iter_init(&src, c, BTREE_ID_EXTENTS, POS_MIN, 0);
	bch2_btree_iter_link(&src, &dst);

	/*
	 * We need i_mutex to keep the page cache consistent with the extents
	 * btree, and the btree consistent with i_size - we don't need outside
	 * locking for the extents btree itself, because we're using linked
	 * iterators
	 */
	inode_lock(&inode->v);
	inode_dio_wait(&inode->v);
	pagecache_block_get(&mapping->add_lock);

	ret = -EINVAL;
	if (offset + len >= inode->v.i_size)
		goto err;

	if (inode->v.i_size < len)
		goto err;

	new_size = inode->v.i_size - len;

	ret = write_invalidate_inode_pages_range(mapping, offset, LLONG_MAX);
	if (ret)
		goto err;

	ret = i_sectors_dirty_start(c, &i_sectors_hook);
	if (ret)
		goto err;

	while (bkey_cmp(dst.pos,
			POS(inode->v.i_ino,
			    round_up(new_size, PAGE_SIZE) >> 9)) < 0) {
		struct disk_reservation disk_res;

		bch2_btree_iter_set_pos(&src,
			POS(dst.pos.inode, dst.pos.offset + (len >> 9)));

		ret = bch2_btree_iter_traverse(&dst);
		if (ret)
			goto btree_iter_err;

		k = bch2_btree_iter_peek_with_holes(&src);
		if ((ret = btree_iter_err(k)))
			goto btree_iter_err;

		bkey_reassemble(&copy.k, k);

		if (bkey_deleted(&copy.k.k))
			copy.k.k.type = KEY_TYPE_DISCARD;

		bch2_cut_front(src.pos, &copy.k);
		copy.k.k.p.offset -= len >> 9;

		BUG_ON(bkey_cmp(dst.pos, bkey_start_pos(&copy.k.k)));

		ret = bch2_disk_reservation_get(c, &disk_res, copy.k.k.size,
					       BCH_DISK_RESERVATION_NOFAIL);
		BUG_ON(ret);

		ret = bch2_btree_insert_at(c, &disk_res, &i_sectors_hook.hook,
					   &inode->ei_journal_seq,
					   BTREE_INSERT_ATOMIC|
					   BTREE_INSERT_NOFAIL,
					   BTREE_INSERT_ENTRY(&dst, &copy.k));
		bch2_disk_reservation_put(c, &disk_res);
btree_iter_err:
		if (ret == -EINTR)
			ret = 0;
		if (ret)
			goto err_put_sectors_dirty;
		/*
		 * XXX: if we error here we've left data with multiple
		 * pointers... which isn't a _super_ serious problem...
		 */

		bch2_btree_iter_cond_resched(&src);
	}

	bch2_btree_iter_unlock(&src);
	bch2_btree_iter_unlock(&dst);

	ret = bch2_inode_truncate(c, inode->v.i_ino,
				 round_up(new_size, PAGE_SIZE) >> 9,
				 &i_sectors_hook.hook,
				 &inode->ei_journal_seq);
	if (ret)
		goto err_put_sectors_dirty;

	i_size_write(&inode->v, new_size);
	i_sectors_hook.new_i_size = new_size;
err_put_sectors_dirty:
	ret = i_sectors_dirty_finish(c, &i_sectors_hook) ?: ret;
err:
	pagecache_block_put(&mapping->add_lock);
	inode_unlock(&inode->v);

	bch2_btree_iter_unlock(&src);
	bch2_btree_iter_unlock(&dst);
	return ret;
}

static long bch2_fallocate(struct bch_inode_info *inode, int mode,
			   loff_t offset, loff_t len)
{
	struct address_space *mapping = inode->v.i_mapping;
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct i_sectors_hook i_sectors_hook = i_sectors_hook_init(inode, 0);
	struct btree_iter iter;
	struct bpos end_pos;
	loff_t block_start, block_end;
	loff_t end = offset + len;
	unsigned sectors;
	unsigned replicas = READ_ONCE(c->opts.data_replicas);
	int ret;

	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN,
			     BTREE_ITER_INTENT);

	inode_lock(&inode->v);
	inode_dio_wait(&inode->v);
	pagecache_block_get(&mapping->add_lock);

	if (!(mode & FALLOC_FL_KEEP_SIZE) && end > inode->v.i_size) {
		ret = inode_newsize_ok(&inode->v, end);
		if (ret)
			goto err;
	}

	if (mode & FALLOC_FL_ZERO_RANGE) {
		ret = __bch2_truncate_page(inode,
					   offset >> PAGE_SHIFT,
					   offset, end);

		if (!ret &&
		    offset >> PAGE_SHIFT != end >> PAGE_SHIFT)
			ret = __bch2_truncate_page(inode,
						   end >> PAGE_SHIFT,
						   offset, end);

		if (unlikely(ret))
			goto err;

		truncate_pagecache_range(&inode->v, offset, end - 1);

		block_start	= round_up(offset, PAGE_SIZE);
		block_end	= round_down(end, PAGE_SIZE);
	} else {
		block_start	= round_down(offset, PAGE_SIZE);
		block_end	= round_up(end, PAGE_SIZE);
	}

	bch2_btree_iter_set_pos(&iter, POS(inode->v.i_ino, block_start >> 9));
	end_pos = POS(inode->v.i_ino, block_end >> 9);

	ret = i_sectors_dirty_start(c, &i_sectors_hook);
	if (unlikely(ret))
		goto err;

	while (bkey_cmp(iter.pos, end_pos) < 0) {
		struct disk_reservation disk_res = { 0 };
		struct bkey_i_reservation reservation;
		struct bkey_s_c k;

		k = bch2_btree_iter_peek_with_holes(&iter);
		if ((ret = btree_iter_err(k)))
			goto btree_iter_err;

		/* already reserved */
		if (k.k->type == BCH_RESERVATION &&
		    bkey_s_c_to_reservation(k).v->nr_replicas >= replicas) {
			bch2_btree_iter_advance_pos(&iter);
			continue;
		}

		if (bkey_extent_is_data(k.k)) {
			if (!(mode & FALLOC_FL_ZERO_RANGE)) {
				bch2_btree_iter_advance_pos(&iter);
				continue;
			}
		}

		bkey_reservation_init(&reservation.k_i);
		reservation.k.type	= BCH_RESERVATION;
		reservation.k.p		= k.k->p;
		reservation.k.size	= k.k->size;

		bch2_cut_front(iter.pos, &reservation.k_i);
		bch2_cut_back(end_pos, &reservation.k);

		sectors = reservation.k.size;
		reservation.v.nr_replicas = bch2_extent_nr_dirty_ptrs(k);

		if (reservation.v.nr_replicas < replicas ||
		    bch2_extent_is_compressed(k)) {
			ret = bch2_disk_reservation_get(c, &disk_res,
						       sectors, 0);
			if (ret)
				goto err_put_sectors_dirty;

			reservation.v.nr_replicas = disk_res.nr_replicas;
		}

		ret = bch2_btree_insert_at(c, &disk_res, &i_sectors_hook.hook,
					  &inode->ei_journal_seq,
					  BTREE_INSERT_ATOMIC|
					  BTREE_INSERT_NOFAIL,
					  BTREE_INSERT_ENTRY(&iter, &reservation.k_i));
		bch2_disk_reservation_put(c, &disk_res);
btree_iter_err:
		if (ret < 0 && ret != -EINTR)
			goto err_put_sectors_dirty;

	}
	bch2_btree_iter_unlock(&iter);

	ret = i_sectors_dirty_finish(c, &i_sectors_hook) ?: ret;

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    end > inode->v.i_size) {
		i_size_write(&inode->v, end);

		mutex_lock(&inode->ei_update_lock);
		ret = bch2_write_inode_size(c, inode, inode->v.i_size);
		mutex_unlock(&inode->ei_update_lock);
	}

	/* blech */
	if ((mode & FALLOC_FL_KEEP_SIZE) &&
	    (mode & FALLOC_FL_ZERO_RANGE) &&
	    inode->ei_inode.bi_size != inode->v.i_size) {
		/* sync appends.. */
		ret = filemap_write_and_wait_range(mapping,
					inode->ei_inode.bi_size, S64_MAX);
		if (ret)
			goto err;

		if (inode->ei_inode.bi_size != inode->v.i_size) {
			mutex_lock(&inode->ei_update_lock);
			ret = bch2_write_inode_size(c, inode, inode->v.i_size);
			mutex_unlock(&inode->ei_update_lock);
		}
	}

	pagecache_block_put(&mapping->add_lock);
	inode_unlock(&inode->v);

	return 0;
err_put_sectors_dirty:
	ret = i_sectors_dirty_finish(c, &i_sectors_hook) ?: ret;
err:
	bch2_btree_iter_unlock(&iter);
	pagecache_block_put(&mapping->add_lock);
	inode_unlock(&inode->v);
	return ret;
}

long bch2_fallocate_dispatch(struct file *file, int mode,
			     loff_t offset, loff_t len)
{
	struct bch_inode_info *inode = file_bch_inode(file);

	if (!(mode & ~(FALLOC_FL_KEEP_SIZE|FALLOC_FL_ZERO_RANGE)))
		return bch2_fallocate(inode, mode, offset, len);

	if (mode == (FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE))
		return bch2_fpunch(inode, offset, len);

	if (mode == FALLOC_FL_COLLAPSE_RANGE)
		return bch2_fcollapse(inode, offset, len);

	return -EOPNOTSUPP;
}

static bool page_is_data(struct page *page)
{
	/* XXX: should only have to check PageDirty */
	return PagePrivate(page) &&
		(page_state(page)->sectors ||
		 page_state(page)->dirty_sectors);
}

static loff_t bch2_next_pagecache_data(struct inode *vinode,
				       loff_t start_offset,
				       loff_t end_offset)
{
	struct address_space *mapping = vinode->i_mapping;
	struct page *page;
	pgoff_t index;

	for (index = start_offset >> PAGE_SHIFT;
	     index < end_offset >> PAGE_SHIFT;
	     index++) {
		if (find_get_pages(mapping, &index, 1, &page)) {
			lock_page(page);

			if (page_is_data(page))
				end_offset =
					min(end_offset,
					max(start_offset,
					    ((loff_t) index) << PAGE_SHIFT));
			unlock_page(page);
			put_page(page);
		} else {
			break;
		}
	}

	return end_offset;
}

static loff_t bch2_seek_data(struct file *file, u64 offset)
{
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 isize, next_data = MAX_LFS_FILESIZE;
	int ret;

	isize = i_size_read(&inode->v);
	if (offset >= isize)
		return -ENXIO;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
			   POS(inode->v.i_ino, offset >> 9), 0, k) {
		if (k.k->p.inode != inode->v.i_ino) {
			break;
		} else if (bkey_extent_is_data(k.k)) {
			next_data = max(offset, bkey_start_offset(k.k) << 9);
			break;
		} else if (k.k->p.offset >> 9 > isize)
			break;
	}

	ret = bch2_btree_iter_unlock(&iter);
	if (ret)
		return ret;

	if (next_data > offset)
		next_data = bch2_next_pagecache_data(&inode->v,
						     offset, next_data);

	if (next_data > isize)
		return -ENXIO;

	return vfs_setpos(file, next_data, MAX_LFS_FILESIZE);
}

static bool page_slot_is_data(struct address_space *mapping, pgoff_t index)
{
	struct page *page;
	bool ret;

	page = find_lock_entry(mapping, index);
	if (!page || radix_tree_exception(page))
		return false;

	ret = page_is_data(page);
	unlock_page(page);

	return ret;
}

static loff_t bch2_next_pagecache_hole(struct inode *vinode,
				       loff_t start_offset,
				       loff_t end_offset)
{
	struct address_space *mapping = vinode->i_mapping;
	pgoff_t index;

	for (index = start_offset >> PAGE_SHIFT;
	     index < end_offset >> PAGE_SHIFT;
	     index++)
		if (!page_slot_is_data(mapping, index))
			end_offset = max(start_offset,
					 ((loff_t) index) << PAGE_SHIFT);

	return end_offset;
}

static loff_t bch2_seek_hole(struct file *file, u64 offset)
{
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 isize, next_hole = MAX_LFS_FILESIZE;
	int ret;

	isize = i_size_read(&inode->v);
	if (offset >= isize)
		return -ENXIO;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
			   POS(inode->v.i_ino, offset >> 9),
			   BTREE_ITER_WITH_HOLES, k) {
		if (k.k->p.inode != inode->v.i_ino) {
			next_hole = bch2_next_pagecache_hole(&inode->v,
					offset, MAX_LFS_FILESIZE);
			break;
		} else if (!bkey_extent_is_data(k.k)) {
			next_hole = bch2_next_pagecache_hole(&inode->v,
					max(offset, bkey_start_offset(k.k) << 9),
					k.k->p.offset << 9);

			if (next_hole < k.k->p.offset << 9)
				break;
		} else {
			offset = max(offset, bkey_start_offset(k.k) << 9);
		}
	}

	ret = bch2_btree_iter_unlock(&iter);
	if (ret)
		return ret;

	if (next_hole > isize)
		next_hole = isize;

	return vfs_setpos(file, next_hole, MAX_LFS_FILESIZE);
}

loff_t bch2_llseek(struct file *file, loff_t offset, int whence)
{
	switch (whence) {
	case SEEK_SET:
	case SEEK_CUR:
	case SEEK_END:
		return generic_file_llseek(file, offset, whence);
	case SEEK_DATA:
		return bch2_seek_data(file, offset);
	case SEEK_HOLE:
		return bch2_seek_hole(file, offset);
	}

	return -EINVAL;
}

void bch2_fs_fsio_exit(struct bch_fs *c)
{
	bioset_exit(&c->dio_write_bioset);
	bioset_exit(&c->dio_read_bioset);
	bioset_exit(&c->writepage_bioset);
}

int bch2_fs_fsio_init(struct bch_fs *c)
{
	if (bioset_init(&c->writepage_bioset,
			4, offsetof(struct bch_writepage_io, op.op.wbio.bio),
			BIOSET_NEED_BVECS) ||
	    bioset_init(&c->dio_read_bioset,
			4, offsetof(struct dio_read, rbio.bio),
			BIOSET_NEED_BVECS) ||
	    bioset_init(&c->dio_write_bioset,
			4, offsetof(struct dio_write, iop.op.wbio.bio),
			BIOSET_NEED_BVECS))
		return -ENOMEM;

	return 0;
}

#endif /* NO_BCACHEFS_FS */
