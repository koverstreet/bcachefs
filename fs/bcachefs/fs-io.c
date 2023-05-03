// SPDX-License-Identifier: GPL-2.0
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
#include "quota.h"
#include "trace.h"

#include <linux/aio.h>
#include <linux/backing-dev.h>
#include <linux/falloc.h>
#include <linux/migrate.h>
#include <linux/mmu_context.h>
#include <linux/pagevec.h>
#include <linux/sched/signal.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/uio.h>
#include <linux/writeback.h>

#include <trace/events/writeback.h>

struct quota_res {
	u64				sectors;
};

struct i_sectors_hook {
	struct extent_insert_hook	hook;
	struct bch_inode_info		*inode;
	struct quota_res		quota_res;
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
	u64				new_sectors;

	/* must be last: */
	struct bchfs_write_op		op;
};

struct dio_write {
	struct closure			cl;
	struct kiocb			*req;
	struct task_struct		*task;
	unsigned			loop:1,
					sync:1,
					free_iov:1;
	struct quota_res		quota_res;

	struct iov_iter			iter;
	struct iovec			inline_vecs[2];

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
		if (!mapping->nrpages)
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

/* quotas */

#ifdef CONFIG_BCACHEFS_QUOTA

static void bch2_quota_reservation_put(struct bch_fs *c,
				       struct bch_inode_info *inode,
				       struct quota_res *res)
{
	if (!res->sectors)
		return;

	mutex_lock(&inode->ei_quota_lock);
	BUG_ON(res->sectors > inode->ei_quota_reserved);

	bch2_quota_acct(c, inode->ei_qid, Q_SPC,
			-((s64) res->sectors), BCH_QUOTA_PREALLOC);
	inode->ei_quota_reserved -= res->sectors;
	mutex_unlock(&inode->ei_quota_lock);

	res->sectors = 0;
}

static int bch2_quota_reservation_add(struct bch_fs *c,
				      struct bch_inode_info *inode,
				      struct quota_res *res,
				      unsigned sectors,
				      bool check_enospc)
{
	int ret;

	mutex_lock(&inode->ei_quota_lock);
	ret = bch2_quota_acct(c, inode->ei_qid, Q_SPC, sectors,
			      check_enospc ? BCH_QUOTA_PREALLOC : BCH_QUOTA_NOCHECK);
	if (likely(!ret)) {
		inode->ei_quota_reserved += sectors;
		res->sectors += sectors;
	}
	mutex_unlock(&inode->ei_quota_lock);

	return ret;
}

#else

static void bch2_quota_reservation_put(struct bch_fs *c,
				       struct bch_inode_info *inode,
				       struct quota_res *res)
{
}

static int bch2_quota_reservation_add(struct bch_fs *c,
				      struct bch_inode_info *inode,
				      struct quota_res *res,
				      unsigned sectors,
				      bool check_enospc)
{
	return 0;
}

#endif

/* i_size updates: */

struct inode_new_size {
	loff_t		new_size;
	u64		now;
	unsigned	fields;
};

static int inode_set_size(struct bch_inode_info *inode,
			  struct bch_inode_unpacked *bi,
			  void *p)
{
	struct inode_new_size *s = p;

	bi->bi_size = s->new_size;
	if (s->fields & ATTR_ATIME)
		bi->bi_atime = s->now;
	if (s->fields & ATTR_MTIME)
		bi->bi_mtime = s->now;
	if (s->fields & ATTR_CTIME)
		bi->bi_ctime = s->now;

	return 0;
}

static int __must_check bch2_write_inode_size(struct bch_fs *c,
					      struct bch_inode_info *inode,
					      loff_t new_size, unsigned fields)
{
	struct inode_new_size s = {
		.new_size	= new_size,
		.now		= bch2_current_time(c),
		.fields		= fields,
	};

	return bch2_write_inode(c, inode, inode_set_size, &s, fields);
}

static void i_sectors_acct(struct bch_fs *c, struct bch_inode_info *inode,
			   struct quota_res *quota_res, int sectors)
{
	mutex_lock(&inode->ei_quota_lock);
#ifdef CONFIG_BCACHEFS_QUOTA
	if (quota_res && sectors > 0) {
		BUG_ON(sectors > quota_res->sectors);
		BUG_ON(sectors > inode->ei_quota_reserved);

		quota_res->sectors -= sectors;
		inode->ei_quota_reserved -= sectors;
	} else {
		bch2_quota_acct(c, inode->ei_qid, Q_SPC, sectors, BCH_QUOTA_WARN);
	}
#endif
	inode->v.i_blocks += sectors;
	mutex_unlock(&inode->ei_quota_lock);
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
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct i_sectors_hook *h = p;

	if (h->new_i_size != U64_MAX &&
	    (!h->appending ||
	     h->new_i_size > bi->bi_size))
		bi->bi_size = h->new_i_size;
	bi->bi_sectors	+= h->sectors;
	bi->bi_flags	&= ~h->flags;
	bi->bi_mtime	= bi->bi_ctime = bch2_current_time(c);
	return 0;
}

static int i_sectors_dirty_finish(struct bch_fs *c, struct i_sectors_hook *h)
{
	int ret;

	mutex_lock(&h->inode->ei_update_lock);
	i_sectors_acct(c, h->inode, &h->quota_res, h->sectors);

	ret = bch2_write_inode(c, h->inode, i_sectors_dirty_finish_fn, h, 0);

	if (!ret && h->new_i_size != U64_MAX)
		i_size_write(&h->inode->v, h->new_i_size);
	mutex_unlock(&h->inode->ei_update_lock);

	bch2_quota_reservation_put(c, h->inode, &h->quota_res);

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
	ret = bch2_write_inode(c, h->inode, i_sectors_dirty_start_fn, h, 0);
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

		/* truncate in progress? */
		if (h->inode_u.bi_flags & BCH_INODE_I_SIZE_DIRTY)
			goto no_i_size_update;

		h->inode_u.bi_size = offset;
		do_pack = true;

		spin_lock(&inode->v.i_lock);
		if (offset > inode->v.i_size) {
			if (h->op->is_dio)
				i_size_write(&inode->v, offset);
			else
				BUG();
		}
		spin_unlock(&inode->v.i_lock);
	}
no_i_size_update:
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
	struct btree_trans trans;
	struct btree_iter *extent_iter, *inode_iter = NULL;
	struct bchfs_extent_trans_hook hook;
	struct bkey_i *k = bch2_keylist_front(keys);
	s64 orig_sectors_added = op->sectors_added;
	int ret;

	BUG_ON(k->k.p.inode != op->inode->v.i_ino);

	bch2_trans_init(&trans, wop->c);

	extent_iter = bch2_trans_get_iter(&trans,
				BTREE_ID_EXTENTS,
				bkey_start_pos(&bch2_keylist_front(keys)->k),
				BTREE_ITER_INTENT);
	BUG_ON(IS_ERR(extent_iter));

	hook.op			= op;
	hook.hook.fn		= bchfs_extent_update_hook;
	hook.need_inode_update	= false;

	do {
		/* XXX: inode->i_size locking */
		k = bch2_keylist_front(keys);
		if (min(k->k.p.offset << 9, op->new_i_size) >
		    op->inode->ei_inode.bi_size)
			hook.need_inode_update = true;

		/* optimization for fewer transaction restarts: */
		ret = bch2_btree_iter_traverse(extent_iter);
		if (ret)
			goto err;

		if (hook.need_inode_update) {
			struct bkey_s_c inode;

			if (!inode_iter) {
				inode_iter = bch2_trans_get_iter(&trans,
					BTREE_ID_INODES,
					POS(extent_iter->pos.inode, 0),
					BTREE_ITER_SLOTS|BTREE_ITER_INTENT);
				BUG_ON(IS_ERR(inode_iter));
			}

			inode = bch2_btree_iter_peek_slot(inode_iter);
			if ((ret = btree_iter_err(inode)))
				goto err;

			if (WARN_ONCE(inode.k->type != BCH_INODE_FS,
				      "inode %llu not found when updating",
				      extent_iter->pos.inode)) {
				ret = -ENOENT;
				break;
			}

			if (WARN_ONCE(bkey_bytes(inode.k) >
				      sizeof(hook.inode_p),
				      "inode %llu too big (%zu bytes, buf %zu)",
				      extent_iter->pos.inode,
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
				      ret, extent_iter->pos.inode)) {
				ret = -ENOENT;
				break;
			}

			ret = bch2_btree_insert_at(wop->c, &wop->res,
					&hook.hook, op_journal_seq(wop),
					BTREE_INSERT_NOFAIL|
					BTREE_INSERT_ATOMIC|
					BTREE_INSERT_USE_RESERVE,
					BTREE_INSERT_ENTRY(extent_iter, k),
					BTREE_INSERT_ENTRY_EXTRA_RES(inode_iter,
							&hook.inode_p.inode.k_i, 2));
		} else {
			ret = bch2_btree_insert_at(wop->c, &wop->res,
					&hook.hook, op_journal_seq(wop),
					BTREE_INSERT_NOFAIL|
					BTREE_INSERT_ATOMIC|
					BTREE_INSERT_NOUNLOCK|
					BTREE_INSERT_USE_RESERVE,
					BTREE_INSERT_ENTRY(extent_iter, k));
		}

		BUG_ON(bkey_cmp(extent_iter->pos, bkey_start_pos(&k->k)));

		if (WARN_ONCE(!ret != !k->k.size,
			      "ret %i k->size %u", ret, k->k.size))
			ret = k->k.size ? -EINTR : 0;
err:
		if (ret == -EINTR)
			continue;
		if (ret)
			break;

		if (hook.need_inode_update)
			op->inode->ei_inode = hook.inode_u;

		BUG_ON(bkey_cmp(extent_iter->pos, k->k.p) < 0);
		bch2_keylist_pop_front(keys);
	} while (!bch2_keylist_empty(keys));

	bch2_trans_exit(&trans);

	if (op->is_dio) {
		struct dio_write *dio = container_of(op, struct dio_write, iop);

		i_sectors_acct(wop->c, op->inode, &dio->quota_res,
			       op->sectors_added - orig_sectors_added);
	}

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

	bch2_write_op_init(&op->op, c, opts);
	op->op.target		= opts.foreground_target;
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
	/* existing data: */
	unsigned		sectors:PAGE_SECTOR_SHIFT + 1;
	unsigned		nr_replicas:4;
	unsigned		compressed:1;

	/* Owns PAGE_SECTORS sized reservation: */
	unsigned		reserved:1;
	unsigned		reservation_replicas:4;

	/* Owns PAGE_SECTORS sized quota reservation: */
	unsigned		quota_reserved:1;

	/*
	 * Number of sectors on disk - for i_blocks
	 * Uncompressed size, not compressed size:
	 */
	unsigned		dirty_sectors:PAGE_SECTOR_SHIFT + 1;
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

static inline unsigned page_res_sectors(struct bch_page_state s)
{

	return s.reserved ? s.reservation_replicas * PAGE_SECTORS : 0;
}

static void __bch2_put_page_reservation(struct bch_fs *c, struct bch_inode_info *inode,
					struct bch_page_state s)
{
	struct disk_reservation res = { .sectors = page_res_sectors(s) };
	struct quota_res quota_res = { .sectors = s.quota_reserved ? PAGE_SECTORS : 0 };

	bch2_quota_reservation_put(c, inode, &quota_res);
	bch2_disk_reservation_put(c, &res);
}

static void bch2_put_page_reservation(struct bch_fs *c, struct bch_inode_info *inode,
				      struct page *page)
{
	struct bch_page_state s;

	s = page_state_cmpxchg(page_state(page), s, {
		s.reserved		= 0;
		s.quota_reserved	= 0;
	});

	__bch2_put_page_reservation(c, inode, s);
}

static int bch2_get_page_reservation(struct bch_fs *c, struct bch_inode_info *inode,
				     struct page *page, bool check_enospc)
{
	struct bch_page_state *s = page_state(page), new, old;

	/* XXX: this should not be open coded */
	unsigned nr_replicas = inode->ei_inode.bi_data_replicas
		? inode->ei_inode.bi_data_replicas - 1
		: c->opts.data_replicas;

	struct disk_reservation disk_res = bch2_disk_reservation_init(c,
						nr_replicas);
	struct quota_res quota_res = { 0 };
	int ret = 0;

	/*
	 * XXX: this could likely be quite a bit simpler, page reservations
	 * _should_ only be manipulated with page locked:
	 */

	old = page_state_cmpxchg(s, new, {
		if (new.reserved
		    ? (new.reservation_replicas < disk_res.nr_replicas)
		    : (new.sectors < PAGE_SECTORS ||
		       new.nr_replicas < disk_res.nr_replicas ||
		       new.compressed)) {
			int sectors = (disk_res.nr_replicas * PAGE_SECTORS -
				       page_res_sectors(new) -
				       disk_res.sectors);

			if (sectors > 0) {
				ret = bch2_disk_reservation_add(c, &disk_res, sectors,
						!check_enospc
						? BCH_DISK_RESERVATION_NOFAIL : 0);
				if (unlikely(ret))
					goto err;
			}

			new.reserved = 1;
			new.reservation_replicas = disk_res.nr_replicas;
		}

		if (!new.quota_reserved &&
		    new.sectors + new.dirty_sectors < PAGE_SECTORS) {
			ret = bch2_quota_reservation_add(c, inode, &quota_res,
						PAGE_SECTORS - quota_res.sectors,
						check_enospc);
			if (unlikely(ret))
				goto err;

			new.quota_reserved = 1;
		}
	});

	quota_res.sectors -= (new.quota_reserved - old.quota_reserved) * PAGE_SECTORS;
	disk_res.sectors -= page_res_sectors(new) - page_res_sectors(old);
err:
	bch2_quota_reservation_put(c, inode, &quota_res);
	bch2_disk_reservation_put(c, &disk_res);
	return ret;
}

static void bch2_clear_page_bits(struct page *page)
{
	struct bch_inode_info *inode = to_bch_ei(page->mapping->host);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct bch_page_state s;

	if (!PagePrivate(page))
		return;

	s.v = xchg(&page_state(page)->v, 0);
	ClearPagePrivate(page);

	if (s.dirty_sectors)
		i_sectors_acct(c, inode, NULL, -s.dirty_sectors);

	__bch2_put_page_reservation(c, inode, s);
}

bool bch2_dirty_folio(struct address_space *mapping, struct folio *folio)
{
	struct bch_inode_info *inode = to_bch_ei(mapping->host);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct quota_res quota_res = { 0 };
	struct bch_page_state old, new;

	old = page_state_cmpxchg(page_state(&folio->page), new,
		new.dirty_sectors = PAGE_SECTORS - new.sectors;
		new.quota_reserved = 0;
	);

	quota_res.sectors += old.quota_reserved * PAGE_SECTORS;

	if (old.dirty_sectors != new.dirty_sectors)
		i_sectors_acct(c, inode, &quota_res,
			       new.dirty_sectors - old.dirty_sectors);
	bch2_quota_reservation_put(c, inode, &quota_res);

	return filemap_dirty_folio(mapping, folio);
}

vm_fault_t bch2_page_fault(struct vm_fault *vmf)
{
	struct file *file = vmf->vma->vm_file;
	struct bch_inode_info *inode = file_bch_inode(file);
	int ret;

	bch2_pagecache_add_get(&inode->ei_pagecache_lock);
	ret = filemap_fault(vmf);
	bch2_pagecache_add_put(&inode->ei_pagecache_lock);

	return ret;
}

vm_fault_t bch2_page_mkwrite(struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct file *file = vmf->vma->vm_file;
	struct bch_inode_info *inode = file_bch_inode(file);
	struct address_space *mapping = file->f_mapping;
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
	bch2_pagecache_add_get(&inode->ei_pagecache_lock);

	lock_page(page);
	if (page->mapping != mapping ||
	    page_offset(page) > i_size_read(&inode->v)) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}

	if (bch2_get_page_reservation(c, inode, page, true)) {
		unlock_page(page);
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	if (!PageDirty(page))
		set_page_dirty(page);
	wait_for_stable_page(page);
out:
	bch2_pagecache_add_put(&inode->ei_pagecache_lock);
	sb_end_pagefault(inode->v.i_sb);
	return ret;
}

void bch2_invalidate_folio(struct folio *folio, size_t offset, size_t length)
{
	EBUG_ON(!PageLocked(&folio->page));
	EBUG_ON(folio_test_writeback(folio));

	if (offset || length < folio_size(folio))
		return;

	bch2_clear_page_bits(&folio->page);
}

bool bch2_release_folio(struct folio *folio, gfp_t gfp_mask)
{
	/* XXX: this can't take locks that are held while we allocate memory */
	EBUG_ON(!PageLocked(&folio->page));
	EBUG_ON(folio_test_writeback(folio));

	if (folio_test_dirty(folio))
		return false;

	bch2_clear_page_bits(&folio->page);
	return true;
}

/* readpages/writepages: */

static bool bio_can_add_page_contig(struct bio *bio, struct page *page)
{
	sector_t offset = (sector_t) page->index << PAGE_SECTOR_SHIFT;

	return bio->bi_vcnt < bio->bi_max_vecs &&
		bio_end_sector(bio) == offset;
}

static int bio_add_page_contig(struct bio *bio, struct page *page)
{
	sector_t offset = (sector_t) page->index << PAGE_SECTOR_SHIFT;

	EBUG_ON(!bio->bi_max_vecs);

	if (!bio->bi_vcnt)
		bio->bi_iter.bi_sector = offset;
	else if (!bio_can_add_page_contig(bio, page))
		return -1;

	__bio_add_page(bio, page, PAGE_SIZE, 0);
	return 0;
}

/* readpage(s): */

static void bch2_readpages_end_io(struct bio *bio)
{
	struct bvec_iter_all iter;
	struct bio_vec bv;

	bio_for_each_segment_all(bv, bio, iter) {
		struct page *page = bv.bv_page;

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

static inline void page_state_init_for_read(struct page *page)
{
	struct bch_page_state *s = page_state(page);

	BUG_ON(s->reserved);
	s->sectors	= 0;
	s->compressed	= 0;
}

struct readpages_iter {
	struct address_space	*mapping;
	struct page		**pages;
	unsigned		nr_pages;
	unsigned		idx;
	pgoff_t			offset;
};

static int readpages_iter_init(struct readpages_iter *iter,
			       struct readahead_control *ractl)
{
	unsigned i, nr_pages = readahead_count(ractl);

	memset(iter, 0, sizeof(*iter));

	iter->mapping	= ractl->mapping;
	iter->offset	= readahead_index(ractl);
	iter->nr_pages	= nr_pages;

	iter->pages = kmalloc_array(nr_pages, sizeof(struct page *), GFP_NOFS);
	if (!iter->pages)
		return -ENOMEM;

	__readahead_batch(ractl, iter->pages, nr_pages);
	for (i = 0; i < nr_pages; i++) {
		put_page(iter->pages[i]);
	}

	return 0;
}

static inline struct page *readpage_iter_next(struct readpages_iter *iter)
{
	if (iter->idx >= iter->nr_pages)
		return NULL;

	EBUG_ON(iter->pages[iter->idx]->index != iter->offset + iter->idx);

	page_state_init_for_read(iter->pages[iter->idx]);
	return iter->pages[iter->idx];
}

static void bch2_add_page_sectors(struct bio *bio, struct bkey_s_c k)
{
	struct bvec_iter iter;
	struct bio_vec bv;
	bool compressed = bch2_extent_is_compressed(k);
	unsigned nr_ptrs = bch2_extent_nr_dirty_ptrs(k);

	bio_for_each_segment(bv, bio, iter) {
		struct bch_page_state *s = page_state(bv.bv_page);

		/* sectors in @k from the start of this page: */
		unsigned k_sectors = k.k->size - (iter.bi_sector - k.k->p.offset);

		unsigned page_sectors = min(bv.bv_len >> 9, k_sectors);

		s->nr_replicas = !s->sectors
			? nr_ptrs
			: min_t(unsigned, s->nr_replicas, nr_ptrs);

		BUG_ON(s->sectors + page_sectors > PAGE_SECTORS);
		s->sectors += page_sectors;

		s->compressed |= compressed;
	}
}

static void readpage_bio_extend(struct readpages_iter *iter,
				struct bio *bio, u64 offset,
				bool get_more)
{
	while (bio_end_sector(bio) < offset &&
	       bio->bi_vcnt < bio->bi_max_vecs) {
		pgoff_t page_offset = bio_end_sector(bio) >> PAGE_SECTOR_SHIFT;
		struct page *page = readpage_iter_next(iter);
		int ret;

		if (page) {
			if (iter->offset + iter->idx != page_offset)
				break;

			iter->idx++;
		} else {
			if (!get_more)
				break;

			page = xa_load(&iter->mapping->i_pages, page_offset);
			if (page && !xa_is_value(page))
				break;

			page = __page_cache_alloc(readahead_gfp_mask(iter->mapping));
			if (!page)
				break;

			page_state_init_for_read(page);

			ret = add_to_page_cache_lru(page, iter->mapping,
						    page_offset, GFP_NOFS);
			if (ret) {
				ClearPagePrivate(page);
				put_page(page);
				break;
			}

			put_page(page);
		}

		__bio_add_page(bio, page, PAGE_SIZE, 0);
	}
}

static void bchfs_read(struct bch_fs *c, struct btree_iter *iter,
		       struct bch_read_bio *rbio, u64 inum,
		       struct readpages_iter *readpages_iter)
{
	struct bio *bio = &rbio->bio;
	int flags = BCH_READ_RETRY_IF_STALE|
		BCH_READ_MAY_PROMOTE;

	rbio->c = c;
	rbio->start_time = local_clock();

	while (1) {
		BKEY_PADDED(k) tmp;
		struct bkey_s_c k;
		unsigned bytes;

		bch2_btree_iter_set_pos(iter, POS(inum, bio->bi_iter.bi_sector));

		k = bch2_btree_iter_peek_slot(iter);
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

		if (readpages_iter) {
			bool want_full_extent = false;

			if (bkey_extent_is_data(k.k)) {
				struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
				struct bch_extent_crc_unpacked crc;
				const union bch_extent_entry *i;

				extent_for_each_crc(e, crc, i)
					want_full_extent |= ((crc.csum_type != 0) |
							     (crc.compression_type != 0));
			}

			readpage_bio_extend(readpages_iter,
					    bio, k.k->p.offset,
					    want_full_extent);
		}

		bytes = (min_t(u64, k.k->p.offset, bio_end_sector(bio)) -
			 bio->bi_iter.bi_sector) << 9;
		swap(bio->bi_iter.bi_size, bytes);

		if (bytes == bio->bi_iter.bi_size)
			flags |= BCH_READ_LAST_FRAGMENT;

		if (bkey_extent_is_allocation(k.k))
			bch2_add_page_sectors(bio, k);

		bch2_read_extent(c, rbio, k, flags);

		if (flags & BCH_READ_LAST_FRAGMENT)
			return;

		swap(bio->bi_iter.bi_size, bytes);
		bio_advance(bio, bytes);
	}
}

void bch2_readahead(struct readahead_control *ractl)
{
	struct bch_inode_info *inode = to_bch_ei(ractl->mapping->host);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct bch_io_opts opts = io_opts(c, inode);
	struct btree_iter iter;
	struct page *page;
	struct readpages_iter readpages_iter;
	int ret;

	ret = readpages_iter_init(&readpages_iter, ractl);
	BUG_ON(ret);

	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN,
			     BTREE_ITER_SLOTS);

	bch2_pagecache_add_get(&inode->ei_pagecache_lock);

	while ((page = readpage_iter_next(&readpages_iter))) {
		pgoff_t index = readpages_iter.offset + readpages_iter.idx;
		unsigned n = min_t(unsigned,
				   readpages_iter.nr_pages -
				   readpages_iter.idx,
				   BIO_MAX_VECS);
		struct bch_read_bio *rbio =
			rbio_init(bio_alloc_bioset(NULL, n, REQ_OP_READ,
						   GFP_NOFS, &c->bio_read),
				  opts);

		readpages_iter.idx++;

		rbio->bio.bi_iter.bi_sector = (sector_t) index << PAGE_SECTOR_SHIFT;
		rbio->bio.bi_end_io = bch2_readpages_end_io;
		__bio_add_page(&rbio->bio, page, PAGE_SIZE, 0);

		bchfs_read(c, &iter, rbio, inode->v.i_ino, &readpages_iter);
	}

	bch2_pagecache_add_put(&inode->ei_pagecache_lock);
	kfree(readpages_iter.pages);
}

static void __bchfs_readpage(struct bch_fs *c, struct bch_read_bio *rbio,
			     u64 inum, struct page *page)
{
	struct btree_iter iter;

	page_state_init_for_read(page);

	rbio->bio.bi_opf = REQ_OP_READ|REQ_SYNC;
	bio_add_page_contig(&rbio->bio, page);

	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN,
			     BTREE_ITER_SLOTS);
	bchfs_read(c, &iter, rbio, inum, NULL);
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

	rbio = rbio_init(bio_alloc_bioset(NULL, 1, REQ_OP_READ, GFP_NOFS, &c->bio_read),
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

int bch2_read_folio(struct file *file, struct folio *folio)
{
	struct page *page = &folio->page;
	int ret;

	ret = bch2_read_single_page(page, page->mapping);
	folio_unlock(folio);
	return ret;
}

/* writepages: */

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
	struct bvec_iter_all iter;
	struct bio_vec bvec;

	if (io->op.op.error) {
		bio_for_each_segment_all(bvec, bio, iter)
			SetPageError(bvec.bv_page);
		set_bit(AS_EIO, &io->op.inode->v.i_mapping->flags);
	}

	/*
	 * racing with fallocate can cause us to add fewer sectors than
	 * expected - but we shouldn't add more sectors than expected:
	 */
	BUG_ON(io->op.sectors_added > (s64) io->new_sectors);

	/*
	 * (error (due to going RO) halfway through a page can screw that up
	 * slightly)
	 * XXX wtf?
	   BUG_ON(io->op.sectors_added - io->new_sectors >= (s64) PAGE_SECTORS);
	 */

	/*
	 * PageWriteback is effectively our ref on the inode - fixup i_blocks
	 * before calling end_page_writeback:
	 */
	if (io->op.sectors_added != io->new_sectors)
		i_sectors_acct(c, io->op.inode, NULL,
			       io->op.sectors_added - (s64) io->new_sectors);

	bio_for_each_segment_all(bvec, bio, iter)
		end_page_writeback(bvec.bv_page);

	closure_return_with_destructor(&io->cl, bch2_writepage_io_free);
}

static void bch2_writepage_do_io(struct bch_writepage_state *w)
{
	struct bch_writepage_io *io = w->io;

	w->io = NULL;
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
				    unsigned nr_replicas)
{
	struct bch_write_op *op;
	u64 offset = (u64) page->index << PAGE_SECTOR_SHIFT;

	w->io = container_of(bio_alloc_bioset(NULL, BIO_MAX_VECS,
					      REQ_OP_WRITE,
					      GFP_NOFS,
					      &c->writepage_bioset),
			     struct bch_writepage_io, op.op.wbio.bio);

	closure_init(&w->io->cl, NULL);
	w->io->new_sectors	= 0;
	bch2_fswrite_op_init(&w->io->op, c, inode, w->opts, false);
	op			= &w->io->op.op;
	op->nr_replicas		= nr_replicas;
	op->res.nr_replicas	= nr_replicas;
	op->write_point		= writepoint_hashed(inode->ei_last_dirtied);
	op->pos			= POS(inode->v.i_ino, offset);
	op->wbio.bio.bi_iter.bi_sector = offset;
}

static int __bch2_writepage(struct folio *folio,
			    struct writeback_control *wbc,
			    void *data)
{
	struct page *page = &folio->page;
	struct bch_inode_info *inode = to_bch_ei(page->mapping->host);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct bch_writepage_state *w = data;
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
			new.compressed));

		if (new.reserved)
			new.nr_replicas = new.reservation_replicas;
		new.reserved = 0;

		new.compressed |= w->opts.compression != 0;

		new.sectors += new.dirty_sectors;
		new.dirty_sectors = 0;
	});

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);

	if (w->io &&
	    (w->io->op.op.res.nr_replicas != new.nr_replicas ||
	     !bio_can_add_page_contig(&w->io->op.op.wbio.bio, page)))
		bch2_writepage_do_io(w);

	if (!w->io)
		bch2_writepage_io_alloc(c, w, inode, page, new.nr_replicas);

	w->io->new_sectors += new.sectors - old.sectors;

	BUG_ON(inode != w->io->op.inode);
	BUG_ON(bio_add_page_contig(&w->io->op.op.wbio.bio, page));

	if (old.reserved)
		w->io->op.op.res.sectors += old.reservation_replicas * PAGE_SECTORS;

	w->io->op.new_i_size = i_size;

	if (wbc->sync_mode == WB_SYNC_ALL)
		w->io->op.op.wbio.bio.bi_opf |= REQ_SYNC;

	return 0;
}

int bch2_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	struct bch_fs *c = mapping->host->i_sb->s_fs_info;
	struct bch_writepage_state w =
		bch_writepage_state_init(c, to_bch_ei(mapping->host));
	struct blk_plug plug;
	int ret;

	blk_start_plug(&plug);
	ret = write_cache_pages(mapping, wbc, __bch2_writepage, &w);
	if (w.io)
		bch2_writepage_do_io(&w);
	blk_finish_plug(&plug);
	return ret;
}

int bch2_writepage(struct page *page, struct writeback_control *wbc)
{
	struct bch_fs *c = page->mapping->host->i_sb->s_fs_info;
	struct bch_writepage_state w =
		bch_writepage_state_init(c, to_bch_ei(page->mapping->host));
	int ret;

	ret = __bch2_writepage(page_folio(page), wbc, &w);
	if (w.io)
		bch2_writepage_do_io(&w);

	return ret;
}

/* buffered writes: */

int bch2_write_begin(struct file *file, struct address_space *mapping,
		     loff_t pos, unsigned len,
		     struct page **pagep, void **fsdata)
{
	struct bch_inode_info *inode = to_bch_ei(mapping->host);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	pgoff_t index = pos >> PAGE_SHIFT;
	unsigned offset = pos & (PAGE_SIZE - 1);
	struct page *page;
	int ret = -ENOMEM;

	BUG_ON(inode_unhashed(&inode->v));

	bch2_pagecache_add_get(&inode->ei_pagecache_lock);

	page = grab_cache_page_write_begin(mapping, index);
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
	ret = bch2_get_page_reservation(c, inode, page, true);
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
	bch2_pagecache_add_put(&inode->ei_pagecache_lock);
	return ret;
}

int bch2_write_end(struct file *file, struct address_space *mapping,
		   loff_t pos, unsigned len, unsigned copied,
		   struct page *page, void *fsdata)
{
	struct bch_inode_info *inode = to_bch_ei(mapping->host);
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

	spin_lock(&inode->v.i_lock);
	if (pos + copied > inode->v.i_size)
		i_size_write(&inode->v, pos + copied);
	spin_unlock(&inode->v.i_lock);

	if (copied) {
		if (!PageUptodate(page))
			SetPageUptodate(page);
		if (!PageDirty(page))
			set_page_dirty(page);

		inode->ei_last_dirtied = (unsigned long) current;
	} else {
		bch2_put_page_reservation(c, inode, page);
	}

	unlock_page(page);
	put_page(page);
	bch2_pagecache_add_put(&inode->ei_pagecache_lock);

	return copied;
}

#define WRITE_BATCH_PAGES	32

static int __bch2_buffered_write(struct bch_inode_info *inode,
				 struct address_space *mapping,
				 struct iov_iter *iter,
				 loff_t pos, unsigned len)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct page *pages[WRITE_BATCH_PAGES];
	unsigned long index = pos >> PAGE_SHIFT;
	unsigned offset = pos & (PAGE_SIZE - 1);
	unsigned nr_pages = DIV_ROUND_UP(offset + len, PAGE_SIZE);
	unsigned i, copied = 0, nr_pages_copied = 0;
	int ret = 0;

	BUG_ON(!len);
	BUG_ON(nr_pages > ARRAY_SIZE(pages));

	for (i = 0; i < nr_pages; i++) {
		pages[i] = grab_cache_page_write_begin(mapping, index + i);
		if (!pages[i]) {
			nr_pages = i;
			ret = -ENOMEM;
			goto out;
		}
	}

	if (offset && !PageUptodate(pages[0])) {
		ret = bch2_read_single_page(pages[0], mapping);
		if (ret)
			goto out;
	}

	if ((pos + len) & (PAGE_SIZE - 1) &&
	    !PageUptodate(pages[nr_pages - 1])) {
		if ((index + nr_pages - 1) << PAGE_SHIFT >= inode->v.i_size) {
			zero_user(pages[nr_pages - 1], 0, PAGE_SIZE);
		} else {
			ret = bch2_read_single_page(pages[nr_pages - 1], mapping);
			if (ret)
				goto out;
		}
	}

	for (i = 0; i < nr_pages; i++) {
		ret = bch2_get_page_reservation(c, inode, pages[i], true);

		if (ret && !PageUptodate(pages[i])) {
			ret = bch2_read_single_page(pages[i], mapping);
			if (ret)
				goto out;

			ret = bch2_get_page_reservation(c, inode, pages[i], true);
		}

		if (ret)
			goto out;
	}

	if (mapping_writably_mapped(mapping))
		for (i = 0; i < nr_pages; i++)
			flush_dcache_page(pages[i]);

	while (copied < len) {
		struct page *page = pages[(offset + copied) >> PAGE_SHIFT];
		unsigned pg_offset = (offset + copied) & (PAGE_SIZE - 1);
		unsigned pg_bytes = min_t(unsigned, len - copied,
					  PAGE_SIZE - pg_offset);
		unsigned pg_copied = copy_page_from_iter_atomic(page,
						pg_offset, pg_bytes, iter);

		flush_dcache_page(page);
		copied += pg_copied;

		if (pg_copied != pg_bytes)
			break;
	}

	if (!copied)
		goto out;

	nr_pages_copied = DIV_ROUND_UP(offset + copied, PAGE_SIZE);
	inode->ei_last_dirtied = (unsigned long) current;

	spin_lock(&inode->v.i_lock);
	if (pos + copied > inode->v.i_size)
		i_size_write(&inode->v, pos + copied);
	spin_unlock(&inode->v.i_lock);

	if (copied < len &&
	    ((offset + copied) & (PAGE_SIZE - 1))) {
		struct page *page = pages[(offset + copied) >> PAGE_SHIFT];

		if (!PageUptodate(page)) {
			zero_user(page, 0, PAGE_SIZE);
			copied -= (offset + copied) & (PAGE_SIZE - 1);
		}
	}
out:
	for (i = 0; i < nr_pages_copied; i++) {
		if (!PageUptodate(pages[i]))
			SetPageUptodate(pages[i]);
		if (!PageDirty(pages[i]))
			set_page_dirty(pages[i]);
		unlock_page(pages[i]);
		put_page(pages[i]);
	}

	for (i = nr_pages_copied; i < nr_pages; i++) {
		if (!PageDirty(pages[i]))
			bch2_put_page_reservation(c, inode, pages[i]);
		unlock_page(pages[i]);
		put_page(pages[i]);
	}

	return copied ?: ret;
}

static ssize_t bch2_buffered_write(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct bch_inode_info *inode = file_bch_inode(file);
	loff_t pos = iocb->ki_pos;
	ssize_t written = 0;
	int ret = 0;

	bch2_pagecache_add_get(&inode->ei_pagecache_lock);

	do {
		unsigned offset = pos & (PAGE_SIZE - 1);
		unsigned bytes = min_t(unsigned long, iov_iter_count(iter),
			      PAGE_SIZE * WRITE_BATCH_PAGES - offset);
again:
		/*
		 * Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the
		 * same page as we're writing to, without it being marked
		 * up-to-date.
		 *
		 * Not only is this an optimisation, but it is also required
		 * to check that the address is actually valid, when atomic
		 * usercopies are used, below.
		 */
		if (unlikely(fault_in_iov_iter_readable(iter, bytes))) {
			bytes = min_t(unsigned long, iov_iter_count(iter),
				      PAGE_SIZE - offset);

			if (unlikely(fault_in_iov_iter_readable(iter, bytes))) {
				ret = -EFAULT;
				break;
			}
		}

		if (unlikely(fatal_signal_pending(current))) {
			ret = -EINTR;
			break;
		}

		ret = __bch2_buffered_write(inode, mapping, iter, pos, bytes);
		if (unlikely(ret < 0))
			break;

		cond_resched();

		if (unlikely(ret == 0)) {
			/*
			 * If we were unable to copy any data at all, we must
			 * fall back to a single segment length write.
			 *
			 * If we didn't fallback here, we could livelock
			 * because not all segments in the iov can be copied at
			 * once without a pagefault.
			 */
			bytes = min_t(unsigned long, PAGE_SIZE - offset,
				      iov_iter_single_seg_count(iter));
			goto again;
		}
		pos += ret;
		written += ret;

		balance_dirty_pages_ratelimited(mapping);
	} while (iov_iter_count(iter));

	bch2_pagecache_add_put(&inode->ei_pagecache_lock);

	return written ? written : ret;
}

/* O_DIRECT reads */

static void bch2_dio_read_complete(struct closure *cl)
{
	struct dio_read *dio = container_of(cl, struct dio_read, cl);

	dio->req->ki_complete(dio->req, dio->ret);
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

static int bch2_direct_IO_read(struct kiocb *req, struct iov_iter *iter)
{
	struct file *file = req->ki_filp;
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct bch_io_opts opts = io_opts(c, inode);
	struct dio_read *dio;
	struct bio *bio;
	loff_t offset = req->ki_pos;
	bool sync = is_sync_kiocb(req);
	size_t shorten;
	ssize_t ret;

	if ((offset|iter->count) & (block_bytes(c) - 1))
		return -EINVAL;

	ret = min_t(loff_t, iter->count,
		    max_t(loff_t, 0, i_size_read(&inode->v) - offset));

	if (!ret)
		return ret;

	shorten = iov_iter_count(iter) - round_up(ret, block_bytes(c));
	iter->count -= shorten;

	bio = bio_alloc_bioset(NULL,
			       iov_iter_npages(iter, BIO_MAX_VECS),
			       REQ_OP_READ,
			       GFP_KERNEL,
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
		bio = bio_alloc_bioset(NULL,
				       iov_iter_npages(iter, BIO_MAX_VECS),
				       REQ_OP_READ,
				       GFP_KERNEL,
				       &c->bio_read);
		bio->bi_end_io		= bch2_direct_IO_read_split_endio;
start:
		bio->bi_opf		= REQ_OP_READ|REQ_SYNC;
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

	iter->count += shorten;

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

ssize_t bch2_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct bch_inode_info *inode = file_bch_inode(file);
	struct address_space *mapping = file->f_mapping;
	size_t count = iov_iter_count(iter);
	ssize_t ret;

	if (!count)
		return 0; /* skip atime */

	if (iocb->ki_flags & IOCB_DIRECT) {
		struct blk_plug plug;

		ret = filemap_write_and_wait_range(mapping,
					iocb->ki_pos,
					iocb->ki_pos + count - 1);
		if (ret < 0)
			return ret;

		file_accessed(file);

		blk_start_plug(&plug);
		ret = bch2_direct_IO_read(iocb, iter);
		blk_finish_plug(&plug);

		if (ret >= 0)
			iocb->ki_pos += ret;
	} else {
		bch2_pagecache_add_get(&inode->ei_pagecache_lock);
		ret = generic_file_read_iter(iocb, iter);
		bch2_pagecache_add_put(&inode->ei_pagecache_lock);
	}

	return ret;
}

/* O_DIRECT writes */

static void bch2_dio_write_loop_async(struct closure *);

static long bch2_dio_write_loop(struct dio_write *dio)
{
	struct kiocb *req = dio->req;
	struct address_space *mapping = req->ki_filp->f_mapping;
	struct bch_inode_info *inode = dio->iop.inode;
	struct bio *bio = &dio->iop.op.wbio.bio;
	struct bvec_iter_all iter;
	struct bio_vec bv;
	bool sync;
	long ret;

	if (dio->loop)
		goto loop;

	inode_dio_begin(&inode->v);
	bch2_pagecache_block_get(&inode->ei_pagecache_lock);

	/* Write and invalidate pagecache range that we're writing to: */
	ret = write_invalidate_inode_pages_range(mapping, req->ki_pos,
				req->ki_pos + iov_iter_count(&dio->iter) - 1);
	if (unlikely(ret))
		goto err;

	while (1) {
		if (current != dio->task)
			kthread_use_mm(dio->task->mm);
		BUG_ON(current->faults_disabled_mapping);
		current->faults_disabled_mapping = mapping;

		ret = bio_iov_iter_get_pages(bio, &dio->iter);

		current->faults_disabled_mapping = NULL;
		if (current != dio->task)
			kthread_unuse_mm(dio->task->mm);

		if (unlikely(ret < 0))
			goto err;

		/* gup might have faulted pages back in: */
		ret = write_invalidate_inode_pages_range(mapping,
				req->ki_pos + (dio->iop.op.written << 9),
				req->ki_pos + iov_iter_count(&dio->iter) - 1);
		if (unlikely(ret))
			goto err;

		dio->iop.op.pos = POS(inode->v.i_ino,
				(req->ki_pos >> 9) + dio->iop.op.written);

		task_io_account_write(bio->bi_iter.bi_size);

		closure_call(&dio->iop.op.cl, bch2_write, NULL, &dio->cl);

		if (!dio->sync && !dio->loop && dio->iter.count) {
			struct iovec *iov = dio->inline_vecs;

			if (dio->iter.nr_segs > ARRAY_SIZE(dio->inline_vecs)) {
				iov = kmalloc(dio->iter.nr_segs * sizeof(*iov),
					      GFP_KERNEL);
				if (unlikely(!iov)) {
					dio->iop.op.error = -ENOMEM;
					goto err_wait_io;
				}

				dio->free_iov = true;
			}

			memcpy(iov, dio->iter.iov, dio->iter.nr_segs * sizeof(*iov));
			dio->iter.iov = iov;
		}
err_wait_io:
		dio->loop = true;

		if (!dio->sync) {
			continue_at(&dio->cl, bch2_dio_write_loop_async, NULL);
			return -EIOCBQUEUED;
		}

		closure_sync(&dio->cl);
loop:
		bio_for_each_segment_all(bv, bio, iter)
			put_page(bv.bv_page);
		if (!dio->iter.count || dio->iop.op.error)
			break;
		bio_reset(bio, NULL, REQ_OP_WRITE);
	}

	ret = dio->iop.op.error ?: ((long) dio->iop.op.written << 9);
err:
	bch2_pagecache_block_put(&inode->ei_pagecache_lock);
	bch2_disk_reservation_put(dio->iop.op.c, &dio->iop.op.res);
	bch2_quota_reservation_put(dio->iop.op.c, inode, &dio->quota_res);

	if (dio->free_iov)
		kfree(dio->iter.iov);

	closure_debug_destroy(&dio->cl);

	sync = dio->sync;
	bio_put(bio);

	/* inode->i_dio_count is our ref on inode and thus bch_fs */
	inode_dio_end(&inode->v);

	if (!sync) {
		req->ki_complete(req, ret);
		ret = -EIOCBQUEUED;
	}
	return ret;
}

static void bch2_dio_write_loop_async(struct closure *cl)
{
	struct dio_write *dio = container_of(cl, struct dio_write, cl);

	bch2_dio_write_loop(dio);
}

static noinline
ssize_t bch2_direct_write(struct kiocb *req, struct iov_iter *iter)
{
	struct file *file = req->ki_filp;
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct dio_write *dio;
	struct bio *bio;
	loff_t offset = req->ki_pos;
	ssize_t ret;

	lockdep_assert_held(&inode->v.i_rwsem);

	if (unlikely(!iter->count))
		return 0;

	if (unlikely((offset|iter->count) & (block_bytes(c) - 1)))
		return -EINVAL;

	bio = bio_alloc_bioset(NULL,
			       iov_iter_npages(iter, BIO_MAX_VECS),
			       REQ_OP_WRITE,
			       GFP_KERNEL,
			       &c->dio_write_bioset);
	dio = container_of(bio, struct dio_write, iop.op.wbio.bio);
	closure_init(&dio->cl, NULL);
	dio->req		= req;
	dio->task		= current;
	dio->loop		= false;
	dio->sync		= is_sync_kiocb(req) ||
		offset + iter->count > inode->v.i_size;
	dio->free_iov		= false;
	dio->quota_res.sectors	= 0;
	dio->iter		= *iter;
	bch2_fswrite_op_init(&dio->iop, c, inode, io_opts(c, inode), true);
	dio->iop.op.write_point	= writepoint_hashed((unsigned long) dio->task);
	dio->iop.op.flags |= BCH_WRITE_NOPUT_RESERVATION;

	if ((req->ki_flags & IOCB_DSYNC) &&
	    !c->opts.journal_flush_disabled)
		dio->iop.op.flags |= BCH_WRITE_FLUSH;

	ret = bch2_quota_reservation_add(c, inode, &dio->quota_res,
					 iter->count >> 9, true);
	if (unlikely(ret))
		goto err;

	ret = bch2_disk_reservation_get(c, &dio->iop.op.res, iter->count >> 9,
					dio->iop.op.opts.data_replicas, 0);
	if (unlikely(ret)) {
		if (bch2_check_range_allocated(c, POS(inode->v.i_ino,
						      offset >> 9),
					       iter->count >> 9))
			goto err;

		dio->iop.unalloc = true;
	}

	dio->iop.op.nr_replicas	= dio->iop.op.res.nr_replicas;

	return bch2_dio_write_loop(dio);
err:
	bch2_disk_reservation_put(c, &dio->iop.op.res);
	bch2_quota_reservation_put(c, inode, &dio->quota_res);
	closure_debug_destroy(&dio->cl);
	bio_put(bio);
	return ret;
}

static ssize_t __bch2_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct bch_inode_info *inode = file_bch_inode(file);
	ssize_t	ret;

	if (iocb->ki_flags & IOCB_DIRECT)
		return bch2_direct_write(iocb, from);

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
		: bch2_buffered_write(iocb, from);

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

/* fsync: */

int bch2_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	int ret;

	ret = file_write_and_wait_range(file, start, end);
	if (ret)
		return ret;

	if (datasync && !(inode->v.i_state & I_DIRTY_DATASYNC))
		goto out;

	ret = sync_inode_metadata(&inode->v, 1);
	if (ret)
		return ret;
out:
	if (c->opts.journal_flush_disabled)
		return 0;

	return bch2_journal_flush_seq(&c->journal, inode->ei_journal_seq);
}

/* truncate: */

static inline int range_has_data(struct bch_fs *c,
				  struct bpos start,
				  struct bpos end)
{

	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
			   start, 0, k) {
		if (bkey_cmp(bkey_start_pos(k.k), end) >= 0)
			break;

		if (bkey_extent_is_data(k.k)) {
			ret = 1;
			break;
		}
	}

	return bch2_btree_iter_unlock(&iter) ?: ret;
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
		/*
		 * XXX: we're doing two index lookups when we end up reading the
		 * page
		 */
		ret = range_has_data(c,
				POS(inode->v.i_ino, index << PAGE_SECTOR_SHIFT),
				POS(inode->v.i_ino, (index + 1) << PAGE_SECTOR_SHIFT));
		if (ret <= 0)
			return ret;

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
	ret = bch2_get_page_reservation(c, inode, page, false);
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

static int bch2_extend(struct bch_inode_info *inode, struct iattr *iattr)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct address_space *mapping = inode->v.i_mapping;
	int ret;

	ret = filemap_write_and_wait_range(mapping,
			inode->ei_inode.bi_size, S64_MAX);
	if (ret)
		return ret;

	truncate_setsize(&inode->v, iattr->ia_size);
	/* ATTR_MODE will never be set here, ns argument isn't needed: */
	setattr_copy(NULL, &inode->v, iattr);

	mutex_lock(&inode->ei_update_lock);
	ret = bch2_write_inode_size(c, inode, inode->v.i_size,
				    ATTR_MTIME|ATTR_CTIME);
	mutex_unlock(&inode->ei_update_lock);

	return ret;
}

int bch2_truncate(struct bch_inode_info *inode, struct iattr *iattr)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct address_space *mapping = inode->v.i_mapping;
	struct i_sectors_hook i_sectors_hook =
		i_sectors_hook_init(inode, BCH_INODE_I_SIZE_DIRTY);
	bool shrink;
	int ret = 0;

	inode_dio_wait(&inode->v);
	bch2_pagecache_block_get(&inode->ei_pagecache_lock);

	BUG_ON(inode->v.i_size < inode->ei_inode.bi_size);

	shrink = iattr->ia_size <= inode->v.i_size;

	if (!shrink) {
		ret = bch2_extend(inode, iattr);
		goto err_put_pagecache;
	}

	ret = bch2_truncate_page(inode, iattr->ia_size);
	if (unlikely(ret))
		goto err_put_pagecache;

	if (iattr->ia_size > inode->ei_inode.bi_size)
		ret = filemap_write_and_wait_range(mapping,
				inode->ei_inode.bi_size,
				iattr->ia_size - 1);
	else if (iattr->ia_size & (PAGE_SIZE - 1))
		ret = filemap_write_and_wait_range(mapping,
				round_down(iattr->ia_size, PAGE_SIZE),
				iattr->ia_size - 1);
	if (ret)
		goto err_put_pagecache;

	i_sectors_hook.new_i_size = iattr->ia_size;

	ret = i_sectors_dirty_start(c, &i_sectors_hook);
	if (unlikely(ret))
		goto err_put_pagecache;

	truncate_setsize(&inode->v, iattr->ia_size);

	ret = bch2_inode_truncate(c, inode->v.i_ino,
				  round_up(iattr->ia_size, PAGE_SIZE) >> 9,
				  &i_sectors_hook.hook,
				  &inode->ei_journal_seq);
	if (unlikely(ret))
		goto err_put_sectors_dirty;

	/* ATTR_MODE will never be set here, ns argument isn't needed: */
	setattr_copy(NULL, &inode->v, iattr);
out:
	ret = i_sectors_dirty_finish(c, &i_sectors_hook) ?: ret;
err_put_pagecache:
	bch2_pagecache_block_put(&inode->ei_pagecache_lock);
	return ret;
err_put_sectors_dirty:
	/*
	 * On error - in particular, bch2_truncate_page() error - don't clear
	 * I_SIZE_DIRTY, as we've left data above i_size!:
	 */
	i_sectors_hook.flags &= ~BCH_INODE_I_SIZE_DIRTY;
	goto out;
}

/* fallocate: */

static long bch2_fpunch(struct bch_inode_info *inode, loff_t offset, loff_t len)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	u64 ino = inode->v.i_ino;
	u64 discard_start = round_up(offset, PAGE_SIZE) >> 9;
	u64 discard_end = round_down(offset + len, PAGE_SIZE) >> 9;
	int ret = 0;

	inode_lock(&inode->v);
	inode_dio_wait(&inode->v);
	bch2_pagecache_block_get(&inode->ei_pagecache_lock);

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
		/*
		 * We need to pass in a disk reservation here because we might
		 * be splitting a compressed extent into two. This isn't a
		 * problem with truncate because truncate will never split an
		 * extent, only truncate it...
		 */
		struct disk_reservation disk_res =
			bch2_disk_reservation_init(c, 0);
		struct i_sectors_hook i_sectors_hook =
			i_sectors_hook_init(inode, 0);
		int ret;

		ret = i_sectors_dirty_start(c, &i_sectors_hook);
		if (unlikely(ret))
			goto err;

		ret = bch2_btree_delete_range(c,
				BTREE_ID_EXTENTS,
				POS(ino, discard_start),
				POS(ino, discard_end),
				ZERO_VERSION,
				&disk_res,
				&i_sectors_hook.hook,
				&inode->ei_journal_seq);

		ret = i_sectors_dirty_finish(c, &i_sectors_hook) ?: ret;
	}
err:
	bch2_pagecache_block_put(&inode->ei_pagecache_lock);
	inode_unlock(&inode->v);

	return ret;
}

static long bch2_fcollapse(struct bch_inode_info *inode,
			   loff_t offset, loff_t len)
{
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct address_space *mapping = inode->v.i_mapping;
	struct btree_trans trans;
	struct btree_iter *src, *dst;
	BKEY_PADDED(k) copy;
	struct bkey_s_c k;
	struct i_sectors_hook i_sectors_hook = i_sectors_hook_init(inode, 0);
	loff_t new_size;
	int ret;

	if ((offset | len) & (block_bytes(c) - 1))
		return -EINVAL;

	bch2_trans_init(&trans, c);

	dst = bch2_trans_get_iter(&trans, BTREE_ID_EXTENTS,
			     POS(inode->v.i_ino, offset >> 9),
			     BTREE_ITER_SLOTS|BTREE_ITER_INTENT);
	BUG_ON(IS_ERR(dst));

	/* position will be set from dst iter's position: */
	src = bch2_trans_get_iter(&trans, BTREE_ID_EXTENTS, POS_MIN,
			     BTREE_ITER_SLOTS);
	BUG_ON(IS_ERR(src));

	/*
	 * We need i_mutex to keep the page cache consistent with the extents
	 * btree, and the btree consistent with i_size - we don't need outside
	 * locking for the extents btree itself, because we're using linked
	 * iterators
	 */
	inode_lock(&inode->v);
	inode_dio_wait(&inode->v);
	bch2_pagecache_block_get(&inode->ei_pagecache_lock);

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

	while (bkey_cmp(dst->pos,
			POS(inode->v.i_ino,
			    round_up(new_size, PAGE_SIZE) >> 9)) < 0) {
		struct disk_reservation disk_res;

		bch2_btree_iter_set_pos(src,
			POS(dst->pos.inode, dst->pos.offset + (len >> 9)));

		k = bch2_btree_iter_peek_slot(src);
		if ((ret = btree_iter_err(k)))
			goto btree_iter_err;

		bkey_reassemble(&copy.k, k);

		bch2_cut_front(src->pos, &copy.k);
		copy.k.k.p.offset -= len >> 9;

		BUG_ON(bkey_cmp(dst->pos, bkey_start_pos(&copy.k.k)));

		ret = bch2_disk_reservation_get(c, &disk_res, copy.k.k.size,
				bch2_extent_nr_dirty_ptrs(bkey_i_to_s_c(&copy.k)),
				BCH_DISK_RESERVATION_NOFAIL);
		BUG_ON(ret);

		ret = bch2_btree_insert_at(c, &disk_res, &i_sectors_hook.hook,
					   &inode->ei_journal_seq,
					   BTREE_INSERT_ATOMIC|
					   BTREE_INSERT_NOFAIL,
					   BTREE_INSERT_ENTRY(dst, &copy.k));
		bch2_disk_reservation_put(c, &disk_res);
btree_iter_err:
		if (ret == -EINTR)
			ret = 0;
		if (ret) {
			bch2_trans_exit(&trans);
			goto err_put_sectors_dirty;
		}
		/*
		 * XXX: if we error here we've left data with multiple
		 * pointers... which isn't a _super_ serious problem...
		 */

		bch2_btree_iter_cond_resched(src);
	}

	bch2_trans_exit(&trans);

	ret = bch2_inode_truncate(c, inode->v.i_ino,
				 round_up(new_size, block_bytes(c)) >> 9,
				 &i_sectors_hook.hook,
				 &inode->ei_journal_seq);
	if (ret)
		goto err_put_sectors_dirty;

	i_sectors_hook.new_i_size = new_size;
err_put_sectors_dirty:
	ret = i_sectors_dirty_finish(c, &i_sectors_hook) ?: ret;
err:
	bch2_pagecache_block_put(&inode->ei_pagecache_lock);
	inode_unlock(&inode->v);
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
	unsigned replicas = io_opts(c, inode).data_replicas;
	int ret;

	bch2_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN,
			     BTREE_ITER_SLOTS|BTREE_ITER_INTENT);

	inode_lock(&inode->v);
	inode_dio_wait(&inode->v);
	bch2_pagecache_block_get(&inode->ei_pagecache_lock);

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

		k = bch2_btree_iter_peek_slot(&iter);
		if ((ret = btree_iter_err(k)))
			goto btree_iter_err;

		/* already reserved */
		if (k.k->type == BCH_RESERVATION &&
		    bkey_s_c_to_reservation(k).v->nr_replicas >= replicas) {
			bch2_btree_iter_next_slot(&iter);
			continue;
		}

		if (bkey_extent_is_data(k.k)) {
			if (!(mode & FALLOC_FL_ZERO_RANGE)) {
				bch2_btree_iter_next_slot(&iter);
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

		if (!bkey_extent_is_allocation(k.k)) {
			ret = bch2_quota_reservation_add(c, inode,
					&i_sectors_hook.quota_res,
					sectors, true);
			if (unlikely(ret))
				goto btree_iter_err;
		}

		if (reservation.v.nr_replicas < replicas ||
		    bch2_extent_is_compressed(k)) {
			ret = bch2_disk_reservation_get(c, &disk_res, sectors,
							replicas, 0);
			if (unlikely(ret))
				goto btree_iter_err;

			reservation.v.nr_replicas = disk_res.nr_replicas;
		}

		ret = bch2_btree_insert_at(c, &disk_res, &i_sectors_hook.hook,
					  &inode->ei_journal_seq,
					  BTREE_INSERT_ATOMIC|
					  BTREE_INSERT_NOFAIL,
					  BTREE_INSERT_ENTRY(&iter, &reservation.k_i));
		bch2_disk_reservation_put(c, &disk_res);
btree_iter_err:
		if (ret == -EINTR)
			ret = 0;
		if (ret) {
			bch2_btree_iter_unlock(&iter);
			goto err_put_sectors_dirty;
		}

	}
	bch2_btree_iter_unlock(&iter);

	ret = i_sectors_dirty_finish(c, &i_sectors_hook) ?: ret;

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    end > inode->v.i_size) {
		i_size_write(&inode->v, end);

		mutex_lock(&inode->ei_update_lock);
		ret = bch2_write_inode_size(c, inode, inode->v.i_size, 0);
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
			ret = bch2_write_inode_size(c, inode,
						    inode->v.i_size, 0);
			mutex_unlock(&inode->ei_update_lock);
		}
	}

	bch2_pagecache_block_put(&inode->ei_pagecache_lock);
	inode_unlock(&inode->v);

	return 0;
err_put_sectors_dirty:
	ret = i_sectors_dirty_finish(c, &i_sectors_hook) ?: ret;
err:
	bch2_pagecache_block_put(&inode->ei_pagecache_lock);
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

/* fseek: */

static bool folio_is_data(struct folio *folio)
{
	/* XXX: should only have to check PageDirty */
	return folio_test_private(folio) &&
		(page_state(&folio->page)->sectors ||
		 page_state(&folio->page)->dirty_sectors);
}

static loff_t bch2_next_pagecache_data(struct inode *vinode,
				       loff_t start_offset,
				       loff_t end_offset)
{
	struct folio_batch fbatch;
	pgoff_t start_index	= start_offset >> PAGE_SHIFT;
	pgoff_t end_index	= end_offset >> PAGE_SHIFT;
	pgoff_t index		= start_index;
	unsigned i;

	folio_batch_init(&fbatch);

	while (filemap_get_folios(vinode->i_mapping,
				  &index, end_index, &fbatch)) {
		for (i = 0; i < folio_batch_count(&fbatch); i++) {
			struct folio *folio = fbatch.folios[i];

			folio_lock(folio);
			if (folio_is_data(folio)) {
				end_offset =
					min(end_offset,
					    max(start_offset,
						((loff_t) index) << PAGE_SHIFT));
				folio_unlock(folio);
				folio_batch_release(&fbatch);
				return end_offset;
			}
			folio_unlock(folio);
		}
		folio_batch_release(&fbatch);
		cond_resched();
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

	page = find_lock_page(mapping, index);
	if (!page)
		return false;

	ret = folio_is_data(page_folio(page));
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
			   BTREE_ITER_SLOTS, k) {
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
	int ret = 0;

	pr_verbose_init(c->opts, "");

	if (bioset_init(&c->writepage_bioset,
			4, offsetof(struct bch_writepage_io, op.op.wbio.bio),
			BIOSET_NEED_BVECS) ||
	    bioset_init(&c->dio_read_bioset,
			4, offsetof(struct dio_read, rbio.bio),
			BIOSET_NEED_BVECS) ||
	    bioset_init(&c->dio_write_bioset,
			4, offsetof(struct dio_write, iop.op.wbio.bio),
			BIOSET_NEED_BVECS))
		ret = -ENOMEM;

	pr_verbose_init(c->opts, "ret %i", ret);
	return ret;
}

#endif /* NO_BCACHEFS_FS */
