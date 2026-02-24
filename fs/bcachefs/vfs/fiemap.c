// SPDX-License-Identifier: GPL-2.0
#ifndef NO_BCACHEFS_FS

#include "bcachefs.h"

#include "btree/bkey_buf.h"
#include "btree/iter.h"

#include "data/extents.h"
#include "data/read.h"

#include "vfs/pagecache.h"

#include <linux/fiemap.h>

struct bch_fiemap_extent {
	struct bkey_buf	kbuf;
	unsigned	flags;
};

static int bch2_fill_extent(struct bch_fs *c,
			    struct fiemap_extent_info *info,
			    struct bch_fiemap_extent *fe)
{
	struct bkey_s_c k = bkey_i_to_s_c(fe->kbuf.k);
	unsigned flags = fe->flags;

	BUG_ON(!k.k->size);

	if (bkey_extent_is_direct_data(k.k)) {
		struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
		const union bch_extent_entry *entry;
		struct extent_ptr_decoded p;

		if (k.k->type == KEY_TYPE_reflink_v)
			flags |= FIEMAP_EXTENT_SHARED;

		bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
			int flags2 = 0;
			u64 offset = p.ptr.offset;

			if (p.ptr.unwritten)
				flags2 |= FIEMAP_EXTENT_UNWRITTEN;

			if (p.crc.compression_type)
				flags2 |= FIEMAP_EXTENT_ENCODED;
			else
				offset += p.crc.offset;

			if ((offset & (block_sectors(c) - 1)) ||
			    (k.k->size & (block_sectors(c) - 1)))
				flags2 |= FIEMAP_EXTENT_NOT_ALIGNED;

			try(fiemap_fill_next_extent(info,
						bkey_start_offset(k.k) << 9,
						offset << 9,
						k.k->size << 9, flags|flags2));
		}

		return 0;
	} else if (bkey_extent_is_inline_data(k.k)) {
		return fiemap_fill_next_extent(info,
					       bkey_start_offset(k.k) << 9,
					       0, k.k->size << 9,
					       flags|
					       FIEMAP_EXTENT_DATA_INLINE);
	} else if (k.k->type == KEY_TYPE_reservation) {
		return fiemap_fill_next_extent(info,
					       bkey_start_offset(k.k) << 9,
					       0, k.k->size << 9,
					       flags|
					       FIEMAP_EXTENT_DELALLOC|
					       FIEMAP_EXTENT_UNWRITTEN);
	} else if (k.k->type == KEY_TYPE_error) {
		return 0;
	} else {
		WARN_ONCE(1, "unhandled key type %s",
			  k.k->type < KEY_TYPE_MAX
			  ? bch2_bkey_types[k.k->type]
			  : "(unknown)");
		return 0;
	}
}

/*
 * Scan a range of an inode for data in pagecache.
 *
 * Intended to be retryable, so don't modify the output params until success is
 * imminent.
 */
static int
bch2_fiemap_hole_pagecache(struct inode *vinode, u64 *start, u64 *end,
			   bool nonblock)
{
	loff_t	dstart, dend;

	dstart = bch2_seek_pagecache_data(vinode, *start, *end, 0, nonblock);
	if (dstart < 0)
		return dstart;

	if (dstart == *end) {
		*start = dstart;
		return 0;
	}

	dend = bch2_seek_pagecache_hole(vinode, dstart, *end, 0, nonblock);
	if (dend < 0)
		return dend;

	/* race */
	BUG_ON(dstart == dend);

	*start = dstart;
	*end = dend;
	return 0;
}

/*
 * Scan a range of pagecache that corresponds to a file mapping hole in the
 * extent btree. If data is found, fake up an extent key so it looks like a
 * delalloc extent to the rest of the fiemap processing code.
 */
static int
bch2_next_fiemap_pagecache_extent(struct btree_trans *trans, struct bch_inode_info *inode,
				  u64 start, u64 end, struct bch_fiemap_extent *cur)
{
	struct bkey_i_extent	*delextent;
	struct bch_extent_ptr	ptr = {};
	loff_t			dstart = start << 9, dend = end << 9;
	int			ret;

	/*
	 * We hold btree locks here so we cannot block on folio locks without
	 * dropping trans locks first. Run a nonblocking scan for the common
	 * case of no folios over holes and fall back on failure.
	 *
	 * Note that dropping locks like this is technically racy against
	 * writeback inserting to the extent tree, but a non-sync fiemap scan is
	 * fundamentally racy with writeback anyways. Therefore, just report the
	 * range as delalloc regardless of whether we have to cycle trans locks.
	 */
	ret = bch2_fiemap_hole_pagecache(&inode->v, &dstart, &dend, true);
	if (ret == -EAGAIN)
		ret = drop_locks_do(trans,
			bch2_fiemap_hole_pagecache(&inode->v, &dstart, &dend, false));
	if (ret < 0)
		return ret;

	/*
	 * Create a fake extent key in the buffer. We have to add a dummy extent
	 * pointer for the fill code to add an extent entry. It's explicitly
	 * zeroed to reflect delayed allocation (i.e. phys offset 0).
	 */
	bch2_bkey_buf_realloc(&cur->kbuf, sizeof(*delextent) / sizeof(u64));
	delextent = bkey_extent_init(cur->kbuf.k);
	delextent->k.p = POS(inode->ei_inum.inum, dend >> 9);
	delextent->k.size = (dend - dstart) >> 9;
	bch2_bkey_append_ptr(trans->c, &delextent->k_i, ptr);

	cur->flags = FIEMAP_EXTENT_DELALLOC;

	return 0;
}

static int bch2_next_fiemap_extent(struct btree_trans *trans,
				   struct bch_inode_info *inode,
				   u64 start, u64 end,
				   struct bch_fiemap_extent *cur)
{
	u32 snapshot;
	try(bch2_subvolume_get_snapshot(trans, inode->ei_inum.subvol, &snapshot));

	CLASS(btree_iter, iter)(trans, BTREE_ID_extents,
				SPOS(inode->ei_inum.inum, start, snapshot), 0);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_max(&iter, POS(inode->ei_inum.inum, end)));

	u64 pagecache_end = k.k ? max(start, bkey_start_offset(k.k)) : end;

	try(bch2_next_fiemap_pagecache_extent(trans, inode, start, pagecache_end, cur));

	struct bpos pagecache_start = bkey_start_pos(&cur->kbuf.k->k);

	/*
	 * Does the pagecache or the btree take precedence?
	 *
	 * It _should_ be the pagecache, so that we correctly report delalloc
	 * extents when dirty in the pagecache (we're COW, after all).
	 *
	 * But we'd have to add per-sector writeback tracking to
	 * bch_folio_state, otherwise we report delalloc extents for clean
	 * cached data in the pagecache.
	 *
	 * We should do this, but even then fiemap won't report stable mappings:
	 * on bcachefs data moves around in the background (copygc, rebalance)
	 * and we don't provide a way for userspace to lock that out.
	 */
	if (k.k &&
	    bkey_le(bpos_max(iter.pos, bkey_start_pos(k.k)),
		    pagecache_start)) {
		bch2_bkey_buf_reassemble(&cur->kbuf, k);
		bch2_cut_front(trans->c, iter.pos, cur->kbuf.k);
		bch2_cut_back(POS(inode->ei_inum.inum, end), cur->kbuf.k);
		cur->flags = 0;
	} else if (k.k) {
		bch2_cut_back(bkey_start_pos(k.k), cur->kbuf.k);
	}

	if (cur->kbuf.k->k.type == KEY_TYPE_reflink_p) {
		unsigned sectors = cur->kbuf.k->k.size;
		s64 offset_into_extent = 0;
		enum btree_id data_btree = BTREE_ID_extents;
		try(bch2_read_indirect_extent(trans, &data_btree, &offset_into_extent, &cur->kbuf));

		struct bkey_i *k = cur->kbuf.k;
		sectors = min_t(unsigned, sectors, k->k.size - offset_into_extent);

		bch2_cut_front(trans->c,
			       POS(k->k.p.inode,
				   bkey_start_offset(&k->k) + offset_into_extent),
			       k);
		bch2_key_resize(&k->k, sectors);
		k->k.p = iter.pos;
		k->k.p.offset += k->k.size;
	}

	return 0;
}

int bch2_fiemap(struct inode *vinode, struct fiemap_extent_info *info,
		u64 start, u64 len)
{
	struct bch_fs *c = vinode->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(vinode);
	struct bch_fiemap_extent cur, prev;
	int ret = 0;

	try(fiemap_prep(&ei->v, info, start, &len, 0));

	if (start + len < start)
		return -EINVAL;

	u64 end = (start + len) >> 9;
	start >>= 9;

	bch2_bkey_buf_init(&cur.kbuf);
	bch2_bkey_buf_init(&prev.kbuf);

	CLASS(btree_trans, trans)(c);

	while (start < end) {
		ret = lockrestart_do(trans,
			bch2_next_fiemap_extent(trans, ei, start, end, &cur));
		if (ret)
			goto err;

		BUG_ON(bkey_start_offset(&cur.kbuf.k->k) < start);
		BUG_ON(cur.kbuf.k->k.p.offset > end);

		if (bkey_start_offset(&cur.kbuf.k->k) == end)
			break;

		start = cur.kbuf.k->k.p.offset;

		if (!bkey_deleted(&prev.kbuf.k->k)) {
			bch2_trans_unlock(trans);
			ret = bch2_fill_extent(c, info, &prev);
			if (ret)
				goto err;
		}

		bch2_bkey_buf_copy(&prev.kbuf, cur.kbuf.k);
		prev.flags = cur.flags;
	}

	if (!bkey_deleted(&prev.kbuf.k->k)) {
		bch2_trans_unlock(trans);
		prev.flags |= FIEMAP_EXTENT_LAST;
		ret = bch2_fill_extent(c, info, &prev);
	}
err:
	bch2_bkey_buf_exit(&cur.kbuf);
	bch2_bkey_buf_exit(&prev.kbuf);

	return bch2_err_class(ret < 0 ? ret : 0);
}

#endif /* NO_BCACHEFS_FS */
