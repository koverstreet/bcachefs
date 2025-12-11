// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/buckets.h"

#include "data/io_misc.h"

#include "fs/check.h"
#include "fs/namei.h"

#include "init/progress.h"

static int snapshots_seen_add_inorder(struct bch_fs *c, struct snapshots_seen *s, u32 id)
{
	u32 *i;
	__darray_for_each(s->ids, i) {
		if (*i == id)
			return 0;
		if (*i > id)
			break;
	}

	int ret = darray_insert_item(&s->ids, i - s->ids.data, id);
	if (ret)
		bch_err(c, "error reallocating snapshots_seen table (size %zu)",
			s->ids.size);
	return ret;
}

/*
 * XXX: this is handling transaction restarts without returning
 * -BCH_ERR_transaction_restart_nested, this is not how we do things anymore:
 */
static s64 bch2_count_inode_sectors(struct btree_trans *trans, u64 inum,
				    u32 snapshot)
{
	u64 sectors = 0;

	int ret = for_each_btree_key_max(trans, iter, BTREE_ID_extents,
				SPOS(inum, 0, snapshot),
				POS(inum, U64_MAX),
				0, k, ({
		if (bkey_extent_is_allocation(k.k))
			sectors += k.k->size;
		0;
	}));

	return ret ?: sectors;
}

static int check_i_sectors_notnested(struct btree_trans *trans, struct inode_walker *w)
{
	struct bch_fs *c = trans->c;
	int ret = 0;
	s64 count2;

	darray_for_each(w->inodes, i) {
		if (i->inode.bi_sectors == i->count)
			continue;

		CLASS(printbuf, buf)();
		lockrestart_do(trans,
			bch2_inum_snapshot_to_path(trans,
						   i->inode.bi_inum,
						   i->inode.bi_snapshot, NULL, &buf));

		count2 = bch2_count_inode_sectors(trans, w->last_pos.inode, i->inode.bi_snapshot);

		if (w->recalculate_sums)
			i->count = count2;

		if (i->count != count2) {
			bch_err_ratelimited(c, "fsck counted i_sectors wrong: got %llu should be %llu\n%s",
					    i->count, count2, buf.buf);
			i->count = count2;
		}

		if (fsck_err_on(!(i->inode.bi_flags & BCH_INODE_i_sectors_dirty) &&
				i->inode.bi_sectors != i->count,
				trans, inode_i_sectors_wrong,
				"incorrect i_sectors: got %llu, should be %llu\n%s",
				i->inode.bi_sectors, i->count, buf.buf)) {
			i->inode.bi_sectors = i->count;
			ret = bch2_fsck_write_inode(trans, &i->inode);
			if (ret)
				break;
		}
	}
fsck_err:
	bch_err_fn(c, ret);
	return ret;
}

static int check_i_sectors(struct btree_trans *trans, struct inode_walker *w)
{
	u32 restart_count = trans->restart_count;
	return check_i_sectors_notnested(trans, w) ?:
		trans_was_restarted(trans, restart_count);
}

struct extent_end {
	u32			snapshot;
	u64			offset;
	struct snapshots_seen	seen;
};

struct extent_ends {
	struct bpos			last_pos;
	DARRAY(struct extent_end)	e;
};

static void extent_ends_reset(struct extent_ends *extent_ends)
{
	darray_for_each(extent_ends->e, i)
		snapshots_seen_exit(&i->seen);
	extent_ends->e.nr = 0;
}

static void extent_ends_exit(struct extent_ends *extent_ends)
{
	extent_ends_reset(extent_ends);
	darray_exit(&extent_ends->e);
}

static struct extent_ends extent_ends_init(void)
{
	return (struct extent_ends) {};
}

DEFINE_CLASS(extent_ends, struct extent_ends,
	     extent_ends_exit(&_T),
	     extent_ends_init(), void)

static int extent_ends_at(struct bch_fs *c,
			  struct extent_ends *extent_ends,
			  struct snapshots_seen *seen,
			  struct bkey_s_c k)
{
	struct extent_end *i, n = (struct extent_end) {
		.offset		= k.k->p.offset,
		.snapshot	= k.k->p.snapshot,
		.seen		= *seen,
	};

	n.seen.ids.data = kmemdup(seen->ids.data,
			      sizeof(seen->ids.data[0]) * seen->ids.size,
			      GFP_KERNEL);
	if (!n.seen.ids.data)
		return bch_err_throw(c, ENOMEM_fsck_extent_ends_at);

	__darray_for_each(extent_ends->e, i) {
		if (i->snapshot == k.k->p.snapshot) {
			snapshots_seen_exit(&i->seen);
			*i = n;
			return 0;
		}

		if (i->snapshot >= k.k->p.snapshot)
			break;
	}

	return darray_insert_item(&extent_ends->e, i - extent_ends->e.data, n);
}

static int overlapping_extents_found(struct btree_trans *trans,
				     struct disk_reservation *res,
				     enum btree_id btree,
				     struct bpos pos1, struct snapshots_seen *pos1_seen,
				     struct bkey pos2,
				     bool *fixed,
				     struct extent_end *extent_end)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();
	int ret = 0;

	BUG_ON(bkey_le(pos1, bkey_start_pos(&pos2)));

	CLASS(btree_iter, iter1)(trans, btree, pos1,
				 BTREE_ITER_all_snapshots|
				 BTREE_ITER_not_extents);
	struct bkey_s_c k1 = bkey_try(bch2_btree_iter_peek_max(&iter1, POS(pos1.inode, U64_MAX)));

	prt_newline(&buf);
	bch2_bkey_val_to_text(&buf, c, k1);

	if (!bpos_eq(pos1, k1.k->p)) {
		prt_str(&buf, "\nwanted\n  ");
		bch2_bpos_to_text(&buf, pos1);
		prt_str(&buf, "\n");
		bch2_bkey_to_text(&buf, &pos2);

		bch_err(c, "%s: error finding first overlapping extent when repairing, got%s",
			__func__, buf.buf);
		return bch_err_throw(c, internal_fsck_err);
	}

	CLASS(btree_iter_copy, iter2)(&iter1);

	struct bkey_s_c k2;
	do {
		bch2_btree_iter_advance(&iter2);
		k2 = bkey_try(bch2_btree_iter_peek_max(&iter2, POS(pos1.inode, U64_MAX)));
	} while (bpos_lt(k2.k->p, pos2.p));

	prt_newline(&buf);
	bch2_bkey_val_to_text(&buf, c, k2);

	if (bpos_gt(k2.k->p, pos2.p) ||
	    pos2.size != k2.k->size) {
		bch_err(c, "%s: error finding seconding overlapping extent when repairing%s",
			__func__, buf.buf);
		return bch_err_throw(c, internal_fsck_err);
	}

	prt_printf(&buf, "\noverwriting %s extent",
		   pos1.snapshot >= pos2.p.snapshot ? "first" : "second");

	if (fsck_err(trans, extent_overlapping,
		     "overlapping extents%s", buf.buf)) {
		struct btree_iter *old_iter = &iter1;

		if (pos1.snapshot < pos2.p.snapshot) {
			old_iter = &iter2;
			swap(k1, k2);
		}

		trans->extra_disk_res += bch2_bkey_sectors_compressed(c, k2);

		try(bch2_trans_update_extent_overwrite(trans, old_iter,
					BTREE_UPDATE_internal_snapshot_node,
					k1, k2));
		try(bch2_trans_commit(trans, res, NULL, BCH_TRANS_COMMIT_no_enospc));

		*fixed = true;

		if (pos1.snapshot == pos2.p.snapshot) {
			/*
			 * We overwrote the first extent, and did the overwrite
			 * in the same snapshot:
			 */
			extent_end->offset = bkey_start_offset(&pos2);
		} else if (pos1.snapshot > pos2.p.snapshot) {
			/*
			 * We overwrote the first extent in pos2's snapshot:
			 */
			ret = snapshots_seen_add_inorder(c, pos1_seen, pos2.p.snapshot);
		} else {
			/*
			 * We overwrote the second extent - restart
			 * check_extent() from the top:
			 */
			ret = bch_err_throw(c, transaction_restart_nested);
		}
	}
fsck_err:
	return ret;
}

static int check_overlapping_extents(struct btree_trans *trans,
				     struct disk_reservation *res,
				     struct snapshots_seen *seen,
				     struct extent_ends *extent_ends,
				     struct bkey_s_c k,
				     struct btree_iter *iter,
				     bool *fixed)
{
	struct bch_fs *c = trans->c;

	/* transaction restart, running again */
	if (bpos_eq(extent_ends->last_pos, k.k->p))
		return 0;

	if (extent_ends->last_pos.inode != k.k->p.inode)
		extent_ends_reset(extent_ends);

	darray_for_each(extent_ends->e, i) {
		if (i->offset <= bkey_start_offset(k.k))
			continue;

		if (!bch2_ref_visible2(c,
				  k.k->p.snapshot, seen,
				  i->snapshot, &i->seen))
			continue;

		try(overlapping_extents_found(trans, res, iter->btree_id,
					      SPOS(iter->pos.inode,
						   i->offset,
						   i->snapshot),
					      &i->seen,
					      *k.k, fixed, i));
	}

	extent_ends->last_pos = k.k->p;
	return 0;
}

static int check_extent_overbig(struct btree_trans *trans, struct btree_iter *iter,
				struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	struct bch_extent_crc_unpacked crc;
	const union bch_extent_entry *i;
	unsigned encoded_extent_max_sectors = c->opts.encoded_extent_max >> 9;

	bkey_for_each_crc(k.k, ptrs, crc, i)
		if (crc_is_encoded(crc) &&
		    crc.uncompressed_size > encoded_extent_max_sectors) {
			CLASS(printbuf, buf)();

			bch2_bkey_val_to_text(&buf, c, k);
			bch_err(c, "overbig encoded extent, please report this:\n  %s", buf.buf);
		}

	return 0;
}

noinline_for_stack
static int check_extent(struct btree_trans *trans, struct btree_iter *iter,
			struct bkey_s_c k,
			struct inode_walker *inode,
			struct snapshots_seen *s,
			struct extent_ends *extent_ends,
			struct disk_reservation *res)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();
	int ret = 0;

	ret = bch2_check_key_has_snapshot(trans, iter, k);
	if (ret < 0)
		return ret;
	/*
	 * We can't use for_each_btree_key_commit() here because we have work to
	 * do after the commit that can't handle a transaction restart
	 */
	if (ret)
		return bch2_trans_commit(trans, res, NULL, BCH_TRANS_COMMIT_no_enospc);

	if (inode->last_pos.inode != k.k->p.inode && inode->have_inodes)
		try(check_i_sectors(trans, inode));

	try(bch2_snapshots_seen_update(c, s, iter->btree_id, k.k->p));

	struct inode_walker_entry *extent_i = errptr_try(bch2_walk_inode(trans, inode, k));

	try(bch2_check_key_has_inode(trans, iter, inode, extent_i, k));

	if (k.k->type != KEY_TYPE_whiteout)
		try(check_overlapping_extents(trans, res, s, extent_ends, k, iter,
					      &inode->recalculate_sums));

	if (!bkey_extent_whiteout(k.k)) {
		/*
		 * Check inodes in reverse order, from oldest snapshots to
		 * newest, starting from the inode that matches this extent's
		 * snapshot. If we didn't have one, iterate over all inodes:
		 */
		for (struct inode_walker_entry *i = extent_i ?: &darray_last(inode->inodes);
		     inode->inodes.data && i >= inode->inodes.data;
		     --i) {
			if (i->inode.bi_snapshot > k.k->p.snapshot ||
			    !bch2_key_visible_in_snapshot(c, s, i->inode.bi_snapshot, k.k->p.snapshot))
				continue;

			u64 last_block = round_up(i->inode.bi_size, block_bytes(c)) >> 9;

			if (fsck_err_on(k.k->p.offset > last_block &&
					!bkey_extent_is_reservation(c, k),
					trans, extent_past_end_of_inode,
					"extent type past end of inode %llu:%u, i_size %llu\n%s",
					i->inode.bi_inum, i->inode.bi_snapshot, i->inode.bi_size,
					(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
				try(snapshots_seen_add_inorder(c, s, i->inode.bi_snapshot));
				try(bch2_fpunch_snapshot(trans,
							 SPOS(i->inode.bi_inum,
							      last_block,
							      i->inode.bi_snapshot),
							 POS(i->inode.bi_inum, U64_MAX)));

				iter->k.type = KEY_TYPE_whiteout;
				break;
			}
		}
	}

	try(check_extent_overbig(trans, iter, k));
	try(bch2_bkey_drop_stale_ptrs(trans, iter, k));

	try(bch2_trans_commit(trans, res, NULL, BCH_TRANS_COMMIT_no_enospc));

	if (bkey_extent_is_allocation(k.k)) {
		for (struct inode_walker_entry *i = extent_i ?: &darray_last(inode->inodes);
		     inode->inodes.data && i >= inode->inodes.data;
		     --i) {
			if (i->whiteout ||
			    i->inode.bi_snapshot > k.k->p.snapshot ||
			    !bch2_key_visible_in_snapshot(c, s, i->inode.bi_snapshot, k.k->p.snapshot))
				continue;

			i->count += k.k->size;
		}
	}

	if (k.k->type != KEY_TYPE_whiteout)
		try(extent_ends_at(c, extent_ends, s, k));
fsck_err:
	return ret;
}

/*
 * Walk extents: verify that extents have a corresponding S_ISREG inode, and
 * that i_size an i_sectors are consistent
 */
int bch2_check_extents(struct bch_fs *c)
{
	CLASS(disk_reservation, res)(c);
	CLASS(btree_trans, trans)(c);
	CLASS(snapshots_seen, s)();
	CLASS(inode_walker, w)();
	CLASS(extent_ends, extent_ends)();

	struct progress_indicator progress;
	bch2_progress_init(&progress, __func__, c, BIT_ULL(BTREE_ID_extents), 0);

	return for_each_btree_key(trans, iter, BTREE_ID_extents,
				POS(BCACHEFS_ROOT_INO, 0),
				BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k, ({
		bch2_disk_reservation_put(c, &res.r);
		bch2_progress_update_iter(trans, &progress, &iter) ?:
		check_extent(trans, &iter, k, &w, &s, &extent_ends, &res.r);
	})) ?:
	check_i_sectors_notnested(trans, &w);
}

int bch2_check_indirect_extents(struct bch_fs *c)
{
	CLASS(disk_reservation, res)(c);
	CLASS(btree_trans, trans)(c);

	struct progress_indicator progress;
	bch2_progress_init(&progress, __func__, c, BIT_ULL(BTREE_ID_reflink), 0);

	return for_each_btree_key_commit(trans, iter, BTREE_ID_reflink,
				POS_MIN,
				BTREE_ITER_prefetch, k,
				&res.r, NULL,
				BCH_TRANS_COMMIT_no_enospc, ({
		bch2_disk_reservation_put(c, &res.r);
		bch2_progress_update_iter(trans, &progress, &iter) ?:
		check_extent_overbig(trans, &iter, k) ?:
		bch2_bkey_drop_stale_ptrs(trans, &iter, k);
	}));
}
