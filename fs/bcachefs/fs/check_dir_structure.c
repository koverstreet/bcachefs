// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "fs/check.h"
#include "fs/namei.h"

#include "init/progress.h"

static int dirent_points_to_inode(struct bch_fs *c,
				  struct bkey_s_c_dirent dirent,
				  struct bch_inode_unpacked *inode)
{
	int ret = dirent_points_to_inode_nowarn(c, dirent, inode);
	if (ret) {
		CLASS(printbuf, buf)();
		bch2_dirent_inode_mismatch_msg(&buf, c, dirent, inode);
		bch_warn(c, "%s", buf.buf);
	}
	return ret;
}

static int remove_backpointer(struct btree_trans *trans,
			      struct bch_inode_unpacked *inode)
{
	if (!bch2_inode_has_backpointer(inode))
		return 0;

	u32 snapshot = inode->bi_snapshot;

	if (inode->bi_parent_subvol)
		try(bch2_subvolume_get_snapshot(trans, inode->bi_parent_subvol, &snapshot));

	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_s_c_dirent d = dirent_get_by_pos(trans, &iter,
				     SPOS(inode->bi_dir, inode->bi_dir_offset, snapshot));
	int ret = bkey_err(d) ?:
		  dirent_points_to_inode(c, d, inode) ?:
		  bch2_fsck_remove_dirent(trans, d.k->p);
	bch2_trans_iter_exit(&iter);
	return ret;
}

static int reattach_subvol(struct btree_trans *trans, struct bkey_s_c_subvolume s)
{
	struct bch_fs *c = trans->c;

	struct bch_inode_unpacked inode;
	try(bch2_inode_find_by_inum_trans(trans,
				(subvol_inum) { s.k->p.offset, le64_to_cpu(s.v->inode) },
				&inode));

	int ret = remove_backpointer(trans, &inode);
	if (!bch2_err_matches(ret, ENOENT))
		bch_err_msg(c, ret, "removing dirent");
	if (ret)
		return ret;

	ret = bch2_reattach_inode(trans, &inode);
	bch_err_msg(c, ret, "reattaching inode %llu", inode.bi_inum);
	return ret;
}

static int check_subvol_path(struct btree_trans *trans, struct btree_iter *iter, struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	CLASS(darray_u32, subvol_path)();
	CLASS(printbuf, buf)();
	int ret = 0;

	if (k.k->type != KEY_TYPE_subvolume)
		return 0;

	CLASS(btree_iter, parent_iter)(trans, BTREE_ID_subvolumes, POS_MIN, 0);

	subvol_inum start = {
		.subvol = k.k->p.offset,
		.inum	= le64_to_cpu(bkey_s_c_to_subvolume(k).v->inode),
	};

	while (k.k->p.offset != BCACHEFS_ROOT_SUBVOL) {
		try(darray_push(&subvol_path, k.k->p.offset));

		struct bkey_s_c_subvolume s = bkey_s_c_to_subvolume(k);

		struct bch_inode_unpacked subvol_root;
		ret = bch2_inode_find_by_inum_trans(trans,
					(subvol_inum) { s.k->p.offset, le64_to_cpu(s.v->inode) },
					&subvol_root);
		if (ret)
			break;

		u32 parent = le32_to_cpu(s.v->fs_path_parent);

		if (darray_find(subvol_path, parent)) {
			printbuf_reset(&buf);
			prt_printf(&buf, "subvolume loop: ");

			try(bch2_inum_to_path(trans, start, &buf));

			if (fsck_err(trans, subvol_loop, "%s", buf.buf))
				ret = reattach_subvol(trans, s);
			break;
		}

		bch2_btree_iter_set_pos(&parent_iter, POS(0, parent));
		k = bkey_try(bch2_btree_iter_peek_slot(&parent_iter));

		if (fsck_err_on(k.k->type != KEY_TYPE_subvolume,
				trans, subvol_unreachable,
				"unreachable subvolume %s",
				(printbuf_reset(&buf),
				 bch2_bkey_val_to_text(&buf, c, s.s_c),
				 buf.buf))) {
			return reattach_subvol(trans, s);
		}
	}
fsck_err:
	return ret;
}

int bch2_check_subvolume_structure(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);

	struct progress_indicator_state progress;
	bch2_progress_init(&progress, c, BIT_ULL(BTREE_ID_subvolumes));

	return for_each_btree_key_commit(trans, iter,
				BTREE_ID_subvolumes, POS_MIN, BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
			progress_update_iter(trans, &progress, &iter);
			check_subvol_path(trans, &iter, k);
	}));
}

static int bch2_bi_depth_renumber_one(struct btree_trans *trans,
				      u64 inum, u32 snapshot,
				      u32 new_depth)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_inodes, SPOS(0, inum, snapshot), 0);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	try(!bkey_is_inode(k.k) ? -BCH_ERR_ENOENT_inode : 0);

	struct bch_inode_unpacked inode;
	try(bch2_inode_unpack(k, &inode));

	if (inode.bi_depth != new_depth) {
		inode.bi_depth = new_depth;
		return __bch2_fsck_write_inode(trans, &inode) ?:
			 bch2_trans_commit(trans, NULL, NULL, 0);
	}

	return 0;
}

static int bch2_bi_depth_renumber(struct btree_trans *trans, darray_u64 *path,
				  u32 snapshot, u32 new_bi_depth)
{
	u32 restart_count = trans->restart_count;
	int ret = 0;

	darray_for_each_reverse(*path, i) {
		ret = nested_lockrestart_do(trans,
				bch2_bi_depth_renumber_one(trans, *i, snapshot, new_bi_depth));
		bch_err_fn(trans->c, ret);
		if (ret)
			break;

		new_bi_depth++;
	}

	return ret ?: trans_was_restarted(trans, restart_count);
}

static int check_path_loop(struct btree_trans *trans, struct bkey_s_c inode_k)
{
	struct bch_fs *c = trans->c;
	CLASS(darray_u64, path)();
	CLASS(printbuf, buf)();
	u32 snapshot = inode_k.k->p.snapshot;
	bool redo_bi_depth = false;
	u32 min_bi_depth = U32_MAX;
	int ret = 0;

	struct bpos start = inode_k.k->p;

	struct bch_inode_unpacked inode;
	try(bch2_inode_unpack(inode_k, &inode));

	CLASS(btree_iter, inode_iter)(trans, BTREE_ID_inodes, POS_MIN, 0);

	/*
	 * If we're running full fsck, check_dirents() will have already ran,
	 * and we shouldn't see any missing alloc/backpointers.here - otherwise that's
	 * handled separately, by check_unreachable_inodes
	 */
	while (!inode.bi_subvol &&
	       bch2_inode_has_backpointer(&inode)) {
		struct btree_iter dirent_iter;
		struct bkey_s_c_dirent d;

		d = dirent_get_by_pos(trans, &dirent_iter,
				      SPOS(inode.bi_dir, inode.bi_dir_offset, snapshot));
		ret = bkey_err(d.s_c);
		if (ret && !bch2_err_matches(ret, ENOENT))
			goto out;

		if (!ret && (ret = dirent_points_to_inode(c, d, &inode)))
			bch2_trans_iter_exit(&dirent_iter);

		if (bch2_err_matches(ret, ENOENT)) {
			printbuf_reset(&buf);
			bch2_bkey_val_to_text(&buf, c, inode_k);
			bch_err(c, "unreachable inode in check_directory_structure: %s\n%s",
				bch2_err_str(ret), buf.buf);
			goto out;
		}

		bch2_trans_iter_exit(&dirent_iter);

		try(darray_push(&path, inode.bi_inum));

		bch2_btree_iter_set_pos(&inode_iter, SPOS(0, inode.bi_dir, snapshot));
		inode_k = bch2_btree_iter_peek_slot(&inode_iter);

		struct bch_inode_unpacked parent_inode;
		ret = bkey_err(inode_k) ?:
			!bkey_is_inode(inode_k.k) ? -BCH_ERR_ENOENT_inode
			: bch2_inode_unpack(inode_k, &parent_inode);
		if (ret) {
			/* Should have been caught in dirents pass */
			bch_err_msg(c, ret, "error looking up parent directory");
			goto out;
		}

		min_bi_depth = parent_inode.bi_depth;

		if (parent_inode.bi_depth < inode.bi_depth &&
		    min_bi_depth < U16_MAX)
			break;

		inode = parent_inode;
		redo_bi_depth = true;

		if (darray_find(path, inode.bi_inum)) {
			printbuf_reset(&buf);
			prt_printf(&buf, "directory structure loop in snapshot %u: ",
				   snapshot);

			ret = bch2_inum_snapshot_to_path(trans, start.offset, start.snapshot, NULL, &buf);
			if (ret)
				goto out;

			if (c->opts.verbose) {
				prt_newline(&buf);
				darray_for_each(path, i)
					prt_printf(&buf, "%llu ", *i);
			}

			if (fsck_err(trans, dir_loop, "%s", buf.buf)) {
				ret = remove_backpointer(trans, &inode);
				bch_err_msg(c, ret, "removing dirent");
				if (ret)
					goto out;

				ret = bch2_reattach_inode(trans, &inode);
				bch_err_msg(c, ret, "reattaching inode %llu", inode.bi_inum);
			}

			goto out;
		}
	}

	if (inode.bi_subvol)
		min_bi_depth = 0;

	if (redo_bi_depth)
		ret = bch2_bi_depth_renumber(trans, &path, snapshot, min_bi_depth);
out:
fsck_err:
	bch_err_fn(c, ret);
	return ret;
}

/*
 * Check for loops in the directory structure: all other connectivity issues
 * have been fixed by prior passes
 */
int bch2_check_directory_structure(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	return for_each_btree_key_reverse_commit(trans, iter, BTREE_ID_inodes, POS_MIN,
					  BTREE_ITER_intent|
					  BTREE_ITER_prefetch|
					  BTREE_ITER_all_snapshots, k,
					  NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
			if (!S_ISDIR(bkey_inode_mode(k)))
				continue;

			if (bch2_inode_flags(k) & BCH_INODE_unlinked)
				continue;

			check_path_loop(trans, k);
		}));
}
