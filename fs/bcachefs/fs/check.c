// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"
#include "bcachefs_ioctl.h"

#include "alloc/buckets.h"

#include "btree/bkey_buf.h"
#include "btree/cache.h"
#include "btree/update.h"

#include "fs/dirent.h"
#include "fs/check.h"
#include "fs/inode.h"
#include "fs/namei.h"
#include "fs/xattr.h"

#include "init/error.h"
#include "init/progress.h"
#include "init/passes.h"
#include "init/fs.h"

#include "snapshots/snapshot.h"

#include "vfs/fs.h"

#include "util/darray.h"
#include "util/thread_with_file.h"

#include <linux/dcache.h> /* struct qstr */

void bch2_dirent_inode_mismatch_msg(struct printbuf *out, struct bch_fs *c,
				    struct bkey_s_c_dirent dirent,
				    struct bch_inode_unpacked *inode)
{
	prt_str(out, "inode points to dirent that does not point back:");
	prt_newline(out);
	bch2_bkey_val_to_text(out, c, dirent.s_c);
	prt_newline(out);
	bch2_inode_unpacked_to_text(out, inode);
}

static s64 bch2_count_subdirs(struct btree_trans *trans, u64 inum,
				    u32 snapshot)
{
	u64 subdirs = 0;

	int ret = for_each_btree_key_max(trans, iter, BTREE_ID_dirents,
				    SPOS(inum, 0, snapshot),
				    POS(inum, U64_MAX),
				    0, k, ({
		if (k.k->type == KEY_TYPE_dirent &&
		    bkey_s_c_to_dirent(k).v->d_type == DT_DIR)
			subdirs++;
		0;
	}));

	return ret ?: subdirs;
}

static int subvol_lookup(struct btree_trans *trans, u32 subvol,
			 u32 *snapshot, u64 *inum)
{
	struct bch_subvolume s;
	int ret = bch2_subvolume_get(trans, subvol, false, &s);

	*snapshot = le32_to_cpu(s.snapshot);
	*inum = le64_to_cpu(s.inode);
	return ret;
}

static int lookup_dirent_in_snapshot(struct btree_trans *trans,
			   struct bch_hash_info hash_info,
			   subvol_inum dir, struct qstr *name,
			   u64 *target, unsigned *type, u32 snapshot)
{
	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_s_c k = bkey_try(bch2_hash_lookup_in_snapshot(trans, &iter, bch2_dirent_hash_desc,
							 &hash_info, dir, name, 0, snapshot));

	struct bkey_s_c_dirent d = bkey_s_c_to_dirent(k);
	*target = le64_to_cpu(d.v->d_inum);
	*type = d.v->d_type;
	return 0;
}

/*
 * Find any subvolume associated with a tree of snapshots
 * We can't rely on master_subvol - it might have been deleted.
 */
static int find_snapshot_tree_subvol(struct btree_trans *trans,
				     u32 tree_id, u32 *subvol)
{
	struct bkey_s_c k;
	int ret;

	for_each_btree_key_norestart(trans, iter, BTREE_ID_snapshots, POS_MIN, 0, k, ret) {
		if (k.k->type != KEY_TYPE_snapshot)
			continue;

		struct bkey_s_c_snapshot s = bkey_s_c_to_snapshot(k);
		if (le32_to_cpu(s.v->tree) != tree_id)
			continue;

		if (s.v->subvol) {
			*subvol = le32_to_cpu(s.v->subvol);
			return 0;
		}
	}

	return ret ?: bch_err_throw(trans->c, ENOENT_no_snapshot_tree_subvol);
}

static struct qstr lostfound_str = QSTR("lost+found");

static int create_lostfound(struct btree_trans *trans, u32 snapshot_tree,
			    subvol_inum root_inum,
			    struct bch_inode_unpacked *root_inode,
			    struct bch_hash_info *root_hash_info,
			    struct bch_inode_unpacked *lostfound)
{
	struct bch_fs *c = trans->c;
	/*
	 * We always create lost+found in the root snapshot; we don't want
	 * different branches of the snapshot tree to have different lost+found
	 */
	struct bch_snapshot_tree st;
	try(bch2_snapshot_tree_lookup(trans, snapshot_tree, &st));

	u32 snapshot = bch2_snapshot_live_descendent(c, le32_to_cpu(st.root_snapshot));

	CLASS(bch_log_msg_level, msg)(c, LOGLEVEL_notice);
	prt_printf(&msg.m, "creating ");
	try(bch2_inum_to_path(trans, root_inum, &msg.m));
	prt_printf(&msg.m, "/lost+found in subvol %llu snapshot %u", root_inum.subvol, snapshot);

	u64 now = bch2_current_time(c);
	u64 cpu = raw_smp_processor_id();

	bch2_inode_init_early(c, lostfound);
	bch2_inode_init_late(c, lostfound, now, 0, 0, S_IFDIR|0700, 0, root_inode);
	lostfound->bi_dir = root_inode->bi_inum;
	lostfound->bi_snapshot = snapshot;

	root_inode->bi_nlink++;

	CLASS(btree_iter_uninit, lostfound_iter)(trans);
	try(bch2_inode_create(trans, &lostfound_iter, lostfound, snapshot, cpu,
			      inode_opt_get(c, root_inode, inodes_32bit)));

	bch2_btree_iter_set_snapshot(&lostfound_iter, snapshot);
	try(bch2_btree_iter_traverse(&lostfound_iter));

	try(bch2_dirent_create_snapshot(trans,
				0, root_inode->bi_inum, snapshot, root_hash_info,
				mode_to_type(lostfound->bi_mode),
				&lostfound_str,
				lostfound->bi_inum,
				&lostfound->bi_dir_offset,
				BTREE_UPDATE_internal_snapshot_node|
				STR_HASH_must_create));

	try(bch2_inode_write_flags(trans, &lostfound_iter, lostfound,
				   BTREE_UPDATE_internal_snapshot_node));

	return bch2_trans_commit_lazy(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc);
}

/* Get lost+found, create if it doesn't exist: */
static int lookup_lostfound(struct btree_trans *trans, u32 snapshot,
			    struct bch_inode_unpacked *lostfound,
			    u64 reattaching_inum)
{
	struct bch_fs *c = trans->c;
	u32 snapshot_tree = bch2_snapshot_tree(c, snapshot);
	int ret;

	u32 subvolid;
	ret = find_snapshot_tree_subvol(trans, snapshot_tree, &subvolid);
	bch_err_msg(c, ret, "finding subvol associated with snapshot tree %u",
		    bch2_snapshot_tree(c, snapshot));
	if (ret)
		return ret;

	struct bch_subvolume subvol;
	ret = bch2_subvolume_get(trans, subvolid, false, &subvol);
	bch_err_msg(c, ret, "looking up subvol %u for snapshot %u", subvolid, snapshot);
	if (ret)
		return ret;

	if (!subvol.inode) {
		struct bkey_i_subvolume *subvol = errptr_try(bch2_bkey_get_mut_typed(trans,
				BTREE_ID_subvolumes, POS(0, subvolid),
				0, subvolume));

		subvol->v.inode = cpu_to_le64(reattaching_inum);
	}

	subvol_inum root_inum = {
		.subvol = subvolid,
		.inum = le64_to_cpu(subvol.inode)
	};

	struct bch_inode_unpacked root_inode;
	ret = bch2_inode_find_by_inum_snapshot(trans, root_inum.inum, snapshot, &root_inode, 0);
	bch_err_msg(c, ret, "looking up root inode %llu for subvol %u",
		    root_inum.inum, subvolid);
	if (ret)
		return ret;

	struct bch_hash_info root_hash_info;
	try(bch2_hash_info_init(c, &root_inode, &root_hash_info));

	u64 inum = 0;
	unsigned d_type = 0;
	ret = lookup_dirent_in_snapshot(trans, root_hash_info, root_inum,
			      &lostfound_str, &inum, &d_type, snapshot);
	if (bch2_err_matches(ret, ENOENT)) {
		/*
		 * We always create lost_found in its own transaction; this will
		 * return a transaction restart:
		 */
		ret = create_lostfound(trans, snapshot_tree, root_inum,
				       &root_inode, &root_hash_info, lostfound);
		bch_err_msg(c, ret, "creating lost+found");
		return ret;
	}

	bch_err_fn(c, ret);
	if (ret)
		return ret;

	if (d_type != DT_DIR) {
		ret = bch_err_throw(c, ENOENT_not_directory);
		bch_err_msg(c, ret, "looking up lost+found");
		return ret;
	}

	/*
	 * The bch2_check_dirents pass has already run, dangling dirents
	 * shouldn't exist here:
	 */
	ret = bch2_inode_find_by_inum_snapshot(trans, inum, snapshot, lostfound, 0);
	bch_err_msg(c, ret, "looking up lost+found %llu:%u in (root inode %llu, snapshot root %u)",
		    inum, snapshot, root_inum.inum, bch2_snapshot_root(c, snapshot));
	return ret;
}

static inline bool inode_should_reattach(struct bch_inode_unpacked *inode)
{
	if (inode->bi_inum == BCACHEFS_ROOT_INO &&
	    inode->bi_subvol == BCACHEFS_ROOT_SUBVOL)
		return false;

	/*
	 * Subvolume roots are special: older versions of subvolume roots may be
	 * disconnected, it's only the newest version that matters.
	 *
	 * We only keep a single dirent pointing to a subvolume root, i.e.
	 * older versions of snapshots will not have a different dirent pointing
	 * to the same subvolume root.
	 *
	 * This is because dirents that point to subvolumes are only visible in
	 * the parent subvolume - versioning is not needed - and keeping them
	 * around would break fsck, because when we're crossing subvolumes we
	 * don't have a consistent snapshot ID to do check the inode <-> dirent
	 * relationships.
	 *
	 * Thus, a subvolume root that's been renamed after a snapshot will have
	 * a disconnected older version - that's expected.
	 *
	 * Note that taking a snapshot always updates the root inode (to update
	 * the dirent backpointer), so a subvolume root inode with
	 * BCH_INODE_has_child_snapshot is never visible.
	 */
	if (inode->bi_subvol &&
	    (inode->bi_flags & BCH_INODE_has_child_snapshot))
		return false;

	return !bch2_inode_has_backpointer(inode) &&
		!(inode->bi_flags & BCH_INODE_unlinked);
}

static int maybe_delete_dirent(struct btree_trans *trans, struct bpos d_pos, u32 snapshot)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_dirents,
				SPOS(d_pos.inode, d_pos.offset, snapshot),
				BTREE_ITER_intent|
				BTREE_ITER_with_updates);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	if (bpos_eq(k.k->p, d_pos)) {
		/*
		 * delet_at() doesn't work because the update path doesn't
		 * internally use BTREE_ITER_with_updates yet
		 */
		struct bkey_i *k = errptr_try(bch2_trans_kmalloc(trans, sizeof(*k)));

		bkey_init(&k->k);
		k->k.type = KEY_TYPE_whiteout;
		k->k.p = iter.pos;
		return bch2_trans_update(trans, &iter, k, BTREE_UPDATE_internal_snapshot_node);
	}

	return 0;
}

int bch2_reattach_inode(struct btree_trans *trans, struct bch_inode_unpacked *inode)
{
	struct bch_fs *c = trans->c;
	struct bch_inode_unpacked lostfound;
	char name_buf[20];
	int ret;

	u32 dirent_snapshot = inode->bi_snapshot;
	if (inode->bi_subvol) {
		inode->bi_parent_subvol = BCACHEFS_ROOT_SUBVOL;

		struct bkey_i_subvolume *subvol =
			errptr_try(bch2_bkey_get_mut_typed(trans,
						BTREE_ID_subvolumes, POS(0, inode->bi_subvol),
						0, subvolume));

		subvol->v.fs_path_parent = BCACHEFS_ROOT_SUBVOL;

		u64 root_inum;
		try(subvol_lookup(trans, inode->bi_parent_subvol, &dirent_snapshot, &root_inum));

		snprintf(name_buf, sizeof(name_buf), "subvol-%u", inode->bi_subvol);
	} else {
		snprintf(name_buf, sizeof(name_buf), "%llu", inode->bi_inum);
	}

	try(lookup_lostfound(trans, dirent_snapshot, &lostfound, inode->bi_inum));

	bch_verbose(c, "got lostfound inum %llu", lostfound.bi_inum);

	lostfound.bi_nlink += S_ISDIR(inode->bi_mode);

	/* ensure lost+found inode is also present in inode snapshot */
	if (!inode->bi_subvol) {
		BUG_ON(!bch2_snapshot_is_ancestor(c, inode->bi_snapshot, lostfound.bi_snapshot));
		lostfound.bi_snapshot = inode->bi_snapshot;
	}

	try(__bch2_fsck_write_inode(trans, &lostfound));

	struct bch_hash_info dir_hash;
	try(bch2_hash_info_init(c, &lostfound, &dir_hash));
	struct qstr name = QSTR(name_buf);

	inode->bi_dir = lostfound.bi_inum;

	ret = bch2_dirent_create_snapshot(trans,
				inode->bi_parent_subvol, lostfound.bi_inum,
				dirent_snapshot,
				&dir_hash,
				inode_d_type(inode),
				&name,
				inode->bi_subvol ?: inode->bi_inum,
				&inode->bi_dir_offset,
				BTREE_UPDATE_internal_snapshot_node|
				STR_HASH_must_create);
	if (ret) {
		bch_err_msg(c, ret, "error creating dirent");
		return ret;
	}

	try(__bch2_fsck_write_inode(trans, inode));

	{
		CLASS(printbuf, buf)();
		try(bch2_inum_snapshot_to_path(trans, inode->bi_inum,
					       inode->bi_snapshot, NULL, &buf));

		bch_info(c, "reattached at %s", buf.buf);
	}

	/*
	 * Fix up inodes in child snapshots: if they should also be reattached
	 * update the backpointer field, if they should not be we need to emit
	 * whiteouts for the dirent we just created.
	 */
	if (!inode->bi_subvol && bch2_snapshot_is_leaf(c, inode->bi_snapshot) <= 0) {
		CLASS(snapshot_id_list, whiteouts_done)();
		struct bkey_s_c k;

		darray_init(&whiteouts_done);

		for_each_btree_key_reverse_norestart(trans, iter,
				BTREE_ID_inodes, SPOS(0, inode->bi_inum, inode->bi_snapshot - 1),
				BTREE_ITER_all_snapshots|BTREE_ITER_intent, k, ret) {
			if (k.k->p.offset != inode->bi_inum)
				break;

			if (!bkey_is_inode(k.k) ||
			    !bch2_snapshot_is_ancestor(c, k.k->p.snapshot, inode->bi_snapshot) ||
			    snapshot_list_has_ancestor(c, &whiteouts_done, k.k->p.snapshot))
				continue;

			struct bch_inode_unpacked child_inode;
			try(bch2_inode_unpack(k, &child_inode));

			if (!inode_should_reattach(&child_inode)) {
				try(maybe_delete_dirent(trans,
							SPOS(lostfound.bi_inum, inode->bi_dir_offset,
							     dirent_snapshot),
							k.k->p.snapshot));
				try(snapshot_list_add(c, &whiteouts_done, k.k->p.snapshot));
			} else {
				iter.snapshot = k.k->p.snapshot;
				child_inode.bi_dir = inode->bi_dir;
				child_inode.bi_dir_offset = inode->bi_dir_offset;

				try(bch2_inode_write_flags(trans, &iter, &child_inode,
							   BTREE_UPDATE_internal_snapshot_node));
			}
		}
	}

	return ret;
}

static int reconstruct_subvol(struct btree_trans *trans, u32 snapshotid, u32 subvolid, u64 inum)
{
	struct bch_fs *c = trans->c;

	if (!bch2_snapshot_is_leaf(c, snapshotid)) {
		bch_err(c, "need to reconstruct subvol, but have interior node snapshot");
		return bch_err_throw(c, fsck_repair_unimplemented);
	}

	/*
	 * If inum isn't set, that means we're being called from check_dirents,
	 * not check_inodes - the root of this subvolume doesn't exist or we
	 * would have found it there:
	 */
	if (!inum) {
		CLASS(btree_iter_uninit, inode_iter)(trans);
		struct bch_inode_unpacked new_inode;
		u64 cpu = raw_smp_processor_id();

		bch2_inode_init_early(c, &new_inode);
		bch2_inode_init_late(c, &new_inode, bch2_current_time(c), 0, 0, S_IFDIR|0755, 0, NULL);

		new_inode.bi_subvol = subvolid;

		try(bch2_inode_create(trans, &inode_iter, &new_inode, snapshotid, cpu, false));
		try(bch2_btree_iter_traverse(&inode_iter));
		try(bch2_inode_write(trans, &inode_iter, &new_inode));

		inum = new_inode.bi_inum;
	}

	bch_info(c, "reconstructing subvol %u with root inode %llu", subvolid, inum);

	struct bkey_i_subvolume *new_subvol = errptr_try(bch2_trans_kmalloc(trans, sizeof(*new_subvol)));

	bkey_subvolume_init(&new_subvol->k_i);
	new_subvol->k.p.offset	= subvolid;
	new_subvol->v.snapshot	= cpu_to_le32(snapshotid);
	new_subvol->v.inode	= cpu_to_le64(inum);
	try(bch2_btree_insert_trans(trans, BTREE_ID_subvolumes, &new_subvol->k_i, 0));

	struct bkey_i_snapshot *s = bch2_bkey_get_mut_typed(trans,
			BTREE_ID_snapshots, POS(0, snapshotid),
			0, snapshot);
	int ret = PTR_ERR_OR_ZERO(s);
	bch_err_msg(c, ret, "getting snapshot %u", snapshotid);
	if (ret)
		return ret;

	u32 snapshot_tree = le32_to_cpu(s->v.tree);

	s->v.subvol = cpu_to_le32(subvolid);
	SET_BCH_SNAPSHOT_SUBVOL(&s->v, true);

	struct bkey_i_snapshot_tree *st = bch2_bkey_get_mut_typed(trans,
			BTREE_ID_snapshot_trees, POS(0, snapshot_tree),
			0, snapshot_tree);
	ret = PTR_ERR_OR_ZERO(st);
	bch_err_msg(c, ret, "getting snapshot tree %u", snapshot_tree);
	if (ret)
		return ret;

	if (!st->v.master_subvol)
		st->v.master_subvol = cpu_to_le32(subvolid);
	return 0;
}

static int reconstruct_inode(struct btree_trans *trans, enum btree_id btree, u32 snapshot, u64 inum)
{
	struct bch_fs *c = trans->c;
	unsigned i_mode = S_IFREG;
	u64 i_size = 0;

	switch (btree) {
	case BTREE_ID_extents: {
		CLASS(btree_iter, iter)(trans, BTREE_ID_extents, SPOS(inum, U64_MAX, snapshot), 0);
		struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_prev_min(&iter, POS(inum, 0)));

		i_size = k.k->p.offset << 9;
		break;
	}
	case BTREE_ID_dirents:
		i_mode = S_IFDIR;
		break;
	case BTREE_ID_xattrs:
		break;
	default:
		BUG();
	}

	struct bch_inode_unpacked new_inode;
	bch2_inode_init_early(c, &new_inode);
	bch2_inode_init_late(c, &new_inode, bch2_current_time(c), 0, 0, i_mode|0600, 0, NULL);
	new_inode.bi_size = i_size;
	new_inode.bi_inum = inum;
	new_inode.bi_snapshot = snapshot;

	return __bch2_fsck_write_inode(trans, &new_inode);
}

int bch2_snapshots_seen_update(struct bch_fs *c, struct snapshots_seen *s,
			       enum btree_id btree_id, struct bpos pos)
{
	if (!bkey_eq(s->pos, pos))
		s->ids.nr = 0;
	s->pos = pos;

	return snapshot_list_add_nodup(c, &s->ids, pos.snapshot);
}

/**
 * bch2_key_visible_in_snapshot - returns true if @id is a descendent of @ancestor,
 * and @ancestor hasn't been overwritten in @seen
 *
 * @c:		filesystem handle
 * @seen:	list of snapshot ids already seen at current position
 * @id:		descendent snapshot id
 * @ancestor:	ancestor snapshot id
 *
 * Returns:	whether key in @ancestor snapshot is visible in @id snapshot
 */
bool bch2_key_visible_in_snapshot(struct bch_fs *c, struct snapshots_seen *seen,
				  u32 id, u32 ancestor)
{
	EBUG_ON(id > ancestor);

	if (id == ancestor)
		return true;

	if (!bch2_snapshot_is_ancestor(c, id, ancestor))
		return false;

	/*
	 * We know that @id is a descendant of @ancestor, we're checking if
	 * we've seen a key that overwrote @ancestor - i.e. also a descendent of
	 * @ascestor and with @id as a descendent.
	 *
	 * But we already know that we're scanning IDs between @id and @ancestor
	 * numerically, since snapshot ID lists are kept sorted, so if we find
	 * an id that's an ancestor of @id we're done:
	 */
	darray_for_each_reverse(seen->ids, i)
		if (*i != ancestor && bch2_snapshot_is_ancestor(c, id, *i))
			return false;

	return true;
}

/**
 * bch2_ref_visible - given a key with snapshot id @src that points to a key with
 * snapshot id @dst, test whether there is some snapshot in which @dst is
 * visible.
 *
 * @c:		filesystem handle
 * @s:		list of snapshot IDs already seen at @src
 * @src:	snapshot ID of src key
 * @dst:	snapshot ID of dst key
 * Returns:	true if there is some snapshot in which @dst is visible
 *
 * Assumes we're visiting @src keys in natural key order
 */
bool bch2_ref_visible(struct bch_fs *c, struct snapshots_seen *s, u32 src, u32 dst)
{
	return dst <= src
		? bch2_key_visible_in_snapshot(c, s, dst, src)
		: bch2_snapshot_is_ancestor(c, src, dst);
}

int bch2_ref_visible2(struct bch_fs *c,
		      u32 src, struct snapshots_seen *src_seen,
		      u32 dst, struct snapshots_seen *dst_seen)
{
	if (dst > src) {
		swap(dst, src);
		swap(dst_seen, src_seen);
	}
	return bch2_key_visible_in_snapshot(c, src_seen, dst, src);
}

#define for_each_visible_inode(_c, _s, _w, _snapshot, _i)				\
	for (_i = (_w)->inodes.data; _i < (_w)->inodes.data + (_w)->inodes.nr &&	\
	     (_i)->inode.bi_snapshot <= (_snapshot); _i++)				\
		if (bch2_key_visible_in_snapshot(_c, _s, _i->inode.bi_snapshot, _snapshot))

static int add_inode(struct bch_fs *c, struct inode_walker *w,
		     struct bkey_s_c inode)
{
	try(darray_push(&w->inodes, ((struct inode_walker_entry) {
		.whiteout	= !bkey_is_inode(inode.k),
	})));

	struct inode_walker_entry *n = &darray_last(w->inodes);
	if (!n->whiteout) {
		return bch2_inode_unpack(inode, &n->inode);
	} else {
		n->inode.bi_inum	= inode.k->p.offset;
		n->inode.bi_snapshot	= inode.k->p.snapshot;
		return 0;
	}
}

static int get_inodes_all_snapshots(struct btree_trans *trans,
				    struct inode_walker *w, u64 inum)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c k;
	int ret;

	/*
	 * We no longer have inodes for w->last_pos; clear this to avoid
	 * screwing up check_i_sectors/check_subdir_count if we take a
	 * transaction restart here:
	 */
	w->have_inodes = false;
	w->recalculate_sums = false;
	w->inodes.nr = 0;

	for_each_btree_key_max_norestart(trans, iter,
			BTREE_ID_inodes, POS(0, inum), SPOS(0, inum, U32_MAX),
			BTREE_ITER_all_snapshots, k, ret)
		try(add_inode(c, w, k));

	if (ret)
		return ret;

	w->first_this_inode = true;
	w->have_inodes = true;
	return 0;
}

static int get_visible_inodes(struct btree_trans *trans,
			      struct inode_walker *w,
			      struct snapshots_seen *s,
			      u64 inum)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c k;
	int ret;

	w->inodes.nr = 0;
	w->deletes.nr = 0;

	for_each_btree_key_reverse_norestart(trans, iter, BTREE_ID_inodes, SPOS(0, inum, s->pos.snapshot),
			   BTREE_ITER_all_snapshots, k, ret) {
		if (k.k->p.offset != inum)
			break;

		if (!bch2_ref_visible(c, s, s->pos.snapshot, k.k->p.snapshot))
			continue;

		if (snapshot_list_has_ancestor(c, &w->deletes, k.k->p.snapshot))
			continue;

		ret = bkey_is_inode(k.k)
			? add_inode(c, w, k)
			: snapshot_list_add(c, &w->deletes, k.k->p.snapshot);
		if (ret)
			break;
	}

	return ret;
}

static struct inode_walker_entry *
lookup_inode_for_snapshot(struct btree_trans *trans, struct inode_walker *w, struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;

	struct inode_walker_entry *i = darray_find_p(w->inodes, i,
		    bch2_snapshot_is_ancestor(c, k.k->p.snapshot, i->inode.bi_snapshot));

	if (!i)
		return NULL;

	CLASS(printbuf, buf)();
	int ret = 0;

	if (fsck_err_on(k.k->p.snapshot != i->inode.bi_snapshot,
			trans, snapshot_key_missing_inode_snapshot,
			 "have key for inode %llu:%u but have inode in ancestor snapshot %u\n"
			 "unexpected because we should always update the inode when we update a key in that inode\n"
			 "%s",
			 w->last_pos.inode, k.k->p.snapshot, i->inode.bi_snapshot,
			 (bch2_bkey_val_to_text(&buf, c, k),
			  buf.buf))) {
		if (!i->whiteout) {
			struct bch_inode_unpacked new = i->inode;
			new.bi_snapshot = k.k->p.snapshot;
			ret = __bch2_fsck_write_inode(trans, &new);
		} else {
			struct bkey_i whiteout;
			bkey_init(&whiteout.k);
			whiteout.k.type = KEY_TYPE_whiteout;
			whiteout.k.p = SPOS(0, i->inode.bi_inum, k.k->p.snapshot);
			ret = bch2_btree_insert_trans(trans, BTREE_ID_inodes,
						      &whiteout,
						      BTREE_ITER_cached|
						      BTREE_UPDATE_internal_snapshot_node);
		}

		if (ret)
			goto fsck_err;

		ret = bch2_trans_commit(trans, NULL, NULL, 0);
		if (ret)
			goto fsck_err;

		struct inode_walker_entry new_entry = *i;

		new_entry.inode.bi_snapshot	= k.k->p.snapshot;
		new_entry.count			= 0;
		new_entry.i_size		= 0;

		while (i > w->inodes.data && i[-1].inode.bi_snapshot > k.k->p.snapshot)
			--i;

		size_t pos = i - w->inodes.data;
		ret = darray_insert_item(&w->inodes, pos, new_entry);
		if (ret)
			goto fsck_err;

		ret = bch_err_throw(c, transaction_restart_nested);
		goto fsck_err;
	}

	return i;
fsck_err:
	return ERR_PTR(ret);
}

struct inode_walker_entry *bch2_walk_inode(struct btree_trans *trans,
					   struct inode_walker *w,
					   struct bkey_s_c k)
{
	if (w->last_pos.inode != k.k->p.inode) {
		int ret = get_inodes_all_snapshots(trans, w, k.k->p.inode);
		if (ret)
			return ERR_PTR(ret);
	}

	w->last_pos = k.k->p;

	return lookup_inode_for_snapshot(trans, w, k);
}

/*
 * Prefer to delete the first one, since that will be the one at the wrong
 * offset:
 * return value: 0 -> delete k1, 1 -> delete k2
 */
int bch2_fsck_update_backpointers(struct btree_trans *trans,
				  struct snapshots_seen *s,
				  const struct bch_hash_desc desc,
				  struct bch_hash_info *hash_info,
				  struct bkey_i *new)
{
	if (new->k.type != KEY_TYPE_dirent)
		return 0;

	struct bkey_i_dirent *d = bkey_i_to_dirent(new);
	CLASS(inode_walker, target)();

	if (d->v.d_type == DT_SUBVOL) {
		bch_err(trans->c, "%s does not support DT_SUBVOL", __func__);
		return bch_err_throw(trans->c, fsck_repair_unimplemented);
	} else {
		try(get_visible_inodes(trans, &target, s, le64_to_cpu(d->v.d_inum)));

		darray_for_each(target.inodes, i) {
			i->inode.bi_dir_offset = d->k.p.offset;
			try(__bch2_fsck_write_inode(trans, &i->inode));
		}

		return 0;
	}
}

static struct bkey_s_c_dirent inode_get_dirent(struct btree_trans *trans,
					       struct btree_iter *iter,
					       struct bch_inode_unpacked *inode,
					       u32 *snapshot)
{
	if (inode->bi_subvol) {
		u64 inum;
		int ret = subvol_lookup(trans, inode->bi_parent_subvol, snapshot, &inum);
		if (ret)
			return ((struct bkey_s_c_dirent) { .k = ERR_PTR(ret) });
	}

	return dirent_get_by_pos(trans, iter, SPOS(inode->bi_dir, inode->bi_dir_offset, *snapshot));
}

static int check_inode_deleted_list(struct btree_trans *trans, struct bpos p)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_deleted_inodes, p, 0);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(&iter);
	return bkey_err(k) ?: k.k->type == KEY_TYPE_set;
}

static int check_inode_dirent_inode(struct btree_trans *trans,
				    struct bch_inode_unpacked *inode,
				    bool *write_inode)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();

	u32 inode_snapshot = inode->bi_snapshot;
	CLASS(btree_iter_uninit, dirent_iter)(trans);
	struct bkey_s_c_dirent d = inode_get_dirent(trans, &dirent_iter, inode, &inode_snapshot);
	int ret = bkey_err(d);
	if (ret && !bch2_err_matches(ret, ENOENT))
		return ret;

	if ((ret || dirent_points_to_inode_nowarn(c, d, inode)) &&
	    inode->bi_subvol &&
	    (inode->bi_flags & BCH_INODE_has_child_snapshot)) {
		/* Older version of a renamed subvolume root: we won't have a
		 * correct dirent for it. That's expected, see
		 * inode_should_reattach().
		 *
		 * We don't clear the backpointer field when doing the rename
		 * because there might be arbitrarily many versions in older
		 * snapshots.
		 */
		inode->bi_dir = 0;
		inode->bi_dir_offset = 0;
		*write_inode = true;
		return 0;
	}

	if (fsck_err_on(ret,
			trans, inode_points_to_missing_dirent,
			"inode points to missing dirent\n%s",
			(bch2_inode_unpacked_to_text(&buf, inode), buf.buf)) ||
	    fsck_err_on(!ret && dirent_points_to_inode_nowarn(c, d, inode),
			trans, inode_points_to_wrong_dirent,
			"%s",
			(printbuf_reset(&buf),
			 bch2_dirent_inode_mismatch_msg(&buf, c, d, inode),
			 buf.buf))) {
		/*
		 * We just clear the backpointer fields for now. If we find a
		 * dirent that points to this inode in check_dirents(), we'll
		 * update it then; then when we get to check_path() if the
		 * backpointer is still 0 we'll reattach it.
		 */
		inode->bi_dir = 0;
		inode->bi_dir_offset = 0;
		*write_inode = true;
	}

	ret = 0;
fsck_err:
	bch_err_fn(c, ret);
	return ret;
}

static int check_inode(struct btree_trans *trans,
		       struct btree_iter *iter,
		       struct bkey_s_c k,
		       struct bch_inode_unpacked *snapshot_root,
		       struct snapshots_seen *s)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();
	struct bch_inode_unpacked u;
	bool do_update = false;
	int ret;

	ret = bch2_check_key_has_snapshot(trans, iter, k);
	if (ret < 0)
		goto err;
	if (ret)
		return 0;

	ret = bch2_snapshots_seen_update(c, s, iter->btree_id, k.k->p);
	if (ret)
		goto err;

	if (!bkey_is_inode(k.k))
		return 0;

	ret = bch2_inode_unpack(k, &u);
	if (ret)
		goto err;

	if (snapshot_root->bi_inum != u.bi_inum) {
		ret = bch2_inode_find_snapshot_root(trans, u.bi_inum, snapshot_root);
		if (ret)
			goto err;
	}

	if (u.bi_hash_seed	!= snapshot_root->bi_hash_seed ||
	    INODE_STR_HASH(&u)	!= INODE_STR_HASH(snapshot_root)) {
		ret = bch2_repair_inode_hash_info(trans, snapshot_root);
		BUG_ON(ret == -BCH_ERR_fsck_repair_unimplemented);
		if (ret)
			goto err;
	}

	ret = bch2_check_inode_has_case_insensitive(trans, &u, &s->ids, &do_update);
	if (bch2_err_matches(ret, ENOENT)) /* disconnected inode; will be fixed by a later pass */
		ret = 0;
	bch_err_msg(c, ret, "bch2_check_inode_has_case_insensitive()");
	if (ret)
		goto err;

	if (bch2_inode_has_backpointer(&u)) {
		ret = check_inode_dirent_inode(trans, &u, &do_update);
		if (ret)
			goto err;
	}

	if (fsck_err_on(bch2_inode_has_backpointer(&u) &&
			(u.bi_flags & BCH_INODE_unlinked),
			trans, inode_unlinked_but_has_dirent,
			"inode unlinked but has dirent\n%s",
			(printbuf_reset(&buf),
			 bch2_inode_unpacked_to_text(&buf, &u),
			 buf.buf))) {
		u.bi_flags &= ~BCH_INODE_unlinked;
		do_update = true;
	}

	if (S_ISDIR(u.bi_mode) && (u.bi_flags & BCH_INODE_unlinked)) {
		/* Check for this early so that check_unreachable_inode() will reattach it */

		ret = bch2_empty_dir_snapshot(trans, k.k->p.offset, 0, k.k->p.snapshot);
		if (ret && ret != -BCH_ERR_ENOTEMPTY_dir_not_empty)
			goto err;

		fsck_err_on(ret, trans, inode_dir_unlinked_but_not_empty,
			    "dir unlinked but not empty\n%s",
			    (printbuf_reset(&buf),
			     bch2_inode_unpacked_to_text(&buf, &u),
			     buf.buf));
		u.bi_flags &= ~BCH_INODE_unlinked;
		do_update = true;
		ret = 0;
	}

	if (fsck_err_on(S_ISDIR(u.bi_mode) && u.bi_size,
			trans, inode_dir_has_nonzero_i_size,
			"directory %llu:%u with nonzero i_size %lli",
			u.bi_inum, u.bi_snapshot, u.bi_size)) {
		u.bi_size = 0;
		do_update = true;
	}

	ret = bch2_inode_has_child_snapshots(trans, k.k->p);
	if (ret < 0)
		goto err;

	if (fsck_err_on(ret != !!(u.bi_flags & BCH_INODE_has_child_snapshot),
			trans, inode_has_child_snapshots_wrong,
			"inode has_child_snapshots flag wrong (should be %u)\n%s",
			ret,
			(printbuf_reset(&buf),
			 bch2_inode_unpacked_to_text(&buf, &u),
			 buf.buf))) {
		if (ret)
			u.bi_flags |= BCH_INODE_has_child_snapshot;
		else
			u.bi_flags &= ~BCH_INODE_has_child_snapshot;
		do_update = true;
	}
	ret = 0;

	if ((u.bi_flags & BCH_INODE_unlinked) &&
	    !(u.bi_flags & BCH_INODE_has_child_snapshot)) {
		if (!test_bit(BCH_FS_started, &c->flags)) {
			/*
			 * If we're not in online fsck, don't delete unlinked
			 * inodes, just make sure they're on the deleted list.
			 *
			 * They might be referred to by a logged operation -
			 * i.e. we might have crashed in the middle of a
			 * truncate on an unlinked but open file - so we want to
			 * let the delete_dead_inodes kill it after resuming
			 * logged ops.
			 */
			ret = check_inode_deleted_list(trans, k.k->p);
			if (ret < 0)
				return ret;

			fsck_err_on(!ret,
				    trans, unlinked_inode_not_on_deleted_list,
				    "inode %llu:%u unlinked, but not on deleted list",
				    u.bi_inum, k.k->p.snapshot);

			ret = bch2_btree_bit_mod_buffered(trans, BTREE_ID_deleted_inodes, k.k->p, 1);
			if (ret)
				goto err;
		} else {
			ret = bch2_inode_or_descendents_is_open(trans, k.k->p);
			if (ret < 0)
				goto err;

			if (fsck_err_on(!ret,
					trans, inode_unlinked_and_not_open,
				      "inode %llu:%u unlinked and not open",
				      u.bi_inum, u.bi_snapshot)) {
				ret = bch2_inode_rm_snapshot(trans, u.bi_inum, iter->pos.snapshot);
				bch_err_msg(c, ret, "in fsck deleting inode");
				return ret;
			}
			ret = 0;
		}
	}

	if (fsck_err_on(u.bi_parent_subvol &&
			(u.bi_subvol == 0 ||
			 u.bi_subvol == BCACHEFS_ROOT_SUBVOL),
			trans, inode_bi_parent_nonzero,
			"inode %llu:%u has subvol %u but nonzero parent subvol %u",
			u.bi_inum, k.k->p.snapshot, u.bi_subvol, u.bi_parent_subvol)) {
		u.bi_parent_subvol = 0;
		do_update = true;
	}

	if (u.bi_subvol) {
		struct bch_subvolume s;

		ret = bch2_subvolume_get(trans, u.bi_subvol, false, &s);
		if (ret && !bch2_err_matches(ret, ENOENT))
			goto err;

		if (ret && (c->sb.btrees_lost_data & BIT_ULL(BTREE_ID_subvolumes))) {
			ret = reconstruct_subvol(trans, k.k->p.snapshot, u.bi_subvol, u.bi_inum);
			goto do_update;
		}

		if (fsck_err_on(ret,
				trans, inode_bi_subvol_missing,
				"inode %llu:%u bi_subvol points to missing subvolume %u",
				u.bi_inum, k.k->p.snapshot, u.bi_subvol) ||
		    fsck_err_on(le64_to_cpu(s.inode) != u.bi_inum ||
				!bch2_snapshot_is_ancestor(c, le32_to_cpu(s.snapshot),
							   k.k->p.snapshot),
				trans, inode_bi_subvol_wrong,
				"inode %llu:%u points to subvol %u, but subvol points to %llu:%u",
				u.bi_inum, k.k->p.snapshot, u.bi_subvol,
				le64_to_cpu(s.inode),
				le32_to_cpu(s.snapshot))) {
			u.bi_subvol = 0;
			u.bi_parent_subvol = 0;
			do_update = true;
		}
	}

	if (fsck_err_on(u.bi_journal_seq > journal_cur_seq(&c->journal),
			trans, inode_journal_seq_in_future,
			"inode journal seq in future (currently at %llu)\n%s",
			journal_cur_seq(&c->journal),
			(printbuf_reset(&buf),
			 bch2_inode_unpacked_to_text(&buf, &u),
			buf.buf))) {
		u.bi_journal_seq = journal_cur_seq(&c->journal);
		do_update = true;
	}
do_update:
	if (do_update) {
		ret = __bch2_fsck_write_inode(trans, &u);
		bch_err_msg(c, ret, "in fsck updating inode");
		if (ret)
			return ret;
	}
err:
fsck_err:
	bch_err_fn(c, ret);
	return ret;
}

int bch2_check_inodes(struct bch_fs *c)
{
	struct bch_inode_unpacked snapshot_root = {};

	CLASS(btree_trans, trans)(c);
	CLASS(snapshots_seen, s)();

	struct progress_indicator progress;
	bch2_progress_init(&progress, __func__, c, BIT_ULL(BTREE_ID_inodes), 0);

	return for_each_btree_key_commit(trans, iter, BTREE_ID_inodes,
				POS_MIN,
				BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		bch2_progress_update_iter(trans, &progress, &iter) ?:
		check_inode(trans, &iter, k, &snapshot_root, &s);
	}));
}

static int find_oldest_inode_needs_reattach(struct btree_trans *trans,
					    struct bch_inode_unpacked *inode)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c k;
	int ret = 0;

	/*
	 * We look for inodes to reattach in natural key order, leaves first,
	 * but we should do the reattach at the oldest version that needs to be
	 * reattached:
	 */
	for_each_btree_key_norestart(trans, iter,
				     BTREE_ID_inodes,
				     SPOS(0, inode->bi_inum, inode->bi_snapshot + 1),
				     BTREE_ITER_all_snapshots, k, ret) {
		if (k.k->p.offset != inode->bi_inum)
			break;

		if (!bch2_snapshot_is_ancestor(c, inode->bi_snapshot, k.k->p.snapshot))
			continue;

		if (!bkey_is_inode(k.k))
			break;

		struct bch_inode_unpacked parent_inode;
		try(bch2_inode_unpack(k, &parent_inode));

		if (!inode_should_reattach(&parent_inode))
			break;

		*inode = parent_inode;
	}

	return ret;
}

static int check_unreachable_inode(struct btree_trans *trans,
				   struct btree_iter *iter,
				   struct bkey_s_c k)
{
	CLASS(printbuf, buf)();
	int ret = 0;

	if (!bkey_is_inode(k.k))
		return 0;

	struct bch_inode_unpacked inode;
	try(bch2_inode_unpack(k, &inode));

	if (!inode_should_reattach(&inode))
		return 0;

	try(find_oldest_inode_needs_reattach(trans, &inode));

	if (fsck_err(trans, inode_unreachable,
		     "unreachable inode:\n%s",
		     (bch2_inode_unpacked_to_text(&buf, &inode),
		      buf.buf)))
		try(bch2_reattach_inode(trans, &inode));
fsck_err:
	return ret;
}

/*
 * Reattach unreachable (but not unlinked) inodes
 *
 * Run after check_inodes() and check_dirents(), so we node that inode
 * backpointer fields point to valid dirents, and every inode that has a dirent
 * that points to it has its backpointer field set - so we're just looking for
 * non-unlinked inodes without backpointers:
 *
 * XXX: this is racy w.r.t. hardlink removal in online fsck
 */
int bch2_check_unreachable_inodes(struct bch_fs *c)
{
	struct progress_indicator progress;
	bch2_progress_init(&progress, __func__, c, BIT_ULL(BTREE_ID_inodes), 0);

	CLASS(btree_trans, trans)(c);
	return for_each_btree_key_commit(trans, iter, BTREE_ID_inodes,
				POS_MIN,
				BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		bch2_progress_update_iter(trans, &progress, &iter) ?:
		check_unreachable_inode(trans, &iter, k);
	}));
}

static inline bool btree_matches_i_mode(enum btree_id btree, unsigned mode)
{
	switch (btree) {
	case BTREE_ID_extents:
		return S_ISREG(mode) || S_ISLNK(mode);
	case BTREE_ID_dirents:
		return S_ISDIR(mode);
	case BTREE_ID_xattrs:
		return true;
	default:
		BUG();
	}
}

int bch2_check_key_has_inode(struct btree_trans *trans,
			     struct btree_iter *iter,
			     struct inode_walker *inode,
			     struct inode_walker_entry *i,
			     struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();
	int ret = PTR_ERR_OR_ZERO(i);
	if (ret)
		return ret;

	if (bkey_extent_whiteout(k.k))
		return 0;

	bool have_inode = i && !i->whiteout;

	if (!have_inode && (c->sb.btrees_lost_data & BIT_ULL(BTREE_ID_inodes)))
		goto reconstruct;

	if (have_inode && btree_matches_i_mode(iter->btree_id, i->inode.bi_mode))
		return 0;

	prt_printf(&buf, ", ");

	bool have_old_inode = false;
	darray_for_each(inode->inodes, i2)
		if (!i2->whiteout &&
		    bch2_snapshot_is_ancestor(c, k.k->p.snapshot, i2->inode.bi_snapshot) &&
		    btree_matches_i_mode(iter->btree_id, i2->inode.bi_mode)) {
			prt_printf(&buf, "but found good inode in older snapshot\n");
			bch2_inode_unpacked_to_text(&buf, &i2->inode);
			prt_newline(&buf);
			have_old_inode = true;
			break;
		}

	struct bkey_s_c k2;
	unsigned nr_keys = 0;

	prt_printf(&buf, "found keys:\n");

	for_each_btree_key_max_norestart(trans, iter2, iter->btree_id,
					 SPOS(k.k->p.inode, 0, k.k->p.snapshot),
					 POS(k.k->p.inode, U64_MAX),
					 0, k2, ret) {
		if (k.k->type == KEY_TYPE_error ||
		    k.k->type == KEY_TYPE_hash_whiteout)
			continue;

		nr_keys++;
		if (nr_keys <= 10) {
			bch2_bkey_val_to_text(&buf, c, k2);
			prt_newline(&buf);
		}
		if (nr_keys >= 100)
			break;
	}

	if (ret)
		goto err;

	unsigned reconstruct_limit = iter->btree_id == BTREE_ID_extents ? 3 : 0;

	if (nr_keys > 100)
		prt_printf(&buf, "found > %u keys for this missing inode\n", nr_keys);
	else if (nr_keys > reconstruct_limit)
		prt_printf(&buf, "found %u keys for this missing inode\n", nr_keys);

	if (!have_inode) {
		if (fsck_err_on(!have_inode,
				trans, key_in_missing_inode,
				"key in missing inode%s", buf.buf)) {
			/*
			 * Maybe a deletion that raced with data move, or something
			 * weird like that? But if we know the inode was deleted, or
			 * it's just a few keys, we can safely delete them.
			 *
			 * If it's many keys, we should probably recreate the inode
			 */
			if (have_old_inode || nr_keys <= 2)
				goto delete;
			else
				goto reconstruct;
		}
	} else {
		/*
		 * not autofix, this one would be a giant wtf - bit error in the
		 * inode corrupting i_mode?
		 *
		 * may want to try repairing inode instead of deleting
		 */
		if (fsck_err_on(!btree_matches_i_mode(iter->btree_id, i->inode.bi_mode),
				trans, key_in_wrong_inode_type,
				"key for wrong inode mode %o%s",
				i->inode.bi_mode, buf.buf))
			goto delete;
	}
out:
err:
fsck_err:
	bch_err_fn(c, ret);
	return ret;
delete:
	/*
	 * XXX: print out more info
	 * count up extents for this inode, check if we have different inode in
	 * an older snapshot version, perhaps decide if we want to reconstitute
	 */
	ret = bch2_btree_delete_at(trans, iter, BTREE_UPDATE_internal_snapshot_node);
	goto out;
reconstruct:
	ret =   reconstruct_inode(trans, iter->btree_id, k.k->p.snapshot, k.k->p.inode) ?:
		bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc);
	if (ret)
		goto err;

	inode->last_pos.inode--;
	ret = bch_err_throw(c, transaction_restart_nested);
	goto out;
}

static int maybe_reconstruct_inum_btree(struct btree_trans *trans,
					u64 inum, u32 snapshot,
					enum btree_id btree)
{
	struct bkey_s_c k;
	int ret = 0;

	for_each_btree_key_max_norestart(trans, iter, btree,
					 SPOS(inum, 0, snapshot),
					 POS(inum, U64_MAX),
					 0, k, ret) {
		ret = 1;
		break;
	}

	if (ret <= 0)
		return ret;

	if (fsck_err(trans, missing_inode_with_contents,
		     "inode %llu:%u type %s missing, but contents found: reconstruct?",
		     inum, snapshot,
		     btree == BTREE_ID_extents ? "reg" : "dir"))
		return  reconstruct_inode(trans, btree, snapshot, inum) ?:
			bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc) ?:
			bch_err_throw(trans->c, transaction_restart_commit);
fsck_err:
	return ret;
}

static int maybe_reconstruct_inum(struct btree_trans *trans,
				  u64 inum, u32 snapshot)
{
	return  maybe_reconstruct_inum_btree(trans, inum, snapshot, BTREE_ID_extents) ?:
		maybe_reconstruct_inum_btree(trans, inum, snapshot, BTREE_ID_dirents);
}

static int check_subdir_count_notnested(struct btree_trans *trans, struct inode_walker *w)
{
	struct bch_fs *c = trans->c;
	int ret = 0;
	s64 count2;

	darray_for_each(w->inodes, i) {
		if (i->inode.bi_nlink == i->count)
			continue;

		count2 = bch2_count_subdirs(trans, w->last_pos.inode, i->inode.bi_snapshot);
		if (count2 < 0)
			return count2;

		if (i->count != count2) {
			bch_err_ratelimited(c, "fsck counted subdirectories wrong for inum %llu:%u: got %llu should be %llu",
					    w->last_pos.inode, i->inode.bi_snapshot, i->count, count2);
			i->count = count2;
			if (i->inode.bi_nlink == i->count)
				continue;
		}

		if (i->inode.bi_nlink != i->count) {
			CLASS(printbuf, buf)();

			lockrestart_do(trans,
				       bch2_inum_snapshot_to_path(trans, w->last_pos.inode,
								  i->inode.bi_snapshot, NULL, &buf));

			if (fsck_err_on(i->inode.bi_nlink != i->count,
					trans, inode_dir_wrong_nlink,
					"directory with wrong i_nlink: got %u, should be %llu\n%s",
					i->inode.bi_nlink, i->count, buf.buf)) {
				i->inode.bi_nlink = i->count;
				ret = bch2_fsck_write_inode(trans, &i->inode);
				if (ret)
					break;
			}
		}
	}
fsck_err:
	bch_err_fn(c, ret);
	return ret;
}

static int check_subdir_dirents_count(struct btree_trans *trans, struct inode_walker *w)
{
	u32 restart_count = trans->restart_count;
	return check_subdir_count_notnested(trans, w) ?:
		trans_was_restarted(trans, restart_count);
}

/* find a subvolume that's a descendent of @snapshot: */
static int find_snapshot_subvol(struct btree_trans *trans, u32 snapshot, u32 *subvolid)
{
	struct bkey_s_c k;
	int ret;

	for_each_btree_key_norestart(trans, iter, BTREE_ID_subvolumes, POS_MIN, 0, k, ret) {
		if (k.k->type != KEY_TYPE_subvolume)
			continue;

		struct bkey_s_c_subvolume s = bkey_s_c_to_subvolume(k);
		if (bch2_snapshot_is_ancestor(trans->c, le32_to_cpu(s.v->snapshot), snapshot)) {
			*subvolid = k.k->p.offset;
			return 0;
		}
	}

	return ret ?: -ENOENT;
}

noinline_for_stack
static int check_dirent_to_subvol(struct btree_trans *trans, struct btree_iter *iter,
				  struct bkey_s_c_dirent d)
{
	struct bch_fs *c = trans->c;
	CLASS(btree_iter_uninit, subvol_iter)(trans);
	struct bch_inode_unpacked subvol_root;
	u32 parent_subvol = le32_to_cpu(d.v->d_parent_subvol);
	u32 target_subvol = le32_to_cpu(d.v->d_child_subvol);
	u32 parent_snapshot;
	u32 new_parent_subvol = 0;
	u64 parent_inum;
	CLASS(printbuf, buf)();
	int ret = 0;

	ret = subvol_lookup(trans, parent_subvol, &parent_snapshot, &parent_inum);
	if (ret && !bch2_err_matches(ret, ENOENT))
		return ret;

	if (ret ||
	    (!ret && !bch2_snapshot_is_ancestor(c, parent_snapshot, d.k->p.snapshot))) {
		ret = find_snapshot_subvol(trans, d.k->p.snapshot, &new_parent_subvol);
		if (ret && !bch2_err_matches(ret, ENOENT))
			return ret;
	}

	if (ret &&
	    !new_parent_subvol &&
	    (c->sb.btrees_lost_data & BIT_ULL(BTREE_ID_subvolumes))) {
		/*
		 * Couldn't find a subvol for dirent's snapshot - but we lost
		 * subvols, so we need to reconstruct:
		 */
		try(reconstruct_subvol(trans, d.k->p.snapshot, parent_subvol, 0));

		parent_snapshot = d.k->p.snapshot;
	}

	if (fsck_err_on(ret,
			trans, dirent_to_missing_parent_subvol,
			"dirent parent_subvol points to missing subvolume\n%s",
			(bch2_bkey_val_to_text(&buf, c, d.s_c), buf.buf)) ||
	    fsck_err_on(!ret && !bch2_snapshot_is_ancestor(c, parent_snapshot, d.k->p.snapshot),
			trans, dirent_not_visible_in_parent_subvol,
			"dirent not visible in parent_subvol (not an ancestor of subvol snap %u)\n%s",
			parent_snapshot,
			(bch2_bkey_val_to_text(&buf, c, d.s_c), buf.buf))) {
		if (!new_parent_subvol) {
			bch_err(c, "could not find a subvol for snapshot %u", d.k->p.snapshot);
			return bch_err_throw(c, fsck_repair_unimplemented);
		}

		struct bkey_i_dirent *new_dirent = errptr_try(bch2_bkey_make_mut_typed(trans, iter, &d.s_c, 0, dirent));

		new_dirent->v.d_parent_subvol = cpu_to_le32(new_parent_subvol);
	}

	bch2_trans_iter_init(trans, &subvol_iter, BTREE_ID_subvolumes, POS(0, target_subvol), 0);
	struct bkey_s_c_subvolume s = bch2_bkey_get_typed(&subvol_iter, subvolume);
	ret = bkey_err(s.s_c);
	if (ret && !bch2_err_matches(ret, ENOENT))
		return ret;

	if (ret) {
		if (fsck_err(trans, dirent_to_missing_subvol,
			     "dirent points to missing subvolume\n%s",
			     (bch2_bkey_val_to_text(&buf, c, d.s_c), buf.buf)))
			return bch2_fsck_remove_dirent(trans, d.k->p);
		return 0;
	}

	if (le32_to_cpu(s.v->fs_path_parent) != parent_subvol) {
		printbuf_reset(&buf);

		prt_printf(&buf, "subvol with wrong fs_path_parent, should be be %u\n",
			   parent_subvol);

		try(bch2_inum_to_path(trans, (subvol_inum) { s.k->p.offset,
				      le64_to_cpu(s.v->inode) }, &buf));
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, s.s_c);

		if (fsck_err(trans, subvol_fs_path_parent_wrong, "%s", buf.buf)) {
			struct bkey_i_subvolume *n =
				errptr_try(bch2_bkey_make_mut_typed(trans, &subvol_iter, &s.s_c, 0, subvolume));

			n->v.fs_path_parent = cpu_to_le32(parent_subvol);
		}
	}

	u64 target_inum = le64_to_cpu(s.v->inode);
	u32 target_snapshot = le32_to_cpu(s.v->snapshot);

	ret = bch2_inode_find_by_inum_snapshot(trans, target_inum, target_snapshot,
					       &subvol_root, 0);
	if (ret && !bch2_err_matches(ret, ENOENT))
		return ret;

	if (ret) {
		bch_err(c, "subvol %u points to missing inode root %llu", target_subvol, target_inum);
		return bch_err_throw(c, fsck_repair_unimplemented);
	}

	if (fsck_err_on(!ret && parent_subvol != subvol_root.bi_parent_subvol,
			trans, inode_bi_parent_wrong,
			"subvol root %llu has wrong bi_parent_subvol: got %u, should be %u",
			target_inum,
			subvol_root.bi_parent_subvol, parent_subvol)) {
		subvol_root.bi_parent_subvol = parent_subvol;
		subvol_root.bi_snapshot = le32_to_cpu(s.v->snapshot);
		try(__bch2_fsck_write_inode(trans, &subvol_root));
	}

	try(bch2_check_dirent_target(trans, iter, d, &subvol_root, true));
fsck_err:
	return ret;
}

static int check_dirent(struct btree_trans *trans, struct btree_iter *iter,
			struct bkey_s_c k,
			struct bch_hash_info *hash_info,
			struct inode_walker *dir,
			struct inode_walker *target,
			struct snapshots_seen *s,
			bool *need_second_pass)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();
	int ret = 0;

	ret = bch2_check_key_has_snapshot(trans, iter, k);
	if (ret)
		return ret < 0 ? ret : 0;

	ret = bch2_snapshots_seen_update(c, s, iter->btree_id, k.k->p);
	if (ret)
		return ret;

	if (k.k->type == KEY_TYPE_whiteout)
		return 0;

	if (dir->last_pos.inode != k.k->p.inode && dir->have_inodes)
		try(check_subdir_dirents_count(trans, dir));

	struct inode_walker_entry *i = errptr_try(bch2_walk_inode(trans, dir, k));

	try(bch2_check_key_has_inode(trans, iter, dir, i, k));

	if (!i || i->whiteout)
		return 0;

	if (dir->first_this_inode)
		try(bch2_hash_info_init(c, &i->inode, hash_info));
	dir->first_this_inode = false;

	hash_info->cf_encoding = bch2_inode_casefold(c, &i->inode) ? c->cf_encoding : NULL;

	ret = bch2_str_hash_check_key(trans, s, &bch2_dirent_hash_desc, hash_info,
				      iter, k, need_second_pass);
	if (ret < 0)
		return ret;
	if (ret)
		return 0; /* dirent has been deleted */
	if (k.k->type != KEY_TYPE_dirent)
		return 0;

	struct bkey_s_c_dirent d = bkey_s_c_to_dirent(k);

	if (d.v->d_type == DT_SUBVOL) {
		try(check_dirent_to_subvol(trans, iter, d));
	} else {
		try(get_visible_inodes(trans, target, s, le64_to_cpu(d.v->d_inum)));

		if (!target->inodes.nr)
			try(maybe_reconstruct_inum(trans, le64_to_cpu(d.v->d_inum), d.k->p.snapshot));

		if (fsck_err_on(!target->inodes.nr,
				trans, dirent_to_missing_inode,
				"dirent points to missing inode:\n%s",
				(printbuf_reset(&buf),
				 bch2_bkey_val_to_text(&buf, c, k),
				 buf.buf)))
			try(bch2_fsck_remove_dirent(trans, d.k->p));

		darray_for_each(target->inodes, i)
			try(bch2_check_dirent_target(trans, iter, d, &i->inode, true));

		darray_for_each(target->deletes, i)
			if (fsck_err_on(!snapshot_list_has_id(&s->ids, *i),
					trans, dirent_to_overwritten_inode,
					"dirent points to inode overwritten in snapshot %u:\n%s",
					*i,
					(printbuf_reset(&buf),
					 bch2_bkey_val_to_text(&buf, c, k),
					 buf.buf))) {
				CLASS(btree_iter, delete_iter)(trans,
						     BTREE_ID_dirents,
						     SPOS(k.k->p.inode, k.k->p.offset, *i),
						     BTREE_ITER_intent);
				try(bch2_btree_iter_traverse(&delete_iter));
				try(bch2_hash_delete_at(trans, bch2_dirent_hash_desc,
							hash_info,
							&delete_iter,
							BTREE_UPDATE_internal_snapshot_node));
			}
	}

	/*
	 * Cannot access key values after doing a transaction commit without
	 * revalidating:
	 */
	bool have_dir = d.v->d_type == DT_DIR;

	try(bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc));

	for_each_visible_inode(c, s, dir, d.k->p.snapshot, i) {
		if (have_dir)
			i->count++;
		i->i_size += bkey_bytes(d.k);
	}
fsck_err:
	return ret;
}

/*
 * Walk dirents: verify that they all have a corresponding S_ISDIR inode,
 * validate d_type
 */
int bch2_check_dirents(struct bch_fs *c)
{
	struct bch_hash_info hash_info;
	CLASS(btree_trans, trans)(c);
	CLASS(snapshots_seen, s)();
	CLASS(inode_walker, dir)();
	CLASS(inode_walker, target)();
	struct progress_indicator progress;
	bool need_second_pass = false, did_second_pass = false;
	int ret;
again:
	bch2_progress_init(&progress, __func__, c, BIT_ULL(BTREE_ID_dirents), 0);

	ret = for_each_btree_key_commit(trans, iter, BTREE_ID_dirents,
				POS(BCACHEFS_ROOT_INO, 0),
				BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
			bch2_progress_update_iter(trans, &progress, &iter) ?:
			check_dirent(trans, &iter, k, &hash_info, &dir, &target, &s,
				     &need_second_pass);
		})) ?:
		check_subdir_count_notnested(trans, &dir);

	if (!ret && need_second_pass && !did_second_pass) {
		bch_info(c, "check_dirents requires second pass");
		swap(did_second_pass, need_second_pass);
		goto again;
	}

	if (!ret && need_second_pass) {
		bch_err(c, "dirents not repairing");
		ret = -EINVAL;
	}

	return ret;
}

static int check_xattr(struct btree_trans *trans, struct btree_iter *iter,
		       struct bkey_s_c k,
		       struct bch_hash_info *hash_info,
		       struct inode_walker *inode)
{
	struct bch_fs *c = trans->c;

	int ret = bch2_check_key_has_snapshot(trans, iter, k);
	if (ret < 0)
		return ret;
	if (ret)
		return 0;

	struct inode_walker_entry *i = errptr_try(bch2_walk_inode(trans, inode, k));

	try(bch2_check_key_has_inode(trans, iter, inode, i, k));

	if (!i || i->whiteout)
		return 0;

	if (inode->first_this_inode)
		try(bch2_hash_info_init(c, &i->inode, hash_info));
	inode->first_this_inode = false;

	bool need_second_pass = false;
	return bch2_str_hash_check_key(trans, NULL, &bch2_xattr_hash_desc, hash_info,
				      iter, k, &need_second_pass);
}

/*
 * Walk xattrs: verify that they all have a corresponding inode
 */
int bch2_check_xattrs(struct bch_fs *c)
{
	struct bch_hash_info hash_info;
	CLASS(btree_trans, trans)(c);
	CLASS(inode_walker, inode)();

	struct progress_indicator progress;
	bch2_progress_init(&progress, __func__, c, BIT_ULL(BTREE_ID_xattrs), 0);

	int ret = for_each_btree_key_commit(trans, iter, BTREE_ID_xattrs,
			POS(BCACHEFS_ROOT_INO, 0),
			BTREE_ITER_prefetch|BTREE_ITER_all_snapshots,
			k,
			NULL, NULL,
			BCH_TRANS_COMMIT_no_enospc, ({
		bch2_progress_update_iter(trans, &progress, &iter) ?:
		check_xattr(trans, &iter, k, &hash_info, &inode);
	}));
	return ret;
}

static int check_root_trans(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;

	u32 snapshot;
	u64 inum;
	int ret = subvol_lookup(trans, BCACHEFS_ROOT_SUBVOL, &snapshot, &inum);
	if (ret && !bch2_err_matches(ret, ENOENT))
		return ret;

	if (mustfix_fsck_err_on(ret, trans, root_subvol_missing,
				"root subvol missing")) {
		struct bkey_i_subvolume *root_subvol =
			errptr_try(bch2_trans_kmalloc(trans, sizeof(*root_subvol)));

		snapshot	= U32_MAX;
		inum		= BCACHEFS_ROOT_INO;

		bkey_subvolume_init(&root_subvol->k_i);
		root_subvol->k.p.offset = BCACHEFS_ROOT_SUBVOL;
		root_subvol->v.flags	= 0;
		root_subvol->v.snapshot	= cpu_to_le32(snapshot);
		root_subvol->v.inode	= cpu_to_le64(inum);
		try(bch2_btree_insert_trans(trans, BTREE_ID_subvolumes, &root_subvol->k_i, 0));
	}

	struct bch_inode_unpacked root_inode;
	ret = bch2_inode_find_by_inum_snapshot(trans, BCACHEFS_ROOT_INO, snapshot,
					       &root_inode, 0);
	if (ret && !bch2_err_matches(ret, ENOENT))
		return ret;

	if (mustfix_fsck_err_on(ret,
				trans, root_dir_missing,
				"root directory missing") ||
	    mustfix_fsck_err_on(!S_ISDIR(root_inode.bi_mode),
				trans, root_inode_not_dir,
				"root inode not a directory")) {
		bch2_inode_init(c, &root_inode, 0, 0, S_IFDIR|0755,
				0, NULL);
		root_inode.bi_inum = inum;
		root_inode.bi_snapshot = snapshot;

		ret = __bch2_fsck_write_inode(trans, &root_inode);
		bch_err_msg(c, ret, "writing root inode");
	}
fsck_err:
	return ret;
}

/* Get root directory, create if it doesn't exist: */
int bch2_check_root(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	return commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			 check_root_trans(trans));
}

static int fix_reflink_p_key(struct btree_trans *trans, struct btree_iter *iter,
			     struct bkey_s_c k)
{
	struct bkey_s_c_reflink_p p;

	if (k.k->type != KEY_TYPE_reflink_p)
		return 0;

	p = bkey_s_c_to_reflink_p(k);

	if (!p.v->front_pad && !p.v->back_pad)
		return 0;

	struct bkey_i_reflink_p *u = errptr_try(bch2_trans_kmalloc(trans, sizeof(*u)));

	bkey_reassemble(&u->k_i, k);
	u->v.front_pad	= 0;
	u->v.back_pad	= 0;

	return bch2_trans_update(trans, iter, &u->k_i, BTREE_TRIGGER_norun);
}

int bch2_fix_reflink_p(struct bch_fs *c)
{
	if (c->sb.version >= bcachefs_metadata_version_reflink_p_fix)
		return 0;

	CLASS(btree_trans, trans)(c);
	return for_each_btree_key_commit(trans, iter,
				BTREE_ID_extents, POS_MIN,
				BTREE_ITER_intent|BTREE_ITER_prefetch|
				BTREE_ITER_all_snapshots, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			fix_reflink_p_key(trans, &iter, k));
}

/* translate to return code of fsck commad - man(8) fsck */
int bch2_fs_fsck_errcode(struct bch_fs *c, struct printbuf *msg)
{
	int ret = 0;

	if (test_bit(BCH_FS_errors_fixed, &c->flags)) {
		prt_printf(msg, "%s: errors fixed\n", c->name);
		ret |= 1;
	}
	if (test_bit(BCH_FS_error, &c->flags)) {
		prt_printf(msg, "%s: still has errors\n", c->name);
		ret |= 4;
	}
	if (test_bit(BCH_FS_emergency_ro, &c->flags)) {
		prt_printf(msg, "%s: fatal error (went emergency read-only)\n", c->name);
		ret |= 4;
	}

	return ret;
}

#ifndef NO_BCACHEFS_CHARDEV

struct fsck_thread {
	struct thread_with_stdio thr;
	struct bch_fs		*c;
	struct bch_opts		opts;
};

static void bch2_fsck_thread_exit(struct thread_with_stdio *_thr)
{
	struct fsck_thread *thr = container_of(_thr, struct fsck_thread, thr);
	kfree(thr);
}

static int bch2_fsck_offline_thread_fn(struct thread_with_stdio *stdio)
{
	struct fsck_thread *thr = container_of(stdio, struct fsck_thread, thr);
	struct bch_fs *c = thr->c;

	errptr_try(c);

	c->recovery_task = current;

	int ret = bch2_fs_start(c);

	CLASS(printbuf, buf)();
	if (ret)
		prt_printf(&buf, "%s: error starting filesystem: %s\n", c->name, bch2_err_str(ret));
	else
		ret = bch2_fs_fsck_errcode(c, &buf);
	if (ret)
		bch2_stdio_redirect_write(&stdio->stdio, false, buf.buf, buf.pos);

	bch2_fs_exit(c);
	return ret;
}

static const struct thread_with_stdio_ops bch2_offline_fsck_ops = {
	.exit		= bch2_fsck_thread_exit,
	.fn		= bch2_fsck_offline_thread_fn,
};

static int parse_mount_opts_user(char __user *optstr_user, struct bch_opts *opts)
{
	char *optstr __free(kfree) = errptr_try(strndup_user(optstr_user, 1 << 16));

	return bch2_parse_mount_opts(NULL, opts, NULL, optstr, false);
}

long bch2_ioctl_fsck_offline(struct bch_ioctl_fsck_offline __user *user_arg)
{
	struct bch_ioctl_fsck_offline arg;

	try(copy_from_user_errcode(&arg, user_arg, sizeof(arg)));

	if (arg.flags)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	struct bch_opts opts = bch2_opts_empty();
	if (arg.opts)
		try(parse_mount_opts_user((char __user *)(unsigned long) arg.opts, &opts));

	CLASS(darray_const_str, devs)();
	for (size_t i = 0; i < arg.nr_devs; i++) {
		u64 dev_u64;
		try(copy_from_user_errcode(&dev_u64, &user_arg->devs[i], sizeof(u64)));

		char *dev_str =
			errptr_try(strndup_user((char __user *)(unsigned long) dev_u64, PATH_MAX));

		int ret = darray_push(&devs, dev_str);
		if (ret) {
			kfree(dev_str);
			return ret;
		}
	}

	struct fsck_thread *thr = kzalloc(sizeof(*thr), GFP_KERNEL);
	if (!thr)
		return -ENOMEM;

	thr->opts = opts;

	opt_set(thr->opts, stdio, (u64)(unsigned long)&thr->thr.stdio);
	opt_set(thr->opts, read_only, 1);
	opt_set(thr->opts, ratelimit_errors, 0);

	/* We need request_key() to be called before we punt to kthread: */
	opt_set(thr->opts, nostart, true);

	bch2_thread_with_stdio_init(&thr->thr, &bch2_offline_fsck_ops);

	thr->c = bch2_fs_open(&devs, &thr->opts);

	if (!IS_ERR(thr->c) &&
	    thr->c->opts.errors == BCH_ON_ERROR_panic)
		thr->c->opts.errors = BCH_ON_ERROR_ro;

	int ret = __bch2_run_thread_with_stdio(&thr->thr);
	if (ret < 0) {
		if (thr)
			bch2_fsck_thread_exit(&thr->thr);
		pr_err("ret %s", bch2_err_str(ret));
	}
	return ret;
}

static int bch2_fsck_online_thread_fn(struct thread_with_stdio *stdio)
{
	struct fsck_thread *thr = container_of(stdio, struct fsck_thread, thr);
	struct bch_fs *c = thr->c;
	CLASS(printbuf, buf)();
	int ret = -EAGAIN;

	u64 online = bch2_recovery_passes_match(PASS_ONLINE);
	u64 passes = bch2_recovery_passes_match(PASS_FSCK) & online;

	if (opt_defined(thr->opts, recovery_passes)) {
		passes = thr->opts.recovery_passes;

		if ((passes & online) != passes) {
			prt_printf(&buf, "Cannot run passes ");
			prt_bitflags(&buf, bch2_recovery_passes, passes & ~online);
			prt_printf(&buf, " online\n");
			bch2_stdio_redirect_write(&stdio->stdio, false, buf.buf, buf.pos);
			return -EINVAL;
		}
	}

	if (mutex_trylock(&c->recovery.run_lock)) {
		c->stdio_filter = current;
		c->stdio = &thr->thr.stdio;

		/*
		 * XXX: can we figure out a way to do this without mucking with c->opts?
		 */
		unsigned old_fix_errors = c->opts.fix_errors;
		if (opt_defined(thr->opts, fix_errors))
			c->opts.fix_errors = thr->opts.fix_errors;
		else
			c->opts.fix_errors = FSCK_FIX_ask;

		c->opts.fsck = true;
		set_bit(BCH_FS_in_fsck, &c->flags);

		ret = bch2_run_recovery_passes(c, passes, true) ?:
			bch2_fs_fsck_errcode(c, &buf);

		clear_bit(BCH_FS_in_fsck, &c->flags);

		c->stdio = NULL;
		c->stdio_filter = NULL;
		c->opts.fix_errors = old_fix_errors;

		mutex_unlock(&c->recovery.run_lock);
	}
	bch2_ro_ref_put(c);

	if (ret < 0) {
		prt_printf(&buf, "%s: error running recovery passes: %s\n", c->name, bch2_err_str(ret));
		ret = 8;
	}

	if (buf.pos)
		bch2_stdio_redirect_write(&stdio->stdio, false, buf.buf, buf.pos);
	return ret;
}

static const struct thread_with_stdio_ops bch2_online_fsck_ops = {
	.exit		= bch2_fsck_thread_exit,
	.fn		= bch2_fsck_online_thread_fn,
};

long bch2_ioctl_fsck_online(struct bch_fs *c, struct bch_ioctl_fsck_online arg)
{
	if (arg.flags)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	struct bch_opts opts = bch2_opts_empty();
	if (arg.opts)
		try(parse_mount_opts_user((char __user *)(unsigned long) arg.opts, &opts));

	if (!bch2_ro_ref_tryget(c))
		return -EROFS;

	struct fsck_thread *thr = kzalloc(sizeof(*thr), GFP_KERNEL);
	if (!thr) {
		bch2_ro_ref_put(c);
		return -ENOMEM;
	}

	thr->c = c;
	thr->opts = opts;

	int ret = bch2_run_thread_with_stdio(&thr->thr, &bch2_online_fsck_ops);
	if (ret < 0) {
		bch_err_fn(c, ret);
		bch2_fsck_thread_exit(&thr->thr);
		bch2_ro_ref_put(c);
	}
	return ret;
}

#endif /* NO_BCACHEFS_CHARDEV */
