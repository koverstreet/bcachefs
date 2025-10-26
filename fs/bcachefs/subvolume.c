// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_key_cache.h"
#include "btree_update.h"
#include "enumerated_ref.h"
#include "errcode.h"
#include "error.h"
#include "fs.h"
#include "recovery_passes.h"
#include "snapshot.h"
#include "subvolume.h"

#include <linux/random.h>

static int bch2_subvolume_delete(struct btree_trans *, u32);

static int bch2_subvolume_missing(struct bch_fs *c, u32 subvolid)
{
	struct printbuf buf = PRINTBUF;
	bch2_log_msg_start(c, &buf);

	prt_printf(&buf, "missing subvolume %u", subvolid);
	bool print = bch2_count_fsck_err(c, subvol_missing, &buf);

	int ret = bch2_run_explicit_recovery_pass(c, &buf,
					BCH_RECOVERY_PASS_check_inodes, 0);
	if (print)
		bch2_print_str(c, KERN_ERR, buf.buf);
	printbuf_exit(&buf);
	return ret;
}

static struct bpos subvolume_children_pos(struct bkey_s_c k)
{
	if (k.k->type != KEY_TYPE_subvolume)
		return POS_MIN;

	struct bkey_s_c_subvolume s = bkey_s_c_to_subvolume(k);
	if (!s.v->fs_path_parent)
		return POS_MIN;
	return POS(le32_to_cpu(s.v->fs_path_parent), s.k->p.offset);
}

static int check_subvol(struct btree_trans *trans,
			struct btree_iter *iter,
			struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c_subvolume subvol;
	struct btree_iter subvol_children_iter = {};
	struct bch_snapshot snapshot;
	struct printbuf buf = PRINTBUF;
	unsigned snapid;
	int ret = 0;

	if (k.k->type != KEY_TYPE_subvolume)
		return 0;

	subvol = bkey_s_c_to_subvolume(k);
	snapid = le32_to_cpu(subvol.v->snapshot);
	ret = bch2_snapshot_lookup(trans, snapid, &snapshot);

	if (bch2_err_matches(ret, ENOENT))
		return bch2_run_print_explicit_recovery_pass(c,
					BCH_RECOVERY_PASS_reconstruct_snapshots) ?: ret;
	if (ret)
		return ret;

	if (BCH_SUBVOLUME_UNLINKED(subvol.v)) {
		ret = bch2_subvolume_delete(trans, iter->pos.offset);
		bch_err_msg(c, ret, "deleting subvolume %llu", iter->pos.offset);
		return ret ?: bch_err_throw(c, transaction_restart_nested);
	}

	if (fsck_err_on(subvol.k->p.offset == BCACHEFS_ROOT_SUBVOL &&
			subvol.v->fs_path_parent,
			trans, subvol_root_fs_path_parent_nonzero,
			"root subvolume has nonzero fs_path_parent\n%s",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
		struct bkey_i_subvolume *n =
			bch2_bkey_make_mut_typed(trans, iter, &subvol.s_c, 0, subvolume);
		ret = PTR_ERR_OR_ZERO(n);
		if (ret)
			goto err;

		n->v.fs_path_parent = 0;
	}

	if (subvol.v->fs_path_parent) {
		struct bpos pos = subvolume_children_pos(k);

		struct bkey_s_c subvol_children_k =
			bch2_bkey_get_iter(trans, &subvol_children_iter,
					   BTREE_ID_subvolume_children, pos, 0);
		ret = bkey_err(subvol_children_k);
		if (ret)
			goto err;

		if (fsck_err_on(subvol_children_k.k->type != KEY_TYPE_set,
				trans, subvol_children_not_set,
				"subvolume not set in subvolume_children btree at %llu:%llu\n%s",
				pos.inode, pos.offset,
				(printbuf_reset(&buf),
				 bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
			ret = bch2_btree_bit_mod(trans, BTREE_ID_subvolume_children, pos, true);
			if (ret)
				goto err;
		}
	}

	struct bch_inode_unpacked inode;
	ret = bch2_inode_find_by_inum_nowarn_trans(trans,
				    (subvol_inum) { k.k->p.offset, le64_to_cpu(subvol.v->inode) },
				    &inode);
	if (!ret) {
		if (fsck_err_on(inode.bi_subvol != subvol.k->p.offset,
				trans, subvol_root_wrong_bi_subvol,
				"subvol root %llu:%u has wrong bi_subvol field: got %u, should be %llu",
				inode.bi_inum, inode.bi_snapshot,
				inode.bi_subvol, subvol.k->p.offset)) {
			inode.bi_subvol = subvol.k->p.offset;
			inode.bi_snapshot = le32_to_cpu(subvol.v->snapshot);
			ret = __bch2_fsck_write_inode(trans, &inode);
			if (ret)
				goto err;
		}
	} else if (bch2_err_matches(ret, ENOENT)) {
		if (fsck_err(trans, subvol_to_missing_root,
			     "subvolume %llu points to missing subvolume root %llu:%u",
			     k.k->p.offset, le64_to_cpu(subvol.v->inode),
			     le32_to_cpu(subvol.v->snapshot))) {
			/*
			 * Recreate - any contents that are still disconnected
			 * will then get reattached under lost+found
			 */
			bch2_inode_init_early(c, &inode);
			bch2_inode_init_late(c, &inode, bch2_current_time(c),
					     0, 0, S_IFDIR|0700, 0, NULL);
			inode.bi_inum			= le64_to_cpu(subvol.v->inode);
			inode.bi_snapshot		= le32_to_cpu(subvol.v->snapshot);
			inode.bi_subvol			= k.k->p.offset;
			inode.bi_parent_subvol		= le32_to_cpu(subvol.v->fs_path_parent);
			ret = __bch2_fsck_write_inode(trans, &inode);
			if (ret)
				goto err;
		}
	} else {
		goto err;
	}

	if (!BCH_SUBVOLUME_SNAP(subvol.v)) {
		u32 snapshot_root = bch2_snapshot_root(c, le32_to_cpu(subvol.v->snapshot));
		u32 snapshot_tree = bch2_snapshot_tree(c, snapshot_root);

		struct bch_snapshot_tree st;
		ret = bch2_snapshot_tree_lookup(trans, snapshot_tree, &st);

		bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), c,
				"%s: snapshot tree %u not found", __func__, snapshot_tree);

		if (ret)
			goto err;

		if (fsck_err_on(le32_to_cpu(st.master_subvol) != subvol.k->p.offset,
				trans, subvol_not_master_and_not_snapshot,
				"subvolume %llu is not set as snapshot but is not master subvolume",
				k.k->p.offset)) {
			struct bkey_i_subvolume *s =
				bch2_bkey_make_mut_typed(trans, iter, &subvol.s_c, 0, subvolume);
			ret = PTR_ERR_OR_ZERO(s);
			if (ret)
				goto err;

			SET_BCH_SUBVOLUME_SNAP(&s->v, true);
		}
	}
err:
fsck_err:
	bch2_trans_iter_exit(trans, &subvol_children_iter);
	printbuf_exit(&buf);
	return ret;
}

int bch2_check_subvols(struct bch_fs *c)
{
	int ret = bch2_trans_run(c,
		for_each_btree_key_commit(trans, iter,
				BTREE_ID_subvolumes, POS_MIN, BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			check_subvol(trans, &iter, k)));
	bch_err_fn(c, ret);
	return ret;
}

static int check_subvol_child(struct btree_trans *trans,
			      struct btree_iter *child_iter,
			      struct bkey_s_c child_k)
{
	struct bch_subvolume s;
	int ret = bch2_bkey_get_val_typed(trans, BTREE_ID_subvolumes, POS(0, child_k.k->p.offset),
					  0, subvolume, &s);
	if (ret && !bch2_err_matches(ret, ENOENT))
		return ret;

	if (fsck_err_on(ret ||
			le32_to_cpu(s.fs_path_parent) != child_k.k->p.inode,
			trans, subvol_children_bad,
			"incorrect entry in subvolume_children btree %llu:%llu",
			child_k.k->p.inode, child_k.k->p.offset)) {
		ret = bch2_btree_delete_at(trans, child_iter, 0);
		if (ret)
			goto err;
	}
err:
fsck_err:
	return ret;
}

int bch2_check_subvol_children(struct bch_fs *c)
{
	int ret = bch2_trans_run(c,
		for_each_btree_key_commit(trans, iter,
				BTREE_ID_subvolume_children, POS_MIN, BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			check_subvol_child(trans, &iter, k)));
	bch_err_fn(c, ret);
	return 0;
}

/* Subvolumes: */

int bch2_subvolume_validate(struct bch_fs *c, struct bkey_s_c k,
			    struct bkey_validate_context from)
{
	struct bkey_s_c_subvolume subvol = bkey_s_c_to_subvolume(k);
	int ret = 0;

	bkey_fsck_err_on(bkey_lt(k.k->p, SUBVOL_POS_MIN) ||
			 bkey_gt(k.k->p, SUBVOL_POS_MAX),
			 c, subvol_pos_bad,
			 "invalid pos");

	bkey_fsck_err_on(!subvol.v->snapshot,
			 c, subvol_snapshot_bad,
			 "invalid snapshot");

	bkey_fsck_err_on(!subvol.v->inode,
			 c, subvol_inode_bad,
			 "invalid inode");
fsck_err:
	return ret;
}

void bch2_subvolume_to_text(struct printbuf *out, struct bch_fs *c,
			    struct bkey_s_c k)
{
	struct bkey_s_c_subvolume s = bkey_s_c_to_subvolume(k);

	prt_printf(out, "root %llu snapshot id %u",
		   le64_to_cpu(s.v->inode),
		   le32_to_cpu(s.v->snapshot));

	if (bkey_val_bytes(s.k) > offsetof(struct bch_subvolume, creation_parent)) {
		prt_printf(out, " creation_parent %u", le32_to_cpu(s.v->creation_parent));
		prt_printf(out, " fs_parent %u", le32_to_cpu(s.v->fs_path_parent));
	}

	if (BCH_SUBVOLUME_RO(s.v))
		prt_printf(out, " ro");
	if (BCH_SUBVOLUME_SNAP(s.v))
		prt_printf(out, " snapshot");
	if (BCH_SUBVOLUME_UNLINKED(s.v))
		prt_printf(out, " unlinked");
}

static int subvolume_children_mod(struct btree_trans *trans, struct bpos pos, bool set)
{
	return !bpos_eq(pos, POS_MIN)
		? bch2_btree_bit_mod(trans, BTREE_ID_subvolume_children, pos, set)
		: 0;
}

int bch2_subvolume_trigger(struct btree_trans *trans,
			   enum btree_id btree_id, unsigned level,
			   struct bkey_s_c old, struct bkey_s new,
			   enum btree_iter_update_trigger_flags flags)
{
	if (flags & BTREE_TRIGGER_transactional) {
		struct bpos children_pos_old = subvolume_children_pos(old);
		struct bpos children_pos_new = subvolume_children_pos(new.s_c);

		if (!bpos_eq(children_pos_old, children_pos_new)) {
			int ret = subvolume_children_mod(trans, children_pos_old, false) ?:
				  subvolume_children_mod(trans, children_pos_new, true);
			if (ret)
				return ret;
		}
	}

	return 0;
}

int bch2_subvol_has_children(struct btree_trans *trans, u32 subvol)
{
	struct btree_iter iter;

	bch2_trans_iter_init(trans, &iter, BTREE_ID_subvolume_children, POS(subvol, 0), 0);
	struct bkey_s_c k = bch2_btree_iter_peek(trans, &iter);
	bch2_trans_iter_exit(trans, &iter);

	return bkey_err(k) ?: k.k && k.k->p.inode == subvol
		? bch_err_throw(trans->c, ENOTEMPTY_subvol_not_empty)
		: 0;
}

static __always_inline int
bch2_subvolume_get_inlined(struct btree_trans *trans, unsigned subvol,
			   bool inconsistent_if_not_found,
			   struct bch_subvolume *s)
{
	int ret = bch2_bkey_get_val_typed(trans, BTREE_ID_subvolumes, POS(0, subvol),
					  BTREE_ITER_cached|
					  BTREE_ITER_with_updates, subvolume, s);
	if (bch2_err_matches(ret, ENOENT) && inconsistent_if_not_found)
		ret = bch2_subvolume_missing(trans->c, subvol) ?: ret;
	return ret;
}

int bch2_subvolume_get(struct btree_trans *trans, unsigned subvol,
		       bool inconsistent_if_not_found,
		       struct bch_subvolume *s)
{
	return bch2_subvolume_get_inlined(trans, subvol, inconsistent_if_not_found, s);
}

int bch2_subvol_is_ro_trans(struct btree_trans *trans, u32 subvol)
{
	struct bch_subvolume s;
	int ret = bch2_subvolume_get_inlined(trans, subvol, true, &s);
	if (ret)
		return ret;

	if (BCH_SUBVOLUME_RO(&s))
		return -EROFS;
	return 0;
}

int bch2_subvol_is_ro(struct bch_fs *c, u32 subvol)
{
	return bch2_trans_do(c, bch2_subvol_is_ro_trans(trans, subvol));
}

int bch2_snapshot_get_subvol(struct btree_trans *trans, u32 snapshot,
			     struct bch_subvolume *subvol)
{
	struct bch_snapshot snap;

	return  bch2_snapshot_lookup(trans, snapshot, &snap) ?:
		bch2_subvolume_get(trans, le32_to_cpu(snap.subvol), true, subvol);
}

int __bch2_subvolume_get_snapshot(struct btree_trans *trans, u32 subvolid,
				  u32 *snapid, bool warn)
{
	struct btree_iter iter;
	struct bkey_s_c_subvolume subvol;
	int ret;

	subvol = bch2_bkey_get_iter_typed(trans, &iter,
					  BTREE_ID_subvolumes, POS(0, subvolid),
					  BTREE_ITER_cached|BTREE_ITER_with_updates,
					  subvolume);
	ret = bkey_err(subvol);

	if (bch2_err_matches(ret, ENOENT))
		ret = bch2_subvolume_missing(trans->c, subvolid) ?: ret;

	if (likely(!ret))
		*snapid = le32_to_cpu(subvol.v->snapshot);
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

int bch2_subvolume_get_snapshot(struct btree_trans *trans, u32 subvolid,
				u32 *snapid)
{
	return __bch2_subvolume_get_snapshot(trans, subvolid, snapid, true);
}

static int bch2_subvolume_reparent(struct btree_trans *trans,
				   struct btree_iter *iter,
				   struct bkey_s_c k,
				   u32 old_parent, u32 new_parent)
{
	struct bkey_i_subvolume *s;
	int ret;

	if (k.k->type != KEY_TYPE_subvolume)
		return 0;

	if (bkey_val_bytes(k.k) > offsetof(struct bch_subvolume, creation_parent) &&
	    le32_to_cpu(bkey_s_c_to_subvolume(k).v->creation_parent) != old_parent)
		return 0;

	s = bch2_bkey_make_mut_typed(trans, iter, &k, 0, subvolume);
	ret = PTR_ERR_OR_ZERO(s);
	if (ret)
		return ret;

	s->v.creation_parent = cpu_to_le32(new_parent);
	return 0;
}

/*
 * Separate from the snapshot tree in the snapshots btree, we record the tree
 * structure of how snapshot subvolumes were created - the parent subvolume of
 * each snapshot subvolume.
 *
 * When a subvolume is deleted, we scan for child subvolumes and reparant them,
 * to avoid dangling references:
 */
static int bch2_subvolumes_reparent(struct btree_trans *trans, u32 subvolid_to_delete)
{
	struct bch_subvolume s;

	return lockrestart_do(trans,
			bch2_subvolume_get(trans, subvolid_to_delete, true, &s)) ?:
		for_each_btree_key_commit(trans, iter,
				BTREE_ID_subvolumes, POS_MIN, BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			bch2_subvolume_reparent(trans, &iter, k,
					subvolid_to_delete, le32_to_cpu(s.creation_parent)));
}

/*
 * Delete subvolume, mark snapshot ID as deleted, queue up snapshot
 * deletion/cleanup:
 */
static int __bch2_subvolume_delete(struct btree_trans *trans, u32 subvolid)
{
	struct btree_iter subvol_iter = {}, snapshot_iter = {}, snapshot_tree_iter = {};

	struct bkey_s_c_subvolume subvol =
		bch2_bkey_get_iter_typed(trans, &subvol_iter,
				BTREE_ID_subvolumes, POS(0, subvolid),
				BTREE_ITER_cached|BTREE_ITER_intent,
				subvolume);
	int ret = bkey_err(subvol);
	if (bch2_err_matches(ret, ENOENT))
		ret = bch2_subvolume_missing(trans->c, subvolid) ?: ret;
	if (ret)
		goto err;

	u32 snapid = le32_to_cpu(subvol.v->snapshot);

	struct bkey_s_c_snapshot snapshot =
		bch2_bkey_get_iter_typed(trans, &snapshot_iter,
				BTREE_ID_snapshots, POS(0, snapid),
				0, snapshot);
	ret = bkey_err(snapshot);
	bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), trans->c,
				"missing snapshot %u", snapid);
	if (ret)
		goto err;

	u32 treeid = le32_to_cpu(snapshot.v->tree);

	struct bkey_s_c_snapshot_tree snapshot_tree =
		bch2_bkey_get_iter_typed(trans, &snapshot_tree_iter,
				BTREE_ID_snapshot_trees, POS(0, treeid),
				0, snapshot_tree);
	ret = bkey_err(snapshot_tree);
	bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), trans->c,
				"missing snapshot tree %u", treeid);
	if (ret)
		goto err;

	if (le32_to_cpu(snapshot_tree.v->master_subvol) == subvolid) {
		struct bkey_i_snapshot_tree *snapshot_tree_mut =
			bch2_bkey_make_mut_typed(trans, &snapshot_tree_iter,
						 &snapshot_tree.s_c,
						 0, snapshot_tree);
		ret = PTR_ERR_OR_ZERO(snapshot_tree_mut);
		if (ret)
			goto err;

		snapshot_tree_mut->v.master_subvol = 0;
	}

	ret =   bch2_btree_delete_at(trans, &subvol_iter, 0) ?:
		bch2_snapshot_node_set_deleted(trans, snapid);
err:
	bch2_trans_iter_exit(trans, &snapshot_tree_iter);
	bch2_trans_iter_exit(trans, &snapshot_iter);
	bch2_trans_iter_exit(trans, &subvol_iter);
	return ret;
}

static int bch2_subvolume_delete(struct btree_trans *trans, u32 subvolid)
{
	int ret = bch2_subvolumes_reparent(trans, subvolid) ?:
		commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			  __bch2_subvolume_delete(trans, subvolid));

	bch2_recovery_pass_set_no_ratelimit(trans->c, BCH_RECOVERY_PASS_check_subvols);
	return ret;
}

static void bch2_subvolume_wait_for_pagecache_and_delete(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs,
				snapshot_wait_for_pagecache_and_delete_work);
	int ret = 0;

	while (!ret) {
		mutex_lock(&c->snapshots_unlinked_lock);
		snapshot_id_list s = c->snapshots_unlinked;
		darray_init(&c->snapshots_unlinked);
		mutex_unlock(&c->snapshots_unlinked_lock);

		if (!s.nr)
			break;

		bch2_evict_subvolume_inodes(c, &s);

		darray_for_each(s, id) {
			ret = bch2_trans_run(c, bch2_subvolume_delete(trans, *id));
			bch_err_msg(c, ret, "deleting subvolume %u", *id);
			if (ret)
				break;
		}

		darray_exit(&s);
	}

	enumerated_ref_put(&c->writes, BCH_WRITE_REF_snapshot_delete_pagecache);
}

struct subvolume_unlink_hook {
	struct btree_trans_commit_hook	h;
	u32				subvol;
};

static int bch2_subvolume_wait_for_pagecache_and_delete_hook(struct btree_trans *trans,
						      struct btree_trans_commit_hook *_h)
{
	struct subvolume_unlink_hook *h = container_of(_h, struct subvolume_unlink_hook, h);
	struct bch_fs *c = trans->c;
	int ret = 0;

	mutex_lock(&c->snapshots_unlinked_lock);
	if (!snapshot_list_has_id(&c->snapshots_unlinked, h->subvol))
		ret = snapshot_list_add(c, &c->snapshots_unlinked, h->subvol);
	mutex_unlock(&c->snapshots_unlinked_lock);

	if (ret)
		return ret;

	if (!enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_snapshot_delete_pagecache))
		return -EROFS;

	if (!queue_work(c->write_ref_wq, &c->snapshot_wait_for_pagecache_and_delete_work))
		enumerated_ref_put(&c->writes, BCH_WRITE_REF_snapshot_delete_pagecache);
	return 0;
}

int bch2_subvolume_unlink(struct btree_trans *trans, u32 subvolid)
{
	struct btree_iter iter;
	struct bkey_i_subvolume *n;
	struct subvolume_unlink_hook *h;
	int ret = 0;

	h = bch2_trans_kmalloc(trans, sizeof(*h));
	ret = PTR_ERR_OR_ZERO(h);
	if (ret)
		return ret;

	h->h.fn		= bch2_subvolume_wait_for_pagecache_and_delete_hook;
	h->subvol	= subvolid;
	bch2_trans_commit_hook(trans, &h->h);

	n = bch2_bkey_get_mut_typed(trans, &iter,
			BTREE_ID_subvolumes, POS(0, subvolid),
			BTREE_ITER_cached, subvolume);
	ret = PTR_ERR_OR_ZERO(n);
	if (bch2_err_matches(ret, ENOENT))
		ret = bch2_subvolume_missing(trans->c, subvolid) ?: ret;
	if (unlikely(ret))
		return ret;

	SET_BCH_SUBVOLUME_UNLINKED(&n->v, true);
	n->v.fs_path_parent = 0;
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

int bch2_subvolume_create(struct btree_trans *trans, u64 inode,
			  u32 parent_subvolid,
			  u32 src_subvolid,
			  u32 *new_subvolid,
			  u32 *new_snapshotid,
			  bool ro)
{
	struct bch_fs *c = trans->c;
	struct btree_iter dst_iter, src_iter = {};
	struct bkey_i_subvolume *new_subvol = NULL;
	struct bkey_i_subvolume *src_subvol = NULL;
	u32 parent = 0, new_nodes[2], snapshot_subvols[2];
	int ret = 0;

	ret = bch2_bkey_get_empty_slot(trans, &dst_iter,
				BTREE_ID_subvolumes, POS(0, U32_MAX));
	if (ret == -BCH_ERR_ENOSPC_btree_slot)
		ret = bch_err_throw(c, ENOSPC_subvolume_create);
	if (ret)
		return ret;

	snapshot_subvols[0] = dst_iter.pos.offset;
	snapshot_subvols[1] = src_subvolid;

	if (src_subvolid) {
		/* Creating a snapshot: */

		src_subvol = bch2_bkey_get_mut_typed(trans, &src_iter,
				BTREE_ID_subvolumes, POS(0, src_subvolid),
				BTREE_ITER_cached, subvolume);
		ret = PTR_ERR_OR_ZERO(src_subvol);
		if (bch2_err_matches(ret, ENOENT))
			ret = bch2_subvolume_missing(trans->c, src_subvolid) ?: ret;
		if (unlikely(ret))
			goto err;

		parent = le32_to_cpu(src_subvol->v.snapshot);
	}

	ret = bch2_snapshot_node_create(trans, parent, new_nodes,
					snapshot_subvols,
					src_subvolid ? 2 : 1);
	if (ret)
		goto err;

	if (src_subvolid) {
		src_subvol->v.snapshot = cpu_to_le32(new_nodes[1]);
		ret = bch2_trans_update(trans, &src_iter, &src_subvol->k_i, 0);
		if (ret)
			goto err;
	}

	new_subvol = bch2_bkey_alloc(trans, &dst_iter, 0, subvolume);
	ret = PTR_ERR_OR_ZERO(new_subvol);
	if (ret)
		goto err;

	new_subvol->v.flags		= 0;
	new_subvol->v.snapshot		= cpu_to_le32(new_nodes[0]);
	new_subvol->v.inode		= cpu_to_le64(inode);
	new_subvol->v.creation_parent	= cpu_to_le32(src_subvolid);
	new_subvol->v.fs_path_parent	= cpu_to_le32(parent_subvolid);
	new_subvol->v.otime.lo		= cpu_to_le64(bch2_current_time(c));
	new_subvol->v.otime.hi		= 0;

	SET_BCH_SUBVOLUME_RO(&new_subvol->v, ro);
	SET_BCH_SUBVOLUME_SNAP(&new_subvol->v, src_subvolid != 0);

	*new_subvolid	= new_subvol->k.p.offset;
	*new_snapshotid	= new_nodes[0];
err:
	bch2_trans_iter_exit(trans, &src_iter);
	bch2_trans_iter_exit(trans, &dst_iter);
	return ret;
}

int bch2_initialize_subvolumes(struct bch_fs *c)
{
	struct bkey_i_snapshot_tree	root_tree;
	struct bkey_i_snapshot		root_snapshot;
	struct bkey_i_subvolume		root_volume;
	int ret;

	bkey_snapshot_tree_init(&root_tree.k_i);
	root_tree.k.p.offset		= 1;
	root_tree.v.master_subvol	= cpu_to_le32(1);
	root_tree.v.root_snapshot	= cpu_to_le32(U32_MAX);

	bkey_snapshot_init(&root_snapshot.k_i);
	root_snapshot.k.p.offset = U32_MAX;
	root_snapshot.v.flags	= 0;
	root_snapshot.v.parent	= 0;
	root_snapshot.v.subvol	= cpu_to_le32(BCACHEFS_ROOT_SUBVOL);
	root_snapshot.v.tree	= cpu_to_le32(1);
	SET_BCH_SNAPSHOT_SUBVOL(&root_snapshot.v, true);

	bkey_subvolume_init(&root_volume.k_i);
	root_volume.k.p.offset = BCACHEFS_ROOT_SUBVOL;
	root_volume.v.flags	= 0;
	root_volume.v.snapshot	= cpu_to_le32(U32_MAX);
	root_volume.v.inode	= cpu_to_le64(BCACHEFS_ROOT_INO);

	ret =   bch2_btree_insert(c, BTREE_ID_snapshot_trees,	&root_tree.k_i, NULL, 0, 0) ?:
		bch2_btree_insert(c, BTREE_ID_snapshots,	&root_snapshot.k_i, NULL, 0, 0) ?:
		bch2_btree_insert(c, BTREE_ID_subvolumes,	&root_volume.k_i, NULL, 0, 0);
	bch_err_fn(c, ret);
	return ret;
}

static int __bch2_fs_upgrade_for_subvolumes(struct btree_trans *trans)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bch_inode_unpacked inode;
	int ret;

	k = bch2_bkey_get_iter(trans, &iter, BTREE_ID_inodes,
			       SPOS(0, BCACHEFS_ROOT_INO, U32_MAX), 0);
	ret = bkey_err(k);
	if (ret)
		return ret;

	if (!bkey_is_inode(k.k)) {
		struct bch_fs *c = trans->c;
		bch_err(c, "root inode not found");
		ret = bch_err_throw(c, ENOENT_inode);
		goto err;
	}

	ret = bch2_inode_unpack(k, &inode);
	BUG_ON(ret);

	inode.bi_subvol = BCACHEFS_ROOT_SUBVOL;

	ret = bch2_inode_write(trans, &iter, &inode);
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

/* set bi_subvol on root inode */
int bch2_fs_upgrade_for_subvolumes(struct bch_fs *c)
{
	int ret = bch2_trans_commit_do(c, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
				       __bch2_fs_upgrade_for_subvolumes(trans));
	bch_err_fn(c, ret);
	return ret;
}

void bch2_fs_subvolumes_init_early(struct bch_fs *c)
{
	INIT_WORK(&c->snapshot_wait_for_pagecache_and_delete_work,
		  bch2_subvolume_wait_for_pagecache_and_delete);
}
