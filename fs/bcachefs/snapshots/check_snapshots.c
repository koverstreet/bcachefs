// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "btree/cache.h"
#include "btree/update.h"

#include "snapshots/snapshot.h"
#include "snapshots/subvolume.h"

#include "init/error.h"
#include "init/passes.h"
#include "init/progress.h"

static int bch2_snapshot_table_make_room(struct bch_fs *c, u32 id)
{
	guard(mutex)(&c->snapshots.table_lock);
	return bch2_snapshot_t_mut(c, id)
		? 0
		: bch_err_throw(c, ENOMEM_mark_snapshot);
}

static int bch2_snapshot_tree_create(struct btree_trans *trans,
				u32 root_id, u32 subvol_id, u32 *tree_id)
{
	struct bkey_i_snapshot_tree *n_tree =
		__bch2_snapshot_tree_create(trans);

	if (IS_ERR(n_tree))
		return PTR_ERR(n_tree);

	n_tree->v.master_subvol	= cpu_to_le32(subvol_id);
	n_tree->v.root_snapshot	= cpu_to_le32(root_id);
	*tree_id = n_tree->k.p.offset;
	return 0;
}

static u32 bch2_snapshot_oldest_subvol(struct bch_fs *c, u32 snapshot_root,
				       snapshot_id_list *skip)
{
	guard(rcu)();
	struct snapshot_table *t = rcu_dereference(c->snapshots.table);

	while (true) {
		u32 subvol = 0;

		__for_each_snapshot_child(c, t, snapshot_root, NULL, id)  {
			if (skip && snapshot_list_has_id(skip, id))
				continue;

			u32 s = __snapshot_t(t, id)->subvol;
			if (s && (!subvol || s < subvol))
				subvol = s;
		}

		if (subvol || !skip)
			return subvol;

		skip = NULL;
	}
}

static int bch2_snapshot_tree_master_subvol(struct btree_trans *trans,
					    u32 snapshot_root, u32 *subvol_id)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c k;
	int ret;

	for_each_btree_key_norestart(trans, iter, BTREE_ID_subvolumes, POS_MIN,
				     0, k, ret) {
		if (k.k->type != KEY_TYPE_subvolume)
			continue;

		struct bkey_s_c_subvolume s = bkey_s_c_to_subvolume(k);
		if (!bch2_snapshot_is_ancestor(c, le32_to_cpu(s.v->snapshot), snapshot_root))
			continue;
		if (!BCH_SUBVOLUME_SNAP(s.v)) {
			*subvol_id = s.k->p.offset;
			return 0;
		}
	}
	if (ret)
		return ret;

	*subvol_id = bch2_snapshot_oldest_subvol(c, snapshot_root, NULL);

	struct bkey_i_subvolume *u =
		errptr_try(bch2_bkey_get_mut_typed(trans, BTREE_ID_subvolumes, POS(0, *subvol_id),
					0, subvolume));

	SET_BCH_SUBVOLUME_SNAP(&u->v, false);
	return 0;
}

static int check_snapshot_tree(struct btree_trans *trans,
			       struct btree_iter *iter,
			       struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();

	if (k.k->type != KEY_TYPE_snapshot_tree)
		return 0;

	struct bkey_s_c_snapshot_tree st = bkey_s_c_to_snapshot_tree(k);
	u32 root_id = le32_to_cpu(st.v->root_snapshot);

	CLASS(btree_iter, snapshot_iter)(trans, BTREE_ID_snapshots, POS(0, root_id), 0);
	struct bkey_s_c_snapshot snapshot_k = bch2_bkey_get_typed(&snapshot_iter, snapshot);
	int ret = bkey_err(snapshot_k);
	if (ret && !bch2_err_matches(ret, ENOENT))
		return ret;

	struct bch_snapshot s;
	if (!ret)
		bkey_val_copy_pad(&s, snapshot_k);

	if (fsck_err_on(ret ||
			root_id != bch2_snapshot_root(c, root_id) ||
			st.k->p.offset != le32_to_cpu(s.tree),
			trans, snapshot_tree_to_missing_snapshot,
			"snapshot tree points to missing/incorrect snapshot:\n%s",
			(bch2_bkey_val_to_text(&buf, c, st.s_c),
			 prt_newline(&buf),
			 ret
			 ? prt_printf(&buf, "(%s)", bch2_err_str(ret))
			 : bch2_bkey_val_to_text(&buf, c, snapshot_k.s_c),
			 buf.buf)))
		return bch2_btree_delete_at(trans, iter, 0);

	if (!st.v->master_subvol)
		return 0;

	struct bch_subvolume subvol;
	ret = bch2_subvolume_get(trans, le32_to_cpu(st.v->master_subvol), false, &subvol);
	if (ret && !bch2_err_matches(ret, ENOENT))
		return ret;

	if (fsck_err_on(ret,
			trans, snapshot_tree_to_missing_subvol,
			"snapshot tree points to missing subvolume:\n%s",
			(printbuf_reset(&buf),
			 bch2_bkey_val_to_text(&buf, c, st.s_c), buf.buf)) ||
	    fsck_err_on(!bch2_snapshot_is_ancestor(c,
						le32_to_cpu(subvol.snapshot),
						root_id),
			trans, snapshot_tree_to_wrong_subvol,
			"snapshot tree points to subvolume that does not point to snapshot in this tree:\n%s",
			(printbuf_reset(&buf),
			 bch2_bkey_val_to_text(&buf, c, st.s_c), buf.buf)) ||
	    fsck_err_on(BCH_SUBVOLUME_SNAP(&subvol),
			trans, snapshot_tree_to_snapshot_subvol,
			"snapshot tree points to snapshot subvolume:\n%s",
			(printbuf_reset(&buf),
			 bch2_bkey_val_to_text(&buf, c, st.s_c), buf.buf))) {
		u32 subvol_id;
		ret = bch2_snapshot_tree_master_subvol(trans, root_id, &subvol_id);
		bch_err_fn(c, ret);

		if (bch2_err_matches(ret, ENOENT)) /* nothing to be done here */
			return 0;

		if (ret)
			return ret;

		struct bkey_i_snapshot_tree *u =
			errptr_try(bch2_bkey_make_mut_typed(trans, iter, &k, 0, snapshot_tree));

		u->v.master_subvol = cpu_to_le32(subvol_id);
		st = snapshot_tree_i_to_s_c(u);
	}
fsck_err:
	return ret;
}

/*
 * For each snapshot_tree, make sure it points to the root of a snapshot tree
 * and that snapshot entry points back to it, or delete it.
 *
 * And, make sure it points to a subvolume within that snapshot tree, or correct
 * it to point to the oldest subvolume within that snapshot tree.
 */
int bch2_check_snapshot_trees(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	return for_each_btree_key_commit(trans, iter,
			BTREE_ID_snapshot_trees, POS_MIN,
			BTREE_ITER_prefetch, k,
			NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
		check_snapshot_tree(trans, &iter, k));
}

/*
 * Look up snapshot tree for @tree_id and find root,
 * make sure @snap_id is a descendent:
 */
static int snapshot_tree_ptr_good(struct btree_trans *trans,
				  u32 snap_id, u32 tree_id)
{
	struct bch_snapshot_tree s_t;
	int ret = bch2_snapshot_tree_lookup(trans, tree_id, &s_t);

	if (bch2_err_matches(ret, ENOENT))
		return 0;
	if (ret)
		return ret;

	return bch2_snapshot_is_ancestor_early(trans->c, snap_id, le32_to_cpu(s_t.root_snapshot));
}

u32 bch2_snapshot_skiplist_get(struct bch_fs *c, u32 id)
{
	if (!id)
		return 0;

	guard(rcu)();
	const struct snapshot_t *s = snapshot_t(c, id);
	return s->parent
		? bch2_snapshot_nth_parent(c, id, get_random_u32_below(s->depth))
		: id;
}

static int snapshot_skiplist_good(struct btree_trans *trans, u32 id, struct bch_snapshot s)
{
	unsigned i;

	for (i = 0; i < 3; i++)
		if (!s.parent) {
			if (s.skip[i])
				return false;
		} else {
			if (!bch2_snapshot_is_ancestor_early(trans->c, id, le32_to_cpu(s.skip[i])))
				return false;
		}

	return true;
}

/*
 * snapshot_tree pointer was incorrect: look up root snapshot node, make sure
 * its snapshot_tree pointer is correct (allocate new one if necessary), then
 * update this node's pointer to root node's pointer:
 */
static int snapshot_tree_ptr_repair(struct btree_trans *trans,
				    struct btree_iter *iter,
				    struct bkey_s_c k,
				    struct bch_snapshot *s)
{
	struct bch_fs *c = trans->c;
	u32 root_id = bch2_snapshot_root(c, k.k->p.offset);

	CLASS(btree_iter, root_iter)(trans, BTREE_ID_snapshots, POS(0, root_id),
				     BTREE_ITER_with_updates);
	struct bkey_s_c_snapshot root = bkey_try(bch2_bkey_get_typed(&root_iter, snapshot));

	u32 tree_id = le32_to_cpu(root.v->tree);

	struct bch_snapshot_tree s_t;
	int ret = bch2_snapshot_tree_lookup(trans, tree_id, &s_t);
	if (ret && !bch2_err_matches(ret, ENOENT))
		return ret;

	if (ret || le32_to_cpu(s_t.root_snapshot) != root_id) {
		struct bkey_i_snapshot *u =
			errptr_try(bch2_bkey_make_mut_typed(trans, &root_iter, &root.s_c, 0, snapshot));

		try(bch2_snapshot_tree_create(trans, root_id,
					      bch2_snapshot_oldest_subvol(c, root_id, NULL),
					      &tree_id));

		u->v.tree = cpu_to_le32(tree_id);
		if (k.k->p.offset == root_id)
			*s = u->v;
	}

	if (k.k->p.offset != root_id) {
		struct bkey_i_snapshot *u =
			errptr_try(bch2_bkey_make_mut_typed(trans, iter, &k, 0, snapshot));

		u->v.tree = cpu_to_le32(tree_id);
		*s = u->v;
	}

	return 0;
}

static int check_snapshot(struct btree_trans *trans,
			  struct btree_iter *iter,
			  struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct bch_snapshot s;
	struct bch_subvolume subvol;
	struct bch_snapshot v;
	struct bkey_i_snapshot *u;
	u32 parent_id = bch2_snapshot_parent_early(c, k.k->p.offset);
	u32 real_depth;
	CLASS(printbuf, buf)();
	u32 i, id;
	int ret = 0;

	if (k.k->type != KEY_TYPE_snapshot)
		return 0;

	memset(&s, 0, sizeof(s));
	memcpy(&s, k.v, min(sizeof(s), bkey_val_bytes(k.k)));

	if (BCH_SNAPSHOT_DELETED(&s))
		return 0;

	id = le32_to_cpu(s.parent);
	if (id) {
		ret = bch2_snapshot_lookup(trans, id, &v);
		if (bch2_err_matches(ret, ENOENT))
			bch_err(c, "snapshot with nonexistent parent:\n  %s",
				(bch2_bkey_val_to_text(&buf, c, k), buf.buf));
		if (ret)
			return ret;

		if (le32_to_cpu(v.children[0]) != k.k->p.offset &&
		    le32_to_cpu(v.children[1]) != k.k->p.offset) {
			bch_err(c, "snapshot parent %u missing pointer to child %llu",
				id, k.k->p.offset);
			return -EINVAL;
		}
	}

	for (i = 0; i < 2 && s.children[i]; i++) {
		id = le32_to_cpu(s.children[i]);

		ret = bch2_snapshot_lookup(trans, id, &v);
		if (bch2_err_matches(ret, ENOENT))
			bch_err(c, "snapshot node %llu has nonexistent child %u",
				k.k->p.offset, id);
		if (ret)
			return ret;

		if (le32_to_cpu(v.parent) != k.k->p.offset) {
			bch_err(c, "snapshot child %u has wrong parent (got %u should be %llu)",
				id, le32_to_cpu(v.parent), k.k->p.offset);
			return -EINVAL;
		}
	}

	bool should_have_subvol = BCH_SNAPSHOT_SUBVOL(&s) &&
		!BCH_SNAPSHOT_WILL_DELETE(&s);

	if (should_have_subvol) {
		id = le32_to_cpu(s.subvol);
		ret = bch2_subvolume_get(trans, id, false, &subvol);
		if (bch2_err_matches(ret, ENOENT))
			bch_err(c, "snapshot points to nonexistent subvolume:\n  %s",
				(bch2_bkey_val_to_text(&buf, c, k), buf.buf));
		if (ret)
			return ret;

		if (BCH_SNAPSHOT_SUBVOL(&s) != (le32_to_cpu(subvol.snapshot) == k.k->p.offset)) {
			bch_err(c, "snapshot node %llu has wrong BCH_SNAPSHOT_SUBVOL",
				k.k->p.offset);
			return -EINVAL;
		}
	} else {
		if (fsck_err_on(s.subvol,
				trans, snapshot_should_not_have_subvol,
				"snapshot should not point to subvol:\n%s",
				(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
			u = errptr_try(bch2_bkey_make_mut_typed(trans, iter, &k, 0, snapshot));

			u->v.subvol = 0;
			s = u->v;
		}
	}

	ret = snapshot_tree_ptr_good(trans, k.k->p.offset, le32_to_cpu(s.tree));
	if (ret < 0)
		return ret;

	if (fsck_err_on(!ret,
			trans, snapshot_to_bad_snapshot_tree,
			"snapshot points to missing/incorrect tree:\n%s",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
		try(snapshot_tree_ptr_repair(trans, iter, k, &s));
	ret = 0;

	real_depth = bch2_snapshot_depth(c, parent_id);

	if (fsck_err_on(le32_to_cpu(s.depth) != real_depth,
			trans, snapshot_bad_depth,
			"snapshot with incorrect depth field, should be %u:\n%s",
			real_depth, (bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
		u = errptr_try(bch2_bkey_make_mut_typed(trans, iter, &k, 0, snapshot));

		u->v.depth = cpu_to_le32(real_depth);
		s = u->v;
	}

	ret = snapshot_skiplist_good(trans, k.k->p.offset, s);
	if (ret < 0)
		return ret;

	if (fsck_err_on(!ret,
			trans, snapshot_bad_skiplist,
			"snapshot with bad skiplist field:\n%s",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
		u = errptr_try(bch2_bkey_make_mut_typed(trans, iter, &k, 0, snapshot));

		for (i = 0; i < ARRAY_SIZE(u->v.skip); i++)
			u->v.skip[i] = cpu_to_le32(bch2_snapshot_skiplist_get(c, parent_id));

		bubble_sort(u->v.skip, ARRAY_SIZE(u->v.skip), cmp_le32);
		s = u->v;
	}
	ret = 0;
fsck_err:
	return ret;
}

int bch2_check_snapshots(struct bch_fs *c)
{
	/*
	 * We iterate backwards as checking/fixing the depth field requires that
	 * the parent's depth already be correct:
	 */
	CLASS(btree_trans, trans)(c);
	return for_each_btree_key_reverse_commit(trans, iter,
				BTREE_ID_snapshots, POS_MAX,
				BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			check_snapshot(trans, &iter, k));
}

static int check_snapshot_exists(struct btree_trans *trans, u32 id)
{
	struct bch_fs *c = trans->c;

	/* Do we need to reconstruct the snapshot_tree entry as well? */
	struct bkey_s_c k;
	int ret = 0;
	u32 tree_id = 0;

	for_each_btree_key_norestart(trans, iter, BTREE_ID_snapshot_trees, POS_MIN,
				     0, k, ret) {
		if (k.k->type == KEY_TYPE_snapshot_tree &&
		    le32_to_cpu(bkey_s_c_to_snapshot_tree(k).v->root_snapshot) == id) {
			tree_id = k.k->p.offset;
			break;
		}
	}

	if (ret)
		return ret;

	if (!tree_id)
		try(bch2_snapshot_tree_create(trans, id, 0, &tree_id));

	struct bkey_i_snapshot *snapshot = bch2_trans_kmalloc(trans, sizeof(*snapshot));
	ret = PTR_ERR_OR_ZERO(snapshot);
	if (ret)
		return ret;

	bkey_snapshot_init(&snapshot->k_i);
	snapshot->k.p		= POS(0, id);
	snapshot->v.tree	= cpu_to_le32(tree_id);
	snapshot->v.btime.lo	= cpu_to_le64(bch2_current_time(c));

	for_each_btree_key_norestart(trans, iter, BTREE_ID_subvolumes, POS_MIN,
				     0, k, ret) {
		if (k.k->type == KEY_TYPE_subvolume &&
		    le32_to_cpu(bkey_s_c_to_subvolume(k).v->snapshot) == id) {
			snapshot->v.subvol = cpu_to_le32(k.k->p.offset);
			SET_BCH_SNAPSHOT_SUBVOL(&snapshot->v, true);
			break;
		}
	}

	return  bch2_snapshot_table_make_room(c, id) ?:
		bch2_btree_insert_trans(trans, BTREE_ID_snapshots, &snapshot->k_i, 0);
}

/* Figure out which snapshot nodes belong in the same tree: */
struct snapshot_tree_reconstruct {
	enum btree_id			btree;
	struct bpos			cur_pos;
	snapshot_id_list		cur_ids;
	DARRAY(snapshot_id_list)	trees;
};

static void snapshot_tree_reconstruct_exit(struct snapshot_tree_reconstruct *r)
{
	darray_for_each(r->trees, i)
		darray_exit(i);
	darray_exit(&r->trees);
	darray_exit(&r->cur_ids);
}

static inline bool same_snapshot(struct snapshot_tree_reconstruct *r, struct bpos pos)
{
	return r->btree == BTREE_ID_inodes
		? r->cur_pos.offset == pos.offset
		: r->cur_pos.inode == pos.inode;
}

static inline bool snapshot_id_lists_have_common(snapshot_id_list *l, snapshot_id_list *r)
{
	return darray_find_p(*l, i, snapshot_list_has_id(r, *i)) != NULL;
}

static void snapshot_id_list_to_text(struct printbuf *out, snapshot_id_list *s)
{
	bool first = true;
	darray_for_each(*s, i) {
		if (!first)
			prt_char(out, ' ');
		first = false;
		prt_printf(out, "%u", *i);
	}
}

static int snapshot_tree_reconstruct_next(struct bch_fs *c, struct snapshot_tree_reconstruct *r)
{
	if (r->cur_ids.nr) {
		darray_for_each(r->trees, i)
			if (snapshot_id_lists_have_common(i, &r->cur_ids)) {
				try(snapshot_list_merge(c, i, &r->cur_ids));
				r->cur_ids.nr = 0;
				return 0;
			}
		darray_push(&r->trees, r->cur_ids);
		darray_init(&r->cur_ids);
	}

	return 0;
}

static int get_snapshot_trees(struct bch_fs *c, struct snapshot_tree_reconstruct *r, struct bpos pos)
{
	if (!same_snapshot(r, pos))
		snapshot_tree_reconstruct_next(c, r);
	r->cur_pos = pos;
	return snapshot_list_add_nodup(c, &r->cur_ids, pos.snapshot);
}

int bch2_reconstruct_snapshots(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	CLASS(printbuf, buf)();
	struct snapshot_tree_reconstruct r __cleanup(snapshot_tree_reconstruct_exit) = {};
	int ret = 0;

	struct progress_indicator progress;
	bch2_progress_init(&progress, __func__, c, btree_has_snapshots_mask, 0);

	for (unsigned btree = 0; btree < BTREE_ID_NR; btree++) {
		if (btree_type_has_snapshots(btree)) {
			r.btree = btree;

			try(for_each_btree_key(trans, iter, btree, POS_MIN,
					BTREE_ITER_all_snapshots|BTREE_ITER_prefetch, k, ({
				bch2_progress_update_iter(trans, &progress, &iter) ?:
				get_snapshot_trees(c, &r, k.k->p);
			})));

			snapshot_tree_reconstruct_next(c, &r);
		}
	}

	darray_for_each(r.trees, t) {
		printbuf_reset(&buf);
		snapshot_id_list_to_text(&buf, t);

		darray_for_each(*t, id) {
			if (fsck_err_on(bch2_snapshot_id_state(c, *id) == SNAPSHOT_ID_empty,
					trans, snapshot_node_missing,
					"snapshot node %u from tree %s missing, recreate?", *id, buf.buf)) {
				if (t->nr > 1) {
					bch_err(c, "cannot reconstruct snapshot trees with multiple nodes");
					return bch_err_throw(c, fsck_repair_unimplemented);
				}

				try(commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
					      check_snapshot_exists(trans, *id)));
			}
		}
	}
fsck_err:
	return ret;
}

int __bch2_check_key_has_snapshot(struct btree_trans *trans,
				  struct btree_iter *iter,
				  struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();
	int ret = 0;
	enum snapshot_id_state state = bch2_snapshot_id_state(c, k.k->p.snapshot);

	/* Snapshot was definitively deleted, this error is marked autofix */
	if (fsck_err_on(state == SNAPSHOT_ID_deleted,
			trans, bkey_in_deleted_snapshot,
			"key in deleted snapshot %s, delete?",
			(bch2_btree_id_to_text(&buf, iter->btree_id),
			 prt_char(&buf, ' '),
			 bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
		ret = bch2_btree_delete_at(trans, iter,
					   BTREE_UPDATE_internal_snapshot_node) ?: 1;

	if (state == SNAPSHOT_ID_empty) {
		/*
		 * Snapshot missing: we should have caught this with btree_lost_data and
		 * kicked off reconstruct_snapshots, so if we end up here we have no
		 * idea what happened.
		 *
		 * Do not delete unless we know that subvolumes and snapshots
		 * are consistent:
		 *
		 * XXX:
		 *
		 * We could be smarter here, and instead of using the generic
		 * recovery pass ratelimiting, track if there have been any
		 * changes to the snapshots or inodes btrees since those passes
		 * last ran.
		 */
		ret = bch2_require_recovery_pass(c, &buf, BCH_RECOVERY_PASS_check_snapshots) ?: ret;
		ret = bch2_require_recovery_pass(c, &buf, BCH_RECOVERY_PASS_check_subvols) ?: ret;

		if (c->sb.btrees_lost_data & BIT_ULL(BTREE_ID_snapshots))
			ret = bch2_require_recovery_pass(c, &buf, BCH_RECOVERY_PASS_reconstruct_snapshots) ?: ret;

		unsigned repair_flags = FSCK_CAN_IGNORE | (!ret ? FSCK_CAN_FIX : 0);

		if (__fsck_err(trans, repair_flags, bkey_in_missing_snapshot,
			     "key in missing snapshot %s, delete?",
			     (bch2_btree_id_to_text(&buf, iter->btree_id),
			      prt_char(&buf, ' '),
			      bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
			ret = bch2_btree_delete_at(trans, iter,
						   BTREE_UPDATE_internal_snapshot_node) ?: 1;
		}
	}
fsck_err:
	return ret;
}
