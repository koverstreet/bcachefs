// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_key_cache.h"
#include "btree_update.h"
#include "errcode.h"
#include "error.h"
#include "fs.h"
#include "snapshot.h"
#include "subvolume.h"

#include <linux/random.h>

static int bch2_subvolume_delete(struct btree_trans *, u32);

static int check_subvol(struct btree_trans *trans,
			struct btree_iter *iter,
			struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c_subvolume subvol;
	struct bch_snapshot snapshot;
	unsigned snapid;
	int ret = 0;

	if (k.k->type != KEY_TYPE_subvolume)
		return 0;

	subvol = bkey_s_c_to_subvolume(k);
	snapid = le32_to_cpu(subvol.v->snapshot);
	ret = bch2_snapshot_lookup(trans, snapid, &snapshot);

	if (bch2_err_matches(ret, ENOENT))
		bch_err(c, "subvolume %llu points to nonexistent snapshot %u",
			k.k->p.offset, snapid);
	if (ret)
		return ret;

	if (BCH_SUBVOLUME_UNLINKED(subvol.v)) {
		bch2_fs_lazy_rw(c);

		ret = bch2_subvolume_delete(trans, iter->pos.offset);
		if (ret)
			bch_err(c, "error deleting subvolume %llu: %s",
				iter->pos.offset, bch2_err_str(ret));
		return ret ?: -BCH_ERR_transaction_restart_nested;
	}

	if (!BCH_SUBVOLUME_SNAP(subvol.v)) {
		u32 snapshot_root = bch2_snapshot_root(c, le32_to_cpu(subvol.v->snapshot));
		u32 snapshot_tree;
		struct bch_snapshot_tree st;

		rcu_read_lock();
		snapshot_tree = snapshot_t(c, snapshot_root)->tree;
		rcu_read_unlock();

		ret = bch2_snapshot_tree_lookup(trans, snapshot_tree, &st);

		bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), c,
				"%s: snapshot tree %u not found", __func__, snapshot_tree);

		if (ret)
			return ret;

		if (fsck_err_on(le32_to_cpu(st.master_subvol) != subvol.k->p.offset, c,
				"subvolume %llu is not set as snapshot but is not master subvolume",
				k.k->p.offset)) {
			struct bkey_i_subvolume *s =
				bch2_bkey_make_mut_typed(trans, iter, &subvol.s_c, 0, subvolume);
			ret = PTR_ERR_OR_ZERO(s);
			if (ret)
				return ret;

			SET_BCH_SUBVOLUME_SNAP(&s->v, true);
		}
	}

fsck_err:
	return ret;
}

int bch2_check_subvols(struct bch_fs *c)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	ret = bch2_trans_run(c,
		for_each_btree_key_commit(&trans, iter,
			BTREE_ID_subvolumes, POS_MIN, BTREE_ITER_PREFETCH, k,
			NULL, NULL, BTREE_INSERT_LAZY_RW|BTREE_INSERT_NOFAIL,
		check_subvol(&trans, &iter, k)));
	if (ret)
		bch_err_fn(c, ret);
	return ret;
}

/*
 * Mark a snapshot as deleted, for future cleanup:
 */
static int bch2_snapshot_node_set_deleted(struct btree_trans *trans, u32 id)
{
	struct btree_iter iter;
	struct bkey_i_snapshot *s;
	int ret = 0;

	s = bch2_bkey_get_mut_typed(trans, &iter,
				    BTREE_ID_snapshots, POS(0, id),
				    0, snapshot);
	ret = PTR_ERR_OR_ZERO(s);
	if (unlikely(ret)) {
		bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT),
					trans->c, "missing snapshot %u", id);
		return ret;
	}

	/* already deleted? */
	if (BCH_SNAPSHOT_DELETED(&s->v))
		goto err;

	SET_BCH_SNAPSHOT_DELETED(&s->v, true);
	SET_BCH_SNAPSHOT_SUBVOL(&s->v, false);
	s->v.subvol = 0;
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static int bch2_snapshot_node_delete(struct btree_trans *trans, u32 id)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter, p_iter = (struct btree_iter) { NULL };
	struct btree_iter tree_iter = (struct btree_iter) { NULL };
	struct bkey_s_c_snapshot s;
	u32 parent_id;
	unsigned i;
	int ret = 0;

	s = bch2_bkey_get_iter_typed(trans, &iter, BTREE_ID_snapshots, POS(0, id),
				     BTREE_ITER_INTENT, snapshot);
	ret = bkey_err(s);
	bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), c,
				"missing snapshot %u", id);

	if (ret)
		goto err;

	BUG_ON(!BCH_SNAPSHOT_DELETED(s.v));
	parent_id = le32_to_cpu(s.v->parent);

	if (parent_id) {
		struct bkey_i_snapshot *parent;

		parent = bch2_bkey_get_mut_typed(trans, &p_iter,
				     BTREE_ID_snapshots, POS(0, parent_id),
				     0, snapshot);
		ret = PTR_ERR_OR_ZERO(parent);
		if (unlikely(ret)) {
			bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), c,
						"missing snapshot %u", parent_id);
			goto err;
		}

		for (i = 0; i < 2; i++)
			if (le32_to_cpu(parent->v.children[i]) == id)
				break;

		if (i == 2)
			bch_err(c, "snapshot %u missing child pointer to %u",
				parent_id, id);
		else
			parent->v.children[i] = 0;

		if (le32_to_cpu(parent->v.children[0]) <
		    le32_to_cpu(parent->v.children[1]))
			swap(parent->v.children[0],
			     parent->v.children[1]);
	} else {
		/*
		 * We're deleting the root of a snapshot tree: update the
		 * snapshot_tree entry to point to the new root, or delete it if
		 * this is the last snapshot ID in this tree:
		 */
		struct bkey_i_snapshot_tree *s_t;

		BUG_ON(s.v->children[1]);

		s_t = bch2_bkey_get_mut_typed(trans, &tree_iter,
				BTREE_ID_snapshot_trees, POS(0, le32_to_cpu(s.v->tree)),
				0, snapshot_tree);
		ret = PTR_ERR_OR_ZERO(s_t);
		if (ret)
			goto err;

		if (s.v->children[0]) {
			s_t->v.root_snapshot = s.v->children[0];
		} else {
			s_t->k.type = KEY_TYPE_deleted;
			set_bkey_val_u64s(&s_t->k, 0);
		}
	}

	ret = bch2_btree_delete_at(trans, &iter, 0);
err:
	bch2_trans_iter_exit(trans, &tree_iter);
	bch2_trans_iter_exit(trans, &p_iter);
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static int create_snapids(struct btree_trans *trans, u32 parent, u32 tree,
			  u32 *new_snapids,
			  u32 *snapshot_subvols,
			  unsigned nr_snapids)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_i_snapshot *n;
	struct bkey_s_c k;
	unsigned i, j;
	u32 depth = bch2_snapshot_depth(c, parent);
	int ret;

	bch2_trans_iter_init(trans, &iter, BTREE_ID_snapshots,
			     POS_MIN, BTREE_ITER_INTENT);
	k = bch2_btree_iter_peek(&iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	for (i = 0; i < nr_snapids; i++) {
		k = bch2_btree_iter_prev_slot(&iter);
		ret = bkey_err(k);
		if (ret)
			goto err;

		if (!k.k || !k.k->p.offset) {
			ret = -BCH_ERR_ENOSPC_snapshot_create;
			goto err;
		}

		n = bch2_bkey_alloc(trans, &iter, 0, snapshot);
		ret = PTR_ERR_OR_ZERO(n);
		if (ret)
			goto err;

		n->v.flags	= 0;
		n->v.parent	= cpu_to_le32(parent);
		n->v.subvol	= cpu_to_le32(snapshot_subvols[i]);
		n->v.tree	= cpu_to_le32(tree);
		n->v.depth	= cpu_to_le32(depth);

		for (j = 0; j < ARRAY_SIZE(n->v.skip); j++)
			n->v.skip[j] = cpu_to_le32(bch2_snapshot_skiplist_get(c, parent));

		bubble_sort(n->v.skip, ARRAY_SIZE(n->v.skip), cmp_le32);
		SET_BCH_SNAPSHOT_SUBVOL(&n->v, true);

		ret = bch2_mark_snapshot(trans, BTREE_ID_snapshots, 0,
					 bkey_s_c_null, bkey_i_to_s_c(&n->k_i), 0);
		if (ret)
			goto err;

		new_snapids[i]	= iter.pos.offset;
	}
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

/*
 * Create new snapshot IDs as children of an existing snapshot ID:
 */
static int bch2_snapshot_node_create_children(struct btree_trans *trans, u32 parent,
			      u32 *new_snapids,
			      u32 *snapshot_subvols,
			      unsigned nr_snapids)
{
	struct btree_iter iter;
	struct bkey_i_snapshot *n_parent;
	int ret = 0;

	n_parent = bch2_bkey_get_mut_typed(trans, &iter,
			BTREE_ID_snapshots, POS(0, parent),
			0, snapshot);
	ret = PTR_ERR_OR_ZERO(n_parent);
	if (unlikely(ret)) {
		if (bch2_err_matches(ret, ENOENT))
			bch_err(trans->c, "snapshot %u not found", parent);
		return ret;
	}

	if (n_parent->v.children[0] || n_parent->v.children[1]) {
		bch_err(trans->c, "Trying to add child snapshot nodes to parent that already has children");
		ret = -EINVAL;
		goto err;
	}

	ret = create_snapids(trans, parent, le32_to_cpu(n_parent->v.tree),
			     new_snapids, snapshot_subvols, nr_snapids);
	if (ret)
		goto err;

	n_parent->v.children[0] = cpu_to_le32(new_snapids[0]);
	n_parent->v.children[1] = cpu_to_le32(new_snapids[1]);
	n_parent->v.subvol = 0;
	SET_BCH_SNAPSHOT_SUBVOL(&n_parent->v, false);
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

/*
 * Create a snapshot node that is the root of a new tree:
 */
static int bch2_snapshot_node_create_tree(struct btree_trans *trans,
			      u32 *new_snapids,
			      u32 *snapshot_subvols,
			      unsigned nr_snapids)
{
	struct bkey_i_snapshot_tree *n_tree;
	int ret;

	n_tree = __bch2_snapshot_tree_create(trans);
	ret =   PTR_ERR_OR_ZERO(n_tree) ?:
		create_snapids(trans, 0, n_tree->k.p.offset,
			     new_snapids, snapshot_subvols, nr_snapids);
	if (ret)
		return ret;

	n_tree->v.master_subvol	= cpu_to_le32(snapshot_subvols[0]);
	n_tree->v.root_snapshot	= cpu_to_le32(new_snapids[0]);
	return 0;
}

int bch2_snapshot_node_create(struct btree_trans *trans, u32 parent,
			      u32 *new_snapids,
			      u32 *snapshot_subvols,
			      unsigned nr_snapids)
{
	BUG_ON((parent == 0) != (nr_snapids == 1));
	BUG_ON((parent != 0) != (nr_snapids == 2));

	return parent
		? bch2_snapshot_node_create_children(trans, parent,
				new_snapids, snapshot_subvols, nr_snapids)
		: bch2_snapshot_node_create_tree(trans,
				new_snapids, snapshot_subvols, nr_snapids);

}

/*
 * If we have an unlinked inode in an internal snapshot node, and the inode
 * really has been deleted in all child snapshots, how does this get cleaned up?
 *
 * first there is the problem of how keys that have been overwritten in all
 * child snapshots get deleted (unimplemented?), but inodes may perhaps be
 * special?
 *
 * also: unlinked inode in internal snapshot appears to not be getting deleted
 * correctly if inode doesn't exist in leaf snapshots
 */

static int snapshot_delete_key(struct btree_trans *trans,
			       struct btree_iter *iter,
			       struct bkey_s_c k,
			       snapshot_id_list *deleted,
			       snapshot_id_list *equiv_seen,
			       struct bpos *last_pos)
{
	struct bch_fs *c = trans->c;
	u32 equiv = bch2_snapshot_equiv(c, k.k->p.snapshot);

	if (!bkey_eq(k.k->p, *last_pos))
		equiv_seen->nr = 0;
	*last_pos = k.k->p;

	if (snapshot_list_has_id(deleted, k.k->p.snapshot) ||
	    snapshot_list_has_id(equiv_seen, equiv)) {
		return bch2_btree_delete_at(trans, iter,
					    BTREE_UPDATE_INTERNAL_SNAPSHOT_NODE);
	} else {
		return snapshot_list_add(c, equiv_seen, equiv);
	}
}

/*
 * For a given snapshot, if it doesn't have a subvolume that points to it, and
 * it doesn't have child snapshot nodes - it's now redundant and we can mark it
 * as deleted.
 */
static int bch2_delete_redundant_snapshot(struct btree_trans *trans, struct btree_iter *iter,
					  struct bkey_s_c k)
{
	struct bkey_s_c_snapshot snap;
	u32 children[2];
	int ret;

	if (k.k->type != KEY_TYPE_snapshot)
		return 0;

	snap = bkey_s_c_to_snapshot(k);
	if (BCH_SNAPSHOT_DELETED(snap.v) ||
	    BCH_SNAPSHOT_SUBVOL(snap.v))
		return 0;

	children[0] = le32_to_cpu(snap.v->children[0]);
	children[1] = le32_to_cpu(snap.v->children[1]);

	ret   = bch2_snapshot_live(trans, children[0]) ?:
		bch2_snapshot_live(trans, children[1]);
	if (ret < 0)
		return ret;

	if (!ret)
		return bch2_snapshot_node_set_deleted(trans, k.k->p.offset);
	return 0;
}

int bch2_delete_dead_snapshots(struct bch_fs *c)
{
	struct btree_trans trans;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_snapshot snap;
	snapshot_id_list deleted = { 0 };
	u32 i, id;
	int ret = 0;

	if (!test_bit(BCH_FS_STARTED, &c->flags)) {
		ret = bch2_fs_read_write_early(c);
		if (ret) {
			bch_err(c, "error deleleting dead snapshots: error going rw: %s", bch2_err_str(ret));
			return ret;
		}
	}

	bch2_trans_init(&trans, c, 0, 0);

	/*
	 * For every snapshot node: If we have no live children and it's not
	 * pointed to by a subvolume, delete it:
	 */
	ret = for_each_btree_key_commit(&trans, iter, BTREE_ID_snapshots,
			POS_MIN, 0, k,
			NULL, NULL, 0,
		bch2_delete_redundant_snapshot(&trans, &iter, k));
	if (ret) {
		bch_err(c, "error deleting redundant snapshots: %s", bch2_err_str(ret));
		goto err;
	}

	for_each_btree_key2(&trans, iter, BTREE_ID_snapshots,
			   POS_MIN, 0, k,
		bch2_snapshot_set_equiv(&trans, k));
	if (ret) {
		bch_err(c, "error in bch2_snapshots_set_equiv: %s", bch2_err_str(ret));
		goto err;
	}

	for_each_btree_key(&trans, iter, BTREE_ID_snapshots,
			   POS_MIN, 0, k, ret) {
		if (k.k->type != KEY_TYPE_snapshot)
			continue;

		snap = bkey_s_c_to_snapshot(k);
		if (BCH_SNAPSHOT_DELETED(snap.v)) {
			ret = snapshot_list_add(c, &deleted, k.k->p.offset);
			if (ret)
				break;
		}
	}
	bch2_trans_iter_exit(&trans, &iter);

	if (ret) {
		bch_err(c, "error walking snapshots: %s", bch2_err_str(ret));
		goto err;
	}

	for (id = 0; id < BTREE_ID_NR; id++) {
		struct bpos last_pos = POS_MIN;
		snapshot_id_list equiv_seen = { 0 };

		if (!btree_type_has_snapshots(id))
			continue;

		ret = for_each_btree_key_commit(&trans, iter,
				id, POS_MIN,
				BTREE_ITER_PREFETCH|BTREE_ITER_ALL_SNAPSHOTS, k,
				NULL, NULL, BTREE_INSERT_NOFAIL,
			snapshot_delete_key(&trans, &iter, k, &deleted, &equiv_seen, &last_pos));

		darray_exit(&equiv_seen);

		if (ret) {
			bch_err(c, "error deleting snapshot keys: %s", bch2_err_str(ret));
			goto err;
		}
	}

	for (i = 0; i < deleted.nr; i++) {
		ret = commit_do(&trans, NULL, NULL, 0,
			bch2_snapshot_node_delete(&trans, deleted.data[i]));
		if (ret) {
			bch_err(c, "error deleting snapshot %u: %s",
				deleted.data[i], bch2_err_str(ret));
			goto err;
		}
	}

	clear_bit(BCH_FS_HAVE_DELETED_SNAPSHOTS, &c->flags);
err:
	darray_exit(&deleted);
	bch2_trans_exit(&trans);
	if (ret)
		bch_err_fn(c, ret);
	return ret;
}

static void bch2_delete_dead_snapshots_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs, snapshot_delete_work);

	if (test_bit(BCH_FS_HAVE_DELETED_SNAPSHOTS, &c->flags))
		bch2_delete_dead_snapshots(c);
	bch2_write_ref_put(c, BCH_WRITE_REF_delete_dead_snapshots);
}

void bch2_delete_dead_snapshots_async(struct bch_fs *c)
{
	if (bch2_write_ref_tryget(c, BCH_WRITE_REF_delete_dead_snapshots) &&
	    !queue_work(c->write_ref_wq, &c->snapshot_delete_work))
		bch2_write_ref_put(c, BCH_WRITE_REF_delete_dead_snapshots);
}

static int bch2_delete_dead_snapshots_hook(struct btree_trans *trans,
					   struct btree_trans_commit_hook *h)
{
	struct bch_fs *c = trans->c;

	set_bit(BCH_FS_HAVE_DELETED_SNAPSHOTS, &c->flags);

	if (c->curr_recovery_pass <= BCH_RECOVERY_PASS_delete_dead_snapshots)
		return 0;

	bch2_delete_dead_snapshots_async(c);
	return 0;
}

/* Subvolumes: */

int bch2_subvolume_invalid(const struct bch_fs *c, struct bkey_s_c k,
			   unsigned flags, struct printbuf *err)
{
	if (bkey_lt(k.k->p, SUBVOL_POS_MIN) ||
	    bkey_gt(k.k->p, SUBVOL_POS_MAX)) {
		prt_printf(err, "invalid pos");
		return -BCH_ERR_invalid_bkey;
	}

	return 0;
}

void bch2_subvolume_to_text(struct printbuf *out, struct bch_fs *c,
			    struct bkey_s_c k)
{
	struct bkey_s_c_subvolume s = bkey_s_c_to_subvolume(k);

	prt_printf(out, "root %llu snapshot id %u",
		   le64_to_cpu(s.v->inode),
		   le32_to_cpu(s.v->snapshot));

	if (bkey_val_bytes(s.k) > offsetof(struct bch_subvolume, parent))
		prt_printf(out, " parent %u", le32_to_cpu(s.v->parent));
}

static __always_inline int
bch2_subvolume_get_inlined(struct btree_trans *trans, unsigned subvol,
			   bool inconsistent_if_not_found,
			   int iter_flags,
			   struct bch_subvolume *s)
{
	int ret = bch2_bkey_get_val_typed(trans, BTREE_ID_subvolumes, POS(0, subvol),
					  iter_flags, subvolume, s);
	bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT) &&
				inconsistent_if_not_found,
				trans->c, "missing subvolume %u", subvol);
	return ret;
}

int bch2_subvolume_get(struct btree_trans *trans, unsigned subvol,
		       bool inconsistent_if_not_found,
		       int iter_flags,
		       struct bch_subvolume *s)
{
	return bch2_subvolume_get_inlined(trans, subvol, inconsistent_if_not_found, iter_flags, s);
}

int bch2_snapshot_get_subvol(struct btree_trans *trans, u32 snapshot,
			     struct bch_subvolume *subvol)
{
	struct bch_snapshot snap;

	return  bch2_snapshot_lookup(trans, snapshot, &snap) ?:
		bch2_subvolume_get(trans, le32_to_cpu(snap.subvol), true, 0, subvol);
}

int bch2_subvolume_get_snapshot(struct btree_trans *trans, u32 subvolid,
				u32 *snapid)
{
	struct btree_iter iter;
	struct bkey_s_c_subvolume subvol;
	int ret;

	subvol = bch2_bkey_get_iter_typed(trans, &iter,
					  BTREE_ID_subvolumes, POS(0, subvolid),
					  BTREE_ITER_CACHED|BTREE_ITER_WITH_UPDATES,
					  subvolume);
	ret = bkey_err(subvol);
	bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), trans->c,
				"missing subvolume %u", subvolid);

	if (likely(!ret))
		*snapid = le32_to_cpu(subvol.v->snapshot);
	bch2_trans_iter_exit(trans, &iter);
	return ret;
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

	if (bkey_val_bytes(k.k) > offsetof(struct bch_subvolume, parent) &&
	    le32_to_cpu(bkey_s_c_to_subvolume(k).v->parent) != old_parent)
		return 0;

	s = bch2_bkey_make_mut_typed(trans, iter, &k, 0, subvolume);
	ret = PTR_ERR_OR_ZERO(s);
	if (ret)
		return ret;

	s->v.parent = cpu_to_le32(new_parent);
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
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bch_subvolume s;

	return lockrestart_do(trans,
			bch2_subvolume_get(trans, subvolid_to_delete, true,
				   BTREE_ITER_CACHED, &s)) ?:
		for_each_btree_key_commit(trans, iter,
				BTREE_ID_subvolumes, POS_MIN, BTREE_ITER_PREFETCH, k,
				NULL, NULL, BTREE_INSERT_NOFAIL,
			bch2_subvolume_reparent(trans, &iter, k,
					subvolid_to_delete, le32_to_cpu(s.parent)));
}

/*
 * Delete subvolume, mark snapshot ID as deleted, queue up snapshot
 * deletion/cleanup:
 */
static int __bch2_subvolume_delete(struct btree_trans *trans, u32 subvolid)
{
	struct btree_iter iter;
	struct bkey_s_c_subvolume subvol;
	struct btree_trans_commit_hook *h;
	u32 snapid;
	int ret = 0;

	subvol = bch2_bkey_get_iter_typed(trans, &iter,
				BTREE_ID_subvolumes, POS(0, subvolid),
				BTREE_ITER_CACHED|BTREE_ITER_INTENT,
				subvolume);
	ret = bkey_err(subvol);
	bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), trans->c,
				"missing subvolume %u", subvolid);
	if (ret)
		return ret;

	snapid = le32_to_cpu(subvol.v->snapshot);

	ret = bch2_btree_delete_at(trans, &iter, 0);
	if (ret)
		goto err;

	ret = bch2_snapshot_node_set_deleted(trans, snapid);
	if (ret)
		goto err;

	h = bch2_trans_kmalloc(trans, sizeof(*h));
	ret = PTR_ERR_OR_ZERO(h);
	if (ret)
		goto err;

	h->fn = bch2_delete_dead_snapshots_hook;
	bch2_trans_commit_hook(trans, h);
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static int bch2_subvolume_delete(struct btree_trans *trans, u32 subvolid)
{
	return bch2_subvolumes_reparent(trans, subvolid) ?:
		commit_do(trans, NULL, NULL, BTREE_INSERT_NOFAIL,
			  __bch2_subvolume_delete(trans, subvolid));
}

static void bch2_subvolume_wait_for_pagecache_and_delete(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs,
				snapshot_wait_for_pagecache_and_delete_work);
	snapshot_id_list s;
	u32 *id;
	int ret = 0;

	while (!ret) {
		mutex_lock(&c->snapshots_unlinked_lock);
		s = c->snapshots_unlinked;
		darray_init(&c->snapshots_unlinked);
		mutex_unlock(&c->snapshots_unlinked_lock);

		if (!s.nr)
			break;

		bch2_evict_subvolume_inodes(c, &s);

		for (id = s.data; id < s.data + s.nr; id++) {
			ret = bch2_trans_run(c, bch2_subvolume_delete(&trans, *id));
			if (ret) {
				bch_err(c, "error deleting subvolume %u: %s", *id, bch2_err_str(ret));
				break;
			}
		}

		darray_exit(&s);
	}

	bch2_write_ref_put(c, BCH_WRITE_REF_snapshot_delete_pagecache);
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

	if (!bch2_write_ref_tryget(c, BCH_WRITE_REF_snapshot_delete_pagecache))
		return -EROFS;

	if (!queue_work(c->write_ref_wq, &c->snapshot_wait_for_pagecache_and_delete_work))
		bch2_write_ref_put(c, BCH_WRITE_REF_snapshot_delete_pagecache);
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
			BTREE_ITER_CACHED, subvolume);
	ret = PTR_ERR_OR_ZERO(n);
	if (unlikely(ret)) {
		bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), trans->c,
					"missing subvolume %u", subvolid);
		return ret;
	}

	SET_BCH_SUBVOLUME_UNLINKED(&n->v, true);
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

int bch2_subvolume_create(struct btree_trans *trans, u64 inode,
			  u32 src_subvolid,
			  u32 *new_subvolid,
			  u32 *new_snapshotid,
			  bool ro)
{
	struct bch_fs *c = trans->c;
	struct btree_iter dst_iter, src_iter = (struct btree_iter) { NULL };
	struct bkey_i_subvolume *new_subvol = NULL;
	struct bkey_i_subvolume *src_subvol = NULL;
	u32 parent = 0, new_nodes[2], snapshot_subvols[2];
	int ret = 0;

	ret = bch2_bkey_get_empty_slot(trans, &dst_iter,
				BTREE_ID_subvolumes, POS(0, U32_MAX));
	if (ret == -BCH_ERR_ENOSPC_btree_slot)
		ret = -BCH_ERR_ENOSPC_subvolume_create;
	if (ret)
		return ret;

	snapshot_subvols[0] = dst_iter.pos.offset;
	snapshot_subvols[1] = src_subvolid;

	if (src_subvolid) {
		/* Creating a snapshot: */

		src_subvol = bch2_bkey_get_mut_typed(trans, &src_iter,
				BTREE_ID_subvolumes, POS(0, src_subvolid),
				BTREE_ITER_CACHED, subvolume);
		ret = PTR_ERR_OR_ZERO(src_subvol);
		if (unlikely(ret)) {
			bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), c,
						"subvolume %u not found", src_subvolid);
			goto err;
		}

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

	new_subvol->v.flags	= 0;
	new_subvol->v.snapshot	= cpu_to_le32(new_nodes[0]);
	new_subvol->v.inode	= cpu_to_le64(inode);
	new_subvol->v.parent	= cpu_to_le32(src_subvolid);
	new_subvol->v.otime.lo	= cpu_to_le64(bch2_current_time(c));
	new_subvol->v.otime.hi	= 0;

	SET_BCH_SUBVOLUME_RO(&new_subvol->v, ro);
	SET_BCH_SUBVOLUME_SNAP(&new_subvol->v, src_subvolid != 0);

	*new_subvolid	= new_subvol->k.p.offset;
	*new_snapshotid	= new_nodes[0];
err:
	bch2_trans_iter_exit(trans, &src_iter);
	bch2_trans_iter_exit(trans, &dst_iter);
	return ret;
}

int bch2_fs_subvolumes_init(struct bch_fs *c)
{
	INIT_WORK(&c->snapshot_delete_work, bch2_delete_dead_snapshots_work);
	INIT_WORK(&c->snapshot_wait_for_pagecache_and_delete_work,
		  bch2_subvolume_wait_for_pagecache_and_delete);
	mutex_init(&c->snapshots_unlinked_lock);
	return 0;
}
