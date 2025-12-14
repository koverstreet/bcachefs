// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/accounting.h"
#include "alloc/buckets.h"

#include "btree/bbpos.h"
#include "btree/update.h"

#include "init/error.h"
#include "init/progress.h"
#include "init/passes.h"

#include "snapshots/snapshot.h"

#include "util/enumerated_ref.h"

#include <linux/random.h>

static void bch2_snapshot_delete_nodes_to_text(struct printbuf *out, struct snapshot_delete *d, bool full)
{
	size_t limit = !full ? 10 : SIZE_MAX;

	prt_printf(out, "deleting from trees");
	darray_for_each_max(d->deleting_from_trees, i, limit)
		prt_printf(out, " %u", *i);

	if (d->deleting_from_trees.nr > limit)
		prt_str(out, " (many)");
	prt_newline(out);

	prt_printf(out, "deleting leaves");
	darray_for_each_max(d->delete_leaves, i, limit)
		prt_printf(out, " %u", *i);

	if (d->delete_leaves.nr > limit)
		prt_str(out, " (many)");
	prt_newline(out);

	prt_printf(out, "interior");
	darray_for_each_max(d->delete_interior, i, limit)
		prt_printf(out, " %u->%u", i->id, i->live_child);

	if (d->delete_interior.nr > limit)
		prt_str(out, " (many)");
	prt_newline(out);
}

void bch2_snapshot_delete_status_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct snapshot_delete *d = &c->snapshots.delete;

	if (!d->running) {
		prt_str(out, "(not running)");
		return;
	}

	scoped_guard(mutex, &d->progress_lock) {
		prt_printf(out, "Snapshot deletion v%u\n", d->version);
		prt_str(out, "Progress: ");
		bch2_progress_to_text(out, &d->progress);
		prt_newline(out);
		bch2_snapshot_delete_nodes_to_text(out, d, false);
	}
}

/*
 * Mark a snapshot as deleted, for future cleanup:
 */
int bch2_snapshot_node_set_deleted(struct btree_trans *trans, u32 id)
{
	struct bkey_i_snapshot *s =
		bch2_bkey_get_mut_typed(trans, BTREE_ID_snapshots, POS(0, id), 0, snapshot);
	int ret = PTR_ERR_OR_ZERO(s);
	bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), trans->c, "missing snapshot %u", id);
	if (unlikely(ret))
		return ret;

	/* already deleted? */
	if (BCH_SNAPSHOT_WILL_DELETE(&s->v))
		return 0;

	SET_BCH_SNAPSHOT_WILL_DELETE(&s->v, true);
	SET_BCH_SNAPSHOT_SUBVOL(&s->v, false);
	s->v.subvol = 0;
	return 0;
}

static int bch2_snapshot_node_set_no_keys(struct btree_trans *trans, u32 id)
{
	struct bkey_i_snapshot *s =
		bch2_bkey_get_mut_typed(trans, BTREE_ID_snapshots, POS(0, id), 0, snapshot);
	int ret = PTR_ERR_OR_ZERO(s);
	bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), trans->c, "missing snapshot %u", id);
	if (unlikely(ret))
		return ret;

	SET_BCH_SNAPSHOT_NO_KEYS(&s->v,		true);
	SET_BCH_SNAPSHOT_WILL_DELETE(&s->v,	false);
	s->v.subvol = 0;
	return 0;
}

static inline void normalize_snapshot_child_pointers(struct bch_snapshot *s)
{
	if (le32_to_cpu(s->children[0]) < le32_to_cpu(s->children[1]))
		swap(s->children[0], s->children[1]);
}

static int bch2_snapshot_node_delete(struct btree_trans *trans, u32 id, bool delete_interior)
{
	struct bch_fs *c = trans->c;

	struct bkey_i_snapshot *s =
		bch2_bkey_get_mut_typed(trans, BTREE_ID_snapshots, POS(0, id), 0, snapshot);
	int ret = PTR_ERR_OR_ZERO(s);
	bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), c,
				"missing snapshot %u", id);

	if (ret)
		return ret;

	BUG_ON(BCH_SNAPSHOT_DELETED(&s->v));

	if (s->v.children[1]) {
		CLASS(bch_log_msg, msg)(c);
		prt_printf(&msg.m, "deleting node with two children:\n");
		bch2_snapshot_tree_keys_to_text(&msg.m, trans, id);
		bch2_snapshot_delete_nodes_to_text(&msg.m, &c->snapshots.delete, true);
		return -EINVAL;
	}

	u32 parent_id = le32_to_cpu(s->v.parent);
	u32 child_id = le32_to_cpu(s->v.children[0]);

	if (parent_id) {
		struct bkey_i_snapshot *parent =
			bch2_bkey_get_mut_typed(trans, BTREE_ID_snapshots, POS(0, parent_id),
						0, snapshot);
		ret = PTR_ERR_OR_ZERO(parent);
		bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), c,
					"missing snapshot %u", parent_id);
		if (unlikely(ret))
			return ret;

		/* find entry in parent->children for node being deleted */
		unsigned i;
		for (i = 0; i < 2; i++)
			if (le32_to_cpu(parent->v.children[i]) == id)
				break;

		if (bch2_fs_inconsistent_on(i == 2, c,
					"snapshot %u missing child pointer to %u",
					parent_id, id))
			return bch_err_throw(c, ENOENT_snapshot);

		parent->v.children[i] = cpu_to_le32(child_id);

		normalize_snapshot_child_pointers(&parent->v);
	}

	if (child_id) {
		if (!delete_interior) {
			CLASS(bch_log_msg, msg)(c);
			prt_printf(&msg.m, "deleting interior node %llu with child %u at runtime:\n",
				   s->k.p.offset, child_id);
			bch2_snapshot_tree_keys_to_text(&msg.m, trans, id);
			bch2_snapshot_delete_nodes_to_text(&msg.m, &c->snapshots.delete, true);
			return -EINVAL;
		}

		struct bkey_i_snapshot *child =
			bch2_bkey_get_mut_typed(trans, BTREE_ID_snapshots, POS(0, child_id),
						0, snapshot);
		ret = PTR_ERR_OR_ZERO(child);
		bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), c,
					"missing snapshot %u", child_id);
		if (unlikely(ret))
			return ret;

		child->v.parent = cpu_to_le32(parent_id);
	}

	if (!parent_id) {
		/*
		 * We're deleting the root of a snapshot tree: update the
		 * snapshot_tree entry to point to the new root, or delete it if
		 * this is the last snapshot ID in this tree:
		 */
		struct bkey_i_snapshot_tree *s_t = errptr_try(bch2_bkey_get_mut_typed(trans,
				BTREE_ID_snapshot_trees, POS(0, le32_to_cpu(s->v.tree)),
				0, snapshot_tree));

		if (s->v.children[0]) {
			s_t->v.root_snapshot = s->v.children[0];
		} else {
			s_t->k.type = KEY_TYPE_deleted;
			set_bkey_val_u64s(&s_t->k, 0);
		}
	}

	if (!bch2_request_incompat_feature(c, bcachefs_metadata_version_snapshot_deletion_v2)) {
		SET_BCH_SNAPSHOT_DELETED(&s->v, true);
		s->v.parent		= 0;
		s->v.children[0]	= 0;
		s->v.children[1]	= 0;
		s->v.subvol		= 0;
		s->v.tree		= 0;
		s->v.depth		= 0;
		s->v.skip[0]		= 0;
		s->v.skip[1]		= 0;
		s->v.skip[2]		= 0;
	} else {
		s->k.type = KEY_TYPE_deleted;
		set_bkey_val_u64s(&s->k, 0);
	}

	/*
	 * Delete accounting: note that designated initializers will not
	 * reliably cause a struct to be zeroed if it's a union:
	 */

	struct disk_accounting_pos acc;
	memset(&acc, 0, sizeof(acc));
	acc.type = BCH_DISK_ACCOUNTING_snapshot;
	acc.snapshot.id = id;

	try(bch2_btree_bit_mod_buffered(trans, BTREE_ID_accounting,
					disk_accounting_pos_to_bpos(&acc),
					false));

	return 0;
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
 *
 * solution:
 *
 * for a key in an interior snapshot node that needs work to be done that
 * requires it to be mutated: iterate over all descendent leaf nodes and copy
 * that key to snapshot leaf nodes, where we can mutate it
 */

static inline u32 interior_delete_has_id(interior_delete_list *l, u32 id)
{
	struct snapshot_interior_delete *i = darray_find_p(*l, i, i->id == id);
	return i ? i->live_child : 0;
}

static bool snapshot_id_dying(struct snapshot_delete *d, unsigned id)
{
	return snapshot_list_has_id(&d->delete_leaves, id) ||
		interior_delete_has_id(&d->delete_interior, id) != 0;
}

static int delete_dead_snapshots_process_key(struct btree_trans *trans,
					     struct btree_iter *iter,
					     struct bkey_s_c k)
{
	struct snapshot_delete *d = &trans->c->snapshots.delete;

	if (snapshot_list_has_id(&d->delete_leaves, k.k->p.snapshot))
		return bch2_btree_delete_at(trans, iter,
					    BTREE_UPDATE_internal_snapshot_node);

	u32 live_child = interior_delete_has_id(&d->delete_interior, k.k->p.snapshot);
	if (live_child) {
		struct bkey_i *new = errptr_try(bch2_bkey_make_mut_noupdate(trans, k));

		new->k.p.snapshot = live_child;

		CLASS(btree_iter, dst_iter)(trans, iter->btree_id, new->k.p,
					    BTREE_ITER_all_snapshots|BTREE_ITER_intent);
		struct bkey_s_c dst_k = bkey_try(bch2_btree_iter_peek_slot(&dst_iter));

		return (bkey_deleted(dst_k.k)
			 ? bch2_trans_update(trans, &dst_iter, new,
					     BTREE_UPDATE_internal_snapshot_node)
			 : 0) ?:
			bch2_btree_delete_at(trans, iter,
					     BTREE_UPDATE_internal_snapshot_node);
	}

	return 0;
}

static bool skip_unrelated_snapshot_tree(struct btree_trans *trans, struct btree_iter *iter, u64 *prev_inum)
{
	struct bch_fs *c = trans->c;
	struct snapshot_delete *d = &c->snapshots.delete;

	u64 inum = iter->btree_id != BTREE_ID_inodes
		? iter->pos.inode
		: iter->pos.offset;

	if (*prev_inum == inum)
		return false;

	*prev_inum = inum;

	bool ret = !snapshot_list_has_id(&d->deleting_from_trees,
					 bch2_snapshot_tree(c, iter->pos.snapshot));
	if (unlikely(ret)) {
		struct bpos pos = iter->pos;
		pos.snapshot = 0;
		if (iter->btree_id != BTREE_ID_inodes)
			pos.offset = U64_MAX;
		bch2_btree_iter_set_pos(iter, bpos_nosnap_successor(pos));
	}

	return ret;
}

static int delete_dead_snapshot_keys_v1(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	struct snapshot_delete *d = &c->snapshots.delete;

	bch2_progress_init(&d->progress, __func__, c, btree_has_snapshots_mask, 0);
	d->progress.silent	= true;
	d->version		= 1;

	for (unsigned btree = 0; btree < BTREE_ID_NR; btree++) {
		CLASS(disk_reservation, res)(c);
		u64 prev_inum = 0;

		if (!btree_type_has_snapshots(btree))
			continue;

		try(for_each_btree_key_commit(trans, iter,
				btree, POS_MIN,
				BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k,
				&res.r, NULL, BCH_TRANS_COMMIT_no_enospc, ({
			bch2_progress_update_iter(trans, &d->progress, &iter);

			if (skip_unrelated_snapshot_tree(trans, &iter, &prev_inum))
				continue;

			bch2_disk_reservation_put(c, &res.r);
			delete_dead_snapshots_process_key(trans, &iter, k);
		})));
	}

	return 0;
}

static int delete_dead_snapshot_keys_range(struct btree_trans *trans,
					   struct disk_reservation *res,
					   enum btree_id btree,
					   struct bpos start, struct bpos end)
{
	struct bch_fs *c = trans->c;

	return for_each_btree_key_max_commit(trans, iter,
			btree, start, end,
			BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k,
			res, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		bch2_disk_reservation_put(c, res);
		delete_dead_snapshots_process_key(trans, &iter, k);
	}));
}

static int delete_dead_snapshot_keys_v2(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	struct snapshot_delete *d = &c->snapshots.delete;
	CLASS(disk_reservation, res)(c);
	u64 prev_inum = 0;

	bch2_progress_init(&d->progress, __func__, c, BIT_ULL(BTREE_ID_inodes), 0);
	d->progress.silent	= true;
	d->version		= 2;

	CLASS(btree_iter, iter)(trans, BTREE_ID_inodes, POS_MIN,
				BTREE_ITER_prefetch|BTREE_ITER_all_snapshots);

	/*
	 * First, delete extents/dirents/xattrs
	 *
	 * If an extent/dirent/xattr is present in a given snapshot ID an inode
	 * must also be present in that same snapshot ID, so we can use this to
	 * greatly accelerate scanning:
	 */

	while (1) {
		struct bkey_s_c k;
		try(lockrestart_do(trans,
				bkey_err(k = bch2_btree_iter_peek(&iter))));
		if (!k.k)
			break;

		bch2_progress_update_iter(trans, &d->progress, &iter);

		if (skip_unrelated_snapshot_tree(trans, &iter, &prev_inum))
			continue;

		if (snapshot_id_dying(d, k.k->p.snapshot)) {
			struct bpos start	= POS(k.k->p.offset, 0);
			struct bpos end		= POS(k.k->p.offset, U64_MAX);

			try(delete_dead_snapshot_keys_range(trans, &res.r, BTREE_ID_extents, start, end));
			try(delete_dead_snapshot_keys_range(trans, &res.r, BTREE_ID_dirents, start, end));
			try(delete_dead_snapshot_keys_range(trans, &res.r, BTREE_ID_xattrs, start, end));

			bch2_btree_iter_set_pos(&iter, POS(0, k.k->p.offset + 1));
		} else {
			bch2_btree_iter_advance(&iter);
		}
	}

	/* Then the inodes */

	prev_inum = 0;
	try(for_each_btree_key_commit(trans, iter,
			BTREE_ID_inodes, POS_MIN,
			BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k,
			&res.r, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		if (skip_unrelated_snapshot_tree(trans, &iter, &prev_inum))
			continue;

		bch2_disk_reservation_put(c, &res.r);
		delete_dead_snapshots_process_key(trans, &iter, k);
	})));

	return 0;
}

/*
 * For a given snapshot, if it doesn't have a subvolume that points to it, and
 * it doesn't have child snapshot nodes - it's now redundant and we can mark it
 * as deleted.
 */
static int check_should_delete_snapshot(struct btree_trans *trans, struct bkey_s_c k)
{
	if (k.k->type != KEY_TYPE_snapshot)
		return 0;

	struct bch_fs *c = trans->c;
	struct bkey_s_c_snapshot s = bkey_s_c_to_snapshot(k);

	if (BCH_SNAPSHOT_SUBVOL(s.v) ||
	    BCH_SNAPSHOT_DELETED(s.v))
		return 0;

	struct snapshot_delete *d = &c->snapshots.delete;
	guard(mutex)(&d->progress_lock);

	u32 live_child = 0, nr_live_children = 0;
	for (unsigned i = 0; i < 2; i++) {
		u32 id = le32_to_cpu(s.v->children[i]);
		if (id && !snapshot_list_has_id(&d->delete_leaves, id)) {
			nr_live_children++;
			live_child = interior_delete_has_id(&d->delete_interior, id) ?: id;
		}
	}

	if (nr_live_children == 2 ||
	    (nr_live_children == 1 && BCH_SNAPSHOT_NO_KEYS(s.v)))
		return 0;

	try(snapshot_list_add_nodup(c, &d->deleting_from_trees,
				    bch2_snapshot_tree(c, s.k->p.offset)));

	if (!nr_live_children) {
		try(snapshot_list_add(c, &d->delete_leaves, s.k->p.offset));
	} else {
		struct snapshot_interior_delete n = {
			.id		= s.k->p.offset,
			.live_child	= live_child,
		};

		if (n.id == n.live_child) {
			bch_err(c, "error finding live descendent of %llu", s.k->p.offset);
			return -EINVAL;
		}
	}

	return 0;
}

static inline u32 bch2_snapshot_nth_parent_skip(struct bch_fs *c, u32 id, u32 n,
						interior_delete_list *skip)
{
	guard(rcu)();
	struct snapshot_table *t = rcu_dereference(c->snapshots.table);

	while (interior_delete_has_id(skip, id))
		id = __bch2_snapshot_parent(c, t, id);

	while (n--) {
		do {
			id = __bch2_snapshot_parent(c, t, id);
		} while (interior_delete_has_id(skip, id));
	}

	return id;
}

static int bch2_fix_child_of_deleted_snapshot(struct btree_trans *trans,
					      struct btree_iter *iter, struct bkey_s_c k,
					      interior_delete_list *deleted)
{
	struct bch_fs *c = trans->c;
	u32 nr_deleted_ancestors = 0;

	if (!bch2_snapshot_exists(c, k.k->p.offset))
		return 0;

	if (k.k->type != KEY_TYPE_snapshot)
		return 0;

	if (interior_delete_has_id(deleted, k.k->p.offset))
		return 0;

	struct bkey_i_snapshot *s =
		errptr_try(bch2_bkey_make_mut_noupdate_typed(trans, k, snapshot));

	darray_for_each(*deleted, i)
		nr_deleted_ancestors += bch2_snapshots_same_tree(c, s->k.p.offset, i->id) &&
		bch2_snapshot_is_ancestor(c, s->k.p.offset, i->id);

	if (!nr_deleted_ancestors)
		return 0;

	le32_add_cpu(&s->v.depth, -nr_deleted_ancestors);

	if (!s->v.depth) {
		s->v.skip[0] = 0;
		s->v.skip[1] = 0;
		s->v.skip[2] = 0;
	} else {
		u32 depth = le32_to_cpu(s->v.depth);
		u32 parent = bch2_snapshot_parent(c, s->k.p.offset);

		for (unsigned j = 0; j < ARRAY_SIZE(s->v.skip); j++) {
			u32 id = le32_to_cpu(s->v.skip[j]);

			if (interior_delete_has_id(deleted, id)) {
				id = bch2_snapshot_nth_parent_skip(c,
							parent,
							depth > 1
							? get_random_u32_below(depth - 1)
							: 0,
							deleted);
				s->v.skip[j] = cpu_to_le32(id);
			}
		}

		bubble_sort(s->v.skip, ARRAY_SIZE(s->v.skip), cmp_le32);
	}

	return bch2_trans_update(trans, iter, &s->k_i, 0);
}

static int delete_dead_snapshots_locked(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);

	/*
	 * For every snapshot node: If we have no live children and it's not
	 * pointed to by a subvolume, delete it:
	 */
	try(for_each_btree_key(trans, iter, BTREE_ID_snapshots, POS_MIN, 0, k,
		check_should_delete_snapshot(trans, k)));

	struct snapshot_delete *d = &c->snapshots.delete;
	if (!d->delete_leaves.nr && !d->delete_interior.nr)
		return 0;

	CLASS(printbuf, buf)();
	bch2_snapshot_delete_nodes_to_text(&buf, d, false);
	try(commit_do(trans, NULL, NULL, 0, bch2_trans_log_msg(trans, &buf)));

	try(!bch2_request_incompat_feature(c, bcachefs_metadata_version_snapshot_deletion_v2)
	    ? delete_dead_snapshot_keys_v2(trans)
	    : delete_dead_snapshot_keys_v1(trans));

	darray_for_each(d->delete_leaves, i)
		try(commit_do(trans, NULL, NULL, 0,
			bch2_snapshot_node_delete(trans, *i, false)));

	darray_for_each(d->delete_interior, i)
		try(commit_do(trans, NULL, NULL, 0,
			bch2_snapshot_node_set_no_keys(trans, i->id)));

	return 0;
}

int __bch2_delete_dead_snapshots(struct bch_fs *c)
{
	struct snapshot_delete *d = &c->snapshots.delete;

	if (!mutex_trylock(&d->lock))
		return 0;

	if (!test_and_clear_bit(BCH_FS_need_delete_dead_snapshots, &c->flags)) {
		mutex_unlock(&d->lock);
		return 0;
	}

	d->running = true;
	d->progress.pos = BBPOS_MIN;

	int ret = delete_dead_snapshots_locked(c);

	scoped_guard(mutex, &d->progress_lock) {
		darray_exit(&d->deleting_from_trees);
		darray_exit(&d->delete_interior);
		darray_exit(&d->delete_leaves);
		d->running = false;
	}

	bch2_recovery_pass_set_no_ratelimit(c, BCH_RECOVERY_PASS_check_snapshots);

	mutex_unlock(&d->lock);
	return ret;
}

int bch2_delete_dead_snapshots(struct bch_fs *c)
{
	if (!c->opts.auto_snapshot_deletion)
		return 0;

	return __bch2_delete_dead_snapshots(c);
}

void bch2_delete_dead_snapshots_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs, snapshots.delete.work);

	set_worker_desc("bcachefs-delete-dead-snapshots/%s", c->name);

	bch2_delete_dead_snapshots(c);
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_delete_dead_snapshots);
}

void bch2_delete_dead_snapshots_async(struct bch_fs *c)
{
	if (!c->opts.auto_snapshot_deletion)
		return;

	if (!enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_delete_dead_snapshots))
		return;

	BUG_ON(!test_bit(BCH_FS_may_go_rw, &c->flags));

	if (!queue_work(system_long_wq, &c->snapshots.delete.work))
		enumerated_ref_put(&c->writes, BCH_WRITE_REF_delete_dead_snapshots);
}

static int bch2_get_dead_interior_snapshots(struct btree_trans *trans, struct bkey_s_c k,
					    interior_delete_list *delete)
{
	if (k.k->type != KEY_TYPE_snapshot)
		return 0;

	struct bkey_s_c_snapshot s = bkey_s_c_to_snapshot(k);

	if (BCH_SNAPSHOT_DELETED(s.v))
		return 0;

	if (BCH_SNAPSHOT_NO_KEYS(s.v)) {
		u32 live_child = 0, nr_live_children = 0;
		for (unsigned i = 0; i < 2; i++) {
			u32 id = le32_to_cpu(s.v->children[i]);
			if (id) {
				nr_live_children++;
				live_child = interior_delete_has_id(delete, id) ?: id;
			}
		}

		if (nr_live_children != 1)
			return 0;

		struct snapshot_interior_delete n = {
			.id		= k.k->p.offset,
			.live_child	= live_child,
		};

		return darray_push(delete, n);
	}

	return 0;
}

int bch2_delete_dead_interior_snapshots(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	CLASS(interior_delete_list, delete)();

	try(for_each_btree_key(trans, iter, BTREE_ID_snapshots, POS_MIN, 0, k,
			       bch2_get_dead_interior_snapshots(trans, k, &delete)));

	if (delete.nr) {
		/*
		 * Fixing children of deleted snapshots can't be done completely
		 * atomically, if we crash between here and when we delete the interior
		 * nodes some depth fields will be off:
		 */
		try(for_each_btree_key_commit(trans, iter, BTREE_ID_snapshots, POS_MIN,
					      BTREE_ITER_intent, k,
					      NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			bch2_fix_child_of_deleted_snapshot(trans, &iter, k, &delete)));

		darray_for_each(delete, i) {
			int ret = commit_do(trans, NULL, NULL, 0,
				bch2_snapshot_node_delete(trans, i->id, true));
			if (!bch2_err_matches(ret, EROFS))
				bch_err_msg(c, ret, "deleting snapshot %u", i->id);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static bool interior_snapshot_needs_delete(struct bkey_s_c_snapshot snap)
{
	/* If there's one child, it's redundant and keys will be moved to the child */
	return !!snap.v->children[0] + !!snap.v->children[1] == 1;
}

int bch2_check_snapshot_needs_deletion(struct btree_trans *trans, struct bkey_s_c k,
				       u32 *nr_empty_interior)
{
	if (k.k->type != KEY_TYPE_snapshot)
		return 0;

	struct bkey_s_c_snapshot s = bkey_s_c_to_snapshot(k);
	struct bch_fs *c = trans->c;

	if (BCH_SNAPSHOT_DELETED(s.v))
		return 0;

	if (BCH_SNAPSHOT_NO_KEYS(s.v))
		*nr_empty_interior += 1;
	else if (BCH_SNAPSHOT_WILL_DELETE(s.v) ||
		 interior_snapshot_needs_delete(s))
		set_bit(BCH_FS_need_delete_dead_snapshots, &c->flags);

	return 0;
}
