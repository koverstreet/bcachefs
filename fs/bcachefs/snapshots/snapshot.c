// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/buckets.h"

#include "btree/bbpos.h"
#include "btree/bkey_buf.h"
#include "btree/cache.h"
#include "btree/key_cache.h"
#include "btree/update.h"

#include "init/error.h"
#include "init/progress.h"
#include "init/passes.h"

#include "snapshots/snapshot.h"

#include "vfs/fs.h"

#include "util/enumerated_ref.h"

#include <linux/random.h>

/*
 * Snapshot trees:
 *
 * Keys in BTREE_ID_snapshot_trees identify a whole tree of snapshot nodes; they
 * exist to provide a stable identifier for the whole lifetime of a snapshot
 * tree.
 */

void bch2_snapshot_tree_to_text(struct printbuf *out, struct bch_fs *c,
				struct bkey_s_c k)
{
	struct bkey_s_c_snapshot_tree t = bkey_s_c_to_snapshot_tree(k);

	prt_printf(out, "subvol %u root snapshot %u",
		   le32_to_cpu(t.v->master_subvol),
		   le32_to_cpu(t.v->root_snapshot));
}

int bch2_snapshot_tree_validate(struct bch_fs *c, struct bkey_s_c k,
				struct bkey_validate_context from)
{
	int ret = 0;

	bkey_fsck_err_on(bkey_gt(k.k->p, POS(0, U32_MAX)) ||
			 bkey_lt(k.k->p, POS(0, 1)),
			 c, snapshot_tree_pos_bad,
			 "bad pos");
fsck_err:
	return ret;
}

int bch2_snapshot_tree_lookup(struct btree_trans *trans, u32 id,
			      struct bch_snapshot_tree *s)
{
	int ret = bch2_bkey_get_val_typed(trans, BTREE_ID_snapshot_trees, POS(0, id),
					  BTREE_ITER_with_updates, snapshot_tree, s);

	if (bch2_err_matches(ret, ENOENT))
		ret = bch_err_throw(trans->c, ENOENT_snapshot_tree);
	return ret;
}

struct bkey_i_snapshot_tree *
__bch2_snapshot_tree_create(struct btree_trans *trans)
{
	CLASS(btree_iter_uninit, iter)(trans);
	int ret = bch2_bkey_get_empty_slot(trans, &iter,
			BTREE_ID_snapshot_trees, POS(0, U32_MAX));
	if (ret == -BCH_ERR_ENOSPC_btree_slot)
		ret = bch_err_throw(trans->c, ENOSPC_snapshot_tree);
	if (ret)
		return ERR_PTR(ret);

	return bch2_bkey_alloc(trans, &iter, 0, snapshot_tree);
}

/* Snapshot nodes: */

static bool __bch2_snapshot_is_ancestor_early(struct snapshot_table *t, u32 id, u32 ancestor)
{
	while (id && id < ancestor) {
		const struct snapshot_t *s = __snapshot_t(t, id);
		id = s ? s->parent : 0;
	}
	return id == ancestor;
}

bool bch2_snapshot_is_ancestor_early(struct bch_fs *c, u32 id, u32 ancestor)
{
	guard(rcu)();
	return __bch2_snapshot_is_ancestor_early(rcu_dereference(c->snapshots), id, ancestor);
}

static inline u32 get_ancestor_below(struct snapshot_table *t, u32 id, u32 ancestor)
{
	const struct snapshot_t *s = __snapshot_t(t, id);
	if (!s)
		return 0;

	if (s->skip[2] <= ancestor)
		return s->skip[2];
	if (s->skip[1] <= ancestor)
		return s->skip[1];
	if (s->skip[0] <= ancestor)
		return s->skip[0];
	return s->parent;
}

static bool test_ancestor_bitmap(struct snapshot_table *t, u32 id, u32 ancestor)
{
	const struct snapshot_t *s = __snapshot_t(t, id);
	if (!s)
		return false;

	return test_bit(ancestor - id - 1, s->is_ancestor);
}

bool __bch2_snapshot_is_ancestor(struct bch_fs *c, u32 id, u32 ancestor)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	u32 orig_id = id;
#endif

	guard(rcu)();
	struct snapshot_table *t = rcu_dereference(c->snapshots);

	if (unlikely(recovery_pass_will_run(c, BCH_RECOVERY_PASS_check_snapshots)))
		return __bch2_snapshot_is_ancestor_early(t, id, ancestor);

	if (likely(ancestor >= IS_ANCESTOR_BITMAP))
		while (id && id < ancestor - IS_ANCESTOR_BITMAP)
			id = get_ancestor_below(t, id, ancestor);

	bool ret = id && id < ancestor
		? test_ancestor_bitmap(t, id, ancestor)
		: id == ancestor;

	EBUG_ON(ret != __bch2_snapshot_is_ancestor_early(t, orig_id, ancestor));
	return ret;
}

static noinline struct snapshot_t *__snapshot_t_mut(struct bch_fs *c, u32 id)
{
	size_t idx = U32_MAX - id;
	struct snapshot_table *new, *old;

	size_t new_bytes = kmalloc_size_roundup(struct_size(new, s, idx + 1));
	size_t new_size = (new_bytes - sizeof(*new)) / sizeof(new->s[0]);

	if (unlikely(new_bytes > INT_MAX))
		return NULL;

	new = kvzalloc(new_bytes, GFP_KERNEL);
	if (!new)
		return NULL;

	new->nr = new_size;

	old = rcu_dereference_protected(c->snapshots, true);
	if (old)
		memcpy(new->s, old->s, sizeof(old->s[0]) * old->nr);

	rcu_assign_pointer(c->snapshots, new);
	kvfree_rcu(old, rcu);

	return &rcu_dereference_protected(c->snapshots,
				lockdep_is_held(&c->snapshot_table_lock))->s[idx];
}

struct snapshot_t *bch2_snapshot_t_mut(struct bch_fs *c, u32 id)
{
	size_t idx = U32_MAX - id;
	struct snapshot_table *table =
		rcu_dereference_protected(c->snapshots,
				lockdep_is_held(&c->snapshot_table_lock));

	lockdep_assert_held(&c->snapshot_table_lock);

	if (likely(table && idx < table->nr))
		return &table->s[idx];

	return __snapshot_t_mut(c, id);
}

void bch2_snapshot_to_text(struct printbuf *out, struct bch_fs *c,
			   struct bkey_s_c k)
{
	struct bkey_s_c_snapshot s = bkey_s_c_to_snapshot(k);

	if (BCH_SNAPSHOT_SUBVOL(s.v))
		prt_str(out, "subvol ");
	if (BCH_SNAPSHOT_WILL_DELETE(s.v))
		prt_str(out, "will_delete ");
	if (BCH_SNAPSHOT_DELETED(s.v))
		prt_str(out, "deleted ");

	prt_printf(out, "parent %10u children %10u %10u subvol %u tree %u",
	       le32_to_cpu(s.v->parent),
	       le32_to_cpu(s.v->children[0]),
	       le32_to_cpu(s.v->children[1]),
	       le32_to_cpu(s.v->subvol),
	       le32_to_cpu(s.v->tree));

	if (bkey_val_bytes(k.k) > offsetof(struct bch_snapshot, depth))
		prt_printf(out, " depth %u skiplist %u %u %u",
			   le32_to_cpu(s.v->depth),
			   le32_to_cpu(s.v->skip[0]),
			   le32_to_cpu(s.v->skip[1]),
			   le32_to_cpu(s.v->skip[2]));
}

int bch2_snapshot_validate(struct bch_fs *c, struct bkey_s_c k,
			   struct bkey_validate_context from)
{
	struct bkey_s_c_snapshot s;
	u32 i, id;
	int ret = 0;

	bkey_fsck_err_on(bkey_gt(k.k->p, POS(0, U32_MAX)) ||
			 bkey_lt(k.k->p, POS(0, 1)),
			 c, snapshot_pos_bad,
			 "bad pos");

	s = bkey_s_c_to_snapshot(k);

	id = le32_to_cpu(s.v->parent);
	bkey_fsck_err_on(id && id <= k.k->p.offset,
			 c, snapshot_parent_bad,
			 "bad parent node (%u <= %llu)",
			 id, k.k->p.offset);

	bkey_fsck_err_on(le32_to_cpu(s.v->children[0]) < le32_to_cpu(s.v->children[1]),
			 c, snapshot_children_not_normalized,
			 "children not normalized");

	bkey_fsck_err_on(s.v->children[0] && s.v->children[0] == s.v->children[1],
			 c, snapshot_child_duplicate,
			 "duplicate child nodes");

	for (i = 0; i < 2; i++) {
		id = le32_to_cpu(s.v->children[i]);

		bkey_fsck_err_on(id >= k.k->p.offset,
				 c, snapshot_child_bad,
				 "bad child node (%u >= %llu)",
				 id, k.k->p.offset);
	}

	if (bkey_val_bytes(k.k) > offsetof(struct bch_snapshot, skip)) {
		bkey_fsck_err_on(le32_to_cpu(s.v->skip[0]) > le32_to_cpu(s.v->skip[1]) ||
				 le32_to_cpu(s.v->skip[1]) > le32_to_cpu(s.v->skip[2]),
				 c, snapshot_skiplist_not_normalized,
				 "skiplist not normalized");

		for (i = 0; i < ARRAY_SIZE(s.v->skip); i++) {
			id = le32_to_cpu(s.v->skip[i]);

			bkey_fsck_err_on(id && id < le32_to_cpu(s.v->parent),
					 c, snapshot_skiplist_bad,
					 "bad skiplist node %u", id);
		}
	}
fsck_err:
	return ret;
}

static int __bch2_mark_snapshot(struct btree_trans *trans,
		       enum btree_id btree, unsigned level,
		       struct bkey_s_c old, struct bkey_s_c new,
		       enum btree_iter_update_trigger_flags flags)
{
	struct bch_fs *c = trans->c;
	struct snapshot_t *t;
	u32 id = new.k->p.offset;

	guard(mutex)(&c->snapshot_table_lock);

	t = bch2_snapshot_t_mut(c, id);
	if (!t)
		return bch_err_throw(c, ENOMEM_mark_snapshot);

	if (new.k->type == KEY_TYPE_snapshot) {
		struct bkey_s_c_snapshot s = bkey_s_c_to_snapshot(new);

		t->state	= !BCH_SNAPSHOT_DELETED(s.v) && !BCH_SNAPSHOT_NO_KEYS(s.v)
			? SNAPSHOT_ID_live
			: SNAPSHOT_ID_deleted;
		t->parent	= le32_to_cpu(s.v->parent);
		t->children[0]	= le32_to_cpu(s.v->children[0]);
		t->children[1]	= le32_to_cpu(s.v->children[1]);
		t->subvol	= BCH_SNAPSHOT_SUBVOL(s.v) ? le32_to_cpu(s.v->subvol) : 0;
		t->tree		= le32_to_cpu(s.v->tree);

		if (bkey_val_bytes(s.k) > offsetof(struct bch_snapshot, depth)) {
			t->depth	= le32_to_cpu(s.v->depth);
			t->skip[0]	= le32_to_cpu(s.v->skip[0]);
			t->skip[1]	= le32_to_cpu(s.v->skip[1]);
			t->skip[2]	= le32_to_cpu(s.v->skip[2]);
		} else {
			t->depth	= 0;
			t->skip[0]	= 0;
			t->skip[1]	= 0;
			t->skip[2]	= 0;
		}

		u32 parent = id;

		while ((parent = bch2_snapshot_parent_early(c, parent)) &&
		       parent - id - 1 < IS_ANCESTOR_BITMAP)
			__set_bit(parent - id - 1, t->is_ancestor);

		if (BCH_SNAPSHOT_WILL_DELETE(s.v)) {
			set_bit(BCH_FS_need_delete_dead_snapshots, &c->flags);
			if (c->recovery.pass_done > BCH_RECOVERY_PASS_delete_dead_snapshots)
				bch2_delete_dead_snapshots_async(c);
		}
	} else {
		memset(t, 0, sizeof(*t));
	}

	return 0;
}

int bch2_mark_snapshot(struct btree_trans *trans,
		       enum btree_id btree, unsigned level,
		       struct bkey_s_c old, struct bkey_s new,
		       enum btree_iter_update_trigger_flags flags)
{
	return __bch2_mark_snapshot(trans, btree, level, old, new.s_c, flags);
}

static u32 bch2_snapshot_child(struct snapshot_table *t,
			       u32 id, unsigned child)
{
	return __snapshot_t(t, id)->children[child];
}

static u32 bch2_snapshot_left_child(struct snapshot_table *t, u32 id)
{
	return bch2_snapshot_child(t, id, 0);
}

static u32 bch2_snapshot_right_child(struct snapshot_table *t, u32 id)
{
	return bch2_snapshot_child(t, id, 1);
}

u32 bch2_snapshot_tree_next(struct snapshot_table *t, u32 id)
{
	u32 n, parent;

	n = bch2_snapshot_left_child(t, id);
	if (n)
		return n;

	while ((parent = __bch2_snapshot_parent(t, id))) {
		n = bch2_snapshot_right_child(t, parent);
		if (n && n != id)
			return n;
		id = parent;
	}

	return 0;
}

int bch2_snapshot_lookup(struct btree_trans *trans, u32 id,
			 struct bch_snapshot *s)
{
	return bch2_bkey_get_val_typed(trans, BTREE_ID_snapshots, POS(0, id),
				       BTREE_ITER_with_updates, snapshot, s);
}

int __bch2_get_snapshot_overwrites(struct btree_trans *trans,
				   enum btree_id btree, struct bpos pos,
				   snapshot_id_list *s)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c k;
	int ret = 0;

	for_each_btree_key_reverse_norestart(trans, iter, btree, bpos_predecessor(pos),
					     BTREE_ITER_all_snapshots, k, ret) {
		if (!bkey_eq(k.k->p, pos))
			break;

		if (!bch2_snapshot_is_ancestor(c, k.k->p.snapshot, pos.snapshot) ||
		    snapshot_list_has_ancestor(c, s, k.k->p.snapshot))
			continue;

		ret = snapshot_list_add(c, s, k.k->p.snapshot);
		if (ret)
			break;
	}
	if (ret)
		darray_exit(s);

	return ret;
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

	SET_BCH_SNAPSHOT_NO_KEYS(&s->v, true);
	s->v.subvol = 0;
	return 0;
}

static inline void normalize_snapshot_child_pointers(struct bch_snapshot *s)
{
	if (le32_to_cpu(s->children[0]) < le32_to_cpu(s->children[1]))
		swap(s->children[0], s->children[1]);
}

static int bch2_snapshot_node_delete(struct btree_trans *trans, u32 id)
{
	struct bch_fs *c = trans->c;
	u32 parent_id, child_id;
	unsigned i;

	struct bkey_i_snapshot *s =
		bch2_bkey_get_mut_typed(trans, BTREE_ID_snapshots, POS(0, id), 0, snapshot);
	int ret = PTR_ERR_OR_ZERO(s);
	bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), c,
				"missing snapshot %u", id);

	if (ret)
		return ret;

	BUG_ON(BCH_SNAPSHOT_DELETED(&s->v));
	BUG_ON(s->v.children[1]);

	parent_id = le32_to_cpu(s->v.parent);
	child_id = le32_to_cpu(s->v.children[0]);

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
		struct bkey_i_snapshot *child =
			bch2_bkey_get_mut_typed(trans, BTREE_ID_snapshots, POS(0, child_id),
						0, snapshot);
		ret = PTR_ERR_OR_ZERO(child);
		bch2_fs_inconsistent_on(bch2_err_matches(ret, ENOENT), c,
					"missing snapshot %u", child_id);
		if (unlikely(ret))
			return ret;

		child->v.parent = cpu_to_le32(parent_id);

		if (!child->v.parent) {
			child->v.skip[0] = 0;
			child->v.skip[1] = 0;
			child->v.skip[2] = 0;
		}
	}

	if (!parent_id) {
		/*
		 * We're deleting the root of a snapshot tree: update the
		 * snapshot_tree entry to point to the new root, or delete it if
		 * this is the last snapshot ID in this tree:
		 */

		BUG_ON(s->v.children[1]);

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

	return 0;
}

static int create_snapids(struct btree_trans *trans, u32 parent, u32 tree,
			  u32 *new_snapids,
			  u32 *snapshot_subvols,
			  unsigned nr_snapids)
{
	struct bch_fs *c = trans->c;
	u32 depth = bch2_snapshot_depth(c, parent);

	CLASS(btree_iter, iter)(trans, BTREE_ID_snapshots, POS_MIN, BTREE_ITER_intent);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek(&iter));

	for (unsigned i = 0; i < nr_snapids; i++) {
		k = bkey_try(bch2_btree_iter_prev_slot(&iter));

		if (!k.k || !k.k->p.offset) {
			return bch_err_throw(c, ENOSPC_snapshot_create);
		}

		struct bkey_i_snapshot *n = errptr_try(bch2_bkey_alloc(trans, &iter, 0, snapshot));

		n->v.flags	= 0;
		n->v.parent	= cpu_to_le32(parent);
		n->v.subvol	= cpu_to_le32(snapshot_subvols[i]);
		n->v.tree	= cpu_to_le32(tree);
		n->v.depth	= cpu_to_le32(depth);
		n->v.btime.lo	= cpu_to_le64(bch2_current_time(c));
		n->v.btime.hi	= 0;

		for (unsigned j = 0; j < ARRAY_SIZE(n->v.skip); j++)
			n->v.skip[j] = cpu_to_le32(bch2_snapshot_skiplist_get(c, parent));

		bubble_sort(n->v.skip, ARRAY_SIZE(n->v.skip), cmp_le32);
		SET_BCH_SNAPSHOT_SUBVOL(&n->v, true);

		try(__bch2_mark_snapshot(trans, BTREE_ID_snapshots, 0,
					 bkey_s_c_null, bkey_i_to_s_c(&n->k_i), 0));

		new_snapids[i]	= iter.pos.offset;
	}

	return 0;
}

/*
 * Create new snapshot IDs as children of an existing snapshot ID:
 */
static int bch2_snapshot_node_create_children(struct btree_trans *trans, u32 parent,
			      u32 *new_snapids,
			      u32 *snapshot_subvols,
			      unsigned nr_snapids)
{
	struct bkey_i_snapshot *n_parent =
		bch2_bkey_get_mut_typed(trans, BTREE_ID_snapshots, POS(0, parent), 0, snapshot);
	int ret = PTR_ERR_OR_ZERO(n_parent);
	if (unlikely(ret)) {
		if (bch2_err_matches(ret, ENOENT))
			bch_err(trans->c, "snapshot %u not found", parent);
		return ret;
	}

	if (n_parent->v.children[0] || n_parent->v.children[1]) {
		bch_err(trans->c, "Trying to add child snapshot nodes to parent that already has children");
		return -EINVAL;
	}

	ret = create_snapids(trans, parent, le32_to_cpu(n_parent->v.tree),
			     new_snapids, snapshot_subvols, nr_snapids);
	if (ret)
		return ret;

	n_parent->v.children[0] = cpu_to_le32(new_snapids[0]);
	n_parent->v.children[1] = cpu_to_le32(new_snapids[1]);
	n_parent->v.subvol = 0;
	SET_BCH_SNAPSHOT_SUBVOL(&n_parent->v, false);
	return 0;
}

/*
 * Create a snapshot node that is the root of a new tree:
 */
static int bch2_snapshot_node_create_tree(struct btree_trans *trans,
			      u32 *new_snapids,
			      u32 *snapshot_subvols,
			      unsigned nr_snapids)
{
	struct bkey_i_snapshot_tree *n_tree =
		errptr_try(__bch2_snapshot_tree_create(trans));

	try(create_snapids(trans, 0, n_tree->k.p.offset,
			   new_snapids, snapshot_subvols, nr_snapids));

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

static unsigned live_child(struct bch_fs *c, u32 start)
{
	struct snapshot_delete *d = &c->snapshot_delete;

	guard(rcu)();
	struct snapshot_table *t = rcu_dereference(c->snapshots);

	for (u32 id = bch2_snapshot_tree_next(t, start);
	     id && id != start;
	     id = bch2_snapshot_tree_next(t, id))
		if (bch2_snapshot_is_leaf(c, id) &&
		    !snapshot_list_has_id(&d->delete_leaves, id) &&
		    !interior_delete_has_id(&d->delete_interior, id))
			return id;

	return 0;
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
	struct snapshot_delete *d = &trans->c->snapshot_delete;

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
	struct snapshot_delete *d = &c->snapshot_delete;

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
	struct snapshot_delete *d = &c->snapshot_delete;

	for (d->pos.btree = 0; d->pos.btree < BTREE_ID_NR; d->pos.btree++) {
		struct disk_reservation res = { 0 };
		u64 prev_inum = 0;

		d->pos.pos = POS_MIN;

		if (!btree_type_has_snapshots(d->pos.btree))
			continue;

		int ret = for_each_btree_key_commit(trans, iter,
				d->pos.btree, POS_MIN,
				BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k,
				&res, NULL, BCH_TRANS_COMMIT_no_enospc, ({
			d->pos.pos = iter.pos;

			if (skip_unrelated_snapshot_tree(trans, &iter, &prev_inum))
				continue;

			delete_dead_snapshots_process_key(trans, &iter, k);
		}));

		bch2_disk_reservation_put(c, &res);

		if (ret)
			return ret;
	}

	return 0;
}

static int delete_dead_snapshot_keys_range(struct btree_trans *trans, enum btree_id btree,
					   struct bpos start, struct bpos end)
{
	struct bch_fs *c = trans->c;
	struct snapshot_delete *d = &c->snapshot_delete;
	struct disk_reservation res = { 0 };

	d->pos.btree	= btree;
	d->pos.pos	= POS_MIN;

	int ret = for_each_btree_key_max_commit(trans, iter,
			btree, start, end,
			BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k,
			&res, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		d->pos.pos = iter.pos;
		delete_dead_snapshots_process_key(trans, &iter, k);
	}));

	bch2_disk_reservation_put(c, &res);
	return ret;
}

static int delete_dead_snapshot_keys_v2(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	struct snapshot_delete *d = &c->snapshot_delete;
	struct disk_reservation res = { 0 };
	u64 prev_inum = 0;
	int ret = 0;

	struct btree_iter iter;
	bch2_trans_iter_init(trans, &iter, BTREE_ID_inodes, POS_MIN,
			     BTREE_ITER_prefetch|BTREE_ITER_all_snapshots);

	while (1) {
		struct bkey_s_c k;
		ret = lockrestart_do(trans,
				bkey_err(k = bch2_btree_iter_peek(&iter)));
		if (ret)
			break;

		if (!k.k)
			break;

		d->pos.btree	= iter.btree_id;
		d->pos.pos	= iter.pos;

		if (skip_unrelated_snapshot_tree(trans, &iter, &prev_inum))
			continue;

		if (snapshot_id_dying(d, k.k->p.snapshot)) {
			struct bpos start	= POS(k.k->p.offset, 0);
			struct bpos end		= POS(k.k->p.offset, U64_MAX);

			ret   = delete_dead_snapshot_keys_range(trans, BTREE_ID_extents, start, end) ?:
				delete_dead_snapshot_keys_range(trans, BTREE_ID_dirents, start, end) ?:
				delete_dead_snapshot_keys_range(trans, BTREE_ID_xattrs, start, end);
			if (ret)
				break;

			bch2_btree_iter_set_pos(&iter, POS(0, k.k->p.offset + 1));
		} else {
			bch2_btree_iter_advance(&iter);
		}
	}
	bch2_trans_iter_exit(&iter);

	if (ret)
		goto err;

	prev_inum = 0;
	ret = for_each_btree_key_commit(trans, iter,
			BTREE_ID_inodes, POS_MIN,
			BTREE_ITER_prefetch|BTREE_ITER_all_snapshots, k,
			&res, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		d->pos.btree	= iter.btree_id;
		d->pos.pos	= iter.pos;

		if (skip_unrelated_snapshot_tree(trans, &iter, &prev_inum))
			continue;

		delete_dead_snapshots_process_key(trans, &iter, k);
	}));
err:
	bch2_disk_reservation_put(c, &res);
	return ret;
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
	struct snapshot_delete *d = &c->snapshot_delete;
	struct bkey_s_c_snapshot s = bkey_s_c_to_snapshot(k);
	unsigned live_children = 0;
	int ret = 0;

	if (BCH_SNAPSHOT_SUBVOL(s.v))
		return 0;

	if (BCH_SNAPSHOT_DELETED(s.v))
		return 0;

	guard(mutex)(&d->progress_lock);
	for (unsigned i = 0; i < 2; i++) {
		u32 child = le32_to_cpu(s.v->children[i]);

		live_children += child &&
			!snapshot_list_has_id(&d->delete_leaves, child);
	}

	u32 tree = bch2_snapshot_tree(c, s.k->p.offset);

	if (live_children == 0) {
		ret =   snapshot_list_add_nodup(c, &d->deleting_from_trees, tree) ?:
			snapshot_list_add(c, &d->delete_leaves, s.k->p.offset);
	} else if (live_children == 1) {
		struct snapshot_interior_delete n = {
			.id		= s.k->p.offset,
			.live_child	= live_child(c, s.k->p.offset),
		};

		if (!n.live_child) {
			bch_err(c, "error finding live child of snapshot %u", n.id);
			ret = -EINVAL;
		} else {
			ret =   snapshot_list_add_nodup(c, &d->deleting_from_trees, tree) ?:
				darray_push(&d->delete_interior, n);
		}
	}

	return ret;
}

static inline u32 bch2_snapshot_nth_parent_skip(struct bch_fs *c, u32 id, u32 n,
						interior_delete_list *skip)
{
	guard(rcu)();
	struct snapshot_table *t = rcu_dereference(c->snapshots);

	while (interior_delete_has_id(skip, id))
		id = __bch2_snapshot_parent(t, id);

	while (n--) {
		do {
			id = __bch2_snapshot_parent(t, id);
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

static void bch2_snapshot_delete_nodes_to_text(struct printbuf *out, struct snapshot_delete *d)
{
	prt_printf(out, "deleting from trees");
	darray_for_each(d->deleting_from_trees, i)
		prt_printf(out, " %u", *i);

	prt_printf(out, "deleting leaves");
	darray_for_each(d->delete_leaves, i)
		prt_printf(out, " %u", *i);
	prt_newline(out);

	prt_printf(out, "interior");
	darray_for_each(d->delete_interior, i)
		prt_printf(out, " %u->%u", i->id, i->live_child);
	prt_newline(out);
}

int __bch2_delete_dead_snapshots(struct bch_fs *c)
{
	struct snapshot_delete *d = &c->snapshot_delete;
	int ret = 0;

	if (!mutex_trylock(&d->lock))
		return 0;

	if (!test_and_clear_bit(BCH_FS_need_delete_dead_snapshots, &c->flags)) {
		mutex_unlock(&d->lock);
		return 0;
	}

	CLASS(btree_trans, trans)(c);

	/*
	 * For every snapshot node: If we have no live children and it's not
	 * pointed to by a subvolume, delete it:
	 */
	d->running = true;
	d->pos = BBPOS_MIN;

	ret = for_each_btree_key(trans, iter, BTREE_ID_snapshots, POS_MIN, 0, k,
		check_should_delete_snapshot(trans, k));
	if (!bch2_err_matches(ret, EROFS))
		bch_err_msg(c, ret, "walking snapshots");
	if (ret)
		goto err;

	if (!d->delete_leaves.nr && !d->delete_interior.nr)
		goto err;

	{
		CLASS(printbuf, buf)();
		bch2_snapshot_delete_nodes_to_text(&buf, d);

		ret = commit_do(trans, NULL, NULL, 0, bch2_trans_log_msg(trans, &buf));
		if (ret)
			goto err;
	}

	ret = !bch2_request_incompat_feature(c, bcachefs_metadata_version_snapshot_deletion_v2)
		? delete_dead_snapshot_keys_v2(trans)
		: delete_dead_snapshot_keys_v1(trans);
	if (!bch2_err_matches(ret, EROFS))
		bch_err_msg(c, ret, "deleting keys from dying snapshots");
	if (ret)
		goto err;

	darray_for_each(d->delete_leaves, i) {
		ret = commit_do(trans, NULL, NULL, 0,
			bch2_snapshot_node_delete(trans, *i));
		if (!bch2_err_matches(ret, EROFS))
			bch_err_msg(c, ret, "deleting snapshot %u", *i);
		if (ret)
			goto err;
	}
	darray_for_each(d->delete_interior, i) {
		ret = commit_do(trans, NULL, NULL, 0,
			bch2_snapshot_node_set_no_keys(trans, i->id));
		if (!bch2_err_matches(ret, EROFS))
			bch_err_msg(c, ret, "deleting snapshot %u", i->id);
		if (ret)
			goto err;
	}
err:
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
	struct bch_fs *c = container_of(work, struct bch_fs, snapshot_delete.work);

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

	if (!queue_work(system_long_wq, &c->snapshot_delete.work))
		enumerated_ref_put(&c->writes, BCH_WRITE_REF_delete_dead_snapshots);
}

void bch2_snapshot_delete_status_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct snapshot_delete *d = &c->snapshot_delete;

	if (!d->running) {
		prt_str(out, "(not running)");
		return;
	}

	scoped_guard(mutex, &d->progress_lock) {
		bch2_snapshot_delete_nodes_to_text(out, d);
		bch2_bbpos_to_text(out, d->pos);
	}
}

int __bch2_key_has_snapshot_overwrites(struct btree_trans *trans,
				       enum btree_id id,
				       struct bpos pos)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c k;
	int ret;

	for_each_btree_key_reverse_norestart(trans, iter, id, bpos_predecessor(pos),
					     BTREE_ITER_not_extents|
					     BTREE_ITER_all_snapshots,
					     k, ret) {
		if (!bkey_eq(pos, k.k->p))
			break;

		if (bch2_snapshot_is_ancestor(c, k.k->p.snapshot, pos.snapshot))
			return 1;
	}

	return ret;
}

static int bch2_get_dead_interior_snapshots(struct btree_trans *trans, struct bkey_s_c k,
					    interior_delete_list *delete)
{
	struct bch_fs *c = trans->c;

	if (k.k->type == KEY_TYPE_snapshot &&
	    BCH_SNAPSHOT_NO_KEYS(bkey_s_c_to_snapshot(k).v)) {
		struct snapshot_interior_delete n = {
			.id		= k.k->p.offset,
			.live_child	= live_child(c, k.k->p.offset),
		};

		if (!n.live_child) {
			bch_err(c, "error finding live child of snapshot %u", n.id);
			return -EINVAL;
		}

		return darray_push(delete, n);
	}

	return 0;
}

int bch2_delete_dead_interior_snapshots(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	CLASS(interior_delete_list, delete)();

	try(for_each_btree_key(trans, iter, BTREE_ID_snapshots, POS_MAX, 0, k,
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
				bch2_snapshot_node_delete(trans, i->id));
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

static int bch2_check_snapshot_needs_deletion(struct btree_trans *trans, struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;

	if (k.k->type != KEY_TYPE_snapshot)
		return 0;

	struct bkey_s_c_snapshot s= bkey_s_c_to_snapshot(k);

	if (BCH_SNAPSHOT_NO_KEYS(s.v))
		c->recovery.passes_to_run |= BIT_ULL(BCH_RECOVERY_PASS_delete_dead_interior_snapshots);
	if (BCH_SNAPSHOT_WILL_DELETE(s.v) ||
	    interior_snapshot_needs_delete(s))
		set_bit(BCH_FS_need_delete_dead_snapshots, &c->flags);

	return 0;
}

int bch2_snapshots_read(struct bch_fs *c)
{
	/*
	 * It's important that we check if we need to reconstruct snapshots
	 * before going RW, so we mark that pass as required in the superblock -
	 * otherwise, we could end up deleting keys with missing snapshot nodes
	 * instead
	 */
	BUG_ON(!test_bit(BCH_FS_new_fs, &c->flags) &&
	       test_bit(BCH_FS_may_go_rw, &c->flags));

	/*
	 * Initializing the is_ancestor bitmaps requires ancestors to already be
	 * initialized - so mark in reverse:
	 */
	CLASS(btree_trans, trans)(c);
	int ret = for_each_btree_key_reverse(trans, iter, BTREE_ID_snapshots,
				   POS_MAX, 0, k,
			__bch2_mark_snapshot(trans, BTREE_ID_snapshots, 0, bkey_s_c_null, k, 0) ?:
			bch2_check_snapshot_needs_deletion(trans, k));
	bch_err_fn(c, ret);

	return ret;
}

void bch2_fs_snapshots_exit(struct bch_fs *c)
{
	kvfree(rcu_dereference_protected(c->snapshots, true));
}

void bch2_fs_snapshots_init_early(struct bch_fs *c)
{
	INIT_WORK(&c->snapshot_delete.work, bch2_delete_dead_snapshots_work);
	mutex_init(&c->snapshot_delete.lock);
	mutex_init(&c->snapshot_delete.progress_lock);
	mutex_init(&c->snapshots_unlinked_lock);
}
