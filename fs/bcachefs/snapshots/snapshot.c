// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "btree/update.h"

#include "init/error.h"
#include "init/passes.h"

#include "snapshots/snapshot.h"

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
			BTREE_ID_snapshot_trees, POS_MIN, POS(0, U32_MAX));
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
	return __bch2_snapshot_is_ancestor_early(rcu_dereference(c->snapshots.table), id, ancestor);
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
	struct snapshot_table *t = rcu_dereference(c->snapshots.table);

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

	old = rcu_dereference_protected(c->snapshots.table, true);
	if (old)
		memcpy(new->s, old->s, sizeof(old->s[0]) * old->nr);

	rcu_assign_pointer(c->snapshots.table, new);
	kvfree_rcu(old, rcu);

	return &rcu_dereference_protected(c->snapshots.table,
				lockdep_is_held(&c->snapshots.table_lock))->s[idx];
}

struct snapshot_t *bch2_snapshot_t_mut(struct bch_fs *c, u32 id)
{
	size_t idx = U32_MAX - id;
	struct snapshot_table *table =
		rcu_dereference_protected(c->snapshots.table,
				lockdep_is_held(&c->snapshots.table_lock));

	if (likely(table && idx < table->nr))
		return &table->s[idx];

	return __snapshot_t_mut(c, id);
}

void bch2_snapshot_to_text(struct printbuf *out, const struct bch_snapshot *s)
{
	if (BCH_SNAPSHOT_SUBVOL(s))
		prt_str(out, "subvol ");
	if (BCH_SNAPSHOT_WILL_DELETE(s))
		prt_str(out, "will_delete ");
	if (BCH_SNAPSHOT_DELETED(s))
		prt_str(out, "deleted ");
	if (BCH_SNAPSHOT_NO_KEYS(s))
		prt_str(out, "no_keys ");

	prt_printf(out, "parent %10u children %10u %10u subvol %u tree %u",
	       le32_to_cpu(s->parent),
	       le32_to_cpu(s->children[0]),
	       le32_to_cpu(s->children[1]),
	       le32_to_cpu(s->subvol),
	       le32_to_cpu(s->tree));

	prt_printf(out, " depth %u skiplist %u %u %u",
		   le32_to_cpu(s->depth),
		   le32_to_cpu(s->skip[0]),
		   le32_to_cpu(s->skip[1]),
		   le32_to_cpu(s->skip[2]));
}

void bch2_snapshot_key_to_text(struct printbuf *out, struct bch_fs *c,
			       struct bkey_s_c k)
{
	struct bch_snapshot snapshot;
	bkey_val_copy_pad(&snapshot, bkey_s_c_to_snapshot(k));
	bch2_snapshot_to_text(out, &snapshot);
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

	guard(mutex)(&c->snapshots.table_lock);

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

static int snapshot_get_print(struct printbuf *out, struct btree_trans *trans, u32 id)
{
	prt_printf(out, "%u \t", id);

	struct bch_snapshot s;
	int ret = lockrestart_do(trans, bch2_snapshot_lookup(trans, id, &s));
	if (ret) {
		prt_str(out, bch2_err_str(ret));
	} else {
		if (BCH_SNAPSHOT_SUBVOL(&s))
			prt_str(out, "subvol ");
		if (BCH_SNAPSHOT_WILL_DELETE(&s))
			prt_str(out, "will_delete ");
		if (BCH_SNAPSHOT_DELETED(&s))
			prt_str(out, "deleted ");
		if (BCH_SNAPSHOT_NO_KEYS(&s))
			prt_str(out, "no_keys ");
		prt_printf(out, "subvol %u", le32_to_cpu(s.subvol));
	}

	prt_newline(out);
	return 0;
}

static unsigned snapshot_tree_max_depth(struct bch_fs *c, u32 start)
{
	unsigned depth = 0, max_depth = 0;

	guard(rcu)();
	struct snapshot_table *t = rcu_dereference(c->snapshots.table);

	__for_each_snapshot_child(c, t, start, &depth, id)
		max_depth = max(depth, max_depth);
	return max_depth;
}

int bch2_snapshot_tree_keys_to_text(struct printbuf *out, struct btree_trans *trans, u32 start)
{
	printbuf_tabstop_push(out, out->indent + 12 + 2 * snapshot_tree_max_depth(trans->c, start));

	unsigned depth = 0, prev_depth = 0;
	for_each_snapshot_child(trans->c, start, &depth, id) {
		int d = depth - prev_depth;
		if (d > 0)
			printbuf_indent_add(out, d * 2);
		else
			printbuf_indent_sub(out, -d * 2);
		prev_depth = depth;

		try(snapshot_get_print(out, trans, id));
	}

	printbuf_indent_sub(out, prev_depth * 2);

	return 0;
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

u32 __bch2_snapshot_tree_next(struct bch_fs *c, struct snapshot_table *t, u32 id, unsigned *depth)
{
	int _depth;
	if (!depth)
		depth = &_depth;

	u32 n = bch2_snapshot_left_child(t, id);
	if (n) {
		(*depth)++;
		return n;
	}

	u32 parent;
	while ((parent = __bch2_snapshot_parent(c, t, id))) {
		(*depth)--;
		n = bch2_snapshot_right_child(t, parent);
		if (n && n != id) {
			(*depth)++;
			return n;
		}
		id = parent;
	}

	return 0;
}

u32 bch2_snapshot_tree_next(struct bch_fs *c, u32 id, unsigned *depth)
{
	guard(rcu)();
	return __bch2_snapshot_tree_next(c, rcu_dereference(c->snapshots.table), id, depth);
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
	u32 nr_empty_interior = 0;
	try(for_each_btree_key_reverse(trans, iter, BTREE_ID_snapshots, POS_MAX, 0, k,
		__bch2_mark_snapshot(trans, BTREE_ID_snapshots, 0, bkey_s_c_null, k, 0) ?:
		bch2_check_snapshot_needs_deletion(trans, k, &nr_empty_interior)));

	if (nr_empty_interior) {
		CLASS(bch_log_msg_level, msg)(c, LOGLEVEL_notice);

		prt_printf(&msg.m, "Found %u empty interior snapshot nodes\n", nr_empty_interior);
		try(bch2_run_explicit_recovery_pass(c, &msg.m,
				BCH_RECOVERY_PASS_delete_dead_interior_snapshots, 0));
	}

	return 0;
}

void bch2_fs_snapshots_exit(struct bch_fs *c)
{
	kvfree(rcu_dereference_protected(c->snapshots.table, true));
}

void bch2_fs_snapshots_init_early(struct bch_fs *c)
{
	mutex_init(&c->snapshots.table_lock);
	init_rwsem(&c->snapshots.create_lock);

	INIT_WORK(&c->snapshots.delete.work, bch2_delete_dead_snapshots_work);
	mutex_init(&c->snapshots.delete.lock);
	mutex_init(&c->snapshots.delete.progress_lock);

	mutex_init(&c->snapshots.unlinked_lock);
}
