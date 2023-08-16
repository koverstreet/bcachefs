// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_key_cache.h"
#include "btree_update.h"
#include "errcode.h"
#include "error.h"
#include "fs.h"
#include "snapshot.h"

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

int bch2_snapshot_tree_invalid(const struct bch_fs *c, struct bkey_s_c k,
			       enum bkey_invalid_flags flags,
			       struct printbuf *err)
{
	if (bkey_gt(k.k->p, POS(0, U32_MAX)) ||
	    bkey_lt(k.k->p, POS(0, 1))) {
		prt_printf(err, "bad pos");
		return -BCH_ERR_invalid_bkey;
	}

	return 0;
}

int bch2_snapshot_tree_lookup(struct btree_trans *trans, u32 id,
			      struct bch_snapshot_tree *s)
{
	int ret = bch2_bkey_get_val_typed(trans, BTREE_ID_snapshot_trees, POS(0, id),
					  BTREE_ITER_WITH_UPDATES, snapshot_tree, s);

	if (bch2_err_matches(ret, ENOENT))
		ret = -BCH_ERR_ENOENT_snapshot_tree;
	return ret;
}

struct bkey_i_snapshot_tree *
__bch2_snapshot_tree_create(struct btree_trans *trans)
{
	struct btree_iter iter;
	int ret = bch2_bkey_get_empty_slot(trans, &iter,
			BTREE_ID_snapshot_trees, POS(0, U32_MAX));
	struct bkey_i_snapshot_tree *s_t;

	if (ret == -BCH_ERR_ENOSPC_btree_slot)
		ret = -BCH_ERR_ENOSPC_snapshot_tree;
	if (ret)
		return ERR_PTR(ret);

	s_t = bch2_bkey_alloc(trans, &iter, 0, snapshot_tree);
	ret = PTR_ERR_OR_ZERO(s_t);
	bch2_trans_iter_exit(trans, &iter);
	return ret ? ERR_PTR(ret) : s_t;
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

/* Snapshot nodes: */

static inline u32 get_ancestor_below(struct snapshot_table *t, u32 id, u32 ancestor)
{
	const struct snapshot_t *s = __snapshot_t(t, id);

	if (s->skip[2] <= ancestor)
		return s->skip[2];
	if (s->skip[1] <= ancestor)
		return s->skip[1];
	if (s->skip[0] <= ancestor)
		return s->skip[0];
	return s->parent;
}

bool __bch2_snapshot_is_ancestor(struct bch_fs *c, u32 id, u32 ancestor)
{
	struct snapshot_table *t;
	bool ret;

	EBUG_ON(c->curr_recovery_pass <= BCH_RECOVERY_PASS_check_snapshots);

	rcu_read_lock();
	t = rcu_dereference(c->snapshots);

	while (id && id < ancestor - IS_ANCESTOR_BITMAP)
		id = get_ancestor_below(t, id, ancestor);

	ret = id && id < ancestor
		? test_bit(ancestor - id - 1, __snapshot_t(t, id)->is_ancestor)
		: id == ancestor;
	rcu_read_unlock();

	return ret;
}

static bool bch2_snapshot_is_ancestor_early(struct bch_fs *c, u32 id, u32 ancestor)
{
	struct snapshot_table *t;

	rcu_read_lock();
	t = rcu_dereference(c->snapshots);

	while (id && id < ancestor)
		id = __snapshot_t(t, id)->parent;
	rcu_read_unlock();

	return id == ancestor;
}

static noinline struct snapshot_t *__snapshot_t_mut(struct bch_fs *c, u32 id)
{
	size_t idx = U32_MAX - id;
	size_t new_size;
	struct snapshot_table *new, *old;

	new_size = max(16UL, roundup_pow_of_two(idx + 1));

	new = kvzalloc(struct_size(new, s, new_size), GFP_KERNEL);
	if (!new)
		return NULL;

	old = rcu_dereference_protected(c->snapshots, true);
	if (old)
		memcpy(new->s,
		       rcu_dereference_protected(c->snapshots, true)->s,
		       sizeof(new->s[0]) * c->snapshot_table_size);

	rcu_assign_pointer(c->snapshots, new);
	c->snapshot_table_size = new_size;
	if (old)
		kvfree_rcu(old);

	return &rcu_dereference_protected(c->snapshots, true)->s[idx];
}

static inline struct snapshot_t *snapshot_t_mut(struct bch_fs *c, u32 id)
{
	size_t idx = U32_MAX - id;

	lockdep_assert_held(&c->snapshot_table_lock);

	if (likely(idx < c->snapshot_table_size))
		return &rcu_dereference_protected(c->snapshots, true)->s[idx];

	return __snapshot_t_mut(c, id);
}

void bch2_snapshot_to_text(struct printbuf *out, struct bch_fs *c,
			   struct bkey_s_c k)
{
	struct bkey_s_c_snapshot s = bkey_s_c_to_snapshot(k);

	prt_printf(out, "is_subvol %llu deleted %llu parent %10u children %10u %10u subvol %u tree %u",
	       BCH_SNAPSHOT_SUBVOL(s.v),
	       BCH_SNAPSHOT_DELETED(s.v),
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

int bch2_snapshot_invalid(const struct bch_fs *c, struct bkey_s_c k,
			  enum bkey_invalid_flags flags,
			  struct printbuf *err)
{
	struct bkey_s_c_snapshot s;
	u32 i, id;

	if (bkey_gt(k.k->p, POS(0, U32_MAX)) ||
	    bkey_lt(k.k->p, POS(0, 1))) {
		prt_printf(err, "bad pos");
		return -BCH_ERR_invalid_bkey;
	}

	s = bkey_s_c_to_snapshot(k);

	id = le32_to_cpu(s.v->parent);
	if (id && id <= k.k->p.offset) {
		prt_printf(err, "bad parent node (%u <= %llu)",
		       id, k.k->p.offset);
		return -BCH_ERR_invalid_bkey;
	}

	if (le32_to_cpu(s.v->children[0]) < le32_to_cpu(s.v->children[1])) {
		prt_printf(err, "children not normalized");
		return -BCH_ERR_invalid_bkey;
	}

	if (s.v->children[0] &&
	    s.v->children[0] == s.v->children[1]) {
		prt_printf(err, "duplicate child nodes");
		return -BCH_ERR_invalid_bkey;
	}

	for (i = 0; i < 2; i++) {
		id = le32_to_cpu(s.v->children[i]);

		if (id >= k.k->p.offset) {
			prt_printf(err, "bad child node (%u >= %llu)",
			       id, k.k->p.offset);
			return -BCH_ERR_invalid_bkey;
		}
	}

	if (bkey_val_bytes(k.k) > offsetof(struct bch_snapshot, skip)) {
		if (le32_to_cpu(s.v->skip[0]) > le32_to_cpu(s.v->skip[1]) ||
		    le32_to_cpu(s.v->skip[1]) > le32_to_cpu(s.v->skip[2])) {
			prt_printf(err, "skiplist not normalized");
			return -BCH_ERR_invalid_bkey;
		}

		for (i = 0; i < ARRAY_SIZE(s.v->skip); i++) {
			id = le32_to_cpu(s.v->skip[i]);

			if (!id != !s.v->parent ||
			    (s.v->parent &&
			     id <= k.k->p.offset)) {
				prt_printf(err, "bad skiplist node %u)", id);
				return -BCH_ERR_invalid_bkey;
			}
		}
	}

	return 0;
}

int bch2_mark_snapshot(struct btree_trans *trans,
		       enum btree_id btree, unsigned level,
		       struct bkey_s_c old, struct bkey_s_c new,
		       unsigned flags)
{
	struct bch_fs *c = trans->c;
	struct snapshot_t *t;
	u32 id = new.k->p.offset;
	int ret = 0;

	mutex_lock(&c->snapshot_table_lock);

	t = snapshot_t_mut(c, id);
	if (!t) {
		ret = -BCH_ERR_ENOMEM_mark_snapshot;
		goto err;
	}

	if (new.k->type == KEY_TYPE_snapshot) {
		struct bkey_s_c_snapshot s = bkey_s_c_to_snapshot(new);
		u32 parent = id;

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

		while ((parent = bch2_snapshot_parent_early(c, parent)) &&
		       parent - id - 1 < IS_ANCESTOR_BITMAP)
			__set_bit(parent - id - 1, t->is_ancestor);

		if (BCH_SNAPSHOT_DELETED(s.v)) {
			set_bit(BCH_FS_HAVE_DELETED_SNAPSHOTS, &c->flags);
			c->recovery_passes_explicit |= BIT_ULL(BCH_RECOVERY_PASS_delete_dead_snapshots);
		}
	} else {
		memset(t, 0, sizeof(*t));
	}
err:
	mutex_unlock(&c->snapshot_table_lock);
	return ret;
}

int bch2_snapshot_lookup(struct btree_trans *trans, u32 id,
			 struct bch_snapshot *s)
{
	return bch2_bkey_get_val_typed(trans, BTREE_ID_snapshots, POS(0, id),
				       BTREE_ITER_WITH_UPDATES, snapshot, s);
}

int bch2_snapshot_live(struct btree_trans *trans, u32 id)
{
	struct bch_snapshot v;
	int ret;

	if (!id)
		return 0;

	ret = bch2_snapshot_lookup(trans, id, &v);
	if (bch2_err_matches(ret, ENOENT))
		bch_err(trans->c, "snapshot node %u not found", id);
	if (ret)
		return ret;

	return !BCH_SNAPSHOT_DELETED(&v);
}

/*
 * If @k is a snapshot with just one live child, it's part of a linear chain,
 * which we consider to be an equivalence class: and then after snapshot
 * deletion cleanup, there should only be a single key at a given position in
 * this equivalence class.
 *
 * This sets the equivalence class of @k to be the child's equivalence class, if
 * it's part of such a linear chain: this correctly sets equivalence classes on
 * startup if we run leaf to root (i.e. in natural key order).
 */
int bch2_snapshot_set_equiv(struct btree_trans *trans, struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	unsigned i, nr_live = 0, live_idx = 0;
	struct bkey_s_c_snapshot snap;
	u32 id = k.k->p.offset, child[2];

	if (k.k->type != KEY_TYPE_snapshot)
		return 0;

	snap = bkey_s_c_to_snapshot(k);

	child[0] = le32_to_cpu(snap.v->children[0]);
	child[1] = le32_to_cpu(snap.v->children[1]);

	for (i = 0; i < 2; i++) {
		int ret = bch2_snapshot_live(trans, child[i]);

		if (ret < 0)
			return ret;

		if (ret)
			live_idx = i;
		nr_live += ret;
	}

	mutex_lock(&c->snapshot_table_lock);

	snapshot_t_mut(c, id)->equiv = nr_live == 1
		? snapshot_t_mut(c, child[live_idx])->equiv
		: id;

	mutex_unlock(&c->snapshot_table_lock);

	return 0;
}

/* fsck: */

static u32 bch2_snapshot_child(struct bch_fs *c, u32 id, unsigned child)
{
	return snapshot_t(c, id)->children[child];
}

static u32 bch2_snapshot_left_child(struct bch_fs *c, u32 id)
{
	return bch2_snapshot_child(c, id, 0);
}

static u32 bch2_snapshot_right_child(struct bch_fs *c, u32 id)
{
	return bch2_snapshot_child(c, id, 1);
}

static u32 bch2_snapshot_tree_next(struct bch_fs *c, u32 id)
{
	u32 n, parent;

	n = bch2_snapshot_left_child(c, id);
	if (n)
		return n;

	while ((parent = bch2_snapshot_parent(c, id))) {
		n = bch2_snapshot_right_child(c, parent);
		if (n && n != id)
			return n;
		id = parent;
	}

	return 0;
}

static u32 bch2_snapshot_tree_oldest_subvol(struct bch_fs *c, u32 snapshot_root)
{
	u32 id = snapshot_root;
	u32 subvol = 0, s;

	while (id) {
		s = snapshot_t(c, id)->subvol;

		if (s && (!subvol || s < subvol))
			subvol = s;

		id = bch2_snapshot_tree_next(c, id);
	}

	return subvol;
}

static int bch2_snapshot_tree_master_subvol(struct btree_trans *trans,
					    u32 snapshot_root, u32 *subvol_id)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_subvolume s;
	bool found = false;
	int ret;

	for_each_btree_key_norestart(trans, iter, BTREE_ID_subvolumes, POS_MIN,
				     0, k, ret) {
		if (k.k->type != KEY_TYPE_subvolume)
			continue;

		s = bkey_s_c_to_subvolume(k);
		if (!bch2_snapshot_is_ancestor(c, le32_to_cpu(s.v->snapshot), snapshot_root))
			continue;
		if (!BCH_SUBVOLUME_SNAP(s.v)) {
			*subvol_id = s.k->p.offset;
			found = true;
			break;
		}
	}

	bch2_trans_iter_exit(trans, &iter);

	if (!ret && !found) {
		struct bkey_i_subvolume *s;

		*subvol_id = bch2_snapshot_tree_oldest_subvol(c, snapshot_root);

		s = bch2_bkey_get_mut_typed(trans, &iter,
					    BTREE_ID_subvolumes, POS(0, *subvol_id),
					    0, subvolume);
		ret = PTR_ERR_OR_ZERO(s);
		if (ret)
			return ret;

		SET_BCH_SUBVOLUME_SNAP(&s->v, false);
	}

	return ret;
}

static int check_snapshot_tree(struct btree_trans *trans,
			       struct btree_iter *iter,
			       struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c_snapshot_tree st;
	struct bch_snapshot s;
	struct bch_subvolume subvol;
	struct printbuf buf = PRINTBUF;
	u32 root_id;
	int ret;

	if (k.k->type != KEY_TYPE_snapshot_tree)
		return 0;

	st = bkey_s_c_to_snapshot_tree(k);
	root_id = le32_to_cpu(st.v->root_snapshot);

	ret = bch2_snapshot_lookup(trans, root_id, &s);
	if (ret && !bch2_err_matches(ret, ENOENT))
		goto err;

	if (fsck_err_on(ret ||
			root_id != bch2_snapshot_root(c, root_id) ||
			st.k->p.offset != le32_to_cpu(s.tree),
			c,
			"snapshot tree points to missing/incorrect snapshot:\n  %s",
			(bch2_bkey_val_to_text(&buf, c, st.s_c), buf.buf))) {
		ret = bch2_btree_delete_at(trans, iter, 0);
		goto err;
	}

	ret = bch2_subvolume_get(trans, le32_to_cpu(st.v->master_subvol),
				 false, 0, &subvol);
	if (ret && !bch2_err_matches(ret, ENOENT))
		goto err;

	if (fsck_err_on(ret, c,
			"snapshot tree points to missing subvolume:\n  %s",
			(printbuf_reset(&buf),
			 bch2_bkey_val_to_text(&buf, c, st.s_c), buf.buf)) ||
	    fsck_err_on(!bch2_snapshot_is_ancestor_early(c,
						le32_to_cpu(subvol.snapshot),
						root_id), c,
			"snapshot tree points to subvolume that does not point to snapshot in this tree:\n  %s",
			(printbuf_reset(&buf),
			 bch2_bkey_val_to_text(&buf, c, st.s_c), buf.buf)) ||
	    fsck_err_on(BCH_SUBVOLUME_SNAP(&subvol), c,
			"snapshot tree points to snapshot subvolume:\n  %s",
			(printbuf_reset(&buf),
			 bch2_bkey_val_to_text(&buf, c, st.s_c), buf.buf))) {
		struct bkey_i_snapshot_tree *u;
		u32 subvol_id;

		ret = bch2_snapshot_tree_master_subvol(trans, root_id, &subvol_id);
		if (ret)
			goto err;

		u = bch2_bkey_make_mut_typed(trans, iter, &k, 0, snapshot_tree);
		ret = PTR_ERR_OR_ZERO(u);
		if (ret)
			goto err;

		u->v.master_subvol = cpu_to_le32(subvol_id);
		st = snapshot_tree_i_to_s_c(u);
	}
err:
fsck_err:
	printbuf_exit(&buf);
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
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	ret = bch2_trans_run(c,
		for_each_btree_key_commit(&trans, iter,
			BTREE_ID_snapshot_trees, POS_MIN,
			BTREE_ITER_PREFETCH, k,
			NULL, NULL, BTREE_INSERT_LAZY_RW|BTREE_INSERT_NOFAIL,
		check_snapshot_tree(&trans, &iter, k)));

	if (ret)
		bch_err(c, "error %i checking snapshot trees", ret);
	return ret;
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
	const struct snapshot_t *s;

	if (!id)
		return 0;

	rcu_read_lock();
	s = snapshot_t(c, id);
	if (s->parent)
		id = bch2_snapshot_nth_parent(c, id, get_random_u32_below(s->depth));
	rcu_read_unlock();

	return id;
}

static int snapshot_skiplist_good(struct btree_trans *trans, struct bch_snapshot s)
{
	struct bch_snapshot a;
	unsigned i;
	int ret;

	for (i = 0; i < 3; i++) {
		if (!s.parent != !s.skip[i])
			return false;

		if (!s.parent)
			continue;

		ret = bch2_snapshot_lookup(trans, le32_to_cpu(s.skip[i]), &a);
		if (bch2_err_matches(ret, ENOENT))
			return false;
		if (ret)
			return ret;

		if (a.tree != s.tree)
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
	struct btree_iter root_iter;
	struct bch_snapshot_tree s_t;
	struct bkey_s_c_snapshot root;
	struct bkey_i_snapshot *u;
	u32 root_id = bch2_snapshot_root(c, k.k->p.offset), tree_id;
	int ret;

	root = bch2_bkey_get_iter_typed(trans, &root_iter,
			       BTREE_ID_snapshots, POS(0, root_id),
			       BTREE_ITER_WITH_UPDATES, snapshot);
	ret = bkey_err(root);
	if (ret)
		goto err;

	tree_id = le32_to_cpu(root.v->tree);

	ret = bch2_snapshot_tree_lookup(trans, tree_id, &s_t);
	if (ret && !bch2_err_matches(ret, ENOENT))
		return ret;

	if (ret || le32_to_cpu(s_t.root_snapshot) != root_id) {
		u = bch2_bkey_make_mut_typed(trans, &root_iter, &root.s_c, 0, snapshot);
		ret =   PTR_ERR_OR_ZERO(u) ?:
			bch2_snapshot_tree_create(trans, root_id,
				bch2_snapshot_tree_oldest_subvol(c, root_id),
				&tree_id);
		if (ret)
			goto err;

		u->v.tree = cpu_to_le32(tree_id);
		if (k.k->p.offset == root_id)
			*s = u->v;
	}

	if (k.k->p.offset != root_id) {
		u = bch2_bkey_make_mut_typed(trans, iter, &k, 0, snapshot);
		ret = PTR_ERR_OR_ZERO(u);
		if (ret)
			goto err;

		u->v.tree = cpu_to_le32(tree_id);
		*s = u->v;
	}
err:
	bch2_trans_iter_exit(trans, &root_iter);
	return ret;
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
	struct printbuf buf = PRINTBUF;
	bool should_have_subvol;
	u32 i, id;
	int ret = 0;

	if (k.k->type != KEY_TYPE_snapshot)
		return 0;

	memset(&s, 0, sizeof(s));
	memcpy(&s, k.v, bkey_val_bytes(k.k));

	id = le32_to_cpu(s.parent);
	if (id) {
		ret = bch2_snapshot_lookup(trans, id, &v);
		if (bch2_err_matches(ret, ENOENT))
			bch_err(c, "snapshot with nonexistent parent:\n  %s",
				(bch2_bkey_val_to_text(&buf, c, k), buf.buf));
		if (ret)
			goto err;

		if (le32_to_cpu(v.children[0]) != k.k->p.offset &&
		    le32_to_cpu(v.children[1]) != k.k->p.offset) {
			bch_err(c, "snapshot parent %u missing pointer to child %llu",
				id, k.k->p.offset);
			ret = -EINVAL;
			goto err;
		}
	}

	for (i = 0; i < 2 && s.children[i]; i++) {
		id = le32_to_cpu(s.children[i]);

		ret = bch2_snapshot_lookup(trans, id, &v);
		if (bch2_err_matches(ret, ENOENT))
			bch_err(c, "snapshot node %llu has nonexistent child %u",
				k.k->p.offset, id);
		if (ret)
			goto err;

		if (le32_to_cpu(v.parent) != k.k->p.offset) {
			bch_err(c, "snapshot child %u has wrong parent (got %u should be %llu)",
				id, le32_to_cpu(v.parent), k.k->p.offset);
			ret = -EINVAL;
			goto err;
		}
	}

	should_have_subvol = BCH_SNAPSHOT_SUBVOL(&s) &&
		!BCH_SNAPSHOT_DELETED(&s);

	if (should_have_subvol) {
		id = le32_to_cpu(s.subvol);
		ret = bch2_subvolume_get(trans, id, 0, false, &subvol);
		if (bch2_err_matches(ret, ENOENT))
			bch_err(c, "snapshot points to nonexistent subvolume:\n  %s",
				(bch2_bkey_val_to_text(&buf, c, k), buf.buf));
		if (ret)
			goto err;

		if (BCH_SNAPSHOT_SUBVOL(&s) != (le32_to_cpu(subvol.snapshot) == k.k->p.offset)) {
			bch_err(c, "snapshot node %llu has wrong BCH_SNAPSHOT_SUBVOL",
				k.k->p.offset);
			ret = -EINVAL;
			goto err;
		}
	} else {
		if (fsck_err_on(s.subvol, c, "snapshot should not point to subvol:\n  %s",
				(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
			u = bch2_bkey_make_mut_typed(trans, iter, &k, 0, snapshot);
			ret = PTR_ERR_OR_ZERO(u);
			if (ret)
				goto err;

			u->v.subvol = 0;
			s = u->v;
		}
	}

	ret = snapshot_tree_ptr_good(trans, k.k->p.offset, le32_to_cpu(s.tree));
	if (ret < 0)
		goto err;

	if (fsck_err_on(!ret, c, "snapshot points to missing/incorrect tree:\n  %s",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
		ret = snapshot_tree_ptr_repair(trans, iter, k, &s);
		if (ret)
			goto err;
	}
	ret = 0;

	real_depth = bch2_snapshot_depth(c, parent_id);

	if (le32_to_cpu(s.depth) != real_depth &&
	    (c->sb.version_upgrade_complete < bcachefs_metadata_version_snapshot_skiplists ||
	     fsck_err(c, "snapshot with incorrect depth field, should be %u:\n  %s",
		      real_depth, (bch2_bkey_val_to_text(&buf, c, k), buf.buf)))) {
		u = bch2_bkey_make_mut_typed(trans, iter, &k, 0, snapshot);
		ret = PTR_ERR_OR_ZERO(u);
		if (ret)
			goto err;

		u->v.depth = cpu_to_le32(real_depth);
		s = u->v;
	}

	ret = snapshot_skiplist_good(trans, s);
	if (ret < 0)
		goto err;

	if (!ret &&
	    (c->sb.version_upgrade_complete < bcachefs_metadata_version_snapshot_skiplists ||
	     fsck_err(c, "snapshot with bad skiplist field:\n  %s",
		      (bch2_bkey_val_to_text(&buf, c, k), buf.buf)))) {
		u = bch2_bkey_make_mut_typed(trans, iter, &k, 0, snapshot);
		ret = PTR_ERR_OR_ZERO(u);
		if (ret)
			goto err;

		for (i = 0; i < ARRAY_SIZE(u->v.skip); i++)
			u->v.skip[i] = cpu_to_le32(bch2_snapshot_skiplist_get(c, parent_id));

		bubble_sort(u->v.skip, ARRAY_SIZE(u->v.skip), cmp_le32);
		s = u->v;
	}
	ret = 0;
err:
fsck_err:
	printbuf_exit(&buf);
	return ret;
}

int bch2_check_snapshots(struct bch_fs *c)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	/*
	 * We iterate backwards as checking/fixing the depth field requires that
	 * the parent's depth already be correct:
	 */
	ret = bch2_trans_run(c,
		for_each_btree_key_reverse_commit(&trans, iter,
			BTREE_ID_snapshots, POS_MAX,
			BTREE_ITER_PREFETCH, k,
			NULL, NULL, BTREE_INSERT_LAZY_RW|BTREE_INSERT_NOFAIL,
		check_snapshot(&trans, &iter, k)));
	if (ret)
		bch_err_fn(c, ret);
	return ret;
}

int bch2_snapshots_read(struct bch_fs *c)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	ret = bch2_trans_run(c,
		for_each_btree_key2(&trans, iter, BTREE_ID_snapshots,
			   POS_MIN, 0, k,
			bch2_mark_snapshot(&trans, BTREE_ID_snapshots, 0, bkey_s_c_null, k, 0) ?:
			bch2_snapshot_set_equiv(&trans, k)));
	if (ret)
		bch_err_fn(c, ret);
	return ret;
}

void bch2_fs_snapshots_exit(struct bch_fs *c)
{
	kfree(rcu_dereference_protected(c->snapshots, true));
}
