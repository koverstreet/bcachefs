// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_key_cache.h"
#include "btree_update.h"
#include "error.h"
#include "fs.h"
#include "subvolume.h"

/* Snapshot tree: */

static void bch2_delete_dead_snapshots_work(struct work_struct *);
static void bch2_delete_dead_snapshots(struct bch_fs *);

void bch2_snapshot_to_text(struct printbuf *out, struct bch_fs *c,
			   struct bkey_s_c k)
{
	struct bkey_s_c_snapshot s = bkey_s_c_to_snapshot(k);

	pr_buf(out, "is_subvol %llu deleted %llu parent %u children %u %u subvol %u",
	       BCH_SNAPSHOT_SUBVOL(s.v),
	       BCH_SNAPSHOT_DELETED(s.v),
	       le32_to_cpu(s.v->parent),
	       le32_to_cpu(s.v->children[0]),
	       le32_to_cpu(s.v->children[1]),
	       le32_to_cpu(s.v->subvol));
}

int bch2_snapshot_invalid(const struct bch_fs *c, struct bkey_s_c k,
			  struct printbuf *err)
{
	struct bkey_s_c_snapshot s;
	u32 i, id;

	if (bkey_cmp(k.k->p, POS(0, U32_MAX)) > 0 ||
	    bkey_cmp(k.k->p, POS(0, 1)) < 0) {
		pr_buf(err, "bad pos");
		return -EINVAL;
	}

	if (bkey_val_bytes(k.k) != sizeof(struct bch_snapshot)) {
		pr_buf(err, "bad val size (%zu != %zu)",
		       bkey_val_bytes(k.k), sizeof(struct bch_snapshot));
		return -EINVAL;
	}

	s = bkey_s_c_to_snapshot(k);

	id = le32_to_cpu(s.v->parent);
	if (id && id <= k.k->p.offset) {
		pr_buf(err, "bad parent node (%u <= %llu)",
		       id, k.k->p.offset);
		return -EINVAL;
	}

	if (le32_to_cpu(s.v->children[0]) < le32_to_cpu(s.v->children[1])) {
		pr_buf(err, "children not normalized");
		return -EINVAL;
	}

	if (s.v->children[0] &&
	    s.v->children[0] == s.v->children[1]) {
		pr_buf(err, "duplicate child nodes");
		return -EINVAL;
	}

	for (i = 0; i < 2; i++) {
		id = le32_to_cpu(s.v->children[i]);

		if (id >= k.k->p.offset) {
			pr_buf(err, "bad child node (%u >= %llu)",
			       id, k.k->p.offset);
			return -EINVAL;
		}
	}

	return 0;
}

int bch2_mark_snapshot(struct btree_trans *trans,
		       struct bkey_s_c old, struct bkey_s_c new,
		       unsigned flags)
{
	struct bch_fs *c = trans->c;
	struct snapshot_t *t;

	t = genradix_ptr_alloc(&c->snapshots,
			       U32_MAX - new.k->p.offset,
			       GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	if (new.k->type == KEY_TYPE_snapshot) {
		struct bkey_s_c_snapshot s = bkey_s_c_to_snapshot(new);

		t->parent	= le32_to_cpu(s.v->parent);
		t->children[0]	= le32_to_cpu(s.v->children[0]);
		t->children[1]	= le32_to_cpu(s.v->children[1]);
		t->subvol	= BCH_SNAPSHOT_SUBVOL(s.v) ? le32_to_cpu(s.v->subvol) : 0;
	} else {
		t->parent	= 0;
		t->children[0]	= 0;
		t->children[1]	= 0;
		t->subvol	= 0;
	}

	return 0;
}

static int snapshot_lookup(struct btree_trans *trans, u32 id,
			   struct bch_snapshot *s)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	bch2_trans_iter_init(trans, &iter, BTREE_ID_snapshots, POS(0, id),
			     BTREE_ITER_WITH_UPDATES);
	k = bch2_btree_iter_peek_slot(&iter);
	ret = bkey_err(k) ?: k.k->type == KEY_TYPE_snapshot ? 0 : -ENOENT;

	if (!ret)
		*s = *bkey_s_c_to_snapshot(k).v;

	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static int snapshot_live(struct btree_trans *trans, u32 id)
{
	struct bch_snapshot v;
	int ret;

	if (!id)
		return 0;

	ret = lockrestart_do(trans, snapshot_lookup(trans, id, &v));
	if (ret == -ENOENT)
		bch_err(trans->c, "snapshot node %u not found", id);
	if (ret)
		return ret;

	return !BCH_SNAPSHOT_DELETED(&v);
}

static int bch2_snapshots_set_equiv(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_snapshot snap;
	unsigned i;
	int ret;

	for_each_btree_key(trans, iter, BTREE_ID_snapshots,
			   POS_MIN, 0, k, ret) {
		u32 id = k.k->p.offset, child[2];
		unsigned nr_live = 0, live_idx = 0;

		if (k.k->type != KEY_TYPE_snapshot)
			continue;

		snap = bkey_s_c_to_snapshot(k);
		child[0] = le32_to_cpu(snap.v->children[0]);
		child[1] = le32_to_cpu(snap.v->children[1]);

		for (i = 0; i < 2; i++) {
			ret = snapshot_live(trans, child[i]);
			if (ret < 0)
				goto err;

			if (ret)
				live_idx = i;
			nr_live += ret;
		}

		snapshot_t(c, id)->equiv = nr_live == 1
			? snapshot_t(c, child[live_idx])->equiv
			: id;
	}
err:
	bch2_trans_iter_exit(trans, &iter);

	if (ret)
		bch_err(c, "error walking snapshots: %i", ret);

	return ret;
}

/* fsck: */
static int bch2_snapshot_check(struct btree_trans *trans,
			       struct bkey_s_c_snapshot s)
{
	struct bch_subvolume subvol;
	struct bch_snapshot v;
	u32 i, id;
	int ret;

	id = le32_to_cpu(s.v->subvol);
	ret = lockrestart_do(trans, bch2_subvolume_get(trans, id, 0, false, &subvol));
	if (ret == -ENOENT)
		bch_err(trans->c, "snapshot node %llu has nonexistent subvolume %u",
			s.k->p.offset, id);
	if (ret)
		return ret;

	if (BCH_SNAPSHOT_SUBVOL(s.v) != (le32_to_cpu(subvol.snapshot) == s.k->p.offset)) {
		bch_err(trans->c, "snapshot node %llu has wrong BCH_SNAPSHOT_SUBVOL",
			s.k->p.offset);
		return -EINVAL;
	}

	id = le32_to_cpu(s.v->parent);
	if (id) {
		ret = lockrestart_do(trans, snapshot_lookup(trans, id, &v));
		if (ret == -ENOENT)
			bch_err(trans->c, "snapshot node %llu has nonexistent parent %u",
				s.k->p.offset, id);
		if (ret)
			return ret;

		if (le32_to_cpu(v.children[0]) != s.k->p.offset &&
		    le32_to_cpu(v.children[1]) != s.k->p.offset) {
			bch_err(trans->c, "snapshot parent %u missing pointer to child %llu",
				id, s.k->p.offset);
			return -EINVAL;
		}
	}

	for (i = 0; i < 2 && s.v->children[i]; i++) {
		id = le32_to_cpu(s.v->children[i]);

		ret = lockrestart_do(trans, snapshot_lookup(trans, id, &v));
		if (ret == -ENOENT)
			bch_err(trans->c, "snapshot node %llu has nonexistent child %u",
				s.k->p.offset, id);
		if (ret)
			return ret;

		if (le32_to_cpu(v.parent) != s.k->p.offset) {
			bch_err(trans->c, "snapshot child %u has wrong parent (got %u should be %llu)",
				id, le32_to_cpu(v.parent), s.k->p.offset);
			return -EINVAL;
		}
	}

	return 0;
}

int bch2_fs_snapshots_check(struct bch_fs *c)
{
	struct btree_trans trans;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bch_snapshot s;
	unsigned id;
	int ret;

	bch2_trans_init(&trans, c, 0, 0);

	for_each_btree_key(&trans, iter, BTREE_ID_snapshots,
			   POS_MIN, 0, k, ret) {
		if (k.k->type != KEY_TYPE_snapshot)
			continue;

		ret = bch2_snapshot_check(&trans, bkey_s_c_to_snapshot(k));
		if (ret)
			break;
	}
	bch2_trans_iter_exit(&trans, &iter);

	if (ret) {
		bch_err(c, "error %i checking snapshots", ret);
		goto err;
	}

	for_each_btree_key(&trans, iter, BTREE_ID_subvolumes,
			   POS_MIN, 0, k, ret) {
		if (k.k->type != KEY_TYPE_subvolume)
			continue;
again_2:
		id = le32_to_cpu(bkey_s_c_to_subvolume(k).v->snapshot);
		ret = snapshot_lookup(&trans, id, &s);

		if (ret == -EINTR) {
			k = bch2_btree_iter_peek(&iter);
			goto again_2;
		} else if (ret == -ENOENT)
			bch_err(c, "subvolume %llu points to nonexistent snapshot %u",
				k.k->p.offset, id);
		else if (ret)
			break;
	}
	bch2_trans_iter_exit(&trans, &iter);
err:
	bch2_trans_exit(&trans);
	return ret;
}

void bch2_fs_snapshots_exit(struct bch_fs *c)
{
	genradix_free(&c->snapshots);
}

int bch2_fs_snapshots_start(struct bch_fs *c)
{
	struct btree_trans trans;
	struct btree_iter iter;
	struct bkey_s_c k;
	bool have_deleted = false;
	int ret = 0;

	bch2_trans_init(&trans, c, 0, 0);

	for_each_btree_key(&trans, iter, BTREE_ID_snapshots,
			   POS_MIN, 0, k, ret) {
	       if (bkey_cmp(k.k->p, POS(0, U32_MAX)) > 0)
		       break;

		if (k.k->type != KEY_TYPE_snapshot) {
			bch_err(c, "found wrong key type %u in snapshot node table",
				k.k->type);
			continue;
		}

		if (BCH_SNAPSHOT_DELETED(bkey_s_c_to_snapshot(k).v))
			have_deleted = true;

		ret = bch2_mark_snapshot(&trans, bkey_s_c_null, k, 0);
		if (ret)
			break;
	}
	bch2_trans_iter_exit(&trans, &iter);

	if (ret)
		goto err;

	ret = bch2_snapshots_set_equiv(&trans);
	if (ret)
		goto err;
err:
	bch2_trans_exit(&trans);

	if (!ret && have_deleted) {
		bch_info(c, "restarting deletion of dead snapshots");
		if (c->opts.fsck) {
			bch2_delete_dead_snapshots_work(&c->snapshot_delete_work);
		} else {
			bch2_delete_dead_snapshots(c);
		}
	}

	return ret;
}

/*
 * Mark a snapshot as deleted, for future cleanup:
 */
static int bch2_snapshot_node_set_deleted(struct btree_trans *trans, u32 id)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_i_snapshot *s;
	int ret = 0;

	bch2_trans_iter_init(trans, &iter, BTREE_ID_snapshots, POS(0, id),
			     BTREE_ITER_INTENT);
	k = bch2_btree_iter_peek_slot(&iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (k.k->type != KEY_TYPE_snapshot) {
		bch2_fs_inconsistent(trans->c, "missing snapshot %u", id);
		ret = -ENOENT;
		goto err;
	}

	/* already deleted? */
	if (BCH_SNAPSHOT_DELETED(bkey_s_c_to_snapshot(k).v))
		goto err;

	s = bch2_trans_kmalloc(trans, sizeof(*s));
	ret = PTR_ERR_OR_ZERO(s);
	if (ret)
		goto err;

	bkey_reassemble(&s->k_i, k);

	SET_BCH_SNAPSHOT_DELETED(&s->v, true);
	ret = bch2_trans_update(trans, &iter, &s->k_i, 0);
	if (ret)
		goto err;
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static int bch2_snapshot_node_delete(struct btree_trans *trans, u32 id)
{
	struct btree_iter iter, p_iter = (struct btree_iter) { NULL };
	struct bkey_s_c k;
	struct bkey_s_c_snapshot s;
	struct bkey_i_snapshot *parent;
	u32 parent_id;
	unsigned i;
	int ret = 0;

	bch2_trans_iter_init(trans, &iter, BTREE_ID_snapshots, POS(0, id),
			     BTREE_ITER_INTENT);
	k = bch2_btree_iter_peek_slot(&iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (k.k->type != KEY_TYPE_snapshot) {
		bch2_fs_inconsistent(trans->c, "missing snapshot %u", id);
		ret = -ENOENT;
		goto err;
	}

	s = bkey_s_c_to_snapshot(k);

	BUG_ON(!BCH_SNAPSHOT_DELETED(s.v));
	parent_id = le32_to_cpu(s.v->parent);

	if (parent_id) {
		bch2_trans_iter_init(trans, &p_iter, BTREE_ID_snapshots,
				     POS(0, parent_id),
				     BTREE_ITER_INTENT);
		k = bch2_btree_iter_peek_slot(&p_iter);
		ret = bkey_err(k);
		if (ret)
			goto err;

		if (k.k->type != KEY_TYPE_snapshot) {
			bch2_fs_inconsistent(trans->c, "missing snapshot %u", parent_id);
			ret = -ENOENT;
			goto err;
		}

		parent = bch2_trans_kmalloc(trans, sizeof(*parent));
		ret = PTR_ERR_OR_ZERO(parent);
		if (ret)
			goto err;

		bkey_reassemble(&parent->k_i, k);

		for (i = 0; i < 2; i++)
			if (le32_to_cpu(parent->v.children[i]) == id)
				break;

		if (i == 2)
			bch_err(trans->c, "snapshot %u missing child pointer to %u",
				parent_id, id);
		else
			parent->v.children[i] = 0;

		if (le32_to_cpu(parent->v.children[0]) <
		    le32_to_cpu(parent->v.children[1]))
			swap(parent->v.children[0],
			     parent->v.children[1]);

		ret = bch2_trans_update(trans, &p_iter, &parent->k_i, 0);
		if (ret)
			goto err;
	}

	ret = bch2_btree_delete_at(trans, &iter, 0);
err:
	bch2_trans_iter_exit(trans, &p_iter);
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

int bch2_snapshot_node_create(struct btree_trans *trans, u32 parent,
			      u32 *new_snapids,
			      u32 *snapshot_subvols,
			      unsigned nr_snapids)
{
	struct btree_iter iter;
	struct bkey_i_snapshot *n;
	struct bkey_s_c k;
	unsigned i;
	int ret = 0;

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
			ret = -ENOSPC;
			goto err;
		}

		n = bch2_trans_kmalloc(trans, sizeof(*n));
		ret = PTR_ERR_OR_ZERO(n);
		if (ret)
			goto err;

		bkey_snapshot_init(&n->k_i);
		n->k.p		= iter.pos;
		n->v.flags	= 0;
		n->v.parent	= cpu_to_le32(parent);
		n->v.subvol	= cpu_to_le32(snapshot_subvols[i]);
		n->v.pad	= 0;
		SET_BCH_SNAPSHOT_SUBVOL(&n->v, true);

		ret   = bch2_trans_update(trans, &iter, &n->k_i, 0) ?:
			bch2_mark_snapshot(trans, bkey_s_c_null, bkey_i_to_s_c(&n->k_i), 0);
		if (ret)
			goto err;

		new_snapids[i]	= iter.pos.offset;
	}

	if (parent) {
		bch2_btree_iter_set_pos(&iter, POS(0, parent));
		k = bch2_btree_iter_peek(&iter);
		ret = bkey_err(k);
		if (ret)
			goto err;

		if (k.k->type != KEY_TYPE_snapshot) {
			bch_err(trans->c, "snapshot %u not found", parent);
			ret = -ENOENT;
			goto err;
		}

		n = bch2_trans_kmalloc(trans, sizeof(*n));
		ret = PTR_ERR_OR_ZERO(n);
		if (ret)
			goto err;

		bkey_reassemble(&n->k_i, k);

		if (n->v.children[0] || n->v.children[1]) {
			bch_err(trans->c, "Trying to add child snapshot nodes to parent that already has children");
			ret = -EINVAL;
			goto err;
		}

		n->v.children[0] = cpu_to_le32(new_snapids[0]);
		n->v.children[1] = cpu_to_le32(new_snapids[1]);
		SET_BCH_SNAPSHOT_SUBVOL(&n->v, false);
		ret = bch2_trans_update(trans, &iter, &n->k_i, 0);
		if (ret)
			goto err;
	}
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static int snapshot_id_add(snapshot_id_list *s, u32 id)
{
	BUG_ON(snapshot_list_has_id(s, id));

	return darray_push(s, id);
}

static int bch2_snapshot_delete_keys_btree(struct btree_trans *trans,
					   snapshot_id_list *deleted,
					   enum btree_id btree_id)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_s_c k;
	snapshot_id_list equiv_seen = { 0 };
	struct bpos last_pos = POS_MIN;
	int ret = 0;

	/*
	 * XXX: We should also delete whiteouts that no longer overwrite
	 * anything
	 */

	bch2_trans_iter_init(trans, &iter, btree_id, POS_MIN,
			     BTREE_ITER_INTENT|
			     BTREE_ITER_PREFETCH|
			     BTREE_ITER_NOT_EXTENTS|
			     BTREE_ITER_ALL_SNAPSHOTS);

	while ((bch2_trans_begin(trans),
		(k = bch2_btree_iter_peek(&iter)).k) &&
	       !(ret = bkey_err(k))) {
		u32 equiv = snapshot_t(c, k.k->p.snapshot)->equiv;

		if (bkey_cmp(k.k->p, last_pos))
			equiv_seen.nr = 0;
		last_pos = k.k->p;

		if (snapshot_list_has_id(deleted, k.k->p.snapshot) ||
		    snapshot_list_has_id(&equiv_seen, equiv)) {
			if (btree_id == BTREE_ID_inodes &&
			    bch2_btree_key_cache_flush(trans, btree_id, iter.pos))
				continue;

			ret = __bch2_trans_do(trans, NULL, NULL,
					      BTREE_INSERT_NOFAIL,
				bch2_btree_iter_traverse(&iter) ?:
				bch2_btree_delete_at(trans, &iter,
					BTREE_UPDATE_INTERNAL_SNAPSHOT_NODE));
			if (ret)
				break;
		} else {
			ret = snapshot_id_add(&equiv_seen, equiv);
			if (ret)
				break;
		}

		bch2_btree_iter_advance(&iter);
	}
	bch2_trans_iter_exit(trans, &iter);

	darray_exit(&equiv_seen);

	return ret;
}

static void bch2_delete_dead_snapshots_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs, snapshot_delete_work);
	struct btree_trans trans;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_snapshot snap;
	snapshot_id_list deleted = { 0 };
	u32 i, id, children[2];
	int ret = 0;

	bch2_trans_init(&trans, c, 0, 0);

	/*
	 * For every snapshot node: If we have no live children and it's not
	 * pointed to by a subvolume, delete it:
	 */
	for_each_btree_key(&trans, iter, BTREE_ID_snapshots,
			   POS_MIN, 0, k, ret) {
		if (k.k->type != KEY_TYPE_snapshot)
			continue;

		snap = bkey_s_c_to_snapshot(k);
		if (BCH_SNAPSHOT_DELETED(snap.v) ||
		    BCH_SNAPSHOT_SUBVOL(snap.v))
			continue;

		children[0] = le32_to_cpu(snap.v->children[0]);
		children[1] = le32_to_cpu(snap.v->children[1]);

		ret   = snapshot_live(&trans, children[0]) ?:
			snapshot_live(&trans, children[1]);
		if (ret < 0)
			break;
		if (ret)
			continue;

		ret = __bch2_trans_do(&trans, NULL, NULL, 0,
			bch2_snapshot_node_set_deleted(&trans, iter.pos.offset));
		if (ret) {
			bch_err(c, "error deleting snapshot %llu: %i", iter.pos.offset, ret);
			break;
		}
	}
	bch2_trans_iter_exit(&trans, &iter);

	if (ret) {
		bch_err(c, "error walking snapshots: %i", ret);
		goto err;
	}

	ret = bch2_snapshots_set_equiv(&trans);
	if (ret)
		goto err;

	for_each_btree_key(&trans, iter, BTREE_ID_snapshots,
			   POS_MIN, 0, k, ret) {
		if (k.k->type != KEY_TYPE_snapshot)
			continue;

		snap = bkey_s_c_to_snapshot(k);
		if (BCH_SNAPSHOT_DELETED(snap.v)) {
			ret = snapshot_id_add(&deleted, k.k->p.offset);
			if (ret)
				break;
		}
	}
	bch2_trans_iter_exit(&trans, &iter);

	if (ret) {
		bch_err(c, "error walking snapshots: %i", ret);
		goto err;
	}

	for (id = 0; id < BTREE_ID_NR; id++) {
		if (!btree_type_has_snapshots(id))
			continue;

		ret = bch2_snapshot_delete_keys_btree(&trans, &deleted, id);
		if (ret) {
			bch_err(c, "error deleting snapshot keys: %i", ret);
			goto err;
		}
	}

	for (i = 0; i < deleted.nr; i++) {
		ret = __bch2_trans_do(&trans, NULL, NULL, 0,
			bch2_snapshot_node_delete(&trans, deleted.data[i]));
		if (ret) {
			bch_err(c, "error deleting snapshot %u: %i",
				deleted.data[i], ret);
			goto err;
		}
	}
err:
	darray_exit(&deleted);
	bch2_trans_exit(&trans);
	percpu_ref_put(&c->writes);
}

static void bch2_delete_dead_snapshots(struct bch_fs *c)
{
	if (unlikely(!percpu_ref_tryget(&c->writes)))
		return;

	if (!queue_work(system_long_wq, &c->snapshot_delete_work))
		percpu_ref_put(&c->writes);
}

static int bch2_delete_dead_snapshots_hook(struct btree_trans *trans,
					   struct btree_trans_commit_hook *h)
{
	bch2_delete_dead_snapshots(trans->c);
	return 0;
}

/* Subvolumes: */

int bch2_subvolume_invalid(const struct bch_fs *c, struct bkey_s_c k,
			   struct printbuf *err)
{
	if (bkey_cmp(k.k->p, SUBVOL_POS_MIN) < 0 ||
	    bkey_cmp(k.k->p, SUBVOL_POS_MAX) > 0) {
		pr_buf(err, "invalid pos");
		return -EINVAL;
	}

	if (bkey_val_bytes(k.k) != sizeof(struct bch_subvolume)) {
		pr_buf(err, "incorrect value size (%zu != %zu)",
		       bkey_val_bytes(k.k), sizeof(struct bch_subvolume));
		return -EINVAL;
	}

	return 0;
}

void bch2_subvolume_to_text(struct printbuf *out, struct bch_fs *c,
			    struct bkey_s_c k)
{
	struct bkey_s_c_subvolume s = bkey_s_c_to_subvolume(k);

	pr_buf(out, "root %llu snapshot id %u",
	       le64_to_cpu(s.v->inode),
	       le32_to_cpu(s.v->snapshot));
}

int bch2_subvolume_get(struct btree_trans *trans, unsigned subvol,
		       bool inconsistent_if_not_found,
		       int iter_flags,
		       struct bch_subvolume *s)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	bch2_trans_iter_init(trans, &iter, BTREE_ID_subvolumes, POS(0, subvol),
			     iter_flags);
	k = bch2_btree_iter_peek_slot(&iter);
	ret = bkey_err(k) ?: k.k->type == KEY_TYPE_subvolume ? 0 : -ENOENT;

	if (ret == -ENOENT && inconsistent_if_not_found)
		bch2_fs_inconsistent(trans->c, "missing subvolume %u", subvol);
	if (!ret)
		*s = *bkey_s_c_to_subvolume(k).v;

	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

int bch2_snapshot_get_subvol(struct btree_trans *trans, u32 snapshot,
			     struct bch_subvolume *subvol)
{
	struct bch_snapshot snap;

	return  snapshot_lookup(trans, snapshot, &snap) ?:
		bch2_subvolume_get(trans, le32_to_cpu(snap.subvol), true, 0, subvol);
}

int bch2_subvolume_get_snapshot(struct btree_trans *trans, u32 subvol,
				u32 *snapid)
{
	struct bch_subvolume s;
	int ret;

	ret = bch2_subvolume_get(trans, subvol, true,
				 BTREE_ITER_CACHED|
				 BTREE_ITER_WITH_UPDATES,
				 &s);

	*snapid = le32_to_cpu(s.snapshot);
	return ret;
}

/*
 * Delete subvolume, mark snapshot ID as deleted, queue up snapshot
 * deletion/cleanup:
 */
int bch2_subvolume_delete(struct btree_trans *trans, u32 subvolid)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_subvolume subvol;
	struct btree_trans_commit_hook *h;
	struct bkey_i *delete;
	u32 snapid;
	int ret = 0;

	bch2_trans_iter_init(trans, &iter, BTREE_ID_subvolumes,
			     POS(0, subvolid),
			     BTREE_ITER_CACHED|
			     BTREE_ITER_INTENT);
	k = bch2_btree_iter_peek_slot(&iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (k.k->type != KEY_TYPE_subvolume) {
		bch2_fs_inconsistent(trans->c, "missing subvolume %u", subvolid);
		ret = -EIO;
		goto err;
	}

	subvol = bkey_s_c_to_subvolume(k);
	snapid = le32_to_cpu(subvol.v->snapshot);

	delete = bch2_trans_kmalloc(trans, sizeof(*delete));
	ret = PTR_ERR_OR_ZERO(delete);
	if (ret)
		goto err;

	bkey_init(&delete->k);
	delete->k.p = iter.pos;
	ret = bch2_trans_update(trans, &iter, delete, 0);
	if (ret)
		goto err;

	ret = bch2_snapshot_node_set_deleted(trans, snapid);

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

void bch2_subvolume_wait_for_pagecache_and_delete(struct work_struct *work)
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
			ret = bch2_trans_do(c, NULL, NULL, BTREE_INSERT_NOFAIL,
				      bch2_subvolume_delete(&trans, *id));
			if (ret) {
				bch_err(c, "error %i deleting subvolume %u", ret, *id);
				break;
			}
		}

		darray_exit(&s);
	}

	percpu_ref_put(&c->writes);
}

struct subvolume_unlink_hook {
	struct btree_trans_commit_hook	h;
	u32				subvol;
};

int bch2_subvolume_wait_for_pagecache_and_delete_hook(struct btree_trans *trans,
						      struct btree_trans_commit_hook *_h)
{
	struct subvolume_unlink_hook *h = container_of(_h, struct subvolume_unlink_hook, h);
	struct bch_fs *c = trans->c;
	int ret = 0;

	mutex_lock(&c->snapshots_unlinked_lock);
	if (!snapshot_list_has_id(&c->snapshots_unlinked, h->subvol))
		ret = snapshot_id_add(&c->snapshots_unlinked, h->subvol);
	mutex_unlock(&c->snapshots_unlinked_lock);

	if (ret)
		return ret;

	if (unlikely(!percpu_ref_tryget(&c->writes)))
		return -EROFS;

	if (!queue_work(system_long_wq, &c->snapshot_wait_for_pagecache_and_delete_work))
		percpu_ref_put(&c->writes);
	return 0;
}

int bch2_subvolume_unlink(struct btree_trans *trans, u32 subvolid)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_i_subvolume *n;
	struct subvolume_unlink_hook *h;
	int ret = 0;

	bch2_trans_iter_init(trans, &iter, BTREE_ID_subvolumes,
			     POS(0, subvolid),
			     BTREE_ITER_CACHED|
			     BTREE_ITER_INTENT);
	k = bch2_btree_iter_peek_slot(&iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (k.k->type != KEY_TYPE_subvolume) {
		bch2_fs_inconsistent(trans->c, "missing subvolume %u", subvolid);
		ret = -EIO;
		goto err;
	}

	n = bch2_trans_kmalloc(trans, sizeof(*n));
	ret = PTR_ERR_OR_ZERO(n);
	if (ret)
		goto err;

	bkey_reassemble(&n->k_i, k);
	SET_BCH_SUBVOLUME_UNLINKED(&n->v, true);

	ret = bch2_trans_update(trans, &iter, &n->k_i, 0);
	if (ret)
		goto err;

	h = bch2_trans_kmalloc(trans, sizeof(*h));
	ret = PTR_ERR_OR_ZERO(h);
	if (ret)
		goto err;

	h->h.fn		= bch2_subvolume_wait_for_pagecache_and_delete_hook;
	h->subvol	= subvolid;
	bch2_trans_commit_hook(trans, &h->h);
err:
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
	struct bkey_s_c k;
	u32 parent = 0, new_nodes[2], snapshot_subvols[2];
	int ret = 0;

	for_each_btree_key(trans, dst_iter, BTREE_ID_subvolumes, SUBVOL_POS_MIN,
			   BTREE_ITER_SLOTS|BTREE_ITER_INTENT, k, ret) {
		if (bkey_cmp(k.k->p, SUBVOL_POS_MAX) > 0)
			break;

		/*
		 * bch2_subvolume_delete() doesn't flush the btree key cache -
		 * ideally it would but that's tricky
		 */
		if (bkey_deleted(k.k) &&
		    !bch2_btree_key_cache_find(c, BTREE_ID_subvolumes, dst_iter.pos))
			goto found_slot;
	}

	if (!ret)
		ret = -ENOSPC;
	goto err;
found_slot:
	snapshot_subvols[0] = dst_iter.pos.offset;
	snapshot_subvols[1] = src_subvolid;

	if (src_subvolid) {
		/* Creating a snapshot: */
		src_subvol = bch2_trans_kmalloc(trans, sizeof(*src_subvol));
		ret = PTR_ERR_OR_ZERO(src_subvol);
		if (ret)
			goto err;

		bch2_trans_iter_init(trans, &src_iter, BTREE_ID_subvolumes,
				     POS(0, src_subvolid),
				     BTREE_ITER_CACHED|
				     BTREE_ITER_INTENT);
		k = bch2_btree_iter_peek_slot(&src_iter);
		ret = bkey_err(k);
		if (ret)
			goto err;

		if (k.k->type != KEY_TYPE_subvolume) {
			bch_err(c, "subvolume %u not found", src_subvolid);
			ret = -ENOENT;
			goto err;
		}

		bkey_reassemble(&src_subvol->k_i, k);
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

	new_subvol = bch2_trans_kmalloc(trans, sizeof(*new_subvol));
	ret = PTR_ERR_OR_ZERO(new_subvol);
	if (ret)
		goto err;

	bkey_subvolume_init(&new_subvol->k_i);
	new_subvol->v.flags	= 0;
	new_subvol->v.snapshot	= cpu_to_le32(new_nodes[0]);
	new_subvol->v.inode	= cpu_to_le64(inode);
	SET_BCH_SUBVOLUME_RO(&new_subvol->v, ro);
	SET_BCH_SUBVOLUME_SNAP(&new_subvol->v, src_subvolid != 0);
	new_subvol->k.p		= dst_iter.pos;
	ret = bch2_trans_update(trans, &dst_iter, &new_subvol->k_i, 0);
	if (ret)
		goto err;

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
