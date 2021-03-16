// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_update.h"
#include "error.h"
#include "subvolume.h"

/* Snapshot tree: */

void bch2_snapshot_to_text(struct printbuf *out, struct bch_fs *c,
			   struct bkey_s_c k)
{
	struct bkey_s_c_snapshot n = bkey_s_c_to_snapshot(k);

	pr_buf(out, "parent: %u", le32_to_cpu(n.v->parent));
}

const char *bch2_snapshot_invalid(const struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_s_c_snapshot n;
	u32 parent;

	if (bkey_cmp(k.k->p, POS(0, U32_MAX)) > 0 ||
	    bkey_cmp(k.k->p, POS(0, 1)) < 0)
		return "bad pos";

	if (bkey_val_bytes(k.k) != sizeof(struct bch_snapshot))
		return "bad val size";

	n = bkey_s_c_to_snapshot(k);

	if (n.v->flags)
		return "bad flags field";

	parent = le32_to_cpu(n.v->parent);
	if (parent && parent <= k.k->p.offset)
		return "bad parent node";

	return NULL;
}

static int subvol_exists(struct btree_trans *trans, unsigned id)
{
	struct btree_iter *iter =
		bch2_trans_get_iter(trans, BTREE_ID_subvolumes, POS(0, id), 0);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(iter);
	int ret = bkey_err(k) ?: k.k->type == KEY_TYPE_subvolume ? 0 : -ENOENT;

	bch2_trans_iter_put(trans, iter);
	return ret;
}

static int snapshot_exists(struct btree_trans *trans, unsigned id)
{
	struct btree_iter *iter =
		bch2_trans_get_iter(trans, BTREE_ID_snapshots, POS(0, id), 0);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(iter);
	int ret = bkey_err(k) ?: k.k->type == KEY_TYPE_snapshot ? 0 : -ENOENT;

	bch2_trans_iter_put(trans, iter);
	return ret;
}

/* fsck: */
int bch2_fs_snapshots_check(struct bch_fs *c)
{
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	unsigned id;
	int ret;

	bch2_trans_init(&trans, c, 0, 0);

	for_each_btree_key(&trans, iter, BTREE_ID_snapshots,
			   POS_MIN, 0, k, ret) {
		if (k.k->type != KEY_TYPE_snapshot)
			continue;

		id = le32_to_cpu(bkey_s_c_to_snapshot(k).v->subvol);
		ret = lockrestart_do(&trans, subvol_exists(&trans, id));
		if (ret == -ENOENT)
			bch_err(c, "snapshot node %llu has nonexistent subvolume %u",
				k.k->p.offset, id);
		else if (ret)
			break;

		id = le32_to_cpu(bkey_s_c_to_snapshot(k).v->parent);
		if (!id)
			continue;

		ret = lockrestart_do(&trans, snapshot_exists(&trans, id));
		if (ret == -ENOENT)
			bch_err(c, "snapshot node %llu has nonexistent parent %u",
				k.k->p.offset, id);
		else if (ret)
			break;
	}
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
		ret = snapshot_exists(&trans, id);

		if (ret == -EINTR) {
			k = bch2_btree_iter_peek(iter);
			goto again_2;
		} else if (ret == -ENOENT)
			bch_err(c, "subvolume %llu points to nonexistent snapshot %u",
				k.k->p.offset, id);
		else if (ret)
			break;
	}
err:
	bch2_trans_exit(&trans);
	return ret;
}

void bch2_fs_snapshots_exit(struct bch_fs *c)
{
	if (c->snapshot_table)
		kfree_rcu(c->snapshot_table, rcu);
}

int bch2_fs_snapshots_start(struct bch_fs *c)
{
	struct btree_trans trans;
	struct btree_iter *iter;
	struct bkey_s_c k;
	struct bkey_s_c_snapshot n;
	struct bch_snapshot_table *t = NULL;
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

		if (!t) {
			t = kzalloc(sizeof(*t) + sizeof(t->d[0]) *
				    ((u64) U32_MAX + 1 - k.k->p.offset),
				    GFP_KERNEL);
			if (!t) {
				ret = -ENOMEM;
				break;
			}

			t->base = k.k->p.offset;
		}

		n = bkey_s_c_to_snapshot(k);
		t->d[n.k->p.offset - t->base] = le32_to_cpu(n.v->parent);
	}
	bch2_trans_iter_put(&trans, iter);

	if (!ret && !t) {
		t = kzalloc(sizeof(*t) + sizeof(t->d[0]), GFP_KERNEL);
		if (!t)
			ret = -ENOMEM;
		else
			t->base = U32_MAX;
	}

	rcu_assign_pointer(c->snapshot_table, t);

	bch2_trans_exit(&trans);
	return ret;
}

struct snapshot_node_hook {
	struct btree_trans_commit_hook	h;
	u32				new_parent;
	unsigned			nr_nodes;
	u32				new_nodes[];
};

static int bch2_snapshot_node_hook(struct btree_trans *trans,
				   struct btree_trans_commit_hook *hook)
{
	struct bch_fs *c = trans->c;
	struct snapshot_node_hook *h =
		container_of(hook, struct snapshot_node_hook, h);
	struct bch_snapshot_table *new, *old;
	unsigned i, new_base;
	int ret = 0;

	mutex_lock(&c->snapshot_table_lock);

	old = rcu_dereference_protected(c->snapshot_table, 1);
	new_base = old->base;

	for (i = 0; i < h->nr_nodes; i++)
		new_base = min(new_base, h->new_nodes[i]);

	new = kzalloc(sizeof(*new) + sizeof(new->d[0]) *
		      (U32_MAX - new_base), GFP_KERNEL);
	if (!new) {
		ret = -ENOMEM;
		goto unlock;
	}

	new->base = new_base;

	memcpy(&new->d[old->base - new->base],
	       &old->d[0],
	       sizeof(old->d[0]) * (U32_MAX - old->base));

	for (i = 0; i < h->nr_nodes; i++)
		new->d[h->new_nodes[i] - new->base] = h->new_parent;

	rcu_assign_pointer(c->snapshot_table, new);
	kfree_rcu(old, rcu);
unlock:
	mutex_unlock(&c->snapshot_table_lock);

	return ret;
}

static int bch2_snapshot_node_create(struct btree_trans *trans, u32 parent,
				     u32 *new_snapids,
				     u32 *snapshot_subvols,
				     unsigned nr_snapids)
{
	struct btree_iter *iter = NULL, *copy;
	struct bkey_i_snapshot *n;
	struct snapshot_node_hook *h;
	struct bkey_s_c k;
	unsigned i;
	int ret = 0;

	h = bch2_trans_kmalloc(trans, sizeof(*h) + sizeof(u32) * nr_snapids);
	ret = PTR_ERR_OR_ZERO(h);
	if (ret)
		goto err;

	h->h.fn = bch2_snapshot_node_hook;
	h->new_parent	= parent;
	h->nr_nodes	= nr_snapids;

	iter = bch2_trans_get_iter(trans, BTREE_ID_snapshots,
				   POS_MIN, BTREE_ITER_INTENT);
	k = bch2_btree_iter_peek(iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	for (i = 0; i < nr_snapids; i++) {
		k = bch2_btree_iter_prev_slot(iter);
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
			return ret;

		bkey_snapshot_init(&n->k_i);
		n->k.p		= iter->pos;
		n->v.flags	= 0;
		n->v.parent	= cpu_to_le32(parent);
		n->v.subvol	= cpu_to_le32(snapshot_subvols[i]);
		n->v.pad	= 0;

		copy = bch2_trans_copy_iter(trans, iter);
		bch2_trans_update(trans, copy, &n->k_i, 0);
		bch2_trans_iter_put(trans, copy);

		h->new_nodes[i] = iter->pos.offset;
		new_snapids[i]	= iter->pos.offset;
	}

	bch2_trans_commit_hook(trans, &h->h);
err:
	bch2_trans_iter_put(trans, iter);
	return ret;
}

/* Subvolumes: */

const char *bch2_subvolume_invalid(const struct bch_fs *c, struct bkey_s_c k)
{
	if (bkey_cmp(k.k->p, SUBVOL_POS_MIN) < 0)
		return "invalid pos";

	if (bkey_cmp(k.k->p, SUBVOL_POS_MAX) > 0)
		return "invalid pos";

	if (bkey_val_bytes(k.k) != sizeof(struct bch_subvolume))
		return "bad val size";

	return NULL;
}

void bch2_subvolume_to_text(struct printbuf *out, struct bch_fs *c,
			    struct bkey_s_c k)
{
	struct bkey_s_c_subvolume s = bkey_s_c_to_subvolume(k);

	pr_buf(out, "root %llu snapshot id %u",
	       le64_to_cpu(s.v->inode),
	       le32_to_cpu(s.v->snapshot));
}

int bch2_subvolume_get_snapshot(struct btree_trans *trans, u32 subvol,
				u32 *snapid)
{
	struct btree_insert_entry *i;
	struct btree_iter *iter;
	struct bkey_s_c k;
	int ret;

	iter = bch2_trans_get_iter(trans, BTREE_ID_subvolumes,
				   POS(0, subvol),
				   BTREE_ITER_CACHED);
	k = bch2_btree_iter_peek_cached(iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	/*
	 * XXX: the btree iterator code doesn't generally include updates yet,
	 * so we're open coding that here for now:
	 */
	trans_for_each_update(trans, i)
		if (i->btree_id == BTREE_ID_subvolumes &&
		    !bkey_cmp(i->k->k.p, POS(0, subvol))) {
			k = bkey_i_to_s_c(i->k);
			break;
		}

	if (k.k->type != KEY_TYPE_subvolume) {
		bch2_fs_inconsistent(trans->c, "missing subvolume %u", subvol);
		ret = -EIO;
		goto err;
	}

	*snapid = le32_to_cpu(bkey_s_c_to_subvolume(k).v->snapshot);
err:
	bch2_trans_iter_put(trans, iter);
	return ret;
}

/* XXX: mark snapshot id for deletion, walk btree and delete: */
int bch2_subvolume_delete(struct btree_trans *trans, u32 subvolid)
{
	struct btree_iter *iter;
	struct bkey_i *delete;
	int ret = 0;

	delete = bch2_trans_kmalloc(trans, sizeof(*delete));
	ret = PTR_ERR_OR_ZERO(delete);
	if (ret)
		return ret;

	iter = bch2_trans_get_iter(trans, BTREE_ID_subvolumes,
				   POS(0, subvolid),
				   BTREE_ITER_CACHED|
				   BTREE_ITER_INTENT);

	bkey_init(&delete->k);
	delete->k.p = iter->pos;
	bch2_trans_update(trans, iter, delete, 0);
	bch2_trans_iter_put(trans, iter);
	return 0;
}

int bch2_subvolume_create(struct btree_trans *trans, u64 inode,
			  u32 src_subvol,
			  u32 *new_subvol,
			  u32 *new_snapshot,
			  bool ro)
{
	struct btree_iter *dst_iter = NULL, *src_iter = NULL;
	struct bkey_i_subvolume *n = NULL;
	struct bkey_s_c k;
	u32 parent = 0, new_nodes[2], snapshot_subvols[2];
	int ret = 0;

	if (src_subvol) {
		n = bch2_trans_kmalloc(trans, sizeof(*n));
		ret = PTR_ERR_OR_ZERO(n);
		if (ret)
			return ret;

		src_iter = bch2_trans_get_iter(trans, BTREE_ID_subvolumes,
					   POS(0, src_subvol),
					   BTREE_ITER_CACHED|
					   BTREE_ITER_INTENT);
		k = bch2_btree_iter_peek_cached(src_iter);
		ret = bkey_err(k);
		if (ret)
			goto err;

		if (k.k->type != KEY_TYPE_subvolume) {
			bch_err(trans->c, "subvolume %u not found", src_subvol);
			ret = -ENOENT;
			goto err;
		}

		bkey_reassemble(&n->k_i, k);
		parent = le32_to_cpu(n->v.snapshot);
	}

	for_each_btree_key(trans, dst_iter, BTREE_ID_subvolumes, SUBVOL_POS_MIN,
			   BTREE_ITER_SLOTS|BTREE_ITER_INTENT, k, ret) {
		if (bkey_cmp(k.k->p, SUBVOL_POS_MAX) > 0)
			break;
		if (bkey_deleted(k.k))
			goto found_slot;
	}

	if (!ret)
		ret = -ENOSPC;
	goto err;
found_slot:
	snapshot_subvols[0] = dst_iter->pos.offset;
	snapshot_subvols[1] = src_subvol;

	ret = bch2_snapshot_node_create(trans, parent, new_nodes,
					snapshot_subvols,
					src_subvol ? 2 : 1);
	if (ret)
		goto err;

	if (src_subvol) {
		n->v.snapshot = cpu_to_le32(new_nodes[1]);
		bch2_trans_update(trans, src_iter, &n->k_i, 0);
		bch2_trans_iter_put(trans, src_iter);
		src_iter = NULL;
	}

	n = bch2_trans_kmalloc(trans, sizeof(*n));
	ret = PTR_ERR_OR_ZERO(n);
	if (ret)
		return ret;

	bkey_subvolume_init(&n->k_i);
	n->v.flags	= 0;
	n->v.snapshot	= cpu_to_le32(new_nodes[0]);
	n->v.inode	= cpu_to_le64(inode);
	SET_BCH_SUBVOLUME_RO(&n->v, ro);
	n->k.p = dst_iter->pos;
	bch2_trans_update(trans, dst_iter, &n->k_i, 0);

	*new_subvol	= n->k.p.offset;
	*new_snapshot	= new_nodes[0];
err:
	bch2_trans_iter_put(trans, src_iter);
	bch2_trans_iter_put(trans, dst_iter);
	return ret;
}
