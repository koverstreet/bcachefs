/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_SNAPSHOT_H
#define _BCACHEFS_SNAPSHOT_H

void bch2_snapshot_tree_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);
int bch2_snapshot_tree_validate(struct bch_fs *, struct bkey_s_c,
				struct bkey_validate_context);

#define bch2_bkey_ops_snapshot_tree ((struct bkey_ops) {	\
	.key_validate	= bch2_snapshot_tree_validate,		\
	.val_to_text	= bch2_snapshot_tree_to_text,		\
	.min_val_size	= 8,					\
})

struct bkey_i_snapshot_tree *__bch2_snapshot_tree_create(struct btree_trans *);

int bch2_snapshot_tree_lookup(struct btree_trans *, u32, struct bch_snapshot_tree *);

void bch2_snapshot_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);
int bch2_snapshot_validate(struct bch_fs *, struct bkey_s_c,
			   struct bkey_validate_context);
int bch2_mark_snapshot(struct btree_trans *, enum btree_id, unsigned,
		       struct bkey_s_c, struct bkey_s,
		       enum btree_iter_update_trigger_flags);

#define bch2_bkey_ops_snapshot ((struct bkey_ops) {		\
	.key_validate	= bch2_snapshot_validate,		\
	.val_to_text	= bch2_snapshot_to_text,		\
	.trigger	= bch2_mark_snapshot,			\
	.min_val_size	= 24,					\
})

static inline struct snapshot_t *__snapshot_t(struct snapshot_table *t, u32 id)
{
	u32 idx = U32_MAX - id;

	return likely(t && idx < t->nr)
		? &t->s[idx]
		: NULL;
}

static inline const struct snapshot_t *snapshot_t(struct bch_fs *c, u32 id)
{
	return __snapshot_t(rcu_dereference(c->snapshots), id);
}

static inline u32 bch2_snapshot_tree(struct bch_fs *c, u32 id)
{
	guard(rcu)();
	const struct snapshot_t *s = snapshot_t(c, id);
	return s ? s->tree : 0;
}

static inline u32 __bch2_snapshot_parent_early(struct bch_fs *c, u32 id)
{
	const struct snapshot_t *s = snapshot_t(c, id);
	return s ? s->parent : 0;
}

static inline u32 bch2_snapshot_parent_early(struct bch_fs *c, u32 id)
{
	guard(rcu)();
	return __bch2_snapshot_parent_early(c, id);
}

static inline u32 __bch2_snapshot_parent(struct bch_fs *c, u32 id)
{
	const struct snapshot_t *s = snapshot_t(c, id);
	if (!s)
		return 0;

	u32 parent = s->parent;
	if (IS_ENABLED(CONFIG_BCACHEFS_DEBUG) &&
	    parent &&
	    s->depth != snapshot_t(c, parent)->depth + 1)
		panic("id %u depth=%u parent %u depth=%u\n",
		      id, snapshot_t(c, id)->depth,
		      parent, snapshot_t(c, parent)->depth);

	return parent;
}

static inline u32 bch2_snapshot_parent(struct bch_fs *c, u32 id)
{
	guard(rcu)();
	return __bch2_snapshot_parent(c, id);
}

static inline u32 bch2_snapshot_nth_parent(struct bch_fs *c, u32 id, u32 n)
{
	guard(rcu)();
	while (n--)
		id = __bch2_snapshot_parent(c, id);
	return id;
}

u32 bch2_snapshot_oldest_subvol(struct bch_fs *, u32, snapshot_id_list *);
u32 bch2_snapshot_skiplist_get(struct bch_fs *, u32);

static inline u32 bch2_snapshot_root(struct bch_fs *c, u32 id)
{
	guard(rcu)();

	u32 parent;
	while ((parent = __bch2_snapshot_parent(c, id)))
		id = parent;
	return id;
}

static inline enum snapshot_id_state __bch2_snapshot_id_state(struct bch_fs *c, u32 id)
{
	const struct snapshot_t *s = snapshot_t(c, id);
	return s ? s->state : SNAPSHOT_ID_empty;
}

static inline enum snapshot_id_state bch2_snapshot_id_state(struct bch_fs *c, u32 id)
{
	guard(rcu)();
	return __bch2_snapshot_id_state(c, id);
}

static inline bool bch2_snapshot_exists(struct bch_fs *c, u32 id)
{
	return bch2_snapshot_id_state(c, id) == SNAPSHOT_ID_live;
}

static inline int bch2_snapshot_is_internal_node(struct bch_fs *c, u32 id)
{
	guard(rcu)();
	const struct snapshot_t *s = snapshot_t(c, id);
	return s ? s->children[0] : bch_err_throw(c, invalid_snapshot_node);
}

static inline int bch2_snapshot_is_leaf(struct bch_fs *c, u32 id)
{
	int ret = bch2_snapshot_is_internal_node(c, id);
	if (ret < 0)
		return ret;
	return !ret;
}

static inline u32 bch2_snapshot_depth(struct bch_fs *c, u32 parent)
{
	guard(rcu)();
	return parent ? snapshot_t(c, parent)->depth + 1 : 0;
}

bool __bch2_snapshot_is_ancestor(struct bch_fs *, u32, u32);

static inline bool bch2_snapshot_is_ancestor(struct bch_fs *c, u32 id, u32 ancestor)
{
	return id == ancestor
		? true
		: __bch2_snapshot_is_ancestor(c, id, ancestor);
}

static inline bool bch2_snapshot_has_children(struct bch_fs *c, u32 id)
{
	guard(rcu)();
	const struct snapshot_t *t = snapshot_t(c, id);
	return t && (t->children[0]|t->children[1]) != 0;
}

static inline bool snapshot_list_has_id(snapshot_id_list *s, u32 id)
{
	return darray_find(*s, id) != NULL;
}

static inline bool snapshot_list_has_ancestor(struct bch_fs *c, snapshot_id_list *s, u32 id)
{
	darray_for_each(*s, i)
		if (bch2_snapshot_is_ancestor(c, id, *i))
			return true;
	return false;
}

static inline int snapshot_list_add(struct bch_fs *c, snapshot_id_list *s, u32 id)
{
	BUG_ON(snapshot_list_has_id(s, id));
	int ret = darray_push(s, id);
	if (ret)
		bch_err(c, "error reallocating snapshot_id_list (size %zu)", s->size);
	return ret;
}

static inline int snapshot_list_add_nodup(struct bch_fs *c, snapshot_id_list *s, u32 id)
{
	int ret = snapshot_list_has_id(s, id)
		? 0
		: darray_push(s, id);
	if (ret)
		bch_err(c, "error reallocating snapshot_id_list (size %zu)", s->size);
	return ret;
}

static inline int snapshot_list_merge(struct bch_fs *c, snapshot_id_list *dst, snapshot_id_list *src)
{
	darray_for_each(*src, i) {
		int ret = snapshot_list_add_nodup(c, dst, *i);
		if (ret)
			return ret;
	}

	return 0;
}

int bch2_snapshot_lookup(struct btree_trans *trans, u32 id,
			 struct bch_snapshot *s);
int bch2_snapshot_get_subvol(struct btree_trans *, u32,
			     struct bch_subvolume *);

/* only exported for tests: */
int bch2_snapshot_node_create(struct btree_trans *, u32,
			      u32 *, u32 *, unsigned);

int bch2_check_snapshot_trees(struct bch_fs *);
int bch2_check_snapshots(struct bch_fs *);
int bch2_reconstruct_snapshots(struct bch_fs *);

int __bch2_check_key_has_snapshot(struct btree_trans *, struct btree_iter *, struct bkey_s_c);

static inline int bch2_check_key_has_snapshot(struct btree_trans *trans,
					      struct btree_iter *iter,
					      struct bkey_s_c k)
{
	return likely(bch2_snapshot_exists(trans->c, k.k->p.snapshot))
		? 0
		: __bch2_check_key_has_snapshot(trans, iter, k);
}

int __bch2_get_snapshot_overwrites(struct btree_trans *,
				   enum btree_id, struct bpos,
				   snapshot_id_list *);

/*
 * Get a list of snapshot IDs that have overwritten a given key:
 */
static inline int bch2_get_snapshot_overwrites(struct btree_trans *trans,
					       enum btree_id btree, struct bpos pos,
					       snapshot_id_list *s)
{
	darray_init(s);

	return bch2_snapshot_has_children(trans->c, pos.snapshot)
		? __bch2_get_snapshot_overwrites(trans, btree, pos, s)
		: 0;

}

int bch2_snapshot_node_set_deleted(struct btree_trans *, u32);

int __bch2_key_has_snapshot_overwrites(struct btree_trans *, enum btree_id, struct bpos);

static inline int bch2_key_has_snapshot_overwrites(struct btree_trans *trans,
					  enum btree_id id,
					  struct bpos pos)
{
	if (!btree_type_has_snapshots(id) ||
	    bch2_snapshot_is_leaf(trans->c, pos.snapshot) > 0)
		return 0;

	return __bch2_key_has_snapshot_overwrites(trans, id, pos);
}

int __bch2_delete_dead_snapshots(struct bch_fs *);
int bch2_delete_dead_snapshots(struct bch_fs *);
void bch2_delete_dead_snapshots_work(struct work_struct *);
void bch2_delete_dead_snapshots_async(struct bch_fs *);
void bch2_snapshot_delete_status_to_text(struct printbuf *, struct bch_fs *);

int bch2_snapshots_read(struct bch_fs *);
void bch2_fs_snapshots_exit(struct bch_fs *);
void bch2_fs_snapshots_init_early(struct bch_fs *);

#endif /* _BCACHEFS_SNAPSHOT_H */
