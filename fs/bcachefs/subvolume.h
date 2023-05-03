/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_SUBVOLUME_H
#define _BCACHEFS_SUBVOLUME_H

#include "darray.h"
#include "subvolume_types.h"

void bch2_snapshot_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);
const char *bch2_snapshot_invalid(const struct bch_fs *, struct bkey_s_c);

#define bch2_bkey_ops_snapshot (struct bkey_ops) {		\
	.key_invalid	= bch2_snapshot_invalid,		\
	.val_to_text	= bch2_snapshot_to_text,		\
}

int bch2_mark_snapshot(struct btree_trans *, struct bkey_s_c,
		       struct bkey_s_c, unsigned);

static inline struct snapshot_t *snapshot_t(struct bch_fs *c, u32 id)
{
	return genradix_ptr(&c->snapshots, U32_MAX - id);
}

static inline u32 bch2_snapshot_parent(struct bch_fs *c, u32 id)
{
	return snapshot_t(c, id)->parent;
}

static inline u32 bch2_snapshot_internal_node(struct bch_fs *c, u32 id)
{
	struct snapshot_t *s = snapshot_t(c, id);

	return s->children[0] || s->children[1];
}

static inline u32 bch2_snapshot_sibling(struct bch_fs *c, u32 id)
{
	struct snapshot_t *s;
	u32 parent = bch2_snapshot_parent(c, id);

	if (!parent)
		return 0;

	s = snapshot_t(c, bch2_snapshot_parent(c, id));
	if (id == s->children[0])
		return s->children[1];
	if (id == s->children[1])
		return s->children[0];
	return 0;
}

static inline bool bch2_snapshot_is_ancestor(struct bch_fs *c, u32 id, u32 ancestor)
{
	while (id && id < ancestor)
		id = bch2_snapshot_parent(c, id);

	return id == ancestor;
}

struct snapshots_seen {
	struct bpos			pos;
	DARRAY(u32)			ids;
};

static inline void snapshots_seen_exit(struct snapshots_seen *s)
{
	kfree(s->ids.data);
	s->ids.data = NULL;
}

static inline void snapshots_seen_init(struct snapshots_seen *s)
{
	memset(s, 0, sizeof(*s));
}

static inline int snapshots_seen_add(struct bch_fs *c, struct snapshots_seen *s, u32 id)
{
	int ret = darray_push(&s->ids, id);
	if (ret)
		bch_err(c, "error reallocating snapshots_seen table (size %zu)",
			s->ids.size);
	return ret;
}

static inline bool snapshot_list_has_id(snapshot_id_list *s, u32 id)
{
	u32 *i;

	darray_for_each(*s, i)
		if (*i == id)
			return true;
	return false;
}

int bch2_fs_snapshots_check(struct bch_fs *);
void bch2_fs_snapshots_exit(struct bch_fs *);
int bch2_fs_snapshots_start(struct bch_fs *);

const char *bch2_subvolume_invalid(const struct bch_fs *, struct bkey_s_c);
void bch2_subvolume_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);

#define bch2_bkey_ops_subvolume (struct bkey_ops) {		\
	.key_invalid	= bch2_subvolume_invalid,		\
	.val_to_text	= bch2_subvolume_to_text,		\
}

int bch2_subvolume_get(struct btree_trans *, unsigned,
		       bool, int, struct bch_subvolume *);
int bch2_snapshot_get_subvol(struct btree_trans *, u32,
			     struct bch_subvolume *);
int bch2_subvolume_get_snapshot(struct btree_trans *, u32, u32 *);

/* only exported for tests: */
int bch2_snapshot_node_create(struct btree_trans *, u32,
			      u32 *, u32 *, unsigned);

int bch2_subvolume_delete(struct btree_trans *, u32);
int bch2_subvolume_unlink(struct btree_trans *, u32);
int bch2_subvolume_create(struct btree_trans *, u64, u32,
			  u32 *, u32 *, bool);

int bch2_fs_subvolumes_init(struct bch_fs *);

#endif /* _BCACHEFS_SUBVOLUME_H */
