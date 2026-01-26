/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_RECONCILE_TRIGGER_H
#define _BCACHEFS_RECONCILE_TRIGGER_H

#include "data/extents.h"

int bch2_extent_reconcile_validate(struct bch_fs *, struct bkey_s_c,
				   struct bkey_validate_context,
				   const struct bch_extent_reconcile *);

static inline struct bpos data_to_rb_work_pos(enum btree_id btree, struct bpos pos)
{
	if (btree == BTREE_ID_reflink ||
	    btree == BTREE_ID_stripes)
		pos = bpos_min(pos, POS(0, U64_MAX));

	if (btree == BTREE_ID_extents)
		pos = bpos_max(pos, POS(BCACHEFS_ROOT_INO, 0));

	if (btree == BTREE_ID_reflink)
		pos.inode++;
	return pos;
}

static inline struct bbpos rb_work_to_data_pos(struct bpos pos)
{
	if (!pos.inode)
		return BBPOS(BTREE_ID_stripes, pos);
	if (pos.inode < BCACHEFS_ROOT_INO) {
		--pos.inode;
		return BBPOS(BTREE_ID_reflink, pos);
	}
	return BBPOS(BTREE_ID_extents, pos);
}

static inline enum reconcile_work_id rb_work_id(const struct bch_extent_reconcile *r)
{
	if (!r || !r->need_rb)
		return RECONCILE_WORK_none;
	if (r->pending)
		return RECONCILE_WORK_pending;
	if (r->hipri)
		return RECONCILE_WORK_hipri;
	return RECONCILE_WORK_normal;
}

static inline enum reconcile_work_id rb_work_id_phys(const struct bch_extent_reconcile *r)
{
	enum reconcile_work_id w = rb_work_id(r);
	return w == RECONCILE_WORK_pending ? RECONCILE_WORK_none : w;
}

static inline struct bch_extent_reconcile io_opts_to_reconcile_opts(struct bch_fs *c,
								    struct bch_inode_opts *opts)
{
	return (struct bch_extent_reconcile) {
		.type = BIT(BCH_EXTENT_ENTRY_reconcile),
#define x(_name)							\
		._name = opts->_name,					\
		._name##_from_inode = opts->_name##_from_inode,
		BCH_RECONCILE_OPTS()
#undef x
	};
};

struct bpos bch2_bkey_get_reconcile_bp_pos(const struct bch_fs *, struct bkey_s_c);
void bch2_bkey_set_reconcile_bp(const struct bch_fs *, struct bkey_s, u64);

int reconcile_bp_del(struct btree_trans *, enum btree_id, unsigned,
		     struct bkey_s_c, struct bpos bp_pos);
int reconcile_bp_add(struct btree_trans *trans, enum btree_id, unsigned,
		     struct bkey_s, struct bpos *);

struct bkey_s_c reconcile_bp_get_key(struct btree_trans *,
				     struct btree_iter *,
				     struct bkey_s_c_backpointer);

static inline struct bch_backpointer rb_bp(enum btree_id btree, unsigned level, struct bkey_s_c k)
{
	return (struct bch_backpointer) {
		.btree_id	= btree,
		.level		= level,
		.pos		= k.k->p,
	};
}

static inline bool extent_has_rotational(struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);

	bkey_for_each_ptr(ptrs, ptr)
		if (bch2_dev_rotational(c, ptr->dev))
			return true;
	return false;
}

void bch2_extent_rebalance_v1_to_text(struct printbuf *, struct bch_fs *,
				      const struct bch_extent_rebalance_v1 *);
void bch2_extent_reconcile_to_text(struct printbuf *, struct bch_fs *,
				      const struct bch_extent_reconcile *);

const struct bch_extent_reconcile *bch2_bkey_reconcile_opts(const struct bch_fs *, struct bkey_s_c);

int __bch2_trigger_extent_reconcile(struct btree_trans *,
				    enum btree_id, unsigned,
				    struct bkey_s_c, struct bkey_s,
				    const struct bch_extent_reconcile *,
				    const struct bch_extent_reconcile *,
				    enum btree_iter_update_trigger_flags);

static inline unsigned rb_needs_trigger(const struct bch_extent_reconcile *r)
{
	return r ? r->need_rb|r->ptrs_moving : 0;
}

static inline int bch2_trigger_extent_reconcile(struct btree_trans *trans,
				enum btree_id btree, unsigned level,
				struct bkey_s_c old, struct bkey_s new,
				enum btree_iter_update_trigger_flags flags)
{
	struct bch_fs *c = trans->c;
	const struct bch_extent_reconcile *old_r = bch2_bkey_reconcile_opts(c, old);
	const struct bch_extent_reconcile *new_r = bch2_bkey_reconcile_opts(c, new.s_c);

	return rb_needs_trigger(old_r) || rb_needs_trigger(new_r)
		? __bch2_trigger_extent_reconcile(trans, btree, level, old, new, old_r, new_r, flags)
		: 0;
}

enum set_needs_reconcile_ctx {
	SET_NEEDS_RECONCILE_opt_change,
	SET_NEEDS_RECONCILE_opt_change_indirect,
	SET_NEEDS_RECONCILE_foreground,
	SET_NEEDS_RECONCILE_other,
};

/* Inodes in different snapshots may have different IO options: */
struct snapshot_io_opts_entry {
	u32			snapshot;
	struct bch_inode_opts	io_opts;
};

struct per_snapshot_io_opts {
	u64			cur_inum;
	bool			metadata;
	bool			fs_scan_cookie;
	bool			inum_scan_cookie;
	struct bch_devs_mask	dev_cookie;

	struct bch_inode_opts	fs_io_opts;
	DARRAY(struct snapshot_io_opts_entry) d;
};

static inline struct per_snapshot_io_opts per_snapshot_io_opts_init(struct bch_fs *c)
{
	return (struct per_snapshot_io_opts) {
		/* io_opts->fs_io_opts will be initialized when we know the key type */
		.fs_io_opts.change_cookie = c->opt_change_cookie - 1,
	};
}

static inline void per_snapshot_io_opts_exit(struct per_snapshot_io_opts *io_opts)
{
	darray_exit(&io_opts->d);
}

DEFINE_CLASS(per_snapshot_io_opts, struct per_snapshot_io_opts,
	     per_snapshot_io_opts_exit(&_T),
	     per_snapshot_io_opts_init(c),
	     struct bch_fs *c);

int bch2_bkey_get_io_opts(struct btree_trans *,
			  struct per_snapshot_io_opts *, struct bkey_s_c,
			  struct bch_inode_opts *opts);

int bch2_update_reconcile_opts(struct btree_trans *,
			       struct per_snapshot_io_opts *,
			       struct bch_inode_opts *,
			       struct btree_iter *,
			       unsigned level,
			       struct bkey_s_c,
			       enum set_needs_reconcile_ctx);

int bch2_bkey_set_needs_reconcile(struct btree_trans *,
				  struct per_snapshot_io_opts *, struct bch_inode_opts *,
				  struct bkey_i *, enum set_needs_reconcile_ctx, u32);

#endif /* _BCACHEFS_RECONCILE_TRIGGER_H */
