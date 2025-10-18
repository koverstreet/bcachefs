/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_PROGRESS_H
#define _BCACHEFS_PROGRESS_H

/*
 * Lame progress indicators
 *
 * We don't like to use these because they print to the dmesg console, which is
 * spammy - we much prefer to be wired up to a userspace programm (e.g. via
 * thread_with_file) and have it print the progress indicator.
 *
 * But some code is old and doesn't support that, or runs in a context where
 * that's not yet practical (mount).
 */

struct progress_indicator_state {
	unsigned long		next_print;
	u64			nodes_seen;
	u64			nodes_total;
	struct btree		*last_node;
};

void bch2_progress_init_inner(struct progress_indicator_state *s,
			      struct bch_fs *c,
			      u64 leaf_btree_id_mask,
			      u64 inner_btree_id_mask);

static inline void bch2_progress_init(struct progress_indicator_state *s,
				      struct bch_fs *c, u64 btree_id_mask)
{
	bch2_progress_init_inner(s, c, btree_id_mask, 0);
}

int bch2_progress_update_iter(struct btree_trans *,
			      struct progress_indicator_state *,
			      struct btree_iter *,
			      const char *);

#define progress_update_iter(trans, p, iter)			\
	bch2_progress_update_iter(trans, p, iter, __func__)

#endif /* _BCACHEFS_PROGRESS_H */
