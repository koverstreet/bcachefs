/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BACKPOINTERS_BACKGROUND_H
#define _BCACHEFS_BACKPOINTERS_BACKGROUND_H

#include "super.h"

int bch2_backpointer_invalid(const struct bch_fs *, struct bkey_s_c k,
			     int, struct printbuf *);
void bch2_backpointer_to_text(struct printbuf *, const struct bch_backpointer *);
void bch2_backpointer_k_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);
void bch2_backpointer_swab(struct bkey_s);

struct bpos bp_pos_to_bucket(const struct bch_fs *,
					   struct bpos);

#define bch2_bkey_ops_backpointer (struct bkey_ops) {	\
	.key_invalid	= bch2_backpointer_invalid,	\
	.val_to_text	= bch2_backpointer_k_to_text,	\
	.swab		= bch2_backpointer_swab,	\
}

void bch2_extent_ptr_to_bp(struct bch_fs *, enum btree_id, unsigned,
			   struct bkey_s_c, struct extent_ptr_decoded,
			   struct bpos *, struct bch_backpointer *);

int bch2_bucket_backpointer_del(struct btree_trans *, struct bkey_i_alloc_v4 *,
				struct bch_backpointer, struct bkey_s_c);
int bch2_bucket_backpointer_add(struct btree_trans *, struct bkey_i_alloc_v4 *,
				struct bch_backpointer, struct bkey_s_c);
int bch2_get_next_backpointer(struct btree_trans *, struct bpos, int,
			      u64 *, struct bch_backpointer *);
struct bkey_s_c bch2_backpointer_get_key(struct btree_trans *, struct btree_iter *,
					 struct bpos, u64, struct bch_backpointer);
struct btree *bch2_backpointer_get_node(struct btree_trans *, struct btree_iter *,
					struct bpos, u64, struct bch_backpointer);

int bch2_check_btree_backpointers(struct bch_fs *);
int bch2_check_extents_to_backpointers(struct bch_fs *);
int bch2_check_backpointers_to_extents(struct bch_fs *);

#endif /* _BCACHEFS_BACKPOINTERS_BACKGROUND_H */
