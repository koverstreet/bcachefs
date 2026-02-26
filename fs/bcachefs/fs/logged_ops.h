/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_LOGGED_OPS_H
#define _BCACHEFS_LOGGED_OPS_H

#include "btree/bkey.h"

#define BCH_LOGGED_OPS()			\
	x(truncate)				\
	x(finsert)				\
	x(stripe_update)

static inline int bch2_logged_op_update(struct btree_trans *trans, struct bkey_i *op)
{
	return bch2_btree_insert_trans(trans, BTREE_ID_logged_ops, op, BTREE_ITER_cached);
}

int bch2_resume_logged_ops(struct bch_fs *);
int __bch2_logged_op_start(struct btree_trans *, struct bkey_i *);
int bch2_logged_op_start(struct btree_trans *, struct bkey_i *);
int bch2_logged_op_finish(struct btree_trans *, struct bkey_i *);

#endif /* _BCACHEFS_LOGGED_OPS_H */
