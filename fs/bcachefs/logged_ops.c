// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "bkey_buf.h"
#include "btree_update.h"
#include "error.h"
#include "io_misc.h"
#include "logged_ops.h"
#include "super.h"

struct bch_logged_op_fn {
	u8		type;
	int		(*resume)(struct btree_trans *, struct bkey_i *);
};

static const struct bch_logged_op_fn logged_op_fns[] = {
#define x(n)		{					\
	.type		= KEY_TYPE_logged_op_##n,		\
	.resume		= bch2_resume_logged_op_##n,		\
},
	BCH_LOGGED_OPS()
#undef x
};

static const struct bch_logged_op_fn *logged_op_fn(enum bch_bkey_type type)
{
	for (unsigned i = 0; i < ARRAY_SIZE(logged_op_fns); i++)
		if (logged_op_fns[i].type == type)
			return logged_op_fns + i;
	return NULL;
}

static int resume_logged_op(struct btree_trans *trans, struct btree_iter *iter,
			    struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	u32 restart_count = trans->restart_count;
	CLASS(printbuf, buf)();
	int ret = 0;

	fsck_err_on(test_bit(BCH_FS_clean_recovery, &c->flags),
		    trans, logged_op_but_clean,
		    "filesystem marked as clean but have logged op\n%s",
		    (bch2_bkey_val_to_text(&buf, c, k),
		     buf.buf));

	struct bkey_buf sk;
	bch2_bkey_buf_init(&sk);
	bch2_bkey_buf_reassemble(&sk, c, k);

	const struct bch_logged_op_fn *fn = logged_op_fn(sk.k->k.type);
	if (fn)
		fn->resume(trans, sk.k);

	ret = bch2_logged_op_finish(trans, sk.k);

	bch2_bkey_buf_exit(&sk, c);
fsck_err:
	return ret ?: trans_was_restarted(trans, restart_count);
}

int bch2_resume_logged_ops(struct bch_fs *c)
{
	CLASS(btree_trans, trans)(c);
	return for_each_btree_key_max(trans, iter,
				   BTREE_ID_logged_ops,
				   POS(LOGGED_OPS_INUM_logged_ops, 0),
				   POS(LOGGED_OPS_INUM_logged_ops, U64_MAX),
				   BTREE_ITER_prefetch, k,
			resume_logged_op(trans, &iter, k));
}

static int __bch2_logged_op_start(struct btree_trans *trans, struct bkey_i *k)
{
	struct btree_iter iter;
	int ret = bch2_bkey_get_empty_slot(trans, &iter,
				 BTREE_ID_logged_ops, POS(LOGGED_OPS_INUM_logged_ops, U64_MAX));
	if (ret)
		return ret;

	k->k.p = iter.pos;

	ret = bch2_trans_update(trans, &iter, k, 0);
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

int bch2_logged_op_start(struct btree_trans *trans, struct bkey_i *k)
{
	return commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			 __bch2_logged_op_start(trans, k));
}

int bch2_logged_op_finish(struct btree_trans *trans, struct bkey_i *k)
{
	int ret = commit_do(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			    bch2_btree_delete(trans, BTREE_ID_logged_ops, k->k.p, 0));
	/*
	 * This needs to be a fatal error because we've left an unfinished
	 * operation in the logged ops btree.
	 *
	 * We should only ever see an error here if the filesystem has already
	 * been shut down, but make sure of that here:
	 */
	if (ret) {
		struct bch_fs *c = trans->c;
		CLASS(printbuf, buf)();

		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(k));
		bch2_fs_fatal_error(c, "deleting logged operation %s: %s",
				    buf.buf, bch2_err_str(ret));
	}

	return ret;
}
