// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "alloc_background.h"
#include "btree_iter.h"
#include "btree_update.h"
#include "btree_write_buffer.h"
#include "error.h"
#include "lru.h"
#include "recovery.h"

/* KEY_TYPE_lru is obsolete: */
int bch2_lru_invalid(struct bch_fs *c, struct bkey_s_c k,
		     enum bkey_invalid_flags flags,
		     struct printbuf *err)
{
	int ret = 0;

	bkey_fsck_err_on(!lru_pos_time(k.k->p), c, err,
			 lru_entry_at_time_0,
			 "lru entry at time=0");
fsck_err:
	return ret;
}

void bch2_lru_to_text(struct printbuf *out, struct bch_fs *c,
		      struct bkey_s_c k)
{
	const struct bch_lru *lru = bkey_s_c_to_lru(k).v;

	prt_printf(out, "idx %llu", le64_to_cpu(lru->idx));
}

void bch2_lru_pos_to_text(struct printbuf *out, struct bpos lru)
{
	prt_printf(out, "%llu:%llu -> %llu:%llu",
		   lru_pos_id(lru),
		   lru_pos_time(lru),
		   u64_to_bucket(lru.offset).inode,
		   u64_to_bucket(lru.offset).offset);
}

static inline int __bch2_lru_set(struct btree_trans *trans, u16 lru_id,
				 u64 dev_bucket, u64 time, bool set)
{
	return time
		? bch2_btree_bit_mod(trans, BTREE_ID_lru,
				     lru_pos(lru_id, dev_bucket, time), set)
		: 0;
}

int bch2_lru_del(struct btree_trans *trans, u16 lru_id, u64 dev_bucket, u64 time)
{
	return __bch2_lru_set(trans, lru_id, dev_bucket, time, false);
}

int bch2_lru_set(struct btree_trans *trans, u16 lru_id, u64 dev_bucket, u64 time)
{
	return __bch2_lru_set(trans, lru_id, dev_bucket, time, true);
}

int bch2_lru_change(struct btree_trans *trans,
		    u16 lru_id, u64 dev_bucket,
		    u64 old_time, u64 new_time)
{
	if (old_time == new_time)
		return 0;

	return  __bch2_lru_set(trans, lru_id, dev_bucket, old_time, false) ?:
		__bch2_lru_set(trans, lru_id, dev_bucket, new_time, true);
}

static const char * const bch2_lru_types[] = {
#define x(n) #n,
	BCH_LRU_TYPES()
#undef x
	NULL
};

/* Returns 1 if key has been deleted */
int bch2_check_lru_key(struct btree_trans *trans,
		       struct btree_iter *lru_iter,
		       struct bkey_s_c lru_k,
		       struct bpos *last_flushed_pos)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a;
	struct printbuf buf1 = PRINTBUF;
	struct printbuf buf2 = PRINTBUF;
	struct bpos alloc_pos = u64_to_bucket(lru_k.k->p.offset);
	u64 idx;
	int ret;

	if (fsck_err_on(!bch2_dev_bucket_exists(c, alloc_pos), c,
			lru_entry_to_invalid_bucket,
			"lru key points to nonexistent device:bucket %llu:%llu",
			alloc_pos.inode, alloc_pos.offset))
		goto delete;

	k = bch2_bkey_get_iter(trans, &iter, BTREE_ID_alloc, alloc_pos, 0);
	ret = bkey_err(k);
	if (ret)
		goto err;

	a = bch2_alloc_to_v4(k, &a_convert);

	enum bch_lru_type type = lru_type(lru_k);
	switch (type) {
	case BCH_LRU_read:
		idx = alloc_lru_idx_read(*a);
		break;
	case BCH_LRU_fragmentation:
		idx = a->fragmentation_lru;
		break;
	default:
		/* unknown LRU type, don't check: */
		goto out;
	}

	if (lru_k.k->type != KEY_TYPE_set ||
	    lru_pos_time(lru_k.k->p) != idx) {
		if (!bpos_eq(*last_flushed_pos, lru_k.k->p)) {
			ret = bch2_btree_write_buffer_flush_sync(trans);
			if (!ret) {
				*last_flushed_pos = lru_k.k->p;
				ret = -BCH_ERR_transaction_restart_write_buffer_flush;
			}
			goto out;
		}

		if ((c->opts.reconstruct_alloc &&
		     c->curr_recovery_pass <= BCH_RECOVERY_PASS_check_lrus) ||
		    fsck_err(c, lru_entry_bad,
			     "incorrect lru entry: lru %s time %llu\n"
			     "  %s\n"
			     "for\n"
			     "  %s",
			     bch2_lru_types[type],
			     lru_pos_time(lru_k.k->p),
			     (bch2_bkey_val_to_text(&buf1, c, lru_k), buf1.buf),
			     (bch2_bkey_val_to_text(&buf2, c, k), buf2.buf)))
			goto delete;
	}
out:
err:
fsck_err:
	bch2_trans_iter_exit(trans, &iter);
	printbuf_exit(&buf2);
	printbuf_exit(&buf1);
	return ret;
delete:
	ret =   bch2_btree_delete_at(trans, lru_iter, 0) ?:
		bch2_trans_commit(trans, NULL, NULL,
				  BCH_WATERMARK_btree|
				  BCH_TRANS_COMMIT_lazy_rw|
				  BCH_TRANS_COMMIT_no_enospc) ?:
		1;
	goto out;
}

int bch2_check_lrus(struct bch_fs *c)
{
	struct bpos last_flushed_pos = POS_MIN;

	int ret = bch2_trans_run(c,
		for_each_btree_key(trans, iter,
				BTREE_ID_lru, POS_MIN, BTREE_ITER_PREFETCH, k, ({
			int ret2 = bch2_check_lru_key(trans, &iter, k, &last_flushed_pos);

			ret2 < 0 ? ret2 : 0;
		})));
	bch_err_fn(c, ret);
	return ret;
}
