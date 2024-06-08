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
		     enum bch_validate_flags flags,
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

static int __bch2_lru_set(struct btree_trans *trans, u16 lru_id,
			  u64 dev_bucket, u64 time, bool set)
{
	return time
		? bch2_btree_bit_mod_buffered(trans, BTREE_ID_lru,
					      lru_pos(lru_id, dev_bucket, time), set)
		: 0;
}

int bch2_lru_del(struct btree_trans *trans, u16 lru_id, u64 dev_bucket, u64 time)
{
	return __bch2_lru_set(trans, lru_id, dev_bucket, time, KEY_TYPE_deleted);
}

int bch2_lru_set(struct btree_trans *trans, u16 lru_id, u64 dev_bucket, u64 time)
{
	return __bch2_lru_set(trans, lru_id, dev_bucket, time, KEY_TYPE_set);
}

int bch2_lru_change(struct btree_trans *trans,
		    u16 lru_id, u64 dev_bucket,
		    u64 old_time, u64 new_time)
{
	if (old_time == new_time)
		return 0;

	return  bch2_lru_del(trans, lru_id, dev_bucket, old_time) ?:
		bch2_lru_set(trans, lru_id, dev_bucket, new_time);
}

static const char * const bch2_lru_types[] = {
#define x(n) #n,
	BCH_LRU_TYPES()
#undef x
	NULL
};

static int bch2_check_lru_key(struct btree_trans *trans,
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
	enum bch_lru_type type = lru_type(lru_k);
	struct bpos alloc_pos = u64_to_bucket(lru_k.k->p.offset);
	u64 idx;
	int ret;

	if (fsck_err_on(!bch2_dev_bucket_exists(c, alloc_pos),
			trans, lru_entry_to_invalid_bucket,
			"lru key points to nonexistent device:bucket %llu:%llu",
			alloc_pos.inode, alloc_pos.offset))
		return bch2_btree_delete_at(trans, lru_iter, 0);

	k = bch2_bkey_get_iter(trans, &iter, BTREE_ID_alloc, alloc_pos, 0);
	ret = bkey_err(k);
	if (ret)
		goto err;

	a = bch2_alloc_to_v4(k, &a_convert);

	switch (type) {
	case BCH_LRU_read:
		idx = alloc_lru_idx_read(*a);
		break;
	case BCH_LRU_fragmentation:
		idx = a->fragmentation_lru;
		break;
	}

	if (lru_k.k->type != KEY_TYPE_set ||
	    lru_pos_time(lru_k.k->p) != idx) {
		if (!bpos_eq(*last_flushed_pos, lru_k.k->p)) {
			*last_flushed_pos = lru_k.k->p;
			ret = bch2_btree_write_buffer_flush_sync(trans) ?:
				-BCH_ERR_transaction_restart_write_buffer_flush;
			goto out;
		}

		if (fsck_err(trans, lru_entry_bad,
			     "incorrect lru entry: lru %s time %llu\n"
			     "  %s\n"
			     "  for %s",
			     bch2_lru_types[type],
			     lru_pos_time(lru_k.k->p),
			     (bch2_bkey_val_to_text(&buf1, c, lru_k), buf1.buf),
			     (bch2_bkey_val_to_text(&buf2, c, k), buf2.buf)))
			ret = bch2_btree_delete_at(trans, lru_iter, 0);
	}
out:
err:
fsck_err:
	bch2_trans_iter_exit(trans, &iter);
	printbuf_exit(&buf2);
	printbuf_exit(&buf1);
	return ret;
}

int bch2_check_lrus(struct bch_fs *c)
{
	struct bpos last_flushed_pos = POS_MIN;
	int ret = bch2_trans_run(c,
		for_each_btree_key_commit(trans, iter,
				BTREE_ID_lru, POS_MIN, BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc|BCH_TRANS_COMMIT_lazy_rw,
			bch2_check_lru_key(trans, &iter, k, &last_flushed_pos)));
	bch_err_fn(c, ret);
	return ret;

}
