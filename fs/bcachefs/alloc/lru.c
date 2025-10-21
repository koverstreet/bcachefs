// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/background.h"
#include "alloc/lru.h"

#include "btree/bkey_buf.h"
#include "btree/iter.h"
#include "btree/update.h"
#include "btree/write_buffer.h"

#include "data/ec.h"

#include "init/error.h"
#include "init/progress.h"
#include "init/recovery.h"

/* KEY_TYPE_lru is obsolete: */
int bch2_lru_validate(struct bch_fs *c, struct bkey_s_c k,
		      struct bkey_validate_context from)
{
	int ret = 0;

	bkey_fsck_err_on(!lru_pos_time(k.k->p),
			 c, lru_entry_at_time_0,
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

static int bch2_lru_set(struct btree_trans *trans, u16 lru_id, u64 dev_bucket, u64 time)
{
	return __bch2_lru_set(trans, lru_id, dev_bucket, time, true);
}

int __bch2_lru_change(struct btree_trans *trans,
		      u16 lru_id, u64 dev_bucket,
		      u64 old_time, u64 new_time)
{
	return  __bch2_lru_set(trans, lru_id, dev_bucket, old_time, false) ?:
		__bch2_lru_set(trans, lru_id, dev_bucket, new_time, true);
}

static const char * const bch2_lru_types[] = {
#define x(n) #n,
	BCH_LRU_TYPES()
#undef x
	NULL
};

int bch2_lru_check_set(struct btree_trans *trans,
		       u16 lru_id,
		       u64 dev_bucket,
		       u64 time,
		       struct bkey_s_c referring_k,
		       struct wb_maybe_flush *last_flushed)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	CLASS(btree_iter, lru_iter)(trans, BTREE_ID_lru, lru_pos(lru_id, dev_bucket, time), 0);
	struct bkey_s_c lru_k = bkey_try(bch2_btree_iter_peek_slot(&lru_iter));

	if (lru_k.k->type != KEY_TYPE_set) {
		try(bch2_btree_write_buffer_maybe_flush(trans, referring_k, last_flushed));

		CLASS(printbuf, buf)();
		prt_printf(&buf, "missing %s lru entry at pos ", bch2_lru_types[lru_type(lru_k)]);
		bch2_bpos_to_text(&buf, lru_iter.pos);
		prt_newline(&buf);
		bch2_bkey_val_to_text(&buf, c, referring_k);

		if (fsck_err(trans, alloc_key_to_missing_lru_entry, "%s", buf.buf))
			try(bch2_lru_set(trans, lru_id, dev_bucket, time));
	}
fsck_err:
	return ret;
}

static struct bbpos lru_pos_to_bp(struct bkey_s_c lru_k)
{
	enum bch_lru_type type = lru_type(lru_k);

	switch (type) {
	case BCH_LRU_read:
	case BCH_LRU_fragmentation:
		return BBPOS(BTREE_ID_alloc, u64_to_bucket(lru_k.k->p.offset));
	case BCH_LRU_stripes:
		return BBPOS(BTREE_ID_stripes, POS(0, lru_k.k->p.offset));
	default:
		BUG();
	}
}

int bch2_dev_remove_lrus(struct bch_fs *c, struct bch_dev *ca)
{
	CLASS(btree_trans, trans)(c);
	int ret = bch2_btree_write_buffer_flush_sync(trans) ?:
		for_each_btree_key(trans, iter,
				 BTREE_ID_lru, POS_MIN, BTREE_ITER_prefetch, k, ({
		struct bbpos bp = lru_pos_to_bp(k);

		bp.btree == BTREE_ID_alloc && bp.pos.inode == ca->dev_idx
		? (bch2_btree_delete_at(trans, &iter, 0) ?:
		   bch2_trans_commit(trans, NULL, NULL, 0))
		: 0;
	}));
	bch_err_fn(c, ret);
	return ret;
}

static u64 bkey_lru_type_idx(struct bch_fs *c,
			     enum bch_lru_type type,
			     struct bkey_s_c k)
{
	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a;

	switch (type) {
	case BCH_LRU_read:
		a = bch2_alloc_to_v4(k, &a_convert);
		return alloc_lru_idx_read(*a);
	case BCH_LRU_fragmentation: {
		a = bch2_alloc_to_v4(k, &a_convert);

		guard(rcu)();
		struct bch_dev *ca = bch2_dev_rcu_noerror(c, k.k->p.inode);
		return ca
			? alloc_lru_idx_fragmentation(*a, ca)
			: 0;
	}
	case BCH_LRU_stripes:
		return k.k->type == KEY_TYPE_stripe
			? stripe_lru_pos(bkey_s_c_to_stripe(k).v)
			: 0;
	default:
		BUG();
	}
}

static int bch2_check_lru_key(struct btree_trans *trans,
			      struct btree_iter *lru_iter,
			      struct bkey_s_c lru_k,
			      struct wb_maybe_flush *last_flushed)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf1)();
	CLASS(printbuf, buf2)();
	int ret = 0;

	struct bbpos bp = lru_pos_to_bp(lru_k);

	CLASS(btree_iter, iter)(trans, bp.btree, bp.pos, 0);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	enum bch_lru_type type = lru_type(lru_k);
	u64 idx = bkey_lru_type_idx(c, type, k);

	if (lru_pos_time(lru_k.k->p) != idx) {
		try(bch2_btree_write_buffer_maybe_flush(trans, lru_k, last_flushed));

		if (fsck_err(trans, lru_entry_bad,
			     "incorrect lru entry: lru %s time %llu\n"
			     "%s\n"
			     "for %s",
			     bch2_lru_types[type],
			     lru_pos_time(lru_k.k->p),
			     (bch2_bkey_val_to_text(&buf1, c, lru_k), buf1.buf),
			     (bch2_bkey_val_to_text(&buf2, c, k), buf2.buf)))
			return bch2_btree_bit_mod_buffered(trans, BTREE_ID_lru, lru_iter->pos, false);
	}
fsck_err:
	return ret;
}

int bch2_check_lrus(struct bch_fs *c)
{
	struct wb_maybe_flush last_flushed __cleanup(wb_maybe_flush_exit);
	wb_maybe_flush_init(&last_flushed);

	struct progress_indicator_state progress;
	bch2_progress_init(&progress, c, BIT_ULL(BTREE_ID_lru));

	CLASS(btree_trans, trans)(c);
	return for_each_btree_key_commit(trans, iter,
				BTREE_ID_lru, POS_MIN, BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		progress_update_iter(trans, &progress, &iter) ?:
		wb_maybe_flush_inc(&last_flushed) ?:
		bch2_check_lru_key(trans, &iter, k, &last_flushed);
	}));
}
