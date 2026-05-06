// SPDX-License-Identifier: GPL-2.0

/* DOC(btree-write-buffer)
 *
 * Batching layer for btrees that receive many small updates which are more
 * efficient to apply in bulk. Backpointers, LRU entries, and accounting
 * updates are written to the write buffer rather than directly to the btree;
 * the buffer is sorted and flushed periodically, coalescing updates to the
 * same key and amortizing the cost of btree traversal across many updates.
 */

#include "bcachefs.h"

#include "alloc/accounting.h"

#include "btree/bkey_buf.h"
#include "btree/locking.h"
#include "btree/update.h"
#include "btree/interior.h"
#include "btree/write_buffer.h"

#include "data/extents.h"

#include "journal/journal.h"
#include "journal/read.h"
#include "journal/reclaim.h"

#include "init/error.h"

#include "sb/counters.h"

#include "util/enumerated_ref.h"

#include <linux/prefetch.h>
#include <linux/sort.h>

/*
 * Catch the "added BTREE_IS_write_buffer but forgot BCH_WRITE_BUFFER_BTREES"
 * footgun at compile time: count the write_buffer bits in BCH_BTREE_IDS() and
 * compare against BCH_WB_BTREE_NR.
 */
enum {
#define x(name, nr, flags, ...)	+ !!((flags) & BTREE_IS_write_buffer)
	__bch_wb_btree_nr_check = 0 BCH_BTREE_IDS(),
#undef x
};
static_assert((int)__bch_wb_btree_nr_check == (int)BCH_WB_BTREE_NR,
	"BCH_WRITE_BUFFER_BTREES() is out of sync with BCH_BTREE_IDS() write_buffer flags");

static const char * const wb_flush_caller_names[] = {
#define x(n)	#n,
	WB_FLUSH_CALLERS()
#undef x
	NULL,
};

static const char * const bch_wb_btree_names[] = {
#define x(name)	#name,
	BCH_WRITE_BUFFER_BTREES()
#undef x
};

static int bch2_btree_write_buffer_journal_flush(struct journal *,
				struct journal_entry_pin *, u64);

static inline bool __wb_key_ref_cmp(const struct wb_key_ref *l, const struct wb_key_ref *r)
{
	return (cmp_int(l->hi, r->hi) ?:
		cmp_int(l->mi, r->mi) ?:
		cmp_int(l->lo, r->lo)) >= 0;
}

static inline bool wb_key_ref_cmp(const struct wb_key_ref *l, const struct wb_key_ref *r)
{
#ifdef CONFIG_X86_64
	int cmp;

	asm("mov   (%[l]), %%rax;"
	    "sub   (%[r]), %%rax;"
	    "mov  8(%[l]), %%rax;"
	    "sbb  8(%[r]), %%rax;"
	    "mov 16(%[l]), %%rax;"
	    "sbb 16(%[r]), %%rax;"
	    : "=@ccae" (cmp)
	    : [l] "r" (l), [r] "r" (r)
	    : "rax", "cc");

	EBUG_ON(cmp != __wb_key_ref_cmp(l, r));
	return cmp;
#else
	return __wb_key_ref_cmp(l, r);
#endif
}

static int wb_key_seq_cmp(const void *_l, const void *_r, const void *priv)
{
	const struct btree_write_buffer_keys *keys = priv;
	const struct wb_key_ref *l = _l;
	const struct wb_key_ref *r = _r;

	return cmp_int(wb_keys_idx(keys, l->idx)->journal_seq,
		       wb_keys_idx(keys, r->idx)->journal_seq);
}

/* Compare excluding idx, the low 24 bits: */
static inline bool wb_key_eq(const void *_l, const void *_r)
{
	const struct wb_key_ref *l = _l;
	const struct wb_key_ref *r = _r;

	return !((l->hi ^ r->hi)|
		 (l->mi ^ r->mi)|
		 ((l->lo >> 24) ^ (r->lo >> 24)));
}

static noinline void wb_sort(struct wb_key_ref *base, size_t num)
{
	size_t n = num, a = num / 2;

	if (!a)		/* num < 2 || size == 0 */
		return;

	for (;;) {
		size_t b, c, d;

		if (a)			/* Building heap: sift down --a */
			--a;
		else if (--n)		/* Sorting: Extract root to --n */
			swap(base[0], base[n]);
		else			/* Sort complete */
			break;

		/*
		 * Sift element at "a" down into heap.  This is the
		 * "bottom-up" variant, which significantly reduces
		 * calls to cmp_func(): we find the sift-down path all
		 * the way to the leaves (one compare per level), then
		 * backtrack to find where to insert the target element.
		 *
		 * Because elements tend to sift down close to the leaves,
		 * this uses fewer compares than doing two per level
		 * on the way down.  (A bit more than half as many on
		 * average, 3/4 worst-case.)
		 */
		for (b = a; c = 2*b + 1, (d = c + 1) < n;)
			b = wb_key_ref_cmp(base + c, base + d) ? c : d;
		if (d == n)		/* Special case last leaf with no sibling */
			b = c;

		/* Now backtrack from "b" to the correct location for "a" */
		while (b != a && wb_key_ref_cmp(base + a, base + b))
			b = (b - 1) / 2;
		c = b;			/* Where "a" belongs */
		while (b != a) {	/* Shift it into place */
			b = (b - 1) / 2;
			swap(base[b], base[c]);
		}
	}
}

static noinline int wb_flush_one_slowpath(struct btree_trans *trans,
					  struct btree_iter *iter,
					  struct btree_write_buffered_key *wb)
{
	struct btree_path *path = btree_iter_path(trans, iter);

	bch2_btree_node_unlock_write(trans, path, path->l[0].b);

	trans->journal_res.seq = wb->journal_seq;

	return bch2_trans_update(trans, iter, &wb->k,
				 BTREE_UPDATE_internal_snapshot_node) ?:
		bch2_trans_commit(trans, NULL, NULL,
				  BCH_WATERMARK_reclaim|
				  BCH_TRANS_COMMIT_no_enospc|
				  BCH_TRANS_COMMIT_no_check_rw|
				  BCH_TRANS_COMMIT_no_journal_res|
				  BCH_TRANS_COMMIT_no_skip_noops|
				  BCH_TRANS_COMMIT_journal_reclaim);
}

static inline int wb_flush_one(struct btree_trans *trans,
			       struct bch_fs_btree_write_buffer *wbb,
			       struct btree_iter *iter,
			       struct btree_write_buffered_key *wb,
			       bool *write_locked,
			       bool *accounting_accumulated,
			       size_t *fast, size_t *noop)
{
	struct btree_path *path;

	EBUG_ON(!wb->journal_seq);
	EBUG_ON(!wbb->flushing.pin.seq);
	EBUG_ON(wbb->flushing.pin.seq > wb->journal_seq);

	try(bch2_btree_iter_traverse(iter));

	if (!*accounting_accumulated && wb->k.k.type == KEY_TYPE_accounting) {
		struct bkey u;
		struct bkey_s_c k = bch2_btree_path_peek_slot_exact(btree_iter_path(trans, iter), &u);

		if (k.k->type == KEY_TYPE_accounting)
			bch2_accounting_accumulate_maybe_kill(trans->c,
					bkey_i_to_accounting(&wb->k),
					bkey_s_c_to_accounting(k));
	}
	*accounting_accumulated = true;

	/*
	 * We can't clone a path that has write locks: unshare it now, before
	 * set_pos and traverse():
	 */
	if (btree_iter_path(trans, iter)->ref > 1)
		iter->path = __bch2_btree_path_make_mut(trans, iter->path, true, _THIS_IP_);

	path = btree_iter_path(trans, iter);

	struct btree_path_level *l = path_l(path);
	struct bkey_packed *old_p = bch2_btree_node_iter_peek_all(&l->iter, l->b);
	if (old_p && bkey_cmp_left_packed(l->b, old_p, &wb->k.k.p))
		old_p = NULL;

	struct bkey old_u;
	struct bkey_s_c old = old_p
		? bkey_disassemble(l->b, old_p, &old_u)
		: bkey_s_c_null;

	if (old.k && bkey_and_val_eq(old, bkey_i_to_s_c(&wb->k))) {
		(*noop)++;
		return 0;
	}

	struct btree *b = path->l[0].b;

	if (!*write_locked) {
		try(bch2_btree_node_lock_write(trans, path, &b->c));

		bch2_btree_node_prep_for_write(trans, path, b);
		*write_locked = true;
	}

	if (unlikely(!bch2_btree_node_insert_fits(b, wb->k.k.u64s))) {
		*write_locked = false;
		return wb_flush_one_slowpath(trans, iter, wb);
	}

	EBUG_ON(!bpos_eq(wb->k.k.p, path->pos));

	bch2_btree_insert_key_leaf(trans, path, &wb->k, wb->journal_seq);
	(*fast)++;

	if (unlikely(btree_node_needs_merge(trans->c, b, 0)))
		bch2_async_btree_op(trans->c, b, ASYNC_BTREE_merge);

	return 0;
}

/*
 * Update a btree with a write buffered key using the journal seq of the
 * original write buffer insert.
 *
 * It is not safe to rejournal the key once it has been inserted into the write
 * buffer because that may break recovery ordering. For example, the key may
 * have already been modified in the active write buffer in a seq that comes
 * before the current transaction. If we were to journal this key again and
 * crash, recovery would process updates in the wrong order.
 */
static int
btree_write_buffered_insert(struct btree_trans *trans,
			    enum btree_id btree,
			    struct btree_write_buffered_key *wb)
{
	CLASS(btree_iter, iter)(trans, btree, bkey_start_pos(&wb->k.k),
				BTREE_ITER_cached|BTREE_ITER_intent);

	trans->journal_res.seq = wb->journal_seq;

	return  bch2_btree_iter_traverse(&iter) ?:
		bch2_trans_update(trans, &iter, &wb->k,
				  BTREE_UPDATE_internal_snapshot_node);
}

static void move_keys_from_inc_to_flushing(struct bch_fs_btree_write_buffer *wb)
{
	struct bch_fs *c = wb->c;
	struct journal *j = &c->journal;

	if (!wb->inc.keys.nr)
		return;

	bch2_journal_pin_add(j, wb_keys_start(&wb->inc)->journal_seq, &wb->flushing.pin,
			     bch2_btree_write_buffer_journal_flush);

	/* Best-effort resizes; may fail under memory pressure */
	darray_resize(&wb->flushing.keys, min_t(size_t, 1U << 20, wb->flushing.keys.nr + wb->inc.keys.nr));
	darray_resize(&wb->sorted, wb->flushing.keys.size);

	/*
	 * Each sorted entry references one key, and each key is at least
	 * BKEY_U64s u64s, so this is a conservative bound on the number
	 * of u64s we can put in flushing while still being able to sort them.
	 */
	size_t sorted_can_address = wb->sorted.size * BKEY_U64s;

	/* Fast path: flushing is empty, just swap the buffers */
	if (!wb->flushing.keys.nr && sorted_can_address >= wb->inc.keys.nr) {
		swap(wb->flushing.keys, wb->inc.keys);
		goto out;
	}

	/* All of inc fits: bulk copy */
	if (wb->flushing.keys.nr + wb->inc.keys.nr <=
	    min(wb->flushing.keys.size, sorted_can_address)) {
		memcpy(&darray_top(wb->flushing.keys),
		       wb->inc.keys.data,
		       sizeof(wb->inc.keys.data[0]) * wb->inc.keys.nr);
		wb->flushing.keys.nr += wb->inc.keys.nr;
		wb->inc.keys.nr = 0;
	} else {
		/* Partial copy: move as many keys as will fit */
		wb_keys_for_each(&wb->inc, i) {
			if (wb->flushing.keys.nr + wb_key_u64s(&i->k) <=
			    min(wb->flushing.keys.size, sorted_can_address)) {
				memcpy_u64s(&darray_top(wb->flushing.keys), i,
					    wb_key_u64s(&i->k));
				wb->flushing.keys.nr += wb_key_u64s(&i->k);
			} else {
				size_t nr = (u64 *) i - wb->inc.keys.data;
				memmove(wb->inc.keys.data,
					wb->inc.keys.data + nr,
					sizeof(wb->inc.keys.data[0]) * (wb->inc.keys.nr - nr));
				wb->inc.keys.nr	 -= nr;
				break;
			}
		}
	}
out:
	if (!wb->inc.keys.nr)
		bch2_journal_pin_drop(j, &wb->inc.pin);
	else
		bch2_journal_pin_update(j, wb_keys_start(&wb->inc)->journal_seq, &wb->inc.pin,
					bch2_btree_write_buffer_journal_flush);

	if (test_bit(JOURNAL_low_on_wb, &j->flags) && !bch2_btree_write_buffer_must_wait(c)) {
		guard(spinlock)(&j->lock);
		bch2_journal_set_watermark(j);
	}

	BUG_ON(wb->sorted.size * BKEY_U64s < wb->flushing.keys.nr);
}

int bch2_btree_write_buffer_insert_err(struct bch_fs *c,
				       enum btree_id btree, struct bkey_i *k)
{
	CLASS(printbuf, buf)();

	prt_printf(&buf, "attempting to do write buffer update on non wb btree=");
	bch2_btree_id_to_text(&buf, btree);
	prt_str(&buf, "\n");
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(k));

	bch2_fs_inconsistent(c, "%s", buf.buf);
	return -EROFS;
}

struct wb_flush_counters {
	size_t			fast;
	size_t			noop;
	size_t			slowpath;
};

/*
 * Flush a contiguous slice of wb->sorted ([start, end)) via the fastpath.
 *
 * The slice is keyspace-disjoint by construction (sorted by btree, pos), so
 * multiple calls with non-overlapping ranges and independent btree_trans's
 * may safely run in parallel: the only shared writes are to
 * wb->flushing.keys.data[i->idx] for i in [start, end), which is per-slice.
 *
 * Same-pos coalesce-and-accumulate is done by the caller before this runs
 * (and only for accounting), so each slice is duplicate-free and sharding is
 * straightforward.
 */
static int wb_flush_sorted_range(struct btree_trans *trans,
				 struct bch_fs_btree_write_buffer *wb,
				 size_t start, size_t end,
				 bool accounting_replay_done,
				 struct wb_flush_counters *cnt)
{
	struct bch_fs *c = trans->c;
	enum btree_id btree = bch_wb_btree_to_btree_id(wb->idx);
	bool write_locked = false;
	int ret = 0;

	bch2_trans_begin(trans);

	CLASS(btree_iter, iter)(trans, btree, POS_MIN,
				BTREE_ITER_intent|BTREE_ITER_all_snapshots);

	struct wb_key_ref *base = wb->sorted.data;
	struct wb_key_ref *slice_end = base + end;

	for (struct wb_key_ref *i = base + start; i < slice_end; i++) {
		if (i->idx + BKEY_U64s > wb->flushing.keys.nr)
			panic("at %zu/%zu of wb->sorted got idx %u/%zu\n",
			      i - base,
			      wb->sorted.nr,
			      i->idx,
			      wb->flushing.keys.nr);

		struct btree_write_buffered_key *k = wb_keys_idx(&wb->flushing, i->idx);

		ret = bch2_btree_write_buffer_insert_checks(c, btree, &k->k);
		if (unlikely(ret))
			break;

		for (struct wb_key_ref *n = i + 1; n < min(i + 4, slice_end); n++)
			prefetch(&wb->flushing.keys.data[n->idx]);

		BUG_ON(!k->journal_seq);

		if (!accounting_replay_done &&
		    k->k.k.type == KEY_TYPE_accounting) {
			cnt->slowpath++;
			continue;
		}

		if (write_locked) {
			struct btree_path *path = btree_iter_path(trans, &iter);

			if (bpos_gt(k->k.k.p, path->l[0].b->key.k.p)) {
				bch2_btree_node_unlock_write(trans, path, path->l[0].b);
				write_locked = false;
			}
		}

		bch2_btree_iter_set_pos(&iter, k->k.k.p);
		btree_iter_path(trans, &iter)->preserve = false;

		bool accounting_accumulated = false;
		do {
			if (race_fault()) {
				ret = bch_err_throw(c, journal_reclaim_would_deadlock);
				break;
			}

			ret = wb_flush_one(trans, wb, &iter, k, &write_locked,
					   &accounting_accumulated, &cnt->fast, &cnt->noop);
			if (!write_locked)
				bch2_trans_begin(trans);
		} while (bch2_err_matches(ret, BCH_ERR_transaction_restart));

		if (!ret) {
			k->journal_seq = 0;
		} else if (ret == -BCH_ERR_journal_reclaim_would_deadlock) {
			cnt->slowpath++;
			ret = 0;
		} else
			break;
	}

	if (write_locked) {
		struct btree_path *path = btree_iter_path(trans, &iter);
		bch2_btree_node_unlock_write(trans, path, path->l[0].b);
	}

	return ret;
}

/*
 * Sharded fastpath. Threshold and shard cap are deliberately conservative:
 * fork/join + per-shard btree_trans setup isn't free, and we need each
 * shard to do enough work to amortize that. Tune empirically.
 */
#define WB_FLUSH_SHARD_MIN_KEYS		(1UL << 12)

static unsigned wb_flush_n_shards(size_t n_keys)
{
	return clamp_t(size_t, n_keys / WB_FLUSH_SHARD_MIN_KEYS, 1, num_online_cpus());
}

typedef struct {
	struct closure			cl;
	struct bch_fs			*c;
	struct bch_fs_btree_write_buffer *wb;
	size_t				start;
	size_t				end;
	bool				accounting_replay_done;
	struct wb_flush_counters	cnt;
	int				ret;
} wb_flush_shard;
DEFINE_DARRAY(wb_flush_shard);

static CLOSURE_CALLBACK(wb_flush_shard_work)
{
	closure_type(s, wb_flush_shard, cl);
	CLASS(btree_trans, trans)(s->c);

	s->ret = wb_flush_sorted_range(trans, s->wb, s->start, s->end,
				       s->accounting_replay_done, &s->cnt);

	closure_return(cl);
}

static int wb_flush_sorted_sharded(struct btree_trans *trans,
				   struct bch_fs_btree_write_buffer *wb,
				   bool accounting_replay_done,
				   struct wb_flush_counters *cnt)
{
	struct bch_fs *c = trans->c;
	size_t n_keys = wb->sorted.nr;
	unsigned n_shards = wb_flush_n_shards(n_keys);

	if (n_shards <= 1)
		return wb_flush_sorted_range(trans, wb, 0, n_keys,
					     accounting_replay_done, cnt);

	CLASS(darray_wb_flush_shard, shards)();
	int ret = darray_make_room(&shards, n_shards);
	if (ret)
		/* OOM: fall back to single-shard inline path. */
		return wb_flush_sorted_range(trans, wb, 0, n_keys,
					     accounting_replay_done, cnt);

	CLASS(closure_stack, cl)();

	for (unsigned i = 0; i < n_shards; i++)
		darray_push(&shards, ((wb_flush_shard) {
			.c			= c,
			.wb			= wb,
			.start			= (n_keys * i) / n_shards,
			.end			= (n_keys * (i + 1)) / n_shards,
			.accounting_replay_done	= accounting_replay_done,
		}));

	darray_for_each(shards, i)
		closure_call(&i->cl, wb_flush_shard_work, c->btree.write_buffer_shard_wq, &cl);

	closure_sync_unbounded(&cl);

	darray_for_each(shards, s) {
		if (s->ret && !ret)
			ret = s->ret;
		cnt->fast	+= s->cnt.fast;
		cnt->noop	+= s->cnt.noop;
		cnt->slowpath	+= s->cnt.slowpath;
	}

	return ret;
}

static int bch2_btree_write_buffer_flush_locked(struct btree_trans *trans,
						enum bch_wb_btree idx,
						enum wb_flush_caller caller)
{
	struct bch_fs *c = trans->c;
	struct journal *j = &c->journal;
	struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[idx];
	enum btree_id btree = bch_wb_btree_to_btree_id(idx);
	struct wb_flush_counters cnt = {};
	size_t could_not_insert = 0;
	bool accounting_replay_done = test_bit(BCH_FS_accounting_replay_done, &c->flags);
	int ret = 0;

	try(bch2_journal_error(&c->journal));

	scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
		guard(mutex)(&wb->inc.lock);
		move_keys_from_inc_to_flushing(wb);
	}

	if (!wb->flushing.keys.nr)
		return 0;

	u64 start_time = local_clock();
	u64 nr_flushing = wb->flushing.keys.nr;

	wb_keys_for_each(&wb->flushing, k)
		BUG_ON(k->journal_seq > journal_cur_seq(&c->journal));

	wb->sorted.nr = 0;
	wb_keys_for_each(&wb->flushing, k) {
		if (wb->sorted.nr == wb->sorted.size)
			panic("Overflowed wb->sorted at %zu, flushing size %zu\n",
			      wb->sorted.nr, wb->flushing.keys.nr);

		struct wb_key_ref *dst = &darray_top(wb->sorted);
		wb->sorted.nr++;

		dst->idx	= (u64 *) k - wb->flushing.keys.data;
		memcpy(&dst->pos, &k->k.k.p, sizeof(struct bpos));
	}

	/*
	 * We first sort so that we can detect and skip redundant updates, and
	 * then we attempt to flush in sorted btree order, as this is most
	 * efficient.
	 *
	 * However, since we're not flushing in the order they appear in the
	 * journal we won't be able to drop our journal pin until everything is
	 * flushed - which means this could deadlock the journal if we weren't
	 * passing BCH_TRANS_COMMIT_journal_reclaim. This causes the update to fail
	 * if it would block taking a journal reservation.
	 *
	 * If that happens, simply skip the key so we can optimistically insert
	 * as many keys as possible in the fast path.
	 */
	wb_sort(wb->sorted.data, wb->sorted.nr);

	/*
	 * Pre-flush dedup: collapse adjacent same-pos entries.
	 *
	 * After wb_sort, same-pos keys sit adjacent in wb->sorted, ordered
	 * by idx (which is journal-insertion order: lower idx = earlier
	 * write). For all btrees we drop the older entry in each same-pos
	 * run and keep the newest. For accounting, where each entry is a
	 * delta, we first accumulate the older value into the newer one,
	 * yielding a single combined delta per pos.
	 *
	 * The dropped entry's journal_seq must be zeroed: the slowpath and
	 * could_not_insert compaction iterate wb->flushing.keys directly
	 * (not wb->sorted), and retain anything with non-zero journal_seq.
	 * If we leave the dropped accounting entry alive in flushing, the
	 * next flush's dedup would re-accumulate the already-accumulated
	 * value into the survivor, multiplying the delta.
	 *
	 * This must run single-threaded before the sharded fastpath: the
	 * partitioner splits wb->sorted by index, so a same-pos run
	 * straddling a shard seam would otherwise be flushed in
	 * non-deterministic order — an older write could clobber a newer
	 * one. Collapsing same-pos runs here removes the constraint
	 * entirely; shards see a slice with at most one entry per pos and
	 * don't need to depend on sort-order semantics.
	 */
	{
		struct wb_key_ref *src_end = wb->sorted.data + wb->sorted.nr;
		struct wb_key_ref *dst = wb->sorted.data;

		for (struct wb_key_ref *src = wb->sorted.data; src < src_end; src++) {
			if (src + 1 < src_end && wb_key_eq(src, src + 1)) {
				struct btree_write_buffered_key *k =
					wb_keys_idx(&wb->flushing, src->idx);
				struct btree_write_buffered_key *n =
					wb_keys_idx(&wb->flushing, src[1].idx);

				/* Accounting: accumulate older delta into newer entry. */
				if (k->k.k.type == KEY_TYPE_accounting &&
				    n->k.k.type == KEY_TYPE_accounting) {
					bch2_accounting_accumulate(bkey_i_to_accounting(&n->k),
								   bkey_i_to_s_c_accounting(&k->k));
					n->journal_seq = min_t(u64, n->journal_seq, k->journal_seq);
				}
				/* Drop older entry; newer (src + 1) wins. */
				k->journal_seq = 0;
				continue;
			}
			if (dst != src)
				*dst = *src;
			dst++;
		}
		wb->sorted.nr = dst - wb->sorted.data;
	}

	ret = wb_flush_sorted_sharded(trans, wb, accounting_replay_done, &cnt);
	if (ret)
		goto err;

	if (cnt.slowpath) {
		wb_keys_for_each(&wb->flushing, k)
			BUG_ON(k->journal_seq > journal_cur_seq(&c->journal));

		/*
		 * Flush in the order they were present in the journal, so that
		 * we can release journal pins:
		 * The fastpath zapped the seq of keys that were successfully flushed so
		 * we can skip those here.
		 */
		event_inc_trace(c, write_buffer_flush_slowpath, buf,
				prt_printf(&buf, "%zu/%zu", cnt.slowpath, wb->flushing.keys.nr));

		sort_r_nonatomic(wb->sorted.data,
				 wb->sorted.nr,
				 sizeof(wb->sorted.data[0]),
				 wb_key_seq_cmp, NULL,
				 &wb->flushing);

		darray_for_each(wb->sorted, i) {
			struct btree_write_buffered_key *k = wb_keys_idx(&wb->flushing, i->idx);
			if (!k->journal_seq)
				continue;

			BUG_ON(k->journal_seq > journal_cur_seq(&c->journal));

			if (!accounting_replay_done &&
			    k->k.k.type == KEY_TYPE_accounting) {
				could_not_insert++;
				continue;
			}

			if (!could_not_insert)
				bch2_journal_pin_update(j, k->journal_seq, &wb->flushing.pin,
							bch2_btree_write_buffer_journal_flush);

			bch2_trans_begin(trans);

			ret = commit_do(trans, NULL, NULL,
					BCH_WATERMARK_reclaim|
					BCH_TRANS_COMMIT_journal_reclaim|
					BCH_TRANS_COMMIT_no_check_rw|
					BCH_TRANS_COMMIT_no_enospc|
					BCH_TRANS_COMMIT_no_journal_res ,
					btree_write_buffered_insert(trans, btree, k));
			if (ret)
				goto err;

			k->journal_seq = 0;
		}

		/*
		 * If journal replay hasn't finished with accounting keys we
		 * can't flush accounting keys at all - condense them and leave
		 * them for next time.
		 *
		 * Q: Can the write buffer overflow?
		 * A Shouldn't be any actual risk. It's just new accounting
		 * updates that the write buffer can't flush, and those are only
		 * going to be generated by interior btree node updates as
		 * journal replay has to split/rewrite nodes to make room for
		 * its updates.
		 *
		 * And for those new acounting updates, updates to the same
		 * counters get accumulated as they're flushed from the journal
		 * to the write buffer - see the patch for eytzingcer tree
		 * accumulated. So we could only overflow if the number of
		 * distinct counters touched somehow was very large.
		 */
		if (could_not_insert) {
			struct btree_write_buffered_key *dst = wb_keys_start(&wb->flushing);

			wb_keys_for_each_safe(&wb->flushing, i)
				if (i->journal_seq) {
					memmove_u64s_down(dst, i, wb_key_u64s(&i->k));
					dst = wb_key_next(dst);
				}
			wb->flushing.keys.nr = (u64 *) dst - wb->flushing.keys.data;
		}
	}
err:
	if (ret || !could_not_insert) {
		bch2_journal_pin_drop(j, &wb->flushing.pin);
		wb->flushing.keys.nr = 0;
	}

	bch2_fs_fatal_err_on(ret, c, "%s", bch2_err_str(ret));

	bch2_time_stats_update(&c->times[BCH_TIME_btree_write_buffer_flush], start_time);

	wb->nr_flushes++;
	wb->nr_flushes_caller[caller]++;
	wb->nr_keys_flushed		+= nr_flushing;
	wb->nr_keys_fast		+= cnt.fast;
	wb->nr_keys_slowpath		+= cnt.slowpath;

	event_inc_trace(c, write_buffer_flush, buf,
		prt_printf(&buf, "flushed %llu fast %zu noop %zu",
			   nr_flushing, cnt.fast, cnt.noop));

	return ret;
}

static int bch2_journal_keys_to_write_buffer(struct bch_fs *c, struct journal_buf *buf)
{
	struct journal_keys_to_wb dst;
	int ret = 0;

	bch2_journal_keys_to_write_buffer_start(c, &dst, le64_to_cpu(buf->data->seq));

	for_each_jset_entry_type(entry, buf->data, BCH_JSET_ENTRY_write_buffer_keys) {
		jset_entry_for_each_key(entry, k) {
			ret = bch2_journal_key_to_wb(c, &dst, entry->btree_id, k);
			if (ret)
				goto out;
		}

		entry->type = BCH_JSET_ENTRY_btree_keys;
	}
out:
	ret = bch2_journal_keys_to_write_buffer_end(c, &dst) ?: ret;
	return ret;
}

static int fetch_wb_keys_from_journal(struct bch_fs *c, u64 max_seq)
{
	struct journal *j = &c->journal;
	struct journal_buf *buf;
	bool blocked;
	int ret = 0;

	while (!ret && (buf = bch2_next_write_buffer_flush_journal_buf(j, max_seq, &blocked))) {
		ret = bch2_journal_keys_to_write_buffer(c, buf);

		if (!blocked && !ret) {
			guard(spinlock)(&j->lock);
			buf->need_flush_to_write_buffer = false;
		}

		mutex_unlock(&j->buf_lock);

		if (blocked) {
			bch2_journal_unblock(j);
			break;
		}
	}

	return ret;
}

static bool any_wb_pin_le(struct bch_fs *c, u64 max_seq)
{
	for (unsigned i = 0; i < BCH_WB_BTREE_NR; i++) {
		struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[i];
		if ((wb->inc.pin.seq && wb->inc.pin.seq <= max_seq) ||
		    (wb->flushing.pin.seq && wb->flushing.pin.seq <= max_seq))
			return true;
	}
	return false;
}

static int btree_write_buffer_flush_seq(struct btree_trans *trans, u64 max_seq,
					bool *did_work, enum wb_flush_caller caller)
{
	struct bch_fs *c = trans->c;
	int ret = 0, fetch_from_journal_err;

	do {
		bch2_trans_unlock_long(trans);

		fetch_from_journal_err = fetch_wb_keys_from_journal(c, max_seq);

		for (enum bch_wb_btree i = 0; i < BCH_WB_BTREE_NR; i++) {
			struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[i];

			*did_work |= wb->inc.keys.nr || wb->flushing.keys.nr;

			/*
			 * Drop any btree locks left over from the previous
			 * iteration's flush_locked() — its commit_do slowpath
			 * pins paths in the trans beyond the iter we explicitly
			 * exit, and we mustn't hold btree locks while taking
			 * wb->flushing.lock.
			 *
			 * On memory allocation failure, flush_locked()
			 * is not guaranteed to empty wb->inc.
			 */
			bch2_trans_unlock_long(trans);

			scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
				guard(mutex)(&wb->flushing.lock);
				ret = bch2_btree_write_buffer_flush_locked(trans, i, caller);
			}
			if (ret)
				break;
		}
	} while (!ret && (fetch_from_journal_err || any_wb_pin_le(c, max_seq)));

	return ret;
}

/*
 * Flush one specific btree's write buffer up to max_seq. Used by the journal
 * pin callback, which knows which btree's pin fired.
 *
 * We still have to fetch from the journal (journal bufs mix keys from all
 * btrees, and other btrees' keys have to land somewhere), but the flush
 * itself is narrowed to the one btree — the other 10 btrees' flush threads
 * will drain their own pressure.
 */
static int btree_write_buffer_flush_seq_one(struct btree_trans *trans,
					    enum bch_wb_btree idx,
					    u64 max_seq,
					    enum wb_flush_caller caller)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[idx];
	int ret = 0, fetch_from_journal_err;

	do {
		bch2_trans_unlock_long(trans);

		fetch_from_journal_err = fetch_wb_keys_from_journal(c, max_seq);

		scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
			guard(mutex)(&wb->flushing.lock);
			ret = bch2_btree_write_buffer_flush_locked(trans, idx, caller);
		}
	} while (!ret &&
		 (fetch_from_journal_err ||
		  (wb->inc.pin.seq && wb->inc.pin.seq <= max_seq) ||
		  (wb->flushing.pin.seq && wb->flushing.pin.seq <= max_seq)));

	return ret;
}

static int bch2_btree_write_buffer_journal_flush(struct journal *j,
				struct journal_entry_pin *_pin, u64 seq)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct btree_write_buffer_keys *keys =
		container_of(_pin, struct btree_write_buffer_keys, pin);
	CLASS(btree_trans, trans)(c);

	return btree_write_buffer_flush_seq_one(trans, keys->wb_btree, seq,
						WB_FLUSH_journal_pin);
}

int bch2_btree_write_buffer_flush_sync(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	bool did_work = false;

	event_inc_trace(c, write_buffer_flush_sync, buf, prt_str(&buf, trans->fn));

	return btree_write_buffer_flush_seq(trans, journal_cur_seq(&c->journal), &did_work,
					    WB_FLUSH_sync);
}

/*
 * The write buffer requires flushing when going RO: keys in the journal for the
 * write buffer don't have a journal pin yet
 */
bool bch2_btree_write_buffer_flush_going_ro(struct bch_fs *c)
{
	if (bch2_journal_error(&c->journal))
		return false;

	CLASS(btree_trans, trans)(c);
	bool did_work = false;
	btree_write_buffer_flush_seq(trans, journal_cur_seq(&c->journal), &did_work,
				     WB_FLUSH_sync);
	return did_work;
}

static int bch2_btree_write_buffer_flush_nocheck_rw(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	for (enum bch_wb_btree i = 0; i < BCH_WB_BTREE_NR; i++) {
		struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[i];

		if (mutex_trylock(&wb->flushing.lock)) {
			bch2_trans_unlock_long(trans);
			ret = bch2_btree_write_buffer_flush_locked(trans, i, WB_FLUSH_tryflush);
			mutex_unlock(&wb->flushing.lock);
			if (ret)
				break;
		}
	}

	return ret;
}

int bch2_btree_write_buffer_tryflush(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	bool any_keys = false;

	for (unsigned i = 0; i < BCH_WB_BTREE_NR; i++) {
		struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[i];
		if (wb->inc.keys.nr || wb->flushing.keys.nr) {
			any_keys = true;
			break;
		}
	}
	if (!any_keys)
		return 0;

	if (!enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_btree_write_buffer))
		return bch_err_throw(c, erofs_no_writes);

	int ret = bch2_btree_write_buffer_flush_nocheck_rw(trans);
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_btree_write_buffer);
	return ret;
}

/*
 * In check and repair code, when checking references to write buffer btrees we
 * need to issue a flush before we have a definitive error: this issues a flush
 * if this is a key we haven't yet checked.
 */
int bch2_btree_write_buffer_maybe_flush(struct btree_trans *trans,
					struct bkey_s_c referring_k,
					struct wb_maybe_flush *f)
{
	struct bch_fs *c = trans->c;

	if (f->seen_error &&
	    f->nr_flushes > 32 &&
	    f->nr_flushes * 8 > f->nr_done)
		return 0;

	if (!bkey_and_val_eq(referring_k, bkey_i_to_s_c(f->last_flushed.k))) {
		event_inc_trace(c, write_buffer_maybe_flush, buf, ({
			prt_printf(&buf, "%s\n", trans->fn);
			bch2_bkey_val_to_text(&buf, c, referring_k);
		}));

		struct bkey_buf tmp __cleanup(bch2_bkey_buf_exit);
		bch2_bkey_buf_init(&tmp);
		bch2_bkey_buf_reassemble(&tmp, referring_k);

		if (bkey_is_btree_ptr(referring_k.k) &&
		    bch2_btree_interior_updates_pending(c)) {
			bch2_trans_unlock_long(trans);
			bch2_btree_interior_updates_flush(c);
		}

		bool did_work = false;
		try(btree_write_buffer_flush_seq(trans, journal_cur_seq(&c->journal), &did_work,
						 WB_FLUSH_maybe));

		bch2_bkey_buf_copy(&f->last_flushed, tmp.k);
		f->nr_flushes++;

		/* can we avoid the unconditional restart? */
		event_inc_trace(c, trans_restart_write_buffer_flush, buf, prt_str(&buf, trans->fn));
		return bch_err_throw(c, transaction_restart_write_buffer_flush);
	}

	f->seen_error = true;
	return 0;
}

/* Per-btree "should flush": this btree's own fill level. */
static inline bool bch_wb_btree_should_flush(struct bch_fs_btree_write_buffer *wb)
{
	return wb->inc.keys.nr + wb->flushing.keys.nr > wb->inc.keys.size / 4;
}

static void bch2_btree_write_buffer_flush_work_fn(struct work_struct *work)
{
	struct bch_fs_btree_write_buffer *wb =
		container_of(work, struct bch_fs_btree_write_buffer, flush_work);
	struct bch_fs *c = wb->c;

	if (!bch_wb_btree_should_flush(wb) || bch2_journal_error(&c->journal))
		return;

	scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
		guard(mutex)(&wb->flushing.lock);
		CLASS(btree_trans, trans)(c);
		do {
			bch2_trans_unlock_long(trans);
			bch2_btree_write_buffer_flush_locked(trans, wb->idx, WB_FLUSH_thread);
		} while (!bch2_journal_error(&c->journal) &&
			 bch_wb_btree_should_flush(wb));
	}

	if (test_bit(JOURNAL_low_on_wb, &c->journal.flags) &&
	    !bch2_btree_write_buffer_must_wait(c)) {
		guard(spinlock)(&c->journal.lock);
		bch2_journal_set_watermark(&c->journal);
	}
}

static void wb_accounting_sort(struct bch_fs_btree_write_buffer *wb)
{
	eytzinger0_sort(wb->accounting.data, wb->accounting.nr,
			sizeof(wb->accounting.data[0]),
			wb_key_cmp, NULL);
}

int bch2_accounting_key_to_wb_slowpath(struct bch_fs *c, enum btree_id btree,
				       struct bkey_i_accounting *k)
{
	struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[bch_wb_btree_idx(btree)];

	event_inc_trace(c, accounting_key_to_wb_slowpath, buf, ({
		prt_printf(&buf, "have: %zu\n", wb->accounting.nr);
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&k->k_i));
	}));

	struct btree_write_buffered_key new = {};
	bkey_copy(&new.k, &k->k_i);

	try(darray_push(&wb->accounting, new));

	wb_accounting_sort(wb);
	return 0;
}

/*
 * Acquire locks + intake state for one per-btree instance during one journal
 * intake pass. Called from _start() for every btree up front — eager, not
 * lazy, so the lock ordering is trivially "always ascending idx" and the
 * caller doesn't need to care about which btrees a journal buf actually
 * touches. Released in _end().
 *
 * Takes inc.lock (always), and flushing.lock (opportunistically, to let us
 * skip staging via inc if flushing has room).
 */
static void bch_wb_acquire(struct bch_fs *c,
			   struct journal_keys_to_wb *dst,
			   enum bch_wb_btree idx)
{
	struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[idx];
	struct journal_keys_to_wb_btree *pb = &dst->per_btree[idx];

	if (mutex_trylock(&wb->flushing.lock)) {
		mutex_lock(&wb->inc.lock);
		move_keys_from_inc_to_flushing(wb);

		if (!wb->inc.keys.nr) {
			pb->wb = &wb->flushing;
		} else {
			mutex_unlock(&wb->flushing.lock);
			pb->wb = &wb->inc;
		}
	} else {
		mutex_lock(&wb->inc.lock);
		pb->wb = &wb->inc;
	}

	pb->room = darray_room(pb->wb->keys);
	if (pb->wb == &wb->flushing)
		pb->room = min(pb->room, wb->sorted.size - wb->flushing.keys.nr);

	bch2_journal_pin_add(&c->journal, dst->seq, &pb->wb->pin,
			     bch2_btree_write_buffer_journal_flush);
}

int bch2_journal_key_to_wb_slowpath(struct bch_fs *c,
			     struct journal_keys_to_wb *dst,
			     enum bch_wb_btree idx,
			     struct bkey_i *k)
{
	struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[idx];
	struct journal_keys_to_wb_btree *pb = &dst->per_btree[idx];
	unsigned u64s = wb_key_u64s(k);
	int ret;
retry:
	ret = darray_make_room_gfp(&pb->wb->keys, u64s, GFP_KERNEL);
	if (!ret && pb->wb == &wb->flushing)
		ret = darray_resize(&wb->sorted, wb->flushing.keys.size);

	if (unlikely(ret)) {
		if (pb->wb == &wb->flushing) {
			mutex_unlock(&pb->wb->lock);
			pb->wb = &wb->inc;
			bch2_journal_pin_add(&c->journal, dst->seq, &pb->wb->pin,
					     bch2_btree_write_buffer_journal_flush);
			goto retry;
		}

		return ret;
	}

	pb->room = darray_room(pb->wb->keys);
	if (pb->wb == &wb->flushing)
		pb->room = min(pb->room, wb->sorted.size - wb->flushing.keys.nr);
	BUG_ON(pb->room < u64s);
	BUG_ON(!dst->seq);

	bch2_journal_key_to_wb_reserved(c, pb, dst->seq, k);
	return 0;
}

void bch2_journal_keys_to_write_buffer_start(struct bch_fs *c,
					     struct journal_keys_to_wb *dst,
					     u64 seq)
{
	BUG_ON(seq > journal_cur_seq(&c->journal));

	memset(dst, 0, sizeof(*dst));
	dst->seq = seq;

	for (enum bch_wb_btree idx = 0; idx < BCH_WB_BTREE_NR; idx++) {
		struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[idx];

		bch_wb_acquire(c, dst, idx);

		/*
		 * Zero accounting accumulators so per-buf deltas start fresh.
		 * wb->accounting is invariantly protected by wb->inc.lock (all
		 * intake paths that touch it — this reset, accumulate via
		 * bch2_accounting_key_to_wb(), slowpath, and _end() inject /
		 * compact / sort — run with inc.lock held).
		 */
		darray_for_each(wb->accounting, i)
			memset(&i->k.v, 0, bkey_val_bytes(&i->k.k));
	}
}

int bch2_journal_keys_to_write_buffer_end(struct bch_fs *c, struct journal_keys_to_wb *dst)
{
	int ret = 0;

	/*
	 * For each btree: inject live (non-zero) accounting accumulators into
	 * that btree's intake buffer, compact the darray if mostly-zero, then
	 * drop the empty-keys pin and release the locks taken in _start().
	 */
	for (enum bch_wb_btree idx = 0; idx < BCH_WB_BTREE_NR; idx++) {
		struct journal_keys_to_wb_btree *pb = &dst->per_btree[idx];
		struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[idx];
		unsigned live_accounting_keys = 0;

		if (!ret)
			darray_for_each(wb->accounting, i)
				if (!bch2_accounting_key_is_zero(bkey_i_to_s_c_accounting(&i->k))) {
					i->journal_seq = dst->seq;
					live_accounting_keys++;
					ret = __bch2_journal_key_to_wb(c, dst, idx, &i->k);
					if (ret)
						break;
				}

		if (live_accounting_keys * 2 < wb->accounting.nr) {
			struct btree_write_buffered_key *d = wb->accounting.data;

			darray_for_each(wb->accounting, src)
				if (!bch2_accounting_key_is_zero(bkey_i_to_s_c_accounting(&src->k)))
					*d++ = *src;
			wb->accounting.nr = d - wb->accounting.data;
			wb_accounting_sort(wb);
		}

		if (!pb->wb->keys.nr)
			bch2_journal_pin_drop(&c->journal, &pb->wb->pin);

		if (pb->wb == &wb->flushing)
			mutex_unlock(&wb->flushing.lock);
		mutex_unlock(&wb->inc.lock);
	}

	if (bch2_btree_write_buffer_should_flush(c))
		bch2_btree_write_buffer_wakeup(c);

	return ret;
}

static int wb_keys_resize(struct btree_write_buffer_keys *wb, size_t new_size)
{
	if (wb->keys.size >= new_size)
		return 0;

	if (!mutex_trylock(&wb->lock))
		return -EINTR;

	int ret = darray_resize(&wb->keys, new_size);
	mutex_unlock(&wb->lock);
	return ret;
}

int bch2_btree_write_buffer_resize(struct bch_fs *c, size_t new_size)
{
	for (unsigned i = 0; i < BCH_WB_BTREE_NR; i++) {
		struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[i];
		try(wb_keys_resize(&wb->flushing, new_size));
		try(wb_keys_resize(&wb->inc, new_size));
	}
	return 0;
}

void bch2_btree_write_buffer_to_text(struct printbuf *out, struct bch_fs *c)
{
	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 24);

	for (unsigned i = 0; i < BCH_WB_BTREE_NR; i++) {
		struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[i];

		prt_printf(out, "=== %s ===\n", bch_wb_btree_names[i]);

		prt_printf(out, "inc keys:\t%zu/%zu\n",		wb->inc.keys.nr, wb->inc.keys.size);
		prt_printf(out, "inc seq pinned:\t%llu\n",	wb->inc.pin.seq);

		prt_printf(out, "flushing keys:\t%zu/%zu\n",	wb->flushing.keys.nr, wb->flushing.keys.size);
		prt_printf(out, "flushing seq pinned:\t%llu\n",	wb->flushing.pin.seq);

		prt_printf(out, "sorted:\t%zu/%zu\n",		wb->sorted.nr, wb->sorted.size);

		prt_printf(out, "nr flushes:\t%llu\n",		wb->nr_flushes);
		for (unsigned j = 0; j < WB_FLUSH_NR; j++)
			prt_printf(out, "  %s:\t%llu\n",	wb_flush_caller_names[j], wb->nr_flushes_caller[j]);
		prt_printf(out, "keys flushed:\t%llu\n",	wb->nr_keys_flushed);
		prt_printf(out, "keys fast:\t%llu\n",		wb->nr_keys_fast);
		prt_printf(out, "keys slowpath:\t%llu\n",	wb->nr_keys_slowpath);

		prt_printf(out, "flush work:\t%s\n",
			   work_busy(&wb->flush_work) ? "busy" : "idle");

		prt_newline(out);
	}

	prt_printf(out, "Time stats (shared):\n");
	scoped_guard(printbuf_indent, out)
		bch2_time_stats_to_text(out, &c->times[BCH_TIME_btree_write_buffer_flush]);
}

void bch2_fs_btree_write_buffer_exit(struct bch_fs *c)
{
	for (unsigned i = 0; i < BCH_WB_BTREE_NR; i++) {
		struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[i];

		BUG_ON((wb->inc.keys.nr || wb->flushing.keys.nr) &&
		       !bch2_journal_error(&c->journal));

		darray_exit(&wb->accounting);
		darray_exit(&wb->sorted);
		darray_exit(&wb->flushing.keys);
		darray_exit(&wb->inc.keys);
	}

	if (c->btree.write_buffer_shard_wq)
		destroy_workqueue(c->btree.write_buffer_shard_wq);
	if (c->btree.write_buffer_wq)
		destroy_workqueue(c->btree.write_buffer_wq);
}

void bch2_btree_write_buffer_stop(struct bch_fs *c)
{
	for (unsigned i = 0; i < BCH_WB_BTREE_NR; i++)
		cancel_work_sync(&c->btree.write_buffer[i].flush_work);
}

int bch2_btree_write_buffer_start(struct bch_fs *c)
{
	/*
	 * Work items are initialized once in init_early; nothing to start —
	 * flushes are driven on demand by queue_work() from the wakeup path.
	 */
	return 0;
}

#ifdef CONFIG_PROVE_LOCKING
static int wb_keys_lock_cmp_fn(const struct lockdep_map *a, const struct lockdep_map *b)
{
	const struct btree_write_buffer_keys *ka =
		container_of(container_of(a, struct mutex, dep_map),
			     struct btree_write_buffer_keys, lock);
	const struct btree_write_buffer_keys *kb =
		container_of(container_of(b, struct mutex, dep_map),
			     struct btree_write_buffer_keys, lock);

	return cmp_int(ka->wb_btree, kb->wb_btree);
}
#endif

void bch2_fs_btree_write_buffer_init_early(struct bch_fs *c)
{
	for (unsigned i = 0; i < BCH_WB_BTREE_NR; i++) {
		struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[i];

		wb->c			= c;
		wb->idx			= i;
		wb->inc.wb_btree	= i;
		wb->inc.is_flushing	= false;
		wb->flushing.wb_btree	= i;
		wb->flushing.is_flushing = true;
		mutex_init(&wb->inc.lock);
		mutex_init(&wb->flushing.lock);
		lock_set_cmp_fn(&wb->inc.lock,	    wb_keys_lock_cmp_fn, NULL);
		lock_set_cmp_fn(&wb->flushing.lock, wb_keys_lock_cmp_fn, NULL);
		INIT_WORK(&wb->flush_work, bch2_btree_write_buffer_flush_work_fn);
	}
}

int bch2_fs_btree_write_buffer_init(struct bch_fs *c)
{
	/*
	 * Matches the journal's default buf size (JOURNAL_ENTRY_SIZE_MIN /
	 * 64 slots); grows via bch2_btree_write_buffer_resize() as the journal
	 * grows. With BCH_WB_BTREE_NR independent instances, keeping this small
	 * matters — at 1<<16 the baseline was ~27 MB per fs.
	 */
	unsigned initial_size = 1 << 10;

	c->btree.write_buffer_wq =
		alloc_workqueue("bcachefs_wb_flush",
				WQ_UNBOUND|WQ_MEM_RECLAIM, 0);
	if (!c->btree.write_buffer_wq)
		return bch_err_throw(c, ENOMEM_fs_other_alloc);

	c->btree.write_buffer_shard_wq =
		alloc_workqueue("bcachefs_wb_flush_shard",
				WQ_UNBOUND|WQ_MEM_RECLAIM, 0);
	if (!c->btree.write_buffer_shard_wq)
		return bch_err_throw(c, ENOMEM_fs_other_alloc);

	for (unsigned i = 0; i < BCH_WB_BTREE_NR; i++) {
		struct bch_fs_btree_write_buffer *wb = &c->btree.write_buffer[i];

		int ret = darray_make_room(&wb->inc.keys, initial_size) ?:
			  darray_make_room(&wb->flushing.keys, initial_size) ?:
			  darray_make_room(&wb->sorted, initial_size);
		if (ret)
			return ret;
	}
	return 0;
}
