// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "btree/bkey_buf.h"
#include "btree/bkey_cmp.h"
#include "btree/bset.h"
#include "btree/interior.h"
#include "btree/sort.h"

#include "data/extents.h"

typedef int (*sort_cmp_fn)(const struct btree *,
			   const struct bkey_packed *,
			   const struct bkey_packed *);

static inline bool sort_iter_end(struct sort_iter *iter)
{
	return !iter->used;
}

static inline void sort_iter_sift(struct sort_iter *iter, unsigned from,
				  sort_cmp_fn cmp)
{
	unsigned i;

	for (i = from;
	     i + 1 < iter->used &&
	     cmp(iter->b, iter->data[i].k, iter->data[i + 1].k) > 0;
	     i++)
		swap(iter->data[i], iter->data[i + 1]);
}

static inline void sort_iter_sort(struct sort_iter *iter, sort_cmp_fn cmp)
{
	unsigned i = iter->used;

	while (i--)
		sort_iter_sift(iter, i, cmp);
}

static inline struct bkey_packed *sort_iter_peek(struct sort_iter *iter)
{
	return !sort_iter_end(iter) ? iter->data->k : NULL;
}

static inline void sort_iter_advance(struct sort_iter *iter, sort_cmp_fn cmp)
{
	struct sort_iter_set *i = iter->data;

	BUG_ON(!iter->used);

	i->k = bkey_p_next(i->k);

	BUG_ON(i->k > i->end);

	if (i->k == i->end)
		array_remove_item(iter->data, iter->used, 0);
	else
		sort_iter_sift(iter, 0, cmp);
}

static inline struct bkey_packed *sort_iter_next(struct sort_iter *iter,
						 sort_cmp_fn cmp)
{
	struct bkey_packed *ret = sort_iter_peek(iter);

	if (ret)
		sort_iter_advance(iter, cmp);

	return ret;
}

/*
 * If keys compare equal, compare by pointer order:
 */
static inline int key_sort_fix_overlapping_cmp(const struct btree *b,
					       const struct bkey_packed *l,
					       const struct bkey_packed *r)
{
	return bch2_bkey_cmp_packed(b, l, r) ?:
		cmp_int((unsigned long) l, (unsigned long) r);
}

static inline bool should_drop_next_key(struct sort_iter *iter)
{
	/*
	 * key_sort_cmp() ensures that when keys compare equal the older key
	 * comes first; so if l->k compares equal to r->k then l->k is older
	 * and should be dropped.
	 */
	return iter->used >= 2 &&
		!bch2_bkey_cmp_packed(iter->b,
				 iter->data[0].k,
				 iter->data[1].k);
}

struct btree_nr_keys
bch2_key_sort_fix_overlapping(struct bch_fs *c, struct bset *dst,
			      struct sort_iter *iter)
{
	struct bkey_packed *out = dst->start;
	struct bkey_packed *k;
	struct btree_nr_keys nr;

	memset(&nr, 0, sizeof(nr));

	sort_iter_sort(iter, key_sort_fix_overlapping_cmp);

	while ((k = sort_iter_peek(iter))) {
		if (!bkey_deleted(k) &&
		    !should_drop_next_key(iter)) {
			bkey_p_copy(out, k);
			btree_keys_account_key_add(&nr, 0, out);
			out = bkey_p_next(out);
		}

		sort_iter_advance(iter, key_sort_fix_overlapping_cmp);
	}

	dst->u64s = cpu_to_le16((u64 *) out - dst->_data);
	return nr;
}

/* Sort + repack in a new format: */
struct btree_nr_keys
bch2_sort_repack(struct bset *dst, struct btree *src,
		 struct btree_node_iter *src_iter,
		 struct bkey_format *out_f,
		 bool filter_whiteouts)
{
	struct bkey_format *in_f = &src->format;
	struct bkey_packed *in, *out = vstruct_last(dst);
	struct btree_nr_keys nr;
	bool transform = memcmp(out_f, &src->format, sizeof(*out_f));

	memset(&nr, 0, sizeof(nr));

	while ((in = bch2_btree_node_iter_next_all(src_iter, src))) {
		if (filter_whiteouts && bkey_deleted(in))
			continue;

		if (!transform)
			bkey_p_copy(out, in);
		else if (bch2_bkey_transform(out_f, out, bkey_packed(in)
					     ? in_f : &bch2_bkey_format_current, in))
			out->format = KEY_FORMAT_LOCAL_BTREE;
		else
			bch2_bkey_unpack(src, (void *) out, in);

		out->needs_whiteout = false;

		btree_keys_account_key_add(&nr, 0, out);
		out = bkey_p_next(out);
	}

	dst->u64s = cpu_to_le16((u64 *) out - dst->_data);
	return nr;
}

static inline int keep_unwritten_whiteouts_cmp(const struct btree *b,
				const struct bkey_packed *l,
				const struct bkey_packed *r)
{
	return bch2_bkey_cmp_packed_inlined(b, l, r) ?:
		(int) bkey_deleted(r) - (int) bkey_deleted(l) ?:
		(long) l - (long) r;
}

/*
 * For sorting in the btree node write path: whiteouts not in the unwritten
 * whiteouts area are dropped, whiteouts in the unwritten whiteouts area are
 * dropped if overwritten by real keys:
 */
unsigned bch2_sort_keys_keep_unwritten_whiteouts(struct bkey_packed *dst, struct sort_iter *iter)
{
	struct bkey_packed *in, *next, *out = dst;

	sort_iter_sort(iter, keep_unwritten_whiteouts_cmp);

	while ((in = sort_iter_next(iter, keep_unwritten_whiteouts_cmp))) {
		if (bkey_deleted(in) && in < unwritten_whiteouts_start(iter->b))
			continue;

		if ((next = sort_iter_peek(iter)) &&
		    !bch2_bkey_cmp_packed_inlined(iter->b, in, next))
			continue;

		bkey_p_copy(out, in);
		out = bkey_p_next(out);
	}

	return (u64 *) out - (u64 *) dst;
}

/*
 * Main sort routine for compacting a btree node in memory: we always drop
 * whiteouts because any whiteouts that need to be written are in the unwritten
 * whiteouts area:
 */
unsigned bch2_sort_keys(struct bkey_packed *dst, struct sort_iter *iter)
{
	struct bkey_packed *in, *out = dst;

	sort_iter_sort(iter, bch2_bkey_cmp_packed_inlined);

	while ((in = sort_iter_next(iter, bch2_bkey_cmp_packed_inlined))) {
		if (bkey_deleted(in))
			continue;

		bkey_p_copy(out, in);
		out = bkey_p_next(out);
	}

	return (u64 *) out - (u64 *) dst;
}

static void verify_no_dups(struct btree *b,
			   struct bkey_packed *start,
			   struct bkey_packed *end)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	struct bkey_packed *k, *p;

	if (start == end)
		return;

	for (p = start, k = bkey_p_next(start);
	     k != end;
	     p = k, k = bkey_p_next(k)) {
		struct bkey l = bkey_unpack_key(b, p);
		struct bkey r = bkey_unpack_key(b, k);

		BUG_ON(bpos_ge(l.p, bkey_start_pos(&r)));
	}
#endif
}

void bch2_btree_bounce_free(struct bch_fs *c, size_t size, bool used_mempool, void *p)
{
	if (used_mempool)
		mempool_free(p, &c->btree_bounce_pool);
	else
		kvfree(p);
}

void *bch2_btree_bounce_alloc(struct bch_fs *c, size_t size, bool *used_mempool)
{
	unsigned flags = memalloc_nofs_save();
	void *p;

	BUG_ON(size > c->opts.btree_node_size);

	*used_mempool = false;
	p = kvmalloc(size, GFP_NOWAIT|__GFP_ACCOUNT|__GFP_RECLAIMABLE);
	if (!p) {
		*used_mempool = true;
		p = mempool_alloc(&c->btree_bounce_pool, GFP_NOFS|__GFP_ACCOUNT|__GFP_RECLAIMABLE);
	}
	memalloc_nofs_restore(flags);
	return p;
}

void bch2_set_bset_needs_whiteout(struct bset *i, int v)
{
	struct bkey_packed *k;

	for (k = i->start; k != vstruct_last(i); k = bkey_p_next(k))
		k->needs_whiteout = v;
}

static void sort_bkey_ptrs(const struct btree *bt,
			   struct bkey_packed **ptrs, unsigned nr)
{
	unsigned n = nr, a = nr / 2, b, c, d;

	if (!a)
		return;

	/* Heap sort: see lib/sort.c: */
	while (1) {
		if (a)
			a--;
		else if (--n)
			swap(ptrs[0], ptrs[n]);
		else
			break;

		for (b = a; c = 2 * b + 1, (d = c + 1) < n;)
			b = bch2_bkey_cmp_packed(bt,
					    ptrs[c],
					    ptrs[d]) >= 0 ? c : d;
		if (d == n)
			b = c;

		while (b != a &&
		       bch2_bkey_cmp_packed(bt,
				       ptrs[a],
				       ptrs[b]) >= 0)
			b = (b - 1) / 2;
		c = b;
		while (b != a) {
			b = (b - 1) / 2;
			swap(ptrs[b], ptrs[c]);
		}
	}
}

void bch2_sort_whiteouts(struct bch_fs *c, struct btree *b)
{
	struct bkey_packed *new_whiteouts, **ptrs, **ptrs_end, *k;
	bool used_mempool = false;
	size_t bytes = b->whiteout_u64s * sizeof(u64);

	if (!b->whiteout_u64s)
		return;

	new_whiteouts = bch2_btree_bounce_alloc(c, bytes, &used_mempool);

	ptrs = ptrs_end = ((void *) new_whiteouts + bytes);

	for (k = unwritten_whiteouts_start(b);
	     k != unwritten_whiteouts_end(b);
	     k = bkey_p_next(k))
		*--ptrs = k;

	sort_bkey_ptrs(b, ptrs, ptrs_end - ptrs);

	k = new_whiteouts;

	while (ptrs != ptrs_end) {
		bkey_p_copy(k, *ptrs);
		k = bkey_p_next(k);
		ptrs++;
	}

	verify_no_dups(b, new_whiteouts,
		       (void *) ((u64 *) new_whiteouts + b->whiteout_u64s));

	memcpy_u64s(unwritten_whiteouts_start(b),
		    new_whiteouts, b->whiteout_u64s);

	bch2_btree_bounce_free(c, bytes, used_mempool, new_whiteouts);
}

static bool should_compact_bset(struct btree *b, struct bset_tree *t,
				bool compacting, enum compact_mode mode)
{
	if (!bset_dead_u64s(b, t))
		return false;

	switch (mode) {
	case COMPACT_LAZY:
		return should_compact_bset_lazy(b, t) ||
			(compacting && !bset_written(b, bset(b, t)));
	case COMPACT_ALL:
		return true;
	default:
		BUG();
	}
}

bool bch2_drop_whiteouts(struct btree *b, enum compact_mode mode)
{
	bool ret = false;

	for_each_bset(b, t) {
		struct bset *i = bset(b, t);
		struct bkey_packed *k, *n, *out, *start, *end;
		struct btree_node_entry *src = NULL, *dst = NULL;

		if (t != b->set && !bset_written(b, i)) {
			src = container_of(i, struct btree_node_entry, keys);
			dst = max(write_block(b),
				  (void *) btree_bkey_last(b, t - 1));
		}

		if (src != dst)
			ret = true;

		if (!should_compact_bset(b, t, ret, mode)) {
			if (src != dst) {
				memmove(dst, src, sizeof(*src) +
					le16_to_cpu(src->keys.u64s) *
					sizeof(u64));
				i = &dst->keys;
				set_btree_bset(b, t, i);
			}
			continue;
		}

		start	= btree_bkey_first(b, t);
		end	= btree_bkey_last(b, t);

		if (src != dst) {
			memmove(dst, src, sizeof(*src));
			i = &dst->keys;
			set_btree_bset(b, t, i);
		}

		out = i->start;

		for (k = start; k != end; k = n) {
			n = bkey_p_next(k);

			if (!bkey_deleted(k)) {
				bkey_p_copy(out, k);
				out = bkey_p_next(out);
			} else {
				BUG_ON(k->needs_whiteout);
			}
		}

		i->u64s = cpu_to_le16((u64 *) out - i->_data);
		set_btree_bset_end(b, t);
		bch2_bset_set_no_aux_tree(b, t);
		ret = true;
	}

	bch2_verify_btree_nr_keys(b);

	bch2_btree_build_aux_trees(b);

	return ret;
}

bool bch2_compact_whiteouts(struct bch_fs *c, struct btree *b,
			    enum compact_mode mode)
{
	return bch2_drop_whiteouts(b, mode);
}

void bch2_btree_node_sort(struct bch_fs *c, struct btree *b,
			  unsigned start_idx, unsigned end_idx)
{
	struct btree_node *out;
	struct sort_iter_stack sort_iter;
	struct bset_tree *t;
	struct bset *start_bset = bset(b, &b->set[start_idx]);
	bool used_mempool = false;
	u64 start_time, seq = 0;
	unsigned i, u64s = 0, bytes, shift = end_idx - start_idx - 1;
	bool sorting_entire_node = start_idx == 0 &&
		end_idx == b->nsets;

	sort_iter_stack_init(&sort_iter, b);

	for (t = b->set + start_idx;
	     t < b->set + end_idx;
	     t++) {
		u64s += le16_to_cpu(bset(b, t)->u64s);
		sort_iter_add(&sort_iter.iter,
			      btree_bkey_first(b, t),
			      btree_bkey_last(b, t));
	}

	bytes = sorting_entire_node
		? btree_buf_bytes(b)
		: __vstruct_bytes(struct btree_node, u64s);

	out = bch2_btree_bounce_alloc(c, bytes, &used_mempool);

	start_time = local_clock();

	u64s = bch2_sort_keys(out->keys.start, &sort_iter.iter);

	out->keys.u64s = cpu_to_le16(u64s);

	BUG_ON(vstruct_end(&out->keys) > (void *) out + bytes);

	if (sorting_entire_node)
		bch2_time_stats_update(&c->times[BCH_TIME_btree_node_sort],
				       start_time);

	/* Make sure we preserve bset journal_seq: */
	for (t = b->set + start_idx; t < b->set + end_idx; t++)
		seq = max(seq, le64_to_cpu(bset(b, t)->journal_seq));
	start_bset->journal_seq = cpu_to_le64(seq);

	if (sorting_entire_node) {
		u64s = le16_to_cpu(out->keys.u64s);

		BUG_ON(bytes != btree_buf_bytes(b));

		/*
		 * Our temporary buffer is the same size as the btree node's
		 * buffer, we can just swap buffers instead of doing a big
		 * memcpy()
		 */
		*out = *b->data;
		out->keys.u64s = cpu_to_le16(u64s);
		swap(out, b->data);
		set_btree_bset(b, b->set, &b->data->keys);
	} else {
		start_bset->u64s = out->keys.u64s;
		memcpy_u64s(start_bset->start,
			    out->keys.start,
			    le16_to_cpu(out->keys.u64s));
	}

	for (i = start_idx + 1; i < end_idx; i++)
		b->nr.bset_u64s[start_idx] +=
			b->nr.bset_u64s[i];

	b->nsets -= shift;

	for (i = start_idx + 1; i < b->nsets; i++) {
		b->nr.bset_u64s[i]	= b->nr.bset_u64s[i + shift];
		b->set[i]		= b->set[i + shift];
	}

	for (i = b->nsets; i < MAX_BSETS; i++)
		b->nr.bset_u64s[i] = 0;

	set_btree_bset_end(b, &b->set[start_idx]);
	bch2_bset_set_no_aux_tree(b, &b->set[start_idx]);

	bch2_btree_bounce_free(c, bytes, used_mempool, out);

	bch2_verify_btree_nr_keys(b);
}

void bch2_btree_sort_into(struct bch_fs *c,
			 struct btree *dst,
			 struct btree *src)
{
	struct btree_nr_keys nr;
	struct btree_node_iter src_iter;
	u64 start_time = local_clock();

	BUG_ON(dst->nsets != 1);

	bch2_bset_set_no_aux_tree(dst, dst->set);

	bch2_btree_node_iter_init_from_start(&src_iter, src);

	nr = bch2_sort_repack(btree_bset_first(dst),
			src, &src_iter,
			&dst->format,
			true);

	bch2_time_stats_update(&c->times[BCH_TIME_btree_node_sort],
			       start_time);

	set_btree_bset_end(dst, dst->set);

	dst->nr.live_u64s	+= nr.live_u64s;
	dst->nr.bset_u64s[0]	+= nr.bset_u64s[0];
	dst->nr.packed_keys	+= nr.packed_keys;
	dst->nr.unpacked_keys	+= nr.unpacked_keys;

	bch2_verify_btree_nr_keys(dst);
}

/*
 * We're about to add another bset to the btree node, so if there's currently
 * too many bsets - sort some of them together:
 */
bool bch2_btree_node_compact(struct bch_fs *c, struct btree *b)
{
	unsigned unwritten_idx;
	bool ret = false;

	for (unwritten_idx = 0;
	     unwritten_idx < b->nsets;
	     unwritten_idx++)
		if (!bset_written(b, bset(b, &b->set[unwritten_idx])))
			break;

	if (b->nsets - unwritten_idx > 1) {
		bch2_btree_node_sort(c, b, unwritten_idx, b->nsets);
		ret = true;
	}

	if (unwritten_idx > 1) {
		bch2_btree_node_sort(c, b, 0, unwritten_idx);
		ret = true;
	}

	return ret;
}

void bch2_btree_build_aux_trees(struct btree *b)
{
	for_each_bset(b, t)
		bch2_bset_build_aux_tree(b, t,
				!bset_written(b, bset(b, t)) &&
				t == bset_tree_last(b));
}
