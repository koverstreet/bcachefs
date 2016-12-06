
#include "bcache.h"
#include "bkey_methods.h"
#include "btree_cache.h"
#include "btree_update.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_locking.h"
#include "buckets.h"
#include "checksum.h"
#include "debug.h"
#include "error.h"
#include "extents.h"
#include "io.h"
#include "journal.h"

#include <trace/events/bcachefs.h>

static void verify_no_dups(struct btree *b,
			   struct bkey_packed *start,
			   struct bkey_packed *end)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	const struct bkey_format *f = &b->keys.format;
	struct bkey_packed *k;

	for (k = start; k != end && bkey_next(k) != end; k = bkey_next(k)) {
		struct bkey l = bkey_unpack_key(f, k);
		struct bkey r = bkey_unpack_key(f, bkey_next(k));

		BUG_ON(btree_node_is_extents(b)
		       ? bkey_cmp(l.p, bkey_start_pos(&r)) > 0
		       : bkey_cmp(l.p, bkey_start_pos(&r)) >= 0);
		//BUG_ON(bkey_cmp_packed(&b->format, k, bkey_next(k)) >= 0);
	}
#endif
}

static void clear_needs_whiteout(struct bset *i)
{
	struct bkey_packed *k;

	for (k = i->start; k != bset_bkey_last(i); k = bkey_next(k))
		k->needs_whiteout = false;
}

static void set_needs_whiteout(struct bset *i)
{
	struct bkey_packed *k;

	for (k = i->start; k != bset_bkey_last(i); k = bkey_next(k))
		k->needs_whiteout = true;
}

static void btree_bounce_free(struct cache_set *c, unsigned order,
			      bool used_mempool, void *p)
{
	if (used_mempool)
		mempool_free(virt_to_page(p), &c->btree_bounce_pool);
	else
		free_pages((unsigned long) p, order);
}

static void *btree_bounce_alloc(struct cache_set *c, unsigned order,
				bool *used_mempool)
{
	void *p;

	BUG_ON(1 << order > btree_pages(c));

	*used_mempool = false;
	p = (void *) __get_free_pages(__GFP_NOWARN|GFP_NOWAIT, order);
	if (p)
		return p;

	*used_mempool = true;
	return page_address(mempool_alloc(&c->btree_bounce_pool, GFP_NOIO));
}

typedef int (*sort_cmp_fn)(struct btree_keys *,
			   struct bkey_packed *,
			   struct bkey_packed *);

struct sort_iter {
	struct btree_keys	*b;
	unsigned		used;

	struct sort_iter_set {
		struct bkey_packed *k, *end;
	} data[MAX_BSETS + 1];
};

static void sort_iter_init(struct sort_iter *iter, struct btree_keys *b)
{
	memset(iter, 0, sizeof(*iter));
	iter->b = b;
}

static inline void __sort_iter_sift(struct sort_iter *iter,
				    unsigned from,
				    sort_cmp_fn cmp)
{
	unsigned i;

	for (i = from;
	     i + 1 < iter->used &&
	     cmp(iter->b, iter->data[i].k, iter->data[i + 1].k) > 0;
	     i++)
		swap(iter->data[i], iter->data[i + 1]);
}

static inline void sort_iter_sift(struct sort_iter *iter, sort_cmp_fn cmp)
{

	__sort_iter_sift(iter, 0, cmp);
}

static inline void sort_iter_sort(struct sort_iter *iter, sort_cmp_fn cmp)
{
	unsigned i = iter->used;

	while (i--)
		__sort_iter_sift(iter, i, cmp);
}

static void sort_iter_add(struct sort_iter *iter,
			  struct bkey_packed *k,
			  struct bkey_packed *end)
{
	BUG_ON(iter->used >= ARRAY_SIZE(iter->data));

	if (k != end)
		iter->data[iter->used++] = (struct sort_iter_set) { k, end };
}

static inline struct bkey_packed *sort_iter_peek(struct sort_iter *iter)
{
	return iter->used ? iter->data->k : NULL;
}

static inline void sort_iter_advance(struct sort_iter *iter, sort_cmp_fn cmp)
{
	iter->data->k = bkey_next(iter->data->k);

	BUG_ON(iter->data->k > iter->data->end);

	if (iter->data->k == iter->data->end)
		memmove(&iter->data[0],
			&iter->data[1],
			sizeof(iter->data[0]) * --iter->used);
	else
		sort_iter_sift(iter, cmp);
}

static inline struct bkey_packed *sort_iter_next(struct sort_iter *iter,
						 sort_cmp_fn cmp)
{
	struct bkey_packed *ret = sort_iter_peek(iter);

	if (ret)
		sort_iter_advance(iter, cmp);

	return ret;
}

static inline int sort_key_whiteouts_cmp(struct btree_keys *b,
					 struct bkey_packed *l,
					 struct bkey_packed *r)
{
	return bkey_cmp_packed(&b->format, l, r);
}

static unsigned sort_key_whiteouts(struct bkey_packed *dst,
				   struct sort_iter *iter)
{
	struct bkey_packed *in, *out = dst;

	sort_iter_sort(iter, sort_key_whiteouts_cmp);

	while ((in = sort_iter_next(iter, sort_key_whiteouts_cmp))) {
		bkey_copy(out, in);
		out = bkey_next(out);
	}

	return (u64 *) out - (u64 *) dst;
}

static inline int sort_extent_whiteouts_cmp(struct btree_keys *b,
					    struct bkey_packed *l,
					    struct bkey_packed *r)
{
	struct bkey ul = bkey_unpack_key(&b->format, l);
	struct bkey ur = bkey_unpack_key(&b->format, r);

	return bkey_cmp(bkey_start_pos(&ul), bkey_start_pos(&ur));
}

static unsigned sort_extent_whiteouts(struct bkey_packed *dst,
				      struct sort_iter *iter)
{
	const struct bkey_format *f = &iter->b->format;
	struct bkey_packed *in, *out = dst;
	struct bkey_i l, r;
	bool prev = false, l_packed;
	u64 max_packed_size	= bkey_field_max(f, BKEY_FIELD_SIZE);
	u64 max_packed_offset	= bkey_field_max(f, BKEY_FIELD_OFFSET);
	u64 new_size;

	max_packed_size = min_t(u64, max_packed_size, KEY_SIZE_MAX);

	sort_iter_sort(iter, sort_extent_whiteouts_cmp);

	while ((in = sort_iter_next(iter, sort_extent_whiteouts_cmp))) {
		EBUG_ON(bkeyp_val_u64s(f, in));
		EBUG_ON(in->type != KEY_TYPE_DISCARD);

		r.k = bkey_unpack_key(f, in);

		if (prev &&
		    bkey_cmp(l.k.p, bkey_start_pos(&r.k)) >= 0) {
			if (bkey_cmp(l.k.p, r.k.p) >= 0)
				continue;

			new_size = l_packed
				? min(max_packed_size, max_packed_offset -
				      bkey_start_offset(&l.k))
				: KEY_SIZE_MAX;

			new_size = min(new_size, r.k.p.offset -
				       bkey_start_offset(&l.k));

			BUG_ON(new_size < l.k.size);

			bch_key_resize(&l.k, new_size);

			if (bkey_cmp(l.k.p, r.k.p) >= 0)
				continue;

			bch_cut_front(l.k.p, &r);
		}

		if (prev) {
			if (!bkey_pack(out, &l, f)) {
				BUG_ON(l_packed);
				bkey_copy(out, &l);
			}
			out = bkey_next(out);
		}

		l = r;
		prev = true;
		l_packed = bkey_packed(in);
	}

	if (prev) {
		if (!bkey_pack(out, &l, f)) {
			BUG_ON(l_packed);
			bkey_copy(out, &l);
		}
		out = bkey_next(out);
	}

	return (u64 *) out - (u64 *) dst;
}

enum compact_mode {
	COMPACT_LAZY,
	COMPACT_WRITTEN,
	COMPACT_WRITTEN_NO_WRITE_LOCK,
};

static unsigned should_compact_bset(struct btree *b, struct bset_tree *t,
				    bool compacting,
				    enum compact_mode mode)
{
	unsigned live_u64s = b->keys.nr.bset_u64s[t - b->keys.set];
	unsigned bset_u64s = le16_to_cpu(t->data->u64s);

	if (live_u64s == bset_u64s)
		return 0;

	if (mode == COMPACT_LAZY) {
		if (live_u64s * 4 < bset_u64s * 3 ||
		    (compacting && bset_unwritten(b, t->data)))
			return bset_u64s - live_u64s;
	} else {
		if (bset_written(b, t->data))
			return bset_u64s - live_u64s;
	}

	return 0;
}

static bool __compact_whiteouts(struct cache_set *c, struct btree *b,
				enum compact_mode mode)
{
	const struct bkey_format *f = &b->keys.format;
	struct bset_tree *t;
	struct bkey_packed *whiteouts = NULL;
	struct bkey_packed *u_start, *u_pos;
	struct sort_iter sort_iter;
	unsigned order, whiteout_u64s = 0, u64s;
	bool used_mempool, compacting = false;

	for_each_bset(&b->keys, t)
		whiteout_u64s += should_compact_bset(b, t,
					whiteout_u64s != 0, mode);

	if (!whiteout_u64s)
		return false;

	sort_iter_init(&sort_iter, &b->keys);

	whiteout_u64s += b->whiteout_u64s;
	order = get_order(whiteout_u64s * sizeof(u64));

	whiteouts = btree_bounce_alloc(c, order, &used_mempool);
	u_start = u_pos = whiteouts;

	memcpy_u64s(u_pos, unwritten_whiteouts_start(c, b),
		    b->whiteout_u64s);
	u_pos = (void *) u_pos + b->whiteout_u64s * sizeof(u64);

	sort_iter_add(&sort_iter, u_start, u_pos);

	for_each_bset(&b->keys, t) {
		struct bset *i = t->data;
		struct bkey_packed *k, *n, *out, *start, *end;
		struct btree_node_entry *src = NULL, *dst = NULL;

		if (t != b->keys.set && bset_unwritten(b, i)) {
			src = container_of(i, struct btree_node_entry, keys);
			dst = max(write_block(b),
				  (void *) bset_bkey_last(t[-1].data));
		}

		if (!should_compact_bset(b, t, compacting, mode)) {
			if (src != dst) {
				memmove(dst, src, sizeof(*src) +
					le16_to_cpu(src->keys.u64s) *
					sizeof(u64));
				t->data = &dst->keys;
			}
			continue;
		}

		compacting = true;
		u_start = u_pos;
		start = i->start;
		end = bset_bkey_last(i);

		if (src != dst) {
			src = container_of(i, struct btree_node_entry, keys);
			dst = max(write_block(b),
				  (void *) bset_bkey_last(t[-1].data));

			memmove(dst, src, sizeof(*src));
			i = t->data = &dst->keys;
		}

		out = i->start;

		for (k = start; k != end; k = n) {
			n = bkey_next(k);

			if (bkey_deleted(k) && btree_node_is_extents(b))
				continue;

			if (bkey_whiteout(k) && !k->needs_whiteout)
				continue;

			if (bkey_whiteout(k)) {
				unreserve_whiteout(b, t, k);
				memcpy_u64s(u_pos, k, bkeyp_key_u64s(f, k));
				set_bkeyp_val_u64s(f, u_pos, 0);
				u_pos = bkey_next(u_pos);
			} else if (mode != COMPACT_WRITTEN_NO_WRITE_LOCK) {
				bkey_copy(out, k);
				out = bkey_next(out);
			}
		}

		sort_iter_add(&sort_iter, u_start, u_pos);

		if (mode != COMPACT_WRITTEN_NO_WRITE_LOCK) {
			i->u64s = cpu_to_le16((u64 *) out - i->_data);
			bch_bset_set_no_aux_tree(&b->keys, t);
		}
	}

	b->whiteout_u64s = (u64 *) u_pos - (u64 *) whiteouts;

	BUG_ON((void *) unwritten_whiteouts_start(c, b) <
	       (void *) bset_bkey_last(btree_bset_last(b)));

	u64s = btree_node_is_extents(b)
		? sort_extent_whiteouts(unwritten_whiteouts_start(c, b),
					&sort_iter)
		: sort_key_whiteouts(unwritten_whiteouts_start(c, b),
				     &sort_iter);

	BUG_ON(u64s > b->whiteout_u64s);
	BUG_ON(u64s != b->whiteout_u64s && !btree_node_is_extents(b));
	BUG_ON(u_pos != whiteouts && !u64s);

	if (u64s != b->whiteout_u64s) {
		void *src = unwritten_whiteouts_start(c, b);

		b->whiteout_u64s = u64s;
		memmove_u64s_up(unwritten_whiteouts_start(c, b), src, u64s);
	}

	verify_no_dups(b,
		       unwritten_whiteouts_start(c, b),
		       unwritten_whiteouts_end(c, b));

	btree_bounce_free(c, order, used_mempool, whiteouts);

	if (mode != COMPACT_WRITTEN_NO_WRITE_LOCK)
		bch_btree_build_aux_trees(b);

	bch_btree_keys_u64s_remaining(c, b);
	bch_verify_btree_nr_keys(&b->keys);

	return true;
}

bool bch_maybe_compact_whiteouts(struct cache_set *c, struct btree *b)
{
	return __compact_whiteouts(c, b, COMPACT_LAZY);
}

static bool bch_drop_whiteouts(struct btree *b)
{
	struct bset_tree *t;
	bool ret = false;

	for_each_bset(&b->keys, t) {
		struct bset *i = t->data;
		struct bkey_packed *k, *n, *out, *start, *end;

		if (!should_compact_bset(b, t, true, true))
			continue;

		start = i->start;
		end = bset_bkey_last(i);

		if (bset_unwritten(b, i) &&
		    t != b->keys.set) {
			struct bset *dst =
			       max_t(struct bset *, write_block(b),
				     (void *) bset_bkey_last(t[-1].data));

			memmove(dst, i, sizeof(struct bset));
			i = t->data = dst;
		}

		out = i->start;

		for (k = start; k != end; k = n) {
			n = bkey_next(k);

			if (!bkey_whiteout(k)) {
				bkey_copy(out, k);
				out = bkey_next(out);
			}
		}

		i->u64s = cpu_to_le16((u64 *) out - i->_data);
		bch_bset_set_no_aux_tree(&b->keys, t);
		ret = true;
	}

	bch_verify_btree_nr_keys(&b->keys);

	return ret;
}

static int sort_keys_cmp(struct btree_keys *b,
			 struct bkey_packed *l,
			 struct bkey_packed *r)
{
	return bkey_cmp_packed(&b->format, l, r) ?:
		(int) bkey_whiteout(r) - (int) bkey_whiteout(l) ?:
		(int) l->needs_whiteout - (int) r->needs_whiteout;
}

static unsigned sort_keys(struct bkey_packed *dst,
			  struct sort_iter *iter,
			  bool filter_whiteouts)
{
	const struct bkey_format *f = &iter->b->format;
	struct bkey_packed *in, *next, *out = dst;

	sort_iter_sort(iter, sort_keys_cmp);

	while ((in = sort_iter_next(iter, sort_keys_cmp))) {
		if (bkey_whiteout(in) &&
		    (filter_whiteouts || !in->needs_whiteout))
			continue;

		if (bkey_whiteout(in) &&
		    (next = sort_iter_peek(iter)) &&
		    !bkey_cmp_packed(f, in, next)) {
			BUG_ON(in->needs_whiteout &&
			       next->needs_whiteout);
			next->needs_whiteout |= in->needs_whiteout;
			continue;
		}

		if (bkey_whiteout(in)) {
			memcpy_u64s(out, in, bkeyp_key_u64s(f, in));
			set_bkeyp_val_u64s(f, out, 0);
		} else {
			bkey_copy(out, in);
		}
		out = bkey_next(out);
	}

	return (u64 *) out - (u64 *) dst;
}

static inline int sort_extents_cmp(struct btree_keys *b,
				   struct bkey_packed *l,
				   struct bkey_packed *r)
{
	return bkey_cmp_packed(&b->format, l, r) ?:
		(int) bkey_deleted(l) - (int) bkey_deleted(r);
}

static unsigned sort_extents(struct bkey_packed *dst,
			     struct sort_iter *iter,
			     bool filter_whiteouts)
{
	struct bkey_packed *in, *out = dst;

	sort_iter_sort(iter, sort_extents_cmp);

	while ((in = sort_iter_next(iter, sort_extents_cmp))) {
		if (bkey_deleted(in))
			continue;

		if (bkey_whiteout(in) &&
		    (filter_whiteouts || !in->needs_whiteout))
			continue;

		bkey_copy(out, in);
		out = bkey_next(out);
	}

	return (u64 *) out - (u64 *) dst;
}

static void btree_node_sort(struct cache_set *c, struct btree *b,
			    struct btree_iter *iter,
			    unsigned start_idx,
			    unsigned end_idx,
			    bool filter_whiteouts)
{
	struct btree_node *out;
	struct sort_iter sort_iter;
	struct bset_tree *t;
	bool used_mempool = false;
	u64 start_time;
	unsigned i, u64s = 0, order, shift = end_idx - start_idx - 1;
	bool sorting_entire_node = start_idx == 0 &&
		end_idx == b->keys.nsets;

	sort_iter_init(&sort_iter, &b->keys);

	for (t = b->keys.set + start_idx;
	     t < b->keys.set + end_idx;
	     t++) {
		u64s += le16_to_cpu(t->data->u64s);
		sort_iter_add(&sort_iter, t->data->start,
			      bset_bkey_last(t->data));
	}

	order = sorting_entire_node
		? b->keys.page_order
		: get_order(__set_bytes(b->data, u64s));

	out = btree_bounce_alloc(c, order, &used_mempool);

	start_time = local_clock();

	if (btree_node_is_extents(b))
		filter_whiteouts = bset_written(b, b->keys.set[start_idx].data);

	u64s = btree_node_is_extents(b)
		? sort_extents(out->keys.start, &sort_iter, filter_whiteouts)
		: sort_keys(out->keys.start, &sort_iter, filter_whiteouts);

	out->keys.u64s = cpu_to_le16(u64s);

	BUG_ON((void *) bset_bkey_last(&out->keys) >
	       (void *) out + (PAGE_SIZE << order));

	if (sorting_entire_node)
		bch_time_stats_update(&c->btree_sort_time, start_time);

	/* Make sure we preserve bset journal_seq: */
	for (t = b->keys.set + start_idx + 1;
	     t < b->keys.set + end_idx;
	     t++)
		b->keys.set[start_idx].data->journal_seq =
			max(b->keys.set[start_idx].data->journal_seq,
			    t->data->journal_seq);

	if (sorting_entire_node) {
		unsigned u64s = le16_to_cpu(out->keys.u64s);

		BUG_ON(order != b->keys.page_order);

		/*
		 * Our temporary buffer is the same size as the btree node's
		 * buffer, we can just swap buffers instead of doing a big
		 * memcpy()
		 */
		*out = *b->data;
		out->keys.u64s = cpu_to_le16(u64s);
		swap(out, b->data);
		b->keys.set->data = &b->data->keys;
	} else {
		b->keys.set[start_idx].data->u64s = out->keys.u64s;
		memcpy_u64s(b->keys.set[start_idx].data->start,
			    out->keys.start,
			    le16_to_cpu(out->keys.u64s));
	}

	for (i = start_idx + 1; i < end_idx; i++)
		b->keys.nr.bset_u64s[start_idx] +=
			b->keys.nr.bset_u64s[i];

	b->keys.nsets -= shift;

	for (i = start_idx + 1; i < b->keys.nsets; i++) {
		b->keys.nr.bset_u64s[i]	= b->keys.nr.bset_u64s[i + shift];
		b->keys.set[i]		= b->keys.set[i + shift];
	}

	for (i = b->keys.nsets; i < MAX_BSETS; i++)
		b->keys.nr.bset_u64s[i] = 0;

	bch_bset_set_no_aux_tree(&b->keys, &b->keys.set[start_idx]);

	btree_bounce_free(c, order, used_mempool, out);

	bch_verify_btree_nr_keys(&b->keys);
}

/* Sort + repack in a new format: */
static struct btree_nr_keys sort_repack(struct bset *dst,
					struct btree_keys *src,
					struct btree_node_iter *src_iter,
					struct bkey_format *in_f,
					struct bkey_format *out_f,
					bool filter_whiteouts)
{
	struct bkey_packed *in, *out = bset_bkey_last(dst);
	struct btree_nr_keys nr;

	memset(&nr, 0, sizeof(nr));

	while ((in = bch_btree_node_iter_next_all(src_iter, src))) {
		if (filter_whiteouts && bkey_whiteout(in))
			continue;

		if (bch_bkey_transform(out_f, out, bkey_packed(in)
				       ? in_f : &bch_bkey_format_current, in))
			out->format = KEY_FORMAT_LOCAL_BTREE;
		else
			bkey_unpack((void *) out, in_f, in);

		btree_keys_account_key_add(&nr, 0, out);
		out = bkey_next(out);
	}

	dst->u64s = cpu_to_le16((u64 *) out - dst->_data);
	return nr;
}

/* Sort, repack, and merge: */
static struct btree_nr_keys sort_repack_merge(struct cache_set *c,
					      struct bset *dst,
					      struct btree_keys *src,
					      struct btree_node_iter *iter,
					      struct bkey_format *in_f,
					      struct bkey_format *out_f,
					      bool filter_whiteouts,
					      key_filter_fn filter,
					      key_merge_fn merge)
{
	struct bkey_packed *k, *prev = NULL, *out;
	struct btree_nr_keys nr;
	BKEY_PADDED(k) tmp;

	memset(&nr, 0, sizeof(nr));

	while ((k = bch_btree_node_iter_next_all(iter, src))) {
		if (filter_whiteouts && bkey_whiteout(k))
			continue;

		/*
		 * The filter might modify pointers, so we have to unpack the
		 * key and values to &tmp.k:
		 */
		bkey_unpack(&tmp.k, in_f, k);

		if (filter && filter(c, src, bkey_i_to_s(&tmp.k)))
			continue;

		/* prev is always unpacked, for key merging: */

		if (prev &&
		    merge &&
		    merge(c, src, (void *) prev, &tmp.k) == BCH_MERGE_MERGE)
			continue;

		/*
		 * the current key becomes the new prev: advance prev, then
		 * copy the current key - but first pack prev (in place):
		 */
		if (prev) {
			bkey_pack(prev, (void *) prev, out_f);

			btree_keys_account_key_add(&nr, 0, prev);
			prev = bkey_next(prev);
		} else {
			prev = bset_bkey_last(dst);
		}

		bkey_copy(prev, &tmp.k);
	}

	if (prev) {
		bkey_pack(prev, (void *) prev, out_f);
		btree_keys_account_key_add(&nr, 0, prev);
		out = bkey_next(prev);
	} else {
		out = bset_bkey_last(dst);
	}

	dst->u64s = cpu_to_le16((u64 *) out - dst->_data);
	return nr;
}

void bch_btree_sort_into(struct cache_set *c,
			 struct btree *dst,
			 struct btree *src)
{
	struct btree_nr_keys nr;
	struct btree_node_iter src_iter;
	u64 start_time = local_clock();

	BUG_ON(dst->keys.nsets != 1);

	bch_bset_set_no_aux_tree(&dst->keys, dst->keys.set);

	bch_btree_node_iter_init_from_start(&src_iter, &src->keys,
					    btree_node_is_extents(src));

	if (btree_node_ops(src)->key_normalize ||
	    btree_node_ops(src)->key_merge)
		nr = sort_repack_merge(c, dst->keys.set->data,
				&src->keys, &src_iter,
				&src->keys.format,
				&dst->keys.format,
				true,
				btree_node_ops(src)->key_normalize,
				btree_node_ops(src)->key_merge);
	else
		nr = sort_repack(dst->keys.set->data,
				&src->keys, &src_iter,
				&src->keys.format,
				&dst->keys.format,
				true);

	bch_time_stats_update(&c->btree_sort_time, start_time);

	dst->keys.nr.live_u64s		+= nr.live_u64s;
	dst->keys.nr.bset_u64s[0]	+= nr.bset_u64s[0];
	dst->keys.nr.packed_keys	+= nr.packed_keys;
	dst->keys.nr.unpacked_keys	+= nr.unpacked_keys;

	bch_verify_btree_nr_keys(&dst->keys);
}

#define SORT_CRIT	(4096 / sizeof(u64))

/*
 * We're about to add another bset to the btree node, so if there's currently
 * too many bsets - sort some of them together:
 */
static bool btree_node_compact(struct cache_set *c, struct btree *b,
			       struct btree_iter *iter)
{
	unsigned unwritten_idx;
	bool ret = false;

	for (unwritten_idx = 0;
	     unwritten_idx < b->keys.nsets;
	     unwritten_idx++)
		if (bset_unwritten(b, b->keys.set[unwritten_idx].data))
			break;

	if (b->keys.nsets - unwritten_idx > 1) {
		btree_node_sort(c, b, iter, unwritten_idx,
				b->keys.nsets, false);
		ret = true;
	}

	if (unwritten_idx > 1) {
		btree_node_sort(c, b, iter, 0, unwritten_idx, false);
		ret = true;
	}

	return ret;
}

void bch_btree_build_aux_trees(struct btree *b)
{
	struct bset_tree *t;

	for_each_bset(&b->keys, t)
		bch_bset_build_aux_tree(&b->keys, t,
				bset_unwritten(b, t->data) &&
				t == bset_tree_last(&b->keys));
}

/*
 * @bch_btree_init_next - initialize a new (unwritten) bset that can then be
 * inserted into
 *
 * Safe to call if there already is an unwritten bset - will only add a new bset
 * if @b doesn't already have one.
 *
 * Returns true if we sorted (i.e. invalidated iterators
 */
void bch_btree_init_next(struct cache_set *c, struct btree *b,
			 struct btree_iter *iter)
{
	struct btree_node_entry *bne;
	bool did_sort;

	EBUG_ON(!(b->lock.state.seq & 1));
	EBUG_ON(iter && iter->nodes[b->level] != b);

	did_sort = btree_node_compact(c, b, iter);

	bne = want_new_bset(c, b);
	if (bne)
		bch_bset_init_next(&b->keys, &bne->keys);

	bch_btree_build_aux_trees(b);

	if (iter && did_sort)
		bch_btree_iter_reinit_node(iter, b);
}

/*
 * We seed the checksum with the entire first pointer (dev, gen and offset),
 * since for btree nodes we have to store the checksum with the data instead of
 * the pointer - this helps guard against reading a valid btree node that is not
 * the node we actually wanted:
 */
#define btree_csum_set(_b, _i)						\
({									\
	void *_data = (void *) (_i) + 8;				\
	void *_end = bset_bkey_last(&(_i)->keys);			\
									\
	bch_checksum_update(BSET_CSUM_TYPE(&(_i)->keys),		\
			    bkey_i_to_extent_c(&(_b)->key)->v._data[0],	\
			    _data,					\
			    _end - _data) ^ 0xffffffffffffffffULL;	\
})

#define btree_node_error(b, c, ptr, fmt, ...)				\
	cache_set_inconsistent(c,					\
		"btree node error at btree %u level %u/%u bucket %zu block %u u64s %u: " fmt,\
		(b)->btree_id, (b)->level, btree_node_root(c, b)	\
			    ? btree_node_root(c, b)->level : -1,	\
		PTR_BUCKET_NR(ca, ptr), (b)->written,			\
		(i)->u64s, ##__VA_ARGS__)

static const char *validate_bset(struct cache_set *c, struct btree *b,
				 struct cache *ca,
				 const struct bch_extent_ptr *ptr,
				 struct bset *i, unsigned sectors,
				 unsigned *whiteout_u64s)
{
	struct bkey_format *f = &b->keys.format;
	struct bkey_packed *k, *prev = NULL;
	bool seen_non_whiteout = false;

	if (le16_to_cpu(i->version) != BCACHE_BSET_VERSION)
		return "unsupported bset version";

	if (b->written + sectors > c->sb.btree_node_size)
		return  "bset past end of btree node";

	if (i != &b->data->keys && !i->u64s)
		btree_node_error(b, c, ptr, "empty set");

	if (!BSET_SEPARATE_WHITEOUTS(i)) {
		seen_non_whiteout = true;
		whiteout_u64s = 0;
	}

	for (k = i->start;
	     k != bset_bkey_last(i);) {
		struct bkey_s_c u;
		struct bkey tmp;
		const char *invalid;

		if (!k->u64s) {
			btree_node_error(b, c, ptr,
				"KEY_U64s 0: %zu bytes of metadata lost",
				(void *) bset_bkey_last(i) - (void *) k);

			i->u64s = cpu_to_le16((u64 *) k - i->_data);
			break;
		}

		if (bkey_next(k) > bset_bkey_last(i)) {
			btree_node_error(b, c, ptr,
					 "key extends past end of bset");

			i->u64s = cpu_to_le16((u64 *) k - i->_data);
			break;
		}

		if (k->format > KEY_FORMAT_CURRENT) {
			btree_node_error(b, c, ptr,
					 "invalid bkey format %u", k->format);

			i->u64s = cpu_to_le16(le16_to_cpu(i->u64s) - k->u64s);
			memmove_u64s_down(k, bkey_next(k),
					  (u64 *) bset_bkey_last(i) - (u64 *) k);
			continue;
		}

		if (BSET_BIG_ENDIAN(i) != CPU_BIG_ENDIAN)
			bch_bkey_swab(btree_node_type(b), &b->keys.format, k);

		u = bkey_disassemble(f, k, &tmp);

		invalid = btree_bkey_invalid(c, b, u);
		if (invalid) {
			char buf[160];

			bch_bkey_val_to_text(c, btree_node_type(b),
					     buf, sizeof(buf), u);
			btree_node_error(b, c, ptr,
					 "invalid bkey %s: %s", buf, invalid);

			i->u64s = cpu_to_le16(le16_to_cpu(i->u64s) - k->u64s);
			memmove_u64s_down(k, bkey_next(k),
					  (u64 *) bset_bkey_last(i) - (u64 *) k);
			continue;
		}

		/*
		 * with the separate whiteouts thing (used for extents), the
		 * second set of keys actually can have whiteouts too, so we
		 * can't solely go off bkey_whiteout()...
		 */

		if (!seen_non_whiteout &&
		    (!bkey_whiteout(k) ||
		     (prev && bkey_cmp_left_packed(f, prev,
					bkey_start_pos(u.k)) > 0))) {
			*whiteout_u64s = k->_data - i->_data;
			seen_non_whiteout = true;
		}

		prev = k;
		k = bkey_next(k);
	}

	SET_BSET_BIG_ENDIAN(i, CPU_BIG_ENDIAN);

	b->written += sectors;
	return NULL;
}

void bch_btree_node_read_done(struct cache_set *c, struct btree *b,
			      struct cache *ca,
			      const struct bch_extent_ptr *ptr)
{
	struct btree_node_entry *bne;
	struct bset *i = &b->data->keys;
	struct btree_node_iter *iter;
	struct btree_node *sorted;
	bool used_mempool;
	unsigned u64s;
	const char *err;
	int ret;

	iter = mempool_alloc(&c->fill_iter, GFP_NOIO);
	__bch_btree_node_iter_init(iter, btree_node_is_extents(b));

	err = "dynamic fault";
	if (bch_meta_read_fault("btree"))
		goto err;

	while (b->written < c->sb.btree_node_size) {
		unsigned sectors, whiteout_u64s = 0;

		if (!b->written) {
			i = &b->data->keys;

			err = "unknown checksum type";
			if (BSET_CSUM_TYPE(i) >= BCH_CSUM_NR)
				goto err;

			/* XXX: retry checksum errors */

			err = "bad checksum";
			if (le64_to_cpu(b->data->csum) !=
			    btree_csum_set(b, b->data))
				goto err;

			sectors = __set_blocks(b->data,
					       le16_to_cpu(b->data->keys.u64s),
					       block_bytes(c)) << c->block_bits;

			err = "bad magic";
			if (le64_to_cpu(b->data->magic) != bset_magic(&c->disk_sb))
				goto err;

			err = "bad btree header";
			if (!b->data->keys.seq)
				goto err;

			if (BSET_BIG_ENDIAN(i) != CPU_BIG_ENDIAN) {
				bch_bpos_swab(&b->data->min_key);
				bch_bpos_swab(&b->data->max_key);
			}

			err = "incorrect max key";
			if (bkey_cmp(b->data->max_key, b->key.k.p))
				goto err;

			err = "incorrect level";
			if (BSET_BTREE_LEVEL(i) != b->level)
				goto err;

			err = bch_bkey_format_validate(&b->data->format);
			if (err)
				goto err;

			b->keys.format = b->data->format;
			b->keys.set->data = &b->data->keys;
		} else {
			bne = write_block(b);
			i = &bne->keys;

			if (i->seq != b->data->keys.seq)
				break;

			err = "unknown checksum type";
			if (BSET_CSUM_TYPE(i) >= BCH_CSUM_NR)
				goto err;

			err = "bad checksum";
			if (le64_to_cpu(bne->csum) !=
			    btree_csum_set(b, bne))
				goto err;

			sectors = __set_blocks(bne,
					       le16_to_cpu(bne->keys.u64s),
					       block_bytes(c)) << c->block_bits;
		}

		err = validate_bset(c, b, ca, ptr, i, sectors, &whiteout_u64s);
		if (err)
			goto err;

		err = "insufficient memory";
		ret = bch_journal_seq_should_ignore(c, le64_to_cpu(i->journal_seq), b);
		if (ret < 0)
			goto err;

		if (ret)
			continue;

		__bch_btree_node_iter_push(iter, &b->keys,
					   i->start,
					   bkey_idx(i, whiteout_u64s));

		__bch_btree_node_iter_push(iter, &b->keys,
					   bkey_idx(i, whiteout_u64s),
					   bset_bkey_last(i));
	}

	err = "corrupted btree";
	for (bne = write_block(b);
	     bset_byte_offset(b, bne) < btree_bytes(c);
	     bne = (void *) bne + block_bytes(c))
		if (bne->keys.seq == b->data->keys.seq)
			goto err;

	sorted = btree_bounce_alloc(c, ilog2(btree_pages(c)), &used_mempool);
	sorted->keys.u64s = 0;

	b->keys.nr = btree_node_is_extents(b)
		? bch_extent_sort_fix_overlapping(c, &sorted->keys, &b->keys, iter)
		: bch_key_sort_fix_overlapping(&sorted->keys, &b->keys, iter);

	u64s = le16_to_cpu(sorted->keys.u64s);
	*sorted = *b->data;
	sorted->keys.u64s = cpu_to_le16(u64s);
	swap(sorted, b->data);
	b->keys.set->data = &b->data->keys;
	b->keys.nsets = 1;

	BUG_ON(b->keys.nr.live_u64s != u64s);

	btree_bounce_free(c, ilog2(btree_pages(c)), used_mempool, sorted);

	bch_bset_build_aux_tree(&b->keys, b->keys.set, false);

	set_needs_whiteout(b->keys.set->data);

	btree_node_reset_sib_u64s(b);

	err = "short btree key";
	if (b->keys.set[0].size &&
	    bkey_cmp_packed(&b->keys.format, &b->key.k,
			    &b->keys.set[0].end) < 0)
		goto err;

out:
	mempool_free(iter, &c->fill_iter);
	return;
err:
	set_btree_node_read_error(b);
	btree_node_error(b, c, ptr, "%s", err);
	goto out;
}

static void btree_node_read_endio(struct bio *bio)
{
	closure_put(bio->bi_private);
}

void bch_btree_node_read(struct cache_set *c, struct btree *b)
{
	uint64_t start_time = local_clock();
	struct closure cl;
	struct bio *bio;
	struct extent_pick_ptr pick;

	trace_bcache_btree_read(c, b);

	closure_init_stack(&cl);

	pick = bch_btree_pick_ptr(c, b);
	if (cache_set_fatal_err_on(!pick.ca, c,
				   "no cache device for btree node")) {
		set_btree_node_read_error(b);
		return;
	}

	bio = bio_alloc_bioset(GFP_NOIO, btree_pages(c), &c->btree_read_bio);
	bio->bi_bdev		= pick.ca->disk_sb.bdev;
	bio->bi_iter.bi_sector	= pick.ptr.offset;
	bio->bi_iter.bi_size	= btree_bytes(c);
	bio->bi_end_io		= btree_node_read_endio;
	bio->bi_private		= &cl;
	bio_set_op_attrs(bio, REQ_OP_READ, REQ_META|READ_SYNC);

	bch_bio_map(bio, b->data);

	closure_get(&cl);
	bch_generic_make_request(bio, c);
	closure_sync(&cl);

	if (cache_fatal_io_err_on(bio->bi_error,
				  pick.ca, "IO error reading bucket %zu",
				  PTR_BUCKET_NR(pick.ca, &pick.ptr)) ||
	    bch_meta_read_fault("btree")) {
		set_btree_node_read_error(b);
		goto out;
	}

	bch_btree_node_read_done(c, b, pick.ca, &pick.ptr);
	bch_time_stats_update(&c->btree_read_time, start_time);
out:
	bio_put(bio);
	percpu_ref_put(&pick.ca->ref);
}

int bch_btree_root_read(struct cache_set *c, enum btree_id id,
			const struct bkey_i *k, unsigned level)
{
	struct closure cl;
	struct btree *b;
	int ret;

	closure_init_stack(&cl);

	do {
		ret = mca_cannibalize_lock(c, &cl);
		closure_sync(&cl);
	} while (ret);

	b = mca_alloc(c);
	mca_cannibalize_unlock(c);

	BUG_ON(IS_ERR(b));

	bkey_copy(&b->key, k);
	BUG_ON(mca_hash_insert(c, b, level, id));

	bch_btree_node_read(c, b);
	six_unlock_write(&b->lock);

	if (btree_node_read_error(b)) {
		six_unlock_intent(&b->lock);
		return -EIO;
	}

	bch_btree_set_root_initial(c, b, NULL);
	six_unlock_intent(&b->lock);

	return 0;
}

void bch_btree_complete_write(struct cache_set *c, struct btree *b,
			      struct btree_write *w)
{
	bch_journal_pin_drop(&c->journal, &w->journal);
	closure_wake_up(&w->wait);
}

static void btree_node_write_done(struct cache_set *c, struct btree *b)
{
	struct btree_write *w = btree_prev_write(b);

	/*
	 * Before calling bch_btree_complete_write() - if the write errored, we
	 * have to halt new journal writes before they see this btree node
	 * write as completed:
	 */
	if (btree_node_write_error(b))
		bch_journal_halt(&c->journal);

	bch_btree_complete_write(c, b, w);
	btree_node_io_unlock(b);
}

static void btree_node_write_endio(struct bio *bio)
{
	struct btree *b = bio->bi_private;
	struct bch_write_bio *wbio = to_wbio(bio);
	struct cache_set *c	= wbio->c;
	struct bio *orig	= wbio->split ? wbio->orig : NULL;
	struct closure *cl	= !wbio->split ? wbio->cl : NULL;
	struct cache *ca	= wbio->ca;

	if (cache_fatal_io_err_on(bio->bi_error, ca, "btree write") ||
	    bch_meta_write_fault("btree"))
		set_btree_node_write_error(b);

	if (wbio->bounce)
		btree_bounce_free(c,
			wbio->order,
			wbio->used_mempool,
			page_address(bio->bi_io_vec[0].bv_page));

	if (wbio->put_bio)
		bio_put(bio);

	if (orig) {
		bio_endio(orig);
	} else {
		btree_node_write_done(c, b);
		if (cl)
			closure_put(cl);
	}

	if (ca)
		percpu_ref_put(&ca->ref);
}

void __bch_btree_node_write(struct cache_set *c, struct btree *b,
			    struct closure *parent,
			    enum six_lock_type lock_type_held,
			    int idx_to_write)
{
	struct bio *bio;
	struct bch_write_bio *wbio;
	struct bset_tree *t;
	struct bset *i;
	struct btree_node *bn = NULL;
	struct btree_node_entry *bne = NULL;
	BKEY_PADDED(key) k;
	struct bkey_s_extent e;
	struct bch_extent_ptr *ptr;
	struct cache *ca;
	struct sort_iter sort_iter;
	unsigned bytes_to_write, sectors_to_write, order, bytes, u64s;
	u64 seq = 0;
	bool used_mempool;
	unsigned long old, new;
	void *data;

	/*
	 * We may only have a read lock on the btree node - the dirty bit is our
	 * "lock" against racing with other threads that may be trying to start
	 * a write, we do a write iff we clear the dirty bit. Since setting the
	 * dirty bit requires a write lock, we can't race with other threads
	 * redirtying it:
	 */
	do {
		old = new = READ_ONCE(b->flags);

		if (!(old & (1 << BTREE_NODE_dirty)))
			return;

		if (idx_to_write >= 0 &&
		    idx_to_write != !!(old & (1 << BTREE_NODE_write_idx)))
			return;

		if (old & (1 << BTREE_NODE_write_in_flight)) {
			wait_on_bit_io(&b->flags,
				       BTREE_NODE_write_in_flight,
				       TASK_UNINTERRUPTIBLE);
			continue;
		}

		new &= ~(1 << BTREE_NODE_dirty);
		new |=  (1 << BTREE_NODE_write_in_flight);
		new |=  (1 << BTREE_NODE_just_written);
		new ^=  (1 << BTREE_NODE_write_idx);
	} while (cmpxchg_acquire(&b->flags, old, new) != old);

	BUG_ON(!list_empty(&b->write_blocked));

	BUG_ON(b->written >= c->sb.btree_node_size);
	BUG_ON(bset_written(b, btree_bset_last(b)));
	BUG_ON(le64_to_cpu(b->data->magic) != bset_magic(&c->disk_sb));
	BUG_ON(memcmp(&b->data->format, &b->keys.format,
		      sizeof(b->keys.format)));

	if (lock_type_held == SIX_LOCK_intent) {
		six_lock_write(&b->lock);
		__compact_whiteouts(c, b, COMPACT_WRITTEN);
		six_unlock_write(&b->lock);
	} else {
		__compact_whiteouts(c, b, COMPACT_WRITTEN_NO_WRITE_LOCK);
	}

	BUG_ON(b->uncompacted_whiteout_u64s);

	sort_iter_init(&sort_iter, &b->keys);

	bytes = !b->written
		? sizeof(struct btree_node)
		: sizeof(struct btree_node_entry);

	bytes += b->whiteout_u64s * sizeof(u64);

	for_each_bset(&b->keys, t) {
		i = t->data;

		if (bset_written(b, i))
			continue;

		bytes += le16_to_cpu(i->u64s) * sizeof(u64);
		sort_iter_add(&sort_iter, i->start, bset_bkey_last(i));
		seq = max(seq, le64_to_cpu(i->journal_seq));
	}

	order = get_order(bytes);
	data = btree_bounce_alloc(c, order, &used_mempool);

	if (!b->written) {
		bn = data;
		*bn = *b->data;
		i = &bn->keys;
	} else {
		bne = data;
		bne->keys = b->data->keys;
		i = &bne->keys;
	}

	i->journal_seq	= cpu_to_le64(seq);
	i->u64s		= 0;

	if (!btree_node_is_extents(b)) {
		sort_iter_add(&sort_iter,
			      unwritten_whiteouts_start(c, b),
			      unwritten_whiteouts_end(c, b));
		SET_BSET_SEPARATE_WHITEOUTS(i, false);
	} else {
		memcpy_u64s(i->start,
			    unwritten_whiteouts_start(c, b),
			    b->whiteout_u64s);
		i->u64s = cpu_to_le16(b->whiteout_u64s);
		SET_BSET_SEPARATE_WHITEOUTS(i, true);
	}

	b->whiteout_u64s = 0;

	u64s = btree_node_is_extents(b)
		? sort_extents(bset_bkey_last(i), &sort_iter, false)
		: sort_keys(i->start, &sort_iter, false);
	le16_add_cpu(&i->u64s, u64s);

	clear_needs_whiteout(i);

	if (b->written && !i->u64s) {
		/* Nothing to write: */
		btree_bounce_free(c, order, used_mempool, data);
		btree_node_write_done(c, b);
		return;
	}

	BUG_ON(BSET_BIG_ENDIAN(i) != CPU_BIG_ENDIAN);
	BUG_ON(i->seq != b->data->keys.seq);

	i->version = cpu_to_le16(BCACHE_BSET_VERSION);
	SET_BSET_CSUM_TYPE(i, c->opts.metadata_checksum);

	if (bn)
		bn->csum = cpu_to_le64(btree_csum_set(b, bn));
	else
		bne->csum = cpu_to_le64(btree_csum_set(b, bne));

	bytes_to_write = (void *) bset_bkey_last(i) - data;
	sectors_to_write = round_up(bytes_to_write, block_bytes(c)) >> 9;

	BUG_ON(b->written + sectors_to_write > c->sb.btree_node_size);

	trace_bcache_btree_write(b, bytes_to_write, sectors_to_write);

	/*
	 * We handle btree write errors by immediately halting the journal -
	 * after we've done that, we can't issue any subsequent btree writes
	 * because they might have pointers to new nodes that failed to write.
	 *
	 * Furthermore, there's no point in doing any more btree writes because
	 * with the journal stopped, we're never going to update the journal to
	 * reflect that those writes were done and the data flushed from the
	 * journal:
	 *
	 * Make sure to update b->written so bch_btree_init_next() doesn't
	 * break:
	 */
	if (bch_journal_error(&c->journal)) {
		set_btree_node_write_error(b);
		b->written += sectors_to_write;

		btree_bounce_free(c, order, used_mempool, data);
		btree_node_write_done(c, b);
		return;
	}

	bio = bio_alloc_bioset(GFP_NOIO, 1 << order, &c->bio_write);

	wbio			= to_wbio(bio);
	wbio->cl		= parent;
	wbio->bounce		= true;
	wbio->put_bio		= true;
	wbio->order		= order;
	wbio->used_mempool	= used_mempool;
	bio->bi_iter.bi_size	= sectors_to_write << 9;
	bio->bi_end_io		= btree_node_write_endio;
	bio->bi_private		= b;
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_META|WRITE_SYNC|REQ_FUA);

	if (parent)
		closure_get(parent);

	bch_bio_map(bio, data);

	/*
	 * If we're appending to a leaf node, we don't technically need FUA -
	 * this write just needs to be persisted before the next journal write,
	 * which will be marked FLUSH|FUA.
	 *
	 * Similarly if we're writing a new btree root - the pointer is going to
	 * be in the next journal entry.
	 *
	 * But if we're writing a new btree node (that isn't a root) or
	 * appending to a non leaf btree node, we need either FUA or a flush
	 * when we write the parent with the new pointer. FUA is cheaper than a
	 * flush, and writes appending to leaf nodes aren't blocking anything so
	 * just make all btree node writes FUA to keep things sane.
	 */

	bkey_copy(&k.key, &b->key);
	e = bkey_i_to_s_extent(&k.key);

	extent_for_each_ptr(e, ptr)
		ptr->offset += b->written;

	rcu_read_lock();
	extent_for_each_online_device(c, e, ptr, ca)
		atomic64_add(sectors_to_write, &ca->btree_sectors_written);
	rcu_read_unlock();

	b->written += sectors_to_write;

	bch_submit_wbio_replicas(wbio, c, &k.key, true);
}

/*
 * Work that must be done with write lock held:
 */
bool bch_btree_post_write_cleanup(struct cache_set *c, struct btree *b)
{
	bool invalidated_iter = false;
	struct btree_node_entry *bne;
	struct bset_tree *t;

	if (!btree_node_just_written(b))
		return false;

	BUG_ON(b->whiteout_u64s);
	BUG_ON(b->uncompacted_whiteout_u64s);

	clear_btree_node_just_written(b);

	/*
	 * Note: immediately after write, bset_unwritten()/bset_written() don't
	 * work - the amount of data we had to write after compaction might have
	 * been smaller than the offset of the last bset.
	 *
	 * However, we know that all bsets have been written here, as long as
	 * we're still holding the write lock:
	 */

	/*
	 * XXX: decide if we really want to unconditionally sort down to a
	 * single bset:
	 */
	if (b->keys.nsets > 1) {
		btree_node_sort(c, b, NULL, 0, b->keys.nsets, true);
		invalidated_iter = true;
	} else {
		invalidated_iter = bch_drop_whiteouts(b);
	}

	for_each_bset(&b->keys, t)
		set_needs_whiteout(t->data);

	bch_btree_verify(c, b);

	/*
	 * If later we don't unconditionally sort down to a single bset, we have
	 * to ensure this is still true:
	 */
	BUG_ON((void *) bset_bkey_last(btree_bset_last(b)) > write_block(b));

	bne = want_new_bset(c, b);
	if (bne)
		bch_bset_init_next(&b->keys, &bne->keys);

	bch_btree_build_aux_trees(b);

	return invalidated_iter;
}

/*
 * Use this one if the node is intent locked:
 */
void bch_btree_node_write(struct cache_set *c, struct btree *b,
			  struct closure *parent,
			  enum six_lock_type lock_type_held,
			  int idx_to_write)
{
	BUG_ON(lock_type_held == SIX_LOCK_write);

	if (lock_type_held == SIX_LOCK_intent ||
	    six_trylock_convert(&b->lock, SIX_LOCK_read,
				SIX_LOCK_intent)) {
		__bch_btree_node_write(c, b, parent, SIX_LOCK_intent, idx_to_write);

		six_lock_write(&b->lock);
		bch_btree_post_write_cleanup(c, b);
		six_unlock_write(&b->lock);

		if (lock_type_held == SIX_LOCK_read)
			six_lock_downgrade(&b->lock);
	} else {
		__bch_btree_node_write(c, b, parent, SIX_LOCK_read, idx_to_write);
	}
}

static void bch_btree_node_write_dirty(struct cache_set *c, struct btree *b,
				       struct closure *parent)
{
	six_lock_read(&b->lock);
	BUG_ON(b->level);

	bch_btree_node_write(c, b, parent, SIX_LOCK_read, -1);
	six_unlock_read(&b->lock);
}

/*
 * Write all dirty btree nodes to disk, including roots
 */
void bch_btree_flush(struct cache_set *c)
{
	struct closure cl;
	struct btree *b;
	struct bucket_table *tbl;
	struct rhash_head *pos;
	bool dropped_lock;
	unsigned i;

	closure_init_stack(&cl);

	rcu_read_lock();

	do {
		dropped_lock = false;
		i = 0;
restart:
		tbl = rht_dereference_rcu(c->btree_cache_table.tbl,
					  &c->btree_cache_table);

		for (; i < tbl->size; i++)
			rht_for_each_entry_rcu(b, pos, tbl, i, hash)
				/*
				 * XXX - locking for b->level, when called from
				 * bch_journal_move()
				 */
				if (!b->level && btree_node_dirty(b)) {
					rcu_read_unlock();
					bch_btree_node_write_dirty(c, b, &cl);
					dropped_lock = true;
					rcu_read_lock();
					goto restart;
				}
	} while (dropped_lock);

	rcu_read_unlock();

	closure_sync(&cl);
}

/**
 * bch_btree_node_flush_journal - flush any journal entries that contain keys
 * from this node
 *
 * The bset's journal sequence number is used for preserving ordering of index
 * updates across unclean shutdowns - it's used to ignore bsets newer than the
 * most recent journal entry.
 *
 * But when rewriting btree nodes we compact all the bsets in a btree node - and
 * if we compacted a bset that should be ignored with bsets we do need, that
 * would be bad. So to avoid that, prior to making the new node visible ensure
 * that the journal has been flushed so that all the bsets we compacted should
 * be visible.
 */
void bch_btree_node_flush_journal_entries(struct cache_set *c,
					  struct btree *b,
					  struct closure *cl)
{
	int i = b->keys.nsets;

	/*
	 * Journal sequence numbers in the different bsets will always be in
	 * ascending order, we only need to flush the highest - except that the
	 * most recent bset might not have a journal sequence number yet, so we
	 * need to loop:
	 */
	while (i--) {
		u64 seq = le64_to_cpu(b->keys.set[i].data->journal_seq);

		if (seq) {
			bch_journal_flush_seq_async(&c->journal, seq, cl);
			break;
		}
	}
}

