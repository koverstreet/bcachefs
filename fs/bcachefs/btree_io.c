// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "bkey_methods.h"
#include "bkey_sort.h"
#include "btree_cache.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_locking.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "buckets.h"
#include "checksum.h"
#include "debug.h"
#include "error.h"
#include "extents.h"
#include "io.h"
#include "journal_reclaim.h"
#include "journal_seq_blacklist.h"
#include "super-io.h"
#include "trace.h"

#include <linux/sched/mm.h>

static void verify_no_dups(struct btree *b,
			   struct bkey_packed *start,
			   struct bkey_packed *end)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	struct bkey_packed *k, *p;

	if (start == end)
		return;

	for (p = start, k = bkey_next(start);
	     k != end;
	     p = k, k = bkey_next(k)) {
		struct bkey l = bkey_unpack_key(b, p);
		struct bkey r = bkey_unpack_key(b, k);

		BUG_ON(bpos_cmp(l.p, bkey_start_pos(&r)) >= 0);
	}
#endif
}

static void set_needs_whiteout(struct bset *i, int v)
{
	struct bkey_packed *k;

	for (k = i->start; k != vstruct_last(i); k = bkey_next(k))
		k->needs_whiteout = v;
}

static void btree_bounce_free(struct bch_fs *c, size_t size,
			      bool used_mempool, void *p)
{
	if (used_mempool)
		mempool_free(p, &c->btree_bounce_pool);
	else
		vpfree(p, size);
}

static void *btree_bounce_alloc(struct bch_fs *c, size_t size,
				bool *used_mempool)
{
	unsigned flags = memalloc_nofs_save();
	void *p;

	BUG_ON(size > btree_bytes(c));

	*used_mempool = false;
	p = vpmalloc(size, __GFP_NOWARN|GFP_NOWAIT);
	if (!p) {
		*used_mempool = true;
		p = mempool_alloc(&c->btree_bounce_pool, GFP_NOIO);
	}
	memalloc_nofs_restore(flags);
	return p;
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

static void bch2_sort_whiteouts(struct bch_fs *c, struct btree *b)
{
	struct bkey_packed *new_whiteouts, **ptrs, **ptrs_end, *k;
	bool used_mempool = false;
	size_t bytes = b->whiteout_u64s * sizeof(u64);

	if (!b->whiteout_u64s)
		return;

	new_whiteouts = btree_bounce_alloc(c, bytes, &used_mempool);

	ptrs = ptrs_end = ((void *) new_whiteouts + bytes);

	for (k = unwritten_whiteouts_start(c, b);
	     k != unwritten_whiteouts_end(c, b);
	     k = bkey_next(k))
		*--ptrs = k;

	sort_bkey_ptrs(b, ptrs, ptrs_end - ptrs);

	k = new_whiteouts;

	while (ptrs != ptrs_end) {
		bkey_copy(k, *ptrs);
		k = bkey_next(k);
		ptrs++;
	}

	verify_no_dups(b, new_whiteouts,
		       (void *) ((u64 *) new_whiteouts + b->whiteout_u64s));

	memcpy_u64s(unwritten_whiteouts_start(c, b),
		    new_whiteouts, b->whiteout_u64s);

	btree_bounce_free(c, bytes, used_mempool, new_whiteouts);
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

static bool bch2_drop_whiteouts(struct btree *b, enum compact_mode mode)
{
	struct bset_tree *t;
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
			n = bkey_next(k);

			if (!bkey_deleted(k)) {
				bkey_copy(out, k);
				out = bkey_next(out);
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

static void btree_node_sort(struct bch_fs *c, struct btree *b,
			    unsigned start_idx,
			    unsigned end_idx,
			    bool filter_whiteouts)
{
	struct btree_node *out;
	struct sort_iter sort_iter;
	struct bset_tree *t;
	struct bset *start_bset = bset(b, &b->set[start_idx]);
	bool used_mempool = false;
	u64 start_time, seq = 0;
	unsigned i, u64s = 0, bytes, shift = end_idx - start_idx - 1;
	bool sorting_entire_node = start_idx == 0 &&
		end_idx == b->nsets;

	sort_iter_init(&sort_iter, b);

	for (t = b->set + start_idx;
	     t < b->set + end_idx;
	     t++) {
		u64s += le16_to_cpu(bset(b, t)->u64s);
		sort_iter_add(&sort_iter,
			      btree_bkey_first(b, t),
			      btree_bkey_last(b, t));
	}

	bytes = sorting_entire_node
		? btree_bytes(c)
		: __vstruct_bytes(struct btree_node, u64s);

	out = btree_bounce_alloc(c, bytes, &used_mempool);

	start_time = local_clock();

	u64s = bch2_sort_keys(out->keys.start, &sort_iter, filter_whiteouts);

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
		unsigned u64s = le16_to_cpu(out->keys.u64s);

		BUG_ON(bytes != btree_bytes(c));

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

	btree_bounce_free(c, bytes, used_mempool, out);

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

	if (btree_node_is_extents(src))
		nr = bch2_sort_repack_merge(c, btree_bset_first(dst),
				src, &src_iter,
				&dst->format,
				true);
	else
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

#define SORT_CRIT	(4096 / sizeof(u64))

/*
 * We're about to add another bset to the btree node, so if there's currently
 * too many bsets - sort some of them together:
 */
static bool btree_node_compact(struct bch_fs *c, struct btree *b)
{
	unsigned unwritten_idx;
	bool ret = false;

	for (unwritten_idx = 0;
	     unwritten_idx < b->nsets;
	     unwritten_idx++)
		if (!bset_written(b, bset(b, &b->set[unwritten_idx])))
			break;

	if (b->nsets - unwritten_idx > 1) {
		btree_node_sort(c, b, unwritten_idx,
				b->nsets, false);
		ret = true;
	}

	if (unwritten_idx > 1) {
		btree_node_sort(c, b, 0, unwritten_idx, false);
		ret = true;
	}

	return ret;
}

void bch2_btree_build_aux_trees(struct btree *b)
{
	struct bset_tree *t;

	for_each_bset(b, t)
		bch2_bset_build_aux_tree(b, t,
				!bset_written(b, bset(b, t)) &&
				t == bset_tree_last(b));
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
void bch2_btree_init_next(struct bch_fs *c, struct btree *b,
			  struct btree_iter *iter)
{
	struct btree_node_entry *bne;
	bool reinit_iter = false;

	EBUG_ON(!(b->c.lock.state.seq & 1));
	EBUG_ON(iter && iter->l[b->c.level].b != b);
	BUG_ON(bset_written(b, bset(b, &b->set[1])));

	if (b->nsets == MAX_BSETS) {
		unsigned log_u64s[] = {
			ilog2(bset_u64s(&b->set[0])),
			ilog2(bset_u64s(&b->set[1])),
			ilog2(bset_u64s(&b->set[2])),
		};

		if (log_u64s[1] >= (log_u64s[0] + log_u64s[2]) / 2) {
			bch2_btree_node_write(c, b, SIX_LOCK_write);
			reinit_iter = true;
		}
	}

	if (b->nsets == MAX_BSETS &&
	    btree_node_compact(c, b))
		reinit_iter = true;

	BUG_ON(b->nsets >= MAX_BSETS);

	bne = want_new_bset(c, b);
	if (bne)
		bch2_bset_init_next(c, b, bne);

	bch2_btree_build_aux_trees(b);

	if (iter && reinit_iter)
		bch2_btree_iter_reinit_node(iter, b);
}

static void btree_pos_to_text(struct printbuf *out, struct bch_fs *c,
			  struct btree *b)
{
	pr_buf(out, "%s level %u/%u\n  ",
	       bch2_btree_ids[b->c.btree_id],
	       b->c.level,
	       c->btree_roots[b->c.btree_id].level);
	bch2_bkey_val_to_text(out, c, bkey_i_to_s_c(&b->key));
}

static void btree_err_msg(struct printbuf *out, struct bch_fs *c,
			  struct bch_dev *ca,
			  struct btree *b, struct bset *i,
			  unsigned offset, int write)
{
	pr_buf(out, "error validating btree node ");
	if (write)
		pr_buf(out, "before write ");
	if (ca)
		pr_buf(out, "on %s ", ca->name);
	pr_buf(out, "at btree ");
	btree_pos_to_text(out, c, b);

	pr_buf(out, "\n  node offset %u", b->written);
	if (i)
		pr_buf(out, " bset u64s %u", le16_to_cpu(i->u64s));
}

enum btree_err_type {
	BTREE_ERR_FIXABLE,
	BTREE_ERR_WANT_RETRY,
	BTREE_ERR_MUST_RETRY,
	BTREE_ERR_FATAL,
};

enum btree_validate_ret {
	BTREE_RETRY_READ = 64,
};

#define btree_err(type, c, ca, b, i, msg, ...)				\
({									\
	__label__ out;							\
	char _buf[300];							\
	char *_buf2 = _buf;						\
	struct printbuf out = PBUF(_buf);				\
									\
	_buf2 = kmalloc(4096, GFP_ATOMIC);				\
	if (_buf2)							\
		out = _PBUF(_buf2, 4986);				\
									\
	btree_err_msg(&out, c, ca, b, i, b->written, write);		\
	pr_buf(&out, ": " msg, ##__VA_ARGS__);				\
									\
	if (type == BTREE_ERR_FIXABLE &&				\
	    write == READ &&						\
	    !test_bit(BCH_FS_INITIAL_GC_DONE, &c->flags)) {		\
		mustfix_fsck_err(c, "%s", _buf2);			\
		goto out;						\
	}								\
									\
	switch (write) {						\
	case READ:							\
		bch_err(c, "%s", _buf2);				\
									\
		switch (type) {						\
		case BTREE_ERR_FIXABLE:					\
			ret = BCH_FSCK_ERRORS_NOT_FIXED;		\
			goto fsck_err;					\
		case BTREE_ERR_WANT_RETRY:				\
			if (have_retry) {				\
				ret = BTREE_RETRY_READ;			\
				goto fsck_err;				\
			}						\
			break;						\
		case BTREE_ERR_MUST_RETRY:				\
			ret = BTREE_RETRY_READ;				\
			goto fsck_err;					\
		case BTREE_ERR_FATAL:					\
			ret = BCH_FSCK_ERRORS_NOT_FIXED;		\
			goto fsck_err;					\
		}							\
		break;							\
	case WRITE:							\
		bch_err(c, "corrupt metadata before write: %s", _buf2);	\
									\
		if (bch2_fs_inconsistent(c)) {				\
			ret = BCH_FSCK_ERRORS_NOT_FIXED;		\
			goto fsck_err;					\
		}							\
		break;							\
	}								\
out:									\
	if (_buf2 != _buf)						\
		kfree(_buf2);						\
	true;								\
})

#define btree_err_on(cond, ...)	((cond) ? btree_err(__VA_ARGS__) : false)

/*
 * When btree topology repair changes the start or end of a node, that might
 * mean we have to drop keys that are no longer inside the node:
 */
__cold
void bch2_btree_node_drop_keys_outside_node(struct btree *b)
{
	struct bset_tree *t;
	struct bkey_s_c k;
	struct bkey unpacked;
	struct btree_node_iter iter;

	for_each_bset(b, t) {
		struct bset *i = bset(b, t);
		struct bkey_packed *k;

		for (k = i->start; k != vstruct_last(i); k = bkey_next(k))
			if (bkey_cmp_left_packed(b, k, &b->data->min_key) >= 0)
				break;

		if (k != i->start) {
			unsigned shift = (u64 *) k - (u64 *) i->start;

			memmove_u64s_down(i->start, k,
					  (u64 *) vstruct_end(i) - (u64 *) k);
			i->u64s = cpu_to_le16(le16_to_cpu(i->u64s) - shift);
			set_btree_bset_end(b, t);
			bch2_bset_set_no_aux_tree(b, t);
		}

		for (k = i->start; k != vstruct_last(i); k = bkey_next(k))
			if (bkey_cmp_left_packed(b, k, &b->data->max_key) > 0)
				break;

		if (k != vstruct_last(i)) {
			i->u64s = cpu_to_le16((u64 *) k - (u64 *) i->start);
			set_btree_bset_end(b, t);
			bch2_bset_set_no_aux_tree(b, t);
		}
	}

	bch2_btree_build_aux_trees(b);

	for_each_btree_node_key_unpack(b, k, &iter, &unpacked) {
		BUG_ON(bpos_cmp(k.k->p, b->data->min_key) < 0);
		BUG_ON(bpos_cmp(k.k->p, b->data->max_key) > 0);
	}
}

static int validate_bset(struct bch_fs *c, struct bch_dev *ca,
			 struct btree *b, struct bset *i,
			 unsigned sectors, int write, bool have_retry)
{
	unsigned version = le16_to_cpu(i->version);
	const char *err;
	char buf1[100];
	char buf2[100];
	int ret = 0;

	btree_err_on((version != BCH_BSET_VERSION_OLD &&
		      version < bcachefs_metadata_version_min) ||
		     version >= bcachefs_metadata_version_max,
		     BTREE_ERR_FATAL, c, ca, b, i,
		     "unsupported bset version");

	if (btree_err_on(version < c->sb.version_min,
			 BTREE_ERR_FIXABLE, c, NULL, b, i,
			 "bset version %u older than superblock version_min %u",
			 version, c->sb.version_min)) {
		mutex_lock(&c->sb_lock);
		c->disk_sb.sb->version_min = cpu_to_le16(version);
		bch2_write_super(c);
		mutex_unlock(&c->sb_lock);
	}

	if (btree_err_on(version > c->sb.version,
			 BTREE_ERR_FIXABLE, c, NULL, b, i,
			 "bset version %u newer than superblock version %u",
			 version, c->sb.version)) {
		mutex_lock(&c->sb_lock);
		c->disk_sb.sb->version = cpu_to_le16(version);
		bch2_write_super(c);
		mutex_unlock(&c->sb_lock);
	}

	btree_err_on(BSET_SEPARATE_WHITEOUTS(i),
		     BTREE_ERR_FATAL, c, ca, b, i,
		     "BSET_SEPARATE_WHITEOUTS no longer supported");

	if (btree_err_on(b->written + sectors > c->opts.btree_node_size,
			 BTREE_ERR_FIXABLE, c, ca, b, i,
			 "bset past end of btree node")) {
		i->u64s = 0;
		return 0;
	}

	btree_err_on(b->written && !i->u64s,
		     BTREE_ERR_FIXABLE, c, ca, b, i,
		     "empty bset");

	if (!b->written) {
		struct btree_node *bn =
			container_of(i, struct btree_node, keys);
		/* These indicate that we read the wrong btree node: */

		if (b->key.k.type == KEY_TYPE_btree_ptr_v2) {
			struct bch_btree_ptr_v2 *bp =
				&bkey_i_to_btree_ptr_v2(&b->key)->v;

			/* XXX endianness */
			btree_err_on(bp->seq != bn->keys.seq,
				     BTREE_ERR_MUST_RETRY, c, ca, b, NULL,
				     "incorrect sequence number (wrong btree node)");
		}

		btree_err_on(BTREE_NODE_ID(bn) != b->c.btree_id,
			     BTREE_ERR_MUST_RETRY, c, ca, b, i,
			     "incorrect btree id");

		btree_err_on(BTREE_NODE_LEVEL(bn) != b->c.level,
			     BTREE_ERR_MUST_RETRY, c, ca, b, i,
			     "incorrect level");

		if (!write)
			compat_btree_node(b->c.level, b->c.btree_id, version,
					  BSET_BIG_ENDIAN(i), write, bn);

		if (b->key.k.type == KEY_TYPE_btree_ptr_v2) {
			struct bch_btree_ptr_v2 *bp =
				&bkey_i_to_btree_ptr_v2(&b->key)->v;

			if (BTREE_PTR_RANGE_UPDATED(bp)) {
				b->data->min_key = bp->min_key;
				b->data->max_key = b->key.k.p;
			}

			btree_err_on(bpos_cmp(b->data->min_key, bp->min_key),
				     BTREE_ERR_MUST_RETRY, c, ca, b, NULL,
				     "incorrect min_key: got %s should be %s",
				     (bch2_bpos_to_text(&PBUF(buf1), bn->min_key), buf1),
				     (bch2_bpos_to_text(&PBUF(buf2), bp->min_key), buf2));
		}

		btree_err_on(bpos_cmp(bn->max_key, b->key.k.p),
			     BTREE_ERR_MUST_RETRY, c, ca, b, i,
			     "incorrect max key %s",
			     (bch2_bpos_to_text(&PBUF(buf1), bn->max_key), buf1));

		if (write)
			compat_btree_node(b->c.level, b->c.btree_id, version,
					  BSET_BIG_ENDIAN(i), write, bn);

		err = bch2_bkey_format_validate(&bn->format);
		btree_err_on(err,
			     BTREE_ERR_FATAL, c, ca, b, i,
			     "invalid bkey format: %s", err);

		compat_bformat(b->c.level, b->c.btree_id, version,
			       BSET_BIG_ENDIAN(i), write,
			       &bn->format);
	}
fsck_err:
	return ret;
}

static int validate_bset_keys(struct bch_fs *c, struct btree *b,
			 struct bset *i, unsigned *whiteout_u64s,
			 int write, bool have_retry)
{
	unsigned version = le16_to_cpu(i->version);
	struct bkey_packed *k, *prev = NULL;
	bool updated_range = b->key.k.type == KEY_TYPE_btree_ptr_v2 &&
		BTREE_PTR_RANGE_UPDATED(&bkey_i_to_btree_ptr_v2(&b->key)->v);
	int ret = 0;

	for (k = i->start;
	     k != vstruct_last(i);) {
		struct bkey_s u;
		struct bkey tmp;
		const char *invalid;

		if (btree_err_on(bkey_next(k) > vstruct_last(i),
				 BTREE_ERR_FIXABLE, c, NULL, b, i,
				 "key extends past end of bset")) {
			i->u64s = cpu_to_le16((u64 *) k - i->_data);
			break;
		}

		if (btree_err_on(k->format > KEY_FORMAT_CURRENT,
				 BTREE_ERR_FIXABLE, c, NULL, b, i,
				 "invalid bkey format %u", k->format)) {
			i->u64s = cpu_to_le16(le16_to_cpu(i->u64s) - k->u64s);
			memmove_u64s_down(k, bkey_next(k),
					  (u64 *) vstruct_end(i) - (u64 *) k);
			continue;
		}

		/* XXX: validate k->u64s */
		if (!write)
			bch2_bkey_compat(b->c.level, b->c.btree_id, version,
				    BSET_BIG_ENDIAN(i), write,
				    &b->format, k);

		u = __bkey_disassemble(b, k, &tmp);

		invalid = __bch2_bkey_invalid(c, u.s_c, btree_node_type(b)) ?:
			(!updated_range ?  bch2_bkey_in_btree_node(b, u.s_c) : NULL) ?:
			(write ? bch2_bkey_val_invalid(c, u.s_c) : NULL);
		if (invalid) {
			char buf[160];

			bch2_bkey_val_to_text(&PBUF(buf), c, u.s_c);
			btree_err(BTREE_ERR_FIXABLE, c, NULL, b, i,
				  "invalid bkey: %s\n%s", invalid, buf);

			i->u64s = cpu_to_le16(le16_to_cpu(i->u64s) - k->u64s);
			memmove_u64s_down(k, bkey_next(k),
					  (u64 *) vstruct_end(i) - (u64 *) k);
			continue;
		}

		if (write)
			bch2_bkey_compat(b->c.level, b->c.btree_id, version,
				    BSET_BIG_ENDIAN(i), write,
				    &b->format, k);

		if (prev && bkey_iter_cmp(b, prev, k) > 0) {
			char buf1[80];
			char buf2[80];
			struct bkey up = bkey_unpack_key(b, prev);

			bch2_bkey_to_text(&PBUF(buf1), &up);
			bch2_bkey_to_text(&PBUF(buf2), u.k);

			bch2_dump_bset(c, b, i, 0);

			if (btree_err(BTREE_ERR_FIXABLE, c, NULL, b, i,
				      "keys out of order: %s > %s",
				      buf1, buf2)) {
				i->u64s = cpu_to_le16(le16_to_cpu(i->u64s) - k->u64s);
				memmove_u64s_down(k, bkey_next(k),
						  (u64 *) vstruct_end(i) - (u64 *) k);
				continue;
			}
		}

		prev = k;
		k = bkey_next(k);
	}
fsck_err:
	return ret;
}

int bch2_btree_node_read_done(struct bch_fs *c, struct bch_dev *ca,
			      struct btree *b, bool have_retry)
{
	struct btree_node_entry *bne;
	struct sort_iter *iter;
	struct btree_node *sorted;
	struct bkey_packed *k;
	struct bch_extent_ptr *ptr;
	struct bset *i;
	bool used_mempool, blacklisted;
	bool updated_range = b->key.k.type == KEY_TYPE_btree_ptr_v2 &&
		BTREE_PTR_RANGE_UPDATED(&bkey_i_to_btree_ptr_v2(&b->key)->v);
	unsigned u64s;
	unsigned nonblacklisted_written = 0;
	int ret, retry_read = 0, write = READ;

	b->version_ondisk = U16_MAX;

	iter = mempool_alloc(&c->fill_iter, GFP_NOIO);
	sort_iter_init(iter, b);
	iter->size = (btree_blocks(c) + 1) * 2;

	if (bch2_meta_read_fault("btree"))
		btree_err(BTREE_ERR_MUST_RETRY, c, ca, b, NULL,
			  "dynamic fault");

	btree_err_on(le64_to_cpu(b->data->magic) != bset_magic(c),
		     BTREE_ERR_MUST_RETRY, c, ca, b, NULL,
		     "bad magic");

	btree_err_on(!b->data->keys.seq,
		     BTREE_ERR_MUST_RETRY, c, ca, b, NULL,
		     "bad btree header");

	if (b->key.k.type == KEY_TYPE_btree_ptr_v2) {
		struct bch_btree_ptr_v2 *bp =
			&bkey_i_to_btree_ptr_v2(&b->key)->v;

		btree_err_on(b->data->keys.seq != bp->seq,
			     BTREE_ERR_MUST_RETRY, c, ca, b, NULL,
			     "got wrong btree node (seq %llx want %llx)",
			     b->data->keys.seq, bp->seq);
	}

	while (b->written < c->opts.btree_node_size) {
		unsigned sectors, whiteout_u64s = 0;
		struct nonce nonce;
		struct bch_csum csum;
		bool first = !b->written;

		if (!b->written) {
			i = &b->data->keys;

			btree_err_on(!bch2_checksum_type_valid(c, BSET_CSUM_TYPE(i)),
				     BTREE_ERR_WANT_RETRY, c, ca, b, i,
				     "unknown checksum type %llu",
				     BSET_CSUM_TYPE(i));

			nonce = btree_nonce(i, b->written << 9);
			csum = csum_vstruct(c, BSET_CSUM_TYPE(i), nonce, b->data);

			btree_err_on(bch2_crc_cmp(csum, b->data->csum),
				     BTREE_ERR_WANT_RETRY, c, ca, b, i,
				     "invalid checksum");

			bset_encrypt(c, i, b->written << 9);

			btree_err_on(btree_node_is_extents(b) &&
				     !BTREE_NODE_NEW_EXTENT_OVERWRITE(b->data),
				     BTREE_ERR_FATAL, c, NULL, b, NULL,
				     "btree node does not have NEW_EXTENT_OVERWRITE set");

			sectors = vstruct_sectors(b->data, c->block_bits);
		} else {
			bne = write_block(b);
			i = &bne->keys;

			if (i->seq != b->data->keys.seq)
				break;

			btree_err_on(!bch2_checksum_type_valid(c, BSET_CSUM_TYPE(i)),
				     BTREE_ERR_WANT_RETRY, c, ca, b, i,
				     "unknown checksum type %llu",
				     BSET_CSUM_TYPE(i));

			nonce = btree_nonce(i, b->written << 9);
			csum = csum_vstruct(c, BSET_CSUM_TYPE(i), nonce, bne);

			btree_err_on(bch2_crc_cmp(csum, bne->csum),
				     BTREE_ERR_WANT_RETRY, c, ca, b, i,
				     "invalid checksum");

			bset_encrypt(c, i, b->written << 9);

			sectors = vstruct_sectors(bne, c->block_bits);
		}

		b->version_ondisk = min(b->version_ondisk,
					le16_to_cpu(i->version));

		ret = validate_bset(c, ca, b, i, sectors,
				    READ, have_retry);
		if (ret)
			goto fsck_err;

		if (!b->written)
			btree_node_set_format(b, b->data->format);

		ret = validate_bset_keys(c, b, i, &whiteout_u64s,
				    READ, have_retry);
		if (ret)
			goto fsck_err;

		SET_BSET_BIG_ENDIAN(i, CPU_BIG_ENDIAN);

		b->written += sectors;

		blacklisted = bch2_journal_seq_is_blacklisted(c,
					le64_to_cpu(i->journal_seq),
					true);

		btree_err_on(blacklisted && first,
			     BTREE_ERR_FIXABLE, c, ca, b, i,
			     "first btree node bset has blacklisted journal seq");
		if (blacklisted && !first)
			continue;

		sort_iter_add(iter, i->start,
			      vstruct_idx(i, whiteout_u64s));

		sort_iter_add(iter,
			      vstruct_idx(i, whiteout_u64s),
			      vstruct_last(i));

		nonblacklisted_written = b->written;
	}

	for (bne = write_block(b);
	     bset_byte_offset(b, bne) < btree_bytes(c);
	     bne = (void *) bne + block_bytes(c))
		btree_err_on(bne->keys.seq == b->data->keys.seq &&
			     !bch2_journal_seq_is_blacklisted(c,
					le64_to_cpu(bne->keys.journal_seq),
					true),
			     BTREE_ERR_WANT_RETRY, c, ca, b, NULL,
			     "found bset signature after last bset");

	/*
	 * Blacklisted bsets are those that were written after the most recent
	 * (flush) journal write. Since there wasn't a flush, they may not have
	 * made it to all devices - which means we shouldn't write new bsets
	 * after them, as that could leave a gap and then reads from that device
	 * wouldn't find all the bsets in that btree node - which means it's
	 * important that we start writing new bsets after the most recent _non_
	 * blacklisted bset:
	 */
	b->written = nonblacklisted_written;

	sorted = btree_bounce_alloc(c, btree_bytes(c), &used_mempool);
	sorted->keys.u64s = 0;

	set_btree_bset(b, b->set, &b->data->keys);

	b->nr = bch2_key_sort_fix_overlapping(c, &sorted->keys, iter);

	u64s = le16_to_cpu(sorted->keys.u64s);
	*sorted = *b->data;
	sorted->keys.u64s = cpu_to_le16(u64s);
	swap(sorted, b->data);
	set_btree_bset(b, b->set, &b->data->keys);
	b->nsets = 1;

	BUG_ON(b->nr.live_u64s != u64s);

	btree_bounce_free(c, btree_bytes(c), used_mempool, sorted);

	if (updated_range)
		bch2_btree_node_drop_keys_outside_node(b);

	i = &b->data->keys;
	for (k = i->start; k != vstruct_last(i);) {
		struct bkey tmp;
		struct bkey_s u = __bkey_disassemble(b, k, &tmp);
		const char *invalid = bch2_bkey_val_invalid(c, u.s_c);

		if (invalid ||
		    (bch2_inject_invalid_keys &&
		     !bversion_cmp(u.k->version, MAX_VERSION))) {
			char buf[160];

			bch2_bkey_val_to_text(&PBUF(buf), c, u.s_c);
			btree_err(BTREE_ERR_FIXABLE, c, NULL, b, i,
				  "invalid bkey %s: %s", buf, invalid);

			btree_keys_account_key_drop(&b->nr, 0, k);

			i->u64s = cpu_to_le16(le16_to_cpu(i->u64s) - k->u64s);
			memmove_u64s_down(k, bkey_next(k),
					  (u64 *) vstruct_end(i) - (u64 *) k);
			set_btree_bset_end(b, b->set);
			continue;
		}

		if (u.k->type == KEY_TYPE_btree_ptr_v2) {
			struct bkey_s_btree_ptr_v2 bp = bkey_s_to_btree_ptr_v2(u);

			bp.v->mem_ptr = 0;
		}

		k = bkey_next(k);
	}

	bch2_bset_build_aux_tree(b, b->set, false);

	set_needs_whiteout(btree_bset_first(b), true);

	btree_node_reset_sib_u64s(b);

	bkey_for_each_ptr(bch2_bkey_ptrs(bkey_i_to_s(&b->key)), ptr) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, ptr->dev);

		if (ca->mi.state != BCH_MEMBER_STATE_rw)
			set_btree_node_need_rewrite(b);
	}
out:
	mempool_free(iter, &c->fill_iter);
	return retry_read;
fsck_err:
	if (ret == BTREE_RETRY_READ) {
		retry_read = 1;
	} else {
		bch2_inconsistent_error(c);
		set_btree_node_read_error(b);
	}
	goto out;
}

static void btree_node_read_work(struct work_struct *work)
{
	struct btree_read_bio *rb =
		container_of(work, struct btree_read_bio, work);
	struct bch_fs *c	= rb->c;
	struct btree *b		= rb->b;
	struct bch_dev *ca	= bch_dev_bkey_exists(c, rb->pick.ptr.dev);
	struct bio *bio		= &rb->bio;
	struct bch_io_failures failed = { .nr = 0 };
	char buf[200];
	struct printbuf out;
	bool saw_error = false;
	bool can_retry;

	goto start;
	while (1) {
		bch_info(c, "retrying read");
		ca = bch_dev_bkey_exists(c, rb->pick.ptr.dev);
		rb->have_ioref		= bch2_dev_get_ioref(ca, READ);
		bio_reset(bio, NULL, REQ_OP_READ|REQ_SYNC|REQ_META);
		bio->bi_iter.bi_sector	= rb->pick.ptr.offset;
		bio->bi_iter.bi_size	= btree_bytes(c);

		if (rb->have_ioref) {
			bio_set_dev(bio, ca->disk_sb.bdev);
			submit_bio_wait(bio);
		} else {
			bio->bi_status = BLK_STS_REMOVED;
		}
start:
		out = PBUF(buf);
		btree_pos_to_text(&out, c, b);
		bch2_dev_io_err_on(bio->bi_status, ca, "btree read error %s for %s",
				   bch2_blk_status_to_str(bio->bi_status), buf);
		if (rb->have_ioref)
			percpu_ref_put(&ca->io_ref);
		rb->have_ioref = false;

		bch2_mark_io_failure(&failed, &rb->pick);

		can_retry = bch2_bkey_pick_read_device(c,
				bkey_i_to_s_c(&b->key),
				&failed, &rb->pick) > 0;

		if (!bio->bi_status &&
		    !bch2_btree_node_read_done(c, ca, b, can_retry))
			break;

		saw_error = true;

		if (!can_retry) {
			set_btree_node_read_error(b);
			break;
		}
	}

	bch2_time_stats_update(&c->times[BCH_TIME_btree_node_read],
			       rb->start_time);
	bio_put(&rb->bio);

	if (saw_error && !btree_node_read_error(b))
		bch2_btree_node_rewrite_async(c, b);

	clear_btree_node_read_in_flight(b);
	wake_up_bit(&b->flags, BTREE_NODE_read_in_flight);
}

static void btree_node_read_endio(struct bio *bio)
{
	struct btree_read_bio *rb =
		container_of(bio, struct btree_read_bio, bio);
	struct bch_fs *c	= rb->c;

	if (rb->have_ioref) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, rb->pick.ptr.dev);
		bch2_latency_acct(ca, rb->start_time, READ);
	}

	queue_work(c->io_complete_wq, &rb->work);
}

struct btree_node_read_all {
	struct closure		cl;
	struct bch_fs		*c;
	struct btree		*b;
	unsigned		nr;
	void			*buf[BCH_REPLICAS_MAX];
	struct bio		*bio[BCH_REPLICAS_MAX];
	int			err[BCH_REPLICAS_MAX];
};

static unsigned btree_node_sectors_written(struct bch_fs *c, void *data)
{
	struct btree_node *bn = data;
	struct btree_node_entry *bne;
	unsigned offset = 0;

	if (le64_to_cpu(bn->magic) !=  bset_magic(c))
		return 0;

	while (offset < c->opts.btree_node_size) {
		if (!offset) {
			offset += vstruct_sectors(bn, c->block_bits);
		} else {
			bne = data + (offset << 9);
			if (bne->keys.seq != bn->keys.seq)
				break;
			offset += vstruct_sectors(bne, c->block_bits);
		}
	}

	return offset;
}

static bool btree_node_has_extra_bsets(struct bch_fs *c, unsigned offset, void *data)
{
	struct btree_node *bn = data;
	struct btree_node_entry *bne;

	if (!offset)
		return false;

	while (offset < c->opts.btree_node_size) {
		bne = data + (offset << 9);
		if (bne->keys.seq == bn->keys.seq)
			return true;
		offset++;
	}

	return false;
	return offset;
}

static void btree_node_read_all_replicas_done(struct closure *cl)
{
	struct btree_node_read_all *ra =
		container_of(cl, struct btree_node_read_all, cl);
	struct bch_fs *c = ra->c;
	struct btree *b = ra->b;
	bool dump_bset_maps = false;
	bool have_retry = false;
	int ret = 0, best = -1, write = READ;
	unsigned i, written, written2;
	__le64 seq = b->key.k.type == KEY_TYPE_btree_ptr_v2
		? bkey_i_to_btree_ptr_v2(&b->key)->v.seq : 0;

	for (i = 0; i < ra->nr; i++) {
		struct btree_node *bn = ra->buf[i];

		if (ra->err[i])
			continue;

		if (le64_to_cpu(bn->magic) != bset_magic(c) ||
		    (seq && seq != bn->keys.seq))
			continue;

		if (best < 0) {
			best = i;
			written = btree_node_sectors_written(c, bn);
			continue;
		}

		written2 = btree_node_sectors_written(c, ra->buf[i]);
		if (btree_err_on(written2 != written, BTREE_ERR_FIXABLE, c, NULL, b, NULL,
				 "btree node sectors written mismatch: %u != %u",
				 written, written2) ||
		    btree_err_on(btree_node_has_extra_bsets(c, written2, ra->buf[i]),
				 BTREE_ERR_FIXABLE, c, NULL, b, NULL,
				 "found bset signature after last bset") ||
		    btree_err_on(memcmp(ra->buf[best], ra->buf[i], written << 9),
				 BTREE_ERR_FIXABLE, c, NULL, b, NULL,
				 "btree node replicas content mismatch"))
			dump_bset_maps = true;

		if (written2 > written) {
			written = written2;
			best = i;
		}
	}
fsck_err:
	if (dump_bset_maps) {
		for (i = 0; i < ra->nr; i++) {
			char buf[200];
			struct printbuf out = PBUF(buf);
			struct btree_node *bn = ra->buf[i];
			struct btree_node_entry *bne = NULL;
			unsigned offset = 0, sectors;
			bool gap = false;

			if (ra->err[i])
				continue;

			while (offset < c->opts.btree_node_size) {
				if (!offset) {
					sectors = vstruct_sectors(bn, c->block_bits);
				} else {
					bne = ra->buf[i] + (offset << 9);
					if (bne->keys.seq != bn->keys.seq)
						break;
					sectors = vstruct_sectors(bne, c->block_bits);
				}

				pr_buf(&out, " %u-%u", offset, offset + sectors);
				if (bne && bch2_journal_seq_is_blacklisted(c,
							le64_to_cpu(bne->keys.journal_seq), false))
					pr_buf(&out, "*");
				offset += sectors;
			}

			while (offset < c->opts.btree_node_size) {
				bne = ra->buf[i] + (offset << 9);
				if (bne->keys.seq == bn->keys.seq) {
					if (!gap)
						pr_buf(&out, " GAP");
					gap = true;

					sectors = vstruct_sectors(bne, c->block_bits);
					pr_buf(&out, " %u-%u", offset, offset + sectors);
					if (bch2_journal_seq_is_blacklisted(c,
							le64_to_cpu(bne->keys.journal_seq), false))
						pr_buf(&out, "*");
				}
				offset++;
			}

			bch_err(c, "replica %u:%s", i, buf);
		}
	}

	if (best >= 0) {
		memcpy(b->data, ra->buf[best], btree_bytes(c));
		ret = bch2_btree_node_read_done(c, NULL, b, false);
	} else {
		ret = -1;
	}

	if (ret)
		set_btree_node_read_error(b);

	for (i = 0; i < ra->nr; i++) {
		mempool_free(ra->buf[i], &c->btree_bounce_pool);
		bio_put(ra->bio[i]);
	}

	closure_debug_destroy(&ra->cl);
	kfree(ra);

	clear_btree_node_read_in_flight(b);
	wake_up_bit(&b->flags, BTREE_NODE_read_in_flight);
}

static void btree_node_read_all_replicas_endio(struct bio *bio)
{
	struct btree_read_bio *rb =
		container_of(bio, struct btree_read_bio, bio);
	struct bch_fs *c	= rb->c;
	struct btree_node_read_all *ra = rb->ra;

	if (rb->have_ioref) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, rb->pick.ptr.dev);
		bch2_latency_acct(ca, rb->start_time, READ);
	}

	ra->err[rb->idx] = bio->bi_status;
	closure_put(&ra->cl);
}

/*
 * XXX This allocates multiple times from the same mempools, and can deadlock
 * under sufficient memory pressure (but is only a debug path)
 */
static int btree_node_read_all_replicas(struct bch_fs *c, struct btree *b, bool sync)
{
	struct bkey_s_c k = bkey_i_to_s_c(&b->key);
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded pick;
	struct btree_node_read_all *ra;
	unsigned i;

	ra = kzalloc(sizeof(*ra), GFP_NOFS);
	if (!ra)
		return -ENOMEM;

	closure_init(&ra->cl, NULL);
	ra->c	= c;
	ra->b	= b;
	ra->nr	= bch2_bkey_nr_ptrs(k);

	for (i = 0; i < ra->nr; i++) {
		ra->buf[i] = mempool_alloc(&c->btree_bounce_pool, GFP_NOFS);
		ra->bio[i] = bio_alloc_bioset(NULL,
					      buf_pages(ra->buf[i], btree_bytes(c)),
					      REQ_OP_READ|REQ_SYNC|REQ_META,
					      GFP_NOFS,
					      &c->btree_bio);
	}

	i = 0;
	bkey_for_each_ptr_decode(k.k, ptrs, pick, entry) {
		struct bch_dev *ca = bch_dev_bkey_exists(c, pick.ptr.dev);
		struct btree_read_bio *rb =
			container_of(ra->bio[i], struct btree_read_bio, bio);
		rb->c			= c;
		rb->b			= b;
		rb->ra			= ra;
		rb->start_time		= local_clock();
		rb->have_ioref		= bch2_dev_get_ioref(ca, READ);
		rb->idx			= i;
		rb->pick		= pick;
		rb->bio.bi_iter.bi_sector = pick.ptr.offset;
		rb->bio.bi_end_io	= btree_node_read_all_replicas_endio;
		bch2_bio_map(&rb->bio, ra->buf[i], btree_bytes(c));

		if (rb->have_ioref) {
			this_cpu_add(ca->io_done->sectors[READ][BCH_DATA_btree],
				     bio_sectors(&rb->bio));
			bio_set_dev(&rb->bio, ca->disk_sb.bdev);

			closure_get(&ra->cl);
			submit_bio(&rb->bio);
		} else {
			ra->err[i] = BLK_STS_REMOVED;
		}

		i++;
	}

	if (sync) {
		closure_sync(&ra->cl);
		btree_node_read_all_replicas_done(&ra->cl);
	} else {
		continue_at(&ra->cl, btree_node_read_all_replicas_done,
			    c->io_complete_wq);
	}

	return 0;
}

void bch2_btree_node_read(struct bch_fs *c, struct btree *b,
			  bool sync)
{
	struct extent_ptr_decoded pick;
	struct btree_read_bio *rb;
	struct bch_dev *ca;
	struct bio *bio;
	char buf[200];
	int ret;

	btree_pos_to_text(&PBUF(buf), c, b);
	trace_btree_read(c, b);

	set_btree_node_read_in_flight(b);

	if (bch2_verify_all_btree_replicas &&
	    !btree_node_read_all_replicas(c, b, sync))
		return;

	ret = bch2_bkey_pick_read_device(c, bkey_i_to_s_c(&b->key),
					 NULL, &pick);
	if (bch2_fs_fatal_err_on(ret <= 0, c,
			"btree node read error: no device to read from\n"
			" at %s", buf)) {
		set_btree_node_read_error(b);
		return;
	}

	ca = bch_dev_bkey_exists(c, pick.ptr.dev);

	bio = bio_alloc_bioset(NULL,
			       buf_pages(b->data, btree_bytes(c)),
			       REQ_OP_READ|REQ_SYNC|REQ_META,
			       GFP_NOIO,
			       &c->btree_bio);
	rb = container_of(bio, struct btree_read_bio, bio);
	rb->c			= c;
	rb->b			= b;
	rb->ra			= NULL;
	rb->start_time		= local_clock();
	rb->have_ioref		= bch2_dev_get_ioref(ca, READ);
	rb->pick		= pick;
	INIT_WORK(&rb->work, btree_node_read_work);
	bio->bi_iter.bi_sector	= pick.ptr.offset;
	bio->bi_end_io		= btree_node_read_endio;
	bch2_bio_map(bio, b->data, btree_bytes(c));

	if (rb->have_ioref) {
		this_cpu_add(ca->io_done->sectors[READ][BCH_DATA_btree],
			     bio_sectors(bio));
		bio_set_dev(bio, ca->disk_sb.bdev);

		if (sync) {
			submit_bio_wait(bio);

			btree_node_read_work(&rb->work);
		} else {
			submit_bio(bio);
		}
	} else {
		bio->bi_status = BLK_STS_REMOVED;

		if (sync)
			btree_node_read_work(&rb->work);
		else
			queue_work(c->io_complete_wq, &rb->work);
	}
}

int bch2_btree_root_read(struct bch_fs *c, enum btree_id id,
			const struct bkey_i *k, unsigned level)
{
	struct closure cl;
	struct btree *b;
	int ret;

	closure_init_stack(&cl);

	do {
		ret = bch2_btree_cache_cannibalize_lock(c, &cl);
		closure_sync(&cl);
	} while (ret);

	b = bch2_btree_node_mem_alloc(c);
	bch2_btree_cache_cannibalize_unlock(c);

	BUG_ON(IS_ERR(b));

	bkey_copy(&b->key, k);
	BUG_ON(bch2_btree_node_hash_insert(&c->btree_cache, b, level, id));

	bch2_btree_node_read(c, b, true);

	if (btree_node_read_error(b)) {
		bch2_btree_node_hash_remove(&c->btree_cache, b);

		mutex_lock(&c->btree_cache.lock);
		list_move(&b->list, &c->btree_cache.freeable);
		mutex_unlock(&c->btree_cache.lock);

		ret = -EIO;
		goto err;
	}

	bch2_btree_set_root_for_read(c, b);
err:
	six_unlock_write(&b->c.lock);
	six_unlock_intent(&b->c.lock);

	return ret;
}

void bch2_btree_complete_write(struct bch_fs *c, struct btree *b,
			      struct btree_write *w)
{
	unsigned long old, new, v = READ_ONCE(b->will_make_reachable);

	do {
		old = new = v;
		if (!(old & 1))
			break;

		new &= ~1UL;
	} while ((v = cmpxchg(&b->will_make_reachable, old, new)) != old);

	if (old & 1)
		closure_put(&((struct btree_update *) new)->cl);

	bch2_journal_pin_drop(&c->journal, &w->journal);
}

static void btree_node_write_done(struct bch_fs *c, struct btree *b)
{
	struct btree_write *w = btree_prev_write(b);

	bch2_btree_complete_write(c, b, w);
	btree_node_io_unlock(b);
}

static void bch2_btree_node_write_error(struct bch_fs *c,
					struct btree_write_bio *wbio)
{
	struct btree *b		= wbio->wbio.bio.bi_private;
	struct bkey_buf k;
	struct bch_extent_ptr *ptr;
	struct btree_trans trans;
	struct btree_iter *iter;
	int ret;

	bch2_bkey_buf_init(&k);
	bch2_trans_init(&trans, c, 0, 0);

	iter = bch2_trans_get_node_iter(&trans, b->c.btree_id, b->key.k.p,
					BTREE_MAX_DEPTH, b->c.level, 0);
retry:
	ret = bch2_btree_iter_traverse(iter);
	if (ret)
		goto err;

	/* has node been freed? */
	if (iter->l[b->c.level].b != b) {
		/* node has been freed: */
		BUG_ON(!btree_node_dying(b));
		goto out;
	}

	BUG_ON(!btree_node_hashed(b));

	bch2_bkey_buf_copy(&k, c, &b->key);

	bch2_bkey_drop_ptrs(bkey_i_to_s(k.k), ptr,
		bch2_dev_list_has_dev(wbio->wbio.failed, ptr->dev));

	if (!bch2_bkey_nr_ptrs(bkey_i_to_s_c(k.k)))
		goto err;

	ret = bch2_btree_node_update_key(c, iter, b, k.k);
	if (ret == -EINTR)
		goto retry;
	if (ret)
		goto err;
out:
	bch2_trans_iter_put(&trans, iter);
	bch2_trans_exit(&trans);
	bch2_bkey_buf_exit(&k, c);
	bio_put(&wbio->wbio.bio);
	btree_node_write_done(c, b);
	return;
err:
	set_btree_node_noevict(b);
	bch2_fs_fatal_error(c, "fatal error writing btree node");
	goto out;
}

void bch2_btree_write_error_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs,
					btree_write_error_work);
	struct bio *bio;

	while (1) {
		spin_lock_irq(&c->btree_write_error_lock);
		bio = bio_list_pop(&c->btree_write_error_list);
		spin_unlock_irq(&c->btree_write_error_lock);

		if (!bio)
			break;

		bch2_btree_node_write_error(c,
			container_of(bio, struct btree_write_bio, wbio.bio));
	}
}

static void btree_node_write_work(struct work_struct *work)
{
	struct btree_write_bio *wbio =
		container_of(work, struct btree_write_bio, work);
	struct bch_fs *c	= wbio->wbio.c;
	struct btree *b		= wbio->wbio.bio.bi_private;

	btree_bounce_free(c,
		wbio->bytes,
		wbio->wbio.used_mempool,
		wbio->data);

	if (wbio->wbio.failed.nr) {
		unsigned long flags;

		spin_lock_irqsave(&c->btree_write_error_lock, flags);
		bio_list_add(&c->btree_write_error_list, &wbio->wbio.bio);
		spin_unlock_irqrestore(&c->btree_write_error_lock, flags);

		queue_work(c->btree_error_wq, &c->btree_write_error_work);
		return;
	}

	bio_put(&wbio->wbio.bio);
	btree_node_write_done(c, b);
}

static void btree_node_write_endio(struct bio *bio)
{
	struct bch_write_bio *wbio	= to_wbio(bio);
	struct bch_write_bio *parent	= wbio->split ? wbio->parent : NULL;
	struct bch_write_bio *orig	= parent ?: wbio;
	struct bch_fs *c		= wbio->c;
	struct bch_dev *ca		= bch_dev_bkey_exists(c, wbio->dev);
	unsigned long flags;

	if (wbio->have_ioref)
		bch2_latency_acct(ca, wbio->submit_time, WRITE);

	if (bch2_dev_io_err_on(bio->bi_status, ca, "btree write error: %s",
			       bch2_blk_status_to_str(bio->bi_status)) ||
	    bch2_meta_write_fault("btree")) {
		spin_lock_irqsave(&c->btree_write_error_lock, flags);
		bch2_dev_list_add_dev(&orig->failed, wbio->dev);
		spin_unlock_irqrestore(&c->btree_write_error_lock, flags);
	}

	if (wbio->have_ioref)
		percpu_ref_put(&ca->io_ref);

	if (parent) {
		bio_put(bio);
		bio_endio(&parent->bio);
	} else {
		struct btree_write_bio *wb =
			container_of(orig, struct btree_write_bio, wbio);

		INIT_WORK(&wb->work, btree_node_write_work);
		queue_work(c->io_complete_wq, &wb->work);
	}
}

static int validate_bset_for_write(struct bch_fs *c, struct btree *b,
				   struct bset *i, unsigned sectors)
{
	unsigned whiteout_u64s = 0;
	int ret;

	if (bch2_bkey_invalid(c, bkey_i_to_s_c(&b->key), BKEY_TYPE_btree))
		return -1;

	ret = validate_bset_keys(c, b, i, &whiteout_u64s, WRITE, false) ?:
		validate_bset(c, NULL, b, i, sectors, WRITE, false);
	if (ret) {
		bch2_inconsistent_error(c);
		dump_stack();
	}

	return ret;
}

static void btree_write_submit(struct work_struct *work)
{
	struct btree_write_bio *wbio = container_of(work, struct btree_write_bio, work);

	bch2_submit_wbio_replicas(&wbio->wbio, wbio->wbio.c, BCH_DATA_btree, &wbio->key);
}

void __bch2_btree_node_write(struct bch_fs *c, struct btree *b)
{
	struct btree_write_bio *wbio;
	struct bset_tree *t;
	struct bset *i;
	struct btree_node *bn = NULL;
	struct btree_node_entry *bne = NULL;
	struct bch_extent_ptr *ptr;
	struct sort_iter sort_iter;
	struct nonce nonce;
	unsigned bytes_to_write, sectors_to_write, bytes, u64s;
	u64 seq = 0;
	bool used_mempool;
	unsigned long old, new;
	bool validate_before_checksum = false;
	void *data;

	if (test_bit(BCH_FS_HOLD_BTREE_WRITES, &c->flags))
		return;

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

		if (!btree_node_may_write(b))
			return;

		if (old & (1 << BTREE_NODE_never_write))
			return;

		if (old & (1 << BTREE_NODE_write_in_flight)) {
			/*
			 * XXX waiting on btree writes with btree locks held -
			 * this can deadlock, and we hit the write error path
			 */
			btree_node_wait_on_io(b);
			continue;
		}

		new &= ~(1 << BTREE_NODE_dirty);
		new &= ~(1 << BTREE_NODE_need_write);
		new |=  (1 << BTREE_NODE_write_in_flight);
		new |=  (1 << BTREE_NODE_just_written);
		new ^=  (1 << BTREE_NODE_write_idx);
	} while (cmpxchg_acquire(&b->flags, old, new) != old);

	atomic_dec(&c->btree_cache.dirty);

	BUG_ON(btree_node_fake(b));
	BUG_ON((b->will_make_reachable != 0) != !b->written);

	BUG_ON(b->written >= c->opts.btree_node_size);
	BUG_ON(b->written & (c->opts.block_size - 1));
	BUG_ON(bset_written(b, btree_bset_last(b)));
	BUG_ON(le64_to_cpu(b->data->magic) != bset_magic(c));
	BUG_ON(memcmp(&b->data->format, &b->format, sizeof(b->format)));

	bch2_sort_whiteouts(c, b);

	sort_iter_init(&sort_iter, b);

	bytes = !b->written
		? sizeof(struct btree_node)
		: sizeof(struct btree_node_entry);

	bytes += b->whiteout_u64s * sizeof(u64);

	for_each_bset(b, t) {
		i = bset(b, t);

		if (bset_written(b, i))
			continue;

		bytes += le16_to_cpu(i->u64s) * sizeof(u64);
		sort_iter_add(&sort_iter,
			      btree_bkey_first(b, t),
			      btree_bkey_last(b, t));
		seq = max(seq, le64_to_cpu(i->journal_seq));
	}

	BUG_ON(b->written && !seq);

	/* bch2_varint_decode may read up to 7 bytes past the end of the buffer: */
	bytes += 8;

	/* buffer must be a multiple of the block size */
	bytes = round_up(bytes, block_bytes(c));

	data = btree_bounce_alloc(c, bytes, &used_mempool);

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

	sort_iter_add(&sort_iter,
		      unwritten_whiteouts_start(c, b),
		      unwritten_whiteouts_end(c, b));
	SET_BSET_SEPARATE_WHITEOUTS(i, false);

	b->whiteout_u64s = 0;

	u64s = bch2_sort_keys(i->start, &sort_iter, false);
	le16_add_cpu(&i->u64s, u64s);

	set_needs_whiteout(i, false);

	/* do we have data to write? */
	if (b->written && !i->u64s)
		goto nowrite;

	bytes_to_write = vstruct_end(i) - data;
	sectors_to_write = round_up(bytes_to_write, block_bytes(c)) >> 9;

	memset(data + bytes_to_write, 0,
	       (sectors_to_write << 9) - bytes_to_write);

	BUG_ON(b->written + sectors_to_write > c->opts.btree_node_size);
	BUG_ON(BSET_BIG_ENDIAN(i) != CPU_BIG_ENDIAN);
	BUG_ON(i->seq != b->data->keys.seq);

	i->version = c->sb.version < bcachefs_metadata_version_new_versioning
		? cpu_to_le16(BCH_BSET_VERSION_OLD)
		: cpu_to_le16(c->sb.version);
	SET_BSET_CSUM_TYPE(i, bch2_meta_checksum_type(c));

	if (bch2_csum_type_is_encryption(BSET_CSUM_TYPE(i)))
		validate_before_checksum = true;

	/* validate_bset will be modifying: */
	if (le16_to_cpu(i->version) < bcachefs_metadata_version_current)
		validate_before_checksum = true;

	/* if we're going to be encrypting, check metadata validity first: */
	if (validate_before_checksum &&
	    validate_bset_for_write(c, b, i, sectors_to_write))
		goto err;

	bset_encrypt(c, i, b->written << 9);

	nonce = btree_nonce(i, b->written << 9);

	if (bn)
		bn->csum = csum_vstruct(c, BSET_CSUM_TYPE(i), nonce, bn);
	else
		bne->csum = csum_vstruct(c, BSET_CSUM_TYPE(i), nonce, bne);

	/* if we're not encrypting, check metadata after checksumming: */
	if (!validate_before_checksum &&
	    validate_bset_for_write(c, b, i, sectors_to_write))
		goto err;

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
	 * Also on journal error, the pending write may have updates that were
	 * never journalled (interior nodes, see btree_update_nodes_written()) -
	 * it's critical that we don't do the write in that case otherwise we
	 * will have updates visible that weren't in the journal:
	 *
	 * Make sure to update b->written so bch2_btree_init_next() doesn't
	 * break:
	 */
	if (bch2_journal_error(&c->journal) ||
	    c->opts.nochanges)
		goto err;

	trace_btree_write(b, bytes_to_write, sectors_to_write);

	wbio = container_of(bio_alloc_bioset(NULL,
				buf_pages(data, sectors_to_write << 9),
				REQ_OP_WRITE|REQ_META,
				GFP_NOIO,
				&c->btree_bio),
			    struct btree_write_bio, wbio.bio);
	wbio_init(&wbio->wbio.bio);
	wbio->data			= data;
	wbio->bytes			= bytes;
	wbio->wbio.c			= c;
	wbio->wbio.used_mempool		= used_mempool;
	wbio->wbio.bio.bi_end_io	= btree_node_write_endio;
	wbio->wbio.bio.bi_private	= b;

	bch2_bio_map(&wbio->wbio.bio, data, sectors_to_write << 9);

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

	bkey_copy(&wbio->key, &b->key);

	bkey_for_each_ptr(bch2_bkey_ptrs(bkey_i_to_s(&wbio->key)), ptr)
		ptr->offset += b->written;

	b->written += sectors_to_write;

	atomic64_inc(&c->btree_writes_nr);
	atomic64_add(sectors_to_write, &c->btree_writes_sectors);

	INIT_WORK(&wbio->work, btree_write_submit);
	queue_work(c->io_complete_wq, &wbio->work);
	return;
err:
	set_btree_node_noevict(b);
	b->written += sectors_to_write;
nowrite:
	btree_bounce_free(c, bytes, used_mempool, data);
	btree_node_write_done(c, b);
}

/*
 * Work that must be done with write lock held:
 */
bool bch2_btree_post_write_cleanup(struct bch_fs *c, struct btree *b)
{
	bool invalidated_iter = false;
	struct btree_node_entry *bne;
	struct bset_tree *t;

	if (!btree_node_just_written(b))
		return false;

	BUG_ON(b->whiteout_u64s);

	clear_btree_node_just_written(b);

	/*
	 * Note: immediately after write, bset_written() doesn't work - the
	 * amount of data we had to write after compaction might have been
	 * smaller than the offset of the last bset.
	 *
	 * However, we know that all bsets have been written here, as long as
	 * we're still holding the write lock:
	 */

	/*
	 * XXX: decide if we really want to unconditionally sort down to a
	 * single bset:
	 */
	if (b->nsets > 1) {
		btree_node_sort(c, b, 0, b->nsets, true);
		invalidated_iter = true;
	} else {
		invalidated_iter = bch2_drop_whiteouts(b, COMPACT_ALL);
	}

	for_each_bset(b, t)
		set_needs_whiteout(bset(b, t), true);

	bch2_btree_verify(c, b);

	/*
	 * If later we don't unconditionally sort down to a single bset, we have
	 * to ensure this is still true:
	 */
	BUG_ON((void *) btree_bkey_last(b, bset_tree_last(b)) > write_block(b));

	bne = want_new_bset(c, b);
	if (bne)
		bch2_bset_init_next(c, b, bne);

	bch2_btree_build_aux_trees(b);

	return invalidated_iter;
}

/*
 * Use this one if the node is intent locked:
 */
void bch2_btree_node_write(struct bch_fs *c, struct btree *b,
			   enum six_lock_type lock_type_held)
{
	if (lock_type_held == SIX_LOCK_intent ||
	    (lock_type_held == SIX_LOCK_read &&
	     six_lock_tryupgrade(&b->c.lock))) {
		__bch2_btree_node_write(c, b);

		/* don't cycle lock unnecessarily: */
		if (btree_node_just_written(b) &&
		    six_trylock_write(&b->c.lock)) {
			bch2_btree_post_write_cleanup(c, b);
			six_unlock_write(&b->c.lock);
		}

		if (lock_type_held == SIX_LOCK_read)
			six_lock_downgrade(&b->c.lock);
	} else {
		__bch2_btree_node_write(c, b);
		if (lock_type_held == SIX_LOCK_write &&
		    btree_node_just_written(b))
			bch2_btree_post_write_cleanup(c, b);
	}
}

static void __bch2_btree_flush_all(struct bch_fs *c, unsigned flag)
{
	struct bucket_table *tbl;
	struct rhash_head *pos;
	struct btree *b;
	unsigned i;
restart:
	rcu_read_lock();
	for_each_cached_btree(b, c, tbl, i, pos)
		if (test_bit(flag, &b->flags)) {
			rcu_read_unlock();
			wait_on_bit_io(&b->flags, flag, TASK_UNINTERRUPTIBLE);
			goto restart;

		}
	rcu_read_unlock();
}

void bch2_btree_flush_all_reads(struct bch_fs *c)
{
	__bch2_btree_flush_all(c, BTREE_NODE_read_in_flight);
}

void bch2_btree_flush_all_writes(struct bch_fs *c)
{
	__bch2_btree_flush_all(c, BTREE_NODE_write_in_flight);
}

void bch2_dirty_btree_nodes_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct bucket_table *tbl;
	struct rhash_head *pos;
	struct btree *b;
	unsigned i;

	rcu_read_lock();
	for_each_cached_btree(b, c, tbl, i, pos) {
		unsigned long flags = READ_ONCE(b->flags);

		if (!(flags & (1 << BTREE_NODE_dirty)))
			continue;

		pr_buf(out, "%p d %u n %u l %u w %u b %u r %u:%lu\n",
		       b,
		       (flags & (1 << BTREE_NODE_dirty)) != 0,
		       (flags & (1 << BTREE_NODE_need_write)) != 0,
		       b->c.level,
		       b->written,
		       !list_empty_careful(&b->write_blocked),
		       b->will_make_reachable != 0,
		       b->will_make_reachable & 1);
	}
	rcu_read_unlock();
}
