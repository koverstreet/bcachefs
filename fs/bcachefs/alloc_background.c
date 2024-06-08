// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"
#include "alloc_background.h"
#include "alloc_foreground.h"
#include "backpointers.h"
#include "btree_cache.h"
#include "btree_io.h"
#include "btree_key_cache.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "btree_gc.h"
#include "btree_write_buffer.h"
#include "buckets.h"
#include "buckets_waiting_for_journal.h"
#include "clock.h"
#include "debug.h"
#include "ec.h"
#include "error.h"
#include "lru.h"
#include "recovery.h"
#include "trace.h"
#include "varint.h"

#include <linux/kthread.h>
#include <linux/math64.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/sort.h>

static void bch2_discard_one_bucket_fast(struct bch_fs *c, struct bpos bucket);

/* Persistent alloc info: */

static const unsigned BCH_ALLOC_V1_FIELD_BYTES[] = {
#define x(name, bits) [BCH_ALLOC_FIELD_V1_##name] = bits / 8,
	BCH_ALLOC_FIELDS_V1()
#undef x
};

struct bkey_alloc_unpacked {
	u64		journal_seq;
	u8		gen;
	u8		oldest_gen;
	u8		data_type;
	bool		need_discard:1;
	bool		need_inc_gen:1;
#define x(_name, _bits)	u##_bits _name;
	BCH_ALLOC_FIELDS_V2()
#undef  x
};

static inline u64 alloc_field_v1_get(const struct bch_alloc *a,
				     const void **p, unsigned field)
{
	unsigned bytes = BCH_ALLOC_V1_FIELD_BYTES[field];
	u64 v;

	if (!(a->fields & (1 << field)))
		return 0;

	switch (bytes) {
	case 1:
		v = *((const u8 *) *p);
		break;
	case 2:
		v = le16_to_cpup(*p);
		break;
	case 4:
		v = le32_to_cpup(*p);
		break;
	case 8:
		v = le64_to_cpup(*p);
		break;
	default:
		BUG();
	}

	*p += bytes;
	return v;
}

static void bch2_alloc_unpack_v1(struct bkey_alloc_unpacked *out,
				 struct bkey_s_c k)
{
	const struct bch_alloc *in = bkey_s_c_to_alloc(k).v;
	const void *d = in->data;
	unsigned idx = 0;

	out->gen = in->gen;

#define x(_name, _bits) out->_name = alloc_field_v1_get(in, &d, idx++);
	BCH_ALLOC_FIELDS_V1()
#undef  x
}

static int bch2_alloc_unpack_v2(struct bkey_alloc_unpacked *out,
				struct bkey_s_c k)
{
	struct bkey_s_c_alloc_v2 a = bkey_s_c_to_alloc_v2(k);
	const u8 *in = a.v->data;
	const u8 *end = bkey_val_end(a);
	unsigned fieldnr = 0;
	int ret;
	u64 v;

	out->gen	= a.v->gen;
	out->oldest_gen	= a.v->oldest_gen;
	out->data_type	= a.v->data_type;

#define x(_name, _bits)							\
	if (fieldnr < a.v->nr_fields) {					\
		ret = bch2_varint_decode_fast(in, end, &v);		\
		if (ret < 0)						\
			return ret;					\
		in += ret;						\
	} else {							\
		v = 0;							\
	}								\
	out->_name = v;							\
	if (v != out->_name)						\
		return -1;						\
	fieldnr++;

	BCH_ALLOC_FIELDS_V2()
#undef  x
	return 0;
}

static int bch2_alloc_unpack_v3(struct bkey_alloc_unpacked *out,
				struct bkey_s_c k)
{
	struct bkey_s_c_alloc_v3 a = bkey_s_c_to_alloc_v3(k);
	const u8 *in = a.v->data;
	const u8 *end = bkey_val_end(a);
	unsigned fieldnr = 0;
	int ret;
	u64 v;

	out->gen	= a.v->gen;
	out->oldest_gen	= a.v->oldest_gen;
	out->data_type	= a.v->data_type;
	out->need_discard = BCH_ALLOC_V3_NEED_DISCARD(a.v);
	out->need_inc_gen = BCH_ALLOC_V3_NEED_INC_GEN(a.v);
	out->journal_seq = le64_to_cpu(a.v->journal_seq);

#define x(_name, _bits)							\
	if (fieldnr < a.v->nr_fields) {					\
		ret = bch2_varint_decode_fast(in, end, &v);		\
		if (ret < 0)						\
			return ret;					\
		in += ret;						\
	} else {							\
		v = 0;							\
	}								\
	out->_name = v;							\
	if (v != out->_name)						\
		return -1;						\
	fieldnr++;

	BCH_ALLOC_FIELDS_V2()
#undef  x
	return 0;
}

static struct bkey_alloc_unpacked bch2_alloc_unpack(struct bkey_s_c k)
{
	struct bkey_alloc_unpacked ret = { .gen	= 0 };

	switch (k.k->type) {
	case KEY_TYPE_alloc:
		bch2_alloc_unpack_v1(&ret, k);
		break;
	case KEY_TYPE_alloc_v2:
		bch2_alloc_unpack_v2(&ret, k);
		break;
	case KEY_TYPE_alloc_v3:
		bch2_alloc_unpack_v3(&ret, k);
		break;
	}

	return ret;
}

static unsigned bch_alloc_v1_val_u64s(const struct bch_alloc *a)
{
	unsigned i, bytes = offsetof(struct bch_alloc, data);

	for (i = 0; i < ARRAY_SIZE(BCH_ALLOC_V1_FIELD_BYTES); i++)
		if (a->fields & (1 << i))
			bytes += BCH_ALLOC_V1_FIELD_BYTES[i];

	return DIV_ROUND_UP(bytes, sizeof(u64));
}

int bch2_alloc_v1_invalid(struct bch_fs *c, struct bkey_s_c k,
			  enum bch_validate_flags flags,
			  struct printbuf *err)
{
	struct bkey_s_c_alloc a = bkey_s_c_to_alloc(k);
	int ret = 0;

	/* allow for unknown fields */
	bkey_fsck_err_on(bkey_val_u64s(a.k) < bch_alloc_v1_val_u64s(a.v), c, err,
			 alloc_v1_val_size_bad,
			 "incorrect value size (%zu < %u)",
			 bkey_val_u64s(a.k), bch_alloc_v1_val_u64s(a.v));
fsck_err:
	return ret;
}

int bch2_alloc_v2_invalid(struct bch_fs *c, struct bkey_s_c k,
			  enum bch_validate_flags flags,
			  struct printbuf *err)
{
	struct bkey_alloc_unpacked u;
	int ret = 0;

	bkey_fsck_err_on(bch2_alloc_unpack_v2(&u, k), c, err,
			 alloc_v2_unpack_error,
			 "unpack error");
fsck_err:
	return ret;
}

int bch2_alloc_v3_invalid(struct bch_fs *c, struct bkey_s_c k,
			  enum bch_validate_flags flags,
			  struct printbuf *err)
{
	struct bkey_alloc_unpacked u;
	int ret = 0;

	bkey_fsck_err_on(bch2_alloc_unpack_v3(&u, k), c, err,
			 alloc_v2_unpack_error,
			 "unpack error");
fsck_err:
	return ret;
}

int bch2_alloc_v4_invalid(struct bch_fs *c, struct bkey_s_c k,
			  enum bch_validate_flags flags, struct printbuf *err)
{
	struct bkey_s_c_alloc_v4 a = bkey_s_c_to_alloc_v4(k);
	int ret = 0;

	bkey_fsck_err_on(alloc_v4_u64s_noerror(a.v) > bkey_val_u64s(k.k), c, err,
			 alloc_v4_val_size_bad,
			 "bad val size (%u > %zu)",
			 alloc_v4_u64s_noerror(a.v), bkey_val_u64s(k.k));

	bkey_fsck_err_on(!BCH_ALLOC_V4_BACKPOINTERS_START(a.v) &&
			 BCH_ALLOC_V4_NR_BACKPOINTERS(a.v), c, err,
			 alloc_v4_backpointers_start_bad,
			 "invalid backpointers_start");

	bkey_fsck_err_on(alloc_data_type(*a.v, a.v->data_type) != a.v->data_type, c, err,
			 alloc_key_data_type_bad,
			 "invalid data type (got %u should be %u)",
			 a.v->data_type, alloc_data_type(*a.v, a.v->data_type));

	switch (a.v->data_type) {
	case BCH_DATA_free:
	case BCH_DATA_need_gc_gens:
	case BCH_DATA_need_discard:
		bkey_fsck_err_on(bch2_bucket_sectors_total(*a.v) || a.v->stripe,
				 c, err, alloc_key_empty_but_have_data,
				 "empty data type free but have data");
		break;
	case BCH_DATA_sb:
	case BCH_DATA_journal:
	case BCH_DATA_btree:
	case BCH_DATA_user:
	case BCH_DATA_parity:
		bkey_fsck_err_on(!bch2_bucket_sectors_dirty(*a.v),
				 c, err, alloc_key_dirty_sectors_0,
				 "data_type %s but dirty_sectors==0",
				 bch2_data_type_str(a.v->data_type));
		break;
	case BCH_DATA_cached:
		bkey_fsck_err_on(!a.v->cached_sectors ||
				 bch2_bucket_sectors_dirty(*a.v) ||
				 a.v->stripe,
				 c, err, alloc_key_cached_inconsistency,
				 "data type inconsistency");

		bkey_fsck_err_on(!a.v->io_time[READ] &&
				 c->curr_recovery_pass > BCH_RECOVERY_PASS_check_alloc_to_lru_refs,
				 c, err, alloc_key_cached_but_read_time_zero,
				 "cached bucket with read_time == 0");
		break;
	case BCH_DATA_stripe:
		break;
	}
fsck_err:
	return ret;
}

void bch2_alloc_v4_swab(struct bkey_s k)
{
	struct bch_alloc_v4 *a = bkey_s_to_alloc_v4(k).v;
	struct bch_backpointer *bp, *bps;

	a->journal_seq		= swab64(a->journal_seq);
	a->flags		= swab32(a->flags);
	a->dirty_sectors	= swab32(a->dirty_sectors);
	a->cached_sectors	= swab32(a->cached_sectors);
	a->io_time[0]		= swab64(a->io_time[0]);
	a->io_time[1]		= swab64(a->io_time[1]);
	a->stripe		= swab32(a->stripe);
	a->nr_external_backpointers = swab32(a->nr_external_backpointers);
	a->fragmentation_lru	= swab64(a->fragmentation_lru);

	bps = alloc_v4_backpointers(a);
	for (bp = bps; bp < bps + BCH_ALLOC_V4_NR_BACKPOINTERS(a); bp++) {
		bp->bucket_offset	= swab40(bp->bucket_offset);
		bp->bucket_len		= swab32(bp->bucket_len);
		bch2_bpos_swab(&bp->pos);
	}
}

void bch2_alloc_to_text(struct printbuf *out, struct bch_fs *c, struct bkey_s_c k)
{
	struct bch_alloc_v4 _a;
	const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k, &_a);

	prt_newline(out);
	printbuf_indent_add(out, 2);

	prt_printf(out, "gen %u oldest_gen %u data_type ", a->gen, a->oldest_gen);
	bch2_prt_data_type(out, a->data_type);
	prt_newline(out);
	prt_printf(out, "journal_seq       %llu\n",	a->journal_seq);
	prt_printf(out, "need_discard      %llu\n",	BCH_ALLOC_V4_NEED_DISCARD(a));
	prt_printf(out, "need_inc_gen      %llu\n",	BCH_ALLOC_V4_NEED_INC_GEN(a));
	prt_printf(out, "dirty_sectors     %u\n",	a->dirty_sectors);
	prt_printf(out, "cached_sectors    %u\n",	a->cached_sectors);
	prt_printf(out, "stripe            %u\n",	a->stripe);
	prt_printf(out, "stripe_redundancy %u\n",	a->stripe_redundancy);
	prt_printf(out, "io_time[READ]     %llu\n",	a->io_time[READ]);
	prt_printf(out, "io_time[WRITE]    %llu\n",	a->io_time[WRITE]);
	prt_printf(out, "fragmentation     %llu\n",	a->fragmentation_lru);
	prt_printf(out, "bp_start          %llu\n", BCH_ALLOC_V4_BACKPOINTERS_START(a));
	printbuf_indent_sub(out, 2);
}

void __bch2_alloc_to_v4(struct bkey_s_c k, struct bch_alloc_v4 *out)
{
	if (k.k->type == KEY_TYPE_alloc_v4) {
		void *src, *dst;

		*out = *bkey_s_c_to_alloc_v4(k).v;

		src = alloc_v4_backpointers(out);
		SET_BCH_ALLOC_V4_BACKPOINTERS_START(out, BCH_ALLOC_V4_U64s);
		dst = alloc_v4_backpointers(out);

		if (src < dst)
			memset(src, 0, dst - src);

		SET_BCH_ALLOC_V4_NR_BACKPOINTERS(out, 0);
	} else {
		struct bkey_alloc_unpacked u = bch2_alloc_unpack(k);

		*out = (struct bch_alloc_v4) {
			.journal_seq		= u.journal_seq,
			.flags			= u.need_discard,
			.gen			= u.gen,
			.oldest_gen		= u.oldest_gen,
			.data_type		= u.data_type,
			.stripe_redundancy	= u.stripe_redundancy,
			.dirty_sectors		= u.dirty_sectors,
			.cached_sectors		= u.cached_sectors,
			.io_time[READ]		= u.read_time,
			.io_time[WRITE]		= u.write_time,
			.stripe			= u.stripe,
		};

		SET_BCH_ALLOC_V4_BACKPOINTERS_START(out, BCH_ALLOC_V4_U64s);
	}
}

static noinline struct bkey_i_alloc_v4 *
__bch2_alloc_to_v4_mut(struct btree_trans *trans, struct bkey_s_c k)
{
	struct bkey_i_alloc_v4 *ret;

	ret = bch2_trans_kmalloc(trans, max(bkey_bytes(k.k), sizeof(struct bkey_i_alloc_v4)));
	if (IS_ERR(ret))
		return ret;

	if (k.k->type == KEY_TYPE_alloc_v4) {
		void *src, *dst;

		bkey_reassemble(&ret->k_i, k);

		src = alloc_v4_backpointers(&ret->v);
		SET_BCH_ALLOC_V4_BACKPOINTERS_START(&ret->v, BCH_ALLOC_V4_U64s);
		dst = alloc_v4_backpointers(&ret->v);

		if (src < dst)
			memset(src, 0, dst - src);

		SET_BCH_ALLOC_V4_NR_BACKPOINTERS(&ret->v, 0);
		set_alloc_v4_u64s(ret);
	} else {
		bkey_alloc_v4_init(&ret->k_i);
		ret->k.p = k.k->p;
		bch2_alloc_to_v4(k, &ret->v);
	}
	return ret;
}

static inline struct bkey_i_alloc_v4 *bch2_alloc_to_v4_mut_inlined(struct btree_trans *trans, struct bkey_s_c k)
{
	struct bkey_s_c_alloc_v4 a;

	if (likely(k.k->type == KEY_TYPE_alloc_v4) &&
	    ((a = bkey_s_c_to_alloc_v4(k), true) &&
	     BCH_ALLOC_V4_NR_BACKPOINTERS(a.v) == 0))
		return bch2_bkey_make_mut_noupdate_typed(trans, k, alloc_v4);

	return __bch2_alloc_to_v4_mut(trans, k);
}

struct bkey_i_alloc_v4 *bch2_alloc_to_v4_mut(struct btree_trans *trans, struct bkey_s_c k)
{
	return bch2_alloc_to_v4_mut_inlined(trans, k);
}

struct bkey_i_alloc_v4 *
bch2_trans_start_alloc_update_noupdate(struct btree_trans *trans, struct btree_iter *iter,
				       struct bpos pos)
{
	struct bkey_s_c k = bch2_bkey_get_iter(trans, iter, BTREE_ID_alloc, pos,
					       BTREE_ITER_with_updates|
					       BTREE_ITER_cached|
					       BTREE_ITER_intent);
	int ret = bkey_err(k);
	if (unlikely(ret))
		return ERR_PTR(ret);

	struct bkey_i_alloc_v4 *a = bch2_alloc_to_v4_mut_inlined(trans, k);
	ret = PTR_ERR_OR_ZERO(a);
	if (unlikely(ret))
		goto err;
	return a;
err:
	bch2_trans_iter_exit(trans, iter);
	return ERR_PTR(ret);
}

__flatten
struct bkey_i_alloc_v4 *bch2_trans_start_alloc_update(struct btree_trans *trans, struct bpos pos)
{
	struct btree_iter iter;
	struct bkey_i_alloc_v4 *a = bch2_trans_start_alloc_update_noupdate(trans, &iter, pos);
	int ret = PTR_ERR_OR_ZERO(a);
	if (ret)
		return ERR_PTR(ret);

	ret = bch2_trans_update(trans, &iter, &a->k_i, 0);
	bch2_trans_iter_exit(trans, &iter);
	return unlikely(ret) ? ERR_PTR(ret) : a;
}

static struct bpos alloc_gens_pos(struct bpos pos, unsigned *offset)
{
	*offset = pos.offset & KEY_TYPE_BUCKET_GENS_MASK;

	pos.offset >>= KEY_TYPE_BUCKET_GENS_BITS;
	return pos;
}

static struct bpos bucket_gens_pos_to_alloc(struct bpos pos, unsigned offset)
{
	pos.offset <<= KEY_TYPE_BUCKET_GENS_BITS;
	pos.offset += offset;
	return pos;
}

static unsigned alloc_gen(struct bkey_s_c k, unsigned offset)
{
	return k.k->type == KEY_TYPE_bucket_gens
		? bkey_s_c_to_bucket_gens(k).v->gens[offset]
		: 0;
}

int bch2_bucket_gens_invalid(struct bch_fs *c, struct bkey_s_c k,
			     enum bch_validate_flags flags,
			     struct printbuf *err)
{
	int ret = 0;

	bkey_fsck_err_on(bkey_val_bytes(k.k) != sizeof(struct bch_bucket_gens), c, err,
			 bucket_gens_val_size_bad,
			 "bad val size (%zu != %zu)",
			 bkey_val_bytes(k.k), sizeof(struct bch_bucket_gens));
fsck_err:
	return ret;
}

void bch2_bucket_gens_to_text(struct printbuf *out, struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_s_c_bucket_gens g = bkey_s_c_to_bucket_gens(k);
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(g.v->gens); i++) {
		if (i)
			prt_char(out, ' ');
		prt_printf(out, "%u", g.v->gens[i]);
	}
}

int bch2_bucket_gens_init(struct bch_fs *c)
{
	struct btree_trans *trans = bch2_trans_get(c);
	struct bkey_i_bucket_gens g;
	bool have_bucket_gens_key = false;
	int ret;

	ret = for_each_btree_key(trans, iter, BTREE_ID_alloc, POS_MIN,
				 BTREE_ITER_prefetch, k, ({
		/*
		 * Not a fsck error because this is checked/repaired by
		 * bch2_check_alloc_key() which runs later:
		 */
		if (!bch2_dev_bucket_exists(c, k.k->p))
			continue;

		struct bch_alloc_v4 a;
		u8 gen = bch2_alloc_to_v4(k, &a)->gen;
		unsigned offset;
		struct bpos pos = alloc_gens_pos(iter.pos, &offset);
		int ret2 = 0;

		if (have_bucket_gens_key && bkey_cmp(iter.pos, pos)) {
			ret2 =  bch2_btree_insert_trans(trans, BTREE_ID_bucket_gens, &g.k_i, 0) ?:
				bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc);
			if (ret2)
				goto iter_err;
			have_bucket_gens_key = false;
		}

		if (!have_bucket_gens_key) {
			bkey_bucket_gens_init(&g.k_i);
			g.k.p = pos;
			have_bucket_gens_key = true;
		}

		g.v.gens[offset] = gen;
iter_err:
		ret2;
	}));

	if (have_bucket_gens_key && !ret)
		ret = commit_do(trans, NULL, NULL,
				BCH_TRANS_COMMIT_no_enospc,
			bch2_btree_insert_trans(trans, BTREE_ID_bucket_gens, &g.k_i, 0));

	bch2_trans_put(trans);

	bch_err_fn(c, ret);
	return ret;
}

int bch2_alloc_read(struct bch_fs *c)
{
	struct btree_trans *trans = bch2_trans_get(c);
	struct bch_dev *ca = NULL;
	int ret;

	down_read(&c->gc_lock);

	if (c->sb.version_upgrade_complete >= bcachefs_metadata_version_bucket_gens) {
		ret = for_each_btree_key(trans, iter, BTREE_ID_bucket_gens, POS_MIN,
					 BTREE_ITER_prefetch, k, ({
			u64 start = bucket_gens_pos_to_alloc(k.k->p, 0).offset;
			u64 end = bucket_gens_pos_to_alloc(bpos_nosnap_successor(k.k->p), 0).offset;

			if (k.k->type != KEY_TYPE_bucket_gens)
				continue;

			ca = bch2_dev_iterate(c, ca, k.k->p.inode);
			/*
			 * Not a fsck error because this is checked/repaired by
			 * bch2_check_alloc_key() which runs later:
			 */
			if (!ca) {
				bch2_btree_iter_set_pos(&iter, POS(k.k->p.inode + 1, 0));
				continue;
			}

			const struct bch_bucket_gens *g = bkey_s_c_to_bucket_gens(k).v;

			for (u64 b = max_t(u64, ca->mi.first_bucket, start);
			     b < min_t(u64, ca->mi.nbuckets, end);
			     b++)
				*bucket_gen(ca, b) = g->gens[b & KEY_TYPE_BUCKET_GENS_MASK];
			0;
		}));
	} else {
		ret = for_each_btree_key(trans, iter, BTREE_ID_alloc, POS_MIN,
					 BTREE_ITER_prefetch, k, ({
			ca = bch2_dev_iterate(c, ca, k.k->p.inode);
			/*
			 * Not a fsck error because this is checked/repaired by
			 * bch2_check_alloc_key() which runs later:
			 */
			if (!ca) {
				bch2_btree_iter_set_pos(&iter, POS(k.k->p.inode + 1, 0));
				continue;
			}

			struct bch_alloc_v4 a;
			*bucket_gen(ca, k.k->p.offset) = bch2_alloc_to_v4(k, &a)->gen;
			0;
		}));
	}

	bch2_dev_put(ca);
	bch2_trans_put(trans);
	up_read(&c->gc_lock);

	bch_err_fn(c, ret);
	return ret;
}

/* Free space/discard btree: */

static int bch2_bucket_do_index(struct btree_trans *trans,
				struct bch_dev *ca,
				struct bkey_s_c alloc_k,
				const struct bch_alloc_v4 *a,
				bool set)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_s_c old;
	struct bkey_i *k;
	enum btree_id btree;
	enum bch_bkey_type old_type = !set ? KEY_TYPE_set : KEY_TYPE_deleted;
	enum bch_bkey_type new_type =  set ? KEY_TYPE_set : KEY_TYPE_deleted;
	struct printbuf buf = PRINTBUF;
	int ret;

	if (a->data_type != BCH_DATA_free &&
	    a->data_type != BCH_DATA_need_discard)
		return 0;

	k = bch2_trans_kmalloc_nomemzero(trans, sizeof(*k));
	if (IS_ERR(k))
		return PTR_ERR(k);

	bkey_init(&k->k);
	k->k.type = new_type;

	switch (a->data_type) {
	case BCH_DATA_free:
		btree = BTREE_ID_freespace;
		k->k.p = alloc_freespace_pos(alloc_k.k->p, *a);
		bch2_key_resize(&k->k, 1);
		break;
	case BCH_DATA_need_discard:
		btree = BTREE_ID_need_discard;
		k->k.p = alloc_k.k->p;
		break;
	default:
		return 0;
	}

	old = bch2_bkey_get_iter(trans, &iter, btree,
			     bkey_start_pos(&k->k),
			     BTREE_ITER_intent);
	ret = bkey_err(old);
	if (ret)
		return ret;

	if (ca->mi.freespace_initialized &&
	    c->curr_recovery_pass > BCH_RECOVERY_PASS_check_alloc_info &&
	    bch2_trans_inconsistent_on(old.k->type != old_type, trans,
			"incorrect key when %s %s:%llu:%llu:0 (got %s should be %s)\n"
			"  for %s",
			set ? "setting" : "clearing",
			bch2_btree_id_str(btree),
			iter.pos.inode,
			iter.pos.offset,
			bch2_bkey_types[old.k->type],
			bch2_bkey_types[old_type],
			(bch2_bkey_val_to_text(&buf, c, alloc_k), buf.buf))) {
		ret = -EIO;
		goto err;
	}

	ret = bch2_trans_update(trans, &iter, k, 0);
err:
	bch2_trans_iter_exit(trans, &iter);
	printbuf_exit(&buf);
	return ret;
}

static noinline int bch2_bucket_gen_update(struct btree_trans *trans,
					   struct bpos bucket, u8 gen)
{
	struct btree_iter iter;
	unsigned offset;
	struct bpos pos = alloc_gens_pos(bucket, &offset);
	struct bkey_i_bucket_gens *g;
	struct bkey_s_c k;
	int ret;

	g = bch2_trans_kmalloc(trans, sizeof(*g));
	ret = PTR_ERR_OR_ZERO(g);
	if (ret)
		return ret;

	k = bch2_bkey_get_iter(trans, &iter, BTREE_ID_bucket_gens, pos,
			       BTREE_ITER_intent|
			       BTREE_ITER_with_updates);
	ret = bkey_err(k);
	if (ret)
		return ret;

	if (k.k->type != KEY_TYPE_bucket_gens) {
		bkey_bucket_gens_init(&g->k_i);
		g->k.p = iter.pos;
	} else {
		bkey_reassemble(&g->k_i, k);
	}

	g->v.gens[offset] = gen;

	ret = bch2_trans_update(trans, &iter, &g->k_i, 0);
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

int bch2_trigger_alloc(struct btree_trans *trans,
		       enum btree_id btree, unsigned level,
		       struct bkey_s_c old, struct bkey_s new,
		       enum btree_iter_update_trigger_flags flags)
{
	struct bch_fs *c = trans->c;
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	struct bch_dev *ca = bch2_dev_bucket_tryget(c, new.k->p);
	if (!ca)
		return -EIO;

	struct bch_alloc_v4 old_a_convert;
	const struct bch_alloc_v4 *old_a = bch2_alloc_to_v4(old, &old_a_convert);

	if (flags & BTREE_TRIGGER_transactional) {
		struct bch_alloc_v4 *new_a = bkey_s_to_alloc_v4(new).v;

		alloc_data_type_set(new_a, new_a->data_type);

		if (bch2_bucket_sectors_total(*new_a) > bch2_bucket_sectors_total(*old_a)) {
			new_a->io_time[READ] = max_t(u64, 1, atomic64_read(&c->io_clock[READ].now));
			new_a->io_time[WRITE]= max_t(u64, 1, atomic64_read(&c->io_clock[WRITE].now));
			SET_BCH_ALLOC_V4_NEED_INC_GEN(new_a, true);
			SET_BCH_ALLOC_V4_NEED_DISCARD(new_a, true);
		}

		if (data_type_is_empty(new_a->data_type) &&
		    BCH_ALLOC_V4_NEED_INC_GEN(new_a) &&
		    !bch2_bucket_is_open_safe(c, new.k->p.inode, new.k->p.offset)) {
			new_a->gen++;
			SET_BCH_ALLOC_V4_NEED_INC_GEN(new_a, false);
		}

		if (old_a->data_type != new_a->data_type ||
		    (new_a->data_type == BCH_DATA_free &&
		     alloc_freespace_genbits(*old_a) != alloc_freespace_genbits(*new_a))) {
			ret =   bch2_bucket_do_index(trans, ca, old, old_a, false) ?:
				bch2_bucket_do_index(trans, ca, new.s_c, new_a, true);
			if (ret)
				goto err;
		}

		if (new_a->data_type == BCH_DATA_cached &&
		    !new_a->io_time[READ])
			new_a->io_time[READ] = max_t(u64, 1, atomic64_read(&c->io_clock[READ].now));

		u64 old_lru = alloc_lru_idx_read(*old_a);
		u64 new_lru = alloc_lru_idx_read(*new_a);
		if (old_lru != new_lru) {
			ret = bch2_lru_change(trans, new.k->p.inode,
					      bucket_to_u64(new.k->p),
					      old_lru, new_lru);
			if (ret)
				goto err;
		}

		new_a->fragmentation_lru = alloc_lru_idx_fragmentation(*new_a, ca);
		if (old_a->fragmentation_lru != new_a->fragmentation_lru) {
			ret = bch2_lru_change(trans,
					BCH_LRU_FRAGMENTATION_START,
					bucket_to_u64(new.k->p),
					old_a->fragmentation_lru, new_a->fragmentation_lru);
			if (ret)
				goto err;
		}

		if (old_a->gen != new_a->gen) {
			ret = bch2_bucket_gen_update(trans, new.k->p, new_a->gen);
			if (ret)
				goto err;
		}

		/*
		 * need to know if we're getting called from the invalidate path or
		 * not:
		 */

		if ((flags & BTREE_TRIGGER_bucket_invalidate) &&
		    old_a->cached_sectors) {
			ret = bch2_update_cached_sectors_list(trans, new.k->p.inode,
							      -((s64) old_a->cached_sectors));
			if (ret)
				goto err;
		}
	}

	if ((flags & BTREE_TRIGGER_atomic) && (flags & BTREE_TRIGGER_insert)) {
		struct bch_alloc_v4 *new_a = bkey_s_to_alloc_v4(new).v;
		u64 journal_seq = trans->journal_res.seq;
		u64 bucket_journal_seq = new_a->journal_seq;

		if ((flags & BTREE_TRIGGER_insert) &&
		    data_type_is_empty(old_a->data_type) !=
		    data_type_is_empty(new_a->data_type) &&
		    new.k->type == KEY_TYPE_alloc_v4) {
			struct bch_alloc_v4 *v = bkey_s_to_alloc_v4(new).v;

			/*
			 * If the btree updates referring to a bucket weren't flushed
			 * before the bucket became empty again, then the we don't have
			 * to wait on a journal flush before we can reuse the bucket:
			 */
			v->journal_seq = bucket_journal_seq =
				data_type_is_empty(new_a->data_type) &&
				(journal_seq == v->journal_seq ||
				 bch2_journal_noflush_seq(&c->journal, v->journal_seq))
				? 0 : journal_seq;
		}

		if (!data_type_is_empty(old_a->data_type) &&
		    data_type_is_empty(new_a->data_type) &&
		    bucket_journal_seq) {
			ret = bch2_set_bucket_needs_journal_commit(&c->buckets_waiting_for_journal,
					c->journal.flushed_seq_ondisk,
					new.k->p.inode, new.k->p.offset,
					bucket_journal_seq);
			if (ret) {
				bch2_fs_fatal_error(c,
					"setting bucket_needs_journal_commit: %s", bch2_err_str(ret));
				goto err;
			}
		}

		percpu_down_read(&c->mark_lock);
		if (new_a->gen != old_a->gen) {
			u8 *gen = bucket_gen(ca, new.k->p.offset);
			if (unlikely(!gen)) {
				percpu_up_read(&c->mark_lock);
				goto invalid_bucket;
			}
			*gen = new_a->gen;
		}

		bch2_dev_usage_update(c, ca, old_a, new_a, journal_seq, false);
		percpu_up_read(&c->mark_lock);

#define eval_state(_a, expr)		({ const struct bch_alloc_v4 *a = _a; expr; })
#define statechange(expr)		!eval_state(old_a, expr) && eval_state(new_a, expr)
#define bucket_flushed(a)		(!a->journal_seq || a->journal_seq <= c->journal.flushed_seq_ondisk)

		if (statechange(a->data_type == BCH_DATA_free) &&
		    bucket_flushed(new_a))
			closure_wake_up(&c->freelist_wait);

		if (statechange(a->data_type == BCH_DATA_need_discard) &&
		    !bch2_bucket_is_open(c, new.k->p.inode, new.k->p.offset) &&
		    bucket_flushed(new_a))
			bch2_discard_one_bucket_fast(c, new.k->p);

		if (statechange(a->data_type == BCH_DATA_cached) &&
		    !bch2_bucket_is_open(c, new.k->p.inode, new.k->p.offset) &&
		    should_invalidate_buckets(ca, bch2_dev_usage_read(ca)))
			bch2_do_invalidates(c);

		if (statechange(a->data_type == BCH_DATA_need_gc_gens))
			bch2_gc_gens_async(c);
	}

	if ((flags & BTREE_TRIGGER_gc) &&
	    (flags & BTREE_TRIGGER_bucket_invalidate)) {
		struct bch_alloc_v4 new_a_convert;
		const struct bch_alloc_v4 *new_a = bch2_alloc_to_v4(new.s_c, &new_a_convert);

		percpu_down_read(&c->mark_lock);
		struct bucket *g = gc_bucket(ca, new.k->p.offset);
		if (unlikely(!g)) {
			percpu_up_read(&c->mark_lock);
			goto invalid_bucket;
		}
		g->gen_valid	= 1;

		bucket_lock(g);

		g->gen_valid		= 1;
		g->gen			= new_a->gen;
		g->data_type		= new_a->data_type;
		g->stripe		= new_a->stripe;
		g->stripe_redundancy	= new_a->stripe_redundancy;
		g->dirty_sectors	= new_a->dirty_sectors;
		g->cached_sectors	= new_a->cached_sectors;

		bucket_unlock(g);
		percpu_up_read(&c->mark_lock);
	}
err:
	printbuf_exit(&buf);
	bch2_dev_put(ca);
	return ret;
invalid_bucket:
	bch2_fs_inconsistent(c, "reference to invalid bucket\n  %s",
			     (bch2_bkey_val_to_text(&buf, c, new.s_c), buf.buf));
	ret = -EIO;
	goto err;
}

/*
 * This synthesizes deleted extents for holes, similar to BTREE_ITER_slots for
 * extents style btrees, but works on non-extents btrees:
 */
static struct bkey_s_c bch2_get_key_or_hole(struct btree_iter *iter, struct bpos end, struct bkey *hole)
{
	struct bkey_s_c k = bch2_btree_iter_peek_slot(iter);

	if (bkey_err(k))
		return k;

	if (k.k->type) {
		return k;
	} else {
		struct btree_iter iter2;
		struct bpos next;

		bch2_trans_copy_iter(&iter2, iter);

		struct btree_path *path = btree_iter_path(iter->trans, iter);
		if (!bpos_eq(path->l[0].b->key.k.p, SPOS_MAX))
			end = bkey_min(end, bpos_nosnap_successor(path->l[0].b->key.k.p));

		end = bkey_min(end, POS(iter->pos.inode, iter->pos.offset + U32_MAX - 1));

		/*
		 * btree node min/max is a closed interval, upto takes a half
		 * open interval:
		 */
		k = bch2_btree_iter_peek_upto(&iter2, end);
		next = iter2.pos;
		bch2_trans_iter_exit(iter->trans, &iter2);

		BUG_ON(next.offset >= iter->pos.offset + U32_MAX);

		if (bkey_err(k))
			return k;

		bkey_init(hole);
		hole->p = iter->pos;

		bch2_key_resize(hole, next.offset - iter->pos.offset);
		return (struct bkey_s_c) { hole, NULL };
	}
}

static bool next_bucket(struct bch_fs *c, struct bch_dev **ca, struct bpos *bucket)
{
	if (*ca) {
		if (bucket->offset < (*ca)->mi.first_bucket)
			bucket->offset = (*ca)->mi.first_bucket;

		if (bucket->offset < (*ca)->mi.nbuckets)
			return true;

		bch2_dev_put(*ca);
		*ca = NULL;
		bucket->inode++;
		bucket->offset = 0;
	}

	rcu_read_lock();
	*ca = __bch2_next_dev_idx(c, bucket->inode, NULL);
	if (*ca) {
		*bucket = POS((*ca)->dev_idx, (*ca)->mi.first_bucket);
		bch2_dev_get(*ca);
	}
	rcu_read_unlock();

	return *ca != NULL;
}

static struct bkey_s_c bch2_get_key_or_real_bucket_hole(struct btree_iter *iter,
					struct bch_dev **ca, struct bkey *hole)
{
	struct bch_fs *c = iter->trans->c;
	struct bkey_s_c k;
again:
	k = bch2_get_key_or_hole(iter, POS_MAX, hole);
	if (bkey_err(k))
		return k;

	*ca = bch2_dev_iterate_noerror(c, *ca, k.k->p.inode);

	if (!k.k->type) {
		struct bpos hole_start = bkey_start_pos(k.k);

		if (!*ca || !bucket_valid(*ca, hole_start.offset)) {
			if (!next_bucket(c, ca, &hole_start))
				return bkey_s_c_null;

			bch2_btree_iter_set_pos(iter, hole_start);
			goto again;
		}

		if (k.k->p.offset > (*ca)->mi.nbuckets)
			bch2_key_resize(hole, (*ca)->mi.nbuckets - hole_start.offset);
	}

	return k;
}

static noinline_for_stack
int bch2_check_alloc_key(struct btree_trans *trans,
			 struct bkey_s_c alloc_k,
			 struct btree_iter *alloc_iter,
			 struct btree_iter *discard_iter,
			 struct btree_iter *freespace_iter,
			 struct btree_iter *bucket_gens_iter)
{
	struct bch_fs *c = trans->c;
	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a;
	unsigned discard_key_type, freespace_key_type;
	unsigned gens_offset;
	struct bkey_s_c k;
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	struct bch_dev *ca = bch2_dev_bucket_tryget_noerror(c, alloc_k.k->p);
	if (fsck_err_on(!ca,
			c, alloc_key_to_missing_dev_bucket,
			"alloc key for invalid device:bucket %llu:%llu",
			alloc_k.k->p.inode, alloc_k.k->p.offset))
		ret = bch2_btree_delete_at(trans, alloc_iter, 0);
	if (!ca)
		return ret;

	if (!ca->mi.freespace_initialized)
		goto out;

	a = bch2_alloc_to_v4(alloc_k, &a_convert);

	discard_key_type = a->data_type == BCH_DATA_need_discard ? KEY_TYPE_set : 0;
	bch2_btree_iter_set_pos(discard_iter, alloc_k.k->p);
	k = bch2_btree_iter_peek_slot(discard_iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (fsck_err_on(k.k->type != discard_key_type,
			c, need_discard_key_wrong,
			"incorrect key in need_discard btree (got %s should be %s)\n"
			"  %s",
			bch2_bkey_types[k.k->type],
			bch2_bkey_types[discard_key_type],
			(bch2_bkey_val_to_text(&buf, c, alloc_k), buf.buf))) {
		struct bkey_i *update =
			bch2_trans_kmalloc(trans, sizeof(*update));

		ret = PTR_ERR_OR_ZERO(update);
		if (ret)
			goto err;

		bkey_init(&update->k);
		update->k.type	= discard_key_type;
		update->k.p	= discard_iter->pos;

		ret = bch2_trans_update(trans, discard_iter, update, 0);
		if (ret)
			goto err;
	}

	freespace_key_type = a->data_type == BCH_DATA_free ? KEY_TYPE_set : 0;
	bch2_btree_iter_set_pos(freespace_iter, alloc_freespace_pos(alloc_k.k->p, *a));
	k = bch2_btree_iter_peek_slot(freespace_iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (fsck_err_on(k.k->type != freespace_key_type,
			c, freespace_key_wrong,
			"incorrect key in freespace btree (got %s should be %s)\n"
			"  %s",
			bch2_bkey_types[k.k->type],
			bch2_bkey_types[freespace_key_type],
			(printbuf_reset(&buf),
			 bch2_bkey_val_to_text(&buf, c, alloc_k), buf.buf))) {
		struct bkey_i *update =
			bch2_trans_kmalloc(trans, sizeof(*update));

		ret = PTR_ERR_OR_ZERO(update);
		if (ret)
			goto err;

		bkey_init(&update->k);
		update->k.type	= freespace_key_type;
		update->k.p	= freespace_iter->pos;
		bch2_key_resize(&update->k, 1);

		ret = bch2_trans_update(trans, freespace_iter, update, 0);
		if (ret)
			goto err;
	}

	bch2_btree_iter_set_pos(bucket_gens_iter, alloc_gens_pos(alloc_k.k->p, &gens_offset));
	k = bch2_btree_iter_peek_slot(bucket_gens_iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (fsck_err_on(a->gen != alloc_gen(k, gens_offset),
			c, bucket_gens_key_wrong,
			"incorrect gen in bucket_gens btree (got %u should be %u)\n"
			"  %s",
			alloc_gen(k, gens_offset), a->gen,
			(printbuf_reset(&buf),
			 bch2_bkey_val_to_text(&buf, c, alloc_k), buf.buf))) {
		struct bkey_i_bucket_gens *g =
			bch2_trans_kmalloc(trans, sizeof(*g));

		ret = PTR_ERR_OR_ZERO(g);
		if (ret)
			goto err;

		if (k.k->type == KEY_TYPE_bucket_gens) {
			bkey_reassemble(&g->k_i, k);
		} else {
			bkey_bucket_gens_init(&g->k_i);
			g->k.p = alloc_gens_pos(alloc_k.k->p, &gens_offset);
		}

		g->v.gens[gens_offset] = a->gen;

		ret = bch2_trans_update(trans, bucket_gens_iter, &g->k_i, 0);
		if (ret)
			goto err;
	}
out:
err:
fsck_err:
	bch2_dev_put(ca);
	printbuf_exit(&buf);
	return ret;
}

static noinline_for_stack
int bch2_check_alloc_hole_freespace(struct btree_trans *trans,
				    struct bch_dev *ca,
				    struct bpos start,
				    struct bpos *end,
				    struct btree_iter *freespace_iter)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c k;
	struct printbuf buf = PRINTBUF;
	int ret;

	if (!ca->mi.freespace_initialized)
		return 0;

	bch2_btree_iter_set_pos(freespace_iter, start);

	k = bch2_btree_iter_peek_slot(freespace_iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	*end = bkey_min(k.k->p, *end);

	if (fsck_err_on(k.k->type != KEY_TYPE_set,
			c, freespace_hole_missing,
			"hole in alloc btree missing in freespace btree\n"
			"  device %llu buckets %llu-%llu",
			freespace_iter->pos.inode,
			freespace_iter->pos.offset,
			end->offset)) {
		struct bkey_i *update =
			bch2_trans_kmalloc(trans, sizeof(*update));

		ret = PTR_ERR_OR_ZERO(update);
		if (ret)
			goto err;

		bkey_init(&update->k);
		update->k.type	= KEY_TYPE_set;
		update->k.p	= freespace_iter->pos;
		bch2_key_resize(&update->k,
				min_t(u64, U32_MAX, end->offset -
				      freespace_iter->pos.offset));

		ret = bch2_trans_update(trans, freespace_iter, update, 0);
		if (ret)
			goto err;
	}
err:
fsck_err:
	printbuf_exit(&buf);
	return ret;
}

static noinline_for_stack
int bch2_check_alloc_hole_bucket_gens(struct btree_trans *trans,
				      struct bpos start,
				      struct bpos *end,
				      struct btree_iter *bucket_gens_iter)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c k;
	struct printbuf buf = PRINTBUF;
	unsigned i, gens_offset, gens_end_offset;
	int ret;

	bch2_btree_iter_set_pos(bucket_gens_iter, alloc_gens_pos(start, &gens_offset));

	k = bch2_btree_iter_peek_slot(bucket_gens_iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (bkey_cmp(alloc_gens_pos(start, &gens_offset),
		     alloc_gens_pos(*end,  &gens_end_offset)))
		gens_end_offset = KEY_TYPE_BUCKET_GENS_NR;

	if (k.k->type == KEY_TYPE_bucket_gens) {
		struct bkey_i_bucket_gens g;
		bool need_update = false;

		bkey_reassemble(&g.k_i, k);

		for (i = gens_offset; i < gens_end_offset; i++) {
			if (fsck_err_on(g.v.gens[i], c,
					bucket_gens_hole_wrong,
					"hole in alloc btree at %llu:%llu with nonzero gen in bucket_gens btree (%u)",
					bucket_gens_pos_to_alloc(k.k->p, i).inode,
					bucket_gens_pos_to_alloc(k.k->p, i).offset,
					g.v.gens[i])) {
				g.v.gens[i] = 0;
				need_update = true;
			}
		}

		if (need_update) {
			struct bkey_i *u = bch2_trans_kmalloc(trans, sizeof(g));

			ret = PTR_ERR_OR_ZERO(u);
			if (ret)
				goto err;

			memcpy(u, &g, sizeof(g));

			ret = bch2_trans_update(trans, bucket_gens_iter, u, 0);
			if (ret)
				goto err;
		}
	}

	*end = bkey_min(*end, bucket_gens_pos_to_alloc(bpos_nosnap_successor(k.k->p), 0));
err:
fsck_err:
	printbuf_exit(&buf);
	return ret;
}

static noinline_for_stack int bch2_check_discard_freespace_key(struct btree_trans *trans,
					      struct btree_iter *iter)
{
	struct bch_fs *c = trans->c;
	struct btree_iter alloc_iter;
	struct bkey_s_c alloc_k;
	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a;
	u64 genbits;
	struct bpos pos;
	enum bch_data_type state = iter->btree_id == BTREE_ID_need_discard
		? BCH_DATA_need_discard
		: BCH_DATA_free;
	struct printbuf buf = PRINTBUF;
	int ret;

	pos = iter->pos;
	pos.offset &= ~(~0ULL << 56);
	genbits = iter->pos.offset & (~0ULL << 56);

	alloc_k = bch2_bkey_get_iter(trans, &alloc_iter, BTREE_ID_alloc, pos, 0);
	ret = bkey_err(alloc_k);
	if (ret)
		return ret;

	if (fsck_err_on(!bch2_dev_bucket_exists(c, pos), c,
			need_discard_freespace_key_to_invalid_dev_bucket,
			"entry in %s btree for nonexistant dev:bucket %llu:%llu",
			bch2_btree_id_str(iter->btree_id), pos.inode, pos.offset))
		goto delete;

	a = bch2_alloc_to_v4(alloc_k, &a_convert);

	if (fsck_err_on(a->data_type != state ||
			(state == BCH_DATA_free &&
			 genbits != alloc_freespace_genbits(*a)), c,
			need_discard_freespace_key_bad,
			"%s\n  incorrectly set at %s:%llu:%llu:0 (free %u, genbits %llu should be %llu)",
			(bch2_bkey_val_to_text(&buf, c, alloc_k), buf.buf),
			bch2_btree_id_str(iter->btree_id),
			iter->pos.inode,
			iter->pos.offset,
			a->data_type == state,
			genbits >> 56, alloc_freespace_genbits(*a) >> 56))
		goto delete;
out:
fsck_err:
	bch2_set_btree_iter_dontneed(&alloc_iter);
	bch2_trans_iter_exit(trans, &alloc_iter);
	printbuf_exit(&buf);
	return ret;
delete:
	ret =   bch2_btree_delete_extent_at(trans, iter,
			iter->btree_id == BTREE_ID_freespace ? 1 : 0, 0) ?:
		bch2_trans_commit(trans, NULL, NULL,
			BCH_TRANS_COMMIT_no_enospc);
	goto out;
}

/*
 * We've already checked that generation numbers in the bucket_gens btree are
 * valid for buckets that exist; this just checks for keys for nonexistent
 * buckets.
 */
static noinline_for_stack
int bch2_check_bucket_gens_key(struct btree_trans *trans,
			       struct btree_iter *iter,
			       struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	struct bkey_i_bucket_gens g;
	u64 start = bucket_gens_pos_to_alloc(k.k->p, 0).offset;
	u64 end = bucket_gens_pos_to_alloc(bpos_nosnap_successor(k.k->p), 0).offset;
	u64 b;
	bool need_update = false;
	struct printbuf buf = PRINTBUF;
	int ret = 0;

	BUG_ON(k.k->type != KEY_TYPE_bucket_gens);
	bkey_reassemble(&g.k_i, k);

	struct bch_dev *ca = bch2_dev_tryget_noerror(c, k.k->p.inode);
	if (!ca) {
		if (fsck_err(c, bucket_gens_to_invalid_dev,
			     "bucket_gens key for invalid device:\n  %s",
			     (bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
			ret = bch2_btree_delete_at(trans, iter, 0);
		goto out;
	}

	if (fsck_err_on(end <= ca->mi.first_bucket ||
			start >= ca->mi.nbuckets, c,
			bucket_gens_to_invalid_buckets,
			"bucket_gens key for invalid buckets:\n  %s",
			(bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
		ret = bch2_btree_delete_at(trans, iter, 0);
		goto out;
	}

	for (b = start; b < ca->mi.first_bucket; b++)
		if (fsck_err_on(g.v.gens[b & KEY_TYPE_BUCKET_GENS_MASK], c,
				bucket_gens_nonzero_for_invalid_buckets,
				"bucket_gens key has nonzero gen for invalid bucket")) {
			g.v.gens[b & KEY_TYPE_BUCKET_GENS_MASK] = 0;
			need_update = true;
		}

	for (b = ca->mi.nbuckets; b < end; b++)
		if (fsck_err_on(g.v.gens[b & KEY_TYPE_BUCKET_GENS_MASK], c,
				bucket_gens_nonzero_for_invalid_buckets,
				"bucket_gens key has nonzero gen for invalid bucket")) {
			g.v.gens[b & KEY_TYPE_BUCKET_GENS_MASK] = 0;
			need_update = true;
		}

	if (need_update) {
		struct bkey_i *u = bch2_trans_kmalloc(trans, sizeof(g));

		ret = PTR_ERR_OR_ZERO(u);
		if (ret)
			goto out;

		memcpy(u, &g, sizeof(g));
		ret = bch2_trans_update(trans, iter, u, 0);
	}
out:
fsck_err:
	bch2_dev_put(ca);
	printbuf_exit(&buf);
	return ret;
}

int bch2_check_alloc_info(struct bch_fs *c)
{
	struct btree_trans *trans = bch2_trans_get(c);
	struct btree_iter iter, discard_iter, freespace_iter, bucket_gens_iter;
	struct bch_dev *ca = NULL;
	struct bkey hole;
	struct bkey_s_c k;
	int ret = 0;

	bch2_trans_iter_init(trans, &iter, BTREE_ID_alloc, POS_MIN,
			     BTREE_ITER_prefetch);
	bch2_trans_iter_init(trans, &discard_iter, BTREE_ID_need_discard, POS_MIN,
			     BTREE_ITER_prefetch);
	bch2_trans_iter_init(trans, &freespace_iter, BTREE_ID_freespace, POS_MIN,
			     BTREE_ITER_prefetch);
	bch2_trans_iter_init(trans, &bucket_gens_iter, BTREE_ID_bucket_gens, POS_MIN,
			     BTREE_ITER_prefetch);

	while (1) {
		struct bpos next;

		bch2_trans_begin(trans);

		k = bch2_get_key_or_real_bucket_hole(&iter, &ca, &hole);
		ret = bkey_err(k);
		if (ret)
			goto bkey_err;

		if (!k.k)
			break;

		if (k.k->type) {
			next = bpos_nosnap_successor(k.k->p);

			ret = bch2_check_alloc_key(trans,
						   k, &iter,
						   &discard_iter,
						   &freespace_iter,
						   &bucket_gens_iter);
			if (ret)
				goto bkey_err;
		} else {
			next = k.k->p;

			ret = bch2_check_alloc_hole_freespace(trans, ca,
						    bkey_start_pos(k.k),
						    &next,
						    &freespace_iter) ?:
				bch2_check_alloc_hole_bucket_gens(trans,
						    bkey_start_pos(k.k),
						    &next,
						    &bucket_gens_iter);
			if (ret)
				goto bkey_err;
		}

		ret = bch2_trans_commit(trans, NULL, NULL,
					BCH_TRANS_COMMIT_no_enospc);
		if (ret)
			goto bkey_err;

		bch2_btree_iter_set_pos(&iter, next);
bkey_err:
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ret)
			break;
	}
	bch2_trans_iter_exit(trans, &bucket_gens_iter);
	bch2_trans_iter_exit(trans, &freespace_iter);
	bch2_trans_iter_exit(trans, &discard_iter);
	bch2_trans_iter_exit(trans, &iter);
	bch2_dev_put(ca);
	ca = NULL;

	if (ret < 0)
		goto err;

	ret = for_each_btree_key(trans, iter,
			BTREE_ID_need_discard, POS_MIN,
			BTREE_ITER_prefetch, k,
		bch2_check_discard_freespace_key(trans, &iter));
	if (ret)
		goto err;

	bch2_trans_iter_init(trans, &iter, BTREE_ID_freespace, POS_MIN,
			     BTREE_ITER_prefetch);
	while (1) {
		bch2_trans_begin(trans);
		k = bch2_btree_iter_peek(&iter);
		if (!k.k)
			break;

		ret = bkey_err(k) ?:
			bch2_check_discard_freespace_key(trans, &iter);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart)) {
			ret = 0;
			continue;
		}
		if (ret) {
			struct printbuf buf = PRINTBUF;
			bch2_bkey_val_to_text(&buf, c, k);

			bch_err(c, "while checking %s", buf.buf);
			printbuf_exit(&buf);
			break;
		}

		bch2_btree_iter_set_pos(&iter, bpos_nosnap_successor(iter.pos));
	}
	bch2_trans_iter_exit(trans, &iter);
	if (ret)
		goto err;

	ret = for_each_btree_key_commit(trans, iter,
			BTREE_ID_bucket_gens, POS_MIN,
			BTREE_ITER_prefetch, k,
			NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
		bch2_check_bucket_gens_key(trans, &iter, k));
err:
	bch2_trans_put(trans);
	bch_err_fn(c, ret);
	return ret;
}

static int bch2_check_alloc_to_lru_ref(struct btree_trans *trans,
				       struct btree_iter *alloc_iter)
{
	struct bch_fs *c = trans->c;
	struct btree_iter lru_iter;
	struct bch_alloc_v4 a_convert;
	const struct bch_alloc_v4 *a;
	struct bkey_s_c alloc_k, lru_k;
	struct printbuf buf = PRINTBUF;
	int ret;

	alloc_k = bch2_btree_iter_peek(alloc_iter);
	if (!alloc_k.k)
		return 0;

	ret = bkey_err(alloc_k);
	if (ret)
		return ret;

	a = bch2_alloc_to_v4(alloc_k, &a_convert);

	if (a->data_type != BCH_DATA_cached)
		return 0;

	if (fsck_err_on(!a->io_time[READ], c,
			alloc_key_cached_but_read_time_zero,
			"cached bucket with read_time 0\n"
			"  %s",
		(printbuf_reset(&buf),
		 bch2_bkey_val_to_text(&buf, c, alloc_k), buf.buf))) {
		struct bkey_i_alloc_v4 *a_mut =
			bch2_alloc_to_v4_mut(trans, alloc_k);
		ret = PTR_ERR_OR_ZERO(a_mut);
		if (ret)
			goto err;

		a_mut->v.io_time[READ] = atomic64_read(&c->io_clock[READ].now);
		ret = bch2_trans_update(trans, alloc_iter,
					&a_mut->k_i, BTREE_TRIGGER_norun);
		if (ret)
			goto err;

		a = &a_mut->v;
	}

	lru_k = bch2_bkey_get_iter(trans, &lru_iter, BTREE_ID_lru,
			     lru_pos(alloc_k.k->p.inode,
				     bucket_to_u64(alloc_k.k->p),
				     a->io_time[READ]), 0);
	ret = bkey_err(lru_k);
	if (ret)
		return ret;

	if (fsck_err_on(lru_k.k->type != KEY_TYPE_set, c,
			alloc_key_to_missing_lru_entry,
			"missing lru entry\n"
			"  %s",
			(printbuf_reset(&buf),
			 bch2_bkey_val_to_text(&buf, c, alloc_k), buf.buf))) {
		ret = bch2_lru_set(trans,
				   alloc_k.k->p.inode,
				   bucket_to_u64(alloc_k.k->p),
				   a->io_time[READ]);
		if (ret)
			goto err;
	}
err:
fsck_err:
	bch2_trans_iter_exit(trans, &lru_iter);
	printbuf_exit(&buf);
	return ret;
}

int bch2_check_alloc_to_lru_refs(struct bch_fs *c)
{
	int ret = bch2_trans_run(c,
		for_each_btree_key_commit(trans, iter, BTREE_ID_alloc,
				POS_MIN, BTREE_ITER_prefetch, k,
				NULL, NULL, BCH_TRANS_COMMIT_no_enospc,
			bch2_check_alloc_to_lru_ref(trans, &iter)));
	bch_err_fn(c, ret);
	return ret;
}

static int discard_in_flight_add(struct bch_fs *c, struct bpos bucket)
{
	int ret;

	mutex_lock(&c->discard_buckets_in_flight_lock);
	darray_for_each(c->discard_buckets_in_flight, i)
		if (bkey_eq(*i, bucket)) {
			ret = -EEXIST;
			goto out;
		}

	ret = darray_push(&c->discard_buckets_in_flight, bucket);
out:
	mutex_unlock(&c->discard_buckets_in_flight_lock);
	return ret;
}

static void discard_in_flight_remove(struct bch_fs *c, struct bpos bucket)
{
	mutex_lock(&c->discard_buckets_in_flight_lock);
	darray_for_each(c->discard_buckets_in_flight, i)
		if (bkey_eq(*i, bucket)) {
			darray_remove_item(&c->discard_buckets_in_flight, i);
			goto found;
		}
	BUG();
found:
	mutex_unlock(&c->discard_buckets_in_flight_lock);
}

struct discard_buckets_state {
	u64		seen;
	u64		open;
	u64		need_journal_commit;
	u64		discarded;
	struct bch_dev	*ca;
	u64		need_journal_commit_this_dev;
};

static void discard_buckets_next_dev(struct bch_fs *c, struct discard_buckets_state *s, struct bch_dev *ca)
{
	if (s->ca == ca)
		return;

	if (s->ca && s->need_journal_commit_this_dev >
	    bch2_dev_usage_read(s->ca).d[BCH_DATA_free].buckets)
		bch2_journal_flush_async(&c->journal, NULL);

	if (s->ca)
		percpu_ref_put(&s->ca->io_ref);
	s->ca = ca;
	s->need_journal_commit_this_dev = 0;
}

static int bch2_discard_one_bucket(struct btree_trans *trans,
				   struct btree_iter *need_discard_iter,
				   struct bpos *discard_pos_done,
				   struct discard_buckets_state *s)
{
	struct bch_fs *c = trans->c;
	struct bpos pos = need_discard_iter->pos;
	struct btree_iter iter = { NULL };
	struct bkey_s_c k;
	struct bkey_i_alloc_v4 *a;
	struct printbuf buf = PRINTBUF;
	bool discard_locked = false;
	int ret = 0;

	struct bch_dev *ca = s->ca && s->ca->dev_idx == pos.inode
		? s->ca
		: bch2_dev_get_ioref(c, pos.inode, WRITE);
	if (!ca) {
		bch2_btree_iter_set_pos(need_discard_iter, POS(pos.inode + 1, 0));
		return 0;
	}

	discard_buckets_next_dev(c, s, ca);

	if (bch2_bucket_is_open_safe(c, pos.inode, pos.offset)) {
		s->open++;
		goto out;
	}

	if (bch2_bucket_needs_journal_commit(&c->buckets_waiting_for_journal,
			c->journal.flushed_seq_ondisk,
			pos.inode, pos.offset)) {
		s->need_journal_commit++;
		s->need_journal_commit_this_dev++;
		goto out;
	}

	k = bch2_bkey_get_iter(trans, &iter, BTREE_ID_alloc,
			       need_discard_iter->pos,
			       BTREE_ITER_cached);
	ret = bkey_err(k);
	if (ret)
		goto out;

	a = bch2_alloc_to_v4_mut(trans, k);
	ret = PTR_ERR_OR_ZERO(a);
	if (ret)
		goto out;

	if (bch2_bucket_sectors_total(a->v)) {
		if (bch2_trans_inconsistent_on(c->curr_recovery_pass > BCH_RECOVERY_PASS_check_alloc_info,
					       trans, "attempting to discard bucket with dirty data\n%s",
					       (bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
			ret = -EIO;
		goto out;
	}

	if (a->v.data_type != BCH_DATA_need_discard) {
		if (data_type_is_empty(a->v.data_type) &&
		    BCH_ALLOC_V4_NEED_INC_GEN(&a->v)) {
			a->v.gen++;
			SET_BCH_ALLOC_V4_NEED_INC_GEN(&a->v, false);
			goto write;
		}

		if (bch2_trans_inconsistent_on(c->curr_recovery_pass > BCH_RECOVERY_PASS_check_alloc_info,
					       trans, "bucket incorrectly set in need_discard btree\n"
					       "%s",
					       (bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
			ret = -EIO;
		goto out;
	}

	if (a->v.journal_seq > c->journal.flushed_seq_ondisk) {
		if (bch2_trans_inconsistent_on(c->curr_recovery_pass > BCH_RECOVERY_PASS_check_alloc_info,
					       trans, "clearing need_discard but journal_seq %llu > flushed_seq %llu\n%s",
					       a->v.journal_seq,
					       c->journal.flushed_seq_ondisk,
					       (bch2_bkey_val_to_text(&buf, c, k), buf.buf)))
			ret = -EIO;
		goto out;
	}

	if (discard_in_flight_add(c, SPOS(iter.pos.inode, iter.pos.offset, true)))
		goto out;

	discard_locked = true;

	if (!bkey_eq(*discard_pos_done, iter.pos) &&
	    ca->mi.discard && !c->opts.nochanges) {
		/*
		 * This works without any other locks because this is the only
		 * thread that removes items from the need_discard tree
		 */
		bch2_trans_unlock_long(trans);
		blkdev_issue_discard(ca->disk_sb.bdev,
				     k.k->p.offset * ca->mi.bucket_size,
				     ca->mi.bucket_size,
				     GFP_KERNEL);
		*discard_pos_done = iter.pos;

		ret = bch2_trans_relock_notrace(trans);
		if (ret)
			goto out;
	}

	SET_BCH_ALLOC_V4_NEED_DISCARD(&a->v, false);
	alloc_data_type_set(&a->v, a->v.data_type);
write:
	ret =   bch2_trans_update(trans, &iter, &a->k_i, 0) ?:
		bch2_trans_commit(trans, NULL, NULL,
				  BCH_WATERMARK_btree|
				  BCH_TRANS_COMMIT_no_enospc);
	if (ret)
		goto out;

	count_event(c, bucket_discard);
	s->discarded++;
out:
	if (discard_locked)
		discard_in_flight_remove(c, iter.pos);
	s->seen++;
	bch2_trans_iter_exit(trans, &iter);
	printbuf_exit(&buf);
	return ret;
}

static void bch2_do_discards_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs, discard_work);
	struct discard_buckets_state s = {};
	struct bpos discard_pos_done = POS_MAX;
	int ret;

	/*
	 * We're doing the commit in bch2_discard_one_bucket instead of using
	 * for_each_btree_key_commit() so that we can increment counters after
	 * successful commit:
	 */
	ret = bch2_trans_run(c,
		for_each_btree_key(trans, iter,
				   BTREE_ID_need_discard, POS_MIN, 0, k,
			bch2_discard_one_bucket(trans, &iter, &discard_pos_done, &s)));

	discard_buckets_next_dev(c, &s, NULL);

	trace_discard_buckets(c, s.seen, s.open, s.need_journal_commit, s.discarded,
			      bch2_err_str(ret));

	bch2_write_ref_put(c, BCH_WRITE_REF_discard);
}

void bch2_do_discards(struct bch_fs *c)
{
	if (bch2_write_ref_tryget(c, BCH_WRITE_REF_discard) &&
	    !queue_work(c->write_ref_wq, &c->discard_work))
		bch2_write_ref_put(c, BCH_WRITE_REF_discard);
}

static int bch2_clear_bucket_needs_discard(struct btree_trans *trans, struct bpos bucket)
{
	struct btree_iter iter;
	bch2_trans_iter_init(trans, &iter, BTREE_ID_alloc, bucket, BTREE_ITER_intent);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(&iter);
	int ret = bkey_err(k);
	if (ret)
		goto err;

	struct bkey_i_alloc_v4 *a = bch2_alloc_to_v4_mut(trans, k);
	ret = PTR_ERR_OR_ZERO(a);
	if (ret)
		goto err;

	BUG_ON(a->v.dirty_sectors);
	SET_BCH_ALLOC_V4_NEED_DISCARD(&a->v, false);
	alloc_data_type_set(&a->v, a->v.data_type);

	ret = bch2_trans_update(trans, &iter, &a->k_i, 0);
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static void bch2_do_discards_fast_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs, discard_fast_work);

	while (1) {
		bool got_bucket = false;
		struct bpos bucket;
		struct bch_dev *ca;

		mutex_lock(&c->discard_buckets_in_flight_lock);
		darray_for_each(c->discard_buckets_in_flight, i) {
			if (i->snapshot)
				continue;

			ca = bch2_dev_get_ioref(c, i->inode, WRITE);
			if (!ca) {
				darray_remove_item(&c->discard_buckets_in_flight, i);
				continue;
			}

			got_bucket = true;
			bucket = *i;
			i->snapshot = true;
			break;
		}
		mutex_unlock(&c->discard_buckets_in_flight_lock);

		if (!got_bucket)
			break;

		if (ca->mi.discard && !c->opts.nochanges)
			blkdev_issue_discard(ca->disk_sb.bdev,
					     bucket.offset * ca->mi.bucket_size,
					     ca->mi.bucket_size,
					     GFP_KERNEL);

		int ret = bch2_trans_do(c, NULL, NULL,
					BCH_WATERMARK_btree|
					BCH_TRANS_COMMIT_no_enospc,
					bch2_clear_bucket_needs_discard(trans, bucket));
		bch_err_fn(c, ret);

		percpu_ref_put(&ca->io_ref);
		discard_in_flight_remove(c, bucket);

		if (ret)
			break;
	}

	bch2_write_ref_put(c, BCH_WRITE_REF_discard_fast);
}

static void bch2_discard_one_bucket_fast(struct bch_fs *c, struct bpos bucket)
{
	rcu_read_lock();
	struct bch_dev *ca = bch2_dev_rcu(c, bucket.inode);
	bool dead = !ca || percpu_ref_is_dying(&ca->io_ref);
	rcu_read_unlock();

	if (!dead &&
	    !discard_in_flight_add(c, bucket) &&
	    bch2_write_ref_tryget(c, BCH_WRITE_REF_discard_fast) &&
	    !queue_work(c->write_ref_wq, &c->discard_fast_work))
		bch2_write_ref_put(c, BCH_WRITE_REF_discard_fast);
}

static int invalidate_one_bucket(struct btree_trans *trans,
				 struct btree_iter *lru_iter,
				 struct bkey_s_c lru_k,
				 s64 *nr_to_invalidate)
{
	struct bch_fs *c = trans->c;
	struct bkey_i_alloc_v4 *a = NULL;
	struct printbuf buf = PRINTBUF;
	struct bpos bucket = u64_to_bucket(lru_k.k->p.offset);
	unsigned cached_sectors;
	int ret = 0;

	if (*nr_to_invalidate <= 0)
		return 1;

	if (!bch2_dev_bucket_exists(c, bucket)) {
		prt_str(&buf, "lru entry points to invalid bucket");
		goto err;
	}

	if (bch2_bucket_is_open_safe(c, bucket.inode, bucket.offset))
		return 0;

	a = bch2_trans_start_alloc_update(trans, bucket);
	ret = PTR_ERR_OR_ZERO(a);
	if (ret)
		goto out;

	/* We expect harmless races here due to the btree write buffer: */
	if (lru_pos_time(lru_iter->pos) != alloc_lru_idx_read(a->v))
		goto out;

	BUG_ON(a->v.data_type != BCH_DATA_cached);
	BUG_ON(a->v.dirty_sectors);

	if (!a->v.cached_sectors)
		bch_err(c, "invalidating empty bucket, confused");

	cached_sectors = a->v.cached_sectors;

	SET_BCH_ALLOC_V4_NEED_INC_GEN(&a->v, false);
	a->v.gen++;
	a->v.data_type		= 0;
	a->v.dirty_sectors	= 0;
	a->v.cached_sectors	= 0;
	a->v.io_time[READ]	= atomic64_read(&c->io_clock[READ].now);
	a->v.io_time[WRITE]	= atomic64_read(&c->io_clock[WRITE].now);

	ret = bch2_trans_commit(trans, NULL, NULL,
				BCH_WATERMARK_btree|
				BCH_TRANS_COMMIT_no_enospc);
	if (ret)
		goto out;

	trace_and_count(c, bucket_invalidate, c, bucket.inode, bucket.offset, cached_sectors);
	--*nr_to_invalidate;
out:
	printbuf_exit(&buf);
	return ret;
err:
	prt_str(&buf, "\n  lru key: ");
	bch2_bkey_val_to_text(&buf, c, lru_k);

	prt_str(&buf, "\n  lru entry: ");
	bch2_lru_pos_to_text(&buf, lru_iter->pos);

	prt_str(&buf, "\n  alloc key: ");
	if (!a)
		bch2_bpos_to_text(&buf, bucket);
	else
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&a->k_i));

	bch_err(c, "%s", buf.buf);
	if (c->curr_recovery_pass > BCH_RECOVERY_PASS_check_lrus) {
		bch2_inconsistent_error(c);
		ret = -EINVAL;
	}

	goto out;
}

static void bch2_do_invalidates_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs, invalidate_work);
	struct btree_trans *trans = bch2_trans_get(c);
	int ret = 0;

	ret = bch2_btree_write_buffer_tryflush(trans);
	if (ret)
		goto err;

	for_each_member_device(c, ca) {
		s64 nr_to_invalidate =
			should_invalidate_buckets(ca, bch2_dev_usage_read(ca));

		ret = for_each_btree_key_upto(trans, iter, BTREE_ID_lru,
				lru_pos(ca->dev_idx, 0, 0),
				lru_pos(ca->dev_idx, U64_MAX, LRU_TIME_MAX),
				BTREE_ITER_intent, k,
			invalidate_one_bucket(trans, &iter, k, &nr_to_invalidate));

		if (ret < 0) {
			bch2_dev_put(ca);
			break;
		}
	}
err:
	bch2_trans_put(trans);
	bch2_write_ref_put(c, BCH_WRITE_REF_invalidate);
}

void bch2_do_invalidates(struct bch_fs *c)
{
	if (bch2_write_ref_tryget(c, BCH_WRITE_REF_invalidate) &&
	    !queue_work(c->write_ref_wq, &c->invalidate_work))
		bch2_write_ref_put(c, BCH_WRITE_REF_invalidate);
}

int bch2_dev_freespace_init(struct bch_fs *c, struct bch_dev *ca,
			    u64 bucket_start, u64 bucket_end)
{
	struct btree_trans *trans = bch2_trans_get(c);
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey hole;
	struct bpos end = POS(ca->dev_idx, bucket_end);
	struct bch_member *m;
	unsigned long last_updated = jiffies;
	int ret;

	BUG_ON(bucket_start > bucket_end);
	BUG_ON(bucket_end > ca->mi.nbuckets);

	bch2_trans_iter_init(trans, &iter, BTREE_ID_alloc,
		POS(ca->dev_idx, max_t(u64, ca->mi.first_bucket, bucket_start)),
		BTREE_ITER_prefetch);
	/*
	 * Scan the alloc btree for every bucket on @ca, and add buckets to the
	 * freespace/need_discard/need_gc_gens btrees as needed:
	 */
	while (1) {
		if (last_updated + HZ * 10 < jiffies) {
			bch_info(ca, "%s: currently at %llu/%llu",
				 __func__, iter.pos.offset, ca->mi.nbuckets);
			last_updated = jiffies;
		}

		bch2_trans_begin(trans);

		if (bkey_ge(iter.pos, end)) {
			ret = 0;
			break;
		}

		k = bch2_get_key_or_hole(&iter, end, &hole);
		ret = bkey_err(k);
		if (ret)
			goto bkey_err;

		if (k.k->type) {
			/*
			 * We process live keys in the alloc btree one at a
			 * time:
			 */
			struct bch_alloc_v4 a_convert;
			const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k, &a_convert);

			ret =   bch2_bucket_do_index(trans, ca, k, a, true) ?:
				bch2_trans_commit(trans, NULL, NULL,
						  BCH_TRANS_COMMIT_no_enospc);
			if (ret)
				goto bkey_err;

			bch2_btree_iter_advance(&iter);
		} else {
			struct bkey_i *freespace;

			freespace = bch2_trans_kmalloc(trans, sizeof(*freespace));
			ret = PTR_ERR_OR_ZERO(freespace);
			if (ret)
				goto bkey_err;

			bkey_init(&freespace->k);
			freespace->k.type	= KEY_TYPE_set;
			freespace->k.p		= k.k->p;
			freespace->k.size	= k.k->size;

			ret = bch2_btree_insert_trans(trans, BTREE_ID_freespace, freespace, 0) ?:
				bch2_trans_commit(trans, NULL, NULL,
						  BCH_TRANS_COMMIT_no_enospc);
			if (ret)
				goto bkey_err;

			bch2_btree_iter_set_pos(&iter, k.k->p);
		}
bkey_err:
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ret)
			break;
	}

	bch2_trans_iter_exit(trans, &iter);
	bch2_trans_put(trans);

	if (ret < 0) {
		bch_err_msg(ca, ret, "initializing free space");
		return ret;
	}

	mutex_lock(&c->sb_lock);
	m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);
	SET_BCH_MEMBER_FREESPACE_INITIALIZED(m, true);
	mutex_unlock(&c->sb_lock);

	return 0;
}

int bch2_fs_freespace_init(struct bch_fs *c)
{
	int ret = 0;
	bool doing_init = false;

	/*
	 * We can crash during the device add path, so we need to check this on
	 * every mount:
	 */

	for_each_member_device(c, ca) {
		if (ca->mi.freespace_initialized)
			continue;

		if (!doing_init) {
			bch_info(c, "initializing freespace");
			doing_init = true;
		}

		ret = bch2_dev_freespace_init(c, ca, 0, ca->mi.nbuckets);
		if (ret) {
			bch2_dev_put(ca);
			bch_err_fn(c, ret);
			return ret;
		}
	}

	if (doing_init) {
		mutex_lock(&c->sb_lock);
		bch2_write_super(c);
		mutex_unlock(&c->sb_lock);
		bch_verbose(c, "done initializing freespace");
	}

	return 0;
}

/* Bucket IO clocks: */

int bch2_bucket_io_time_reset(struct btree_trans *trans, unsigned dev,
			      size_t bucket_nr, int rw)
{
	struct bch_fs *c = trans->c;
	struct btree_iter iter;
	struct bkey_i_alloc_v4 *a;
	u64 now;
	int ret = 0;

	if (bch2_trans_relock(trans))
		bch2_trans_begin(trans);

	a = bch2_trans_start_alloc_update_noupdate(trans, &iter, POS(dev, bucket_nr));
	ret = PTR_ERR_OR_ZERO(a);
	if (ret)
		return ret;

	now = atomic64_read(&c->io_clock[rw].now);
	if (a->v.io_time[rw] == now)
		goto out;

	a->v.io_time[rw] = now;

	ret   = bch2_trans_update(trans, &iter, &a->k_i, 0) ?:
		bch2_trans_commit(trans, NULL, NULL, 0);
out:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

/* Startup/shutdown (ro/rw): */

void bch2_recalc_capacity(struct bch_fs *c)
{
	u64 capacity = 0, reserved_sectors = 0, gc_reserve;
	unsigned bucket_size_max = 0;
	unsigned long ra_pages = 0;

	lockdep_assert_held(&c->state_lock);

	for_each_online_member(c, ca) {
		struct backing_dev_info *bdi = ca->disk_sb.bdev->bd_disk->bdi;

		ra_pages += bdi->ra_pages;
	}

	bch2_set_ra_pages(c, ra_pages);

	for_each_rw_member(c, ca) {
		u64 dev_reserve = 0;

		/*
		 * We need to reserve buckets (from the number
		 * of currently available buckets) against
		 * foreground writes so that mainly copygc can
		 * make forward progress.
		 *
		 * We need enough to refill the various reserves
		 * from scratch - copygc will use its entire
		 * reserve all at once, then run against when
		 * its reserve is refilled (from the formerly
		 * available buckets).
		 *
		 * This reserve is just used when considering if
		 * allocations for foreground writes must wait -
		 * not -ENOSPC calculations.
		 */

		dev_reserve += ca->nr_btree_reserve * 2;
		dev_reserve += ca->mi.nbuckets >> 6; /* copygc reserve */

		dev_reserve += 1;	/* btree write point */
		dev_reserve += 1;	/* copygc write point */
		dev_reserve += 1;	/* rebalance write point */

		dev_reserve *= ca->mi.bucket_size;

		capacity += bucket_to_sector(ca, ca->mi.nbuckets -
					     ca->mi.first_bucket);

		reserved_sectors += dev_reserve * 2;

		bucket_size_max = max_t(unsigned, bucket_size_max,
					ca->mi.bucket_size);
	}

	gc_reserve = c->opts.gc_reserve_bytes
		? c->opts.gc_reserve_bytes >> 9
		: div64_u64(capacity * c->opts.gc_reserve_percent, 100);

	reserved_sectors = max(gc_reserve, reserved_sectors);

	reserved_sectors = min(reserved_sectors, capacity);

	c->capacity = capacity - reserved_sectors;

	c->bucket_size_max = bucket_size_max;

	/* Wake up case someone was waiting for buckets */
	closure_wake_up(&c->freelist_wait);
}

u64 bch2_min_rw_member_capacity(struct bch_fs *c)
{
	u64 ret = U64_MAX;

	for_each_rw_member(c, ca)
		ret = min(ret, ca->mi.nbuckets * ca->mi.bucket_size);
	return ret;
}

static bool bch2_dev_has_open_write_point(struct bch_fs *c, struct bch_dev *ca)
{
	struct open_bucket *ob;
	bool ret = false;

	for (ob = c->open_buckets;
	     ob < c->open_buckets + ARRAY_SIZE(c->open_buckets);
	     ob++) {
		spin_lock(&ob->lock);
		if (ob->valid && !ob->on_partial_list &&
		    ob->dev == ca->dev_idx)
			ret = true;
		spin_unlock(&ob->lock);
	}

	return ret;
}

/* device goes ro: */
void bch2_dev_allocator_remove(struct bch_fs *c, struct bch_dev *ca)
{
	unsigned i;

	/* First, remove device from allocation groups: */

	for (i = 0; i < ARRAY_SIZE(c->rw_devs); i++)
		clear_bit(ca->dev_idx, c->rw_devs[i].d);

	/*
	 * Capacity is calculated based off of devices in allocation groups:
	 */
	bch2_recalc_capacity(c);

	bch2_open_buckets_stop(c, ca, false);

	/*
	 * Wake up threads that were blocked on allocation, so they can notice
	 * the device can no longer be removed and the capacity has changed:
	 */
	closure_wake_up(&c->freelist_wait);

	/*
	 * journal_res_get() can block waiting for free space in the journal -
	 * it needs to notice there may not be devices to allocate from anymore:
	 */
	wake_up(&c->journal.wait);

	/* Now wait for any in flight writes: */

	closure_wait_event(&c->open_buckets_wait,
			   !bch2_dev_has_open_write_point(c, ca));
}

/* device goes rw: */
void bch2_dev_allocator_add(struct bch_fs *c, struct bch_dev *ca)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(c->rw_devs); i++)
		if (ca->mi.data_allowed & (1 << i))
			set_bit(ca->dev_idx, c->rw_devs[i].d);
}

void bch2_fs_allocator_background_exit(struct bch_fs *c)
{
	darray_exit(&c->discard_buckets_in_flight);
}

void bch2_fs_allocator_background_init(struct bch_fs *c)
{
	spin_lock_init(&c->freelist_lock);
	mutex_init(&c->discard_buckets_in_flight_lock);
	INIT_WORK(&c->discard_work, bch2_do_discards_work);
	INIT_WORK(&c->discard_fast_work, bch2_do_discards_fast_work);
	INIT_WORK(&c->invalidate_work, bch2_do_invalidates_work);
}
