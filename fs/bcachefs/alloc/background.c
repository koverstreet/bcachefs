// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/accounting.h"
#include "alloc/background.h"
#include "alloc/backpointers.h"
#include "alloc/buckets.h"
#include "alloc/buckets_waiting_for_journal.h"
#include "alloc/check.h"
#include "alloc/discard.h"
#include "alloc/foreground.h"
#include "alloc/lru.h"

#include "btree/bkey_buf.h"
#include "btree/cache.h"
#include "btree/key_cache.h"
#include "btree/update.h"
#include "btree/interior.h"
#include "btree/check.h"
#include "btree/write_buffer.h"

#include "data/ec/init.h"

#include "init/error.h"
#include "init/progress.h"
#include "init/recovery.h"

#include "sb/counters.h"

#include "util/clock.h"
#include "util/enumerated_ref.h"
#include "util/varint.h"

#include <linux/kthread.h>
#include <linux/math64.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/sort.h>
#include <linux/jiffies.h>

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

int bch2_alloc_v1_validate(struct bch_fs *c, struct bkey_s_c k,
			   struct bkey_validate_context from)
{
	struct bkey_s_c_alloc a = bkey_s_c_to_alloc(k);
	int ret = 0;

	/* allow for unknown fields */
	bkey_fsck_err_on(bkey_val_u64s(a.k) < bch_alloc_v1_val_u64s(a.v),
			 c, alloc_v1_val_size_bad,
			 "incorrect value size (%zu < %u)",
			 bkey_val_u64s(a.k), bch_alloc_v1_val_u64s(a.v));
fsck_err:
	return ret;
}

int bch2_alloc_v2_validate(struct bch_fs *c, struct bkey_s_c k,
			   struct bkey_validate_context from)
{
	struct bkey_alloc_unpacked u;
	int ret = 0;

	bkey_fsck_err_on(bch2_alloc_unpack_v2(&u, k),
			 c, alloc_v2_unpack_error,
			 "unpack error");
fsck_err:
	return ret;
}

int bch2_alloc_v3_validate(struct bch_fs *c, struct bkey_s_c k,
			   struct bkey_validate_context from)
{
	struct bkey_alloc_unpacked u;
	int ret = 0;

	bkey_fsck_err_on(bch2_alloc_unpack_v3(&u, k),
			 c, alloc_v3_unpack_error,
			 "unpack error");
fsck_err:
	return ret;
}

int bch2_alloc_v4_validate(struct bch_fs *c, struct bkey_s_c k,
			   struct bkey_validate_context from)
{
	struct bch_alloc_v4 a;
	int ret = 0;

	bkey_val_copy_pad(&a, bkey_s_c_to_alloc_v4(k));

	bkey_fsck_err_on(alloc_v4_u64s_noerror(&a) > bkey_val_u64s(k.k),
			 c, alloc_v4_val_size_bad,
			 "bad val size (%u > %zu)",
			 alloc_v4_u64s_noerror(&a), bkey_val_u64s(k.k));

	bkey_fsck_err_on(!BCH_ALLOC_V4_BACKPOINTERS_START(&a) &&
			 BCH_ALLOC_V4_NR_BACKPOINTERS(&a),
			 c, alloc_v4_backpointers_start_bad,
			 "invalid backpointers_start");

	bkey_fsck_err_on(alloc_data_type(a, a.data_type) != a.data_type,
			 c, alloc_key_data_type_bad,
			 "invalid data type (got %u should be %u)",
			 a.data_type, alloc_data_type(a, a.data_type));

	for (unsigned i = 0; i < 2; i++)
		bkey_fsck_err_on(a.io_time[i] > LRU_TIME_MAX,
				 c, alloc_key_io_time_bad,
				 "invalid io_time[%s]: %llu, max %llu",
				 i == READ ? "read" : "write",
				 a.io_time[i], LRU_TIME_MAX);

	unsigned stripe_sectors = BCH_ALLOC_V4_BACKPOINTERS_START(&a) * sizeof(u64) >
		offsetof(struct bch_alloc_v4, stripe_sectors)
		? a.stripe_sectors
		: 0;

	switch (a.data_type) {
	case BCH_DATA_free:
	case BCH_DATA_need_gc_gens:
	case BCH_DATA_need_discard:
		bkey_fsck_err_on(stripe_sectors ||
				 a.dirty_sectors ||
				 a.cached_sectors ||
				 a.stripe_refcount,
				 c, alloc_key_empty_but_have_data,
				 "empty data type free but have data %u.%u.%u %u",
				 stripe_sectors,
				 a.dirty_sectors,
				 a.cached_sectors,
				 a.stripe_refcount);
		break;
	case BCH_DATA_sb:
	case BCH_DATA_journal:
	case BCH_DATA_btree:
	case BCH_DATA_user:
	case BCH_DATA_parity:
		bkey_fsck_err_on(!a.dirty_sectors &&
				 !stripe_sectors,
				 c, alloc_key_dirty_sectors_0,
				 "data_type %s but dirty_sectors==0",
				 bch2_data_type_str(a.data_type));
		break;
	case BCH_DATA_cached:
		bkey_fsck_err_on(!a.cached_sectors ||
				 a.dirty_sectors ||
				 stripe_sectors ||
				 a.stripe_refcount,
				 c, alloc_key_cached_inconsistency,
				 "data type inconsistency");
		break;
	case BCH_DATA_stripe:
		break;
	}
fsck_err:
	return ret;
}

void bch2_alloc_v4_swab(const struct bch_fs *c, struct bkey_s k)
{
	struct bch_alloc_v4 *a = bkey_s_to_alloc_v4(k).v;

	a->journal_seq_nonempty	= swab64(a->journal_seq_nonempty);
	a->journal_seq_empty	= swab64(a->journal_seq_empty);
	a->flags		= swab32(a->flags);
	a->dirty_sectors	= swab32(a->dirty_sectors);
	a->cached_sectors	= swab32(a->cached_sectors);
	a->io_time[0]		= swab64(a->io_time[0]);
	a->io_time[1]		= swab64(a->io_time[1]);
	a->stripe_refcount	= swab32(a->stripe_refcount);
	a->nr_external_backpointers = swab32(a->nr_external_backpointers);
	a->stripe_sectors	= swab32(a->stripe_sectors);
}

static inline void __bch2_alloc_v4_to_text(struct printbuf *out, struct bch_fs *c,
					   struct bkey_s_c k,
					   const struct bch_alloc_v4 *a)
{
	struct bch_dev *ca = c ? bch2_dev_tryget_noerror(c, k.k->p.inode) : NULL;

	prt_newline(out);

	prt_printf(out, "gen %u oldest_gen %u data_type ", a->gen, a->oldest_gen);
	bch2_prt_data_type(out, a->data_type);
	prt_newline(out);
	prt_printf(out, "journal_seq_nonempty %llu\n",	a->journal_seq_nonempty);
	if (bkey_val_bytes(k.k) > offsetof(struct bch_alloc_v4, journal_seq_empty))
		prt_printf(out, "journal_seq_empty    %llu\n",	a->journal_seq_empty);

	prt_printf(out, "need_discard         %llu\n",	BCH_ALLOC_V4_NEED_DISCARD(a));
	prt_printf(out, "need_inc_gen         %llu\n",	BCH_ALLOC_V4_NEED_INC_GEN(a));
	prt_printf(out, "dirty_sectors        %u\n",	a->dirty_sectors);
	if (bkey_val_bytes(k.k) > offsetof(struct bch_alloc_v4, stripe_sectors))
		prt_printf(out, "stripe_sectors       %u\n",	a->stripe_sectors);
	prt_printf(out, "cached_sectors       %u\n",	a->cached_sectors);
	prt_printf(out, "stripe_refcount      %u\n",	a->stripe_refcount);
	prt_printf(out, "io_time[READ]        %llu\n",	a->io_time[READ]);
	prt_printf(out, "io_time[WRITE]       %llu\n",	a->io_time[WRITE]);

	if (ca)
		prt_printf(out, "fragmentation     %llu\n",	alloc_lru_idx_fragmentation(*a, ca));
	prt_printf(out, "bp_start          %llu\n", BCH_ALLOC_V4_BACKPOINTERS_START(a));

	bch2_dev_put(ca);
}

void bch2_alloc_to_text(struct printbuf *out, struct bch_fs *c, struct bkey_s_c k)
{
	struct bch_alloc_v4 _a;
	const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k, &_a);

	__bch2_alloc_v4_to_text(out, c, k, a);
}

void bch2_alloc_v4_to_text(struct printbuf *out, struct bch_fs *c, struct bkey_s_c k)
{
	__bch2_alloc_v4_to_text(out, c, k, bkey_s_c_to_alloc_v4(k).v);
}

void __bch2_alloc_to_v4(struct bkey_s_c k, struct bch_alloc_v4 *out)
{
	if (k.k->type == KEY_TYPE_alloc_v4) {
		void *src, *dst;

		bkey_val_copy_pad(out, bkey_s_c_to_alloc_v4(k));

		src = alloc_v4_backpointers(out);
		SET_BCH_ALLOC_V4_BACKPOINTERS_START(out, BCH_ALLOC_V4_U64s);
		dst = alloc_v4_backpointers(out);

		if (src < dst)
			memset(src, 0, dst - src);

		SET_BCH_ALLOC_V4_NR_BACKPOINTERS(out, 0);
	} else {
		struct bkey_alloc_unpacked u = bch2_alloc_unpack(k);

		*out = (struct bch_alloc_v4) {
			.journal_seq_nonempty	= u.journal_seq,
			.flags			= u.need_discard,
			.gen			= u.gen,
			.oldest_gen		= u.oldest_gen,
			.data_type		= u.data_type,
			.dirty_sectors		= u.dirty_sectors,
			.cached_sectors		= u.cached_sectors,
			.io_time[READ]		= u.read_time,
			.io_time[WRITE]		= u.write_time,
			.stripe_refcount	= u.stripe != 0,
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
	bch2_trans_iter_init(trans, iter, BTREE_ID_alloc, pos,
			     BTREE_ITER_cached|
			     BTREE_ITER_intent);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(iter);
	int ret = bkey_err(k);
	if (unlikely(ret))
		return ERR_PTR(ret);

	return bch2_alloc_to_v4_mut_inlined(trans, k);
}

__flatten
struct bkey_i_alloc_v4 *bch2_trans_start_alloc_update(struct btree_trans *trans, struct bpos pos,
						      enum btree_iter_update_trigger_flags flags)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_alloc, pos,
				BTREE_ITER_cached|
				BTREE_ITER_intent);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(&iter);
	int ret = bkey_err(k);
	if (unlikely(ret))
		return ERR_PTR(ret);

	if ((void *) k.v >= trans->mem &&
	    (void *) k.v <  trans->mem + trans->mem_top)
		return container_of(bkey_s_c_to_alloc_v4(k).v, struct bkey_i_alloc_v4, v);

	struct bkey_i_alloc_v4 *a = bch2_alloc_to_v4_mut_inlined(trans, k);
	if (IS_ERR(a))
		return a;

	ret = bch2_trans_update_ip(trans, &iter, &a->k_i, flags, _RET_IP_);
	return unlikely(ret) ? ERR_PTR(ret) : a;
}

int bch2_bucket_gens_validate(struct bch_fs *c, struct bkey_s_c k,
			      struct bkey_validate_context from)
{
	int ret = 0;

	bkey_fsck_err_on(bkey_val_bytes(k.k) != sizeof(struct bch_bucket_gens),
			 c, bucket_gens_val_size_bad,
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

static int bucket_gens_init_iter(struct btree_trans *trans, struct bkey_s_c k,
				 struct bkey_i_bucket_gens *g,
				 bool *have_bucket_gens_key)
{
	/*
	 * Not a fsck error because this is checked/repaired by
	 * bch2_check_alloc_key() which runs later:
	 */
	if (!bch2_dev_bucket_exists(trans->c, k.k->p))
		return 0;

	unsigned offset;
	struct bpos pos = alloc_gens_pos(k.k->p, &offset);

	if (*have_bucket_gens_key && !bkey_eq(g->k.p, pos)) {
		try(bch2_btree_insert_trans(trans, BTREE_ID_bucket_gens, &g->k_i, 0));
		try(bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc));

		*have_bucket_gens_key = false;
	}

	if (!*have_bucket_gens_key) {
		bkey_bucket_gens_init(&g->k_i);
		g->k.p = pos;
		*have_bucket_gens_key = true;
	}

	struct bch_alloc_v4 a;
	g->v.gens[offset] = bch2_alloc_to_v4(k, &a)->gen;
	return 0;
}

int bch2_bucket_gens_init(struct bch_fs *c)
{
	struct bkey_i_bucket_gens g;
	bool have_bucket_gens_key = false;

	CLASS(btree_trans, trans)(c);
	try(for_each_btree_key(trans, iter, BTREE_ID_alloc, POS_MIN,
				 BTREE_ITER_prefetch, k, ({
		bucket_gens_init_iter(trans, k, &g, &have_bucket_gens_key);
	})));

	if (have_bucket_gens_key)
		try(commit_do(trans, NULL, NULL,
				BCH_TRANS_COMMIT_no_enospc,
			bch2_btree_insert_trans(trans, BTREE_ID_bucket_gens, &g.k_i, 0)));

	return 0;
}

int bch2_alloc_read(struct bch_fs *c)
{
	guard(rwsem_read)(&c->state_lock);

	CLASS(btree_trans, trans)(c);
	struct bch_dev *ca = NULL;
	int ret;

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

			if (k.k->p.offset < ca->mi.first_bucket) {
				bch2_btree_iter_set_pos(&iter, POS(k.k->p.inode, ca->mi.first_bucket));
				continue;
			}

			if (k.k->p.offset >= ca->mi.nbuckets) {
				bch2_btree_iter_set_pos(&iter, POS(k.k->p.inode + 1, 0));
				continue;
			}

			struct bch_alloc_v4 a;
			*bucket_gen(ca, k.k->p.offset) = bch2_alloc_to_v4(k, &a)->gen;
			0;
		}));
	}

	bch2_dev_put(ca);
	return ret;
}

/* Free space/discard btree: */

int bch2_bucket_do_index(struct btree_trans *trans,
			 struct bch_dev *ca,
			 struct bkey_s_c alloc_k,
			 const struct bch_alloc_v4 *a,
			 bool set)
{
	enum btree_id btree;
	struct bpos pos;
	int ret = 0;

	if (a->data_type != BCH_DATA_free &&
	    a->data_type != BCH_DATA_need_discard)
		return 0;

	switch (a->data_type) {
	case BCH_DATA_free:
		btree = BTREE_ID_freespace;
		pos = alloc_freespace_pos(alloc_k.k->p, *a);
		break;
	case BCH_DATA_need_discard:
		btree = BTREE_ID_need_discard;
		pos = alloc_k.k->p;
		break;
	default:
		return 0;
	}

	CLASS(btree_iter, iter)(trans, btree, pos, BTREE_ITER_intent);
	struct bkey_s_c old = bkey_try(bch2_btree_iter_peek_slot(&iter));

	need_discard_or_freespace_err_on(ca->mi.freespace_initialized &&
					 !old.k->type != set,
					 trans, alloc_k, set,
					 btree == BTREE_ID_need_discard, false);

	return bch2_btree_bit_mod_iter(trans, &iter, set);
fsck_err:
	return ret;
}

static noinline int bch2_bucket_gen_update(struct btree_trans *trans,
					   struct bpos bucket, u8 gen)
{
	struct bkey_i_bucket_gens *g = errptr_try(bch2_trans_kmalloc(trans, sizeof(*g)));

	unsigned offset;
	struct bpos pos = alloc_gens_pos(bucket, &offset);

	CLASS(btree_iter, iter)(trans, BTREE_ID_bucket_gens, pos, BTREE_ITER_intent);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	if (k.k->type != KEY_TYPE_bucket_gens) {
		bkey_bucket_gens_init(&g->k_i);
		g->k.p = iter.pos;
	} else {
		bkey_reassemble(&g->k_i, k);
	}

	g->v.gens[offset] = gen;

	return bch2_trans_update(trans, &iter, &g->k_i, 0);
}

static inline int bch2_dev_data_type_accounting_mod(struct btree_trans *trans, struct bch_dev *ca,
						    enum bch_data_type data_type,
						    s64 delta_buckets,
						    s64 delta_sectors,
						    s64 delta_fragmented, unsigned flags)
{
	s64 d[3] = { delta_buckets, delta_sectors, delta_fragmented };

	return bch2_disk_accounting_mod2(trans, flags & BTREE_TRIGGER_gc,
					 d, dev_data_type,
					 .dev		= ca->dev_idx,
					 .data_type	= data_type);
}

int bch2_alloc_key_to_dev_counters(struct btree_trans *trans, struct bch_dev *ca,
				   const struct bch_alloc_v4 *old,
				   const struct bch_alloc_v4 *new,
				   unsigned flags)
{
	s64 old_sectors = bch2_bucket_sectors(*old);
	s64 new_sectors = bch2_bucket_sectors(*new);
	if (old->data_type != new->data_type) {
		try(bch2_dev_data_type_accounting_mod(trans, ca, new->data_type,
				 1,  new_sectors,  bch2_bucket_sectors_fragmented(ca, *new), flags));
		try(bch2_dev_data_type_accounting_mod(trans, ca, old->data_type,
				-1, -old_sectors, -bch2_bucket_sectors_fragmented(ca, *old), flags));
	} else if (old_sectors != new_sectors) {
		try(bch2_dev_data_type_accounting_mod(trans, ca, new->data_type,
					 0,
					 new_sectors - old_sectors,
					 bch2_bucket_sectors_fragmented(ca, *new) -
					 bch2_bucket_sectors_fragmented(ca, *old), flags));
	}

	s64 old_unstriped = bch2_bucket_sectors_unstriped(*old);
	s64 new_unstriped = bch2_bucket_sectors_unstriped(*new);
	if (old_unstriped != new_unstriped) {
		try(bch2_dev_data_type_accounting_mod(trans, ca, BCH_DATA_unstriped,
					 !!new_unstriped - !!old_unstriped,
					 new_unstriped - old_unstriped,
					 0,
					 flags));
	}

	return 0;
}

static noinline int inval_bucket_key(struct btree_trans *trans, struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();
	bch2_fs_inconsistent(c, "reference to invalid bucket\n%s",
			     (bch2_bkey_val_to_text(&buf, c, k), buf.buf));
	return bch_err_throw(c, trigger_alloc);
}

int bch2_trigger_alloc(struct btree_trans *trans,
		       enum btree_id btree, unsigned level,
		       struct bkey_s_c old, struct bkey_s new,
		       enum btree_iter_update_trigger_flags flags)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	CLASS(bch2_dev_bucket_tryget, ca)(c, new.k->p);
	if (!ca)
		return bch_err_throw(c, trigger_alloc);

	struct bch_alloc_v4 old_a_convert;
	const struct bch_alloc_v4 *old_a = bch2_alloc_to_v4(old, &old_a_convert);

	struct bch_alloc_v4 *new_a;
	if (likely(new.k->type == KEY_TYPE_alloc_v4)) {
		new_a = bkey_s_to_alloc_v4(new).v;
	} else {
		BUG_ON(!(flags & (BTREE_TRIGGER_gc|BTREE_TRIGGER_check_repair)));

		struct bkey_i_alloc_v4 *new_ka =
			errptr_try(bch2_alloc_to_v4_mut_inlined(trans, new.s_c));
		new_a = &new_ka->v;
	}

	if (flags & BTREE_TRIGGER_transactional) {
		alloc_data_type_set(new_a, new_a->data_type);

		int is_empty_delta = (int) data_type_is_empty(new_a->data_type) -
				     (int) data_type_is_empty(old_a->data_type);

		if (is_empty_delta < 0 &&
		    (new_a->data_type != BCH_DATA_sb &&
		     new_a->data_type != BCH_DATA_journal) &&
		    !bch2_bucket_is_open_safe(c, new.k->p.inode, new.k->p.offset) &&
		    !bch2_bucket_nouse(ca, new.k->p.offset)) {
			CLASS(printbuf, buf)();
			log_fsck_err_on(true, trans,
				alloc_key_bucket_nonempty_to_empty_not_open,
				"bucket %llu:%llu going empty but not open\n%s",
				new.k->p.inode, new.k->p.offset,
				(bch2_bkey_val_to_text(&buf, c, new.s_c), buf.buf));
		}

		if (is_empty_delta < 0) {
			new_a->io_time[READ] = bch2_current_io_time(c, READ);
			new_a->io_time[WRITE]= bch2_current_io_time(c, WRITE);
			SET_BCH_ALLOC_V4_NEED_INC_GEN(new_a, true);
			SET_BCH_ALLOC_V4_NEED_DISCARD(new_a, true);
		}

		if (data_type_is_empty(new_a->data_type) &&
		    BCH_ALLOC_V4_NEED_INC_GEN(new_a) &&
		    !bch2_bucket_is_open_safe(c, new.k->p.inode, new.k->p.offset)) {
			if (new_a->oldest_gen == new_a->gen &&
			    !bch2_bucket_sectors_total(*new_a))
				new_a->oldest_gen++;
			new_a->gen++;
			SET_BCH_ALLOC_V4_NEED_INC_GEN(new_a, false);
			alloc_data_type_set(new_a, new_a->data_type);
		}

		if (old_a->data_type != new_a->data_type ||
		    (new_a->data_type == BCH_DATA_free &&
		     alloc_freespace_genbits(*old_a) != alloc_freespace_genbits(*new_a))) {
			try(bch2_bucket_do_index(trans, ca, old, old_a, false));
			try(bch2_bucket_do_index(trans, ca, new.s_c, new_a, true));
		}

		if (new_a->data_type == BCH_DATA_cached &&
		    !new_a->io_time[READ])
			new_a->io_time[READ] = bch2_current_io_time(c, READ);

		try(bch2_lru_change(trans, new.k->p.inode,
				    bucket_to_u64(new.k->p),
				    alloc_lru_idx_read(*old_a),
				    alloc_lru_idx_read(*new_a)));

		try(bch2_lru_change(trans,
				    BCH_LRU_BUCKET_FRAGMENTATION,
				    bucket_to_u64(new.k->p),
				    alloc_lru_idx_fragmentation(*old_a, ca),
				    alloc_lru_idx_fragmentation(*new_a, ca)));

		if (old_a->gen != new_a->gen)
			try(bch2_bucket_gen_update(trans, new.k->p, new_a->gen));

		try(bch2_alloc_key_to_dev_counters(trans, ca, old_a, new_a, flags));
	}

	if ((flags & BTREE_TRIGGER_atomic) && (flags & BTREE_TRIGGER_insert)) {
		u64 transaction_seq = trans->journal_res.seq;
		BUG_ON(!transaction_seq);

		CLASS(printbuf, buf)();
		if (log_fsck_err_on(transaction_seq && new_a->journal_seq_nonempty > transaction_seq,
				    trans, alloc_key_journal_seq_in_future,
				    "bucket journal seq in future (currently at %llu)\n%s",
				    journal_cur_seq(&c->journal),
				    (bch2_bkey_val_to_text(&buf, c, new.s_c), buf.buf)))
			new_a->journal_seq_nonempty = transaction_seq;

		int is_empty_delta = (int) data_type_is_empty(new_a->data_type) -
				     (int) data_type_is_empty(old_a->data_type);

		/*
		 * Record journal sequence number of empty -> nonempty transition:
		 * Note that there may be multiple empty -> nonempty
		 * transitions, data in a bucket may be overwritten while we're
		 * still writing to it - so be careful to only record the first:
		 * */
		if (is_empty_delta < 0 &&
		    new_a->journal_seq_empty <= c->journal.flushed_seq_ondisk) {
			new_a->journal_seq_nonempty	= transaction_seq;
			new_a->journal_seq_empty	= 0;
		}

		/*
		 * Bucket becomes empty: mark it as waiting for a journal flush,
		 * unless updates since empty -> nonempty transition were never
		 * flushed - we may need to ask the journal not to flush
		 * intermediate sequence numbers:
		 */
		if (is_empty_delta > 0) {
			if (new_a->journal_seq_nonempty == transaction_seq ||
			    bch2_journal_noflush_seq(&c->journal,
						     new_a->journal_seq_nonempty,
						     transaction_seq)) {
				new_a->journal_seq_nonempty = new_a->journal_seq_empty = 0;
			} else {
				new_a->journal_seq_empty = transaction_seq;

				ret = bch2_set_bucket_needs_journal_commit(&c->buckets_waiting_for_journal,
									   c->journal.flushed_seq_ondisk,
									   new.k->p.inode, new.k->p.offset,
									   transaction_seq);
				if (bch2_fs_fatal_err_on(ret, c,
						"setting bucket_needs_journal_commit: %s",
						bch2_err_str(ret)))
					return ret;
			}
		}

		if (new_a->gen != old_a->gen) {
			guard(rcu)();
			u8 *gen = bucket_gen(ca, new.k->p.offset);
			if (unlikely(!gen))
				return inval_bucket_key(trans, new.s_c);
			*gen = new_a->gen;
		}

#define eval_state(_a, expr)		({ const struct bch_alloc_v4 *a = _a; expr; })
#define statechange(expr)		!eval_state(old_a, expr) && eval_state(new_a, expr)
#define bucket_flushed(a)		(a->journal_seq_empty <= c->journal.flushed_seq_ondisk)

		if (statechange(a->data_type == BCH_DATA_free) &&
		    bucket_flushed(new_a))
			closure_wake_up(&c->allocator.freelist_wait);

		if (statechange(a->data_type == BCH_DATA_need_discard) &&
		    !bch2_bucket_is_open_safe(c, new.k->p.inode, new.k->p.offset) &&
		    bucket_flushed(new_a))
			bch2_discard_one_bucket_fast(ca, new.k->p.offset);

		if (statechange(a->data_type == BCH_DATA_cached) &&
		    !bch2_bucket_is_open(c, new.k->p.inode, new.k->p.offset) &&
		    should_invalidate_buckets(ca, bch2_dev_usage_read(ca)))
			bch2_dev_do_invalidates(ca);

		if (statechange(a->data_type == BCH_DATA_need_gc_gens))
			bch2_gc_gens_async(c);
	}

	if ((flags & BTREE_TRIGGER_gc) && (flags & BTREE_TRIGGER_insert)) {
		guard(rcu)();
		struct bucket *g = gc_bucket(ca, new.k->p.offset);
		if (unlikely(!g))
			return inval_bucket_key(trans, new.s_c);
		g->gen_valid	= 1;
		g->gen		= new_a->gen;
	}
fsck_err:
	return ret;
}

/* device removal */

int bch2_dev_remove_alloc(struct bch_fs *c, struct bch_dev *ca)
{
	struct bpos start	= POS(ca->dev_idx, 0);
	struct bpos end		= POS(ca->dev_idx, U64_MAX);
	int ret;

	/*
	 * We clear the LRU and need_discard btrees first so that we don't race
	 * with bch2_do_invalidates() and bch2_do_discards()
	 */
	ret =   bch2_dev_remove_lrus(c, ca) ?:
		bch2_btree_delete_range(c, BTREE_ID_need_discard, start, end,
					BTREE_TRIGGER_norun) ?:
		bch2_btree_delete_range(c, BTREE_ID_freespace, start, end,
					BTREE_TRIGGER_norun) ?:
		bch2_btree_delete_range(c, BTREE_ID_backpointers, start, end,
					BTREE_TRIGGER_norun) ?:
		bch2_btree_delete_range(c, BTREE_ID_bucket_gens, start, end,
					BTREE_TRIGGER_norun) ?:
		bch2_btree_delete_range(c, BTREE_ID_alloc, start, end,
					BTREE_TRIGGER_norun) ?:
		bch2_dev_usage_remove(c, ca);
	bch_err_msg_dev(ca, ret, "removing dev alloc info");
	return ret;
}

/* Bucket IO clocks: */

static int __bch2_bucket_io_time_reset(struct btree_trans *trans, unsigned dev,
				size_t bucket_nr, int rw)
{
	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_i_alloc_v4 *a =
		errptr_try(bch2_trans_start_alloc_update_noupdate(trans, &iter, POS(dev, bucket_nr)));

	u64 now = bch2_current_io_time(trans->c, rw);
	if (a->v.io_time[rw] == now)
		return 0;

	a->v.io_time[rw] = now;

	try(bch2_trans_update(trans, &iter, &a->k_i, 0));
	try(bch2_trans_commit(trans, NULL, NULL, 0));
	return 0;
}

int bch2_bucket_io_time_reset(struct btree_trans *trans, unsigned dev,
			      size_t bucket_nr, int rw)
{
	if (bch2_trans_relock(trans))
		bch2_trans_begin(trans);

	return nested_lockrestart_do(trans, __bch2_bucket_io_time_reset(trans, dev, bucket_nr, rw));
}

/* Startup/shutdown (ro/rw): */

void bch2_recalc_capacity(struct bch_fs *c)
{
	u64 capacity = 0, reserved_sectors = 0, gc_reserve;
	unsigned bucket_size_max = 0;
	unsigned long ra_pages = 0;

	lockdep_assert_held(&c->state_lock);

	guard(rcu)();
	for_each_member_device_rcu(c, ca, NULL) {
		struct block_device *bdev = READ_ONCE(ca->disk_sb.bdev);
		if (bdev)
			ra_pages += bdev->bd_disk->bdi->ra_pages;

		if (ca->mi.state != BCH_MEMBER_STATE_rw)
			continue;

		if (!ca->mi.durability)
			continue;

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

	bch2_set_ra_pages(c, ra_pages);

	gc_reserve = c->opts.gc_reserve_bytes
		? c->opts.gc_reserve_bytes >> 9
		: div64_u64(capacity * c->opts.gc_reserve_percent, 100);

	reserved_sectors = max(gc_reserve, reserved_sectors);

	reserved_sectors = min(reserved_sectors, capacity);

	c->capacity.reserved = reserved_sectors;
	c->capacity.capacity = capacity - reserved_sectors;

	c->capacity.bucket_size_max = bucket_size_max;

	/* Wake up case someone was waiting for buckets */
	closure_wake_up(&c->allocator.freelist_wait);
}

u64 bch2_min_rw_member_capacity(struct bch_fs *c)
{
	u64 ret = U64_MAX;

	guard(rcu)();
	for_each_rw_member_rcu(c, ca)
		ret = min(ret, ca->mi.nbuckets * ca->mi.bucket_size);
	return ret;
}

static bool bch2_dev_has_open_write_point(struct bch_fs *c, struct bch_dev *ca)
{
	struct open_bucket *ob;

	for (ob = c->allocator.open_buckets;
	     ob < c->allocator.open_buckets + ARRAY_SIZE(c->allocator.open_buckets);
	     ob++) {
		scoped_guard(spinlock, &ob->lock) {
			if (ob->valid && !ob->on_partial_list &&
			    ob->dev == ca->dev_idx)
				return true;
		}
	}

	return false;
}

void bch2_dev_allocator_set_rw(struct bch_fs *c, struct bch_dev *ca, bool rw)
{
	/* BCH_DATA_free == all rw devs */

	for (unsigned i = 0; i < ARRAY_SIZE(c->allocator.rw_devs); i++) {
		bool data_type_rw = rw;

		if (i != BCH_DATA_free &&
		    !(ca->mi.data_allowed & BIT(i)))
			data_type_rw = false;

		if ((i == BCH_DATA_journal ||
		     i == BCH_DATA_btree) &&
		    !ca->mi.durability)
			data_type_rw = false;

		mod_bit(ca->dev_idx, c->allocator.rw_devs[i].d, data_type_rw);
	}

	c->allocator.rw_devs_change_count++;
}

/* device goes ro: */
void bch2_dev_allocator_remove(struct bch_fs *c, struct bch_dev *ca)
{
	lockdep_assert_held(&c->state_lock);

	/* First, remove device from allocation groups: */
	bch2_dev_allocator_set_rw(c, ca, false);

	/*
	 * Capacity is calculated based off of devices in allocation groups:
	 */
	bch2_recalc_capacity(c);

	bch2_open_buckets_stop(c, ca, false);

	/*
	 * Wake up threads that were blocked on allocation, so they can notice
	 * the device can no longer be removed and the capacity has changed:
	 */
	closure_wake_up(&c->allocator.freelist_wait);

	/*
	 * journal_res_get() can block waiting for free space in the journal -
	 * it needs to notice there may not be devices to allocate from anymore:
	 */
	wake_up(&c->journal.wait);

	/* Now wait for any in flight writes: */

	closure_wait_event(&c->allocator.open_buckets_wait,
			   !bch2_dev_has_open_write_point(c, ca));
}

/* device goes rw: */
void bch2_dev_allocator_add(struct bch_fs *c, struct bch_dev *ca)
{
	lockdep_assert_held(&c->state_lock);

	bch2_dev_allocator_set_rw(c, ca, true);
	c->allocator.rw_devs_change_count++;
}

void bch2_dev_allocator_background_exit(struct bch_dev *ca)
{
	darray_exit(&ca->discard_buckets_in_flight);
}

void bch2_dev_allocator_background_init(struct bch_dev *ca)
{
	mutex_init(&ca->discard_buckets_in_flight_lock);
	INIT_WORK(&ca->discard_work, bch2_do_discards_work);
	INIT_WORK(&ca->discard_fast_work, bch2_do_discards_fast_work);
	INIT_WORK(&ca->invalidate_work, bch2_do_invalidates_work);
}

void bch2_fs_allocator_background_init(struct bch_fs *c)
{
	spin_lock_init(&c->allocator.freelist_lock);
}

void bch2_fs_capacity_exit(struct bch_fs *c)
{
	percpu_free_rwsem(&c->capacity.mark_lock);
	if (c->capacity.pcpu) {
		u64 v = percpu_u64_get(&c->capacity.pcpu->online_reserved);
		WARN(v, "online_reserved not 0 at shutdown: %lli", v);
	}

	free_percpu(c->capacity.pcpu);
	free_percpu(c->capacity.usage);
}

int bch2_fs_capacity_init(struct bch_fs *c)
{
	mutex_init(&c->capacity.sectors_available_lock);
	seqcount_init(&c->capacity.usage_lock);

	try(percpu_init_rwsem(&c->capacity.mark_lock));

	if (!(c->capacity.pcpu = alloc_percpu(struct bch_fs_capacity_pcpu)) ||
	    !(c->capacity.usage = alloc_percpu(struct bch_fs_usage_base)))
		return bch_err_throw(c, ENOMEM_fs_other_alloc);

	return 0;
}
