/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_DISK_ACCOUNTING_H
#define _BCACHEFS_DISK_ACCOUNTING_H

#include "eytzinger.h"
#include "sb-members.h"

static inline void bch2_u64s_neg(u64 *v, unsigned nr)
{
	for (unsigned i = 0; i < nr; i++)
		v[i] = -v[i];
}

static inline unsigned bch2_accounting_counters(const struct bkey *k)
{
	return bkey_val_u64s(k) - offsetof(struct bch_accounting, d) / sizeof(u64);
}

static inline void bch2_accounting_neg(struct bkey_s_accounting a)
{
	bch2_u64s_neg(a.v->d, bch2_accounting_counters(a.k));
}

static inline bool bch2_accounting_key_is_zero(struct bkey_s_c_accounting a)
{
	for (unsigned i = 0;  i < bch2_accounting_counters(a.k); i++)
		if (a.v->d[i])
			return false;
	return true;
}

static inline void bch2_accounting_accumulate(struct bkey_i_accounting *dst,
					      struct bkey_s_c_accounting src)
{
	EBUG_ON(dst->k.u64s != src.k->u64s);

	for (unsigned i = 0; i < bch2_accounting_counters(&dst->k); i++)
		dst->v.d[i] += src.v->d[i];
	if (bversion_cmp(dst->k.version, src.k->version) < 0)
		dst->k.version = src.k->version;
}

static inline void fs_usage_data_type_to_base(struct bch_fs_usage_base *fs_usage,
					      enum bch_data_type data_type,
					      s64 sectors)
{
	switch (data_type) {
	case BCH_DATA_btree:
		fs_usage->btree		+= sectors;
		break;
	case BCH_DATA_user:
	case BCH_DATA_parity:
		fs_usage->data		+= sectors;
		break;
	case BCH_DATA_cached:
		fs_usage->cached	+= sectors;
		break;
	default:
		break;
	}
}

static inline void bpos_to_disk_accounting_pos(struct disk_accounting_pos *acc, struct bpos p)
{
	acc->_pad = p;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	bch2_bpos_swab(&acc->_pad);
#endif
}

static inline struct bpos disk_accounting_pos_to_bpos(struct disk_accounting_pos *k)
{
	struct bpos ret = k->_pad;

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	bch2_bpos_swab(&ret);
#endif
	return ret;
}

int bch2_disk_accounting_mod(struct btree_trans *, struct disk_accounting_pos *,
			     s64 *, unsigned, bool);
int bch2_mod_dev_cached_sectors(struct btree_trans *, unsigned, s64, bool);

int bch2_accounting_invalid(struct bch_fs *, struct bkey_s_c,
			    enum bch_validate_flags, struct printbuf *);
void bch2_accounting_key_to_text(struct printbuf *, struct disk_accounting_pos *);
void bch2_accounting_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);
void bch2_accounting_swab(struct bkey_s);

#define bch2_bkey_ops_accounting ((struct bkey_ops) {	\
	.key_invalid	= bch2_accounting_invalid,	\
	.val_to_text	= bch2_accounting_to_text,	\
	.swab		= bch2_accounting_swab,		\
	.min_val_size	= 8,				\
})

int bch2_accounting_update_sb(struct btree_trans *);

static inline int accounting_pos_cmp(const void *_l, const void *_r)
{
	const struct bpos *l = _l, *r = _r;

	return bpos_cmp(*l, *r);
}

int bch2_accounting_mem_mod_slowpath(struct bch_fs *, struct bkey_s_c_accounting, bool);

static inline int __bch2_accounting_mem_mod(struct bch_fs *c, struct bkey_s_c_accounting a, bool gc)
{
	struct bch_accounting_mem *acc = &c->accounting[gc];
	unsigned idx = eytzinger0_find(acc->k.data, acc->k.nr, sizeof(acc->k.data[0]),
				       accounting_pos_cmp, &a.k->p);
	if (unlikely(idx >= acc->k.nr))
		return bch2_accounting_mem_mod_slowpath(c, a, gc);

	unsigned offset = acc->k.data[idx].offset;

	EBUG_ON(bch2_accounting_counters(a.k) != acc->k.data[idx].nr_counters);

	for (unsigned i = 0; i < bch2_accounting_counters(a.k); i++)
		this_cpu_add(acc->v[offset + i], a.v->d[i]);
	return 0;
}

/*
 * Update in memory counters so they match the btree update we're doing; called
 * from transaction commit path
 */
static inline int bch2_accounting_mem_mod_locked(struct btree_trans *trans, struct bkey_s_c_accounting a, bool gc)
{
	struct bch_fs *c = trans->c;

	if (!gc) {
		struct disk_accounting_pos acc_k;
		bpos_to_disk_accounting_pos(&acc_k, a.k->p);

		switch (acc_k.type) {
		case BCH_DISK_ACCOUNTING_persistent_reserved:
			trans->fs_usage_delta.reserved += acc_k.persistent_reserved.nr_replicas * a.v->d[0];
			break;
		case BCH_DISK_ACCOUNTING_replicas:
			fs_usage_data_type_to_base(&trans->fs_usage_delta, acc_k.replicas.data_type, a.v->d[0]);
			break;
		case BCH_DISK_ACCOUNTING_dev_data_type:
			rcu_read_lock();
			struct bch_dev *ca = bch2_dev_rcu(c, acc_k.dev_data_type.dev);
			if (ca) {
				this_cpu_add(ca->usage->d[acc_k.dev_data_type.data_type].buckets, a.v->d[0]);
				this_cpu_add(ca->usage->d[acc_k.dev_data_type.data_type].sectors, a.v->d[1]);
				this_cpu_add(ca->usage->d[acc_k.dev_data_type.data_type].fragmented, a.v->d[2]);
			}
			rcu_read_unlock();
			break;
		}
	}

	return __bch2_accounting_mem_mod(c, a, gc);
}

static inline int bch2_accounting_mem_add(struct btree_trans *trans, struct bkey_s_c_accounting a, bool gc)
{
	percpu_down_read(&trans->c->mark_lock);
	int ret = bch2_accounting_mem_mod_locked(trans, a, gc);
	percpu_up_read(&trans->c->mark_lock);
	return ret;
}

static inline void bch2_accounting_mem_read_counters(struct bch_fs *c, unsigned idx,
						     u64 *v, unsigned nr, bool gc)
{
	memset(v, 0, sizeof(*v) * nr);

	struct bch_accounting_mem *acc = &c->accounting[gc];
	if (unlikely(idx >= acc->k.nr))
		return;

	unsigned offset = acc->k.data[idx].offset;
	nr = min_t(unsigned, nr, acc->k.data[idx].nr_counters);

	for (unsigned i = 0; i < nr; i++)
		v[i] = percpu_u64_get(acc->v + offset + i);
}

static inline void bch2_accounting_mem_read(struct bch_fs *c, struct bpos p,
					    u64 *v, unsigned nr)
{
	struct bch_accounting_mem *acc = &c->accounting[0];
	unsigned idx = eytzinger0_find(acc->k.data, acc->k.nr, sizeof(acc->k.data[0]),
				       accounting_pos_cmp, &p);

	bch2_accounting_mem_read_counters(c, idx, v, nr, false);
}

int bch2_fs_replicas_usage_read(struct bch_fs *, darray_char *);
int bch2_fs_accounting_read(struct bch_fs *, darray_char *, unsigned);
void bch2_fs_accounting_to_text(struct printbuf *, struct bch_fs *);

int bch2_accounting_gc_done(struct bch_fs *);

int bch2_accounting_read(struct bch_fs *);

int bch2_dev_usage_remove(struct bch_fs *, unsigned);
int bch2_dev_usage_init(struct bch_dev *, bool);

void bch2_verify_accounting_clean(struct bch_fs *c);

void bch2_accounting_free(struct bch_accounting_mem *);
void bch2_fs_accounting_exit(struct bch_fs *);

#endif /* _BCACHEFS_DISK_ACCOUNTING_H */
