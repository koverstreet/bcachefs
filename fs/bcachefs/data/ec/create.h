/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_DATA_EC_CREATE_H
#define _BCACHEFS_DATA_EC_CREATE_H

#include "io.h"
#include "util/darray.h"

struct ec_dev_stripe_state {
	struct list_head	list;
	struct mutex		lock;

	unsigned		disk_label;

	struct dev_stripe_state	block_stripe;
	struct dev_stripe_state	parity_stripe;
};

enum ec_stripe_ref {
	STRIPE_REF_io,
	STRIPE_REF_stripe,
	STRIPE_REF_NR
};

struct ec_stripe_new_bucket {
	struct hlist_node	hash;
	u64			dev_bucket;
};

struct ec_stripe_handle {
	struct hlist_node	hash;
	u64			idx;
};

struct ec_stripe_new {
	struct bch_fs		*c;
	struct moving_context	*ctxt;
	struct mutex		lock;
	struct list_head	list;
	struct work_struct	work;

	atomic_t		ref[STRIPE_REF_NR];

	u64			seq;

	int			err;

	struct bch_devs_mask	devs;
	enum bch_watermark	watermark;

	bool			have_old_stripe:1;

	bool			allocated:1;
	bool			mem_allocated:1;
	bool			old_mem_allocated:1;
	bool			pending:1;

	unsigned long		blocks_gotten[BITS_TO_LONGS(BCH_BKEY_PTRS_MAX)];
	unsigned long		blocks_allocated[BITS_TO_LONGS(BCH_BKEY_PTRS_MAX)];
	unsigned long		blocks_moving[BITS_TO_LONGS(BCH_BKEY_PTRS_MAX)];
	open_bucket_idx_t	blocks[BCH_BKEY_PTRS_MAX];
	struct disk_reservation	res;

	struct ec_stripe_new_bucket buckets[BCH_BKEY_PTRS_MAX];

	struct ec_stripe_buf	new_stripe;
	struct ec_stripe_buf	old_stripe;

	struct ec_stripe_handle	new_stripe_handle;
	struct ec_stripe_handle	old_stripe_handle;

	u8			old_block_map[BCH_BKEY_PTRS_MAX];
	u8			old_blocks_nr;
};

/*
 * Geometry lives entirely in the on-disk bkey; ec_stripe_new derives
 * the nr_data/nr_parity split from it.
 */
static inline unsigned ec_stripe_new_nr_data(const struct ec_stripe_new *s)
{
	return s->new_stripe.key.v.nr_blocks - s->new_stripe.key.v.nr_redundant;
}

static inline unsigned ec_stripe_new_nr_parity(const struct ec_stripe_new *s)
{
	return s->new_stripe.key.v.nr_redundant;
}

/*
 * Stripe block layout: data slots at [0, nr_data), parity slots at
 * [nr_data, nr_data + nr_parity). These macros name the ranges for
 * readers; pass nr_data/nr_parity directly so they work for both
 * struct ec_stripe_new (via accessors) and struct bch_stripe
 * (nr_blocks - nr_redundant, nr_redundant).
 */
#define for_each_data_block(_i, _nr_data)				\
	for (unsigned _i = 0; _i < (_nr_data); _i++)

#define for_each_parity_block(_i, _nr_data, _nr_parity)			\
	for (unsigned _i = (_nr_data); _i < (_nr_data) + (_nr_parity); _i++)

#define for_each_data_parity_block(_i, _nr_data, _nr_parity)		\
	for (unsigned _i = 0; _i < (_nr_data) + (_nr_parity); _i++)

struct ec_stripe_head {
	struct list_head	list;
	struct mutex		lock;

	unsigned		disk_label;
	unsigned		algo;
	unsigned		redundancy;
	enum bch_watermark	watermark;
	bool			insufficient_devs;

	unsigned long		rw_devs_change_count;

	u64			nr_created;

	struct bch_devs_mask	devs;
	unsigned		nr_active_devs;

	unsigned		blocksize;

	struct ec_dev_stripe_state *dev_stripe;

	struct ec_stripe_new	*s;
};

void *bch2_writepoint_ec_buf(struct bch_fs *, struct write_point *);

unsigned bch2_disk_label_ec_devs(struct bch_fs *, unsigned, struct bch_devs_mask *, unsigned);
void bch2_disk_label_ec_rw_member_devs(struct bch_fs *, unsigned,
				       struct bch_devs_mask *, unsigned);

/*
 * Lazy per-(disk_label, sectors) cache of RW member counts (the can_widen
 * target); shared by callers that walk stripes and need the widening target
 * many times (scan, check). Kept eytzinger-sorted between inserts.
 */
struct widen_cache_entry {
	u8	disk_label;
	u16	sectors;
	u16	nr_devs;
};

DEFINE_DARRAY_NAMED(widen_cache, struct widen_cache_entry);

int bch2_widen_cache_init(widen_cache *);
int bch2_widen_cache_lookup(widen_cache *, struct bch_fs *,
			    u8 disk_label, u16 sectors, unsigned *nr_devs);

void bch2_ec_stripe_new_cancel(struct bch_fs *, struct ec_stripe_head *, int);
void bch2_ec_bucket_cancel(struct bch_fs *, struct open_bucket *, int);

int bch2_ec_stripe_new_alloc(struct bch_fs *, struct ec_stripe_head *);

void bch2_ec_stripe_head_put(struct bch_fs *, struct ec_stripe_head *);

struct alloc_request;
struct ec_stripe_head *bch2_ec_stripe_head_get(struct btree_trans *,
			struct alloc_request *, unsigned);

void bch2_do_stripe_deletes(struct bch_fs *);
void bch2_ec_stripe_create_start(struct bch_fs *, struct ec_stripe_new *);
void bch2_ec_stripe_new_free(struct bch_fs *, struct ec_stripe_new *);

static inline void ec_stripe_new_get(struct ec_stripe_new *s,
				     enum ec_stripe_ref ref)
{
	atomic_inc(&s->ref[ref]);
}

static inline void ec_stripe_new_put(struct bch_fs *c, struct ec_stripe_new *s,
				     enum ec_stripe_ref ref)
{
	BUG_ON(atomic_read(&s->ref[ref]) <= 0);

	if (atomic_dec_and_test(&s->ref[ref]))
		switch (ref) {
		case STRIPE_REF_stripe:
			bch2_ec_stripe_new_free(c, s);
			break;
		case STRIPE_REF_io:
			/*
			 * seq is the commit-ready marker: assigned when all
			 * accumulating writes have finished (refs drained).
			 * bch2_fs_ec_flush_outstanding() waits on this.
			 */
			s->seq = atomic64_inc_return(&c->ec.stripe_new_seq);
			wake_up(&c->ec.stripe_new_wait);
			bch2_ec_stripe_create_start(c, s);
			break;
		default:
			BUG();
		}
}

void bch2_ec_stripe_delete_work(struct work_struct *);

void bch2_new_stripes_to_text(struct printbuf *, struct bch_fs *);

struct moving_context;
int bch2_stripe_repair(struct moving_context *, struct btree_iter *, struct bkey_s_c_stripe);

void bch2_logged_op_stripe_update_to_text(struct printbuf *, struct bch_fs *, struct bkey_s_c);

#define bch2_bkey_ops_logged_op_stripe_update ((struct bkey_ops) {	\
	.val_to_text	= bch2_logged_op_stripe_update_to_text,		\
	.min_val_size	= 40,						\
})

int bch2_resume_logged_op_stripe_update(struct btree_trans *, struct bkey_i *);

#endif /* _BCACHEFS_DATA_EC_CREATE_H */
