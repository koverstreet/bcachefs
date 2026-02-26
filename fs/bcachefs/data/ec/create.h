/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_DATA_EC_CREATE_H
#define _BCACHEFS_DATA_EC_CREATE_H

#include "io.h"

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

	atomic_t		ref[STRIPE_REF_NR];

	int			err;

	struct bch_devs_mask	devs;
	enum bch_watermark	watermark;
	u8			nr_data;
	u8			nr_parity;
	bool			allocated;
	bool			pending;
	bool			have_old_stripe;

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

void bch2_ec_stripe_new_cancel(struct bch_fs *, struct ec_stripe_head *, int);
void bch2_ec_bucket_cancel(struct bch_fs *, struct open_bucket *, int);

int bch2_ec_stripe_new_alloc(struct bch_fs *, struct ec_stripe_head *);

void bch2_ec_stripe_head_put(struct bch_fs *, struct ec_stripe_head *);

struct alloc_request;
struct ec_stripe_head *bch2_ec_stripe_head_get(struct btree_trans *,
			struct alloc_request *, unsigned);

void bch2_do_stripe_deletes(struct bch_fs *);
void bch2_ec_do_stripe_creates(struct bch_fs *);
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
			bch2_ec_do_stripe_creates(c);
			break;
		default:
			BUG();
		}
}

void bch2_ec_stripe_delete_work(struct work_struct *);
void bch2_ec_stripe_create_work(struct work_struct *);

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
