/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_REPLICAS_H
#define _BCACHEFS_REPLICAS_H

#include "btree/bkey.h"
#include "alloc/replicas_types.h"
#include "util/eytzinger.h"

void bch2_replicas_entry_sort(struct bch_replicas_entry_v1 *);
void bch2_replicas_entry_to_text(struct printbuf *,
				 struct bch_replicas_entry_v1 *);
int bch2_replicas_entry_validate(struct bch_replicas_entry_v1 *,
				 struct bch_fs *, struct printbuf *);
void bch2_cpu_replicas_to_text(struct printbuf *, struct bch_replicas_cpu *);

void bch2_devlist_to_replicas(struct bch_replicas_entry_v1 *,
			      enum bch_data_type,
			      struct bch_devs_list);

bool bch2_replicas_marked_locked(struct bch_fs *,
			  struct bch_replicas_entry_v1 *);
bool bch2_replicas_marked(struct bch_fs *, struct bch_replicas_entry_v1 *);
int bch2_mark_replicas(struct bch_fs *,
		       struct bch_replicas_entry_v1 *);

void bch2_bkey_to_replicas(struct bch_replicas_entry_v1 *, struct bkey_s_c);

static inline void bch2_replicas_entry_cached(struct bch_replicas_entry_v1 *e,
					      unsigned dev)
{
	e->data_type	= BCH_DATA_cached;
	e->nr_devs	= 1;
	e->nr_required	= 1;
	e->devs[0]	= dev;
}

bool bch2_can_read_fs_with_devs(struct bch_fs *, struct bch_devs_mask,
				unsigned, struct printbuf *);
bool bch2_have_enough_devs(struct bch_fs *, struct bch_devs_mask,
			   unsigned, struct printbuf *, bool);

bool bch2_sb_has_journal(struct bch_sb *);
unsigned bch2_sb_dev_has_data(struct bch_sb *, unsigned);
unsigned bch2_dev_has_data(struct bch_fs *, struct bch_dev *);

void bch2_replicas_entry_put_many(struct bch_fs *, struct bch_replicas_entry_v1 *, unsigned);
static inline void bch2_replicas_entry_put(struct bch_fs *c, struct bch_replicas_entry_v1 *r)
{
	bch2_replicas_entry_put_many(c, r, 1);
}

int bch2_replicas_entry_get(struct bch_fs *, struct bch_replicas_entry_v1 *);

void bch2_replicas_entry_kill(struct bch_fs *, struct bch_replicas_entry_v1 *);

int bch2_replicas_gc_reffed(struct bch_fs *);

static inline bool bch2_replicas_entry_has_dev(struct bch_replicas_entry_v1 *r, unsigned dev)
{
	for (unsigned i = 0; i < r->nr_devs; i++)
		if (r->devs[i] == dev)
			return true;
	return false;
}

static inline bool bch2_replicas_entry_eq(struct bch_replicas_entry_v1 *l,
					  struct bch_replicas_entry_v1 *r)
{
	return l->nr_devs == r->nr_devs && !memcmp(l, r, replicas_entry_bytes(l));
}

/* iterate over superblock replicas - used by userspace tools: */

#define replicas_entry_next(_i)						\
	((typeof(_i)) ((void *) (_i) + replicas_entry_bytes(_i)))

#define for_each_replicas_entry(_r, _i)					\
	for (typeof(&(_r)->entries[0]) _i = (_r)->entries;		\
	     (void *) (_i) < vstruct_end(&(_r)->field) && (_i)->data_type;\
	     (_i) = replicas_entry_next(_i))

int bch2_sb_replicas_to_cpu_replicas(struct bch_fs *);

extern const struct bch_sb_field_ops bch_sb_field_ops_replicas;
extern const struct bch_sb_field_ops bch_sb_field_ops_replicas_v0;

void bch2_fs_replicas_exit(struct bch_fs *);

#endif /* _BCACHEFS_REPLICAS_H */
