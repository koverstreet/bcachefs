#ifndef _BCACHEFS_ALLOC_H
#define _BCACHEFS_ALLOC_H

#include "bcachefs.h"
#include "alloc_types.h"

struct bkey;
struct bucket;
struct bch_dev;
struct bch_fs;
struct dev_group;

struct dev_alloc_list {
	unsigned	nr;
	u8		devs[BCH_SB_MEMBERS_MAX];
};

struct dev_alloc_list bch2_wp_alloc_list(struct bch_fs *,
					 struct write_point *,
					 struct bch_devs_mask *);
void bch2_wp_rescale(struct bch_fs *, struct bch_dev *,
		     struct write_point *);

int bch2_alloc_read(struct bch_fs *, struct list_head *);
int bch2_alloc_replay_key(struct bch_fs *, struct bpos);

long bch2_bucket_alloc(struct bch_fs *, struct bch_dev *, enum alloc_reserve);

void bch2_open_bucket_put(struct bch_fs *, struct open_bucket *);

struct write_point *bch2_alloc_sectors_start(struct bch_fs *,
					     enum bch_data_type,
					     struct bch_devs_mask *,
					     unsigned long,
					     unsigned, unsigned,
					     enum alloc_reserve,
					     unsigned,
					     struct closure *);

void bch2_alloc_sectors_append_ptrs(struct bch_fs *, struct bkey_i_extent *,
				   unsigned, struct open_bucket *, unsigned);
void bch2_alloc_sectors_done(struct bch_fs *, struct write_point *);

struct open_bucket *bch2_alloc_sectors(struct bch_fs *,
				       enum bch_data_type,
				       struct bch_devs_mask *,
				       unsigned long,
				       struct bkey_i_extent *,
				       unsigned, unsigned,
				       enum alloc_reserve,
				       unsigned,
				       struct closure *);

static inline void bch2_wake_allocator(struct bch_dev *ca)
{
	struct task_struct *p;

	rcu_read_lock();
	if ((p = READ_ONCE(ca->alloc_thread)))
		wake_up_process(p);
	rcu_read_unlock();
}

#define open_bucket_for_each_ptr(_ob, _ptr)				\
	for ((_ptr) = (_ob)->ptrs;					\
	     (_ptr) < (_ob)->ptrs + (_ob)->nr_ptrs;			\
	     (_ptr)++)

void bch2_recalc_capacity(struct bch_fs *);

void bch2_dev_allocator_remove(struct bch_fs *, struct bch_dev *);
void bch2_dev_allocator_add(struct bch_fs *, struct bch_dev *);

void bch2_dev_allocator_stop(struct bch_dev *);
int bch2_dev_allocator_start(struct bch_dev *);

void bch2_fs_allocator_init(struct bch_fs *);

extern const struct bkey_ops bch2_bkey_alloc_ops;

#endif /* _BCACHEFS_ALLOC_H */
