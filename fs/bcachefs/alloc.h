#ifndef _BCACHEFS_ALLOC_H
#define _BCACHEFS_ALLOC_H

#include "bcachefs.h"
#include "alloc_types.h"

struct bkey;
struct bch_dev;
struct bch_fs;
struct bch_devs_List;

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

enum bucket_alloc_ret {
	ALLOC_SUCCESS		= 0,
	OPEN_BUCKETS_EMPTY	= -1,
	FREELIST_EMPTY		= -2,	/* Allocator thread not keeping up */
	NO_DEVICES		= -3,	/* -EROFS */
};

int bch2_bucket_alloc(struct bch_fs *, struct bch_dev *, enum alloc_reserve, bool,
		      struct closure *);

void __bch2_open_bucket_put(struct bch_fs *, struct open_bucket *);

static inline void bch2_open_bucket_put(struct bch_fs *c, struct open_bucket *ob)
{
	if (atomic_dec_and_test(&ob->pin))
		__bch2_open_bucket_put(c, ob);
}

static inline void bch2_open_bucket_put_refs(struct bch_fs *c, u8 *nr, u8 *refs)
{
	unsigned i;

	for (i = 0; i < *nr; i++)
		bch2_open_bucket_put(c, c->open_buckets + refs[i]);

	*nr = 0;
}

static inline void bch2_open_bucket_get(struct bch_fs *c,
					struct write_point *wp,
					u8 *nr, u8 *refs)
{
	unsigned i;

	for (i = 0; i < wp->nr_ptrs_can_use; i++) {
		struct open_bucket *ob = wp->ptrs[i];

		atomic_inc(&ob->pin);
		refs[(*nr)++] = ob - c->open_buckets;
	}
}

struct write_point *bch2_alloc_sectors_start(struct bch_fs *,
					     struct bch_devs_mask *,
					     struct write_point_specifier,
					     struct bch_devs_list *,
					     unsigned, unsigned,
					     enum alloc_reserve,
					     unsigned,
					     struct closure *);

void bch2_alloc_sectors_append_ptrs(struct bch_fs *, struct write_point *,
				    struct bkey_i_extent *, unsigned);
void bch2_alloc_sectors_done(struct bch_fs *, struct write_point *);

static inline void bch2_wake_allocator(struct bch_dev *ca)
{
	struct task_struct *p;

	rcu_read_lock();
	if ((p = READ_ONCE(ca->alloc_thread)))
		wake_up_process(p);
	rcu_read_unlock();
}

#define writepoint_for_each_ptr(_wp, _ob, _i)				\
	for ((_i) = 0;							\
	     (_i) < (_wp)->nr_ptrs && ((_ob) = (_wp)->ptrs[_i], true);	\
	     (_i)++)

static inline struct write_point_specifier writepoint_hashed(unsigned long v)
{
	return (struct write_point_specifier) { .v = v | 1 };
}

static inline struct write_point_specifier writepoint_ptr(struct write_point *wp)
{
	return (struct write_point_specifier) { .v = (unsigned long) wp };
}

void bch2_recalc_capacity(struct bch_fs *);

void bch2_dev_allocator_remove(struct bch_fs *, struct bch_dev *);
void bch2_dev_allocator_add(struct bch_fs *, struct bch_dev *);

void bch2_dev_allocator_stop(struct bch_dev *);
int bch2_dev_allocator_start(struct bch_dev *);

static inline void writepoint_init(struct write_point *wp,
				   enum bch_data_type type)
{
	mutex_init(&wp->lock);
	wp->type = type;
}

int bch2_alloc_write(struct bch_fs *);
int bch2_fs_allocator_start(struct bch_fs *);
void bch2_fs_allocator_init(struct bch_fs *);

extern const struct bkey_ops bch2_bkey_alloc_ops;

#endif /* _BCACHEFS_ALLOC_H */
