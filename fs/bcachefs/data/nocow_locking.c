// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree/bkey_methods.h"
#include "closure.h"
#include "nocow_locking.h"

#include "util/util.h"

#include <linux/prefetch.h>

static bool nocow_bucket_empty(struct nocow_lock_bucket *l)
{
	for (unsigned i = 0; i < ARRAY_SIZE(l->b); i++)
		if (atomic_read(&l->l[i]))
			return false;
	return true;
}

bool bch2_bucket_nocow_is_locked(struct bucket_nocow_lock_table *t, struct bpos bucket)
{
	u64 dev_bucket = bucket_to_u64(bucket);
	struct nocow_lock_bucket *l = bucket_nocow_lock(t, dev_bucket);
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(l->b); i++)
		if (l->b[i] == dev_bucket && atomic_read(&l->l[i]))
			return true;
	return false;
}

#define sign(v)		(v < 0 ? -1 : v > 0 ? 1 : 0)

void __bch2_bucket_nocow_unlock(struct bucket_nocow_lock_table *t, u64 dev_bucket, int flags)
{
	struct nocow_lock_bucket *l = bucket_nocow_lock(t, dev_bucket);
	int lock_val = flags ? 1 : -1;

	for (unsigned i = 0; i < ARRAY_SIZE(l->b); i++)
		if (l->b[i] == dev_bucket) {
			int v = atomic_sub_return(lock_val, &l->l[i]);

			BUG_ON(v && sign(v) != lock_val);
			if (!v)
				closure_wake_up(&l->wait);
			return;
		}

	BUG();
}

static int __bch2_bucket_nocow_trylock(struct bch_fs *c, struct nocow_lock_bucket *l,
				u64 dev_bucket, int flags)
{
	int v, lock_val = flags ? 1 : -1;
	unsigned i;

	guard(spinlock)(&l->lock);

	for (i = 0; i < ARRAY_SIZE(l->b); i++)
		if (l->b[i] == dev_bucket)
			goto got_entry;

	for (i = 0; i < ARRAY_SIZE(l->b); i++)
		if (!atomic_read(&l->l[i])) {
			l->b[i] = dev_bucket;
			goto take_lock;
		}

	return bch_err_throw(c, nocow_trylock_bucket_full);
got_entry:
	v = atomic_read(&l->l[i]);
	if (lock_val > 0 ? v < 0 : v > 0)
		return bch_err_throw(c, nocow_trylock_contended);
take_lock:
	v = atomic_read(&l->l[i]);
	/* Overflow? */
	if (v && sign(v + lock_val) != sign(v))
		return bch_err_throw(c, nocow_trylock_contended);

	atomic_add(lock_val, &l->l[i]);
	return 0;
}

static inline bool bch2_bucket_nocow_trylock(struct bch_fs *c, struct bpos bucket, int flags)
{
	struct bucket_nocow_lock_table *t = &c->nocow_locks;
	u64 dev_bucket = bucket_to_u64(bucket);
	struct nocow_lock_bucket *l = bucket_nocow_lock(t, dev_bucket);

	return !__bch2_bucket_nocow_trylock(c, l, dev_bucket, flags);
}

void bch2_bkey_nocow_unlock(struct bch_fs *c, struct bkey_s_c k,
			    unsigned ptrs_held, int flags)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	unsigned ptr_bit = 1;

	bkey_for_each_ptr(ptrs, ptr) {
		if ((ptrs_held & ptr_bit) && ptr->dev != BCH_SB_MEMBER_INVALID) {
			struct bch_dev *ca = bch2_dev_have_ref(c, ptr->dev);
			struct bpos bucket = PTR_BUCKET_POS(ca, ptr);

			bch2_bucket_nocow_unlock(&c->nocow_locks, bucket, flags);
		}
		ptr_bit <<= 1;
	}
}

bool bch2_bkey_nocow_trylock(struct bch_fs *c, struct bkey_ptrs_c ptrs,
			    unsigned ptrs_held, int flags)
{
	unsigned ptr_bit = 1;

	bkey_for_each_ptr(ptrs, ptr) {
		if (!(ptrs_held & ptr_bit) || ptr->dev == BCH_SB_MEMBER_INVALID) {
			ptr_bit <<= 1;
			continue;
		}

		struct bch_dev *ca = bch2_dev_have_ref(c, ptr->dev);
		struct bpos bucket = PTR_BUCKET_POS(ca, ptr);

		if (unlikely(!bch2_bucket_nocow_trylock(c, bucket, flags))) {
			unsigned ptr_bit2 = 1;
			bkey_for_each_ptr(ptrs, ptr2) {
				if (ptr2 == ptr)
					break;
				if ((ptrs_held & ptr_bit2) &&
				    ptr2->dev != BCH_SB_MEMBER_INVALID) {
					ca = bch2_dev_have_ref(c, ptr2->dev);
					bucket = PTR_BUCKET_POS(ca, ptr2);
					bch2_bucket_nocow_unlock(&c->nocow_locks, bucket, flags);
				}
				ptr_bit2 <<= 1;
			}
			return false;
		}
		ptr_bit <<= 1;
	}

	return true;
}

struct bucket_to_lock {
	u64			b;
	struct nocow_lock_bucket *l;
};

static inline int bucket_to_lock_cmp(struct bucket_to_lock l,
				     struct bucket_to_lock r)
{
	return cmp_int(l.l, r.l);
}

void bch2_bkey_nocow_lock(struct bch_fs *c, struct bkey_ptrs_c ptrs,
			  unsigned ptrs_held, int flags)
{
	if (bch2_bkey_nocow_trylock(c, ptrs, ptrs_held, flags))
		return;

	DARRAY_PREALLOCATED(struct bucket_to_lock, 3) buckets;
	darray_init(&buckets);

	unsigned ptr_bit = 1;
	bkey_for_each_ptr(ptrs, ptr) {
		if (!(ptrs_held & ptr_bit) || ptr->dev == BCH_SB_MEMBER_INVALID) {
			ptr_bit <<= 1;
			continue;
		}

		struct bch_dev *ca = bch2_dev_have_ref(c, ptr->dev);
		u64 b = bucket_to_u64(PTR_BUCKET_POS(ca, ptr));
		struct nocow_lock_bucket *l =
			bucket_nocow_lock(&c->nocow_locks, b);
		prefetch(l);

		/* XXX allocating memory with btree locks held - rare */
		darray_push_gfp(&buckets, ((struct bucket_to_lock) { .b = b, .l = l, }),
				GFP_KERNEL|__GFP_NOFAIL);
		ptr_bit <<= 1;
	}

	WARN_ON_ONCE(buckets.nr > NOCOW_LOCK_BUCKET_SIZE);

	bubble_sort(buckets.data, buckets.nr, bucket_to_lock_cmp);
retake_all:
	darray_for_each(buckets, i) {
		int ret = __bch2_bucket_nocow_trylock(c, i->l, i->b, flags);
		if (!ret)
			continue;

		u64 start_time = local_clock();

		if (ret == -BCH_ERR_nocow_trylock_contended)
			__closure_wait_event(&i->l->wait,
					(ret = __bch2_bucket_nocow_trylock(c, i->l, i->b, flags)) != -BCH_ERR_nocow_trylock_contended);
		if (!ret) {
			bch2_time_stats_update(&c->times[BCH_TIME_nocow_lock_contended], start_time);
			continue;
		}

		BUG_ON(ret != -BCH_ERR_nocow_trylock_bucket_full);

		darray_for_each(buckets, i2) {
			if (i2 == i)
				break;
			__bch2_bucket_nocow_unlock(&c->nocow_locks, i2->b, flags);
		}

		__closure_wait_event(&i->l->wait, nocow_bucket_empty(i->l));
		bch2_time_stats_update(&c->times[BCH_TIME_nocow_lock_contended], start_time);
		goto retake_all;
	}

	darray_exit(&buckets);
}

void bch2_nocow_locks_to_text(struct printbuf *out, struct bucket_nocow_lock_table *t)

{
	unsigned i, nr_zero = 0;
	struct nocow_lock_bucket *l;

	for (l = t->l; l < t->l + ARRAY_SIZE(t->l); l++) {
		unsigned v = 0;

		for (i = 0; i < ARRAY_SIZE(l->l); i++)
			v |= atomic_read(&l->l[i]);

		if (!v) {
			nr_zero++;
			continue;
		}

		if (nr_zero)
			prt_printf(out, "(%u empty entries)\n", nr_zero);
		nr_zero = 0;

		for (i = 0; i < ARRAY_SIZE(l->l); i++) {
			int v = atomic_read(&l->l[i]);
			if (v) {
				bch2_bpos_to_text(out, u64_to_bucket(l->b[i]));
				prt_printf(out, ": %s %u ", v < 0 ? "copy" : "update", abs(v));
			}
		}
		prt_newline(out);
	}

	if (nr_zero)
		prt_printf(out, "(%u empty entries)\n", nr_zero);
}

void bch2_fs_nocow_locking_exit(struct bch_fs *c)
{
	struct bucket_nocow_lock_table *t = &c->nocow_locks;

	for (struct nocow_lock_bucket *l = t->l; l < t->l + ARRAY_SIZE(t->l); l++)
		for (unsigned j = 0; j < ARRAY_SIZE(l->l); j++)
			BUG_ON(atomic_read(&l->l[j]));
}

void bch2_fs_nocow_locking_init_early(struct bch_fs *c)
{
	struct bucket_nocow_lock_table *t = &c->nocow_locks;

	for (struct nocow_lock_bucket *l = t->l; l < t->l + ARRAY_SIZE(t->l); l++)
		spin_lock_init(&l->lock);
}
