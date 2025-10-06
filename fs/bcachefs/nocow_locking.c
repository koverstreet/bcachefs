// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "bkey_methods.h"
#include "closure.h"
#include "nocow_locking.h"
#include "util.h"

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

void bch2_bucket_nocow_unlock(struct bucket_nocow_lock_table *t, struct bpos bucket, int flags)
{
	u64 dev_bucket = bucket_to_u64(bucket);
	struct nocow_lock_bucket *l = bucket_nocow_lock(t, dev_bucket);
	int lock_val = flags ? 1 : -1;
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(l->b); i++)
		if (l->b[i] == dev_bucket) {
			int v = atomic_sub_return(lock_val, &l->l[i]);

			BUG_ON(v && sign(v) != lock_val);
			if (!v)
				closure_wake_up(&l->wait);
			return;
		}

	BUG();
}

bool __bch2_bucket_nocow_trylock(struct nocow_lock_bucket *l,
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

	return false;
got_entry:
	v = atomic_read(&l->l[i]);
	if (lock_val > 0 ? v < 0 : v > 0)
		return false;
take_lock:
	v = atomic_read(&l->l[i]);
	/* Overflow? */
	if (v && sign(v + lock_val) != sign(v))
		return false;

	atomic_add(lock_val, &l->l[i]);
	return true;
}

void __bch2_bucket_nocow_lock(struct bucket_nocow_lock_table *t,
			      struct nocow_lock_bucket *l,
			      u64 dev_bucket, int flags)
{
	if (!__bch2_bucket_nocow_trylock(l, dev_bucket, flags)) {
		struct bch_fs *c = container_of(t, struct bch_fs, nocow_locks);
		u64 start_time = local_clock();

		__closure_wait_event(&l->wait, __bch2_bucket_nocow_trylock(l, dev_bucket, flags));
		bch2_time_stats_update(&c->times[BCH_TIME_nocow_lock_contended], start_time);
	}
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
