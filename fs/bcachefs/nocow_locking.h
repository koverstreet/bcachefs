/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_NOCOW_LOCKING_H
#define _BCACHEFS_NOCOW_LOCKING_H

#include "bcachefs_format.h"
#include "two_state_shared_lock.h"

#include <linux/siphash.h>

#define BUCKET_NOCOW_LOCKS		(1U << 10)

struct bucket_nocow_lock_table {
	siphash_key_t			key;
	two_state_lock_t		l[BUCKET_NOCOW_LOCKS];
};

#define BUCKET_NOCOW_LOCK_UPDATE	(1 << 0)

static inline two_state_lock_t *bucket_nocow_lock(struct bucket_nocow_lock_table *t,
						  struct bpos bucket)
{
	u64 dev_bucket = bucket.inode << 56 | bucket.offset;
	unsigned h = siphash_1u64(dev_bucket, &t->key);

	return t->l + (h & (BUCKET_NOCOW_LOCKS - 1));
}

static inline bool bch2_bucket_nocow_is_locked(struct bucket_nocow_lock_table *t,
					       struct bpos bucket)
{
	two_state_lock_t *l = bucket_nocow_lock(t, bucket);

	return atomic_long_read(&l->v) != 0;
}

static inline void bch2_bucket_nocow_unlock(struct bucket_nocow_lock_table *t,
					    struct bpos bucket, int flags)
{
	two_state_lock_t *l = bucket_nocow_lock(t, bucket);

	bch2_two_state_unlock(l, flags & BUCKET_NOCOW_LOCK_UPDATE);
}

void __bch2_bucket_nocow_lock(struct bucket_nocow_lock_table *, struct bpos, int);

static inline void bch2_bucket_nocow_lock(struct bucket_nocow_lock_table *t,
					  struct bpos bucket, int flags)
{
	two_state_lock_t *l = bucket_nocow_lock(t, bucket);

	if (!bch2_two_state_trylock(l, flags & BUCKET_NOCOW_LOCK_UPDATE))
		__bch2_bucket_nocow_lock(t, bucket, flags);
}

#endif /* _BCACHEFS_NOCOW_LOCKING_H */
