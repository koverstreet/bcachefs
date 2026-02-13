/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_NOCOW_LOCKING_H
#define _BCACHEFS_NOCOW_LOCKING_H

#include "bcachefs.h"
#include "alloc/background.h"
#include "nocow_locking_types.h"

#include <linux/hash.h>

static inline struct nocow_lock_bucket *bucket_nocow_lock(struct bucket_nocow_lock_table *t,
							  u64 dev_bucket)
{
	unsigned h = hash_64(dev_bucket, BUCKET_NOCOW_LOCKS_BITS);

	return t->l + (h & (BUCKET_NOCOW_LOCKS - 1));
}

#define BUCKET_NOCOW_LOCK_UPDATE	(1 << 0)

bool bch2_bucket_nocow_is_locked(struct bucket_nocow_lock_table *, struct bpos);

void __bch2_bucket_nocow_unlock(struct bucket_nocow_lock_table *, u64, int);

static inline void bch2_bucket_nocow_unlock(struct bucket_nocow_lock_table *t, struct bpos bucket,
					    int flags)
{
	__bch2_bucket_nocow_unlock(t, bucket_to_u64(bucket), flags);
}

void bch2_bkey_nocow_unlock(struct bch_fs *, struct bkey_s_c, unsigned, int);
bool bch2_bkey_nocow_trylock(struct bch_fs *, struct bkey_ptrs_c, unsigned, int);
void bch2_bkey_nocow_lock(struct bch_fs *, struct bkey_ptrs_c, unsigned, int);

void bch2_nocow_locks_to_text(struct printbuf *, struct bucket_nocow_lock_table *);

void bch2_fs_nocow_locking_exit(struct bch_fs *);
void bch2_fs_nocow_locking_init_early(struct bch_fs *);

#endif /* _BCACHEFS_NOCOW_LOCKING_H */
