/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_NOCOW_LOCKING_TYPES_H
#define _BCACHEFS_NOCOW_LOCKING_TYPES_H

#define BUCKET_NOCOW_LOCKS_BITS		10
#define BUCKET_NOCOW_LOCKS		(1U << BUCKET_NOCOW_LOCKS_BITS)

#define NOCOW_LOCK_BUCKET_SIZE	6

struct nocow_lock_bucket {
	struct closure_waitlist		wait;
	spinlock_t			lock;
	u64				b[NOCOW_LOCK_BUCKET_SIZE];
	atomic_t			l[NOCOW_LOCK_BUCKET_SIZE];
} __aligned(SMP_CACHE_BYTES);

struct bucket_nocow_lock_table {
	struct nocow_lock_bucket	l[BUCKET_NOCOW_LOCKS];
};

#endif /* _BCACHEFS_NOCOW_LOCKING_TYPES_H */

