/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_FS_FDM_H
#define _BCACHEFS_FS_FDM_H

/*
 * Faults-disabled-mapping hash table
 *
 * Replaces the per-task faults_disabled_mapping field (removed in 7.0)
 * with a fixed-size cuckoo hash in bch_fs. Used to prevent deadlock
 * when the page fault handler is invoked for a mapping that is already
 * being written to by the current task (DIO path).
 *
 * Properties:
 *  - O(1) lookup: exactly three slots to check (3-way cuckoo)
 *  - No locks: each task only writes/removes its own entry
 *  - No resize: table is oversized at init, occupancy stays very low
 *  - Low bit of mapping pointer stolen for dropped_locks signaling
 *  - Closure waitlist fallback if all slots full (just a read when empty)
 *
 * Hash function approach borrowed from buckets_waiting_for_journal:
 * random seeds with hash_64() give truly independent distributions.
 * With 3 hash functions and 512 slots at ~16 concurrent tasks,
 * probability of all 3 slots occupied is ~(16/512)^3 ≈ 0.003%.
 */

#include <linux/hash.h>
#include <linux/random.h>
#include <linux/closure.h>

#define FDM_NR_HASH		3
#define FDM_HASH_BITS		9
#define FDM_HASH_SIZE		(1 << FDM_HASH_BITS)

struct fdm_slot {
	struct task_struct	*task;
	unsigned long		mapping;	/* address_space * | dropped_locks bit */
};

struct fdm_hash {
	u64			hash_seeds[FDM_NR_HASH];
	struct closure_waitlist	wait;
	struct fdm_slot		slots[FDM_HASH_SIZE];
};

static inline unsigned fdm_hash(struct fdm_hash *ht, int idx,
				const struct task_struct *task)
{
	return hash_64((unsigned long)task ^ ht->hash_seeds[idx], FDM_HASH_BITS);
}

static inline bool __fdm_has_slot(struct fdm_hash *ht)
{
	for (unsigned i = 0; i < FDM_NR_HASH; i++)
		if (!READ_ONCE(ht->slots[fdm_hash(ht, i, current)].task))
			return true;
	return false;
}

static inline struct address_space *fdm_get(struct fdm_hash *ht)
{
	for (unsigned i = 0; i < FDM_NR_HASH; i++) {
		unsigned h = fdm_hash(ht, i, current);
		if (READ_ONCE(ht->slots[h].task) == current) {
			smp_rmb(); /* pair with smp_wmb() in fdm_set */
			return (void *)(READ_ONCE(ht->slots[h].mapping) & ~1UL);
		}
	}
	return NULL;
}

static inline bool fdm_dropped_locks(struct fdm_hash *ht)
{
	for (unsigned i = 0; i < FDM_NR_HASH; i++) {
		unsigned h = fdm_hash(ht, i, current);
		if (READ_ONCE(ht->slots[h].task) == current) {
			smp_rmb();
			return READ_ONCE(ht->slots[h].mapping) & 1;
		}
	}
	return false;
}

static inline void fdm_set_dropped_locks(struct fdm_hash *ht)
{
	for (unsigned i = 0; i < FDM_NR_HASH; i++) {
		unsigned h = fdm_hash(ht, i, current);
		if (READ_ONCE(ht->slots[h].task) == current) {
			ht->slots[h].mapping |= 1;
			return;
		}
	}
}

/*
 * Insert current task's mapping. Only current ever inserts for itself,
 * so no lock needed. With 3-way hashing at ~3% occupancy, all three
 * slots being occupied is vanishingly rare (~0.003%). If it does
 * happen, sleep on the closure waitlist until a slot frees up.
 */
static inline void fdm_set(struct fdm_hash *ht, struct address_space *mapping)
{
	for (unsigned i = 0; i < FDM_NR_HASH; i++)
		EBUG_ON(READ_ONCE(ht->slots[fdm_hash(ht, i, current)].task) == current);

	closure_wait_event(&ht->wait, __fdm_has_slot(ht));

	for (unsigned i = 0; i < FDM_NR_HASH; i++) {
		unsigned h = fdm_hash(ht, i, current);
		if (!READ_ONCE(ht->slots[h].task)) {
			WRITE_ONCE(ht->slots[h].mapping, (unsigned long)mapping);
			/* mapping must be visible before task (task acts as "valid" marker) */
			smp_wmb();
			WRITE_ONCE(ht->slots[h].task, current);
			return;
		}
	}

	/* Lost race after wakeup — retry */
	fdm_set(ht, mapping);
}

static inline void fdm_clear(struct fdm_hash *ht)
{
	for (unsigned i = 0; i < FDM_NR_HASH; i++) {
		unsigned h = fdm_hash(ht, i, current);
		if (READ_ONCE(ht->slots[h].task) == current) {
			WRITE_ONCE(ht->slots[h].task, NULL);
			/* Ensure task is cleared before mapping could be reused */
			smp_wmb();
			closure_wake_up(&ht->wait);
			return;
		}
	}
}

static inline void fdm_init(struct fdm_hash *ht)
{
	memset(ht, 0, sizeof(*ht));
	for (unsigned i = 0; i < FDM_NR_HASH; i++)
		ht->hash_seeds[i] = get_random_u64();
}

#endif /* _BCACHEFS_FS_FDM_H */
