// SPDX-License-Identifier: GPL-2.0

#ifndef _LINUX_SIX_H
#define _LINUX_SIX_H

/*
 * Shared/intent/exclusive locks: sleepable read/write locks, much like rw
 * semaphores, except with a third intermediate state, intent. Basic operations
 * are:
 *
 * six_lock_read(&foo->lock);
 * six_unlock_read(&foo->lock);
 *
 * six_lock_intent(&foo->lock);
 * six_unlock_intent(&foo->lock);
 *
 * six_lock_write(&foo->lock);
 * six_unlock_write(&foo->lock);
 *
 * Intent locks block other intent locks, but do not block read locks, and you
 * must have an intent lock held before taking a write lock, like so:
 *
 * six_lock_intent(&foo->lock);
 * six_lock_write(&foo->lock);
 * six_unlock_write(&foo->lock);
 * six_unlock_intent(&foo->lock);
 *
 * Other operations:
 *
 *   six_trylock_read()
 *   six_trylock_intent()
 *   six_trylock_write()
 *
 *   six_lock_downgrade():	convert from intent to read
 *   six_lock_tryupgrade():	attempt to convert from read to intent
 *
 * Locks also embed a sequence number, which is incremented when the lock is
 * locked or unlocked for write. The current sequence number can be grabbed
 * while a lock is held from lock->state.seq; then, if you drop the lock you can
 * use six_relock_(read|intent_write)(lock, seq) to attempt to retake the lock
 * iff it hasn't been locked for write in the meantime.
 *
 * There are also operations that take the lock type as a parameter, where the
 * type is one of SIX_LOCK_read, SIX_LOCK_intent, or SIX_LOCK_write:
 *
 *   six_lock_type(lock, type)
 *   six_unlock_type(lock, type)
 *   six_relock(lock, type, seq)
 *   six_trylock_type(lock, type)
 *   six_trylock_convert(lock, from, to)
 *
 * A lock may be held multiple types by the same thread (for read or intent,
 * not write) - up to SIX_LOCK_MAX_RECURSE. However, the six locks code does
 * _not_ implement the actual recursive checks itself though - rather, if your
 * code (e.g. btree iterator code) knows that the current thread already has a
 * lock held, and for the correct type, six_lock_increment() may be used to
 * bump up the counter for that type - the only effect is that one more call to
 * unlock will be required before the lock is unlocked.
 */

#include <linux/lockdep.h>
#include <linux/osq_lock.h>
#include <linux/sched.h>
#include <linux/types.h>

#define SIX_LOCK_SEPARATE_LOCKFNS

union six_lock_state {
	struct {
		atomic64_t	counter;
	};

	struct {
		u64		v;
	};

	struct {
		/* for waitlist_bitnr() */
		unsigned long	l;
	};

	struct {
		unsigned	read_lock:26;
		unsigned	intent_lock:3;
		unsigned	waiters:3;
		/*
		 * seq works much like in seqlocks: it's incremented every time
		 * we lock and unlock for write.
		 *
		 * If it's odd write lock is held, even unlocked.
		 *
		 * Thus readers can unlock, and then lock again later iff it
		 * hasn't been modified in the meantime.
		 */
		u32		seq;
	};
};

#define SIX_LOCK_MAX_RECURSE	((1 << 3) - 1)

enum six_lock_type {
	SIX_LOCK_read,
	SIX_LOCK_intent,
	SIX_LOCK_write,
};

struct six_lock {
	union six_lock_state	state;
	struct task_struct	*owner;
	struct optimistic_spin_queue osq;

	raw_spinlock_t		wait_lock;
	struct list_head	wait_list[2];
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
#endif
};

static __always_inline void __six_lock_init(struct six_lock *lock,
					    const char *name,
					    struct lock_class_key *key)
{
	atomic64_set(&lock->state.counter, 0);
	raw_spin_lock_init(&lock->wait_lock);
	INIT_LIST_HEAD(&lock->wait_list[SIX_LOCK_read]);
	INIT_LIST_HEAD(&lock->wait_list[SIX_LOCK_intent]);
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	debug_check_no_locks_freed((void *) lock, sizeof(*lock));
	lockdep_init_map(&lock->dep_map, name, key, 0);
#endif
}

#define six_lock_init(lock)						\
do {									\
	static struct lock_class_key __key;				\
									\
	__six_lock_init((lock), #lock, &__key);				\
} while (0)

#define __SIX_VAL(field, _v)	(((union six_lock_state) { .field = _v }).v)

#ifdef SIX_LOCK_SEPARATE_LOCKFNS

#define __SIX_LOCK(type)						\
bool six_trylock_##type(struct six_lock *);				\
bool six_relock_##type(struct six_lock *, u32);				\
void six_lock_##type(struct six_lock *);				\
void six_unlock_##type(struct six_lock *);

__SIX_LOCK(read)
__SIX_LOCK(intent)
__SIX_LOCK(write)
#undef __SIX_LOCK

#define SIX_LOCK_DISPATCH(type, fn, ...)			\
	switch (type) {						\
	case SIX_LOCK_read:					\
		return fn##_read(__VA_ARGS__);			\
	case SIX_LOCK_intent:					\
		return fn##_intent(__VA_ARGS__);		\
	case SIX_LOCK_write:					\
		return fn##_write(__VA_ARGS__);			\
	default:						\
		BUG();						\
	}

static inline bool six_trylock_type(struct six_lock *lock, enum six_lock_type type)
{
	SIX_LOCK_DISPATCH(type, six_trylock, lock);
}

static inline bool six_relock_type(struct six_lock *lock, enum six_lock_type type,
		     unsigned seq)
{
	SIX_LOCK_DISPATCH(type, six_relock, lock, seq);
}

static inline void six_lock_type(struct six_lock *lock, enum six_lock_type type)
{
	SIX_LOCK_DISPATCH(type, six_lock, lock);
}

static inline void six_unlock_type(struct six_lock *lock, enum six_lock_type type)
{
	SIX_LOCK_DISPATCH(type, six_unlock, lock);
}

#else

bool six_trylock_type(struct six_lock *, enum six_lock_type);
bool six_relock_type(struct six_lock *, enum six_lock_type, unsigned);
void six_lock_type(struct six_lock *, enum six_lock_type);
void six_unlock_type(struct six_lock *, enum six_lock_type);

#define __SIX_LOCK(type)						\
static __always_inline bool six_trylock_##type(struct six_lock *lock)	\
{									\
	return six_trylock_type(lock, SIX_LOCK_##type);			\
}									\
									\
static __always_inline bool six_relock_##type(struct six_lock *lock, u32 seq)\
{									\
	return six_relock_type(lock, SIX_LOCK_##type, seq);		\
}									\
									\
static __always_inline void six_lock_##type(struct six_lock *lock)	\
{									\
	six_lock_type(lock, SIX_LOCK_##type);				\
}									\
									\
static __always_inline void six_unlock_##type(struct six_lock *lock)	\
{									\
	six_unlock_type(lock, SIX_LOCK_##type);				\
}

__SIX_LOCK(read)
__SIX_LOCK(intent)
__SIX_LOCK(write)
#undef __SIX_LOCK

#endif

void six_lock_downgrade(struct six_lock *);
bool six_lock_tryupgrade(struct six_lock *);
bool six_trylock_convert(struct six_lock *, enum six_lock_type,
			 enum six_lock_type);

void six_lock_increment(struct six_lock *, enum six_lock_type);

#endif /* _LINUX_SIX_H */
