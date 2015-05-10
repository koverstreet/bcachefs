
#ifndef _BCACHE_SIX_H
#define _BCACHE_SIX_H

#include <linux/sched.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "util.h"

/*
 * LOCK STATES:
 *
 * read, intent, write (i.e. shared/intent/exclusive, hence the name)
 *
 * read and write work as with normal read/write locks - a lock can have
 * multiple readers, but write excludes reads and other write locks.
 *
 * Intent does not block read, but it does block other intent locks. The idea is
 * by taking an intent lock, you can then later upgrade to a write lock without
 * dropping your read lock and without deadlocking - because no other thread has
 * the intent lock and thus no other thread could be trying to take the write
 * lock.
 */

union six_lock_state {
	struct {
		atomic64_t	counter;
	};

	struct {
		u64		v;
	};

	struct {
		unsigned	read_lock:28;
		unsigned	intent_lock:1;
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

enum six_lock_type {
	SIX_LOCK_read,
	SIX_LOCK_intent,
	SIX_LOCK_write,
};

struct six_lock {
	union six_lock_state	state;

	spinlock_t		wait_lock;
	struct list_head	wait_list[3];
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
#endif
};

static inline void __six_lock_init(struct six_lock *lock, const char *name,
				   struct lock_class_key *key)
{
	atomic64_set(&lock->state.counter, 0);
	spin_lock_init(&lock->wait_lock);
	INIT_LIST_HEAD(&lock->wait_list[SIX_LOCK_read]);
	INIT_LIST_HEAD(&lock->wait_list[SIX_LOCK_intent]);
	INIT_LIST_HEAD(&lock->wait_list[SIX_LOCK_write]);
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

bool __six_trylock_convert(struct six_lock *, unsigned long, unsigned long,
			   unsigned long, unsigned);
bool __six_trylock(struct six_lock *, unsigned long, unsigned long);
bool __six_relock(struct six_lock *, unsigned long, unsigned long, unsigned);
void __six_lock(struct six_lock *, unsigned long, unsigned long, unsigned);
void __six_unlock(struct six_lock *, unsigned long, unsigned);

#ifdef CONFIG_DEBUG_LOCK_ALLOC

#define six_acquire(l)	lock_acquire(l, 0, 0, 0, 0, NULL, _THIS_IP_)
#define six_release(l)	lock_release(l, 0, _THIS_IP_)

#else

#define six_acquire(l)
#define six_release(l)

#endif

#define __SIX_VAL(field, _v)	(((union six_lock_state) { .field = _v }).v)

#define __SIX_VAL_WAIT			__SIX_VAL(waiters, 1)

#define __SIX_LOCK_HELD_read		__SIX_VAL(read_lock, ~0)
#define __SIX_LOCK_HELD_intent		__SIX_VAL(intent_lock, 1)
#define __SIX_LOCK_HELD_write		__SIX_VAL(seq, 1)

#define __SIX_LOCK_FAIL_read		__SIX_LOCK_HELD_write
#define __SIX_LOCK_VAL_read		__SIX_VAL(read_lock, 1)
#define __SIX_UNLOCK_VAL_read		(-__SIX_VAL(read_lock, 1))
#define __SIX_UNLOCK_WAKEUP_read	SIX_LOCK_write

#define __SIX_LOCK_FAIL_intent		__SIX_LOCK_HELD_intent
#define __SIX_LOCK_VAL_intent		__SIX_VAL(intent_lock, 1)
#define __SIX_UNLOCK_VAL_intent		(-__SIX_VAL(intent_lock, 1))
#define __SIX_UNLOCK_WAKEUP_intent	SIX_LOCK_intent

#define __SIX_LOCK_FAIL_write		__SIX_LOCK_HELD_read
#define __SIX_LOCK_VAL_write		__SIX_VAL(seq, 1)
#define __SIX_UNLOCK_VAL_write		__SIX_VAL(seq, 1)
#define __SIX_UNLOCK_WAKEUP_write	SIX_LOCK_read

#define SIX_LOCK_SPIN_COUNT		1

#define __SIX_LOCK(type)						\
	static inline bool six_trylock_##type(struct six_lock *lock)	\
	{								\
		if (__six_trylock(lock,					\
				  __SIX_LOCK_VAL_##type,		\
				  __SIX_LOCK_FAIL_##type)) {		\
			six_acquire(&lock->dep_map);			\
			return true;					\
		}							\
		return false;						\
	}								\
									\
	static inline bool six_relock_##type(struct six_lock *lock, u32 seq)\
	{								\
		if (__six_relock(lock,					\
				 __SIX_LOCK_VAL_##type,			\
				 __SIX_LOCK_FAIL_##type,		\
				 seq)) {				\
			six_acquire(&lock->dep_map);			\
			return true;					\
		}							\
		return false;						\
	}								\
									\
	static inline void six_lock_##type(struct six_lock *lock)	\
	{								\
		__six_lock(lock,					\
			   __SIX_LOCK_VAL_##type,			\
			   __SIX_LOCK_FAIL_##type,			\
			   SIX_LOCK_##type);				\
		six_acquire(&lock->dep_map);				\
	}								\
									\
	static inline void six_unlock_##type(struct six_lock *lock)	\
	{								\
		six_release(&lock->dep_map);				\
									\
		__six_unlock(lock,					\
			     __SIX_UNLOCK_VAL_##type,			\
			     __SIX_UNLOCK_WAKEUP_##type);		\
	}

__SIX_LOCK(read)
__SIX_LOCK(intent)
__SIX_LOCK(write)

#define six_trylock_convert(lock, from, to)				\
	__six_trylock_convert(lock,					\
			      __SIX_UNLOCK_VAL_##from,			\
			      __SIX_LOCK_VAL_##to,			\
			      __SIX_LOCK_FAIL_##to,			\
			      __SIX_UNLOCK_WAKEUP_##from)

#endif /* _BCACHE_SIX_H */
