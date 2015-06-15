
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

static __always_inline void __six_lock_init(struct six_lock *lock, const char *name,
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

bool __six_trylock_type(struct six_lock *, enum six_lock_type);
bool __six_relock_type(struct six_lock *, enum six_lock_type, unsigned);
void __six_lock_type(struct six_lock *, enum six_lock_type);
void __six_unlock_type(struct six_lock *, enum six_lock_type);
bool six_trylock_convert(struct six_lock *, enum six_lock_type,
			 enum six_lock_type);
void __six_lock_increment(struct six_lock *, enum six_lock_type);

#ifdef CONFIG_DEBUG_LOCK_ALLOC

#define six_acquire(l)	lock_acquire(l, 0, 0, 0, 0, NULL, _THIS_IP_)
#define six_release(l)	lock_release(l, 0, _THIS_IP_)

#else

#define six_acquire(l)
#define six_release(l)

#endif

#define __SIX_VAL(field, _v)	(((union six_lock_state) { .field = _v }).v)

static __always_inline bool six_trylock_type(struct six_lock *lock,
					     enum six_lock_type type)
{
	if (!__six_trylock_type(lock, type))
		return false;

	six_acquire(&lock->dep_map);
	return true;
}

static __always_inline bool six_relock_type(struct six_lock *lock,
					    enum six_lock_type type,
					    u32 seq)
{
	if (!__six_relock_type(lock, type, seq))
		return false;

	six_acquire(&lock->dep_map);
	return true;
}

static __always_inline void six_lock_type(struct six_lock *lock,
					  enum six_lock_type type)
{
	__six_lock_type(lock, type);
	six_acquire(&lock->dep_map);
}

static __always_inline void six_unlock_type(struct six_lock *lock,
					    enum six_lock_type type)
{
	six_release(&lock->dep_map);
	__six_unlock_type(lock, type);
}

static __always_inline void six_lock_increment(struct six_lock *lock,
					       enum six_lock_type type)
{
	__six_lock_increment(lock, type);
	six_acquire(&lock->dep_map);
}

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

#endif /* _BCACHE_SIX_H */
