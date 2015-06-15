
#include "six.h"

/* Number of times to trylock() before sleeping in six_lock(): */
#define SIX_LOCK_SPIN_COUNT		1

#define __SIX_LOCK_HELD_read		__SIX_VAL(read_lock, ~0)
#define __SIX_LOCK_HELD_intent		__SIX_VAL(intent_lock, ~0)
#define __SIX_LOCK_HELD_write		__SIX_VAL(seq, 1)

struct six_lock_vals {
	/* Value we add to the lock in order to take the lock: */
	unsigned long		lock_val;

	/* If the lock has this value (used as a mask), taking the lock fails: */
	unsigned long		lock_fail;

	/* Value we add to the lock in order to release the lock: */
	unsigned long		unlock_val;

	/* Waitlist we wakeup when releasing the lock: */
	enum six_lock_type	unlock_wakeup;
};

#define LOCK_VALS {							\
	[SIX_LOCK_read] = {						\
		.lock_val	= __SIX_VAL(read_lock, 1),		\
		.lock_fail	= __SIX_LOCK_HELD_write,		\
		.unlock_val	= -__SIX_VAL(read_lock, 1),		\
		.unlock_wakeup	= SIX_LOCK_write,			\
	},								\
	[SIX_LOCK_intent] = {						\
		.lock_val	= __SIX_VAL(intent_lock, 1),		\
		.lock_fail	= __SIX_LOCK_HELD_intent,		\
		.unlock_val	= -__SIX_VAL(intent_lock, 1),		\
		.unlock_wakeup	= SIX_LOCK_intent,			\
	},								\
	[SIX_LOCK_write] = {						\
		.lock_val	= __SIX_VAL(seq, 1),			\
		.lock_fail	= __SIX_LOCK_HELD_read,			\
		.unlock_val	= __SIX_VAL(seq, 1),			\
		.unlock_wakeup	= SIX_LOCK_read,			\
	},								\
}

bool __six_trylock_type(struct six_lock *lock, enum six_lock_type type)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state old;
	unsigned long v = lock->state.v;

	do {
		old.v = v;

		EBUG_ON(type == SIX_LOCK_write &&
			((old.v & __SIX_LOCK_HELD_write) ||
			 !(old.v & __SIX_LOCK_HELD_intent)));

		if (old.v & l[type].lock_fail)
			return false;
	} while ((v = cmpxchg(&lock->state.v,
			      old.v,
			      old.v + l[type].lock_val)) != old.v);

	return true;
}

bool __six_relock_type(struct six_lock *lock, enum six_lock_type type,
		       unsigned seq)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state old;
	unsigned long v = lock->state.v;

	do {
		old.v = v;

		if (old.seq != seq || old.v & l[type].lock_fail)
			return false;
	} while ((v = cmpxchg(&lock->state.v,
			      old.v,
			      old.v + l[type].lock_val)) != old.v);

	return true;
}

struct six_lock_waiter {
	struct list_head	list;
	struct task_struct	*task;
};

/* This is probably up there with the more evil things I've done */
#define waitlist_bitnr(id) ilog2(__SIX_VAL(waiters, 1 << (id)))

void __six_lock_type(struct six_lock *lock, enum six_lock_type type)
{
	struct six_lock_waiter wait;
	unsigned i;

	for (i = 0; i < SIX_LOCK_SPIN_COUNT; i++) {
		if (__six_trylock_type(lock, type))
			return;
		cpu_relax();
	}

	INIT_LIST_HEAD(&wait.list);
	wait.task = current;

	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (list_empty(&wait.list)) {
			spin_lock(&lock->wait_lock);
			list_add_tail(&wait.list, &lock->wait_list[type]);
			spin_unlock(&lock->wait_lock);
		}

		set_bit(waitlist_bitnr(type),
			(unsigned long *) &lock->state.v);

		if (__six_trylock_type(lock, type))
			break;

		schedule();
	}

	__set_current_state(TASK_RUNNING);

	if (!list_empty_careful(&wait.list)) {
		spin_lock(&lock->wait_lock);
		list_del(&wait.list);
		spin_unlock(&lock->wait_lock);
	}
}

static inline void six_lock_wakeup(struct six_lock *lock,
				   union six_lock_state state,
				   unsigned waitlist_id)
{
	struct list_head *wait_list = &lock->wait_list[waitlist_id];
	struct six_lock_waiter *w, *next;

	if (waitlist_id == SIX_LOCK_write && state.read_lock)
		return;

	if (!(state.waiters & (1 << waitlist_id)))
		return;

	clear_bit(waitlist_bitnr(waitlist_id),
		  (unsigned long *) &lock->state.v);

	spin_lock(&lock->wait_lock);

	list_for_each_entry_safe(w, next, wait_list, list) {
		list_del_init(&w->list);

		if (wake_up_process(w->task) &&
		    waitlist_id != SIX_LOCK_read) {
			if (!list_empty(wait_list))
				set_bit(waitlist_bitnr(waitlist_id),
					(unsigned long *) &lock->state.v);
			break;
		}
	}

	spin_unlock(&lock->wait_lock);
}

void __six_unlock_type(struct six_lock *lock, enum six_lock_type type)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state state;

	/* unlock barrier */
	smp_wmb();
	state.v = atomic64_add_return(l[type].unlock_val,
				      &lock->state.counter);

	six_lock_wakeup(lock, state, l[type].unlock_wakeup);
}

bool six_trylock_convert(struct six_lock *lock,
			 enum six_lock_type from,
			 enum six_lock_type to)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state old, new;
	unsigned long v = lock->state.v;

	do {
		new.v = old.v = v;
		new.v += l[from].unlock_val;

		if (new.v & l[to].lock_fail)
			return false;
	} while ((v = cmpxchg(&lock->state.v,
			      old.v,
			      new.v + l[to].lock_val)) != old.v);

	six_lock_wakeup(lock, new, l[from].unlock_wakeup);

	return true;
}

/*
 * Increment read/intent lock count, assuming we already have it read or intent
 * locked:
 */
void __six_lock_increment(struct six_lock *lock, enum six_lock_type type)
{
	const struct six_lock_vals l[] = LOCK_VALS;

	BUG_ON(type == SIX_LOCK_write);

	/* XXX: assert already locked, and that we don't overflow: */

	atomic64_add(l[type].lock_val, &lock->state.counter);

	/* lock barrier: */
	smp_mb__after_atomic();
}
