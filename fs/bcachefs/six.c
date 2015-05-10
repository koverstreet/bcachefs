
#include "six.h"

bool __six_trylock(struct six_lock *lock,
		   unsigned long lock_val,
		   unsigned long lock_fail)
{
	union six_lock_state old;
	unsigned long v = lock->state.v;

	do {
		old.v = v;

		EBUG_ON(lock_val == __SIX_LOCK_VAL_write &&
			((old.v & __SIX_LOCK_HELD_write) ||
			 !(old.v & __SIX_LOCK_HELD_intent)));

		if (old.v & lock_fail)
			return false;
	} while ((v = cmpxchg(&lock->state.v,
			      old.v,
			      old.v + lock_val)) != old.v);

	return true;
}

bool __six_relock(struct six_lock *lock,
		  unsigned long lock_val,
		  unsigned long lock_fail,
		  unsigned seq)
{
	union six_lock_state old = lock->state;
	unsigned long v;

	while (1) {
		if (old.seq != seq ||
		    old.v & lock_fail)
			return false;

		v = cmpxchg(&lock->state.v, old.v, old.v + lock_val);
		if (v == old.v)
			return true;

		old.v = v;
	}
}

struct six_lock_waiter {
	struct list_head	list;
	struct task_struct	*task;
};

/* This is probably up there with the more evil things I've done */
#define waitlist_bitnr(id) ilog2(__SIX_VAL(waiters, 1 << (id)))

void __six_lock(struct six_lock *lock,
		unsigned long lock_val,
		unsigned long lock_fail,
		unsigned waitlist_id)
{
	struct six_lock_waiter wait;
	unsigned i;

	for (i = 0; i < SIX_LOCK_SPIN_COUNT; i++) {
		if (__six_trylock(lock, lock_val, lock_fail))
			return;
		cpu_relax();
	}

	INIT_LIST_HEAD(&wait.list);
	wait.task = current;

	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (list_empty(&wait.list)) {
			spin_lock(&lock->wait_lock);
			list_add_tail(&wait.list,
				      &lock->wait_list[waitlist_id]);
			spin_unlock(&lock->wait_lock);
		}

		set_bit(waitlist_bitnr(waitlist_id),
			(unsigned long *) &lock->state.v);

		if (__six_trylock(lock, lock_val, lock_fail))
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

bool __six_trylock_convert(struct six_lock *lock,
			   unsigned long unlock_val,
			   unsigned long lock_val,
			   unsigned long lock_fail,
			   unsigned wakeup)
{
	union six_lock_state old, new;
	unsigned long v = lock->state.v;

	do {
		new.v = old.v = v;
		new.v += unlock_val;

		if (new.v & lock_fail)
			return false;
	} while ((v = cmpxchg(&lock->state.v,
			      old.v,
			      new.v + lock_val)) != old.v);

	six_lock_wakeup(lock, new, wakeup);

	return true;
}

void __six_unlock(struct six_lock *lock,
		  unsigned long unlock_val,
		  unsigned wakeup)
{
	union six_lock_state state;

	/* unlock barrier */
	smp_wmb();
	state.v = atomic64_add_return(unlock_val,
				      &lock->state.counter);

	six_lock_wakeup(lock, state, wakeup);
}
