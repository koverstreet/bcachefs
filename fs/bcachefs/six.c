
#include <linux/log2.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>

#include "six.h"

#define six_acquire(l, t)	lock_acquire(l, 0, t, 0, 0, NULL, _RET_IP_)
#define six_release(l)		lock_release(l, 0, _RET_IP_)

#define __SIX_LOCK_HELD_read		__SIX_VAL(read_lock, ~0)
#define __SIX_LOCK_HELD_intent		__SIX_VAL(intent_lock, ~0)
#define __SIX_LOCK_HELD_write		__SIX_VAL(seq, 1)

struct six_lock_vals {
	/* Value we add to the lock in order to take the lock: */
	u64			lock_val;

	/* If the lock has this value (used as a mask), taking the lock fails: */
	u64			lock_fail;

	/* Value we add to the lock in order to release the lock: */
	u64			unlock_val;

	/* Mask that indicates lock is held for this type: */
	u64			held_mask;

	/* Waitlist we wakeup when releasing the lock: */
	enum six_lock_type	unlock_wakeup;
};

#define LOCK_VALS {							\
	[SIX_LOCK_read] = {						\
		.lock_val	= __SIX_VAL(read_lock, 1),		\
		.lock_fail	= __SIX_LOCK_HELD_write,		\
		.unlock_val	= -__SIX_VAL(read_lock, 1),		\
		.held_mask	= __SIX_LOCK_HELD_read,			\
		.unlock_wakeup	= SIX_LOCK_write,			\
	},								\
	[SIX_LOCK_intent] = {						\
		.lock_val	= __SIX_VAL(intent_lock, 1),		\
		.lock_fail	= __SIX_LOCK_HELD_intent,		\
		.unlock_val	= -__SIX_VAL(intent_lock, 1),		\
		.held_mask	= __SIX_LOCK_HELD_intent,		\
		.unlock_wakeup	= SIX_LOCK_intent,			\
	},								\
	[SIX_LOCK_write] = {						\
		.lock_val	= __SIX_VAL(seq, 1),			\
		.lock_fail	= __SIX_LOCK_HELD_read,			\
		.unlock_val	= __SIX_VAL(seq, 1),			\
		.held_mask	= __SIX_LOCK_HELD_write,		\
		.unlock_wakeup	= SIX_LOCK_read,			\
	},								\
}

static void six_set_owner(struct six_lock *lock, enum six_lock_type type)
{
	if (type == SIX_LOCK_intent)
		lock->owner = current;
}

static void six_clear_owner(struct six_lock *lock, enum six_lock_type type)
{
	if (type == SIX_LOCK_intent)
		lock->owner = NULL;
}

static inline bool __six_trylock_type(struct six_lock *lock,
				      enum six_lock_type type)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state old;
	u64 v = READ_ONCE(lock->state.v);

	do {
		old.v = v;

		EBUG_ON(type == SIX_LOCK_write &&
			((old.v & __SIX_LOCK_HELD_write) ||
			 !(old.v & __SIX_LOCK_HELD_intent)));

		if (old.v & l[type].lock_fail)
			return false;
	} while ((v = atomic64_cmpxchg_acquire(&lock->state.counter,
				old.v,
				old.v + l[type].lock_val)) != old.v);
	return true;
}

bool six_trylock_type(struct six_lock *lock, enum six_lock_type type)
{
	bool ret = __six_trylock_type(lock, type);

	if (ret) {
		six_acquire(&lock->dep_map, 1);
		six_set_owner(lock, type);
	}

	return ret;
}

bool six_relock_type(struct six_lock *lock, enum six_lock_type type,
		     unsigned seq)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state old;
	u64 v = READ_ONCE(lock->state.v);

	do {
		old.v = v;

		if (old.seq != seq || old.v & l[type].lock_fail)
			return false;
	} while ((v = atomic64_cmpxchg_acquire(&lock->state.counter,
				old.v,
				old.v + l[type].lock_val)) != old.v);

	six_acquire(&lock->dep_map, 1);
	six_set_owner(lock, type);
	return true;
}

struct six_lock_waiter {
	struct list_head	list;
	struct task_struct	*task;
};

/* This is probably up there with the more evil things I've done */
#define waitlist_bitnr(id) ilog2((((union six_lock_state) { .waiters = 1 << (id) }).l))

static inline int six_can_spin_on_owner(struct six_lock *lock)
{
	struct task_struct *owner;
	int retval = 1;

	if (need_resched())
		return 0;

	rcu_read_lock();
	owner = READ_ONCE(lock->owner);
	if (owner)
		retval = owner->on_cpu;
	rcu_read_unlock();
	/*
	 * if lock->owner is not set, the mutex owner may have just acquired
	 * it and not set the owner yet or the mutex has been released.
	 */
	return retval;
}

static bool six_spin_on_owner(struct six_lock *lock, struct task_struct *owner)
{
	bool ret = true;

	rcu_read_lock();
	while (lock->owner == owner) {
		/*
		 * Ensure we emit the owner->on_cpu, dereference _after_
		 * checking lock->owner still matches owner. If that fails,
		 * owner might point to freed memory. If it still matches,
		 * the rcu_read_lock() ensures the memory stays valid.
		 */
		barrier();

		if (!owner->on_cpu || need_resched()) {
			ret = false;
			break;
		}

		cpu_relax();
	}
	rcu_read_unlock();

	return ret;
}

static bool six_optimistic_spin(struct six_lock *lock, enum six_lock_type type)
{
	struct task_struct *task = current;

	if (type == SIX_LOCK_write)
		return false;

	preempt_disable();
	if (!six_can_spin_on_owner(lock))
		goto fail;

	if (!osq_lock(&lock->osq))
		goto fail;

	while (1) {
		struct task_struct *owner;

		/*
		 * If there's an owner, wait for it to either
		 * release the lock or go to sleep.
		 */
		owner = READ_ONCE(lock->owner);
		if (owner && !six_spin_on_owner(lock, owner))
			break;

		if (__six_trylock_type(lock, type)) {
			osq_unlock(&lock->osq);
			preempt_enable();
			return true;
		}

		/*
		 * When there's no owner, we might have preempted between the
		 * owner acquiring the lock and setting the owner field. If
		 * we're an RT task that will live-lock because we won't let
		 * the owner complete.
		 */
		if (!owner && (need_resched() || rt_task(task)))
			break;

		/*
		 * The cpu_relax() call is a compiler barrier which forces
		 * everything in this loop to be re-loaded. We don't need
		 * memory barriers as we'll eventually observe the right
		 * values at the cost of a few extra spins.
		 */
		cpu_relax();
	}

	osq_unlock(&lock->osq);
fail:
	preempt_enable();

	/*
	 * If we fell out of the spin path because of need_resched(),
	 * reschedule now, before we try-lock again. This avoids getting
	 * scheduled out right after we obtained the lock.
	 */
	if (need_resched())
		schedule();

	return false;
}

void six_lock_type(struct six_lock *lock, enum six_lock_type type)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state old, new;
	struct six_lock_waiter wait;
	u64 v;

	six_acquire(&lock->dep_map, 0);

	if (__six_trylock_type(lock, type))
		goto done;

	if (six_optimistic_spin(lock, type))
		goto done;

	lock_contended(&lock->dep_map, _RET_IP_);

	INIT_LIST_HEAD(&wait.list);
	wait.task = current;

	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (list_empty_careful(&wait.list)) {
			raw_spin_lock(&lock->wait_lock);
			list_add_tail(&wait.list, &lock->wait_list[type]);
			raw_spin_unlock(&lock->wait_lock);
		}

		v = READ_ONCE(lock->state.v);
		do {
			new.v = old.v = v;

			if (!(old.v & l[type].lock_fail))
				new.v += l[type].lock_val;
			else if (!(new.waiters & (1 << type)))
				new.waiters |= 1 << type;
			else
				break; /* waiting bit already set */
		} while ((v = atomic64_cmpxchg_acquire(&lock->state.counter,
					old.v, new.v)) != old.v);

		if (!(old.v & l[type].lock_fail))
			break;

		schedule();
	}

	__set_current_state(TASK_RUNNING);

	if (!list_empty_careful(&wait.list)) {
		raw_spin_lock(&lock->wait_lock);
		list_del_init(&wait.list);
		raw_spin_unlock(&lock->wait_lock);
	}
done:
	lock_acquired(&lock->dep_map, _RET_IP_);
	six_set_owner(lock, type);
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

	raw_spin_lock(&lock->wait_lock);

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

	raw_spin_unlock(&lock->wait_lock);
}

void six_unlock_type(struct six_lock *lock, enum six_lock_type type)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state state;

	six_clear_owner(lock, type);

	EBUG_ON(!(lock->state.v & l[type].held_mask));
	EBUG_ON(type == SIX_LOCK_write &&
		!(lock->state.v & __SIX_LOCK_HELD_intent));

	state.v = atomic64_add_return_release(l[type].unlock_val,
					      &lock->state.counter);
	six_release(&lock->dep_map);
	six_lock_wakeup(lock, state, l[type].unlock_wakeup);
}

bool six_trylock_convert(struct six_lock *lock,
			 enum six_lock_type from,
			 enum six_lock_type to)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state old, new;
	u64 v = READ_ONCE(lock->state.v);

	do {
		new.v = old.v = v;
		new.v += l[from].unlock_val;

		if (new.v & l[to].lock_fail)
			return false;
	} while ((v = atomic64_cmpxchg_acquire(&lock->state.counter,
				old.v,
				new.v + l[to].lock_val)) != old.v);

	six_clear_owner(lock, from);
	six_set_owner(lock, to);

	six_lock_wakeup(lock, new, l[from].unlock_wakeup);

	return true;
}

/*
 * Increment read/intent lock count, assuming we already have it read or intent
 * locked:
 */
void six_lock_increment(struct six_lock *lock, enum six_lock_type type)
{
	const struct six_lock_vals l[] = LOCK_VALS;

	EBUG_ON(type == SIX_LOCK_write);
	six_acquire(&lock->dep_map, 0);

	/* XXX: assert already locked, and that we don't overflow: */

	atomic64_add(l[type].lock_val, &lock->state.counter);
}

/* Convert from intent to read: */
void six_lock_downgrade(struct six_lock *lock)
{
	six_lock_increment(lock, SIX_LOCK_read);
	six_unlock_intent(lock);
}
