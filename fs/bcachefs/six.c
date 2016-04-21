
#include "linux/lockdep.h"

#include "six.h"

#define six_acquire(l, t)	lock_acquire(l, 0, t, 0, 0, NULL, _RET_IP_)
#define six_release(l)		lock_release(l, 0, _RET_IP_)

/* Number of times to trylock() before sleeping in six_lock(): */
#define SIX_LOCK_SPIN_COUNT		1

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
	u64 v = lock->state.v;

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
	u64 v = lock->state.v;

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

void six_lock_type(struct six_lock *lock, enum six_lock_type type)
{
	const struct six_lock_vals l[] = LOCK_VALS;
	union six_lock_state old, new;
	struct six_lock_waiter wait;
	unsigned i;
	u64 v;

	six_acquire(&lock->dep_map, 0);

	for (i = 0; i < SIX_LOCK_SPIN_COUNT; i++) {
		if (__six_trylock_type(lock, type))
			goto done;
		cpu_relax();
	}

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

		v = lock->state.v;
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

	lock_acquired(&lock->dep_map, _RET_IP_);
done:
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
	u64 v = lock->state.v;

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
