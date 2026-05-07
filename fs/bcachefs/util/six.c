// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include <linux/export.h>
#include <linux/log2.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/sched/rt.h>
#include <linux/sched/task.h>
#include <linux/slab.h>

#include <trace/events/lock.h>

#include "six.h"
#include "btree/types.h"

#define six_acquire(l, t, r, ip)	lock_acquire(l, 0, t, r, 1, NULL, ip)
#define six_release(l, ip)		lock_release(l, ip)

static void do_six_unlock_type(struct six_lock *lock, enum six_lock_type type);

#define SIX_LOCK_HELD_read_OFFSET	0
#define SIX_LOCK_HELD_read		~(~0U << 26)
#define SIX_LOCK_HELD_intent		(1U << 26)
#define SIX_LOCK_HELD_write		(1U << 27)
#define SIX_LOCK_WAITING_read		(1U << (28 + SIX_LOCK_read))
#define SIX_LOCK_WAITING_write		(1U << (28 + SIX_LOCK_write))
#define SIX_LOCK_NOSPIN			(1U << 31)

struct six_lock_vals {
	/* Value we add to the lock in order to take the lock: */
	u32			lock_val;

	/* If the lock has this value (used as a mask), taking the lock fails: */
	u32			lock_fail;

	/* Mask that indicates lock is held for this type: */
	u32			held_mask;

	/* Waitlist we wakeup when releasing the lock: */
	enum six_lock_type	unlock_wakeup;
};

static const struct six_lock_vals l[] = {
	[SIX_LOCK_read] = {
		.lock_val	= 1U << SIX_LOCK_HELD_read_OFFSET,
		.lock_fail	= SIX_LOCK_HELD_write,
		.held_mask	= SIX_LOCK_HELD_read,
		.unlock_wakeup	= SIX_LOCK_write,
	},
	[SIX_LOCK_intent] = {
		.lock_val	= SIX_LOCK_HELD_intent,
		.lock_fail	= SIX_LOCK_HELD_intent,
		.held_mask	= SIX_LOCK_HELD_intent,
		.unlock_wakeup	= SIX_LOCK_intent,
	},
	[SIX_LOCK_write] = {
		.lock_val	= SIX_LOCK_HELD_write,
		.lock_fail	= SIX_LOCK_HELD_read,
		.held_mask	= SIX_LOCK_HELD_write,
		.unlock_wakeup	= SIX_LOCK_read,
	},
};

static inline void six_set_bitmask(struct six_lock *lock, u32 mask)
{
	if ((atomic_read(&lock->state) & mask) != mask)
		atomic_or(mask, &lock->state);
}

static inline void six_clear_bitmask(struct six_lock *lock, u32 mask)
{
	if (atomic_read(&lock->state) & mask)
		atomic_and(~mask, &lock->state);
}

static inline void six_set_owner(struct six_lock *lock, enum six_lock_type type,
				 u32 old, struct task_struct *owner)
{
	if (type != SIX_LOCK_intent)
		return;

	if (!(old & SIX_LOCK_HELD_intent)) {
		EBUG_ON(lock->owner);
		lock->owner = owner;
	} else {
		EBUG_ON(lock->owner != current);
	}
}

static void six_lock_record_acquire(struct six_lock *lock, enum six_lock_type type)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	if (type == SIX_LOCK_intent)
		bch2_save_backtrace(&lock->owner_stack, current, 1, GFP_ATOMIC);
#endif
}

static inline unsigned pcpu_read_count(struct six_lock *lock)
{
	unsigned read_count = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		read_count += *per_cpu_ptr(lock->readers, cpu);
	return read_count;
}

/*
 * __do_six_trylock() - main trylock routine
 *
 * Returns 1 on success, 0 on failure
 *
 * In percpu reader mode, a failed trylock may cause a spurious trylock failure
 * for anoter thread taking the competing lock type, and we may havve to do a
 * wakeup: when a wakeup is required, we return -1 - wakeup_type.
 */
static int __do_six_trylock(struct six_lock *lock, enum six_lock_type type,
			    struct task_struct *task, bool try)
{
	int ret;
	u32 old;

	EBUG_ON(type == SIX_LOCK_write && lock->owner != task);
	EBUG_ON(type == SIX_LOCK_write &&
		(try != !(atomic_read(&lock->state) & SIX_LOCK_HELD_write)));

	/*
	 * Percpu reader mode:
	 *
	 * The basic idea behind this algorithm is that you can implement a lock
	 * between two threads without any atomics, just memory barriers:
	 *
	 * For two threads you'll need two variables, one variable for "thread a
	 * has the lock" and another for "thread b has the lock".
	 *
	 * To take the lock, a thread sets its variable indicating that it holds
	 * the lock, then issues a full memory barrier, then reads from the
	 * other thread's variable to check if the other thread thinks it has
	 * the lock. If we raced, we backoff and retry/sleep.
	 *
	 * Failure to take the lock may cause a spurious trylock failure in
	 * another thread, because we temporarily set the lock to indicate that
	 * we held it. This would be a problem for a thread in six_lock(), when
	 * they are calling trylock after adding themself to the waitlist and
	 * prior to sleeping.
	 *
	 * Therefore, if we fail to get the lock, and there were waiters of the
	 * type we conflict with, we will have to issue a wakeup.
	 *
	 * Since we may be called under wait_lock (and by the wakeup code
	 * itself), we return that the wakeup has to be done instead of doing it
	 * here.
	 */
	if (type == SIX_LOCK_read && lock->readers) {
		scoped_guard(preempt) {
			this_cpu_inc(*lock->readers); /* signal that we own lock */

			smp_mb();

			old = atomic_read(&lock->state);
			ret = !(old & l[type].lock_fail);

			this_cpu_sub(*lock->readers, !ret);
		}

		if (!ret) {
			smp_mb();
			if (atomic_read(&lock->state) & SIX_LOCK_WAITING_write)
				ret = -1 - SIX_LOCK_write;
		}
	} else if (type == SIX_LOCK_write && lock->readers) {
		if (try)
			atomic_add(SIX_LOCK_HELD_write, &lock->state);

		/*
		 * Make sure atomic_add happens before pcpu_read_count and
		 * six_set_bitmask in slow path happens before pcpu_read_count.
		 *
		 * Paired with the smp_mb() in read lock fast path (per-cpu mode)
		 * and the one before atomic_read in read unlock path.
		 */
		smp_mb();
		ret = !pcpu_read_count(lock);

		if (try && !ret) {
			old = atomic_sub_return(SIX_LOCK_HELD_write, &lock->state);
			if (old & SIX_LOCK_WAITING_read)
				ret = -1 - SIX_LOCK_read;
		}
	} else {
		old = atomic_read(&lock->state);
		do {
			ret = !(old & l[type].lock_fail);
			if (!ret || (type == SIX_LOCK_write && !try)) {
				smp_mb();
				break;
			}
		} while (!atomic_try_cmpxchg_acquire(&lock->state, &old, old + l[type].lock_val));

		EBUG_ON(ret && !(atomic_read(&lock->state) & l[type].held_mask));
	}

	if (ret > 0)
		six_set_owner(lock, type, old, task);

	EBUG_ON(type == SIX_LOCK_write && try && ret <= 0 &&
		(atomic_read(&lock->state) & SIX_LOCK_HELD_write));

	return ret;
}

/*
 * Trim @nr while the tail is all tombstones. Clamp hint inside [0, nr].
 * Caller must hold wait_lock.
 */
static inline void six_lock_wait_fifo_shrink(struct six_lock_wait_fifo *wf)
{
	while (wf->nr > 0 && !wf->data[wf->nr - 1].w)
		wf->nr--;
	if (wf->next_free_hint > wf->nr)
		wf->next_free_hint = wf->nr;
}

/*
 * Null out the entry at @idx and update the free-slot hint. Caller must hold
 * wait_lock. Does not shrink @nr — that's done lazily by the caller when
 * convenient (e.g. at the end of a wakeup scan).
 */
static inline void six_lock_wait_fifo_remove(struct six_lock_wait_fifo *wf, u16 idx)
{
	wf->data[idx].w = NULL;
	if (idx < wf->next_free_hint)
		wf->next_free_hint = idx;
}

/*
 * Find a free slot (starting from @next_free_hint) and write the entry.
 * Returns 0 on success, -ENOMEM if the list is full.
 * Caller must hold wait_lock.
 */
static inline int six_lock_wait_fifo_insert(struct six_lock_wait_fifo *wf,
					    struct six_lock_waiter *wait)
{
	u16 i;

	for (i = wf->next_free_hint; i < wf->nr; i++) {
		if (!wf->data[i].w)
			goto fill;
	}

	if (wf->nr < wf->size) {
		i = wf->nr++;
		goto fill;
	}

	return -ENOMEM;
fill:
	wf->data[i].w		= wait;
	wf->data[i].start_time	= (wait->trans_start_time << SIX_LOCK_WANT_BITS) |
				  ((u8) wait->lock_want & SIX_LOCK_WANT_MASK);
	wait->slot_idx		= i;
	wf->next_free_hint	= i + 1;
	return 0;
}

/*
 * Wake the single matching waiter with the smallest start_time (oldest
 * transaction). On release, only that slot is nulled — the rest of the list
 * remains stable from the lockless cycle detector's perspective.
 *
 * For reads: wake all matching waiters, same start-time ordering isn't
 * relevant since readers don't conflict with each other.
 */
static void __six_lock_wakeup(struct six_lock *lock, enum six_lock_type lock_type)
{
	struct six_lock_wait_slot *slot;
	struct task_struct *task;
	int ret;
again:
	ret = 0;
	raw_spin_lock(&lock->wait_lock);
	struct six_lock_wait_fifo *wf = rcu_dereference_protected(lock->wait_fifo,
						lockdep_is_held(&lock->wait_lock));

	if (lock_type == SIX_LOCK_read) {
		/* Readers don't conflict: wake all matching waiters. */
		for (u16 i = 0; i < wf->nr; i++) {
			slot = &wf->data[i];
			if (!slot->w ||
			    (slot->start_time & SIX_LOCK_WANT_MASK) != lock_type)
				continue;

			ret = __do_six_trylock(lock, lock_type, slot->w->task, false);
			if (ret <= 0)
				goto unlock;

			/*
			 * Similar to percpu_rwsem_wake_function(), we need to
			 * guard against the wakee noticing w->lock_acquired,
			 * returning, and then exiting before we do the wakeup:
			 */
			struct six_lock_waiter *w = slot->w;
			task = get_task_struct(w->task);
			six_lock_wait_fifo_remove(wf, i);
			/*
			 * Release barrier orders the slot clear before
			 * setting w->lock_acquired; @w is on the stack of the
			 * waiting thread and will be reused after it sees
			 * w->lock_acquired with no other locking: pairs with
			 * smp_load_acquire() in six_lock_slowpath()
			 */
			smp_store_release(&w->lock_acquired, true);
			wake_up_process(task);
			put_task_struct(task);
		}
	} else {
		/*
		 * Intent/write locks have a single holder: prefer the waiter
		 * whose transaction started earliest. start_time is cached in
		 * the slot so the scan doesn't deref each waiter.
		 */
		struct six_lock_wait_slot *oldest = NULL;
		u16 oldest_iter = 0;
		unsigned n_matches = 0;

		for (u16 i = 0; i < wf->nr; i++) {
			slot = &wf->data[i];
			if (!slot->w ||
			    (slot->start_time & SIX_LOCK_WANT_MASK) != lock_type)
				continue;
			n_matches++;
			if (!oldest ||
			    time_before64(slot->start_time, oldest->start_time)) {
				oldest = slot;
				oldest_iter = i;
			}
		}

		if (oldest) {
			ret = __do_six_trylock(lock, lock_type, oldest->w->task, false);
			if (ret <= 0)
				goto unlock;

			struct six_lock_waiter *w = oldest->w;
			task = get_task_struct(w->task);
			six_lock_wait_fifo_remove(wf, oldest_iter);
			smp_store_release(&w->lock_acquired, true);
			wake_up_process(task);
			put_task_struct(task);

			/*
			 * More non-read waiters still queued: leave the
			 * WAITING bit set so the next unlock re-enters
			 * __six_lock_wakeup and serves them.
			 */
			if (n_matches > 1)
				goto unlock;
		}
	}

	six_clear_bitmask(lock, SIX_LOCK_WAITING_read << lock_type);
unlock:
	six_lock_wait_fifo_shrink(wf);
	raw_spin_unlock(&lock->wait_lock);

	if (ret < 0) {
		lock_type = -ret - 1;
		goto again;
	}
}

__always_inline
static void six_lock_wakeup(struct six_lock *lock, u32 state,
			    enum six_lock_type lock_type)
{
	if (lock_type == SIX_LOCK_write && (state & SIX_LOCK_HELD_read))
		return;

	if (!(state & (SIX_LOCK_WAITING_read << lock_type)))
		return;

	__six_lock_wakeup(lock, lock_type);
}

__always_inline
static bool do_six_trylock(struct six_lock *lock, enum six_lock_type type, bool try)
{
	int ret;

	ret = __do_six_trylock(lock, type, current, try);
	if (ret < 0)
		__six_lock_wakeup(lock, -ret - 1);

	return ret > 0;
}

/**
 * six_trylock_ip - attempt to take a six lock without blocking
 * @lock:	lock to take
 * @type:	SIX_LOCK_read, SIX_LOCK_intent, or SIX_LOCK_write
 * @ip:		ip parameter for lockdep/lockstat, i.e. _THIS_IP_
 *
 * Return: true on success, false on failure.
 */
bool six_trylock_ip(struct six_lock *lock, enum six_lock_type type, unsigned long ip)
{
	if (!do_six_trylock(lock, type, true))
		return false;

	if (type != SIX_LOCK_write)
		six_acquire(&lock->dep_map, 1, type == SIX_LOCK_read, ip);
	six_lock_record_acquire(lock, type);
	return true;
}
EXPORT_SYMBOL_GPL(six_trylock_ip);

/**
 * six_relock_ip - attempt to re-take a lock that was held previously
 * @lock:	lock to take
 * @type:	SIX_LOCK_read, SIX_LOCK_intent, or SIX_LOCK_write
 * @seq:	lock sequence number obtained from six_lock_seq() while lock was
 *		held previously
 * @ip:		ip parameter for lockdep/lockstat, i.e. _THIS_IP_
 *
 * Return: true on success, false on failure.
 */
bool six_relock_ip(struct six_lock *lock, enum six_lock_type type,
		   unsigned seq, unsigned long ip)
{
	if (six_lock_seq(lock) != seq || !six_trylock_ip(lock, type, ip))
		return false;

	if (six_lock_seq(lock) != seq) {
		six_unlock_ip(lock, type, ip);
		return false;
	}

	return true;
}
EXPORT_SYMBOL_GPL(six_relock_ip);

#ifdef CONFIG_BCACHEFS_SIX_OPTIMISTIC_SPIN

static inline bool six_owner_running(struct six_lock *lock)
{
	/*
	 * When there's no owner, we might have preempted between the owner
	 * acquiring the lock and setting the owner field. If we're an RT task
	 * that will live-lock because we won't let the owner complete.
	 */
	guard(rcu)();
	struct task_struct *owner = READ_ONCE(lock->owner);
	return owner ? owner_on_cpu(owner) : !rt_or_dl_task(current);
}

static inline bool six_optimistic_spin(struct six_lock *lock,
				       struct six_lock_waiter *wait,
				       enum six_lock_type type)
{
	unsigned loop = 0;
	u64 end_time;

	if (type == SIX_LOCK_write)
		return false;

	scoped_guard(rcu) {
		struct six_lock_wait_fifo *wf = rcu_dereference(lock->wait_fifo);
		/*
		 * Only spin if we're the sole entry in the wait list. Anything
		 * more and someone older might get woken ahead of us.
		 */
		if (wf->nr != 1 || wf->data[0].w != wait)
			return false;
	}

	if (atomic_read(&lock->state) & SIX_LOCK_NOSPIN)
		return false;

	guard(preempt)();
	end_time = sched_clock() + 10 * NSEC_PER_USEC;

	while (!need_resched() && six_owner_running(lock)) {
		/*
		 * Ensures that writes to the waitlist entry happen after we see
		 * wait->lock_acquired: pairs with the smp_store_release in
		 * __six_lock_wakeup
		 */
		if (smp_load_acquire(&wait->lock_acquired))
			return true;

		if (!(++loop & 0xf) && (time_after64(sched_clock(), end_time))) {
			six_set_bitmask(lock, SIX_LOCK_NOSPIN);
			break;
		}

		/*
		 * The cpu_relax() call is a compiler barrier which forces
		 * everything in this loop to be re-loaded. We don't need
		 * memory barriers as we'll eventually observe the right
		 * values at the cost of a few extra spins.
		 */
		cpu_relax();
	}

	return false;
}

#else /* CONFIG_LOCK_SPIN_ON_OWNER */

static inline bool six_optimistic_spin(struct six_lock *lock,
				       struct six_lock_waiter *wait,
				       enum six_lock_type type)
{
	return false;
}

#endif

noinline
static struct six_lock_wait_fifo *alloc_wait_fifo(struct six_lock *lock, u16 *new_size)
{
	struct six_lock_wait_fifo *wf = rcu_dereference_protected(lock->wait_fifo, true);
	unsigned old_size = READ_ONCE(wf->size);

	if (old_size >= (1 << 15))
		return NULL;

	*new_size = old_size * 2;
	return kzalloc(struct_size(wf, data, *new_size), GFP_KERNEL);
}

noinline
static int six_lock_slowpath(struct six_lock *lock, enum six_lock_type type,
			     struct six_lock_waiter *wait,
			     six_lock_should_sleep_fn should_sleep_fn,
			     unsigned long ip)
{
	struct six_lock_wait_fifo *new_wf = NULL;
	struct six_lock_wait_fifo *old_wf = NULL;
	int ret = 0;

	if (type == SIX_LOCK_write) {
		EBUG_ON(atomic_read(&lock->state) & SIX_LOCK_HELD_write);
		atomic_add(SIX_LOCK_HELD_write, &lock->state);
		smp_mb__after_atomic();
	}

	trace_contention_begin(lock, 0);
	lock_contended(&lock->dep_map, ip);

	wait->task		= current;
	wait->lock_want		= type;
	wait->lock_acquired	= false;

	u16 new_size = 0;
	{
		struct six_lock_wait_fifo *peek = rcu_dereference_protected(lock->wait_fifo, true);
		if (unlikely(peek->nr == peek->size))
			new_wf = alloc_wait_fifo(lock, &new_size);
	}

	raw_spin_lock(&lock->wait_lock);
	struct six_lock_wait_fifo *wf = rcu_dereference_protected(lock->wait_fifo,
						lockdep_is_held(&lock->wait_lock));

	if (unlikely(new_wf) && new_size == wf->size * 2) {
		new_wf->size		= new_size;
		new_wf->nr		= wf->nr;
		new_wf->next_free_hint	= wf->next_free_hint;

		memcpy(new_wf->data, wf->data, wf->nr * sizeof(wf->data[0]));

		rcu_assign_pointer(lock->wait_fifo, new_wf);
		old_wf = wf;
		wf = new_wf;
		new_wf = NULL;
	}

	/*
	 * Retry taking the lock after taking waitlist lock, in case we raced
	 * with an unlock:
	 */
	six_set_bitmask(lock, SIX_LOCK_WAITING_read << type);
	ret = __do_six_trylock(lock, type, current, false);
	if (ret <= 0) {
		wait->start_time = local_clock();

		if (six_lock_wait_fifo_insert(wf, wait)) {
			raw_spin_unlock(&lock->wait_lock);
			if (type == SIX_LOCK_write) {
				six_clear_bitmask(lock, SIX_LOCK_HELD_write);
				six_lock_wakeup(lock, atomic_read(&lock->state), SIX_LOCK_read);
			}
			ret = -ENOMEM;
			goto out;
		}
	}
	raw_spin_unlock(&lock->wait_lock);

	if (unlikely(ret > 0)) {
		ret = 0;
		goto out;
	}

	if (unlikely(ret < 0)) {
		__six_lock_wakeup(lock, -ret - 1);
		ret = 0;
	}

	if (six_optimistic_spin(lock, wait, type) ||
	    smp_load_acquire(&wait->lock_acquired))
		goto out;

	/* Yield before running the cycle detector: */
	schedule();

	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);

		/*
		 * Ensures that writes to the waitlist entry happen after we see
		 * wait->lock_acquired: pairs with the smp_store_release in
		 * __six_lock_wakeup
		 */
		if (smp_load_acquire(&wait->lock_acquired))
			break;

		ret = should_sleep_fn ? should_sleep_fn(lock, wait) : 0;
		if (unlikely(ret)) {
			/*
			 * If should_sleep_fn() returns an error, we are
			 * required to return that error even if we already
			 * acquired the lock - should_sleep_fn() might have
			 * modified external state (e.g. when the deadlock cycle
			 * detector in bcachefs issued a transaction restart)
			 */
			raw_spin_lock(&lock->wait_lock);
			bool acquired = wait->lock_acquired;
			if (!acquired) {
				struct six_lock_wait_fifo *wf = rcu_dereference_protected(
					lock->wait_fifo, lockdep_is_held(&lock->wait_lock));

				six_lock_wait_fifo_remove(wf, wait->slot_idx);
				six_lock_wait_fifo_shrink(wf);
			}
			raw_spin_unlock(&lock->wait_lock);

			if (unlikely(acquired)) {
				do_six_unlock_type(lock, type);
			} else if (type == SIX_LOCK_write) {
				six_clear_bitmask(lock, SIX_LOCK_HELD_write);
				six_lock_wakeup(lock, atomic_read(&lock->state), SIX_LOCK_read);
			}
			break;
		}

		schedule();
	}

	__set_current_state(TASK_RUNNING);
out:
	/*
	 * Free any heap-allocated wait_fifos: new_wf if we lost the grow
	 * race (either another thread grew first, or we bailed out on a
	 * re-check of fifo_full before swapping it in), and old_wf if we
	 * successfully swapped. Centralized here so every goto-out path
	 * is covered — the earlier -ENOMEM path in particular used to
	 * leak new_wf on the grow-race-then-still-full code path.
	 */
	if (old_wf && old_wf != (struct six_lock_wait_fifo *) &lock->inline_fifo)
		kfree_rcu_mightsleep(old_wf);
	kfree(new_wf);

	trace_contention_end(lock, 0);

	return ret;
}

/**
 * six_lock_ip_waiter - take a lock, with full waitlist interface
 * @lock:	lock to take
 * @type:	SIX_LOCK_read, SIX_LOCK_intent, or SIX_LOCK_write
 * @wait:	pointer to wait object, which will be added to lock's waitlist
 * @should_sleep_fn: callback run after adding to waitlist, immediately prior
 *		to scheduling
 * @p:		passed through to @should_sleep_fn
 * @ip:		ip parameter for lockdep/lockstat, i.e. _THIS_IP_
 *
 * This is the most general six_lock() variant, with parameters to support full
 * cycle detection for deadlock avoidance.
 *
 * The code calling this function must implement tracking of held locks, and the
 * @wait object should be embedded into the struct that tracks held locks -
 * which must also be accessible in a thread-safe way.
 *
 * @should_sleep_fn should invoke the cycle detector; it should walk each
 * lock's waiters, and for each waiter recursively walk their held locks.
 *
 * When this function must block, @wait will be added to @lock's waitlist before
 * calling trylock, and before calling @should_sleep_fn, and @wait will not be
 * removed from the lock waitlist until the lock has been successfully acquired,
 * or we abort.
 *
 * @wait.start_time will be monotonically increasing for any given waitlist, and
 * thus may be used as a loop cursor.
 *
 * Return: 0 on success, or the return code from @should_sleep_fn on failure.
 */
int six_lock_ip_waiter(struct six_lock *lock, enum six_lock_type type,
		       struct six_lock_waiter *wait,
		       six_lock_should_sleep_fn should_sleep_fn,
		       unsigned long ip)
{
	int ret;

	wait->start_time = 0;

	if (type != SIX_LOCK_write)
		six_acquire(&lock->dep_map, 0, type == SIX_LOCK_read, ip);

	ret = do_six_trylock(lock, type, true) ? 0
		: six_lock_slowpath(lock, type, wait, should_sleep_fn, ip);

	if (ret && type != SIX_LOCK_write)
		six_release(&lock->dep_map, ip);
	if (!ret) {
		lock_acquired(&lock->dep_map, ip);
		six_lock_record_acquire(lock, type);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(six_lock_ip_waiter);

__always_inline
static void do_six_unlock_type(struct six_lock *lock, enum six_lock_type type)
{
	u32 state;

	if (type == SIX_LOCK_intent)
		lock->owner = NULL;

	if (type == SIX_LOCK_read &&
	    lock->readers) {
		smp_mb(); /* unlock barrier */
		this_cpu_dec(*lock->readers);
		smp_mb(); /* between unlocking and checking for waiters */
		state = atomic_read(&lock->state);
	} else {
		u32 v = l[type].lock_val;

		if (type != SIX_LOCK_read)
			v += atomic_read(&lock->state) & SIX_LOCK_NOSPIN;

		EBUG_ON(!(atomic_read(&lock->state) & l[type].held_mask));
		state = atomic_sub_return_release(v, &lock->state);
	}

	six_lock_wakeup(lock, state, l[type].unlock_wakeup);
}

/**
 * six_unlock_ip - drop a six lock
 * @lock:	lock to unlock
 * @type:	SIX_LOCK_read, SIX_LOCK_intent, or SIX_LOCK_write
 * @ip:		ip parameter for lockdep/lockstat, i.e. _THIS_IP_
 *
 * When a lock is held multiple times (because six_lock_incement()) was used),
 * this decrements the 'lock held' counter by one.
 *
 * For example:
 * six_lock_read(&foo->lock);				read count 1
 * six_lock_increment(&foo->lock, SIX_LOCK_read);	read count 2
 * six_lock_unlock(&foo->lock, SIX_LOCK_read);		read count 1
 * six_lock_unlock(&foo->lock, SIX_LOCK_read);		read count 0
 */
void six_unlock_ip(struct six_lock *lock, enum six_lock_type type, unsigned long ip)
{
	EBUG_ON(type == SIX_LOCK_write &&
		!(atomic_read(&lock->state) & SIX_LOCK_HELD_intent));
	EBUG_ON((type == SIX_LOCK_write ||
		 type == SIX_LOCK_intent) &&
		lock->owner != current);

	if (type != SIX_LOCK_write)
		six_release(&lock->dep_map, ip);

	if (type == SIX_LOCK_intent &&
	    lock->intent_lock_recurse) {
		--lock->intent_lock_recurse;
		return;
	}

	if (type == SIX_LOCK_write &&
	    lock->write_lock_recurse) {
		--lock->write_lock_recurse;
		return;
	}

	if (type == SIX_LOCK_write)
		lock->seq++;

	do_six_unlock_type(lock, type);
}
EXPORT_SYMBOL_GPL(six_unlock_ip);

/**
 * six_lock_downgrade - convert an intent lock to a read lock
 * @lock:	lock to dowgrade
 *
 * @lock will have read count incremented and intent count decremented
 */
void six_lock_downgrade(struct six_lock *lock)
{
	six_lock_increment(lock, SIX_LOCK_read);
	six_unlock_intent(lock);
}
EXPORT_SYMBOL_GPL(six_lock_downgrade);

/**
 * six_lock_tryupgrade - attempt to convert read lock to an intent lock
 * @lock:	lock to upgrade
 *
 * On success, @lock will have intent count incremented and read count
 * decremented
 *
 * Return: true on success, false on failure
 */
bool six_lock_tryupgrade(struct six_lock *lock)
{
	u32 old = atomic_read(&lock->state), new;

	do {
		new = old;

		if (new & SIX_LOCK_HELD_intent)
			return false;

		if (!lock->readers) {
			EBUG_ON(!(new & SIX_LOCK_HELD_read));
			new -= l[SIX_LOCK_read].lock_val;
		}

		new |= SIX_LOCK_HELD_intent;
	} while (!atomic_try_cmpxchg_acquire(&lock->state, &old, new));

	if (lock->readers)
		this_cpu_dec(*lock->readers);

	six_set_owner(lock, SIX_LOCK_intent, old, current);

	return true;
}
EXPORT_SYMBOL_GPL(six_lock_tryupgrade);

/**
 * six_trylock_convert - attempt to convert a held lock from one type to another
 * @lock:	lock to upgrade
 * @from:	SIX_LOCK_read or SIX_LOCK_intent
 * @to:		SIX_LOCK_read or SIX_LOCK_intent
 *
 * On success, @lock will have intent count incremented and read count
 * decremented
 *
 * Return: true on success, false on failure
 */
bool six_trylock_convert(struct six_lock *lock,
			 enum six_lock_type from,
			 enum six_lock_type to)
{
	EBUG_ON(to == SIX_LOCK_write || from == SIX_LOCK_write);

	if (to == from)
		return true;

	if (to == SIX_LOCK_read) {
		six_lock_downgrade(lock);
		return true;
	} else {
		return six_lock_tryupgrade(lock);
	}
}
EXPORT_SYMBOL_GPL(six_trylock_convert);

/**
 * six_lock_increment - increase held lock count on a lock that is already held
 * @lock:	lock to increment
 * @type:	SIX_LOCK_read or SIX_LOCK_intent
 *
 * @lock must already be held, with a lock type that is greater than or equal to
 * @type
 *
 * A corresponding six_unlock_type() call will be required for @lock to be fully
 * unlocked.
 */
void six_lock_increment(struct six_lock *lock, enum six_lock_type type)
{
	six_acquire(&lock->dep_map, 0, type == SIX_LOCK_read, _RET_IP_);

	/* XXX: assert already locked, and that we don't overflow: */

	switch (type) {
	case SIX_LOCK_read:
		if (lock->readers) {
			this_cpu_inc(*lock->readers);
		} else {
			EBUG_ON(!(atomic_read(&lock->state) &
				  (SIX_LOCK_HELD_read|
				   SIX_LOCK_HELD_intent)));
			atomic_add(l[type].lock_val, &lock->state);
		}
		break;
	case SIX_LOCK_write:
		lock->write_lock_recurse++;
		fallthrough;
	case SIX_LOCK_intent:
		EBUG_ON(!(atomic_read(&lock->state) & SIX_LOCK_HELD_intent));
		lock->intent_lock_recurse++;
		break;
	}
}
EXPORT_SYMBOL_GPL(six_lock_increment);

/**
 * six_lock_wakeup_all - wake up all waiters on @lock
 * @lock:	lock to wake up waiters for
 *
 * Wakeing up waiters will cause them to re-run should_sleep_fn, which may then
 * abort the lock operation.
 *
 * This function is never needed in a bug-free program; it's only useful in
 * debug code, e.g. to determine if a cycle detector is at fault.
 */
void six_lock_wakeup_all(struct six_lock *lock)
{
	u32 state = atomic_read(&lock->state);

	/*
	 * First, run the normal wakeup machinery for any waiters the lock
	 * state actually permits to acquire: those slots get removed by
	 * __six_lock_wakeup and lock_acquired is set on the waiter.
	 */
	six_lock_wakeup(lock, state, SIX_LOCK_read);
	six_lock_wakeup(lock, state, SIX_LOCK_intent);
	six_lock_wakeup(lock, state, SIX_LOCK_write);

	/*
	 * Then wake any remaining waiters without removing their slots:
	 * lock_acquired stays clear, so they'll re-run should_sleep_fn in
	 * six_lock_slowpath() and self-remove via wait->slot_idx if it
	 * returns an error. Removing here would corrupt that self-remove.
	 */
	raw_spin_lock(&lock->wait_lock);
	struct six_lock_wait_fifo *wf = rcu_dereference_protected(lock->wait_fifo,
						lockdep_is_held(&lock->wait_lock));
	for (u16 i = 0; i < wf->nr; i++)
		if (wf->data[i].w)
			wake_up_process(wf->data[i].w->task);
	raw_spin_unlock(&lock->wait_lock);
}
EXPORT_SYMBOL_GPL(six_lock_wakeup_all);

/**
 * six_lock_counts - return held lock counts, for each lock type
 * @lock:	lock to return counters for
 *
 * Return: the number of times a lock is held for read, intent and write.
 */
struct six_lock_count six_lock_counts(struct six_lock *lock)
{
	struct six_lock_count ret;

	ret.n[SIX_LOCK_read]	= !lock->readers
		? atomic_read(&lock->state) & SIX_LOCK_HELD_read
		: pcpu_read_count(lock);
	ret.n[SIX_LOCK_intent]	= !!(atomic_read(&lock->state) & SIX_LOCK_HELD_intent) +
		lock->intent_lock_recurse;
	ret.n[SIX_LOCK_write]	= !!(atomic_read(&lock->state) & SIX_LOCK_HELD_write);

	return ret;
}
EXPORT_SYMBOL_GPL(six_lock_counts);

/**
 * six_lock_readers_add - directly manipulate reader count of a lock
 * @lock:	lock to add/subtract readers for
 * @nr:		reader count to add/subtract
 *
 * When an upper layer is implementing lock reentrency, we may have both read
 * and intent locks on the same lock.
 *
 * When we need to take a write lock, the read locks will cause self-deadlock,
 * because six locks themselves do not track which read locks are held by the
 * current thread and which are held by a different thread - it does no
 * per-thread tracking of held locks.
 *
 * The upper layer that is tracking held locks may however, if trylock() has
 * failed, count up its own read locks, subtract them, take the write lock, and
 * then re-add them.
 *
 * As in any other situation when taking a write lock, @lock must be held for
 * intent one (or more) times, so @lock will never be left unlocked.
 */
void six_lock_readers_add(struct six_lock *lock, int nr)
{
	if (lock->readers) {
		this_cpu_add(*lock->readers, nr);
	} else {
		EBUG_ON((int) (atomic_read(&lock->state) & SIX_LOCK_HELD_read) + nr < 0);
		/* reader count starts at bit 0 */
		atomic_add(nr, &lock->state);
	}
}
EXPORT_SYMBOL_GPL(six_lock_readers_add);

/**
 * six_lock_exit - release resources held by a lock prior to freeing
 * @lock:	lock to exit
 *
 * When a lock was initialized in percpu mode (SIX_OLCK_INIT_PCPU), this is
 * required to free the percpu read counts.
 */
void six_lock_exit(struct six_lock *lock)
{
	WARN_ON(lock->readers && pcpu_read_count(lock));
	WARN_ON(atomic_read(&lock->state) & SIX_LOCK_HELD_read);

	free_percpu(lock->readers);
	lock->readers = NULL;

	struct six_lock_wait_fifo *wf = rcu_dereference_protected(lock->wait_fifo, true);
	if (wf != (struct six_lock_wait_fifo *) &lock->inline_fifo)
		kfree(wf);
	RCU_INIT_POINTER(lock->wait_fifo, NULL);
#ifdef CONFIG_BCACHEFS_DEBUG
	darray_exit(&lock->owner_stack);
#endif
}
EXPORT_SYMBOL_GPL(six_lock_exit);

void __six_lock_init(struct six_lock *lock, const char *name,
		     struct lock_class_key *key, enum six_lock_init_flags flags,
		     gfp_t gfp)
{
	atomic_set(&lock->state, 0);
	raw_spin_lock_init(&lock->wait_lock);
	lock->inline_fifo.size		= ARRAY_SIZE(lock->inline_fifo.data);
	lock->inline_fifo.nr		= 0;
	lock->inline_fifo.next_free_hint = 0;
	RCU_INIT_POINTER(lock->wait_fifo,
			 (struct six_lock_wait_fifo *) &lock->inline_fifo);
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	debug_check_no_locks_freed((void *) lock, sizeof(*lock));
	lockdep_init_map(&lock->dep_map, name, key, 0);
#endif

	/*
	 * Don't assume that we have real percpu variables available in
	 * userspace:
	 */
#ifdef __KERNEL__
	if (flags & SIX_LOCK_INIT_PCPU) {
		/*
		 * We don't return an error here on memory allocation failure
		 * since percpu is an optimization, and locks will work with the
		 * same semantics in non-percpu mode: callers can check for
		 * failure if they wish by checking lock->readers, but generally
		 * will not want to treat it as an error.
		 */
		lock->readers = alloc_percpu_gfp(unsigned, gfp);
	}
#endif
}
EXPORT_SYMBOL_GPL(__six_lock_init);
