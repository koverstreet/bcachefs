// SPDX-License-Identifier: GPL-2.0
/*
 * Asynchronous refcounty things
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "closure.h"
#include <linux/debugfs.h>
#include <linux/export.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/sched/debug.h>

static void closure_val_checks(struct closure *cl, unsigned new, int d)
{
	unsigned count = new & CLOSURE_REMAINING_MASK;

	if (WARN(new & CLOSURE_GUARD_MASK,
		 "closure %ps has guard bits set: %x (%u), delta %i",
		 cl->fn,
		 new, (unsigned) __fls(new & CLOSURE_GUARD_MASK), d))
		new &= ~CLOSURE_GUARD_MASK;

	WARN(!count && (new & ~(CLOSURE_DESTRUCTOR|CLOSURE_SLEEPING)),
	     "closure %ps ref hit 0 with incorrect flags set: %x (%u)",
	     cl->fn,
	     new, (unsigned) __fls(new));
}

enum new_closure_state {
	CLOSURE_normal_put,
	CLOSURE_requeue,
	CLOSURE_done,
};

/* For clearing flags with the same atomic op as a put */
void bch2_closure_sub(struct closure *cl, int v)
{
	enum new_closure_state s;
	struct task_struct *sleeper;

	/* rcu_read_lock, atomic_read_acquire() are both for cl->sleeper: */
	guard(rcu)();

	int old = atomic_read_acquire(&cl->remaining), new;
	do {
		new = old - v;

		if (new & CLOSURE_REMAINING_MASK) {
			s = CLOSURE_normal_put;
		} else {
			if ((cl->fn || (new & CLOSURE_SLEEPING)) &&
			    !(new & CLOSURE_DESTRUCTOR)) {
				s = CLOSURE_requeue;
				new += CLOSURE_REMAINING_INITIALIZER;
			} else
				s = CLOSURE_done;

			sleeper = new & CLOSURE_SLEEPING ? cl->sleeper : NULL;
			new &= ~CLOSURE_SLEEPING;
		}

		closure_val_checks(cl, new, -v);
	} while (!atomic_try_cmpxchg_release(&cl->remaining, &old, new));

	if (s == CLOSURE_normal_put)
		return;

	if (sleeper) {
		smp_mb();
		wake_up_process(sleeper);
		return;
	}

	if (s == CLOSURE_requeue) {
		closure_queue(cl);
	} else {
		struct closure *parent = cl->parent;
		closure_fn *destructor = cl->fn;

		closure_debug_destroy(cl);

		if (destructor)
			destructor(&cl->work);

		if (parent)
			closure_put(parent);
	}
}

/*
 * closure_wake_up - wake up all closures on a wait list, without memory barrier
 */
void __bch2_closure_wake_up(struct closure_waitlist *wait_list)
{
	struct llist_node *list;
	struct closure *cl, *t;
	struct llist_node *reverse = NULL;

	list = llist_del_all(&wait_list->list);

	/* We first reverse the list to preserve FIFO ordering and fairness */
	reverse = llist_reverse_order(list);

	/* Then do the wakeups */
	llist_for_each_entry_safe(cl, t, reverse, list) {
		closure_set_waiting(cl, 0);
		bch2_closure_sub(cl, CLOSURE_WAITING + 1);
	}
}

/**
 * closure_wait - add a closure to a waitlist
 * @waitlist: will own a ref on @cl, which will be released when
 * closure_wake_up() is called on @waitlist.
 * @cl: closure pointer.
 *
 */
bool bch2_closure_wait(struct closure_waitlist *waitlist, struct closure *cl)
{
	if (atomic_read(&cl->remaining) & CLOSURE_WAITING)
		return false;

	closure_set_waiting(cl, _RET_IP_);
	unsigned r = atomic_add_return(CLOSURE_WAITING + 1, &cl->remaining);
	closure_val_checks(cl, r, CLOSURE_WAITING + 1);

	llist_add(&cl->list, &waitlist->list);

	return true;
}

void __sched __bch2_closure_sync(struct closure *cl)
{
	cl->sleeper = current;
	bch2_closure_sub(cl,
		    CLOSURE_REMAINING_INITIALIZER -
		    CLOSURE_SLEEPING);

	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (!(atomic_read(&cl->remaining) & CLOSURE_SLEEPING))
			break;
		schedule();
	}

	__set_current_state(TASK_RUNNING);
}

/*
 * closure_return_sync - finish running a closure, synchronously (i.e. waiting
 * for outstanding get()s to finish) and returning once closure refcount is 0.
 *
 * Unlike closure_sync() this doesn't reinit the ref to 1; subsequent
 * closure_get_not_zero() calls will fail.
 */
void __sched bch2_closure_return_sync(struct closure *cl)
{
	cl->sleeper = current;
	bch2_closure_sub(cl,
		    CLOSURE_REMAINING_INITIALIZER -
		    CLOSURE_DESTRUCTOR -
		    CLOSURE_SLEEPING);

	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (!(atomic_read(&cl->remaining) & CLOSURE_SLEEPING))
			break;
		schedule();
	}

	__set_current_state(TASK_RUNNING);

	if (cl->parent)
		closure_put(cl->parent);
}

int __sched __bch2_closure_sync_timeout(struct closure *cl, unsigned long timeout)
{
	int ret = 0;

	cl->sleeper = current;
	bch2_closure_sub(cl,
		    CLOSURE_REMAINING_INITIALIZER -
		    CLOSURE_SLEEPING);

	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		/*
		 * Carefully undo the continue_at() - but only if it
		 * hasn't completed, i.e. the final closure_put() hasn't
		 * happened yet:
		 */
		unsigned old = atomic_read(&cl->remaining), new;
		if (!(old & CLOSURE_SLEEPING))
			goto success;

		if (!timeout) {
			do {
				if (!(old & CLOSURE_SLEEPING))
					goto success;

				new = old + CLOSURE_REMAINING_INITIALIZER - CLOSURE_SLEEPING;
				closure_val_checks(cl, new, CLOSURE_REMAINING_INITIALIZER - CLOSURE_SLEEPING);
			} while (!atomic_try_cmpxchg(&cl->remaining, &old, new));

			ret = -ETIME;
			break;
		}

		timeout = schedule_timeout(timeout);
	}
success:
	__set_current_state(TASK_RUNNING);
	return ret;
}
