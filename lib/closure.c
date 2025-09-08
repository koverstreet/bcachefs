// SPDX-License-Identifier: GPL-2.0
/*
 * Asynchronous refcounty things
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include <linux/closure.h>
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
void closure_sub(struct closure *cl, int v)
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
		cl->closure_get_happened = false;
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
EXPORT_SYMBOL(closure_sub);

/*
 * closure_wake_up - wake up all closures on a wait list, without memory barrier
 */
void __closure_wake_up(struct closure_waitlist *wait_list)
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
		closure_sub(cl, CLOSURE_WAITING + 1);
	}
}
EXPORT_SYMBOL(__closure_wake_up);

/**
 * closure_wait - add a closure to a waitlist
 * @waitlist: will own a ref on @cl, which will be released when
 * closure_wake_up() is called on @waitlist.
 * @cl: closure pointer.
 *
 */
bool closure_wait(struct closure_waitlist *waitlist, struct closure *cl)
{
	if (atomic_read(&cl->remaining) & CLOSURE_WAITING)
		return false;

	cl->closure_get_happened = true;
	closure_set_waiting(cl, _RET_IP_);
	unsigned r = atomic_add_return(CLOSURE_WAITING + 1, &cl->remaining);
	closure_val_checks(cl, r, CLOSURE_WAITING + 1);

	llist_add(&cl->list, &waitlist->list);

	return true;
}
EXPORT_SYMBOL(closure_wait);

void __sched __closure_sync(struct closure *cl)
{
	cl->sleeper = current;
	closure_sub(cl,
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
EXPORT_SYMBOL(__closure_sync);

/*
 * closure_return_sync - finish running a closure, synchronously (i.e. waiting
 * for outstanding get()s to finish) and returning once closure refcount is 0.
 *
 * Unlike closure_sync() this doesn't reinit the ref to 1; subsequent
 * closure_get_not_zero() calls will fail.
 */
void __sched closure_return_sync(struct closure *cl)
{
	cl->sleeper = current;
	closure_sub(cl,
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
EXPORT_SYMBOL(closure_return_sync);

int __sched __closure_sync_timeout(struct closure *cl, unsigned long timeout)
{
	int ret = 0;

	cl->sleeper = current;
	closure_sub(cl,
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
EXPORT_SYMBOL(__closure_sync_timeout);

#ifdef CONFIG_DEBUG_CLOSURES

static LIST_HEAD(closure_list);
static DEFINE_SPINLOCK(closure_list_lock);

void closure_debug_create(struct closure *cl)
{
	unsigned long flags;

	BUG_ON(cl->magic == CLOSURE_MAGIC_ALIVE);
	cl->magic = CLOSURE_MAGIC_ALIVE;

	spin_lock_irqsave(&closure_list_lock, flags);
	list_add(&cl->all, &closure_list);
	spin_unlock_irqrestore(&closure_list_lock, flags);
}
EXPORT_SYMBOL(closure_debug_create);

void closure_debug_destroy(struct closure *cl)
{
	unsigned long flags;

	if (cl->magic == CLOSURE_MAGIC_STACK)
		return;

	BUG_ON(cl->magic != CLOSURE_MAGIC_ALIVE);
	cl->magic = CLOSURE_MAGIC_DEAD;

	spin_lock_irqsave(&closure_list_lock, flags);
	list_del(&cl->all);
	spin_unlock_irqrestore(&closure_list_lock, flags);
}
EXPORT_SYMBOL(closure_debug_destroy);

static int debug_show(struct seq_file *f, void *data)
{
	struct closure *cl;

	spin_lock_irq(&closure_list_lock);

	list_for_each_entry(cl, &closure_list, all) {
		int r = atomic_read(&cl->remaining);

		seq_printf(f, "%p: %pS -> %pS p %p r %i ",
			   cl, (void *) cl->ip, cl->fn, cl->parent,
			   r & CLOSURE_REMAINING_MASK);

		seq_printf(f, "%s%s\n",
			   test_bit(WORK_STRUCT_PENDING_BIT,
				    work_data_bits(&cl->work)) ? "Q" : "",
			   r & CLOSURE_RUNNING	? "R" : "");

		if (r & CLOSURE_WAITING)
			seq_printf(f, " W %pS\n",
				   (void *) cl->waiting_on);

		seq_putc(f, '\n');
	}

	spin_unlock_irq(&closure_list_lock);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(debug);

static int __init closure_debug_init(void)
{
	debugfs_create_file("closures", 0400, NULL, NULL, &debug_fops);
	return 0;
}
late_initcall(closure_debug_init)

#endif
