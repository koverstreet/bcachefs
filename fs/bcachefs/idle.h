/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_IDLE_H
#define _BCACHEFS_IDLE_H

/*
 * Idle/background work classes:
 *
 * We have a number of background tasks (copygc, rebalance, journal reclaim).
 *
 * SUSTAINED LOAD REGIME
 * ---------------------
 *
 * When the system is under continuous load, we want these jobs to run
 * continuously - this is perhaps best modelled with a P/D controller, where
 * they'll be trying to keep a target value (i.e. fragmented disk space,
 * available journal space) roughly in the middle of some range.
 *
 * The goal under sustained load is to balance our ability to handle load spikes
 * without running out of x resource (free disk space, free space in the
 * journal), while also letting some work accumululate to be batched (or become
 * unnecessary).
 *
 * For example, we don't want to run copygc too aggressively, because then it
 * will be evacuating buckets that would have become empty (been overwritten or
 * deleted) anyways, and we don't want to wait until we're almost out of free
 * space because then the system will behave unpredicably - suddenly we're doing
 * a lot more work to service each write and the system becomes much slower.
 *
 * IDLE REGIME
 * -----------
 *
 * Many systems are however not under sustained load - they're idle most of the
 * time, and the goal is to let them idle as much as possible because power
 * useage is a prime consideration. Thus, we need to detect when we've been
 * idle - and the longer we've been idle, the more pending work we should do;
 * the goal being to complete all of our pending work as quickly as possible so
 * that the system can go back to sleep.
 *
 * But this does not mean that we should do _all_ our pending work immediately
 * when the system is idle; remember that if we allow work to build up, much
 * work will not need to be done.
 *
 * Therefore when we're idle we want to wake up and do some amount of pending
 * work in batches; increasing both the amount of work we do and the duration of
 * our sleeps proportional to how long we've been idle for.
 *
 * CLASSES OF IDLE WORK
 * --------------------
 *
 * There are levels of foreground and background tasks; a foreground operation
 * (generated from outsisde the system, i.e. userspace) will generate work for
 * the data move class and the journal reclaim class, and the data move class
 * will generate more work for the journal reclaim class.
 *
 * This complicates idle detection, because a given class wants to know if
 * everything above it has finished or is no longer running, and will want to
 * behave differently for work above it coming from outside the system (which we
 * cannot schedule and can only guess at based on past behaviour), versus work
 * above it but from inside the system (which we can schedule).
 *
 * That is
 * - data moves want to wake up when foreground operations have been quiet for
 *   a little while
 * - journal reclaim wants to wake up when foreground operations have been quiet
 *   for a little while, and immediately after background data moves have
 *   finished and gone back to sleep
 */

#define BCACHEFS_IDLE_CLASSES()		\
	x(foreground)			\
	x(data_move)			\
	x(journal_reclaim)

enum bch_idle_class {
#define x(n)	BCH_IDLE_##n,
	BCACHEFS_IDLE_CLASSES()
#undef x
};

#endif /* _BCACHEFS_IDLE_H */
