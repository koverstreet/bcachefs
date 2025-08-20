/* SPDX-License-Identifier: GPL-2.0 */
/*
 * workqueue.h --- work queue handling for Linux.
 */

#ifndef _LINUX_WORKQUEUE_H
#define _LINUX_WORKQUEUE_H

#include <linux/alloc_tag.h>
#include <linux/timer.h>
#include <linux/linkage.h>
#include <linux/bitops.h>
#include <linux/lockdep.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cpumask_types.h>
#include <linux/rcupdate.h>
#include <linux/workqueue_types.h>

/*
 * The first word is the work queue pointer and the flags rolled into
 * one
 */
#define work_data_bits(work) ((unsigned long *)(&(work)->data))

enum work_bits {
	WORK_STRUCT_PENDING_BIT	= 0,	/* work item is pending execution */
	WORK_STRUCT_INACTIVE_BIT,	/* work item is inactive */
	WORK_STRUCT_PWQ_BIT,		/* data points to pwq */
	WORK_STRUCT_LINKED_BIT,		/* next work is linked to this one */
#ifdef CONFIG_DEBUG_OBJECTS_WORK
	WORK_STRUCT_STATIC_BIT,		/* static initializer (debugobjects) */
#endif
	WORK_STRUCT_FLAG_BITS,

	/* color for workqueue flushing */
	WORK_STRUCT_COLOR_SHIFT	= WORK_STRUCT_FLAG_BITS,
	WORK_STRUCT_COLOR_BITS	= 4,

	/*
	 * When WORK_STRUCT_PWQ is set, reserve 8 bits off of pwq pointer w/
	 * debugobjects turned off. This makes pwqs aligned to 256 bytes (512
	 * bytes w/ DEBUG_OBJECTS_WORK) and allows 16 workqueue flush colors.
	 *
	 * MSB
	 * [ pwq pointer ] [ flush color ] [ STRUCT flags ]
	 *                     4 bits        4 or 5 bits
	 */
	WORK_STRUCT_PWQ_SHIFT	= WORK_STRUCT_COLOR_SHIFT + WORK_STRUCT_COLOR_BITS,

	/*
	 * data contains off-queue information when !WORK_STRUCT_PWQ.
	 *
	 * MSB
	 * [ pool ID ] [ disable depth ] [ OFFQ flags ] [ STRUCT flags ]
	 *                  16 bits          1 bit        4 or 5 bits
	 */
	WORK_OFFQ_FLAG_SHIFT	= WORK_STRUCT_FLAG_BITS,
	WORK_OFFQ_BH_BIT	= WORK_OFFQ_FLAG_SHIFT,
	WORK_OFFQ_FLAG_END,
	WORK_OFFQ_FLAG_BITS	= WORK_OFFQ_FLAG_END - WORK_OFFQ_FLAG_SHIFT,

	WORK_OFFQ_DISABLE_SHIFT	= WORK_OFFQ_FLAG_SHIFT + WORK_OFFQ_FLAG_BITS,
	WORK_OFFQ_DISABLE_BITS	= 16,

	/*
	 * When a work item is off queue, the high bits encode off-queue flags
	 * and the last pool it was on. Cap pool ID to 31 bits and use the
	 * highest number to indicate that no pool is associated.
	 */
	WORK_OFFQ_POOL_SHIFT	= WORK_OFFQ_DISABLE_SHIFT + WORK_OFFQ_DISABLE_BITS,
	WORK_OFFQ_LEFT		= BITS_PER_LONG - WORK_OFFQ_POOL_SHIFT,
	WORK_OFFQ_POOL_BITS	= WORK_OFFQ_LEFT <= 31 ? WORK_OFFQ_LEFT : 31,
};

enum work_flags {
	WORK_STRUCT_PENDING	= 1 << WORK_STRUCT_PENDING_BIT,
	WORK_STRUCT_INACTIVE	= 1 << WORK_STRUCT_INACTIVE_BIT,
	WORK_STRUCT_PWQ		= 1 << WORK_STRUCT_PWQ_BIT,
	WORK_STRUCT_LINKED	= 1 << WORK_STRUCT_LINKED_BIT,
#ifdef CONFIG_DEBUG_OBJECTS_WORK
	WORK_STRUCT_STATIC	= 1 << WORK_STRUCT_STATIC_BIT,
#else
	WORK_STRUCT_STATIC	= 0,
#endif
};

enum wq_misc_consts {
	WORK_NR_COLORS		= (1 << WORK_STRUCT_COLOR_BITS),

	/* not bound to any CPU, prefer the local CPU */
	WORK_CPU_UNBOUND	= NR_CPUS,

	/* bit mask for work_busy() return values */
	WORK_BUSY_PENDING	= 1 << 0,
	WORK_BUSY_RUNNING	= 1 << 1,

	/* maximum string length for set_worker_desc() */
	WORKER_DESC_LEN		= 32,
};

/* Convenience constants - of type 'unsigned long', not 'enum'! */
#define WORK_OFFQ_BH		(1ul << WORK_OFFQ_BH_BIT)
#define WORK_OFFQ_FLAG_MASK	(((1ul << WORK_OFFQ_FLAG_BITS) - 1) << WORK_OFFQ_FLAG_SHIFT)
#define WORK_OFFQ_DISABLE_MASK	(((1ul << WORK_OFFQ_DISABLE_BITS) - 1) << WORK_OFFQ_DISABLE_SHIFT)
#define WORK_OFFQ_POOL_NONE	((1ul << WORK_OFFQ_POOL_BITS) - 1)
#define WORK_STRUCT_NO_POOL	(WORK_OFFQ_POOL_NONE << WORK_OFFQ_POOL_SHIFT)
#define WORK_STRUCT_PWQ_MASK	(~((1ul << WORK_STRUCT_PWQ_SHIFT) - 1))

#define WORK_DATA_INIT()	ATOMIC_LONG_INIT((unsigned long)WORK_STRUCT_NO_POOL)
#define WORK_DATA_STATIC_INIT()	\
	ATOMIC_LONG_INIT((unsigned long)(WORK_STRUCT_NO_POOL | WORK_STRUCT_STATIC))

struct delayed_work {
	struct work_struct work;
	struct timer_list timer;

	/* target workqueue and CPU ->timer uses to queue ->work */
	struct workqueue_struct *wq;
	int cpu;
};

struct rcu_work {
	struct work_struct work;
	struct rcu_head rcu;

	/* target workqueue ->rcu uses to queue ->work */
	struct workqueue_struct *wq;
};

enum wq_affn_scope {
	WQ_AFFN_DFL,			/* use system default */
	WQ_AFFN_CPU,			/* one pod per CPU */
	WQ_AFFN_SMT,			/* one pod poer SMT */
	WQ_AFFN_CACHE,			/* one pod per LLC */
	WQ_AFFN_NUMA,			/* one pod per NUMA node */
	WQ_AFFN_SYSTEM,			/* one pod across the whole system */

	WQ_AFFN_NR_TYPES,
};

/**
 * struct workqueue_attrs - A struct for workqueue attributes.
 *
 * This can be used to change attributes of an unbound workqueue.
 */
struct workqueue_attrs {
	/**
	 * @nice: nice level
	 */
	int nice;

	/**
	 * @cpumask: allowed CPUs
	 *
	 * Work items in this workqueue are affine to these CPUs and not allowed
	 * to execute on other CPUs. A pool serving a workqueue must have the
	 * same @cpumask.
	 */
	cpumask_var_t cpumask;

	/**
	 * @__pod_cpumask: internal attribute used to create per-pod pools
	 *
	 * Internal use only.
	 *
	 * Per-pod unbound worker pools are used to improve locality. Always a
	 * subset of ->cpumask. A workqueue can be associated with multiple
	 * worker pools with disjoint @__pod_cpumask's. Whether the enforcement
	 * of a pool's @__pod_cpumask is strict depends on @affn_strict.
	 */
	cpumask_var_t __pod_cpumask;

	/**
	 * @affn_strict: affinity scope is strict
	 *
	 * If clear, workqueue will make a best-effort attempt at starting the
	 * worker inside @__pod_cpumask but the scheduler is free to migrate it
	 * outside.
	 *
	 * If set, workers are only allowed to run inside @__pod_cpumask.
	 */
	bool affn_strict;

	/*
	 * Below fields aren't properties of a worker_pool. They only modify how
	 * :c:func:`apply_workqueue_attrs` select pools and thus don't
	 * participate in pool hash calculations or equality comparisons.
	 *
	 * If @affn_strict is set, @cpumask isn't a property of a worker_pool
	 * either.
	 */

	/**
	 * @affn_scope: unbound CPU affinity scope
	 *
	 * CPU pods are used to improve execution locality of unbound work
	 * items. There are multiple pod types, one for each wq_affn_scope, and
	 * every CPU in the system belongs to one pod in every pod type. CPUs
	 * that belong to the same pod share the worker pool. For example,
	 * selecting %WQ_AFFN_NUMA makes the workqueue use a separate worker
	 * pool for each NUMA node.
	 */
	enum wq_affn_scope affn_scope;

	/**
	 * @ordered: work items must be executed one by one in queueing order
	 */
	bool ordered;
};

static inline struct delayed_work *to_delayed_work(struct work_struct *work)
{
	return container_of(work, struct delayed_work, work);
}

static inline struct rcu_work *to_rcu_work(struct work_struct *work)
{
	return container_of(work, struct rcu_work, work);
}

struct execute_work {
	struct work_struct work;
};

#ifdef CONFIG_LOCKDEP
/*
 * NB: because we have to copy the lockdep_map, setting _key
 * here is required, otherwise it could get initialised to the
 * copy of the lockdep_map!
 */
#define __WORK_INIT_LOCKDEP_MAP(n, k) \
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(n, k),
#else
#define __WORK_INIT_LOCKDEP_MAP(n, k)
#endif

#define __WORK_INITIALIZER(n, f) {					\
	.data = WORK_DATA_STATIC_INIT(),				\
	.entry	= { &(n).entry, &(n).entry },				\
	.func = (f),							\
	__WORK_INIT_LOCKDEP_MAP(#n, &(n))				\
	}

#define __DELAYED_WORK_INITIALIZER(n, f, tflags) {			\
	.work = __WORK_INITIALIZER((n).work, (f)),			\
	.timer = __TIMER_INITIALIZER(delayed_work_timer_fn,\
				     (tflags) | TIMER_IRQSAFE),		\
	}

#define DECLARE_WORK(n, f)						\
	struct work_struct n = __WORK_INITIALIZER(n, f)

#define DECLARE_DELAYED_WORK(n, f)					\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f, 0)

#define DECLARE_DEFERRABLE_WORK(n, f)					\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f, TIMER_DEFERRABLE)

#ifdef CONFIG_DEBUG_OBJECTS_WORK
extern void __init_work(struct work_struct *work, int onstack);
extern void destroy_work_on_stack(struct work_struct *work);
extern void destroy_delayed_work_on_stack(struct delayed_work *work);
static inline unsigned int work_static(struct work_struct *work)
{
	return *work_data_bits(work) & WORK_STRUCT_STATIC;
}
#else
static inline void __init_work(struct work_struct *work, int onstack) { }
static inline void destroy_work_on_stack(struct work_struct *work) { }
static inline void destroy_delayed_work_on_stack(struct delayed_work *work) { }
static inline unsigned int work_static(struct work_struct *work) { return 0; }
#endif

/*
 * initialize all of a work item in one go
 *
 * NOTE! No point in using "atomic_long_set()": using a direct
 * assignment of the work data initializer allows the compiler
 * to generate better code.
 */
#ifdef CONFIG_LOCKDEP
#define __INIT_WORK_KEY(_work, _func, _onstack, _key)			\
	do {								\
		__init_work((_work), _onstack);				\
		(_work)->data = (atomic_long_t) WORK_DATA_INIT();	\
		lockdep_init_map(&(_work)->lockdep_map, "(work_completion)"#_work, (_key), 0); \
		INIT_LIST_HEAD(&(_work)->entry);			\
		(_work)->func = (_func);				\
	} while (0)
#else
#define __INIT_WORK_KEY(_work, _func, _onstack, _key)			\
	do {								\
		__init_work((_work), _onstack);				\
		(_work)->data = (atomic_long_t) WORK_DATA_INIT();	\
		INIT_LIST_HEAD(&(_work)->entry);			\
		(_work)->func = (_func);				\
	} while (0)
#endif

#define __INIT_WORK(_work, _func, _onstack)				\
	do {								\
		static __maybe_unused struct lock_class_key __key;	\
									\
		__INIT_WORK_KEY(_work, _func, _onstack, &__key);	\
	} while (0)

#define INIT_WORK(_work, _func)						\
	__INIT_WORK((_work), (_func), 0)

#define INIT_WORK_ONSTACK(_work, _func)					\
	__INIT_WORK((_work), (_func), 1)

#define INIT_WORK_ONSTACK_KEY(_work, _func, _key)			\
	__INIT_WORK_KEY((_work), (_func), 1, _key)

#define __INIT_DELAYED_WORK(_work, _func, _tflags)			\
	do {								\
		INIT_WORK(&(_work)->work, (_func));			\
		__timer_init(&(_work)->timer,				\
			     delayed_work_timer_fn,			\
			     (_tflags) | TIMER_IRQSAFE);		\
	} while (0)

#define __INIT_DELAYED_WORK_ONSTACK(_work, _func, _tflags)		\
	do {								\
		INIT_WORK_ONSTACK(&(_work)->work, (_func));		\
		__timer_init_on_stack(&(_work)->timer,			\
				      delayed_work_timer_fn,		\
				      (_tflags) | TIMER_IRQSAFE);	\
	} while (0)

#define INIT_DELAYED_WORK(_work, _func)					\
	__INIT_DELAYED_WORK(_work, _func, 0)

#define INIT_DELAYED_WORK_ONSTACK(_work, _func)				\
	__INIT_DELAYED_WORK_ONSTACK(_work, _func, 0)

#define INIT_DEFERRABLE_WORK(_work, _func)				\
	__INIT_DELAYED_WORK(_work, _func, TIMER_DEFERRABLE)

#define INIT_DEFERRABLE_WORK_ONSTACK(_work, _func)			\
	__INIT_DELAYED_WORK_ONSTACK(_work, _func, TIMER_DEFERRABLE)

#define INIT_RCU_WORK(_work, _func)					\
	INIT_WORK(&(_work)->work, (_func))

#define INIT_RCU_WORK_ONSTACK(_work, _func)				\
	INIT_WORK_ONSTACK(&(_work)->work, (_func))

/**
 * work_pending - Find out whether a work item is currently pending
 * @work: The work item in question
 */
#define work_pending(work) \
	test_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work))

/**
 * delayed_work_pending - Find out whether a delayable work item is currently
 * pending
 * @w: The work item in question
 */
#define delayed_work_pending(w) \
	work_pending(&(w)->work)

/*
 * Workqueue flags and constants.  For details, please refer to
 * Documentation/core-api/workqueue.rst.
 */
enum wq_flags {
	WQ_BH			= 1 << 0, /* execute in bottom half (softirq) context */
	WQ_UNBOUND		= 1 << 1, /* not bound to any cpu */
	WQ_FREEZABLE		= 1 << 2, /* freeze during suspend */
	WQ_MEM_RECLAIM		= 1 << 3, /* may be used for memory reclaim */
	WQ_HIGHPRI		= 1 << 4, /* high priority */
	WQ_CPU_INTENSIVE	= 1 << 5, /* cpu intensive workqueue */
	WQ_SYSFS		= 1 << 6, /* visible in sysfs, see workqueue_sysfs_register() */

	/*
	 * Per-cpu workqueues are generally preferred because they tend to
	 * show better performance thanks to cache locality.  Per-cpu
	 * workqueues exclude the scheduler from choosing the CPU to
	 * execute the worker threads, which has an unfortunate side effect
	 * of increasing power consumption.
	 *
	 * The scheduler considers a CPU idle if it doesn't have any task
	 * to execute and tries to keep idle cores idle to conserve power;
	 * however, for example, a per-cpu work item scheduled from an
	 * interrupt handler on an idle CPU will force the scheduler to
	 * execute the work item on that CPU breaking the idleness, which in
	 * turn may lead to more scheduling choices which are sub-optimal
	 * in terms of power consumption.
	 *
	 * Workqueues marked with WQ_POWER_EFFICIENT are per-cpu by default
	 * but become unbound if workqueue.power_efficient kernel param is
	 * specified.  Per-cpu workqueues which are identified to
	 * contribute significantly to power-consumption are identified and
	 * marked with this flag and enabling the power_efficient mode
	 * leads to noticeable power saving at the cost of small
	 * performance disadvantage.
	 *
	 * http://thread.gmane.org/gmane.linux.kernel/1480396
	 */
	WQ_POWER_EFFICIENT	= 1 << 7,

	__WQ_DESTROYING		= 1 << 15, /* internal: workqueue is destroying */
	__WQ_DRAINING		= 1 << 16, /* internal: workqueue is draining */
	__WQ_ORDERED		= 1 << 17, /* internal: workqueue is ordered */
	__WQ_LEGACY		= 1 << 18, /* internal: create*_workqueue() */

	/* BH wq only allows the following flags */
	__WQ_BH_ALLOWS		= WQ_BH | WQ_HIGHPRI,
};

enum wq_consts {
	WQ_MAX_ACTIVE		= 2048,	  /* I like 2048, better ideas? */
	WQ_UNBOUND_MAX_ACTIVE	= WQ_MAX_ACTIVE,
	WQ_DFL_ACTIVE		= WQ_MAX_ACTIVE / 2,

	/*
	 * Per-node default cap on min_active. Unless explicitly set, min_active
	 * is set to min(max_active, WQ_DFL_MIN_ACTIVE). For more details, see
	 * workqueue_struct->min_active definition.
	 */
	WQ_DFL_MIN_ACTIVE	= 8,
};

/*
 * System-wide workqueues which are always present.
 *
 * system_wq is the one used by schedule[_delayed]_work[_on]().
 * Multi-CPU multi-threaded.  There are users which expect relatively
 * short queue flush time.  Don't queue works which can run for too
 * long.
 *
 * system_highpri_wq is similar to system_wq but for work items which
 * require WQ_HIGHPRI.
 *
 * system_long_wq is similar to system_wq but may host long running
 * works.  Queue flushing might take relatively long.
 *
 * system_unbound_wq is unbound workqueue.  Workers are not bound to
 * any specific CPU, not concurrency managed, and all queued works are
 * executed immediately as long as max_active limit is not reached and
 * resources are available.
 *
 * system_freezable_wq is equivalent to system_wq except that it's
 * freezable.
 *
 * *_power_efficient_wq are inclined towards saving power and converted
 * into WQ_UNBOUND variants if 'wq_power_efficient' is enabled; otherwise,
 * they are same as their non-power-efficient counterparts - e.g.
 * system_power_efficient_wq is identical to system_wq if
 * 'wq_power_efficient' is disabled.  See WQ_POWER_EFFICIENT for more info.
 *
 * system_bh[_highpri]_wq are convenience interface to softirq. BH work items
 * are executed in the queueing CPU's BH context in the queueing order.
 */
extern struct workqueue_struct *system_wq;
extern struct workqueue_struct *system_highpri_wq;
extern struct workqueue_struct *system_long_wq;
extern struct workqueue_struct *system_unbound_wq;
extern struct workqueue_struct *system_freezable_wq;
extern struct workqueue_struct *system_power_efficient_wq;
extern struct workqueue_struct *system_freezable_power_efficient_wq;
extern struct workqueue_struct *system_bh_wq;
extern struct workqueue_struct *system_bh_highpri_wq;

void workqueue_softirq_action(bool highpri);
void workqueue_softirq_dead(unsigned int cpu);

/**
 * alloc_workqueue - allocate a workqueue
 * @fmt: printf format for the name of the workqueue
 * @flags: WQ_* flags
 * @max_active: max in-flight work items, 0 for default
 * @...: args for @fmt
 *
 * For a per-cpu workqueue, @max_active limits the number of in-flight work
 * items for each CPU. e.g. @max_active of 1 indicates that each CPU can be
 * executing at most one work item for the workqueue.
 *
 * For unbound workqueues, @max_active limits the number of in-flight work items
 * for the whole system. e.g. @max_active of 16 indicates that there can be
 * at most 16 work items executing for the workqueue in the whole system.
 *
 * As sharing the same active counter for an unbound workqueue across multiple
 * NUMA nodes can be expensive, @max_active is distributed to each NUMA node
 * according to the proportion of the number of online CPUs and enforced
 * independently.
 *
 * Depending on online CPU distribution, a node may end up with per-node
 * max_active which is significantly lower than @max_active, which can lead to
 * deadlocks if the per-node concurrency limit is lower than the maximum number
 * of interdependent work items for the workqueue.
 *
 * To guarantee forward progress regardless of online CPU distribution, the
 * concurrency limit on every node is guaranteed to be equal to or greater than
 * min_active which is set to min(@max_active, %WQ_DFL_MIN_ACTIVE). This means
 * that the sum of per-node max_active's may be larger than @max_active.
 *
 * For detailed information on %WQ_* flags, please refer to
 * Documentation/core-api/workqueue.rst.
 *
 * RETURNS:
 * Pointer to the allocated workqueue on success, %NULL on failure.
 */
__printf(1, 4) struct workqueue_struct *
alloc_workqueue_noprof(const char *fmt, unsigned int flags, int max_active, ...);
#define alloc_workqueue(...)	alloc_hooks(alloc_workqueue_noprof(__VA_ARGS__))

#ifdef CONFIG_LOCKDEP
/**
 * alloc_workqueue_lockdep_map - allocate a workqueue with user-defined lockdep_map
 * @fmt: printf format for the name of the workqueue
 * @flags: WQ_* flags
 * @max_active: max in-flight work items, 0 for default
 * @lockdep_map: user-defined lockdep_map
 * @...: args for @fmt
 *
 * Same as alloc_workqueue but with the a user-define lockdep_map. Useful for
 * workqueues created with the same purpose and to avoid leaking a lockdep_map
 * on each workqueue creation.
 *
 * RETURNS:
 * Pointer to the allocated workqueue on success, %NULL on failure.
 */
__printf(1, 5) struct workqueue_struct *
alloc_workqueue_lockdep_map(const char *fmt, unsigned int flags, int max_active,
			    struct lockdep_map *lockdep_map, ...);

/**
 * alloc_ordered_workqueue_lockdep_map - allocate an ordered workqueue with
 * user-defined lockdep_map
 *
 * @fmt: printf format for the name of the workqueue
 * @flags: WQ_* flags (only WQ_FREEZABLE and WQ_MEM_RECLAIM are meaningful)
 * @lockdep_map: user-defined lockdep_map
 * @args: args for @fmt
 *
 * Same as alloc_ordered_workqueue but with the a user-define lockdep_map.
 * Useful for workqueues created with the same purpose and to avoid leaking a
 * lockdep_map on each workqueue creation.
 *
 * RETURNS:
 * Pointer to the allocated workqueue on success, %NULL on failure.
 */
#define alloc_ordered_workqueue_lockdep_map(fmt, flags, lockdep_map, args...)	\
	alloc_hooks(alloc_workqueue_lockdep_map(fmt, WQ_UNBOUND | __WQ_ORDERED | (flags),\
						1, lockdep_map, ##args))
#endif

/**
 * alloc_ordered_workqueue - allocate an ordered workqueue
 * @fmt: printf format for the name of the workqueue
 * @flags: WQ_* flags (only WQ_FREEZABLE and WQ_MEM_RECLAIM are meaningful)
 * @args: args for @fmt
 *
 * Allocate an ordered workqueue.  An ordered workqueue executes at
 * most one work item at any given time in the queued order.  They are
 * implemented as unbound workqueues with @max_active of one.
 *
 * RETURNS:
 * Pointer to the allocated workqueue on success, %NULL on failure.
 */
#define alloc_ordered_workqueue(fmt, flags, args...)			\
	alloc_workqueue(fmt, WQ_UNBOUND | __WQ_ORDERED | (flags), 1, ##args)

#define create_workqueue(name)						\
	alloc_workqueue("%s", __WQ_LEGACY | WQ_MEM_RECLAIM, 1, (name))
#define create_freezable_workqueue(name)				\
	alloc_workqueue("%s", __WQ_LEGACY | WQ_FREEZABLE | WQ_UNBOUND |	\
			WQ_MEM_RECLAIM, 1, (name))
#define create_singlethread_workqueue(name)				\
	alloc_ordered_workqueue("%s", __WQ_LEGACY | WQ_MEM_RECLAIM, name)

#define from_work(var, callback_work, work_fieldname)	\
	container_of(callback_work, typeof(*var), work_fieldname)

extern void destroy_workqueue(struct workqueue_struct *wq);

struct workqueue_attrs *alloc_workqueue_attrs_noprof(void);
#define alloc_workqueue_attrs(...)	alloc_hooks(alloc_workqueue_attrs_noprof(__VA_ARGS__))

void free_workqueue_attrs(struct workqueue_attrs *attrs);
int apply_workqueue_attrs(struct workqueue_struct *wq,
			  const struct workqueue_attrs *attrs);
extern int workqueue_unbound_exclude_cpumask(cpumask_var_t cpumask);

extern bool queue_work_on(int cpu, struct workqueue_struct *wq,
			struct work_struct *work);
extern bool queue_work_node(int node, struct workqueue_struct *wq,
			    struct work_struct *work);
extern bool queue_delayed_work_on(int cpu, struct workqueue_struct *wq,
			struct delayed_work *work, unsigned long delay);
extern bool mod_delayed_work_on(int cpu, struct workqueue_struct *wq,
			struct delayed_work *dwork, unsigned long delay);
extern bool queue_rcu_work(struct workqueue_struct *wq, struct rcu_work *rwork);

extern void __flush_workqueue(struct workqueue_struct *wq);
extern void drain_workqueue(struct workqueue_struct *wq);

extern int schedule_on_each_cpu(work_func_t func);

int execute_in_process_context(work_func_t fn, struct execute_work *);

extern bool flush_work(struct work_struct *work);
extern bool cancel_work(struct work_struct *work);
extern bool cancel_work_sync(struct work_struct *work);

extern bool flush_delayed_work(struct delayed_work *dwork);
extern bool cancel_delayed_work(struct delayed_work *dwork);
extern bool cancel_delayed_work_sync(struct delayed_work *dwork);

extern bool disable_work(struct work_struct *work);
extern bool disable_work_sync(struct work_struct *work);
extern bool enable_work(struct work_struct *work);

extern bool disable_delayed_work(struct delayed_work *dwork);
extern bool disable_delayed_work_sync(struct delayed_work *dwork);
extern bool enable_delayed_work(struct delayed_work *dwork);

extern bool flush_rcu_work(struct rcu_work *rwork);

extern void workqueue_set_max_active(struct workqueue_struct *wq,
				     int max_active);
extern void workqueue_set_min_active(struct workqueue_struct *wq,
				     int min_active);
extern struct work_struct *current_work(void);
extern bool current_is_workqueue_rescuer(void);
extern bool workqueue_congested(int cpu, struct workqueue_struct *wq);
extern unsigned int work_busy(struct work_struct *work);
extern __printf(1, 2) void set_worker_desc(const char *fmt, ...);
extern void print_worker_info(const char *log_lvl, struct task_struct *task);
extern void show_all_workqueues(void);
extern void show_freezable_workqueues(void);
extern void show_one_workqueue(struct workqueue_struct *wq);
extern void wq_worker_comm(char *buf, size_t size, struct task_struct *task);

/**
 * queue_work - queue work on a workqueue
 * @wq: workqueue to use
 * @work: work to queue
 *
 * Returns %false if @work was already on a queue, %true otherwise.
 *
 * We queue the work to the CPU on which it was submitted, but if the CPU dies
 * it can be processed by another CPU.
 *
 * Memory-ordering properties:  If it returns %true, guarantees that all stores
 * preceding the call to queue_work() in the program order will be visible from
 * the CPU which will execute @work by the time such work executes, e.g.,
 *
 * { x is initially 0 }
 *
 *   CPU0				CPU1
 *
 *   WRITE_ONCE(x, 1);			[ @work is being executed ]
 *   r0 = queue_work(wq, work);		  r1 = READ_ONCE(x);
 *
 * Forbids: r0 == true && r1 == 0
 */
static inline bool queue_work(struct workqueue_struct *wq,
			      struct work_struct *work)
{
	return queue_work_on(WORK_CPU_UNBOUND, wq, work);
}

/**
 * queue_delayed_work - queue work on a workqueue after delay
 * @wq: workqueue to use
 * @dwork: delayable work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * Equivalent to queue_delayed_work_on() but tries to use the local CPU.
 */
static inline bool queue_delayed_work(struct workqueue_struct *wq,
				      struct delayed_work *dwork,
				      unsigned long delay)
{
	return queue_delayed_work_on(WORK_CPU_UNBOUND, wq, dwork, delay);
}

/**
 * mod_delayed_work - modify delay of or queue a delayed work
 * @wq: workqueue to use
 * @dwork: work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * mod_delayed_work_on() on local CPU.
 */
static inline bool mod_delayed_work(struct workqueue_struct *wq,
				    struct delayed_work *dwork,
				    unsigned long delay)
{
	return mod_delayed_work_on(WORK_CPU_UNBOUND, wq, dwork, delay);
}

/**
 * schedule_work_on - put work task on a specific cpu
 * @cpu: cpu to put the work task on
 * @work: job to be done
 *
 * This puts a job on a specific cpu
 */
static inline bool schedule_work_on(int cpu, struct work_struct *work)
{
	return queue_work_on(cpu, system_wq, work);
}

/**
 * schedule_work - put work task in global workqueue
 * @work: job to be done
 *
 * Returns %false if @work was already on the kernel-global workqueue and
 * %true otherwise.
 *
 * This puts a job in the kernel-global workqueue if it was not already
 * queued and leaves it in the same position on the kernel-global
 * workqueue otherwise.
 *
 * Shares the same memory-ordering properties of queue_work(), cf. the
 * DocBook header of queue_work().
 */
static inline bool schedule_work(struct work_struct *work)
{
	return queue_work(system_wq, work);
}

/**
 * enable_and_queue_work - Enable and queue a work item on a specific workqueue
 * @wq: The target workqueue
 * @work: The work item to be enabled and queued
 *
 * This function combines the operations of enable_work() and queue_work(),
 * providing a convenient way to enable and queue a work item in a single call.
 * It invokes enable_work() on @work and then queues it if the disable depth
 * reached 0. Returns %true if the disable depth reached 0 and @work is queued,
 * and %false otherwise.
 *
 * Note that @work is always queued when disable depth reaches zero. If the
 * desired behavior is queueing only if certain events took place while @work is
 * disabled, the user should implement the necessary state tracking and perform
 * explicit conditional queueing after enable_work().
 */
static inline bool enable_and_queue_work(struct workqueue_struct *wq,
					 struct work_struct *work)
{
	if (enable_work(work)) {
		queue_work(wq, work);
		return true;
	}
	return false;
}

/*
 * Detect attempt to flush system-wide workqueues at compile time when possible.
 * Warn attempt to flush system-wide workqueues at runtime.
 *
 * See https://lkml.kernel.org/r/49925af7-78a8-a3dd-bce6-cfc02e1a9236@I-love.SAKURA.ne.jp
 * for reasons and steps for converting system-wide workqueues into local workqueues.
 */
extern void __warn_flushing_systemwide_wq(void)
	__compiletime_warning("Please avoid flushing system-wide workqueues.");

/* Please stop using this function, for this function will be removed in near future. */
#define flush_scheduled_work()						\
({									\
	__warn_flushing_systemwide_wq();				\
	__flush_workqueue(system_wq);					\
})

#define flush_workqueue(wq)						\
({									\
	struct workqueue_struct *_wq = (wq);				\
									\
	if ((__builtin_constant_p(_wq == system_wq) &&			\
	     _wq == system_wq) ||					\
	    (__builtin_constant_p(_wq == system_highpri_wq) &&		\
	     _wq == system_highpri_wq) ||				\
	    (__builtin_constant_p(_wq == system_long_wq) &&		\
	     _wq == system_long_wq) ||					\
	    (__builtin_constant_p(_wq == system_unbound_wq) &&		\
	     _wq == system_unbound_wq) ||				\
	    (__builtin_constant_p(_wq == system_freezable_wq) &&	\
	     _wq == system_freezable_wq) ||				\
	    (__builtin_constant_p(_wq == system_power_efficient_wq) &&	\
	     _wq == system_power_efficient_wq) ||			\
	    (__builtin_constant_p(_wq == system_freezable_power_efficient_wq) && \
	     _wq == system_freezable_power_efficient_wq))		\
		__warn_flushing_systemwide_wq();			\
	__flush_workqueue(_wq);						\
})

/**
 * schedule_delayed_work_on - queue work in global workqueue on CPU after delay
 * @cpu: cpu to use
 * @dwork: job to be done
 * @delay: number of jiffies to wait
 *
 * After waiting for a given time this puts a job in the kernel-global
 * workqueue on the specified CPU.
 */
static inline bool schedule_delayed_work_on(int cpu, struct delayed_work *dwork,
					    unsigned long delay)
{
	return queue_delayed_work_on(cpu, system_wq, dwork, delay);
}

/**
 * schedule_delayed_work - put work task in global workqueue after delay
 * @dwork: job to be done
 * @delay: number of jiffies to wait or 0 for immediate execution
 *
 * After waiting for a given time this puts a job in the kernel-global
 * workqueue.
 */
static inline bool schedule_delayed_work(struct delayed_work *dwork,
					 unsigned long delay)
{
	return queue_delayed_work(system_wq, dwork, delay);
}

#ifndef CONFIG_SMP
static inline long work_on_cpu(int cpu, long (*fn)(void *), void *arg)
{
	return fn(arg);
}
static inline long work_on_cpu_safe(int cpu, long (*fn)(void *), void *arg)
{
	return fn(arg);
}
#else
long work_on_cpu_key(int cpu, long (*fn)(void *),
		     void *arg, struct lock_class_key *key);
/*
 * A new key is defined for each caller to make sure the work
 * associated with the function doesn't share its locking class.
 */
#define work_on_cpu(_cpu, _fn, _arg)			\
({							\
	static struct lock_class_key __key;		\
							\
	work_on_cpu_key(_cpu, _fn, _arg, &__key);	\
})

long work_on_cpu_safe_key(int cpu, long (*fn)(void *),
			  void *arg, struct lock_class_key *key);

/*
 * A new key is defined for each caller to make sure the work
 * associated with the function doesn't share its locking class.
 */
#define work_on_cpu_safe(_cpu, _fn, _arg)		\
({							\
	static struct lock_class_key __key;		\
							\
	work_on_cpu_safe_key(_cpu, _fn, _arg, &__key);	\
})
#endif /* CONFIG_SMP */

#ifdef CONFIG_FREEZER
extern void freeze_workqueues_begin(void);
extern bool freeze_workqueues_busy(void);
extern void thaw_workqueues(void);
#endif /* CONFIG_FREEZER */

#ifdef CONFIG_SYSFS
int workqueue_sysfs_register(struct workqueue_struct *wq);
#else	/* CONFIG_SYSFS */
static inline int workqueue_sysfs_register(struct workqueue_struct *wq)
{ return 0; }
#endif	/* CONFIG_SYSFS */

#ifdef CONFIG_WQ_WATCHDOG
void wq_watchdog_touch(int cpu);
#else	/* CONFIG_WQ_WATCHDOG */
static inline void wq_watchdog_touch(int cpu) { }
#endif	/* CONFIG_WQ_WATCHDOG */

#ifdef CONFIG_SMP
int workqueue_prepare_cpu(unsigned int cpu);
int workqueue_online_cpu(unsigned int cpu);
int workqueue_offline_cpu(unsigned int cpu);
#endif

void __init workqueue_init_early(void);
void __init workqueue_init(void);
void __init workqueue_init_topology(void);

#endif
