/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sched

#if !defined(_TRACE_SCHED_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SCHED_H

#include <linux/kthread.h>
#include <linux/sched/numa_balancing.h>
#include <linux/tracepoint.h>
#include <linux/binfmts.h>

/*
 * Tracepoint for calling kthread_stop, performed to end a kthread:
 */
TRACE_EVENT(sched_kthread_stop,

	TP_PROTO(struct task_struct *t),

	TP_ARGS(t),

	TP_STRUCT__entry(
		__string(	comm,	t->comm		)
		__field(	pid_t,	pid		)
	),

	TP_fast_assign(
		__assign_str(comm);
		__entry->pid	= t->pid;
	),

	TP_printk("comm=%s pid=%d", __get_str(comm), __entry->pid)
);

/*
 * Tracepoint for the return value of the kthread stopping:
 */
TRACE_EVENT(sched_kthread_stop_ret,

	TP_PROTO(int ret),

	TP_ARGS(ret),

	TP_STRUCT__entry(
		__field(	int,	ret	)
	),

	TP_fast_assign(
		__entry->ret	= ret;
	),

	TP_printk("ret=%d", __entry->ret)
);

/**
 * sched_kthread_work_queue_work - called when a work gets queued
 * @worker:	pointer to the kthread_worker
 * @work:	pointer to struct kthread_work
 *
 * This event occurs when a work is queued immediately or once a
 * delayed work is actually queued (ie: once the delay has been
 * reached).
 */
TRACE_EVENT(sched_kthread_work_queue_work,

	TP_PROTO(struct kthread_worker *worker,
		 struct kthread_work *work),

	TP_ARGS(worker, work),

	TP_STRUCT__entry(
		__field( void *,	work	)
		__field( void *,	function)
		__field( void *,	worker)
	),

	TP_fast_assign(
		__entry->work		= work;
		__entry->function	= work->func;
		__entry->worker		= worker;
	),

	TP_printk("work struct=%p function=%ps worker=%p",
		  __entry->work, __entry->function, __entry->worker)
);

/**
 * sched_kthread_work_execute_start - called immediately before the work callback
 * @work:	pointer to struct kthread_work
 *
 * Allows to track kthread work execution.
 */
TRACE_EVENT(sched_kthread_work_execute_start,

	TP_PROTO(struct kthread_work *work),

	TP_ARGS(work),

	TP_STRUCT__entry(
		__field( void *,	work	)
		__field( void *,	function)
	),

	TP_fast_assign(
		__entry->work		= work;
		__entry->function	= work->func;
	),

	TP_printk("work struct %p: function %ps", __entry->work, __entry->function)
);

/**
 * sched_kthread_work_execute_end - called immediately after the work callback
 * @work:	pointer to struct work_struct
 * @function:   pointer to worker function
 *
 * Allows to track workqueue execution.
 */
TRACE_EVENT(sched_kthread_work_execute_end,

	TP_PROTO(struct kthread_work *work, kthread_work_func_t function),

	TP_ARGS(work, function),

	TP_STRUCT__entry(
		__field( void *,	work	)
		__field( void *,	function)
	),

	TP_fast_assign(
		__entry->work		= work;
		__entry->function	= function;
	),

	TP_printk("work struct %p: function %ps", __entry->work, __entry->function)
);

/*
 * Tracepoint for waking up a task:
 */
DECLARE_EVENT_CLASS(sched_wakeup_template,

	TP_PROTO(struct task_struct *p),

	TP_ARGS(__perf_task(p)),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(	int,	prio			)
		__field(	int,	target_cpu		)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid		= p->pid;
		__entry->prio		= p->prio; /* XXX SCHED_DEADLINE */
		__entry->target_cpu	= task_cpu(p);
	),

	TP_printk("comm=%s pid=%d prio=%d target_cpu=%03d",
		  __entry->comm, __entry->pid, __entry->prio,
		  __entry->target_cpu)
);

/*
 * Tracepoint called when waking a task; this tracepoint is guaranteed to be
 * called from the waking context.
 */
DEFINE_EVENT(sched_wakeup_template, sched_waking,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));

/*
 * Tracepoint called when the task is actually woken; p->state == TASK_RUNNING.
 * It is not always called from the waking context.
 */
DEFINE_EVENT(sched_wakeup_template, sched_wakeup,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));

/*
 * Tracepoint for waking up a new task:
 */
DEFINE_EVENT(sched_wakeup_template, sched_wakeup_new,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));

#ifdef CREATE_TRACE_POINTS
static inline long __trace_sched_switch_state(bool preempt,
					      unsigned int prev_state,
					      struct task_struct *p)
{
	unsigned int state;

	BUG_ON(p != current);

	/*
	 * Preemption ignores task state, therefore preempted tasks are always
	 * RUNNING (we will not have dequeued if state != RUNNING).
	 */
	if (preempt)
		return TASK_REPORT_MAX;

	/*
	 * task_state_index() uses fls() and returns a value from 0-8 range.
	 * Decrement it by 1 (except TASK_RUNNING state i.e 0) before using
	 * it for left shift operation to get the correct task->state
	 * mapping.
	 */
	state = __task_state_index(prev_state, p->exit_state);

	return state ? (1 << (state - 1)) : state;
}
#endif /* CREATE_TRACE_POINTS */

/*
 * Tracepoint for task switches, performed by the scheduler:
 */
TRACE_EVENT(sched_switch,

	TP_PROTO(bool preempt,
		 struct task_struct *prev,
		 struct task_struct *next,
		 unsigned int prev_state),

	TP_ARGS(preempt, prev, next, prev_state),

	TP_STRUCT__entry(
		__array(	char,	prev_comm,	TASK_COMM_LEN	)
		__field(	pid_t,	prev_pid			)
		__field(	int,	prev_prio			)
		__field(	long,	prev_state			)
		__array(	char,	next_comm,	TASK_COMM_LEN	)
		__field(	pid_t,	next_pid			)
		__field(	int,	next_prio			)
	),

	TP_fast_assign(
		memcpy(__entry->prev_comm, prev->comm, TASK_COMM_LEN);
		__entry->prev_pid	= prev->pid;
		__entry->prev_prio	= prev->prio;
		__entry->prev_state	= __trace_sched_switch_state(preempt, prev_state, prev);
		memcpy(__entry->next_comm, next->comm, TASK_COMM_LEN);
		__entry->next_pid	= next->pid;
		__entry->next_prio	= next->prio;
		/* XXX SCHED_DEADLINE */
	),

	TP_printk("prev_comm=%s prev_pid=%d prev_prio=%d prev_state=%s%s ==> next_comm=%s next_pid=%d next_prio=%d",
		__entry->prev_comm, __entry->prev_pid, __entry->prev_prio,

		(__entry->prev_state & (TASK_REPORT_MAX - 1)) ?
		  __print_flags(__entry->prev_state & (TASK_REPORT_MAX - 1), "|",
				{ TASK_INTERRUPTIBLE, "S" },
				{ TASK_UNINTERRUPTIBLE, "D" },
				{ __TASK_STOPPED, "T" },
				{ __TASK_TRACED, "t" },
				{ EXIT_DEAD, "X" },
				{ EXIT_ZOMBIE, "Z" },
				{ TASK_PARKED, "P" },
				{ TASK_DEAD, "I" }) :
		  "R",

		__entry->prev_state & TASK_REPORT_MAX ? "+" : "",
		__entry->next_comm, __entry->next_pid, __entry->next_prio)
);

/*
 * Tracepoint for a task being migrated:
 */
TRACE_EVENT(sched_migrate_task,

	TP_PROTO(struct task_struct *p, int dest_cpu),

	TP_ARGS(p, dest_cpu),

	TP_STRUCT__entry(
		__string(	comm,	p->comm		)
		__field(	pid_t,	pid		)
		__field(	int,	prio		)
		__field(	int,	orig_cpu	)
		__field(	int,	dest_cpu	)
	),

	TP_fast_assign(
		__assign_str(comm);
		__entry->pid		= p->pid;
		__entry->prio		= p->prio; /* XXX SCHED_DEADLINE */
		__entry->orig_cpu	= task_cpu(p);
		__entry->dest_cpu	= dest_cpu;
	),

	TP_printk("comm=%s pid=%d prio=%d orig_cpu=%d dest_cpu=%d",
		  __get_str(comm), __entry->pid, __entry->prio,
		  __entry->orig_cpu, __entry->dest_cpu)
);

DECLARE_EVENT_CLASS(sched_process_template,

	TP_PROTO(struct task_struct *p),

	TP_ARGS(p),

	TP_STRUCT__entry(
		__string(	comm,	p->comm		)
		__field(	pid_t,	pid		)
		__field(	int,	prio		)
	),

	TP_fast_assign(
		__assign_str(comm);
		__entry->pid		= p->pid;
		__entry->prio		= p->prio; /* XXX SCHED_DEADLINE */
	),

	TP_printk("comm=%s pid=%d prio=%d",
		  __get_str(comm), __entry->pid, __entry->prio)
);

/*
 * Tracepoint for freeing a task:
 */
DEFINE_EVENT(sched_process_template, sched_process_free,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));

/*
 * Tracepoint for a task exiting.
 * Note, it's a superset of sched_process_template and should be kept
 * compatible as much as possible. sched_process_exits has an extra
 * `group_dead` argument, so sched_process_template can't be used,
 * unfortunately, just like sched_migrate_task above.
 */
TRACE_EVENT(sched_process_exit,

	TP_PROTO(struct task_struct *p, bool group_dead),

	TP_ARGS(p, group_dead),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(	int,	prio			)
		__field(	bool,	group_dead		)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid		= p->pid;
		__entry->prio		= p->prio; /* XXX SCHED_DEADLINE */
		__entry->group_dead	= group_dead;
	),

	TP_printk("comm=%s pid=%d prio=%d group_dead=%s",
		  __entry->comm, __entry->pid, __entry->prio,
		  __entry->group_dead ? "true" : "false"
	)
);

/*
 * Tracepoint for waiting on task to unschedule:
 */
DEFINE_EVENT(sched_process_template, sched_wait_task,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

/*
 * Tracepoint for a waiting task:
 */
TRACE_EVENT(sched_process_wait,

	TP_PROTO(struct pid *pid),

	TP_ARGS(pid),

	TP_STRUCT__entry(
		__string(	comm,	current->comm		)
		__field(	pid_t,	pid			)
		__field(	int,	prio			)
	),

	TP_fast_assign(
		__assign_str(comm);
		__entry->pid		= pid_nr(pid);
		__entry->prio		= current->prio; /* XXX SCHED_DEADLINE */
	),

	TP_printk("comm=%s pid=%d prio=%d",
		  __get_str(comm), __entry->pid, __entry->prio)
);

/*
 * Tracepoint for kernel_clone:
 */
TRACE_EVENT(sched_process_fork,

	TP_PROTO(struct task_struct *parent, struct task_struct *child),

	TP_ARGS(parent, child),

	TP_STRUCT__entry(
		__string(	parent_comm,	parent->comm	)
		__field(	pid_t,		parent_pid	)
		__string(	child_comm,	child->comm	)
		__field(	pid_t,		child_pid	)
	),

	TP_fast_assign(
		__assign_str(parent_comm);
		__entry->parent_pid	= parent->pid;
		__assign_str(child_comm);
		__entry->child_pid	= child->pid;
	),

	TP_printk("comm=%s pid=%d child_comm=%s child_pid=%d",
		__get_str(parent_comm), __entry->parent_pid,
		__get_str(child_comm), __entry->child_pid)
);

/*
 * Tracepoint for exec:
 */
TRACE_EVENT(sched_process_exec,

	TP_PROTO(struct task_struct *p, pid_t old_pid,
		 struct linux_binprm *bprm),

	TP_ARGS(p, old_pid, bprm),

	TP_STRUCT__entry(
		__string(	filename,	bprm->filename	)
		__field(	pid_t,		pid		)
		__field(	pid_t,		old_pid		)
	),

	TP_fast_assign(
		__assign_str(filename);
		__entry->pid		= p->pid;
		__entry->old_pid	= old_pid;
	),

	TP_printk("filename=%s pid=%d old_pid=%d", __get_str(filename),
		  __entry->pid, __entry->old_pid)
);

/**
 * sched_prepare_exec - called before setting up new exec
 * @task:	pointer to the current task
 * @bprm:	pointer to linux_binprm used for new exec
 *
 * Called before flushing the old exec, where @task is still unchanged, but at
 * the point of no return during switching to the new exec. At the point it is
 * called the exec will either succeed, or on failure terminate the task. Also
 * see the "sched_process_exec" tracepoint, which is called right after @task
 * has successfully switched to the new exec.
 */
TRACE_EVENT(sched_prepare_exec,

	TP_PROTO(struct task_struct *task, struct linux_binprm *bprm),

	TP_ARGS(task, bprm),

	TP_STRUCT__entry(
		__string(	interp,		bprm->interp	)
		__string(	filename,	bprm->filename	)
		__field(	pid_t,		pid		)
		__string(	comm,		task->comm	)
	),

	TP_fast_assign(
		__assign_str(interp);
		__assign_str(filename);
		__entry->pid = task->pid;
		__assign_str(comm);
	),

	TP_printk("interp=%s filename=%s pid=%d comm=%s",
		  __get_str(interp), __get_str(filename),
		  __entry->pid, __get_str(comm))
);

#ifdef CONFIG_SCHEDSTATS
#define DEFINE_EVENT_SCHEDSTAT DEFINE_EVENT
#define DECLARE_EVENT_CLASS_SCHEDSTAT DECLARE_EVENT_CLASS
#else
#define DEFINE_EVENT_SCHEDSTAT DEFINE_EVENT_NOP
#define DECLARE_EVENT_CLASS_SCHEDSTAT DECLARE_EVENT_CLASS_NOP
#endif

/*
 * XXX the below sched_stat tracepoints only apply to SCHED_OTHER/BATCH/IDLE
 *     adding sched_stat support to SCHED_FIFO/RR would be welcome.
 */
DECLARE_EVENT_CLASS_SCHEDSTAT(sched_stat_template,

	TP_PROTO(struct task_struct *tsk, u64 delay),

	TP_ARGS(__perf_task(tsk), __perf_count(delay)),

	TP_STRUCT__entry(
		__string( comm,	tsk->comm	)
		__field(  pid_t,	pid	)
		__field(  u64,		delay	)
	),

	TP_fast_assign(
		__assign_str(comm);
		__entry->pid	= tsk->pid;
		__entry->delay	= delay;
	),

	TP_printk("comm=%s pid=%d delay=%Lu [ns]",
			__get_str(comm), __entry->pid,
			(unsigned long long)__entry->delay)
);

/*
 * Tracepoint for accounting wait time (time the task is runnable
 * but not actually running due to scheduler contention).
 */
DEFINE_EVENT_SCHEDSTAT(sched_stat_template, sched_stat_wait,
	     TP_PROTO(struct task_struct *tsk, u64 delay),
	     TP_ARGS(tsk, delay));

/*
 * Tracepoint for accounting sleep time (time the task is not runnable,
 * including iowait, see below).
 */
DEFINE_EVENT_SCHEDSTAT(sched_stat_template, sched_stat_sleep,
	     TP_PROTO(struct task_struct *tsk, u64 delay),
	     TP_ARGS(tsk, delay));

/*
 * Tracepoint for accounting iowait time (time the task is not runnable
 * due to waiting on IO to complete).
 */
DEFINE_EVENT_SCHEDSTAT(sched_stat_template, sched_stat_iowait,
	     TP_PROTO(struct task_struct *tsk, u64 delay),
	     TP_ARGS(tsk, delay));

/*
 * Tracepoint for accounting blocked time (time the task is in uninterruptible).
 */
DEFINE_EVENT_SCHEDSTAT(sched_stat_template, sched_stat_blocked,
	     TP_PROTO(struct task_struct *tsk, u64 delay),
	     TP_ARGS(tsk, delay));

/*
 * Tracepoint for accounting runtime (time the task is executing
 * on a CPU).
 */
DECLARE_EVENT_CLASS(sched_stat_runtime,

	TP_PROTO(struct task_struct *tsk, u64 runtime),

	TP_ARGS(tsk, __perf_count(runtime)),

	TP_STRUCT__entry(
		__string( comm,		tsk->comm	)
		__field(  pid_t,	pid		)
		__field(  u64,		runtime		)
	),

	TP_fast_assign(
		__assign_str(comm);
		__entry->pid		= tsk->pid;
		__entry->runtime	= runtime;
	),

	TP_printk("comm=%s pid=%d runtime=%Lu [ns]",
			__get_str(comm), __entry->pid,
			(unsigned long long)__entry->runtime)
);

DEFINE_EVENT(sched_stat_runtime, sched_stat_runtime,
	     TP_PROTO(struct task_struct *tsk, u64 runtime),
	     TP_ARGS(tsk, runtime));

/*
 * Tracepoint for showing priority inheritance modifying a tasks
 * priority.
 */
TRACE_EVENT(sched_pi_setprio,

	TP_PROTO(struct task_struct *tsk, struct task_struct *pi_task),

	TP_ARGS(tsk, pi_task),

	TP_STRUCT__entry(
		__string( comm,		tsk->comm	)
		__field(  pid_t,	pid		)
		__field(  int,		oldprio		)
		__field(  int,		newprio		)
	),

	TP_fast_assign(
		__assign_str(comm);
		__entry->pid		= tsk->pid;
		__entry->oldprio	= tsk->prio;
		__entry->newprio	= pi_task ?
				min(tsk->normal_prio, pi_task->prio) :
				tsk->normal_prio;
		/* XXX SCHED_DEADLINE bits missing */
	),

	TP_printk("comm=%s pid=%d oldprio=%d newprio=%d",
			__get_str(comm), __entry->pid,
			__entry->oldprio, __entry->newprio)
);

#ifdef CONFIG_DETECT_HUNG_TASK
TRACE_EVENT(sched_process_hang,
	TP_PROTO(struct task_struct *tsk),
	TP_ARGS(tsk),

	TP_STRUCT__entry(
		__string( comm,		tsk->comm	)
		__field(  pid_t,	pid		)
	),

	TP_fast_assign(
		__assign_str(comm);
		__entry->pid = tsk->pid;
	),

	TP_printk("comm=%s pid=%d", __get_str(comm), __entry->pid)
);
#endif /* CONFIG_DETECT_HUNG_TASK */

#ifdef CONFIG_NUMA_BALANCING
/*
 * Tracks migration of tasks from one runqueue to another. Can be used to
 * detect if automatic NUMA balancing is bouncing between nodes.
 */
TRACE_EVENT(sched_move_numa,

	TP_PROTO(struct task_struct *tsk, int src_cpu, int dst_cpu),

	TP_ARGS(tsk, src_cpu, dst_cpu),

	TP_STRUCT__entry(
		__field( pid_t,	pid			)
		__field( pid_t,	tgid			)
		__field( pid_t,	ngid			)
		__field( int,	src_cpu			)
		__field( int,	src_nid			)
		__field( int,	dst_cpu			)
		__field( int,	dst_nid			)
	),

	TP_fast_assign(
		__entry->pid		= task_pid_nr(tsk);
		__entry->tgid		= task_tgid_nr(tsk);
		__entry->ngid		= task_numa_group_id(tsk);
		__entry->src_cpu	= src_cpu;
		__entry->src_nid	= cpu_to_node(src_cpu);
		__entry->dst_cpu	= dst_cpu;
		__entry->dst_nid	= cpu_to_node(dst_cpu);
	),

	TP_printk("pid=%d tgid=%d ngid=%d src_cpu=%d src_nid=%d dst_cpu=%d dst_nid=%d",
			__entry->pid, __entry->tgid, __entry->ngid,
			__entry->src_cpu, __entry->src_nid,
			__entry->dst_cpu, __entry->dst_nid)
);

DECLARE_EVENT_CLASS(sched_numa_pair_template,

	TP_PROTO(struct task_struct *src_tsk, int src_cpu,
		 struct task_struct *dst_tsk, int dst_cpu),

	TP_ARGS(src_tsk, src_cpu, dst_tsk, dst_cpu),

	TP_STRUCT__entry(
		__field( pid_t,	src_pid			)
		__field( pid_t,	src_tgid		)
		__field( pid_t,	src_ngid		)
		__field( int,	src_cpu			)
		__field( int,	src_nid			)
		__field( pid_t,	dst_pid			)
		__field( pid_t,	dst_tgid		)
		__field( pid_t,	dst_ngid		)
		__field( int,	dst_cpu			)
		__field( int,	dst_nid			)
	),

	TP_fast_assign(
		__entry->src_pid	= task_pid_nr(src_tsk);
		__entry->src_tgid	= task_tgid_nr(src_tsk);
		__entry->src_ngid	= task_numa_group_id(src_tsk);
		__entry->src_cpu	= src_cpu;
		__entry->src_nid	= cpu_to_node(src_cpu);
		__entry->dst_pid	= dst_tsk ? task_pid_nr(dst_tsk) : 0;
		__entry->dst_tgid	= dst_tsk ? task_tgid_nr(dst_tsk) : 0;
		__entry->dst_ngid	= dst_tsk ? task_numa_group_id(dst_tsk) : 0;
		__entry->dst_cpu	= dst_cpu;
		__entry->dst_nid	= dst_cpu >= 0 ? cpu_to_node(dst_cpu) : -1;
	),

	TP_printk("src_pid=%d src_tgid=%d src_ngid=%d src_cpu=%d src_nid=%d dst_pid=%d dst_tgid=%d dst_ngid=%d dst_cpu=%d dst_nid=%d",
			__entry->src_pid, __entry->src_tgid, __entry->src_ngid,
			__entry->src_cpu, __entry->src_nid,
			__entry->dst_pid, __entry->dst_tgid, __entry->dst_ngid,
			__entry->dst_cpu, __entry->dst_nid)
);

DEFINE_EVENT(sched_numa_pair_template, sched_stick_numa,

	TP_PROTO(struct task_struct *src_tsk, int src_cpu,
		 struct task_struct *dst_tsk, int dst_cpu),

	TP_ARGS(src_tsk, src_cpu, dst_tsk, dst_cpu)
);

DEFINE_EVENT(sched_numa_pair_template, sched_swap_numa,

	TP_PROTO(struct task_struct *src_tsk, int src_cpu,
		 struct task_struct *dst_tsk, int dst_cpu),

	TP_ARGS(src_tsk, src_cpu, dst_tsk, dst_cpu)
);

#define NUMAB_SKIP_REASON					\
	EM( NUMAB_SKIP_UNSUITABLE,		"unsuitable" )	\
	EM( NUMAB_SKIP_SHARED_RO,		"shared_ro" )	\
	EM( NUMAB_SKIP_INACCESSIBLE,		"inaccessible" )	\
	EM( NUMAB_SKIP_SCAN_DELAY,		"scan_delay" )	\
	EM( NUMAB_SKIP_PID_INACTIVE,		"pid_inactive" )	\
	EM( NUMAB_SKIP_IGNORE_PID,		"ignore_pid_inactive" )		\
	EMe(NUMAB_SKIP_SEQ_COMPLETED,		"seq_completed" )

/* Redefine for export. */
#undef EM
#undef EMe
#define EM(a, b)	TRACE_DEFINE_ENUM(a);
#define EMe(a, b)	TRACE_DEFINE_ENUM(a);

NUMAB_SKIP_REASON

/* Redefine for symbolic printing. */
#undef EM
#undef EMe
#define EM(a, b)	{ a, b },
#define EMe(a, b)	{ a, b }

TRACE_EVENT(sched_skip_vma_numa,

	TP_PROTO(struct mm_struct *mm, struct vm_area_struct *vma,
		 enum numa_vmaskip_reason reason),

	TP_ARGS(mm, vma, reason),

	TP_STRUCT__entry(
		__field(unsigned long, numa_scan_offset)
		__field(unsigned long, vm_start)
		__field(unsigned long, vm_end)
		__field(enum numa_vmaskip_reason, reason)
	),

	TP_fast_assign(
		__entry->numa_scan_offset	= mm->numa_scan_offset;
		__entry->vm_start		= vma->vm_start;
		__entry->vm_end			= vma->vm_end;
		__entry->reason			= reason;
	),

	TP_printk("numa_scan_offset=%lX vm_start=%lX vm_end=%lX reason=%s",
		  __entry->numa_scan_offset,
		  __entry->vm_start,
		  __entry->vm_end,
		  __print_symbolic(__entry->reason, NUMAB_SKIP_REASON))
);

TRACE_EVENT(sched_skip_cpuset_numa,

	TP_PROTO(struct task_struct *tsk, nodemask_t *mem_allowed_ptr),

	TP_ARGS(tsk, mem_allowed_ptr),

	TP_STRUCT__entry(
		__array( char,		comm,		TASK_COMM_LEN		)
		__field( pid_t,		pid					)
		__field( pid_t,		tgid					)
		__field( pid_t,		ngid					)
		__array( unsigned long, mem_allowed, BITS_TO_LONGS(MAX_NUMNODES))
	),

	TP_fast_assign(
		memcpy(__entry->comm, tsk->comm, TASK_COMM_LEN);
		__entry->pid		 = task_pid_nr(tsk);
		__entry->tgid		 = task_tgid_nr(tsk);
		__entry->ngid		 = task_numa_group_id(tsk);
		BUILD_BUG_ON(sizeof(nodemask_t) != \
			     BITS_TO_LONGS(MAX_NUMNODES) * sizeof(long));
		memcpy(__entry->mem_allowed, mem_allowed_ptr->bits,
		       sizeof(__entry->mem_allowed));
	),

	TP_printk("comm=%s pid=%d tgid=%d ngid=%d mem_nodes_allowed=%*pbl",
		  __entry->comm,
		  __entry->pid,
		  __entry->tgid,
		  __entry->ngid,
		  MAX_NUMNODES, __entry->mem_allowed)
);
#endif /* CONFIG_NUMA_BALANCING */

/*
 * Tracepoint for waking a polling cpu without an IPI.
 */
TRACE_EVENT(sched_wake_idle_without_ipi,

	TP_PROTO(int cpu),

	TP_ARGS(cpu),

	TP_STRUCT__entry(
		__field(	int,	cpu	)
	),

	TP_fast_assign(
		__entry->cpu	= cpu;
	),

	TP_printk("cpu=%d", __entry->cpu)
);

/*
 * Following tracepoints are not exported in tracefs and provide hooking
 * mechanisms only for testing and debugging purposes.
 */
DECLARE_TRACE(pelt_cfs,
	TP_PROTO(struct cfs_rq *cfs_rq),
	TP_ARGS(cfs_rq));

DECLARE_TRACE(pelt_rt,
	TP_PROTO(struct rq *rq),
	TP_ARGS(rq));

DECLARE_TRACE(pelt_dl,
	TP_PROTO(struct rq *rq),
	TP_ARGS(rq));

DECLARE_TRACE(pelt_hw,
	TP_PROTO(struct rq *rq),
	TP_ARGS(rq));

DECLARE_TRACE(pelt_irq,
	TP_PROTO(struct rq *rq),
	TP_ARGS(rq));

DECLARE_TRACE(pelt_se,
	TP_PROTO(struct sched_entity *se),
	TP_ARGS(se));

DECLARE_TRACE(sched_cpu_capacity,
	TP_PROTO(struct rq *rq),
	TP_ARGS(rq));

DECLARE_TRACE(sched_overutilized,
	TP_PROTO(struct root_domain *rd, bool overutilized),
	TP_ARGS(rd, overutilized));

DECLARE_TRACE(sched_util_est_cfs,
	TP_PROTO(struct cfs_rq *cfs_rq),
	TP_ARGS(cfs_rq));

DECLARE_TRACE(sched_util_est_se,
	TP_PROTO(struct sched_entity *se),
	TP_ARGS(se));

DECLARE_TRACE(sched_update_nr_running,
	TP_PROTO(struct rq *rq, int change),
	TP_ARGS(rq, change));

DECLARE_TRACE(sched_compute_energy,
	TP_PROTO(struct task_struct *p, int dst_cpu, unsigned long energy,
		 unsigned long max_util, unsigned long busy_time),
	TP_ARGS(p, dst_cpu, energy, max_util, busy_time));

DECLARE_TRACE(sched_entry,
	TP_PROTO(bool preempt),
	TP_ARGS(preempt));

DECLARE_TRACE(sched_exit,
	TP_PROTO(bool is_switch),
	TP_ARGS(is_switch));

DECLARE_TRACE_CONDITION(sched_set_state,
	TP_PROTO(struct task_struct *tsk, int state),
	TP_ARGS(tsk, state),
	TP_CONDITION(!!(tsk->__state) != !!state));

DECLARE_TRACE(sched_set_need_resched,
	TP_PROTO(struct task_struct *tsk, int cpu, int tif),
	TP_ARGS(tsk, cpu, tif));

#endif /* _TRACE_SCHED_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
