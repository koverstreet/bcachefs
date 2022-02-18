// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015 Davidlohr Bueso.
 */

/* For the CLR_() macros */
#include <string.h>
#include <pthread.h>

#include <signal.h>
#include "../util/stat.h"
#include <subcmd/parse-options.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/zalloc.h>
#include <errno.h>
#include <perf/cpumap.h>
#include "bench.h"
#include "futex.h"

#include <err.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/mman.h>

struct worker {
	int tid;
	u_int32_t *futex;
	pthread_t thread;
	unsigned long ops;
};

static u_int32_t global_futex = 0;
static struct worker *worker;
static bool done = false;
static int futex_flag = 0;
static pthread_mutex_t thread_lock;
static unsigned int threads_starting;
static struct stats throughput_stats;
static pthread_cond_t thread_parent, thread_worker;

static struct bench_futex_parameters params = {
	.runtime  = 10,
};

static const struct option options[] = {
	OPT_UINTEGER('t', "threads", &params.nthreads, "Specify amount of threads"),
	OPT_UINTEGER('r', "runtime", &params.runtime, "Specify runtime (in seconds)"),
	OPT_BOOLEAN( 'M', "multi",   &params.multi, "Use multiple futexes"),
	OPT_BOOLEAN( 's', "silent",  &params.silent, "Silent mode: do not display data/details"),
	OPT_BOOLEAN( 'S', "shared",  &params.fshared, "Use shared futexes instead of private ones"),
	OPT_BOOLEAN( 'm', "mlockall", &params.mlockall, "Lock all current and future memory"),
	OPT_END()
};

static const char * const bench_futex_lock_pi_usage[] = {
	"perf bench futex lock-pi <options>",
	NULL
};

static void print_summary(void)
{
	unsigned long avg = avg_stats(&throughput_stats);
	double stddev = stddev_stats(&throughput_stats);

	printf("%sAveraged %ld operations/sec (+- %.2f%%), total secs = %d\n",
	       !params.silent ? "\n" : "", avg, rel_stddev_stats(stddev, avg),
	       (int)bench__runtime.tv_sec);
}

static void toggle_done(int sig __maybe_unused,
			siginfo_t *info __maybe_unused,
			void *uc __maybe_unused)
{
	/* inform all threads that we're done for the day */
	done = true;
	gettimeofday(&bench__end, NULL);
	timersub(&bench__end, &bench__start, &bench__runtime);
}

static void *workerfn(void *arg)
{
	struct worker *w = (struct worker *) arg;
	unsigned long ops = w->ops;

	pthread_mutex_lock(&thread_lock);
	threads_starting--;
	if (!threads_starting)
		pthread_cond_signal(&thread_parent);
	pthread_cond_wait(&thread_worker, &thread_lock);
	pthread_mutex_unlock(&thread_lock);

	do {
		int ret;
	again:
		ret = futex_lock_pi(w->futex, NULL, futex_flag);

		if (ret) { /* handle lock acquisition */
			if (!params.silent)
				warn("thread %d: Could not lock pi-lock for %p (%d)",
				     w->tid, w->futex, ret);
			if (done)
				break;

			goto again;
		}

		usleep(1);
		ret = futex_unlock_pi(w->futex, futex_flag);
		if (ret && !params.silent)
			warn("thread %d: Could not unlock pi-lock for %p (%d)",
			     w->tid, w->futex, ret);
		ops++; /* account for thread's share of work */
	}  while (!done);

	w->ops = ops;
	return NULL;
}

static void create_threads(struct worker *w, pthread_attr_t thread_attr,
			   struct perf_cpu_map *cpu)
{
	cpu_set_t cpuset;
	unsigned int i;

	threads_starting = params.nthreads;

	for (i = 0; i < params.nthreads; i++) {
		worker[i].tid = i;

		if (params.multi) {
			worker[i].futex = calloc(1, sizeof(u_int32_t));
			if (!worker[i].futex)
				err(EXIT_FAILURE, "calloc");
		} else
			worker[i].futex = &global_futex;

		CPU_ZERO(&cpuset);
		CPU_SET(cpu->map[i % cpu->nr], &cpuset);

		if (pthread_attr_setaffinity_np(&thread_attr, sizeof(cpu_set_t), &cpuset))
			err(EXIT_FAILURE, "pthread_attr_setaffinity_np");

		if (pthread_create(&w[i].thread, &thread_attr, workerfn, &worker[i]))
			err(EXIT_FAILURE, "pthread_create");
	}
}

int bench_futex_lock_pi(int argc, const char **argv)
{
	int ret = 0;
	unsigned int i;
	struct sigaction act;
	pthread_attr_t thread_attr;
	struct perf_cpu_map *cpu;

	argc = parse_options(argc, argv, options, bench_futex_lock_pi_usage, 0);
	if (argc)
		goto err;

	cpu = perf_cpu_map__new(NULL);
	if (!cpu)
		err(EXIT_FAILURE, "calloc");

	memset(&act, 0, sizeof(act));
	sigfillset(&act.sa_mask);
	act.sa_sigaction = toggle_done;
	sigaction(SIGINT, &act, NULL);

	if (params.mlockall) {
		if (mlockall(MCL_CURRENT | MCL_FUTURE))
			err(EXIT_FAILURE, "mlockall");
	}

	if (!params.nthreads)
		params.nthreads = cpu->nr;

	worker = calloc(params.nthreads, sizeof(*worker));
	if (!worker)
		err(EXIT_FAILURE, "calloc");

	if (!params.fshared)
		futex_flag = FUTEX_PRIVATE_FLAG;

	printf("Run summary [PID %d]: %d threads doing pi lock/unlock pairing for %d secs.\n\n",
	       getpid(), params.nthreads, params.runtime);

	init_stats(&throughput_stats);
	pthread_mutex_init(&thread_lock, NULL);
	pthread_cond_init(&thread_parent, NULL);
	pthread_cond_init(&thread_worker, NULL);

	threads_starting = params.nthreads;
	pthread_attr_init(&thread_attr);
	gettimeofday(&bench__start, NULL);

	create_threads(worker, thread_attr, cpu);
	pthread_attr_destroy(&thread_attr);

	pthread_mutex_lock(&thread_lock);
	while (threads_starting)
		pthread_cond_wait(&thread_parent, &thread_lock);
	pthread_cond_broadcast(&thread_worker);
	pthread_mutex_unlock(&thread_lock);

	sleep(params.runtime);
	toggle_done(0, NULL, NULL);

	for (i = 0; i < params.nthreads; i++) {
		ret = pthread_join(worker[i].thread, NULL);
		if (ret)
			err(EXIT_FAILURE, "pthread_join");
	}

	/* cleanup & report results */
	pthread_cond_destroy(&thread_parent);
	pthread_cond_destroy(&thread_worker);
	pthread_mutex_destroy(&thread_lock);

	for (i = 0; i < params.nthreads; i++) {
		unsigned long t = bench__runtime.tv_sec > 0 ?
			worker[i].ops / bench__runtime.tv_sec : 0;

		update_stats(&throughput_stats, t);
		if (!params.silent)
			printf("[thread %3d] futex: %p [ %ld ops/sec ]\n",
			       worker[i].tid, worker[i].futex, t);

		if (params.multi)
			zfree(&worker[i].futex);
	}

	print_summary();

	free(worker);
	perf_cpu_map__put(cpu);
	return ret;
err:
	usage_with_options(bench_futex_lock_pi_usage, options);
	exit(EXIT_FAILURE);
}
