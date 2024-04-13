#define pr_fmt(fmt) "%s() " fmt "\n", __func__

#include <linux/debugfs.h>
#include <linux/generic-radix-tree.h>
#include <linux/init.h>
#include <linux/mmu_context.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/spinlock.h>
#include <linux/stacktrace.h>
#include <linux/time_stats.h>

#include "sched.h"

struct sched_wakeup_bt {
	unsigned long	d[10];
};

struct sched_wakeup_stats {
	struct rhash_head	hash;
	struct sched_wakeup_bt	bt;
	struct time_stats	stats;
};

static const struct rhashtable_params sched_wakeup_bt_params = {
	.head_offset		= offsetof(struct sched_wakeup_stats, hash),
	.key_offset		= offsetof(struct sched_wakeup_stats, bt),
	.key_len		= sizeof(struct sched_wakeup_bt),
};

static struct rhashtable stats_table;
static GENRADIX(struct sched_wakeup_stats *) stats_list;
static unsigned stats_nr;
static DEFINE_SPINLOCK(stats_lock);

static struct sched_wakeup_stats *__sched_wakeup_stats_new(struct sched_wakeup_bt *bt)
{
	struct sched_wakeup_stats **slot =
		genradix_ptr_alloc(&stats_list, stats_nr, GFP_ATOMIC);
	if (!slot)
		return ERR_PTR(-ENOMEM);

	struct sched_wakeup_stats *s = kzalloc(sizeof(*s), GFP_ATOMIC);
	if (!s)
		return ERR_PTR(-ENOMEM);

	s->bt = *bt;
	int ret = rhashtable_lookup_insert_fast(&stats_table, &s->hash, sched_wakeup_bt_params);
	if (unlikely(ret)) {
		kfree(s);
		return ret != -EEXIST ? ERR_PTR(ret) : NULL;
	}

	*slot = s;
	stats_nr++;
	return s;
}

static noinline struct sched_wakeup_stats *sched_wakeup_stats_new(struct sched_wakeup_bt *bt)
{
	spin_lock(&stats_lock);
	struct sched_wakeup_stats *s = __sched_wakeup_stats_new(bt);
	spin_unlock(&stats_lock);
	return s;
}

void sched_wakeup_backtrace(struct task_struct *task, u64 start_time)
{
	if (!stats_table.tbl)
		return;

	if (task->__state & TASK_NOLOAD)
		return;

	u64 now = ktime_get_ns();
	u64 duration = now - start_time;

	if (duration < NSEC_PER_USEC)
		return;

	struct sched_wakeup_bt bt = {};
	stack_trace_save_tsk(task, bt.d, ARRAY_SIZE(bt.d), 0);

	struct sched_wakeup_stats *s;
	while (!(s = rhashtable_lookup(&stats_table, &bt, sched_wakeup_bt_params) ?:
		 sched_wakeup_stats_new(&bt)))
	       ;

	if (likely(!IS_ERR(s)))
		__time_stats_update(&s->stats, start_time, now);
}

struct sched_wakeup_iter {
	loff_t				pos;
	size_t				nr;
	struct sched_wakeup_stats	*d[];
};

#define cmp_int(l, r)		((l > r) - (l < r))

static int sched_wakeup_stats_cmp(const void *_l, const void *_r)
{
	const struct sched_wakeup_stats * const *l = _l;
	const struct sched_wakeup_stats * const *r = _r;

	return -cmp_int((*l)->stats.total_duration, (*r)->stats.total_duration);
}

static void *sched_wakeup_start(struct seq_file *m, loff_t *pos)
{
	unsigned nr = READ_ONCE(stats_nr);
	struct sched_wakeup_iter *iter =
		kzalloc(struct_size(iter, d, nr), GFP_KERNEL);
	if (!iter)
		return NULL;

	iter->pos	= *pos;
	iter->nr	= nr;

	for (size_t i = 0; i < nr; i++)
		iter->d[i] = *genradix_ptr(&stats_list, i);

	sort(iter->d, nr, sizeof(iter->d[0]), sched_wakeup_stats_cmp, NULL);
	return iter;
}

static void sched_wakeup_stop(struct seq_file *m, void *arg)
{
	kfree(arg);
}

static void *sched_wakeup_next(struct seq_file *m, void *arg, loff_t *pos)
{
	struct sched_wakeup_iter *iter = arg;

	*pos = ++iter->pos;

	if (iter->pos >= iter->nr)
		return NULL;

	return iter;
}

static int sched_wakeup_show(struct seq_file *m, void *arg)
{
	struct sched_wakeup_iter *iter = arg;
	struct sched_wakeup_stats *s = iter->d[iter->pos];

	if (!s)
		return 0;

	char *bufp;
	size_t n = seq_get_buf(m, &bufp);

	struct seq_buf buf;
	seq_buf_init(&buf, bufp, n);

	if (iter->pos)
		seq_buf_puts(&buf, "\n");

	for (unsigned i = 0; i < ARRAY_SIZE(s->bt.d) && s->bt.d[i]; i++)
		seq_buf_printf(&buf, "%pS\n", (void *) s->bt.d[i]);

	time_stats_to_seq_buf(&buf, &s->stats, "startup", 0);
	seq_commit(m, seq_buf_used(&buf));
	return 0;
}

static const struct seq_operations sched_wakeup_ops = {
	.start	= sched_wakeup_start,
	.stop	= sched_wakeup_stop,
	.next	= sched_wakeup_next,
	.show	= sched_wakeup_show,
};

static int sched_wakeups_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &sched_wakeup_ops);
}

static const struct file_operations sched_wakeups_fops = {
	.open		= sched_wakeups_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int sched_wakeup_backtrace_init(void)
{
	int ret = rhashtable_init(&stats_table, &sched_wakeup_bt_params);
	WARN_ON(ret);

	WARN_ON(!stats_table.tbl);

	debugfs_create_file("wakeups", 0444, debugfs_sched, NULL, &sched_wakeups_fops);
	return 0;
}
late_initcall(sched_wakeup_backtrace_init);
