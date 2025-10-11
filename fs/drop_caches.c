// SPDX-License-Identifier: GPL-2.0
/*
 * Implement the manual drop-all-pagecache function
 */

#include <linux/pagemap.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/writeback.h>
#include <linux/sysctl.h>
#include <linux/gfp.h>
#include <linux/swap.h>
#include "internal.h"

/* A global variable is a bit ugly, but it keeps the code simple */
static int sysctl_drop_caches;

static void drop_pagecache_sb(struct super_block *sb, void *unused)
{
	struct genradix_iter iter;
	void **i;

	rcu_read_lock();
	genradix_for_each(&sb->s_inodes.items, iter, i) {
		struct inode *inode = *((struct inode **) i);
		if (!inode)
			continue;

		spin_lock(&inode->i_lock);
		/*
		 * We must skip inodes in unusual state. We may also skip
		 * inodes without pages but we deliberately won't in case
		 * we need to reschedule to avoid softlockups.
		 */
		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (mapping_empty(inode->i_mapping) && !need_resched())) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		rcu_read_unlock();

		invalidate_mapping_pages(inode->i_mapping, 0, -1);
		iput(inode);

		cond_resched();
		rcu_read_lock();
	}
	rcu_read_unlock();
}

static int drop_caches_sysctl_handler(const struct ctl_table *table, int write,
		void *buffer, size_t *length, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (ret)
		return ret;
	if (write) {
		static int stfu;

		if (sysctl_drop_caches & 1) {
			lru_add_drain_all();
			iterate_supers(drop_pagecache_sb, NULL);
			count_vm_event(DROP_PAGECACHE);
		}
		if (sysctl_drop_caches & 2) {
			drop_slab();
			count_vm_event(DROP_SLAB);
		}
		if (!stfu) {
			pr_info("%s (%d): drop_caches: %d\n",
				current->comm, task_pid_nr(current),
				sysctl_drop_caches);
		}
		stfu |= sysctl_drop_caches & 4;
	}
	return 0;
}

static const struct ctl_table drop_caches_table[] = {
	{
		.procname	= "drop_caches",
		.data		= &sysctl_drop_caches,
		.maxlen		= sizeof(int),
		.mode		= 0200,
		.proc_handler	= drop_caches_sysctl_handler,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_FOUR,
	},
};

static int __init init_vm_drop_caches_sysctls(void)
{
	register_sysctl_init("vm", drop_caches_table);
	return 0;
}
fs_initcall(init_vm_drop_caches_sysctls);
