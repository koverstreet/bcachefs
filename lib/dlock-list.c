/*
 * Distributed and locked list
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * (C) Copyright 2016 Hewlett-Packard Enterprise Development LP
 * (C) Copyright 2017-2018 Red Hat, Inc.
 *
 * Authors: Waiman Long <longman@redhat.com>
 */
#include <linux/dlock-list.h>
#include <linux/lockdep.h>
#include <linux/slab.h>
#include <linux/cpumask.h>

/*
 * The distributed and locked list is a distributed set of lists each of
 * which is protected by its own spinlock, but acts like a single
 * consolidated list to the callers. For scaling purpose, the number of
 * lists used is equal to the number of possible cores in the system to
 * minimize contention. All threads of the same CPU core will share the
 * same list.
 *
 * We need to map each CPU number to a list index.
 */
static DEFINE_PER_CPU_READ_MOSTLY(int, cpu2idx);
static int nr_dlock_lists __read_mostly;

/*
 * Initialize cpu2idx mapping table & nr_dlock_lists.
 *
 * It is possible that a dlock-list can be allocated before the cpu2idx is
 * initialized. In this case, all the cpus are mapped to the first entry
 * before initialization.
 *
 * All the sibling CPUs of a sibling group will map to the same dlock list so
 * as to reduce the number of dlock lists to be maintained while minimizing
 * cacheline contention.
 *
 * As the sibling masks are set up in the core initcall phase, this function
 * has to be done in the postcore phase to get the right data.
 */
static int __init cpu2idx_init(void)
{
	int idx, cpu;
	struct cpumask *sibling_mask;
	static struct cpumask mask __initdata;

	cpumask_clear(&mask);
	idx = 0;
	for_each_possible_cpu(cpu) {
		int scpu;

		if (cpumask_test_cpu(cpu, &mask))
			continue;
		per_cpu(cpu2idx, cpu) = idx;
		cpumask_set_cpu(cpu, &mask);

		sibling_mask = topology_sibling_cpumask(cpu);
		if (sibling_mask) {
			for_each_cpu(scpu, sibling_mask) {
				per_cpu(cpu2idx, scpu) = idx;
				cpumask_set_cpu(scpu, &mask);
			}
		}
		idx++;
	}

	/*
	 * nr_dlock_lists can only be set after cpu2idx is properly
	 * initialized.
	 */
	smp_mb();
	nr_dlock_lists = idx;
	WARN_ON(nr_dlock_lists > nr_cpu_ids);

	pr_info("dlock-list: %d head entries per dlock list.\n",
		nr_dlock_lists);
	return 0;
}
postcore_initcall(cpu2idx_init);

/**
 * __alloc_dlock_list_heads - Initialize and allocate the list of head entries
 * @dlist: Pointer to the dlock_list_heads structure to be initialized
 * @key  : The lock class key to be used for lockdep
 * Return: 0 if successful, -ENOMEM if memory allocation error
 *
 * This function does not allocate the dlock_list_heads structure itself. The
 * callers will have to do their own memory allocation, if necessary. However,
 * this allows embedding the dlock_list_heads structure directly into other
 * structures.
 *
 * Dynamically allocated locks need to have their own special lock class
 * to avoid lockdep warning.
 *
 * Since nr_dlock_lists will always be <= nr_cpu_ids, having more lists
 * than necessary allocated is not a problem other than some wasted memory.
 * The extra lists will not be ever used as all the cpu2idx entries will be
 * 0 before initialization.
 */
int __alloc_dlock_list_heads(struct dlock_list_heads *dlist,
			     struct lock_class_key *key)
{
	int idx, cnt = nr_dlock_lists ? nr_dlock_lists : nr_cpu_ids;

	dlist->heads = kcalloc(cnt, sizeof(struct dlock_list_head), GFP_KERNEL);

	if (!dlist->heads)
		return -ENOMEM;

	for (idx = 0; idx < cnt; idx++) {
		struct dlock_list_head *head = &dlist->heads[idx];

		INIT_LIST_HEAD(&head->list);
		head->lock = __SPIN_LOCK_UNLOCKED(&head->lock);
		lockdep_set_class(&head->lock, key);
	}
	return 0;
}
EXPORT_SYMBOL(__alloc_dlock_list_heads);

/**
 * free_dlock_list_heads - Free all the heads entries of the dlock list
 * @dlist: Pointer of the dlock_list_heads structure to be freed
 *
 * This function doesn't free the dlock_list_heads structure itself. So
 * the caller will have to do it, if necessary.
 */
void free_dlock_list_heads(struct dlock_list_heads *dlist)
{
	kfree(dlist->heads);
	dlist->heads = NULL;
}
EXPORT_SYMBOL(free_dlock_list_heads);

/**
 * dlock_lists_empty - Check if all the dlock lists are empty
 * @dlist: Pointer to the dlock_list_heads structure
 * Return: true if list is empty, false otherwise.
 *
 * This can be a pretty expensive function call. If this function is required
 * in a performance critical path, we may have to maintain a global count
 * of the list entries in the global dlock_list_heads structure instead.
 */
bool dlock_lists_empty(struct dlock_list_heads *dlist)
{
	int idx;

	/* Shouldn't be called before nr_dlock_lists is initialized */
	WARN_ON_ONCE(!nr_dlock_lists);

	for (idx = 0; idx < nr_dlock_lists; idx++)
		if (!list_empty(&dlist->heads[idx].list))
			return false;
	return true;
}
EXPORT_SYMBOL(dlock_lists_empty);

/**
 * dlock_lists_add - Adds a node to the given dlock list
 * @node : The node to be added
 * @dlist: The dlock list where the node is to be added
 *
 * List selection is based on the CPU being used when the dlock_list_add()
 * function is called. However, deletion may be done by a different CPU.
 */
void dlock_lists_add(struct dlock_list_node *node,
		     struct dlock_list_heads *dlist)
{
	struct dlock_list_head *head = &dlist->heads[this_cpu_read(cpu2idx)];

	/*
	 * There is no need to disable preemption
	 */
	spin_lock(&head->lock);
	WRITE_ONCE(node->head, head);
	list_add(&node->list, &head->list);
	spin_unlock(&head->lock);
}
EXPORT_SYMBOL(dlock_lists_add);

/**
 * dlock_lists_del - Delete a node from a dlock list
 * @node : The node to be deleted
 *
 * We need to check the lock pointer again after taking the lock to guard
 * against concurrent deletion of the same node. If the lock pointer changes
 * (becomes NULL or to a different one), we assume that the deletion was done
 * elsewhere. A warning will be printed if this happens as it is likely to be
 * a bug.
 */
void dlock_lists_del(struct dlock_list_node *node)
{
	struct dlock_list_head *head;
	bool retry;

	do {
		head = READ_ONCE(node->head);
		if (WARN_ONCE(!head, "%s: node 0x%lx has no associated head\n",
			      __func__, (unsigned long)node))
			return;

		spin_lock(&head->lock);
		if (likely(head == READ_ONCE(node->head))) {
			list_del_init(&node->list);
			WRITE_ONCE(node->head, NULL);
			retry = false;
		} else {
			/*
			 * The lock has somehow changed. Retry again if it is
			 * not NULL. Otherwise, just ignore the delete
			 * operation.
			 */
			retry = (READ_ONCE(node->head) != NULL);
		}
		spin_unlock(&head->lock);
	} while (retry);
}
EXPORT_SYMBOL(dlock_lists_del);

/**
 * __dlock_list_next_list: Find the first entry of the next available list
 * @dlist: Pointer to the dlock_list_heads structure
 * @iter : Pointer to the dlock list iterator structure
 * Return: true if the entry is found, false if all the lists exhausted
 *
 * The information about the next available list will be put into the iterator.
 */
struct dlock_list_node *__dlock_list_next_list(struct dlock_list_iter *iter)
{
	struct dlock_list_node *next;
	struct dlock_list_head *head;

	/* Shouldn't be called before nr_dlock_lists is initialized */
	WARN_ON_ONCE(!nr_dlock_lists);

restart:
	if (iter->entry) {
		spin_unlock(&iter->entry->lock);
		iter->entry = NULL;
	}

next_list:
	/*
	 * Try next list
	 */
	if (++iter->index >= nr_dlock_lists)
		return NULL;	/* All the entries iterated */

	if (list_empty(&iter->head[iter->index].list))
		goto next_list;

	head = iter->entry = &iter->head[iter->index];
	spin_lock(&head->lock);
	/*
	 * There is a slight chance that the list may become empty just
	 * before the lock is acquired. So an additional check is
	 * needed to make sure that a valid node will be returned.
	 */
	if (list_empty(&head->list))
		goto restart;

	next = list_entry(head->list.next, struct dlock_list_node,
			  list);
	WARN_ON_ONCE(next->head != head);

	return next;
}
EXPORT_SYMBOL(__dlock_list_next_list);
