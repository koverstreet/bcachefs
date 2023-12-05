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
#ifndef __LINUX_DLOCK_LIST_H
#define __LINUX_DLOCK_LIST_H

#include <linux/spinlock.h>
#include <linux/list.h>

/*
 * include/linux/dlock-list.h
 *
 * The dlock_list_head structure contains the spinlock. It is cacheline
 * aligned to reduce contention among different CPUs. The other
 * dlock_list_node structures contains a pointer to the head entry instead.
 */
struct dlock_list_head {
	struct list_head list;
	spinlock_t lock;
} ____cacheline_aligned_in_smp;

struct dlock_list_heads {
	struct dlock_list_head *heads;
};

/*
 * dlock list node data structure
 */
struct dlock_list_node {
	struct list_head list;
	struct dlock_list_head *head;
};

/*
 * dlock list iteration state
 *
 * This is an opaque data structure that may change. Users of this structure
 * should not access the structure members directly other than using the
 * helper functions and macros provided in this header file.
 */
struct dlock_list_iter {
	int index;
	struct dlock_list_head *head, *entry;
};

#define DLOCK_LIST_ITER_INIT(dlist)		\
	{					\
		.index = -1,			\
		.head = (dlist)->heads,		\
	}

#define DEFINE_DLOCK_LIST_ITER(s, heads)	\
	struct dlock_list_iter s = DLOCK_LIST_ITER_INIT(heads)

static inline void init_dlock_list_iter(struct dlock_list_iter *iter,
					struct dlock_list_heads *heads)
{
	*iter = (struct dlock_list_iter)DLOCK_LIST_ITER_INIT(heads);
}

#define DLOCK_LIST_NODE_INIT(name)		\
	{					\
		.list = LIST_HEAD_INIT(name)	\
	}

static inline void init_dlock_list_node(struct dlock_list_node *node)
{
	*node = (struct dlock_list_node)DLOCK_LIST_NODE_INIT(node->list);
}

/**
 * dlock_list_unlock - unlock the spinlock that protects the current list
 * @iter: Pointer to the dlock list iterator structure
 */
static inline void dlock_list_unlock(struct dlock_list_iter *iter)
{
	spin_unlock(&iter->entry->lock);
}

/**
 * dlock_list_relock - lock the spinlock that protects the current list
 * @iter: Pointer to the dlock list iterator structure
 */
static inline void dlock_list_relock(struct dlock_list_iter *iter)
{
	spin_lock(&iter->entry->lock);
}

/*
 * Allocation and freeing of dlock list
 */
extern int  __alloc_dlock_list_heads(struct dlock_list_heads *dlist,
				     struct lock_class_key *key);
extern void free_dlock_list_heads(struct dlock_list_heads *dlist);

/**
 * alloc_dlock_list_head - Initialize and allocate the list of head entries.
 * @dlist  : Pointer to the dlock_list_heads structure to be initialized
 * Return  : 0 if successful, -ENOMEM if memory allocation error
 */
#define alloc_dlock_list_heads(dlist)					\
({									\
	static struct lock_class_key _key;				\
	__alloc_dlock_list_heads(dlist, &_key);				\
})

/*
 * Check if a dlock list is empty or not.
 */
extern bool dlock_lists_empty(struct dlock_list_heads *dlist);

/*
 * The dlock list addition and deletion functions here are not irq-safe.
 * Special irq-safe variants will have to be added if we need them.
 */
extern void dlock_lists_add(struct dlock_list_node *node,
			    struct dlock_list_heads *dlist);
extern void dlock_lists_del(struct dlock_list_node *node);

/*
 * Find the first entry of the next available list.
 */
extern struct dlock_list_node *
__dlock_list_next_list(struct dlock_list_iter *iter);

/**
 * __dlock_list_next_entry - Iterate to the next entry of the dlock list
 * @curr : Pointer to the current dlock_list_node structure
 * @iter : Pointer to the dlock list iterator structure
 * Return: Pointer to the next entry or NULL if all the entries are iterated
 *
 * The iterator has to be properly initialized before calling this function.
 */
static inline struct dlock_list_node *
__dlock_list_next_entry(struct dlock_list_node *curr,
			struct dlock_list_iter *iter)
{
	/*
	 * Find next entry
	 */
	if (curr)
		curr = list_next_entry(curr, list);

	if (!curr || (&curr->list == &iter->entry->list)) {
		/*
		 * The current list has been exhausted, try the next available
		 * list.
		 */
		curr = __dlock_list_next_list(iter);
	}

	return curr;	/* Continue the iteration */
}

/**
 * _dlock_list_next_list_entry - get first element from next list in iterator
 * @iter  : The dlock list iterator.
 * @pos   : A variable of the struct that is embedded in.
 * @member: The name of the dlock_list_node within the struct.
 * Return : Pointer to first entry or NULL if all the lists are iterated.
 */
#define _dlock_list_next_list_entry(iter, pos, member)			\
	({								\
		struct dlock_list_node *_n;				\
		_n = __dlock_list_next_entry(NULL, iter);		\
		_n ? list_entry(_n, typeof(*pos), member) : NULL;	\
	})

/**
 * _dlock_list_next_entry - iterate to the next entry of the list
 * @pos   : The type * to cursor
 * @iter  : The dlock list iterator.
 * @member: The name of the dlock_list_node within the struct.
 * Return : Pointer to the next entry or NULL if all the entries are iterated.
 *
 * Note that pos can't be NULL.
 */
#define _dlock_list_next_entry(pos, iter, member)			\
	({								\
		struct dlock_list_node *_n;				\
		_n = __dlock_list_next_entry(&(pos)->member, iter);	\
		_n ? list_entry(_n, typeof(*(pos)), member) : NULL;	\
	})

/**
 * dlist_for_each_entry - iterate over the dlock list
 * @pos   : Type * to use as a loop cursor
 * @iter  : The dlock list iterator
 * @member: The name of the dlock_list_node within the struct
 *
 * This iteration macro isn't safe with respect to list entry removal, but
 * it can correctly iterate newly added entries right after the current one.
 * This iteration function is designed to be used in a while loop.
 */
#define dlist_for_each_entry(pos, iter, member)				\
	for (pos = _dlock_list_next_list_entry(iter, pos, member);	\
	     pos != NULL;						\
	     pos = _dlock_list_next_entry(pos, iter, member))

/**
 * dlist_for_each_entry_safe - iterate over the dlock list & safe over removal
 * @pos   : Type * to use as a loop cursor
 * @n	  : Another type * to use as temporary storage
 * @iter  : The dlock list iterator
 * @member: The name of the dlock_list_node within the struct
 *
 * This iteration macro is safe with respect to list entry removal.
 * However, it cannot correctly iterate newly added entries right after the
 * current one.
 *
 * The call to __dlock_list_next_list() is deferred until the next entry
 * is being iterated to avoid use-after-unlock problem.
 */
#define dlist_for_each_entry_safe(pos, n, iter, member)			\
	for (pos = NULL;						\
	    ({								\
		if (!pos ||						\
		   (&(pos)->member.list == &(iter)->entry->list))	\
			pos = _dlock_list_next_list_entry(iter, pos,	\
							  member);	\
		if (pos)						\
			n = list_next_entry(pos, member.list);		\
		pos;							\
	    });								\
	    pos = n)

#endif /* __LINUX_DLOCK_LIST_H */
