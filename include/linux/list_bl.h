/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LIST_BL_H
#define _LINUX_LIST_BL_H

#include <linux/list.h>
#include <linux/bit_spinlock.h>
#include <linux/spinlock.h>

/*
 * Special version of lists, where head of the list has a lock in the lowest
 * bit. This is useful for scalable hash tables without increasing memory
 * footprint overhead.
 *
 * Whilst the general use of bit spin locking is considered safe, PREEMPT_RT
 * introduces a problem with nesting spin locks inside bit locks: spin locks
 * become sleeping locks, and we can't sleep inside spinning locks such as bit
 * locks. However, for RTPREEMPT, performance is less of an issue than
 * correctness, so we trade off the memory and cache footprint of a spinlock per
 * list so the list locks are converted to sleeping locks and work correctly
 * with PREEMPT_RT kernels.
 *
 * An added advantage of this is that we can use the same trick when lockdep is
 * enabled (again, performance doesn't matter) and gain lockdep coverage of all
 * the hash-bl operations.
 *
 * For modification operations when using pure bit locking, the 0 bit of
 * hlist_bl_head->first pointer must be set.
 *
 * With some small modifications, this can easily be adapted to store several
 * arbitrary bits (not just a single lock bit), if the need arises to store
 * some fast and compact auxiliary data.
 */

#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
#define LIST_BL_LOCKMASK	1UL
#else
#define LIST_BL_LOCKMASK	0UL
#endif

#ifdef CONFIG_DEBUG_LIST
#define LIST_BL_BUG_ON(x) BUG_ON(x)
#else
#define LIST_BL_BUG_ON(x)
#endif

#undef LIST_BL_USE_SPINLOCKS
#if defined(CONFIG_PREEMPT_RT) || defined(CONFIG_LOCKDEP)
#define LIST_BL_USE_SPINLOCKS	1
#endif

struct hlist_bl_head {
	struct hlist_bl_node *first;
#ifdef LIST_BL_USE_SPINLOCKS
	spinlock_t lock;
#endif
};

struct hlist_bl_node {
	struct hlist_bl_node *next, **pprev;
};

static inline void INIT_HLIST_BL_NODE(struct hlist_bl_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

#define hlist_bl_entry(ptr, type, member) container_of(ptr,type,member)

static inline bool  hlist_bl_unhashed(const struct hlist_bl_node *h)
{
	return !h->pprev;
}

#ifdef LIST_BL_USE_SPINLOCKS
#define INIT_HLIST_BL_HEAD(ptr) do { \
	(ptr)->first = NULL; \
	spin_lock_init(&(ptr)->lock); \
} while (0)

static inline void hlist_bl_lock(struct hlist_bl_head *b)
{
	spin_lock(&b->lock);
}

static inline void hlist_bl_lock_nested(struct hlist_bl_head *b, int subclass)
{
	spin_lock_nested(&b->lock, subclass);
}

static inline void hlist_bl_unlock(struct hlist_bl_head *b)
{
	spin_unlock(&b->lock);
}

static inline bool hlist_bl_is_locked(struct hlist_bl_head *b)
{
	return spin_is_locked(&b->lock);
}

static inline struct hlist_bl_node *hlist_bl_first(struct hlist_bl_head *h)
{
	return h->first;
}

static inline void hlist_bl_set_first(struct hlist_bl_head *h,
					struct hlist_bl_node *n)
{
	h->first = n;
}

static inline void hlist_bl_set_before(struct hlist_bl_node **pprev,
					struct hlist_bl_node *n)
{
	WRITE_ONCE(*pprev, n);
}

static inline bool hlist_bl_empty(const struct hlist_bl_head *h)
{
	return !READ_ONCE(h->first);
}

#else /* !LIST_BL_USE_SPINLOCKS */

#define INIT_HLIST_BL_HEAD(ptr) \
	((ptr)->first = NULL)

static inline void hlist_bl_lock(struct hlist_bl_head *b)
{
	bit_spin_lock(0, (unsigned long *)b);
}

static inline void hlist_bl_lock_nested(struct hlist_bl_head *b, int subclass)
{
	hlist_bl_lock(b);
}

static inline void hlist_bl_unlock(struct hlist_bl_head *b)
{
	__bit_spin_unlock(0, (unsigned long *)b);
}

static inline bool hlist_bl_is_locked(struct hlist_bl_head *b)
{
	return bit_spin_is_locked(0, (unsigned long *)b);
}

static inline struct hlist_bl_node *hlist_bl_first(struct hlist_bl_head *h)
{
	return (struct hlist_bl_node *)
		((unsigned long)h->first & ~LIST_BL_LOCKMASK);
}

static inline void hlist_bl_set_first(struct hlist_bl_head *h,
					struct hlist_bl_node *n)
{
	LIST_BL_BUG_ON((unsigned long)n & LIST_BL_LOCKMASK);
	LIST_BL_BUG_ON(((unsigned long)h->first & LIST_BL_LOCKMASK) !=
							LIST_BL_LOCKMASK);
	h->first = (struct hlist_bl_node *)((unsigned long)n | LIST_BL_LOCKMASK);
}

static inline void hlist_bl_set_before(struct hlist_bl_node **pprev,
					struct hlist_bl_node *n)
{
	WRITE_ONCE(*pprev,
		   (struct hlist_bl_node *)
			((uintptr_t)n | ((uintptr_t)*pprev & LIST_BL_LOCKMASK)));
}

static inline bool hlist_bl_empty(const struct hlist_bl_head *h)
{
	return !((unsigned long)READ_ONCE(h->first) & ~LIST_BL_LOCKMASK);
}

#endif /* LIST_BL_USE_SPINLOCKS */

static inline void hlist_bl_add_head(struct hlist_bl_node *n,
					struct hlist_bl_head *h)
{
	struct hlist_bl_node *first = hlist_bl_first(h);

	n->next = first;
	if (first)
		first->pprev = &n->next;
	n->pprev = &h->first;
	hlist_bl_set_first(h, n);
}

static inline void hlist_bl_add_before(struct hlist_bl_node *n,
				       struct hlist_bl_node *next)
{
	struct hlist_bl_node **pprev = next->pprev;

	n->pprev = pprev;
	n->next = next;
	next->pprev = &n->next;
	hlist_bl_set_before(pprev, n);
}

static inline void hlist_bl_add_behind(struct hlist_bl_node *n,
				       struct hlist_bl_node *prev)
{
	n->next = prev->next;
	n->pprev = &prev->next;
	prev->next = n;

	if (n->next)
		n->next->pprev = &n->next;
}

static inline void __hlist_bl_del(struct hlist_bl_node *n)
{
	struct hlist_bl_node *next = n->next;
	struct hlist_bl_node **pprev = n->pprev;

	LIST_BL_BUG_ON((unsigned long)n & LIST_BL_LOCKMASK);

	hlist_bl_set_before(pprev, next);
	if (next)
		next->pprev = pprev;
}

static inline void hlist_bl_del(struct hlist_bl_node *n)
{
	__hlist_bl_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}

static inline void hlist_bl_del_init(struct hlist_bl_node *n)
{
	if (!hlist_bl_unhashed(n)) {
		__hlist_bl_del(n);
		INIT_HLIST_BL_NODE(n);
	}
}

/**
 * hlist_bl_add_fake - create a fake list consisting of a single headless node
 * @n: Node to make a fake list out of
 *
 * This makes @n appear to be its own predecessor on a headless hlist.
 * The point of this is to allow things like hlist_bl_del() to work correctly
 * in cases where there is no list.
 */
static inline void hlist_bl_add_fake(struct hlist_bl_node *n)
{
	n->pprev = &n->next;
}

/**
 * hlist_fake: Is this node a fake hlist_bl?
 * @h: Node to check for being a self-referential fake hlist.
 */
static inline bool hlist_bl_fake(struct hlist_bl_node *n)
{
	return n->pprev == &n->next;
}

/**
 * hlist_bl_for_each_entry	- iterate over list of given type
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 *
 */
#define hlist_bl_for_each_entry(tpos, pos, head, member)		\
	for (pos = hlist_bl_first(head);				\
	     pos &&							\
		({ tpos = hlist_bl_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

/**
 * hlist_bl_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @n:		another &struct hlist_node to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_bl_for_each_entry_safe(tpos, pos, n, head, member)	 \
	for (pos = hlist_bl_first(head);				 \
	     pos && ({ n = pos->next; 1; }) && 				 \
		({ tpos = hlist_bl_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)

#endif
