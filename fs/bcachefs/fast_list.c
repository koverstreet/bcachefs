// SPDX-License-Identifier: GPL-2.0

/*
 * Fast, unordered lists
 *
 * Supports add, remove, and iterate
 *
 * Underneath, they're a radix tree and an IDA, with a percpu buffer for slot
 * allocation and freeing.
 *
 * This means that adding, removing, and iterating over items is lockless,
 * except when refilling/emptying the percpu slot buffers.
 */

#include <linux/fast_list.h>

struct fast_list_pcpu {
	size_t			nr;
	size_t			entries[31];
};

/**
 * fast_list_get_idx - get a slot in a fast_list
 * @l:		list to get slot in
 *
 * This allocates a slot in the radix tree without storing to it, so that we can
 * take the potential memory allocation failure early and do the list add later
 * when we can't take an allocation failure.
 *
 * Returns: positive integer on success, -ENOMEM on failure
 */
int fast_list_get_idx(struct fast_list *l)
{
	int idx;

	preempt_disable();
	struct fast_list_pcpu *lp = this_cpu_ptr(l->buffer);

	if (unlikely(!lp->nr))
		while (lp->nr <= ARRAY_SIZE(lp->entries) / 2) {
			idx = ida_alloc_range(&l->slots_allocated, 1, ~0, GFP_NOWAIT|__GFP_NOWARN);
			if (unlikely(idx < 0)) {
				preempt_enable();
				idx = ida_alloc_range(&l->slots_allocated, 1, ~0, GFP_KERNEL);
				if (unlikely(idx < 0))
					return idx;

				preempt_disable();
				lp = this_cpu_ptr(l->buffer);
			}

			if (unlikely(!genradix_ptr_alloc_inlined(&l->items, idx,
							GFP_NOWAIT|__GFP_NOWARN))) {
				preempt_enable();
				if (!genradix_ptr_alloc(&l->items, idx, GFP_KERNEL)) {
					ida_free(&l->slots_allocated, idx);
					return -ENOMEM;
				}

				preempt_disable();
				lp = this_cpu_ptr(l->buffer);
			}

			if (unlikely(lp->nr == ARRAY_SIZE(lp->entries)))
				ida_free(&l->slots_allocated, idx);
			else
				lp->entries[lp->nr++] = idx;
		}

	idx = lp->entries[--lp->nr];
	preempt_enable();

	return idx;
}

/**
 * fast_list_add - add an item to a fast_list
 * @l:		list
 * @item:	item to add
 *
 * Allocates a slot in the radix tree and stores to it and then returns the
 * slot index, which must be passed to fast_list_remove().
 *
 * Returns: positive integer on success, -ENOMEM on failure
 */
int fast_list_add(struct fast_list *l, void *item)
{
	int idx = fast_list_get_idx(l);
	if (idx < 0)
		return idx;

	*genradix_ptr_inlined(&l->items, idx) = item;
	return idx;
}

/**
 * fast_list_remove - remove an item from a fast_list
 * @l:		list
 * @idx:	item's slot index
 *
 * Zeroes out the slot in the radix tree and frees the slot for future
 * fast_list_add() operations.
 */
void fast_list_remove(struct fast_list *l, unsigned idx)
{
	if (!idx)
		return;

	*genradix_ptr_inlined(&l->items, idx) = NULL;

	preempt_disable();
	struct fast_list_pcpu *lp = this_cpu_ptr(l->buffer);

	if (unlikely(lp->nr == ARRAY_SIZE(lp->entries)))
		while (lp->nr >= ARRAY_SIZE(lp->entries) / 2) {
			ida_free(&l->slots_allocated, idx);
			idx = lp->entries[--lp->nr];
		}

	lp->entries[lp->nr++] = idx;
	preempt_enable();
}

void fast_list_exit(struct fast_list *l)
{
	/* XXX: warn if list isn't empty */
	free_percpu(l->buffer);
	ida_destroy(&l->slots_allocated);
	genradix_free(&l->items);
}

int fast_list_init(struct fast_list *l)
{
	genradix_init(&l->items);
	ida_init(&l->slots_allocated);
	l->buffer = alloc_percpu(*l->buffer);
	if (!l->buffer)
		return -ENOMEM;
	return 0;
}
