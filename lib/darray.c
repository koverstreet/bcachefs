// SPDX-License-Identifier: GPL-2.0
/*
 * (C) 2022-2024 Kent Overstreet <kent.overstreet@linux.dev>
 */

#include <linux/darray.h>
#include <linux/export.h>
#include <linux/log2.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

int __darray_resize_slowpath(darray_char *d, size_t element_size, size_t new_size, gfp_t gfp,
			     bool rcu)
{
	if (new_size > d->size) {
		new_size = roundup_pow_of_two(new_size);

		/*
		 * This is a workaround: kvmalloc() doesn't support > INT_MAX
		 * allocations, but vmalloc() does.
		 * The limit needs to be lifted from kvmalloc, and when it does
		 * we'll go back to just using that.
		 */
		size_t bytes;
		if (unlikely(check_mul_overflow(new_size, element_size, &bytes)))
			return -ENOMEM;

		void *old = d->data;
		void *new = likely(bytes < INT_MAX)
			? kvmalloc_noprof(bytes, gfp)
			: vmalloc_noprof(bytes);
		if (!new)
			return -ENOMEM;

		if (d->size)
			memcpy(new, old, d->size * element_size);

		rcu_assign_pointer(d->data, new);
		d->size = new_size;

		if (old != d->preallocated) {
			if (!rcu)
				kvfree(old);
			else
				kvfree_rcu_mightsleep(old);
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(__darray_resize_slowpath);
