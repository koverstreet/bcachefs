// SPDX-License-Identifier: GPL-2.0

#include <linux/log2.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include "darray.h"

int __bch2_darray_resize_noprof(darray_char *d, size_t element_size, size_t new_size, gfp_t gfp,
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
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,17,0)
		void *new = likely(bytes < INT_MAX)
			? kvmalloc_noprof(bytes, gfp)
			: vmalloc_noprof(bytes);
#else
		void *new = likely(bytes < INT_MAX)
			? kvmalloc_node_align_noprof(bytes, 1, gfp, NUMA_NO_NODE)
			: vmalloc_noprof(bytes);
#endif
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
