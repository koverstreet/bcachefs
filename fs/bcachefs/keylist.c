
#include "bcache.h"
#include "btree_gc.h"
#include "btree_iter.h"
#include "extents.h"
#include "keylist.h"

#include <trace/events/bcachefs.h>

/* Utilities for plain keylists */

int bch_keylist_realloc_max(struct keylist *l,
			    unsigned needu64s,
			    unsigned maxu64s)
{
	size_t oldcap = bch_keylist_capacity(l);
	size_t newsize = max(oldcap, BKEY_EXTENT_U64s_MAX) + needu64s;
	u64 *new_keys;

	if (bch_keylist_fits(l, needu64s))
		return 0;

	/*
	 * The idea here is that the allocated size is always a power of two:
	 * thus, we know we need to reallocate if current_space_used and
	 * current_space_used + new_space spans a power of two
	 *
	 * Note that the max size may not be a power of two, in which case,
	 * the last reallocation may allocate very few new entries.
	 */
	newsize = roundup_pow_of_two(newsize);

	/* We simulate being out of memory -- the code using the key list
	   has to handle that case. */
	if (newsize > maxu64s) {
		if (oldcap >= maxu64s) {
			trace_bcache_keylist_realloc_full(l);
			return -ENOMEM;
		}
		newsize = maxu64s;
	}

	new_keys = kmalloc_array(newsize, sizeof(u64), GFP_NOIO);

	if (!new_keys) {
		trace_bcache_keylist_realloc_fail(l);
		return -ENOMEM;
	}

	/* Has @top wrapped around? */
	if (l->top_p < l->bot_p) {
		/*
		 * The FIFO wraps around the end with a "gap" in the
		 * middle. Copy the first half to the beginning and the
		 * second to the end and grow the gap.
		 */

		/* Copy @start_keys up to @top */
		memcpy(new_keys,
		       l->start_keys_p,
		       (l->top_p - l->start_keys_p) * sizeof(u64));

		/* Copy @bot up to @end_keys */
		memcpy(new_keys + newsize - (l->end_keys_p - l->bot_p),
		       l->bot_p,
		       (l->end_keys_p - l->bot_p) * sizeof(u64));

		l->top_p = new_keys + (l->top_p - l->start_keys_p);
		l->bot_p = new_keys + newsize - (l->end_keys_p - l->bot_p);
	} else {
		/*
		 * Else copy everything over and shift the bottom of
		 * the FIFO to align with the start of the keylist
		 */
		memcpy(new_keys,
		       l->bot_p,
		       (l->top_p - l->bot_p) * sizeof(u64));
		l->top_p = new_keys + (l->top_p - l->bot_p);
		l->bot_p = new_keys;
	}

	if (l->has_buf)
		kfree(l->start_keys_p);
	l->has_buf = true;

	l->start_keys_p = new_keys;
	l->end_keys_p = new_keys + newsize;

	trace_bcache_keylist_realloc(l);

	return 0;
}

int bch_keylist_realloc(struct keylist *l, unsigned needu64s)
{
	return bch_keylist_realloc_max(l, needu64s, KEYLIST_MAX);
}

void bch_keylist_add_in_order(struct keylist *l, struct bkey_i *insert)
{
	struct bkey_i *where = l->bot;

	/*
	 * Shouldn't fire since we only use this on a fresh keylist
	 * before calling bch_keylist_dequeue()
	 */
	BUG_ON(l->top_p < l->bot_p);

	while (where != l->top &&
	       bkey_cmp(insert->k.p, where->k.p) >= 0)
		where = bkey_next(where);

	memmove((u64 *) where + insert->k.u64s,
		where,
		((void *) l->top) - ((void *) where));

	l->top_p += insert->k.u64s;
	BUG_ON(l->top_p > l->end_keys_p);
	bkey_copy(where, insert);
}
