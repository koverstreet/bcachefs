
#include "bcache.h"
#include "keylist.h"

int bch_keylist_realloc(struct keylist *l, u64 *inline_u64s,
			size_t nr_inline_u64s, size_t new_u64s)
{
	size_t oldsize = bch_keylist_u64s(l);
	size_t newsize = oldsize + new_u64s;
	u64 *old_buf = l->keys_p == inline_u64s ? NULL : l->keys_p;
	u64 *new_keys;

	newsize = roundup_pow_of_two(newsize);

	if (newsize <= nr_inline_u64s ||
	    (old_buf && roundup_pow_of_two(oldsize) == newsize))
		return 0;

	new_keys = krealloc(old_buf, sizeof(u64) * newsize, GFP_NOIO);
	if (!new_keys)
		return -ENOMEM;

	if (!old_buf)
		memcpy(new_keys, inline_u64s, sizeof(u64) * oldsize);

	l->keys_p = new_keys;
	l->top_p = new_keys + oldsize;

	return 0;
}

void bch_keylist_add_in_order(struct keylist *l, struct bkey_i *insert)
{
	struct bkey_i *where;

	for_each_keylist_key(l, where)
		if (bkey_cmp(insert->k.p, where->k.p) < 0)
			break;

	memmove((u64 *) where + insert->k.u64s,
		where,
		((void *) l->top) - ((void *) where));

	l->top_p += insert->k.u64s;
	bkey_copy(where, insert);
}

void bch_keylist_pop_front(struct keylist *l)
{
	l->top_p -= bch_keylist_front(l)->k.u64s;

	memmove(l->keys,
		bkey_next(l->keys),
		bch_keylist_bytes(l));
}
