#ifndef _BCACHE_KEYLIST_H
#define _BCACHE_KEYLIST_H

#include "keylist_types.h"

static inline void bch_keylist_init(struct keylist *l, u64 *inline_keys,
				    size_t nr_inline_u64s)
{
	l->bot_p = l->top_p = l->start_keys_p = inline_keys;
	l->end_keys_p = l->start_keys_p + nr_inline_u64s;
	l->has_buf = false;
}

static inline size_t bch_keylist_capacity(struct keylist *l)
{
	return l->end_keys_p - l->start_keys_p;
}

/*
 * XXX: why are we using BKEY_EXTENT_U64s_MAX here? keylists aren't used just
 * for extents, this doesn't make any sense
 */

static inline bool bch_keylist_fits(struct keylist *l, size_t u64s)
{
	if (l->bot_p > l->top_p)
		return (l->bot_p - l->top_p) > u64s;
	else if (l->top_p + u64s + BKEY_EXTENT_U64s_MAX > l->end_keys_p)
		return l->start_keys_p != l->bot_p;
	else
		return true;
}

static inline struct bkey_i *__bch_keylist_next(struct keylist *l,
						struct bkey_i *k)
{
	k = bkey_next(k);
	BUG_ON(k > l->end_keys);

	/* single_keylists don't wrap */
	if (k == l->top)
		return k;

	if ((u64 *) k + BKEY_EXTENT_U64s_MAX > l->end_keys_p)
		return l->start_keys;

	return k;
}

#define for_each_keylist_key(_keys, _k)					\
	for (_k = ACCESS_ONCE((_keys)->bot);				\
	     _k != (_keys)->top;					\
	     _k = __bch_keylist_next(_keys, _k))

static inline void bch_keylist_enqueue(struct keylist *l)
{
	BUG_ON(!bch_keylist_fits(l, l->top->k.u64s));
	l->top = __bch_keylist_next(l, l->top);
}

static inline void bch_keylist_add(struct keylist *l, const struct bkey_i *k)
{
	bkey_copy(l->top, k);
	bch_keylist_enqueue(l);
}

static inline bool bch_keylist_empty(struct keylist *l)
{
	return l->bot == l->top;
}

static inline void bch_keylist_free(struct keylist *l)
{
	if (l->has_buf)
		kfree(l->start_keys_p);
	memset(l, 0, sizeof(*l));
}

/*
 * This returns the number of u64s, rather than the number of keys. As keys are
 * variable sized, the actual number of keys would have to be counted.
 */
static inline size_t bch_keylist_nkeys(struct keylist *l)
{
	/*
	 * We don't know the exact number of u64s in the wrapped case
	 * because of internal fragmentation at the end!
	 */
	if (l->top_p >= l->bot_p)
		return l->top_p - l->bot_p;
	else
		return ((l->top_p - l->start_keys_p) +
			(l->end_keys_p - l->bot_p));
}

static inline struct bkey_i *bch_keylist_front(struct keylist *l)
{
	return l->bot;
}

static inline void bch_keylist_dequeue(struct keylist *l)
{
	BUG_ON(bch_keylist_empty(l));
	l->bot = __bch_keylist_next(l, l->bot);
}

#define keylist_single(k)						\
((struct keylist) {							\
	.start_keys = k,						\
	.top = bkey_next(k),						\
	.bot = k,							\
	.end_keys = bkey_next(k)					\
})

void bch_keylist_add_in_order(struct keylist *, struct bkey_i *);
int bch_keylist_realloc(struct keylist *, unsigned);
int bch_keylist_realloc_max(struct keylist *, unsigned, unsigned);

#endif /* _BCACHE_KEYLIST_H */
