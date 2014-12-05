#ifndef _BCACHE_KEYLIST_H
#define _BCACHE_KEYLIST_H

#include "keylist_types.h"

static inline void bch_keylist_init(struct keylist *l)
{
	l->bot_p = l->top_p = l->start_keys_p = l->inline_keys;
	l->end_keys_p = (&l->inline_keys[KEYLIST_INLINE]);
}

/* __bch_keylist_push can be used if we've just checked the size */

static inline void __bch_keylist_push(struct keylist *l)
{
	l->top = bkey_next(l->top);
}

static inline void bch_keylist_push(struct keylist *l)
{
	__bch_keylist_push(l);
	BUG_ON(l->top_p > l->end_keys_p);
}

/* __bch_keylist_add can be used if we've just checked the size */

static inline void __bch_keylist_add(struct keylist *l, struct bkey *k)
{
	bkey_copy(l->top, k);
	__bch_keylist_push(l);
}

static inline void bch_keylist_add(struct keylist *l, struct bkey *k)
{
	bkey_copy(l->top, k);
	bch_keylist_push(l);
}

static inline bool bch_keylist_empty(struct keylist *l)
{
	return l->bot == l->top;
}

static inline void bch_keylist_free(struct keylist *l)
{
	if (l->start_keys_p != l->inline_keys)
		kfree(l->start_keys_p);
}

/*
 * This returns the number of u64s, rather than the number of keys. As keys are
 * variable sized, the actual number of keys would have to be counted.
 */
static inline size_t bch_keylist_nkeys(struct keylist *l)
{
	return l->top_p - l->bot_p;
}

static inline size_t bch_keylist_size(struct keylist *l)
{
	return l->top_p - l->start_keys_p;
}

static inline size_t bch_keylist_capacity(struct keylist *l)
{
	return l->end_keys_p - l->start_keys_p;
}

static inline size_t bch_keylist_offset(struct keylist *l)
{
	return l->bot_p - l->start_keys_p;
}

static inline bool bch_keylist_is_end(struct keylist *l, struct bkey *k)
{
	return k == (l->top);
}

static inline bool bch_keylist_is_last(struct keylist *l, struct bkey *k)
{
	return bch_keylist_is_end(l, bkey_next(k));
}

static inline struct bkey *bch_keylist_front(struct keylist *l)
{
	return l->bot;
}

static inline void bch_keylist_pop_front(struct keylist *l)
{
	l->bot_p += (KEY_U64s(l->bot));

	if (l->bot == l->top)
		l->bot = l->top = l->start_keys;
}

#define keylist_single(k)						\
((struct keylist) {							\
	.start_keys = k,						\
	.top = bkey_next(k),						\
	.bot = k,							\
	.end_keys = bkey_next(k)					\
})

void bch_keylist_add_in_order(struct keylist *, struct bkey *);
int bch_keylist_realloc(struct keylist *, unsigned);
int bch_keylist_realloc_max(struct keylist *, unsigned, unsigned);

void bch_scan_keylist_init(struct scan_keylist *kl,
			   unsigned max_size);

void bch_scan_keylist_reset(struct scan_keylist *kl);

/* The keylist is dynamically adjusted. This just clamps the maxima */

static inline unsigned bch_scan_keylist_size(struct scan_keylist *kl)
{
	return kl->max_size;
}

void bch_scan_keylist_resize(struct scan_keylist *kl,
			     unsigned max_size);

void bch_scan_keylist_destroy(struct scan_keylist *kl);

/*
 * IMPORTANT: The caller of bch_scan_keylist_next or
 * bch_scan_keylist_next_rescan needs to copy any
 * non-null return value before calling either again!
 * These functions return a pointer into the internal structure.
 * Furthermore, they need to call bch_scan_keylist_advance after
 * copying the structure.
 */

struct bkey *bch_scan_keylist_next(struct scan_keylist *);

struct bkey *bch_scan_keylist_next_rescan(struct cache_set *c,
					  struct scan_keylist *kl,
					  struct bkey *end,
					  scan_keylist_pred_fn *pred);

static inline void bch_scan_keylist_advance(struct scan_keylist *kl)
{
	bch_keylist_pop_front(&kl->list);
}

void bch_mark_scan_keylist_keys(struct cache_set *, struct scan_keylist *);

bool bch_scan_keylist_full(struct scan_keylist *kl);

#endif /* _BCACHE_KEYLIST_H */
