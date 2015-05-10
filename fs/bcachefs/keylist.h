#ifndef _BCACHE_KEYLIST_H
#define _BCACHE_KEYLIST_H

#include "keylist_types.h"

static inline void bch_keylist_init(struct keylist *l)
{
	l->bot_p = l->top_p = l->start_keys_p = l->inline_keys;
	l->end_keys_p = &l->inline_keys[KEYLIST_INLINE];
}

static inline size_t bch_keylist_capacity(struct keylist *l)
{
	return l->end_keys_p - l->start_keys_p;
}

static inline bool bch_keylist_fits(struct keylist *l, size_t u64s)
{
	if (l->bot_p > l->top_p)
		return (l->bot_p - l->top_p) > u64s;
	else if (l->top_p + u64s + BKEY_EXTENT_MAX_U64s > l->end_keys_p)
		return l->start_keys_p != l->bot_p;
	else
		return true;
}

static inline u64 *__bch_keylist_next(struct keylist *l, u64 *p)
{
	p += KEY_U64s((struct bkey *) p);
	BUG_ON(p > l->end_keys_p);

	/* single_keylists don't wrap */
	if (p == l->top_p)
		return p;

	if (p + BKEY_EXTENT_MAX_U64s > l->end_keys_p)
		return l->start_keys_p;

	return p;
}

static inline void bch_keylist_enqueue(struct keylist *l)
{
	BUG_ON(!bch_keylist_fits(l, KEY_U64s(l->top)));
	l->top_p = __bch_keylist_next(l, l->top_p);
}

static inline void bch_keylist_add(struct keylist *l, const struct bkey *k)
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
	if (l->start_keys_p != l->inline_keys) {
		kfree(l->start_keys_p);
		bch_keylist_init(l);
	}
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

static inline bool bch_keylist_is_last(struct keylist *l, struct bkey *k)
{
	u64 *k_p = __bch_keylist_next(l, (u64 *) k);
	return k_p == l->top_p;
}

static inline struct bkey *bch_keylist_front(struct keylist *l)
{
	return l->bot;
}

static inline void bch_keylist_dequeue(struct keylist *l)
{
	BUG_ON(bch_keylist_empty(l));
	l->bot_p = __bch_keylist_next(l, l->bot_p);
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

static inline u64 bch_scan_keylist_sectors(struct scan_keylist *kl)
{
	return atomic64_read(&kl->sectors);
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
					  struct bkey *last_scanned,
					  struct bkey *end,
					  scan_keylist_pred_fn *pred);

int bch_scan_keylist_add(struct scan_keylist *, const struct bkey *);
void bch_scan_keylist_dequeue(struct scan_keylist *);

void bch_mark_scan_keylist_keys(struct cache_set *, struct scan_keylist *);

#endif /* _BCACHE_KEYLIST_H */
