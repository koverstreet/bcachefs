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

static inline struct bkey_i *__bch_keylist_next(struct keylist *l,
						struct bkey_i *k)
{
	k = bkey_next(k);
	BUG_ON(k > l->end_keys);

	/* single_keylists don't wrap */
	if (k == l->top)
		return k;

	if ((u64 *) k + BKEY_EXTENT_MAX_U64s > l->end_keys_p)
		return l->start_keys;

	return k;
}

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

void bch_scan_keylist_init(struct scan_keylist *kl,
			   struct cache_set *c,
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

struct bkey_i *bch_scan_keylist_next(struct scan_keylist *);

struct bkey_i *bch_scan_keylist_next_rescan(struct cache_set *c,
					    struct scan_keylist *kl,
					    struct bpos *last_scanned,
					    struct bpos end,
					    scan_keylist_pred_fn *pred);

int bch_scan_keylist_add(struct scan_keylist *, struct bkey_s_c);
void bch_scan_keylist_dequeue(struct scan_keylist *);

void bch_keylist_recalc_oldest_gens(struct cache_set *, struct scan_keylist *);

#endif /* _BCACHE_KEYLIST_H */
