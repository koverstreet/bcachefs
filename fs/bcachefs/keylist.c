
#include "bcache.h"
#include "btree.h"
#include "gc.h"
#include "keylist.h"

#include <trace/events/bcachefs.h>

/* Utilities for plain keylists */

int bch_keylist_realloc_max(struct keylist *l,
			    unsigned needu64s,
			    unsigned maxu64s)
{
	size_t oldcap = bch_keylist_capacity(l);
	size_t newsize = oldcap + needu64s;
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

	if (l->start_keys_p != l->inline_keys)
		kfree(l->start_keys_p);

	l->start_keys_p = new_keys;
	l->end_keys_p = new_keys + newsize;

	trace_bcache_keylist_realloc(l);

	return 0;
}

int bch_keylist_realloc(struct keylist *l, unsigned needu64s)
{
	return bch_keylist_realloc_max(l, needu64s, KEYLIST_MAX);
}

void bch_keylist_add_in_order(struct keylist *l, struct bkey *insert)
{
	struct bkey *where = l->bot;

	/*
	 * Shouldn't fire since we only use this on a fresh keylist
	 * before calling bch_keylist_dequeue()
	 */
	BUG_ON(l->top_p < l->bot_p);

	while (where != l->top &&
	       bkey_cmp(insert, where) >= 0)
		where = bkey_next(where);

	memmove((u64 *) where + KEY_U64s(insert),
		where,
		((void *) l->top) - ((void *) where));

	l->top_p += KEY_U64s(insert);
	BUG_ON(l->top_p > l->end_keys_p);
	bkey_copy(where, insert);
}

/* Scan keylists simple utilities */

void bch_scan_keylist_init(struct scan_keylist *kl,
			   struct cache_set *c,
			   unsigned max_size)

{
	kl->c = c;
	kl->owner = NULL;

	mutex_init(&kl->lock);
	kl->max_size = max_size;
	bch_keylist_init(&kl->list);

	/*
	 * Order of initialization is tricky, and this makes sure that
	 * we have a valid cache set in case the order of
	 * initialization chages and breaks things.
	 */
	BUG_ON(c == NULL);
	mutex_lock(&c->gc_scan_keylist_lock);
	list_add_tail(&kl->mark_list, &c->gc_scan_keylists);
	mutex_unlock(&c->gc_scan_keylist_lock);
}

void bch_scan_keylist_destroy(struct scan_keylist *kl)
{
	mutex_lock(&kl->c->gc_scan_keylist_lock);
	list_del(&kl->mark_list);
	mutex_unlock(&kl->c->gc_scan_keylist_lock);

	mutex_lock(&kl->lock);
	bch_keylist_free(&kl->list);
	mutex_unlock(&kl->lock);
}

void bch_scan_keylist_reset(struct scan_keylist *kl)
{
	kl->list.bot_p = kl->list.top_p = kl->list.start_keys_p;
}

/*
 * This should only be called from sysfs, and holding a lock that prevents
 * re-entrancy.
 */
void bch_scan_keylist_resize(struct scan_keylist *kl,
			     unsigned max_size)
{
	mutex_lock(&kl->lock);
	kl->max_size = max_size;	/* May be smaller than current size */
	mutex_unlock(&kl->lock);
}

#define keylist_for_each(k, l)						\
for (k = ACCESS_ONCE((l)->bot);						\
	k != (l)->top;							\
	k = __bch_keylist_next(l, k))

/**
 * bch_keylist_recalc_oldest_gens - update oldest_gen pointers from keylist keys
 *
 * This prevents us from wrapping around gens for a bucket only referenced from
 * the tiering or moving GC keylists. We don't actually care that the data in
 * those buckets is marked live, only that we don't wrap the gens.
 *
 * Note: This interlocks with insertions, but not all dequeues interlock.
 * The particular case in which dequeues don't interlock is when a
 * scan list used by the copy offload ioctls is used as a plain
 * keylist for btree insertion.
 * The btree insertion code doesn't go through
 * bch_scan_keylist_dequeue below, and instead uses plain
 * bch_keylist_dequeue.  The other pointers (top, start, end) are
 * unchanged in this case.
 * A little care with the bottomp pointer suffices in this case.
 * Of course, we may end up marking stuff that we don't need to mark,
 * but was recently valid and we have likely just inserted in the tree
 * anyway.
 */
void bch_keylist_recalc_oldest_gens(struct cache_set *c,
				    struct scan_keylist *kl)
{
	struct bkey *k;

	mutex_lock(&kl->lock);

	keylist_for_each(k, &kl->list) {
		rcu_read_lock();
		bch_btree_key_recalc_oldest_gen(c, k);
		rcu_read_unlock();
	}

	mutex_unlock(&kl->lock);
}

int bch_scan_keylist_add(struct scan_keylist *kl, const struct bkey *k)
{
	int ret;

	mutex_lock(&kl->lock);
	ret = bch_keylist_realloc_max(&kl->list,
				      KEY_U64s(k),
				      kl->max_size);

	if (!ret) {
		bch_keylist_add(&kl->list, k);
		atomic64_add(KEY_SIZE(k), &kl->sectors);
	}
	mutex_unlock(&kl->lock);

	return ret;
}

/* Actual scanning functionality of scan_keylists */

static void bch_refill_scan_keylist(struct cache_set *c,
				    struct scan_keylist *kl,
				    struct bkey *last_scanned,
				    struct bkey *end,
				    scan_keylist_pred_fn *pred)
{
	struct bkey start = *last_scanned;
	struct btree_iter iter;
	const struct bkey *k;
	unsigned nr_found = 0;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS, last_scanned, k) {
		if (bkey_cmp(k, end) >= 0) {
			*last_scanned = *k;
			goto done;
		}

		if (pred(kl, k)) {
			if (bch_scan_keylist_add(kl, k))
				goto done;

			nr_found++;
		}

		*last_scanned = *k;
		bch_btree_iter_cond_resched(&iter);
	}

	/* If we end up here, it means:
	 * - the map_fn didn't fill up the keybuf
	 * - the map_fn didn't see the end key
	 * - there were no more keys to map over
	 * Therefore, we are at the end of the key space */
	*last_scanned = MAX_KEY;
done:
	bch_btree_iter_unlock(&iter);

	trace_bcache_keyscan(nr_found,
			     KEY_INODE(&start), KEY_OFFSET(&start),
			     KEY_INODE(last_scanned),
			     KEY_OFFSET(last_scanned));
}

struct bkey *bch_scan_keylist_next(struct scan_keylist *kl)
{
	if (bch_keylist_empty(&kl->list))
		return NULL;

	return bch_keylist_front(&kl->list);
}

struct bkey *bch_scan_keylist_next_rescan(struct cache_set *c,
					  struct scan_keylist *kl,
					  struct bkey *last_scanned,
					  struct bkey *end,
					  scan_keylist_pred_fn *pred)
{
	if (bch_keylist_empty(&kl->list)) {
		if (bkey_cmp(last_scanned, end) >= 0)
			return NULL;

		bch_refill_scan_keylist(c, kl, last_scanned, end, pred);
	}

	return bch_scan_keylist_next(kl);
}

void bch_scan_keylist_dequeue(struct scan_keylist *kl)
{
	u64 sectors;

	mutex_lock(&kl->lock);
	sectors = KEY_SIZE(kl->list.bot);
	bch_keylist_dequeue(&kl->list);
	mutex_unlock(&kl->lock);

	BUG_ON(atomic64_sub_return(sectors, &kl->sectors) < 0);
}
