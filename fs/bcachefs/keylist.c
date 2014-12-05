
#include "bcache.h"
#include "btree.h"
#include "keylist.h"

#include <trace/events/bcachefs.h>

/* Utilities for plain keylists */

int bch_keylist_realloc_max(struct keylist *l,
			    unsigned needu64s,
			    unsigned maxu64s)
{
	size_t oldcap = bch_keylist_capacity(l);
	size_t oldsize = bch_keylist_size(l);
	size_t offset = bch_keylist_offset(l);
	size_t newsize = oldsize + needu64s;
	u64 *old_keys = l->start_keys_p;
	u64 *new_keys;

	if (old_keys == l->inline_keys)
		old_keys = NULL;

	/*
	 * The idea here is that the allocated size is always a power of two:
	 * thus, we know we need to reallocate if current_space_used and
	 * current_space_used + new_space spans a power of two
	 *
	 * Note that the max size may not be a power of two, in which case,
	 * the last reallocation may allocate very few new entries.
	 */
	newsize = roundup_pow_of_two(newsize);

	if (newsize <= KEYLIST_INLINE ||
	    roundup_pow_of_two(oldsize) == newsize)
		return 0;

	/* We simulate being out of memory -- the code using the key list
	   has to handle that case. */
	if (newsize > maxu64s) {
		if (oldcap >= maxu64s)
			return -ENOMEM;
		newsize = maxu64s;
	}

	new_keys = krealloc(old_keys, sizeof(u64) * newsize, GFP_NOIO);

	if (!new_keys)
		return -ENOMEM;

	if (!old_keys)
		memcpy(new_keys, l->inline_keys, sizeof(u64) * oldsize);

	l->start_keys_p = new_keys;
	l->top_p = new_keys + oldsize;
	l->bot_p = new_keys + offset;
	l->end_keys_p = new_keys + newsize;

	return 0;
}

int bch_keylist_realloc(struct keylist *l, unsigned needu64s)
{
	return bch_keylist_realloc_max(l, needu64s, KEYLIST_MAX);
}

void bch_keylist_add_in_order(struct keylist *l, struct bkey *insert)
{
	struct bkey *where = l->bot;

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
			   unsigned max_size)
{
	spin_lock_init(&kl->lock);
	kl->last_scanned = MAX_KEY;
	kl->max_size = max_size;
	bch_keylist_init(&kl->list);
}

void bch_scan_keylist_destroy(struct scan_keylist *kl)
{
	bch_keylist_free(&kl->list);
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
	spin_lock(&kl->lock);
	kl->max_size = max_size;	/* May be smaller than current size */
	spin_unlock(&kl->lock);
}

/*
 * This makes sure that we have enough room for another bkey, no matter
 * how many extent pointers it has.
 * As bkeys are variable size, we don't really know whether the next one
 * will fit, so we are conservative.
 */

bool bch_scan_keylist_full(struct scan_keylist *kl)
{
	bool ret = false;

	spin_lock(&kl->lock);

	if ((bch_keylist_capacity(&kl->list) >= kl->max_size)
	    && ((bch_keylist_capacity(&kl->list)
		 - bch_keylist_size(&kl->list))
		< BKEY_EXTENT_MAX_U64s)) {
		ret = true;
	}
	spin_unlock(&kl->lock);

	return ret;
}

/**
 * bch_mark_keylist_keys - update oldest generation pointer into a bucket
 *
 * This prevents us from wrapping around gens for a bucket only referenced from
 * the tiering or moving GC keylists. We don't actually care that the data in
 * those buckets is marked live, only that we don't wrap the gens.
 */
void bch_mark_scan_keylist_keys(struct cache_set *c, struct scan_keylist *kl)
{
	struct bkey *k;

	spin_lock(&kl->lock);
	rcu_read_lock();

	for (k = kl->list.bot; k < kl->list.top; k = bkey_next(k))
		bch_btree_mark_last_gc(c, k);

	rcu_read_unlock();
	spin_unlock(&kl->lock);
}

/* Actual scanning functionality of scan_keylists */

struct skl_refill {
	struct btree_op		op;
	unsigned		nr_found;
	struct scan_keylist	*kl;
	struct bkey		*end;
	scan_keylist_pred_fn	*pred;
};

static int refill_scan_keylist_fn(struct btree_op *op,
				  struct btree *b,
				  struct bkey *k)
{
	struct skl_refill *refill = container_of(op, struct skl_refill, op);
	struct scan_keylist *kl = refill->kl;
	int ret = MAP_CONTINUE;

	if (bkey_cmp(k, refill->end) >= 0)
		ret = MAP_DONE;
	else if (refill->pred(kl, k)) {
		if (bch_keylist_realloc(&kl->list, KEY_U64s(k)))
			ret = MAP_DONE;
		else {
			spin_lock(&kl->lock);

			__bch_keylist_add(&kl->list, k);
			refill->nr_found += 1;

			spin_unlock(&kl->lock);
		}
	}

	kl->last_scanned = *k;
	return ret;
}

static void bch_refill_scan_keylist(struct cache_set *c,
				    struct scan_keylist *kl,
				    struct bkey *end,
				    scan_keylist_pred_fn *pred)
{
	struct bkey start = kl->last_scanned;
	struct skl_refill refill;
	int ret;

	cond_resched();

	bch_btree_op_init(&refill.op, BTREE_ID_EXTENTS, -1);
	refill.nr_found	= 0;
	refill.kl	= kl;
	refill.end	= end;
	refill.pred	= pred;

	ret = bch_btree_map_keys(&refill.op, c,
				 &kl->last_scanned,
				 refill_scan_keylist_fn, 0);
	if (ret == MAP_CONTINUE) {
		/* If we end up here, it means:
		 * - the map_fn didn't fill up the keylist
		 * - the map_fn didn't see the end key
		 * - there were no more keys to map over
		 * Therefore, we are at the end of the key space */
		kl->last_scanned = MAX_KEY;
	}

	trace_bcache_keyscan(refill.nr_found,
			     KEY_INODE(&start), KEY_OFFSET(&start),
			     KEY_INODE(&kl->last_scanned),
			     KEY_OFFSET(&kl->last_scanned));
}

struct bkey *bch_scan_keylist_next(struct scan_keylist *kl)
{
	struct bkey *k;

	k = bch_keylist_front(&kl->list);
	if (bch_keylist_is_end(&kl->list, k))
		return NULL;

	return k;
}

struct bkey *bch_scan_keylist_next_rescan(struct cache_set *c,
					  struct scan_keylist *kl,
					  struct bkey *end,
					  scan_keylist_pred_fn *pred)
{
	struct bkey *ret;

	while (1) {
		ret = bch_scan_keylist_next(kl);
		if (ret)
			break;

		if (bkey_cmp(&kl->last_scanned, end) >= 0) {
			pr_debug("scan finished");
			break;
		}

		bch_refill_scan_keylist(c, kl, end, pred);
	}

	return ret;
}
