#ifndef _BCACHE_KEYLIST_TYPES_H
#define _BCACHE_KEYLIST_TYPES_H

/*
 * Keylists are growable FIFOs storing bkeys.
 *
 * New keys are added via bch_keylist_enqueue(), which increments @top until
 * it wraps around.
 *
 * Old keys are removed via bch_keylist_dequeue() which increments @bot
 * until it wraps around.
 *
 * If @top == @bot, the keylist is empty.
 *
 * We always ensure there is room for a maximum-sized extent key at @top;
 * that is, @top_p + BKEY_EXTENT_MAX_U64s <= @end_keys_p.
 *
 * If this invariant does not hold after enqueuing a key, we wrap @top back
 * to @start_keys_p.
 *
 * If at any time, @top_p + BKEY_EXTENT_MAX_U64s >= @bot_p, the keylist is
 * full.
 */

struct keylist {
	/* This is a pointer to the LSB (inline_keys until realloc'd) */
	union {
		struct bkey		*start_keys;
		u64			*start_keys_p;
	};
	/* This is a pointer to the next to enqueue */
	union {
		struct bkey		*top;
		u64			*top_p;
	};
	/* This is a pointer to the next to dequeue */
	union {
		struct bkey		*bot;
		u64			*bot_p;
	};
	/* This is a pointer to beyond the MSB */
	union {
		struct bkey		*end_keys;
		u64			*end_keys_p;
	};
	/* Enough room for btree_split's keys without realloc */
#define KEYLIST_INLINE		roundup_pow_of_two(BKEY_EXTENT_MAX_U64s * 3)
	/* Prevent key lists from growing too big */
	/*
	 * This should always be big enough to allow btree_gc_coalesce and
	 * btree_split to complete.
	 * The current value is the (current) size of a bucket, so it
	 * is far more than enough, as those two operations require only
	 * a handful of keys.
	 */
#define KEYLIST_MAX		(1 << 18)
	u64			inline_keys[KEYLIST_INLINE];
};

/*
 * scan_keylists are conceptually similar to keybufs, but they don't
 * have an internal RB tree.
 * keybufs should be used when read or write operations need to
 * examine keys in flight, as for writeback.
 * But for moving operations (moving gc, tiering, moving data off
 * devices), read and writes don't need to look at all, so we don't
 * need the RB tree and use scan_keylists instead.
 *
 * Note that unlike keybufs, they don't contain a semaphore to limit
 * bios.  That must be done externally, if necessary.
 */

#define DFLT_SCAN_KEYLIST_MAX_SIZE	(1 << 14)

struct scan_keylist {
	/*
	 * The last key we added to the keylist while refilling. Refilling will
	 * restart from the next key after this key.
	 */
	struct bkey		last_scanned;
	/*
	 * Only one thread is allowed to mutate the keylist. Other threads can
	 * read it. The mutex has to be taken by the mutator thread when
	 * mutating the keylist, and by other threads when reading, but not by
	 * the mutator thread when reading.
	 */
	struct mutex		lock;
	/*
	 * Maximum size, in u64s. The keylist will not grow beyond this size.
	 */
	unsigned		max_size;
	/*
	 * Number of sectors in keys currently on the keylist.
	 */
	atomic64_t		sectors;
	/*
	 * The underlying keylist.
	 */
	struct keylist		list;
};

typedef bool (scan_keylist_pred_fn)(struct scan_keylist *, struct bkey *);

#endif /* _BCACHE_KEYLIST_TYPES_H */
