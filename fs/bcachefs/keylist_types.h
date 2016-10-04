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
 * that is, @top_p + BKEY_EXTENT_U64s_MAX <= @end_keys_p.
 *
 * If this invariant does not hold after enqueuing a key, we wrap @top back
 * to @start_keys_p.
 *
 * If at any time, @top_p + BKEY_EXTENT_U64s_MAX >= @bot_p, the keylist is
 * full.
 */

#define KEYLIST_MAX		(1 << 18)

struct keylist {
	/* This is a pointer to the LSB (inline_keys until realloc'd) */
	union {
		struct bkey_i		*start_keys;
		u64			*start_keys_p;
	};
	/* This is a pointer to the next to enqueue */
	union {
		struct bkey_i		*top;
		u64			*top_p;
	};
	/* This is a pointer to the next to dequeue */
	union {
		struct bkey_i		*bot;
		u64			*bot_p;
	};
	/* This is a pointer to beyond the MSB */
	union {
		struct bkey_i		*end_keys;
		u64			*end_keys_p;
	};
	bool				has_buf;
};

#endif /* _BCACHE_KEYLIST_TYPES_H */
