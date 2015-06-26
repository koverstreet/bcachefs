#ifndef _BCACHE_KEYBUF_TYPES_H
#define _BCACHE_KEYBUF_TYPES_H

struct keybuf_key {
	struct rb_node		node;
	BKEY_PADDED(key);
	atomic_t		ref;
};

#define KEYBUF_REFILL_BATCH	500

struct keybuf {
	struct bpos		last_scanned;
	spinlock_t		lock;

	/*
	 * Beginning and end of range in rb tree - so that we can skip taking
	 * lock and checking the rb tree when we need to check for overlapping
	 * keys.
	 */
	struct bpos		start;
	struct bpos		end;

	struct rb_root		keys;

	unsigned		max_in_flight;
	struct semaphore	in_flight;

	DECLARE_ARRAY_ALLOCATOR(struct keybuf_key, freelist,
				KEYBUF_REFILL_BATCH);
};

#endif /* _BCACHE_KEYBUF_TYPES_H */
