#ifndef _BCACHE_KEYBUF_TYPES_H
#define _BCACHE_KEYBUF_TYPES_H

struct keybuf_key {
	struct rb_node		node;
	BKEY_PADDED(key);
	atomic_t		ref;
};

struct keybuf {
	struct bkey		last_scanned;
	spinlock_t		lock;

	/*
	 * Beginning and end of range in rb tree - so that we can skip taking
	 * lock and checking the rb tree when we need to check for overlapping
	 * keys.
	 */
	struct bkey		start;
	struct bkey		end;

	struct rb_root		keys;

	struct semaphore	in_flight;

#define KEYBUF_NR		500
	DECLARE_ARRAY_ALLOCATOR(struct keybuf_key, freelist, KEYBUF_NR);
};

#endif /* _BCACHE_KEYBUF_TYPES_H */
