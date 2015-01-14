#ifndef _BCACHE_MOVE_TYPES_H
#define _BCACHE_MOVE_TYPES_H

#define MOVING_QUEUE_INITIALIZED	1

/*
 * We rely on moving_queue being kzalloc'd so that the initial value of
 * the flags is 0.
 */

struct moving_queue {
	unsigned long flags;
	struct work_struct work;
	struct scan_keylist keys;
	struct workqueue_struct *wq;

	/* Configuration */
	unsigned		max_count;
	unsigned		max_read_count;
	unsigned		max_write_count;

	/* This can be examined without locking */
	bool			stopped;

	/* Protects everything below */
	spinlock_t		lock;

	struct closure		*stop_waitcl;

	/*
	 * List of struct moving_io, sorted by logical offset.
	 * Contains writes which have not yet been issued; when a write is
	 * issued, it is removed from the list.
	 *
	 * Writes are issued in logical offset order, and only when all
	 * prior writes have been issued.
	 */
	struct list_head	pending;

	/*
	 * List of struct moving_io, sorted by logical offset.
	 *
	 * Contains writes which are in-flight.
	 */
	struct list_head	write_pending;

	unsigned		count;
	unsigned		read_count;
	unsigned		write_count;
};

#endif /* _BCACHE_MOVE_TYPES_H */
