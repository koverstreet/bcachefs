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
	unsigned max_count; /* Total number of requests in queue */
	unsigned max_read_count; /* Reads in flight */
	unsigned max_write_count; /* Writes in flight */

	/* Protects everything below */
	spinlock_t lock;
	bool stopped;		/* This can be examined without locking */
	struct closure *stop_waitcl;
	struct list_head pending; /* List of struct moving_io */
	unsigned count;
	unsigned read_count;
	unsigned write_count;
};

#endif /* _BCACHE_MOVE_TYPES_H */
