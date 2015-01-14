#ifndef _BCACHE_MOVE_H
#define _BCACHE_MOVE_H

#include "io.h"

enum moving_purpose {
	MOVING_PURPOSE_UNKNOWN,	/* Un-init */
	MOVING_PURPOSE_MIGRATION,
	MOVING_PURPOSE_TIERING,
	MOVING_PURPOSE_COPY_GC,
};

enum moving_flag_bitnos {
	MOVING_FLAG_BITNO_READ = 0,
	MOVING_FLAG_BITNO_WRITE,
};

#define MOVING_FLAG_READ	(1U << MOVING_FLAG_BITNO_READ)
#define MOVING_FLAG_WRITE	(1U << MOVING_FLAG_BITNO_WRITE)

struct moving_context {
	/* Closure for waiting on all reads and writes to complete */
	struct closure		cl;

	/* Number and types of errors reported */
	atomic_t		error_count;
	atomic_t		error_flags;

	/* If != 0, @task is waiting for a read or write to complete */
	atomic_t		pending;
	struct task_struct	*task;

	/* Key and sector moves issued, updated from submission context */
	u64			keys_moved;
	u64			sectors_moved;

	/* Last key scanned */
	struct bpos		last_scanned;

	/* Rate-limiter counting submitted reads */
	struct bch_ratelimit	*rate;

	/* Try to avoid reading the following device */
	struct cache		*avoid;

	/* Debugging... */
	enum moving_purpose	purpose;
};

void bch_moving_context_init(struct moving_context *, struct bch_ratelimit *,
			     enum moving_purpose);

static inline int bch_moving_context_wait(struct moving_context *ctxt)
{
	return bch_ratelimit_wait_freezable_stoppable(ctxt->rate, &ctxt->cl);
}

void bch_moving_wait(struct moving_context *);

struct moving_io {
	struct list_head	list;
	struct rb_node		node;
	struct closure		cl;
	struct moving_queue	*q;
	struct bch_write_op	op;
	struct moving_context	*context;
	BKEY_PADDED(key);
	/* Sort key for moving_queue->tree */
	u64			sort_key;
	/* Protected by q->lock */

	/*
	 * 1) !read_issued && !read_completed
	 *    - Closure is not running yet, starts when read_issued is set
	 *    - IO is in q->pending
	 * 2) !write_issued && !write_completed:
	 *    - IO is in q->pending
	 * 3) write_issued:
	 *    - IO is in q->write_pending
	 * 4) write_completed:
	 *    - Closure is about to return and the IO is about to be freed
	 *
	 * If read_issued, we hold a reference on q->read_count
	 * If write_issued, we hold a reference on q->write_count
	 * Until IO is freed, we hold a reference on q->count
	 */
	int			read_issued : 1;
	int			read_completed : 1;
	int			write_issued : 1;
	/* Must be last since it is variable size */
	struct bbio		bio;
};

struct moving_io *moving_io_alloc(const struct bkey *);

typedef struct moving_io *(moving_queue_fn)(struct moving_queue *,
					    struct moving_context *);

void bch_queue_init(struct moving_queue *,
		    struct cache_set *,
		    unsigned max_keys,
		    unsigned max_ios,
		    unsigned max_reads,
		    unsigned max_writes);
int bch_queue_start(struct moving_queue *,
		    const char *);
bool bch_queue_full(struct moving_queue *);
void bch_data_move(struct moving_queue *,
		   struct moving_context *,
		   struct moving_io *);
void bch_queue_destroy(struct moving_queue *);
void bch_queue_stop(struct moving_queue *);

void bch_queue_recalc_oldest_gens(struct cache_set *, struct moving_queue *);

void bch_queue_run(struct moving_queue *, struct moving_context *);

#define sysfs_queue_attribute(name)					\
	rw_attribute(name##_max_count);					\
	rw_attribute(name##_max_read_count);				\
	rw_attribute(name##_max_write_count);				\
	rw_attribute(name##_max_keys)

#define sysfs_queue_files(name)						\
	&sysfs_##name##_max_count,					\
	&sysfs_##name##_max_read_count,					\
	&sysfs_##name##_max_write_count,				\
	&sysfs_##name##_max_keys

#define sysfs_queue_show(name, var)					\
do {									\
	sysfs_hprint(name##_max_count,		(var)->max_count);	\
	sysfs_print(name##_max_read_count,	(var)->max_read_count);	\
	sysfs_print(name##_max_write_count,	(var)->max_write_count);\
	sysfs_print(name##_max_keys, bch_scan_keylist_size(&(var)->keys));\
} while (0)

#define sysfs_queue_store(name, var)					\
do {									\
	sysfs_strtoul(name##_max_count, (var)->max_count);		\
	sysfs_strtoul(name##_max_read_count, (var)->max_read_count);	\
	sysfs_strtoul(name##_max_write_count, (var)->max_write_count);	\
	if (attr == &sysfs_##name##_max_keys) {				\
		int v = strtoi_h_or_return(buf);			\
									\
		v = clamp(v, 2, KEYLIST_MAX);				\
		bch_scan_keylist_resize(&(var)->keys, v);		\
	}								\
} while (0)

int bch_move_data_off_device(struct cache *);
int bch_move_meta_data_off_device(struct cache *);
int bch_flag_data_bad(struct cache *);

#endif /* _BCACHE_MOVE_H */
