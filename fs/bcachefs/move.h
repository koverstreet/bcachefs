#ifndef _BCACHE_MOVE_H
#define _BCACHE_MOVE_H

#include "buckets.h"
#include "io_types.h"
#include "move_types.h"

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


	/* Key and sector moves issued, updated from submission context */
	u64			keys_moved;
	u64			sectors_moved;

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
	if (ctxt->rate == NULL)
		return 0;

	return bch_ratelimit_wait_freezable_stoppable(ctxt->rate, &ctxt->cl);
}

struct migrate_write {
	BKEY_PADDED(key);
	bool			promote;
	bool			move;
	struct bch_extent_ptr	move_ptr;
	struct bch_write_op	op;
	struct bch_write_bio	wbio;
};

void bch_migrate_write_init(struct cache_set *,
			    struct migrate_write *,
			    struct write_point *,
			    struct bkey_s_c,
			    const struct bch_extent_ptr *,
			    unsigned);

struct moving_io {
	struct list_head	list;
	struct rb_node		node;
	struct closure		cl;
	struct moving_queue	*q;
	struct moving_context	*context;
	struct migrate_write	write;
	/* Sort key for moving_queue->tree */
	u64			sort_key;
	/* Protected by q->lock */

	/*
	 * 1) !read_issued && !read_completed
	 *    - Closure is not running yet, starts when read_issued is set
	 *    - IO is in q->tree (if q->rotational) and q->pending
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
	unsigned		read_issued:1;
	unsigned		read_completed:1;
	unsigned		write_issued:1;

	struct bch_read_bio	rbio;
	/* Must be last since it is variable size */
	struct bio_vec		bi_inline_vecs[0];
};

void moving_io_free(struct moving_io *);
struct moving_io *moving_io_alloc(struct cache_set *,
				  struct moving_queue *,
				  struct write_point *,
				  struct bkey_s_c,
				  const struct bch_extent_ptr *);

typedef struct moving_io *(moving_queue_fn)(struct moving_queue *,
					    struct moving_context *);

int bch_queue_init(struct moving_queue *,
		   struct cache_set *,
		   unsigned max_ios,
		   unsigned max_reads,
		   unsigned max_writes,
		   bool rotational,
		   const char *);
void bch_queue_start(struct moving_queue *);

/*
 * bch_queue_full() - return if more reads can be queued with bch_data_move().
 *
 * In rotational mode, always returns false if no reads are in flight (see
 * how max_count is initialized in bch_queue_init()).
 */
static inline bool bch_queue_full(struct moving_queue *q)
{
	EBUG_ON(atomic_read(&q->count) > q->max_count);
	EBUG_ON(atomic_read(&q->read_count) > q->max_read_count);

	return atomic_read(&q->count) == q->max_count ||
		atomic_read(&q->read_count) == q->max_read_count;
}

void bch_data_move(struct moving_queue *,
		   struct moving_context *,
		   struct moving_io *);
void queue_io_resize(struct moving_queue *,
		     unsigned,
		     unsigned,
		     unsigned);
void bch_queue_destroy(struct moving_queue *);
void bch_queue_stop(struct moving_queue *);

void bch_queue_recalc_oldest_gens(struct cache_set *, struct moving_queue *);

void bch_queue_run(struct moving_queue *, struct moving_context *);

#define sysfs_queue_attribute(name)					\
	rw_attribute(name##_max_count);					\
	rw_attribute(name##_max_read_count);				\
	rw_attribute(name##_max_write_count);

#define sysfs_queue_files(name)						\
	&sysfs_##name##_max_count,					\
	&sysfs_##name##_max_read_count,					\
	&sysfs_##name##_max_write_count

#define sysfs_queue_show(name, var)					\
do {									\
	sysfs_hprint(name##_max_count,		(var)->max_count);	\
	sysfs_print(name##_max_read_count,	(var)->max_read_count);	\
	sysfs_print(name##_max_write_count,	(var)->max_write_count);\
} while (0)

#define sysfs_queue_store(name, var)					\
do {									\
	sysfs_strtoul(name##_max_count, (var)->max_count);		\
	sysfs_strtoul(name##_max_read_count, (var)->max_read_count);	\
	sysfs_strtoul(name##_max_write_count, (var)->max_write_count);	\
} while (0)

#endif /* _BCACHE_MOVE_H */
