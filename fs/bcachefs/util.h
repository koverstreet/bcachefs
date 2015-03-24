#ifndef _BCACHE_UTIL_H
#define _BCACHE_UTIL_H

#include <linux/blkdev.h>
#include <linux/closure.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include <linux/freezer.h>
#include <linux/kernel.h>
#include <linux/llist.h>
#include <linux/ratelimit.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#define PAGE_SECTORS		(PAGE_SIZE / 512)

struct closure;

#ifdef CONFIG_BCACHEFS_DEBUG

#define EBUG_ON(cond)		BUG_ON(cond)
#define atomic_dec_bug(v)	BUG_ON(atomic_dec_return(v) < 0)
#define atomic_inc_bug(v, i)	BUG_ON(atomic_inc_return(v) <= i)
#define atomic_sub_bug(i, v)	BUG_ON(atomic_sub_return(i, v) < 0)
#define atomic_add_bug(i, v)	BUG_ON(atomic_add_return(i, v) < 0)
#define atomic64_dec_bug(v)	BUG_ON(atomic64_dec_return(v) < 0)
#define atomic64_inc_bug(v, i)	BUG_ON(atomic64_inc_return(v) <= i)
#define atomic64_sub_bug(i, v)	BUG_ON(atomic64_sub_return(i, v) < 0)
#define atomic64_add_bug(i, v)	BUG_ON(atomic64_add_return(i, v) < 0)

#else /* DEBUG */

#define EBUG_ON(cond)
#define atomic_dec_bug(v)	atomic_dec(v)
#define atomic_inc_bug(v, i)	atomic_inc(v)
#define atomic_sub_bug(i, v)	atomic_sub(i, v)
#define atomic_add_bug(i, v)	atomic_add(i, v)
#define atomic64_dec_bug(v)	atomic64_dec(v)
#define atomic64_inc_bug(v, i)	atomic64_inc(v)
#define atomic64_sub_bug(i, v)	atomic64_sub(i, v)
#define atomic64_add_bug(i, v)	atomic64_add(i, v)

#endif

#define DECLARE_HEAP(type, name)					\
	struct {							\
		size_t size, used;					\
		type *data;						\
	} name

#define init_heap(heap, _size, gfp)					\
({									\
	size_t _bytes;							\
	(heap)->used = 0;						\
	(heap)->size = (_size);						\
	_bytes = (heap)->size * sizeof(*(heap)->data);			\
	(heap)->data = NULL;						\
	if (_bytes < KMALLOC_MAX_SIZE)					\
		(heap)->data = kmalloc(_bytes, (gfp));			\
	if ((!(heap)->data) && ((gfp) & GFP_KERNEL))			\
		(heap)->data = vmalloc(_bytes);				\
	(heap)->data;							\
})

#define free_heap(heap)							\
do {									\
	kvfree((heap)->data);						\
	(heap)->data = NULL;						\
} while (0)

#define heap_swap(h, i, j)	swap((h)->data[i], (h)->data[j])

#define heap_sift(h, i, cmp)						\
do {									\
	size_t _r, _j = i;						\
									\
	for (; _j * 2 + 1 < (h)->used; _j = _r) {			\
		_r = _j * 2 + 1;					\
		if (_r + 1 < (h)->used &&				\
		    cmp((h)->data[_r], (h)->data[_r + 1]))		\
			_r++;						\
									\
		if (cmp((h)->data[_r], (h)->data[_j]))			\
			break;						\
		heap_swap(h, _r, _j);					\
	}								\
} while (0)

#define heap_sift_down(h, i, cmp)					\
do {									\
	while (i) {							\
		size_t p = (i - 1) / 2;					\
		if (cmp((h)->data[i], (h)->data[p]))			\
			break;						\
		heap_swap(h, i, p);					\
		i = p;							\
	}								\
} while (0)

#define heap_add(h, d, cmp)						\
({									\
	bool _r = !heap_full(h);					\
	if (_r) {							\
		size_t _i = (h)->used++;				\
		(h)->data[_i] = d;					\
									\
		heap_sift_down(h, _i, cmp);				\
		heap_sift(h, _i, cmp);					\
	}								\
	_r;								\
})

#define heap_pop(h, d, cmp)						\
({									\
	bool _r = (h)->used;						\
	if (_r) {							\
		(d) = (h)->data[0];					\
		(h)->used--;						\
		heap_swap(h, 0, (h)->used);				\
		heap_sift(h, 0, cmp);					\
	}								\
	_r;								\
})

#define heap_peek(h)							\
({									\
	EBUG_ON(!(h)->used);						\
	(h)->data[0];							\
})

#define heap_full(h)	((h)->used == (h)->size)

#define heap_resort(heap, cmp)						\
do {									\
	ssize_t _i;							\
	for (_i = (ssize_t) (heap)->used / 2 -  1; _i >= 0; --_i)	\
		heap_sift(heap, _i, cmp);				\
} while (0)

/*
 * Simple array based allocator - preallocates a number of elements and you can
 * never allocate more than that, also has no locking.
 *
 * Handy because if you know you only need a fixed number of elements you don't
 * have to worry about memory allocation failure, and sometimes a mempool isn't
 * what you want.
 *
 * We treat the free elements as entries in a singly linked list, and the
 * freelist as a stack - allocating and freeing push and pop off the freelist.
 */

#define DECLARE_ARRAY_ALLOCATOR(type, name, size)			\
	struct {							\
		type	*freelist;					\
		type	data[size];					\
	} name

#define array_alloc(array)						\
({									\
	typeof((array)->freelist) _ret = (array)->freelist;		\
									\
	if (_ret)							\
		(array)->freelist = *((typeof((array)->freelist) *) _ret);\
									\
	_ret;								\
})

#define array_free(array, ptr)						\
do {									\
	typeof((array)->freelist) _ptr = ptr;				\
									\
	*((typeof((array)->freelist) *) _ptr) = (array)->freelist;	\
	(array)->freelist = _ptr;					\
} while (0)

#define array_allocator_init(array)					\
do {									\
	typeof((array)->freelist) _i;					\
									\
	BUILD_BUG_ON(sizeof((array)->data[0]) < sizeof(void *));	\
	(array)->freelist = NULL;					\
									\
	for (_i = (array)->data;					\
	     _i < (array)->data + ARRAY_SIZE((array)->data);		\
	     _i++)							\
		array_free(array, _i);					\
} while (0)

#define array_freelist_empty(array)	((array)->freelist == NULL)

#define ANYSINT_MAX(t)							\
	((((t) 1 << (sizeof(t) * 8 - 2)) - (t) 1) * (t) 2 + (t) 1)

int bch_strtoint_h(const char *, int *);
int bch_strtouint_h(const char *, unsigned int *);
int bch_strtoll_h(const char *, long long *);
int bch_strtoull_h(const char *, unsigned long long *);

static inline int bch_strtol_h(const char *cp, long *res)
{
#if BITS_PER_LONG == 32
	return bch_strtoint_h(cp, (int *) res);
#else
	return bch_strtoll_h(cp, (long long *) res);
#endif
}

static inline int bch_strtoul_h(const char *cp, long *res)
{
#if BITS_PER_LONG == 32
	return bch_strtouint_h(cp, (unsigned int *) res);
#else
	return bch_strtoull_h(cp, (unsigned long long *) res);
#endif
}

#define strtoi_h(cp, res)						\
	(__builtin_types_compatible_p(typeof(*res), int)		\
	? bch_strtoint_h(cp, (void *) res)				\
	: __builtin_types_compatible_p(typeof(*res), long)		\
	? bch_strtol_h(cp, (void *) res)				\
	: __builtin_types_compatible_p(typeof(*res), long long)		\
	? bch_strtoll_h(cp, (void *) res)				\
	: __builtin_types_compatible_p(typeof(*res), unsigned int)	\
	? bch_strtouint_h(cp, (void *) res)				\
	: __builtin_types_compatible_p(typeof(*res), unsigned long)	\
	? bch_strtoul_h(cp, (void *) res)				\
	: __builtin_types_compatible_p(typeof(*res), unsigned long long)\
	? bch_strtoull_h(cp, (void *) res) : -EINVAL)

#define strtoul_safe(cp, var)						\
({									\
	unsigned long _v;						\
	int _r = kstrtoul(cp, 10, &_v);					\
	if (!_r)							\
		var = _v;						\
	_r;								\
})

#define strtoul_safe_clamp(cp, var, min, max)				\
({									\
	unsigned long _v;						\
	int _r = kstrtoul(cp, 10, &_v);					\
	if (!_r)							\
		var = clamp_t(typeof(var), _v, min, max);		\
	_r;								\
})

#define strtoul_safe_restrict(cp, var, min, max)			\
({									\
	unsigned long _v;						\
	int _r = kstrtoul(cp, 10, &_v);					\
	if (!_r && _v >= min && _v <= max)				\
		var = _v;						\
	else								\
		_r = -EINVAL;						\
	_r;								\
})

#define snprint(buf, size, var)						\
	snprintf(buf, size,						\
		__builtin_types_compatible_p(typeof(var), int)		\
		     ? "%i\n" :						\
		__builtin_types_compatible_p(typeof(var), unsigned)	\
		     ? "%u\n" :						\
		__builtin_types_compatible_p(typeof(var), long)		\
		     ? "%li\n" :					\
		__builtin_types_compatible_p(typeof(var), unsigned long)\
		     ? "%lu\n" :					\
		__builtin_types_compatible_p(typeof(var), int64_t)	\
		     ? "%lli\n" :					\
		__builtin_types_compatible_p(typeof(var), uint64_t)	\
		     ? "%llu\n" :					\
		__builtin_types_compatible_p(typeof(var), const char *)	\
		     ? "%s\n" : "%i\n", var)

ssize_t bch_hprint(char *buf, int64_t v);

bool bch_is_zero(const char *p, size_t n);

ssize_t bch_snprint_string_list(char *buf, size_t size, const char * const list[],
			    size_t selected);

ssize_t bch_read_string_list(const char *buf, const char * const list[]);

struct time_stats {
	spinlock_t	lock;
	u64		count;
	/*
	 * all fields are in nanoseconds, averages are ewmas stored left shifted
	 * by 8
	 */
	u64		last_duration;
	u64		max_duration;
	u64		average_duration;
	u64		average_frequency;
	u64		last;
};

void bch_time_stats_clear(struct time_stats *stats);
void bch_time_stats_update(struct time_stats *stats, u64 time);

static inline unsigned local_clock_us(void)
{
	return local_clock() >> 10;
}

#define NSEC_PER_ns			1L
#define NSEC_PER_us			NSEC_PER_USEC
#define NSEC_PER_ms			NSEC_PER_MSEC
#define NSEC_PER_sec			NSEC_PER_SEC

#define __print_time_stat(stats, name, stat, units)			\
	sysfs_print(name ## _ ## stat ## _ ## units,			\
		    div_u64((stats)->stat >> 8, NSEC_PER_ ## units))

#define sysfs_print_time_stats(stats, name,				\
			       frequency_units,				\
			       duration_units)				\
do {									\
	__print_time_stat(stats, name,					\
			  average_frequency,	frequency_units);	\
	__print_time_stat(stats, name,					\
			  average_duration,	duration_units);	\
	sysfs_print(name ## _ ##count, (stats)->count);			\
	sysfs_print(name ## _ ##last_duration ## _ ## duration_units,	\
			div_u64((stats)->last_duration,			\
				NSEC_PER_ ## duration_units));		\
	sysfs_print(name ## _ ##max_duration ## _ ## duration_units,	\
			div_u64((stats)->max_duration,			\
				NSEC_PER_ ## duration_units));		\
									\
	sysfs_print(name ## _last_ ## frequency_units, (stats)->last	\
		    ? div_s64(local_clock() - (stats)->last,		\
			      NSEC_PER_ ## frequency_units)		\
		    : -1LL);						\
} while (0)

#define sysfs_clear_time_stats(stats, name)				\
do {									\
	if (attr == &sysfs_ ## name ## _clear)				\
		bch_time_stats_clear(stats);				\
} while (0)

#define sysfs_time_stats_attribute(name,				\
				   frequency_units,			\
				   duration_units)			\
write_attribute(name ## _clear);					\
read_attribute(name ## _count);						\
read_attribute(name ## _average_frequency_ ## frequency_units);		\
read_attribute(name ## _average_duration_ ## duration_units);		\
read_attribute(name ## _last_duration_ ## duration_units);		\
read_attribute(name ## _max_duration_ ## duration_units);		\
read_attribute(name ## _last_ ## frequency_units)

#define sysfs_time_stats_attribute_list(name,				\
					frequency_units,		\
					duration_units)			\
&sysfs_ ## name ## _clear,						\
&sysfs_ ## name ## _count,						\
&sysfs_ ## name ## _average_frequency_ ## frequency_units,		\
&sysfs_ ## name ## _average_duration_ ## duration_units,		\
&sysfs_ ## name ## _last_duration_ ## duration_units,			\
&sysfs_ ## name ## _max_duration_ ## duration_units,			\
&sysfs_ ## name ## _last_ ## frequency_units,

#define ewma_add(ewma, val, weight)					\
({									\
	typeof(ewma) _ewma = (ewma);					\
	typeof(weight) _weight = (weight);				\
									\
	(((_ewma << _weight) - _ewma) + (val)) >> _weight;		\
})

struct bch_ratelimit {
	/* Next time we want to do some work, in nanoseconds */
	uint64_t		next;

	/*
	 * Rate at which we want to do work, in units per nanosecond
	 * The units here correspond to the units passed to
	 * bch_ratelimit_increment()
	 */
	unsigned		rate;
};

static inline void bch_ratelimit_reset(struct bch_ratelimit *d)
{
	d->next = local_clock();
}

u64 bch_ratelimit_delay(struct bch_ratelimit *);
void bch_ratelimit_increment(struct bch_ratelimit *, u64);
int bch_ratelimit_wait_freezable_stoppable(struct bch_ratelimit *,
					   struct closure *);

struct bch_pd_controller {
	struct bch_ratelimit	rate;
	unsigned long		last_update;

	s64			last_actual;
	s64			smoothed_derivative;

	unsigned		p_term_inverse;
	unsigned		d_smooth;
	unsigned		d_term;

	/* for exporting to sysfs (no effect on behavior) */
	s64			last_derivative;
	s64			last_proportional;
	s64			last_change;
	s64			last_target;

	/* If true, the rate will not increase if bch_ratelimit_delay()
	 * is not being called often enough. */
	bool			backpressure;
};

void bch_pd_controller_update(struct bch_pd_controller *, s64, s64, int);
void bch_pd_controller_init(struct bch_pd_controller *);
size_t bch_pd_controller_print_debug(struct bch_pd_controller *, char *);

#define sysfs_pd_controller_attribute(name)				\
	rw_attribute(name##_rate);					\
	rw_attribute(name##_rate_bytes);				\
	rw_attribute(name##_rate_d_term);				\
	rw_attribute(name##_rate_p_term_inverse);			\
	read_attribute(name##_rate_debug)

#define sysfs_pd_controller_files(name)					\
	&sysfs_##name##_rate,						\
	&sysfs_##name##_rate_bytes,					\
	&sysfs_##name##_rate_d_term,					\
	&sysfs_##name##_rate_p_term_inverse,				\
	&sysfs_##name##_rate_debug

#define sysfs_pd_controller_show(name, var)				\
do {									\
	sysfs_hprint(name##_rate,		(var)->rate.rate);	\
	sysfs_print(name##_rate_bytes,		(var)->rate.rate);	\
	sysfs_print(name##_rate_d_term,		(var)->d_term);		\
	sysfs_print(name##_rate_p_term_inverse,	(var)->p_term_inverse);	\
									\
	if (attr == &sysfs_##name##_rate_debug)				\
		return bch_pd_controller_print_debug(var, buf);		\
} while (0)

#define sysfs_pd_controller_store(name, var)				\
do {									\
	sysfs_strtoul_clamp(name##_rate,				\
			    (var)->rate.rate, 1, UINT_MAX);		\
	sysfs_strtoul_clamp(name##_rate_bytes,				\
			    (var)->rate.rate, 1, UINT_MAX);		\
	sysfs_strtoul(name##_rate_d_term,	(var)->d_term);		\
	sysfs_strtoul_clamp(name##_rate_p_term_inverse,			\
			    (var)->p_term_inverse, 1, INT_MAX);		\
} while (0)

#define __DIV_SAFE(n, d, zero)						\
({									\
	typeof(n) _n = (n);						\
	typeof(d) _d = (d);						\
	_d ? _n / _d : zero;						\
})

#define DIV_SAFE(n, d)	__DIV_SAFE(n, d, 0)

#define container_of_or_null(ptr, type, member)				\
({									\
	typeof(ptr) _ptr = ptr;						\
	_ptr ? container_of(_ptr, type, member) : NULL;			\
})

#define RB_INSERT(root, new, member, cmp)				\
({									\
	__label__ dup;							\
	struct rb_node **n = &(root)->rb_node, *parent = NULL;		\
	typeof(new) this;						\
	int res, ret = -1;						\
									\
	while (*n) {							\
		parent = *n;						\
		this = container_of(*n, typeof(*(new)), member);	\
		res = cmp(new, this);					\
		if (!res)						\
			goto dup;					\
		n = res < 0						\
			? &(*n)->rb_left				\
			: &(*n)->rb_right;				\
	}								\
									\
	rb_link_node(&(new)->member, parent, n);			\
	rb_insert_color(&(new)->member, root);				\
	ret = 0;							\
dup:									\
	ret;								\
})

#define RB_SEARCH(root, search, member, cmp)				\
({									\
	struct rb_node *n = (root)->rb_node;				\
	typeof(&(search)) this, ret = NULL;				\
	int res;							\
									\
	while (n) {							\
		this = container_of(n, typeof(search), member);		\
		res = cmp(&(search), this);				\
		if (!res) {						\
			ret = this;					\
			break;						\
		}							\
		n = res < 0						\
			? n->rb_left					\
			: n->rb_right;					\
	}								\
	ret;								\
})

#define RB_GREATER(root, search, member, cmp)				\
({									\
	struct rb_node *n = (root)->rb_node;				\
	typeof(&(search)) this, ret = NULL;				\
	int res;							\
									\
	while (n) {							\
		this = container_of(n, typeof(search), member);		\
		res = cmp(&(search), this);				\
		if (res < 0) {						\
			ret = this;					\
			n = n->rb_left;					\
		} else							\
			n = n->rb_right;				\
	}								\
	ret;								\
})

#define RB_FIRST(root, type, member)					\
	container_of_or_null(rb_first(root), type, member)

#define RB_LAST(root, type, member)					\
	container_of_or_null(rb_last(root), type, member)

#define RB_NEXT(ptr, member)						\
	container_of_or_null(rb_next(&(ptr)->member), typeof(*ptr), member)

#define RB_PREV(ptr, member)						\
	container_of_or_null(rb_prev(&(ptr)->member), typeof(*ptr), member)

/* Does linear interpolation between powers of two */
static inline unsigned fract_exp_two(unsigned x, unsigned fract_bits)
{
	unsigned fract = x & ~(~0 << fract_bits);

	x >>= fract_bits;
	x   = 1 << x;
	x  += (x * fract) >> fract_bits;

	return x;
}

void bch_bio_map(struct bio *bio, void *base);

static inline sector_t bdev_sectors(struct block_device *bdev)
{
	return bdev->bd_inode->i_size >> 9;
}

#define closure_bio_submit(bio, cl)					\
do {									\
	closure_get(cl);						\
	generic_make_request(bio);					\
} while (0)

#define closure_bio_submit_punt(bio, cl, c)				\
do {									\
	closure_get(cl);						\
	bch_generic_make_request(bio, c);				\
} while (0)

uint64_t bch_crc64_update(uint64_t, const void *, size_t);
uint64_t bch_crc64(const void *, size_t);

int bch_kthread_loop_ratelimit(unsigned long *, unsigned long);

#define kthread_wait_freezable(cond)					\
({									\
	int _ret = 0;							\
	while (1) {							\
		set_current_state(TASK_INTERRUPTIBLE);			\
		if (kthread_should_stop()) {				\
			_ret = -1;					\
			break;						\
		}							\
									\
		if (cond)						\
			break;						\
									\
		try_to_freeze();					\
		schedule();						\
	}								\
	set_current_state(TASK_RUNNING);				\
	_ret;								\
})

static inline s64 timekeeping_clocktai_ns(void)
{
	struct timespec ts;

	timekeeping_clocktai(&ts);
	return (s64) ts.tv_sec * NSEC_PER_SEC + (s64) ts.tv_nsec;
}

size_t bch_rand_range(size_t);

void bch_semaphore_resize(struct semaphore *sem, int delta);

#endif /* _BCACHE_UTIL_H */
