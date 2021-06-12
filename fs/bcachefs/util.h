/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_UTIL_H
#define _BCACHEFS_UTIL_H

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/closure.h>
#include <linux/errno.h>
#include <linux/freezer.h>
#include <linux/kernel.h>
#include <linux/sched/clock.h>
#include <linux/llist.h>
#include <linux/log2.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#define PAGE_SECTOR_SHIFT	(PAGE_SHIFT - 9)
#define PAGE_SECTORS		(1UL << PAGE_SECTOR_SHIFT)

struct closure;

#ifdef CONFIG_BCACHEFS_DEBUG

#define EBUG_ON(cond)		BUG_ON(cond)
#define atomic_dec_bug(v)	BUG_ON(atomic_dec_return(v) < 0)
#define atomic_inc_bug(v, i)	BUG_ON(atomic_inc_return(v) <= i)
#define atomic_sub_bug(i, v)	BUG_ON(atomic_sub_return(i, v) < 0)
#define atomic_add_bug(i, v)	BUG_ON(atomic_add_return(i, v) < 0)
#define atomic_long_dec_bug(v)		BUG_ON(atomic_long_dec_return(v) < 0)
#define atomic_long_sub_bug(i, v)	BUG_ON(atomic_long_sub_return(i, v) < 0)
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
#define atomic_long_dec_bug(v)		atomic_long_dec(v)
#define atomic_long_sub_bug(i, v)	atomic_long_sub(i, v)
#define atomic64_dec_bug(v)	atomic64_dec(v)
#define atomic64_inc_bug(v, i)	atomic64_inc(v)
#define atomic64_sub_bug(i, v)	atomic64_sub(i, v)
#define atomic64_add_bug(i, v)	atomic64_add(i, v)

#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define CPU_BIG_ENDIAN		0
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define CPU_BIG_ENDIAN		1
#endif

/* type hackery */

#define type_is_exact(_val, _type)					\
	__builtin_types_compatible_p(typeof(_val), _type)

#define type_is(_val, _type)						\
	(__builtin_types_compatible_p(typeof(_val), _type) ||		\
	 __builtin_types_compatible_p(typeof(_val), const _type))

/* Userspace doesn't align allocations as nicely as the kernel allocators: */
static inline size_t buf_pages(void *p, size_t len)
{
	return DIV_ROUND_UP(len +
			    ((unsigned long) p & (PAGE_SIZE - 1)),
			    PAGE_SIZE);
}

static inline void vpfree(void *p, size_t size)
{
	if (is_vmalloc_addr(p))
		vfree(p);
	else
		free_pages((unsigned long) p, get_order(size));
}

static inline void *vpmalloc(size_t size, gfp_t gfp_mask)
{
	return (void *) __get_free_pages(gfp_mask|__GFP_NOWARN,
					 get_order(size)) ?:
		__vmalloc(size, gfp_mask);
}

static inline void kvpfree(void *p, size_t size)
{
	if (size < PAGE_SIZE)
		kfree(p);
	else
		vpfree(p, size);
}

static inline void *kvpmalloc(size_t size, gfp_t gfp_mask)
{
	return size < PAGE_SIZE
		? kmalloc(size, gfp_mask)
		: vpmalloc(size, gfp_mask);
}

int mempool_init_kvpmalloc_pool(mempool_t *, int, size_t);

#define HEAP(type)							\
struct {								\
	size_t size, used;						\
	type *data;							\
}

#define DECLARE_HEAP(type, name) HEAP(type) name

#define init_heap(heap, _size, gfp)					\
({									\
	(heap)->used = 0;						\
	(heap)->size = (_size);						\
	(heap)->data = kvpmalloc((heap)->size * sizeof((heap)->data[0]),\
				 (gfp));				\
})

#define free_heap(heap)							\
do {									\
	kvpfree((heap)->data, (heap)->size * sizeof((heap)->data[0]));	\
	(heap)->data = NULL;						\
} while (0)

#define heap_set_backpointer(h, i, _fn)					\
do {									\
	void (*fn)(typeof(h), size_t) = _fn;				\
	if (fn)								\
		fn(h, i);						\
} while (0)

#define heap_swap(h, i, j, set_backpointer)				\
do {									\
	swap((h)->data[i], (h)->data[j]);				\
	heap_set_backpointer(h, i, set_backpointer);			\
	heap_set_backpointer(h, j, set_backpointer);			\
} while (0)

#define heap_peek(h)							\
({									\
	EBUG_ON(!(h)->used);						\
	(h)->data[0];							\
})

#define heap_full(h)	((h)->used == (h)->size)

#define heap_sift_down(h, i, cmp, set_backpointer)			\
do {									\
	size_t _c, _j = i;						\
									\
	for (; _j * 2 + 1 < (h)->used; _j = _c) {			\
		_c = _j * 2 + 1;					\
		if (_c + 1 < (h)->used &&				\
		    cmp(h, (h)->data[_c], (h)->data[_c + 1]) >= 0)	\
			_c++;						\
									\
		if (cmp(h, (h)->data[_c], (h)->data[_j]) >= 0)		\
			break;						\
		heap_swap(h, _c, _j, set_backpointer);			\
	}								\
} while (0)

#define heap_sift_up(h, i, cmp, set_backpointer)			\
do {									\
	while (i) {							\
		size_t p = (i - 1) / 2;					\
		if (cmp(h, (h)->data[i], (h)->data[p]) >= 0)		\
			break;						\
		heap_swap(h, i, p, set_backpointer);			\
		i = p;							\
	}								\
} while (0)

#define __heap_add(h, d, cmp, set_backpointer)				\
({									\
	size_t _i = (h)->used++;					\
	(h)->data[_i] = d;						\
	heap_set_backpointer(h, _i, set_backpointer);			\
									\
	heap_sift_up(h, _i, cmp, set_backpointer);			\
	_i;								\
})

#define heap_add(h, d, cmp, set_backpointer)				\
({									\
	bool _r = !heap_full(h);					\
	if (_r)								\
		__heap_add(h, d, cmp, set_backpointer);			\
	_r;								\
})

#define heap_add_or_replace(h, new, cmp, set_backpointer)		\
do {									\
	if (!heap_add(h, new, cmp, set_backpointer) &&			\
	    cmp(h, new, heap_peek(h)) >= 0) {				\
		(h)->data[0] = new;					\
		heap_set_backpointer(h, 0, set_backpointer);		\
		heap_sift_down(h, 0, cmp, set_backpointer);		\
	}								\
} while (0)

#define heap_del(h, i, cmp, set_backpointer)				\
do {									\
	size_t _i = (i);						\
									\
	BUG_ON(_i >= (h)->used);					\
	(h)->used--;							\
	heap_swap(h, _i, (h)->used, set_backpointer);			\
	heap_sift_up(h, _i, cmp, set_backpointer);			\
	heap_sift_down(h, _i, cmp, set_backpointer);			\
} while (0)

#define heap_pop(h, d, cmp, set_backpointer)				\
({									\
	bool _r = (h)->used;						\
	if (_r) {							\
		(d) = (h)->data[0];					\
		heap_del(h, 0, cmp, set_backpointer);			\
	}								\
	_r;								\
})

#define heap_resort(heap, cmp, set_backpointer)				\
do {									\
	ssize_t _i;							\
	for (_i = (ssize_t) (heap)->used / 2 -  1; _i >= 0; --_i)	\
		heap_sift_down(heap, _i, cmp, set_backpointer);		\
} while (0)

#define ANYSINT_MAX(t)							\
	((((t) 1 << (sizeof(t) * 8 - 2)) - (t) 1) * (t) 2 + (t) 1)

struct printbuf {
	char		*pos;
	char		*end;
};

static inline size_t printbuf_remaining(struct printbuf *buf)
{
	return buf->end - buf->pos;
}

#define _PBUF(_buf, _len)						\
	((struct printbuf) {						\
		.pos	= _buf,						\
		.end	= _buf + _len,					\
	})

#define PBUF(_buf) _PBUF(_buf, sizeof(_buf))

#define pr_buf(_out, ...)						\
do {									\
	(_out)->pos += scnprintf((_out)->pos, printbuf_remaining(_out),	\
				 __VA_ARGS__);				\
} while (0)

void bch_scnmemcpy(struct printbuf *, const char *, size_t);

int bch2_strtoint_h(const char *, int *);
int bch2_strtouint_h(const char *, unsigned int *);
int bch2_strtoll_h(const char *, long long *);
int bch2_strtoull_h(const char *, unsigned long long *);
int bch2_strtou64_h(const char *, u64 *);

static inline int bch2_strtol_h(const char *cp, long *res)
{
#if BITS_PER_LONG == 32
	return bch2_strtoint_h(cp, (int *) res);
#else
	return bch2_strtoll_h(cp, (long long *) res);
#endif
}

static inline int bch2_strtoul_h(const char *cp, long *res)
{
#if BITS_PER_LONG == 32
	return bch2_strtouint_h(cp, (unsigned int *) res);
#else
	return bch2_strtoull_h(cp, (unsigned long long *) res);
#endif
}

#define strtoi_h(cp, res)						\
	( type_is(*res, int)		? bch2_strtoint_h(cp, (void *) res)\
	: type_is(*res, long)		? bch2_strtol_h(cp, (void *) res)\
	: type_is(*res, long long)	? bch2_strtoll_h(cp, (void *) res)\
	: type_is(*res, unsigned)	? bch2_strtouint_h(cp, (void *) res)\
	: type_is(*res, unsigned long)	? bch2_strtoul_h(cp, (void *) res)\
	: type_is(*res, unsigned long long) ? bch2_strtoull_h(cp, (void *) res)\
	: -EINVAL)

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
		   type_is(var, int)		? "%i\n"		\
		 : type_is(var, unsigned)	? "%u\n"		\
		 : type_is(var, long)		? "%li\n"		\
		 : type_is(var, unsigned long)	? "%lu\n"		\
		 : type_is(var, s64)		? "%lli\n"		\
		 : type_is(var, u64)		? "%llu\n"		\
		 : type_is(var, char *)		? "%s\n"		\
		 : "%i\n", var)

void bch2_hprint(struct printbuf *, s64);

bool bch2_is_zero(const void *, size_t);

void bch2_string_opt_to_text(struct printbuf *,
			     const char * const [], size_t);

void bch2_flags_to_text(struct printbuf *, const char * const[], u64);
u64 bch2_read_flag_list(char *, const char * const[]);

#define NR_QUANTILES	15
#define QUANTILE_IDX(i)	inorder_to_eytzinger0(i, NR_QUANTILES)
#define QUANTILE_FIRST	eytzinger0_first(NR_QUANTILES)
#define QUANTILE_LAST	eytzinger0_last(NR_QUANTILES)

struct quantiles {
	struct quantile_entry {
		u64	m;
		u64	step;
	}		entries[NR_QUANTILES];
};

struct time_stat_buffer {
	unsigned	nr;
	struct time_stat_buffer_entry {
		u64	start;
		u64	end;
	}		entries[32];
};

struct time_stats {
	spinlock_t	lock;
	u64		count;
	/* all fields are in nanoseconds */
	u64		average_duration;
	u64		average_frequency;
	u64		max_duration;
	u64		last_event;
	struct quantiles quantiles;

	struct time_stat_buffer __percpu *buffer;
};

void __bch2_time_stats_update(struct time_stats *stats, u64, u64);

static inline void bch2_time_stats_update(struct time_stats *stats, u64 start)
{
	__bch2_time_stats_update(stats, start, local_clock());
}

void bch2_time_stats_to_text(struct printbuf *, struct time_stats *);

void bch2_time_stats_exit(struct time_stats *);
void bch2_time_stats_init(struct time_stats *);

#define ewma_add(ewma, val, weight)					\
({									\
	typeof(ewma) _ewma = (ewma);					\
	typeof(weight) _weight = (weight);				\
									\
	(((_ewma << _weight) - _ewma) + (val)) >> _weight;		\
})

struct bch_ratelimit {
	/* Next time we want to do some work, in nanoseconds */
	u64			next;

	/*
	 * Rate at which we want to do work, in units per nanosecond
	 * The units here correspond to the units passed to
	 * bch2_ratelimit_increment()
	 */
	unsigned		rate;
};

static inline void bch2_ratelimit_reset(struct bch_ratelimit *d)
{
	d->next = local_clock();
}

u64 bch2_ratelimit_delay(struct bch_ratelimit *);
void bch2_ratelimit_increment(struct bch_ratelimit *, u64);

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

	/* If true, the rate will not increase if bch2_ratelimit_delay()
	 * is not being called often enough. */
	bool			backpressure;
};

void bch2_pd_controller_update(struct bch_pd_controller *, s64, s64, int);
void bch2_pd_controller_init(struct bch_pd_controller *);
size_t bch2_pd_controller_print_debug(struct bch_pd_controller *, char *);

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
		return bch2_pd_controller_print_debug(var, buf);		\
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

#define container_of_or_null(ptr, type, member)				\
({									\
	typeof(ptr) _ptr = ptr;						\
	_ptr ? container_of(_ptr, type, member) : NULL;			\
})

/* Does linear interpolation between powers of two */
static inline unsigned fract_exp_two(unsigned x, unsigned fract_bits)
{
	unsigned fract = x & ~(~0 << fract_bits);

	x >>= fract_bits;
	x   = 1 << x;
	x  += (x * fract) >> fract_bits;

	return x;
}

void bch2_bio_map(struct bio *bio, void *base, size_t);
int bch2_bio_alloc_pages(struct bio *, size_t, gfp_t);

static inline sector_t bdev_sectors(struct block_device *bdev)
{
	return bdev->bd_inode->i_size >> 9;
}

#define closure_bio_submit(bio, cl)					\
do {									\
	closure_get(cl);						\
	submit_bio(bio);						\
} while (0)

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
		schedule();						\
		try_to_freeze();					\
	}								\
	set_current_state(TASK_RUNNING);				\
	_ret;								\
})

size_t bch2_rand_range(size_t);

void memcpy_to_bio(struct bio *, struct bvec_iter, const void *);
void memcpy_from_bio(void *, struct bio *, struct bvec_iter);

static inline void memcpy_u64s_small(void *dst, const void *src,
				     unsigned u64s)
{
	u64 *d = dst;
	const u64 *s = src;

	while (u64s--)
		*d++ = *s++;
}

static inline void __memcpy_u64s(void *dst, const void *src,
				 unsigned u64s)
{
#ifdef CONFIG_X86_64
	long d0, d1, d2;
	asm volatile("rep ; movsq"
		     : "=&c" (d0), "=&D" (d1), "=&S" (d2)
		     : "0" (u64s), "1" (dst), "2" (src)
		     : "memory");
#else
	u64 *d = dst;
	const u64 *s = src;

	while (u64s--)
		*d++ = *s++;
#endif
}

static inline void memcpy_u64s(void *dst, const void *src,
			       unsigned u64s)
{
	EBUG_ON(!(dst >= src + u64s * sizeof(u64) ||
		 dst + u64s * sizeof(u64) <= src));

	__memcpy_u64s(dst, src, u64s);
}

static inline void __memmove_u64s_down(void *dst, const void *src,
				       unsigned u64s)
{
	__memcpy_u64s(dst, src, u64s);
}

static inline void memmove_u64s_down(void *dst, const void *src,
				     unsigned u64s)
{
	EBUG_ON(dst > src);

	__memmove_u64s_down(dst, src, u64s);
}

static inline void __memmove_u64s_up_small(void *_dst, const void *_src,
					   unsigned u64s)
{
	u64 *dst = (u64 *) _dst + u64s;
	u64 *src = (u64 *) _src + u64s;

	while (u64s--)
		*--dst = *--src;
}

static inline void memmove_u64s_up_small(void *dst, const void *src,
					 unsigned u64s)
{
	EBUG_ON(dst < src);

	__memmove_u64s_up_small(dst, src, u64s);
}

static inline void __memmove_u64s_up(void *_dst, const void *_src,
				     unsigned u64s)
{
	u64 *dst = (u64 *) _dst + u64s - 1;
	u64 *src = (u64 *) _src + u64s - 1;

#ifdef CONFIG_X86_64
	long d0, d1, d2;
	asm volatile("std ;\n"
		     "rep ; movsq\n"
		     "cld ;\n"
		     : "=&c" (d0), "=&D" (d1), "=&S" (d2)
		     : "0" (u64s), "1" (dst), "2" (src)
		     : "memory");
#else
	while (u64s--)
		*dst-- = *src--;
#endif
}

static inline void memmove_u64s_up(void *dst, const void *src,
				   unsigned u64s)
{
	EBUG_ON(dst < src);

	__memmove_u64s_up(dst, src, u64s);
}

static inline void memmove_u64s(void *dst, const void *src,
				unsigned u64s)
{
	if (dst < src)
		__memmove_u64s_down(dst, src, u64s);
	else
		__memmove_u64s_up(dst, src, u64s);
}

/* Set the last few bytes up to a u64 boundary given an offset into a buffer. */
static inline void memset_u64s_tail(void *s, int c, unsigned bytes)
{
	unsigned rem = round_up(bytes, sizeof(u64)) - bytes;

	memset(s + bytes, c, rem);
}

void sort_cmp_size(void *base, size_t num, size_t size,
	  int (*cmp_func)(const void *, const void *, size_t),
	  void (*swap_func)(void *, void *, size_t));

/* just the memmove, doesn't update @_nr */
#define __array_insert_item(_array, _nr, _pos)				\
	memmove(&(_array)[(_pos) + 1],					\
		&(_array)[(_pos)],					\
		sizeof((_array)[0]) * ((_nr) - (_pos)))

#define array_insert_item(_array, _nr, _pos, _new_item)			\
do {									\
	__array_insert_item(_array, _nr, _pos);				\
	(_nr)++;							\
	(_array)[(_pos)] = (_new_item);					\
} while (0)

#define array_remove_items(_array, _nr, _pos, _nr_to_remove)		\
do {									\
	(_nr) -= (_nr_to_remove);					\
	memmove(&(_array)[(_pos)],					\
		&(_array)[(_pos) + (_nr_to_remove)],			\
		sizeof((_array)[0]) * ((_nr) - (_pos)));		\
} while (0)

#define array_remove_item(_array, _nr, _pos)				\
	array_remove_items(_array, _nr, _pos, 1)

#define bubble_sort(_base, _nr, _cmp)					\
do {									\
	ssize_t _i, _end;						\
	bool _swapped = true;						\
									\
	for (_end = (ssize_t) (_nr) - 1; _end > 0 && _swapped; --_end) {\
		_swapped = false;					\
		for (_i = 0; _i < _end; _i++)				\
			if (_cmp((_base)[_i], (_base)[_i + 1]) > 0) {	\
				swap((_base)[_i], (_base)[_i + 1]);	\
				_swapped = true;			\
			}						\
	}								\
} while (0)

static inline u64 percpu_u64_get(u64 __percpu *src)
{
	u64 ret = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		ret += *per_cpu_ptr(src, cpu);
	return ret;
}

static inline void percpu_u64_set(u64 __percpu *dst, u64 src)
{
	int cpu;

	for_each_possible_cpu(cpu)
		*per_cpu_ptr(dst, cpu) = 0;
	this_cpu_write(*dst, src);
}

static inline void acc_u64s(u64 *acc, const u64 *src, unsigned nr)
{
	unsigned i;

	for (i = 0; i < nr; i++)
		acc[i] += src[i];
}

static inline void acc_u64s_percpu(u64 *acc, const u64 __percpu *src,
				   unsigned nr)
{
	int cpu;

	for_each_possible_cpu(cpu)
		acc_u64s(acc, per_cpu_ptr(src, cpu), nr);
}

static inline void percpu_memset(void __percpu *p, int c, size_t bytes)
{
	int cpu;

	for_each_possible_cpu(cpu)
		memset(per_cpu_ptr(p, cpu), c, bytes);
}

u64 *bch2_acc_percpu_u64s(u64 __percpu *, unsigned);

#define cmp_int(l, r)		((l > r) - (l < r))

static inline int u8_cmp(u8 l, u8 r)
{
	return cmp_int(l, r);
}

#endif /* _BCACHEFS_UTIL_H */
