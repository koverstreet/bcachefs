/* SPDX-License-Identifier: GPL-2.0 */
/*
 * memory buffer pool support
 */
#ifndef _LINUX_MEMPOOL_H
#define _LINUX_MEMPOOL_H

#include <linux/sched.h>
#include <linux/alloc_tag.h>
#include <linux/wait.h>
#include <linux/compiler.h>

struct kmem_cache;

typedef void * (mempool_alloc_t)(gfp_t gfp_mask, void *pool_data);
typedef void (mempool_free_t)(void *element, void *pool_data);

typedef struct mempool_s {
	spinlock_t lock;
	int min_nr;		/* nr of elements at *elements */
	int curr_nr;		/* Current nr of elements at *elements */
	void **elements;

	void *pool_data;
	mempool_alloc_t *alloc;
	mempool_free_t *free;
	wait_queue_head_t wait;
} mempool_t;

static inline bool mempool_initialized(mempool_t *pool)
{
	return pool->elements != NULL;
}

static inline bool mempool_is_saturated(mempool_t *pool)
{
	return READ_ONCE(pool->curr_nr) >= pool->min_nr;
}

void mempool_exit(mempool_t *pool);
int mempool_init_node(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
		      mempool_free_t *free_fn, void *pool_data,
		      gfp_t gfp_mask, int node_id);

int _mempool_init(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
		 mempool_free_t *free_fn, void *pool_data);
#define mempool_init(...)			\
	alloc_hooks(_mempool_init(__VA_ARGS__), int, -ENOMEM)

extern mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data);

extern mempool_t *_mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data,
			gfp_t gfp_mask, int nid);
#define mempool_create_node(...)			\
	alloc_hooks(_mempool_create_node(__VA_ARGS__), mempool_t *, NULL)

#define mempool_create(_min_nr, _alloc_fn, _free_fn, _pool_data)	\
	mempool_create_node(_min_nr, _alloc_fn, _free_fn, _pool_data,	\
			    GFP_KERNEL, NUMA_NO_NODE)

extern int mempool_resize(mempool_t *pool, int new_min_nr);
extern void mempool_destroy(mempool_t *pool);

extern void *_mempool_alloc(mempool_t *pool, gfp_t gfp_mask) __malloc;
#define mempool_alloc(_pool, _gfp)			\
	alloc_hooks(_mempool_alloc((_pool), (_gfp)), void *, NULL)

extern void mempool_free(void *element, mempool_t *pool);

/*
 * A mempool_alloc_t and mempool_free_t that get the memory from
 * a slab cache that is passed in through pool_data.
 * Note: the slab cache may not have a ctor function.
 */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data);
void mempool_free_slab(void *element, void *pool_data);

#define mempool_init_slab_pool(_pool, _min_nr, _kc)			\
	mempool_init(_pool, (_min_nr), mempool_alloc_slab, mempool_free_slab, (void *)(_kc))
#define mempool_create_slab_pool(_min_nr, _kc)			\
	mempool_create((_min_nr), mempool_alloc_slab, mempool_free_slab, (void *)(_kc))

/*
 * a mempool_alloc_t and a mempool_free_t to kmalloc and kfree the
 * amount of memory specified by pool_data
 */
void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data);
void mempool_kfree(void *element, void *pool_data);

#define mempool_init_kmalloc_pool(_pool, _min_nr, _size)			\
	mempool_init(_pool, (_min_nr), mempool_kmalloc, mempool_kfree, (void *)(unsigned long)(_size))
#define mempool_create_kmalloc_pool(_min_nr, _size)			\
	mempool_create((_min_nr), mempool_kmalloc, mempool_kfree, (void *)(unsigned long)(_size))

/*
 * A mempool_alloc_t and mempool_free_t for a simple page allocator that
 * allocates pages of the order specified by pool_data
 */
void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data);
void mempool_free_pages(void *element, void *pool_data);

#define mempool_init_page_pool(_pool, _min_nr, _order)			\
	mempool_init(_pool, (_min_nr), mempool_alloc_pages, mempool_free_pages, (void *)(long)(_order))
#define mempool_create_page_pool(_min_nr, _order)			\
	mempool_create((_min_nr), mempool_alloc_pages, mempool_free_pages, (void *)(long)(_order))

#endif /* _LINUX_MEMPOOL_H */
