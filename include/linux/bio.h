/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2001 Jens Axboe <axboe@suse.de>
 */
#ifndef __LINUX_BIO_H
#define __LINUX_BIO_H

#include <linux/mempool.h>
/* struct bio, bio_vec and BIO_* flags are defined in blk_types.h */
#include <linux/blk_types.h>
#include <linux/uio.h>

#define BIO_MAX_VECS		256U
#define BIO_MAX_INLINE_VECS	UIO_MAXIOV

struct queue_limits;

static inline unsigned int bio_max_segs(unsigned int nr_segs)
{
	return min(nr_segs, BIO_MAX_VECS);
}

#define bio_iter_iovec(bio, iter)				\
	bvec_iter_bvec((bio)->bi_io_vec, (iter))

#define bio_iter_page(bio, iter)				\
	bvec_iter_page((bio)->bi_io_vec, (iter))
#define bio_iter_len(bio, iter)					\
	bvec_iter_len((bio)->bi_io_vec, (iter))
#define bio_iter_offset(bio, iter)				\
	bvec_iter_offset((bio)->bi_io_vec, (iter))

#define bio_page(bio)		bio_iter_page((bio), (bio)->bi_iter)
#define bio_offset(bio)		bio_iter_offset((bio), (bio)->bi_iter)
#define bio_iovec(bio)		bio_iter_iovec((bio), (bio)->bi_iter)

#define bvec_iter_sectors(iter)	((iter).bi_size >> 9)
#define bvec_iter_end_sector(iter) ((iter).bi_sector + bvec_iter_sectors((iter)))

#define bio_sectors(bio)	bvec_iter_sectors((bio)->bi_iter)
#define bio_end_sector(bio)	bvec_iter_end_sector((bio)->bi_iter)

/*
 * Return the data direction, READ or WRITE.
 */
#define bio_data_dir(bio) \
	(op_is_write(bio_op(bio)) ? WRITE : READ)

/*
 * Check whether this bio carries any data or not. A NULL bio is allowed.
 */
static inline bool bio_has_data(struct bio *bio)
{
	if (bio &&
	    bio->bi_iter.bi_size &&
	    bio_op(bio) != REQ_OP_DISCARD &&
	    bio_op(bio) != REQ_OP_SECURE_ERASE &&
	    bio_op(bio) != REQ_OP_WRITE_ZEROES)
		return true;

	return false;
}

static inline bool bio_no_advance_iter(const struct bio *bio)
{
	return bio_op(bio) == REQ_OP_DISCARD ||
	       bio_op(bio) == REQ_OP_SECURE_ERASE ||
	       bio_op(bio) == REQ_OP_WRITE_ZEROES;
}

static inline void *bio_data(struct bio *bio)
{
	if (bio_has_data(bio))
		return page_address(bio_page(bio)) + bio_offset(bio);

	return NULL;
}

static inline struct bio_vec bio_iter_all_peek(const struct bio *bio,
					       struct bvec_iter_all *iter)
{
	if (WARN_ON(iter->idx >= bio->bi_vcnt))
		return (struct bio_vec) { NULL };

	return bvec_iter_all_peek(bio->bi_io_vec, iter);
}

static inline void bio_iter_all_advance(const struct bio *bio,
					struct bvec_iter_all *iter,
					unsigned bytes)
{
	bvec_iter_all_advance(bio->bi_io_vec, iter, bytes);

	WARN_ON(iter->idx > bio->bi_vcnt ||
		(iter->idx == bio->bi_vcnt && iter->done));
}

#define bio_for_each_segment_all_continue(bvl, bio, iter)		\
	for (;								\
	     iter.idx < bio->bi_vcnt &&					\
		((bvl = bio_iter_all_peek(bio, &iter)), true);		\
	     bio_iter_all_advance((bio), &iter, bvl.bv_len))

/*
 * drivers should _never_ use the all version - the bio may have been split
 * before it got to the driver and the driver won't own all of it
 */
#define bio_for_each_segment_all(bvl, bio, iter)			\
	for (bvec_iter_all_init(&iter);					\
	     iter.idx < (bio)->bi_vcnt &&				\
		((bvl = bio_iter_all_peek((bio), &iter)), true);		\
	     bio_iter_all_advance((bio), &iter, bvl.bv_len))

static inline void bio_advance_iter(const struct bio *bio,
				    struct bvec_iter *iter, unsigned int bytes)
{
	iter->bi_sector += bytes >> 9;

	if (bio_no_advance_iter(bio))
		iter->bi_size -= bytes;
	else
		bvec_iter_advance(bio->bi_io_vec, iter, bytes);
		/* TODO: It is reasonable to complete bio with error here. */
}

/* @bytes should be less or equal to bvec[i->bi_idx].bv_len */
static inline void bio_advance_iter_single(const struct bio *bio,
					   struct bvec_iter *iter,
					   unsigned int bytes)
{
	iter->bi_sector += bytes >> 9;

	if (bio_no_advance_iter(bio))
		iter->bi_size -= bytes;
	else
		bvec_iter_advance_single(bio->bi_io_vec, iter, bytes);
}

void __bio_advance(struct bio *, unsigned bytes);

/**
 * bio_advance - increment/complete a bio by some number of bytes
 * @bio:	bio to advance
 * @nbytes:	number of bytes to complete
 *
 * This updates bi_sector, bi_size and bi_idx; if the number of bytes to
 * complete doesn't align with a bvec boundary, then bv_len and bv_offset will
 * be updated on the last bvec as well.
 *
 * @bio will then represent the remaining, uncompleted portion of the io.
 */
static inline void bio_advance(struct bio *bio, unsigned int nbytes)
{
	if (nbytes == bio->bi_iter.bi_size) {
		bio->bi_iter.bi_size = 0;
		return;
	}
	__bio_advance(bio, nbytes);
}

#define __bio_for_each_segment(bvl, bio, iter, start)			\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = bio_iter_iovec((bio), (iter))), 1);		\
	     bio_advance_iter_single((bio), &(iter), (bvl).bv_len))

#define bio_for_each_segment(bvl, bio, iter)				\
	__bio_for_each_segment(bvl, bio, iter, (bio)->bi_iter)

#define __bio_for_each_bvec(bvl, bio, iter, start)		\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = mp_bvec_iter_bvec((bio)->bi_io_vec, (iter))), 1); \
	     bio_advance_iter_single((bio), &(iter), (bvl).bv_len))

/* iterate over multi-page bvec */
#define bio_for_each_bvec(bvl, bio, iter)			\
	__bio_for_each_bvec(bvl, bio, iter, (bio)->bi_iter)

/*
 * Iterate over all multi-page bvecs. Drivers shouldn't use this version for the
 * same reasons as bio_for_each_segment_all().
 */
#define bio_for_each_bvec_all(bvl, bio, i)		\
	for (i = 0, bvl = bio_first_bvec_all(bio);	\
	     i < (bio)->bi_vcnt; i++, bvl++)

#define bio_iter_last(bvec, iter) ((iter).bi_size == (bvec).bv_len)

static inline unsigned bio_segments(struct bio *bio)
{
	unsigned segs = 0;
	struct bio_vec bv;
	struct bvec_iter iter;

	/*
	 * We special case discard/write same/write zeroes, because they
	 * interpret bi_size differently:
	 */

	switch (bio_op(bio)) {
	case REQ_OP_DISCARD:
	case REQ_OP_SECURE_ERASE:
	case REQ_OP_WRITE_ZEROES:
		return 0;
	default:
		break;
	}

	bio_for_each_segment(bv, bio, iter)
		segs++;

	return segs;
}

/*
 * get a reference to a bio, so it won't disappear. the intended use is
 * something like:
 *
 * bio_get(bio);
 * submit_bio(rw, bio);
 * if (bio->bi_flags ...)
 *	do_something
 * bio_put(bio);
 *
 * without the bio_get(), it could potentially complete I/O before submit_bio
 * returns. and then bio would be freed memory when if (bio->bi_flags ...)
 * runs
 */
static inline void bio_get(struct bio *bio)
{
	bio->bi_flags |= (1 << BIO_REFFED);
	smp_mb__before_atomic();
	atomic_inc(&bio->__bi_cnt);
}

static inline void bio_cnt_set(struct bio *bio, unsigned int count)
{
	if (count != 1) {
		bio->bi_flags |= (1 << BIO_REFFED);
		smp_mb();
	}
	atomic_set(&bio->__bi_cnt, count);
}

static inline bool bio_flagged(struct bio *bio, unsigned int bit)
{
	return bio->bi_flags & (1U << bit);
}

static inline void bio_set_flag(struct bio *bio, unsigned int bit)
{
	bio->bi_flags |= (1U << bit);
}

static inline void bio_clear_flag(struct bio *bio, unsigned int bit)
{
	bio->bi_flags &= ~(1U << bit);
}

static inline struct bio_vec *bio_first_bvec_all(struct bio *bio)
{
	WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED));
	return bio->bi_io_vec;
}

static inline struct page *bio_first_page_all(struct bio *bio)
{
	return bio_first_bvec_all(bio)->bv_page;
}

static inline struct folio *bio_first_folio_all(struct bio *bio)
{
	return page_folio(bio_first_page_all(bio));
}

static inline struct bio_vec *bio_last_bvec_all(struct bio *bio)
{
	WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED));
	return &bio->bi_io_vec[bio->bi_vcnt - 1];
}

/**
 * struct folio_iter - State for iterating all folios in a bio.
 * @folio: The current folio we're iterating.  NULL after the last folio.
 * @offset: The byte offset within the current folio.
 * @length: The number of bytes in this iteration (will not cross folio
 *	boundary).
 */
struct folio_iter {
	struct folio *folio;
	size_t offset;
	size_t length;
	/* private: for use by the iterator */
	struct folio *_next;
	size_t _seg_count;
	int _i;
};

static inline void bio_first_folio(struct folio_iter *fi, struct bio *bio,
				   int i)
{
	struct bio_vec *bvec = bio_first_bvec_all(bio) + i;

	if (unlikely(i >= bio->bi_vcnt)) {
		fi->folio = NULL;
		return;
	}

	fi->folio = page_folio(bvec->bv_page);
	fi->offset = bvec->bv_offset +
			PAGE_SIZE * folio_page_idx(fi->folio, bvec->bv_page);
	fi->_seg_count = bvec->bv_len;
	fi->length = min(folio_size(fi->folio) - fi->offset, fi->_seg_count);
	fi->_next = folio_next(fi->folio);
	fi->_i = i;
}

static inline void bio_next_folio(struct folio_iter *fi, struct bio *bio)
{
	fi->_seg_count -= fi->length;
	if (fi->_seg_count) {
		fi->folio = fi->_next;
		fi->offset = 0;
		fi->length = min(folio_size(fi->folio), fi->_seg_count);
		fi->_next = folio_next(fi->folio);
	} else {
		bio_first_folio(fi, bio, fi->_i + 1);
	}
}

/**
 * bio_for_each_folio_all - Iterate over each folio in a bio.
 * @fi: struct folio_iter which is updated for each folio.
 * @bio: struct bio to iterate over.
 */
#define bio_for_each_folio_all(fi, bio)				\
	for (bio_first_folio(&fi, bio, 0); fi.folio; bio_next_folio(&fi, bio))

void bio_trim(struct bio *bio, sector_t offset, sector_t size);
extern struct bio *bio_split(struct bio *bio, int sectors,
			     gfp_t gfp, struct bio_set *bs);
int bio_split_rw_at(struct bio *bio, const struct queue_limits *lim,
		unsigned *segs, unsigned max_bytes);

/**
 * bio_next_split - get next @sectors from a bio, splitting if necessary
 * @bio:	bio to split
 * @sectors:	number of sectors to split from the front of @bio
 * @gfp:	gfp mask
 * @bs:		bio set to allocate from
 *
 * Return: a bio representing the next @sectors of @bio - if the bio is smaller
 * than @sectors, returns the original bio unchanged.
 */
static inline struct bio *bio_next_split(struct bio *bio, int sectors,
					 gfp_t gfp, struct bio_set *bs)
{
	if (sectors >= bio_sectors(bio))
		return bio;

	return bio_split(bio, sectors, gfp, bs);
}

enum {
	BIOSET_NEED_BVECS = BIT(0),
	BIOSET_NEED_RESCUER = BIT(1),
	BIOSET_PERCPU_CACHE = BIT(2),
};
extern int bioset_init(struct bio_set *, unsigned int, unsigned int, int flags);
extern void bioset_exit(struct bio_set *);
extern int biovec_init_pool(mempool_t *pool, int pool_entries);

struct bio *bio_alloc_bioset(struct block_device *bdev, unsigned short nr_vecs,
			     blk_opf_t opf, gfp_t gfp_mask,
			     struct bio_set *bs);
struct bio *bio_kmalloc(unsigned short nr_vecs, gfp_t gfp_mask);
extern void bio_put(struct bio *);

struct bio *bio_alloc_clone(struct block_device *bdev, struct bio *bio_src,
		gfp_t gfp, struct bio_set *bs);
int bio_init_clone(struct block_device *bdev, struct bio *bio,
		struct bio *bio_src, gfp_t gfp);

extern struct bio_set fs_bio_set;

static inline struct bio *bio_alloc(struct block_device *bdev,
		unsigned short nr_vecs, blk_opf_t opf, gfp_t gfp_mask)
{
	return bio_alloc_bioset(bdev, nr_vecs, opf, gfp_mask, &fs_bio_set);
}

void submit_bio(struct bio *bio);

extern void bio_endio(struct bio *);

static inline void bio_io_error(struct bio *bio)
{
	bio->bi_status = BLK_STS_IOERR;
	bio_endio(bio);
}

static inline void bio_wouldblock_error(struct bio *bio)
{
	bio_set_flag(bio, BIO_QUIET);
	bio->bi_status = BLK_STS_AGAIN;
	bio_endio(bio);
}

/*
 * Calculate number of bvec segments that should be allocated to fit data
 * pointed by @iter. If @iter is backed by bvec it's going to be reused
 * instead of allocating a new one.
 */
static inline int bio_iov_vecs_to_alloc(struct iov_iter *iter, int max_segs)
{
	if (iov_iter_is_bvec(iter))
		return 0;
	return iov_iter_npages(iter, max_segs);
}

struct request_queue;

void bio_init(struct bio *bio, struct block_device *bdev, struct bio_vec *table,
	      unsigned short max_vecs, blk_opf_t opf);
extern void bio_uninit(struct bio *);
void bio_reset(struct bio *bio, struct block_device *bdev, blk_opf_t opf);
void bio_chain(struct bio *, struct bio *);

int __must_check bio_add_page(struct bio *bio, struct page *page, unsigned len,
			      unsigned off);
bool __must_check bio_add_folio(struct bio *bio, struct folio *folio,
				size_t len, size_t off);
void __bio_add_page(struct bio *bio, struct page *page,
		unsigned int len, unsigned int off);
void bio_add_folio_nofail(struct bio *bio, struct folio *folio, size_t len,
			  size_t off);
void bio_add_virt_nofail(struct bio *bio, void *vaddr, unsigned len);

/**
 * bio_add_max_vecs - number of bio_vecs needed to add data to a bio
 * @kaddr: kernel virtual address to add
 * @len: length in bytes to add
 *
 * Calculate how many bio_vecs need to be allocated to add the kernel virtual
 * address range in [@kaddr:@len] in the worse case.
 */
static inline unsigned int bio_add_max_vecs(void *kaddr, unsigned int len)
{
	if (is_vmalloc_addr(kaddr))
		return DIV_ROUND_UP(offset_in_page(kaddr) + len, PAGE_SIZE);
	return 1;
}

unsigned int bio_add_vmalloc_chunk(struct bio *bio, void *vaddr, unsigned len);
bool bio_add_vmalloc(struct bio *bio, void *vaddr, unsigned int len);

int submit_bio_wait(struct bio *bio);
int bdev_rw_virt(struct block_device *bdev, sector_t sector, void *data,
		size_t len, enum req_op op);

int bio_iov_iter_get_pages(struct bio *bio, struct iov_iter *iter);
void bio_iov_bvec_set(struct bio *bio, const struct iov_iter *iter);
void __bio_release_pages(struct bio *bio, bool mark_dirty);
extern void bio_set_pages_dirty(struct bio *bio);
extern void bio_check_pages_dirty(struct bio *bio);

extern void bio_copy_data_iter(struct bio *dst, struct bvec_iter *dst_iter,
			       struct bio *src, struct bvec_iter *src_iter);
extern void bio_copy_data(struct bio *dst, struct bio *src);
extern void bio_free_pages(struct bio *bio);
void guard_bio_eod(struct bio *bio);
void zero_fill_bio_iter(struct bio *bio, struct bvec_iter iter);

static inline void zero_fill_bio(struct bio *bio)
{
	zero_fill_bio_iter(bio, bio->bi_iter);
}

static inline void bio_release_pages(struct bio *bio, bool mark_dirty)
{
	if (bio_flagged(bio, BIO_PAGE_PINNED))
		__bio_release_pages(bio, mark_dirty);
}

#define bio_dev(bio) \
	disk_devt((bio)->bi_bdev->bd_disk)

#ifdef CONFIG_BLK_CGROUP
void bio_associate_blkg(struct bio *bio);
void bio_associate_blkg_from_css(struct bio *bio,
				 struct cgroup_subsys_state *css);
void bio_clone_blkg_association(struct bio *dst, struct bio *src);
void blkcg_punt_bio_submit(struct bio *bio);
#else	/* CONFIG_BLK_CGROUP */
static inline void bio_associate_blkg(struct bio *bio) { }
static inline void bio_associate_blkg_from_css(struct bio *bio,
					       struct cgroup_subsys_state *css)
{ }
static inline void bio_clone_blkg_association(struct bio *dst,
					      struct bio *src) { }
static inline void blkcg_punt_bio_submit(struct bio *bio)
{
	submit_bio(bio);
}
#endif	/* CONFIG_BLK_CGROUP */

static inline void bio_set_dev(struct bio *bio, struct block_device *bdev)
{
	bio_clear_flag(bio, BIO_REMAPPED);
	if (bio->bi_bdev != bdev)
		bio_clear_flag(bio, BIO_BPS_THROTTLED);
	bio->bi_bdev = bdev;
	bio_associate_blkg(bio);
}

/*
 * BIO list management for use by remapping drivers (e.g. DM or MD) and loop.
 *
 * A bio_list anchors a singly-linked list of bios chained through the bi_next
 * member of the bio.  The bio_list also caches the last list member to allow
 * fast access to the tail.
 */
struct bio_list {
	struct bio *head;
	struct bio *tail;
};

static inline int bio_list_empty(const struct bio_list *bl)
{
	return bl->head == NULL;
}

static inline void bio_list_init(struct bio_list *bl)
{
	bl->head = bl->tail = NULL;
}

#define BIO_EMPTY_LIST	{ NULL, NULL }

#define bio_list_for_each(bio, bl) \
	for (bio = (bl)->head; bio; bio = bio->bi_next)

static inline unsigned bio_list_size(const struct bio_list *bl)
{
	unsigned sz = 0;
	struct bio *bio;

	bio_list_for_each(bio, bl)
		sz++;

	return sz;
}

static inline void bio_list_add(struct bio_list *bl, struct bio *bio)
{
	bio->bi_next = NULL;

	if (bl->tail)
		bl->tail->bi_next = bio;
	else
		bl->head = bio;

	bl->tail = bio;
}

static inline void bio_list_add_head(struct bio_list *bl, struct bio *bio)
{
	bio->bi_next = bl->head;

	bl->head = bio;

	if (!bl->tail)
		bl->tail = bio;
}

static inline void bio_list_merge(struct bio_list *bl, struct bio_list *bl2)
{
	if (!bl2->head)
		return;

	if (bl->tail)
		bl->tail->bi_next = bl2->head;
	else
		bl->head = bl2->head;

	bl->tail = bl2->tail;
}

static inline void bio_list_merge_init(struct bio_list *bl,
		struct bio_list *bl2)
{
	bio_list_merge(bl, bl2);
	bio_list_init(bl2);
}

static inline void bio_list_merge_head(struct bio_list *bl,
				       struct bio_list *bl2)
{
	if (!bl2->head)
		return;

	if (bl->head)
		bl2->tail->bi_next = bl->head;
	else
		bl->tail = bl2->tail;

	bl->head = bl2->head;
}

static inline struct bio *bio_list_peek(struct bio_list *bl)
{
	return bl->head;
}

static inline struct bio *bio_list_pop(struct bio_list *bl)
{
	struct bio *bio = bl->head;

	if (bio) {
		bl->head = bl->head->bi_next;
		if (!bl->head)
			bl->tail = NULL;

		bio->bi_next = NULL;
	}

	return bio;
}

static inline struct bio *bio_list_get(struct bio_list *bl)
{
	struct bio *bio = bl->head;

	bl->head = bl->tail = NULL;

	return bio;
}

/*
 * Increment chain count for the bio. Make sure the CHAIN flag update
 * is visible before the raised count.
 */
static inline void bio_inc_remaining(struct bio *bio)
{
	bio_set_flag(bio, BIO_CHAIN);
	smp_mb__before_atomic();
	atomic_inc(&bio->__bi_remaining);
}

/*
 * bio_set is used to allow other portions of the IO system to
 * allocate their own private memory pools for bio and iovec structures.
 * These memory pools in turn all allocate from the bio_slab
 * and the bvec_slabs[].
 */
#define BIO_POOL_SIZE 2

struct bio_set {
	struct kmem_cache *bio_slab;
	unsigned int front_pad;

	/*
	 * per-cpu bio alloc cache
	 */
	struct bio_alloc_cache __percpu *cache;

	mempool_t bio_pool;
	mempool_t bvec_pool;

	unsigned int back_pad;
	/*
	 * Deadlock avoidance for stacking block drivers: see comments in
	 * bio_alloc_bioset() for details
	 */
	spinlock_t		rescue_lock;
	struct bio_list		rescue_list;
	struct work_struct	rescue_work;
	struct workqueue_struct	*rescue_workqueue;

	/*
	 * Hot un-plug notifier for the per-cpu cache, if used
	 */
	struct hlist_node cpuhp_dead;
};

static inline bool bioset_initialized(struct bio_set *bs)
{
	return bs->bio_slab != NULL;
}

/*
 * Mark a bio as polled. Note that for async polled IO, the caller must
 * expect -EWOULDBLOCK if we cannot allocate a request (or other resources).
 * We cannot block waiting for requests on polled IO, as those completions
 * must be found by the caller. This is different than IRQ driven IO, where
 * it's safe to wait for IO to complete.
 */
static inline void bio_set_polled(struct bio *bio, struct kiocb *kiocb)
{
	bio->bi_opf |= REQ_POLLED;
	if (kiocb->ki_flags & IOCB_NOWAIT)
		bio->bi_opf |= REQ_NOWAIT;
}

static inline void bio_clear_polled(struct bio *bio)
{
	bio->bi_opf &= ~REQ_POLLED;
}

/**
 * bio_is_zone_append - is this a zone append bio?
 * @bio:	bio to check
 *
 * Check if @bio is a zone append operation.  Core block layer code and end_io
 * handlers must use this instead of an open coded REQ_OP_ZONE_APPEND check
 * because the block layer can rewrite REQ_OP_ZONE_APPEND to REQ_OP_WRITE if
 * it is not natively supported.
 */
static inline bool bio_is_zone_append(struct bio *bio)
{
	if (!IS_ENABLED(CONFIG_BLK_DEV_ZONED))
		return false;
	return bio_op(bio) == REQ_OP_ZONE_APPEND ||
		bio_flagged(bio, BIO_EMULATES_ZONE_APPEND);
}

struct bio *blk_next_bio(struct bio *bio, struct block_device *bdev,
		unsigned int nr_pages, blk_opf_t opf, gfp_t gfp);
struct bio *bio_chain_and_submit(struct bio *prev, struct bio *new);

struct bio *blk_alloc_discard_bio(struct block_device *bdev,
		sector_t *sector, sector_t *nr_sects, gfp_t gfp_mask);

#endif /* __LINUX_BIO_H */
