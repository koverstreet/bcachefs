/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_FOLIO_H
#define _BCACHEFS_FOLIO_H

struct folio {
	union {
		struct page page;
	struct {

	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	/*
	 * Five words (20/40 bytes) are available in this union.
	 * WARNING: bit 0 of the first word is used for PageTail(). That
	 * means the other users of this union MUST NOT use the bit to
	 * avoid collision and false-positive PageTail().
	 */
	union {
		struct {	/* Page cache and anonymous pages */
			/**
			 * @lru: Pageout list, eg. active_list protected by
			 * zone_lru_lock.  Sometimes used as a generic list
			 * by the page owner.
			 */
			struct list_head lru;
			/* See page-flags.h for PAGE_MAPPING_FLAGS */
			struct address_space *mapping;
			pgoff_t index;		/* Our offset within mapping. */
			/**
			 * @private: Mapping-private opaque data.
			 * Usually used for buffer_heads if PagePrivate.
			 * Used for swp_entry_t if PageSwapCache.
			 * Indicates order in the buddy system if PageBuddy.
			 */
			void *private;
		};
		struct {	/* Tail pages of compound page */
			unsigned long compound_head;	/* Bit zero is set */

			/* First tail page only */
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
		};
		struct {	/* Second tail page of compound page */
			unsigned long _compound_pad_1;	/* compound_head */
			unsigned long _compound_pad_2;
			struct list_head deferred_list;
		};

		/** @rcu_head: You can use this to free a page by RCU. */
		struct rcu_head rcu_head;
	};

	union {		/* This union is 4 bytes in size. */
		/*
		 * If the page can be mapped to userspace, encodes the number
		 * of times this page is referenced by a page table.
		 */
		atomic_t _mapcount;

		/*
		 * If the page is neither PageSlab nor mappable to userspace,
		 * the value stored here may help determine what this page
		 * is used for.  See page-flags.h for a list of page types
		 * which are currently stored here.
		 */
		unsigned int page_type;

		unsigned int active;		/* SLAB */
		int units;			/* SLOB */
	};

	/* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
	atomic_t _refcount;

#ifdef CONFIG_MEMCG
	struct mem_cgroup *mem_cgroup;
#endif

	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */

#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
	int _last_cpupid;
#endif
	};
	};
} _struct_page_alignment;

static inline struct folio *page_folio(struct page *page)
{
	return (void *) page;
}

static inline bool folio_test_locked(struct folio *folio)
{
	return PageLocked(&folio->page);
}

static inline void folio_lock(struct folio *folio)
{
	return lock_page(&folio->page);
}

static inline bool folio_trylock(struct folio *folio)
{
	return trylock_page(&folio->page);
}

static inline void folio_unlock(struct folio *folio)
{
	return unlock_page(&folio->page);
}

static inline bool folio_test_uptodate(struct folio *folio)
{
	return PageUptodate(&folio->page);
}

static inline void folio_mark_uptodate(struct folio *folio)
{
	SetPageUptodate(&folio->page);
}

static inline void folio_clear_uptodate(struct folio *folio)
{
	ClearPageUptodate(&folio->page);
}

static inline bool folio_test_dirty(struct folio *folio)
{
	return PageDirty(&folio->page);
}

static inline bool folio_test_writeback(struct folio *folio)
{
	return PageWriteback(&folio->page);
}

static inline void folio_set_error(struct folio *folio)
{
	SetPageError(&folio->page);
}

static inline void folio_set_private(struct folio *folio)
{
	SetPagePrivate(&folio->page);
}

static inline void folio_clear_private(struct folio *folio)
{
	ClearPagePrivate(&folio->page);
}

static inline bool folio_test_private(struct folio *folio)
{
	return PagePrivate(&folio->page);
}

static inline bool folio_has_private(struct folio *folio)
{
	return page_has_private(&folio->page);
}

static inline void folio_get(struct folio *folio)
{
	get_page(&folio->page);
}

static inline void folio_put(struct folio *folio)
{
	put_page(&folio->page);
}

static inline unsigned folio_order(struct folio *folio)
{
	return compound_order(&folio->page);
}

static inline long folio_nr_pages(struct folio *folio)
{
	return 1UL << folio_order(folio);
}

#define folio_page(folio, n)	nth_page(&(folio)->page, n)

static inline struct folio *folio_next(struct folio *folio)
{
	return (struct folio *)folio_page(folio, folio_nr_pages(folio));
}

static inline size_t folio_size(struct folio *folio)
{
	return PAGE_SIZE << folio_order(folio);
}

static inline loff_t folio_pos(struct folio *folio)
{
	return page_offset(&folio->page);
}

static inline void *folio_get_private(struct folio *folio)
{
	return folio->private;
}

static inline void folio_attach_private(struct folio *folio, void *data)
{
	folio_get(folio);
	folio->private = data;
	folio_set_private(folio);
}

static inline void *folio_detach_private(struct folio *folio)
{
	void *data = folio_get_private(folio);

	if (!folio_test_private(folio))
		return NULL;
	folio_clear_private(folio);
	folio->private = NULL;
	folio_put(folio);

	return data;
}

static inline void folio_zero_segments(struct folio *folio,
		size_t start1, size_t xend1, size_t start2, size_t xend2)
{
	zero_user_segments(&folio->page, start1, xend1, start2, xend2);
}

static inline void folio_zero_segment(struct folio *folio,
		size_t start, size_t xend)
{
	zero_user_segments(&folio->page, start, xend, 0, 0);
}

static inline void folio_zero_range(struct folio *folio,
		size_t start, size_t length)
{
	zero_user_segments(&folio->page, start, start + length, 0, 0);
}

static inline unsigned folio_page_idx(struct folio *folio, struct page *page)
{
	return 0;
}

static inline void folio_wait_stable(struct folio *folio)
{
	wait_for_stable_page(&folio->page);
}

static inline void mapping_set_large_folios(struct address_space *mapping) {}

static inline void filemap_dirty_folio(struct address_space *mapping, struct folio *folio)
{
	__set_page_dirty_nobuffers(&folio->page);
}

static inline struct folio *__filemap_get_folio(struct address_space *mapping, pgoff_t index,
						int fgp, gfp_t gfp)
{

	return page_folio(pagecache_get_page(mapping, index, fgp, gfp));
}

static inline struct folio *filemap_lock_folio(struct address_space *mapping, pgoff_t index)
{

	return page_folio(find_lock_page(mapping, index));
}

#include <linux/pagevec.h>

struct folio_batch {
	unsigned char nr;
	bool percpu_pvec_drained;
	struct folio *folios[PAGEVEC_SIZE];
};

static inline void folio_batch_init(struct folio_batch *fbatch)
{
	fbatch->nr = 0;
	fbatch->percpu_pvec_drained = false;
}

static inline void folio_batch_reinit(struct folio_batch *fbatch)
{
	fbatch->nr = 0;
}

static inline unsigned int folio_batch_count(struct folio_batch *fbatch)
{
	return fbatch->nr;
}

static inline unsigned int fbatch_space(struct folio_batch *fbatch)
{
	return PAGEVEC_SIZE - fbatch->nr;
}

/**
 * folio_batch_add() - Add a folio to a batch.
 * @fbatch: The folio batch.
 * @folio: The folio to add.
 *
 * The folio is added to the end of the batch.
 * The batch must have previously been initialised using folio_batch_init().
 *
 * Return: The number of slots still available.
 */
static inline unsigned folio_batch_add(struct folio_batch *fbatch,
		struct folio *folio)
{
	fbatch->folios[fbatch->nr++] = folio;
	return fbatch_space(fbatch);
}

static inline void folio_batch_release(struct folio_batch *fbatch)
{
	pagevec_release((struct pagevec *)fbatch);
}

static inline unsigned filemap_get_folios(struct address_space *mapping, pgoff_t *start,
					  pgoff_t end, struct folio_batch *fbatch)
{
	BUG_ON(fbatch->nr);

	fbatch->nr = find_get_pages_range(mapping, start, end,
			PAGEVEC_SIZE, (void *) &fbatch->folios[0]);

	return folio_batch_count(fbatch);
}

static inline struct folio *filemap_alloc_folio(gfp_t gfp, unsigned order)
{
	return page_folio(__page_cache_alloc(gfp));
}

static inline int filemap_add_folio(struct address_space *mapping, struct folio *folio,
				    pgoff_t offset, gfp_t gfp)
{
	return add_to_page_cache_lru(&folio->page, mapping, offset, gfp);
}

#include <linux/rmap.h>

static inline void folio_mkclean(struct folio *folio)
{
	page_mkclean(&folio->page);
}

#include <linux/uio.h>

static inline unsigned copy_page_from_iter_atomic(struct page *page,
				unsigned offset, unsigned len, struct iov_iter *iter)
{
	return iov_iter_copy_from_user_atomic(page, iter, offset, len);
}

static inline void folio_end_writeback(struct folio *folio)
{
	end_page_writeback(&folio->page);
}

static inline void flush_dcache_folio(struct folio *folio)
{
	flush_dcache_page(&folio->page);
}

static inline void folio_start_writeback(struct folio *folio)
{
	set_page_writeback(&folio->page);
}

#include <linux/bio.h>

static inline bool bio_add_folio(struct bio *bio, struct folio *folio, size_t len, size_t offset)
{
	return bio_add_page(bio, &folio->page, len, offset);
}

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

	fi->folio = page_folio(bvec->bv_page);
	fi->offset = bvec->bv_offset +
			PAGE_SIZE * (bvec->bv_page - &fi->folio->page);
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
	} else if (fi->_i + 1 < bio->bi_vcnt) {
		bio_first_folio(fi, bio, fi->_i + 1);
	} else {
		fi->folio = NULL;
	}
}

/**
 * bio_for_each_folio_all - Iterate over each folio in a bio.
 * @fi: struct folio_iter which is updated for each folio.
 * @bio: struct bio to iterate over.
 */
#define bio_for_each_folio_all(fi, bio)				\
	for (bio_first_folio(&fi, bio, 0); fi.folio; bio_next_folio(&fi, bio))

#define FGP_STABLE	0

#endif /* _BCACHEFS_FOLIO_H */
