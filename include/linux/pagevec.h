/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/pagevec.h
 *
 * In many places it is efficient to batch an operation up against multiple
 * pages.  A pagevec is a multipage container which is used for that.
 */

#ifndef _LINUX_PAGEVEC_H
#define _LINUX_PAGEVEC_H

/* 14 pointers + two long's align the pagevec structure to a power of two */
#define PAGEVEC_SIZE	14

struct page;
struct address_space;

struct pagevec {
	unsigned long nr;
	bool percpu_pvec_drained;
	struct page *pages[PAGEVEC_SIZE];
};

void __pagevec_release(struct pagevec *pvec);
void __pagevec_lru_add(struct pagevec *pvec);
unsigned pagevec_lookup_entries(struct pagevec *pvec,
				struct address_space *mapping,
				pgoff_t start, unsigned nr_entries,
				pgoff_t *indices);
void pagevec_remove_exceptionals(struct pagevec *pvec);
unsigned pagevec_lookup_range(struct pagevec *pvec,
			      struct address_space *mapping,
			      pgoff_t *start, pgoff_t end);
static inline unsigned pagevec_lookup(struct pagevec *pvec,
				      struct address_space *mapping,
				      pgoff_t *start)
{
	return pagevec_lookup_range(pvec, mapping, start, (pgoff_t)-1);
}

unsigned pagevec_lookup_range_tag(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *index, pgoff_t end,
		int tag);
unsigned pagevec_lookup_range_nr_tag(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *index, pgoff_t end,
		int tag, unsigned max_pages);
static inline unsigned pagevec_lookup_tag(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *index, int tag)
{
	return pagevec_lookup_range_tag(pvec, mapping, index, (pgoff_t)-1, tag);
}

static inline void pagevec_init(struct pagevec *pvec)
{
	pvec->nr = 0;
	pvec->percpu_pvec_drained = false;
}

static inline void pagevec_reinit(struct pagevec *pvec)
{
	pvec->nr = 0;
}

static inline unsigned pagevec_count(struct pagevec *pvec)
{
	return pvec->nr;
}

static inline unsigned pagevec_space(struct pagevec *pvec)
{
	return PAGEVEC_SIZE - pvec->nr;
}

/*
 * Add a page to a pagevec.  Returns the number of slots still available.
 */
static inline unsigned pagevec_add(struct pagevec *pvec, struct page *page)
{
	pvec->pages[pvec->nr++] = page;
	return pagevec_space(pvec);
}

static inline void pagevec_release(struct pagevec *pvec)
{
	if (pagevec_count(pvec))
		__pagevec_release(pvec);
}

struct pagecache_iter {
	unsigned	nr;
	unsigned	idx;
	pgoff_t		index;
	struct page	*pages[PAGEVEC_SIZE];
	pgoff_t		indices[PAGEVEC_SIZE];
};

static inline void pagecache_iter_init(struct pagecache_iter *iter,
				       pgoff_t start)
{
	iter->nr	= 0;
	iter->idx	= 0;
	iter->index	= start;
}

void __pagecache_iter_release(struct pagecache_iter *iter);

/**
 * pagecache_iter_release - release cached pages from pagacache_iter
 *
 * Must be called if breaking out of for_each_pagecache_page() etc. early - not
 * needed if pagecache_iter_next() returned NULL and loop terminated normally
 */
static inline void pagecache_iter_release(struct pagecache_iter *iter)
{
	if (iter->nr)
		__pagecache_iter_release(iter);
}

struct page *pagecache_iter_next(struct pagecache_iter *iter,
				 struct address_space *mapping,
				 pgoff_t end, pgoff_t *index,
				 unsigned flags);

#define __pagecache_iter_for_each(_iter, _mapping, _start, _end,	\
				  _page, _index, _flags)		\
	for (pagecache_iter_init((_iter), (_start));			\
	     ((_page) = pagecache_iter_next((_iter), (_mapping),	\
			(_end), (_index), (_flags)));)

#define for_each_pagecache_page(_iter, _mapping, _start, _end, _page)	\
	__pagecache_iter_for_each((_iter), (_mapping), (_start), (_end),\
			(_page), NULL, 0)

#define for_each_pagecache_page_contig(_iter, _mapping, _start, _end, _page)\
	__pagecache_iter_for_each((_iter), (_mapping), (_start), (_end),\
			(_page), NULL, RADIX_TREE_ITER_CONTIG)

#define for_each_pagecache_tag(_iter, _mapping, _tag, _start, _end, _page)\
	__pagecache_iter_for_each((_iter), (_mapping), (_start), (_end),\
			(_page), NULL, RADIX_TREE_ITER_TAGGED|(_tag))

#define for_each_pagecache_entry(_iter, _mapping, _start, _end, _page, _index)\
	__pagecache_iter_for_each((_iter), (_mapping), (_start), (_end),\
			(_page), &(_index), RADIX_TREE_ITER_EXCEPTIONAL)

#define for_each_pagecache_entry_tag(_iter, _mapping, _tag,		\
				     _start, _end, _page, _index)	\
	__pagecache_iter_for_each((_iter), (_mapping), (_start), (_end),\
			(_page), &(_index), RADIX_TREE_ITER_EXCEPTIONAL|\
			RADIX_TREE_ITER_TAGGED|(_tag))

#endif /* _LINUX_PAGEVEC_H */
