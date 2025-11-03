// SPDX-License-Identifier: GPL-2.0
#ifndef NO_BCACHEFS_FS

#include <linux/blkdev.h>
#include <linux/uio.h>

#include "vendor/bio_iov_iter.h"

static inline bool bio_full(struct bio *bio, unsigned len)
{
	if (bio->bi_vcnt >= bio->bi_max_vecs)
		return true;
	if (bio->bi_iter.bi_size > UINT_MAX - len)
		return true;
	return false;
}

static inline void bio_release_page(struct bio *bio, struct page *page)
{
	if (bio_flagged(bio, BIO_PAGE_PINNED))
		unpin_user_page(page);
}

#define PAGE_PTRS_PER_BVEC     (sizeof(struct bio_vec) / sizeof(struct page *))

static unsigned int get_contig_folio_len(unsigned int *num_pages,
					 struct page **pages, unsigned int i,
					 struct folio *folio, size_t left,
					 size_t offset)
{
	size_t bytes = left;
	size_t contig_sz = min_t(size_t, PAGE_SIZE - offset, bytes);
	unsigned int j;

	/*
	 * We might COW a single page in the middle of
	 * a large folio, so we have to check that all
	 * pages belong to the same folio.
	 */
	bytes -= contig_sz;
	for (j = i + 1; j < i + *num_pages; j++) {
		size_t next = min_t(size_t, PAGE_SIZE, bytes);

		if (page_folio(pages[j]) != folio ||
		    pages[j] != pages[j - 1] + 1) {
			break;
		}
		contig_sz += next;
		bytes -= next;
	}
	*num_pages = j - i;

	return contig_sz;
}

static int __bio_iov_iter_get_pages(struct bio *bio, struct iov_iter *iter)
{
	iov_iter_extraction_t extraction_flags = 0;
	unsigned short nr_pages = bio->bi_max_vecs - bio->bi_vcnt;
	unsigned short entries_left = bio->bi_max_vecs - bio->bi_vcnt;
	struct bio_vec *bv = bio->bi_io_vec + bio->bi_vcnt;
	struct page **pages = (struct page **)bv;
	ssize_t size;
	unsigned int num_pages, i = 0;
	size_t offset, folio_offset, left, len;
	int ret = 0;

	/*
	 * Move page array up in the allocated memory for the bio vecs as far as
	 * possible so that we can start filling biovecs from the beginning
	 * without overwriting the temporary page array.
	 */
	BUILD_BUG_ON(PAGE_PTRS_PER_BVEC < 2);
	pages += entries_left * (PAGE_PTRS_PER_BVEC - 1);

	if (bio->bi_bdev && blk_queue_pci_p2pdma(bio->bi_bdev->bd_disk->queue))
		extraction_flags |= ITER_ALLOW_P2PDMA;

	size = iov_iter_extract_pages(iter, &pages,
				      UINT_MAX - bio->bi_iter.bi_size,
				      nr_pages, extraction_flags, &offset);
	if (unlikely(size <= 0))
		return size ? size : -EFAULT;

	nr_pages = DIV_ROUND_UP(offset + size, PAGE_SIZE);
	for (left = size, i = 0; left > 0; left -= len, i += num_pages) {
		struct page *page = pages[i];
		struct folio *folio = page_folio(page);
		unsigned int old_vcnt = bio->bi_vcnt;

		folio_offset = ((size_t)folio_page_idx(folio, page) <<
			       PAGE_SHIFT) + offset;

		len = min(folio_size(folio) - folio_offset, left);

		num_pages = DIV_ROUND_UP(offset + len, PAGE_SIZE);

		if (num_pages > 1)
			len = get_contig_folio_len(&num_pages, pages, i,
						   folio, left, offset);

		if (!bio_add_folio(bio, folio, len, folio_offset)) {
			WARN_ON_ONCE(1);
			ret = -EINVAL;
			goto out;
		}

		if (bio_flagged(bio, BIO_PAGE_PINNED)) {
			/*
			 * We're adding another fragment of a page that already
			 * was part of the last segment.  Undo our pin as the
			 * page was pinned when an earlier fragment of it was
			 * added to the bio and __bio_release_pages expects a
			 * single pin per page.
			 */
			if (offset && bio->bi_vcnt == old_vcnt)
				unpin_user_folio(folio, 1);
		}
		offset = 0;
	}

	iov_iter_revert(iter, left);
out:
	while (i < nr_pages)
		bio_release_page(bio, pages[i++]);

	return ret;
}

/*
 * Aligns the bio size to the len_align_mask, releasing excessive bio vecs that
 * __bio_iov_iter_get_pages may have inserted, and reverts the trimmed length
 * for the next iteration.
 */
static int bio_iov_iter_align_down(struct bio *bio, struct iov_iter *iter,
			    unsigned len_align_mask)
{
	size_t nbytes = bio->bi_iter.bi_size & len_align_mask;

	if (!nbytes)
		return 0;

	iov_iter_revert(iter, nbytes);
	bio->bi_iter.bi_size -= nbytes;
	do {
		struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt - 1];

		if (nbytes < bv->bv_len) {
			bv->bv_len -= nbytes;
			break;
		}

		bio_release_page(bio, bv->bv_page);
		bio->bi_vcnt--;
		nbytes -= bv->bv_len;
	} while (nbytes);

	if (!bio->bi_vcnt)
		return -EFAULT;
	return 0;
}

static void bch2_bio_iov_bvec_set(struct bio *bio, const struct iov_iter *iter)
{
	WARN_ON_ONCE(bio->bi_max_vecs);

	bio->bi_vcnt = iter->nr_segs;
	bio->bi_io_vec = (struct bio_vec *)iter->bvec;
	bio->bi_iter.bi_bvec_done = iter->iov_offset;
	bio->bi_iter.bi_size = iov_iter_count(iter);
	bio_set_flag(bio, BIO_CLONED);
}

int bch2_bio_iov_iter_get_pages(struct bio *bio, struct iov_iter *iter,
				unsigned len_align_mask)
{
	int ret = 0;

	if (WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED)))
		return -EIO;

	if (iov_iter_is_bvec(iter)) {
		bch2_bio_iov_bvec_set(bio, iter);
		iov_iter_advance(iter, bio->bi_iter.bi_size);
		return 0;
	}

	if (iov_iter_extract_will_pin(iter))
		bio_set_flag(bio, BIO_PAGE_PINNED);
	do {
		ret = __bio_iov_iter_get_pages(bio, iter);
	} while (!ret && iov_iter_count(iter) && !bio_full(bio, 0));

	if (bio->bi_vcnt)
		return bio_iov_iter_align_down(bio, iter, len_align_mask);
	return ret;
}

#endif /* NO_BCACHEFS_FS */
