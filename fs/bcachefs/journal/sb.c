// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "journal/read.h"
#include "journal/sb.h"

#include "util/darray.h"

#include <linux/sort.h>

/* BCH_SB_FIELD_journal: */

static int u64_cmp(const void *_l, const void *_r)
{
	const u64 *l = _l;
	const u64 *r = _r;

	return cmp_int(*l, *r);
}

static int bch2_sb_journal_validate(struct bch_sb *sb, struct bch_sb_field *f,
				enum bch_validate_flags flags, struct printbuf *err)
{
	struct bch_sb_field_journal *journal = field_to_type(f, journal);
	struct bch_member m = bch2_sb_member_get(sb, sb->dev_idx);

	unsigned nr = bch2_nr_journal_buckets(journal);
	if (!nr)
		return 0;

	CLASS(darray_u64, b)();

	for (unsigned i = 0; i < nr; i++)
		try(darray_push(&b, le64_to_cpu(journal->buckets[i])));

	darray_sort(b, u64_cmp);

	if (!darray_first(b)) {
		prt_printf(err, "journal bucket at sector 0");
		return -BCH_ERR_invalid_sb_journal;
	}

	if (darray_first(b) < le16_to_cpu(m.first_bucket)) {
		prt_printf(err, "journal bucket %llu before first bucket %u",
			   darray_first(b), le16_to_cpu(m.first_bucket));
		return -BCH_ERR_invalid_sb_journal;
	}

	if (darray_last(b) >= le64_to_cpu(m.nbuckets)) {
		prt_printf(err, "journal bucket %llu past end of device (nbuckets %llu)",
			   darray_last(b), le64_to_cpu(m.nbuckets));
		return -BCH_ERR_invalid_sb_journal;
	}

	darray_for_each(b, i)
		if (i != &darray_last(b) && i[0] == i[1]) {
			prt_printf(err, "duplicate journal buckets %llu", *i);
			return -BCH_ERR_invalid_sb_journal;
		}

	return 0;
}

static void bch2_sb_journal_to_text(struct printbuf *out,
				    struct bch_fs *c, struct bch_sb *sb,
				    struct bch_sb_field *f)
{
	struct bch_sb_field_journal *journal = field_to_type(f, journal);
	unsigned i, nr = bch2_nr_journal_buckets(journal);

	prt_printf(out, "Buckets: ");
	for (i = 0; i < nr; i++)
		prt_printf(out, " %llu", le64_to_cpu(journal->buckets[i]));
	prt_newline(out);
}

const struct bch_sb_field_ops bch_sb_field_ops_journal = {
	.validate	= bch2_sb_journal_validate,
	.to_text	= bch2_sb_journal_to_text,
};

static int u64_range_cmp(const void *_l, const void *_r)
{
	const struct u64_range *l = _l;
	const struct u64_range *r = _r;

	return cmp_int(l->start, r->start);
}

static int bch2_sb_journal_v2_validate(struct bch_sb *sb, struct bch_sb_field *f,
				enum bch_validate_flags flags, struct printbuf *err)
{
	struct bch_sb_field_journal_v2 *journal = field_to_type(f, journal_v2);
	struct bch_member m = bch2_sb_member_get(sb, sb->dev_idx);
	u64 sum = 0;

	unsigned nr = bch2_sb_field_journal_v2_nr_entries(journal);
	if (!nr)
		return 0;

	CLASS(darray_u64_range, b)();

	for (unsigned i = 0; i < nr; i++) {
		struct u64_range r = {
			.start	= le64_to_cpu(journal->d[i].start),
			.end	= le64_to_cpu(journal->d[i].start) +
				le64_to_cpu(journal->d[i].nr),
		};

		if (r.end <= r.start) {
			prt_printf(err, "journal buckets entry with bad nr: %llu+%llu",
				   le64_to_cpu(journal->d[i].start),
				   le64_to_cpu(journal->d[i].nr));
			return -BCH_ERR_invalid_sb_journal;
		}

		sum += le64_to_cpu(journal->d[i].nr);
		try(darray_push(&b, r));
	}

	darray_sort(b, u64_range_cmp);

	if (!darray_first(b).start) {
		prt_printf(err, "journal bucket at sector 0");
		return -BCH_ERR_invalid_sb_journal;
	}

	if (darray_first(b).start < le16_to_cpu(m.first_bucket)) {
		prt_printf(err, "journal bucket %llu before first bucket %u",
		       darray_first(b).start, le16_to_cpu(m.first_bucket));
		return -BCH_ERR_invalid_sb_journal;
	}

	if (darray_last(b).end > le64_to_cpu(m.nbuckets)) {
		prt_printf(err, "journal bucket %llu past end of device (nbuckets %llu)",
			   darray_last(b).end - 1, le64_to_cpu(m.nbuckets));
		return -BCH_ERR_invalid_sb_journal;
	}

	darray_for_each(b, i)
		if (i != &darray_last(b) && i[0].end > i[1].start) {
			prt_printf(err, "duplicate journal buckets in ranges %llu-%llu, %llu-%llu",
				   i[0].start, i[0].end, i[1].start, i[1].end);
			return -BCH_ERR_invalid_sb_journal;
		}

	if (sum > UINT_MAX) {
		prt_printf(err, "too many journal buckets: %llu > %u", sum, UINT_MAX);
		return -BCH_ERR_invalid_sb_journal;
	}

	return 0;
}

static void bch2_sb_journal_v2_to_text(struct printbuf *out,
				       struct bch_fs *c, struct bch_sb *sb,
				       struct bch_sb_field *f)
{
	struct bch_sb_field_journal_v2 *journal = field_to_type(f, journal_v2);
	unsigned i, nr = bch2_sb_field_journal_v2_nr_entries(journal);

	prt_printf(out, "Buckets: ");
	for (i = 0; i < nr; i++)
		prt_printf(out, " %llu-%llu",
		       le64_to_cpu(journal->d[i].start),
		       le64_to_cpu(journal->d[i].start) + le64_to_cpu(journal->d[i].nr));
	prt_newline(out);
}

const struct bch_sb_field_ops bch_sb_field_ops_journal_v2 = {
	.validate	= bch2_sb_journal_v2_validate,
	.to_text	= bch2_sb_journal_v2_to_text,
};

int bch2_journal_buckets_to_sb(struct bch_fs *c, struct bch_dev *ca,
			       u64 *buckets, unsigned nr)
{
	unsigned dst = 0, nr_compacted = 1;

	lockdep_assert_held(&c->sb_lock);

	if (!nr) {
		bch2_sb_field_delete(&ca->disk_sb, BCH_SB_FIELD_journal);
		bch2_sb_field_delete(&ca->disk_sb, BCH_SB_FIELD_journal_v2);
		return 0;
	}

	for (unsigned i = 0; i + 1 < nr; i++)
		if (buckets[i] + 1 != buckets[i + 1])
			nr_compacted++;

	struct bch_sb_field_journal_v2 *j =
		bch2_sb_field_resize(&ca->disk_sb, journal_v2,
			 (sizeof(*j) + sizeof(j->d[0]) * nr_compacted) / sizeof(u64));
	if (!j)
		return bch_err_throw(c, ENOSPC_sb_journal);

	bch2_sb_field_delete(&ca->disk_sb, BCH_SB_FIELD_journal);

	j->d[dst].start = cpu_to_le64(buckets[0]);
	j->d[dst].nr	= cpu_to_le64(1);

	for (unsigned i = 1; i < nr; i++) {
		if (buckets[i] == buckets[i - 1] + 1) {
			le64_add_cpu(&j->d[dst].nr, 1);
		} else {
			dst++;
			j->d[dst].start = cpu_to_le64(buckets[i]);
			j->d[dst].nr	= cpu_to_le64(1);
		}
	}

	BUG_ON(dst + 1 != nr_compacted);
	return 0;
}

static inline bool journal_v2_unsorted(struct bch_sb_field_journal_v2 *j)
{
	unsigned nr = bch2_sb_field_journal_v2_nr_entries(j);
	for (unsigned i = 0; i + 1 < nr; i++)
		if (le64_to_cpu(j->d[i].start) > le64_to_cpu(j->d[i + 1].start))
			return true;
	return false;
}

int bch2_sb_journal_sort(struct bch_fs *c)
{
	BUG_ON(!c->sb.clean);
	BUG_ON(test_bit(BCH_FS_rw, &c->flags));

	guard(memalloc_flags)(PF_MEMALLOC_NOFS);
	guard(mutex)(&c->sb_lock);
	bool write_sb = false;

	for_each_online_member(c, ca, BCH_DEV_READ_REF_sb_journal_sort) {
		struct bch_sb_field_journal_v2 *j = bch2_sb_field_get(ca->disk_sb.sb, journal_v2);
		if (!j)
			continue;

		if ((j && journal_v2_unsorted(j)) ||
		    bch2_sb_field_get(ca->disk_sb.sb, journal)) {
			struct journal_device *ja = &ca->journal;

			sort(ja->buckets, ja->nr, sizeof(ja->buckets[0]), u64_cmp, NULL);
			bch2_journal_buckets_to_sb(c, ca, ja->buckets, ja->nr);
			write_sb = true;
		}
	}

	return write_sb
		? bch2_write_super(c)
		: 0;
}
