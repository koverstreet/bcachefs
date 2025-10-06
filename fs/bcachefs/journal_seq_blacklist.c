// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "eytzinger.h"
#include "journal.h"
#include "journal_seq_blacklist.h"
#include "super-io.h"

/*
 * journal_seq_blacklist machinery:
 *
 * To guarantee order of btree updates after a crash, we need to detect when a
 * btree node entry (bset) is newer than the newest journal entry that was
 * successfully written, and ignore it - effectively ignoring any btree updates
 * that didn't make it into the journal.
 *
 * If we didn't do this, we might have two btree nodes, a and b, both with
 * updates that weren't written to the journal yet: if b was updated after a,
 * but b was flushed and not a - oops; on recovery we'll find that the updates
 * to b happened, but not the updates to a that happened before it.
 *
 * Ignoring bsets that are newer than the newest journal entry is always safe,
 * because everything they contain will also have been journalled - and must
 * still be present in the journal on disk until a journal entry has been
 * written _after_ that bset was written.
 *
 * To accomplish this, bsets record the newest journal sequence number they
 * contain updates for; then, on startup, the btree code queries the journal
 * code to ask "Is this sequence number newer than the newest journal entry? If
 * so, ignore it."
 *
 * When this happens, we must blacklist that journal sequence number: the
 * journal must not write any entries with that sequence number, and it must
 * record that it was blacklisted so that a) on recovery we don't think we have
 * missing journal entries and b) so that the btree code continues to ignore
 * that bset, until that btree node is rewritten.
 */

static unsigned sb_blacklist_u64s(unsigned nr)
{
	struct bch_sb_field_journal_seq_blacklist *bl;

	return (sizeof(*bl) + sizeof(bl->start[0]) * nr) / sizeof(u64);
}

int bch2_journal_seq_blacklist_add(struct bch_fs *c, u64 start, u64 end)
{
	struct bch_sb_field_journal_seq_blacklist *bl;
	unsigned i = 0, nr;
	int ret = 0;

	mutex_lock(&c->sb_lock);
	bl = bch2_sb_field_get(c->disk_sb.sb, journal_seq_blacklist);
	nr = blacklist_nr_entries(bl);

	while (i < nr) {
		struct journal_seq_blacklist_entry *e =
			bl->start + i;

		if (end < le64_to_cpu(e->start))
			break;

		if (start > le64_to_cpu(e->end)) {
			i++;
			continue;
		}

		/*
		 * Entry is contiguous or overlapping with new entry: merge it
		 * with new entry, and delete:
		 */

		start	= min(start,	le64_to_cpu(e->start));
		end	= max(end,	le64_to_cpu(e->end));
		array_remove_item(bl->start, nr, i);
	}

	bl = bch2_sb_field_resize(&c->disk_sb, journal_seq_blacklist,
				  sb_blacklist_u64s(nr + 1));
	if (!bl) {
		ret = bch_err_throw(c, ENOSPC_sb_journal_seq_blacklist);
		goto out;
	}

	array_insert_item(bl->start, nr, i, ((struct journal_seq_blacklist_entry) {
		.start	= cpu_to_le64(start),
		.end	= cpu_to_le64(end),
	}));
	c->disk_sb.sb->features[0] |= cpu_to_le64(1ULL << BCH_FEATURE_journal_seq_blacklist_v3);

	ret = bch2_write_super(c);
out:
	mutex_unlock(&c->sb_lock);

	return ret ?: bch2_blacklist_table_initialize(c);
}

static int journal_seq_blacklist_table_cmp(const void *_l, const void *_r)
{
	const struct journal_seq_blacklist_table_entry *l = _l;
	const struct journal_seq_blacklist_table_entry *r = _r;

	return cmp_int(l->start, r->start);
}

static int journal_seq_blacklist_table_end_cmp(const void *_l, const void *_r)
{
	const struct journal_seq_blacklist_table_entry *l = _l;
	const struct journal_seq_blacklist_table_entry *r = _r;

	return cmp_int(l->end, r->end);
}

u64 bch2_journal_seq_next_blacklisted(struct bch_fs *c, u64 seq)
{
	struct journal_seq_blacklist_table *t = c->journal_seq_blacklist_table;

	if (!t)
		return U64_MAX;

	struct journal_seq_blacklist_table_entry search = { .end = seq };
	int idx = eytzinger0_find_gt(t->entries, t->nr,
				     sizeof(t->entries[0]),
				     journal_seq_blacklist_table_end_cmp,
				     &search);
	if (idx < 0)
		return U64_MAX;

	return max(seq, t->entries[idx].start);
}

u64 bch2_journal_seq_next_nonblacklisted(struct bch_fs *c, u64 seq)
{
	struct journal_seq_blacklist_table *t = c->journal_seq_blacklist_table;

	if (!t)
		return seq;

	while (true) {
		struct journal_seq_blacklist_table_entry search = { .start = seq };
		int idx = eytzinger0_find_le(t->entries, t->nr,
					     sizeof(t->entries[0]),
					     journal_seq_blacklist_table_cmp,
					     &search);
		if (idx < 0 || t->entries[idx].end <= seq)
			return seq;

		seq = t->entries[idx].end;
	}
}

bool bch2_journal_seq_is_blacklisted(struct bch_fs *c, u64 seq,
				     bool dirty)
{
	struct journal_seq_blacklist_table *t = c->journal_seq_blacklist_table;
	struct journal_seq_blacklist_table_entry search = { .start = seq };
	int idx;

	if (!t)
		return false;

	idx = eytzinger0_find_le(t->entries, t->nr,
				 sizeof(t->entries[0]),
				 journal_seq_blacklist_table_cmp,
				 &search);
	if (idx < 0)
		return false;

	BUG_ON(t->entries[idx].start > seq);

	if (seq >= t->entries[idx].end)
		return false;

	if (dirty)
		t->entries[idx].dirty = true;
	return true;
}

u64 bch2_journal_last_blacklisted_seq(struct bch_fs *c)
{
	struct journal_seq_blacklist_table *t = c->journal_seq_blacklist_table;

	if (!t || !t->nr)
		return 0;

	return t->entries[eytzinger0_last(t->nr)].end - 1;
}

int bch2_blacklist_table_initialize(struct bch_fs *c)
{
	struct bch_sb_field_journal_seq_blacklist *bl =
		bch2_sb_field_get(c->disk_sb.sb, journal_seq_blacklist);
	struct journal_seq_blacklist_table *t;
	unsigned i, nr = blacklist_nr_entries(bl);

	if (!bl)
		return 0;

	t = kzalloc(struct_size(t, entries, nr), GFP_KERNEL);
	if (!t)
		return bch_err_throw(c, ENOMEM_blacklist_table_init);

	t->nr = nr;

	for (i = 0; i < nr; i++) {
		t->entries[i].start	= le64_to_cpu(bl->start[i].start);
		t->entries[i].end	= le64_to_cpu(bl->start[i].end);
	}

	eytzinger0_sort(t->entries,
			t->nr,
			sizeof(t->entries[0]),
			journal_seq_blacklist_table_cmp,
			NULL);

	kfree(c->journal_seq_blacklist_table);
	c->journal_seq_blacklist_table = t;
	return 0;
}

static int bch2_sb_journal_seq_blacklist_validate(struct bch_sb *sb, struct bch_sb_field *f,
				enum bch_validate_flags flags, struct printbuf *err)
{
	struct bch_sb_field_journal_seq_blacklist *bl =
		field_to_type(f, journal_seq_blacklist);
	unsigned i, nr = blacklist_nr_entries(bl);

	for (i = 0; i < nr; i++) {
		struct journal_seq_blacklist_entry *e = bl->start + i;

		if (le64_to_cpu(e->start) >=
		    le64_to_cpu(e->end)) {
			prt_printf(err, "entry %u start >= end (%llu >= %llu)",
			       i, le64_to_cpu(e->start), le64_to_cpu(e->end));
			return -BCH_ERR_invalid_sb_journal_seq_blacklist;
		}

		if (i + 1 < nr &&
		    le64_to_cpu(e[0].end) >
		    le64_to_cpu(e[1].start)) {
			prt_printf(err, "entry %u out of order with next entry (%llu > %llu)",
			       i + 1, le64_to_cpu(e[0].end), le64_to_cpu(e[1].start));
			return -BCH_ERR_invalid_sb_journal_seq_blacklist;
		}
	}

	return 0;
}

static void bch2_sb_journal_seq_blacklist_to_text(struct printbuf *out,
						  struct bch_sb *sb,
						  struct bch_sb_field *f)
{
	struct bch_sb_field_journal_seq_blacklist *bl =
		field_to_type(f, journal_seq_blacklist);
	struct journal_seq_blacklist_entry *i;
	unsigned nr = blacklist_nr_entries(bl);

	for (i = bl->start; i < bl->start + nr; i++) {
		if (i != bl->start)
			prt_printf(out, " ");

		prt_printf(out, "%llu-%llu",
		       le64_to_cpu(i->start),
		       le64_to_cpu(i->end));
	}
	prt_newline(out);
}

const struct bch_sb_field_ops bch_sb_field_ops_journal_seq_blacklist = {
	.validate	= bch2_sb_journal_seq_blacklist_validate,
	.to_text	= bch2_sb_journal_seq_blacklist_to_text
};

bool bch2_blacklist_entries_gc(struct bch_fs *c)
{
	struct journal_seq_blacklist_entry *src, *dst;

	struct bch_sb_field_journal_seq_blacklist *bl =
		bch2_sb_field_get(c->disk_sb.sb, journal_seq_blacklist);
	if (!bl)
		return false;

	unsigned nr = blacklist_nr_entries(bl);
	dst = bl->start;

	struct journal_seq_blacklist_table *t = c->journal_seq_blacklist_table;
	BUG_ON(nr != t->nr);

	src = bl->start;
	eytzinger0_for_each(i, nr) {
		BUG_ON(t->entries[i].start	!= le64_to_cpu(src->start));
		BUG_ON(t->entries[i].end	!= le64_to_cpu(src->end));

		if (t->entries[i].dirty || t->entries[i].end >= c->journal.oldest_seq_found_ondisk)
			*dst++ = *src;
		src++;
	}

	unsigned new_nr = dst - bl->start;
	if (new_nr == nr)
		return false;

	bch_verbose(c, "nr blacklist entries was %u, now %u", nr, new_nr);

	bl = bch2_sb_field_resize(&c->disk_sb, journal_seq_blacklist,
				  new_nr ? sb_blacklist_u64s(new_nr) : 0);
	BUG_ON(new_nr && !bl);
	return true;
}
