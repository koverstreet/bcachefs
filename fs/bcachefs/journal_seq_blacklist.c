// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_iter.h"
#include "eytzinger.h"
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

static struct bch_sb_field_journal_seq_blacklist *
blacklist_entry_try_merge(struct bch_fs *c,
			  struct bch_sb_field_journal_seq_blacklist *bl,
			  unsigned i)
{
	unsigned nr = blacklist_nr_entries(bl);

	if (le64_to_cpu(bl->start[i].end) >=
	    le64_to_cpu(bl->start[i + 1].start)) {
		bl->start[i].end = bl->start[i + 1].end;
		--nr;
		memmove(&bl->start[i],
			&bl->start[i + 1],
			sizeof(bl->start[0]) * (nr - i));

		bl = bch2_sb_resize_journal_seq_blacklist(&c->disk_sb,
							sb_blacklist_u64s(nr));
		BUG_ON(!bl);
	}

	return bl;
}

int bch2_journal_seq_blacklist_add(struct bch_fs *c, u64 start, u64 end)
{
	struct bch_sb_field_journal_seq_blacklist *bl;
	unsigned i, nr;
	int ret = 0;

	mutex_lock(&c->sb_lock);
	bl = bch2_sb_get_journal_seq_blacklist(c->disk_sb.sb);
	nr = blacklist_nr_entries(bl);

	if (bl) {
		for (i = 0; i < nr; i++) {
			struct journal_seq_blacklist_entry *e =
				bl->start + i;

			if (start == le64_to_cpu(e->start) &&
			    end   == le64_to_cpu(e->end))
				goto out;

			if (start <= le64_to_cpu(e->start) &&
			    end   >= le64_to_cpu(e->end)) {
				e->start = cpu_to_le64(start);
				e->end	= cpu_to_le64(end);

				if (i + 1 < nr)
					bl = blacklist_entry_try_merge(c,
								bl, i);
				if (i)
					bl = blacklist_entry_try_merge(c,
								bl, i - 1);
				goto out_write_sb;
			}
		}
	}

	bl = bch2_sb_resize_journal_seq_blacklist(&c->disk_sb,
					sb_blacklist_u64s(nr + 1));
	if (!bl) {
		ret = -ENOMEM;
		goto out;
	}

	bl->start[nr].start	= cpu_to_le64(start);
	bl->start[nr].end	= cpu_to_le64(end);
out_write_sb:
	c->disk_sb.sb->features[0] |= cpu_to_le64(1ULL << BCH_FEATURE_journal_seq_blacklist_v3);

	ret = bch2_write_super(c);
out:
	mutex_unlock(&c->sb_lock);

	return ret ?: bch2_blacklist_table_initialize(c);
}

static int journal_seq_blacklist_table_cmp(const void *_l,
					   const void *_r, size_t size)
{
	const struct journal_seq_blacklist_table_entry *l = _l;
	const struct journal_seq_blacklist_table_entry *r = _r;

	return cmp_int(l->start, r->start);
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

int bch2_blacklist_table_initialize(struct bch_fs *c)
{
	struct bch_sb_field_journal_seq_blacklist *bl =
		bch2_sb_get_journal_seq_blacklist(c->disk_sb.sb);
	struct journal_seq_blacklist_table *t;
	unsigned i, nr = blacklist_nr_entries(bl);

	if (!bl)
		return 0;

	t = kzalloc(sizeof(*t) + sizeof(t->entries[0]) * nr,
		    GFP_KERNEL);
	if (!t)
		return -ENOMEM;

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

static const char *
bch2_sb_journal_seq_blacklist_validate(struct bch_sb *sb,
				       struct bch_sb_field *f)
{
	struct bch_sb_field_journal_seq_blacklist *bl =
		field_to_type(f, journal_seq_blacklist);
	struct journal_seq_blacklist_entry *i;
	unsigned nr = blacklist_nr_entries(bl);

	for (i = bl->start; i < bl->start + nr; i++) {
		if (le64_to_cpu(i->start) >=
		    le64_to_cpu(i->end))
			return "entry start >= end";

		if (i + 1 < bl->start + nr &&
		    le64_to_cpu(i[0].end) >
		    le64_to_cpu(i[1].start))
			return "entries out of order";
	}

	return NULL;
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
			pr_buf(out, " ");

		pr_buf(out, "%llu-%llu",
		       le64_to_cpu(i->start),
		       le64_to_cpu(i->end));
	}
}

const struct bch_sb_field_ops bch_sb_field_ops_journal_seq_blacklist = {
	.validate	= bch2_sb_journal_seq_blacklist_validate,
	.to_text	= bch2_sb_journal_seq_blacklist_to_text
};

void bch2_blacklist_entries_gc(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs,
					journal_seq_blacklist_gc_work);
	struct journal_seq_blacklist_table *t;
	struct bch_sb_field_journal_seq_blacklist *bl;
	struct journal_seq_blacklist_entry *src, *dst;
	struct btree_trans trans;
	unsigned i, nr, new_nr;
	int ret;

	bch2_trans_init(&trans, c, 0, 0);

	for (i = 0; i < BTREE_ID_NR; i++) {
		struct btree_iter *iter;
		struct btree *b;

		for_each_btree_node(&trans, iter, i, POS_MIN,
				    BTREE_ITER_PREFETCH, b)
			if (test_bit(BCH_FS_STOPPING, &c->flags)) {
				bch2_trans_exit(&trans);
				return;
			}
		bch2_trans_iter_free(&trans, iter);
	}

	ret = bch2_trans_exit(&trans);
	if (ret)
		return;

	mutex_lock(&c->sb_lock);
	bl = bch2_sb_get_journal_seq_blacklist(c->disk_sb.sb);
	if (!bl)
		goto out;

	nr = blacklist_nr_entries(bl);
	dst = bl->start;

	t = c->journal_seq_blacklist_table;
	BUG_ON(nr != t->nr);

	for (src = bl->start, i = eytzinger0_first(t->nr);
	     src < bl->start + nr;
	     src++, i = eytzinger0_next(i, nr)) {
		BUG_ON(t->entries[i].start	!= le64_to_cpu(src->start));
		BUG_ON(t->entries[i].end	!= le64_to_cpu(src->end));

		if (t->entries[i].dirty)
			*dst++ = *src;
	}

	new_nr = dst - bl->start;

	bch_info(c, "nr blacklist entries was %u, now %u", nr, new_nr);

	if (new_nr != nr) {
		bl = bch2_sb_resize_journal_seq_blacklist(&c->disk_sb,
				new_nr ? sb_blacklist_u64s(new_nr) : 0);
		BUG_ON(new_nr && !bl);

		if (!new_nr)
			c->disk_sb.sb->features[0] &= cpu_to_le64(~(1ULL << BCH_FEATURE_journal_seq_blacklist_v3));

		bch2_write_super(c);
	}
out:
	mutex_unlock(&c->sb_lock);
}
