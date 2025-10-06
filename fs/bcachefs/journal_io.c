// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"
#include "alloc_background.h"
#include "alloc_foreground.h"
#include "btree_io.h"
#include "btree_journal_iter.h"
#include "btree_update_interior.h"
#include "btree_write_buffer.h"
#include "buckets.h"
#include "checksum.h"
#include "disk_groups.h"
#include "error.h"
#include "journal.h"
#include "journal_io.h"
#include "journal_reclaim.h"
#include "journal_seq_blacklist.h"
#include "replicas.h"
#include "sb-clean.h"
#include "trace.h"

#include <linux/ioprio.h>
#include <linux/string_choices.h>
#include <linux/sched/sysctl.h>

void bch2_journal_pos_from_member_info_set(struct bch_fs *c)
{
	lockdep_assert_held(&c->sb_lock);

	for_each_member_device(c, ca) {
		struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);

		m->last_journal_bucket = cpu_to_le32(ca->journal.cur_idx);
		m->last_journal_bucket_offset = cpu_to_le32(ca->mi.bucket_size - ca->journal.sectors_free);
	}
}

void bch2_journal_pos_from_member_info_resume(struct bch_fs *c)
{
	guard(mutex)(&c->sb_lock);

	for_each_member_device(c, ca) {
		struct bch_member m = bch2_sb_member_get(c->disk_sb.sb, ca->dev_idx);

		unsigned idx = le32_to_cpu(m.last_journal_bucket);
		if (idx < ca->journal.nr)
			ca->journal.cur_idx = idx;
		unsigned offset = le32_to_cpu(m.last_journal_bucket_offset);
		if (offset <= ca->mi.bucket_size)
			ca->journal.sectors_free = ca->mi.bucket_size - offset;
	}
}

static void bch2_journal_ptr_to_text(struct printbuf *out, struct bch_fs *c, struct journal_ptr *p)
{
	CLASS(bch2_dev_tryget_noerror, ca)(c, p->dev);
	prt_printf(out, "%s %u:%u:%u (sector %llu)",
		   ca ? ca->name : "(invalid dev)",
		   p->dev, p->bucket, p->bucket_offset, p->sector);
}

void bch2_journal_ptrs_to_text(struct printbuf *out, struct bch_fs *c, struct journal_replay *j)
{
	darray_for_each(j->ptrs, i) {
		if (i != j->ptrs.data)
			prt_printf(out, " ");
		bch2_journal_ptr_to_text(out, c, i);
	}
}

static void bch2_journal_datetime_to_text(struct printbuf *out, struct jset *j)
{
	for_each_jset_entry_type(entry, j, BCH_JSET_ENTRY_datetime) {
		struct jset_entry_datetime *datetime =
			container_of(entry, struct jset_entry_datetime, entry);
		bch2_prt_datetime(out, le64_to_cpu(datetime->seconds));
		break;
	}
}

static void bch2_journal_replay_to_text(struct printbuf *out, struct bch_fs *c,
					struct journal_replay *j)
{
	prt_printf(out, "seq %llu ", le64_to_cpu(j->j.seq));
	bch2_journal_datetime_to_text(out, &j->j);
	prt_char(out, ' ');
	bch2_journal_ptrs_to_text(out, c, j);
}

static struct nonce journal_nonce(const struct jset *jset)
{
	return (struct nonce) {{
		[0] = 0,
		[1] = ((__le32 *) &jset->seq)[0],
		[2] = ((__le32 *) &jset->seq)[1],
		[3] = BCH_NONCE_JOURNAL,
	}};
}

static bool jset_csum_good(struct bch_fs *c, struct jset *j, struct bch_csum *csum)
{
	if (!bch2_checksum_type_valid(c, JSET_CSUM_TYPE(j))) {
		*csum = (struct bch_csum) {};
		return false;
	}

	*csum = csum_vstruct(c, JSET_CSUM_TYPE(j), journal_nonce(j), j);
	return !bch2_crc_cmp(j->csum, *csum);
}

static void __journal_replay_free(struct bch_fs *c,
				  struct journal_replay *i)
{
	struct journal_replay **p =
		genradix_ptr(&c->journal_entries,
			     journal_entry_radix_idx(c, le64_to_cpu(i->j.seq)));

	BUG_ON(*p != i);
	*p = NULL;
	kvfree(i);
}

static void journal_replay_free(struct bch_fs *c, struct journal_replay *i, bool blacklisted)
{
	if (blacklisted)
		i->ignore_blacklisted = true;
	else
		i->ignore_not_dirty = true;

	if (!c->opts.read_entire_journal)
		__journal_replay_free(c, i);
}

struct journal_list {
	struct closure		cl;
	u64			last_seq;
	struct mutex		lock;
	int			ret;
};

#define JOURNAL_ENTRY_ADD_OK		0
#define JOURNAL_ENTRY_ADD_OUT_OF_RANGE	5

/*
 * Given a journal entry we just read, add it to the list of journal entries to
 * be replayed:
 */
static int journal_entry_add(struct bch_fs *c, struct bch_dev *ca,
			     struct journal_ptr entry_ptr,
			     struct journal_list *jlist, struct jset *j)
{
	struct genradix_iter iter;
	struct journal_replay **_i, *i, *dup;
	size_t bytes = vstruct_bytes(j);
	u64 last_seq = !JSET_NO_FLUSH(j) ? le64_to_cpu(j->last_seq) : 0;
	CLASS(printbuf, buf)();
	int ret = JOURNAL_ENTRY_ADD_OK;

	if (last_seq && c->opts.journal_rewind)
		last_seq = min(last_seq, c->opts.journal_rewind);

	if (!c->journal.oldest_seq_found_ondisk ||
	    le64_to_cpu(j->seq) < c->journal.oldest_seq_found_ondisk)
		c->journal.oldest_seq_found_ondisk = le64_to_cpu(j->seq);

	/* Is this entry older than the range we need? */
	if (!c->opts.read_entire_journal &&
	    le64_to_cpu(j->seq) < jlist->last_seq)
		return JOURNAL_ENTRY_ADD_OUT_OF_RANGE;

	/*
	 * genradixes are indexed by a ulong, not a u64, so we can't index them
	 * by sequence number directly: Assume instead that they will all fall
	 * within the range of +-2billion of the filrst one we find.
	 */
	if (!c->journal_entries_base_seq)
		c->journal_entries_base_seq = max_t(s64, 1, le64_to_cpu(j->seq) - S32_MAX);

	/* Drop entries we don't need anymore */
	if (last_seq > jlist->last_seq && !c->opts.read_entire_journal) {
		genradix_for_each_from(&c->journal_entries, iter, _i,
				       journal_entry_radix_idx(c, jlist->last_seq)) {
			i = *_i;

			if (journal_replay_ignore(i))
				continue;

			if (le64_to_cpu(i->j.seq) >= last_seq)
				break;

			journal_replay_free(c, i, false);
		}
	}

	jlist->last_seq = max(jlist->last_seq, last_seq);

	_i = genradix_ptr_alloc(&c->journal_entries,
				journal_entry_radix_idx(c, le64_to_cpu(j->seq)),
				GFP_KERNEL);
	if (!_i)
		return bch_err_throw(c, ENOMEM_journal_entry_add);

	/*
	 * Duplicate journal entries? If so we want the one that didn't have a
	 * checksum error:
	 */
	dup = *_i;
	if (dup) {
		bool identical = bytes == vstruct_bytes(&dup->j) &&
			!memcmp(j, &dup->j, bytes);
		bool not_identical = !identical &&
			entry_ptr.csum_good &&
			dup->csum_good;

		bool same_device = false;
		darray_for_each(dup->ptrs, ptr)
			if (ptr->dev == ca->dev_idx)
				same_device = true;

		ret = darray_push(&dup->ptrs, entry_ptr);
		if (ret)
			return ret;

		bch2_journal_replay_to_text(&buf, c, dup);

		fsck_err_on(same_device,
			    c, journal_entry_dup_same_device,
			    "duplicate journal entry on same device\n%s",
			    buf.buf);

		fsck_err_on(not_identical,
			    c, journal_entry_replicas_data_mismatch,
			    "found duplicate but non identical journal entries\n%s",
			    buf.buf);

		if (entry_ptr.csum_good && !identical)
			goto replace;

		return ret;
	}
replace:
	i = kvmalloc(offsetof(struct journal_replay, j) + bytes, GFP_KERNEL);
	if (!i)
		return bch_err_throw(c, ENOMEM_journal_entry_add);

	darray_init(&i->ptrs);
	i->csum_good		= entry_ptr.csum_good;
	i->ignore_blacklisted	= false;
	i->ignore_not_dirty	= false;
	unsafe_memcpy(&i->j, j, bytes, "embedded variable length struct");

	if (dup) {
		/* The first ptr should represent the jset we kept: */
		darray_for_each(dup->ptrs, ptr)
			darray_push(&i->ptrs, *ptr);
		__journal_replay_free(c, dup);
	} else {
		darray_push(&i->ptrs, entry_ptr);
	}

	*_i = i;
fsck_err:
	return ret;
}

/* this fills in a range with empty jset_entries: */
static void journal_entry_null_range(void *start, void *end)
{
	struct jset_entry *entry;

	for (entry = start; entry != end; entry = vstruct_next(entry))
		memset(entry, 0, sizeof(*entry));
}

#define JOURNAL_ENTRY_REREAD	5
#define JOURNAL_ENTRY_NONE	6
#define JOURNAL_ENTRY_BAD	7

static void journal_entry_err_msg(struct printbuf *out,
				  u32 version,
				  struct jset *jset,
				  struct jset_entry *entry)
{
	prt_str(out, "invalid journal entry, version=");
	bch2_version_to_text(out, version);

	if (entry) {
		prt_str(out, " type=");
		bch2_prt_jset_entry_type(out, entry->type);
	}

	if (!jset) {
		prt_printf(out, " in superblock");
	} else {

		prt_printf(out, " seq=%llu", le64_to_cpu(jset->seq));

		if (entry)
			prt_printf(out, " offset=%zi/%u",
				   (u64 *) entry - jset->_data,
				   le32_to_cpu(jset->u64s));
	}

	prt_str(out, ": ");
}

#define journal_entry_err(c, version, jset, entry, _err, msg, ...)	\
({									\
	CLASS(printbuf, _buf)();					\
									\
	journal_entry_err_msg(&_buf, version, jset, entry);		\
	prt_printf(&_buf, msg, ##__VA_ARGS__);				\
									\
	switch (from.flags & BCH_VALIDATE_write) {			\
	case READ:							\
		mustfix_fsck_err(c, _err, "%s", _buf.buf);		\
		break;							\
	case WRITE:							\
		bch2_sb_error_count(c, BCH_FSCK_ERR_##_err);		\
		if (bch2_fs_inconsistent(c,				\
				"corrupt metadata before write: %s\n", _buf.buf)) {\
			ret = bch_err_throw(c, fsck_errors_not_fixed);		\
			goto fsck_err;					\
		}							\
		break;							\
	}								\
									\
	true;								\
})

#define journal_entry_err_on(cond, ...)					\
	((cond) ? journal_entry_err(__VA_ARGS__) : false)

#define FSCK_DELETED_KEY	5

static int journal_validate_key(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				struct bkey_i *k,
				struct bkey_validate_context from,
				unsigned version, int big_endian)
{
	enum bch_validate_flags flags = from.flags;
	int write = flags & BCH_VALIDATE_write;
	void *next = vstruct_next(entry);
	int ret = 0;

	if (journal_entry_err_on(!k->k.u64s,
				 c, version, jset, entry,
				 journal_entry_bkey_u64s_0,
				 "k->u64s 0")) {
		entry->u64s = cpu_to_le16((u64 *) k - entry->_data);
		journal_entry_null_range(vstruct_next(entry), next);
		return FSCK_DELETED_KEY;
	}

	if (journal_entry_err_on((void *) bkey_next(k) >
				 (void *) vstruct_next(entry),
				 c, version, jset, entry,
				 journal_entry_bkey_past_end,
				 "extends past end of journal entry")) {
		entry->u64s = cpu_to_le16((u64 *) k - entry->_data);
		journal_entry_null_range(vstruct_next(entry), next);
		return FSCK_DELETED_KEY;
	}

	if (journal_entry_err_on(k->k.format != KEY_FORMAT_CURRENT,
				 c, version, jset, entry,
				 journal_entry_bkey_bad_format,
				 "bad format %u", k->k.format)) {
		le16_add_cpu(&entry->u64s, -((u16) k->k.u64s));
		memmove(k, bkey_next(k), next - (void *) bkey_next(k));
		journal_entry_null_range(vstruct_next(entry), next);
		return FSCK_DELETED_KEY;
	}

	if (!write)
		bch2_bkey_compat(from.level, from.btree, version, big_endian,
				 write, NULL, bkey_to_packed(k));

	ret = bch2_bkey_validate(c, bkey_i_to_s_c(k), from);
	if (ret == -BCH_ERR_fsck_delete_bkey) {
		le16_add_cpu(&entry->u64s, -((u16) k->k.u64s));
		memmove(k, bkey_next(k), next - (void *) bkey_next(k));
		journal_entry_null_range(vstruct_next(entry), next);
		return FSCK_DELETED_KEY;
	}
	if (ret)
		goto fsck_err;

	if (write)
		bch2_bkey_compat(from.level, from.btree, version, big_endian,
				 write, NULL, bkey_to_packed(k));
fsck_err:
	return ret;
}

static int journal_entry_btree_keys_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	struct bkey_i *k = entry->start;

	from.level	= entry->level;
	from.btree	= entry->btree_id;

	while (k != vstruct_last(entry)) {
		int ret = journal_validate_key(c, jset, entry, k, from, version, big_endian);
		if (ret == FSCK_DELETED_KEY)
			continue;
		else if (ret)
			return ret;

		k = bkey_next(k);
	}

	return 0;
}

static void journal_entry_btree_keys_to_text(struct printbuf *out, struct bch_fs *c,
					     struct jset_entry *entry)
{
	bool first = true;

	jset_entry_for_each_key(entry, k) {
		if (!first) {
			prt_newline(out);
			bch2_prt_jset_entry_type(out, entry->type);
			prt_str(out, ": ");
		}
		/* We may be called on entries that haven't been validated: */
		if (!k->k.u64s) {
			prt_str(out, "(invalid, k->u64s 0)");
			break;
		}

		if (bkey_next(k) > vstruct_last(entry)) {
			prt_str(out, "(invalid, bkey overruns jset_entry)");
			break;
		}

		bch2_btree_id_level_to_text(out, entry->btree_id, entry->level);
		prt_char(out, ' ');
		bch2_bkey_val_to_text(out, c, bkey_i_to_s_c(k));
		first = false;
	}
}

static int journal_entry_btree_root_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	struct bkey_i *k = entry->start;
	int ret = 0;

	from.root	= true;
	from.level	= entry->level + 1;
	from.btree	= entry->btree_id;

	if (journal_entry_err_on(!entry->u64s ||
				 le16_to_cpu(entry->u64s) != k->k.u64s,
				 c, version, jset, entry,
				 journal_entry_btree_root_bad_size,
				 "invalid btree root journal entry: wrong number of keys")) {
		void *next = vstruct_next(entry);
		/*
		 * we don't want to null out this jset_entry,
		 * just the contents, so that later we can tell
		 * we were _supposed_ to have a btree root
		 */
		entry->u64s = 0;
		journal_entry_null_range(vstruct_next(entry), next);
		return 0;
	}

	ret = journal_validate_key(c, jset, entry, k, from, version, big_endian);
	if (ret == FSCK_DELETED_KEY)
		ret = 0;
fsck_err:
	return ret;
}

static void journal_entry_btree_root_to_text(struct printbuf *out, struct bch_fs *c,
					     struct jset_entry *entry)
{
	journal_entry_btree_keys_to_text(out, c, entry);
}

static int journal_entry_prio_ptrs_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	/* obsolete, don't care: */
	return 0;
}

static void journal_entry_prio_ptrs_to_text(struct printbuf *out, struct bch_fs *c,
					    struct jset_entry *entry)
{
}

static int journal_entry_blacklist_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	int ret = 0;

	if (journal_entry_err_on(le16_to_cpu(entry->u64s) != 1,
				 c, version, jset, entry,
				 journal_entry_blacklist_bad_size,
		"invalid journal seq blacklist entry: bad size")) {
		journal_entry_null_range(entry, vstruct_next(entry));
	}
fsck_err:
	return ret;
}

static void journal_entry_blacklist_to_text(struct printbuf *out, struct bch_fs *c,
					    struct jset_entry *entry)
{
	struct jset_entry_blacklist *bl =
		container_of(entry, struct jset_entry_blacklist, entry);

	prt_printf(out, "seq=%llu", le64_to_cpu(bl->seq));
}

static int journal_entry_blacklist_v2_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	struct jset_entry_blacklist_v2 *bl_entry;
	int ret = 0;

	if (journal_entry_err_on(le16_to_cpu(entry->u64s) != 2,
				 c, version, jset, entry,
				 journal_entry_blacklist_v2_bad_size,
		"invalid journal seq blacklist entry: bad size")) {
		journal_entry_null_range(entry, vstruct_next(entry));
		goto out;
	}

	bl_entry = container_of(entry, struct jset_entry_blacklist_v2, entry);

	if (journal_entry_err_on(le64_to_cpu(bl_entry->start) >
				 le64_to_cpu(bl_entry->end),
				 c, version, jset, entry,
				 journal_entry_blacklist_v2_start_past_end,
		"invalid journal seq blacklist entry: start > end")) {
		journal_entry_null_range(entry, vstruct_next(entry));
	}
out:
fsck_err:
	return ret;
}

static void journal_entry_blacklist_v2_to_text(struct printbuf *out, struct bch_fs *c,
					       struct jset_entry *entry)
{
	struct jset_entry_blacklist_v2 *bl =
		container_of(entry, struct jset_entry_blacklist_v2, entry);

	prt_printf(out, "start=%llu end=%llu",
	       le64_to_cpu(bl->start),
	       le64_to_cpu(bl->end));
}

static int journal_entry_usage_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	struct jset_entry_usage *u =
		container_of(entry, struct jset_entry_usage, entry);
	unsigned bytes = jset_u64s(le16_to_cpu(entry->u64s)) * sizeof(u64);
	int ret = 0;

	if (journal_entry_err_on(bytes < sizeof(*u),
				 c, version, jset, entry,
				 journal_entry_usage_bad_size,
				 "invalid journal entry usage: bad size")) {
		journal_entry_null_range(entry, vstruct_next(entry));
		return ret;
	}

fsck_err:
	return ret;
}

static void journal_entry_usage_to_text(struct printbuf *out, struct bch_fs *c,
					struct jset_entry *entry)
{
	struct jset_entry_usage *u =
		container_of(entry, struct jset_entry_usage, entry);

	prt_str(out, "type=");
	bch2_prt_fs_usage_type(out, u->entry.btree_id);
	prt_printf(out, " v=%llu", le64_to_cpu(u->v));
}

static int journal_entry_data_usage_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	struct jset_entry_data_usage *u =
		container_of(entry, struct jset_entry_data_usage, entry);
	unsigned bytes = jset_u64s(le16_to_cpu(entry->u64s)) * sizeof(u64);
	CLASS(printbuf, err)();
	int ret = 0;

	if (journal_entry_err_on(bytes < sizeof(*u) ||
				 bytes < sizeof(*u) + u->r.nr_devs,
				 c, version, jset, entry,
				 journal_entry_data_usage_bad_size,
				 "invalid journal entry usage: bad size")) {
		journal_entry_null_range(entry, vstruct_next(entry));
		return 0;
	}

	if (journal_entry_err_on(bch2_replicas_entry_validate(&u->r, c, &err),
				 c, version, jset, entry,
				 journal_entry_data_usage_bad_size,
				 "invalid journal entry usage: %s", err.buf)) {
		journal_entry_null_range(entry, vstruct_next(entry));
		return 0;
	}
fsck_err:
	return ret;
}

static void journal_entry_data_usage_to_text(struct printbuf *out, struct bch_fs *c,
					     struct jset_entry *entry)
{
	struct jset_entry_data_usage *u =
		container_of(entry, struct jset_entry_data_usage, entry);

	bch2_replicas_entry_to_text(out, &u->r);
	prt_printf(out, "=%llu", le64_to_cpu(u->v));
}

static int journal_entry_clock_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	struct jset_entry_clock *clock =
		container_of(entry, struct jset_entry_clock, entry);
	unsigned bytes = jset_u64s(le16_to_cpu(entry->u64s)) * sizeof(u64);
	int ret = 0;

	if (journal_entry_err_on(bytes != sizeof(*clock),
				 c, version, jset, entry,
				 journal_entry_clock_bad_size,
				 "bad size")) {
		journal_entry_null_range(entry, vstruct_next(entry));
		return ret;
	}

	if (journal_entry_err_on(clock->rw > 1,
				 c, version, jset, entry,
				 journal_entry_clock_bad_rw,
				 "bad rw")) {
		journal_entry_null_range(entry, vstruct_next(entry));
		return ret;
	}

fsck_err:
	return ret;
}

static void journal_entry_clock_to_text(struct printbuf *out, struct bch_fs *c,
					struct jset_entry *entry)
{
	struct jset_entry_clock *clock =
		container_of(entry, struct jset_entry_clock, entry);

	prt_printf(out, "%s=%llu", str_write_read(clock->rw), le64_to_cpu(clock->time));
}

static int journal_entry_dev_usage_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	struct jset_entry_dev_usage *u =
		container_of(entry, struct jset_entry_dev_usage, entry);
	unsigned bytes = jset_u64s(le16_to_cpu(entry->u64s)) * sizeof(u64);
	unsigned expected = sizeof(*u);
	int ret = 0;

	if (journal_entry_err_on(bytes < expected,
				 c, version, jset, entry,
				 journal_entry_dev_usage_bad_size,
				 "bad size (%u < %u)",
				 bytes, expected)) {
		journal_entry_null_range(entry, vstruct_next(entry));
		return ret;
	}

	if (journal_entry_err_on(u->pad,
				 c, version, jset, entry,
				 journal_entry_dev_usage_bad_pad,
				 "bad pad")) {
		journal_entry_null_range(entry, vstruct_next(entry));
		return ret;
	}

fsck_err:
	return ret;
}

static void journal_entry_dev_usage_to_text(struct printbuf *out, struct bch_fs *c,
					    struct jset_entry *entry)
{
	struct jset_entry_dev_usage *u =
		container_of(entry, struct jset_entry_dev_usage, entry);
	unsigned i, nr_types = jset_entry_dev_usage_nr_types(u);

	if (vstruct_bytes(entry) < sizeof(*u))
		return;

	prt_printf(out, "dev=%u", le32_to_cpu(u->dev));

	printbuf_indent_add(out, 2);
	for (i = 0; i < nr_types; i++) {
		prt_newline(out);
		bch2_prt_data_type(out, i);
		prt_printf(out, ": buckets=%llu sectors=%llu fragmented=%llu",
		       le64_to_cpu(u->d[i].buckets),
		       le64_to_cpu(u->d[i].sectors),
		       le64_to_cpu(u->d[i].fragmented));
	}
	printbuf_indent_sub(out, 2);
}

static int journal_entry_log_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	return 0;
}

static void journal_entry_log_to_text(struct printbuf *out, struct bch_fs *c,
				      struct jset_entry *entry)
{
	struct jset_entry_log *l = container_of(entry, struct jset_entry_log, entry);

	prt_printf(out, "%.*s", jset_entry_log_msg_bytes(l), l->d);
}

static int journal_entry_overwrite_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	from.flags = 0;
	return journal_entry_btree_keys_validate(c, jset, entry,
				version, big_endian, from);
}

static void journal_entry_overwrite_to_text(struct printbuf *out, struct bch_fs *c,
					    struct jset_entry *entry)
{
	journal_entry_btree_keys_to_text(out, c, entry);
}

static int journal_entry_log_bkey_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	from.flags = 0;
	return journal_entry_btree_keys_validate(c, jset, entry,
				version, big_endian, from);
}

static void journal_entry_log_bkey_to_text(struct printbuf *out, struct bch_fs *c,
					   struct jset_entry *entry)
{
	journal_entry_btree_keys_to_text(out, c, entry);
}

static int journal_entry_write_buffer_keys_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	return journal_entry_btree_keys_validate(c, jset, entry,
				version, big_endian, from);
}

static void journal_entry_write_buffer_keys_to_text(struct printbuf *out, struct bch_fs *c,
					    struct jset_entry *entry)
{
	journal_entry_btree_keys_to_text(out, c, entry);
}

static int journal_entry_datetime_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	unsigned bytes = vstruct_bytes(entry);
	unsigned expected = 16;
	int ret = 0;

	if (journal_entry_err_on(vstruct_bytes(entry) < expected,
				 c, version, jset, entry,
				 journal_entry_dev_usage_bad_size,
				 "bad size (%u < %u)",
				 bytes, expected)) {
		journal_entry_null_range(entry, vstruct_next(entry));
		return ret;
	}
fsck_err:
	return ret;
}

static void journal_entry_datetime_to_text(struct printbuf *out, struct bch_fs *c,
					    struct jset_entry *entry)
{
	struct jset_entry_datetime *datetime =
		container_of(entry, struct jset_entry_datetime, entry);

	bch2_prt_datetime(out, le64_to_cpu(datetime->seconds));
}

struct jset_entry_ops {
	int (*validate)(struct bch_fs *, struct jset *,
			struct jset_entry *, unsigned, int,
			struct bkey_validate_context);
	void (*to_text)(struct printbuf *, struct bch_fs *, struct jset_entry *);
};

static const struct jset_entry_ops bch2_jset_entry_ops[] = {
#define x(f, nr)						\
	[BCH_JSET_ENTRY_##f]	= (struct jset_entry_ops) {	\
		.validate	= journal_entry_##f##_validate,	\
		.to_text	= journal_entry_##f##_to_text,	\
	},
	BCH_JSET_ENTRY_TYPES()
#undef x
};

int bch2_journal_entry_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	return entry->type < BCH_JSET_ENTRY_NR
		? bch2_jset_entry_ops[entry->type].validate(c, jset, entry,
				version, big_endian, from)
		: 0;
}

void bch2_journal_entry_to_text(struct printbuf *out, struct bch_fs *c,
				struct jset_entry *entry)
{
	bch2_prt_jset_entry_type(out, entry->type);

	if (entry->type < BCH_JSET_ENTRY_NR) {
		prt_str(out, ": ");
		bch2_jset_entry_ops[entry->type].to_text(out, c, entry);
	}
}

static int jset_validate_entries(struct bch_fs *c, struct jset *jset,
				 enum bch_validate_flags flags)
{
	struct bkey_validate_context from = {
		.flags		= flags,
		.from		= BKEY_VALIDATE_journal,
		.journal_seq	= le64_to_cpu(jset->seq),
	};

	unsigned version = le32_to_cpu(jset->version);
	int ret = 0;

	vstruct_for_each(jset, entry) {
		from.journal_offset = (u64 *) entry - jset->_data;

		if (journal_entry_err_on(vstruct_next(entry) > vstruct_last(jset),
				c, version, jset, entry,
				journal_entry_past_jset_end,
				"journal entry extends past end of jset")) {
			jset->u64s = cpu_to_le32((u64 *) entry - jset->_data);
			break;
		}

		ret = bch2_journal_entry_validate(c, jset, entry, version,
						  JSET_BIG_ENDIAN(jset), from);
		if (ret)
			break;
	}
fsck_err:
	return ret;
}

static int jset_validate(struct bch_fs *c,
			 struct bch_dev *ca,
			 struct jset *jset, u64 sector,
			 enum bch_validate_flags flags)
{
	struct bkey_validate_context from = {
		.flags		= flags,
		.from		= BKEY_VALIDATE_journal,
		.journal_seq	= le64_to_cpu(jset->seq),
	};
	int ret = 0;

	if (le64_to_cpu(jset->magic) != jset_magic(c))
		return JOURNAL_ENTRY_NONE;

	unsigned version = le32_to_cpu(jset->version);
	if (journal_entry_err_on(!bch2_version_compatible(version),
			c, version, jset, NULL,
			jset_unsupported_version,
			"%s sector %llu seq %llu: incompatible journal entry version %u.%u",
			ca ? ca->name : c->name,
			sector, le64_to_cpu(jset->seq),
			BCH_VERSION_MAJOR(version),
			BCH_VERSION_MINOR(version))) {
		/* don't try to continue: */
		return -EINVAL;
	}

	if (journal_entry_err_on(!bch2_checksum_type_valid(c, JSET_CSUM_TYPE(jset)),
			c, version, jset, NULL,
			jset_unknown_csum,
			"%s sector %llu seq %llu: journal entry with unknown csum type %llu",
			ca ? ca->name : c->name,
			sector, le64_to_cpu(jset->seq),
			JSET_CSUM_TYPE(jset)))
		ret = JOURNAL_ENTRY_BAD;

	/* last_seq is ignored when JSET_NO_FLUSH is true */
	if (journal_entry_err_on(!JSET_NO_FLUSH(jset) &&
				 le64_to_cpu(jset->last_seq) > le64_to_cpu(jset->seq),
				 c, version, jset, NULL,
				 jset_last_seq_newer_than_seq,
				 "invalid journal entry: last_seq > seq (%llu > %llu)",
				 le64_to_cpu(jset->last_seq),
				 le64_to_cpu(jset->seq))) {
		jset->last_seq = jset->seq;
		return JOURNAL_ENTRY_BAD;
	}

	ret = jset_validate_entries(c, jset, flags);
fsck_err:
	return ret;
}

static int jset_validate_early(struct bch_fs *c,
			 struct bch_dev *ca,
			 struct jset *jset, u64 sector,
			 unsigned bucket_sectors_left,
			 unsigned sectors_read)
{
	struct bkey_validate_context from = {
		.from		= BKEY_VALIDATE_journal,
		.journal_seq	= le64_to_cpu(jset->seq),
	};
	int ret = 0;

	if (le64_to_cpu(jset->magic) != jset_magic(c))
		return JOURNAL_ENTRY_NONE;

	unsigned version = le32_to_cpu(jset->version);
	if (journal_entry_err_on(!bch2_version_compatible(version),
			c, version, jset, NULL,
			jset_unsupported_version,
			"%s sector %llu seq %llu: unknown journal entry version %u.%u",
			ca ? ca->name : c->name,
			sector, le64_to_cpu(jset->seq),
			BCH_VERSION_MAJOR(version),
			BCH_VERSION_MINOR(version))) {
		/* don't try to continue: */
		return -EINVAL;
	}

	size_t bytes = vstruct_bytes(jset);
	if (bytes > (sectors_read << 9) &&
	    sectors_read < bucket_sectors_left)
		return JOURNAL_ENTRY_REREAD;

	if (journal_entry_err_on(bytes > bucket_sectors_left << 9,
			c, version, jset, NULL,
			jset_past_bucket_end,
			"%s sector %llu seq %llu: journal entry too big (%zu bytes)",
			ca ? ca->name : c->name,
			sector, le64_to_cpu(jset->seq), bytes))
		le32_add_cpu(&jset->u64s,
			     -((bytes - (bucket_sectors_left << 9)) / 8));
fsck_err:
	return ret;
}

struct journal_read_buf {
	void		*data;
	size_t		size;
};

static int journal_read_buf_realloc(struct bch_fs *c, struct journal_read_buf *b,
				    size_t new_size)
{
	void *n;

	/* the bios are sized for this many pages, max: */
	if (new_size > JOURNAL_ENTRY_SIZE_MAX)
		return bch_err_throw(c, ENOMEM_journal_read_buf_realloc);

	new_size = roundup_pow_of_two(new_size);
	n = kvmalloc(new_size, GFP_KERNEL);
	if (!n)
		return bch_err_throw(c, ENOMEM_journal_read_buf_realloc);

	kvfree(b->data);
	b->data = n;
	b->size = new_size;
	return 0;
}

static int journal_read_bucket(struct bch_dev *ca,
			       struct journal_read_buf *buf,
			       struct journal_list *jlist,
			       unsigned bucket)
{
	struct bch_fs *c = ca->fs;
	struct journal_device *ja = &ca->journal;
	struct jset *j = NULL;
	unsigned sectors, sectors_read = 0;
	u64 offset = bucket_to_sector(ca, ja->buckets[bucket]),
	    end = offset + ca->mi.bucket_size;
	bool saw_bad = false, csum_good;
	int ret = 0;

	pr_debug("reading %u", bucket);

	while (offset < end) {
		if (!sectors_read) {
			struct bio *bio;
			unsigned nr_bvecs;
reread:
			sectors_read = min_t(unsigned,
				end - offset, buf->size >> 9);
			nr_bvecs = buf_pages(buf->data, sectors_read << 9);

			bio = bio_kmalloc(nr_bvecs, GFP_KERNEL);
			if (!bio)
				return bch_err_throw(c, ENOMEM_journal_read_bucket);
			bio_init(bio, ca->disk_sb.bdev, bio->bi_inline_vecs, nr_bvecs, REQ_OP_READ);

			bio->bi_iter.bi_sector = offset;
			bch2_bio_map(bio, buf->data, sectors_read << 9);

			u64 submit_time = local_clock();
			ret = submit_bio_wait(bio);
			kfree(bio);

			if (!ret && bch2_meta_read_fault("journal"))
				ret = bch_err_throw(c, EIO_fault_injected);

			bch2_account_io_completion(ca, BCH_MEMBER_ERROR_read,
						   submit_time, !ret);

			if (ret) {
				bch_err_dev_ratelimited(ca,
					"journal read error: sector %llu", offset);
				/*
				 * We don't error out of the recovery process
				 * here, since the relevant journal entry may be
				 * found on a different device, and missing or
				 * no journal entries will be handled later
				 */
				return 0;
			}

			j = buf->data;
		}

		ret = jset_validate_early(c, ca, j, offset,
				    end - offset, sectors_read);
		switch (ret) {
		case 0:
			sectors = vstruct_sectors(j, c->block_bits);
			break;
		case JOURNAL_ENTRY_REREAD:
			if (vstruct_bytes(j) > buf->size) {
				ret = journal_read_buf_realloc(c, buf,
							vstruct_bytes(j));
				if (ret)
					return ret;
			}
			goto reread;
		case JOURNAL_ENTRY_NONE:
			if (!saw_bad)
				return 0;
			/*
			 * On checksum error we don't really trust the size
			 * field of the journal entry we read, so try reading
			 * again at next block boundary:
			 */
			sectors = block_sectors(c);
			goto next_block;
		default:
			return ret;
		}

		if (le64_to_cpu(j->seq) > ja->highest_seq_found) {
			ja->highest_seq_found = le64_to_cpu(j->seq);
			ja->cur_idx = bucket;
			ja->sectors_free = ca->mi.bucket_size -
				bucket_remainder(ca, offset) - sectors;
		}

		/*
		 * This happens sometimes if we don't have discards on -
		 * when we've partially overwritten a bucket with new
		 * journal entries. We don't need the rest of the
		 * bucket:
		 */
		if (le64_to_cpu(j->seq) < ja->bucket_seq[bucket])
			return 0;

		ja->bucket_seq[bucket] = le64_to_cpu(j->seq);

		struct bch_csum csum;
		csum_good = jset_csum_good(c, j, &csum);

		bch2_account_io_completion(ca, BCH_MEMBER_ERROR_checksum, 0, csum_good);

		if (!csum_good) {
			/*
			 * Don't print an error here, we'll print the error
			 * later if we need this journal entry
			 */
			saw_bad = true;
		}

		ret = bch2_encrypt(c, JSET_CSUM_TYPE(j), journal_nonce(j),
			     j->encrypted_start,
			     vstruct_end(j) - (void *) j->encrypted_start);
		bch2_fs_fatal_err_on(ret, c, "decrypting journal entry: %s", bch2_err_str(ret));

		scoped_guard(mutex, &jlist->lock)
			ret = journal_entry_add(c, ca, (struct journal_ptr) {
						.csum_good	= csum_good,
						.csum		= csum,
						.dev		= ca->dev_idx,
						.bucket		= bucket,
						.bucket_offset	= offset -
							bucket_to_sector(ca, ja->buckets[bucket]),
						.sector		= offset,
						}, jlist, j);

		switch (ret) {
		case JOURNAL_ENTRY_ADD_OK:
			break;
		case JOURNAL_ENTRY_ADD_OUT_OF_RANGE:
			break;
		default:
			return ret;
		}
next_block:
		pr_debug("next");
		offset		+= sectors;
		sectors_read	-= sectors;
		j = ((void *) j) + (sectors << 9);
	}

	return 0;
}

static CLOSURE_CALLBACK(bch2_journal_read_device)
{
	closure_type(ja, struct journal_device, read);
	struct bch_dev *ca = container_of(ja, struct bch_dev, journal);
	struct bch_fs *c = ca->fs;
	struct journal_list *jlist =
		container_of(cl->parent, struct journal_list, cl);
	struct journal_read_buf buf = { NULL, 0 };
	unsigned i;
	int ret = 0;

	if (!ja->nr)
		goto out;

	ret = journal_read_buf_realloc(c, &buf, PAGE_SIZE);
	if (ret)
		goto err;

	pr_debug("%u journal buckets", ja->nr);

	for (i = 0; i < ja->nr; i++) {
		ret = journal_read_bucket(ca, &buf, jlist, i);
		if (ret)
			goto err;
	}

	/*
	 * Set dirty_idx to indicate the entire journal is full and needs to be
	 * reclaimed - journal reclaim will immediately reclaim whatever isn't
	 * pinned when it first runs:
	 */
	ja->discard_idx = ja->dirty_idx_ondisk =
		ja->dirty_idx = (ja->cur_idx + 1) % ja->nr;
out:
	bch_verbose(c, "journal read done on device %s, ret %i", ca->name, ret);
	kvfree(buf.data);
	enumerated_ref_put(&ca->io_ref[READ], BCH_DEV_READ_REF_journal_read);
	closure_return(cl);
	return;
err:
	scoped_guard(mutex, &jlist->lock)
		jlist->ret = ret;
	goto out;
}

noinline_for_stack
static void bch2_journal_print_checksum_error(struct bch_fs *c, struct journal_replay *j)
{
	CLASS(printbuf, buf)();
	bch2_log_msg_start(c, &buf);

	enum bch_csum_type csum_type = JSET_CSUM_TYPE(&j->j);
	bool have_good = false;

	prt_printf(&buf, "invalid journal checksum(s) at seq %llu ", le64_to_cpu(j->j.seq));
	bch2_journal_datetime_to_text(&buf, &j->j);
	prt_newline(&buf);

	darray_for_each(j->ptrs, ptr)
		if (!ptr->csum_good) {
			bch2_journal_ptr_to_text(&buf, c, ptr);
			prt_char(&buf, ' ');
			bch2_csum_to_text(&buf, csum_type, ptr->csum);
			prt_newline(&buf);
		} else {
			have_good = true;
		}

	prt_printf(&buf, "should be ");
	bch2_csum_to_text(&buf, csum_type, j->j.csum);

	if (have_good)
		prt_printf(&buf, "\n(had good copy on another device)");

	bch2_print_str(c, KERN_ERR, buf.buf);
}

struct u64_range bch2_journal_entry_missing_range(struct bch_fs *c, u64 start, u64 end)
{
	BUG_ON(start > end);

	if (start == end)
		return (struct u64_range) {};

	start = bch2_journal_seq_next_nonblacklisted(c, start);
	if (start >= end)
		return (struct u64_range) {};

	struct u64_range missing = {
		.start	= start,
		.end	= min(end, bch2_journal_seq_next_blacklisted(c, start)),
	};

	if (missing.start == missing.end)
		return (struct u64_range) {};

	return missing;
}

noinline_for_stack
static int bch2_journal_check_for_missing(struct bch_fs *c, u64 start_seq, u64 end_seq)
{
	int ret = 0;

	struct genradix_iter radix_iter;
	struct journal_replay *i, **_i, *prev = NULL;
	/* Sequence number we expect to find next, to check for missing entries */
	u64 seq = start_seq;

	genradix_for_each(&c->journal_entries, radix_iter, _i) {
		i = *_i;

		if (journal_replay_ignore(i))
			continue;

		BUG_ON(seq > le64_to_cpu(i->j.seq));

		struct u64_range missing;

		while ((missing = bch2_journal_entry_missing_range(c, seq, le64_to_cpu(i->j.seq))).start) {
			CLASS(printbuf, buf)();
			prt_printf(&buf, "journal entries %llu-%llu missing! (replaying %llu-%llu)",
				   missing.start, missing.end - 1,
				   start_seq, end_seq);

			if (prev) {
				prt_printf(&buf, "\n%llu at ", le64_to_cpu(prev->j.seq));
				bch2_journal_ptrs_to_text(&buf, c, prev);
				prt_printf(&buf, " size %zu", vstruct_sectors(&prev->j, c->block_bits));
			}

			prt_printf(&buf, "\n%llu at ", le64_to_cpu(i->j.seq));
			bch2_journal_ptrs_to_text(&buf, c, i);
			prt_printf(&buf, ", continue?");

			fsck_err(c, journal_entries_missing, "%s", buf.buf);

			seq = missing.end;
		}

		prev = i;
		seq = le64_to_cpu(i->j.seq) + 1;
	}
fsck_err:
	return ret;
}

int bch2_journal_read(struct bch_fs *c,
		      u64 *last_seq,
		      u64 *blacklist_seq,
		      u64 *start_seq)
{
	struct journal_list jlist;
	struct journal_replay *i, **_i;
	struct genradix_iter radix_iter;
	bool degraded = false, last_write_torn = false;
	u64 seq;
	int ret = 0;

	closure_init_stack(&jlist.cl);
	mutex_init(&jlist.lock);
	jlist.last_seq = 0;
	jlist.ret = 0;

	for_each_member_device(c, ca) {
		if (!c->opts.fsck &&
		    !(bch2_dev_has_data(c, ca) & (1 << BCH_DATA_journal)))
			continue;

		if ((ca->mi.state == BCH_MEMBER_STATE_rw ||
		     ca->mi.state == BCH_MEMBER_STATE_ro) &&
		    enumerated_ref_tryget(&ca->io_ref[READ],
					  BCH_DEV_READ_REF_journal_read))
			closure_call(&ca->journal.read,
				     bch2_journal_read_device,
				     system_unbound_wq,
				     &jlist.cl);
		else
			degraded = true;
	}

	while (closure_sync_timeout(&jlist.cl, sysctl_hung_task_timeout_secs * HZ / 2))
		;

	if (jlist.ret)
		return jlist.ret;

	*last_seq	= 0;
	*start_seq	= 0;
	*blacklist_seq	= 0;

	/*
	 * Find most recent flush entry, and ignore newer non flush entries -
	 * those entries will be blacklisted:
	 */
	genradix_for_each_reverse(&c->journal_entries, radix_iter, _i) {
		i = *_i;

		if (journal_replay_ignore(i))
			continue;

		if (!*start_seq)
			*blacklist_seq = *start_seq = le64_to_cpu(i->j.seq) + 1;

		if (JSET_NO_FLUSH(&i->j)) {
			i->ignore_blacklisted = true;
			continue;
		}

		if (!last_write_torn && !i->csum_good) {
			last_write_torn = true;
			i->ignore_blacklisted = true;
			continue;
		}

		struct bkey_validate_context from = {
			.from		= BKEY_VALIDATE_journal,
			.journal_seq	= le64_to_cpu(i->j.seq),
		};
		if (journal_entry_err_on(le64_to_cpu(i->j.last_seq) > le64_to_cpu(i->j.seq),
					 c, le32_to_cpu(i->j.version), &i->j, NULL,
					 jset_last_seq_newer_than_seq,
					 "invalid journal entry: last_seq > seq (%llu > %llu)",
					 le64_to_cpu(i->j.last_seq),
					 le64_to_cpu(i->j.seq)))
			i->j.last_seq = i->j.seq;

		*last_seq	= le64_to_cpu(i->j.last_seq);
		*blacklist_seq	= le64_to_cpu(i->j.seq) + 1;
		break;
	}

	if (!*start_seq) {
		bch_info(c, "journal read done, but no entries found");
		return 0;
	}

	if (!*last_seq) {
		fsck_err(c, dirty_but_no_journal_entries_post_drop_nonflushes,
			 "journal read done, but no entries found after dropping non-flushes");
		return 0;
	}

	u64 drop_before = *last_seq;
	{
		CLASS(printbuf, buf)();
		prt_printf(&buf, "journal read done, replaying entries %llu-%llu",
			   *last_seq, *blacklist_seq - 1);

		/*
		 * Drop blacklisted entries and entries older than last_seq (or start of
		 * journal rewind:
		 */
		if (c->opts.journal_rewind) {
			drop_before = min(drop_before, c->opts.journal_rewind);
			prt_printf(&buf, " (rewinding from %llu)", c->opts.journal_rewind);
		}

		*last_seq = drop_before;
		if (*start_seq != *blacklist_seq)
			prt_printf(&buf, " (unflushed %llu-%llu)", *blacklist_seq, *start_seq - 1);
		bch_info(c, "%s", buf.buf);
	}

	genradix_for_each(&c->journal_entries, radix_iter, _i) {
		i = *_i;

		if (journal_replay_ignore(i))
			continue;

		seq = le64_to_cpu(i->j.seq);
		if (seq < drop_before) {
			journal_replay_free(c, i, false);
			continue;
		}

		if (bch2_journal_seq_is_blacklisted(c, seq, true)) {
			fsck_err_on(!JSET_NO_FLUSH(&i->j), c,
				    jset_seq_blacklisted,
				    "found blacklisted journal entry %llu", seq);
			i->ignore_blacklisted = true;
		}
	}

	ret = bch2_journal_check_for_missing(c, drop_before, *blacklist_seq - 1);
	if (ret)
		return ret;

	genradix_for_each(&c->journal_entries, radix_iter, _i) {
		union bch_replicas_padded replicas = {
			.e.data_type = BCH_DATA_journal,
			.e.nr_devs = 0,
			.e.nr_required = 1,
		};

		i = *_i;
		if (journal_replay_ignore(i))
			continue;

		/*
		 * Don't print checksum errors until we know we're going to use
		 * a given journal entry:
		 */
		darray_for_each(i->ptrs, ptr)
			if (!ptr->csum_good) {
				bch2_journal_print_checksum_error(c, i);
				break;
			}

		ret = jset_validate(c,
				    bch2_dev_have_ref(c, i->ptrs.data[0].dev),
				    &i->j,
				    i->ptrs.data[0].sector,
				    READ);
		if (ret)
			return ret;

		darray_for_each(i->ptrs, ptr)
			replicas_entry_add_dev(&replicas.e, ptr->dev);

		bch2_replicas_entry_sort(&replicas.e);

		CLASS(printbuf, buf)();
		bch2_replicas_entry_to_text(&buf, &replicas.e);

		if (!degraded &&
		    !bch2_replicas_marked(c, &replicas.e) &&
		    (le64_to_cpu(i->j.seq) == *last_seq ||
		     fsck_err(c, journal_entry_replicas_not_marked,
			      "superblock not marked as containing replicas for journal entry %llu\n%s",
			      le64_to_cpu(i->j.seq), buf.buf))) {
			ret = bch2_mark_replicas(c, &replicas.e);
			if (ret)
				return ret;
		}
	}
fsck_err:
	return ret;
}

/* journal write: */

static void journal_advance_devs_to_next_bucket(struct journal *j,
						struct dev_alloc_list *devs,
						unsigned sectors, __le64 seq)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	guard(rcu)();
	darray_for_each(*devs, i) {
		struct bch_dev *ca = rcu_dereference(c->devs[*i]);
		if (!ca)
			continue;

		struct journal_device *ja = &ca->journal;

		if (sectors > ja->sectors_free &&
		    sectors <= ca->mi.bucket_size &&
		    bch2_journal_dev_buckets_available(j, ja,
					journal_space_discarded)) {
			ja->cur_idx = (ja->cur_idx + 1) % ja->nr;
			ja->sectors_free = ca->mi.bucket_size;

			/*
			 * ja->bucket_seq[ja->cur_idx] must always have
			 * something sensible:
			 */
			ja->bucket_seq[ja->cur_idx] = le64_to_cpu(seq);
		}
	}
}

static void __journal_write_alloc(struct journal *j,
				  struct journal_buf *w,
				  struct dev_alloc_list *devs,
				  unsigned sectors,
				  unsigned *replicas,
				  unsigned replicas_want)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	darray_for_each(*devs, i) {
		struct bch_dev *ca = bch2_dev_get_ioref(c, *i, WRITE,
					BCH_DEV_WRITE_REF_journal_write);
		if (!ca)
			continue;

		struct journal_device *ja = &ca->journal;

		/*
		 * Check that we can use this device, and aren't already using
		 * it:
		 */
		if (!ca->mi.durability ||
		    ca->mi.state != BCH_MEMBER_STATE_rw ||
		    !ja->nr ||
		    bch2_bkey_has_device_c(bkey_i_to_s_c(&w->key), ca->dev_idx) ||
		    sectors > ja->sectors_free) {
			enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_journal_write);
			continue;
		}

		bch2_dev_stripe_increment(ca, &j->wp.stripe);

		bch2_bkey_append_ptr(&w->key,
			(struct bch_extent_ptr) {
				  .offset = bucket_to_sector(ca,
					ja->buckets[ja->cur_idx]) +
					ca->mi.bucket_size -
					ja->sectors_free,
				  .dev = ca->dev_idx,
		});

		ja->sectors_free -= sectors;
		ja->bucket_seq[ja->cur_idx] = le64_to_cpu(w->data->seq);

		*replicas += ca->mi.durability;

		if (*replicas >= replicas_want)
			break;
	}
}

static int journal_write_alloc(struct journal *j, struct journal_buf *w,
			       unsigned *replicas)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct bch_devs_mask devs;
	struct dev_alloc_list devs_sorted;
	unsigned sectors = vstruct_sectors(w->data, c->block_bits);
	unsigned target = c->opts.metadata_target ?:
		c->opts.foreground_target;
	unsigned replicas_want = READ_ONCE(c->opts.metadata_replicas);
	unsigned replicas_need = min_t(unsigned, replicas_want,
				       READ_ONCE(c->opts.metadata_replicas_required));
	bool advance_done = false;

retry_target:
	devs = target_rw_devs(c, BCH_DATA_journal, target);
	bch2_dev_alloc_list(c, &j->wp.stripe, &devs, &devs_sorted);
retry_alloc:
	__journal_write_alloc(j, w, &devs_sorted, sectors, replicas, replicas_want);

	if (likely(*replicas >= replicas_want))
		goto done;

	if (!advance_done) {
		journal_advance_devs_to_next_bucket(j, &devs_sorted, sectors, w->data->seq);
		advance_done = true;
		goto retry_alloc;
	}

	if (*replicas < replicas_want && target) {
		/* Retry from all devices: */
		target = 0;
		advance_done = false;
		goto retry_target;
	}
done:
	BUG_ON(bkey_val_u64s(&w->key.k) > BCH_REPLICAS_MAX);

#if 0
	/*
	 * XXX: we need a way to alert the user when we go degraded for any
	 * reason
	 */
	if (*replicas < min(replicas_want,
			    dev_mask_nr(&c->rw_devs[BCH_DATA_free]))) {
	}
#endif

	return *replicas >= replicas_need ? 0 : -BCH_ERR_insufficient_journal_devices;
}

static void journal_buf_realloc(struct journal *j, struct journal_buf *buf)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	/* we aren't holding j->lock: */
	unsigned new_size = READ_ONCE(j->buf_size_want);
	void *new_buf;

	if (buf->buf_size >= new_size)
		return;

	size_t btree_write_buffer_size = new_size / 64;

	if (bch2_btree_write_buffer_resize(c, btree_write_buffer_size))
		return;

	new_buf = kvmalloc(new_size, GFP_NOFS|__GFP_NOWARN);
	if (!new_buf)
		return;

	memcpy(new_buf, buf->data, buf->buf_size);

	scoped_guard(spinlock, &j->lock) {
		swap(buf->data,		new_buf);
		swap(buf->buf_size,	new_size);
	}

	kvfree(new_buf);
}

static CLOSURE_CALLBACK(journal_write_done)
{
	closure_type(w, struct journal_buf, io);
	struct journal *j = container_of(w, struct journal, buf[w->idx]);
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	union bch_replicas_padded replicas;
	u64 seq = le64_to_cpu(w->data->seq);
	int err = 0;

	bch2_time_stats_update(!JSET_NO_FLUSH(w->data)
			       ? j->flush_write_time
			       : j->noflush_write_time, j->write_start_time);

	if (!w->devs_written.nr) {
		err = bch_err_throw(c, journal_write_err);
	} else {
		bch2_devlist_to_replicas(&replicas.e, BCH_DATA_journal,
					 w->devs_written);
		err = bch2_mark_replicas(c, &replicas.e);
	}

	if (err && !bch2_journal_error(j)) {
		CLASS(printbuf, buf)();
		bch2_log_msg_start(c, &buf);

		if (err == -BCH_ERR_journal_write_err)
			prt_printf(&buf, "unable to write journal to sufficient devices\n");
		else
			prt_printf(&buf, "journal write error marking replicas: %s\n",
				   bch2_err_str(err));

		bch2_fs_emergency_read_only2(c, &buf);

		bch2_print_str(c, KERN_ERR, buf.buf);
	}

	closure_debug_destroy(cl);

	spin_lock(&j->lock);
	if (seq >= j->pin.front)
		journal_seq_pin(j, seq)->devs = w->devs_written;
	if (err && (!j->err_seq || seq < j->err_seq))
		j->err_seq	= seq;
	w->write_done = true;

	if (!j->free_buf || j->free_buf_size < w->buf_size) {
		swap(j->free_buf,	w->data);
		swap(j->free_buf_size,	w->buf_size);
	}

	if (w->data) {
		void *buf = w->data;
		w->data = NULL;
		w->buf_size = 0;

		spin_unlock(&j->lock);
		kvfree(buf);
		spin_lock(&j->lock);
	}

	bool completed = false;
	bool do_discards = false;

	for (seq = journal_last_unwritten_seq(j);
	     seq <= journal_cur_seq(j);
	     seq++) {
		w = j->buf + (seq & JOURNAL_BUF_MASK);
		if (!w->write_done)
			break;

		if (!j->err_seq && !w->noflush) {
			j->flushed_seq_ondisk = seq;
			j->last_seq_ondisk = w->last_seq;

			closure_wake_up(&c->freelist_wait);
			bch2_reset_alloc_cursors(c);
			do_discards = true;
		}

		j->seq_ondisk = seq;

		/*
		 * Updating last_seq_ondisk may let bch2_journal_reclaim_work() discard
		 * more buckets:
		 *
		 * Must come before signaling write completion, for
		 * bch2_fs_journal_stop():
		 */
		if (j->watermark != BCH_WATERMARK_stripe)
			journal_reclaim_kick(&c->journal);

		closure_wake_up(&w->wait);
		completed = true;
	}

	if (completed) {
		bch2_journal_reclaim_fast(j);
		bch2_journal_space_available(j);

		track_event_change(&c->times[BCH_TIME_blocked_journal_max_in_flight], false);

		journal_wake(j);
	}

	if (journal_last_unwritten_seq(j) == journal_cur_seq(j) &&
	    j->reservations.cur_entry_offset < JOURNAL_ENTRY_CLOSED_VAL) {
		struct journal_buf *buf = journal_cur_buf(j);
		long delta = buf->expires - jiffies;

		/*
		 * We don't close a journal entry to write it while there's
		 * previous entries still in flight - the current journal entry
		 * might want to be written now:
		 */
		mod_delayed_work(j->wq, &j->write_work, max(0L, delta));
	}

	/*
	 * We don't typically trigger journal writes from her - the next journal
	 * write will be triggered immediately after the previous one is
	 * allocated, in bch2_journal_write() - but the journal write error path
	 * is special:
	 */
	bch2_journal_do_writes(j);
	spin_unlock(&j->lock);

	if (do_discards)
		bch2_do_discards(c);

	closure_put(&c->cl);
}

static void journal_write_endio(struct bio *bio)
{
	struct journal_bio *jbio = container_of(bio, struct journal_bio, bio);
	struct bch_dev *ca = jbio->ca;
	struct journal *j = &ca->fs->journal;
	struct journal_buf *w = j->buf + jbio->buf_idx;

	bch2_account_io_completion(ca, BCH_MEMBER_ERROR_write,
				   jbio->submit_time, !bio->bi_status);

	if (bio->bi_status) {
		bch_err_dev_ratelimited(ca,
			       "error writing journal entry %llu: %s",
			       le64_to_cpu(w->data->seq),
			       bch2_blk_status_to_str(bio->bi_status));

		unsigned long flags;
		spin_lock_irqsave(&j->err_lock, flags);
		bch2_dev_list_drop_dev(&w->devs_written, ca->dev_idx);
		spin_unlock_irqrestore(&j->err_lock, flags);
	}

	closure_put(&w->io);
	enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_journal_write);
}

static CLOSURE_CALLBACK(journal_write_submit)
{
	closure_type(w, struct journal_buf, io);
	struct journal *j = container_of(w, struct journal, buf[w->idx]);
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	unsigned sectors = vstruct_sectors(w->data, c->block_bits);

	extent_for_each_ptr(bkey_i_to_s_extent(&w->key), ptr) {
		struct bch_dev *ca = bch2_dev_have_ref(c, ptr->dev);

		this_cpu_add(ca->io_done->sectors[WRITE][BCH_DATA_journal],
			     sectors);

		struct journal_device *ja = &ca->journal;
		struct journal_bio *jbio = ja->bio[w->idx];
		struct bio *bio = &jbio->bio;

		jbio->submit_time	= local_clock();

		/*
		 * blk-wbt.c throttles all writes except those that have both
		 * REQ_SYNC and REQ_IDLE set...
		 */
		bio_reset(bio, ca->disk_sb.bdev, REQ_OP_WRITE|REQ_SYNC|REQ_IDLE|REQ_META);
		bio->bi_iter.bi_sector	= ptr->offset;
		bio->bi_end_io		= journal_write_endio;
		bio->bi_private		= ca;
		bio->bi_ioprio		= IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 0);

		BUG_ON(bio->bi_iter.bi_sector == ca->prev_journal_sector);
		ca->prev_journal_sector = bio->bi_iter.bi_sector;

		if (!JSET_NO_FLUSH(w->data))
			bio->bi_opf    |= REQ_FUA;
		if (!JSET_NO_FLUSH(w->data) && !w->separate_flush)
			bio->bi_opf    |= REQ_PREFLUSH;

		bch2_bio_map(bio, w->data, sectors << 9);

		trace_and_count(c, journal_write, bio);
		closure_bio_submit(bio, cl);

		ja->bucket_seq[ja->cur_idx] = le64_to_cpu(w->data->seq);
	}

	continue_at(cl, journal_write_done, j->wq);
}

static CLOSURE_CALLBACK(journal_write_preflush)
{
	closure_type(w, struct journal_buf, io);
	struct journal *j = container_of(w, struct journal, buf[w->idx]);
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	/*
	 * Wait for previous journal writes to comelete; they won't necessarily
	 * be flushed if they're still in flight
	 */
	if (j->seq_ondisk + 1 != le64_to_cpu(w->data->seq)) {
		spin_lock(&j->lock);
		if (j->seq_ondisk + 1 != le64_to_cpu(w->data->seq)) {
			closure_wait(&j->async_wait, cl);
			spin_unlock(&j->lock);
			continue_at(cl, journal_write_preflush, j->wq);
			return;
		}
		spin_unlock(&j->lock);
	}

	if (w->separate_flush) {
		for_each_rw_member(c, ca, BCH_DEV_WRITE_REF_journal_write) {
			enumerated_ref_get(&ca->io_ref[WRITE],
					   BCH_DEV_WRITE_REF_journal_write);

			struct journal_device *ja = &ca->journal;
			struct bio *bio = &ja->bio[w->idx]->bio;
			bio_reset(bio, ca->disk_sb.bdev,
				  REQ_OP_WRITE|REQ_SYNC|REQ_META|REQ_PREFLUSH);
			bio->bi_end_io		= journal_write_endio;
			bio->bi_private		= ca;
			closure_bio_submit(bio, cl);
		}

		continue_at(cl, journal_write_submit, j->wq);
	} else {
		/*
		 * no need to punt to another work item if we're not waiting on
		 * preflushes
		 */
		journal_write_submit(&cl->work);
	}
}

static int bch2_journal_write_prep(struct journal *j, struct journal_buf *w)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct jset_entry *start, *end;
	struct jset *jset = w->data;
	struct journal_keys_to_wb wb = { NULL };
	unsigned u64s;
	unsigned long btree_roots_have = 0;
	u64 seq = le64_to_cpu(jset->seq);
	int ret;

	/*
	 * Simple compaction, dropping empty jset_entries (from journal
	 * reservations that weren't fully used) and merging jset_entries that
	 * can be.
	 *
	 * If we wanted to be really fancy here, we could sort all the keys in
	 * the jset and drop keys that were overwritten - probably not worth it:
	 */
	vstruct_for_each(jset, i) {
		unsigned u64s = le16_to_cpu(i->u64s);

		/* Empty entry: */
		if (!u64s)
			continue;

		/*
		 * New btree roots are set by journalling them; when the journal
		 * entry gets written we have to propagate them to
		 * c->btree_roots
		 *
		 * But, every journal entry we write has to contain all the
		 * btree roots (at least for now); so after we copy btree roots
		 * to c->btree_roots we have to get any missing btree roots and
		 * add them to this journal entry:
		 */
		switch (i->type) {
		case BCH_JSET_ENTRY_btree_root:
			bch2_journal_entry_to_btree_root(c, i);
			__set_bit(i->btree_id, &btree_roots_have);
			break;
		case BCH_JSET_ENTRY_write_buffer_keys:
			EBUG_ON(!w->need_flush_to_write_buffer);

			if (!wb.wb)
				bch2_journal_keys_to_write_buffer_start(c, &wb, seq);

			jset_entry_for_each_key(i, k) {
				ret = bch2_journal_key_to_wb(c, &wb, i->btree_id, k);
				if (ret) {
					bch2_fs_fatal_error(c, "flushing journal keys to btree write buffer: %s",
							    bch2_err_str(ret));
					bch2_journal_keys_to_write_buffer_end(c, &wb);
					return ret;
				}
			}
			i->type = BCH_JSET_ENTRY_btree_keys;
			break;
		}
	}

	if (wb.wb) {
		ret = bch2_journal_keys_to_write_buffer_end(c, &wb);
		if (ret) {
			bch2_fs_fatal_error(c, "error flushing journal keys to btree write buffer: %s",
					    bch2_err_str(ret));
			return ret;
		}
	}

	scoped_guard(spinlock, &c->journal.lock)
		w->need_flush_to_write_buffer = false;

	start = end = vstruct_last(jset);

	end	= bch2_btree_roots_to_journal_entries(c, end, btree_roots_have);

	struct jset_entry_datetime *d =
		container_of(jset_entry_init(&end, sizeof(*d)), struct jset_entry_datetime, entry);
	d->entry.type	= BCH_JSET_ENTRY_datetime;
	d->seconds	= cpu_to_le64(ktime_get_real_seconds());

	bch2_journal_super_entries_add_common(c, &end, seq);
	u64s	= (u64 *) end - (u64 *) start;

	WARN_ON(u64s > j->entry_u64s_reserved);

	le32_add_cpu(&jset->u64s, u64s);

	unsigned sectors = vstruct_sectors(jset, c->block_bits);

	if (sectors > w->sectors) {
		bch2_fs_fatal_error(c, ": journal write overran available space, %zu > %u (extra %u reserved %u/%u)",
				    vstruct_bytes(jset), w->sectors << 9,
				    u64s, w->u64s_reserved, j->entry_u64s_reserved);
		return -EINVAL;
	}

	return 0;
}

static int bch2_journal_write_checksum(struct journal *j, struct journal_buf *w)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct jset *jset = w->data;
	u64 seq = le64_to_cpu(jset->seq);
	bool validate_before_checksum = false;
	int ret = 0;

	jset->magic		= cpu_to_le64(jset_magic(c));
	jset->version		= cpu_to_le32(c->sb.version);

	SET_JSET_BIG_ENDIAN(jset, CPU_BIG_ENDIAN);
	SET_JSET_CSUM_TYPE(jset, bch2_meta_checksum_type(c));

	if (!JSET_NO_FLUSH(jset) && journal_entry_empty(jset))
		j->last_empty_seq = seq;

	if (bch2_csum_type_is_encryption(JSET_CSUM_TYPE(jset)))
		validate_before_checksum = true;

	if (le32_to_cpu(jset->version) < bcachefs_metadata_version_current)
		validate_before_checksum = true;

	if (validate_before_checksum &&
	    (ret = jset_validate(c, NULL, jset, 0, WRITE)))
		return ret;

	ret = bch2_encrypt(c, JSET_CSUM_TYPE(jset), journal_nonce(jset),
		    jset->encrypted_start,
		    vstruct_end(jset) - (void *) jset->encrypted_start);
	if (bch2_fs_fatal_err_on(ret, c, "encrypting journal entry: %s", bch2_err_str(ret)))
		return ret;

	jset->csum = csum_vstruct(c, JSET_CSUM_TYPE(jset),
				  journal_nonce(jset), jset);

	if (!validate_before_checksum &&
	    (ret = jset_validate(c, NULL, jset, 0, WRITE)))
		return ret;

	unsigned sectors = vstruct_sectors(jset, c->block_bits);
	unsigned bytes	= vstruct_bytes(jset);
	memset((void *) jset + bytes, 0, (sectors << 9) - bytes);
	return 0;
}

static int bch2_journal_write_pick_flush(struct journal *j, struct journal_buf *w)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	int error = bch2_journal_error(j);

	/*
	 * If the journal is in an error state - we did an emergency shutdown -
	 * we prefer to continue doing journal writes. We just mark them as
	 * noflush so they'll never be used, but they'll still be visible by the
	 * list_journal tool - this helps in debugging.
	 *
	 * There's a caveat: the first journal write after marking the
	 * superblock dirty must always be a flush write, because on startup
	 * from a clean shutdown we didn't necessarily read the journal and the
	 * new journal write might overwrite whatever was in the journal
	 * previously - we can't leave the journal without any flush writes in
	 * it.
	 *
	 * So if we're in an error state, and we're still starting up, we don't
	 * write anything at all.
	 */
	if (error && test_bit(JOURNAL_need_flush_write, &j->flags))
		return error;

	if (error ||
	    w->noflush ||
	    (!w->must_flush &&
	     time_before(jiffies, j->last_flush_write +
		 msecs_to_jiffies(c->opts.journal_flush_delay)) &&
	     test_bit(JOURNAL_may_skip_flush, &j->flags))) {
		w->noflush = true;
		SET_JSET_NO_FLUSH(w->data, true);
		w->data->last_seq	= 0;
		w->last_seq		= 0;

		j->nr_noflush_writes++;
	} else {
		w->must_flush = true;
		j->last_flush_write = jiffies;
		j->nr_flush_writes++;
		clear_bit(JOURNAL_need_flush_write, &j->flags);
	}

	return 0;
}

CLOSURE_CALLBACK(bch2_journal_write)
{
	closure_type(w, struct journal_buf, io);
	struct journal *j = container_of(w, struct journal, buf[w->idx]);
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	union bch_replicas_padded replicas;
	unsigned nr_rw_members = dev_mask_nr(&c->rw_devs[BCH_DATA_free]);
	int ret;

	BUG_ON(BCH_SB_CLEAN(c->disk_sb.sb));
	BUG_ON(!w->write_started);
	BUG_ON(w->write_allocated);
	BUG_ON(w->write_done);

	j->write_start_time = local_clock();

	scoped_guard(spinlock, &j->lock) {
		if (nr_rw_members > 1)
			w->separate_flush = true;

		ret = bch2_journal_write_pick_flush(j, w);
	}

	if (unlikely(ret))
		goto err;

	scoped_guard(mutex, &j->buf_lock) {
		journal_buf_realloc(j, w);

		ret = bch2_journal_write_prep(j, w);
	}

	if (unlikely(ret))
		goto err;

	unsigned replicas_allocated = 0;
	while (1) {
		ret = journal_write_alloc(j, w, &replicas_allocated);
		if (!ret || !j->can_discard)
			break;

		bch2_journal_do_discards(j);
	}

	if (unlikely(ret))
		goto err_allocate_write;

	ret = bch2_journal_write_checksum(j, w);
	if (unlikely(ret))
		goto err;

	scoped_guard(spinlock, &j->lock) {
		/*
		 * write is allocated, no longer need to account for it in
		 * bch2_journal_space_available():
		 */
		w->sectors = 0;
		w->write_allocated = true;
		j->entry_bytes_written += vstruct_bytes(w->data);

		/*
		 * journal entry has been compacted and allocated, recalculate space
		 * available:
		 */
		bch2_journal_space_available(j);
		bch2_journal_do_writes(j);
	}

	w->devs_written = bch2_bkey_devs(bkey_i_to_s_c(&w->key));

	/*
	 * Mark journal replicas before we submit the write to guarantee
	 * recovery will find the journal entries after a crash.
	 */
	bch2_devlist_to_replicas(&replicas.e, BCH_DATA_journal,
				 w->devs_written);
	ret = bch2_mark_replicas(c, &replicas.e);
	if (ret)
		goto err;

	if (c->opts.nochanges)
		goto no_io;

	if (!JSET_NO_FLUSH(w->data))
		continue_at(cl, journal_write_preflush, j->wq);
	else
		continue_at(cl, journal_write_submit, j->wq);
	return;
err_allocate_write:
	if (!bch2_journal_error(j)) {
		CLASS(printbuf, buf)();

		bch2_journal_debug_to_text(&buf, j);
		prt_printf(&buf, bch2_fmt(c, "Unable to allocate journal write at seq %llu for %zu sectors: %s"),
					  le64_to_cpu(w->data->seq),
					  vstruct_sectors(w->data, c->block_bits),
					  bch2_err_str(ret));
		bch2_print_str(c, KERN_ERR, buf.buf);
	}
err:
	bch2_fatal_error(c);
no_io:
	extent_for_each_ptr(bkey_i_to_s_extent(&w->key), ptr) {
		struct bch_dev *ca = bch2_dev_have_ref(c, ptr->dev);
		enumerated_ref_put(&ca->io_ref[WRITE], BCH_DEV_WRITE_REF_journal_write);
	}

	continue_at(cl, journal_write_done, j->wq);
}
