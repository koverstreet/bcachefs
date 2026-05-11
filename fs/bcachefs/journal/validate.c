// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/replicas.h"
#include "btree/cache.h"
#include "init/error.h"
#include "journal/journal.h"
#include "journal/read.h"
#include "journal/validate.h"
#include "sb/io.h"

#include <linux/string_choices.h>

#define FSCK_DELETED_KEY	5

void bch2_journal_entry_err_msg(struct printbuf *out,
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

/* this fills in a range with empty jset_entries: */
static void journal_entry_null_range(void *start, void *end)
{
	struct jset_entry *entry;

	for (entry = start; entry != end; entry = vstruct_next(entry))
		memset(entry, 0, sizeof(*entry));
}

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
		bch2_bkey_compat(c, from.level, from.btree, version, big_endian,
				 write, NULL, bkey_to_packed(k));

	if (journal_entry_err_on(ret = bch2_bkey_validate(c, bkey_i_to_s_c(k), &from),
				 c, version, jset, entry,
				 journal_entry_bkey_bad_format,
				 "bkey validate error %s", bch2_err_str(ret))) {
		le16_add_cpu(&entry->u64s, -((u16) k->k.u64s));
		memmove(k, bkey_next(k), next - (void *) bkey_next(k));
		journal_entry_null_range(vstruct_next(entry), next);
		return FSCK_DELETED_KEY;
	}

	if (write)
		bch2_bkey_compat(c, from.level, from.btree, version, big_endian,
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
	guard(printbuf_indent)(out);

	for (i = 0; i < nr_types; i++) {
		prt_newline(out);
		bch2_prt_data_type(out, i);
		prt_printf(out, ": buckets=%llu sectors=%llu fragmented=%llu",
		       le64_to_cpu(u->d[i].buckets),
		       le64_to_cpu(u->d[i].sectors),
		       le64_to_cpu(u->d[i].fragmented));
	}
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

static int journal_entry_rewind_limit_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	unsigned bytes = jset_u64s(le16_to_cpu(entry->u64s)) * sizeof(u64);
	int ret = 0;

	if (journal_entry_err_on(bytes < sizeof(struct jset_entry_rewind_limit),
				 c, version, jset, entry,
				 journal_entry_rewind_limit_bad_size,
				 "bad size (got %u, expected >= %zu)",
				 bytes, sizeof(struct jset_entry_rewind_limit))) {
		journal_entry_null_range(entry, vstruct_next(entry));
	}
fsck_err:
	return ret;
}

static void journal_entry_rewind_limit_to_text(struct printbuf *out, struct bch_fs *c,
					       struct jset_entry *entry)
{
	struct jset_entry_rewind_limit *r =
		container_of(entry, struct jset_entry_rewind_limit, entry);

	prt_printf(out, "seq %llu", le64_to_cpu(r->seq));
}

static int journal_entry_rewind_validate(struct bch_fs *c,
				struct jset *jset,
				struct jset_entry *entry,
				unsigned version, int big_endian,
				struct bkey_validate_context from)
{
	unsigned bytes = jset_u64s(le16_to_cpu(entry->u64s)) * sizeof(u64);
	int ret = 0;

	if (journal_entry_err_on(bytes < sizeof(struct jset_entry_rewind),
				 c, version, jset, entry,
				 journal_entry_rewind_bad_size,
				 "bad size (got %u, expected >= %zu)",
				 bytes, sizeof(struct jset_entry_rewind))) {
		journal_entry_null_range(entry, vstruct_next(entry));
	}
fsck_err:
	return ret;
}

static void journal_entry_rewind_to_text(struct printbuf *out, struct bch_fs *c,
					 struct jset_entry *entry)
{
	struct jset_entry_rewind *r =
		container_of(entry, struct jset_entry_rewind, entry);

	prt_printf(out, "from %llu to %llu", le64_to_cpu(r->from), le64_to_cpu(r->to));
}

struct jset_entry_ops {
	int (*validate)(struct bch_fs *, struct jset *,
			struct jset_entry *, unsigned, int,
			struct bkey_validate_context);
	void (*to_text)(struct printbuf *, struct bch_fs *, struct jset_entry *);
};

static const struct jset_entry_ops bch2_jset_entry_ops[] = {
#define x(f, nr, ...)						\
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

int bch2_jset_validate(struct bch_fs *c,
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
		return bch_err_throw(c, EINVAL_journal_entry_version_incompatible);
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

int bch2_jset_validate_early(struct bch_fs *c,
			     struct bch_dev *ca,
			     struct jset *jset, u64 sector,
			     unsigned bucket_sectors_left)
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
		return bch_err_throw(c, EINVAL_journal_validate_version_incompatible);
	}

	size_t bytes = vstruct_bytes(jset);

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
