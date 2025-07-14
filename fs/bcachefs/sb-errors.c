// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "sb-errors.h"
#include "super-io.h"

const char * const bch2_sb_error_strs[] = {
#define x(t, n, ...) [n] = #t,
	BCH_SB_ERRS()
#undef x
};

void bch2_sb_error_id_to_text(struct printbuf *out, enum bch_sb_error_id id)
{
	if (id < BCH_FSCK_ERR_MAX)
		prt_str(out, bch2_sb_error_strs[id]);
	else
		prt_printf(out, "(unknown error %u)", id);
}

static inline unsigned bch2_sb_field_errors_nr_entries(struct bch_sb_field_errors *e)
{
	return bch2_sb_field_nr_entries(e);
}

static inline unsigned bch2_sb_field_errors_u64s(unsigned nr)
{
	return (sizeof(struct bch_sb_field_errors) +
		sizeof(struct bch_sb_field_error_entry) * nr) / sizeof(u64);
}

static int bch2_sb_errors_validate(struct bch_sb *sb, struct bch_sb_field *f,
				   enum bch_validate_flags flags, struct printbuf *err)
{
	struct bch_sb_field_errors *e = field_to_type(f, errors);
	unsigned i, nr = bch2_sb_field_errors_nr_entries(e);

	for (i = 0; i < nr; i++) {
		if (!BCH_SB_ERROR_ENTRY_NR(&e->entries[i])) {
			prt_printf(err, "entry with count 0 (id ");
			bch2_sb_error_id_to_text(err, BCH_SB_ERROR_ENTRY_ID(&e->entries[i]));
			prt_printf(err, ")");
			return -BCH_ERR_invalid_sb_errors;
		}

		if (i + 1 < nr &&
		    BCH_SB_ERROR_ENTRY_ID(&e->entries[i]) >=
		    BCH_SB_ERROR_ENTRY_ID(&e->entries[i + 1])) {
			prt_printf(err, "entries out of order");
			return -BCH_ERR_invalid_sb_errors;
		}
	}

	return 0;
}

static void bch2_sb_errors_to_text(struct printbuf *out, struct bch_sb *sb,
				   struct bch_sb_field *f)
{
	struct bch_sb_field_errors *e = field_to_type(f, errors);
	unsigned i, nr = bch2_sb_field_errors_nr_entries(e);

	if (out->nr_tabstops <= 1)
		printbuf_tabstop_push(out, 16);

	for (i = 0; i < nr; i++) {
		bch2_sb_error_id_to_text(out, BCH_SB_ERROR_ENTRY_ID(&e->entries[i]));
		prt_tab(out);
		prt_u64(out, BCH_SB_ERROR_ENTRY_NR(&e->entries[i]));
		prt_tab(out);
		bch2_prt_datetime(out, le64_to_cpu(e->entries[i].last_error_time));
		prt_newline(out);
	}
}

const struct bch_sb_field_ops bch_sb_field_ops_errors = {
	.validate	= bch2_sb_errors_validate,
	.to_text	= bch2_sb_errors_to_text,
};

void bch2_fs_errors_to_text(struct printbuf *out, struct bch_fs *c)
{
	if (out->nr_tabstops < 1)
		printbuf_tabstop_push(out, 48);
	if (out->nr_tabstops < 2)
		printbuf_tabstop_push(out, 8);
	if (out->nr_tabstops < 3)
		printbuf_tabstop_push(out, 16);

	guard(mutex)(&c->fsck_error_counts_lock);

	bch_sb_errors_cpu *e = &c->fsck_error_counts;
	darray_for_each(*e, i) {
		bch2_sb_error_id_to_text(out, i->id);
		prt_tab(out);
		prt_u64(out, i->nr);
		prt_tab(out);
		bch2_prt_datetime(out, i->last_error_time);
		prt_newline(out);
	}
}

void bch2_sb_error_count(struct bch_fs *c, enum bch_sb_error_id err)
{
	bch_sb_errors_cpu *e = &c->fsck_error_counts;
	struct bch_sb_error_entry_cpu n = {
		.id = err,
		.nr = 1,
		.last_error_time = ktime_get_real_seconds()
	};
	unsigned i;

	guard(mutex)(&c->fsck_error_counts_lock);

	for (i = 0; i < e->nr; i++) {
		if (err == e->data[i].id) {
			e->data[i].nr++;
			e->data[i].last_error_time = n.last_error_time;
			return;
		}
		if (err < e->data[i].id)
			break;
	}

	if (darray_make_room(e, 1))
		return;

	darray_insert_item(e, i, n);
}

void bch2_sb_errors_from_cpu(struct bch_fs *c)
{
	guard(mutex)(&c->fsck_error_counts_lock);

	bch_sb_errors_cpu *src = &c->fsck_error_counts;
	struct bch_sb_field_errors *dst =
		bch2_sb_field_resize(&c->disk_sb, errors,
				     bch2_sb_field_errors_u64s(src->nr));
	if (!dst)
		return;

	for (unsigned i = 0; i < src->nr; i++) {
		SET_BCH_SB_ERROR_ENTRY_ID(&dst->entries[i], src->data[i].id);
		SET_BCH_SB_ERROR_ENTRY_NR(&dst->entries[i], src->data[i].nr);
		dst->entries[i].last_error_time = cpu_to_le64(src->data[i].last_error_time);
	}
}

static int bch2_sb_errors_to_cpu(struct bch_fs *c)
{
	guard(mutex)(&c->fsck_error_counts_lock);

	struct bch_sb_field_errors *src = bch2_sb_field_get(c->disk_sb.sb, errors);
	bch_sb_errors_cpu *dst = &c->fsck_error_counts;
	unsigned nr = bch2_sb_field_errors_nr_entries(src);

	if (!nr)
		return 0;

	int ret = darray_make_room(dst, nr);
	if (ret)
		return ret;

	dst->nr = nr;

	for (unsigned i = 0; i < nr; i++) {
		dst->data[i].id = BCH_SB_ERROR_ENTRY_ID(&src->entries[i]);
		dst->data[i].nr = BCH_SB_ERROR_ENTRY_NR(&src->entries[i]);
		dst->data[i].last_error_time = le64_to_cpu(src->entries[i].last_error_time);
	}

	return 0;
}

void bch2_fs_sb_errors_exit(struct bch_fs *c)
{
	darray_exit(&c->fsck_error_counts);
}

void bch2_fs_sb_errors_init_early(struct bch_fs *c)
{
	mutex_init(&c->fsck_error_counts_lock);
	darray_init(&c->fsck_error_counts);
}

int bch2_fs_sb_errors_init(struct bch_fs *c)
{
	return bch2_sb_errors_to_cpu(c);
}
