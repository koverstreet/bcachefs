// SPDX-License-Identifier: GPL-2.0

/*
 * Superblock section that contains sizes of extent fields, so that old versions
 * can parse extents from newer versions with unknown fields
 */

#include "bcachefs.h"

#include "data/extents_sb.h"

#include "sb/io.h"

static inline unsigned extent_entry_u64s_known(unsigned type)
{
	switch (type) {
#define x(f, n)						\
	case BCH_EXTENT_ENTRY_##f:			\
		return sizeof(struct bch_extent_##f) / sizeof(u64);
	BCH_EXTENT_ENTRY_TYPES()
#undef x
	default:
		BUG();
	}
}

static inline size_t bch2_sb_extent_type_u64s_nr_entries(struct bch_sb_field_extent_type_u64s *e)
{
	return e
		? (u8 *) vstruct_end(&e->field) - &e->d[0]
		: 0;
}

void bch2_sb_extent_type_u64s_to_cpu(struct bch_fs *c)
{
	struct bch_sb_field_extent_type_u64s *e = bch2_sb_field_get(c->disk_sb.sb, extent_type_u64s);

	for (unsigned i = 0; i < bch2_sb_extent_type_u64s_nr_entries(e) && e->d[i]; i++) {
		c->extent_type_u64s[i] = e->d[i];
		c->extent_types_known = i + 1;
	}

	for (unsigned i = 0; i < BCH_EXTENT_ENTRY_MAX; i++)
		c->extent_type_u64s[i] = extent_entry_u64s_known(i);;

	c->extent_types_known = max(c->extent_types_known, BCH_EXTENT_ENTRY_MAX);
}

int bch2_sb_extent_type_u64s_from_cpu(struct bch_fs *c)
{
	lockdep_assert_held(&c->sb_lock);

	struct bch_sb_field_extent_type_u64s *e =
		bch2_sb_field_get_minsize(&c->disk_sb, extent_type_u64s,
					  DIV_ROUND_UP(sizeof(*e) + BCH_EXTENT_ENTRY_MAX,
						       sizeof(u64)));
	if (!e) {
		bch_err(c, "error allocating superblock space for extent_type_u64s");
		return bch_err_throw(c, ENOSPC_sb_extent_type_u64s);
	}

	for (unsigned i = 0; i < BCH_EXTENT_ENTRY_MAX; i++)
		e->d[i] = extent_entry_u64s_known(i);

	return 0;
}

static int bch2_sb_extent_type_u64s_validate(struct bch_sb *sb, struct bch_sb_field *f,
				      enum bch_validate_flags flags, struct printbuf *err)
{
	struct bch_sb_field_extent_type_u64s *e = field_to_type(f, extent_type_u64s);

	for (unsigned i = 0;
	     i < min(bch2_sb_extent_type_u64s_nr_entries(e), BCH_EXTENT_ENTRY_MAX) &&
	     e->d[i];
	     i++)
		if (e->d[i] != extent_entry_u64s_known(i)) {
			prt_printf(err, "extent_type_u64s for %s does not match in-mem (%u != %u)",
				   bch2_extent_entry_types[i], e->d[i], extent_entry_u64s_known(i));
			return -BCH_ERR_invalid_sb_extent_type_u64s;
		}

	return 0;
}

static void bch2_sb_extent_type_u64s_to_text(struct printbuf *out,
					     struct bch_fs *c, struct bch_sb *sb,
					     struct bch_sb_field *f)
{
	struct bch_sb_field_extent_type_u64s *e = field_to_type(f, extent_type_u64s);

	for (unsigned i = 0; i < bch2_sb_extent_type_u64s_nr_entries(e) && e->d[i]; i++) {
		if (i < BCH_EXTENT_ENTRY_MAX)
			prt_str(out, bch2_extent_entry_types[i]);
		else
			prt_printf(out, "(unknown type %u)", i);
		prt_printf(out, ":\t%u\n", e->d[i]);
	}
}

const struct bch_sb_field_ops bch_sb_field_ops_extent_type_u64s = {
	.validate	= bch2_sb_extent_type_u64s_validate,
	.to_text	= bch2_sb_extent_type_u64s_to_text,
};
