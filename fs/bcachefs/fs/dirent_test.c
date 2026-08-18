// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>

#include "bcachefs.h"
#include "fs/dirent.h"
#include "btree/bkey_types.h"
#include "util/printbuf.h"

/*
 * Kernel layout notes (measured on x86-64, see kunit run logs): struct
 * bch_val is zero-sized, so value fields start at value offset 0 —
 * d_inum@0, the d_type/d_casefold byte@8 (d_casefold is bit 7),
 * d_pad@9, d_name_len@11, d_cf_name_len@13, d_names@15,
 * offsetof(d_name) == 9, sizeof(struct bch_dirent) == 16.
 */
struct dirent_test_key {
	struct bkey_i	k;
	u64		v[4];
};

static void dirent_to_text_truncated_test(struct kunit *test)
{
	struct dirent_test_key buf;
	struct printbuf out = PRINTBUF;

	/* Truncated key headers and truncated values must print an
	 * invalid marker, not read past the key: */
	for (unsigned u64s = 0; u64s < BKEY_U64s + 3; u64s++) {
		memset(&buf, 0, sizeof(buf));
		buf.k.k.u64s = u64s;
		buf.k.k.type = KEY_TYPE_dirent;

		bch2_dirent_to_text(&out, NULL, bkey_i_to_s_c(&buf.k));
		KUNIT_EXPECT_NOT_NULL_MSG(test, strstr(out.buf, "(invalid"), out.buf ?: "(null)");

		printbuf_reset(&out);
	}

	printbuf_exit(&out);
}

static void dirent_to_text_underflowed_name_test(struct kunit *test)
{
	struct dirent_test_key buf = {};
	struct printbuf out = PRINTBUF;

	/* Full-size value, but the last value u64 is all zero: the name
	 * length computation underflows (val_bytes 16 - offsetof(d_name)
	 * 9 - 8 trailing nuls) and the guard must catch the wrapped
	 * length: */
	buf.k.k.u64s = BKEY_U64s + 2;
	buf.k.k.type = KEY_TYPE_dirent;

	bch2_dirent_to_text(&out, NULL, bkey_i_to_s_c(&buf.k));
	KUNIT_EXPECT_NOT_NULL_MSG(test, strstr(out.buf, "(invalid"), out.buf ?: "(null)");

	printbuf_exit(&out);
}

static void dirent_to_text_casefold_overrun_test(struct kunit *test)
{
	struct dirent_test_key buf = {};
	struct bch_dirent *d = (void *) buf.v;
	struct printbuf out = PRINTBUF;

	/* d_name_len fits, but the casefold lookup name is inflated
	 * (d_cf_name_len = 0xffff) and must be caught: */
	buf.k.k.u64s = BKEY_U64s + 2;
	buf.k.k.type = KEY_TYPE_dirent;
	d->d_casefold = 1;
	d->d_cf_name_block.d_name_len = cpu_to_le16(1);
	d->d_cf_name_block.d_cf_name_len = cpu_to_le16(0xffff);
	d->d_cf_name_block.d_names[0] = 'a';

	bch2_dirent_to_text(&out, NULL, bkey_i_to_s_c(&buf.k));
	KUNIT_EXPECT_NOT_NULL_MSG(test, strstr(out.buf, "(invalid"), out.buf ?: "(null)");

	printbuf_exit(&out);
}

static struct kunit_case dirent_test_cases[] = {
	KUNIT_CASE(dirent_to_text_truncated_test),
	KUNIT_CASE(dirent_to_text_underflowed_name_test),
	KUNIT_CASE(dirent_to_text_casefold_overrun_test),
	{}
};

static struct kunit_suite dirent_test_suite = {
	.name		= "dirent tests",
	.test_cases	= dirent_test_cases
};

kunit_test_suite(dirent_test_suite);

MODULE_AUTHOR("Matthias Goergens");
MODULE_DESCRIPTION("bcachefs filesystem dirent unit tests");
MODULE_LICENSE("GPL");
