// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>

#include "bcachefs.h"
#include "alloc/backpointers.h"
#include "btree/bkey_types.h"
#include "util/printbuf.h"

#define BP_VAL_U64s	DIV_ROUND_UP(sizeof(struct bch_backpointer), sizeof(u64))

struct backpointer_test_key {
	struct bkey_i	k;
	u64		v[BP_VAL_U64s];
};

static void backpointer_to_text_truncated_test(struct kunit *test)
{
	struct backpointer_test_key buf;
	struct printbuf out = PRINTBUF;

	/* Truncated key headers and truncated values must print an
	 * invalid marker, not read past the key: */
	for (unsigned u64s = 0; u64s < BKEY_U64s + BP_VAL_U64s; u64s++) {
		memset(&buf, 0, sizeof(buf));
		buf.k.k.u64s = u64s;
		buf.k.k.type = KEY_TYPE_backpointer;

		bch2_backpointer_to_text(&out, NULL, bkey_i_to_s_c(&buf.k));
		KUNIT_EXPECT_NOT_NULL(test, strstr(out.buf, "(invalid"));

		printbuf_reset(&out);
	}

	printbuf_exit(&out);
}

static void backpointer_to_text_null_fs_test(struct kunit *test)
{
	struct backpointer_test_key buf = {};
	struct printbuf out = PRINTBUF;

	buf.k.k.u64s = BKEY_U64s + BP_VAL_U64s;
	buf.k.k.type = KEY_TYPE_backpointer;

	/* We may be called with a NULL fs: */
	bch2_backpointer_to_text(&out, NULL, bkey_i_to_s_c(&buf.k));
	KUNIT_EXPECT_NOT_NULL(test, strstr(out.buf, "pos="));

	printbuf_exit(&out);
}

static struct kunit_case backpointer_test_cases[] = {
	KUNIT_CASE(backpointer_to_text_truncated_test),
	KUNIT_CASE(backpointer_to_text_null_fs_test),
	{}
};

static struct kunit_suite backpointer_test_suite = {
	.name		= "backpointer tests",
	.test_cases	= backpointer_test_cases
};

kunit_test_suite(backpointer_test_suite);

MODULE_AUTHOR("Matthias Goergens");
MODULE_DESCRIPTION("bcachefs filesystem backpointer unit tests");
MODULE_LICENSE("GPL");
