// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "errcode.h"

#include <linux/errname.h>

static const char * const bch2_errcode_strs[] = {
#define x(class, err) [BCH_ERR_##err - BCH_ERR_START] = #err,
	BCH_ERRCODES()
#undef x
	NULL
};

static const unsigned bch2_errcode_parents[] = {
#define x(class, err) [BCH_ERR_##err - BCH_ERR_START] = class,
	BCH_ERRCODES()
#undef x
};

__attribute__((const))
const char *bch2_err_str(int err)
{
	const char *errstr;

	err = abs(err);

	if (err >= BCH_ERR_MAX)
		return "(Invalid error)";

	if (err >= BCH_ERR_START)
		errstr = bch2_errcode_strs[err - BCH_ERR_START];
	else if (err)
		errstr = errname(err);
	else
		errstr = "(No error)";
	return errstr ?: "(Invalid error)";
}

__attribute__((const))
bool __bch2_err_matches(int err, int class)
{
	err	= abs(err);
	class	= abs(class);

	BUG_ON(err	>= BCH_ERR_MAX);
	BUG_ON(class	>= BCH_ERR_MAX);

	while (err >= BCH_ERR_START && err != class)
		err = bch2_errcode_parents[err - BCH_ERR_START];

	return err == class;
}

int __bch2_err_class(int bch_err)
{
	int std_err = -bch_err;
	BUG_ON((unsigned) std_err >= BCH_ERR_MAX);

	while (std_err >= BCH_ERR_START && bch2_errcode_parents[std_err - BCH_ERR_START])
		std_err = bch2_errcode_parents[std_err - BCH_ERR_START];

	return -std_err;
}

const char *bch2_blk_status_to_str(blk_status_t status)
{
	if (status == BLK_STS_REMOVED)
		return "device removed";
	return blk_status_to_str(status);
}

enum bch_errcode blk_status_to_bch_err(blk_status_t err)
{
	if (!err)
		return 0;

	switch (err) {
#undef BLK_STS
#define BLK_STS(n) case BLK_STS_##n:	return BCH_ERR_BLK_STS_##n;
		BLK_ERRS()
#undef BLK_STS
		default:		return BCH_ERR_BLK_STS_UNKNOWN;
	}
}
