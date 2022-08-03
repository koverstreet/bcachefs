/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ERRNAME_H
#define _LINUX_ERRNAME_H

#include <linux/stddef.h>

#ifdef CONFIG_SYMBOLIC_ERRNAME

const char *errname(int err);

#include <linux/codetag.h>

struct codetag_error_code {
	const char		*str;
	int			err;
};

/**
 * ERR - return an error code that records the error site
 *
 * E.g., instead of
 *   return -ENOMEM;
 * Use
 *   return -ERR(ENOMEM);
 *
 * Then, when a caller prints out the error with errname(), the error string
 * will include the file and line number.
 */
#define ERR(_err)							\
({									\
	static struct codetag_error_code				\
	__used								\
	__section("error_code_tags")					\
	__aligned(8) e = {						\
		.str	= #_err " at " __FILE__ ":" __stringify(__LINE__),\
		.err	= _err,						\
	};								\
									\
	e.err;								\
})

int error_class(int err);
bool error_matches(int err, int class);

#else

static inline int error_class(int err)
{
	return err;
}

static inline bool error_matches(int err, int class)
{
	return err == class;
}

#define ERR(_err)	_err

static inline const char *errname(int err)
{
	return NULL;
}

#endif

#endif /* _LINUX_ERRNAME_H */
