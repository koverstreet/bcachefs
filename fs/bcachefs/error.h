#ifndef _BCACHE_ERROR_H
#define _BCACHE_ERROR_H

#include <linux/printk.h>

struct cache;
struct cache_set;
struct bbio;

/*
 * XXX: separate out errors that indicate on disk data is inconsistent, and flag
 * superblock as such
 */

/* Error messages: */

#define __bch_cache_error(ca, fmt, ...)					\
do {									\
	char _buf[BDEVNAME_SIZE];					\
	bch_err((ca)->set, "%s: " fmt,					\
		bdevname((ca)->disk_sb.bdev, _buf), ##__VA_ARGS__);	\
} while (0)

/*
 * Very fatal logic/inconsistency errors: these indicate that we've majorly
 * screwed up at runtime, i.e. it's not likely that it was just caused by the
 * data on disk being inconsistent. These BUG():
 *
 * XXX: audit and convert to inconsistent() checks
 */

#define cache_set_bug(c, ...)						\
do {									\
	bch_err(c, __VA_ARGS__);					\
	BUG();								\
} while (0)

#define cache_set_bug_on(cond, c, ...)					\
do {									\
	if (cond)							\
		cache_set_bug(c, __VA_ARGS__);				\
} while (0)

/*
 * Inconsistency errors: The on disk data is inconsistent. If these occur during
 * initial recovery, they don't indicate a bug in the running code - we walk all
 * the metadata before modifying anything. If they occur at runtime, they
 * indicate either a bug in the running code or (less likely) data is being
 * silently corrupted under us.
 *
 * XXX: audit all inconsistent errors and make sure they're all recoverable, in
 * BCH_ON_ERROR_CONTINUE mode
 */

void bch_inconsistent_error(struct cache_set *);

#define cache_set_inconsistent(c, ...)					\
do {									\
	bch_err(c, __VA_ARGS__);					\
	bch_inconsistent_error(c);					\
} while (0)

#define cache_set_inconsistent_on(cond, c, ...)				\
({									\
	int _ret = !!(cond);						\
									\
	if (_ret)							\
		cache_set_inconsistent(c, __VA_ARGS__);			\
	_ret;								\
})

/*
 * Later we might want to mark only the particular device inconsistent, not the
 * entire cache set:
 */

#define cache_inconsistent(ca, ...)					\
do {									\
	__bch_cache_error(ca, __VA_ARGS__);				\
	bch_inconsistent_error((ca)->set);				\
} while (0)

#define cache_inconsistent_on(cond, ca, ...)				\
({									\
	int _ret = !!(cond);						\
									\
	if (_ret)							\
		cache_inconsistent(ca, __VA_ARGS__);			\
	_ret;								\
})

/*
 * Fatal errors: these don't indicate a bug, but we can't continue running in RW
 * mode - pretty much just due to metadata IO errors:
 */

void bch_fatal_error(struct cache_set *);

#define cache_set_fatal_error(c, ...)					\
do {									\
	bch_err(c, __VA_ARGS__);					\
	bch_fatal_error(c);						\
} while (0)

#define cache_set_fatal_err_on(cond, c, ...)				\
({									\
	int _ret = !!(cond);						\
									\
	if (_ret)							\
		cache_set_fatal_error(c, __VA_ARGS__);			\
	_ret;								\
})

#define cache_fatal_error(ca, ...)					\
do {									\
	__bch_cache_error(ca, __VA_ARGS__);				\
	bch_fatal_error(c);						\
} while (0)

#define cache_fatal_io_error(ca, fmt, ...)				\
do {									\
	char _buf[BDEVNAME_SIZE];					\
									\
	printk_ratelimited(KERN_ERR bch_fmt((ca)->set,			\
		"fatal IO error on %s for " fmt),			\
		bdevname((ca)->disk_sb.bdev, _buf), ##__VA_ARGS__);	\
	bch_fatal_error((ca)->set);					\
} while (0)

#define cache_fatal_io_err_on(cond, ca, ...)				\
({									\
	int _ret = !!(cond);						\
									\
	if (_ret)							\
		cache_fatal_io_error(ca, __VA_ARGS__);			\
	_ret;								\
})

/*
 * Nonfatal IO errors: either recoverable metadata IO (because we have
 * replicas), or data IO - we need to log it and print out a message, but we
 * don't (necessarily) want to shut down the fs:
 */

void bch_account_io_completion(struct cache *);
void bch_account_io_completion_time(struct cache *, unsigned, int);

void bch_nonfatal_io_error_work(struct work_struct *);

/* Does the error handling without logging a message */
void bch_nonfatal_io_error(struct cache *);

#if 0
#define cache_set_nonfatal_io_error(c, ...)				\
do {									\
	bch_err(c, __VA_ARGS__);					\
	bch_nonfatal_io_error(c);					\
} while (0)
#endif

/* Logs message and handles the error: */
#define cache_nonfatal_io_error(ca, fmt, ...)				\
do {									\
	char _buf[BDEVNAME_SIZE];					\
									\
	printk_ratelimited(KERN_ERR bch_fmt((ca)->set,			\
		"IO error on %s for " fmt),				\
		bdevname((ca)->disk_sb.bdev, _buf), ##__VA_ARGS__);	\
	bch_nonfatal_io_error(ca);					\
} while (0)

#define cache_nonfatal_io_err_on(cond, ca, ...)				\
({									\
	bool _ret = (cond);						\
									\
	if (_ret)							\
		cache_nonfatal_io_error(ca, __VA_ARGS__);		\
	_ret;								\
})

/* kill? */

#define __bcache_io_error(c, fmt, ...)					\
	printk_ratelimited(KERN_ERR bch_fmt(c,				\
			"IO error: " fmt), ##__VA_ARGS__)

#define bcache_io_error(c, bio, fmt, ...)				\
do {									\
	__bcache_io_error(c, fmt, ##__VA_ARGS__);			\
	(bio)->bi_error = -EIO;						\
} while (0)

#endif /* _BCACHE_ERROR_H */
