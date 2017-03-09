#ifndef _BCACHE_ERROR_H
#define _BCACHE_ERROR_H

#include <linux/printk.h>

struct bch_dev;
struct bch_fs;

/*
 * XXX: separate out errors that indicate on disk data is inconsistent, and flag
 * superblock as such
 */

/* Error messages: */

#define __bch_dev_error(ca, fmt, ...)					\
do {									\
	char _buf[BDEVNAME_SIZE];					\
	bch_err((ca)->fs, "%s: " fmt,					\
		bdevname((ca)->disk_sb.bdev, _buf), ##__VA_ARGS__);	\
} while (0)

/*
 * Very fatal logic/inconsistency errors: these indicate that we've majorly
 * screwed up at runtime, i.e. it's not likely that it was just caused by the
 * data on disk being inconsistent. These BUG():
 *
 * XXX: audit and convert to inconsistent() checks
 */

#define bch_fs_bug(c, ...)						\
do {									\
	bch_err(c, __VA_ARGS__);					\
	BUG();								\
} while (0)

#define bch_fs_bug_on(cond, c, ...)					\
do {									\
	if (cond)							\
		bch_fs_bug(c, __VA_ARGS__);				\
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

void bch_inconsistent_error(struct bch_fs *);

#define bch_fs_inconsistent(c, ...)					\
do {									\
	bch_err(c, __VA_ARGS__);					\
	bch_inconsistent_error(c);					\
} while (0)

#define bch_fs_inconsistent_on(cond, c, ...)				\
({									\
	int _ret = !!(cond);						\
									\
	if (_ret)							\
		bch_fs_inconsistent(c, __VA_ARGS__);			\
	_ret;								\
})

/*
 * Later we might want to mark only the particular device inconsistent, not the
 * entire filesystem:
 */

#define bch_dev_inconsistent(ca, ...)					\
do {									\
	__bch_dev_error(ca, __VA_ARGS__);				\
	bch_inconsistent_error((ca)->fs);				\
} while (0)

#define bch_dev_inconsistent_on(cond, ca, ...)				\
({									\
	int _ret = !!(cond);						\
									\
	if (_ret)							\
		bch_dev_inconsistent(ca, __VA_ARGS__);			\
	_ret;								\
})

/*
 * Fsck errors: inconsistency errors we detect at mount time, and should ideally
 * be able to repair:
 */

enum {
	BCH_FSCK_OK			= 0,
	BCH_FSCK_ERRORS_NOT_FIXED	= 1,
	BCH_FSCK_REPAIR_UNIMPLEMENTED	= 2,
	BCH_FSCK_REPAIR_IMPOSSIBLE	= 3,
	BCH_FSCK_UNKNOWN_VERSION	= 4,
};

/* These macros return true if error should be fixed: */

/* XXX: mark in superblock that filesystem contains errors, if we ignore: */

#ifndef __fsck_err
#define __fsck_err(c, _can_fix, _can_ignore, _nofix_msg, msg, ...)	\
({									\
	bool _fix = false;						\
									\
	if (_can_fix && (c)->opts.fix_errors) {				\
		bch_err(c, msg ", fixing", ##__VA_ARGS__);		\
		set_bit(BCH_FS_FSCK_FIXED_ERRORS, &(c)->flags);	\
		_fix = true;						\
	} else if (_can_ignore &&					\
		   (c)->opts.errors == BCH_ON_ERROR_CONTINUE) {		\
		bch_err(c, msg " (ignoring)", ##__VA_ARGS__);		\
	} else {							\
		bch_err(c, msg " ("_nofix_msg")", ##__VA_ARGS__);	\
		ret = BCH_FSCK_ERRORS_NOT_FIXED;			\
		goto fsck_err;						\
	}								\
									\
	BUG_ON(!_fix && !_can_ignore);					\
	_fix;								\
})
#endif

#define __fsck_err_on(cond, c, _can_fix, _can_ignore, _nofix_msg, ...)	\
	((cond) ? __fsck_err(c, _can_fix, _can_ignore,			\
			     _nofix_msg, ##__VA_ARGS__) : false)

#define unfixable_fsck_err_on(cond, c, ...)				\
	__fsck_err_on(cond, c, false, true, "repair unimplemented", ##__VA_ARGS__)

#define need_fsck_err_on(cond, c, ...)					\
	__fsck_err_on(cond, c, false, true, "run fsck to correct", ##__VA_ARGS__)

#define mustfix_fsck_err(c, ...)					\
	__fsck_err(c, true, false, "not fixing", ##__VA_ARGS__)

#define mustfix_fsck_err_on(cond, c, ...)				\
	__fsck_err_on(cond, c, true, false, "not fixing", ##__VA_ARGS__)

#define fsck_err_on(cond, c, ...)					\
	__fsck_err_on(cond, c, true, true, "not fixing", ##__VA_ARGS__)

/*
 * Fatal errors: these don't indicate a bug, but we can't continue running in RW
 * mode - pretty much just due to metadata IO errors:
 */

void bch_fatal_error(struct bch_fs *);

#define bch_fs_fatal_error(c, ...)					\
do {									\
	bch_err(c, __VA_ARGS__);					\
	bch_fatal_error(c);						\
} while (0)

#define bch_fs_fatal_err_on(cond, c, ...)				\
({									\
	int _ret = !!(cond);						\
									\
	if (_ret)							\
		bch_fs_fatal_error(c, __VA_ARGS__);			\
	_ret;								\
})

#define bch_dev_fatal_error(ca, ...)					\
do {									\
	__bch_dev_error(ca, __VA_ARGS__);				\
	bch_fatal_error(c);						\
} while (0)

#define bch_dev_fatal_io_error(ca, fmt, ...)				\
do {									\
	char _buf[BDEVNAME_SIZE];					\
									\
	printk_ratelimited(KERN_ERR bch_fmt((ca)->fs,			\
		"fatal IO error on %s for " fmt),			\
		bdevname((ca)->disk_sb.bdev, _buf), ##__VA_ARGS__);	\
	bch_fatal_error((ca)->fs);					\
} while (0)

#define bch_dev_fatal_io_err_on(cond, ca, ...)				\
({									\
	int _ret = !!(cond);						\
									\
	if (_ret)							\
		bch_dev_fatal_io_error(ca, __VA_ARGS__);		\
	_ret;								\
})

/*
 * Nonfatal IO errors: either recoverable metadata IO (because we have
 * replicas), or data IO - we need to log it and print out a message, but we
 * don't (necessarily) want to shut down the fs:
 */

void bch_account_io_completion(struct bch_dev *);
void bch_account_io_completion_time(struct bch_dev *, unsigned, int);

void bch_nonfatal_io_error_work(struct work_struct *);

/* Does the error handling without logging a message */
void bch_nonfatal_io_error(struct bch_dev *);

#if 0
#define bch_fs_nonfatal_io_error(c, ...)				\
do {									\
	bch_err(c, __VA_ARGS__);					\
	bch_nonfatal_io_error(c);					\
} while (0)
#endif

/* Logs message and handles the error: */
#define bch_dev_nonfatal_io_error(ca, fmt, ...)				\
do {									\
	char _buf[BDEVNAME_SIZE];					\
									\
	printk_ratelimited(KERN_ERR bch_fmt((ca)->fs,			\
		"IO error on %s for " fmt),				\
		bdevname((ca)->disk_sb.bdev, _buf), ##__VA_ARGS__);	\
	bch_nonfatal_io_error(ca);					\
} while (0)

#define bch_dev_nonfatal_io_err_on(cond, ca, ...)			\
({									\
	bool _ret = (cond);						\
									\
	if (_ret)							\
		bch_dev_nonfatal_io_error(ca, __VA_ARGS__);		\
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
