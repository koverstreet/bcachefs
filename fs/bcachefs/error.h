/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ERROR_H
#define _BCACHEFS_ERROR_H

#include <linux/list.h>
#include <linux/printk.h>
#include "bkey_types.h"
#include "sb-errors.h"

struct bch_dev;
struct bch_fs;
struct work_struct;

/*
 * XXX: separate out errors that indicate on disk data is inconsistent, and flag
 * superblock as such
 */

/* Error messages: */

void __bch2_log_msg_start(const char *, struct printbuf *);

static inline void bch2_log_msg_start(struct bch_fs *c, struct printbuf *out)
{
	__bch2_log_msg_start(c->name, out);
}

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

bool __bch2_inconsistent_error(struct bch_fs *, struct printbuf *);
bool bch2_inconsistent_error(struct bch_fs *);
__printf(2, 3)
bool bch2_fs_inconsistent(struct bch_fs *, const char *, ...);

#define bch2_fs_inconsistent_on(cond, ...)				\
({									\
	bool _ret = unlikely(!!(cond));					\
	if (_ret)							\
		bch2_fs_inconsistent(__VA_ARGS__);			\
	_ret;								\
})

__printf(2, 3)
bool bch2_trans_inconsistent(struct btree_trans *, const char *, ...);

#define bch2_trans_inconsistent_on(cond, ...)				\
({									\
	bool _ret = unlikely(!!(cond));					\
	if (_ret)							\
		bch2_trans_inconsistent(__VA_ARGS__);			\
	_ret;								\
})

int __bch2_topology_error(struct bch_fs *, struct printbuf *);
__printf(2, 3)
int bch2_fs_topology_error(struct bch_fs *, const char *, ...);

/*
 * Fsck errors: inconsistency errors we detect at mount time, and should ideally
 * be able to repair:
 */

struct fsck_err_state {
	struct list_head	list;
	enum bch_sb_error_id	id;
	u64			nr;
	bool			ratelimited;
	int			ret;
	int			fix;
	char			*last_msg;
};

#define fsck_err_count(_c, _err)	bch2_sb_err_count(_c, BCH_FSCK_ERR_##_err)

bool __bch2_count_fsck_err(struct bch_fs *, enum bch_sb_error_id, struct printbuf *);
#define bch2_count_fsck_err(_c, _err, ...)				\
	__bch2_count_fsck_err(_c, BCH_FSCK_ERR_##_err, __VA_ARGS__)

int bch2_fsck_err_opt(struct bch_fs *,
		      enum bch_fsck_flags,
		      enum bch_sb_error_id);

__printf(5, 6) __cold
int __bch2_fsck_err(struct bch_fs *, struct btree_trans *,
		  enum bch_fsck_flags,
		  enum bch_sb_error_id,
		  const char *, ...);
#define bch2_fsck_err(c, _flags, _err_type, ...)				\
	__bch2_fsck_err(type_is(c, struct bch_fs *) ? (struct bch_fs *) c : NULL,\
			type_is(c, struct btree_trans *) ? (struct btree_trans *) c : NULL,\
			_flags, BCH_FSCK_ERR_##_err_type, __VA_ARGS__)

void bch2_flush_fsck_errs(struct bch_fs *);
void bch2_free_fsck_errs(struct bch_fs *);

#define fsck_err_wrap(_do)						\
({									\
	int _ret = _do;							\
	if (!bch2_err_matches(_ret, BCH_ERR_fsck_fix) &&		\
	    !bch2_err_matches(_ret, BCH_ERR_fsck_ignore)) {		\
		ret = _ret;						\
		goto fsck_err;						\
	}								\
									\
	bch2_err_matches(_ret, BCH_ERR_fsck_fix);			\
})

#define __fsck_err(...)		fsck_err_wrap(bch2_fsck_err(__VA_ARGS__))

/* These macros return true if error should be fixed: */

/* XXX: mark in superblock that filesystem contains errors, if we ignore: */

#define __fsck_err_on(cond, c, _flags, _err_type, ...)			\
({									\
	might_sleep();							\
									\
	if (type_is(c, struct bch_fs *))				\
		WARN_ON(bch2_current_has_btree_trans((struct bch_fs *) c));\
									\
	(unlikely(cond) ? __fsck_err(c, _flags, _err_type, __VA_ARGS__) : false);\
})

#define mustfix_fsck_err(c, _err_type, ...)				\
	__fsck_err(c, FSCK_CAN_FIX, _err_type, __VA_ARGS__)

#define mustfix_fsck_err_on(cond, c, _err_type, ...)			\
	__fsck_err_on(cond, c, FSCK_CAN_FIX, _err_type, __VA_ARGS__)

#define fsck_err(c, _err_type, ...)					\
	__fsck_err(c, FSCK_CAN_FIX|FSCK_CAN_IGNORE, _err_type, __VA_ARGS__)

#define fsck_err_on(cond, c, _err_type, ...)				\
	__fsck_err_on(cond, c, FSCK_CAN_FIX|FSCK_CAN_IGNORE, _err_type, __VA_ARGS__)

#define log_fsck_err(c, _err_type, ...)					\
	__fsck_err(c, FSCK_CAN_IGNORE, _err_type, __VA_ARGS__)

#define log_fsck_err_on(cond, ...)					\
({									\
	bool _ret = unlikely(!!(cond));					\
	if (_ret)							\
		log_fsck_err(__VA_ARGS__);				\
	_ret;								\
})

enum bch_validate_flags;
__printf(5, 6)
int __bch2_bkey_fsck_err(struct bch_fs *,
			 struct bkey_s_c,
			 struct bkey_validate_context from,
			 enum bch_sb_error_id,
			 const char *, ...);

/*
 * for now, bkey fsck errors are always handled by deleting the entire key -
 * this will change at some point
 */
#define bkey_fsck_err(c, _err_type, _err_msg, ...)			\
do {									\
	int _ret = __bch2_bkey_fsck_err(c, k, from,			\
				BCH_FSCK_ERR_##_err_type,		\
				_err_msg, ##__VA_ARGS__);		\
	if (!bch2_err_matches(_ret, BCH_ERR_fsck_fix) &&		\
	    !bch2_err_matches(_ret, BCH_ERR_fsck_ignore))		\
		ret = _ret;						\
	else								\
		ret = bch_err_throw(c, fsck_delete_bkey);		\
	goto fsck_err;							\
} while (0)

#define bkey_fsck_err_on(cond, ...)					\
do {									\
	if (unlikely(cond))						\
		bkey_fsck_err(__VA_ARGS__);				\
} while (0)

/*
 * Fatal errors: these don't indicate a bug, but we can't continue running in RW
 * mode - pretty much just due to metadata IO errors:
 */

void bch2_fatal_error(struct bch_fs *);

#define bch2_fs_fatal_error(c, _msg, ...)				\
do {									\
	bch_err(c, "%s(): fatal error " _msg, __func__, ##__VA_ARGS__);	\
	bch2_fatal_error(c);						\
} while (0)

#define bch2_fs_fatal_err_on(cond, c, ...)				\
({									\
	bool _ret = unlikely(!!(cond));					\
									\
	if (_ret)							\
		bch2_fs_fatal_error(c, __VA_ARGS__);			\
	_ret;								\
})

/*
 * IO errors: either recoverable metadata IO (because we have replicas), or data
 * IO - we need to log it and print out a message, but we don't (necessarily)
 * want to shut down the fs:
 */

void bch2_io_error_work(struct work_struct *);

/* Does the error handling without logging a message */
void bch2_io_error(struct bch_dev *, enum bch_member_error_type);

#ifndef CONFIG_BCACHEFS_NO_LATENCY_ACCT
void bch2_latency_acct(struct bch_dev *, u64, int);
#else
static inline void bch2_latency_acct(struct bch_dev *ca, u64 submit_time, int rw) {}
#endif

static inline void bch2_account_io_success_fail(struct bch_dev *ca,
						enum bch_member_error_type type,
						bool success)
{
	if (likely(success)) {
		if (type == BCH_MEMBER_ERROR_write &&
		    ca->write_errors_start)
			ca->write_errors_start = 0;
	} else {
		bch2_io_error(ca, type);
	}
}

static inline void bch2_account_io_completion(struct bch_dev *ca,
					      enum bch_member_error_type type,
					      u64 submit_time, bool success)
{
	if (unlikely(!ca))
		return;

	if (type != BCH_MEMBER_ERROR_checksum)
		bch2_latency_acct(ca, submit_time, type);

	bch2_account_io_success_fail(ca, type, success);
}

int bch2_inum_offset_err_msg_trans(struct btree_trans *, struct printbuf *, subvol_inum, u64);

void bch2_inum_offset_err_msg(struct bch_fs *, struct printbuf *, subvol_inum, u64);

int bch2_inum_snap_offset_err_msg_trans(struct btree_trans *, struct printbuf *, struct bpos);
void bch2_inum_snap_offset_err_msg(struct bch_fs *, struct printbuf *, struct bpos);

#endif /* _BCACHEFS_ERROR_H */
