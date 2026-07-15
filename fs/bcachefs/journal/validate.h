/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_JOURNAL_VALIDATE_H
#define _BCACHEFS_JOURNAL_VALIDATE_H

void bch2_journal_entry_err_msg(struct printbuf *, u32,
				struct jset *, struct jset_entry *);

#define journal_entry_err(c, version, jset, entry, _err, msg, ...)	\
({									\
	CLASS(printbuf, _buf)();					\
									\
	bch2_journal_entry_err_msg(&_buf, version, jset, entry);	\
	prt_printf(&_buf, msg, ##__VA_ARGS__);				\
									\
	switch (from.flags & BCH_VALIDATE_write) {			\
	case READ:							\
		mustfix_fsck_err(c, _err, "%s", _buf.buf);		\
		break;							\
	case WRITE:							\
		bch2_sb_error_count(c, BCH_FSCK_ERR_##_err);		\
		if (bch2_fs_inconsistent(c,				\
				"corrupt metadata before write: %s\n", _buf.buf)) {\
			ret = bch_err_throw(c, fsck_errors_not_fixed);		\
			goto fsck_err;					\
		}							\
		break;							\
	}								\
									\
	true;								\
})

#define journal_entry_err_on(cond, ...)					\
	((cond) ? journal_entry_err(__VA_ARGS__) : false)

int bch2_journal_entry_validate(struct bch_fs *, struct jset *,
				struct jset_entry *, unsigned, int,
				struct bkey_validate_context);
void bch2_journal_entry_to_text(struct printbuf *, struct bch_fs *,
				struct jset_entry *);

int bch2_jset_validate(struct bch_fs *, struct bch_dev *, struct jset *,
		       u64, enum bch_validate_flags);

int bch2_jset_validate_early(struct bch_fs *, struct bch_dev *,
			     struct jset *, u64, unsigned);

#define JOURNAL_ENTRY_NONE	6
#define JOURNAL_ENTRY_BAD	7

#endif /* _BCACHEFS_JOURNAL_VALIDATE_H */
