#ifndef _BCACHEFS_RECOVERY_PASSES_H
#define _BCACHEFS_RECOVERY_PASSES_H

#include <linux/kthread.h>

extern const char * const bch2_recovery_passes[];

extern const struct bch_sb_field_ops bch_sb_field_ops_recovery_passes;

u64 bch2_recovery_passes_to_stable(u64 v);
u64 bch2_recovery_passes_from_stable(u64 v);

u64 bch2_fsck_recovery_passes(void);

void bch2_recovery_pass_set_no_ratelimit(struct bch_fs *, enum bch_recovery_pass);

enum bch_run_recovery_pass_flags {
	RUN_RECOVERY_PASS_nopersistent	= BIT(0),
	RUN_RECOVERY_PASS_ratelimit	= BIT(1),
};

static inline bool go_rw_in_recovery(struct bch_fs *c)
{
	return test_bit(BCH_FS_may_upgrade_downgrade, &c->flags) &&
		(c->journal_keys.nr ||
		!c->opts.read_only ||
		!c->sb.clean ||
		c->opts.recovery_passes ||
		(c->opts.fsck && !(c->sb.features & BIT_ULL(BCH_FEATURE_no_alloc_info))));
}

static inline bool recovery_pass_will_run(struct bch_fs *c, enum bch_recovery_pass pass)
{
	return unlikely(test_bit(BCH_FS_in_recovery, &c->flags) &&
			c->recovery.current_passes & BIT_ULL(pass));
}

static inline int bch2_recovery_cancelled(struct bch_fs *c)
{
	if (test_bit(BCH_FS_going_ro, &c->flags))
		return bch_err_throw(c, erofs_recovery_cancelled);

	if ((current->flags & PF_KTHREAD) && kthread_should_stop())
		return bch_err_throw(c, recovery_cancelled);

	return 0;
}

bool bch2_recovery_pass_want_ratelimit(struct bch_fs *, enum bch_recovery_pass, unsigned);

int __bch2_run_explicit_recovery_pass(struct bch_fs *, struct printbuf *,
				      enum bch_recovery_pass,
				      enum bch_run_recovery_pass_flags,
				      bool *);
int bch2_run_explicit_recovery_pass(struct bch_fs *, struct printbuf *,
				    enum bch_recovery_pass,
				    enum bch_run_recovery_pass_flags);

int bch2_require_recovery_pass(struct bch_fs *, struct printbuf *,
			       enum bch_recovery_pass);

u64 bch2_recovery_passes_match(unsigned);
void bch2_run_async_recovery_passes(struct bch_fs *);
int bch2_run_recovery_passes(struct bch_fs *, u64, bool);
int bch2_run_recovery_passes_startup(struct bch_fs *, enum bch_recovery_pass);

void bch2_recovery_pass_status_to_text(struct printbuf *, struct bch_fs *);

void bch2_fs_recovery_passes_init(struct bch_fs *);

#endif /* _BCACHEFS_RECOVERY_PASSES_H */
