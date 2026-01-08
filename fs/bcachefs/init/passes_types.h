/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_RECOVERY_PASSES_TYPES_H
#define _BCACHEFS_RECOVERY_PASSES_TYPES_H

struct bch_fs_recovery {
	/* counterpart to c->sb.recovery_passes_required */
	u64			scheduled_passes_ephemeral;

	u64			current_passes;
	enum bch_recovery_pass	current_pass;
	enum bch_recovery_pass	rewound_from;
	enum bch_recovery_pass	rewound_to;

	/* never rewinds version of curr_pass */
	enum bch_recovery_pass	pass_done;

	/* bitmask of recovery passes that we actually ran */
	u64			passes_complete;
	u64			passes_failing;
	u64			passes_ratelimiting;

	spinlock_t		lock;
	struct mutex		run_lock;
	struct work_struct	work;
};

#endif /* _BCACHEFS_RECOVERY_PASSES_TYPES_H */
