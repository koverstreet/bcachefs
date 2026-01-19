/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_REBALANCE_TYPES_H
#define _BCACHEFS_REBALANCE_TYPES_H

#include "btree/bbpos_types.h"
#include "data/move_types.h"

struct bch_fs_reconcile {
	struct task_struct __rcu	*thread;
	u32				kick;

	bool				running;
	u64				wait_iotime_start;
	u64				wait_iotime_end;
	u64				wait_wallclock_start;

	struct bbpos			work_pos;
	struct bch_move_stats		work_stats;

	struct bbpos			scan_start;
	struct bbpos			scan_end;
	struct bch_move_stats		scan_stats;

	bool				on_battery;
#ifdef CONFIG_POWER_SUPPLY
	struct notifier_block		power_notifier;
#endif
};

#endif /* _BCACHEFS_REBALANCE_TYPES_H */
