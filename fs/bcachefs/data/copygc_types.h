/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_COPYGC_TYPES_H
#define _BCACHEFS_COPYGC_TYPES_H

struct bch_fs_copygc {
	struct task_struct	*thread;
	struct write_point	write_point;
	s64			wait_at;
	s64			wait;
	bool			running;
	wait_queue_head_t	running_wq;
};

#endif /* _BCACHEFS_COPYGC_TYPES_H */

