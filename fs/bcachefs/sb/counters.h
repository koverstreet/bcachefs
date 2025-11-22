/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_SB_COUNTERS_H
#define _BCACHEFS_SB_COUNTERS_H

#include "bcachefs.h"
#include "sb/io.h"

int bch2_sb_counters_to_cpu(struct bch_fs *);
int bch2_sb_counters_from_cpu(struct bch_fs *);

void bch2_fs_counters_exit(struct bch_fs *);
int bch2_fs_counters_init(struct bch_fs *);

extern const char * const bch2_counter_names[];
extern const struct bch_sb_field_ops bch_sb_field_ops_counters;

long bch2_ioctl_query_counters(struct bch_fs *,
			struct bch_ioctl_query_counters __user *);

#define count_event(_c, _name)	this_cpu_inc((_c)->counters.now[BCH_COUNTER_##_name])

#define trace_and_count(_c, _name, ...)					\
do {									\
	count_event(_c, _name);						\
	trace_##_name(__VA_ARGS__);					\
} while (0)

#endif // _BCACHEFS_SB_COUNTERS_H
