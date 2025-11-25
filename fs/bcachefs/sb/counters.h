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

void bch2_sb_recent_counters_to_text(struct printbuf *out, struct bch_fs_counters *c);

#define counter_typecheck(_name, _type)					\
	BUILD_BUG_ON(bch2_counter_flags[BCH_COUNTER_##_name] != _type)

#define event_inc(_c, _name)						\
do {									\
	counter_typecheck(_name, TYPE_COUNTER);				\
	this_cpu_inc((_c)->counters.now[BCH_COUNTER_##_name]);		\
} while (0)

#define event_add(_c, _name, _nr)					\
do {									\
	counter_typecheck(_name, TYPE_SECTORS);				\
	this_cpu_add((_c)->counters.now[BCH_COUNTER_##_name], _nr);	\
} while (0)

#define event_trace(_c, _name, _buf, ...)				\
do {									\
	if (trace_##_name##_enabled()) {				\
		CLASS(printbuf, _buf)();				\
		printbuf_indent_add_nextline(&_buf, 2);			\
		__VA_ARGS__;						\
		trace_##_name(_c, _buf.buf);				\
	}								\
} while (0)

#define event_add_trace(_c, _name, _nr, ...)				\
do {									\
	event_trace(_c, _name, __VA_ARGS__);				\
	event_add(_c, _name, _nr);					\
} while (0)

#define event_inc_trace(_c, _name, ...)					\
do {									\
	event_trace(_c, _name, __VA_ARGS__);				\
	event_inc(_c, _name);						\
} while (0)

#endif // _BCACHEFS_SB_COUNTERS_H
