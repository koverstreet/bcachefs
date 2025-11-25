/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM bcachefs

#if !defined(_TRACE_BCACHEFS_H) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(fs_str,
	TP_PROTO(struct bch_fs *c, const char *str),
	TP_ARGS(c, str),

	TP_STRUCT__entry(
		__array(char,		fs, 32			)
		__string(str,		str			)
	),

	TP_fast_assign(
		strscpy(__entry->fs, c->name, sizeof(__entry->fs));
		__assign_str(str);
	),

	TP_printk("%s: %s", __entry->fs, __get_str(str))
);

#define BCH_NOCOUNTER_TRACEPOINTS()					\
	x(accounting_mem_insert)					\
	x(journal_entry_close)						\
	x(extent_trim_atomic)						\
	x(path_downgrade)						\
	x(btree_iter_peek_slot)						\
	x(__btree_iter_peek)						\
	x(btree_iter_peek_max)						\
	x(btree_iter_peek_prev_min)

#define __BCH_PATH_TRACEPOINTS()					\
	x(update_by_path)						\
	x(btree_path_traverse_start)					\
	x(btree_path_traverse_end)					\
	x(btree_path_set_pos)						\
	x(btree_path_lock)						\
	x(btree_path_should_be_locked)					\
	x(btree_path_clone)						\
	x(btree_path_save_pos)						\
	x(btree_path_get_ll)						\
	x(btree_path_put_ll)						\
	x(btree_path_get)						\
	x(btree_path_alloc)						\
	x(btree_path_free)

#ifdef CONFIG_BCACHEFS_PATH_TRACEPOINTS
#define BCH_PATH_TRACEPOINTS()		__BCH_PATH_TRACEPOINTS()
#else
#define BCH_PATH_TRACEPOINTS()

#ifndef _TRACE_BCACHEFS_H
#define x(n, ...)							\
	static inline void trace_##n(struct bch_fs *c, const char *s) {}\
	static inline bool trace_##n##_enabled(void) { return false; }
	__BCH_PATH_TRACEPOINTS()
#undef x
#endif /* _TRACE_BCACHEFS_H */

#endif

#define x(n, ...)							\
	DEFINE_EVENT(fs_str, n,						\
		TP_PROTO(struct bch_fs *c, const char *str),		\
		TP_ARGS(c, str)						\
	);
	BCH_PERSISTENT_COUNTERS()
	BCH_NOCOUNTER_TRACEPOINTS()
	BCH_PATH_TRACEPOINTS()
#undef x

#define _TRACE_BCACHEFS_H
#endif /* _TRACE_BCACHEFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../fs/bcachefs/debug

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

#include <trace/define_trace.h>
