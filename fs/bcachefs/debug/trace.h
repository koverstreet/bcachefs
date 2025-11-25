/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM bcachefs

#if !defined(_TRACE_BCACHEFS_H) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>

#define TRACE_BPOS_entries(name)				\
	__field(u64,			name##_inode	)	\
	__field(u64,			name##_offset	)	\
	__field(u32,			name##_snapshot	)

#define TRACE_BPOS_assign(dst, src)				\
	__entry->dst##_inode		= (src).inode;		\
	__entry->dst##_offset		= (src).offset;		\
	__entry->dst##_snapshot		= (src).snapshot

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

#define BCH_NOCOUNTER_TRACEPOINTS()				\
	x(accounting_mem_insert)				\
	x(journal_entry_close)					\
	x(extent_trim_atomic)					\
	x(path_downgrade)					\
	x(btree_iter_peek_slot)					\
	x(__btree_iter_peek)					\
	x(btree_iter_peek_max)					\
	x(btree_iter_peek_prev_min)

#define x(n, ...)						\
	DEFINE_EVENT(fs_str, n,					\
		TP_PROTO(struct bch_fs *c, const char *str),	\
		TP_ARGS(c, str)					\
	);
	BCH_PERSISTENT_COUNTERS()
	BCH_NOCOUNTER_TRACEPOINTS()
#undef x

#ifdef CONFIG_BCACHEFS_PATH_TRACEPOINTS

TRACE_EVENT(update_by_path,
	TP_PROTO(struct btree_trans *trans, struct btree_path *path,
		 struct btree_insert_entry *i, bool overwrite),
	TP_ARGS(trans, path, i, overwrite),

	TP_STRUCT__entry(
		__array(char,			trans_fn, 32	)
		__field(btree_path_idx_t,	path_idx	)
		__field(u8,			btree_id	)
		TRACE_BPOS_entries(pos)
		__field(u8,			overwrite	)
		__field(btree_path_idx_t,	update_idx	)
		__field(btree_path_idx_t,	nr_updates	)
	),

	TP_fast_assign(
		strscpy(__entry->trans_fn, trans->fn, sizeof(__entry->trans_fn));
		__entry->path_idx		= path - trans->paths;
		__entry->btree_id		= path->btree_id;
		TRACE_BPOS_assign(pos, path->pos);
		__entry->overwrite		= overwrite;
		__entry->update_idx		= i - trans->updates;
		__entry->nr_updates		= trans->nr_updates;
	),

	TP_printk("%s path %3u btree %s pos %llu:%llu:%u overwrite %u update %u/%u",
		  __entry->trans_fn,
		  __entry->path_idx,
		  bch2_btree_id_str(__entry->btree_id),
		  __entry->pos_inode,
		  __entry->pos_offset,
		  __entry->pos_snapshot,
		  __entry->overwrite,
		  __entry->update_idx,
		  __entry->nr_updates)
);

TRACE_EVENT(btree_path_lock,
	TP_PROTO(struct btree_trans *trans,
		 unsigned long caller_ip,
		 struct btree_bkey_cached_common *b),
	TP_ARGS(trans, caller_ip, b),

	TP_STRUCT__entry(
		__array(char,			trans_fn, 32	)
		__field(unsigned long,		caller_ip	)
		__field(u8,			btree_id	)
		__field(u8,			level		)
		__array(char,			node, 24	)
		__field(u32,			lock_seq	)
	),

	TP_fast_assign(
		strscpy(__entry->trans_fn, trans->fn, sizeof(__entry->trans_fn));
		__entry->caller_ip		= caller_ip;
		__entry->btree_id		= b->btree_id;
		__entry->level			= b->level;

		scnprintf(__entry->node, sizeof(__entry->node), "%px", b);
		__entry->lock_seq		= six_lock_seq(&b->lock);
	),

	TP_printk("%s %pS\nbtree %s level %u node %s lock seq %u",
		  __entry->trans_fn,
		  (void *) __entry->caller_ip,
		  bch2_btree_id_str(__entry->btree_id),
		  __entry->level,
		  __entry->node,
		  __entry->lock_seq)
);

DECLARE_EVENT_CLASS(btree_path_ev,
	TP_PROTO(struct btree_trans *trans, struct btree_path *path),
	TP_ARGS(trans, path),

	TP_STRUCT__entry(
		__field(u16,			idx		)
		__field(u8,			ref		)
		__field(u8,			btree_id	)
		TRACE_BPOS_entries(pos)
	),

	TP_fast_assign(
		__entry->idx			= path - trans->paths;
		__entry->ref			= path->ref;
		__entry->btree_id		= path->btree_id;
		TRACE_BPOS_assign(pos, path->pos);
	),

	TP_printk("path %3u ref %u btree %s pos %llu:%llu:%u",
		  __entry->idx, __entry->ref,
		  bch2_btree_id_str(__entry->btree_id),
		  __entry->pos_inode,
		  __entry->pos_offset,
		  __entry->pos_snapshot)
);

DEFINE_EVENT(btree_path_ev, btree_path_get_ll,
	TP_PROTO(struct btree_trans *trans, struct btree_path *path),
	TP_ARGS(trans, path)
);

DEFINE_EVENT(btree_path_ev, btree_path_put_ll,
	TP_PROTO(struct btree_trans *trans, struct btree_path *path),
	TP_ARGS(trans, path)
);

DEFINE_EVENT(btree_path_ev, btree_path_should_be_locked,
	TP_PROTO(struct btree_trans *trans, struct btree_path *path),
	TP_ARGS(trans, path)
);

TRACE_EVENT(btree_path_alloc,
	TP_PROTO(struct btree_trans *trans, struct btree_path *path),
	TP_ARGS(trans, path),

	TP_STRUCT__entry(
		__field(btree_path_idx_t,	idx		)
		__field(u8,			locks_want	)
		__field(u8,			btree_id	)
		TRACE_BPOS_entries(pos)
	),

	TP_fast_assign(
		__entry->idx			= path - trans->paths;
		__entry->locks_want		= path->locks_want;
		__entry->btree_id		= path->btree_id;
		TRACE_BPOS_assign(pos, path->pos);
	),

	TP_printk("path %3u btree %s locks_want %u pos %llu:%llu:%u",
		  __entry->idx,
		  bch2_btree_id_str(__entry->btree_id),
		  __entry->locks_want,
		  __entry->pos_inode,
		  __entry->pos_offset,
		  __entry->pos_snapshot)
);

TRACE_EVENT(btree_path_get,
	TP_PROTO(struct btree_trans *trans, struct btree_path *path, struct bpos *new_pos),
	TP_ARGS(trans, path, new_pos),

	TP_STRUCT__entry(
		__field(btree_path_idx_t,	idx		)
		__field(u8,			ref		)
		__field(u8,			preserve	)
		__field(u8,			locks_want	)
		__field(u8,			btree_id	)
		TRACE_BPOS_entries(old_pos)
		TRACE_BPOS_entries(new_pos)
	),

	TP_fast_assign(
		__entry->idx			= path - trans->paths;
		__entry->ref			= path->ref;
		__entry->preserve		= path->preserve;
		__entry->locks_want		= path->locks_want;
		__entry->btree_id		= path->btree_id;
		TRACE_BPOS_assign(old_pos, path->pos);
		TRACE_BPOS_assign(new_pos, *new_pos);
	),

	TP_printk("    path %3u ref %u preserve %u btree %s locks_want %u pos %llu:%llu:%u -> %llu:%llu:%u",
		  __entry->idx,
		  __entry->ref,
		  __entry->preserve,
		  bch2_btree_id_str(__entry->btree_id),
		  __entry->locks_want,
		  __entry->old_pos_inode,
		  __entry->old_pos_offset,
		  __entry->old_pos_snapshot,
		  __entry->new_pos_inode,
		  __entry->new_pos_offset,
		  __entry->new_pos_snapshot)
);

DECLARE_EVENT_CLASS(btree_path_clone,
	TP_PROTO(struct btree_trans *trans, struct btree_path *path, struct btree_path *new),
	TP_ARGS(trans, path, new),

	TP_STRUCT__entry(
		__field(btree_path_idx_t,	idx		)
		__field(u8,			new_idx		)
		__field(u8,			btree_id	)
		__field(u8,			ref		)
		__field(u8,			preserve	)
		TRACE_BPOS_entries(pos)
	),

	TP_fast_assign(
		__entry->idx			= path - trans->paths;
		__entry->new_idx		= new - trans->paths;
		__entry->btree_id		= path->btree_id;
		__entry->ref			= path->ref;
		__entry->preserve		= path->preserve;
		TRACE_BPOS_assign(pos, path->pos);
	),

	TP_printk("  path %3u ref %u preserve %u btree %s %llu:%llu:%u -> %u",
		  __entry->idx,
		  __entry->ref,
		  __entry->preserve,
		  bch2_btree_id_str(__entry->btree_id),
		  __entry->pos_inode,
		  __entry->pos_offset,
		  __entry->pos_snapshot,
		  __entry->new_idx)
);

DEFINE_EVENT(btree_path_clone, btree_path_clone,
	TP_PROTO(struct btree_trans *trans, struct btree_path *path, struct btree_path *new),
	TP_ARGS(trans, path, new)
);

DEFINE_EVENT(btree_path_clone, btree_path_save_pos,
	TP_PROTO(struct btree_trans *trans, struct btree_path *path, struct btree_path *new),
	TP_ARGS(trans, path, new)
);

DECLARE_EVENT_CLASS(btree_path_traverse,
	TP_PROTO(struct btree_trans *trans,
		 struct btree_path *path),
	TP_ARGS(trans, path),

	TP_STRUCT__entry(
		__array(char,			trans_fn, 32	)
		__field(btree_path_idx_t,	idx		)
		__field(u8,			ref		)
		__field(u8,			preserve	)
		__field(u8,			should_be_locked )
		__field(u8,			btree_id	)
		__field(u8,			level		)
		TRACE_BPOS_entries(pos)
		__field(u8,			locks_want	)
		__field(u8,			nodes_locked	)
		__array(char,			node0, 24	)
		__array(char,			node1, 24	)
		__array(char,			node2, 24	)
		__array(char,			node3, 24	)
	),

	TP_fast_assign(
		strscpy(__entry->trans_fn, trans->fn, sizeof(__entry->trans_fn));

		__entry->idx			= path - trans->paths;
		__entry->ref			= path->ref;
		__entry->preserve		= path->preserve;
		__entry->btree_id		= path->btree_id;
		__entry->level			= path->level;
		TRACE_BPOS_assign(pos, path->pos);

		__entry->locks_want		= path->locks_want;
		__entry->nodes_locked		= path->nodes_locked;
		struct btree *b = path->l[0].b;
		if (IS_ERR(b))
			strscpy(__entry->node0, bch2_err_str(PTR_ERR(b)), sizeof(__entry->node0));
		else
			scnprintf(__entry->node0, sizeof(__entry->node0), "%px", &b->c);
		b = path->l[1].b;
		if (IS_ERR(b))
			strscpy(__entry->node1, bch2_err_str(PTR_ERR(b)), sizeof(__entry->node0));
		else
			scnprintf(__entry->node1, sizeof(__entry->node0), "%px", &b->c);
		b = path->l[2].b;
		if (IS_ERR(b))
			strscpy(__entry->node2, bch2_err_str(PTR_ERR(b)), sizeof(__entry->node0));
		else
			scnprintf(__entry->node2, sizeof(__entry->node0), "%px", &b->c);
		b = path->l[3].b;
		if (IS_ERR(b))
			strscpy(__entry->node3, bch2_err_str(PTR_ERR(b)), sizeof(__entry->node0));
		else
			scnprintf(__entry->node3, sizeof(__entry->node0), "%px", &b->c);
	),

	TP_printk("%s\npath %3u ref %u preserve %u btree %s %llu:%llu:%u level %u locks_want %u\n"
		  "locks %u %u %u %u node %s %s %s %s",
		  __entry->trans_fn,
		  __entry->idx,
		  __entry->ref,
		  __entry->preserve,
		  bch2_btree_id_str(__entry->btree_id),
		  __entry->pos_inode,
		  __entry->pos_offset,
		  __entry->pos_snapshot,
		  __entry->level,
		  __entry->locks_want,
		  (__entry->nodes_locked >> 6) & 3,
		  (__entry->nodes_locked >> 4) & 3,
		  (__entry->nodes_locked >> 2) & 3,
		  (__entry->nodes_locked >> 0) & 3,
		  __entry->node3,
		  __entry->node2,
		  __entry->node1,
		  __entry->node0)
);

DEFINE_EVENT(btree_path_traverse, btree_path_traverse_start,
	TP_PROTO(struct btree_trans *trans,
		 struct btree_path *path),
	TP_ARGS(trans, path)
);

DEFINE_EVENT(btree_path_traverse, btree_path_traverse_end,
	TP_PROTO(struct btree_trans *trans, struct btree_path *path),
	TP_ARGS(trans, path)
);

DEFINE_EVENT(fs_str,	btree_path_set_pos,
	TP_PROTO(struct bch_fs *c, const char *str),
	TP_ARGS(c, str)
);

TRACE_EVENT(btree_path_free,
	TP_PROTO(struct btree_trans *trans, btree_path_idx_t path, struct btree_path *dup),
	TP_ARGS(trans, path, dup),

	TP_STRUCT__entry(
		__field(btree_path_idx_t,	idx		)
		__field(u8,			preserve	)
		__field(u8,			should_be_locked)
		__field(s8,			dup		)
		__field(u8,			dup_locked	)
	),

	TP_fast_assign(
		__entry->idx			= path;
		__entry->preserve		= trans->paths[path].preserve;
		__entry->should_be_locked	= trans->paths[path].should_be_locked;
		__entry->dup			= dup ? dup - trans->paths  : -1;
		__entry->dup_locked		= dup ? btree_node_locked(dup, dup->level) : 0;
	),

	TP_printk("   path %3u %c %c dup %2i locked %u", __entry->idx,
		  __entry->preserve ? 'P' : ' ',
		  __entry->should_be_locked ? 'S' : ' ',
		  __entry->dup,
		  __entry->dup_locked)
);

#else /* CONFIG_BCACHEFS_PATH_TRACEPOINTS */
#ifndef _TRACE_BCACHEFS_H

static inline void trace_update_by_path(struct btree_trans *trans, struct btree_path *path,
					struct btree_insert_entry *i, bool overwrite) {}
static inline void trace_btree_path_lock(struct btree_trans *trans, unsigned long caller_ip, struct btree_bkey_cached_common *b) {}
static inline void trace_btree_path_get_ll(struct btree_trans *trans, struct btree_path *path) {}
static inline void trace_btree_path_put_ll(struct btree_trans *trans, struct btree_path *path) {}
static inline void trace_btree_path_should_be_locked(struct btree_trans *trans, struct btree_path *path) {}
static inline void trace_btree_path_alloc(struct btree_trans *trans, struct btree_path *path) {}
static inline void trace_btree_path_get(struct btree_trans *trans, struct btree_path *path, struct bpos *new_pos) {}
static inline void trace_btree_path_clone(struct btree_trans *trans, struct btree_path *path, struct btree_path *new) {}
static inline void trace_btree_path_save_pos(struct btree_trans *trans, struct btree_path *path, struct btree_path *new) {}
static inline void trace_btree_path_traverse_start(struct btree_trans *trans, struct btree_path *path) {}
static inline void trace_btree_path_traverse_end(struct btree_trans *trans, struct btree_path *path) {}
static inline void trace_btree_path_set_pos(struct bch_fs *c, const char *str) {}
static inline void trace_btree_path_free(struct btree_trans *trans, btree_path_idx_t path, struct btree_path *dup) {}

static inline bool trace_btree_path_set_pos_enabled(void) { return false; }

#endif
#endif /* CONFIG_BCACHEFS_PATH_TRACEPOINTS */

#define _TRACE_BCACHEFS_H
#endif /* _TRACE_BCACHEFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../fs/bcachefs/debug

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

#include <trace/define_trace.h>
