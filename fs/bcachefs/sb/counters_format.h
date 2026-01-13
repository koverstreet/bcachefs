/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_SB_COUNTERS_FORMAT_H
#define _BCACHEFS_SB_COUNTERS_FORMAT_H

enum bch_counters_flags {
	TYPE_COUNTER	= BIT(0),	/* event counters */
	TYPE_SECTORS	= BIT(1),	/* amount counters, the unit is sectors */
};

#define BCH_PERSISTENT_COUNTERS()					\
	x(sync_fs,					110,	TYPE_COUNTER)	\
	x(fsync,					111,	TYPE_COUNTER)	\
	x(data_read,					0,	TYPE_SECTORS)	\
	x(data_read_inline,				80,	TYPE_SECTORS)	\
	x(data_read_hole,				81,	TYPE_SECTORS)	\
	x(data_read_promote,				30,	TYPE_SECTORS)	\
	x(data_read_nopromote,				85,	TYPE_COUNTER)	\
	x(data_read_nopromote_may_not,			86,	TYPE_COUNTER)	\
	x(data_read_nopromote_already_promoted,		87,	TYPE_COUNTER)	\
	x(data_read_nopromote_unwritten,		88,	TYPE_COUNTER)	\
	x(data_read_nopromote_congested,		89,	TYPE_COUNTER)	\
	x(data_read_bounce,				31,	TYPE_COUNTER)	\
	x(data_read_split,				33,	TYPE_COUNTER)	\
	x(data_read_reuse_race,				34,	TYPE_COUNTER)	\
	x(data_read_retry,				32,	TYPE_COUNTER)	\
	x(data_read_fail_and_poison,			95,	TYPE_COUNTER)	\
	x(data_read_narrow_crcs,			97,	TYPE_COUNTER)	\
	x(data_read_narrow_crcs_fail,			98,	TYPE_COUNTER)	\
	x(data_write,					1,	TYPE_SECTORS)	\
	x(data_update_pred,				96,	TYPE_SECTORS)	\
	x(data_update,					2,	TYPE_SECTORS)	\
	x(data_update_no_io,				91,	TYPE_SECTORS)	\
	x(data_update_in_flight,			90,	TYPE_COUNTER)	\
	x(data_update_fail,				82,	TYPE_SECTORS)	\
	x(data_update_read,				35,	TYPE_SECTORS)	\
	x(data_update_write,				36,	TYPE_SECTORS)	\
	x(data_update_key,				37,	TYPE_SECTORS)	\
	x(data_update_key_fail,				38,	TYPE_SECTORS)	\
	x(data_update_start_fail_obsolete,		39,	TYPE_COUNTER)	\
	x(data_update_noop_obsolete,			92,	TYPE_COUNTER)	\
	x(reconcile_scan_fs,				113,	TYPE_SECTORS)	\
	x(reconcile_scan_metadata,			114,	TYPE_SECTORS)	\
	x(reconcile_scan_pending,			115,	TYPE_SECTORS)	\
	x(reconcile_scan_device,			116,	TYPE_SECTORS)	\
	x(reconcile_scan_inum,				117,	TYPE_SECTORS)	\
	x(reconcile_btree,				118,	TYPE_SECTORS)	\
	x(reconcile_data,				119,	TYPE_SECTORS)	\
	x(reconcile_phys,				120,	TYPE_SECTORS)	\
	x(reconcile_set_pending,			83,	TYPE_SECTORS)	\
	x(evacuate_bucket,				84,	TYPE_COUNTER)	\
	x(stripe_alloc,					125,	TYPE_COUNTER)	\
	x(stripe_create,				102,	TYPE_COUNTER)	\
	x(stripe_reuse,					123,	TYPE_COUNTER)	\
	x(stripe_create_fail,				103,	TYPE_COUNTER)	\
	x(stripe_delete,				124,	TYPE_COUNTER)	\
	x(stripe_update_bucket,				104,	TYPE_COUNTER)	\
	x(stripe_update_extent,				99,	TYPE_COUNTER)	\
	x(stripe_update_extent_fail,			100,	TYPE_COUNTER)	\
	x(copygc,					40,	TYPE_COUNTER)	\
	x(copygc_wait_obsolete,				41,	TYPE_COUNTER)	\
	x(cached_ptr_drop,				121,	TYPE_SECTORS)	\
	x(bucket_invalidate,				3,	TYPE_COUNTER)	\
	x(bucket_discard_worker,			108,	TYPE_COUNTER)	\
	x(bucket_discard_fast_worker,			109,	TYPE_COUNTER)	\
	x(bucket_discard,				4,	TYPE_COUNTER)	\
	x(bucket_discard_fast,				79,	TYPE_COUNTER)	\
	x(bucket_alloc,					5,	TYPE_COUNTER)	\
	x(bucket_alloc_fail,				6,	TYPE_COUNTER)	\
	x(open_bucket_alloc_fail,			122,	TYPE_COUNTER)	\
	x(bucket_alloc_from_stripe,			127,	TYPE_COUNTER)	\
	x(sectors_alloc,				126,	TYPE_SECTORS)	\
	x(bkey_pack_pos_fail,				112,	TYPE_COUNTER)	\
	x(btree_cache_scan,				7,	TYPE_COUNTER)	\
	x(btree_cache_reap,				8,	TYPE_COUNTER)	\
	x(btree_cache_cannibalize,			9,	TYPE_COUNTER)	\
	x(btree_cache_cannibalize_lock,			10,	TYPE_COUNTER)	\
	x(btree_cache_cannibalize_lock_fail,		11,	TYPE_COUNTER)	\
	x(btree_cache_cannibalize_unlock,		12,	TYPE_COUNTER)	\
	x(btree_node_write,				13,	TYPE_COUNTER)	\
	x(btree_node_read,				14,	TYPE_COUNTER)	\
	x(btree_node_compact,				15,	TYPE_COUNTER)	\
	x(btree_node_merge,				16,	TYPE_COUNTER)	\
	x(btree_node_merge_attempt,			101,	TYPE_COUNTER)	\
	x(btree_node_split,				17,	TYPE_COUNTER)	\
	x(btree_node_rewrite,				18,	TYPE_COUNTER)	\
	x(btree_node_alloc,				19,	TYPE_COUNTER)	\
	x(btree_node_free,				20,	TYPE_COUNTER)	\
	x(btree_node_set_root,				21,	TYPE_COUNTER)	\
	x(btree_key_cache_fill,				107,	TYPE_COUNTER)	\
	x(btree_path_relock_fail,			22,	TYPE_COUNTER)	\
	x(btree_path_upgrade_fail,			23,	TYPE_COUNTER)	\
	x(btree_reserve_get_fail,			24,	TYPE_COUNTER)	\
	x(journal_entry_full,				25,	TYPE_COUNTER)	\
	x(journal_full,					26,	TYPE_COUNTER)	\
	x(journal_reclaim_finish,			27,	TYPE_COUNTER)	\
	x(journal_reclaim_start,			28,	TYPE_COUNTER)	\
	x(journal_write,				29,	TYPE_COUNTER)	\
	x(gc_gens_end,					42,	TYPE_COUNTER)	\
	x(gc_gens_start,				43,	TYPE_COUNTER)	\
	x(trans_blocked_journal_reclaim,		44,	TYPE_COUNTER)	\
	x(trans_restart_btree_node_reused,		45,	TYPE_COUNTER)	\
	x(trans_restart_btree_node_split,		46,	TYPE_COUNTER)	\
	x(trans_restart_fault_inject,			47,	TYPE_COUNTER)	\
	x(trans_restart_iter_upgrade,			48,	TYPE_COUNTER)	\
	x(trans_restart_journal_preres_get,		49,	TYPE_COUNTER)	\
	x(trans_restart_journal_reclaim,		50,	TYPE_COUNTER)	\
	x(trans_restart_journal_res_get,		51,	TYPE_COUNTER)	\
	x(trans_restart_key_cache_key_realloced,	52,	TYPE_COUNTER)	\
	x(trans_restart_key_cache_raced,		53,	TYPE_COUNTER)	\
	x(trans_restart_mark_replicas,			54,	TYPE_COUNTER)	\
	x(trans_restart_mem_realloced,			55,	TYPE_COUNTER)	\
	x(trans_restart_memory_allocation_failure,	56,	TYPE_COUNTER)	\
	x(trans_restart_relock,				57,	TYPE_COUNTER)	\
	x(trans_restart_relock_after_fill,		58,	TYPE_COUNTER)	\
	x(trans_restart_relock_key_cache_fill_obsolete,	59,	TYPE_COUNTER)	\
	x(trans_restart_relock_next_node,		60,	TYPE_COUNTER)	\
	x(trans_restart_relock_parent_for_fill_obsolete,61,	TYPE_COUNTER)	\
	x(trans_restart_relock_path,			62,	TYPE_COUNTER)	\
	x(trans_restart_relock_path_intent,		63,	TYPE_COUNTER)	\
	x(trans_restart_too_many_iters,			64,	TYPE_COUNTER)	\
	x(trans_restart_traverse,			65,	TYPE_COUNTER)	\
	x(trans_restart_upgrade,			66,	TYPE_COUNTER)	\
	x(trans_restart_would_deadlock,			67,	TYPE_COUNTER)	\
	x(trans_restart_would_deadlock_write,		68,	TYPE_COUNTER)	\
	x(trans_restart_injected,			69,	TYPE_COUNTER)	\
	x(trans_restart_key_cache_upgrade,		70,	TYPE_COUNTER)	\
	x(trans_traverse_all,				71,	TYPE_COUNTER)	\
	x(transaction_commit,				72,	TYPE_COUNTER)	\
	x(write_super,					73,	TYPE_COUNTER)	\
	x(trans_restart_would_deadlock_recursion_limit,	74,	TYPE_COUNTER)	\
	x(trans_restart_write_buffer_flush,		75,	TYPE_COUNTER)	\
	x(trans_restart_split_race,			76,	TYPE_COUNTER)	\
	x(write_buffer_flush,				105,	TYPE_COUNTER)	\
	x(write_buffer_flush_slowpath,			77,	TYPE_COUNTER)	\
	x(write_buffer_flush_sync,			78,	TYPE_COUNTER)	\
	x(write_buffer_maybe_flush,			106,	TYPE_COUNTER)	\
	x(accounting_key_to_wb_slowpath,		94,	TYPE_COUNTER)	\
	x(error_throw,					93,	TYPE_COUNTER)

enum bch_persistent_counters {
#define x(t, n, ...) BCH_COUNTER_##t,
	BCH_PERSISTENT_COUNTERS()
#undef x
	BCH_COUNTER_NR
};

__maybe_unused
static const enum bch_counters_flags bch2_counter_flags[] = {
#define x(t, n, flags) [BCH_COUNTER_##t] = flags,
	BCH_PERSISTENT_COUNTERS()
#undef x
};

enum bch_persistent_counters_stable {
#define x(t, n, ...) BCH_COUNTER_STABLE_##t = n,
	BCH_PERSISTENT_COUNTERS()
#undef x
	BCH_COUNTER_STABLE_NR
};

struct bch_sb_field_counters {
	struct bch_sb_field	field;
	__le64			d[];
};

static inline void __maybe_unused check_bch_counter_ids_unique(void) {
	switch(0){
#define x(t, n, ...) case (n):
        BCH_PERSISTENT_COUNTERS();
#undef x
		;
	}
}

#endif /* _BCACHEFS_SB_COUNTERS_FORMAT_H */
