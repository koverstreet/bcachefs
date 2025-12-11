// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/accounting.h"
#include "alloc/buckets.h"
#include "alloc/check.h"
#include "alloc/replicas.h"

#include "btree/bkey_buf.h"
#include "btree/interior.h"
#include "btree/journal_overlay.h"
#include "btree/node_scan.h"
#include "btree/read.h"
#include "btree/update.h"

#include "data/move.h"
#include "data/copygc.h"
#include "data/reconcile.h"

#include "fs/dirent.h"
#include "fs/logged_ops.h"
#include "fs/namei.h"
#include "fs/quota.h"

#include "init/error.h"
#include "init/fs.h"
#include "init/passes.h"
#include "init/recovery.h"

#include "journal/init.h"
#include "journal/read.h"
#include "journal/reclaim.h"
#include "journal/sb.h"
#include "journal/seq_blacklist.h"

#include "sb/clean.h"
#include "sb/downgrade.h"
#include "sb/io.h"

#include "snapshots/snapshot.h"

#include <linux/sort.h>
#include <linux/stat.h>

int bch2_btree_lost_data(struct bch_fs *c,
			 struct printbuf *msg,
			 enum btree_id btree)
{
	int ret = 0;

	guard(mutex)(&c->sb_lock);
	bool write_sb = false;
	struct bch_sb_field_ext *ext = bch2_sb_field_get(c->disk_sb.sb, ext);

	if (!(c->sb.btrees_lost_data & BIT_ULL(btree))) {
		prt_printf(msg, "flagging btree ");
		bch2_btree_id_to_text(msg, btree);
		prt_printf(msg, " lost data\n");

		write_sb |= !__test_and_set_bit_le64(btree, &ext->btrees_lost_data);
	}

	/* Once we have runtime self healing for topology errors we won't need this: */
	ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_topology, 0, &write_sb) ?: ret;

	/* Btree node accounting will be off: */
	write_sb |= !__test_and_set_bit_le64(BCH_FSCK_ERR_accounting_mismatch, ext->errors_silent);
	ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_allocations, 0, &write_sb) ?: ret;

#ifdef CONFIG_BCACHEFS_DEBUG
	/*
	 * These are much more minor, and don't need to be corrected right away,
	 * but in debug mode we want the next fsck run to be clean:
	 */
	ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_lrus, 0, &write_sb) ?: ret;
#endif

	write_sb |= !__test_and_set_bit_le64(BCH_FSCK_ERR_lru_entry_bad, ext->errors_silent);
	write_sb |= !__test_and_set_bit_le64(BCH_FSCK_ERR_alloc_key_to_missing_lru_entry, ext->errors_silent);
	write_sb |= !__test_and_set_bit_le64(BCH_FSCK_ERR_backpointer_to_missing_ptr, ext->errors_silent);
	write_sb |= !__test_and_set_bit_le64(BCH_FSCK_ERR_alloc_key_data_type_wrong, ext->errors_silent);
	write_sb |= !__test_and_set_bit_le64(BCH_FSCK_ERR_alloc_key_dirty_sectors_wrong, ext->errors_silent);
	write_sb |= !__test_and_set_bit_le64(BCH_FSCK_ERR_need_discard_key_wrong, ext->errors_silent);
	write_sb |= !__test_and_set_bit_le64(BCH_FSCK_ERR_freespace_key_wrong, ext->errors_silent);

	switch (btree) {
	case BTREE_ID_alloc:
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_alloc_info, 0, &write_sb) ?: ret;

		write_sb |= !__test_and_set_bit_le64(BCH_FSCK_ERR_alloc_key_gen_wrong, ext->errors_silent);
		write_sb |= !__test_and_set_bit_le64(BCH_FSCK_ERR_alloc_key_cached_sectors_wrong, ext->errors_silent);
		write_sb |= !__test_and_set_bit_le64(BCH_FSCK_ERR_alloc_key_stripe_wrong, ext->errors_silent);
		write_sb |= !__test_and_set_bit_le64(BCH_FSCK_ERR_alloc_key_stripe_redundancy_wrong, ext->errors_silent);
		break;
	case BTREE_ID_backpointers:
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_btree_backpointers, 0, &write_sb) ?: ret;
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_extents_to_backpointers, 0, &write_sb) ?: ret;
		break;
	case BTREE_ID_need_discard:
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_alloc_info, 0, &write_sb) ?: ret;
		break;
	case BTREE_ID_freespace:
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_alloc_info, 0, &write_sb) ?: ret;
		break;
	case BTREE_ID_bucket_gens:
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_alloc_info, 0, &write_sb) ?: ret;
		break;
	case BTREE_ID_lru:
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_alloc_info, 0, &write_sb) ?: ret;
		break;
	case BTREE_ID_accounting:
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_allocations, 0, &write_sb) ?: ret;
		break;
	case BTREE_ID_snapshots:
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_reconstruct_snapshots, 0, &write_sb) ?: ret;
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_topology, 0, &write_sb) ?: ret;
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_scan_for_btree_nodes, 0, &write_sb) ?: ret;
		break;
	default:
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_check_topology, 0, &write_sb) ?: ret;
		ret = __bch2_run_explicit_recovery_pass(c, msg, BCH_RECOVERY_PASS_scan_for_btree_nodes, 0, &write_sb) ?: ret;
		break;
	}

	if (write_sb) {
		bch2_write_super(c);
		msg->suppress = false;
	}
	return ret;
}

static void kill_btree(struct bch_fs *c, enum btree_id btree)
{
	bch2_btree_id_root(c, btree)->alive = false;
	bch2_shoot_down_journal_keys(c, btree, 0, BTREE_MAX_DEPTH, POS_MIN, SPOS_MAX);
}

/* for -o reconstruct_alloc: */
void bch2_reconstruct_alloc(struct bch_fs *c)
{
	guard(mutex)(&c->sb_lock);
	struct bch_sb_field_ext *ext = bch2_sb_field_get(c->disk_sb.sb, ext);

	__set_bit_le64(BCH_RECOVERY_PASS_STABLE_check_allocations, ext->recovery_passes_required);
	__set_bit_le64(BCH_RECOVERY_PASS_STABLE_check_alloc_info, ext->recovery_passes_required);
	__set_bit_le64(BCH_RECOVERY_PASS_STABLE_check_lrus, ext->recovery_passes_required);
	__set_bit_le64(BCH_RECOVERY_PASS_STABLE_check_extents_to_backpointers, ext->recovery_passes_required);
	__set_bit_le64(BCH_RECOVERY_PASS_STABLE_check_alloc_to_lru_refs, ext->recovery_passes_required);

	__set_bit_le64(BCH_FSCK_ERR_ptr_to_missing_alloc_key, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_ptr_gen_newer_than_bucket_gen, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_stale_dirty_ptr, ext->errors_silent);

	__set_bit_le64(BCH_FSCK_ERR_dev_usage_buckets_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_dev_usage_sectors_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_dev_usage_fragmented_wrong, ext->errors_silent);

	__set_bit_le64(BCH_FSCK_ERR_fs_usage_btree_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_fs_usage_cached_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_fs_usage_persistent_reserved_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_fs_usage_replicas_wrong, ext->errors_silent);

	__set_bit_le64(BCH_FSCK_ERR_alloc_key_to_missing_lru_entry, ext->errors_silent);

	__set_bit_le64(BCH_FSCK_ERR_alloc_key_data_type_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_alloc_key_gen_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_alloc_key_dirty_sectors_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_alloc_key_cached_sectors_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_alloc_key_stripe_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_alloc_key_stripe_redundancy_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_alloc_key_to_missing_lru_entry, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_need_discard_key_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_freespace_key_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_bucket_gens_key_wrong, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_freespace_hole_missing, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_ptr_to_missing_backpointer, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_lru_entry_bad, ext->errors_silent);
	__set_bit_le64(BCH_FSCK_ERR_accounting_mismatch, ext->errors_silent);
	c->sb.compat &= ~(1ULL << BCH_COMPAT_alloc_info);

	c->opts.recovery_passes |= bch2_recovery_passes_from_stable(le64_to_cpu(ext->recovery_passes_required[0]));

	c->disk_sb.sb->features[0] &= ~cpu_to_le64(BIT_ULL(BCH_FEATURE_no_alloc_info));

	bch2_write_super(c);

	for (unsigned i = 0; i < btree_id_nr_alive(c); i++)
		if (btree_id_is_alloc(i))
			kill_btree(c, i);
}

/*
 * Btree node pointers have a field to stack a pointer to the in memory btree
 * node; we need to zero out this field when reading in btree nodes, or when
 * reading in keys from the journal:
 */
static void zero_out_btree_mem_ptr(struct journal_keys *keys)
{
	struct bch_fs *c = container_of(keys, struct bch_fs, journal_keys);
	darray_for_each(*keys, i) {
		struct bkey_i *k = journal_key_k(c, i);
		if (k->k.type == KEY_TYPE_btree_ptr_v2)
			bkey_i_to_btree_ptr_v2(k)->v.mem_ptr = 0;
	}
}

int bch2_set_may_go_rw(struct bch_fs *c)
{
	struct journal_keys *keys = &c->journal_keys;

	/*
	 * After we go RW, the journal keys buffer can't be modified (except for
	 * setting journal_key->overwritten: it will be accessed by multiple
	 * threads
	 */
	move_gap(keys, keys->nr);

	set_bit(BCH_FS_may_go_rw, &c->flags);

	if (go_rw_in_recovery(c)) {
		if (c->sb.features & BIT_ULL(BCH_FEATURE_no_alloc_info)) {
			bch_info(c, "mounting a filesystem with no alloc info read-write; will recreate");
			bch2_reconstruct_alloc(c);
		}

		return bch2_fs_read_write_early(c);
	}
	return 0;
}

/* journal replay: */

static void replay_now_at(struct journal *j, u64 seq)
{
	BUG_ON(seq < j->replay_journal_seq);

	seq = min(seq, j->replay_journal_seq_end);

	while (j->replay_journal_seq < seq)
		bch2_journal_pin_put(j, j->replay_journal_seq++);
}

static int bch2_journal_replay_accounting_key(struct btree_trans *trans,
					      struct journal_key *k)
{
	struct bch_fs *c = trans->c;
	struct bkey_i *bk = journal_key_k(c, k);

	CLASS(btree_node_iter, iter)(trans, k->btree_id, bk->k.p,
				     BTREE_MAX_DEPTH, k->level,
				     BTREE_ITER_intent);
	try(bch2_btree_iter_traverse(&iter));

	struct bkey u;
	struct bkey_s_c old = bch2_btree_path_peek_slot(btree_iter_path(trans, &iter), &u);

	/* Has this delta already been applied to the btree? */
	if (bversion_cmp(old.k->bversion, bk->k.bversion) >= 0)
		return 0;

	struct bkey_i *new = bk;
	if (old.k->type == KEY_TYPE_accounting) {
		new = errptr_try(bch2_bkey_make_mut_noupdate(trans, bkey_i_to_s_c(bk)));
		bch2_accounting_accumulate(bkey_i_to_accounting(new),
					   bkey_s_c_to_accounting(old));
	}

	if (!k->allocated)
		trans->journal_res.seq = c->journal_entries_base_seq + k->journal_seq_offset;

	return bch2_trans_update(trans, &iter, new, BTREE_TRIGGER_norun);
}

static int bch2_journal_replay_key(struct btree_trans *trans,
				   struct journal_key *k)
{
	struct bch_fs *c = trans->c;
	unsigned iter_flags =
		BTREE_ITER_intent|
		BTREE_ITER_not_extents;
	unsigned update_flags = BTREE_TRIGGER_norun;

	if (k->overwritten)
		return 0;

	if (!k->allocated)
		trans->journal_res.seq = c->journal_entries_base_seq + k->journal_seq_offset;

	/*
	 * BTREE_UPDATE_key_cache_reclaim disables key cache lookup/update to
	 * keep the key cache coherent with the underlying btree. Nothing
	 * besides the allocator is doing updates yet so we don't need key cache
	 * coherency for non-alloc btrees, and key cache fills for snapshots
	 * btrees use BTREE_ITER_filter_snapshots, which isn't available until
	 * the snapshots recovery pass runs.
	 */
	if (!k->level && k->btree_id == BTREE_ID_alloc)
		iter_flags |= BTREE_ITER_cached;
	else
		update_flags |= BTREE_UPDATE_key_cache_reclaim;

	struct bkey_i *bk = journal_key_k(c, k);
	CLASS(btree_node_iter, iter)(trans, k->btree_id, bk->k.p,
				     BTREE_MAX_DEPTH, k->level,
				     iter_flags);
	try(bch2_btree_iter_traverse(&iter));

	struct btree_path *path = btree_iter_path(trans, &iter);
	if (unlikely(!btree_path_node(path, k->level))) {
		CLASS(printbuf, buf)();
		prt_str(&buf, "btree=");
		bch2_btree_id_to_text(&buf, k->btree_id);
		prt_printf(&buf, " level=%u ", k->level);
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(bk));

		if (!(c->recovery.passes_complete & (BIT_ULL(BCH_RECOVERY_PASS_scan_for_btree_nodes)|
						     BIT_ULL(BCH_RECOVERY_PASS_check_topology)))) {
			bch_err(c, "have key in journal replay for btree depth that does not exist, confused\n%s",
				buf.buf);
			return -EINVAL;
		}

		if (!k->allocated) {
			bch_notice(c, "dropping key in journal replay for depth that does not exist because we're recovering from scan\n%s",
				   buf.buf);
			k->overwritten = true;
			return 0;
		}

		bch2_trans_node_iter_init(trans, &iter, k->btree_id, bk->k.p,
					  BTREE_MAX_DEPTH, 0, iter_flags);

		try(bch2_btree_iter_traverse(&iter));
		try(bch2_btree_increase_depth(trans, iter.path, 0));
		return btree_trans_restart(trans, BCH_ERR_transaction_restart_nested);
	}

	/* Must be checked with btree locked: */
	if (k->overwritten)
		return 0;

	if (bk->k.type == KEY_TYPE_accounting) {
		struct bkey_i *n = errptr_try(bch2_trans_subbuf_alloc(trans, &trans->accounting, bk->k.u64s));
		bkey_copy(n, bk);
		return 0;
	}

	return bch2_trans_update(trans, &iter, bk, update_flags);
}

static int journal_sort_seq_cmp(const void *_l, const void *_r)
{
	const struct journal_key *l = *((const struct journal_key **)_l);
	const struct journal_key *r = *((const struct journal_key **)_r);

	return !l->allocated && !r->allocated
		? cmp_int(l->journal_seq_offset, r->journal_seq_offset)
		: cmp_int(l->allocated, r->allocated);
}

DEFINE_DARRAY_NAMED(darray_journal_keys, struct journal_key *)

int bch2_journal_replay(struct bch_fs *c)
{
	struct journal_keys *keys = &c->journal_keys;
	CLASS(darray_journal_keys, keys_sorted)();
	struct journal *j = &c->journal;
	u64 start_seq	= c->journal_replay_seq_start;
	u64 end_seq	= c->journal_replay_seq_start;
	bool immediate_flush = false;
	int ret = 0;

	BUG_ON(!atomic_read(&keys->ref));
	BUG_ON(keys->gap != keys->nr);

	if (keys->nr)
		try(bch2_journal_log_msg(c, "Starting journal replay (%zu keys in entries %llu-%llu)",
					 keys->nr, start_seq, end_seq));

	CLASS(btree_trans, trans)(c);

	/*
	 * Replay accounting keys first: we can't allow the write buffer to
	 * flush accounting keys until we're done
	 */
	darray_for_each(*keys, k) {
		struct bkey_i *bk = journal_key_k(trans->c, k);

		if (!(bk->k.type == KEY_TYPE_accounting && !k->allocated))
			continue;

		cond_resched();

		ret = commit_do(trans, NULL, NULL,
				BCH_TRANS_COMMIT_no_enospc|
				BCH_TRANS_COMMIT_no_skip_noops|
				BCH_TRANS_COMMIT_journal_reclaim|
				BCH_TRANS_COMMIT_skip_accounting_apply|
				BCH_TRANS_COMMIT_no_journal_res|
				BCH_WATERMARK_reclaim,
			     bch2_journal_replay_accounting_key(trans, k));
		if (bch2_fs_fatal_err_on(ret, c, "error replaying accounting; %s", bch2_err_str(ret)))
			return ret;

		k->overwritten = true;
	}

	set_bit(BCH_FS_accounting_replay_done, &c->flags);

	/*
	 * First, attempt to replay keys in sorted order. This is more
	 * efficient - better locality of btree access -  but some might fail if
	 * that would cause a journal deadlock.
	 */
	darray_for_each(*keys, k) {
		cond_resched();

		/*
		 * k->allocated means the key wasn't read in from the journal,
		 * rather it was from early repair code
		 */
		if (k->allocated)
			immediate_flush = true;

		/* Skip fastpath if we're low on space in the journal */
		ret = c->journal.watermark ? -1 :
			commit_do(trans, NULL, NULL,
				  BCH_TRANS_COMMIT_no_enospc|
				  BCH_TRANS_COMMIT_no_skip_noops|
				  BCH_TRANS_COMMIT_journal_reclaim|
				  BCH_TRANS_COMMIT_skip_accounting_apply|
				  (!k->allocated ? BCH_TRANS_COMMIT_no_journal_res : 0),
			     bch2_journal_replay_key(trans, k));
		if (ret)
			try(darray_push(&keys_sorted, k));
	}

	bch2_trans_unlock_long(trans);
	/*
	 * Now, replay any remaining keys in the order in which they appear in
	 * the journal, unpinning those journal entries as we go:
	 */
	sort_nonatomic(keys_sorted.data, keys_sorted.nr,
		       sizeof(keys_sorted.data[0]),
		       journal_sort_seq_cmp, NULL);

	darray_for_each(keys_sorted, kp) {
		cond_resched();

		struct journal_key *k = *kp;

		if (!k->allocated)
			replay_now_at(j, c->journal_entries_base_seq + k->journal_seq_offset);
		else
			replay_now_at(j, j->replay_journal_seq_end);

		ret = commit_do(trans, NULL, NULL,
				BCH_TRANS_COMMIT_no_enospc|
				BCH_TRANS_COMMIT_no_skip_noops|
				BCH_TRANS_COMMIT_skip_accounting_apply|
				(!k->allocated
				 ? BCH_TRANS_COMMIT_no_journal_res|BCH_WATERMARK_reclaim
				 : 0),
			     bch2_journal_replay_key(trans, k));
		if (ret) {
			CLASS(printbuf, buf)();
			bch2_btree_id_level_to_text(&buf, k->btree_id, k->level);
			bch_err_msg(c, ret, "while replaying key at %s:", buf.buf);
			return ret;
		}

		BUG_ON(k->btree_id != BTREE_ID_accounting && !k->overwritten);
	}

	bch2_trans_unlock_long(trans);

	if (!c->opts.retain_recovery_info &&
	    c->recovery.pass_done >= BCH_RECOVERY_PASS_journal_replay)
		bch2_journal_keys_put_initial(c);

	replay_now_at(j, j->replay_journal_seq_end);
	j->replay_journal_seq = 0;

	bch2_journal_set_replay_done(j);

	/* if we did any repair, flush it immediately */
	if (immediate_flush) {
		bch2_journal_flush_all_pins(&c->journal);
		ret = bch2_journal_meta(&c->journal);
	}

	if (keys->nr)
		bch2_journal_log_msg(c, "journal replay finished");
	return 0;
}

/* journal replay early: */

static int journal_replay_entry_early(struct bch_fs *c,
				      struct jset_entry *entry)
{
	int ret = 0;

	switch (entry->type) {
	case BCH_JSET_ENTRY_btree_root: {

		if (unlikely(!entry->u64s))
			return 0;

		if (fsck_err_on(entry->btree_id >= BTREE_ID_NR_MAX,
				c, invalid_btree_id,
				"invalid btree id %u (max %u)",
				entry->btree_id, BTREE_ID_NR_MAX))
			return 0;

		while (entry->btree_id >= c->btree.cache.roots_extra.nr + BTREE_ID_NR)
			try(darray_push(&c->btree.cache.roots_extra, (struct btree_root) { NULL }));

		struct btree_root *r = bch2_btree_id_root(c, entry->btree_id);

		r->level = entry->level;
		bkey_copy(&r->key, (struct bkey_i *) entry->start);
		r->error = 0;
		r->alive = true;
		break;
	}
	case BCH_JSET_ENTRY_usage: {
		struct jset_entry_usage *u =
			container_of(entry, struct jset_entry_usage, entry);

		switch (entry->btree_id) {
		case BCH_FS_USAGE_key_version:
			atomic64_set(&c->key_version, le64_to_cpu(u->v));
			break;
		}
		break;
	}
	case BCH_JSET_ENTRY_blacklist: {
		struct jset_entry_blacklist *bl_entry =
			container_of(entry, struct jset_entry_blacklist, entry);

		ret = bch2_journal_seq_blacklist_add(c,
				le64_to_cpu(bl_entry->seq),
				le64_to_cpu(bl_entry->seq) + 1);
		break;
	}
	case BCH_JSET_ENTRY_blacklist_v2: {
		struct jset_entry_blacklist_v2 *bl_entry =
			container_of(entry, struct jset_entry_blacklist_v2, entry);

		ret = bch2_journal_seq_blacklist_add(c,
				le64_to_cpu(bl_entry->start),
				le64_to_cpu(bl_entry->end) + 1);
		break;
	}
	case BCH_JSET_ENTRY_clock: {
		struct jset_entry_clock *clock =
			container_of(entry, struct jset_entry_clock, entry);

		atomic64_set(&c->io_clock[clock->rw].now, le64_to_cpu(clock->time));
	}
	}
fsck_err:
	return ret;
}

static int journal_replay_early(struct bch_fs *c,
				struct bch_sb_field_clean *clean)
{
	if (clean) {
		for (struct jset_entry *entry = clean->start;
		     entry != vstruct_end(&clean->field);
		     entry = vstruct_next(entry))
			try(journal_replay_entry_early(c, entry));
	} else {
		struct genradix_iter iter;
		struct journal_replay *i, **_i;

		genradix_for_each(&c->journal_entries, iter, _i) {
			i = *_i;

			if (journal_replay_ignore(i))
				continue;

			vstruct_for_each(&i->j, entry)
				try(journal_replay_entry_early(c, entry));
		}
	}

	return 0;
}

/* sb clean section: */

static int read_btree_roots(struct bch_fs *c)
{
	CLASS(printbuf, buf)();
	int ret = 0;

	for (unsigned i = 0; i < btree_id_nr_alive(c); i++) {
		struct btree_root *r = bch2_btree_id_root(c, i);

		if (!r->alive)
			continue;

		printbuf_reset(&buf);
		bch2_btree_id_level_to_text(&buf, i, r->level);

		if (mustfix_fsck_err_on((ret = r->error),
					c, btree_root_bkey_invalid,
					"invalid btree root %s",
					buf.buf) ||
		    mustfix_fsck_err_on((ret = r->error = bch2_btree_root_read(c, i, &r->key, r->level)),
					c, btree_root_read_error,
					"error reading btree root %s: %s",
					buf.buf, bch2_err_str(ret))) {
			if (btree_id_can_reconstruct(i))
				r->error = 0;
			ret = 0;
		}
	}

	for (unsigned i = 0; i < BTREE_ID_NR; i++) {
		struct btree_root *r = bch2_btree_id_root(c, i);

		if (!r->b && !r->error) {
			r->alive = false;
			r->level = 0;
			bch2_btree_root_alloc_fake(c, i, 0);
		}
	}
fsck_err:
	return ret;
}

static int __bch2_fs_recovery(struct bch_fs *c)
{
	struct bch_sb_field_clean *clean __free(kfree) = NULL;
	struct journal_start_info journal_start = {};
	int ret = 0;

	if (c->sb.clean) {
		clean = errptr_try(bch2_read_superblock_clean(c));

		bch_info(c, "recovering from clean shutdown, journal seq %llu",
			 le64_to_cpu(clean->journal_seq));

		try(bch2_sb_journal_sort(c));
	} else {
		bch_info(c, "recovering from unclean shutdown");
	}

	bch2_journal_pos_from_member_info_resume(c);

	if (!c->sb.clean || c->opts.retain_recovery_info) {
		struct genradix_iter iter;
		struct journal_replay **i;

		bch_verbose(c, "starting journal read");
		try(bch2_journal_read(c, &journal_start));

		/*
		 * note: cmd_list_journal needs the blacklist table fully up to date so
		 * it can asterisk ignored journal entries:
		 */
		if (c->opts.read_journal_only)
			return 0;

		if (mustfix_fsck_err_on(c->sb.clean && !journal_start.clean,
					c, clean_but_journal_not_empty,
					"filesystem marked clean but journal not empty")) {
			c->sb.compat &= ~(1ULL << BCH_COMPAT_alloc_info);
			SET_BCH_SB_CLEAN(c->disk_sb.sb, false);
			c->sb.clean = false;
		}

		struct jset *last_journal_entry = NULL;
		genradix_for_each_reverse(&c->journal_entries, iter, i)
			if (!journal_replay_ignore(*i)) {
				last_journal_entry = &(*i)->j;
				break;
			}

		if (!last_journal_entry) {
			fsck_err_on(!c->sb.clean, c,
				    dirty_but_no_journal_entries,
				    "no journal entries found");
			if (clean)
				goto use_clean;

			genradix_for_each_reverse(&c->journal_entries, iter, i)
				if (*i) {
					last_journal_entry = &(*i)->j;
					(*i)->ignore_blacklisted = false;
					(*i)->ignore_not_dirty= false;
					/*
					 * This was probably a NO_FLUSH entry,
					 * so last_seq was garbage - but we know
					 * we're only using a single journal
					 * entry, set it here:
					 */
					(*i)->j.last_seq = (*i)->j.seq;
					break;
				}
		}

		try(bch2_journal_keys_sort(c));

		if (c->sb.clean && last_journal_entry)
			try(bch2_verify_superblock_clean(c, &clean, last_journal_entry));
	} else {
use_clean:
		if (!clean) {
			bch_err(c, "no superblock clean section found");
			return bch_err_throw(c, fsck_repair_impossible);

		}

		journal_start.start_seq = le64_to_cpu(clean->journal_seq) + 1;
	}

	c->journal_replay_seq_start	= journal_start.seq_read_start;
	c->journal_replay_seq_end	= journal_start.seq_read_end;

	zero_out_btree_mem_ptr(&c->journal_keys);

	try(journal_replay_early(c, clean));

	scoped_guard(rwsem_write, &c->state_lock)
		try(bch2_fs_resize_on_mount(c));

	if (c->sb.features & BIT_ULL(BCH_FEATURE_small_image)) {
		bch_info(c, "filesystem is an unresized image file, mounting ro");
		c->opts.read_only = true;
	}

	if (!c->opts.read_only &&
	    (c->sb.features & BIT_ULL(BCH_FEATURE_no_alloc_info))) {
		bch_info(c, "mounting a filesystem with no alloc info read-write; will recreate");

		bch2_reconstruct_alloc(c);
	} else if (c->opts.reconstruct_alloc) {
		bch2_journal_log_msg(c, "dropping alloc info");
		bch_info(c, "dropping and reconstructing all alloc info");

		bch2_reconstruct_alloc(c);
	}

	if (c->sb.features & BIT_ULL(BCH_FEATURE_no_alloc_info)) {
		/* We can't go RW to fix errors without alloc info */
		if (c->opts.fix_errors == FSCK_FIX_yes ||
		    c->opts.fix_errors == FSCK_FIX_ask)
			c->opts.fix_errors = FSCK_FIX_no;
		if (c->opts.errors == BCH_ON_ERROR_fix_safe)
			c->opts.errors = BCH_ON_ERROR_continue;
	}

	/*
	 * After an unclean shutdown, skip then next few journal sequence
	 * numbers as they may have been referenced by btree writes that
	 * happened before their corresponding journal writes - those btree
	 * writes need to be ignored, by skipping and blacklisting the next few
	 * journal sequence numbers:
	 */
	if (!c->sb.clean)
		journal_start.start_seq += JOURNAL_BUF_NR * 4;

	if (journal_start.seq_read_end &&
	    journal_start.seq_read_end + 1 != journal_start.start_seq) {
		u64 blacklist_seq = journal_start.seq_read_end + 1;
		try(bch2_journal_log_msg(c, "blacklisting entries %llu-%llu",
					 blacklist_seq, journal_start.start_seq));
		try(bch2_journal_seq_blacklist_add(c, blacklist_seq, journal_start.start_seq));
	}

	try(bch2_journal_log_msg(c, "starting journal at entry %llu, replaying %llu-%llu",
				 journal_start.start_seq,
				 journal_start.seq_read_start,
				 journal_start.seq_read_end));
	try(bch2_fs_journal_start(&c->journal, journal_start));

	/*
	 * Skip past versions that might have possibly been used (as nonces),
	 * but hadn't had their pointers written:
	 */
	if (c->sb.encryption_type && !c->sb.clean)
		atomic64_add(1 << 16, &c->key_version);

	try(read_btree_roots(c));

	set_bit(BCH_FS_btree_running, &c->flags);

	/* some mount options can only be checked after the btree is running */
	try(bch2_opts_hooks_pre_set(c));

	try(bch2_sb_set_upgrade_extra(c));

	try(bch2_run_recovery_passes_startup(c, 0));

	/*
	 * Normally set by the appropriate recovery pass: when cleared, this
	 * indicates we're in early recovery and btree updates should be done by
	 * being applied to the journal replay keys. _Must_ be cleared before
	 * multithreaded use:
	 */
	set_bit(BCH_FS_may_go_rw, &c->flags);
	clear_bit(BCH_FS_in_fsck, &c->flags);

	/* in case we don't run journal replay, i.e. norecovery mode */
	set_bit(BCH_FS_accounting_replay_done, &c->flags);

	bch2_async_btree_node_rewrites_flush(c);

	/* fsync if we fixed errors */
	bool errors_fixed = test_bit(BCH_FS_errors_fixed, &c->flags) ||
		test_bit(BCH_FS_errors_fixed_silent, &c->flags);

	if (errors_fixed) {
		bch2_journal_flush_all_pins(&c->journal);
		bch2_journal_meta(&c->journal);
	}

	/* If we fixed errors, verify that fs is actually clean now: */
	if (IS_ENABLED(CONFIG_BCACHEFS_DEBUG) &&
	    errors_fixed &&
	    !test_bit(BCH_FS_errors_not_fixed, &c->flags) &&
	    !test_bit(BCH_FS_error, &c->flags)) {
		bch2_flush_fsck_errs(c);

		bch_info(c, "Fixed errors, running fsck a second time to verify fs is clean");
		errors_fixed = test_bit(BCH_FS_errors_fixed, &c->flags);
		clear_bit(BCH_FS_errors_fixed, &c->flags);
		clear_bit(BCH_FS_errors_fixed_silent, &c->flags);

		try(bch2_run_recovery_passes_startup(c, BCH_RECOVERY_PASS_check_alloc_info));

		if (errors_fixed ||
		    test_bit(BCH_FS_errors_not_fixed, &c->flags)) {
			bch_err(c, "Second fsck run was not clean");
			set_bit(BCH_FS_errors_not_fixed, &c->flags);
		}

		if (errors_fixed)
			set_bit(BCH_FS_errors_fixed, &c->flags);
	}

	if (enabled_qtypes(c)) {
		bch_verbose(c, "reading quotas");
		try(bch2_fs_quota_read(c));
		bch_verbose(c, "quotas done");
	}

	scoped_guard(mutex, &c->sb_lock) {
		struct bch_sb_field_ext *ext = bch2_sb_field_get(c->disk_sb.sb, ext);
		bool write_sb = false;

		if (BCH_SB_VERSION_UPGRADE_COMPLETE(c->disk_sb.sb) != le16_to_cpu(c->disk_sb.sb->version)) {
			SET_BCH_SB_VERSION_UPGRADE_COMPLETE(c->disk_sb.sb, le16_to_cpu(c->disk_sb.sb->version));
			write_sb = true;
		}

		if (!test_bit(BCH_FS_error, &c->flags) &&
		    !(c->disk_sb.sb->compat[0] & cpu_to_le64(1ULL << BCH_COMPAT_alloc_info))) {
			c->disk_sb.sb->compat[0] |= cpu_to_le64(1ULL << BCH_COMPAT_alloc_info);
			write_sb = true;
		}

		if (!test_bit(BCH_FS_error, &c->flags) &&
		    !bch2_is_zero(ext->errors_silent, sizeof(ext->errors_silent))) {
			memset(ext->errors_silent, 0, sizeof(ext->errors_silent));
			write_sb = true;
		}

		if (c->opts.fsck &&
		    !test_bit(BCH_FS_error, &c->flags) &&
		    c->recovery.pass_done == BCH_RECOVERY_PASS_NR - 1 &&
		    ext->btrees_lost_data) {
			ext->btrees_lost_data = 0;
			write_sb = true;
		}

		if (c->opts.fsck &&
		    !test_bit(BCH_FS_error, &c->flags) &&
		    !test_bit(BCH_FS_errors_not_fixed, &c->flags)) {
			SET_BCH_SB_HAS_ERRORS(c->disk_sb.sb, 0);
			SET_BCH_SB_HAS_TOPOLOGY_ERRORS(c->disk_sb.sb, 0);
			write_sb = true;
		}

		if (bch2_blacklist_entries_gc(c))
			write_sb = true;

		if (!(c->sb.compat & BIT_ULL(BCH_COMPAT_no_stale_ptrs)) &&
		    (c->recovery.passes_complete & BIT_ULL(BCH_RECOVERY_PASS_check_extents)) &&
		    (c->recovery.passes_complete & BIT_ULL(BCH_RECOVERY_PASS_check_indirect_extents))) {
			c->disk_sb.sb->compat[0] |= cpu_to_le64(BIT_ULL(BCH_COMPAT_no_stale_ptrs));
			write_sb = true;
		}

		if (write_sb)
			bch2_write_super(c);
	}

	if (test_bit(BCH_FS_need_delete_dead_snapshots, &c->flags) &&
	    !c->opts.nochanges) {
		bch2_fs_read_write_early(c);
		bch2_delete_dead_snapshots_async(c);
	}

	/*
	 * (Hopefully unnecessary) cleanup, once per mount - we should be
	 * killing replicas entries when accounting entries go to 0, but - old
	 * filesystems, etc.:
	 */
	bch2_replicas_gc_accounted(c);
fsck_err:
	return ret;
}

int bch2_fs_recovery(struct bch_fs *c)
{
	int ret = __bch2_fs_recovery(c);

	bch2_flush_fsck_errs(c);

	if (ret) {
		CLASS(bch_log_msg, msg)(c);
		prt_printf(&msg.m, "error in recovery: %s\n", bch2_err_str(ret));
		bch2_fs_emergency_read_only2(c, &msg.m);
	}
	return ret;
}

int bch2_fs_initialize(struct bch_fs *c)
{
	struct bch_inode_unpacked root_inode, lostfound_inode;
	struct bkey_inode_buf packed_inode;
	struct qstr lostfound = QSTR("lost+found");
	int ret;

	bch_notice(c, "initializing new filesystem");
	set_bit(BCH_FS_new_fs, &c->flags);

	scoped_guard(mutex, &c->sb_lock) {
		c->disk_sb.sb->compat[0] |= cpu_to_le64(BIT_ULL(BCH_COMPAT_extents_above_btree_updates_done));
		c->disk_sb.sb->compat[0] |= cpu_to_le64(BIT_ULL(BCH_COMPAT_bformat_overflow_done));
		c->disk_sb.sb->compat[0] |= cpu_to_le64(BIT_ULL(BCH_COMPAT_no_stale_ptrs));

		bch2_check_version_downgrade(c);

		if (c->opts.version_upgrade != BCH_VERSION_UPGRADE_none) {
			bch2_sb_upgrade(c, bcachefs_metadata_version_current, false);
			SET_BCH_SB_VERSION_UPGRADE_COMPLETE(c->disk_sb.sb, bcachefs_metadata_version_current);
			bch2_write_super(c);
		}

		for_each_member_device(c, ca) {
			struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);
			SET_BCH_MEMBER_FREESPACE_INITIALIZED(m, false);
		}

		bch2_write_super(c);
	}

	for (unsigned i = 0; i < BTREE_ID_NR; i++)
		bch2_btree_root_alloc_fake(c, i, 0);

	set_bit(BCH_FS_btree_running, &c->flags);

	for_each_member_device(c, ca)
		try(bch2_dev_usage_init(ca, false));

	/*
	 * Write out the superblock and journal buckets, now that we can do
	 * btree updates
	 */
	bch_verbose(c, "marking superblocks");
	ret = bch2_trans_mark_dev_sbs(c);
	bch_err_msg(c, ret, "marking superblocks");
	if (ret)
		return ret;

	try(bch2_fs_journal_alloc(c));

	/*
	 * journal_res_get() will crash if called before this has
	 * set up the journal.pin FIFO and journal.cur pointer:
	 */
	struct journal_start_info journal_start = { .start_seq = 1 };
	try(bch2_fs_journal_start(&c->journal, journal_start));

	try(bch2_set_may_go_rw(c));
	try(bch2_journal_replay(c));
	try(bch2_fs_freespace_init(c));
	try(bch2_initialize_subvolumes(c));
	try(bch2_snapshots_read(c));

	bch2_inode_init(c, &root_inode, 0, 0, S_IFDIR|0755, 0, NULL);
	root_inode.bi_inum	= BCACHEFS_ROOT_INO;
	root_inode.bi_subvol	= BCACHEFS_ROOT_SUBVOL;
	bch2_inode_pack(&packed_inode, &root_inode);
	packed_inode.inode.k.p.snapshot = U32_MAX;

	ret = bch2_btree_insert(c, BTREE_ID_inodes, &packed_inode.inode.k_i, NULL, 0, 0);
	bch_err_msg(c, ret, "creating root directory");
	if (ret)
		return ret;

	bch2_inode_init_early(c, &lostfound_inode);

	ret = bch2_trans_commit_do(c, NULL, NULL, 0,
		bch2_create_trans(trans,
				  BCACHEFS_ROOT_SUBVOL_INUM,
				  &root_inode, &lostfound_inode,
				  &lostfound,
				  0, 0, S_IFDIR|0700, 0,
				  NULL, NULL, (subvol_inum) { 0 }, 0));
	bch_err_msg(c, ret, "creating lost+found");
	if (ret)
		return ret;

	c->recovery.pass_done = BCH_RECOVERY_PASS_NR - 1;

	bch2_copygc_wakeup(c);
	bch2_reconcile_wakeup(c);

	if (enabled_qtypes(c))
		try(bch2_fs_quota_read(c));

	ret = bch2_journal_flush(&c->journal);
	bch_err_msg(c, ret, "writing first journal entry");
	if (ret)
		return ret;

	scoped_guard(mutex, &c->sb_lock) {
		SET_BCH_SB_INITIALIZED(c->disk_sb.sb, true);
		SET_BCH_SB_CLEAN(c->disk_sb.sb, false);

		struct bch_sb_field_ext *ext = bch2_sb_field_get(c->disk_sb.sb, ext);
		memset(ext->errors_silent, 0, sizeof(ext->errors_silent));
		memset(ext->recovery_passes_required, 0, sizeof(ext->recovery_passes_required));

		bch2_write_super(c);
	}

	return 0;
}
