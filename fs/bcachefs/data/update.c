// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/buckets.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"

#include "btree/bkey_buf.h"
#include "btree/update.h"

#include "data/compress.h"
#include "data/copygc.h"
#include "data/extents.h"
#include "data/keylist.h"
#include "data/move.h"
#include "data/nocow_locking.h"
#include "data/reconcile/trigger.h"
#include "data/update.h"
#include "data/write.h"

#include "fs/inode.h"

#include "init/dev.h"
#include "init/error.h"
#include "init/fs.h"

#include "sb/counters.h"

#include "snapshots/snapshot.h"
#include "snapshots/subvolume.h"

#include <linux/ioprio.h>

static const char * const bch2_data_update_type_strs[] = {
#define x(n) #n,
	BCH_DATA_UPDATE_TYPES()
#undef x
	NULL
};

static const struct rhashtable_params bch_update_params = {
	.head_offset		= offsetof(struct data_update, hash),
	.key_offset		= offsetof(struct data_update, pos),
	.key_len		= sizeof(struct bbpos),
	.automatic_shrinking	= true,
};

bool bch2_data_update_in_flight(struct bch_fs *c, struct bbpos *pos)
{
	guard(rcu)();
	return rhltable_lookup(&c->update_table, pos, bch_update_params) != NULL;
}

static void ptr_bits_to_text(struct printbuf *out, unsigned ptrs, const char *name)
{
	if (ptrs) {
		prt_printf(out, "%s ptrs:\t", name);
		bch2_prt_u64_base2(out, ptrs);
		prt_newline(out);
	}
}

static void bkey_put_dev_refs(struct bch_fs *c, struct bkey_s_c k, unsigned ptrs_held)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	unsigned ptr_bit = 1;

	bkey_for_each_ptr(ptrs, ptr) {
		if (ptrs_held & ptr_bit)
			bch2_dev_put(bch2_dev_have_ref(c, ptr->dev));
		ptr_bit <<= 1;
	}
}

static unsigned bkey_get_dev_refs(struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	unsigned ptrs_held = 0, ptr_bit = 1;

	bkey_for_each_ptr(ptrs, ptr) {
		if (likely(bch2_dev_bkey_tryget(c, k, ptr->dev)))
			ptrs_held |= ptr_bit;
		ptr_bit <<= 1;
	}

	return ptrs_held;
}

static unsigned ptr_remap(struct bch_fs *c, struct bkey_s_c old,
			  struct extent_ptr_decoded oldp,
			  struct bkey_s_c new)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(new);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded newp;
	unsigned ptr_bit = 1;

	bkey_for_each_ptr_decode(new.k, ptrs, newp, entry) {
		if (bch2_bkey_ptrs_match(old, oldp, new, newp))
			return ptr_bit;
		ptr_bit <<= 1;
	}
	return 0;
}

static unsigned ptr_mask_remap(struct bch_fs *c,
			       struct bkey_s_c old, unsigned oldmask,
			       struct bkey_s_c new)
{
	if (!oldmask)
		return 0;

	unsigned newmask = 0;
	unsigned ptr_bit = 1;

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(old);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded oldp;
	bkey_for_each_ptr_decode(old.k, ptrs, oldp, entry) {
		if (oldmask & ptr_bit)
			newmask |= ptr_remap(c, old, oldp, new);
		ptr_bit <<= 1;
	}

	return newmask;
}

static unsigned bkey_has_device_mask(struct bch_fs *c, struct bkey_s_c k, unsigned dev)
{
	unsigned ptr_bit = 1;
	bkey_for_each_ptr(bch2_bkey_ptrs_c(k), ptr) {
		if (ptr->dev == dev)
			return ptr_bit;
		ptr_bit <<= 1;
	}

	return 0;
}

/* Returns mask of pointers in @k1 that conflict with pointers in @k2 */
static unsigned bkey_ptr_conflicts_mask(struct bch_fs *c, struct bkey_s_c k1, struct bkey_s_c k2)
{
	unsigned ptrs_conflict = 0;

	bkey_for_each_ptr(bch2_bkey_ptrs_c(k2), ptr)
		ptrs_conflict |= bkey_has_device_mask(c, k1, ptr->dev);
	return ptrs_conflict;
}

static void data_update_key_to_text(struct printbuf *out,
				    struct data_update *u,
				    struct bkey_s_c new,
				    struct bkey_s_c wrote,
				    struct bkey_i *insert)
{
	struct bch_fs *c = u->op.c;
	struct bkey_s_c old = bkey_i_to_s_c(u->k.k);

	prt_str(out, "rewrites found:\t");
	bch2_prt_u64_base2(out,
			   ptr_mask_remap(c, old, u->opts.ptrs_kill, bkey_i_to_s_c(insert)));
	prt_newline(out);

	bch2_data_update_opts_to_text(out, c, &u->op.opts, &u->opts);

	prt_str(out, "\nold:    ");
	bch2_bkey_val_to_text(out, c, old);

	prt_str(out, "\nnew:    ");
	bch2_bkey_val_to_text(out, c, new);

	prt_str(out, "\nwrote:  ");
	bch2_bkey_val_to_text(out, c, wrote);

	prt_str(out, "\ninsert: ");
	bch2_bkey_val_to_text(out, c, bkey_i_to_s_c(insert));
}

noinline_for_stack
static void count_data_update_key_fail(struct data_update *u,
				       struct bkey_s_c new,
				       struct bkey_s_c wrote,
				       struct bkey_i *insert,
				       const char *msg)
{
	struct bch_fs *c = u->op.c;

	if (u->stats) {
		atomic64_inc(&u->stats->keys_raced);
		atomic64_add(insert->k.size, &u->stats->sectors_raced);
	}

	event_add_trace(c, data_update_key_fail, insert->k.size, buf, ({
		prt_printf(&buf, "%s\n", msg);
		data_update_key_to_text(&buf, u, new, wrote, insert);
	}));
}

static int data_update_index_update_key(struct btree_trans *trans,
					struct data_update *u,
					struct btree_iter *iter)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c old = bkey_i_to_s_c(u->k.k);

	bch2_trans_begin(trans);

	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(iter));

	/* make a local copy, so that we can trace it after the transaction commit:  */
	k = bkey_i_to_s_c(errptr_try(bch2_bkey_make_mut_noupdate(trans, k)));

	/*
	 * We're calling set_needs_reconcile() on both @insert and @new,
	 * and it can add a bch_extent_reconcile and additional
	 * pointers to BCH_SB_MEMBER_INVALID if the extent is now
	 * degraded due to option changes:
	 */
	struct bkey_i_extent *new = bkey_i_to_extent(bch2_keylist_front(&u->op.insert_keys));
	new = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(&new->k) +
				 sizeof(struct bch_extent_reconcile) +
				 sizeof(struct bch_extent_ptr) * BCH_REPLICAS_MAX));
	bkey_copy(&new->k_i, bch2_keylist_front(&u->op.insert_keys));

	struct bkey_i *insert = errptr_try(bch2_trans_kmalloc(trans,
				    bkey_bytes(k.k) +
				    bkey_val_bytes(&new->k) +
				    sizeof(struct bch_extent_reconcile) +
				    sizeof(struct bch_extent_ptr) * BCH_REPLICAS_MAX));
	bkey_reassemble(insert, k);

	bch2_cut_front(c, iter->pos,	&new->k_i);
	bch2_cut_front(c, iter->pos,	insert);
	bch2_cut_back(new->k.p,		insert);
	bch2_cut_back(insert->k.p,	&new->k_i);

	struct bpos next_pos = insert->k.p;

	if (!bch2_extents_match(c, k, old)) {
		count_data_update_key_fail(u, k, bkey_i_to_s_c(&new->k_i), insert, "no match:");
		bch2_btree_iter_set_pos(iter, next_pos);
		return 0;
	}

	unsigned ptrs_kill = ptr_mask_remap(c, old, u->opts.ptrs_kill,	bkey_i_to_s_c(insert));
	if (ptrs_kill) {
		/* Don't replace non-cached replicas with cached: */
		bool replacing_non_cached_replicas = false;
		unsigned ptr_bit = 1;
		bkey_for_each_ptr(bch2_bkey_ptrs_c(bkey_i_to_s_c(insert)), ptr) {
			if (ptrs_kill & ptr_bit)
				replacing_non_cached_replicas |= !ptr->cached;
			ptr_bit <<= 1;
		}

		if (replacing_non_cached_replicas)
			bkey_for_each_ptr(bch2_bkey_ptrs_c(bkey_i_to_s_c(&new->k_i)), ptr)
				if (ptr->cached) {
					CLASS(bch_log_msg_ratelimited, msg)(c);
					prt_printf(&msg.m, "data update tried to replace non cached data with cached:\n");
					data_update_key_to_text(&msg.m, u, k, bkey_i_to_s_c(&new->k_i),
								insert);
					return 0;
				}
	}

	if (!u->opts.no_devs_have) {
		/*
		 * Drop replicas in the existing extent that conflict with what
		 * we just wrote - but only if they were explicitly specified in
		 * ptrs_kill:
		 * A replica that we just wrote might conflict with a replica
		 * that we want to keep, due to racing with another move:
		 */
		unsigned ptrs_conflict = bkey_ptr_conflicts_mask(c, bkey_i_to_s_c(insert), bkey_i_to_s_c(&new->k_i)) &
			ptr_mask_remap(c, old, u->opts.ptrs_kill, bkey_i_to_s_c(insert));
		bch2_bkey_drop_ptrs_mask(c, insert, ptrs_conflict);


		/* Any conflicts that are left over were useless writes -
		 * perhaps due to a copygc race:
		 */
		ptrs_conflict = bkey_ptr_conflicts_mask(c, bkey_i_to_s_c(&new->k_i), bkey_i_to_s_c(insert));
		if (ptrs_conflict) {
			event_add_trace(c, data_update_useless_write_fail,
					k.k->size * hweight32(ptrs_conflict), buf, ({
				ptr_bits_to_text(&buf, ptrs_conflict, "conflicted");
				prt_printf(&buf, "wrote: ");
				bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&new->k_i));
				prt_newline(&buf);
				bch2_data_update_to_text(&buf, u);
			}));

			bch2_bkey_drop_ptrs_mask(c, &new->k_i, ptrs_conflict);

			if (!bkey_val_u64s(&new->k)) {
				count_data_update_key_fail(u, k,
							   bkey_i_to_s_c(bch2_keylist_front(&u->op.insert_keys)),
							   insert, "new replicas conflicted:");
				bch2_btree_iter_advance(iter);
				return 0;
			}
		}
	} else {
		/*
		 * Drop all conflicts from the existing extent, not the newly
		 * written replicas:
		 *
		 * When converting an extent to erasure coding, we don't
		 * disallow the write from allocating on the extent's existing
		 * devices: we just want a new replica that will have a stripe
		 * pointer added asynchronously by erasure coding, and it can
		 * overwrite whichever device it happens to land on
		 *
		 * XXX: make sure drop_extra_replicas does not drop the new
		 * replica
		 */
		unsigned ptrs_conflict = bkey_ptr_conflicts_mask(c, bkey_i_to_s_c(insert), bkey_i_to_s_c(&new->k_i));
		bch2_bkey_drop_ptrs_mask(c, insert, ptrs_conflict);
	}

	/* Now, merge newly written replicas:
	 * Since these are appended to the end of @insert, they don't invalidate
	 * our pointer masks:
	 */
	struct extent_ptr_decoded p;
	union bch_extent_entry *entry;
	extent_for_each_ptr_decode(extent_i_to_s(new), p, entry)
		bch2_extent_ptr_decoded_append(c, insert, &p);

	struct bch_inode_opts opts;
	try(bch2_bkey_get_io_opts(trans, NULL, k, &opts));

	struct bkey_durability old_durability, new_durability;
	try(bch2_bkey_durability(trans, k, &old_durability));
	try(bch2_bkey_durability(trans, bkey_i_to_s_c(insert), &new_durability));

	if (new_durability.total < old_durability.total &&
	    new_durability.total < min(u->op.opts.data_replicas, opts.data_replicas)) {
		/*
		 * This can happen when a move - evacuate or copygc - races with an
		 * extent being erasure coded: we replaced a pointer with one on the
		 * same device (so we have to drop it early, to avoid conflicts) which
		 * is no longer erasure coded.
		 *
		 * XXX: trace this
		 */
		bch2_btree_iter_set_pos(iter, next_pos);
		return 0;
	}

	try(bch2_bkey_drop_extra_durability(trans, &opts,	insert,
		ptr_mask_remap(c, old, u->opts.ptrs_io_error,	bkey_i_to_s_c(insert)), true));

	try(bch2_bkey_drop_extra_ec_durability(trans, &opts,	insert,
		ptr_mask_remap(c, old, u->opts.ptrs_kill_ec,	bkey_i_to_s_c(insert))));

	try(bch2_bkey_drop_extra_durability(trans, &opts,	insert,
		ptr_mask_remap(c, old, u->opts.ptrs_kill,	bkey_i_to_s_c(insert)), false));

	/* Prefer to drop existing replicas over new - we don't want to drop the
	 * new replica being erasure coded*/
	if (u->opts.no_devs_have) {
		try(bch2_bkey_drop_extra_durability(trans, &opts,	insert,
			~bkey_ptr_conflicts_mask(c, bkey_i_to_s_c(insert), bkey_i_to_s_c(&new->k_i)),
			false));
	} else {
		/* Prefer to drop new replicas, and if we did, trace that we did
		 * useless work
		 *
		 * XXX: break up bch2_bkey_drop_extra_durability() so we can
		 * trace what we're doing (or have it return a mask)
		 */
	}

	try(bch2_bkey_drop_extra_durability(trans, &opts,	insert, ~0, false));

	bch2_bkey_drop_extra_cached_ptrs(c, &opts, bkey_i_to_s(insert));

	bch2_bkey_propagate_incompressible(c, insert, k);

	bool should_check_enospc = false;
	s64 i_sectors_delta = 0, disk_sectors_delta = 0;
	try(bch2_sum_sector_overwrites(trans, iter, insert,
				       &should_check_enospc,
				       &i_sectors_delta,
				       &disk_sectors_delta));

	if (disk_sectors_delta > (s64) u->op.res.sectors)
		try(bch2_disk_reservation_add(c, &u->op.res,
					disk_sectors_delta - u->op.res.sectors,
					!should_check_enospc
					? BCH_DISK_RESERVATION_NOFAIL : 0));

	try(bch2_trans_log_str(trans, bch2_data_update_type_strs[u->opts.type]));
	try(bch2_trans_log_bkey(trans, u->btree_id, 0, u->k.k));

	try(bch2_insert_snapshot_whiteouts(trans, u->btree_id, k.k->p, insert->k.p));

	/*
	 * This set_needs_reconcile call is only for verifying that the data we
	 * just wrote was written correctly, otherwise we could fail to flag
	 * incorrectly written data due to needs_rb already being set on the
	 * existing extent
	 */
	try(bch2_bkey_set_needs_reconcile(trans, NULL, &opts, &new->k_i,
					  SET_NEEDS_RECONCILE_foreground,
					  u->op.opts.change_cookie));
	/* This is the real set_needs_reconcile() call */
	try(bch2_bkey_set_needs_reconcile(trans, NULL, &opts, insert,
					  SET_NEEDS_RECONCILE_foreground,
					  u->op.opts.change_cookie));

	if (u->op.opts.change_cookie == c->opt_change_cookie) {
		struct bkey_durability old_durability, new_durability;
		try(bch2_bkey_durability(trans, k, &old_durability));
		try(bch2_bkey_durability(trans, bkey_i_to_s_c(insert), &new_durability));

		if ((new_durability.total < old_durability.total &&
		     new_durability.total < min(u->op.opts.data_replicas, opts.data_replicas)) ||
		    !new_durability.total) {
			CLASS(bch_log_msg, msg)(c);
			prt_printf(&msg.m, "Data update would have reduced extent durability:\n");
			prt_printf(&msg.m, "Old extent %u, new %u, option specifies %u\n",
				   old_durability.total,
				   new_durability.total,
				   opts.data_replicas);
			data_update_key_to_text(&msg.m, u, k, bkey_i_to_s_c(&new->k_i), insert);
			bch2_fs_emergency_read_only(c, &msg.m);
			return bch_err_throw(c, emergency_ro);
		}
	}

	try(bch2_trans_update(trans, iter, insert, BTREE_UPDATE_internal_snapshot_node));
	try(bch2_trans_commit(trans, &u->op.res, NULL,
			      BCH_TRANS_COMMIT_no_check_rw|
			      BCH_TRANS_COMMIT_no_enospc|
			      u->opts.commit_flags));

	bch2_btree_iter_set_pos(iter, next_pos);

	event_add_trace(c, data_update_key, new->k.size, buf, ({
		prt_str(&buf, "\nold: ");
		bch2_bkey_val_to_text(&buf, c, old);
		prt_str(&buf, "\nk:   ");
		bch2_bkey_val_to_text(&buf, c, k);
		prt_str(&buf, "\nnew: ");
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(insert));
	}));

	return 0;
}

static int __bch2_data_update_index_update(struct btree_trans *trans,
					   struct bch_write_op *op)
{
	struct bch_fs *c = op->c;
	struct data_update *u = container_of(op, struct data_update, op);
	int ret = 0;

	CLASS(btree_iter, iter)(trans, u->btree_id,
				bkey_start_pos(&bch2_keylist_front(&op->insert_keys)->k),
				BTREE_ITER_slots|BTREE_ITER_intent);

	while (!bch2_keylist_empty(&op->insert_keys)) {
		struct bkey_i *insert = bch2_keylist_front(&op->insert_keys);

		if (insert->k.type != KEY_TYPE_extent) {
			CLASS(bch_log_msg, msg)(c);
			prt_printf(&msg.m, "Got non-extent key to insert in data update path - confused:\n");
			bch2_bkey_val_to_text(&msg.m, c, bkey_i_to_s_c(insert));
			msg.m.suppress = !bch2_count_fsck_err(c, data_update_got_non_extent, &msg.m);
			return 0;
		}

		bch2_trans_begin(trans);
		ret = data_update_index_update_key(trans, u, &iter);

		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			ret = 0;
		if (ret)
			break;

		while (!bch2_keylist_empty(&op->insert_keys) &&
		       bkey_ge(iter.pos, bch2_keylist_front(&op->insert_keys)->k.p))
			bch2_keylist_pop_front(&op->insert_keys);
	}

	return ret;
}

int bch2_data_update_index_update(struct bch_write_op *op)
{
	CLASS(btree_trans, trans)(op->c);
	return __bch2_data_update_index_update(trans, op);
}

static int data_update_index_update_key_nowrite(struct btree_trans *trans,
						struct data_update *u,
						struct btree_iter *iter,
						struct bkey_s_c k,
						struct printbuf *msg)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c old = bkey_i_to_s_c(u->k.k);

	unsigned ptrs_kill = ptr_mask_remap(c, old, u->opts.ptrs_kill, k);
	if (!ptrs_kill)
		return 0;

	struct bkey_i *new = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(k.k) +
				 sizeof(struct bch_extent_reconcile) +
				 sizeof(struct bch_extent_ptr) * BCH_REPLICAS_MAX));
	bkey_reassemble(new, k);

	bch2_bkey_drop_ptrs_mask(c, new, ptrs_kill);

	struct bch_inode_opts opts;
	try(bch2_bkey_get_io_opts(trans, NULL, k, &opts));
	try(bch2_bkey_set_needs_reconcile(trans, NULL, &opts, new,
					  SET_NEEDS_RECONCILE_foreground,
					  u->op.opts.change_cookie - 1));
	try(bch2_trans_update(trans, iter, new, BTREE_UPDATE_internal_snapshot_node));

	prt_printf(msg, "new: ");
	bch2_bkey_val_to_text(msg, c, bkey_i_to_s_c(new));
	prt_newline(msg);

	return 0;
}

static int data_update_index_update_nowrite(struct btree_trans *trans,
					    struct data_update *u)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c old = bkey_i_to_s_c(u->k.k);

	CLASS(bch_log_msg, msg)(c);
	prt_printf(&msg.m, "%s():\n", __func__);
	prt_printf(&msg.m, "old: ");
	bch2_bkey_val_to_text(&msg.m, c, old);
	prt_newline(&msg.m);
	ptr_bits_to_text(&msg.m, u->opts.ptrs_kill, "ptrs_kill");

	CLASS(disk_reservation, res)(c);

	BUG_ON(u->opts.ptrs_kill_ec);
	BUG_ON(!u->opts.ptrs_kill);

	return for_each_btree_key_commit(trans, iter, u->btree_id,
			bkey_start_pos(old.k),
			BTREE_ITER_slots|BTREE_ITER_intent,
			k, &res.r, NULL,
			BCH_TRANS_COMMIT_no_check_rw|
			BCH_TRANS_COMMIT_no_enospc, ({
		if (bkey_le(old.k->p, bkey_start_pos(k.k)))
			break;

		prt_printf(&msg.m, "k: ");
		bch2_bkey_val_to_text(&msg.m, c, k);
		prt_newline(&msg.m);

		if (!bch2_extents_match(c, k, old))
			continue;

		data_update_index_update_key_nowrite(trans, u, &iter, k, &msg.m);
	}));
}

void bch2_data_update_read_done(struct data_update *u)
{
	struct bch_fs *c = u->op.c;
	struct bch_read_bio *rbio = &u->rbio;
	struct bch_extent_crc_unpacked crc = rbio->pick.crc;

	u->read_done = true;

	/*
	 * If the extent has been bitrotted, we're going to have to give it a
	 * new checksum in order to move it - but the poison bit will ensure
	 * that userspace still gets the appropriate error.
	 */
	if (unlikely(rbio->ret == -BCH_ERR_data_read_csum_err &&
		     (bch2_bkey_extent_flags(bkey_i_to_s_c(u->k.k)) & BIT_ULL(BCH_EXTENT_FLAG_poisoned)))) {
		struct nonce nonce = extent_nonce(rbio->version, crc);

		crc.csum	= bch2_checksum_bio(c, crc.csum_type, nonce, &rbio->bio);
		rbio->ret	= 0;
	}

	if (unlikely(rbio->ret)) {
		u->op.error = rbio->ret;
		u->op.end_io(&u->op);
		return;
	}

	if (u->opts.type == BCH_DATA_UPDATE_scrub && !u->opts.ptrs_io_error) {
		u->op.end_io(&u->op);
		return;
	}

	if (unlikely(u->opts.ptrs_io_error) ){
		CLASS(btree_trans, trans)(c);
		struct bkey_s_c k = bkey_i_to_s_c(u->k.k);
		struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
		const union bch_extent_entry *entry;
		struct extent_ptr_decoded p;
		unsigned ptr_bit = 1;

		bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
			if ((u->opts.ptrs_io_error & ptr_bit) &&
			    !(u->opts.ptrs_kill & ptr_bit)) {
				int d = lockrestart_do(trans, bch2_extent_ptr_durability(trans, &p));

				if (d >= 0)
					u->op.nr_replicas += d;
				u->opts.ptrs_kill |= ptr_bit;
				bch2_dev_list_drop_dev(&u->op.devs_have, p.ptr.dev);
			}

			ptr_bit <<= 1;
		}

		if (!u->op.nr_replicas) {
			u->op.error = data_update_index_update_nowrite(trans, u);
			u->op.end_io(&u->op);
			return;
		}
	}

	/* write bio must own pages: */
	BUG_ON(!u->op.wbio.bio.bi_vcnt);

	u->op.crc = crc;
	u->op.wbio.bio.bi_iter.bi_size = crc.compressed_size << 9;

	closure_call(&u->op.cl, bch2_write, NULL, NULL);
}

static inline bool should_trace_update_err(struct data_update *u, int ret)
{
	if (bch2_err_matches(ret, BCH_ERR_data_update_fail_in_flight) ||
	    bch2_err_matches(ret, BCH_ERR_data_update_fail_need_copygc) ||
	    ((u->opts.type == BCH_DATA_UPDATE_reconcile ||
	      u->opts.type == BCH_DATA_UPDATE_promote) &&
	     (bch2_err_matches(ret, BCH_ERR_data_update_fail_no_rw_devs) ||
	      bch2_err_matches(ret, BCH_ERR_insufficient_devices))))
		return false;

	return true;
}

static void data_update_trace(struct data_update *u, int ret)
{
	struct bch_fs *c = u->op.c;

	if (!ret)
		event_add_trace(c, data_update, u->k.k->k.size, buf,
				bch2_data_update_to_text(&buf, u));
	else if (bch2_err_matches(ret, BCH_ERR_data_update_done))
		event_add_trace(c, data_update_no_io, u->k.k->k.size, buf, ({
				bch2_data_update_to_text(&buf, u);
				prt_printf(&buf, "\nret:\t%s\n", bch2_err_str(ret));
		}));
	else if (should_trace_update_err(u, ret))
		event_add_trace(c, data_update_fail, u->k.k->k.size, buf, ({
				bch2_data_update_to_text(&buf, u);
				prt_printf(&buf, "\nret:\t%s\n", bch2_err_str(ret));
		}));
}

void bch2_data_update_exit(struct data_update *update, int ret)
{
	data_update_trace(update, ret);

	struct bch_fs *c = update->op.c;
	struct bkey_s_c k = bkey_i_to_s_c(update->k.k);

	if (update->on_hashtable) {
		int ret2 = rhltable_remove(&c->update_table, &update->hash, bch_update_params);
		BUG_ON(ret2);
		update->on_hashtable = false;
	}

	if (update->b)
		atomic_dec(&update->b->count);

	if (update->ctxt) {
		scoped_guard(mutex, &update->ctxt->lock)
			list_del(&update->io_list);
		wake_up(&update->ctxt->wait);
	}

	bch2_bio_free_pages_pool(c, &update->op.wbio.bio);
	kfree(update->bvecs);
	update->bvecs = NULL;

	if (c->opts.nocow_enabled)
		bch2_bkey_nocow_unlock(c, k, update->ptrs_held, 0);
	bkey_put_dev_refs(c, k, update->ptrs_held);
	bch2_disk_reservation_put(c, &update->op.res);
	bch2_bkey_buf_exit(&update->k);
}

static noinline_for_stack
int bch2_update_unwritten_extent(struct btree_trans *trans,
				 struct data_update *update)
{
	struct bch_fs *c = update->op.c;
	struct bkey_i_extent *e;
	struct write_point *wp;
	struct bkey_s_c k;
	int ret = 0;

	CLASS(closure_stack, cl)();
	bch2_keylist_init(&update->op.insert_keys, update->op.inline_keys);

	while (bpos_lt(update->op.pos, update->k.k->k.p)) {
		unsigned sectors = update->k.k->k.p.offset -
			update->op.pos.offset;

		bch2_trans_begin(trans);

		{
			CLASS(btree_iter, iter)(trans, update->btree_id, update->op.pos,
						BTREE_ITER_slots);
			ret = lockrestart_do(trans, bkey_err(k = bch2_btree_iter_peek_slot(&iter)));
			if (ret || !bch2_extents_match(c, k, bkey_i_to_s_c(update->k.k)))
				break;
		}

		e = bkey_extent_init(update->op.insert_keys.top);
		e->k.p = update->op.pos;

		ret = bch2_alloc_sectors_start_trans(trans,
				update->op.target,
				false,
				update->op.write_point,
				&update->op.devs_have,
				update->op.nr_replicas,
				update->op.nr_replicas,
				update->op.watermark,
				0, &cl, &wp);
		if (bch2_err_matches(ret, BCH_ERR_operation_blocked)) {
			bch2_trans_unlock(trans);
			closure_sync(&cl);
			continue;
		}

		bch_err_fn_ratelimited(c, ret);

		if (ret)
			break;

		sectors = min(sectors, wp->sectors_free);

		bch2_key_resize(&e->k, sectors);

		bch2_open_bucket_get(c, wp, &update->op.open_buckets);
		bch2_alloc_sectors_append_ptrs(c, wp, &e->k_i, sectors, false);
		bch2_alloc_sectors_done(c, wp);

		update->op.pos.offset += sectors;

		extent_for_each_ptr(extent_i_to_s(e), ptr)
			ptr->unwritten = true;
		bch2_keylist_push(&update->op.insert_keys);

		ret = __bch2_data_update_index_update(trans, &update->op);

		bch2_open_buckets_put(c, &update->op.open_buckets);

		if (ret)
			break;
	}

	if (closure_nr_remaining(&cl) != 1) {
		bch2_trans_unlock(trans);
		closure_sync(&cl);
	}

	return ret;
}

void bch2_data_update_opts_to_text(struct printbuf *out, struct bch_fs *c,
				   struct bch_inode_opts *io_opts,
				   struct data_update_opts *data_opts)
{
	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 20);

	prt_str(out, bch2_data_update_type_strs[data_opts->type]);
	prt_newline(out);

	ptr_bits_to_text(out, data_opts->ptrs_io_error,	"io error");
	ptr_bits_to_text(out, data_opts->ptrs_kill,	"kill");
	ptr_bits_to_text(out, data_opts->ptrs_kill_ec,	"kill ec");

	prt_str(out, "target:\t");
	bch2_target_to_text(out, c, data_opts->target);
	prt_newline(out);

	prt_str(out, "extra replicas:\t");
	prt_u64(out, data_opts->extra_replicas);
	prt_newline(out);

	prt_printf(out, "read_dev:\t%i\n", data_opts->read_dev);
	prt_printf(out, "checksum_paranoia:\t%i\n", data_opts->checksum_paranoia);

	prt_str(out, "io path options:\t");
	bch2_inode_opts_to_text(out, c, *io_opts);
	prt_newline(out);
}

void bch2_data_update_to_text(struct printbuf *out, struct data_update *m)
{
	bch2_data_update_opts_to_text(out, m->op.c, &m->op.opts, &m->opts);
	prt_newline(out);

	prt_str(out, "old key:\t");
	bch2_bkey_val_to_text(out, m->op.c, bkey_i_to_s_c(m->k.k));
	prt_newline(out);

	prt_printf(out, "write: ");
	__bch2_write_op_to_text(out, &m->op);
}

void bch2_data_update_inflight_to_text(struct printbuf *out, struct data_update *m)
{
	bch2_bkey_val_to_text(out, m->op.c, bkey_i_to_s_c(m->k.k));
	prt_newline(out);
	guard(printbuf_indent)(out);
	bch2_data_update_opts_to_text(out, m->op.c, &m->op.opts, &m->opts);

	if (!m->read_done) {
		prt_printf(out, "read:\n");
		guard(printbuf_indent)(out);
		bch2_read_bio_to_text(out, m->op.c, &m->rbio);
	} else {
		prt_printf(out, "write:\n");
		guard(printbuf_indent)(out);
		__bch2_write_op_to_text(out, &m->op);
	}
}

static int bch2_extent_drop_ptrs(struct btree_trans *trans,
				 struct btree_iter *iter,
				 struct bkey_s_c k,
				 struct bch_inode_opts *io_opts,
				 struct data_update_opts *data_opts)
{
	struct bch_fs *c = trans->c;

	struct bkey_i *n = errptr_try(bch2_bkey_make_mut_noupdate(trans, k));

	if (data_opts->ptrs_kill_ec)
		try(bch2_bkey_drop_extra_ec_durability(trans, io_opts, n, data_opts->ptrs_kill_ec));

	if (data_opts->ptrs_kill)
		try(bch2_bkey_drop_extra_durability(trans, io_opts, n, data_opts->ptrs_kill, false));

	/*
	 * If the new extent no longer has any pointers, bch2_extent_normalize()
	 * will do the appropriate thing with it (turning it into a
	 * KEY_TYPE_error key, or just a discard if it was a cached extent)
	 */
	bch2_bkey_drop_extra_cached_ptrs(c, io_opts, bkey_i_to_s(n));

	/*
	 * Since we're not inserting through an extent iterator
	 * (BTREE_ITER_all_snapshots iterators aren't extent iterators),
	 * we aren't using the extent overwrite path to delete, we're
	 * just using the normal key deletion path:
	 */
	if (bkey_deleted(&n->k) && !(iter->flags & BTREE_ITER_is_extents))
		n->k.size = 0;

	return bch2_trans_relock(trans) ?:
		bch2_trans_update(trans, iter, n, BTREE_UPDATE_internal_snapshot_node) ?:
		bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc);
}

static int bch2_data_update_bios_init(struct data_update *m, struct bch_fs *c,
				      struct bch_inode_opts *io_opts,
				      unsigned buf_bytes)
{
	/* be paranoid */
	buf_bytes = round_up(buf_bytes, c->opts.block_size);

	unsigned nr_vecs = DIV_ROUND_UP(buf_bytes, PAGE_SIZE);

	m->bvecs = kmalloc_array(nr_vecs, sizeof*(m->bvecs), GFP_KERNEL);
	if (!m->bvecs)
		return -ENOMEM;

	bio_init(&m->rbio.bio,		NULL, m->bvecs, nr_vecs, REQ_OP_READ);
	bio_init(&m->op.wbio.bio,	NULL, m->bvecs, nr_vecs, 0);

	if (bch2_bio_alloc_pages(&m->op.wbio.bio, c->opts.block_size, buf_bytes, GFP_KERNEL)) {
		kfree(m->bvecs);
		m->bvecs = NULL;
		return -ENOMEM;
	}

	rbio_init(&m->rbio.bio, c, *io_opts, NULL);
	m->rbio.data_update		= true;
	m->rbio.bio.bi_iter.bi_size	= buf_bytes;
	m->rbio.bio.bi_iter.bi_sector	= bkey_start_offset(&m->k.k->k);
	m->op.wbio.bio.bi_ioprio	= IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0);
	return 0;
}

static unsigned durability_available_on_target(struct bch_fs *c,
					       enum bch_watermark watermark,
					       enum bch_data_type data_type,
					       unsigned target,
					       struct bch_devs_list *devs_have,
					       bool nonblocking,
					       struct printbuf *trace,
					       bool *need_copygc)
{
	if (trace) {
		prt_str(trace, "available to write on ");
		bch2_target_to_text(trace, c, target);
		prt_newline(trace);
		printbuf_indent_add(trace, 2);
		printbuf_atomic_inc(trace);
	}

	guard(rcu)();
	struct bch_devs_mask devs = target_rw_devs(c, data_type, target);
	unsigned durability = 0;

	unsigned i;
	for_each_set_bit(i, devs.d, BCH_SB_MEMBERS_MAX) {
		if (bch2_dev_list_has_dev(*devs_have, i))
			continue;

		struct bch_dev *ca = bch2_dev_rcu_noerror(c, i);
		if (!ca)
			continue;

		u64 free = nonblocking
			? dev_buckets_free(ca, watermark)
			: dev_buckets_available(ca, watermark);
		if (free)
			durability += ca->mi.durability;
		else if (!bch2_copygc_dev_wait_amount(ca)) {
			*need_copygc = true;
			bch2_copygc_wakeup(c);
		}

		if (trace)
			prt_printf(trace, "%s: %llu\n", ca->name, free);
	}

	if (trace) {
		printbuf_indent_sub(trace, 2);
		printbuf_atomic_dec(trace);
	}

	return durability;
}

static unsigned bch2_btree_ptr_durability_on_target(struct bch_fs *c, struct bkey_s_c k,
					       unsigned target)
{
	/* Doesn't handle stripe pointers: */

	struct bch_devs_mask devs = target_rw_devs(c, BCH_DATA_user, target);
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	unsigned durability = 0;

	bkey_for_each_ptr_decode(k.k, ptrs, p, entry)
		if (p.ptr.dev != BCH_SB_MEMBER_INVALID &&
		    !p.ptr.cached &&
		    test_bit(p.ptr.dev, devs.d))
			durability += bch2_dev_durability(c, p.ptr.dev);

	return durability;
}

static int bch2_can_do_write_btree(struct bch_fs *c,
				   struct bch_inode_opts *opts,
				   struct data_update_opts *data_opts, struct bkey_s_c k,
				   struct printbuf *trace)
{
	enum bch_watermark watermark = data_opts->commit_flags & BCH_WATERMARK_MASK;
	struct bch_devs_list empty = {};
	bool need_copygc = false;

	if (bch2_bkey_nr_dirty_ptrs(c, k) > opts->data_replicas)
		return 0;

	if (durability_available_on_target(c, watermark, BCH_DATA_btree, data_opts->target, &empty,
					   data_opts->write_flags & BCH_WRITE_alloc_nowait,
					   trace, &need_copygc) >
	    bch2_btree_ptr_durability_on_target(c, k, data_opts->target))
		return 0;

	if (!(data_opts->write_flags & BCH_WRITE_only_specified_devs)) {
		unsigned d = bch2_btree_ptr_durability(c, k).total;
		if (d < opts->data_replicas &&
		    d < durability_available_on_target(c, watermark, BCH_DATA_btree, 0, &empty,
						       data_opts->write_flags & BCH_WRITE_alloc_nowait,
						       trace, &need_copygc))
			return 0;
	}

	return __bch2_err_throw(c, !need_copygc
				? -BCH_ERR_data_update_fail_no_rw_devs
				: -BCH_ERR_data_update_fail_need_copygc);
}

static int __bch2_can_do_write(struct bch_fs *c,
			       struct bch_inode_opts *opts,
			       struct data_update_opts *data_opts,
			       struct bch_devs_list *devs_have,
			       struct bkey_s_c k,
			       struct printbuf *trace)
{
	bool btree = bkey_is_btree_ptr(k.k);
	enum bch_watermark watermark = data_opts->commit_flags & BCH_WATERMARK_MASK;
	enum bch_data_type data_type = btree
		? BCH_DATA_btree
		: BCH_DATA_user;
	unsigned target = data_opts->write_flags & BCH_WRITE_only_specified_devs
		? data_opts->target
		: 0;

	if ((data_opts->write_flags & BCH_WRITE_alloc_nowait) &&
	    unlikely(c->allocator.open_buckets_nr_free <= bch2_open_buckets_reserved(watermark)))
		return bch_err_throw(c, data_update_fail_would_block);

	if (btree &&
	    data_opts->type == BCH_DATA_UPDATE_reconcile &&
	    !bch2_bkey_has_dev_bad_or_evacuating(c, k))
		return bch2_can_do_write_btree(c, opts, data_opts, k, trace);

	if (trace) {
		prt_str(trace, "keeping devices: ");
		bch2_devs_list_to_text(trace, c, devs_have);
		prt_newline(trace);

		if (data_opts->write_flags & BCH_WRITE_alloc_nowait)
			prt_str(trace, "nonblocking\n");
	}

	bool need_copygc = false;
	if (durability_available_on_target(c, watermark, data_type, target, devs_have,
					   data_opts->write_flags & BCH_WRITE_alloc_nowait,
					   trace, &need_copygc))
		return 0;

	return __bch2_err_throw(c, !need_copygc
				? -BCH_ERR_data_update_fail_no_rw_devs
				: -BCH_ERR_data_update_fail_need_copygc);
}

int bch2_can_do_data_update(struct btree_trans *trans,
			    struct bch_inode_opts *opts,
			    struct data_update_opts *data_opts,
			    struct bkey_s_c k,
			    struct printbuf *trace)
{
	struct bch_fs *c = trans->c;
	struct bch_devs_list devs_have = {};
	unsigned durability_keeping = 0;

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	unsigned ptr_bit = 1;

	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		if (p.ptr.dev != BCH_SB_MEMBER_INVALID &&
		    !(ptr_bit & data_opts->ptrs_kill)) {
			int d = ptr_bit & data_opts->ptrs_kill_ec
				? bch2_dev_durability(c, p.ptr.dev)
				: bch2_extent_ptr_durability(trans, &p);
			if (d < 0)
				return d;

			durability_keeping += d;
			if (!data_opts->no_devs_have)
				devs_have.data[devs_have.nr++] = p.ptr.dev;
		}

		ptr_bit <<= 1;
	}

	if (!bkey_is_btree_ptr(k.k) &&
	    !data_opts->extra_replicas &&
	    durability_keeping >= opts->data_replicas)
		return 0;

	if (trace)
		prt_printf(trace, "need %u replicas\n", opts->data_replicas - durability_keeping);

	return __bch2_can_do_write(c, opts, data_opts, &devs_have, k, trace);
}

/*
 * When an extent has non-checksummed pointers and is supposed to be
 * checksummed, special handling applies:
 *
 * We don't want to blindly apply an existing checksum to non-checksummed data,
 * or lose our ability to detect that different replicas in the same extent have
 * or had different data, so:
 *
 * - prefer to read from the specific replica being rewritten
 * - if we're rewriting a replica without a checksum, only rewrite that specific
 *   replica in this data update
 */
static void checksummed_and_non_checksummed_handling(struct data_update *u, struct bkey_ptrs_c ptrs)
{
	if (unlikely(!u->op.opts.data_checksum))
		return;

	struct bch_fs *c = u->op.c;
	struct bkey_s_c k = bkey_i_to_s_c(u->k.k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	bkey_for_each_ptr_decode(k.k, ptrs, p, entry)
		u->opts.checksum_paranoia |= p.crc.csum_type == 0;

	if (likely(!u->opts.checksum_paranoia))
		return;

	bool rewrite_found = false;
	unsigned ptr_bit = 1;

	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		if (ptr_bit & u->opts.ptrs_kill) {
			if (!rewrite_found) {
				rewrite_found = true;
				u->opts.read_dev = p.ptr.dev;
			} else {
				u->opts.ptrs_kill &= ~ptr_bit;
			}
		}

		ptr_bit <<= 1;
	}
}

int bch2_data_update_init(struct btree_trans *trans,
			  struct btree_iter *iter,
			  struct moving_context *ctxt,
			  struct data_update *m,
			  struct write_point_specifier wp,
			  struct bch_inode_opts *io_opts,
			  struct data_update_opts data_opts,
			  enum btree_id btree_id,
			  struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	m->pos = BBPOS(iter ? iter->btree_id : BTREE_ID_extents, k.k->p);
	bch2_bkey_buf_init(&m->k);
	bch2_bkey_buf_reassemble(&m->k, k);
	k = bkey_i_to_s_c(m->k.k);

	m->btree_id	= btree_id;
	m->opts		= data_opts;

	m->ctxt		= ctxt;
	m->stats	= ctxt ? ctxt->stats : NULL;
	INIT_LIST_HEAD(&m->read_list);
	INIT_LIST_HEAD(&m->io_list);

	bch2_write_op_init(&m->op, c, *io_opts);
	m->op.pos	= bkey_start_pos(k.k);
	m->op.version	= k.k->bversion;
	m->op.target	= data_opts.target;
	m->op.write_point = wp;
	m->op.nr_replicas = 0;
	m->op.flags	|= BCH_WRITE_pages_stable|
		BCH_WRITE_pages_owned|
		BCH_WRITE_data_encoded|
		BCH_WRITE_move|
		m->opts.write_flags;
	m->op.compression_opt	= io_opts->background_compression;
	m->op.watermark		= max(m->opts.commit_flags & BCH_WATERMARK_MASK,
				      BCH_WATERMARK_normal);

	if (k.k->p.snapshot &&
	    unlikely(ret = bch2_check_key_has_snapshot(trans, iter, k))) {
		if (ret > 0) /* key was deleted */
			ret = bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc) ?:
				bch_err_throw(c, data_update_fail_no_snapshot);
		if (bch2_err_matches(ret, BCH_ERR_recovery_will_run)) {
			/* Can't repair yet, waiting on other recovery passes */
			ret = bch_err_throw(c, data_update_fail_no_snapshot);
		}
		goto out;
	}

	if (m->opts.extra_replicas) {
		ret = bch2_disk_reservation_add(c, &m->op.res, k.k->size * m->opts.extra_replicas, 0);
		if (ret)
			goto out;
	}

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(bkey_i_to_s_c(m->k.k));
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	unsigned buf_bytes = 0;
	bool unwritten = false;
	unsigned durability_keeping = 0;

	if (m->opts.ptrs_kill)
		checksummed_and_non_checksummed_handling(m, ptrs);

	unsigned ptr_bit = 1;
	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		if (!(ptr_bit & m->opts.ptrs_kill)) {
			int d = ptr_bit & m->opts.ptrs_kill_ec
				? bch2_dev_durability(c, p.ptr.dev)
				: bch2_extent_ptr_durability(trans, &p);
			if (d < 0) {
				ret = d;
				goto out;
			}

			durability_keeping += d;
			if (!m->opts.no_devs_have)
				bch2_dev_list_add_dev(&m->op.devs_have, p.ptr.dev);
		}

		/*
		 * op->csum_type is normally initialized from the fs/file's
		 * current options - but if an extent is encrypted, we require
		 * that it stays encrypted:
		 */
		if (bch2_csum_type_is_encryption(p.crc.csum_type)) {
			m->op.nonce	= p.crc.nonce + p.crc.offset;
			m->op.csum_type = p.crc.csum_type;
		}

		if (p.crc.compression_type == BCH_COMPRESSION_TYPE_incompressible)
			m->op.incompressible = true;

		buf_bytes = max_t(unsigned, buf_bytes, p.crc.uncompressed_size << 9);
		unwritten |= p.ptr.unwritten;

		ptr_bit <<= 1;
	}

	if (m->opts.type != BCH_DATA_UPDATE_scrub) {
		/*
		 * If current extent durability is less than io_opts.data_replicas,
		 * we're not trying to rereplicate the extent up to data_alloc/replicas.here -
		 * unless extra_replicas was specified
		 *
		 * Increasing replication is an explicit operation triggered by
		 * rereplicate, currently, so that users don't get an unexpected -ENOSPC
		 */
		m->op.nr_replicas = max(0, (int) (io_opts->data_replicas - durability_keeping)) +
			m->opts.extra_replicas;

		if (!durability_keeping) {
			m->op.nr_replicas = max_t(unsigned, m->op.nr_replicas, 1);
			m->op.flags &= ~BCH_WRITE_cached;
		}

		/*
		 * It might turn out that we don't need any new replicas, if the
		 * replicas or durability settings have been changed since the extent
		 * was written:
		 */
		if (!m->op.nr_replicas) {
			/* if iter == NULL, it's just a promote */
			if (iter)
				ret = bch2_extent_drop_ptrs(trans, iter, k, io_opts, &m->opts);
			if (!ret)
				ret = bch_err_throw(c, data_update_done_no_writes_needed);
			goto out;
		}

		/*
		 * Check if the allocation will succeed, to avoid getting an error later
		 * in bch2_write() -> bch2_alloc_sectors_start() and doing a useless
		 * read:
		 *
		 * This guards against
		 * - BCH_WRITE_alloc_nowait allocations failing (promotes)
		 * - Destination target full
		 * - Device(s) in destination target offline
		 * - Insufficient durability available in destination target
		 *   (i.e. trying to move a durability=2 replica to a target with a
		 *   single durability=2 device)
		 */
		if (data_opts.type != BCH_DATA_UPDATE_copygc) {
			ret = __bch2_can_do_write(c, io_opts, &m->opts, &m->op.devs_have, k, NULL);
			if (ret)
				goto out;

			if (bch2_data_update_in_flight(c, &m->pos)) {
				event_inc(c, data_update_in_flight);
				ret = bch_err_throw(c, data_update_fail_in_flight);
				goto out;
			}
		}

		if (!rhltable_insert_key(&c->update_table, &m->pos, &m->hash, bch_update_params))
			m->on_hashtable = true;
	} else {
		if (unwritten) {
			ret = bch_err_throw(c, data_update_done_unwritten);
			goto out;
		}
	}

	/*
	 * Check if we have checksummed and non-checksummed pointers, prefer to
	 * read from the pointer we're operating on
	 */

	m->ptrs_held = bkey_get_dev_refs(c, k);

	if (c->opts.nocow_enabled) {
		if (!bch2_bkey_nocow_trylock(c, ptrs, m->ptrs_held, 0)) {
			if (!ctxt) {
				/* We're being called from the promote path:
				 * there is a btree_trans on the stack that's
				 * holding locks, but we don't have a pointer to
				 * it. Ouch - this needs to be fixed.
				 */
				ret = bch_err_throw(c, nocow_lock_blocked);
				goto out;
			}

			bool locked = false;
			if (ctxt)
				move_ctxt_wait_event(ctxt,
					(locked = bch2_bkey_nocow_trylock(c, ptrs, m->ptrs_held, 0)) ||
					list_empty(&ctxt->ios));
			if (!locked) {
				if (ctxt)
					bch2_trans_unlock(ctxt->trans);
				bch2_bkey_nocow_lock(c, ptrs, m->ptrs_held, 0);
			}
		}
	}

	if (unwritten) {
		ret = bch2_update_unwritten_extent(trans, m) ?:
			bch_err_throw(c, data_update_done_unwritten);
		goto out_nocow_unlock;
	}

	bch2_trans_unlock(trans);

	ret = bch2_data_update_bios_init(m, c, io_opts, buf_bytes);
	if (ret)
		goto out_nocow_unlock;

	m->rbio.data_update_verify_decompress = m->opts.type == BCH_DATA_UPDATE_scrub;

	return 0;
out_nocow_unlock:
	if (c->opts.nocow_enabled)
		bch2_bkey_nocow_unlock(c, k, m->ptrs_held, 0);
out:
	BUG_ON(!ret);

	if (!bch2_err_matches(ret, BCH_ERR_transaction_restart))
		data_update_trace(m, ret);

	if (m->on_hashtable) {
		int ret2 = rhltable_remove(&c->update_table, &m->hash, bch_update_params);
		BUG_ON(ret2);
		m->on_hashtable = false;
	}

	bkey_put_dev_refs(c, k, m->ptrs_held);
	m->ptrs_held = 0;
	bch2_disk_reservation_put(c, &m->op.res);
	bch2_bkey_buf_exit(&m->k);

	return ret;
}

void bch2_fs_data_update_exit(struct bch_fs *c)
{
	if (c->update_table.ht.tbl)
		rhltable_destroy(&c->update_table);
}

int bch2_fs_data_update_init(struct bch_fs *c)
{
	if (rhltable_init(&c->update_table, &bch_update_params))
		return bch_err_throw(c, ENOMEM_promote_table_init);

	return 0;
}
