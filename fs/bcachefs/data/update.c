// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/buckets.h"
#include "alloc/disk_groups.h"
#include "alloc/foreground.h"

#include "btree/bkey_buf.h"
#include "btree/update.h"

#include "data/compress.h"
#include "data/ec.h"
#include "data/extents.h"
#include "data/keylist.h"
#include "data/move.h"
#include "data/nocow_locking.h"
#include "data/rebalance.h"
#include "data/update.h"
#include "data/write.h"

#include "fs/inode.h"

#include "init/error.h"
#include "init/fs.h"

#include "snapshots/snapshot.h"
#include "snapshots/subvolume.h"

#include <linux/ioprio.h>

static const char * const bch2_data_update_type_strs[] = {
#define x(n) #n,
	BCH_DATA_UPDATE_TYPES()
#undef x
	NULL
};

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
		if (likely(bch2_dev_tryget(c, ptr->dev)))
			ptrs_held |= ptr_bit;
		ptr_bit <<= 1;
	}

	return ptrs_held;
}

noinline_for_stack
static void trace_data_update_key_fail2(struct data_update *m,
					struct btree_iter *iter,
					struct bkey_s_c new,
					struct bkey_s_c wrote,
					struct bkey_i *insert,
					const char *msg)
{
	if (m->stats) {
		atomic64_inc(&m->stats->keys_raced);
		atomic64_add(new.k->p.offset - iter->pos.offset,
			     &m->stats->sectors_raced);
	}

	count_event(m->op.c, data_update_key_fail);

	if (!trace_data_update_key_fail_enabled())
		return;

	struct bch_fs *c = m->op.c;
	struct bkey_s_c old = bkey_i_to_s_c(m->k.k);
	unsigned rewrites_found = 0;

	CLASS(printbuf, buf)();
	printbuf_indent_add_nextline(&buf, 2);

	prt_str(&buf, msg);
	prt_newline(&buf);

	if (insert) {
		const union bch_extent_entry *entry;
		struct bch_extent_ptr *ptr;
		struct extent_ptr_decoded p;

		unsigned ptr_bit = 1;
		bkey_for_each_ptr_decode(old.k, bch2_bkey_ptrs_c(old), p, entry) {
			if ((ptr_bit & m->opts.ptrs_rewrite) &&
			    (ptr = bch2_extent_has_ptr(old, p, bkey_i_to_s(insert))) &&
			    !ptr->cached)
				rewrites_found |= ptr_bit;
			ptr_bit <<= 1;
		}
	}

	prt_str(&buf, "rewrites found:\t");
	bch2_prt_u64_base2(&buf, rewrites_found);
	prt_newline(&buf);

	bch2_data_update_opts_to_text(&buf, c, &m->op.opts, &m->opts);

	prt_str_indented(&buf, "\nold:    ");
	bch2_bkey_val_to_text(&buf, c, old);

	prt_str_indented(&buf, "\nnew:    ");
	bch2_bkey_val_to_text(&buf, c, new);

	prt_str_indented(&buf, "\nwrote:  ");
	bch2_bkey_val_to_text(&buf, c, wrote);

	if (insert) {
		prt_str_indented(&buf, "\ninsert: ");
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(insert));
	}

	trace_data_update_key_fail(c, buf.buf);
}

noinline_for_stack
static void trace_data_update_key2(struct data_update *m,
			       struct bkey_s_c old, struct bkey_s_c k,
			       struct bkey_i *insert)
{
	struct bch_fs *c = m->op.c;
	CLASS(printbuf, buf)();

	prt_str(&buf, "\nold: ");
	bch2_bkey_val_to_text(&buf, c, old);
	prt_str(&buf, "\nk:   ");
	bch2_bkey_val_to_text(&buf, c, k);
	prt_str(&buf, "\nnew: ");
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(insert));

	trace_data_update_key(c, buf.buf);
}

static int __bch2_data_update_index_update(struct btree_trans *trans,
					   struct bch_write_op *op)
{
	struct bch_fs *c = op->c;
	struct data_update *m = container_of(op, struct data_update, op);
	int ret = 0;

	CLASS(btree_iter, iter)(trans, m->btree_id,
			     bkey_start_pos(&bch2_keylist_front(&op->insert_keys)->k),
			     BTREE_ITER_slots|BTREE_ITER_intent);

	while (1) {
		struct bkey_s_c k;
		struct bkey_s_c old = bkey_i_to_s_c(m->k.k);
		struct bkey_i *insert = NULL;
		struct bkey_i_extent *new;
		const union bch_extent_entry *entry_c;
		union bch_extent_entry *entry;
		struct extent_ptr_decoded p;
		struct bch_extent_ptr *ptr;
		const struct bch_extent_ptr *ptr_c;
		struct bpos next_pos;
		bool should_check_enospc;
		s64 i_sectors_delta = 0, disk_sectors_delta = 0;
		unsigned rewrites_found = 0, durability, ptr_bit;

		bch2_trans_begin(trans);

		k = bch2_btree_iter_peek_slot(&iter);
		ret = bkey_err(k);
		if (ret)
			goto err;

		struct bkey_i *tmp_k = bch2_bkey_make_mut_noupdate(trans, k);
		ret = PTR_ERR_OR_ZERO(tmp_k);
		if (ret)
			goto err;

		k = bkey_i_to_s_c(tmp_k);

		new = bkey_i_to_extent(bch2_keylist_front(&op->insert_keys));

		if (!bch2_extents_match(k, old)) {
			trace_data_update_key_fail2(m, &iter, k, bkey_i_to_s_c(&new->k_i), NULL, "no match:");
			goto nowork;
		}

		insert = bch2_trans_kmalloc(trans,
					    bkey_bytes(k.k) +
					    bkey_val_bytes(&new->k) +
					    sizeof(struct bch_extent_rebalance));
		ret = PTR_ERR_OR_ZERO(insert);
		if (ret)
			goto err;

		bkey_reassemble(insert, k);

		new = bch2_trans_kmalloc(trans, bkey_bytes(&new->k));
		ret = PTR_ERR_OR_ZERO(new);
		if (ret)
			goto err;

		bkey_copy(&new->k_i, bch2_keylist_front(&op->insert_keys));
		bch2_cut_front(iter.pos, &new->k_i);

		bch2_cut_front(iter.pos,	insert);
		bch2_cut_back(new->k.p,		insert);
		bch2_cut_back(insert->k.p,	&new->k_i);

		bch2_bkey_propagate_incompressible(insert, bkey_i_to_s_c(&new->k_i));

		/*
		 * @old: extent that we read from
		 * @insert: key that we're going to update, initialized from
		 * extent currently in btree - same as @old unless we raced with
		 * other updates
		 * @new: extent with new pointers that we'll be adding to @insert
		 *
		 * Fist, drop ptrs_rewrite from @new:
		 */
		ptr_bit = 1;
		bkey_for_each_ptr_decode(old.k, bch2_bkey_ptrs_c(old), p, entry_c) {
			if ((ptr_bit & m->opts.ptrs_rewrite) &&
			    (ptr = bch2_extent_has_ptr(old, p, bkey_i_to_s(insert)))) {
				if (ptr_bit & m->opts.ptrs_io_error)
					bch2_bkey_drop_ptr_noerror(bkey_i_to_s(insert), ptr);
				else if (!ptr->cached)
					bch2_extent_ptr_set_cached(c, &m->op.opts,
								   bkey_i_to_s(insert), ptr);

				rewrites_found |= ptr_bit;
			}
			ptr_bit <<= 1;
		}

		if (m->opts.ptrs_rewrite &&
		    !rewrites_found &&
		    bch2_bkey_durability(c, k) >= m->op.opts.data_replicas) {
			trace_data_update_key_fail2(m, &iter, k, bkey_i_to_s_c(&new->k_i), insert,
						    "no rewrites found:");
			goto nowork;
		}

		/*
		 * A replica that we just wrote might conflict with a replica
		 * that we want to keep, due to racing with another move:
		 */
restart_drop_conflicting_replicas:
		extent_for_each_ptr(extent_i_to_s(new), ptr)
			if ((ptr_c = bch2_bkey_has_device_c(bkey_i_to_s_c(insert), ptr->dev)) &&
			    !ptr_c->cached) {
				bch2_bkey_drop_ptr_noerror(bkey_i_to_s(&new->k_i), ptr);
				goto restart_drop_conflicting_replicas;
			}

		if (!bkey_val_u64s(&new->k)) {
			trace_data_update_key_fail2(m, &iter, k,
					    bkey_i_to_s_c(bch2_keylist_front(&op->insert_keys)),
					    insert, "new replicas conflicted:");
			goto nowork;
		}

		/* Now, drop pointers that conflict with what we just wrote: */
		extent_for_each_ptr_decode(extent_i_to_s(new), p, entry)
			if ((ptr = bch2_bkey_has_device(bkey_i_to_s(insert), p.ptr.dev)))
				bch2_bkey_drop_ptr_noerror(bkey_i_to_s(insert), ptr);

		durability = bch2_bkey_durability(c, bkey_i_to_s_c(insert)) +
			bch2_bkey_durability(c, bkey_i_to_s_c(&new->k_i));

		/* Now, drop excess replicas: */
		scoped_guard(rcu) {
restart_drop_extra_replicas:
			bkey_for_each_ptr_decode(old.k, bch2_bkey_ptrs(bkey_i_to_s(insert)), p, entry) {
				unsigned ptr_durability = bch2_extent_ptr_durability(c, &p);

				if (!p.ptr.cached &&
				    durability - ptr_durability >= m->op.opts.data_replicas) {
					durability -= ptr_durability;

					bch2_extent_ptr_set_cached(c, &m->op.opts,
								   bkey_i_to_s(insert), &entry->ptr);
					goto restart_drop_extra_replicas;
				}
			}
		}

		/* Finally, add the pointers we just wrote: */
		extent_for_each_ptr_decode(extent_i_to_s(new), p, entry)
			bch2_extent_ptr_decoded_append(insert, &p);

		bch2_bkey_narrow_crcs(insert, (struct bch_extent_crc_unpacked) { 0 });
		bch2_bkey_drop_extra_cached_ptrs(c, &m->op.opts, bkey_i_to_s(insert));

		ret = bch2_sum_sector_overwrites(trans, &iter, insert,
						 &should_check_enospc,
						 &i_sectors_delta,
						 &disk_sectors_delta);
		if (ret)
			goto err;

		if (disk_sectors_delta > (s64) op->res.sectors) {
			ret = bch2_disk_reservation_add(c, &op->res,
						disk_sectors_delta - op->res.sectors,
						!should_check_enospc
						? BCH_DISK_RESERVATION_NOFAIL : 0);
			if (ret)
				goto out;
		}

		next_pos = insert->k.p;

		struct bch_inode_opts opts;

		ret =   bch2_trans_log_str(trans, bch2_data_update_type_strs[m->opts.type]) ?:
			bch2_trans_log_bkey(trans, m->btree_id, 0, m->k.k) ?:
			bch2_insert_snapshot_whiteouts(trans, m->btree_id,
						k.k->p, bkey_start_pos(&insert->k)) ?:
			bch2_insert_snapshot_whiteouts(trans, m->btree_id,
						k.k->p, insert->k.p) ?:
			bch2_bkey_get_io_opts(trans, NULL, k, &opts) ?:
			bch2_bkey_set_needs_rebalance(c, &opts, insert,
						      SET_NEEDS_REBALANCE_foreground,
						      m->op.opts.change_cookie) ?:
			bch2_trans_update(trans, &iter, insert,
				BTREE_UPDATE_internal_snapshot_node) ?:
			bch2_trans_commit(trans, &op->res,
				NULL,
				BCH_TRANS_COMMIT_no_check_rw|
				BCH_TRANS_COMMIT_no_enospc|
				m->opts.commit_flags);
		if (ret)
			goto err;

		bch2_btree_iter_set_pos(&iter, next_pos);

		if (trace_data_update_key_enabled())
			trace_data_update_key2(m, old, k, insert);
		this_cpu_add(c->counters[BCH_COUNTER_data_update_key], new->k.size);
err:
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			ret = 0;
		if (ret)
			break;
next:
		while (bkey_ge(iter.pos, bch2_keylist_front(&op->insert_keys)->k.p)) {
			bch2_keylist_pop_front(&op->insert_keys);
			if (bch2_keylist_empty(&op->insert_keys))
				goto out;
		}
		continue;
nowork:
		bch2_btree_iter_advance(&iter);
		goto next;
	}
out:
	BUG_ON(bch2_err_matches(ret, BCH_ERR_transaction_restart));
	return ret;
}

int bch2_data_update_index_update(struct bch_write_op *op)
{
	CLASS(btree_trans, trans)(op->c);
	return __bch2_data_update_index_update(trans, op);
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
		u->op.end_io(&u->op);
		return;
	}

	if (u->opts.type == BCH_DATA_UPDATE_scrub && !u->opts.ptrs_io_error) {
		u->op.end_io(&u->op);
		return;
	}

	if (u->opts.ptrs_io_error) {
		struct bkey_s_c k = bkey_i_to_s_c(u->k.k);
		struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
		const union bch_extent_entry *entry;
		struct extent_ptr_decoded p;
		unsigned ptr_bit = 1;

		guard(rcu)();
		bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
			if ((u->opts.ptrs_io_error & ptr_bit) &&
			    !(u->opts.ptrs_rewrite & ptr_bit)) {
				u->op.nr_replicas += bch2_extent_ptr_durability(c, &p);
				u->opts.ptrs_rewrite |= ptr_bit;
				bch2_dev_list_drop_dev(&u->op.devs_have, p.ptr.dev);
			}

			ptr_bit <<= 1;
		}
	}

	/* write bio must own pages: */
	BUG_ON(!u->op.wbio.bio.bi_vcnt);

	u->op.crc = crc;
	u->op.wbio.bio.bi_iter.bi_size = crc.compressed_size << 9;

	closure_call(&u->op.cl, bch2_write, NULL, NULL);
}

static void data_update_trace(struct data_update *u, int ret)
{
	struct bch_fs *c = u->op.c;

	if (!ret) {
		if (trace_data_update_enabled()) {
			CLASS(printbuf, buf)();
			bch2_data_update_to_text(&buf, u);
			trace_data_update(c, buf.buf);
		}
		count_event(c, data_update);
	} else if (bch2_err_matches(ret, BCH_ERR_data_update_done)) {
		if (trace_data_update_no_io_enabled()) {
			CLASS(printbuf, buf)();
			bch2_data_update_to_text(&buf, u);
			prt_printf(&buf, "\nret:\t%s\n", bch2_err_str(ret));
			trace_data_update_no_io(c, buf.buf);
		}
		count_event(c, data_update_no_io);
	} else if (ret != -BCH_ERR_data_update_fail_no_rw_devs) {
		if (trace_data_update_fail_enabled()) {
			CLASS(printbuf, buf)();
			bch2_data_update_to_text(&buf, u);
			prt_printf(&buf, "\nret:\t%s\n", bch2_err_str(ret));
			trace_data_update_fail(c, buf.buf);
		}

		count_event(c, data_update_fail);
	}
}

void bch2_data_update_exit(struct data_update *update, int ret)
{
	data_update_trace(update, ret);

	struct bch_fs *c = update->op.c;
	struct bkey_s_c k = bkey_i_to_s_c(update->k.k);

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
		bch2_bkey_nocow_unlock(c, k, 0);
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
	struct closure cl;
	struct bkey_s_c k;
	int ret = 0;

	closure_init_stack(&cl);
	bch2_keylist_init(&update->op.insert_keys, update->op.inline_keys);

	while (bpos_lt(update->op.pos, update->k.k->k.p)) {
		unsigned sectors = update->k.k->k.p.offset -
			update->op.pos.offset;

		bch2_trans_begin(trans);

		{
			CLASS(btree_iter, iter)(trans, update->btree_id, update->op.pos,
						BTREE_ITER_slots);
			ret = lockrestart_do(trans, bkey_err(k = bch2_btree_iter_peek_slot(&iter)));
			if (ret || !bch2_extents_match(k, bkey_i_to_s_c(update->k.k)))
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

static void ptr_bits_to_text(struct printbuf *out, unsigned ptrs, const char *name)
{
	if (ptrs) {
		prt_printf(out, "%s ptrs:\t", name);
		bch2_prt_u64_base2(out, ptrs);
		prt_newline(out);
	}
}

void bch2_data_update_opts_to_text(struct printbuf *out, struct bch_fs *c,
				   struct bch_inode_opts *io_opts,
				   struct data_update_opts *data_opts)
{
	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 20);

	prt_str(out, bch2_data_update_type_strs[data_opts->type]);
	prt_newline(out);

	ptr_bits_to_text(out, data_opts->ptrs_rewrite,	"rewrite");
	ptr_bits_to_text(out, data_opts->ptrs_io_error,	"io error");
	ptr_bits_to_text(out, data_opts->ptrs_kill,	"kill");
	ptr_bits_to_text(out, data_opts->ptrs_kill_ec,	"kill ec");

	prt_str_indented(out, "target:\t");
	bch2_target_to_text(out, c, data_opts->target);
	prt_newline(out);

	prt_str_indented(out, "compression:\t");
	bch2_compression_opt_to_text(out, io_opts->background_compression);
	prt_newline(out);

	prt_str_indented(out, "opts.replicas:\t");
	prt_u64(out, io_opts->data_replicas);
	prt_newline(out);

	prt_str_indented(out, "extra replicas:\t");
	prt_u64(out, data_opts->extra_replicas);
	prt_newline(out);
}

void bch2_data_update_to_text(struct printbuf *out, struct data_update *m)
{
	bch2_data_update_opts_to_text(out, m->op.c, &m->op.opts, &m->opts);
	prt_newline(out);

	prt_str_indented(out, "old key:\t");
	bch2_bkey_val_to_text(out, m->op.c, bkey_i_to_s_c(m->k.k));

	bch2_write_op_to_text(out, &m->op);
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
		bch2_write_op_to_text(out, &m->op);
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

	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p = {};
	unsigned i = 0;
	bkey_for_each_ptr_decode(k.k, bch2_bkey_ptrs_c(k), p, entry) {
		if (data_opts->ptrs_kill_ec & BIT(i))
			bch2_bkey_drop_ec(n, p.ptr.dev);
		i++;
	}

	while (data_opts->ptrs_kill) {
		unsigned i = 0, drop = __fls(data_opts->ptrs_kill);

		bch2_bkey_drop_ptrs_noerror(bkey_i_to_s(n), p, entry, i++ == drop);
		data_opts->ptrs_kill ^= 1U << drop;
	}

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

static int can_write_extent(struct bch_fs *c, struct data_update *m)
{
	if ((m->op.flags & BCH_WRITE_alloc_nowait) &&
	    unlikely(c->open_buckets_nr_free <= bch2_open_buckets_reserved(m->op.watermark)))
		return bch_err_throw(c, data_update_fail_would_block);

	unsigned target = m->op.flags & BCH_WRITE_only_specified_devs
		? m->op.target
		: 0;
	struct bch_devs_mask devs = target_rw_devs(c, BCH_DATA_user, target);

	darray_for_each(m->op.devs_have, i)
		if (*i != BCH_SB_MEMBER_INVALID)
			__clear_bit(*i, devs.d);

	bool trace = trace_data_update_fail_enabled();
	CLASS(printbuf, buf)();

	guard(printbuf_atomic)(&buf);
	guard(rcu)();

	unsigned nr_replicas = 0, i;
	for_each_set_bit(i, devs.d, BCH_SB_MEMBERS_MAX) {
		struct bch_dev *ca = bch2_dev_rcu_noerror(c, i);
		if (!ca)
			continue;

		struct bch_dev_usage usage;
		bch2_dev_usage_read_fast(ca, &usage);

		u64 nr_free = dev_buckets_free(ca, usage, m->op.watermark);

		if (trace)
			prt_printf(&buf, "%s=%llu ", ca->name, nr_free);

		if (!nr_free)
			continue;

		nr_replicas += ca->mi.durability;
		if (nr_replicas >= m->op.nr_replicas)
			break;
	}

	if (!nr_replicas) {
		/*
		 * If it's a promote that's failing because the promote target
		 * is full - we expect that in normal operation; it'll still
		 * show up in io_read_nopromote and error_throw:
		 */
		if (m->opts.type != BCH_DATA_UPDATE_promote) {
			if (trace) {
				prt_printf(&buf, " - got replicas %u\n", nr_replicas);
				bch2_data_update_to_text(&buf, m);
				prt_printf(&buf, "\nret:\t%s\n", bch2_err_str(-BCH_ERR_data_update_fail_no_rw_devs));
				trace_data_update_fail(c, buf.buf);
			}
			count_event(c, data_update_fail);
		}

		return bch_err_throw(c, data_update_fail_no_rw_devs);
	}

	return 0;
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
	m->op.watermark		= m->opts.commit_flags & BCH_WATERMARK_MASK;

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

	unsigned durability_have = 0, durability_removing = 0;

	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(bkey_i_to_s_c(m->k.k));
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	unsigned reserve_sectors = k.k->size * data_opts.extra_replicas;
	unsigned buf_bytes = 0;
	bool unwritten = false;

	scoped_guard(rcu) {
		unsigned ptr_bit = 1;
		bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
			if (!p.ptr.cached) {
				if (ptr_bit & m->opts.ptrs_rewrite) {
					if (crc_is_compressed(p.crc))
						reserve_sectors += k.k->size;

					m->op.nr_replicas += bch2_extent_ptr_desired_durability(c, &p);
					durability_removing += bch2_extent_ptr_desired_durability(c, &p);
				} else if (!(ptr_bit & m->opts.ptrs_kill)) {
					bch2_dev_list_add_dev(&m->op.devs_have, p.ptr.dev);
					durability_have += bch2_extent_ptr_durability(c, &p);
				}
			} else {
				if (m->opts.ptrs_rewrite & ptr_bit) {
					m->opts.ptrs_kill |= ptr_bit;
					m->opts.ptrs_rewrite ^= ptr_bit;
				}
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
	}

	if (m->opts.type != BCH_DATA_UPDATE_scrub) {
		unsigned durability_required = max(0, (int) (io_opts->data_replicas - durability_have));

		/*
		 * If current extent durability is less than io_opts.data_replicas,
		 * we're not trying to rereplicate the extent up to data_alloc/replicas.here -
		 * unless extra_replicas was specified
		 *
		 * Increasing replication is an explicit operation triggered by
		 * rereplicate, currently, so that users don't get an unexpected -ENOSPC
		 */
		m->op.nr_replicas = min(durability_removing, durability_required) +
			m->opts.extra_replicas;

		/*
		 * If device(s) were set to durability=0 after data was written to them
		 * we can end up with a duribilty=0 extent, and the normal algorithm
		 * that tries not to increase durability doesn't work:
		 */
		if (!(durability_have + durability_removing))
			m->op.nr_replicas = max((unsigned) m->op.nr_replicas, 1);

		m->op.nr_replicas_required = m->op.nr_replicas;

		/*
		 * It might turn out that we don't need any new replicas, if the
		 * replicas or durability settings have been changed since the extent
		 * was written:
		 */
		if (!m->op.nr_replicas) {
			m->opts.ptrs_kill |= m->opts.ptrs_rewrite;
			m->opts.ptrs_rewrite = 0;
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
		ret = can_write_extent(c, m);
		if (ret)
			goto out;

		if (reserve_sectors) {
			ret = bch2_disk_reservation_add(c, &m->op.res, reserve_sectors,
					m->opts.extra_replicas
					? 0
					: BCH_DISK_RESERVATION_NOFAIL);
			if (ret)
				goto out;
		}
	} else {
		if (unwritten) {
			ret = bch_err_throw(c, data_update_done_unwritten);
			goto out;
		}
	}

	m->ptrs_held = bkey_get_dev_refs(c, k);

	if (c->opts.nocow_enabled) {
		if (!bch2_bkey_nocow_trylock(c, ptrs, 0)) {
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
					(locked = bch2_bkey_nocow_trylock(c, ptrs, 0)) ||
					list_empty(&ctxt->ios));
			if (!locked) {
				if (ctxt)
					bch2_trans_unlock(ctxt->trans);
				bch2_bkey_nocow_lock(c, ptrs, 0);
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
	return 0;
out_nocow_unlock:
	if (c->opts.nocow_enabled)
		bch2_bkey_nocow_unlock(c, k, 0);
out:
	BUG_ON(!ret);

	data_update_trace(m, ret);

	bkey_put_dev_refs(c, k, m->ptrs_held);
	m->ptrs_held = 0;
	bch2_disk_reservation_put(c, &m->op.res);
	bch2_bkey_buf_exit(&m->k);

	return ret;
}
