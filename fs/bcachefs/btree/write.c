// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "btree/interior.h"
#include "btree/read.h"
#include "btree/sort.h"
#include "btree/write.h"

#include "data/reconcile.h"
#include "data/write.h"

#include "debug/async_objs.h"
#include "debug/debug.h"

#include "init/dev.h"
#include "init/error.h"
#include "init/fs.h"

#include "sb/counters.h"

#include "journal/reclaim.h"

static void bch2_btree_complete_write(struct bch_fs *c, struct btree *b,
				      struct btree_write *w)
{
	unsigned long old, new;

	old = READ_ONCE(b->will_make_reachable);
	do {
		new = old;
		if (!(old & 1))
			break;

		new &= ~1UL;
	} while (!try_cmpxchg(&b->will_make_reachable, &old, new));

	if (old & 1)
		closure_put(&((struct btree_update *) new)->cl);

	bch2_journal_pin_drop(&c->journal, &w->journal);
}

static void __btree_node_write_done(struct bch_fs *c, struct btree *b, u64 start_time)
{
	struct btree_write *w = btree_prev_write(b);
	unsigned long old, new;
	unsigned type = 0;

	bch2_btree_complete_write(c, b, w);

	if (start_time)
		bch2_time_stats_update(&c->times[BCH_TIME_btree_node_write], start_time);

	old = READ_ONCE(b->flags);
	do {
		new = old;

		if ((old & (1U << BTREE_NODE_dirty)) &&
		    (old & (1U << BTREE_NODE_need_write)) &&
		    !(old & (1U << BTREE_NODE_never_write)) &&
		    !(old & (1U << BTREE_NODE_write_blocked)) &&
		    !(old & (1U << BTREE_NODE_will_make_reachable))) {
			new &= ~(1U << BTREE_NODE_dirty);
			new &= ~(1U << BTREE_NODE_need_write);
			new |=  (1U << BTREE_NODE_write_in_flight);
			new |=  (1U << BTREE_NODE_write_in_flight_inner);
			new |=  (1U << BTREE_NODE_just_written);
			new ^=  (1U << BTREE_NODE_write_idx);

			type = new & BTREE_WRITE_TYPE_MASK;
			new &= ~BTREE_WRITE_TYPE_MASK;
		} else {
			new &= ~(1U << BTREE_NODE_write_in_flight);
			new &= ~(1U << BTREE_NODE_write_in_flight_inner);
		}
	} while (!try_cmpxchg(&b->flags, &old, new));

	if (new & (1U << BTREE_NODE_write_in_flight))
		__bch2_btree_node_write(c, b, BTREE_WRITE_ALREADY_STARTED|type);
	else {
		smp_mb__after_atomic();
		wake_up_bit(&b->flags, BTREE_NODE_write_in_flight);
	}
}

static void btree_node_write_done(struct bch_fs *c, struct btree *b, u64 start_time)
{
	struct btree_trans *trans = bch2_trans_get(c);

	btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_read);

	/* we don't need transaction context anymore after we got the lock. */
	bch2_trans_put(trans);
	__btree_node_write_done(c, b, start_time);
	six_unlock_read(&b->c.lock);
}

static int btree_node_write_update_key(struct btree_trans *trans,
				       struct btree_write_bio *wbio, struct btree *b)
{
	struct bch_fs *c = trans->c;

	CLASS(btree_iter_uninit, iter)(trans);
	int ret = bch2_btree_node_get_iter(trans, &iter, b);
	if (ret)
		return ret == -BCH_ERR_btree_node_dying ? 0 : ret;

	struct bkey_i *n = errptr_try(bch2_trans_kmalloc(trans, bkey_bytes(&b->key.k) +
					      sizeof(struct bch_extent_reconcile) +
					      sizeof(struct bch_extent_ptr) * BCH_REPLICAS_MAX));
	bkey_copy(n, &b->key);

	bkey_i_to_btree_ptr_v2(n)->v.sectors_written =
		bkey_i_to_btree_ptr_v2(&wbio->key)->v.sectors_written;

	bch2_bkey_drop_ptrs(bkey_i_to_s(n), p, entry,
		bch2_dev_io_failures(&wbio->wbio.failed, p.ptr.dev));

	if (!bch2_bkey_nr_dirty_ptrs(c, bkey_i_to_s_c(n)))
		return bch_err_throw(c, btree_node_write_all_failed);

	if (wbio->wbio.failed.nr) {
		struct bch_inode_opts opts;
		try(bch2_bkey_get_io_opts(trans, NULL, bkey_i_to_s_c(n), &opts));
		try(bch2_bkey_set_needs_reconcile(trans, NULL, &opts, n,
						  SET_NEEDS_REBALANCE_opt_change, 0));
	}

	return bch2_btree_node_update_key(trans, &iter, b, n,
					  BCH_WATERMARK_interior_updates|
					  BCH_TRANS_COMMIT_journal_reclaim|
					  BCH_TRANS_COMMIT_no_enospc|
					  BCH_TRANS_COMMIT_no_check_rw,
					  !wbio->wbio.failed.nr);
}

static void btree_node_write_work(struct work_struct *work)
{
	struct btree_write_bio *wbio =
		container_of(work, struct btree_write_bio, work);
	struct bch_fs *c	= wbio->wbio.c;
	struct btree *b		= wbio->wbio.bio.bi_private;
	u64 start_time		= wbio->start_time;

	bch2_btree_bounce_free(c,
		wbio->data_bytes,
		wbio->wbio.used_mempool,
		wbio->data);

	if (!wbio->wbio.first_btree_write || wbio->wbio.failed.nr) {
		int ret = bch2_trans_do(c, btree_node_write_update_key(trans, wbio, b));
		if (ret)
			set_btree_node_noevict(b);

		if ((ret && !bch2_err_matches(ret, EROFS)) ||
		    wbio->wbio.failed.nr) {
			CLASS(bch_log_msg, msg)(c);

			/* Separate ratelimit_states for hard and soft errors */
			msg.m.suppress = !ret
				? bch2_ratelimit(c)
				: bch2_ratelimit(c);

			prt_printf(&msg.m, "error writing btree node at ");
			bch2_btree_pos_to_text(&msg.m, c, b);
			prt_newline(&msg.m);

			bch2_io_failures_to_text(&msg.m, c, &wbio->wbio.failed);

			if (!ret) {
				prt_printf(&msg.m, "wrote degraded to ");
				struct bch_devs_list d = bch2_bkey_devs(c, bkey_i_to_s_c(&b->key));
				bch2_devs_list_to_text(&msg.m, c, &d);
				prt_newline(&msg.m);
			} else {
				prt_printf(&msg.m, "error %s\n", bch2_err_str(ret));
				bch2_fs_emergency_read_only(c, &msg.m);
			}
		}
	}

	async_object_list_del(c, btree_write_bio, wbio->list_idx);
	bio_put(&wbio->wbio.bio);
	btree_node_write_done(c, b, start_time);
}

static void btree_node_write_endio(struct bio *bio)
{
	struct bch_write_bio *wbio	= to_wbio(bio);
	struct bch_write_bio *parent	= wbio->split ? wbio->parent : NULL;
	struct bch_write_bio *orig	= parent ?: wbio;
	struct btree_write_bio *wb	= container_of(orig, struct btree_write_bio, wbio);
	struct bch_fs *c		= wbio->c;
	struct btree *b			= wbio->bio.bi_private;
	struct bch_dev *ca		= wbio->have_ioref ? bch2_dev_have_ref(c, wbio->dev) : NULL;

	/* XXX: ca can be null, stash dev_idx */

	bch2_account_io_completion(ca, BCH_MEMBER_ERROR_write,
				   wbio->submit_time, !bio->bi_status);

	if (unlikely(bio->bi_status)) {
		guard(spinlock_irqsave)(&c->write_error_lock);
		bch2_dev_io_failures_mut(&orig->failed, wbio->dev)->errcode =
			__bch2_err_throw(c, -blk_status_to_bch_err(bio->bi_status));
	}

	/*
	 * XXX: we should be using io_ref[WRITE], but we aren't retrying failed
	 * btree writes yet (due to device removal/ro):
	 */
	if (wbio->have_ioref)
		enumerated_ref_put(&ca->io_ref[READ],
				   BCH_DEV_READ_REF_btree_node_write);

	if (parent) {
		bio_put(bio);
		bio_endio(&parent->bio);
		return;
	}

	clear_btree_node_write_in_flight_inner(b);
	smp_mb__after_atomic();
	wake_up_bit(&b->flags, BTREE_NODE_write_in_flight_inner);
	INIT_WORK(&wb->work, btree_node_write_work);
	queue_work(c->btree.write_complete_wq, &wb->work);
}

static int validate_bset_for_write(struct bch_fs *c, struct btree *b,
				   struct bset *i)
{
	int ret = bch2_bkey_validate(c, bkey_i_to_s_c(&b->key),
				     (struct bkey_validate_context) {
					.from	= BKEY_VALIDATE_btree_node,
					.level	= b->c.level + 1,
					.btree	= b->c.btree_id,
					.flags	= BCH_VALIDATE_write,
				     });
	if (ret) {
		bch2_fs_inconsistent(c, "invalid btree node key before write");
		return ret;
	}

	ret = bch2_validate_bset_keys(c, NULL, b, i, WRITE, NULL, NULL) ?:
		bch2_validate_bset(c, NULL, b, i, b->written, WRITE, NULL, NULL);
	if (ret) {
		bch2_inconsistent_error(c);
		dump_stack();
	}

	return ret;
}

static void btree_write_submit(struct work_struct *work)
{
	struct btree_write_bio *wbio = container_of(work, struct btree_write_bio, work);
	struct bch_fs *c	= wbio->wbio.c;
	BKEY_PADDED_ONSTACK(k, BKEY_BTREE_PTR_VAL_U64s_MAX) tmp;

	bkey_copy(&tmp.k, &wbio->key);

	bkey_for_each_ptr(bch2_bkey_ptrs(bkey_i_to_s(&tmp.k)), ptr)
		ptr->offset += wbio->sector_offset;

	bch2_submit_wbio_replicas(&wbio->wbio, wbio->wbio.c, BCH_DATA_btree,
				  &tmp.k, false);
}

void __bch2_btree_node_write(struct bch_fs *c, struct btree *b, unsigned flags)
{
	struct btree_write_bio *wbio;
	struct bset *i;
	struct btree_node *bn = NULL;
	struct btree_node_entry *bne = NULL;
	struct sort_iter_stack sort_iter;
	struct nonce nonce;
	unsigned bytes_to_write, sectors_to_write, bytes, u64s;
	u64 seq = 0;
	bool used_mempool;
	unsigned long old, new;
	bool validate_before_checksum = false;
	enum btree_write_type type = flags & BTREE_WRITE_TYPE_MASK;
	void *data;
	u64 start_time = local_clock();
	int ret;

	if (flags & BTREE_WRITE_ALREADY_STARTED)
		goto do_write;

	/*
	 * We may only have a read lock on the btree node - the dirty bit is our
	 * "lock" against racing with other threads that may be trying to start
	 * a write, we do a write iff we clear the dirty bit. Since setting the
	 * dirty bit requires a write lock, we can't race with other threads
	 * redirtying it:
	 */
	old = READ_ONCE(b->flags);
	do {
		new = old;

		if (!(old & (1 << BTREE_NODE_dirty)))
			return;

		if ((flags & BTREE_WRITE_ONLY_IF_NEED) &&
		    !(old & (1 << BTREE_NODE_need_write)))
			return;

		if (old &
		    ((1 << BTREE_NODE_never_write)|
		     (1 << BTREE_NODE_write_blocked)))
			return;

		if (b->written &&
		    (old & (1 << BTREE_NODE_will_make_reachable)))
			return;

		if (old & (1 << BTREE_NODE_write_in_flight))
			return;

		if (flags & BTREE_WRITE_ONLY_IF_NEED)
			type = new & BTREE_WRITE_TYPE_MASK;
		new &= ~BTREE_WRITE_TYPE_MASK;

		new &= ~(1 << BTREE_NODE_dirty);
		new &= ~(1 << BTREE_NODE_need_write);
		new |=  (1 << BTREE_NODE_write_in_flight);
		new |=  (1 << BTREE_NODE_write_in_flight_inner);
		new |=  (1 << BTREE_NODE_just_written);
		new ^=  (1 << BTREE_NODE_write_idx);
	} while (!try_cmpxchg_acquire(&b->flags, &old, new));

	if (new & (1U << BTREE_NODE_need_write))
		return;
do_write:
	BUG_ON((type == BTREE_WRITE_initial) != (b->written == 0));

	atomic_long_dec(&c->btree.cache.nr_dirty);

	BUG_ON(btree_node_fake(b));
	BUG_ON((b->will_make_reachable != 0) != !b->written);

	BUG_ON(b->written >= btree_sectors(c));
	BUG_ON(b->written & (block_sectors(c) - 1));
	BUG_ON(bset_written(b, btree_bset_last(b)));
	BUG_ON(le64_to_cpu(b->data->magic) != bset_magic(c));
	BUG_ON(memcmp(&b->data->format, &b->format, sizeof(b->format)));

	bch2_sort_whiteouts(c, b);

	sort_iter_stack_init(&sort_iter, b);

	bytes = !b->written
		? sizeof(struct btree_node)
		: sizeof(struct btree_node_entry);

	bytes += b->whiteout_u64s * sizeof(u64);

	for_each_bset(b, t) {
		i = bset(b, t);

		if (bset_written(b, i))
			continue;

		bytes += le16_to_cpu(i->u64s) * sizeof(u64);
		sort_iter_add(&sort_iter.iter,
			      btree_bkey_first(b, t),
			      btree_bkey_last(b, t));
		seq = max(seq, le64_to_cpu(i->journal_seq));
	}

	BUG_ON(b->written && !seq);

	/* bch2_varint_decode may read up to 7 bytes past the end of the buffer: */
	bytes += 8;

	/* buffer must be a multiple of the block size */
	bytes = round_up(bytes, block_bytes(c));

	data = bch2_btree_bounce_alloc(c, bytes, &used_mempool);

	if (!b->written) {
		bn = data;
		*bn = *b->data;
		i = &bn->keys;
	} else {
		bne = data;
		bne->keys = b->data->keys;
		i = &bne->keys;
	}

	i->journal_seq	= cpu_to_le64(seq);
	i->u64s		= 0;

	sort_iter_add(&sort_iter.iter,
		      unwritten_whiteouts_start(b),
		      unwritten_whiteouts_end(b));
	SET_BSET_SEPARATE_WHITEOUTS(i, false);

	u64s = bch2_sort_keys_keep_unwritten_whiteouts(i->start, &sort_iter.iter);
	le16_add_cpu(&i->u64s, u64s);

	b->whiteout_u64s = 0;

	BUG_ON(!b->written && i->u64s != b->data->keys.u64s);

	bch2_set_bset_needs_whiteout(i, false);

	/* do we have data to write? */
	if (b->written && !i->u64s)
		goto nowrite;

	bytes_to_write = vstruct_end(i) - data;
	sectors_to_write = round_up(bytes_to_write, block_bytes(c)) >> 9;

	if (!b->written &&
	    b->key.k.type == KEY_TYPE_btree_ptr_v2)
		BUG_ON(btree_ptr_sectors_written(bkey_i_to_s_c(&b->key)) != sectors_to_write);

	memset(data + bytes_to_write, 0,
	       (sectors_to_write << 9) - bytes_to_write);

	BUG_ON(b->written + sectors_to_write > btree_sectors(c));
	BUG_ON(BSET_BIG_ENDIAN(i) != CPU_BIG_ENDIAN);
	BUG_ON(i->seq != b->data->keys.seq);

	i->version = cpu_to_le16(c->sb.version);
	SET_BSET_OFFSET(i, b->written);
	SET_BSET_CSUM_TYPE(i, bch2_meta_checksum_type(c));

	if (bch2_csum_type_is_encryption(BSET_CSUM_TYPE(i)))
		validate_before_checksum = true;

	/* bch2_validate_bset will be modifying: */
	if (le16_to_cpu(i->version) < bcachefs_metadata_version_current)
		validate_before_checksum = true;

	/* if we're going to be encrypting, check metadata validity first: */
	if (validate_before_checksum &&
	    validate_bset_for_write(c, b, i))
		goto err;

	ret = bset_encrypt(c, i, b->written << 9);
	if (bch2_fs_fatal_err_on(ret, c,
			"encrypting btree node: %s", bch2_err_str(ret)))
		goto err;

	nonce = btree_nonce(i, b->written << 9);

	if (bn)
		bn->csum = csum_vstruct(c, BSET_CSUM_TYPE(i), nonce, bn);
	else
		bne->csum = csum_vstruct(c, BSET_CSUM_TYPE(i), nonce, bne);

	/* if we're not encrypting, check metadata after checksumming: */
	if (!validate_before_checksum &&
	    validate_bset_for_write(c, b, i))
		goto err;

	/*
	 * We handle btree write errors by immediately halting the journal -
	 * after we've done that, we can't issue any subsequent btree writes
	 * because they might have pointers to new nodes that failed to write.
	 *
	 * Furthermore, there's no point in doing any more btree writes because
	 * with the journal stopped, we're never going to update the journal to
	 * reflect that those writes were done and the data flushed from the
	 * journal:
	 *
	 * Also on journal error, the pending write may have updates that were
	 * never journalled (interior nodes, see btree_update_nodes_written()) -
	 * it's critical that we don't do the write in that case otherwise we
	 * will have updates visible that weren't in the journal:
	 *
	 * Make sure to update b->written so bch2_btree_init_next() doesn't
	 * break:
	 */
	if (bch2_journal_error(&c->journal) ||
	    c->opts.nochanges)
		goto err;

	event_inc_trace(c, btree_node_write, buf, ({
		prt_printf(&buf, "offset %u sectors %u bytes %u\n",
			   b->written,
			   sectors_to_write,
			   bytes_to_write);
		bch2_btree_pos_to_text(&buf, c, b);
	}));

	/*
	 * blk-wbt.c throttles all writes except those that have both REQ_SYNC
	 * and REQ_IDLE set...
	 */

	wbio = container_of(bio_alloc_bioset(NULL,
				buf_pages(data, sectors_to_write << 9),
				REQ_OP_WRITE|REQ_META|REQ_SYNC|REQ_IDLE,
				GFP_NOFS,
				&c->btree.bio),
			    struct btree_write_bio, wbio.bio);
	wbio_init(&wbio->wbio.bio);
	wbio->data			= data;
	wbio->data_bytes		= bytes;
	wbio->sector_offset		= b->written;
	wbio->start_time		= start_time;
	wbio->wbio.c			= c;
	wbio->wbio.used_mempool		= used_mempool;
	wbio->wbio.first_btree_write	= !b->written;
	wbio->wbio.bio.bi_end_io	= btree_node_write_endio;
	wbio->wbio.bio.bi_private	= b;

	bch2_bio_map(&wbio->wbio.bio, data, sectors_to_write << 9);

	bkey_copy(&wbio->key, &b->key);

	b->written += sectors_to_write;

	if (wbio->key.k.type == KEY_TYPE_btree_ptr_v2)
		bkey_i_to_btree_ptr_v2(&wbio->key)->v.sectors_written =
			cpu_to_le16(b->written);

	atomic64_inc(&c->btree.write_stats[type].nr);
	atomic64_add(bytes_to_write, &c->btree.write_stats[type].bytes);

	async_object_list_add(c, btree_write_bio, wbio, &wbio->list_idx);

	INIT_WORK(&wbio->work, btree_write_submit);
	queue_work(c->btree.write_submit_wq, &wbio->work);
	return;
err:
	set_btree_node_noevict(b);
	b->written += sectors_to_write;
nowrite:
	bch2_btree_bounce_free(c, bytes, used_mempool, data);
	__btree_node_write_done(c, b, 0);
}

/*
 * Work that must be done with write lock held:
 */
bool bch2_btree_post_write_cleanup(struct bch_fs *c, struct btree *b)
{
	bool invalidated_iter = false;
	struct btree_node_entry *bne;

	if (!btree_node_just_written(b))
		return false;

	BUG_ON(b->whiteout_u64s);

	clear_btree_node_just_written(b);

	/*
	 * Note: immediately after write, bset_written() doesn't work - the
	 * amount of data we had to write after compaction might have been
	 * smaller than the offset of the last bset.
	 *
	 * However, we know that all bsets have been written here, as long as
	 * we're still holding the write lock:
	 */

	/*
	 * XXX: decide if we really want to unconditionally sort down to a
	 * single bset:
	 */
	if (b->nsets > 1) {
		bch2_btree_node_sort(c, b, 0, b->nsets);
		invalidated_iter = true;
	} else {
		invalidated_iter = bch2_drop_whiteouts(b, COMPACT_ALL);
	}

	for_each_bset(b, t)
		bch2_set_bset_needs_whiteout(bset(b, t), true);

	bch2_btree_verify(c, b);

	/*
	 * If later we don't unconditionally sort down to a single bset, we have
	 * to ensure this is still true:
	 */
	BUG_ON((void *) btree_bkey_last(b, bset_tree_last(b)) > write_block(b));

	bne = want_new_bset(c, b);
	if (bne)
		bch2_bset_init_next(b, bne);

	bch2_btree_build_aux_trees(b);

	return invalidated_iter;
}

/*
 * Use this one if the node is intent locked:
 */
void bch2_btree_node_write(struct bch_fs *c, struct btree *b,
			   enum six_lock_type lock_type_held,
			   unsigned flags)
{
	if (lock_type_held == SIX_LOCK_intent ||
	    (lock_type_held == SIX_LOCK_read &&
	     six_lock_tryupgrade(&b->c.lock))) {
		__bch2_btree_node_write(c, b, flags);

		/* don't cycle lock unnecessarily: */
		if (btree_node_just_written(b) &&
		    six_trylock_write(&b->c.lock)) {
			bch2_btree_post_write_cleanup(c, b);
			six_unlock_write(&b->c.lock);
		}

		if (lock_type_held == SIX_LOCK_read)
			six_lock_downgrade(&b->c.lock);
	} else {
		__bch2_btree_node_write(c, b, flags);
		if (lock_type_held == SIX_LOCK_write &&
		    btree_node_just_written(b))
			bch2_btree_post_write_cleanup(c, b);
	}
}

void bch2_btree_node_write_trans(struct btree_trans *trans, struct btree *b,
				 enum six_lock_type lock_type_held,
				 unsigned flags)
{
	struct bch_fs *c = trans->c;

	if (lock_type_held == SIX_LOCK_intent ||
	    (lock_type_held == SIX_LOCK_read &&
	     six_lock_tryupgrade(&b->c.lock))) {
		__bch2_btree_node_write(c, b, flags);

		/* don't cycle lock unnecessarily: */
		if (btree_node_just_written(b) &&
		    six_trylock_write(&b->c.lock)) {
			bch2_btree_post_write_cleanup(c, b);
			__bch2_btree_node_unlock_write(trans, b);
		}

		if (lock_type_held == SIX_LOCK_read)
			six_lock_downgrade(&b->c.lock);
	} else {
		__bch2_btree_node_write(c, b, flags);
		if (lock_type_held == SIX_LOCK_write &&
		    btree_node_just_written(b))
			bch2_btree_post_write_cleanup(c, b);
	}
}

/*
 * @bch_btree_init_next - initialize a new (unwritten) bset that can then be
 * inserted into
 *
 * Safe to call if there already is an unwritten bset - will only add a new bset
 * if @b doesn't already have one.
 *
 * Returns true if we sorted (i.e. invalidated iterators
 */
void bch2_btree_init_next(struct btree_trans *trans, struct btree *b)
{
	struct bch_fs *c = trans->c;
	struct btree_node_entry *bne;
	bool reinit_iter = false;

	EBUG_ON(!six_lock_counts(&b->c.lock).n[SIX_LOCK_write]);
	BUG_ON(bset_written(b, bset(b, &b->set[1])));
	BUG_ON(btree_node_just_written(b));

	if (b->nsets == MAX_BSETS &&
	    !btree_node_write_in_flight(b) &&
	    should_compact_all(c, b)) {
		bch2_btree_node_write_trans(trans, b, SIX_LOCK_write,
					    BTREE_WRITE_init_next_bset);
		reinit_iter = true;
	}

	if (b->nsets == MAX_BSETS &&
	    bch2_btree_node_compact(c, b))
		reinit_iter = true;

	BUG_ON(b->nsets >= MAX_BSETS);

	bne = want_new_bset(c, b);
	if (bne)
		bch2_bset_init_next(b, bne);

	bch2_btree_build_aux_trees(b);

	if (reinit_iter)
		bch2_trans_node_reinit_iter(trans, b);
}

static bool __bch2_btree_flush_all(struct bch_fs *c, unsigned flag)
{
	struct bucket_table *tbl;
	struct rhash_head *pos;
	struct btree *b;
	unsigned i;
	bool ret = false;
restart:
	rcu_read_lock();
	for_each_cached_btree(b, c, tbl, i, pos)
		if (test_bit(flag, &b->flags)) {
			rcu_read_unlock();
			wait_on_bit_io(&b->flags, flag, TASK_UNINTERRUPTIBLE);
			ret = true;
			goto restart;
		}
	rcu_read_unlock();

	return ret;
}

bool bch2_btree_flush_all_reads(struct bch_fs *c)
{
	return __bch2_btree_flush_all(c, BTREE_NODE_read_in_flight);
}

bool bch2_btree_flush_all_writes(struct bch_fs *c)
{
	return __bch2_btree_flush_all(c, BTREE_NODE_write_in_flight);
}

static const char * const bch2_btree_write_types[] = {
#define x(t, n) [n] = #t,
	BCH_BTREE_WRITE_TYPES()
	NULL
};

void bch2_btree_write_stats_to_text(struct printbuf *out, struct bch_fs *c)
{
	printbuf_tabstop_push(out, 20);
	printbuf_tabstop_push(out, 10);

	prt_printf(out, "\tnr\tsize\n");

	for (unsigned i = 0; i < BTREE_WRITE_TYPE_NR; i++) {
		u64 nr		= atomic64_read(&c->btree.write_stats[i].nr);
		u64 bytes	= atomic64_read(&c->btree.write_stats[i].bytes);

		prt_printf(out, "%s:\t%llu\t", bch2_btree_write_types[i], nr);
		prt_human_readable_u64(out, nr ? div64_u64(bytes, nr) : 0);
		prt_newline(out);
	}
}
