// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "alloc_foreground.h"
#include "bkey_buf.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "disk_groups.h"
#include "ec.h"
#include "errcode.h"
#include "inode.h"
#include "io.h"
#include "journal_reclaim.h"
#include "keylist.h"
#include "move.h"
#include "replicas.h"
#include "super-io.h"
#include "trace.h"

#include <linux/ioprio.h>
#include <linux/kthread.h>

static void progress_list_add(struct bch_fs *c, struct bch_move_stats *stats)
{
	mutex_lock(&c->data_progress_lock);
	list_add(&stats->list, &c->data_progress_list);
	mutex_unlock(&c->data_progress_lock);
}

static void progress_list_del(struct bch_fs *c, struct bch_move_stats *stats)
{
	mutex_lock(&c->data_progress_lock);
	list_del(&stats->list);
	mutex_unlock(&c->data_progress_lock);
}

struct moving_io {
	struct list_head	list;
	struct closure		cl;
	bool			read_completed;

	unsigned		read_sectors;
	unsigned		write_sectors;

	struct bch_read_bio	rbio;

	struct data_update	write;
	/* Must be last since it is variable size */
	struct bio_vec		bi_inline_vecs[0];
};

static void move_free(struct moving_io *io)
{
	struct moving_context *ctxt = io->write.ctxt;
	struct bch_fs *c = ctxt->c;

	bch2_data_update_exit(&io->write);
	wake_up(&ctxt->wait);
	percpu_ref_put(&c->writes);
	kfree(io);
}

static void move_write_done(struct bch_write_op *op)
{
	struct moving_io *io = container_of(op, struct moving_io, write.op);
	struct moving_context *ctxt = io->write.ctxt;

	atomic_sub(io->write_sectors, &io->write.ctxt->write_sectors);
	move_free(io);
	closure_put(&ctxt->cl);
}

static void move_write(struct moving_io *io)
{
	if (unlikely(io->rbio.bio.bi_status || io->rbio.hole)) {
		move_free(io);
		return;
	}

	closure_get(&io->write.ctxt->cl);
	atomic_add(io->write_sectors, &io->write.ctxt->write_sectors);

	bch2_data_update_read_done(&io->write, io->rbio.pick.crc);
}

static inline struct moving_io *next_pending_write(struct moving_context *ctxt)
{
	struct moving_io *io =
		list_first_entry_or_null(&ctxt->reads, struct moving_io, list);

	return io && io->read_completed ? io : NULL;
}

static void move_read_endio(struct bio *bio)
{
	struct moving_io *io = container_of(bio, struct moving_io, rbio.bio);
	struct moving_context *ctxt = io->write.ctxt;

	atomic_sub(io->read_sectors, &ctxt->read_sectors);
	io->read_completed = true;

	wake_up(&ctxt->wait);
	closure_put(&ctxt->cl);
}

static void do_pending_writes(struct moving_context *ctxt, struct btree_trans *trans)
{
	struct moving_io *io;

	if (trans)
		bch2_trans_unlock(trans);

	while ((io = next_pending_write(ctxt))) {
		list_del(&io->list);
		move_write(io);
	}
}

#define move_ctxt_wait_event(_ctxt, _trans, _cond)		\
do {								\
	do_pending_writes(_ctxt, _trans);			\
								\
	if (_cond)						\
		break;						\
	__wait_event((_ctxt)->wait,				\
		     next_pending_write(_ctxt) || (_cond));	\
} while (1)

static void bch2_move_ctxt_wait_for_io(struct moving_context *ctxt,
				       struct btree_trans *trans)
{
	unsigned sectors_pending = atomic_read(&ctxt->write_sectors);

	move_ctxt_wait_event(ctxt, trans,
		!atomic_read(&ctxt->write_sectors) ||
		atomic_read(&ctxt->write_sectors) != sectors_pending);
}

void bch2_moving_ctxt_exit(struct moving_context *ctxt)
{
	move_ctxt_wait_event(ctxt, NULL, list_empty(&ctxt->reads));
	closure_sync(&ctxt->cl);
	EBUG_ON(atomic_read(&ctxt->write_sectors));

	if (ctxt->stats) {
		progress_list_del(ctxt->c, ctxt->stats);

		trace_move_data(ctxt->c,
				atomic64_read(&ctxt->stats->sectors_moved),
				atomic64_read(&ctxt->stats->keys_moved));
	}
}

void bch2_moving_ctxt_init(struct moving_context *ctxt,
			   struct bch_fs *c,
			   struct bch_ratelimit *rate,
			   struct bch_move_stats *stats,
			   struct write_point_specifier wp,
			   bool wait_on_copygc)
{
	memset(ctxt, 0, sizeof(*ctxt));

	ctxt->c		= c;
	ctxt->rate	= rate;
	ctxt->stats	= stats;
	ctxt->wp	= wp;
	ctxt->wait_on_copygc = wait_on_copygc;

	closure_init_stack(&ctxt->cl);
	INIT_LIST_HEAD(&ctxt->reads);
	init_waitqueue_head(&ctxt->wait);

	if (stats) {
		progress_list_add(c, stats);
		stats->data_type = BCH_DATA_user;
	}
}

void bch_move_stats_init(struct bch_move_stats *stats, char *name)
{
	memset(stats, 0, sizeof(*stats));
	scnprintf(stats->name, sizeof(stats->name), "%s", name);
}

static int bch2_extent_drop_ptrs(struct btree_trans *trans,
				 struct btree_iter *iter,
				 struct bkey_s_c k,
				 struct data_update_opts data_opts)
{
	struct bch_fs *c = trans->c;
	struct bkey_i *n;
	int ret;

	n = bch2_trans_kmalloc(trans, bkey_bytes(k.k));
	ret = PTR_ERR_OR_ZERO(n);
	if (ret)
		return ret;

	bkey_reassemble(n, k);

	while (data_opts.kill_ptrs) {
		unsigned i = 0, drop = __fls(data_opts.kill_ptrs);
		struct bch_extent_ptr *ptr;

		bch2_bkey_drop_ptrs(bkey_i_to_s(n), ptr, i++ == drop);
		data_opts.kill_ptrs ^= 1U << drop;
	}

	/*
	 * If the new extent no longer has any pointers, bch2_extent_normalize()
	 * will do the appropriate thing with it (turning it into a
	 * KEY_TYPE_error key, or just a discard if it was a cached extent)
	 */
	bch2_extent_normalize(c, bkey_i_to_s(n));

	/*
	 * Since we're not inserting through an extent iterator
	 * (BTREE_ITER_ALL_SNAPSHOTS iterators aren't extent iterators),
	 * we aren't using the extent overwrite path to delete, we're
	 * just using the normal key deletion path:
	 */
	if (bkey_deleted(&n->k))
		n->k.size = 0;

	return bch2_trans_update(trans, iter, n, BTREE_UPDATE_INTERNAL_SNAPSHOT_NODE) ?:
		bch2_trans_commit(trans, NULL, NULL, BTREE_INSERT_NOFAIL);
}

static int bch2_move_extent(struct btree_trans *trans,
			    struct btree_iter *iter,
			    struct moving_context *ctxt,
			    struct bch_io_opts io_opts,
			    enum btree_id btree_id,
			    struct bkey_s_c k,
			    struct data_update_opts data_opts)
{
	struct bch_fs *c = trans->c;
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	struct moving_io *io;
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;
	unsigned sectors = k.k->size, pages;
	int ret = -ENOMEM;

	bch2_data_update_opts_normalize(k, &data_opts);

	if (!data_opts.rewrite_ptrs &&
	    !data_opts.extra_replicas) {
		if (data_opts.kill_ptrs)
			return bch2_extent_drop_ptrs(trans, iter, k, data_opts);
		return 0;
	}

	if (!percpu_ref_tryget_live(&c->writes))
		return -EROFS;

	/* write path might have to decompress data: */
	bkey_for_each_ptr_decode(k.k, ptrs, p, entry)
		sectors = max_t(unsigned, sectors, p.crc.uncompressed_size);

	pages = DIV_ROUND_UP(sectors, PAGE_SECTORS);
	io = kzalloc(sizeof(struct moving_io) +
		     sizeof(struct bio_vec) * pages, GFP_KERNEL);
	if (!io)
		goto err;

	io->write.ctxt		= ctxt;
	io->read_sectors	= k.k->size;
	io->write_sectors	= k.k->size;

	bio_init(&io->write.op.wbio.bio, NULL, io->bi_inline_vecs, pages, 0);
	bio_set_prio(&io->write.op.wbio.bio,
		     IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	if (bch2_bio_alloc_pages(&io->write.op.wbio.bio, sectors << 9,
				 GFP_KERNEL))
		goto err_free;

	io->rbio.c		= c;
	io->rbio.opts		= io_opts;
	bio_init(&io->rbio.bio, NULL, io->bi_inline_vecs, pages, 0);
	io->rbio.bio.bi_vcnt = pages;
	bio_set_prio(&io->rbio.bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));
	io->rbio.bio.bi_iter.bi_size = sectors << 9;

	io->rbio.bio.bi_opf		= REQ_OP_READ;
	io->rbio.bio.bi_iter.bi_sector	= bkey_start_offset(k.k);
	io->rbio.bio.bi_end_io		= move_read_endio;

	ret = bch2_data_update_init(c, &io->write, ctxt->wp, io_opts,
				    data_opts, btree_id, k);
	if (ret)
		goto err_free_pages;

	io->write.ctxt = ctxt;
	io->write.op.end_io = move_write_done;

	atomic64_inc(&ctxt->stats->keys_moved);
	atomic64_add(k.k->size, &ctxt->stats->sectors_moved);
	this_cpu_add(c->counters[BCH_COUNTER_io_move], k.k->size);
	this_cpu_add(c->counters[BCH_COUNTER_move_extent_read], k.k->size);
	trace_move_extent_read(k.k);

	atomic_add(io->read_sectors, &ctxt->read_sectors);
	list_add_tail(&io->list, &ctxt->reads);

	/*
	 * dropped by move_read_endio() - guards against use after free of
	 * ctxt when doing wakeup
	 */
	closure_get(&ctxt->cl);
	bch2_read_extent(trans, &io->rbio,
			 bkey_start_pos(k.k),
			 btree_id, k, 0,
			 BCH_READ_NODECODE|
			 BCH_READ_LAST_FRAGMENT);
	return 0;
err_free_pages:
	bio_free_pages(&io->write.op.wbio.bio);
err_free:
	kfree(io);
err:
	percpu_ref_put(&c->writes);
	trace_and_count(c, move_extent_alloc_mem_fail, k.k);
	return ret;
}

static int lookup_inode(struct btree_trans *trans, struct bpos pos,
			struct bch_inode_unpacked *inode)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret;

	bch2_trans_iter_init(trans, &iter, BTREE_ID_inodes, pos,
			     BTREE_ITER_ALL_SNAPSHOTS);
	k = bch2_btree_iter_peek(&iter);
	ret = bkey_err(k);
	if (ret)
		goto err;

	if (!k.k || bkey_cmp(k.k->p, pos)) {
		ret = -ENOENT;
		goto err;
	}

	ret = bkey_is_inode(k.k) ? 0 : -EIO;
	if (ret)
		goto err;

	ret = bch2_inode_unpack(k, inode);
	if (ret)
		goto err;
err:
	bch2_trans_iter_exit(trans, &iter);
	return ret;
}

static int move_ratelimit(struct btree_trans *trans,
			  struct moving_context *ctxt)
{
	struct bch_fs *c = trans->c;
	u64 delay;

	if (ctxt->wait_on_copygc) {
		bch2_trans_unlock(trans);
		wait_event_killable(c->copygc_running_wq,
				    !c->copygc_running ||
				    kthread_should_stop());
	}

	do {
		delay = ctxt->rate ? bch2_ratelimit_delay(ctxt->rate) : 0;

		if (delay) {
			bch2_trans_unlock(trans);
			set_current_state(TASK_INTERRUPTIBLE);
		}

		if ((current->flags & PF_KTHREAD) && kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			return 1;
		}

		if (delay)
			schedule_timeout(delay);

		if (unlikely(freezing(current))) {
			move_ctxt_wait_event(ctxt, trans, list_empty(&ctxt->reads));
			try_to_freeze();
		}
	} while (delay);

	move_ctxt_wait_event(ctxt, trans,
		atomic_read(&ctxt->write_sectors) <
		c->opts.move_bytes_in_flight >> 9);

	move_ctxt_wait_event(ctxt, trans,
		atomic_read(&ctxt->read_sectors) <
		c->opts.move_bytes_in_flight >> 9);

	return 0;
}

static int __bch2_move_data(struct moving_context *ctxt,
			    struct bpos start,
			    struct bpos end,
			    move_pred_fn pred, void *arg,
			    enum btree_id btree_id)
{
	struct bch_fs *c = ctxt->c;
	struct bch_io_opts io_opts = bch2_opts_to_inode_opts(c->opts);
	struct bkey_buf sk;
	struct btree_trans trans;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct data_update_opts data_opts;
	u64 cur_inum = U64_MAX;
	int ret = 0, ret2;

	bch2_bkey_buf_init(&sk);
	bch2_trans_init(&trans, c, 0, 0);

	ctxt->stats->data_type	= BCH_DATA_user;
	ctxt->stats->btree_id	= btree_id;
	ctxt->stats->pos	= start;

	bch2_trans_iter_init(&trans, &iter, btree_id, start,
			     BTREE_ITER_PREFETCH|
			     BTREE_ITER_ALL_SNAPSHOTS);

	if (ctxt->rate)
		bch2_ratelimit_reset(ctxt->rate);

	while (!move_ratelimit(&trans, ctxt)) {
		bch2_trans_begin(&trans);

		k = bch2_btree_iter_peek(&iter);
		if (!k.k)
			break;

		ret = bkey_err(k);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ret)
			break;

		if (bkey_cmp(bkey_start_pos(k.k), end) >= 0)
			break;

		ctxt->stats->pos = iter.pos;

		if (!bkey_extent_is_direct_data(k.k))
			goto next_nondata;

		if (btree_id == BTREE_ID_extents &&
		    cur_inum != k.k->p.inode) {
			struct bch_inode_unpacked inode;

			io_opts = bch2_opts_to_inode_opts(c->opts);

			ret = lookup_inode(&trans,
					SPOS(0, k.k->p.inode, k.k->p.snapshot),
					&inode);
			if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
				continue;

			if (!ret)
				bch2_io_opts_apply(&io_opts, bch2_inode_opts_get(&inode));

			cur_inum = k.k->p.inode;
		}

		memset(&data_opts, 0, sizeof(data_opts));
		if (!pred(c, arg, k, &io_opts, &data_opts))
			goto next;

		/*
		 * The iterator gets unlocked by __bch2_read_extent - need to
		 * save a copy of @k elsewhere:
		  */
		bch2_bkey_buf_reassemble(&sk, c, k);
		k = bkey_i_to_s_c(sk.k);

		ret2 = bch2_move_extent(&trans, &iter, ctxt, io_opts,
					btree_id, k, data_opts);
		if (ret2) {
			if (bch2_err_matches(ret2, BCH_ERR_transaction_restart))
				continue;

			if (ret2 == -ENOMEM) {
				/* memory allocation failure, wait for some IO to finish */
				bch2_move_ctxt_wait_for_io(ctxt, &trans);
				continue;
			}

			/* XXX signal failure */
			goto next;
		}

		if (ctxt->rate)
			bch2_ratelimit_increment(ctxt->rate, k.k->size);
next:
		atomic64_add(k.k->size, &ctxt->stats->sectors_seen);
next_nondata:
		bch2_btree_iter_advance(&iter);
	}

	bch2_trans_iter_exit(&trans, &iter);
	bch2_trans_exit(&trans);
	bch2_bkey_buf_exit(&sk, c);

	return ret;
}

int bch2_move_data(struct bch_fs *c,
		   enum btree_id start_btree_id, struct bpos start_pos,
		   enum btree_id end_btree_id,   struct bpos end_pos,
		   struct bch_ratelimit *rate,
		   struct bch_move_stats *stats,
		   struct write_point_specifier wp,
		   bool wait_on_copygc,
		   move_pred_fn pred, void *arg)
{
	struct moving_context ctxt;
	enum btree_id id;
	int ret;

	bch2_moving_ctxt_init(&ctxt, c, rate, stats, wp, wait_on_copygc);

	for (id = start_btree_id;
	     id <= min_t(unsigned, end_btree_id, BTREE_ID_NR - 1);
	     id++) {
		stats->btree_id = id;

		if (id != BTREE_ID_extents &&
		    id != BTREE_ID_reflink)
			continue;

		ret = __bch2_move_data(&ctxt,
				       id == start_btree_id ? start_pos : POS_MIN,
				       id == end_btree_id   ? end_pos   : POS_MAX,
				       pred, arg, id);
		if (ret)
			break;
	}

	bch2_moving_ctxt_exit(&ctxt);

	return ret;
}

typedef bool (*move_btree_pred)(struct bch_fs *, void *,
				struct btree *, struct bch_io_opts *,
				struct data_update_opts *);

static int bch2_move_btree(struct bch_fs *c,
			   enum btree_id start_btree_id, struct bpos start_pos,
			   enum btree_id end_btree_id,   struct bpos end_pos,
			   move_btree_pred pred, void *arg,
			   struct bch_move_stats *stats)
{
	bool kthread = (current->flags & PF_KTHREAD) != 0;
	struct bch_io_opts io_opts = bch2_opts_to_inode_opts(c->opts);
	struct btree_trans trans;
	struct btree_iter iter;
	struct btree *b;
	enum btree_id id;
	struct data_update_opts data_opts;
	int ret = 0;

	bch2_trans_init(&trans, c, 0, 0);
	progress_list_add(c, stats);

	stats->data_type = BCH_DATA_btree;

	for (id = start_btree_id;
	     id <= min_t(unsigned, end_btree_id, BTREE_ID_NR - 1);
	     id++) {
		stats->btree_id = id;

		bch2_trans_node_iter_init(&trans, &iter, id, POS_MIN, 0, 0,
					  BTREE_ITER_PREFETCH);
retry:
		ret = 0;
		while (bch2_trans_begin(&trans),
		       (b = bch2_btree_iter_peek_node(&iter)) &&
		       !(ret = PTR_ERR_OR_ZERO(b))) {
			if (kthread && kthread_should_stop())
				break;

			if ((cmp_int(id, end_btree_id) ?:
			     bpos_cmp(b->key.k.p, end_pos)) > 0)
				break;

			stats->pos = iter.pos;

			if (!pred(c, arg, b, &io_opts, &data_opts))
				goto next;

			ret = bch2_btree_node_rewrite(&trans, &iter, b, 0) ?: ret;
			if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
				continue;
			if (ret)
				break;
next:
			bch2_btree_iter_next_node(&iter);
		}
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			goto retry;

		bch2_trans_iter_exit(&trans, &iter);

		if (kthread && kthread_should_stop())
			break;
	}

	bch2_trans_exit(&trans);

	if (ret)
		bch_err(c, "error in %s(): %s", __func__, bch2_err_str(ret));

	bch2_btree_interior_updates_flush(c);

	progress_list_del(c, stats);
	return ret;
}

static bool rereplicate_pred(struct bch_fs *c, void *arg,
			     struct bkey_s_c k,
			     struct bch_io_opts *io_opts,
			     struct data_update_opts *data_opts)
{
	unsigned nr_good = bch2_bkey_durability(c, k);
	unsigned replicas = bkey_is_btree_ptr(k.k)
		? c->opts.metadata_replicas
		: io_opts->data_replicas;

	if (!nr_good || nr_good >= replicas)
		return false;

	data_opts->target		= 0;
	data_opts->extra_replicas	= replicas - nr_good;
	data_opts->btree_insert_flags	= 0;
	return true;
}

static bool migrate_pred(struct bch_fs *c, void *arg,
			 struct bkey_s_c k,
			 struct bch_io_opts *io_opts,
			 struct data_update_opts *data_opts)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const struct bch_extent_ptr *ptr;
	struct bch_ioctl_data *op = arg;
	unsigned i = 0;

	data_opts->rewrite_ptrs		= 0;
	data_opts->target		= 0;
	data_opts->extra_replicas	= 0;
	data_opts->btree_insert_flags	= 0;

	bkey_for_each_ptr(ptrs, ptr) {
		if (ptr->dev == op->migrate.dev)
			data_opts->rewrite_ptrs |= 1U << i;
		i++;
	}

	return data_opts->rewrite_ptrs != 0;;
}

static bool rereplicate_btree_pred(struct bch_fs *c, void *arg,
				   struct btree *b,
				   struct bch_io_opts *io_opts,
				   struct data_update_opts *data_opts)
{
	return rereplicate_pred(c, arg, bkey_i_to_s_c(&b->key), io_opts, data_opts);
}

static bool migrate_btree_pred(struct bch_fs *c, void *arg,
			       struct btree *b,
			       struct bch_io_opts *io_opts,
			       struct data_update_opts *data_opts)
{
	return migrate_pred(c, arg, bkey_i_to_s_c(&b->key), io_opts, data_opts);
}

static bool bformat_needs_redo(struct bkey_format *f)
{
	unsigned i;

	for (i = 0; i < f->nr_fields; i++) {
		unsigned unpacked_bits = bch2_bkey_format_current.bits_per_field[i];
		u64 unpacked_mask = ~((~0ULL << 1) << (unpacked_bits - 1));
		u64 field_offset = le64_to_cpu(f->field_offset[i]);

		if (f->bits_per_field[i] > unpacked_bits)
			return true;

		if ((f->bits_per_field[i] == unpacked_bits) && field_offset)
			return true;

		if (((field_offset + ((1ULL << f->bits_per_field[i]) - 1)) &
		     unpacked_mask) <
		    field_offset)
			return true;
	}

	return false;
}

static bool rewrite_old_nodes_pred(struct bch_fs *c, void *arg,
				   struct btree *b,
				   struct bch_io_opts *io_opts,
				   struct data_update_opts *data_opts)
{
	if (b->version_ondisk != c->sb.version ||
	    btree_node_need_rewrite(b) ||
	    bformat_needs_redo(&b->format)) {
		data_opts->target		= 0;
		data_opts->extra_replicas	= 0;
		data_opts->btree_insert_flags	= 0;
		return true;
	}

	return false;
}

int bch2_scan_old_btree_nodes(struct bch_fs *c, struct bch_move_stats *stats)
{
	int ret;

	ret = bch2_move_btree(c,
			      0,		POS_MIN,
			      BTREE_ID_NR,	SPOS_MAX,
			      rewrite_old_nodes_pred, c, stats);
	if (!ret) {
		mutex_lock(&c->sb_lock);
		c->disk_sb.sb->compat[0] |= cpu_to_le64(1ULL << BCH_COMPAT_extents_above_btree_updates_done);
		c->disk_sb.sb->compat[0] |= cpu_to_le64(1ULL << BCH_COMPAT_bformat_overflow_done);
		c->disk_sb.sb->version_min = c->disk_sb.sb->version;
		bch2_write_super(c);
		mutex_unlock(&c->sb_lock);
	}

	return ret;
}

int bch2_data_job(struct bch_fs *c,
		  struct bch_move_stats *stats,
		  struct bch_ioctl_data op)
{
	int ret = 0;

	switch (op.op) {
	case BCH_DATA_OP_REREPLICATE:
		bch_move_stats_init(stats, "rereplicate");
		stats->data_type = BCH_DATA_journal;
		ret = bch2_journal_flush_device_pins(&c->journal, -1);

		ret = bch2_move_btree(c,
				      op.start_btree,	op.start_pos,
				      op.end_btree,	op.end_pos,
				      rereplicate_btree_pred, c, stats) ?: ret;
		ret = bch2_replicas_gc2(c) ?: ret;

		ret = bch2_move_data(c,
				     op.start_btree,	op.start_pos,
				     op.end_btree,	op.end_pos,
				     NULL,
				     stats,
				     writepoint_hashed((unsigned long) current),
				     true,
				     rereplicate_pred, c) ?: ret;
		ret = bch2_replicas_gc2(c) ?: ret;
		break;
	case BCH_DATA_OP_MIGRATE:
		if (op.migrate.dev >= c->sb.nr_devices)
			return -EINVAL;

		bch_move_stats_init(stats, "migrate");
		stats->data_type = BCH_DATA_journal;
		ret = bch2_journal_flush_device_pins(&c->journal, op.migrate.dev);

		ret = bch2_move_btree(c,
				      op.start_btree,	op.start_pos,
				      op.end_btree,	op.end_pos,
				      migrate_btree_pred, &op, stats) ?: ret;
		ret = bch2_replicas_gc2(c) ?: ret;

		ret = bch2_move_data(c,
				     op.start_btree,	op.start_pos,
				     op.end_btree,	op.end_pos,
				     NULL,
				     stats,
				     writepoint_hashed((unsigned long) current),
				     true,
				     migrate_pred, &op) ?: ret;
		ret = bch2_replicas_gc2(c) ?: ret;
		break;
	case BCH_DATA_OP_REWRITE_OLD_NODES:
		bch_move_stats_init(stats, "rewrite_old_nodes");
		ret = bch2_scan_old_btree_nodes(c, stats);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}
