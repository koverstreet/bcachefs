// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_locking.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "btree_write_buffer.h"
#include "error.h"
#include "journal.h"
#include "journal_reclaim.h"

#include <linux/sort.h>

static int btree_write_buffered_key_cmp(const void *_l, const void *_r)
{
	const struct btree_write_buffered_key *l = _l;
	const struct btree_write_buffered_key *r = _r;

	return  cmp_int(l->btree, r->btree) ?:
		bpos_cmp(l->k.k.p, r->k.k.p) ?:
		cmp_int(l->journal_seq, r->journal_seq) ?:
		cmp_int(l->journal_offset, r->journal_offset);
}

static int btree_write_buffered_journal_cmp(const void *_l, const void *_r)
{
	const struct btree_write_buffered_key *l = _l;
	const struct btree_write_buffered_key *r = _r;

	return  cmp_int(l->journal_seq, r->journal_seq);
}

static int bch2_btree_write_buffer_flush_one(struct btree_trans *trans,
					     struct btree_iter *iter,
					     struct btree_write_buffered_key *wb,
					     bool *write_locked,
					     size_t *fast)
{
	struct bch_fs *c = trans->c;
	struct btree_path *path = iter->path;
	int ret;

	ret = bch2_btree_iter_traverse(iter);
	if (ret)
		return ret;

	if (!*write_locked) {
		ret = bch2_btree_node_lock_write(trans, path, &path->l[0].b->c);
		if (ret)
			return ret;

		bch2_btree_node_prep_for_write(trans, path, path->l[0].b);
		*write_locked = true;
	}

	if (!bch2_btree_node_insert_fits(c, path->l[0].b, wb->k.k.u64s)) {
		bch2_btree_node_unlock_write(trans, path, path->l[0].b);
		*write_locked = false;
		goto trans_commit;
	}

	bch2_btree_insert_key_leaf(trans, path, &wb->k, wb->journal_seq);
	(*fast)++;
	return 0;
trans_commit:
	return  bch2_trans_update(trans, iter, &wb->k, 0) ?:
		bch2_trans_commit(trans, NULL, NULL,
				  BTREE_INSERT_NOFAIL|
				  BTREE_INSERT_JOURNAL_RECLAIM);
}

int __bch2_btree_write_buffer_flush(struct btree_trans *trans, unsigned commit_flags,
				    bool locked)
{
	struct bch_fs *c = trans->c;
	struct journal *j = &c->journal;
	struct btree_write_buffer *wb = &c->btree_write_buffer;
	struct journal_entry_pin pin;
	struct btree_write_buffered_key *i, *dst;
	struct btree_iter iter = { NULL };
	size_t nr = 0, skipped = 0, fast = 0;
	bool write_locked = false;
	int ret = 0;

	memset(&pin, 0, sizeof(pin));

	if (!locked && !mutex_trylock(&wb->flush_lock))
		return 0;

	mutex_lock(&wb->lock);
	swap(wb->keys, wb->flushing);
	swap(wb->nr, nr);

	bch2_journal_pin_copy(j, &pin, &wb->journal_pin, NULL);
	bch2_journal_pin_drop(j, &wb->journal_pin);
	mutex_unlock(&wb->lock);

	/*
	 * We first sort so that we can detect and skip redundant updates, and
	 * then we attempt to flush in sorted btree order, as this is most
	 * efficient.
	 *
	 * However, since we're not flushing in the order they appear in the
	 * journal we won't be able to drop our journal pin until everything is
	 * flushed - which means this could deadlock the journal, if we weren't
	 * passing BTREE_INSERT_JORUNAL_RECLAIM. This causes the update to fail
	 * if it would block taking a journal reservation.
	 *
	 * If that happens, we sort them by the order they appeared in the
	 * journal - after dropping redundant entries - and then restart
	 * flushing, this time dropping journal pins as we go.
	 */

	sort(wb->flushing, nr,
	     sizeof(wb->flushing[0]),
	     btree_write_buffered_key_cmp,
	     NULL);

	for (i = wb->flushing;
	     i < wb->flushing + nr && !ret;
	     i++) {
		if (i + 1 < wb->flushing + nr &&
		    i[0].btree == i[1].btree &&
		    bpos_eq(i[0].k.k.p, i[1].k.k.p)) {
			skipped++;
			if (bkey_deleted(&i[1].k.k)) {
				skipped++;
				i++;
			}
			continue;
		}

		if (write_locked &&
		    (iter.path->btree_id != i->btree ||
		     bpos_gt(i->k.k.p, iter.path->l[0].b->key.k.p))) {
			bch2_btree_node_unlock_write(trans, iter.path, iter.path->l[0].b);
			write_locked = false;
		}

		if (!iter.path || iter.path->btree_id != i->btree) {
			bch2_trans_iter_exit(trans, &iter);
			bch2_trans_iter_init(trans, &iter, i->btree, i->k.k.p, BTREE_ITER_INTENT);
			iter.path->preserve = false;
		}

		bch2_btree_iter_set_pos(&iter, i->k.k.p);

		while (1) {
			ret = bch2_btree_write_buffer_flush_one(trans, &iter, i, &write_locked, &fast);
			if (!bch2_err_matches(ret, BCH_ERR_transaction_restart))
				break;
			bch2_trans_begin(trans);
		}
	}
	if (write_locked)
		bch2_btree_node_unlock_write(trans, iter.path, iter.path->l[0].b);
	bch2_trans_iter_exit(trans, &iter);

	trace_write_buffer_flush(trans, nr, skipped, fast, wb->size);

	if (ret == -BCH_ERR_journal_reclaim_would_deadlock)
		goto slowpath;

	bch2_fs_fatal_err_on(ret, c, "%s: insert error %s", __func__, bch2_err_str(ret));
out:
	bch2_journal_pin_drop(j, &pin);
	mutex_unlock(&wb->flush_lock);
	return ret;
slowpath:
	trace_write_buffer_flush_slowpath(trans, i - wb->flushing, nr);

	dst = wb->flushing;
	for (;
	     i < wb->flushing + nr;
	     i++) {
		if (i + 1 < wb->flushing + nr &&
		    i[0].btree == i[1].btree &&
		    bpos_eq(i[0].k.k.p, i[1].k.k.p)) {
			if (bkey_deleted(&i[1].k.k))
				i++;
			continue;
		}

		*dst = *i;
		dst++;
	}
	nr = dst - wb->flushing;

	sort(wb->flushing, nr,
	     sizeof(wb->flushing[0]),
	     btree_write_buffered_journal_cmp,
	     NULL);

	for (i = wb->flushing;
	     i < wb->flushing + nr;
	     i++) {
		if (i->journal_seq > pin.seq) {
			struct journal_entry_pin pin2;

			memset(&pin2, 0, sizeof(pin2));

			bch2_journal_pin_add(j, i->journal_seq, &pin2, NULL);
			bch2_journal_pin_drop(j, &pin);
			bch2_journal_pin_copy(j, &pin, &pin2, NULL);
			bch2_journal_pin_drop(j, &pin2);
		}

		ret = commit_do(trans, NULL, NULL,
				commit_flags|
				BTREE_INSERT_NOFAIL|
				BTREE_INSERT_JOURNAL_RECLAIM|
				JOURNAL_WATERMARK_reserved,
				__bch2_btree_insert(trans, i->btree, &i->k));
		if (bch2_fs_fatal_err_on(ret, c, "%s: insert error %s", __func__, bch2_err_str(ret)))
			break;
	}

	goto out;
}

int bch2_btree_write_buffer_flush(struct btree_trans *trans)
{
	return __bch2_btree_write_buffer_flush(trans, 0, false);
}

static int bch2_btree_write_buffer_journal_flush(struct journal *j,
				struct journal_entry_pin *_pin, u64 seq)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	return bch2_trans_run(c,
			__bch2_btree_write_buffer_flush(&trans, BTREE_INSERT_NOCHECK_RW,
							false));
}

int bch2_btree_insert_keys_write_buffer(struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;
	struct btree_write_buffer *wb = &c->btree_write_buffer;
	struct btree_write_buffered_key *i;

	EBUG_ON(trans->flags & BTREE_INSERT_JOURNAL_REPLAY);

	trans_for_each_wb_update(trans, i) {
		EBUG_ON(i->k.k.u64s > BTREE_WRITE_BUFERED_U64s_MAX);

		i->journal_seq		= trans->journal_res.seq;
		i->journal_offset	= trans->journal_res.offset;
	}

	mutex_lock(&wb->lock);
	if (wb->nr + trans->nr_wb_updates > wb->size) {
		mutex_unlock(&wb->lock);
		return -BCH_ERR_btree_insert_need_flush_buffer;
	}

	memcpy(wb->keys + wb->nr,
	       trans->wb_updates,
	       sizeof(trans->wb_updates[0]) * trans->nr_wb_updates);
	wb->nr += trans->nr_wb_updates;

	if (likely(!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY)))
		bch2_journal_pin_add(&c->journal, trans->journal_res.seq, &wb->journal_pin,
				     bch2_btree_write_buffer_journal_flush);
	mutex_unlock(&wb->lock);

	return 0;
}

void bch2_fs_btree_write_buffer_exit(struct bch_fs *c)
{
	struct btree_write_buffer *wb = &c->btree_write_buffer;

	kvfree(wb->flushing);
	kvfree(wb->keys);
}

int bch2_fs_btree_write_buffer_init(struct bch_fs *c)
{
	struct btree_write_buffer *wb = &c->btree_write_buffer;

	mutex_init(&wb->lock);
	mutex_init(&wb->flush_lock);
	wb->size = c->opts.btree_write_buffer_size;

	wb->keys = kvmalloc_array(wb->size, sizeof(wb->keys[0]), GFP_KERNEL);
	wb->flushing = kvmalloc_array(wb->size, sizeof(wb->keys[0]), GFP_KERNEL);
	if (!wb->keys || !wb->flushing)
		return -ENOMEM;

	return 0;
}
