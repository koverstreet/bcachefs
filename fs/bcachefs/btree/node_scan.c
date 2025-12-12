// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/buckets.h"

#include "btree/cache.h"
#include "btree/interior.h"
#include "btree/journal_overlay.h"
#include "btree/node_scan.h"
#include "btree/read.h"

#include "init/error.h"
#include "init/passes.h"

#include <linux/kthread.h>
#include <linux/sched/sysctl.h>
#include <linux/sort.h>

struct find_btree_nodes_worker {
	struct closure		*cl;
	struct find_btree_nodes	*f;
	struct bch_dev		*ca;
};

void bch2_found_btree_node_to_text(struct printbuf *out, struct bch_fs *c, const struct found_btree_node *n)
{
	bch2_btree_id_level_to_text(out, n->btree_id, n->level);
	prt_printf(out, " seq=%u journal_seq=%llu cookie=%llx ",
		   n->seq, n->journal_seq, n->cookie);
	bch2_bpos_to_text(out, n->min_key);
	prt_str(out, "-");
	bch2_bpos_to_text(out, n->max_key);

	if (n->range_updated)
		prt_str(out, " range updated");
	prt_newline(out);

	guard(printbuf_indent)(out);
	guard(printbuf_atomic)(out);
	guard(rcu)();

	for (unsigned i = 0; i < n->nr_ptrs; i++) {
		bch2_extent_ptr_to_text(out, c, n->ptrs + i);
		prt_newline(out);
	}
}

static void found_btree_nodes_to_text(struct printbuf *out, struct bch_fs *c,
				      darray_found_btree_node nodes)
{
	guard(printbuf_indent)(out);
	darray_for_each(nodes, i)
		bch2_found_btree_node_to_text(out, c, i);
}

static void found_btree_node_to_key(struct bkey_i *k, const struct found_btree_node *f)
{
	struct bkey_i_btree_ptr_v2 *bp = bkey_btree_ptr_v2_init(k);

	set_bkey_val_u64s(&bp->k, sizeof(struct bch_btree_ptr_v2) / sizeof(u64) + f->nr_ptrs);
	bp->k.p			= f->max_key;
	bp->v.seq		= cpu_to_le64(f->cookie);
	bp->v.sectors_written	= 0;
	bp->v.flags		= 0;
	bp->v.sectors_written	= cpu_to_le16(f->sectors_written);
	bp->v.min_key		= f->min_key;
	SET_BTREE_PTR_RANGE_UPDATED(&bp->v, f->range_updated);
	memcpy(bp->v.start, f->ptrs, sizeof(struct bch_extent_ptr) * f->nr_ptrs);
}

static int found_btree_node_cmp_cookie(const void *_l, const void *_r)
{
	const struct found_btree_node *l = _l;
	const struct found_btree_node *r = _r;

	return  cmp_int(l->btree_id,	r->btree_id) ?:
		cmp_int(l->level,	r->level) ?:
		cmp_int(l->cookie,	r->cookie);
}

/*
 * Given two found btree nodes, if their sequence numbers are equal, take the
 * one that's readable:
 */
static int found_btree_node_cmp_time(const struct found_btree_node *l,
				     const struct found_btree_node *r)
{
	return  cmp_int(l->seq, r->seq) ?:
		cmp_int(l->journal_seq, r->journal_seq);
}

static int found_btree_node_cmp_pos(const void *_l, const void *_r)
{
	const struct found_btree_node *l = _l;
	const struct found_btree_node *r = _r;

	return  cmp_int(l->btree_id,	r->btree_id) ?:
	       -cmp_int(l->level,	r->level) ?:
		bpos_cmp(l->min_key,	r->min_key) ?:
	       -found_btree_node_cmp_time(l, r);
}

static inline bool found_btree_node_cmp_pos_less(const void *l, const void *r, void *arg)
{
	return found_btree_node_cmp_pos(l, r) < 0;
}

static inline void found_btree_node_swap(void *_l, void *_r, void *arg)
{
	struct found_btree_node *l = _l;
	struct found_btree_node *r = _r;

	swap(*l, *r);
}

static const struct min_heap_callbacks found_btree_node_heap_cbs = {
	.less = found_btree_node_cmp_pos_less,
	.swp = found_btree_node_swap,
};

static void try_read_btree_node(struct find_btree_nodes *f, struct bch_dev *ca,
				struct btree *b, struct bio *bio, u64 offset)
{
	struct bch_fs *c = container_of(f, struct bch_fs, btree.node_scan);
	struct btree_node *bn = b->data;

	bio_reset(bio, ca->disk_sb.bdev, REQ_OP_READ);
	bio->bi_iter.bi_sector	= offset;
	bch2_bio_map(bio, b->data, c->opts.block_size);

	u64 submit_time = local_clock();
	submit_bio_wait(bio);
	bch2_account_io_completion(ca, BCH_MEMBER_ERROR_read, submit_time, !bio->bi_status);

	if (bio->bi_status) {
		bch_err_dev_ratelimited(ca,
				"IO error in try_read_btree_node() at %llu: %s",
				offset, bch2_blk_status_to_str(bio->bi_status));
		return;
	}

	if (le64_to_cpu(bn->magic) != bset_magic(c))
		return;

	if (bch2_csum_type_is_encryption(BSET_CSUM_TYPE(&bn->keys))) {
		if (!c->chacha20_key_set)
			return;

		struct nonce nonce = btree_nonce(&bn->keys, 0);
		unsigned bytes = (void *) &bn->keys - (void *) &bn->flags;

		bch2_encrypt(c, BSET_CSUM_TYPE(&bn->keys), nonce, &bn->flags, bytes);
	}

	if (btree_id_can_reconstruct(BTREE_NODE_ID(bn)))
		return;

	if (BTREE_NODE_LEVEL(bn) >= BTREE_MAX_DEPTH)
		return;

	if (BTREE_NODE_ID(bn) >= BTREE_ID_NR_MAX)
		return;

	rcu_read_lock();
	struct found_btree_node n = {
		.btree_id	= BTREE_NODE_ID(bn),
		.level		= BTREE_NODE_LEVEL(bn),
		.seq		= BTREE_NODE_SEQ(bn),
		.cookie		= le64_to_cpu(bn->keys.seq),
		.min_key	= bn->min_key,
		.max_key	= bn->max_key,
		.nr_ptrs	= 1,
		.ptrs[0].type	= 1 << BCH_EXTENT_ENTRY_ptr,
		.ptrs[0].offset	= offset,
		.ptrs[0].dev	= ca->dev_idx,
		.ptrs[0].gen	= bucket_gen_get(ca, sector_to_bucket(ca, offset)),
	};
	rcu_read_unlock();

	bio_reset(bio, ca->disk_sb.bdev, REQ_OP_READ);
	bio->bi_iter.bi_sector	= offset;
	bch2_bio_map(bio, b->data, c->opts.btree_node_size);

	submit_time = local_clock();
	submit_bio_wait(bio);
	bch2_account_io_completion(ca, BCH_MEMBER_ERROR_read, submit_time, !bio->bi_status);

	found_btree_node_to_key(&b->key, &n);

	CLASS(printbuf, buf)();
	if (!bch2_btree_node_read_done(c, ca, b, NULL, &buf)) {
		/* read_done will swap out b->data for another buffer */
		bn = b->data;
		/*
		 * Grab journal_seq here because we want the max journal_seq of
		 * any bset; read_done sorts down to a single set and picks the
		 * max journal_seq
		 */
		n.journal_seq		= le64_to_cpu(bn->keys.journal_seq),
		n.sectors_written	= b->written;

		guard(mutex)(&f->lock);
		if (BSET_BIG_ENDIAN(&bn->keys) != CPU_BIG_ENDIAN) {
			bch_err(c, "try_read_btree_node() can't handle endian conversion");
			f->ret = -EINVAL;
			return;
		}

		if (darray_push(&f->nodes, n))
			f->ret = -ENOMEM;
	}
}

static int read_btree_nodes_worker(void *p)
{
	struct find_btree_nodes_worker *w = p;
	struct bch_fs *c = container_of(w->f, struct bch_fs, btree.node_scan);
	struct bch_dev *ca = w->ca;
	unsigned long last_print = jiffies;
	struct btree *b = NULL;
	struct bio *bio = NULL;

	b = __bch2_btree_node_mem_alloc(c);
	if (!b) {
		bch_err(c, "read_btree_nodes_worker: error allocating buf");
		w->f->ret = -ENOMEM;
		goto err;
	}

	bio = bio_alloc(NULL, buf_pages(b->data, c->opts.btree_node_size), 0, GFP_KERNEL);
	if (!bio) {
		bch_err(c, "read_btree_nodes_worker: error allocating bio");
		w->f->ret = -ENOMEM;
		goto err;
	}

	u64 buckets_to_scan = 0;
	for (u64 bucket = ca->mi.first_bucket; bucket < ca->mi.nbuckets; bucket++)
		buckets_to_scan += c->sb.version_upgrade_complete < bcachefs_metadata_version_mi_btree_bitmap ||
			bch2_dev_btree_bitmap_marked_sectors_any(ca, bucket_to_sector(ca, bucket), ca->mi.bucket_size);

	u64 buckets_scanned = 0;
	for (u64 bucket = ca->mi.first_bucket; bucket < ca->mi.nbuckets; bucket++) {
		if (c->sb.version_upgrade_complete >= bcachefs_metadata_version_mi_btree_bitmap &&
		    !bch2_dev_btree_bitmap_marked_sectors_any(ca, bucket_to_sector(ca, bucket), ca->mi.bucket_size))
			continue;

		for (unsigned bucket_offset = 0;
		     bucket_offset + btree_sectors(c) <= ca->mi.bucket_size;
		     bucket_offset += btree_sectors(c))
			try_read_btree_node(w->f, ca, b, bio, bucket_to_sector(ca, bucket) + bucket_offset);

		buckets_scanned++;

		if (time_after(jiffies, last_print + HZ * 30)) {
			bch_info_dev(ca, "%s: %2u%% done", __func__,
				     (unsigned) div64_u64(buckets_scanned * 100, buckets_to_scan));
			last_print = jiffies;
		}
	}
err:
	if (b)
		bch2_btree_node_data_free_locked(b);
	kfree(b);
	bio_put(bio);
	enumerated_ref_put(&ca->io_ref[READ], BCH_DEV_READ_REF_btree_node_scan);
	closure_put(w->cl);
	kfree(w);
	return 0;
}

static int read_btree_nodes(struct find_btree_nodes *f)
{
	struct bch_fs *c = container_of(f, struct bch_fs, btree.node_scan);
	int ret = 0;

	CLASS(closure_stack, cl)();
	CLASS(printbuf, buf)();

	prt_printf(&buf, "scanning for btree nodes on");

	for_each_online_member(c, ca, BCH_DEV_READ_REF_btree_node_scan) {
		if (!(ca->mi.data_allowed & BIT(BCH_DATA_btree)))
			continue;

		struct find_btree_nodes_worker *w = kmalloc(sizeof(*w), GFP_KERNEL);
		if (!w) {
			enumerated_ref_put(&ca->io_ref[READ], BCH_DEV_READ_REF_btree_node_scan);
			ret = -ENOMEM;
			goto err;
		}

		w->cl		= &cl;
		w->f		= f;
		w->ca		= ca;

		struct task_struct *t = kthread_create(read_btree_nodes_worker, w, "read_btree_nodes/%s", ca->name);
		ret = PTR_ERR_OR_ZERO(t);
		if (ret) {
			enumerated_ref_put(&ca->io_ref[READ], BCH_DEV_READ_REF_btree_node_scan);
			kfree(w);
			bch_err_msg(c, ret, "starting kthread");
			break;
		}

		prt_printf(&buf, " %s", ca->name);

		closure_get(&cl);
		enumerated_ref_get(&ca->io_ref[READ], BCH_DEV_READ_REF_btree_node_scan);
		wake_up_process(t);
	}

	bch_notice(c, "%s", buf.buf);
err:
	if (!sysctl_hung_task_timeout_secs)
		closure_sync(&cl);
	else
		while (closure_sync_timeout(&cl, sysctl_hung_task_timeout_secs * HZ / 2))
			;

	return f->ret ?: ret;
}

static bool nodes_overlap(const struct found_btree_node *l,
			  const struct found_btree_node *r)
{
	return (l->btree_id	== r->btree_id &&
		l->level	== r->level &&
		bpos_gt(l->max_key, r->min_key));
}

static int handle_overwrites(struct bch_fs *c,
			     struct found_btree_node *l,
			     darray_found_btree_node *nodes_heap)
{
	struct found_btree_node *r;

	while ((r = min_heap_peek(nodes_heap)) &&
	       nodes_overlap(l, r)) {
		int cmp = found_btree_node_cmp_time(l, r);

		if (cmp > 0) {
			if (bpos_cmp(l->max_key, r->max_key) >= 0)
				min_heap_pop(nodes_heap, &found_btree_node_heap_cbs, NULL);
			else {
				r->range_updated = true;
				r->min_key = bpos_successor(l->max_key);
				r->range_updated = true;
				min_heap_sift_down(nodes_heap, 0, &found_btree_node_heap_cbs, NULL);
			}
		} else if (cmp < 0) {
			BUG_ON(bpos_eq(l->min_key, r->min_key));

			l->max_key = bpos_predecessor(r->min_key);
			l->range_updated = true;
		} else if (r->level) {
			min_heap_pop(nodes_heap, &found_btree_node_heap_cbs, NULL);
		} else {
			if (bpos_cmp(l->max_key, r->max_key) >= 0)
				min_heap_pop(nodes_heap, &found_btree_node_heap_cbs, NULL);
			else {
				r->range_updated = true;
				r->min_key = bpos_successor(l->max_key);
				r->range_updated = true;
				min_heap_sift_down(nodes_heap, 0, &found_btree_node_heap_cbs, NULL);
			}
		}

		cond_resched();
	}

	return 0;
}

int bch2_scan_for_btree_nodes(struct bch_fs *c)
{
	struct find_btree_nodes *f = &c->btree.node_scan;
	CLASS(printbuf, buf)();
	CLASS(darray_found_btree_node, nodes_heap)();
	size_t dst;

	if (f->nodes.nr)
		return 0;

	try(read_btree_nodes(f));

	guard(mutex)(&f->lock);

	if (!f->nodes.nr) {
		bch_err(c, "%s: no btree nodes found", __func__);
		return -EINVAL;
	}

	if (0 && c->opts.verbose) {
		printbuf_reset(&buf);
		prt_printf(&buf, "%s: nodes found:\n", __func__);
		found_btree_nodes_to_text(&buf, c, f->nodes);
		bch2_print_str(c, KERN_INFO, buf.buf);
	}

	sort_nonatomic(f->nodes.data, f->nodes.nr, sizeof(f->nodes.data[0]), found_btree_node_cmp_cookie, NULL);

	dst = 0;
	darray_for_each(f->nodes, i) {
		struct found_btree_node *prev = dst ? f->nodes.data + dst - 1 : NULL;

		if (prev &&
		    prev->cookie == i->cookie) {
			if (prev->nr_ptrs == ARRAY_SIZE(prev->ptrs)) {
				bch_err(c, "%s: found too many replicas for btree node", __func__);
				return -EINVAL;
			}
			prev->ptrs[prev->nr_ptrs++] = i->ptrs[0];
		} else {
			f->nodes.data[dst++] = *i;
		}
	}
	f->nodes.nr = dst;

	sort_nonatomic(f->nodes.data, f->nodes.nr, sizeof(f->nodes.data[0]), found_btree_node_cmp_pos, NULL);

	if (0 && c->opts.verbose) {
		printbuf_reset(&buf);
		prt_printf(&buf, "%s: nodes after merging replicas:\n", __func__);
		found_btree_nodes_to_text(&buf, c, f->nodes);
		bch2_print_str(c, KERN_INFO, buf.buf);
	}

	swap(nodes_heap, f->nodes);

	{
		/* darray must have same layout as a heap */
		min_heap_char real_heap;
		BUILD_BUG_ON(sizeof(nodes_heap.nr)			!= sizeof(real_heap.nr));
		BUILD_BUG_ON(sizeof(nodes_heap.size)			!= sizeof(real_heap.size));
		BUILD_BUG_ON(offsetof(darray_found_btree_node, nr)	!= offsetof(min_heap_char, nr));
		BUILD_BUG_ON(offsetof(darray_found_btree_node, size)	!= offsetof(min_heap_char, size));
	}

	min_heapify_all(&nodes_heap, &found_btree_node_heap_cbs, NULL);

	if (nodes_heap.nr) {
		try(darray_push(&f->nodes, *min_heap_peek(&nodes_heap)));

		min_heap_pop(&nodes_heap, &found_btree_node_heap_cbs, NULL);
	}

	while (true) {
		try(handle_overwrites(c, &darray_last(f->nodes), &nodes_heap));

		if (!nodes_heap.nr)
			break;

		try(darray_push(&f->nodes, *min_heap_peek(&nodes_heap)));

		min_heap_pop(&nodes_heap, &found_btree_node_heap_cbs, NULL);
	}

	for (struct found_btree_node *n = f->nodes.data; n < &darray_last(f->nodes); n++)
		BUG_ON(nodes_overlap(n, n + 1));

	if (0 && c->opts.verbose) {
		printbuf_reset(&buf);
		prt_printf(&buf, "%s: nodes found after overwrites:\n", __func__);
		found_btree_nodes_to_text(&buf, c, f->nodes);
		bch2_print_str(c, KERN_INFO, buf.buf);
	} else {
		bch_info(c, "btree node scan found %zu nodes after overwrites", f->nodes.nr);
	}

	eytzinger0_sort(f->nodes.data, f->nodes.nr, sizeof(f->nodes.data[0]), found_btree_node_cmp_pos, NULL);
	return 0;
}

static int found_btree_node_range_start_cmp(const void *_l, const void *_r)
{
	const struct found_btree_node *l = _l;
	const struct found_btree_node *r = _r;

	return  cmp_int(l->btree_id,	r->btree_id) ?:
	       -cmp_int(l->level,	r->level) ?:
		bpos_cmp(l->max_key,	r->min_key);
}

#define for_each_found_btree_node_in_range(_f, _search, _idx)				\
	for (size_t _idx = eytzinger0_find_gt((_f)->nodes.data, (_f)->nodes.nr,		\
					sizeof((_f)->nodes.data[0]),			\
					found_btree_node_range_start_cmp, &search);	\
	     _idx < (_f)->nodes.nr &&							\
	     (_f)->nodes.data[_idx].btree_id == _search.btree_id &&			\
	     (_f)->nodes.data[_idx].level == _search.level &&				\
	     bpos_lt((_f)->nodes.data[_idx].min_key, _search.max_key);			\
	     _idx = eytzinger0_next(_idx, (_f)->nodes.nr))

bool bch2_btree_node_is_stale(struct bch_fs *c, struct btree *b)
{
	struct find_btree_nodes *f = &c->btree.node_scan;

	struct found_btree_node search = {
		.btree_id	= b->c.btree_id,
		.level		= b->c.level,
		.min_key	= b->data->min_key,
		.max_key	= b->key.k.p,
	};

	for_each_found_btree_node_in_range(f, search, idx)
		if (f->nodes.data[idx].seq > BTREE_NODE_SEQ(b->data))
			return true;
	return false;
}

int bch2_btree_has_scanned_nodes(struct bch_fs *c, enum btree_id btree, struct printbuf *out)
{
	try(bch2_run_explicit_recovery_pass(c, out, BCH_RECOVERY_PASS_scan_for_btree_nodes, 0));

	struct found_btree_node search = {
		.btree_id	= btree,
		.level		= 0,
		.min_key	= POS_MIN,
		.max_key	= SPOS_MAX,
	};

	for_each_found_btree_node_in_range(&c->btree.node_scan, search, idx)
		return true;
	return false;
}

int bch2_get_scanned_nodes(struct bch_fs *c, enum btree_id btree,
			   unsigned level, struct bpos node_min, struct bpos node_max,
			   struct printbuf *out, size_t *nodes_found)
{
	if (!btree_id_recovers_from_scan(btree))
		return 0;

	try(bch2_run_explicit_recovery_pass(c, out, BCH_RECOVERY_PASS_scan_for_btree_nodes, 0));

	if (c->opts.verbose) {
		CLASS(printbuf, buf)();

		prt_str(&buf, "recovery ");
		bch2_btree_id_level_to_text(&buf, btree, level);
		prt_str(&buf, " ");
		bch2_bpos_to_text(&buf, node_min);
		prt_str(&buf, " - ");
		bch2_bpos_to_text(&buf, node_max);

		bch_info(c, "%s(): %s", __func__, buf.buf);
	}

	struct found_btree_node search = {
		.btree_id	= btree,
		.level		= level,
		.min_key	= node_min,
		.max_key	= node_max,
	};

	struct find_btree_nodes *f = &c->btree.node_scan;
	for_each_found_btree_node_in_range(f, search, idx) {
		struct found_btree_node n = f->nodes.data[idx];

		n.range_updated |= bpos_lt(n.min_key, node_min);
		n.min_key = bpos_max(n.min_key, node_min);

		n.range_updated |= bpos_gt(n.max_key, node_max);
		n.max_key = bpos_min(n.max_key, node_max);

		struct { __BKEY_PADDED(k, BKEY_BTREE_PTR_VAL_U64s_MAX); } tmp;

		found_btree_node_to_key(&tmp.k, &n);

		BUG_ON(bch2_bkey_validate(c, bkey_i_to_s_c(&tmp.k),
					  (struct bkey_validate_context) {
						.from	= BKEY_VALIDATE_btree_node,
						.level	= level + 1,
						.btree	= btree,
					  }));

		if (!*nodes_found) {
			prt_printf(out, "recovering from btree node scan at ");
			bch2_btree_id_level_to_text(out, btree, level);
			prt_newline(out);
			printbuf_indent_add(out, 2);
		}

		*nodes_found += 1;

		if (*nodes_found < 10) {
			bch2_bkey_val_to_text(out, c, bkey_i_to_s_c(&tmp.k));
			prt_newline(out);
		} else if (*nodes_found == 10)
			prt_printf(out, "<many>\n");

		try(bch2_journal_key_insert(c, btree, level + 1, &tmp.k));
	}

	if (*nodes_found)
		printbuf_indent_sub(out, 2);

	return 0;
}

void bch2_find_btree_nodes_exit(struct find_btree_nodes *f)
{
	darray_exit(&f->nodes);
}

void bch2_find_btree_nodes_init(struct find_btree_nodes *f)
{
	mutex_init(&f->lock);
}
