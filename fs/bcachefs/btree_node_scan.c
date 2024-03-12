// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_cache.h"
#include "btree_io.h"
#include "btree_journal_iter.h"
#include "btree_node_scan.h"
#include "btree_update_interior.h"
#include "buckets.h"
#include "error.h"
#include "journal_io.h"
#include "recovery.h"

#include <linux/kthread.h>
#include <linux/sort.h>

struct find_btree_nodes_worker {
	struct closure		*cl;
	struct find_btree_nodes	*f;
	struct bch_dev		*ca;
	u64			bucket_start;
	u64			bucket_end;
};

static void found_btree_node_to_text(struct printbuf *out, struct bch_fs *c, const struct found_btree_node *n)
{
	prt_printf(out, "%s l=%u seq=%u cookie=%llx ", bch2_btree_id_str(n->btree_id), n->level, n->seq, n->cookie);
	bch2_bpos_to_text(out, n->min_key);
	prt_str(out, "-");
	bch2_bpos_to_text(out, n->max_key);

	if (n->range_updated)
		prt_str(out, " range updated");
	if (n->overwritten)
		prt_str(out, " overwritten");

	for (unsigned i = 0; i < n->nr_ptrs; i++) {
		prt_char(out, ' ');
		bch2_extent_ptr_to_text(out, c, n->ptrs + i);
	}
}

static void found_btree_nodes_to_text(struct printbuf *out, struct bch_fs *c, found_btree_nodes nodes)
{
	printbuf_indent_add(out, 2);
	darray_for_each(nodes, i) {
		found_btree_node_to_text(out, c, i);
		prt_newline(out);
	}
	printbuf_indent_sub(out, 2);
}

static void found_btree_node_to_key(struct bkey_i *k, const struct found_btree_node *f)
{
	struct bkey_i_btree_ptr_v2 *bp = bkey_btree_ptr_v2_init(k);

	set_bkey_val_u64s(&bp->k, sizeof(struct bch_btree_ptr_v2) / sizeof(u64) + f->nr_ptrs);
	bp->k.p			= f->max_key;
	bp->v.seq		= cpu_to_le64(f->cookie);
	bp->v.sectors_written	= 0;
	bp->v.flags		= 0;
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
static int found_btree_node_cmp_time(struct btree_trans *trans,
				     const struct found_btree_node *l,
				     const struct found_btree_node *r)
{
	struct { __BKEY_PADDED(k, BKEY_BTREE_PTR_VAL_U64s_MAX); } k_l;
	struct { __BKEY_PADDED(k, BKEY_BTREE_PTR_VAL_U64s_MAX); } k_r;
	struct btree *b_l, *b_r;
	int ret, cmp = cmp_int(l->version, r->version) ?:
		cmp_int(l->seq, r->seq);

	if (cmp)
		return cmp;

	found_btree_node_to_key(&k_l.k, l);
	found_btree_node_to_key(&k_r.k, l);

	b_l = bch2_btree_node_get_noiter(trans, &k_l.k, l->btree_id, l->level, false);
	b_r = bch2_btree_node_get_noiter(trans, &k_r.k, l->btree_id, l->level, false);

	if (!IS_ERR_OR_NULL(b_l))
		ret = 1;
	else
		ret = -1;

	if (!IS_ERR_OR_NULL(b_l))
		six_unlock_read(&b_l->c.lock);
	if (!IS_ERR_OR_NULL(b_r))
		six_unlock_read(&b_r->c.lock);

	return ret;
}

static int found_btree_node_cmp_pos(const void *_l, const void *_r, const void *priv)
{
	struct btree_trans *trans = (void *) priv;
	const struct found_btree_node *l = _l;
	const struct found_btree_node *r = _r;

	return  cmp_int(l->btree_id,	r->btree_id) ?:
	       -cmp_int(l->level,	r->level) ?:
		bpos_cmp(l->min_key,	r->min_key) ?:
	       -found_btree_node_cmp_time(trans, l, r);
}

static void try_read_btree_node(struct find_btree_nodes *f, struct bch_dev *ca,
				struct bio *bio, struct btree_node *bn, u64 offset)
{
	struct bch_fs *c = container_of(f, struct bch_fs, found_btree_nodes);

	bio_reset(bio, ca->disk_sb.bdev, REQ_OP_READ);
	bio->bi_iter.bi_sector	= offset;
	bch2_bio_map(bio, bn, PAGE_SIZE);

	submit_bio_wait(bio);
	if (bch2_dev_io_err_on(bio->bi_status, ca, BCH_MEMBER_ERROR_read,
			       "IO error in try_read_btree_node() at %llu: %s",
			       offset, bch2_blk_status_to_str(bio->bi_status)))
		return;

	if (le64_to_cpu(bn->magic) != bset_magic(c))
		return;

	rcu_read_lock();
	struct found_btree_node n = {
		.btree_id	= BTREE_NODE_ID(bn),
		.level		= BTREE_NODE_LEVEL(bn),
		.version	= le16_to_cpu(bn->keys.version),
		.seq		= BTREE_NODE_SEQ(bn),
		.cookie		= le64_to_cpu(bn->keys.seq),
		.min_key	= bn->min_key,
		.max_key	= bn->max_key,
		.nr_ptrs	= 1,
		.ptrs		= { (struct bch_extent_ptr) {
			.type	= 1 << BCH_EXTENT_ENTRY_ptr,
			.offset	= offset,
			.dev	= ca->dev_idx,
			.gen	= *bucket_gen(ca, sector_to_bucket(ca, offset)),
		},
		},
	};
	rcu_read_unlock();

	mutex_lock(&f->lock);
	if (BSET_BIG_ENDIAN(&bn->keys) != CPU_BIG_ENDIAN) {
		bch_err(c, "try_read_btree_node() can't handle endian conversion");
		f->ret = -EINVAL;
		goto out;
	}

	if (darray_push(&f->nodes, n))
		f->ret = -ENOMEM;
out:
	mutex_unlock(&f->lock);
}

static int read_btree_nodes_worker(void *p)
{
	struct find_btree_nodes_worker *w = p;
	struct bch_fs *c = container_of(w->f, struct bch_fs, found_btree_nodes);
	struct bch_dev *ca = w->ca;
	void *buf = (void *) __get_free_page(GFP_KERNEL);
	struct bio *bio = bio_alloc(NULL, 1, 0, GFP_KERNEL);
	unsigned long last_print = jiffies;

	if (!buf || !bio) {
		bch_err(c, "read_btree_nodes_worker: error allocating bio/buf");
		w->f->ret = -ENOMEM;
		goto err;
	}

	for (u64 bucket = w->bucket_start; bucket < w->bucket_end; bucket++)
		for (unsigned bucket_offset = 0;
		     bucket_offset + btree_sectors(c) <= ca->mi.bucket_size;
		     bucket_offset += btree_sectors(c)) {
			if (time_after(jiffies, last_print + HZ * 30)) {
				bch_info(ca, "%s: at sector %llu/%llu", __func__,
					    bucket * ca->mi.bucket_size + bucket_offset,
					    w->bucket_end * ca->mi.bucket_size);
				last_print = jiffies;
			}

			try_read_btree_node(w->f, ca, bio, buf,
					    bucket * ca->mi.bucket_size + bucket_offset);
		}
err:
	bio_put(bio);
	free_page((unsigned long) buf);
	percpu_ref_get(&ca->io_ref);
	closure_put(w->cl);
	kfree(w);
	return 0;
}

static int read_btree_nodes(struct find_btree_nodes *f)
{
	struct bch_fs *c = container_of(f, struct bch_fs, found_btree_nodes);
	struct closure cl;
	int ret = 0;

	closure_init_stack(&cl);

	for_each_online_member(c, ca) {
		struct find_btree_nodes_worker *w = kmalloc(sizeof(*w), GFP_KERNEL);
		struct task_struct *t;

		if (!w) {
			percpu_ref_put(&ca->io_ref);
			ret = -ENOMEM;
			goto err;
		}

		percpu_ref_get(&ca->io_ref);
		closure_get(&cl);
		w->cl		= &cl;
		w->f		= f;
		w->ca		= ca;

		w->bucket_start	= ca->mi.first_bucket;
		w->bucket_end	= ca->mi.nbuckets;
		t = kthread_run(read_btree_nodes_worker, w, "read_btree_nodes/%s", ca->name);
		ret = IS_ERR_OR_NULL(t);
		if (ret) {
			percpu_ref_put(&ca->io_ref);
			closure_put(&cl);
			f->ret = ret;
			bch_err(c, "error starting kthread: %i", ret);
			break;
		}
	}
err:
	closure_sync(&cl);
	return f->ret ?: ret;
}

static void bubble_up(struct btree_trans *trans,
		      struct found_btree_node *n, struct found_btree_node *end)
{
	while (n + 1 < end &&
	       found_btree_node_cmp_pos(n, n + 1, trans) > 0) {
		swap(n[0], n[1]);
		n++;
	}
}

static int handle_overwrites(struct btree_trans *trans,
			     struct found_btree_node *start,
			     struct found_btree_node *end)
{
	struct bch_fs *c = trans->c;
	struct found_btree_node *n;
again:
	for (n = start + 1;
	     n < end &&
	     n->btree_id	== start->btree_id &&
	     n->level		== start->level &&
	     bpos_cmp(start->max_key, n->min_key) > 0;
	     n++)  {
		int cmp = found_btree_node_cmp_time(trans, start, n);

		if (cmp > 0) {
			n->range_updated = true;

			if (bpos_cmp(start->max_key, n->max_key) >= 0)
				n->overwritten = true;
			else {
				n->min_key = bpos_successor(start->max_key);
				n->range_updated = true;
				bubble_up(trans, n, end);
				goto again;
			}
		} else if (cmp < 0) {
			BUG_ON(bpos_cmp(n->min_key, start->min_key) <= 0);

			start->max_key = bpos_predecessor(n->min_key);
			start->range_updated = true;
		} else {
			struct printbuf buf = PRINTBUF;

			prt_str(&buf, "overlapping btree nodes with same seq! halting\n  ");
			found_btree_node_to_text(&buf, c, start);
			prt_str(&buf, "\n  ");
			found_btree_node_to_text(&buf, c, n);
			bch_err(c, "%s", buf.buf);
			printbuf_exit(&buf);
			return -1;
		}
	}

	return 0;
}

int bch2_scan_for_btree_nodes(struct bch_fs *c)
{
	struct find_btree_nodes *f = &c->found_btree_nodes;
	struct printbuf buf = PRINTBUF;
	size_t dst;
	int ret = 0;

	if (f->nodes.nr)
		return 0;

	mutex_init(&f->lock);

	bch_info(c, "scanning devices for btree nodes");
	ret = read_btree_nodes(f);
	if (ret)
		return ret;

	bch_info(c, "done scanning devices for btree nodes");

	if (!f->nodes.nr) {
		bch_err(c, "no btree nodes found");
		ret = -EINVAL;
		goto err;
	}

	if (c->opts.verbose) {
		printbuf_reset(&buf);
		prt_str(&buf, "Nodes found:\n");
		found_btree_nodes_to_text(&buf, c, f->nodes);
		bch2_print_string_as_lines(KERN_INFO, buf.buf);
	}

	sort(f->nodes.data, f->nodes.nr, sizeof(f->nodes.data[0]), found_btree_node_cmp_cookie, NULL);

	dst = 0;
	darray_for_each(f->nodes, i) {
		struct found_btree_node *prev = dst ? f->nodes.data + dst - 1 : NULL;

		if (prev &&
		    prev->cookie == i->cookie) {
			if (prev->nr_ptrs == ARRAY_SIZE(prev->ptrs)) {
				bch_err(c, "%s: found too many replicas for btree node", __func__);
				ret = -EINVAL;
				goto err;
			}
			prev->ptrs[prev->nr_ptrs++] = i->ptrs[0];
		} else {
			f->nodes.data[dst++] = *i;
		}
	}
	f->nodes.nr = dst;

	sort_r(f->nodes.data, f->nodes.nr, sizeof(f->nodes.data[0]), found_btree_node_cmp_pos, NULL, c);

	if (c->opts.verbose) {
		printbuf_reset(&buf);
		prt_str(&buf, "Nodes after merging replicas:\n");
		found_btree_nodes_to_text(&buf, c, f->nodes);
		bch2_print_string_as_lines(KERN_INFO, buf.buf);
	}

	dst = 0;
	darray_for_each(f->nodes, i) {
		if (i->overwritten)
			continue;

		ret = bch2_trans_run(c, handle_overwrites(trans, i, &darray_top(f->nodes)));
		if (ret)
			goto err;

		BUG_ON(i->overwritten);
		f->nodes.data[dst++] = *i;
	}
	f->nodes.nr = dst;

	if (c->opts.verbose) {
		printbuf_reset(&buf);
		prt_str(&buf, "Nodes found after overwrites:\n");
		found_btree_nodes_to_text(&buf, c, f->nodes);
		bch2_print_string_as_lines(KERN_INFO, buf.buf);
	}
err:
	printbuf_exit(&buf);
	return ret;
}

int bch2_repair_missing_btree_node(struct bch_fs *c, enum btree_id btree,
				   unsigned level, struct bpos node_min, struct bpos node_max)
{
	int ret = bch2_scan_for_btree_nodes(c);
	if (ret)
		return ret;

	darray_for_each(c->found_btree_nodes.nodes, i)
		if (i->btree_id == btree &&
		    i->level + 1 == level &&
		    bpos_ge(i->min_key, node_min) &&
		    bpos_le(i->max_key, node_max)) {
			struct { __BKEY_PADDED(k, BKEY_BTREE_PTR_VAL_U64s_MAX); } tmp;

			found_btree_node_to_key(&tmp.k, i);

			struct printbuf buf = PRINTBUF;
			bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&tmp.k));
			pr_info("recovering %s", buf.buf);
			printbuf_exit(&buf);

			ret = bch2_journal_key_insert(c, btree, level, &tmp.k);
			if (ret)
				return ret;
		}

	return 0;
}

void bch2_find_btree_nodes_exit(struct find_btree_nodes *f)
{
	darray_exit(&f->nodes);
}
