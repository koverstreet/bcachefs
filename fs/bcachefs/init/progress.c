// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/accounting.h"

#include "btree/bbpos.h"

#include "init/passes.h"
#include "init/progress.h"

void bch2_progress_init(struct progress_indicator *s,
			const char *msg,
			struct bch_fs *c,
			u64 leaf_btree_id_mask,
			u64 inner_btree_id_mask)
{
	memset(s, 0, sizeof(*s));

	s->msg = strip_bch2(msg);
	s->next_print = jiffies + HZ * 10;

	/* This is only an estimation: nodes can have different replica counts */
	const u32 expected_node_disk_sectors =
		READ_ONCE(c->opts.metadata_replicas) * btree_sectors(c);

	const u64 btree_id_mask = leaf_btree_id_mask | inner_btree_id_mask;

	for (unsigned i = 0; i < btree_id_nr_alive(c); i++) {
		if (!(btree_id_mask & BIT_ULL(i)))
			continue;

		struct disk_accounting_pos acc;
		disk_accounting_key_init(acc, btree, .id = i);

		struct {
			u64 disk_sectors;
			u64 total_nodes;
			u64 inner_nodes;
		} v = {0};
		bch2_accounting_mem_read(c, disk_accounting_pos_to_bpos(&acc),
			(u64 *)&v, sizeof(v) / sizeof(u64));

		/* Better to estimate as 0 than the total node count */
		if (inner_btree_id_mask & BIT_ULL(i))
			s->nodes_total += v.inner_nodes;

		if (!(leaf_btree_id_mask & BIT_ULL(i)))
			continue;

		/*
		 * We check for zeros to degrade gracefully when run
		 * with un-upgraded accounting info (missing some counters).
		 */
		if (v.total_nodes != 0)
			s->nodes_total += v.total_nodes - v.inner_nodes;
		else
			s->nodes_total += div_u64(v.disk_sectors, expected_node_disk_sectors);
	}
}

static inline bool progress_update_p(struct progress_indicator *s)
{
	bool ret = time_after_eq(jiffies, s->next_print);

	if (ret)
		s->next_print = jiffies + HZ * 10;
	return ret;
}

int bch2_progress_update_iter(struct btree_trans *trans,
			      struct progress_indicator *s,
			      struct btree_iter *iter)
{
	struct bch_fs *c = trans->c;

	try(bch2_recovery_cancelled(c));

	struct btree *b = path_l(btree_iter_path(trans, iter))->b;

	if (IS_ERR_OR_NULL(b))
		return 0;

	struct bbpos pos = BBPOS(b->c.btree_id, b->key.k.p);

	s->nodes_seen  += b != s->last_node && bbpos_cmp(pos, s->pos) > 0;
	s->last_node	= b;
	s->pos		= pos;

	if (!s->silent && progress_update_p(s)) {
		CLASS(printbuf, buf)();
		prt_printf(&buf, "%s ", s->msg);
		bch2_progress_to_text(&buf, s);
		bch_info(c, "%s", buf.buf);
	}

	return 0;
}

void bch2_progress_to_text(struct printbuf *out, struct progress_indicator *s)
{
	unsigned percent = s->nodes_total
		? div64_u64(s->nodes_seen * 100, s->nodes_total)
		: 0;
	prt_printf(out, "%d%%, done %llu/%llu nodes, at ",
		   percent, s->nodes_seen, s->nodes_total);
	bch2_bbpos_to_text(out, s->pos);
}
