// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "btree/cache.h"
#include "btree/init.h"
#include "btree/interior.h"
#include "btree/key_cache.h"
#include "btree/node_scan.h"
#include "btree/read.h"
#include "btree/sort.h"
#include "btree/write.h"
#include "btree/write_buffer.h"

void bch2_fs_btree_exit(struct bch_fs *c)
{
	bch2_find_btree_nodes_exit(&c->btree.node_scan);
	bch2_fs_btree_write_buffer_exit(c);
	bch2_fs_btree_key_cache_exit(&c->btree.key_cache);
	bch2_fs_btree_iter_exit(c);
	bch2_fs_btree_interior_update_exit(c);
	bch2_fs_btree_cache_exit(c);

	if (c->btree.read_complete_wq)
		destroy_workqueue(c->btree.read_complete_wq);
	if (c->btree.write_submit_wq)
		destroy_workqueue(c->btree.write_submit_wq);
	if (c->btree.write_complete_wq)
		destroy_workqueue(c->btree.write_complete_wq);

	mempool_exit(&c->btree.bounce_pool);
	bioset_exit(&c->btree.bio);
	mempool_exit(&c->btree.fill_iter);
}

void bch2_fs_btree_init_early(struct bch_fs *c)
{
	bch2_fs_btree_cache_init_early(&c->btree.cache);
	bch2_fs_btree_interior_update_init_early(c);
	bch2_fs_btree_iter_init_early(c);
	bch2_fs_btree_write_buffer_init_early(c);
	bch2_find_btree_nodes_init(&c->btree.node_scan);
}

int bch2_fs_btree_init(struct bch_fs *c)
{
	c->btree.foreground_merge_threshold = BTREE_FOREGROUND_MERGE_THRESHOLD(c);

	unsigned iter_size = sizeof(struct sort_iter) +
		(btree_blocks(c) + 1) * 2 *
		sizeof(struct sort_iter_set);

	if (!(c->btree.read_complete_wq = alloc_workqueue("bcachefs_btree_read_complete",
				WQ_HIGHPRI|WQ_FREEZABLE|WQ_MEM_RECLAIM, 512)) ||
	    mempool_init_kmalloc_pool(&c->btree.fill_iter, 1, iter_size) ||
	    bioset_init(&c->btree.bio, 1,
			max(offsetof(struct btree_read_bio, bio),
			    offsetof(struct btree_write_bio, wbio.bio)),
			BIOSET_NEED_BVECS) ||
	    mempool_init_kvmalloc_pool(&c->btree.bounce_pool, 1,
				       c->opts.btree_node_size))
		return bch_err_throw(c, ENOMEM_fs_other_alloc);

	try(bch2_fs_btree_cache_init(c));
	try(bch2_fs_btree_iter_init(c));
	try(bch2_fs_btree_key_cache_init(&c->btree.key_cache));

	c->btree.read_errors_soft = (struct ratelimit_state)
		RATELIMIT_STATE_INIT(btree_read_error_soft,
				     DEFAULT_RATELIMIT_INTERVAL,
				     DEFAULT_RATELIMIT_BURST);
	c->btree.read_errors_hard = (struct ratelimit_state)
		RATELIMIT_STATE_INIT(btree_read_error_hard,
				     DEFAULT_RATELIMIT_INTERVAL,
				     DEFAULT_RATELIMIT_BURST);

	return 0;
}

int bch2_fs_btree_init_rw(struct bch_fs *c)
{
	if (!(c->btree.write_submit_wq = alloc_workqueue("bcachefs_btree_write_sumit",
				WQ_HIGHPRI|WQ_FREEZABLE|WQ_MEM_RECLAIM, 1)) ||
	    !(c->btree.write_complete_wq = alloc_workqueue("bcachefs_btree_write_complete",
				WQ_HIGHPRI|WQ_FREEZABLE|WQ_MEM_RECLAIM, 1)))
		return bch_err_throw(c, ENOMEM_fs_other_alloc);

	try(bch2_fs_btree_interior_update_init(c));
	try(bch2_fs_btree_write_buffer_init(c));

	return 0;
}
