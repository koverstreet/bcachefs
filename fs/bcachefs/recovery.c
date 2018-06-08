
#include "bcachefs.h"
#include "alloc.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "btree_io.h"
#include "error.h"
#include "fsck.h"
#include "journal_io.h"
#include "quota.h"
#include "recovery.h"
#include "super-io.h"

int bch2_fs_recovery(struct bch_fs *c)
{
	const char *err = "cannot allocate memory";
	LIST_HEAD(journal);
	struct jset *j;
	unsigned i;
	int ret;

	mutex_lock(&c->sb_lock);
	if (!bch2_sb_get_replicas(c->disk_sb.sb)) {
		bch_info(c, "building replicas info");
		set_bit(BCH_FS_REBUILD_REPLICAS, &c->flags);
	}
	mutex_unlock(&c->sb_lock);

	ret = bch2_journal_read(c, &journal);
	if (ret)
		goto err;

	j = &list_entry(journal.prev, struct journal_replay, list)->j;

	c->bucket_clock[READ].hand = le16_to_cpu(j->read_clock);
	c->bucket_clock[WRITE].hand = le16_to_cpu(j->write_clock);

	for (i = 0; i < BTREE_ID_NR; i++) {
		unsigned level;
		struct bkey_i *k;

		k = bch2_journal_find_btree_root(c, j, i, &level);
		if (!k)
			continue;

		err = "invalid btree root pointer";
		if (IS_ERR(k))
			goto err;

		err = "error reading btree root";
		if (bch2_btree_root_read(c, i, k, level)) {
			if (i != BTREE_ID_ALLOC)
				goto err;

			mustfix_fsck_err(c, "error reading btree root");
		}
	}

	for (i = 0; i < BTREE_ID_NR; i++)
		if (!c->btree_roots[i].b)
			bch2_btree_root_alloc(c, i);

	err = "error reading allocation information";
	ret = bch2_alloc_read(c, &journal);
	if (ret)
		goto err;

	set_bit(BCH_FS_ALLOC_READ_DONE, &c->flags);

	bch_verbose(c, "starting mark and sweep:");
	err = "error in recovery";
	ret = bch2_initial_gc(c, &journal);
	if (ret)
		goto err;
	bch_verbose(c, "mark and sweep done");

	if (c->opts.noreplay)
		goto out;

	/*
	 * bch2_fs_journal_start() can't happen sooner, or btree_gc_finish()
	 * will give spurious errors about oldest_gen > bucket_gen -
	 * this is a hack but oh well.
	 */
	bch2_fs_journal_start(&c->journal);

	err = "error starting allocator";
	if (bch2_fs_allocator_start(c))
		goto err;

	bch_verbose(c, "starting journal replay:");
	err = "journal replay failed";
	ret = bch2_journal_replay(c, &journal);
	if (ret)
		goto err;
	bch_verbose(c, "journal replay done");

	if (c->opts.norecovery)
		goto out;

	bch_verbose(c, "starting fsck:");
	err = "error in fsck";
	ret = bch2_fsck(c, !c->opts.nofsck);
	if (ret)
		goto err;
	bch_verbose(c, "fsck done");

	if (enabled_qtypes(c)) {
		bch_verbose(c, "reading quotas:");
		ret = bch2_fs_quota_read(c);
		if (ret)
			goto err;
		bch_verbose(c, "quotas done");
	}

out:
	bch2_journal_entries_free(&journal);
	return ret;
err:
fsck_err:
	BUG_ON(!ret);
	goto out;
}

int bch2_fs_initialize(struct bch_fs *c)
{
	struct bch_inode_unpacked inode;
	struct bkey_inode_buf packed_inode;
	const char *err = "cannot allocate memory";
	struct bch_dev *ca;
	LIST_HEAD(journal);
	unsigned i;
	int ret;

	bch_notice(c, "initializing new filesystem");

	set_bit(BCH_FS_ALLOC_READ_DONE, &c->flags);

	ret = bch2_initial_gc(c, &journal);
	if (ret)
		goto err;

	err = "unable to allocate journal buckets";
	for_each_online_member(ca, c, i)
		if (bch2_dev_journal_alloc(ca)) {
			percpu_ref_put(&ca->io_ref);
			goto err;
		}

	for (i = 0; i < BTREE_ID_NR; i++)
		bch2_btree_root_alloc(c, i);

	/*
	 * journal_res_get() will crash if called before this has
	 * set up the journal.pin FIFO and journal.cur pointer:
	 */
	bch2_fs_journal_start(&c->journal);
	bch2_journal_set_replay_done(&c->journal);

	err = "error starting allocator";
	if (bch2_fs_allocator_start(c))
		goto err;

	bch2_inode_init(c, &inode, 0, 0,
			S_IFDIR|S_IRWXU|S_IRUGO|S_IXUGO, 0, NULL);
	inode.bi_inum = BCACHEFS_ROOT_INO;

	bch2_inode_pack(&packed_inode, &inode);

	err = "error creating root directory";
	if (bch2_btree_insert(c, BTREE_ID_INODES,
			      &packed_inode.inode.k_i,
			      NULL, NULL, NULL, 0))
		goto err;

	if (enabled_qtypes(c)) {
		ret = bch2_fs_quota_read(c);
		if (ret)
			goto err;
	}

	err = "error writing first journal entry";
	if (bch2_journal_meta(&c->journal))
		goto err;

	return 0;
err:
	BUG_ON(!ret);
	return ret;
}
