
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

#include <linux/stat.h>

struct bkey_i *btree_root_find(struct bch_fs *c,
			       struct bch_sb_field_clean *clean,
			       struct jset *j,
			       enum btree_id id, unsigned *level)
{
	struct bkey_i *k;
	struct jset_entry *entry, *start, *end;

	if (clean) {
		start = clean->start;
		end = vstruct_end(&clean->field);
	} else {
		start = j->start;
		end = vstruct_last(j);
	}

	for (entry = start; entry < end; entry = vstruct_next(entry))
		if (entry->type == BCH_JSET_ENTRY_btree_root &&
		    entry->btree_id == id)
			goto found;

	return NULL;
found:
	if (!entry->u64s)
		return ERR_PTR(-EINVAL);

	k = entry->start;
	*level = entry->level;
	return k;
}

static int verify_superblock_clean(struct bch_fs *c,
				   struct bch_sb_field_clean *clean,
				   struct jset *j)
{
	unsigned i;
	int ret = 0;

	if (!clean || !j)
		return 0;

	if (mustfix_fsck_err_on(j->seq != clean->journal_seq, c,
			"superblock journal seq (%llu) doesn't match journal (%llu) after clean shutdown",
			le64_to_cpu(clean->journal_seq),
			le64_to_cpu(j->seq)))
		bch2_fs_mark_clean(c, false);

	mustfix_fsck_err_on(j->read_clock != clean->read_clock, c,
			"superblock read clock doesn't match journal after clean shutdown");
	mustfix_fsck_err_on(j->write_clock != clean->write_clock, c,
			"superblock read clock doesn't match journal after clean shutdown");

	for (i = 0; i < BTREE_ID_NR; i++) {
		struct bkey_i *k1, *k2;
		unsigned l1, l2;

		k1 = btree_root_find(c, clean, NULL, i, &l1);
		k2 = btree_root_find(c, NULL, j, i, &l2);

		if (!k1 && !k2)
			continue;

		if (!k1 || !k2 ||
		    k1->k.u64s != k2->k.u64s ||
		    memcmp(k1, k2, bkey_bytes(k1)) ||
		    l1 != l2)
			panic("k1 %px l1 %u k2 %px l2 %u\n", k1, l1, k2, l2);

		mustfix_fsck_err_on(!k1 || !k2 ||
				    k1->k.u64s != k2->k.u64s ||
				    memcmp(k1, k2, bkey_bytes(k1)) ||
				    l1 != l2, c,
			"superblock btree root doesn't match journal after clean shutdown");
	}
fsck_err:
	return ret;
}

static bool journal_empty(struct list_head *journal)
{
	struct journal_replay *i;
	struct jset_entry *entry;

	if (list_empty(journal))
		return true;

	i = list_last_entry(journal, struct journal_replay, list);

	if (i->j.last_seq != i->j.seq)
		return false;

	list_for_each_entry(i, journal, list) {
		vstruct_for_each(&i->j, entry) {
			if (entry->type == BCH_JSET_ENTRY_btree_root)
				continue;

			if (entry->type == BCH_JSET_ENTRY_btree_keys &&
			    !entry->u64s)
				continue;
			return false;
		}
	}

	return true;
}

int bch2_fs_recovery(struct bch_fs *c)
{
	const char *err = "cannot allocate memory";
	struct bch_sb_field_clean *clean = NULL, *sb_clean = NULL;
	LIST_HEAD(journal);
	struct jset *j = NULL;
	unsigned i;
	int ret;

	mutex_lock(&c->sb_lock);
	if (!bch2_sb_get_replicas(c->disk_sb.sb)) {
		bch_info(c, "building replicas info");
		set_bit(BCH_FS_REBUILD_REPLICAS, &c->flags);
	}

	if (c->sb.clean)
		sb_clean = bch2_sb_get_clean(c->disk_sb.sb);
	if (sb_clean) {
		clean = kmemdup(sb_clean, vstruct_bytes(&sb_clean->field),
				GFP_KERNEL);
		if (!clean) {
			ret = -ENOMEM;
			mutex_unlock(&c->sb_lock);
			goto err;
		}
	}
	mutex_unlock(&c->sb_lock);

	if (clean)
		bch_info(c, "recovering from clean shutdown, journal seq %llu",
			 le64_to_cpu(clean->journal_seq));

	if (!clean || !c->opts.nofsck) {
		ret = bch2_journal_read(c, &journal);
		if (ret)
			goto err;

		j = &list_entry(journal.prev, struct journal_replay, list)->j;
	} else {
		ret = bch2_journal_set_seq(c,
					   le64_to_cpu(clean->journal_seq),
					   le64_to_cpu(clean->journal_seq));
		BUG_ON(ret);
	}

	ret = verify_superblock_clean(c, clean, j);
	if (ret)
		goto err;

	fsck_err_on(clean && !journal_empty(&journal), c,
		    "filesystem marked clean but journal not empty");

	if (clean) {
		c->bucket_clock[READ].hand = le16_to_cpu(clean->read_clock);
		c->bucket_clock[WRITE].hand = le16_to_cpu(clean->write_clock);
	} else {
		c->bucket_clock[READ].hand = le16_to_cpu(j->read_clock);
		c->bucket_clock[WRITE].hand = le16_to_cpu(j->write_clock);
	}

	for (i = 0; i < BTREE_ID_NR; i++) {
		unsigned level;
		struct bkey_i *k;

		k = btree_root_find(c, clean, j, i, &level);
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
	 * Mark dirty before journal replay, fsck:
	 * XXX: after a clean shutdown, this could be done lazily only when fsck
	 * finds an error
	 */
	bch2_fs_mark_clean(c, false);

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
	kfree(clean);
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

	mutex_lock(&c->sb_lock);
	SET_BCH_SB_INITIALIZED(c->disk_sb.sb, true);
	SET_BCH_SB_CLEAN(c->disk_sb.sb, false);

	bch2_write_super(c);
	mutex_unlock(&c->sb_lock);

	return 0;
err:
	BUG_ON(!ret);
	return ret;
}
