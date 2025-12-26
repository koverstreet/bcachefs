// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "btree/cache.h"
#include "btree/update.h"

#include "fs/dirent.h"
#include "fs/check.h"
#include "fs/str_hash.h"

#include "snapshots/subvolume.h"

static inline struct bch_hash_info
__bch2_hash_info_init(struct bch_fs *c, const struct bch_inode_unpacked *bi)
{
	struct bch_hash_info info = {
		.inum_snapshot	= bi->bi_snapshot,
		.type		= INODE_STR_HASH(bi),
		.is_31bit	= bi->bi_flags & BCH_INODE_31bit_dirent_offset,
		.cf_encoding	= bch2_inode_casefold(c, bi) ? c->cf_encoding : NULL,
		.siphash_key	= { .k0 = bi->bi_hash_seed }
	};

	if (unlikely(info.type == BCH_STR_HASH_siphash_old)) {
		u8 digest[SHA256_DIGEST_SIZE];

		sha256((const u8 *)&bi->bi_hash_seed,
		       sizeof(bi->bi_hash_seed), digest);
		memcpy(&info.siphash_key, digest, sizeof(info.siphash_key));
	}

	return info;
}

int bch2_hash_info_init(struct bch_fs *c, const struct bch_inode_unpacked *bi,
			struct bch_hash_info *ret)
{
	if (bch2_inode_casefold(c, bi) && !c->cf_encoding)
		return bch_err_throw(c, casefold_dir_but_disabled);

	*ret = __bch2_hash_info_init(c, bi);
	return 0;
}

static int bch2_dirent_has_target(struct btree_trans *trans, struct bkey_s_c_dirent d)
{
	if (d.v->d_type == DT_SUBVOL) {
		struct bch_subvolume subvol;
		int ret = bch2_subvolume_get(trans, le32_to_cpu(d.v->d_child_subvol),
					     false, &subvol);
		if (ret && !bch2_err_matches(ret, ENOENT))
			return ret;
		return !ret;
	} else {
		CLASS(btree_iter, iter)(trans, BTREE_ID_inodes,
				SPOS(0, le64_to_cpu(d.v->d_inum), d.k->p.snapshot), 0);
		struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

		return bkey_is_inode(k.k);
	}
}

static int bch2_fsck_rename_dirent(struct btree_trans *trans,
				   struct snapshots_seen *s,
				   const struct bch_hash_desc desc,
				   struct bch_hash_info *hash_info,
				   struct bkey_s_c_dirent old,
				   bool *updated_before_k_pos)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	struct qstr old_name = bch2_dirent_get_name(old);

	struct bkey_i_dirent *new = errptr_try(bch2_trans_kmalloc(trans, BKEY_U64s_MAX * sizeof(u64)));
	bkey_dirent_init(&new->k_i);
	dirent_copy_target(new, old);
	new->k.p = old.k->p;

	char *renamed_buf = errptr_try(bch2_trans_kmalloc(trans, old_name.len + 20));

	for (unsigned i = 0; i < 1000; i++) {
		new->k.u64s = BKEY_U64s_MAX;

		struct qstr renamed_name = (struct qstr) QSTR_INIT(renamed_buf,
					sprintf(renamed_buf, "%.*s.fsck_renamed-%u",
						old_name.len, old_name.name, i));

		try(bch2_dirent_init_name(c, new, hash_info, &renamed_name, NULL));

		ret = bch2_hash_set_in_snapshot(trans, bch2_dirent_hash_desc, hash_info,
						(subvol_inum) { 0, old.k->p.inode },
						old.k->p.snapshot, &new->k_i,
						BTREE_UPDATE_internal_snapshot_node|
						STR_HASH_must_create);
		if (ret && !bch2_err_matches(ret, EEXIST))
			break;
		if (!ret) {
			if (bpos_lt(new->k.p, old.k->p))
				*updated_before_k_pos = true;
			break;
		}
	}

	ret = ret ?: bch2_fsck_update_backpointers(trans, s, desc, hash_info, &new->k_i);
	bch_err_fn(c, ret);
	return ret;
}

static noinline int hash_pick_winner(struct btree_trans *trans,
				     const struct bch_hash_desc desc,
				     struct bch_hash_info *hash_info,
				     struct bkey_s_c k1,
				     struct bkey_s_c k2)
{
	if (bkey_val_bytes(k1.k) == bkey_val_bytes(k2.k) &&
	    !memcmp(k1.v, k2.v, bkey_val_bytes(k1.k)))
		return 0;

	if (k1.k->p.snapshot != k2.k->p.snapshot)
		return k1.k->p.snapshot < k2.k->p.snapshot; /* Delete the older key from the newer snapshot */

	switch (desc.btree_id) {
	case BTREE_ID_dirents: {
		int ret = bch2_dirent_has_target(trans, bkey_s_c_to_dirent(k1));
		if (ret < 0)
			return ret;
		if (!ret)
			return 0;

		ret = bch2_dirent_has_target(trans, bkey_s_c_to_dirent(k2));
		if (ret < 0)
			return ret;
		if (!ret)
			return 1;
		return 2;
	}
	default:
		return 0;
	}
}

/*
 * str_hash lookups across snapshots break in wild ways if hash_info in
 * different snapshot versions doesn't match - so if we find one mismatch, check
 * them all
 */
int bch2_repair_inode_hash_info(struct btree_trans *trans,
				struct bch_inode_unpacked *bad_inode,
				struct bch_inode_unpacked *snapshot_root)
{
	BUG_ON(bad_inode->bi_inum != snapshot_root->bi_inum);
	BUG_ON(!bch2_snapshot_is_ancestor(trans->c, bad_inode->bi_snapshot, snapshot_root->bi_snapshot));

	CLASS(printbuf, buf)();
	prt_printf(&buf, "inum %llu: inode hash info in snapshots %u, %u mismatch\n",
		   snapshot_root->bi_inum,
		   bad_inode->bi_snapshot,
		   snapshot_root->bi_snapshot);

	bch2_prt_str_hash_type(&buf, INODE_STR_HASH(bad_inode));
	prt_printf(&buf, " %llx\n", bad_inode->bi_hash_seed);

	bch2_prt_str_hash_type(&buf, INODE_STR_HASH(snapshot_root));
	prt_printf(&buf, " %llx\n", snapshot_root->bi_hash_seed);

	bad_inode->bi_hash_seed = snapshot_root->bi_hash_seed;
	SET_INODE_STR_HASH(bad_inode, INODE_STR_HASH(snapshot_root));

	try(__bch2_fsck_write_inode(trans, bad_inode));

	bch2_trans_updates_to_text(&buf, trans);

	if (ret_fsck_err(trans, inode_snapshot_mismatch, "%s", buf.buf)) {
		try(bch2_trans_commit_lazy(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc));
	}

	return 0;
}

/*
 * All versions of the same inode in different snapshots must have the same hash
 * seed/type: verify that the hash info we're using matches the root
 */
static noinline int check_inode_hash_info_matches_root(struct btree_trans *trans, u64 inum,
						       struct bch_hash_info *hash_info,
						       bool *repaired_inode)
{
	struct bch_fs *c = trans->c;

	struct bch_inode_unpacked snapshot_root;
	try(bch2_inode_find_oldest_snapshot(trans, inum, hash_info->inum_snapshot, &snapshot_root));

	struct bch_hash_info hash_root = __bch2_hash_info_init(c, &snapshot_root);
	if (hash_info->type != hash_root.type ||
	    memcmp(&hash_info->siphash_key,
		   &hash_root.siphash_key,
		   sizeof(hash_root.siphash_key))) {
		struct bch_inode_unpacked bad_inode;
		try(bch2_inode_find_by_inum_snapshot(trans, snapshot_root.bi_inum,
						     hash_info->inum_snapshot, &bad_inode, 0));

		struct bch_hash_info hash_info_verify = __bch2_hash_info_init(c, &bad_inode);

		BUG_ON(memcmp(hash_info, &hash_info_verify, sizeof(hash_info_verify)));

		*repaired_inode = true;

		try(bch2_repair_inode_hash_info(trans, &bad_inode, &snapshot_root));

		/* unreachable, we'll always return BCH_ERR_transaction_restart_commit */
	}

	return 0;
}

static int str_hash_dup_entries(struct btree_trans *trans,
				struct snapshots_seen *s,
				const struct bch_hash_desc *desc,
				struct bch_hash_info *hash_info,
				struct bkey_s_c k, struct bkey_s_c dup_k,
				bool *updated_before_k_pos)
{
	struct bch_fs *c = trans->c;

	int ret = hash_pick_winner(trans, *desc, hash_info, k, dup_k);
	if (ret < 0)
		return ret;

	CLASS(printbuf, buf)();
	prt_str(&buf, "duplicate hash table keys");
	if (ret == 2)
		prt_str(&buf, ", both point to valid inodes");
	prt_newline(&buf);

	bch2_bkey_val_to_text(&buf, c, k);
	prt_newline(&buf);
	bch2_bkey_val_to_text(&buf, c, dup_k);

	if (!ret_fsck_err(trans, hash_table_key_duplicate, "%s", buf.buf))
		return 0;

	if (ret == 2) {
		try(bch2_fsck_rename_dirent(trans, s, *desc, hash_info,
					    bkey_s_c_to_dirent(k),
					    updated_before_k_pos));
		/* delete @k */
		ret = 1;
	}

	if (ret)
		swap(k, dup_k); /* @dup_k wins, delete @k */

	/*
	 * delete @dup_k, in @k's snapshot: if they're in different snapshots,
	 * @dup is older
	 */
	BUG_ON(dup_k.k->p.snapshot < k.k->p.snapshot);

	CLASS(btree_iter, del_iter)(trans, desc->btree_id,
				    SPOS(dup_k.k->p.inode, dup_k.k->p.offset, k.k->p.snapshot),
				    BTREE_ITER_slots);
	try(bch2_hash_delete_at(trans, *desc, hash_info, &del_iter, 0));

	return bch2_trans_commit_lazy(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc);
}

/* Put a str_hash key in its proper location, checking for duplicates */
static int bch2_str_hash_repair_key(struct btree_trans *trans,
			     struct snapshots_seen *s,
			     const struct bch_hash_desc *desc,
			     struct bch_hash_info *hash_info,
			     struct bkey_s_c k, struct bkey_s_c dup_k,
			     bool *updated_before_k_pos)
{
	CLASS(snapshots_seen, s_onstack)();

	if (!s) {
		s = &s_onstack;
		s->pos = k.k->p;

		try(bch2_get_snapshot_overwrites(trans, desc->btree_id, k.k->p, &s->ids));
	}

	if (!dup_k.k) {
		struct bkey_i *new = errptr_try(bch2_bkey_make_mut_noupdate(trans, k));

		CLASS(btree_iter_uninit, iter)(trans);
		dup_k = bkey_try(bch2_hash_set_or_get_in_snapshot(trans, &iter, *desc, hash_info,
				       (subvol_inum) { 0, new->k.p.inode },
				       new->k.p.snapshot, new,
				       STR_HASH_must_create|
				       BTREE_UPDATE_internal_snapshot_node));

		if (!dup_k.k) {
			try(bch2_insert_snapshot_whiteouts(trans, desc->btree_id,
							   k.k->p, new->k.p));

			CLASS(btree_iter, k_iter)(trans, desc->btree_id, k.k->p, BTREE_ITER_slots);
			try(bch2_hash_delete_at(trans, *desc, hash_info, &k_iter,
					    BTREE_UPDATE_internal_snapshot_node));
			try(bch2_fsck_update_backpointers(trans, s, *desc, hash_info, new));
			try(bch2_trans_commit_lazy(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc));
		}
	} else {
		try(str_hash_dup_entries(trans, s, desc, hash_info, k, dup_k, updated_before_k_pos));
	}

	return 0;
}

static int str_hash_bad_hash(struct btree_trans *trans,
			     struct snapshots_seen *s,
			     const struct bch_hash_desc *desc,
			     struct bch_hash_info *hash_info,
			     struct bkey_s_c hash_k,
			     bool *updated_before_k_pos,
			     bool *repaired_inode, u64 hash)
{
	CLASS(printbuf, buf)();
	/*
	 * Before doing any repair, check hash_info itself:
	 */
	try(check_inode_hash_info_matches_root(trans, hash_k.k->p.inode, hash_info, repaired_inode));

	if (ret_fsck_err(trans, hash_table_key_wrong_offset,
		     "hash table key at wrong offset: should be at %llu\n%s",
		     hash,
		     (bch2_bkey_val_to_text(&buf, trans->c, hash_k), buf.buf)))
		try(bch2_str_hash_repair_key(trans, s, desc, hash_info,
					     hash_k, bkey_s_c_null,
					     updated_before_k_pos));
	return 0;
}

/* XXX: should move to dirent.c */
static int str_hash_check_dirent(struct btree_trans *trans,
				 struct snapshots_seen *s,
				 struct bch_hash_info *hash_info,
				 struct bkey_s_c k,
				 bool *updated_before_k_pos)
{
	struct bch_fs *c = trans->c;
	struct bkey_s_c_dirent d = bkey_s_c_to_dirent(k);

	CLASS(printbuf, buf)();
	if (ret_fsck_err_on(d.v->d_casefold != !!hash_info->cf_encoding,
			trans, dirent_casefold_mismatch,
			"dirent casefold does not match dir casefold\n%s",
			(bch2_bkey_val_to_text(&buf, c, k),
			 buf.buf))) {
		subvol_inum dir_inum = { .subvol = d.v->d_type == DT_SUBVOL
				? le32_to_cpu(d.v->d_parent_subvol)
				: 0,
		};
		u64 target = d.v->d_type == DT_SUBVOL
			? le32_to_cpu(d.v->d_child_subvol)
			: le64_to_cpu(d.v->d_inum);
		struct qstr name = bch2_dirent_get_name(d);

		struct bkey_i_dirent *new_d =
			errptr_try(bch2_dirent_create_key(trans, hash_info, dir_inum,
					       d.v->d_type, &name, NULL, target));

		new_d->k.p.inode	= d.k->p.inode;
		new_d->k.p.snapshot	= d.k->p.snapshot;

		CLASS(btree_iter, iter)(trans, BTREE_ID_dirents, k.k->p, BTREE_ITER_slots);
		try(bch2_hash_delete_at(trans,
					bch2_dirent_hash_desc, hash_info, &iter,
					BTREE_UPDATE_internal_snapshot_node));
		try(bch2_str_hash_repair_key(trans, s,
					     &bch2_dirent_hash_desc, hash_info,
					     bkey_i_to_s_c(&new_d->k_i), bkey_s_c_null,
					     updated_before_k_pos));

		/* skip this key, it moved */
		return 1;
	}

	return 0;
}

int __bch2_str_hash_check_key(struct btree_trans *trans,
			      struct snapshots_seen *s,
			      const struct bch_hash_desc *desc,
			      struct bch_hash_info *hash_info,
			      struct bkey_s_c hash_k,
			      bool *updated_before_k_pos,
			      bool *repaired_inode)
{
	u64 hash = desc->hash_bkey(hash_info, hash_k);

	if (hash_k.k->p.offset < hash)
		return str_hash_bad_hash(trans, s, desc, hash_info, hash_k,
					 updated_before_k_pos, repaired_inode, hash);

	struct bkey_s_c k;
	int ret = 0;
	for_each_btree_key_norestart(trans, iter, desc->btree_id,
				     SPOS(hash_k.k->p.inode, hash, hash_k.k->p.snapshot),
				     BTREE_ITER_slots, k, ret) {
		if (bkey_eq(k.k->p, hash_k.k->p))
			break;

		if (k.k->type == desc->key_type &&
		    !desc->cmp_bkey(k, hash_k)) {
			/* dup */
			try(check_inode_hash_info_matches_root(trans, hash_k.k->p.inode, hash_info,
							       repaired_inode));
			try(bch2_str_hash_repair_key(trans, s, desc, hash_info,
						     hash_k, k, updated_before_k_pos));
			break;
		}

		if (bkey_deleted(k.k))
			return str_hash_bad_hash(trans, s, desc, hash_info, hash_k,
						 updated_before_k_pos, repaired_inode, hash);
	}
	if (ret)
		return ret;

	switch (k.k->type) {
	case KEY_TYPE_dirent:
		try(str_hash_check_dirent(trans, s, hash_info, hash_k,
					  updated_before_k_pos));
		break;
	}

	return 0;
}
