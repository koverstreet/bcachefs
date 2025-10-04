/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ALLOC_CHECK_H
#define _BCACHEFS_ALLOC_CHECK_H

int bch2_need_discard_or_freespace_err(struct btree_trans *, struct bkey_s_c, bool, bool, bool);

#define need_discard_or_freespace_err(...)		\
	fsck_err_wrap(bch2_need_discard_or_freespace_err(__VA_ARGS__))

#define need_discard_or_freespace_err_on(cond, ...)		\
	(unlikely(cond) ?  need_discard_or_freespace_err(__VA_ARGS__) : false)

int __bch2_check_discard_freespace_key(struct btree_trans *, struct btree_iter *, u8 *,
				       enum bch_fsck_flags);

static inline int bch2_check_discard_freespace_key_async(struct btree_trans *trans, struct btree_iter *iter, u8 *gen)
{
	return __bch2_check_discard_freespace_key(trans, iter, gen, FSCK_ERR_NO_LOG);
}

int bch2_check_alloc_info(struct bch_fs *);
int bch2_check_alloc_to_lru_refs(struct bch_fs *);

int bch2_dev_freespace_init(struct bch_fs *, struct bch_dev *, u64, u64);
int bch2_fs_freespace_init(struct bch_fs *);

#endif /* _BCACHEFS_ALLOC_CHECK_H */

