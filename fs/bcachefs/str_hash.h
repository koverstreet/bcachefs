#ifndef _BCACHEFS_STR_HASH_H
#define _BCACHEFS_STR_HASH_H

#include "btree_iter.h"
#include "btree_update.h"
#include "checksum.h"
#include "error.h"
#include "inode.h"
#include "siphash.h"
#include "super.h"

#include <linux/crc32c.h>
#include <crypto/hash.h>

struct bch_hash_info {
	u8			type;
	union {
		__le64		crc_key;
		SIPHASH_KEY	siphash_key;
	};
};

static inline struct bch_hash_info
bch2_hash_info_init(struct bch_fs *c,
		   const struct bch_inode_unpacked *bi)
{
	/* XXX ick */
	struct bch_hash_info info = {
		.type = (bi->bi_flags >> INODE_STR_HASH_OFFSET) &
			~(~0U << INODE_STR_HASH_BITS)
	};

	switch (info.type) {
	case BCH_STR_HASH_CRC32C:
	case BCH_STR_HASH_CRC64:
		info.crc_key = bi->bi_hash_seed;
		break;
	case BCH_STR_HASH_SIPHASH: {
		SHASH_DESC_ON_STACK(desc, c->sha256);
		u8 digest[crypto_shash_digestsize(c->sha256)];

		desc->tfm = c->sha256;
		desc->flags = 0;

		crypto_shash_digest(desc, (void *) &bi->bi_hash_seed,
				    sizeof(bi->bi_hash_seed), digest);
		memcpy(&info.siphash_key, digest, sizeof(info.siphash_key));
		break;
	}
	default:
		BUG();
	}

	return info;
}

struct bch_str_hash_ctx {
	union {
		u32		crc32c;
		u64		crc64;
		SIPHASH_CTX	siphash;
	};
};

static inline void bch2_str_hash_init(struct bch_str_hash_ctx *ctx,
				     const struct bch_hash_info *info)
{
	switch (info->type) {
	case BCH_STR_HASH_CRC32C:
		ctx->crc32c = crc32c(~0, &info->crc_key, sizeof(info->crc_key));
		break;
	case BCH_STR_HASH_CRC64:
		ctx->crc64 = bch2_crc64_update(~0, &info->crc_key, sizeof(info->crc_key));
		break;
	case BCH_STR_HASH_SIPHASH:
		SipHash24_Init(&ctx->siphash, &info->siphash_key);
		break;
	default:
		BUG();
	}
}

static inline void bch2_str_hash_update(struct bch_str_hash_ctx *ctx,
				       const struct bch_hash_info *info,
				       const void *data, size_t len)
{
	switch (info->type) {
	case BCH_STR_HASH_CRC32C:
		ctx->crc32c = crc32c(ctx->crc32c, data, len);
		break;
	case BCH_STR_HASH_CRC64:
		ctx->crc64 = bch2_crc64_update(ctx->crc64, data, len);
		break;
	case BCH_STR_HASH_SIPHASH:
		SipHash24_Update(&ctx->siphash, data, len);
		break;
	default:
		BUG();
	}
}

static inline u64 bch2_str_hash_end(struct bch_str_hash_ctx *ctx,
				   const struct bch_hash_info *info)
{
	switch (info->type) {
	case BCH_STR_HASH_CRC32C:
		return ctx->crc32c;
	case BCH_STR_HASH_CRC64:
		return ctx->crc64 >> 1;
	case BCH_STR_HASH_SIPHASH:
		return SipHash24_End(&ctx->siphash) >> 1;
	default:
		BUG();
	}
}

struct bch_hash_desc {
	enum btree_id	btree_id;
	u8		key_type;
	u8		whiteout_type;

	u64		(*hash_key)(const struct bch_hash_info *, const void *);
	u64		(*hash_bkey)(const struct bch_hash_info *, struct bkey_s_c);
	bool		(*cmp_key)(struct bkey_s_c, const void *);
	bool		(*cmp_bkey)(struct bkey_s_c, struct bkey_s_c);
};

static inline struct bkey_s_c
bch2_hash_lookup_at(const struct bch_hash_desc desc,
		   const struct bch_hash_info *info,
		   struct btree_iter *iter, const void *search)
{
	u64 inode = iter->pos.inode;
	struct bkey_s_c k;

	for_each_btree_key_continue(iter, BTREE_ITER_SLOTS, k) {
		if (iter->pos.inode != inode)
			break;

		if (k.k->type == desc.key_type) {
			if (!desc.cmp_key(k, search))
				return k;
		} else if (k.k->type == desc.whiteout_type) {
			;
		} else {
			/* hole, not found */
			break;
		}
	}
	return btree_iter_err(k) ? k : bkey_s_c_err(-ENOENT);
}

static inline struct bkey_s_c
bch2_hash_lookup_bkey_at(const struct bch_hash_desc desc,
			const struct bch_hash_info *info,
			struct btree_iter *iter, struct bkey_s_c search)
{
	u64 inode = iter->pos.inode;
	struct bkey_s_c k;

	for_each_btree_key_continue(iter, BTREE_ITER_SLOTS, k) {
		if (iter->pos.inode != inode)
			break;

		if (k.k->type == desc.key_type) {
			if (!desc.cmp_bkey(k, search))
				return k;
		} else if (k.k->type == desc.whiteout_type) {
			;
		} else {
			/* hole, not found */
			break;
		}
	}
	return btree_iter_err(k) ? k : bkey_s_c_err(-ENOENT);
}

static inline struct bkey_s_c
bch2_hash_lookup(const struct bch_hash_desc desc,
		const struct bch_hash_info *info,
		struct bch_fs *c, u64 inode,
		struct btree_iter *iter, const void *key)
{
	bch2_btree_iter_init(iter, c, desc.btree_id,
			    POS(inode, desc.hash_key(info, key)),
			    BTREE_ITER_SLOTS);

	return bch2_hash_lookup_at(desc, info, iter, key);
}

static inline struct bkey_s_c
bch2_hash_lookup_intent(const struct bch_hash_desc desc,
		       const struct bch_hash_info *info,
		       struct bch_fs *c, u64 inode,
		       struct btree_iter *iter, const void *key)
{
	bch2_btree_iter_init(iter, c, desc.btree_id,
			     POS(inode, desc.hash_key(info, key)),
			     BTREE_ITER_SLOTS|BTREE_ITER_INTENT);

	return bch2_hash_lookup_at(desc, info, iter, key);
}

static inline struct bkey_s_c
bch2_hash_hole_at(const struct bch_hash_desc desc, struct btree_iter *iter)
{
	u64 inode = iter->pos.inode;
	struct bkey_s_c k;

	for_each_btree_key_continue(iter, BTREE_ITER_SLOTS, k) {
		if (iter->pos.inode != inode)
			break;

		if (k.k->type != desc.key_type)
			return k;
	}
	return btree_iter_err(k) ? k : bkey_s_c_err(-ENOENT);
}

static inline struct bkey_s_c bch2_hash_hole(const struct bch_hash_desc desc,
					    const struct bch_hash_info *info,
					    struct bch_fs *c, u64 inode,
					    struct btree_iter *iter,
					    const void *key)
{
	bch2_btree_iter_init(iter, c, desc.btree_id,
			     POS(inode, desc.hash_key(info, key)),
			     BTREE_ITER_SLOTS|BTREE_ITER_INTENT);

	return bch2_hash_hole_at(desc, iter);
}

static inline int bch2_hash_needs_whiteout(const struct bch_hash_desc desc,
					   const struct bch_hash_info *info,
					   struct btree_iter *iter,
					   struct btree_iter *start)
{
	struct bkey_s_c k;

	bch2_btree_iter_next_slot(iter);

	for_each_btree_key_continue(iter, BTREE_ITER_SLOTS, k) {
		if (k.k->type != desc.key_type &&
		    k.k->type != desc.whiteout_type)
			return false;

		if (k.k->type == desc.key_type &&
		    desc.hash_bkey(info, k) <= start->pos.offset)
			return true;
	}
	return btree_iter_err(k);
}

static inline int bch2_hash_set(const struct bch_hash_desc desc,
			       const struct bch_hash_info *info,
			       struct bch_fs *c, u64 inode,
			       u64 *journal_seq,
			       struct bkey_i *insert, int flags)
{
	struct btree_iter iter, hashed_slot;
	struct bkey_s_c k;
	int ret;

	bch2_btree_iter_init(&hashed_slot, c, desc.btree_id,
		POS(inode, desc.hash_bkey(info, bkey_i_to_s_c(insert))),
		BTREE_ITER_SLOTS|BTREE_ITER_INTENT);
	bch2_btree_iter_init(&iter, c, desc.btree_id, hashed_slot.pos,
			     BTREE_ITER_SLOTS|BTREE_ITER_INTENT);
	bch2_btree_iter_link(&hashed_slot, &iter);
retry:
	/*
	 * On hash collision, we have to keep the slot we hashed to locked while
	 * we do the insert - to avoid racing with another thread deleting
	 * whatever's in the slot we hashed to:
	 */
	ret = bch2_btree_iter_traverse(&hashed_slot);
	if (ret)
		goto err;

	/*
	 * On -EINTR/retry, we dropped locks - always restart from the slot we
	 * hashed to:
	 */
	bch2_btree_iter_copy(&iter, &hashed_slot);

	k = bch2_hash_lookup_bkey_at(desc, info, &iter, bkey_i_to_s_c(insert));

	ret = btree_iter_err(k);
	if (ret == -ENOENT) {
		if (flags & BCH_HASH_SET_MUST_REPLACE) {
			ret = -ENOENT;
			goto err;
		}

		/*
		 * Not found, so we're now looking for any open
		 * slot - we might have skipped over a whiteout
		 * that we could have used, so restart from the
		 * slot we hashed to:
		 */
		bch2_btree_iter_copy(&iter, &hashed_slot);
		k = bch2_hash_hole_at(desc, &iter);
		if ((ret = btree_iter_err(k)))
			goto err;
	} else if (!ret) {
		if (flags & BCH_HASH_SET_MUST_CREATE) {
			ret = -EEXIST;
			goto err;
		}
	} else {
		goto err;
	}

	insert->k.p = iter.pos;
	ret = bch2_btree_insert_at(c, NULL, NULL, journal_seq,
				  BTREE_INSERT_ATOMIC|flags,
				  BTREE_INSERT_ENTRY(&iter, insert));
err:
	if (ret == -EINTR)
		goto retry;

	/*
	 * On successful insert, we don't want to clobber ret with error from
	 * iter:
	 */
	bch2_btree_iter_unlock(&iter);
	bch2_btree_iter_unlock(&hashed_slot);
	return ret;
}

static inline int bch2_hash_delete_at(const struct bch_hash_desc desc,
				      const struct bch_hash_info *info,
				      struct btree_iter *iter,
				      u64 *journal_seq)
{
	struct btree_iter whiteout_iter;
	struct bkey_i delete;
	int ret = -ENOENT;

	bch2_btree_iter_init(&whiteout_iter, iter->c, desc.btree_id,
			     iter->pos, BTREE_ITER_SLOTS);
	bch2_btree_iter_link(iter, &whiteout_iter);

	ret = bch2_hash_needs_whiteout(desc, info, &whiteout_iter, iter);
	if (ret < 0)
		goto err;

	bkey_init(&delete.k);
	delete.k.p = iter->pos;
	delete.k.type = ret ? desc.whiteout_type : KEY_TYPE_DELETED;

	ret = bch2_btree_insert_at(iter->c, NULL, NULL, journal_seq,
				  BTREE_INSERT_NOFAIL|
				  BTREE_INSERT_ATOMIC,
				  BTREE_INSERT_ENTRY(iter, &delete));
err:
	bch2_btree_iter_unlink(&whiteout_iter);
	return ret;
}

static inline int bch2_hash_delete(const struct bch_hash_desc desc,
				  const struct bch_hash_info *info,
				  struct bch_fs *c, u64 inode,
				  u64 *journal_seq, const void *key)
{
	struct btree_iter iter, whiteout_iter;
	struct bkey_s_c k;
	int ret = -ENOENT;

	bch2_btree_iter_init(&iter, c, desc.btree_id,
			     POS(inode, desc.hash_key(info, key)),
			     BTREE_ITER_SLOTS|BTREE_ITER_INTENT);
	bch2_btree_iter_init(&whiteout_iter, c, desc.btree_id,
			    POS(inode, desc.hash_key(info, key)),
			    BTREE_ITER_SLOTS);
	bch2_btree_iter_link(&iter, &whiteout_iter);
retry:
	k = bch2_hash_lookup_at(desc, info, &iter, key);
	if ((ret = btree_iter_err(k)))
		goto err;

	ret = bch2_hash_delete_at(desc, info, &iter, journal_seq);
err:
	if (ret == -EINTR)
		goto retry;

	bch2_btree_iter_unlock(&whiteout_iter);
	bch2_btree_iter_unlock(&iter);
	return ret;
}

#endif /* _BCACHEFS_STR_HASH_H */
