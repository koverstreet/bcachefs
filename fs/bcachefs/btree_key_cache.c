
#include "bcachefs.h"
#include "btree_iter.h"
#include "btree_key_cache.h"

static const struct rhashtable_params bch_btree_key_cache_params = {
	.head_offset	= offsetof(struct btree_key_cache, hash),
	.key_offset	= offsetof(struct btree_key_cache, k.k.p),
	.key_len	= sizeof(struct bpos),
};

__flatten
static inline struct btree_key_cache *btree_key_cache_find(struct bch_fs *c,
						 enum btree_id btree_id,
						 struct bpos pos)
{
	return rhashtable_lookup_fast(&c->btree_key_cache[btree_id], &pos,
				      bch_btree_key_cache_params);
}

static struct btree_key_cache *
btree_key_cache_fill(struct bch_fs *c,
		     enum btree_id btree_id,
		     struct bpos pos)
{
	struct btree_key_cache *c_k;
	unsigned u64s = 64;
	int ret;

	mutex_lock(&c->btree_key_cache_lock);

	rcu_read_lock();
	c_k = btree_key_cache_find(c, btree_id, pos);
	if (c_k) {
		atomic_inc(&c_k->ref);
		rcu_read_unlock();
		return c_k;
	}
	rcu_read_unlock();

	c_k = kmalloc(offsetof(struct btree_key_cache, k) +
		      u64s * sizeof(u64), GFP_NOFS);
	if (!c_k) {
		mutex_unlock(&c->btree_key_cache_lock);
		return ERR_PTR(-ENOMEM);
	}

	memset(c_k, 0, offsetof(struct btree_key_cache, k));

	mutex_init(&c_k->lock);
	BUG_ON(!mutex_trylock(&c_k->lock));
	atomic_set(&c_k->ref, 1);

	c_k->allocated_u64s	= u64s;
	c_k->btree_id		= btree_id;
	c_k->k.k.p		= pos;

	ret = rhashtable_lookup_insert_fast(&c->btree_key_cache[btree_id],
					    &c_k->hash,
					    bch_btree_key_cache_params);
	BUG_ON(ret);

	mutex_unlock(&c->btree_key_cache_lock);

	return c_k;
}

static int btree_key_cache_read(struct btree_trans *trans,
			      struct btree_key_cache *c_k)
{
	struct btree_iter *iter;
	struct bkey_s_c k;
	int ret;

	iter = bch2_trans_get_iter(trans, c_k->btree_id, c_k->k.k.p, 0);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	k = bch2_btree_iter_peek_slot(iter);
	ret = btree_iter_err(k);
	if (ret)
		return ret;

	BUG_ON(k.k->u64s > c_k->allocated_u64s);
	bkey_reassemble(&c_k->k, k);
	c_k->read_done = true;

	bch2_trans_iter_put(trans, iter);

	return 0;
}

void bch2_btree_key_cache_put(struct bch_fs *c,
			      struct btree_key_cache *c_k)
{
	if (atomic_dec_and_test(&c_k->ref)) {
	}
}

struct btree_key_cache *
bch2_btree_key_cache_get(struct btree_trans *trans,
			 enum btree_id btree_id,
			 struct bpos pos)
{
	struct bch_fs *c = trans->c;
	struct btree_key_cache *c_k;

	rcu_read_lock();
	c_k = btree_key_cache_find(c, btree_id, pos);
	if (c_k) {
		atomic_inc(&c_k->ref);
		rcu_read_unlock();
		goto out;
	}

	rcu_read_unlock();

	c_k = btree_key_cache_fill(c, btree_id, pos);
	if (IS_ERR(c_k))
		return c_k;
out:
	if (!c_k->read_done) {
		int ret = 0;

		mutex_lock(&c_k->lock);
		if (!c_k->read_done)
			ret = btree_key_cache_read(trans, c_k);
		mutex_unlock(&c_k->lock);

		if (ret) {
			bch2_btree_key_cache_put(c, c_k);
			return ERR_PTR(ret);
		}
	}

	return c_k;
}

void bch2_btree_key_cache_exit(struct bch_fs *c)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(c->btree_key_cache); i++) {
		rhashtable_destroy(&c->btree_key_cache[i]);
	}
}

int bch2_btree_key_cache_init(struct bch_fs *c)
{
	unsigned i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(c->btree_key_cache); i++) {
		ret = rhashtable_init(&c->btree_key_cache[i],
				      &bch_btree_key_cache_params);
		if (ret)
			return ret;
	}

	return 0;
}
