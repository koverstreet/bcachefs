// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "buckets_waiting_for_journal.h"
#include <linux/jhash.h>

static u32 hash_seeds[] = {
	2168153708,
	1262039142,
	1183479835,
};

static inline unsigned bucket_hash(u64 dev_bucket, unsigned hash_seed_idx)
{
	return jhash_2words(dev_bucket << 32, dev_bucket, hash_seeds[hash_seed_idx]);
}

bool bch2_bucket_needs_journal_commit(struct bch_fs *c,
				      u64 flushed_seq,
				      unsigned dev, u64 bucket)
{
	struct buckets_waiting_for_journal *b = &c->buckets_waiting_for_journal;
	u64 dev_bucket = (u64) dev << 56 | bucket;
	bool ret = false;
	unsigned i;

	mutex_lock(&b->lock);
	BUG_ON(!is_power_of_2(b->nr));

	for (i = 0; i < ARRAY_SIZE(hash_seeds); i++) {
		u32 h = bucket_hash(dev_bucket, i) & (b->nr - 1);

		if (b->d[h].dev_bucket == dev_bucket) {
			ret = b->d[h].journal_seq > flushed_seq;
			break;
		}
	}

	mutex_unlock(&b->lock);

	return ret;
}

static int bch2_buckets_waiting_for_journal_rehash(struct bch_fs *c)
{
	struct buckets_waiting_for_journal *b = &c->buckets_waiting_for_journal;
	u64 flushed_seq = c->journal.flushed_seq_ondisk;
	unsigned i, j, h, new_nr = b->nr * 2, elements = 0;
	struct bucket_hashed *new_table;

	new_table = kvmalloc_array(new_nr, sizeof(*new_table), __GFP_ZERO);
	if (!new_table)
		return -ENOMEM;

	for (i = 0; i < b->nr; i++) {
		if (b->d[i].journal_seq < flushed_seq)
			continue;

		for (j = 0; j < ARRAY_SIZE(hash_seeds); j++) {
			h = bucket_hash(b->d[i].dev_bucket, j);
			if ((h & (b->nr - 1)) == i)
				break;
		}

		BUG_ON(j == ARRAY_SIZE(hash_seeds));
		BUG_ON(new_table[h & (new_nr - 1)].dev_bucket);

		new_table[h & (new_nr - 1)] = b->d[i];

		elements++;
	}

	kvfree(b->d);
	b->nr	= new_nr;
	b->d	= new_table;
	return 0;
}

int bch2_set_bucket_needs_journal_commit(struct bch_fs *c, unsigned dev, u64 bucket,
					 u64 journal_seq)
{
	struct buckets_waiting_for_journal *b = &c->buckets_waiting_for_journal;
	struct bucket_hashed new = {
		.dev_bucket	= (u64) dev << 56 | bucket,
		.journal_seq	= journal_seq,
	}, *last_evicted = NULL;
	u64 flushed_seq = c->journal.flushed_seq_ondisk;
	unsigned tries, i;
	int ret = 0;

	mutex_lock(&b->lock);
	BUG_ON(!is_power_of_2(b->nr));
retry:
	for (tries = 0; tries < 5; tries++) {
		struct bucket_hashed *old, *victim = NULL;

		for (i = 0; i < ARRAY_SIZE(hash_seeds); i++) {
			old = b->d + (bucket_hash(new.dev_bucket, i) & (b->nr - 1));

			if (old->dev_bucket == new.dev_bucket ||
			    old->journal_seq <= flushed_seq) {
				*old = new;
				goto out;
			}

			if (last_evicted != old)
				victim = old;
		}

		/* hashed to same slot 3 times: */
		if (!victim)
			break;

		/* Failed to find an empty slot: */
		swap(new, *victim);
		last_evicted = victim;
	}

	ret = bch2_buckets_waiting_for_journal_rehash(c);
	if (!ret)
		goto retry;
out:
	mutex_unlock(&b->lock);

	return ret;
}

void bch2_fs_buckets_waiting_for_journal_exit(struct bch_fs *c)
{
	struct buckets_waiting_for_journal *b = &c->buckets_waiting_for_journal;

	kvfree(b->d);
}

int bch2_fs_buckets_waiting_for_journal_init(struct bch_fs *c)
{
	struct buckets_waiting_for_journal *b = &c->buckets_waiting_for_journal;

	mutex_init(&b->lock);

	b->nr = 8;
	b->d = kvmalloc_array(b->nr, sizeof(*b->d), __GFP_ZERO);
	if (!b->d)
		return -ENOMEM;

	return 0;
}
