/*
 * bcache journalling code, for btree insertions
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"
#include "journal.h"

#include <trace/events/bcachefs.h>

#define for_each_jset_key(k, jkeys, jset)			\
	for_each_jset_jkeys(jkeys, jset)			\
		if (JKEYS_TYPE(jkeys) == JKEYS_BTREE_KEYS)	\
			for (k = (jkeys)->start;		\
			     k < bset_bkey_last(jkeys);		\
			     k = bkey_next(k))

struct bkey *bch_journal_find_btree_root(struct cache_set *c, struct jset *j,
					 enum btree_id id, unsigned *level)
{
	struct bkey *k;
	struct jset_keys *jkeys;

	for_each_jset_jkeys(jkeys, j)
		if (JKEYS_TYPE(jkeys) == JKEYS_BTREE_ROOT &&
		    jkeys->btree_id == id) {
			k = jkeys->start;
			*level = jkeys->level;

			if (!jkeys->keys ||
			    jkeys->keys != KEY_U64s(k))
				goto err;

			goto found;
		}

	return NULL;
found:
	if (!__bch_btree_ptr_invalid(c, k))
		return k;

err:
	bch_cache_set_error(c, "invalid btree root in journal");
	return NULL;
}

static void bch_journal_add_btree_root(struct jset *j, enum btree_id id,
				       struct bkey *k, unsigned level)
{
	__bch_journal_add_keys(j, id, k, KEY_U64s(k), level, JKEYS_BTREE_ROOT);
}

static inline void bch_journal_add_prios(struct cache_set *c, struct jset *j)
{
	struct jset_keys *prio_set = (struct jset_keys *) bset_bkey_last(j);
	struct cache *ca;
	unsigned i;

	for_each_cache(ca, c, i) {
		spin_lock(&ca->prio_buckets_lock);
		prio_set->d[ca->sb.nr_this_dev] = ca->prio_journal_bucket;
		spin_unlock(&ca->prio_buckets_lock);
	}

	prio_set->keys = c->sb.nr_in_set;
	SET_JKEYS_TYPE(prio_set, JKEYS_PRIO_PTRS);
	j->keys += sizeof(struct jset_keys) / sizeof(u64) + c->sb.nr_in_set;
}

/*
 * Journal replay/recovery:
 *
 * This code is all driven from run_cache_set(); we first read the journal
 * entries, do some other stuff, then we mark all the keys in the journal
 * entries (same as garbage collection would), then we replay them - reinserting
 * them into the cache in precisely the same order as they appear in the
 * journal.
 *
 * We only journal keys that go in leaf nodes, which simplifies things quite a
 * bit.
 */

static int journal_read_bucket(struct cache *ca, struct list_head *list,
			       unsigned bucket_index)
{
	struct journal_device *ja = &ca->journal;
	struct bio *bio = &ja->bio;

	struct journal_replay *i;
	struct jset *j, *data = ca->set->journal.w[0].data;
	unsigned len, left, offset = 0;
	int ret = 0;
	sector_t bucket = bucket_to_sector(ca->set,
				journal_bucket(ca, bucket_index));

	pr_debug("reading %u", bucket_index);

	while (offset < ca->sb.bucket_size) {
reread:		left = ca->sb.bucket_size - offset;
		len = min_t(unsigned, left, PAGE_SECTORS << JSET_BITS);

		bio_reset(bio);
		bio->bi_bdev		= ca->bdev;
		bio->bi_iter.bi_sector	= bucket + offset;
		bio->bi_iter.bi_size	= len << 9;
		bio_set_op_attrs(bio, REQ_OP_READ, 0);
		bch_bio_map(bio, data);

		ret = submit_bio_wait(bio);
		if (ret)
			return -EIO;

		/* This function could be simpler now since we no longer write
		 * journal entries that overlap bucket boundaries; this means
		 * the start of a bucket will always have a valid journal entry
		 * if it has any journal entries at all.
		 */

		j = data;
		while (len) {
			struct list_head *where;
			size_t blocks, bytes = set_bytes(j);

			if (cache_set_init_fault("journal_read"))
				return ret;

			if (j->magic != jset_magic(&ca->sb)) {
				pr_debug("%u: bad magic", bucket_index);
				return ret;
			}

			if (j->version != BCACHE_JSET_VERSION) {
				pr_info("unsupported journal version");
				return ret;
			}

			if (bytes > left << 9 ||
			    bytes > PAGE_SIZE << JSET_BITS) {
				pr_info("%u: too big, %zu bytes, offset %u",
					bucket_index, bytes, offset);
				return ret;
			}

			if (bytes > len << 9)
				goto reread;

			if (j->csum != csum_set(j, JSET_CSUM_TYPE(j))) {
				pr_info("%u: bad csum, %zu bytes, offset %u",
					bucket_index, bytes, offset);
				return ret;
			}

			blocks = set_blocks(j, block_bytes(ca->set));

			while (!list_empty(list)) {
				i = list_first_entry(list,
					struct journal_replay, list);
				if (i->j.seq >= j->last_seq)
					break;
				list_del(&i->list);
				kfree(i);
			}

			list_for_each_entry_reverse(i, list, list) {
				if (j->seq == i->j.seq) {
					pr_debug("j->seq %llu i->j.seq %llu",
						 j->seq, i->j.seq);
					goto next_set;
				}

				if (j->seq < i->j.last_seq) {
					pr_debug("j->seq %llu i->j.seq %llu",
						 j->seq, i->j.seq);
					goto next_set;
				}

				if (j->seq > i->j.seq) {
					where = &i->list;
					goto add;
				}
			}

			where = list;
add:
			i = kmalloc(offsetof(struct journal_replay, j) +
				    bytes, GFP_KERNEL);
			if (!i)
				return -ENOMEM;
			memcpy(&i->j, j, bytes);
			list_add(&i->list, where);
			ret = 1;

			ja->seq[bucket_index] = j->seq;
			pr_debug("seq %llu", j->seq);
next_set:
			pr_debug("next");
			offset	+= blocks * ca->sb.block_size;
			len	-= blocks * ca->sb.block_size;
			j = ((void *) j) + blocks * block_bytes(ca);
		}
	}

	return ret;
}

int bch_journal_read(struct cache_set *c, struct list_head *list)
{
#define read_bucket(b)							\
	({								\
		int ret = journal_read_bucket(ca, list, b);		\
		__set_bit(b, bitmap);					\
		if (ret < 0) {						\
			percpu_ref_put(&ca->ref);			\
			return ret;					\
		}							\
		ret;							\
	})

	struct cache *ca;
	unsigned iter;

	for_each_cache(ca, c, iter) {
		struct journal_device *ja = &ca->journal;
		unsigned nr_buckets = bch_nr_journal_buckets(&ca->sb);
		DECLARE_BITMAP(bitmap, nr_buckets);
		unsigned i, l, r, m;
		uint64_t seq;

		bitmap_zero(bitmap, nr_buckets);
		pr_debug("%u journal buckets", nr_buckets);

		/*
		 * Read journal buckets ordered by golden ratio hash to quickly
		 * find a sequence of buckets with valid journal entries
		 */
		for (i = 0; i < nr_buckets; i++) {
			l = (i * 2654435769U) % nr_buckets;

			if (test_bit(l, bitmap))
				break;

			if (read_bucket(l))
				goto bsearch;
		}

		/*
		 * If that fails, check all the buckets we haven't checked
		 * already
		 */
		pr_debug("falling back to linear search");

		for (l = find_first_zero_bit(bitmap, nr_buckets);
		     l < nr_buckets;
		     l = find_next_zero_bit(bitmap, nr_buckets, l + 1))
			if (read_bucket(l))
				goto bsearch;

		/* no journal entries on this device? */
		if (l == nr_buckets)
			continue;
bsearch:
		BUG_ON(list_empty(list));

		/* Binary search */
		m = l;
		r = find_next_bit(bitmap, nr_buckets, l + 1);
		pr_debug("starting binary search, l %u r %u", l, r);

		while (l + 1 < r) {
			seq = list_entry(list->prev, struct journal_replay,
					 list)->j.seq;

			m = (l + r) >> 1;
			read_bucket(m);

			if (seq != list_entry(list->prev, struct journal_replay,
					      list)->j.seq)
				l = m;
			else
				r = m;
		}

		/*
		 * Read buckets in reverse order until we stop finding more
		 * journal entries
		 */
		pr_debug("finishing up: m %u njournal_buckets %u",
			 m, nr_buckets);
		l = m;

		while (1) {
			if (!l--)
				l = nr_buckets - 1;

			if (l == m)
				break;

			if (test_bit(l, bitmap))
				continue;

			if (!read_bucket(l))
				break;
		}

		seq = 0;

		for (i = 0; i < nr_buckets; i++)
			if (ja->seq[i] > seq) {
				seq = ja->seq[i];
				/*
				 * When journal_reclaim() goes to allocate for
				 * the first time, it'll use the bucket after
				 * ja->cur_idx
				 */
				ja->cur_idx = i;
				ja->last_idx = ja->discard_idx = (i + 1) %
					nr_buckets;
				pr_debug("cur_idx %d last_idx %d",
					 ja->cur_idx, ja->last_idx);
			}
	}

	if (!list_empty(list))
		c->journal.seq = list_entry(list->prev,
					    struct journal_replay,
					    list)->j.seq;

	return 0;
#undef read_bucket
}

void bch_journal_mark(struct cache_set *c, struct list_head *list)
{
	struct bkey *k;
	struct jset_keys *j;
	struct journal_replay *r;

	list_for_each_entry(r, list, list)
		for_each_jset_key(k, j, &r->j) {
			if (j->level) {
				if (!__bch_btree_ptr_invalid(c, k))
					__bch_btree_mark_key(c, j->level, k);
			} else if (j->btree_id == BTREE_ID_EXTENTS) {
				if (!__bch_extent_invalid(c, k))
					__bch_btree_mark_key(c, j->level, k);
			}
		}
}

static int bch_journal_replay_key(struct cache_set *c, enum btree_id id,
				  struct bkey *k)
{
	trace_bcache_journal_replay_key(k);

	return bch_btree_insert(c, id, &keylist_single(k), NULL);
}

int bch_journal_replay(struct cache_set *c, struct list_head *list)
{
	int ret = 0, keys = 0, entries = 0;
	struct bkey *k;
	struct jset_keys *jkeys;
	struct journal_replay *i =
		list_entry(list->prev, struct journal_replay, list);

	uint64_t start = i->j.last_seq, end = i->j.seq, n = start;

	list_for_each_entry(i, list, list) {
		cache_set_err_on(n != i->j.seq, c,
"bcache: journal entries %llu-%llu missing! (replaying %llu-%llu)",
				 n, i->j.seq - 1, start, end);

		for_each_jset_key(k, jkeys, &i->j) {
			cond_resched();
			bch_journal_replay_key(c, jkeys->btree_id, k);
			if (ret)
				goto err;

			keys++;
		}

		n = i->j.seq + 1;
		entries++;
	}

	bch_btree_flush(c);

	pr_info("journal replay done, %i keys in %i entries, seq %llu",
		keys, entries, end);
err:
	if (ret)
		pr_err("journal replay error: %d", ret);

	while (!list_empty(list)) {
		i = list_first_entry(list, struct journal_replay, list);
		list_del(&i->list);
		kfree(i);
	}

	return ret;
}

static int bch_set_nr_journal_buckets(struct cache *ca, unsigned nr)
{
	unsigned keys = bch_journal_buckets_offset(&ca->sb) + nr;
	u64 *p;
	int ret;

	ret = bch_super_realloc(ca, keys);
	if (ret)
		return ret;

	p = krealloc(ca->journal.seq, nr * sizeof(u64), GFP_KERNEL|__GFP_ZERO);
	if (!p)
		return -ENOMEM;

	ca->journal.seq = p;
	ca->sb.keys = keys;

	return 0;
}

int bch_cache_journal_alloc(struct cache *ca)
{
	int ret;
	unsigned i;

	ret = bch_set_nr_journal_buckets(ca,
					 max_t(unsigned, 2,
					       ca->sb.nbuckets >> 8));
	if (ret)
		return ret;

	for (i = 0; i < bch_nr_journal_buckets(&ca->sb); i++)
		set_journal_bucket(ca, i, ca->sb.first_bucket + i);

	return 0;
}

/* Journalling */

void btree_write_oldest(struct cache_set *c)
{
	/*
	 * Try to find the btree node with that references the oldest journal
	 * entry, best is our current candidate and is locked if non NULL:
	 */
	struct btree *b, *best;
	struct bucket_table *tbl;
	struct rhash_head *pos;
	unsigned i;
retry:
	cond_resched();
	best = NULL;

	rcu_read_lock();
	for_each_cached_btree(b, c, tbl, i, pos)
		if (btree_current_write(b)->journal) {
			if (!best)
				best = b;
			else if (journal_pin_cmp(c,
					btree_current_write(best)->journal,
					btree_current_write(b)->journal)) {
				best = b;
			}
		}
	rcu_read_unlock();

	b = best;
	if (b) {
		six_lock_read(&b->lock);
		if (!btree_current_write(b)->journal) {
			six_unlock_read(&b->lock);
			/* We raced */
			goto retry;
		}

		__bch_btree_node_write(b, NULL);
		six_unlock_read(&b->lock);
	}
}

#define last_seq(j)	((j)->seq - fifo_used(&(j)->pin) + 1)

static void journal_discard_endio(struct bio *bio)
{
	struct journal_device *ja =
		container_of(bio, struct journal_device, discard_bio);
	struct cache *ca = container_of(ja, struct cache, journal);

	atomic_set(&ja->discard_in_flight, DISCARD_DONE);

	wake_up(&ca->set->journal.wait);
	closure_put(&ca->set->cl);
}

static void journal_discard_work(struct work_struct *work)
{
	struct journal_device *ja =
		container_of(work, struct journal_device, discard_work);

	submit_bio(&ja->discard_bio);
}

static void do_journal_discard(struct cache *ca)
{
	struct journal_device *ja = &ca->journal;
	struct bio *bio = &ja->discard_bio;

	if (!CACHE_DISCARD(cache_member_info(ca)) ||
	    !blk_queue_discard(bdev_get_queue(ca->bdev))) {
		ja->discard_idx = ja->last_idx;
		return;
	}

	switch (atomic_read(&ja->discard_in_flight)) {
	case DISCARD_IN_FLIGHT:
		return;

	case DISCARD_DONE:
		ja->discard_idx = (ja->discard_idx + 1) %
			bch_nr_journal_buckets(&ca->sb);

		atomic_set(&ja->discard_in_flight, DISCARD_READY);
		/* fallthrough */

	case DISCARD_READY:
		if (ja->discard_idx == ja->last_idx)
			return;

		atomic_set(&ja->discard_in_flight, DISCARD_IN_FLIGHT);

		bio_init(bio);
		bio_set_op_attrs(bio, REQ_OP_DISCARD, 0);
		bio->bi_iter.bi_sector	=
			bucket_to_sector(ca->set,
					 journal_bucket(ca, ja->discard_idx));
		bio->bi_bdev		= ca->bdev;
		bio->bi_max_vecs	= 1;
		bio->bi_io_vec		= bio->bi_inline_vecs;
		bio->bi_iter.bi_size	= bucket_bytes(ca);
		bio->bi_end_io		= journal_discard_endio;

		closure_get(&ca->set->cl);
		INIT_WORK(&ja->discard_work, journal_discard_work);
		schedule_work(&ja->discard_work);
	}
}

static size_t journal_write_u64s_remaining(struct cache_set *c,
					   struct journal_write *w)
{
	ssize_t u64s = (min_t(size_t,
			     c->journal.blocks_free * block_bytes(c),
			     PAGE_SIZE << JSET_BITS) -
			set_bytes(w->data)) / sizeof(u64);

	/* Subtract off some for the btree roots */
	u64s -= BTREE_ID_NR * (JSET_KEYS_U64s + BKEY_EXTENT_MAX_U64s);

	/* And for the prio pointers */
	u64s -= JSET_KEYS_U64s + c->sb.nr_in_set;

	return max_t(ssize_t, 0L, u64s);
}

static void journal_reclaim(struct cache_set *c)
{
	struct bkey *k = &c->journal.key;
	struct cache *ca;
	uint64_t last_seq;
	unsigned iter;
	atomic_t p;

	pr_debug("started");

	/*
	 * only supposed to be called when we're out of space/haven't started a
	 * new journal entry
	 */
	BUG_ON(c->journal.u64s_remaining);

	while (!atomic_read(&fifo_front(&c->journal.pin)))
		fifo_pop(&c->journal.pin, p);

	last_seq = last_seq(&c->journal);

	/* Update last_idx */

	rcu_read_lock();

	for_each_cache_rcu(ca, c, iter) {
		struct journal_device *ja = &ca->journal;

		while (ja->last_idx != ja->cur_idx &&
		       ja->seq[ja->last_idx] < last_seq)
			ja->last_idx = (ja->last_idx + 1) %
				bch_nr_journal_buckets(&ca->sb);
	}

	for_each_cache_rcu(ca, c, iter)
		do_journal_discard(ca);

	if (!journal_write_u64s_remaining(c, c->journal.cur)) {
		/*
		 * Not enough space remaining in the current bucket for an empty
		 * journal write
		 */

		c->journal.blocks_free = 0;
	}

	if (c->journal.blocks_free)
		goto out;

	/*
	 * Determine location of the next journal write:
	 * XXX: sort caches by free journal space
	 */

	bkey_init(k);

	for_each_cache_rcu(ca, c, iter) {
		struct journal_device *ja = &ca->journal;
		unsigned next = (ja->cur_idx + 1) %
			bch_nr_journal_buckets(&ca->sb);

		if (CACHE_TIER(cache_member_info(ca)))
			continue;

		/* No space available on this device */
		if (next == ja->discard_idx)
			continue;

		ja->cur_idx = next;
		k->val[bch_extent_ptrs(k)] =
			PTR(0, bucket_to_sector(c,
					journal_bucket(ca, ja->cur_idx)),
			    ca->sb.nr_this_dev);

		bch_set_extent_ptrs(k, bch_extent_ptrs(k) + 1);

		if (bch_extent_ptrs(k) == CACHE_SET_META_REPLICAS_WANT(&c->sb))
			break;
	}

	if (bch_extent_ptrs(k))
		c->journal.blocks_free = c->sb.bucket_size >> c->block_bits;
out:
	rcu_read_unlock();

	if (!journal_full(&c->journal)) {
		c->journal.u64s_remaining =
			journal_write_u64s_remaining(c, c->journal.cur);
		pr_debug("done: %d", c->journal.u64s_remaining);
		wake_up(&c->journal.wait);
	}
}

void bch_journal_next(struct journal *j)
{
	atomic_t p = { 1 };

	j->cur = (j->cur == j->w)
		? &j->w[1]
		: &j->w[0];

	/*
	 * The fifo_push() needs to happen at the same time as j->seq is
	 * incremented for last_seq() to be calculated correctly
	 */
	BUG_ON(!fifo_push(&j->pin, p));
	atomic_set(&fifo_back(&j->pin), 1);

	j->cur->data->seq	= ++j->seq;
	j->cur->data->keys	= 0;
	j->u64s_remaining	= 0;

	if (fifo_full(&j->pin))
		pr_debug("journal_pin full (%zu)", fifo_used(&j->pin));
}

static void journal_write_endio(struct bio *bio)
{
	struct cache *ca = container_of(bio, struct cache, journal.bio);
	struct journal_write *w = bio->bi_private;

	cache_set_err_on(bio->bi_error, w->c, "journal io error");
	closure_put(&w->c->journal.io);
	percpu_ref_put(&ca->ref);
}

static void journal_write_done(struct closure *cl)
{
	struct journal *j = container_of(cl, struct journal, io);
	struct journal_write *w = (j->cur == j->w)
		? &j->w[1]
		: &j->w[0];

	__closure_wake_up(&w->wait);

	atomic_set(&j->in_flight, 0);
	wake_up(&j->wait);

	if (test_bit(JOURNAL_NEED_WRITE, &j->flags))
		mod_delayed_work(system_wq, &j->work, 0);
}

static void journal_write_locked(struct closure *cl)
	__releases(c->journal.lock)
{
	struct cache_set *c = container_of(cl, struct cache_set, journal.io);
	struct cache *ca;
	struct journal_write *w = c->journal.cur;
	struct bkey *k = &c->journal.key;
	BKEY_PADDED(k) tmp;
	unsigned i, sectors;

	struct bio *bio;
	struct bio_list list;
	bio_list_init(&list);

	BUG_ON(c->journal.res_count);
	BUG_ON(journal_full(&c->journal));

	clear_bit(JOURNAL_NEED_WRITE, &c->journal.flags);
	clear_bit(JOURNAL_DIRTY, &c->journal.flags);
	cancel_delayed_work(&c->journal.work);

	spin_lock(&c->btree_root_lock);

	for (i = 0; i < BTREE_ID_NR; i++) {
		struct btree *b = c->btree_roots[i];

		if (b)
			bch_journal_add_btree_root(w->data, i,
						   &b->key, b->level);
	}

	spin_unlock(&c->btree_root_lock);

	bch_journal_add_prios(c, w->data);

	c->journal.blocks_free -= set_blocks(w->data, block_bytes(c));

	w->data->read_clock	= c->prio_clock[READ].hand;
	w->data->write_clock	= c->prio_clock[WRITE].hand;
	w->data->magic		= jset_magic(&c->sb);
	w->data->version	= BCACHE_JSET_VERSION;
	w->data->last_seq	= last_seq(&c->journal);

	SET_JSET_CSUM_TYPE(w->data, CACHE_PREFERRED_CSUM_TYPE(&c->sb));
	w->data->csum		= csum_set(w->data, JSET_CSUM_TYPE(w->data));

	sectors = set_blocks(w->data, block_bytes(c)) * c->sb.block_size;

	for (i = 0; i < bch_extent_ptrs(k); i++) {
		rcu_read_lock();
		ca = PTR_CACHE(c, k, i);
		if (ca)
			percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		if (!ca) {
			/* XXX: fix this */
			pr_err("missing journal write\n");
			continue;
		}

		bio = &ca->journal.bio;

		atomic_long_add(sectors, &ca->meta_sectors_written);

		bio_reset(bio);
		bio->bi_iter.bi_sector	= PTR_OFFSET(k, i);
		bio->bi_bdev	= ca->bdev;
		bio->bi_iter.bi_size = sectors << 9;

		bio->bi_end_io	= journal_write_endio;
		bio->bi_private = w;
		bio_set_op_attrs(bio, REQ_OP_WRITE,
				 REQ_SYNC|REQ_META|REQ_PREFLUSH|REQ_FUA);
		bch_bio_map(bio, w->data);

		trace_bcache_journal_write(bio);
		bio_list_add(&list, bio);

		SET_PTR_OFFSET(k, i, PTR_OFFSET(k, i) + sectors);

		ca->journal.seq[ca->journal.cur_idx] = w->data->seq;
	}

	/*
	 * Make a copy of the key we're writing to for check_mark_super, since
	 * journal_reclaim will change it
	 */
	bkey_copy(&tmp.k, k);

	atomic_dec_bug(&fifo_back(&c->journal.pin));
	bch_journal_next(&c->journal);
	journal_reclaim(c);

	spin_unlock(&c->journal.lock);

	bch_check_mark_super(c, &tmp.k, true);

	while ((bio = bio_list_pop(&list)))
		closure_bio_submit_punt(bio, cl, c);

	closure_return_with_destructor(cl, journal_write_done);
}

static bool __journal_write(struct cache_set *c)
	__releases(c->journal.lock)
{
	BUG_ON(!c->journal.res_count &&
	       !test_bit(JOURNAL_DIRTY, &c->journal.flags));

	if (!c->journal.res_count &&
	    !atomic_xchg(&c->journal.in_flight, 1)) {
		closure_call(&c->journal.io, journal_write_locked,
			     NULL, &c->cl);
		return true;
	} else {
		spin_unlock(&c->journal.lock);
		return false;
	}
}

static bool journal_try_write(struct cache_set *c)
{
	set_bit(JOURNAL_NEED_WRITE, &c->journal.flags);
	return __journal_write(c);
}

static void journal_unlock(struct cache_set *c)
{
	if (test_bit(JOURNAL_NEED_WRITE, &c->journal.flags))
		__journal_write(c);
	else
		spin_unlock(&c->journal.lock);
}

static void journal_write_work(struct work_struct *work)
{
	struct cache_set *c = container_of(to_delayed_work(work),
					   struct cache_set,
					   journal.work);
	spin_lock(&c->journal.lock);
	if (test_bit(JOURNAL_DIRTY, &c->journal.flags))
		set_bit(JOURNAL_NEED_WRITE, &c->journal.flags);
	journal_unlock(c);
}

/*
 * This function releases the journal write structure so other threads can
 * then proceed to add their keys as well.
 */
void __bch_journal_res_put(struct cache_set *c,
			   struct journal_res *res,
			   struct closure *parent)
{
	BUG_ON(!res->ref);

	c->journal.u64s_remaining += res->nkeys;
	--c->journal.res_count;
	res->nkeys = 0;
	res->ref = 0;

	if (!__test_and_set_bit(JOURNAL_DIRTY, &c->journal.flags))
		schedule_delayed_work(&c->journal.work,
				      msecs_to_jiffies(c->journal.delay_ms));

	if (parent) {
		BUG_ON(!closure_wait(&c->journal.cur->wait, parent));
		set_bit(JOURNAL_NEED_WRITE, &c->journal.flags);
	}

	journal_unlock(c);
}

static bool __journal_res_get(struct cache_set *c, struct journal_res *res,
			      unsigned u64s_min, unsigned u64s_max)
{
	unsigned actual_min = u64s_min + sizeof(struct jset_keys) / sizeof(u64);
	unsigned actual_max = u64s_max + sizeof(struct jset_keys) / sizeof(u64);

	BUG_ON(res->ref);

	spin_lock(&c->journal.lock);

	while (1) {
		if (actual_min < c->journal.u64s_remaining) {
			res->nkeys = min_t(unsigned, actual_max,
					   c->journal.u64s_remaining - 1);
			res->ref = 1;

			c->journal.u64s_remaining -= res->nkeys;
			c->journal.res_count++;
			spin_unlock(&c->journal.lock);
			return true;
		}

		if (!c->journal.u64s_remaining) {
			journal_reclaim(c);

			if (!c->journal.u64s_remaining) {
				spin_unlock(&c->journal.lock);
				trace_bcache_journal_full(c);
				btree_write_oldest(c);
				return false;
			}
		} else {
			/*
			 * Not much room for this journal entry (near the end of
			 * a journal bucket) but there's nothing in this journal
			 * entry yet - skip it and allocate a new journal entry
			 */
			if (!c->journal.cur->data->keys) {
				c->journal.blocks_free = 0;
				c->journal.u64s_remaining = 0;
				continue;
			}

			if (!journal_try_write(c)) {
				trace_bcache_journal_entry_full(c);
				return false;
			}

			spin_lock(&c->journal.lock);
		}
	}
}

/*
 * Essentially the entry function to the journaling code. When bcache is doing
 * a btree insert, it calls this function to get the current journal write.
 * Journal write is the structure used set up journal writes. The calling
 * function will then add its keys to the structure, queuing them for the
 * next write.
 */
void bch_journal_res_get(struct cache_set *c, struct journal_res *res,
			 unsigned u64s_min, unsigned u64s_max)
{
	wait_event(c->journal.wait,
		   __journal_res_get(c, res, u64s_min, u64s_max));
}

void bch_journal_meta(struct cache_set *c, struct closure *parent)
{
	struct journal_res res;

	memset(&res, 0, sizeof(res));

	if (!CACHE_SYNC(&c->sb))
		return;

	bch_journal_res_get(c, &res, 0, 0);
	bch_journal_res_put(c, &res, parent);
}

void bch_journal_free(struct cache_set *c)
{
	free_pages((unsigned long) c->journal.w[1].data, JSET_BITS);
	free_pages((unsigned long) c->journal.w[0].data, JSET_BITS);
	free_fifo(&c->journal.pin);
}

int bch_journal_alloc(struct cache_set *c)
{
	struct journal *j = &c->journal;

	spin_lock_init(&j->lock);
	init_waitqueue_head(&j->wait);
	INIT_DELAYED_WORK(&j->work, journal_write_work);

	c->journal.delay_ms = 100;

	j->w[0].c = c;
	j->w[1].c = c;

	if (!(init_fifo(&j->pin, JOURNAL_PIN, GFP_KERNEL)) ||
	    !(j->w[0].data = (void *) __get_free_pages(GFP_KERNEL, JSET_BITS)) ||
	    !(j->w[1].data = (void *) __get_free_pages(GFP_KERNEL, JSET_BITS)))
		return -ENOMEM;

	return 0;
}

ssize_t bch_journal_print_debug(struct journal *j, char *buf)
{
	return snprintf(buf, PAGE_SIZE,
			"active journal entries:\t%zu\n"
			"seq:\t\t\t%llu\n"
			"reservation count:\t%u\n"
			"io in flight:\t\t%i\n"
			"need write:\t\t%i\n"
			"dirty:\t\t\t%i\n"
			"replay done:\t\t%i\n",
			fifo_used(&j->pin),
			j->seq,
			j->res_count,
			atomic_read(&j->in_flight),
			test_bit(JOURNAL_NEED_WRITE,	&j->flags),
			test_bit(JOURNAL_DIRTY,		&j->flags),
			test_bit(JOURNAL_REPLAY_DONE,	&j->flags));
}
