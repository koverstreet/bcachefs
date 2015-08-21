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

#define for_each_jset_jkeys(jkeys, jset)			\
	for (jkeys = (jset)->start;				\
	     jkeys < (struct jset_keys *) bset_bkey_last(jset);	\
	     jkeys = jset_keys_next(jkeys))

#define for_each_jset_key(k, jkeys, jset)			\
	for_each_jset_jkeys(jkeys, jset)			\
		if (!JKEYS_BTREE_ROOT(jkeys))			\
			for (k = (jkeys)->start;		\
			     k < bset_bkey_last(jkeys);		\
			     k = bkey_next(k))

struct bkey *bch_journal_find_btree_root(struct cache_set *c, struct jset *j,
					 enum btree_id id, unsigned *level)
{
	struct bkey *k;
	struct jset_keys *jkeys;

	for_each_jset_jkeys(jkeys, j)
		if (jkeys->btree_id == id &&
		    JKEYS_BTREE_ROOT(jkeys)) {
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
	bch_journal_add_keys(j, id, k, KEY_U64s(k), level, true);
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

static void journal_read_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;
	closure_put(cl);
}

static int journal_read_bucket(struct cache *ca, struct list_head *list,
			       unsigned bucket_index)
{
	struct journal_device *ja = &ca->journal;
	struct bio *bio = &ja->bio;

	struct journal_replay *i;
	struct jset *j, *data = ca->set->journal.w[0].data;
	struct closure cl;
	unsigned len, left, offset = 0;
	int ret = 0;
	sector_t bucket = bucket_to_sector(ca->set, ca->sb.d[bucket_index]);

	closure_init_stack(&cl);

	pr_debug("reading %u", bucket_index);

	while (offset < ca->sb.bucket_size) {
reread:		left = ca->sb.bucket_size - offset;
		len = min_t(unsigned, left, PAGE_SECTORS << JSET_BITS);

		bio_reset(bio);
		bio->bi_iter.bi_sector	= bucket + offset;
		bio->bi_bdev	= ca->bdev;
		bio->bi_iter.bi_size	= len << 9;

		bio->bi_end_io	= journal_read_endio;
		bio->bi_private = &cl;
		bio_set_op_attrs(bio, REQ_OP_READ, 0);
		bch_bio_map(bio, data);

		closure_bio_submit(bio, &cl);
		closure_sync(&cl);

		/* This function could be simpler now since we no longer write
		 * journal entries that overlap bucket boundaries; this means
		 * the start of a bucket will always have a valid journal entry
		 * if it has any journal entries at all.
		 */

		j = data;
		while (len) {
			struct list_head *where;
			size_t blocks, bytes = set_bytes(j);

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

			if (j->csum != csum_set(j)) {
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
				if (j->seq == i->j.seq)
					goto next_set;

				if (j->seq < i->j.last_seq)
					goto next_set;

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
next_set:
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
		if (ret < 0)						\
			return ret;					\
		ret;							\
	})

	struct cache *ca;
	unsigned iter;

	for_each_cache(ca, c, iter) {
		struct journal_device *ja = &ca->journal;
		DECLARE_BITMAP(bitmap, SB_JOURNAL_BUCKETS);
		unsigned i, l, r, m;
		uint64_t seq;

		bitmap_zero(bitmap, SB_JOURNAL_BUCKETS);
		pr_debug("%u journal buckets", ca->sb.njournal_buckets);

		/*
		 * Read journal buckets ordered by golden ratio hash to quickly
		 * find a sequence of buckets with valid journal entries
		 */
		for (i = 0; i < ca->sb.njournal_buckets; i++) {
			l = (i * 2654435769U) % ca->sb.njournal_buckets;

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

		for (l = find_first_zero_bit(bitmap, ca->sb.njournal_buckets);
		     l < ca->sb.njournal_buckets;
		     l = find_next_zero_bit(bitmap, ca->sb.njournal_buckets, l + 1))
			if (read_bucket(l))
				goto bsearch;

		/* no journal entries on this device? */
		if (l == ca->sb.njournal_buckets)
			continue;
bsearch:
		BUG_ON(list_empty(list));

		/* Binary search */
		m = l;
		r = find_next_bit(bitmap, ca->sb.njournal_buckets, l + 1);
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
			 m, ca->sb.njournal_buckets);
		l = m;

		while (1) {
			if (!l--)
				l = ca->sb.njournal_buckets - 1;

			if (l == m)
				break;

			if (test_bit(l, bitmap))
				continue;

			if (!read_bucket(l))
				break;
		}

		seq = 0;

		for (i = 0; i < ca->sb.njournal_buckets; i++)
			if (ja->seq[i] > seq) {
				seq = ja->seq[i];
				/*
				 * When journal_reclaim() goes to allocate for
				 * the first time, it'll use the bucket after
				 * ja->cur_idx
				 */
				ja->cur_idx = i;
				ja->last_idx = ja->discard_idx = (i + 1) %
					ca->sb.njournal_buckets;

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
	int ret;
	struct keylist keys;

	trace_bcache_journal_replay_key(k);

	bch_keylist_init_single(&keys, k);

	ret = bch_btree_insert(c, id, &keys, NULL, NULL);
	BUG_ON(!bch_keylist_empty(&keys));

	cond_resched();

	return ret;
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
	while (!list_empty(list)) {
		i = list_first_entry(list, struct journal_replay, list);
		list_del(&i->list);
		kfree(i);
	}

	return ret;
}

/* Journalling */

void btree_flush_write(struct cache_set *c)
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
		mutex_lock(&b->write_lock);
		if (!btree_current_write(b)->journal) {
			mutex_unlock(&b->write_lock);
			/* We raced */
			goto retry;
		}

		__bch_btree_node_write(b, NULL);
		mutex_unlock(&b->write_lock);
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

	if (!ca->discard) {
		ja->discard_idx = ja->last_idx;
		return;
	}

	switch (atomic_read(&ja->discard_in_flight)) {
	case DISCARD_IN_FLIGHT:
		return;

	case DISCARD_DONE:
		ja->discard_idx = (ja->discard_idx + 1) %
			ca->sb.njournal_buckets;

		atomic_set(&ja->discard_in_flight, DISCARD_READY);
		/* fallthrough */

	case DISCARD_READY:
		if (ja->discard_idx == ja->last_idx)
			return;

		atomic_set(&ja->discard_in_flight, DISCARD_IN_FLIGHT);

		bio_init(bio);
		bio_set_op_attrs(bio, REQ_OP_DISCARD, 0);
		bio->bi_iter.bi_sector	= bucket_to_sector(ca->set,
						ca->sb.d[ja->discard_idx]);
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

static void journal_reclaim(struct cache_set *c)
{
	struct bkey *k = &c->journal.key;
	struct cache *ca;
	uint64_t last_seq;
	unsigned iter;
	atomic_t p;

	while (!atomic_read(&fifo_front(&c->journal.pin)))
		fifo_pop(&c->journal.pin, p);

	last_seq = last_seq(&c->journal);

	/* Update last_idx */

	for_each_cache(ca, c, iter) {
		struct journal_device *ja = &ca->journal;

		while (ja->last_idx != ja->cur_idx &&
		       ja->seq[ja->last_idx] < last_seq)
			ja->last_idx = (ja->last_idx + 1) %
				ca->sb.njournal_buckets;
	}

	for_each_cache(ca, c, iter)
		do_journal_discard(ca);

	if (c->journal.blocks_free)
		goto out;

	/*
	 * Determine location of the next journal write:
	 * XXX: sort caches by free journal space
	 */

	bkey_init(k);
	for_each_cache(ca, c, iter) {
		struct journal_device *ja = &ca->journal;
		unsigned next = (ja->cur_idx + 1) % ca->sb.njournal_buckets;

		/* No space available on this device */
		if (next == ja->discard_idx)
			continue;

		ja->cur_idx = next;
		k->val[bch_extent_ptrs(k)] =
			PTR(0, bucket_to_sector(c, ca->sb.d[ja->cur_idx]),
			    ca->sb.nr_this_dev);

		bch_set_extent_ptrs(k, bch_extent_ptrs(k) + 1);

		if (bch_extent_ptrs(k) == c->meta_replicas)
			break;
	}

	if (bch_extent_ptrs(k))
		c->journal.blocks_free = c->sb.bucket_size >> c->block_bits;
out:
	if (!journal_full(&c->journal))
		wake_up(&c->journal.wait);
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

	if (fifo_full(&j->pin))
		pr_debug("journal_pin full (%zu)", fifo_used(&j->pin));
}

static void journal_write_endio(struct bio *bio)
{
	struct journal_write *w = bio->bi_private;

	cache_set_err_on(bio->bi_error, w->c, "journal io error");
	closure_put(&w->c->journal.io);
}

static void journal_write_done(struct closure *cl)
{
	struct journal *j = container_of(cl, struct journal, io);
	struct journal_write *w = (j->cur == j->w)
		? &j->w[1]
		: &j->w[0];

	__closure_wake_up(&w->wait);

	clear_bit(JOURNAL_IO_IN_FLIGHT, &j->flags);
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
	unsigned i, sectors;

	struct bio *bio;
	struct bio_list list;
	bio_list_init(&list);

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

	c->journal.blocks_free -= set_blocks(w->data, block_bytes(c));

	for_each_cache(ca, c, i)
		w->data->prio_bucket[ca->sb.nr_this_dev] =
			ca->prio_journal_bucket;

	w->data->magic		= jset_magic(&c->sb);
	w->data->version	= BCACHE_JSET_VERSION;
	w->data->last_seq	= last_seq(&c->journal);
	w->data->csum		= csum_set(w->data);

	sectors = set_blocks(w->data, block_bytes(c)) * c->sb.block_size;

	for (i = 0; i < bch_extent_ptrs(k); i++) {
		ca = PTR_CACHE(c, k, i);
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

	atomic_dec_bug(&fifo_back(&c->journal.pin));
	bch_journal_next(&c->journal);
	journal_reclaim(c);

	spin_unlock(&c->journal.lock);

	while ((bio = bio_list_pop(&list)))
		closure_bio_submit_punt(bio, cl, c);

	closure_return_with_destructor(cl, journal_write_done);
}

static bool journal_try_write(struct cache_set *c)
	__releases(c->journal.lock)
{
	BUG_ON(!test_bit(JOURNAL_DIRTY, &c->journal.flags));

	set_bit(JOURNAL_NEED_WRITE, &c->journal.flags);

	if (!test_and_set_bit(JOURNAL_IO_IN_FLIGHT, &c->journal.flags)) {
		closure_call(&c->journal.io, journal_write_locked,
			     NULL, &c->cl);
		return true;
	} else {
		spin_unlock(&c->journal.lock);
		return false;
	}
}

static void journal_write_work(struct work_struct *work)
{
	struct cache_set *c = container_of(to_delayed_work(work),
					   struct cache_set,
					   journal.work);
	spin_lock(&c->journal.lock);
	if (test_bit(JOURNAL_DIRTY, &c->journal.flags))
		journal_try_write(c);
	else
		spin_unlock(&c->journal.lock);
}

void bch_journal_write_put(struct cache_set *c,
			   struct journal_write *w,
			   struct closure *parent)
	__releases(c->journal.lock)
{
	if (parent) {
		BUG_ON(!closure_wait(&w->wait, parent));
		set_bit(JOURNAL_DIRTY, &c->journal.flags);
		journal_try_write(c);
	} else if (!test_bit(JOURNAL_DIRTY, &c->journal.flags)) {
		set_bit(JOURNAL_DIRTY, &c->journal.flags);
		schedule_delayed_work(&c->journal.work,
				      msecs_to_jiffies(c->journal_delay_ms));
		spin_unlock(&c->journal.lock);
	} else {
		spin_unlock(&c->journal.lock);
	}
}

struct journal_write *bch_journal_write_get(struct cache_set *c, unsigned nkeys)
	__acquires(c->journal.lock)
{
	struct journal_write *w;

	while (1) {
		spin_lock(&c->journal.lock);
		w = c->journal.cur;

		if (journal_full(&c->journal))
			journal_reclaim(c);

		if (journal_full(&c->journal)) {
			/* Caller needs to flush btree nodes */
			spin_unlock(&c->journal.lock);
			trace_bcache_journal_full(c);
			return NULL;
		}

		if (nkeys <= journal_write_u64s_remaining(c, w))
			return w;

		/*
		 * XXX: If we were inserting so many keys that they
		 * won't fit in an _empty_ journal write, we'll
		 * deadlock. For now, handle this in
		 * bch_keylist_realloc() - but something to think about.
		 */
		BUG_ON(!w->data->keys);

		if (!journal_try_write(c)) {
			trace_bcache_journal_entry_full(c);
			return ERR_PTR(-EINTR);
		}
	}
}

static struct journal_write *__journal_meta_write_get(struct cache_set *c,
						      unsigned nkeys)
{
	struct journal_write *ret = bch_journal_write_get(c, nkeys);

	if (!IS_ERR_OR_NULL(ret))
		return ret;
	if (!ret)
		btree_flush_write(c);
	return NULL;
}

void bch_journal_meta(struct cache_set *c, struct closure *parent)
{
	struct journal_write *w;

	if (!CACHE_SYNC(&c->sb))
		return;

	wait_event(c->journal.wait,
		   (w = __journal_meta_write_get(c, 0)));
	bch_journal_write_put(c, w, parent);
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

	c->journal_delay_ms = 100;

	j->w[0].c = c;
	j->w[1].c = c;

	if (!(init_fifo(&j->pin, JOURNAL_PIN, GFP_KERNEL)) ||
	    !(j->w[0].data = (void *) __get_free_pages(GFP_KERNEL, JSET_BITS)) ||
	    !(j->w[1].data = (void *) __get_free_pages(GFP_KERNEL, JSET_BITS)))
		return -ENOMEM;

	return 0;
}
