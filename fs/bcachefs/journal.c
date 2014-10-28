/*
 * bcache journalling code, for btree insertions
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "buckets.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"
#include "gc.h"
#include "io.h"
#include "keylist.h"
#include "journal.h"
#include "super.h"

#include <trace/events/bcachefs.h>

#define for_each_jset_key(k, jkeys, jset)			\
	for_each_jset_jkeys(jkeys, jset)			\
		if (JKEYS_TYPE(jkeys) == JKEYS_BTREE_KEYS)	\
			for (k = (jkeys)->start;		\
			     k < bset_bkey_last(jkeys);		\
			     k = bkey_next(k))

static inline void __bch_journal_add_keys(struct jset *, enum btree_id,
					  const struct bkey *, unsigned,
					  unsigned, unsigned);

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

struct journal_list {
	struct closure		cl;
	struct mutex		lock;
	struct mutex		cache_set_buffer_lock;
	struct list_head	*head;
	int			ret;
};

static int journal_add_entry(struct journal_list *jlist, struct jset *j)
{
	struct journal_replay *i, *pos;
	struct list_head *where;
	size_t bytes = set_bytes(j);
	int ret = 0;

	mutex_lock(&jlist->lock);

	/* This entry too old? */
	if (!list_empty(jlist->head)) {
		i = list_last_entry(jlist->head, struct journal_replay, list);
		if (j->seq < i->j.last_seq) {
			pr_debug("j->seq %llu i->j.seq %llu",
				 j->seq, i->j.seq);
			goto out;
		}
	}

	ret = 1;

	/* Drop entries we don't need anymore */
	list_for_each_entry_safe(i, pos, jlist->head, list) {
		if (i->j.seq >= j->last_seq)
			break;
		list_del(&i->list);
		kfree(i);
	}

	list_for_each_entry_reverse(i, jlist->head, list) {
		if (j->seq == i->j.seq) {
			pr_debug("j->seq %llu i->j.seq %llu",
				 j->seq, i->j.seq);
			goto out;
		}

		if (j->seq > i->j.seq) {
			where = &i->list;
			goto add;
		}
	}

	where = jlist->head;
add:
	i = kmalloc(offsetof(struct journal_replay, j) + bytes, GFP_KERNEL);
	if (!i) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(&i->j, j, bytes);
	list_add(&i->list, where);

	pr_debug("seq %llu", j->seq);
out:
	mutex_unlock(&jlist->lock);
	return ret;
}

static int journal_read_bucket(struct cache *ca, struct journal_list *jlist,
			       unsigned bucket_index, u64 *seq)
{
	struct journal_device *ja = &ca->journal;
	struct bio *bio = &ja->bio;
	struct jset *j, *data;
	unsigned len, left, offset = 0;
	sector_t bucket = bucket_to_sector(ca->set,
				journal_bucket(ca, bucket_index));
	bool entries_found = false;
	int ret = 0;

	data = (void *) __get_free_pages(GFP_KERNEL, JSET_BITS);
	if (!data) {
		mutex_lock(&jlist->cache_set_buffer_lock);
		data = ca->set->journal.w[0].data;
	}

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
		if (ret) {
			__bch_cache_error(ca,
				"IO error %d reading journal from offset %zu",
				ret, bucket + offset);
			goto err;
		}

		/* This function could be simpler now since we no longer write
		 * journal entries that overlap bucket boundaries; this means
		 * the start of a bucket will always have a valid journal entry
		 * if it has any journal entries at all.
		 */

		j = data;
		while (len) {
			size_t blocks, bytes = set_bytes(j);
			u64 got, expect;

			if (cache_set_init_fault("journal_read"))
				goto err;

			if (j->magic != jset_magic(&ca->sb)) {
				pr_debug("%u: bad magic", bucket_index);
				goto err;
			}

			got = j->version;
			expect = BCACHE_JSET_VERSION;
			if (got != expect) {
				__bch_cache_error(ca,
					"bad version (got %llu expect %llu) while reading journal from offset %zu",
					got, expect, bucket + offset);
				goto err;
			}

			if (bytes > left << 9 ||
			    bytes > PAGE_SIZE << JSET_BITS) {
				__bch_cache_error(ca,
					"too big (%zu bytes) while reading journal from offset %zu",
					bytes, bucket + offset);
				goto err;
			}

			if (bytes > len << 9)
				goto reread;

			got = j->csum;
			expect = csum_set(j, JSET_CSUM_TYPE(j));
			if (got != expect) {
				__bch_cache_error(ca,
					"bad checksum (got %llu expect %llu) while reading journal from offset %zu",
					got, expect, bucket + offset);
				goto err;
			}

			ret = journal_add_entry(jlist, j);
			if (ret < 0)
				goto err;
			if (ret) {
				ja->seq[bucket_index] = j->seq;
				entries_found = true;
			}

			if (j->seq > *seq)
				*seq = j->seq;

			blocks = set_blocks(j, block_bytes(ca->set));

			pr_debug("next");
			offset	+= blocks * ca->sb.block_size;
			len	-= blocks * ca->sb.block_size;
			j = ((void *) j) + blocks * block_bytes(ca);
		}
	}

	ret = entries_found;
err:
	if (data == ca->set->journal.w[0].data)
		mutex_unlock(&jlist->cache_set_buffer_lock);
	else
		free_pages((unsigned long) data, JSET_BITS);

	return ret;
}

static void bch_journal_read_device(struct closure *cl)
{
#define read_bucket(b)							\
	({								\
		int ret = journal_read_bucket(ca, jlist, b, &seq);	\
		__set_bit(b, bitmap);					\
		if (ret < 0) {						\
			mutex_lock(&jlist->lock);			\
			jlist->ret = ret;				\
			mutex_unlock(&jlist->lock);			\
			closure_return(cl);				\
		}							\
		ret;							\
	 })

	struct journal_device *ja =
		container_of(cl, struct journal_device, read);
	struct cache *ca = container_of(ja, struct cache, journal);
	struct journal_list *jlist =
		container_of(cl->parent, struct journal_list, cl);

	unsigned nr_buckets = bch_nr_journal_buckets(&ca->sb);
	DECLARE_BITMAP(bitmap, nr_buckets);
	unsigned i, l, r, m;
	u64 seq = 0;

	bitmap_zero(bitmap, nr_buckets);
	pr_debug("%u journal buckets", nr_buckets);

	if (!blk_queue_nonrot(bdev_get_queue(ca->bdev)))
		goto linear_scan;

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
linear_scan:
	for (l = find_first_zero_bit(bitmap, nr_buckets);
	     l < nr_buckets;
	     l = find_next_zero_bit(bitmap, nr_buckets, l + 1))
		if (read_bucket(l))
			goto bsearch;

	/* no journal entries on this device? */
	if (l == nr_buckets)
		closure_return(cl);
bsearch:
	/* Binary search */
	m = l;
	r = find_next_bit(bitmap, nr_buckets, l + 1);
	pr_debug("starting binary search, l %u r %u", l, r);

	while (l + 1 < r) {
		u64 cur_seq = seq;

		m = (l + r) >> 1;
		read_bucket(m);

		if (cur_seq != seq)
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

	closure_return(cl);
#undef read_bucket
}

int bch_journal_read(struct cache_set *c, struct list_head *list)
{
	struct journal_list jlist;
	struct cache *ca;
	unsigned iter;

	closure_init_stack(&jlist.cl);
	mutex_init(&jlist.lock);
	mutex_init(&jlist.cache_set_buffer_lock);
	jlist.head = list;
	jlist.ret = 0;

	for_each_cache(ca, c, iter)
		closure_call(&ca->journal.read,
			     bch_journal_read_device,
			     system_unbound_wq,
			     &jlist.cl);

	closure_sync(&jlist.cl);

	if (!list_empty(list))
		c->journal.seq = list_entry(list->prev,
					    struct journal_replay,
					    list)->j.seq;

	return jlist.ret;
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

	return bch_btree_insert(c, id, &keylist_single(k), NULL, NULL);
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

	/* clamp journal size to 512MB (in sectors) */

	ret = bch_set_nr_journal_buckets(ca,
			clamp_t(unsigned, ca->sb.nbuckets >> 8,
				2, (1 << 20) / ca->sb.bucket_size));
	if (ret)
		return ret;

	for (i = 0; i < bch_nr_journal_buckets(&ca->sb); i++) {
		unsigned long r = ca->sb.first_bucket + i;

		bch_mark_metadata_bucket(ca, &ca->buckets[r], true);
		set_journal_bucket(ca, i, r);
	}

	return 0;
}

/* Journalling */

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

	if (!CACHE_DISCARD(&ca->mi) ||
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
			     c->journal.sectors_free * block_bytes(c),
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
	unsigned iter, i;
	atomic_t p;

	pr_debug("started");
	lockdep_assert_held(&c->journal.lock);

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

		c->journal.sectors_free = 0;
	}

	if (c->journal.sectors_free) {
		/*
		 * Check that the devices we are writing the journal
		 * to are still writable, and if not, pick new
		 * devices.
		 * See bch_journal_move that depends on this check.
		 */
		for (i = 0; i < bch_extent_ptrs(k); i++) {
			ca = PTR_CACHE(c, k, i);
			if (CACHE_STATE(&ca->mi) != CACHE_ACTIVE)
				goto pick_new_devices;
		}
		goto out;
	}

pick_new_devices:
	/*
	 * Determine location of the next journal write:
	 * XXX: sort caches by free journal space
	 */


	i = 0;
	while (i < bch_extent_ptrs(k)) {
		/*
		 * Don't wipe all ptrs, delete the ptr if the bucket is full
		 * then add back ptrs until we have the correct amount of
		 * replicas
		 */
		ca = PTR_CACHE(c, k, i);

		if (!ca->journal.sectors_free)
			bch_extent_drop_ptr(k, i);
		else
			i++;
	}

	for_each_cache_rcu(ca, c, iter) {
		struct journal_device *ja = &ca->journal;
		unsigned next = (ja->cur_idx + 1) %
			bch_nr_journal_buckets(&ca->sb);
		int same_cache = 0;

		/* Check that we don't already have a ptr to this cache */
		for (i = 0; i < bch_extent_ptrs(k); i++) {
			if (PTR_CACHE(c, k, i) == ca) {
				same_cache = 1;
				break;
			}
		}

		if (same_cache)
			continue;

		if ((CACHE_TIER(&ca->mi) != 0)
		    || (CACHE_STATE(&ca->mi) != CACHE_ACTIVE))
			continue;

		/* No space available on this device */
		if (next == ja->discard_idx)
			continue;

		BUG_ON(bch_extent_ptrs(k) >= BKEY_EXTENT_PTRS_MAX);

		ja->sectors_free = CACHE_BTREE_NODE_SIZE(&ca->sb) >>
			c->block_bits;

		ja->cur_idx = next;
		k->val[bch_extent_ptrs(k)] =
			PTR(0, bucket_to_sector(c,
					journal_bucket(ca, ja->cur_idx)),
			    ca->sb.nr_this_dev);

		bch_set_extent_ptrs(k, bch_extent_ptrs(k) + 1);

		if (bch_extent_ptrs(k) == CACHE_SET_META_REPLICAS_WANT(&c->sb))
			break;
	}

	for (i = 0; i < bch_extent_ptrs(k); i++) {
		ca = PTR_CACHE(c, k, i);
		if (!c->journal.sectors_free ||
			(c->journal.sectors_free > ca->journal.sectors_free))
			c->journal.sectors_free = ca->journal.sectors_free;
	}

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

	if (bio->bi_error)
		bch_cache_error(ca,
				"IO error %d writing journal at offset %zu",
				bio->bi_error, ca->journal.offset);

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

	BUG_ON(c->journal.sectors_free < set_blocks(w->data, block_bytes(c)));
	c->journal.sectors_free -= set_blocks(w->data, block_bytes(c));

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

		ca->journal.sectors_free -= set_blocks(w->data, block_bytes(c));

		bio = &ca->journal.bio;

		atomic_long_add(sectors, &ca->meta_sectors_written);

		ca->journal.offset = PTR_OFFSET(k, i);

		bio_reset(bio);
		bio->bi_iter.bi_sector	= ca->journal.offset;
		bio->bi_bdev		= ca->bdev;
		bio->bi_iter.bi_size	= sectors << 9;
		bio->bi_end_io		= journal_write_endio;
		bio->bi_private		= w;
		bio_set_op_attrs(bio, REQ_OP_WRITE,
				 REQ_SYNC|REQ_META|REQ_PREFLUSH|REQ_FUA);
		bch_bio_map(bio, w->data);

		trace_bcache_journal_write(bio);
		bio_list_add(&list, bio);

		SET_PTR_OFFSET(k, i, ca->journal.offset + sectors);

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
			   struct journal_res *res)
{
	BUG_ON(!res->ref);

	c->journal.u64s_remaining += res->nkeys;
	--c->journal.res_count;
	res->nkeys = 0;
	res->ref = 0;

	journal_unlock(c);
}

static bool __journal_res_get(struct cache_set *c, struct journal_res *res,
			      unsigned u64s_min, unsigned u64s_max,
			      u64 *start_time)
{
	unsigned actual_min = jset_u64s(u64s_min);
	unsigned actual_max = jset_u64s(u64s_max);

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

			if (*start_time)
				bch_time_stats_update(&c->journal_full_time,
						      *start_time);

			return true;
		}

		/* local_clock() can of course be 0 but we don't care */
		if (*start_time == 0)
			*start_time = local_clock();

		if (!c->journal.u64s_remaining) {
			journal_reclaim(c);

			if (!c->journal.u64s_remaining) {
				spin_unlock(&c->journal.lock);
				trace_bcache_journal_full(c);
				bch_btree_write_oldest(c);
				return false;
			}
		} else {
			/*
			 * Not much room for this journal entry (near the end of
			 * a journal bucket) but there's nothing in this journal
			 * entry yet - skip it and allocate a new journal entry
			 */
			if (!c->journal.cur->data->keys) {
				BUG_ON(test_bit(JOURNAL_DIRTY,
						&c->journal.flags));
				c->journal.sectors_free = 0;
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
 *
 * To ensure forward progress, the current task must not be holding any
 * btree node write locks.
 */
void bch_journal_res_get(struct cache_set *c, struct journal_res *res,
			 unsigned u64s_min, unsigned u64s_max)
{
	u64 start_time = 0;

	wait_event(c->journal.wait,
		   __journal_res_get(c, res, u64s_min, u64s_max, &start_time));
}

void bch_journal_set_dirty(struct cache_set *c, struct closure *parent)
{
	/*
	 * We sometimes need to write an empty journal entry to e.g. set a new
	 * btree root - but when that happens it's always going to be an
	 * immediate journal write someone is waiting on.
	 *
	 * Other than that, the journal write shouldn't be empty:
	 */
	BUG_ON(!parent && !c->journal.cur->data->keys);

	if (!test_and_set_bit(JOURNAL_DIRTY, &c->journal.flags))
		schedule_delayed_work(&c->journal.work,
				      msecs_to_jiffies(c->journal.delay_ms));

	if (parent) {
		BUG_ON(!closure_wait(&c->journal.cur->wait, parent));
		set_bit(JOURNAL_NEED_WRITE, &c->journal.flags);
	}
}

static inline void __bch_journal_add_keys(struct jset *j, enum btree_id id,
					  const struct bkey *k, unsigned nkeys,
					  unsigned level, unsigned type)
{
	struct jset_keys *jkeys = (struct jset_keys *) bset_bkey_last(j);

	jkeys->keys = nkeys;
	jkeys->btree_id = id;
	jkeys->level = level;
	jkeys->flags = 0;
	SET_JKEYS_TYPE(jkeys, type);

	memcpy(jkeys->start, k, sizeof(u64) * nkeys);
	j->keys += jset_u64s(nkeys);
}

void bch_journal_add_keys(struct cache_set *c, struct journal_res *res,
			  enum btree_id id, const struct bkey *k,
			  unsigned nkeys, unsigned level,
			  struct closure *parent)
{
	unsigned actual = jset_u64s(nkeys);

	BUG_ON(!res->ref);
	BUG_ON(actual > res->nkeys);
	res->nkeys -= actual;

	spin_lock(&c->journal.lock);
	__bch_journal_add_keys(c->journal.cur->data, id, k, nkeys,
			       level, JKEYS_BTREE_KEYS);
	bch_journal_set_dirty(c, parent);

	if (!res->nkeys)
		__bch_journal_res_put(c, res);
	else
		spin_unlock(&c->journal.lock);
}

void bch_journal_meta(struct cache_set *c, struct closure *parent)
{
	struct journal_res res;

	memset(&res, 0, sizeof(res));

	if (!CACHE_SYNC(&c->sb))
		return;

	bch_journal_res_get(c, &res, 0, 0);
	bch_journal_set_dirty(c, parent);
	bch_journal_res_put(c, &res);
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

	c->journal.delay_ms = 10;

	bkey_init(&j->key);

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

static bool bch_journal_writing_to_device(struct cache *ca)
{
	struct bkey *k;
	bool found = false;
	struct cache_set *c = ca->set;
	unsigned i, mov_dev = ca->sb.nr_this_dev;

	spin_lock(&c->journal.lock);

	k = &c->journal.key;
	for (i = 0; i < bch_extent_ptrs(k); i++) {
		if (PTR_DEV(k, i) == mov_dev) {
			found = true;
			break;
		}
	}

	spin_unlock(&c->journal.lock);
	return found;
}

/*
 * This asumes that ca has already been marked read-only so that
 * journal_reclaim won't pick buckets out of ca any more.
 * Hence, if the journal is not currently pointing to ca, there
 * will be no new writes to journal entries in ca after all the
 * pending ones have been flushed to disk.
 *
 * If the journal is being written to ca, write a new record, and
 * journal_reclaim will notice that the device is no longer writeable
 * and pick a new set of devices to write to.
 */

int bch_journal_move(struct cache *ca)
{
	struct closure cl;
	unsigned i, nr_buckets;
	u64 last_flushed_seq;
	struct cache_set *c = ca->set;
	int ret = 0;		/* Success */

	closure_init_stack(&cl);

	if (bch_journal_writing_to_device(ca)) {
		/*
		 * bch_journal_meta will write a record and we'll wait
		 * for the write to complete.
		 * Actually writing the journal (journal_write_locked)
		 * will call journal_reclaim which notices that the
		 * device is no longer writeable, and picks a new one.
		 */
		bch_journal_meta(c, &cl);
		/* Wait for the meta-data write */
		closure_sync(&cl);
		BUG_ON(bch_journal_writing_to_device(ca));
	}

	/*
	 * Flush all btree updates to backing store so that any
	 * journal entries written to ca become stale and are no
	 * longer needed.
	 */
	bch_btree_flush(c);

	/*
	 * Force a meta-data journal entry to be written so that
	 * we have newer journal entries in devices other than ca,
	 * and wait for the meta data write to complete.
	 */
	bch_journal_meta(c, &cl);
	closure_sync(&cl);

	/*
	 * Verify that we no longer need any of the journal entries in
	 * the device
	 */
	spin_lock(&c->journal.lock);
	last_flushed_seq = last_seq(&c->journal);
	spin_unlock(&c->journal.lock);

	nr_buckets = bch_nr_journal_buckets(&ca->sb);

	for (i = 0; i < nr_buckets; i += 1)
		BUG_ON(ca->journal.seq[i] > last_flushed_seq);

	return ret;
}
