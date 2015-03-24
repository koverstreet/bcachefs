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

/* Sequence number of oldest dirty journal entry */
#define last_seq(j)	((j)->seq - fifo_used(&(j)->pin) + 1)

#define for_each_jset_key(k, jkeys, jset)			\
	for_each_jset_jkeys(jkeys, jset)			\
		if (JKEYS_TYPE(jkeys) == JKEYS_BTREE_KEYS)	\
			for (k = (jkeys)->start;		\
			     k < bset_bkey_last(jkeys);		\
			     k = bkey_next(k))

static inline void bch_journal_add_entry(struct jset *j, const void *data,
					 size_t u64s, unsigned type,
					 enum btree_id id, unsigned level)
{
	struct jset_entry *jkeys = (struct jset_entry *) bset_bkey_last(j);

	jkeys->u64s = u64s;
	jkeys->btree_id = id;
	jkeys->level = level;
	jkeys->flags = 0;
	SET_JKEYS_TYPE(jkeys, type);

	memcpy(jkeys->_data, data, u64s * sizeof(u64));
	j->u64s += jset_u64s(u64s);
}

static struct jset_entry *bch_journal_find_entry(struct jset *j, unsigned type,
						enum btree_id id)
{
	struct jset_entry *jkeys;

	for_each_jset_jkeys(jkeys, j)
		if (JKEYS_TYPE(jkeys) == type && jkeys->btree_id == id)
			return jkeys;

	return NULL;
}

struct bkey_i *bch_journal_find_btree_root(struct cache_set *c, struct jset *j,
					   enum btree_id id, unsigned *level)
{
	struct bkey_i *k;
	struct jset_entry *jkeys =
		bch_journal_find_entry(j, JKEYS_BTREE_ROOT, id);

	if (!jkeys)
		return NULL;

	k = jkeys->start;
	*level = jkeys->level;

	if (!jkeys->u64s || jkeys->u64s != k->k.u64s ||
	    bkey_invalid(c, BKEY_TYPE_BTREE, bkey_i_to_s_c(k))) {
		bch_cache_set_error(c, "invalid btree root in journal");
		return NULL;
	}

	*level = jkeys->level;
	return k;
}

static void bch_journal_add_btree_root(struct jset *j, enum btree_id id,
				       struct bkey_i *k, unsigned level)
{
	bch_journal_add_entry(j, k, k->k.u64s, JKEYS_BTREE_ROOT, id, level);
}

static inline void bch_journal_add_prios(struct cache_set *c, struct jset *j)
{
	bch_journal_add_entry(j, c->journal.prio_buckets, c->sb.nr_in_set,
			      JKEYS_PRIO_PTRS, 0, 0);
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

/*
 * Given a journal entry we just read, add it to the list of journal entries to
 * be replayed:
 */
static enum {
	JOURNAL_ENTRY_ADD_ERROR,
	JOURNAL_ENTRY_ADD_OUT_OF_RANGE,
	JOURNAL_ENTRY_ADD_OK,

} journal_entry_add(struct journal_list *jlist, struct jset *j)
{
	struct journal_replay *i, *pos;
	struct list_head *where;
	size_t bytes = set_bytes(j);
	int ret = JOURNAL_ENTRY_ADD_OUT_OF_RANGE;

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

	ret = JOURNAL_ENTRY_ADD_OK;

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
		ret = JOURNAL_ENTRY_ADD_ERROR;
		goto out;
	}

	memcpy(&i->j, j, bytes);
	list_add(&i->list, where);

	pr_debug("seq %llu", j->seq);
out:
	mutex_unlock(&jlist->lock);
	return ret;
}

static enum {
	JOURNAL_ENTRY_BAD,
	JOURNAL_ENTRY_REREAD,
	JOURNAL_ENTRY_OK,
} journal_entry_validate(struct cache *ca, const struct jset *j, u64 sector,
			 unsigned bucket_sectors_left, unsigned sectors_read)
{
	size_t bytes = set_bytes(j);
	u64 got, expect;

	if (bch_meta_read_fault("journal"))
		return JOURNAL_ENTRY_BAD;

	if (j->magic != jset_magic(&ca->set->sb)) {
		pr_debug("bad magic while reading journal from %llu", sector);
		return JOURNAL_ENTRY_BAD;
	}

	got = j->version;
	expect = BCACHE_JSET_VERSION;
	if (got != expect) {
		__bch_cache_error(ca,
			"bad journal version (got %llu expect %llu) sector %lluu",
			got, expect, sector);
		return JOURNAL_ENTRY_BAD;
	}

	if (bytes > bucket_sectors_left << 9 ||
	    bytes > PAGE_SIZE << JSET_BITS) {
		__bch_cache_error(ca,
			"journal entry too big (%zu bytes), sector %lluu",
			bytes, sector);
		return JOURNAL_ENTRY_BAD;
	}

	if (bytes > sectors_read << 9)
		return JOURNAL_ENTRY_REREAD;

	got = j->csum;
	expect = csum_set(j, JSET_CSUM_TYPE(j));
	if (got != expect) {
		__bch_cache_error(ca,
			"journal checksum bad (got %llu expect %llu), sector %lluu",
			got, expect, sector);
		return JOURNAL_ENTRY_BAD;
	}

	if (j->last_seq > j->seq) {
		__bch_cache_error(ca,
				  "invalid journal entry: last_seq > seq");
		return JOURNAL_ENTRY_BAD;
	}

	return JOURNAL_ENTRY_OK;
}

static int journal_read_bucket(struct cache *ca, struct journal_list *jlist,
			       unsigned bucket, u64 *seq)
{
	struct cache_set *c = ca->set;
	struct journal_device *ja = &ca->journal;
	struct bio *bio = &ja->bio;
	struct jset *j, *data;
	unsigned blocks, sectors_read, bucket_offset = 0;
	u64 sector = bucket_to_sector(ca, journal_bucket(ca, bucket));
	bool entries_found = false;
	int ret = 0;

	data = (void *) __get_free_pages(GFP_KERNEL, JSET_BITS);
	if (!data) {
		mutex_lock(&jlist->cache_set_buffer_lock);
		data = c->journal.w[0].data;
	}

	pr_debug("reading %u", bucket);

	while (bucket_offset < ca->mi.bucket_size) {
reread:
		sectors_read = min_t(unsigned,
				     ca->mi.bucket_size - bucket_offset,
				     PAGE_SECTORS << JSET_BITS);

		bio_reset(bio);
		bio->bi_bdev		= ca->disk_sb.bdev;
		bio->bi_iter.bi_sector	= sector + bucket_offset;
		bio->bi_iter.bi_size	= sectors_read << 9;
		bio_set_op_attrs(bio, REQ_OP_READ, 0);
		bch_bio_map(bio, data);

		ret = submit_bio_wait(bio);
		if (bch_meta_read_fault("journal"))
			ret = -EIO;
		if (ret) {
			__bch_cache_error(ca,
				"IO error %d reading journal from bucket_offset %llu",
				ret, sector + bucket_offset);
			goto err;
		}

		/* This function could be simpler now since we no longer write
		 * journal entries that overlap bucket boundaries; this means
		 * the start of a bucket will always have a valid journal entry
		 * if it has any journal entries at all.
		 */

		j = data;
		while (sectors_read) {
			switch (journal_entry_validate(ca, j,
					sector + bucket_offset,
					ca->mi.bucket_size - bucket_offset,
					sectors_read)) {
			case JOURNAL_ENTRY_BAD:
				/* XXX: don't skip rest of bucket if single
				 * checksum error */
				goto err;
			case JOURNAL_ENTRY_REREAD:
				goto reread;
			case JOURNAL_ENTRY_OK:
				break;
			}

			/*
			 * This happens sometimes if we don't have discards on -
			 * when we've partially overwritten a bucket with new
			 * journal entries. We don't need the rest of the
			 * bucket:
			 */
			if (j->seq < ja->bucket_seq[bucket])
				goto out;

			ja->bucket_seq[bucket] = j->seq;

			switch (journal_entry_add(jlist, j)) {
			case JOURNAL_ENTRY_ADD_ERROR:
				ret = -ENOMEM;
				goto err;
			case JOURNAL_ENTRY_ADD_OUT_OF_RANGE:
				break;
			case JOURNAL_ENTRY_ADD_OK:
				entries_found = true;
				break;
			}

			if (j->seq > *seq)
				*seq = j->seq;

			blocks = set_blocks(j, block_bytes(c));

			pr_debug("next");
			bucket_offset	+= blocks * ca->sb.block_size;
			sectors_read	-= blocks * ca->sb.block_size;
			j = ((void *) j) + blocks * block_bytes(ca);
		}
	}
out:
	ret = entries_found;
err:
	if (data == c->journal.w[0].data)
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
	struct request_queue *q = bdev_get_queue(ca->disk_sb.bdev);

	unsigned nr_buckets = bch_nr_journal_buckets(&ca->sb);
	DECLARE_BITMAP(bitmap, nr_buckets);
	unsigned i, l, r;
	u64 seq = 0;

	bitmap_zero(bitmap, nr_buckets);
	pr_debug("%u journal buckets", nr_buckets);

	if (!blk_queue_nonrot(q))
		goto linear_scan;

	/*
	 * If the device supports discard but not secure discard, we can't do
	 * the fancy fibonacci hash/binary search because the live journal
	 * entries might not form a contiguous range:
	 */
	if (blk_queue_discard(q) &&
	    !blk_queue_secure_erase(q)) {
		for (i = 0; i < nr_buckets; i++)
			read_bucket(i);
		goto search_done;
	}

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
	r = find_next_bit(bitmap, nr_buckets, l + 1);
	pr_debug("starting binary search, l %u r %u", l, r);

	while (l + 1 < r) {
		unsigned m = (l + r) >> 1;
		u64 cur_seq = seq;

		read_bucket(m);

		if (cur_seq != seq)
			l = m;
		else
			r = m;
	}

search_done:
	/* Find the journal bucket with the highest sequence number: */
	seq = 0;

	for (i = 0; i < nr_buckets; i++)
		if (ja->bucket_seq[i] > seq) {
			/*
			 * When journal_next_bucket() goes to allocate for
			 * the first time, it'll use the bucket after
			 * ja->cur_idx
			 */
			ja->cur_idx = i;
			seq = ja->bucket_seq[i];
		}

	/*
	 * Set last_idx and discard_idx to indicate the entire journal is full
	 * and needs to be reclaimed - journal reclaim will immediately reclaim
	 * whatever isn't pinned when it first runs:
	 */
	ja->last_idx = ja->discard_idx = (i + 1) % nr_buckets;

	/*
	 * Read buckets in reverse order until we stop finding more journal
	 * entries:
	 */
	for (i = (ja->cur_idx + nr_buckets - 1) % nr_buckets;
	     i != ja->cur_idx;
	     i = (i + nr_buckets - 1) % nr_buckets)
		if (!test_bit(i, bitmap) &&
		    !read_bucket(i))
			break;

	closure_return(cl);
#undef read_bucket
}

static void journal_entries_free(struct list_head *list)
{

	while (!list_empty(list)) {
		struct journal_replay *i =
			list_first_entry(list, struct journal_replay, list);
		list_del(&i->list);
		kfree(i);
	}
}

const char *bch_journal_read(struct cache_set *c, struct list_head *list)
{
	struct jset_entry *prio_ptrs;
	struct journal_list jlist;
	struct journal_replay *i;
	struct jset *j;
	atomic_t *p;
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

	if (jlist.ret) {
		journal_entries_free(list);

		return jlist.ret == -ENOMEM
			? "cannot allocate memory for journal"
			: "error reading journal";
	}

	if (list_empty(list))
		return "no journal entries found";

	j = &list_entry(list->prev, struct journal_replay, list)->j;

	if (j->seq - j->last_seq + 1 > c->journal.pin.size)
		return "too many journal entries open for refcount fifo";

	c->journal.pin.back = j->seq - j->last_seq + 1;

	c->journal.seq = j->seq;
	c->journal.last_seq_ondisk = j->last_seq;

	BUG_ON(last_seq(&c->journal) != j->last_seq);

	i = list_first_entry(list, struct journal_replay, list);

	fifo_for_each_entry_ptr(p, &c->journal.pin, iter) {
		u64 seq = last_seq(&c->journal) +
			fifo_entry_idx(&c->journal.pin, p);

		if (!i || i->j.seq != seq) {
			atomic_set(p, 0);

			bch_cache_set_error(c,
				"bcache: journal entry %llu missing! (replaying %llu-%llu)",
				seq, last_seq(&c->journal), c->journal.seq);
		} else {
			atomic_set(p, 1);

			i = list_next_entry(i, list);
			if (&i->list == list)
				i = NULL;
		}
	}

	prio_ptrs = bch_journal_find_entry(j, JKEYS_PRIO_PTRS, 0);
	if (!prio_ptrs)
		return "prio bucket ptrs not found";

	memcpy(c->journal.prio_buckets,
	       prio_ptrs->_data,
	       prio_ptrs->u64s * sizeof(u64));

	return NULL;
}

void bch_journal_mark(struct cache_set *c, struct list_head *list)
{
	struct bkey_i *k;
	struct jset_entry *j;
	struct journal_replay *r;

	list_for_each_entry(r, list, list)
		for_each_jset_key(k, j, &r->j) {
			if ((j->level || j->btree_id == BTREE_ID_EXTENTS) &&
			    !bkey_invalid(c, j->level
					  ? BKEY_TYPE_BTREE : j->btree_id,
					  bkey_i_to_s_c(k)))
				__bch_btree_mark_key(c, j->level,
						     bkey_i_to_s_c(k));
		}
}

static int bch_journal_replay_key(struct cache_set *c, enum btree_id id,
				  struct bkey_i *k)
{
	int ret;
	BKEY_PADDED(key) temp;
	bool do_subtract = id == BTREE_ID_EXTENTS && k->k.type == BCH_EXTENT;

	trace_bcache_journal_replay_key(&k->k);

	if (do_subtract)
		bkey_copy(&temp.key, k);

	ret = bch_btree_insert(c, id, &keylist_single(k), NULL, NULL);
	if (ret)
		return ret;

	/*
	 * Subtract sectors after replay since bch_btree_insert() added
	 * them again
	 */
	if (do_subtract)
		__bch_add_sectors(c, NULL, bkey_i_to_s_c_extent(&temp.key),
				  bkey_start_offset(&temp.key.k),
				  -temp.key.k.size, false);

	return 0;
}

int bch_journal_replay(struct cache_set *c, struct list_head *list)
{
	int ret = 0, keys = 0, entries = 0;
	struct bkey_i *k;
	struct jset_entry *jkeys;
	struct journal_replay *i =
		list_entry(list->prev, struct journal_replay, list);

	list_for_each_entry(i, list, list) {
		c->journal.cur_pin =
			&c->journal.pin.data[((c->journal.pin.back - 1 -
					       (c->journal.seq - i->j.seq)) &
					      c->journal.pin.mask)];

		BUG_ON(atomic_read(c->journal.cur_pin) != 1);

		for_each_jset_key(k, jkeys, &i->j) {
			cond_resched();
			ret = bch_journal_replay_key(c, jkeys->btree_id, k);
			if (ret)
				goto err;

			keys++;
		}

		if (atomic_dec_and_test(c->journal.cur_pin))
			wake_up(&c->journal.wait);

		entries++;
	}

	pr_info("journal replay done, %i keys in %i entries, seq %llu",
		keys, entries, c->journal.seq);
err:
	if (ret)
		pr_err("journal replay error: %d", ret);

	journal_entries_free(list);

	return ret;
}

static int bch_set_nr_journal_buckets(struct cache *ca, unsigned nr)
{
	unsigned u64s = bch_journal_buckets_offset(&ca->sb) + nr;
	u64 *p;
	int ret;

	ret = bch_super_realloc(&ca->disk_sb, u64s);
	if (ret)
		return ret;

	p = krealloc(ca->journal.bucket_seq,
		     nr * sizeof(u64),
		     GFP_KERNEL|__GFP_ZERO);
	if (!p)
		return -ENOMEM;

	ca->journal.bucket_seq = p;
	ca->sb.u64s = u64s;

	return 0;
}

int bch_cache_journal_alloc(struct cache *ca)
{
	int ret;
	unsigned i;

	if (CACHE_TIER(&ca->mi) != 0)
		return 0;

	if (dynamic_fault("bcache:add:journal_alloc"))
		return -ENOMEM;

	/* clamp journal size to 512MB (in sectors) */

	ret = bch_set_nr_journal_buckets(ca,
			clamp_t(unsigned, ca->mi.nbuckets >> 8,
				8, (1 << 20) / ca->mi.bucket_size));
	if (ret)
		return ret;

	for (i = 0; i < bch_nr_journal_buckets(&ca->sb); i++) {
		unsigned long r = ca->mi.first_bucket + i;

		bch_mark_metadata_bucket(ca, &ca->buckets[r], true);
		set_journal_bucket(ca, i, r);
	}

	return 0;
}

/* Journalling */

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
	    !blk_queue_discard(bdev_get_queue(ca->disk_sb.bdev))) {
		ja->discard_idx = ja->last_idx;
		return;
	}

	switch (atomic_read(&ja->discard_in_flight)) {
	case DISCARD_IN_FLIGHT:
		break;

	case DISCARD_DONE:
		ja->discard_idx = (ja->discard_idx + 1) %
			bch_nr_journal_buckets(&ca->sb);

		atomic_set(&ja->discard_in_flight, DISCARD_READY);
		/* fallthrough */

	case DISCARD_READY:
		if (ja->discard_idx == ja->last_idx)
			break;

		atomic_set(&ja->discard_in_flight, DISCARD_IN_FLIGHT);

		bio_init(bio);
		bio_set_op_attrs(bio, REQ_OP_DISCARD, 0);
		bio->bi_iter.bi_sector	=
			bucket_to_sector(ca,
					 journal_bucket(ca, ja->discard_idx));
		bio->bi_bdev		= ca->disk_sb.bdev;
		bio->bi_max_vecs	= 1;
		bio->bi_io_vec		= bio->bi_inline_vecs;
		bio->bi_iter.bi_size	= bucket_bytes(ca);
		bio->bi_end_io		= journal_discard_endio;

		closure_get(&ca->set->cl);
		INIT_WORK(&ja->discard_work, journal_discard_work);
		schedule_work(&ja->discard_work);

		break;
	default:
		BUG();
	}
}

/* Number of journal buckets which may be discarded and reused */
static inline unsigned journal_free_buckets(struct cache *ca)
{
	struct journal_device *ja = &ca->journal;
	unsigned nr = bch_nr_journal_buckets(&ca->sb);

	return (ja->last_idx - ja->cur_idx + nr - 1) % nr;
}

#define JSET_SECTORS (PAGE_SECTORS << JSET_BITS)

/* Number of u64s we can write to the current journal bucket */
static size_t journal_write_u64s_remaining(struct cache_set *c)
{
	ssize_t u64s = (min_t(size_t,
			      c->journal.sectors_free,
			      JSET_SECTORS) << 9) / sizeof(u64);

	/* Subtract off some for the btree roots */
	u64s -= BTREE_ID_NR * (JSET_KEYS_U64s + BKEY_EXTENT_MAX_U64s);

	/* And for the prio pointers */
	u64s -= JSET_KEYS_U64s + c->sb.nr_in_set;

	return max_t(ssize_t, 0L, u64s);
}

static void journal_entry_no_room(struct cache_set *c)
{
	struct bkey_s_extent e = bkey_i_to_s_extent(&c->journal.key);
	struct bch_extent_ptr *ptr;
	struct cache *ca;

	extent_for_each_ptr_backwards(e, ptr)
		if (!(ca = PTR_CACHE(c, ptr)) ||
		    ca->journal.sectors_free <= c->journal.sectors_free)
			bch_extent_drop_ptr(e, ptr - e.v->ptr);

	c->journal.sectors_free = 0;
	c->journal.u64s_remaining = 0;
}

/**
 * journal_reclaim_work - free up journal buckets
 *
 * Background journal reclaim writes out btree nodes. It should be run
 * early enough so that we never completely run out of journal buckets.
 *
 * High watermarks for triggering background reclaim:
 * - FIFO has fewer than 512 entries left
 * - fewer than 25% journal buckets free
 *
 * Background reclaim runs until low watermarks are reached:
 * - FIFO has more than 1024 entries left
 * - more than 50% journal buckets free
 *
 * As long as a reclaim can complete in the time it takes to fill up
 * 512 journal entries or 25% of all journal buckets, then
 * journal_next_bucket() should not stall.
 */
static void journal_reclaim_work(struct work_struct *work)
{
	struct cache_set *c = container_of(work, struct cache_set,
					   journal.reclaim_work);
	struct cache *ca;
	u64 oldest_seq = 0;
	unsigned iter;
	bool flush = false;
	size_t fifo_cutoff;

	pr_debug("started");
	spin_lock(&c->journal.lock);

	rcu_read_lock();

	group_for_each_cache_rcu(ca, &c->cache_tiers[0], iter) {
		struct journal_device *ja = &ca->journal;
		unsigned nr = bch_nr_journal_buckets(&ca->sb);
		unsigned next = (ja->cur_idx + (nr >> 1)) % nr;

		/*
		 * Write out enough btree nodes to free up 50% journal
		 * buckets
		 */
		if (journal_free_buckets(ca) < (nr >> 1)) {
			oldest_seq = max_t(u64, oldest_seq,
					   ja->bucket_seq[next]);
			flush = true;
		}
	}

	rcu_read_unlock();

	fifo_cutoff = (c->journal.pin.size >> 5);
	if (fifo_free(&c->journal.pin) <= fifo_cutoff) {
		/* Write out enough btree nodes to free up 33% of the FIFO */
		oldest_seq = max_t(u64, oldest_seq,
				   last_seq(&c->journal)
				   + fifo_cutoff);
		flush = true;
	}

	if (!flush) {
		spin_unlock(&c->journal.lock);
		return;
	}

	BUG_ON(oldest_seq == 0);
	oldest_seq -= last_seq(&c->journal);
	spin_unlock(&c->journal.lock);
	bch_btree_write_oldest(c, oldest_seq);
}

/**
 * journal_reclaim_fast - do the fast part of journal reclaim
 *
 * Called from IO submission context, does not block. Cleans up after btree
 * write completions by advancing the journal pin and each cache's last_idx,
 * kicking off discards and background reclaim as necessary.
 */
static void journal_reclaim_fast(struct cache_set *c)
{
	struct cache *ca;
	u64 last_seq;
	atomic_t p;
	unsigned iter;
	bool need_reclaim = false;

	lockdep_assert_held(&c->journal.lock);

	/*
	 * Unpin journal entries whose reference counts reached zero, meaning
	 * all btree nodes got written out
	 */
	while (!atomic_read(&fifo_front(&c->journal.pin)))
		BUG_ON(!fifo_pop(&c->journal.pin, p));

	/* If less than 15% space free, kick off background reclaim */
	if (fifo_free(&c->journal.pin) <= (c->journal.pin.size >> 6))
		need_reclaim = true;

	last_seq = c->journal.last_seq_ondisk;

	rcu_read_lock();

	/*
	 * Advance last_idx to point to the oldest journal entry containing
	 * btree node updates that have not yet been written out
	 */
	group_for_each_cache_rcu(ca, &c->cache_tiers[0], iter) {
		struct journal_device *ja = &ca->journal;
		unsigned nr = bch_nr_journal_buckets(&ca->sb);

		while (ja->last_idx != ja->cur_idx &&
		       ja->bucket_seq[ja->last_idx] < last_seq)
			ja->last_idx = (ja->last_idx + 1) % nr;

		/*
		 * If less than 25% journal buckets free, kick off
		 * background reclaim
		 */
		if (journal_free_buckets(ca) < (nr >> 2))
			need_reclaim = true;

		do_journal_discard(ca);
	}

	rcu_read_unlock();

	if (need_reclaim)
		queue_work(system_long_wq, &c->journal.reclaim_work);
}

/**
 * journal_next_bucket - move on to the next journal bucket if possible
 */
static void journal_next_bucket(struct cache_set *c)
{
	struct bkey_s_extent e = bkey_i_to_s_extent(&c->journal.key);
	struct bch_extent_ptr *ptr;
	struct cache *ca;
	unsigned iter;

	pr_debug("started");
	lockdep_assert_held(&c->journal.lock);

	/*
	 * only supposed to be called when we're out of space/haven't started a
	 * new journal entry
	 */
	BUG_ON(c->journal.u64s_remaining);
	BUG_ON(c->journal.cur->data->u64s);

	journal_reclaim_fast(c);

	rcu_read_lock();

	/*
	 * Drop any pointers to devices that have been removed, are no longer
	 * empty, or filled up their current journal bucket:
	 */
	extent_for_each_ptr_backwards(e, ptr)
		if (!(ca = PTR_CACHE(c, ptr)) ||
		    !ca->journal.sectors_free ||
		    CACHE_STATE(&ca->mi) != CACHE_ACTIVE)
			bch_extent_drop_ptr(e, ptr - e.v->ptr);

	/*
	 * Determine location of the next journal write:
	 * XXX: sort caches by free journal space
	 */
	group_for_each_cache_rcu(ca, &c->cache_tiers[0], iter) {
		struct journal_device *ja = &ca->journal;
		unsigned next, remaining, nr_buckets =
			bch_nr_journal_buckets(&ca->sb);

		if (bch_extent_ptrs(e) == CACHE_SET_META_REPLICAS_WANT(&c->sb))
			break;

		/*
		 * Check that we can use this device, and aren't already using
		 * it:
		 */
		if (bch_extent_has_device(extent_s_to_s_c(e),
					  ca->sb.nr_this_dev))
			continue;

		next = (ja->cur_idx + 1) % nr_buckets;
		remaining = (ja->discard_idx + nr_buckets - next) % nr_buckets;

		if (!remaining)
			continue;

		/*
		 * Don't use the last bucket unless writing the new last_seq
		 * will make another bucket available:
		 */
		if (remaining == 1 &&
		    ja->bucket_seq[(next + 1) % nr_buckets] >=
		    last_seq(&c->journal))
			continue;

		BUG_ON(bch_extent_ptrs(e) >= BKEY_EXTENT_PTRS_MAX);

		ja->sectors_free = ca->mi.bucket_size;

		ja->cur_idx = next;
		e.v->ptr[bch_extent_ptrs(e)] =
			PTR(0, bucket_to_sector(ca,
					journal_bucket(ca, ja->cur_idx)),
			    ca->sb.nr_this_dev);

		ja->bucket_seq[ja->cur_idx] = c->journal.seq;

		trace_bcache_journal_next_bucket(ca, ja->cur_idx,
				ja->last_idx, ja->discard_idx);
		bch_set_extent_ptrs(e, bch_extent_ptrs(e) + 1);
	}

	/* set c->journal.sectors_free to the min of any device */
	c->journal.sectors_free = UINT_MAX;

	extent_for_each_online_device(c, e, ptr, ca)
		c->journal.sectors_free = min(c->journal.sectors_free,
					     ca->journal.sectors_free);
	if (c->journal.sectors_free == UINT_MAX)
		c->journal.sectors_free = 0;

	rcu_read_unlock();
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

	if (test_bit(JOURNAL_REPLAY_DONE, &j->flags))
		j->cur_pin = &fifo_back(&j->pin);

	j->cur->data->seq	= ++j->seq;
	j->cur->data->u64s	= 0;
	j->u64s_remaining	= 0;
}

static void journal_write_endio(struct bio *bio)
{
	struct cache *ca = container_of(bio, struct cache, journal.bio);
	struct journal_write *w = bio->bi_private;

	if (bio->bi_error || bch_meta_write_fault("journal"))
		bch_cache_error(ca, "IO error %d writing journal",
				bio->bi_error);

	closure_put(&w->c->journal.io);
	percpu_ref_put(&ca->ref);
}

static void journal_write_done(struct closure *cl)
{
	struct journal *j = container_of(cl, struct journal, io);
	struct journal_write *w = (j->cur == j->w)
		? &j->w[1]
		: &j->w[0];

	j->last_seq_ondisk = w->data->last_seq;

	__closure_wake_up(&w->wait);

	atomic_set(&j->in_flight, 0);
	wake_up(&j->wait);

	if (test_bit(JOURNAL_NEED_WRITE, &j->flags))
		mod_delayed_work(system_wq, &j->write_work, 0);
}

static void journal_write_locked(struct closure *cl)
	__releases(c->journal.lock)
{
	struct cache_set *c = container_of(cl, struct cache_set, journal.io);
	struct cache *ca;
	struct journal_write *w = c->journal.cur;
	struct bkey_s_extent e = bkey_i_to_s_extent(&c->journal.key);
	struct bch_extent_ptr *ptr;
	BKEY_PADDED(k) tmp;
	unsigned i, sectors;

	struct bio *bio;
	struct bio_list list;
	bio_list_init(&list);

	BUG_ON(c->journal.res_count);
	BUG_ON(journal_full(&c->journal));

	clear_bit(JOURNAL_NEED_WRITE, &c->journal.flags);
	clear_bit(JOURNAL_DIRTY, &c->journal.flags);
	cancel_delayed_work(&c->journal.write_work);

	spin_lock(&c->btree_root_lock);

	for (i = 0; i < BTREE_ID_NR; i++) {
		struct btree *b = c->btree_roots[i];

		if (b)
			bch_journal_add_btree_root(w->data, i,
						   &b->key, b->level);
	}

	spin_unlock(&c->btree_root_lock);

	bch_journal_add_prios(c, w->data);

	w->data->read_clock	= c->prio_clock[READ].hand;
	w->data->write_clock	= c->prio_clock[WRITE].hand;
	w->data->magic		= jset_magic(&c->sb);
	w->data->version	= BCACHE_JSET_VERSION;
	w->data->last_seq	= last_seq(&c->journal);

	SET_JSET_CSUM_TYPE(w->data, CACHE_PREFERRED_CSUM_TYPE(&c->sb));
	w->data->csum		= csum_set(w->data, JSET_CSUM_TYPE(w->data));

	sectors = set_blocks(w->data, block_bytes(c)) * c->sb.block_size;

	BUG_ON(sectors > c->journal.sectors_free);
	c->journal.sectors_free -= sectors;

	extent_for_each_ptr(e, ptr) {
		rcu_read_lock();
		ca = PTR_CACHE(c, ptr);
		if (ca)
			percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		if (!ca) {
			/* XXX: fix this */
			pr_err("missing journal write\n");
			continue;
		}

		BUG_ON(sectors > ca->journal.sectors_free);
		ca->journal.sectors_free -= sectors;

		/*
		 * If we don't have enough space for a full-sized journal
		 * entry, go to the next bucket. We do this check after
		 * the write, so that if our bucket size is really small
		 * we don't get stuck forever.
		 */
		if (ca->journal.sectors_free < JSET_SECTORS) {
			c->journal.sectors_free = 0;
			ca->journal.sectors_free = 0;
		}

		bio = &ca->journal.bio;

		atomic_long_add(sectors, &ca->meta_sectors_written);

		bio_reset(bio);
		bio->bi_iter.bi_sector	= PTR_OFFSET(ptr);
		bio->bi_bdev		= ca->disk_sb.bdev;
		bio->bi_iter.bi_size	= sectors << 9;
		bio->bi_end_io		= journal_write_endio;
		bio->bi_private		= w;
		bio_set_op_attrs(bio, REQ_OP_WRITE,
				 REQ_SYNC|REQ_META|REQ_PREFLUSH|REQ_FUA);
		bch_bio_map(bio, w->data);

		trace_bcache_journal_write(bio);
		bio_list_add(&list, bio);

		SET_PTR_OFFSET(ptr, PTR_OFFSET(ptr) + sectors);

		ca->journal.bucket_seq[ca->journal.cur_idx] = w->data->seq;
	}

	/*
	 * Make a copy of the key we're writing to for check_mark_super, since
	 * journal_next_bucket will change it
	 */
	bkey_reassemble(&tmp.k, to_bkey_s_c(e));

	atomic_dec_bug(&fifo_back(&c->journal.pin));
	bch_journal_next(&c->journal);
	wake_up(&c->journal.wait);

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
					   journal.write_work);
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
	lockdep_assert_held(&c->journal.lock);

	BUG_ON(!res->ref);

	c->journal.u64s_remaining += res->nkeys;
	--c->journal.res_count;
	res->nkeys = 0;
	res->ref = 0;

	if (parent && test_bit(JOURNAL_DIRTY, &c->journal.flags)) {
		BUG_ON(!closure_wait(&c->journal.cur->wait, parent));
		set_bit(JOURNAL_NEED_WRITE, &c->journal.flags);
	}

	journal_unlock(c);
}

static inline bool journal_bucket_has_room(struct cache_set *c)
{
	return (c->journal.sectors_free && fifo_free(&c->journal.pin) > 1);
}

static bool __journal_res_get(struct cache_set *c, struct journal_res *res,
			      unsigned u64s_min, unsigned u64s_max,
			      u64 *start_time)
{
	BUG_ON(res->ref);
	BUG_ON(u64s_max < u64s_min);

	spin_lock(&c->journal.lock);

	while (1) {
		/* Check if there is still room in the current journal entry */
		if (u64s_min < c->journal.u64s_remaining) {
			res->nkeys = min_t(unsigned, u64s_max,
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

		/* If the current journal entry is not empty, write it */
		if (c->journal.cur->data->u64s) {
			__set_current_state(TASK_RUNNING);
			/*
			 * If the previous journal entry is still being written,
			 * we have to wait
			 */
			if (!journal_try_write(c)) {
				trace_bcache_journal_entry_full(c);
				return false;
			}

			spin_lock(&c->journal.lock);
			continue;
		}

		/*
		 * There's room in the entry, but not enough for our
		 * reservation: since we haven't added any keys yet, we're at
		 * the end of a bucket, so skip to the end of the bucket
		 */
		if (c->journal.u64s_remaining) {
			BUG_ON(test_bit(JOURNAL_DIRTY,
					&c->journal.flags) &&
			       !test_bit(JOURNAL_NEED_WRITE,
					 &c->journal.flags));

			journal_entry_no_room(c);
		}

		/* If there's room in the journal bucket, start a new entry */
		if (journal_bucket_has_room(c)) {
			c->journal.u64s_remaining =
				journal_write_u64s_remaining(c);
			BUG_ON(!c->journal.u64s_remaining);
			pr_debug("done: %d", c->journal.u64s_remaining);
			continue;
		}

		/* Try to get a new journal bucket */
		journal_next_bucket(c);

		if (!journal_bucket_has_room(c)) {
			/* Still no room, we have to wait */
			spin_unlock(&c->journal.lock);
			trace_bcache_journal_full(c);
			queue_work(system_long_wq, &c->journal.reclaim_work);
			return false;
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

void bch_journal_set_dirty(struct cache_set *c)
{
	if (!test_and_set_bit(JOURNAL_DIRTY, &c->journal.flags))
		schedule_delayed_work(&c->journal.write_work,
				      msecs_to_jiffies(c->journal.delay_ms));
}

void bch_journal_add_keys(struct cache_set *c, struct journal_res *res,
			  enum btree_id id, const struct bkey_i *k,
			  unsigned level)
{
	unsigned actual = jset_u64s(k->k.u64s);

	BUG_ON(!res->ref);
	BUG_ON(actual > res->nkeys);
	res->nkeys -= actual;

	spin_lock(&c->journal.lock);
	bch_journal_add_entry(c->journal.cur->data, k, k->k.u64s,
			      JKEYS_BTREE_KEYS, id, level);
	bch_journal_set_dirty(c);
	spin_unlock(&c->journal.lock);
}

void bch_journal_meta(struct cache_set *c, struct closure *parent)
{
	struct journal_res res;
	unsigned u64s = jset_u64s(0);

	memset(&res, 0, sizeof(res));

	if (!CACHE_SYNC(&c->sb))
		return;

	bch_journal_res_get(c, &res, u64s, u64s);
	if (res.ref) {
		bch_journal_set_dirty(c);
		bch_journal_res_put(c, &res, parent);
	}
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
	INIT_DELAYED_WORK(&j->write_work, journal_write_work);
	INIT_WORK(&j->reclaim_work, journal_reclaim_work);

	c->journal.delay_ms = 10;

	bkey_extent_init(&j->key);

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
	struct cache_set *c = ca->set;
	bool ret;

	spin_lock(&c->journal.lock);
	ret = bch_extent_has_device(bkey_i_to_s_c_extent(&c->journal.key),
				    ca->sb.nr_this_dev);
	spin_unlock(&c->journal.lock);

	return ret;
}

/*
 * This asumes that ca has already been marked read-only so that
 * journal_next_bucket won't pick buckets out of ca any more.
 * Hence, if the journal is not currently pointing to ca, there
 * will be no new writes to journal entries in ca after all the
 * pending ones have been flushed to disk.
 *
 * If the journal is being written to ca, write a new record, and
 * journal_next_bucket will notice that the device is no longer
 * writeable and pick a new set of devices to write to.
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
		 * will call journal_next_bucket which notices that the
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
		BUG_ON(ca->journal.bucket_seq[i] > last_flushed_seq);

	return ret;
}
