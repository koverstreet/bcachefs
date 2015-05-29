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

static void __bch_journal_next_entry(struct journal *);

/* Sequence number of oldest dirty journal entry */

static inline u64 last_seq(struct journal *j)
{
	return j->seq - fifo_used(&j->pin) + 1;
}

static inline u64 journal_pin_seq(struct journal *j,
				  struct journal_entry_pin_list *pin_list)
{
	return last_seq(j) + fifo_entry_idx(&j->pin, pin_list);
}

#define for_each_jset_jkeys(jkeys, jset)				\
	for (jkeys = (jset)->start;					\
	     jkeys < (struct jset_entry *) bset_bkey_last(jset);	\
	     jkeys = jset_keys_next(jkeys))

#define for_each_jset_key(k, _n, jkeys, jset)				\
	for_each_jset_jkeys(jkeys, jset)				\
		if (JKEYS_TYPE(jkeys) == JKEYS_BTREE_KEYS)		\
			for (k = (jkeys)->start;			\
			     (k < bset_bkey_last(jkeys) &&		\
			      (_n = bkey_next(k), 1));			\
			     k = _n)

#define JSET_SECTORS (PAGE_SECTORS << JSET_BITS)

static inline void bch_journal_add_entry_at(struct journal *j, const void *data,
					    size_t u64s, unsigned type,
					    enum btree_id id, unsigned level,
					    unsigned offset)
{
	struct jset_entry *jkeys = bkey_idx(journal_cur_write(j)->data, offset);

	jkeys->u64s = u64s;
	jkeys->btree_id = id;
	jkeys->level = level;
	jkeys->flags = 0;
	SET_JKEYS_TYPE(jkeys, type);

	memcpy(jkeys->_data, data, u64s * sizeof(u64));
}

static inline void bch_journal_add_entry(struct journal *j, const void *data,
					 size_t u64s, unsigned type,
					 enum btree_id id, unsigned level)
{
	struct jset *jset = journal_cur_write(j)->data;

	bch_journal_add_entry_at(j, data, u64s, type, id, level, jset->u64s);
	jset->u64s += jset_u64s(u64s);
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

static void bch_journal_add_btree_root(struct journal *j, enum btree_id id,
				       struct bkey_i *k, unsigned level)
{
	bch_journal_add_entry(j, k, k->k.u64s, JKEYS_BTREE_ROOT, id, level);
}

static inline void bch_journal_add_prios(struct journal *j)
{
	bch_journal_add_entry(j, j->prio_buckets, j->nr_prio_buckets,
			      JKEYS_PRIO_PTRS, 0, 0);
}

static void journal_seq_blacklist_flush(struct journal_entry_pin *pin)
{
	struct journal_seq_blacklist *bl =
		container_of(pin, struct journal_seq_blacklist, pin);
	struct cache_set *c = bl->c;
	struct btree *b;
	struct btree_iter iter;

	while (1) {
		mutex_lock(&c->journal.blacklist_lock);
		if (list_empty(&bl->nodes))
			break;

		b = list_first_entry(&bl->nodes, struct btree,
				     journal_seq_blacklisted);
		mutex_unlock(&c->journal.blacklist_lock);

		/*
		 * b might be changing underneath us, but it won't be _freed_
		 * underneath us - and if the fields we're reading out of it to
		 * traverse to it are garbage because we raced, that's ok
		 */

		bch_btree_iter_init(&iter, c, b->btree_id, b->key.k.p);
		iter.is_extents = false;

		b = bch_btree_iter_peek_node(&iter);

		if (!list_empty_careful(&b->journal_seq_blacklisted))
			bch_btree_node_rewrite(b, &iter, true);

		bch_btree_iter_unlock(&iter);
	}

	journal_pin_drop(&c->journal, &bl->pin);
	list_del(&bl->list);
	kfree(bl);

	mutex_unlock(&c->journal.blacklist_lock);
}

static struct journal_seq_blacklist *
journal_seq_blacklist_find(struct journal *j, u64 seq)
{
	struct journal_seq_blacklist *bl;

	lockdep_assert_held(&j->blacklist_lock);

	list_for_each_entry(bl, &j->seq_blacklist, list)
		if (seq == bl->seq)
			return bl;

	return NULL;
}

static struct journal_seq_blacklist *
bch_journal_seq_blacklisted_new(struct cache_set *c, u64 seq)
{
	struct journal *j = &c->journal;
	struct journal_seq_blacklist *bl;

	lockdep_assert_held(&j->blacklist_lock);

	bl = kzalloc(sizeof(*bl), GFP_KERNEL);
	if (!bl)
		return NULL;

	bl->c	= c;
	bl->seq	= seq;
	INIT_LIST_HEAD(&bl->nodes);

	BUG_ON(!list_empty(&j->seq_blacklist) &&
	       list_last_entry(&j->seq_blacklist,
			       struct journal_seq_blacklist,
			       list)->seq >= bl->seq);

	list_add_tail(&bl->list, &j->seq_blacklist);
	return bl;
}

static int __bch_journal_seq_blacklisted(struct cache_set *c, u64 seq,
					 struct btree *b)
{
	struct journal *j = &c->journal;
	struct journal_seq_blacklist *bl = journal_seq_blacklist_find(j, seq);

	if (bl)
		goto found;

	/*
	 * After startup, all the blacklisted sequence numbers will already be
	 * in the list, we don't create new ones
	 */

	if (seq <= j->seq)
		return 0;

	cache_set_err_on(seq > j->seq + 1, c,
			 "bset journal seq too far in the future: %llu > %llu",
			 seq, j->seq);

	bl = bch_journal_seq_blacklisted_new(c, seq);
	if (!bl)
		return -ENOMEM;
found:
	pr_debug("found %s blacklisted seq %llu",
		 seq <= j->seq ? "old" : "new", seq);

	if (list_empty(&b->journal_seq_blacklisted))
		list_add(&b->journal_seq_blacklisted, &bl->nodes);

	return 1;
}

int bch_journal_seq_blacklisted(struct cache_set *c, u64 seq, struct btree *b)
{
	int ret;

	if (test_bit(CACHE_SET_INITIAL_GC_DONE, &c->flags))
		return 0;

	mutex_lock(&c->journal.blacklist_lock);
	ret = __bch_journal_seq_blacklisted(c, seq, b);
	mutex_unlock(&c->journal.blacklist_lock);

	return ret;
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

	/*
	 * If the device supports discard but not secure discard, we can't do
	 * the fancy fibonacci hash/binary search because the live journal
	 * entries might not form a contiguous range:
	 */
		for (i = 0; i < nr_buckets; i++)
			read_bucket(i);
		goto search_done;

	if (!blk_queue_nonrot(q))
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
	 * Set last_idx to indicate the entire journal is full and needs to be
	 * reclaimed - journal reclaim will immediately reclaim whatever isn't
	 * pinned when it first runs:
	 */
	ja->last_idx = (ja->cur_idx + 1) % nr_buckets;

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

static void journal_entries_free(struct journal *j,
				 struct list_head *list)
{

	while (!list_empty(list)) {
		struct journal_replay *i =
			list_first_entry(list, struct journal_replay, list);
		list_del(&i->list);
		kfree(i);
	}
}

static int journal_seq_blacklist_read(struct cache_set *c,
				      struct journal_replay *i,
				      struct journal_entry_pin_list *p)
{
	struct jset_entry *entry;
	struct journal_seq_blacklist *bl;
	u64 seq;

	for_each_jset_jkeys(entry, &i->j)
		switch (JKEYS_TYPE(entry)) {
		case JKEYS_JOURNAL_SEQ_BLACKLISTED:
			seq = entry->_data[0];
			bl = bch_journal_seq_blacklisted_new(c, seq);
			if (!bl) {
				mutex_unlock(&c->journal.blacklist_lock);
				return -ENOMEM;
			}

			journal_pin_add(&c->journal, p, &bl->pin,
					journal_seq_blacklist_flush);
			bl->written = true;
			break;
		}

	return 0;
}

const char *bch_journal_read(struct cache_set *c, struct list_head *list)
{
	struct jset_entry *prio_ptrs;
	struct journal_list jlist;
	struct journal_replay *i;
	struct jset *j;
	struct journal_entry_pin_list *p;
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
		journal_entries_free(&c->journal, list);

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

	mutex_lock(&c->journal.blacklist_lock);

	fifo_for_each_entry_ptr(p, &c->journal.pin, iter) {
		u64 seq = journal_pin_seq(&c->journal, p);

		INIT_LIST_HEAD(&p->list);

		if (i && i->j.seq == seq) {
			atomic_set(&p->count, 1);

			if (journal_seq_blacklist_read(c, i, p))
				return "insufficient memory";

			i = list_is_last(&i->list, list)
				? NULL
				: list_next_entry(i, list);
		} else {
			atomic_set(&p->count, 0);
		}
	}

	mutex_unlock(&c->journal.blacklist_lock);

	prio_ptrs = bch_journal_find_entry(j, JKEYS_PRIO_PTRS, 0);
	if (!prio_ptrs)
		return "prio bucket ptrs not found";

	memcpy(c->journal.prio_buckets,
	       prio_ptrs->_data,
	       prio_ptrs->u64s * sizeof(u64));
	c->journal.nr_prio_buckets = prio_ptrs->u64s;

	return NULL;
}

void bch_journal_mark(struct cache_set *c, struct list_head *list)
{
	struct bkey_i *k, *n;
	struct jset_entry *j;
	struct journal_replay *r;

	list_for_each_entry(r, list, list)
		for_each_jset_key(k, n, j, &r->j) {
			if ((j->level || j->btree_id == BTREE_ID_EXTENTS) &&
			    !bkey_invalid(c, j->level
					  ? BKEY_TYPE_BTREE : j->btree_id,
					  bkey_i_to_s_c(k)))
				__bch_btree_mark_key(c, j->level,
						     bkey_i_to_s_c(k));
		}
}

static union journal_res_state journal_res_state(unsigned count,
						 unsigned entry_offset)
{
	return (union journal_res_state) {
		.count = count,
		.cur_entry_offset = entry_offset,
	};
}

static bool journal_entry_is_open(struct journal *j)
{
	return j->reservations.cur_entry_offset < S32_MAX;
}

/*
 * Closes the current journal entry so that new reservations cannot be take on
 * it - returns true if the count of outstanding reservations is 0.
 */
static bool journal_entry_close(struct journal *j)
{
	union journal_res_state old, new;
	u64 v = atomic64_read(&j->reservations.counter);

	do {
		old.v = new.v = v;
		if (old.cur_entry_offset == S32_MAX)
			return old.count == 0;

		new.cur_entry_offset = S32_MAX;
	} while ((v = cmpxchg(&j->reservations.v, old.v, new.v)) != old.v);

	journal_cur_write(j)->data->u64s = old.cur_entry_offset;

	return old.count == 0;
}

/* Number of u64s we can write to the current journal bucket */
static void journal_entry_open(struct journal *j)
{
	struct journal_write *w = journal_cur_write(j);
	ssize_t u64s;

	lockdep_assert_held(&j->lock);
	BUG_ON(journal_entry_is_open(j) ||
	       test_bit(JOURNAL_DIRTY, &j->flags));

	u64s = (min_t(size_t,
		      j->sectors_free,
		      JSET_SECTORS) << 9) / sizeof(u64);

	/* Subtract the journal header */
	u64s -= sizeof(struct jset) / sizeof(u64);

	/*
	 * Btree roots, prio pointers don't get added until right before we do
	 * the write:
	 */
	u64s -= BTREE_ID_NR * (JSET_KEYS_U64s + BKEY_EXTENT_MAX_U64s);
	u64s -= JSET_KEYS_U64s + j->nr_prio_buckets;
	u64s  = max_t(ssize_t, 0L, u64s);

	if (u64s > w->data->u64s) {
		j->cur_entry_u64s	= max_t(ssize_t, 0L, u64s);

		/* Handle any already added entries */
		atomic64_set(&j->reservations.counter,
			     journal_res_state(0, w->data->u64s).v);
		wake_up(&j->wait);
	}
}

void bch_journal_start(struct cache_set *c)
{
	struct journal *j = &c->journal;
	struct journal_seq_blacklist *bl;
	u64 new_seq = 0;

	list_for_each_entry(bl, &j->seq_blacklist, list)
		new_seq = max(new_seq, bl->seq);

	spin_lock(&j->lock);

	while (j->seq < new_seq) {
		struct journal_entry_pin_list pin_list, *p;

		BUG_ON(!fifo_push(&j->pin, pin_list));
		p = &fifo_back(&j->pin);

		INIT_LIST_HEAD(&p->list);
		atomic_set(&p->count, 0);
		j->seq++;
	}

	__bch_journal_next_entry(j);

	/*
	 * Adding entries to the next journal entry before allocating space on
	 * disk for the next journal entry - this is ok, because these entries
	 * only have to go down with the next journal entry we write:
	 */

	list_for_each_entry(bl, &j->seq_blacklist, list)
		if (!bl->written) {
			bch_journal_add_entry(j, &bl->seq, 1,
					      JKEYS_JOURNAL_SEQ_BLACKLISTED,
					      0, 0);

			journal_pin_add(j, &fifo_back(&j->pin), &bl->pin,
					journal_seq_blacklist_flush);
			bl->written = true;
		}

	/*
	 * Recalculate, since we just added entries directly bypassing
	 * reservations
	 */
	journal_entry_open(j);
	spin_unlock(&j->lock);

	queue_work(system_long_wq, &j->reclaim_work);
}

static int bch_journal_replay_key(struct cache_set *c, enum btree_id id,
				  struct bkey_i *k)
{
	int ret;
	BKEY_PADDED(key) temp;
	bool do_subtract = id == BTREE_ID_EXTENTS && bkey_extent_is_data(&k->k);

	trace_bcache_journal_replay_key(&k->k);

	if (do_subtract)
		bkey_copy(&temp.key, k);

	ret = bch_btree_insert(c, id, &keylist_single(k), NULL, NULL, NULL, 0);
	if (ret)
		return ret;

	/*
	 * Subtract sectors after replay since bch_btree_insert() added
	 * them again
	 */
	if (do_subtract)
		bch_mark_pointers(c, NULL, bkey_i_to_s_c_extent(&temp.key),
				  -temp.key.k.size, false, false);

	return 0;
}

int bch_journal_replay(struct cache_set *c, struct list_head *list)
{
	int ret = 0, keys = 0, entries = 0;
	struct journal *j = &c->journal;
	struct bkey_i *k, *_n;
	struct jset_entry *jkeys;
	struct journal_replay *i, *n;
	u64 cur_seq = last_seq(j);
	u64 end_seq = list_last_entry(list, struct journal_replay, list)->j.seq;

	list_for_each_entry_safe(i, n, list, list) {
		mutex_lock(&j->blacklist_lock);

		while (cur_seq < i->j.seq &&
		       journal_seq_blacklist_find(j, cur_seq))
			cur_seq++;

		cache_set_err_on(journal_seq_blacklist_find(j, i->j.seq), c,
				 "found blacklisted journal entry %llu",
				 i->j.seq);

		mutex_unlock(&j->blacklist_lock);

		cache_set_err_on(i->j.seq != cur_seq, c,
			"journal entries %llu-%llu missing! (replaying %llu-%llu)",
			cur_seq, i->j.seq - 1, last_seq(j), end_seq);

		cur_seq = i->j.seq + 1;

		j->cur_pin_list =
			&j->pin.data[((j->pin.back - 1 - (j->seq - i->j.seq)) &
				      j->pin.mask)];

		BUG_ON(atomic_read(&j->cur_pin_list->count) != 1);

		for_each_jset_key(k, _n, jkeys, &i->j) {
			cond_resched();
			ret = bch_journal_replay_key(c, jkeys->btree_id, k);
			if (ret)
				goto err;

			keys++;
		}

		if (atomic_dec_and_test(&j->cur_pin_list->count))
			wake_up(&j->wait);

		entries++;
	}

	pr_info("journal replay done, %i keys in %i entries, seq %llu",
		keys, entries, j->seq);

	bch_journal_set_replay_done(&c->journal);
err:
	if (ret)
		pr_err("journal replay error: %d", ret);

	journal_entries_free(j, list);

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

/**
 * journal_reclaim_fast - do the fast part of journal reclaim
 *
 * Called from IO submission context, does not block. Cleans up after btree
 * write completions by advancing the journal pin and each cache's last_idx,
 * kicking off discards and background reclaim as necessary.
 */
static void journal_reclaim_fast(struct journal *j)
{
	struct journal_entry_pin_list temp;

	lockdep_assert_held(&j->lock);

	/*
	 * Unpin journal entries whose reference counts reached zero, meaning
	 * all btree nodes got written out
	 */
	while (!atomic_read(&fifo_front(&j->pin).count)) {
		BUG_ON(!list_empty(&fifo_front(&j->pin).list));
		BUG_ON(!fifo_pop(&j->pin, temp));
	}
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
	struct journal *j = &c->journal;
	struct cache *ca;
	struct journal_entry_pin_list *pin_list;
	struct journal_entry_pin *pin;
	u64 seq_to_flush = 0, last_seq = j->last_seq_ondisk;
	unsigned iter;

	/*
	 * Advance last_idx to point to the oldest journal entry containing
	 * btree node updates that have not yet been written out
	 */
	group_for_each_cache(ca, &c->cache_tiers[0], iter) {
		struct journal_device *ja = &ca->journal;
		unsigned nr = bch_nr_journal_buckets(&ca->sb),
			 cur_idx, bucket_to_flush;

		spin_lock(&j->lock);
		cur_idx = ja->cur_idx;
		spin_unlock(&j->lock);

		/* We're the only thread that modifies last_idx: */

		while (ja->last_idx != cur_idx &&
		       ja->bucket_seq[ja->last_idx] < last_seq) {
			if (CACHE_DISCARD(&ca->mi) &&
			    blk_queue_discard(bdev_get_queue(ca->disk_sb.bdev)))
				blkdev_issue_discard(ca->disk_sb.bdev,
					bucket_to_sector(ca,
						journal_bucket(ca,
							       ja->last_idx)),
					ca->mi.bucket_size, GFP_NOIO, 0);

			spin_lock(&j->lock);
			ja->last_idx = (ja->last_idx + 1) % nr;
			spin_unlock(&j->lock);

			wake_up(&j->wait);
		}

		/*
		 * Write out enough btree nodes to free up 50% journal
		 * buckets
		 */
		spin_lock(&j->lock);
		bucket_to_flush = (cur_idx + (nr >> 1)) % nr;
		seq_to_flush = max_t(u64, seq_to_flush,
				     ja->bucket_seq[bucket_to_flush]);
		spin_unlock(&j->lock);
	}

	spin_lock(&j->lock);

	/* Also flush if the pin fifo is more than half full */
	seq_to_flush = max_t(s64, seq_to_flush,
			     (s64) j->seq - (j->pin.size >> 1));

	journal_reclaim_fast(j);
	spin_unlock(&j->lock);

	spin_lock_irq(&j->pin_lock);

restart_flush:
	/* Now do the actual flushing */
	fifo_for_each_entry_ptr(pin_list, &j->pin, iter) {
		if (journal_pin_seq(j, pin_list) > seq_to_flush)
			break;

		if (!list_empty(&pin_list->list)) {
			pin = list_first_entry(&pin_list->list,
					       struct journal_entry_pin,
					       list);
			list_del_init(&pin->list);
			spin_unlock_irq(&j->pin_lock);

			pin->flush(pin);

			spin_lock_irq(&j->pin_lock);
			goto restart_flush;
		}
	}

	spin_unlock_irq(&j->pin_lock);
}

/**
 * journal_next_bucket - move on to the next journal bucket if possible
 */
static void journal_next_bucket(struct cache_set *c)
{
	struct journal *j = &c->journal;
	struct bkey_s_extent e = bkey_i_to_s_extent(&j->key);
	struct bch_extent_ptr *ptr;
	struct cache *ca;
	unsigned iter, replicas;

	lockdep_assert_held(&j->lock);

	/*
	 * only supposed to be called when we're out of space/haven't started a
	 * new journal entry
	 */
	BUG_ON(test_bit(JOURNAL_DIRTY, &j->flags));

	/* We use last_idx() below, make sure it's up to date: */
	journal_reclaim_fast(j);

	rcu_read_lock();

	/*
	 * Drop any pointers to devices that have been removed, are no longer
	 * empty, or filled up their current journal bucket:
	 *
	 * Note that a device may have had a small amount of free space (perhaps
	 * one sector) that wasn't enough for the smallest possible journal
	 * entry - that's why we drop pointers to devices <= current free space,
	 * i.e. whichever device was limiting the current journal entry size.
	 */
	extent_for_each_ptr_backwards(e, ptr)
		if (!(ca = PTR_CACHE(c, ptr)) ||
		    CACHE_STATE(&ca->mi) != CACHE_ACTIVE ||
		    ca->journal.sectors_free <= j->sectors_free)
			__bch_extent_drop_ptr(e, ptr);

	replicas = 0;
	extent_for_each_ptr(e, ptr)
		replicas++;

	/*
	 * Determine location of the next journal write:
	 * XXX: sort caches by free journal space
	 */
	group_for_each_cache_rcu(ca, &c->cache_tiers[0], iter) {
		struct journal_device *ja = &ca->journal;
		unsigned next, remaining, nr_buckets =
			bch_nr_journal_buckets(&ca->sb);

		if (replicas >= CACHE_SET_META_REPLICAS_WANT(&c->sb))
			break;

		/*
		 * Check that we can use this device, and aren't already using
		 * it:
		 */
		if (bch_extent_has_device(e.c, ca->sb.nr_this_dev))
			continue;

		next = (ja->cur_idx + 1) % nr_buckets;
		remaining = (ja->last_idx + nr_buckets - next) % nr_buckets;

		/*
		 * Hack to avoid a deadlock during journal replay:
		 * journal replay might require setting a new btree
		 * root, which requires writing another journal entry -
		 * thus, if the journal is full (and this happens when
		 * replaying the first journal bucket's entries) we're
		 * screwed.
		 *
		 * So don't let the journal fill up unless we're in
		 * replay:
		 */
		if (test_bit(JOURNAL_REPLAY_DONE, &j->flags))
			remaining = max((int) remaining - 2, 0);

		/*
		 * Don't use the last bucket unless writing the new last_seq
		 * will make another bucket available:
		 */
		if (remaining == 1 &&
		    ja->bucket_seq[ja->last_idx] >= last_seq(j))
			continue;

		if (!remaining)
			continue;

		ja->sectors_free = ca->mi.bucket_size;
		ja->cur_idx = next;
		ja->bucket_seq[ja->cur_idx] = j->seq;

		extent_ptr_append(bkey_i_to_extent(&j->key),
			(struct bch_extent_ptr) {
				  .offset = bucket_to_sector(ca,
					journal_bucket(ca, ja->cur_idx)),
				  .dev = ca->sb.nr_this_dev,
		});
		replicas++;

		trace_bcache_journal_next_bucket(ca, ja->cur_idx, ja->last_idx);
	}

	/* set j->sectors_free to the min of any device */
	j->sectors_free = UINT_MAX;

	if (replicas >= CACHE_SET_META_REPLICAS_WANT(&c->sb))
		extent_for_each_online_device(c, e, ptr, ca)
			j->sectors_free = min(j->sectors_free,
					      ca->journal.sectors_free);

	if (j->sectors_free == UINT_MAX)
		j->sectors_free = 0;

	journal_entry_open(j);

	rcu_read_unlock();

	queue_work(system_long_wq, &j->reclaim_work);
}

static void __bch_journal_next_entry(struct journal *j)
{
	struct journal_entry_pin_list pin_list, *p;
	struct jset *jset;

	change_bit(JOURNAL_WRITE_IDX, &j->flags);

	/*
	 * The fifo_push() needs to happen at the same time as j->seq is
	 * incremented for last_seq() to be calculated correctly
	 */
	BUG_ON(!fifo_push(&j->pin, pin_list));
	p = &fifo_back(&j->pin);

	INIT_LIST_HEAD(&p->list);
	atomic_set(&p->count, 1);

	if (test_bit(JOURNAL_REPLAY_DONE, &j->flags))
		j->cur_pin_list = p;

	jset = journal_cur_write(j)->data;
	jset->seq	= ++j->seq;
	jset->u64s	= 0;
}

static void bch_journal_next_entry(struct journal *j)
{
	__bch_journal_next_entry(j);
	journal_entry_open(j);
}

static void journal_write_endio(struct bio *bio)
{
	struct cache *ca = container_of(bio, struct cache, journal.bio);
	struct journal_write *w = bio->bi_private;

	if (bio->bi_error || bch_meta_write_fault("journal"))
		bch_cache_error(ca, "IO error %d writing journal",
				bio->bi_error);

	closure_put(&w->j->io);
	percpu_ref_put(&ca->ref);
}

static void journal_write_done(struct closure *cl)
{
	struct journal *j = container_of(cl, struct journal, io);
	struct journal_write *w = journal_prev_write(j);

	j->last_seq_ondisk = w->data->last_seq;

	clear_bit(JOURNAL_IO_IN_FLIGHT, &j->flags);

	closure_wake_up(&w->wait);
	wake_up(&j->wait);

	if (test_bit(JOURNAL_NEED_WRITE, &j->flags))
		mod_delayed_work(system_wq, &j->write_work, 0);

	/*
	 * Updating last_seq_ondisk may let journal_reclaim_work() discard more
	 * buckets:
	 */
	queue_work(system_long_wq, &j->reclaim_work);
}

static void journal_write_locked(struct closure *cl)
	__releases(c->journal.lock)
{
	struct journal *j =  container_of(cl, struct journal, io);
	struct cache_set *c = container_of(j, struct cache_set, journal);
	struct cache *ca;
	struct btree *b;
	struct journal_write *w = journal_cur_write(j);
	struct bkey_s_extent e = bkey_i_to_s_extent(&j->key);
	struct bch_extent_ptr *ptr;
	BKEY_PADDED(k) tmp;
	unsigned i, sectors;

	struct bio *bio;
	struct bio_list list;
	bio_list_init(&list);

	BUG_ON(j->reservations.count);
	BUG_ON(journal_full(j));
	BUG_ON(!test_bit(JOURNAL_DIRTY, &j->flags));

	clear_bit(JOURNAL_NEED_WRITE, &j->flags);
	clear_bit(JOURNAL_DIRTY, &j->flags);
	cancel_delayed_work(&j->write_work);

	spin_lock(&c->btree_root_lock);

	for (i = 0; i < BTREE_ID_NR; i++)
		if ((b = c->btree_roots[i]))
			bch_journal_add_btree_root(j, i, &b->key, b->level);

	spin_unlock(&c->btree_root_lock);

	bch_journal_add_prios(j);

	/* So last_seq is up to date */
	journal_reclaim_fast(j);

	w->data->read_clock	= c->prio_clock[READ].hand;
	w->data->write_clock	= c->prio_clock[WRITE].hand;
	w->data->magic		= jset_magic(&c->sb);
	w->data->version	= BCACHE_JSET_VERSION;
	w->data->last_seq	= last_seq(j);

	SET_JSET_CSUM_TYPE(w->data, CACHE_META_PREFERRED_CSUM_TYPE(&c->sb));
	w->data->csum		= csum_set(w->data, JSET_CSUM_TYPE(w->data));

	sectors = set_blocks(w->data, block_bytes(c)) * c->sb.block_size;

	BUG_ON(sectors > j->sectors_free);
	j->sectors_free -= sectors;

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
			j->sectors_free = 0;
			ca->journal.sectors_free = 0;
		}

		bio = &ca->journal.bio;

		atomic_long_add(sectors, &ca->meta_sectors_written);

		bio_reset(bio);
		bio->bi_iter.bi_sector	= ptr->offset;
		bio->bi_bdev		= ca->disk_sb.bdev;
		bio->bi_iter.bi_size	= sectors << 9;
		bio->bi_end_io		= journal_write_endio;
		bio->bi_private		= w;
		bio_set_op_attrs(bio, REQ_OP_WRITE,
				 REQ_SYNC|REQ_META|REQ_PREFLUSH|REQ_FUA);
		bch_bio_map(bio, w->data);

		trace_bcache_journal_write(bio);
		bio_list_add(&list, bio);

		ptr->offset += sectors;

		ca->journal.bucket_seq[ca->journal.cur_idx] = w->data->seq;
	}

	/*
	 * Make a copy of the key we're writing to for check_mark_super, since
	 * journal_next_bucket will change it
	 */
	bkey_reassemble(&tmp.k, e.s_c);

	atomic_dec_bug(&fifo_back(&j->pin).count);
	bch_journal_next_entry(j);
	wake_up(&j->wait);

	spin_unlock(&j->lock);

	bch_check_mark_super(c, &tmp.k, true);

	while ((bio = bio_list_pop(&list)))
		closure_bio_submit_punt(bio, cl, c);

	closure_return_with_destructor(cl, journal_write_done);
}

static bool __journal_write(struct journal *j)
	__releases(j->lock)
{
	struct cache_set *c = container_of(j, struct cache_set, journal);

	EBUG_ON(!j->reservations.count &&
		!test_bit(JOURNAL_DIRTY, &j->flags));

	if (test_bit(JOURNAL_IO_IN_FLIGHT, &j->flags) ||
	    !journal_entry_close(j))
		goto nowrite;

	set_bit(JOURNAL_IO_IN_FLIGHT, &j->flags);

	__set_current_state(TASK_RUNNING);
	closure_call(&j->io, journal_write_locked, NULL, &c->cl);
	return true;
nowrite:
	spin_unlock(&j->lock);
	return false;
}

static bool journal_try_write(struct journal *j)
{
	set_bit(JOURNAL_NEED_WRITE, &j->flags);
	return __journal_write(j);
}

static void journal_unlock(struct journal *j)
{
	if (test_bit(JOURNAL_NEED_WRITE, &j->flags))
		__journal_write(j);
	else
		spin_unlock(&j->lock);
}

static void journal_write_work(struct work_struct *work)
{
	struct journal *j = container_of(to_delayed_work(work),
					 struct journal, write_work);
	spin_lock(&j->lock);
	if (test_bit(JOURNAL_DIRTY, &j->flags))
		set_bit(JOURNAL_NEED_WRITE, &j->flags);
	journal_unlock(j);
}

void bch_journal_add_keys(struct journal *j, struct journal_res *res,
			  enum btree_id id, const struct bkey_i *k,
			  unsigned level)
{
	unsigned actual = jset_u64s(k->k.u64s);

	BUG_ON(!res->ref);
	BUG_ON(actual > res->u64s);

	bch_journal_add_entry_at(j, k, k->k.u64s,
				 JKEYS_BTREE_KEYS, id, level, res->offset);

	res->offset	+= actual;
	res->u64s	-= actual;
}

/*
 * This function releases the journal write structure so other threads can
 * then proceed to add their keys as well.
 */
void bch_journal_res_put(struct journal *j, struct journal_res *res)
{
	union journal_res_state s;
	bool do_write = false;

	BUG_ON(!res->ref);

	res->ref = false;

	while (res->u64s) {
		unsigned actual = jset_u64s(0);

		bch_journal_add_entry_at(j, NULL, 0, JKEYS_BTREE_KEYS,
					 0, 0, res->offset);
		res->offset	+= actual;
		res->u64s	-= actual;
	}

	if (!test_bit(JOURNAL_DIRTY, &j->flags)) {
		set_bit(JOURNAL_DIRTY, &j->flags);
		schedule_delayed_work(&j->write_work,
				      msecs_to_jiffies(j->delay_ms));
	}

	if (test_bit(JOURNAL_NEED_WRITE, &j->flags) &&
	    !test_bit(JOURNAL_IO_IN_FLIGHT, &j->flags)) {
		journal_entry_close(j);
		do_write = true;
	}

	s.v = atomic64_sub_return(journal_res_state(1, 0).v,
				  &j->reservations.counter);
	BUG_ON((int) s.count < 0);

	if (!s.count) {
		if (do_write) {
			spin_lock(&j->lock);
			journal_unlock(j);
		}

		wake_up(&j->wait);
	}
}

static inline bool journal_bucket_has_room(struct journal *j)
{
	return (j->sectors_free && fifo_free(&j->pin) > 1);
}

static inline bool journal_res_get_fast(struct journal *j,
					struct journal_res *res,
					unsigned u64s_min,
					unsigned u64s_max)
{
	union journal_res_state old, new;
	u64 v = atomic64_read(&j->reservations.counter);

	do {
		old.v = new.v = v;

		/*
		 * Check if there is still room in the current journal
		 * entry:
		 */
		if (old.cur_entry_offset + u64s_min > j->cur_entry_u64s)
			return false;

		res->offset	= old.cur_entry_offset;
		res->u64s	= min(u64s_max, j->cur_entry_u64s -
				      old.cur_entry_offset);

		new.cur_entry_offset += res->u64s;
		new.count++;
	} while ((v = cmpxchg(&j->reservations.v,
			      old.v, new.v)) != old.v);

	res->ref = true;
	return true;
}

static bool __journal_res_get(struct journal *j, struct journal_res *res,
			      unsigned u64s_min, unsigned u64s_max,
			      u64 *start_time)
{
	struct cache_set *c = container_of(j, struct cache_set, journal);

	while (1) {
		if (journal_res_get_fast(j, res, u64s_min, u64s_max))
			return true;

		spin_lock(&j->lock);

		/*
		 * Recheck after taking the lock, so we don't race with another
		 * thread that just did journal_entry_open() and call
		 * journal_entry_close() unnecessarily
		 */
		if (journal_res_get_fast(j, res, u64s_min, u64s_max)) {
			spin_unlock(&j->lock);
			return true;
		}

		/* local_clock() can of course be 0 but we don't care */
		if (*start_time == 0)
			*start_time = local_clock();

		if (!journal_entry_close(j)) {
			spin_unlock(&j->lock);
			return false;
		}

		if (test_bit(JOURNAL_DIRTY, &j->flags)) {
			/*
			 * If the current journal entry isn't empty, try to
			 * write it - if previous journal write is still in
			 * flight, we'll have to wait:
			 */

			if (!journal_try_write(j)) {
				trace_bcache_journal_entry_full(c);
				return false;
			}
		} else {
			/* Try to get a new journal bucket */
			journal_next_bucket(c);

			if (!journal_bucket_has_room(j)) {
				/* Still no room, we have to wait */
				spin_unlock(&j->lock);
				trace_bcache_journal_full(c);
				return false;
			}

			spin_unlock(&j->lock);
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
void bch_journal_res_get(struct journal *j, struct journal_res *res,
			 unsigned u64s_min, unsigned u64s_max)
{
	u64 start_time = 0;

	BUG_ON(res->ref);
	BUG_ON(u64s_max < u64s_min);

	wait_event(j->wait,
		   __journal_res_get(j, res, u64s_min, u64s_max, &start_time));

	BUG_ON(!res->ref);

	if (start_time)
		bch_time_stats_update(&j->full_time, start_time);
}

void bch_journal_push_seq(struct journal *j, u64 seq, struct closure *parent)
{
	spin_lock(&j->lock);

	BUG_ON(seq > j->seq);

	if (seq == j->seq) {
		BUG_ON(!test_bit(JOURNAL_DIRTY, &j->flags));
		set_bit(JOURNAL_NEED_WRITE, &j->flags);
		if (parent &&
		    !closure_wait(&journal_cur_write(j)->wait, parent))
			BUG();
	} else if (seq + 1 == j->seq &&
		   test_bit(JOURNAL_IO_IN_FLIGHT, &j->flags)) {
		if (parent &&
		    !closure_wait(&journal_prev_write(j)->wait, parent))
			BUG();
	}

	journal_unlock(j);
}

void bch_journal_meta(struct journal *j, struct closure *parent)
{
	struct journal_res res;
	unsigned u64s = jset_u64s(0);
	u64 seq;

	memset(&res, 0, sizeof(res));

	bch_journal_res_get(j, &res, u64s, u64s);
	seq = j->seq;
	bch_journal_res_put(j, &res);

	bch_journal_push_seq(j, seq, parent);
}

void bch_journal_flush(struct journal *j, struct closure *parent)
{
	u64 seq;

	spin_lock(&j->lock);
	if (test_bit(JOURNAL_DIRTY, &j->flags)) {
		seq = j->seq;
	} else if (j->seq) {
		seq = j->seq - 1;
	} else {
		spin_unlock(&j->lock);
		return;
	}
	spin_unlock(&j->lock);

	bch_journal_push_seq(j, seq, parent);
}

void bch_journal_free(struct journal *j)
{
	free_pages((unsigned long) j->w[1].data, JSET_BITS);
	free_pages((unsigned long) j->w[0].data, JSET_BITS);
	free_fifo(&j->pin);
}

int bch_journal_alloc(struct journal *j)
{
	spin_lock_init(&j->lock);
	spin_lock_init(&j->pin_lock);
	init_waitqueue_head(&j->wait);
	INIT_DELAYED_WORK(&j->write_work, journal_write_work);
	INIT_WORK(&j->reclaim_work, journal_reclaim_work);
	mutex_init(&j->blacklist_lock);
	INIT_LIST_HEAD(&j->seq_blacklist);
	spin_lock_init(&j->full_time.lock);

	j->delay_ms = 10;

	bkey_extent_init(&j->key);

	atomic64_set(&j->reservations.counter,
		     journal_res_state(0, S32_MAX).v);

	j->w[0].j = j;
	j->w[1].j = j;

	if (!(init_fifo(&j->pin, JOURNAL_PIN, GFP_KERNEL)) ||
	    !(j->w[0].data = (void *) __get_free_pages(GFP_KERNEL, JSET_BITS)) ||
	    !(j->w[1].data = (void *) __get_free_pages(GFP_KERNEL, JSET_BITS)))
		return -ENOMEM;

	return 0;
}

ssize_t bch_journal_print_debug(struct journal *j, char *buf)
{
	struct cache_set *c = container_of(j, struct cache_set, journal);
	struct cache *ca;
	unsigned iter;
	ssize_t ret = 0;

	rcu_read_lock();
	spin_lock(&j->lock);

	ret += scnprintf(buf + ret, PAGE_SIZE - ret,
			 "active journal entries:\t%zu\n"
			 "seq:\t\t\t%llu\n"
			 "last_seq:\t\t%llu\n"
			 "last_seq_ondisk:\t%llu\n"
			 "sectors_free:\t\t%u\n"
			 "reservation count:\t%u\n"
			 "reservation offset:\t%u\n"
			 "current entry u64s:\t%u\n"
			 "io in flight:\t\t%i\n"
			 "need write:\t\t%i\n"
			 "dirty:\t\t\t%i\n"
			 "replay done:\t\t%i\n",
			 fifo_used(&j->pin),
			 j->seq,
			 last_seq(j),
			 j->last_seq_ondisk,
			 j->sectors_free,
			 j->reservations.count,
			 j->reservations.cur_entry_offset,
			 j->cur_entry_u64s,
			 test_bit(JOURNAL_IO_IN_FLIGHT,	&j->flags),
			 test_bit(JOURNAL_NEED_WRITE,	&j->flags),
			 test_bit(JOURNAL_DIRTY,	&j->flags),
			 test_bit(JOURNAL_REPLAY_DONE,	&j->flags));

	group_for_each_cache_rcu(ca, &c->cache_tiers[0], iter) {
		struct journal_device *ja = &ca->journal;

		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "dev %u:\n"
				 "\tnr\t\t%u\n"
				 "\tcur_idx\t\t%u (seq %llu)\n"
				 "\tlast_idx\t%u (seq %llu)\n",
				 iter, bch_nr_journal_buckets(&ca->sb),
				 ja->cur_idx,	ja->bucket_seq[ja->cur_idx],
				 ja->last_idx,	ja->bucket_seq[ja->last_idx]);
	}

	spin_unlock(&j->lock);
	rcu_read_unlock();

	return ret;
}

static bool bch_journal_writing_to_device(struct cache *ca)
{
	struct journal *j = &ca->set->journal;
	bool ret;

	spin_lock(&j->lock);
	ret = bch_extent_has_device(bkey_i_to_s_c_extent(&j->key),
				    ca->sb.nr_this_dev);
	spin_unlock(&j->lock);

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
	struct journal *j = &c->journal;
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
		bch_journal_meta(j, &cl);
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
	bch_journal_meta(j, &cl);
	closure_sync(&cl);

	/*
	 * Verify that we no longer need any of the journal entries in
	 * the device
	 */
	spin_lock(&j->lock);
	last_flushed_seq = last_seq(j);
	spin_unlock(&j->lock);

	nr_buckets = bch_nr_journal_buckets(&ca->sb);

	for (i = 0; i < nr_buckets; i += 1)
		BUG_ON(ca->journal.bucket_seq[i] > last_flushed_seq);

	return ret;
}
