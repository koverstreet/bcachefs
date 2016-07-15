/*
 * bcache journalling code, for btree insertions
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "bkey_methods.h"
#include "buckets.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "btree_io.h"
#include "debug.h"
#include "error.h"
#include "extents.h"
#include "io.h"
#include "keylist.h"
#include "journal.h"
#include "super.h"

#include <trace/events/bcachefs.h>

static void journal_write(struct closure *);
static void journal_reclaim_fast(struct journal *);

static inline struct journal_buf *journal_cur_buf(struct journal *j)
{
	return j->buf + j->reservations.idx;
}

static inline struct journal_buf *journal_prev_buf(struct journal *j)
{
	return j->buf + !j->reservations.idx;
}

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

#define for_each_jset_entry(entry, jset)				\
	for (entry = (jset)->start;					\
	     entry < bkey_idx(jset, le32_to_cpu((jset)->u64s));\
	     entry = jset_keys_next(entry))

static inline struct jset_entry *__jset_entry_type_next(struct jset *jset,
					struct jset_entry *entry, unsigned type)
{
	while (entry < bkey_idx(jset, le32_to_cpu(jset->u64s))) {
		if (JOURNAL_ENTRY_TYPE(entry) == type)
			return entry;

		entry = jset_keys_next(entry);
	}

	return NULL;
}

#define for_each_jset_entry_type(entry, jset, type)			\
	for (entry = (jset)->start;					\
	     (entry = __jset_entry_type_next(jset, entry, type));	\
	     entry = jset_keys_next(entry))

#define for_each_jset_key(k, _n, entry, jset)				\
	for_each_jset_entry_type(entry, jset, JOURNAL_ENTRY_BTREE_KEYS)	\
		for (k = (entry)->start;			\
		     (k < bkey_idx(entry, le16_to_cpu((entry)->u64s)) &&\
		      (_n = bkey_next(k), 1));			\
		     k = _n)

static inline void bch_journal_add_entry_at(struct journal_buf *buf,
					    const void *data, size_t u64s,
					    unsigned type, enum btree_id id,
					    unsigned level, unsigned offset)
{
	struct jset_entry *entry = bkey_idx(buf->data, offset);

	entry->u64s = cpu_to_le16(u64s);
	entry->btree_id = id;
	entry->level = level;
	entry->flags = 0;
	SET_JOURNAL_ENTRY_TYPE(entry, type);

	memcpy(entry->_data, data, u64s * sizeof(u64));
}

static inline void bch_journal_add_entry(struct journal_buf *buf,
					 const void *data, size_t u64s,
					 unsigned type, enum btree_id id,
					 unsigned level)
{
	struct jset *jset = buf->data;

	bch_journal_add_entry_at(buf, data, u64s, type, id, level,
				 le32_to_cpu(jset->u64s));
	le32_add_cpu(&jset->u64s, jset_u64s(u64s));
}

static struct jset_entry *bch_journal_find_entry(struct jset *j, unsigned type,
						 enum btree_id id)
{
	struct jset_entry *entry;

	for_each_jset_entry_type(entry, j, type)
		if (entry->btree_id == id)
			return entry;

	return NULL;
}

struct bkey_i *bch_journal_find_btree_root(struct cache_set *c, struct jset *j,
					   enum btree_id id, unsigned *level)
{
	struct bkey_i *k;
	struct jset_entry *entry =
		bch_journal_find_entry(j, JOURNAL_ENTRY_BTREE_ROOT, id);

	if (!entry)
		return NULL;

	k = entry->start;
	*level = entry->level;

	if (cache_set_inconsistent_on(!entry->u64s ||
			le16_to_cpu(entry->u64s) != k->k.u64s ||
			bkey_invalid(c, BKEY_TYPE_BTREE, bkey_i_to_s_c(k)),
			c, "invalid btree root in journal"))
		return NULL;

	*level = entry->level;
	return k;
}

static void bch_journal_add_btree_root(struct journal_buf *buf,
				       enum btree_id id, struct bkey_i *k,
				       unsigned level)
{
	bch_journal_add_entry(buf, k, k->k.u64s,
			      JOURNAL_ENTRY_BTREE_ROOT, id, level);
}

static inline void bch_journal_add_prios(struct journal *j,
					 struct journal_buf *buf)
{
	/*
	 * no prio bucket ptrs yet... XXX should change the allocator so this
	 * can't happen:
	 */
	if (!j->nr_prio_buckets)
		return;

	bch_journal_add_entry(buf, j->prio_buckets, j->nr_prio_buckets,
			      JOURNAL_ENTRY_PRIO_PTRS, 0, 0);
}

static void journal_seq_blacklist_flush(struct journal_entry_pin *pin)
{
	struct journal_seq_blacklist *bl =
		container_of(pin, struct journal_seq_blacklist, pin);
	struct cache_set *c = bl->c;
	struct btree *b;
	struct btree_iter iter;
	struct closure cl;

	closure_init_stack(&cl);

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
			bch_btree_node_rewrite(&iter, b, &cl);

		bch_btree_iter_unlock(&iter);
		closure_sync(&cl);
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

	cache_set_inconsistent_on(seq > j->seq + 1, c,
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
	size_t bytes = __set_bytes(j, le32_to_cpu(j->u64s));
	int ret = JOURNAL_ENTRY_ADD_OUT_OF_RANGE;

	mutex_lock(&jlist->lock);

	/* This entry too old? */
	if (!list_empty(jlist->head)) {
		i = list_last_entry(jlist->head, struct journal_replay, list);
		if (le64_to_cpu(j->seq) < le64_to_cpu(i->j.last_seq)) {
			pr_debug("j->seq %llu i->j.seq %llu",
				 le64_to_cpu(j->seq),
				 le64_to_cpu(i->j.seq));
			goto out;
		}
	}

	ret = JOURNAL_ENTRY_ADD_OK;

	/* Drop entries we don't need anymore */
	list_for_each_entry_safe(i, pos, jlist->head, list) {
		if (le64_to_cpu(i->j.seq) >= le64_to_cpu(j->last_seq))
			break;
		list_del(&i->list);
		kfree(i);
	}

	list_for_each_entry_reverse(i, jlist->head, list) {
		if (le64_to_cpu(j->seq) == le64_to_cpu(i->j.seq)) {
			pr_debug("j->seq %llu i->j.seq %llu",
				 j->seq, i->j.seq);
			goto out;
		}

		if (le64_to_cpu(j->seq) > le64_to_cpu(i->j.seq)) {
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

	pr_debug("seq %llu", le64_to_cpu(j->seq));
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
	size_t bytes = __set_bytes(j, le32_to_cpu(j->u64s));
	u64 got, expect;

	if (bch_meta_read_fault("journal"))
		return JOURNAL_ENTRY_BAD;

	if (le64_to_cpu(j->magic) != jset_magic(&ca->set->disk_sb)) {
		pr_debug("bad magic while reading journal from %llu", sector);
		return JOURNAL_ENTRY_BAD;
	}

	got = le32_to_cpu(j->version);
	expect = BCACHE_JSET_VERSION;

	if (cache_inconsistent_on(got != expect, ca,
			"bad journal version (got %llu expect %llu) sector %lluu",
			got, expect, sector))
		return JOURNAL_ENTRY_BAD;

	if (cache_inconsistent_on(bytes > bucket_sectors_left << 9 ||
				  bytes > JOURNAL_BUF_BYTES, ca,
			"journal entry too big (%zu bytes), sector %lluu",
			bytes, sector))
		return JOURNAL_ENTRY_BAD;

	if (bytes > sectors_read << 9)
		return JOURNAL_ENTRY_REREAD;

	/* XXX: retry on checksum error */

	got = le64_to_cpu(j->csum);
	expect = __csum_set(j, le32_to_cpu(j->u64s), JSET_CSUM_TYPE(j));
	if (cache_inconsistent_on(got != expect, ca,
			"journal checksum bad (got %llu expect %llu), sector %lluu",
			got, expect, sector))
		return JOURNAL_ENTRY_BAD;

	if (cache_inconsistent_on(le64_to_cpu(j->last_seq) >
				  le64_to_cpu(j->seq), ca,
				  "invalid journal entry: last_seq > seq"))
		return JOURNAL_ENTRY_BAD;

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
	u64 sector = bucket_to_sector(ca,
				journal_bucket(ca->disk_sb.sb, bucket));
	bool entries_found = false;
	int ret = 0;

	data = (void *) __get_free_pages(GFP_KERNEL, JOURNAL_BUF_ORDER);
	if (!data) {
		mutex_lock(&jlist->cache_set_buffer_lock);
		data = c->journal.buf[0].data;
	}

	pr_debug("reading %u", bucket);

	while (bucket_offset < ca->mi.bucket_size) {
reread:
		sectors_read = min_t(unsigned,
				     ca->mi.bucket_size - bucket_offset,
				     JOURNAL_BUF_SECTORS);

		bio_reset(bio);
		bio->bi_bdev		= ca->disk_sb.bdev;
		bio->bi_iter.bi_sector	= sector + bucket_offset;
		bio->bi_iter.bi_size	= sectors_read << 9;
		bio_set_op_attrs(bio, REQ_OP_READ, 0);
		bch_bio_map(bio, data);

		ret = submit_bio_wait(bio);

		if (cache_fatal_io_err_on(ret, ca,
					  "journal read from sector %llu",
					  sector + bucket_offset) ||
		    bch_meta_read_fault("journal")) {
			ret = -EIO;
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
			if (le64_to_cpu(j->seq) < ja->bucket_seq[bucket])
				goto out;

			ja->bucket_seq[bucket] = le64_to_cpu(j->seq);

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

			if (le64_to_cpu(j->seq) > *seq)
				*seq = le64_to_cpu(j->seq);

			blocks = __set_blocks(j, le32_to_cpu(j->u64s),
					      block_bytes(c));

			pr_debug("next");
			bucket_offset	+= blocks * c->sb.block_size;
			sectors_read	-= blocks * c->sb.block_size;
			j = ((void *) j) + blocks * block_bytes(c);
		}
	}
out:
	ret = entries_found;
err:
	if (data == c->journal.buf[0].data)
		mutex_unlock(&jlist->cache_set_buffer_lock);
	else
		free_pages((unsigned long) data, JOURNAL_BUF_ORDER);

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

	unsigned nr_buckets = bch_nr_journal_buckets(ca->disk_sb.sb);
	DECLARE_BITMAP(bitmap, nr_buckets);
	unsigned i, l, r;
	u64 seq = 0;

	if (!nr_buckets)
		closure_return(cl);

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

	for_each_jset_entry_type(entry, &i->j,
			JOURNAL_ENTRY_JOURNAL_SEQ_BLACKLISTED) {
		seq = entry->_data[0];

		bl = bch_journal_seq_blacklisted_new(c, seq);
		if (!bl) {
			mutex_unlock(&c->journal.blacklist_lock);
			return -ENOMEM;
		}

		journal_pin_add(&c->journal, p, &bl->pin,
				journal_seq_blacklist_flush);
		bl->written = true;
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

	/* Swabbing: */
	list_for_each_entry(i, list, list) {
		struct jset_entry *entry;
		struct bkey_i *k;

		if (JSET_BIG_ENDIAN(&i->j) == CPU_BIG_ENDIAN)
			continue;

		for_each_jset_entry(entry, &i->j)
			switch (JOURNAL_ENTRY_TYPE(entry)) {
			case JOURNAL_ENTRY_BTREE_KEYS:
				for (k = entry->start;
				     k < bkey_idx(entry, le16_to_cpu(entry->u64s));
				     k = bkey_next(k))
					bch_bkey_swab(bkey_type(entry->level,
								entry->btree_id),
						      NULL, bkey_to_packed(k));
				break;
			case JOURNAL_ENTRY_BTREE_ROOT:
				bch_bkey_swab(BKEY_TYPE_BTREE,
					      NULL, bkey_to_packed(entry->start));
				break;
			}
	}

	j = &list_entry(list->prev, struct journal_replay, list)->j;

	if (le64_to_cpu(j->seq) -
	    le64_to_cpu(j->last_seq) + 1 > c->journal.pin.size)
		return "too many journal entries open for refcount fifo";

	c->journal.pin.back = le64_to_cpu(j->seq) -
		le64_to_cpu(j->last_seq) + 1;

	c->journal.seq = le64_to_cpu(j->seq);
	c->journal.last_seq_ondisk = le64_to_cpu(j->last_seq);

	BUG_ON(last_seq(&c->journal) != le64_to_cpu(j->last_seq));

	i = list_first_entry(list, struct journal_replay, list);

	mutex_lock(&c->journal.blacklist_lock);

	fifo_for_each_entry_ptr(p, &c->journal.pin, iter) {
		u64 seq = journal_pin_seq(&c->journal, p);

		INIT_LIST_HEAD(&p->list);

		if (i && le64_to_cpu(i->j.seq) == seq) {
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

	prio_ptrs = bch_journal_find_entry(j, JOURNAL_ENTRY_PRIO_PTRS, 0);
	if (!prio_ptrs) {
		/*
		 * there weren't any prio bucket ptrs yet... XXX should change
		 * the allocator so this can't happen:
		 */
		return NULL;
	}

	memcpy(c->journal.prio_buckets,
	       prio_ptrs->_data,
	       le16_to_cpu(prio_ptrs->u64s) * sizeof(u64));
	c->journal.nr_prio_buckets = le16_to_cpu(prio_ptrs->u64s);

	return NULL;
}

void bch_journal_mark(struct cache_set *c, struct list_head *list)
{
	struct bkey_i *k, *n;
	struct jset_entry *j;
	struct journal_replay *r;

	list_for_each_entry(r, list, list)
		for_each_jset_key(k, n, j, &r->j) {
			enum bkey_type type = bkey_type(j->level, j->btree_id);
			struct bkey_s_c k_s_c = bkey_i_to_s_c(k);

			if (btree_type_has_ptrs(type) &&
			    !bkey_invalid(c, type, k_s_c))
				__bch_btree_mark_key(c, type, k_s_c);
		}
}

static bool journal_entry_is_open(struct journal *j)
{
	return j->reservations.cur_entry_offset < JOURNAL_ENTRY_CLOSED_VAL;
}

static inline int journal_state_count(union journal_res_state s, int idx)
{
	return idx == 0 ? s.buf0_count : s.buf1_count;
}

static inline void journal_state_inc(union journal_res_state *s)
{
	s->buf0_count += s->idx == 0;
	s->buf1_count += s->idx == 1;
}

static void __journal_res_put(struct journal *j, unsigned idx,
			      bool need_write_just_set)
{
	union journal_res_state s;

	s.v = atomic64_sub_return(((union journal_res_state) {
				    .buf0_count = idx == 0,
				    .buf1_count = idx == 1,
				    }).v, &j->reservations.counter);

	BUG_ON(s.idx != idx && !s.prev_buf_unwritten);

	/*
	 * Do not initiate a journal write if the journal is in an error state
	 * (previous journal entry write may have failed)
	 */

	if (s.idx != idx &&
	    !journal_state_count(s, idx) &&
	    s.cur_entry_offset != JOURNAL_ENTRY_ERROR_VAL) {
		struct cache_set *c = container_of(j,
					struct cache_set, journal);

		if (!need_write_just_set &&
		    test_bit(JOURNAL_NEED_WRITE, &j->flags))
			__bch_time_stats_update(j->delay_time,
						j->need_write_time);

#if 0
		closure_call(&j->io, journal_write, NULL, &c->cl);
#else
		/* Shut sparse up: */
		closure_init(&j->io, &c->cl);
		set_closure_fn(&j->io, journal_write, NULL);
		journal_write(&j->io);
#endif
	}
}

static void __bch_journal_next_entry(struct journal *j)
{
	struct journal_entry_pin_list pin_list, *p;
	struct jset *jset;

	/*
	 * The fifo_push() needs to happen at the same time as j->seq is
	 * incremented for last_seq() to be calculated correctly
	 */
	BUG_ON(!fifo_push(&j->pin, pin_list));
	p = &fifo_back(&j->pin);

	INIT_LIST_HEAD(&p->list);
	atomic_set(&p->count, 1);

	if (test_bit(JOURNAL_REPLAY_DONE, &j->flags)) {
		smp_wmb();
		j->cur_pin_list = p;
	}

	jset = journal_cur_buf(j)->data;
	jset->seq	= cpu_to_le64(++j->seq);
	jset->u64s	= 0;
}

static enum {
	JOURNAL_ENTRY_ERROR,
	JOURNAL_ENTRY_INUSE,
	JOURNAL_ENTRY_CLOSED,
	JOURNAL_UNLOCKED,
} journal_buf_switch(struct journal *j, bool need_write_just_set)
{
	struct journal_buf *buf;
	union journal_res_state old, new;
	u64 v = atomic64_read(&j->reservations.counter);

	do {
		old.v = new.v = v;
		if (old.cur_entry_offset == JOURNAL_ENTRY_CLOSED_VAL)
			return JOURNAL_ENTRY_CLOSED;

		if (old.cur_entry_offset == JOURNAL_ENTRY_ERROR_VAL)
			return JOURNAL_ENTRY_ERROR;

		if (new.prev_buf_unwritten)
			return JOURNAL_ENTRY_INUSE;

		/*
		 * avoid race between setting buf->data->u64s and
		 * journal_res_put starting write:
		 */
		journal_state_inc(&new);

		new.cur_entry_offset = JOURNAL_ENTRY_CLOSED_VAL;
		new.idx++;
		new.prev_buf_unwritten = 1;

		BUG_ON(journal_state_count(new, new.idx));
	} while ((v = atomic64_cmpxchg(&j->reservations.counter,
				       old.v, new.v)) != old.v);

	journal_reclaim_fast(j);

	clear_bit(JOURNAL_NEED_WRITE, &j->flags);

	buf = &j->buf[old.idx];
	buf->data->u64s		= cpu_to_le32(old.cur_entry_offset);
	buf->data->last_seq	= cpu_to_le64(last_seq(j));

	atomic_dec_bug(&fifo_back(&j->pin).count);
	__bch_journal_next_entry(j);

	spin_unlock(&j->lock);

	/* ugh - might be called from __journal_res_get() under wait_event() */
	__set_current_state(TASK_RUNNING);
	__journal_res_put(j, old.idx, need_write_just_set);

	return JOURNAL_UNLOCKED;
}

void bch_journal_halt(struct journal *j)
{
	union journal_res_state old, new;
	u64 v = atomic64_read(&j->reservations.counter);

	do {
		old.v = new.v = v;
		if (old.cur_entry_offset == JOURNAL_ENTRY_ERROR_VAL)
			return;

		new.cur_entry_offset = JOURNAL_ENTRY_ERROR_VAL;
	} while ((v = atomic64_cmpxchg(&j->reservations.counter,
				       old.v, new.v)) != old.v);

	wake_up(&j->wait);
	closure_wake_up(&journal_cur_buf(j)->wait);
	closure_wake_up(&journal_prev_buf(j)->wait);
}

static unsigned journal_dev_buckets_available(struct journal *j,
					      struct cache *ca)
{
	struct journal_device *ja = &ca->journal;
	unsigned nr = bch_nr_journal_buckets(ca->disk_sb.sb);
	unsigned next = (ja->cur_idx + 1) % nr;
	unsigned available = (ja->last_idx + nr - next) % nr;

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
		available = max((int) available - 2, 0);

	/*
	 * Don't use the last bucket unless writing the new last_seq
	 * will make another bucket available:
	 */
	if (ja->bucket_seq[ja->last_idx] >= last_seq(j))
		available = max((int) available - 1, 0);

	return available;
}

/* returns number of sectors available for next journal entry: */
static int journal_entry_sectors(struct journal *j)
{
	struct cache_set *c = container_of(j, struct cache_set, journal);
	struct cache *ca;
	unsigned i, nr_buckets = UINT_MAX, sectors = JOURNAL_BUF_SECTORS,
		 nr_devs = 0;

	lockdep_assert_held(&j->lock);

	rcu_read_lock();
	group_for_each_cache_rcu(ca, &c->cache_tiers[0], i) {
		nr_devs++;
		nr_buckets = min(nr_buckets,
				 journal_dev_buckets_available(j, ca));
		sectors = min_t(unsigned, sectors, ca->mi.bucket_size);
	}
	rcu_read_unlock();

	if (nr_devs < c->opts.metadata_replicas)
		return -EROFS;

	if (nr_buckets == UINT_MAX)
		nr_buckets = 0;

	return nr_buckets ? sectors : 0;
}

/*
 * should _only_ called from journal_res_get() - when we actually want a
 * journal reservation - journal entry is open means journal is dirty:
 */
static int journal_entry_open(struct journal *j)
{
	struct journal_buf *buf = journal_cur_buf(j);
	ssize_t u64s;
	int ret = 0, sectors;

	lockdep_assert_held(&j->lock);
	BUG_ON(journal_entry_is_open(j));

	if (!fifo_free(&j->pin))
		return 0;

	sectors = journal_entry_sectors(j);
	if (sectors <= 0)
		return sectors;

	u64s = (sectors << 9) / sizeof(u64);

	/* Subtract the journal header */
	u64s -= sizeof(struct jset) / sizeof(u64);

	/*
	 * Btree roots, prio pointers don't get added until right before we do
	 * the write:
	 */
	u64s -= BTREE_ID_NR * (JSET_KEYS_U64s + BKEY_EXTENT_U64s_MAX);
	u64s -= JSET_KEYS_U64s + j->nr_prio_buckets;
	u64s  = max_t(ssize_t, 0L, u64s);

	if (u64s > le32_to_cpu(buf->data->u64s)) {
		union journal_res_state old, new;
		u64 v = atomic64_read(&j->reservations.counter);

		/*
		 * Must be set before marking the journal entry as open:
		 */
		j->cur_entry_u64s = u64s;

		do {
			old.v = new.v = v;

			if (old.cur_entry_offset == JOURNAL_ENTRY_ERROR_VAL)
				return false;

			/* Handle any already added entries */
			new.cur_entry_offset = le32_to_cpu(buf->data->u64s);
		} while ((v = atomic64_cmpxchg(&j->reservations.counter,
					       old.v, new.v)) != old.v);
		ret = 1;

		wake_up(&j->wait);

		if (j->res_get_blocked_start) {
			__bch_time_stats_update(j->blocked_time,
						j->res_get_blocked_start);
			j->res_get_blocked_start = 0;
		}

		if (!old.prev_buf_unwritten)
			mod_delayed_work(system_freezable_wq,
					 &j->write_work,
					 msecs_to_jiffies(j->delay_ms));
	}

	return ret;
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

	/*
	 * journal_buf_switch() only inits the next journal entry when it
	 * closes an open journal entry - the very first journal entry gets
	 * initialized here:
	 */
	__bch_journal_next_entry(j);

	/*
	 * Adding entries to the next journal entry before allocating space on
	 * disk for the next journal entry - this is ok, because these entries
	 * only have to go down with the next journal entry we write:
	 */
	list_for_each_entry(bl, &j->seq_blacklist, list)
		if (!bl->written) {
			bch_journal_add_entry(journal_cur_buf(j), &bl->seq, 1,
					JOURNAL_ENTRY_JOURNAL_SEQ_BLACKLISTED,
					0, 0);

			journal_pin_add(j, &fifo_back(&j->pin), &bl->pin,
					journal_seq_blacklist_flush);
			bl->written = true;
		}

	spin_unlock(&j->lock);

	queue_work(system_freezable_wq, &j->reclaim_work);
}

int bch_journal_replay(struct cache_set *c, struct list_head *list)
{
	int ret = 0, keys = 0, entries = 0;
	struct journal *j = &c->journal;
	struct bkey_i *k, *_n;
	struct jset_entry *entry;
	struct journal_replay *i, *n;
	u64 cur_seq = last_seq(j);
	u64 end_seq = le64_to_cpu(list_last_entry(list, struct journal_replay,
						  list)->j.seq);

	list_for_each_entry_safe(i, n, list, list) {
		mutex_lock(&j->blacklist_lock);

		while (cur_seq < le64_to_cpu(i->j.seq) &&
		       journal_seq_blacklist_find(j, cur_seq))
			cur_seq++;

		cache_set_inconsistent_on(journal_seq_blacklist_find(j,
							le64_to_cpu(i->j.seq)), c,
				 "found blacklisted journal entry %llu",
				 le64_to_cpu(i->j.seq));

		mutex_unlock(&j->blacklist_lock);

		cache_set_inconsistent_on(le64_to_cpu(i->j.seq) != cur_seq, c,
			"journal entries %llu-%llu missing! (replaying %llu-%llu)",
			cur_seq, le64_to_cpu(i->j.seq) - 1,
			last_seq(j), end_seq);

		cur_seq = le64_to_cpu(i->j.seq) + 1;

		j->cur_pin_list =
			&j->pin.data[((j->pin.back - 1 -
				       (j->seq - le64_to_cpu(i->j.seq))) &
				      j->pin.mask)];

		for_each_jset_key(k, _n, entry, &i->j) {
			trace_bcache_journal_replay_key(&k->k);

			ret = bch_btree_insert(c, entry->btree_id, k,
					       NULL, NULL, NULL,
					       BTREE_INSERT_NOFAIL|
					       BTREE_INSERT_NO_MARK_KEY);
			if (ret)
				goto err;

			cond_resched();
			keys++;
		}

		if (atomic_dec_and_test(&j->cur_pin_list->count))
			wake_up(&j->wait);

		entries++;
	}

	bch_info(c, "journal replay done, %i keys in %i entries, seq %llu",
		 keys, entries, j->seq);

	bch_journal_set_replay_done(&c->journal);
err:
	if (ret)
		bch_err(c, "journal replay error: %d", ret);

	journal_entries_free(j, list);

	return ret;
}

static int bch_set_nr_journal_buckets(struct cache *ca, unsigned nr)
{
	unsigned u64s = bch_journal_buckets_offset(ca->disk_sb.sb) + nr;
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
	ca->disk_sb.sb->u64s = cpu_to_le16(u64s);

	return 0;
}

int bch_cache_journal_alloc(struct cache *ca)
{
	int ret;
	unsigned i;

	if (ca->mi.tier != 0)
		return 0;

	if (dynamic_fault("bcache:add:journal_alloc"))
		return -ENOMEM;

	/*
	 * clamp journal size to 1024 buckets or 512MB (in sectors), whichever
	 * is smaller:
	 */
	ret = bch_set_nr_journal_buckets(ca,
			clamp_t(unsigned, ca->mi.nbuckets >> 8, 8,
				min(1 << 10,
				    (1 << 20) / ca->mi.bucket_size)));
	if (ret)
		return ret;

	for (i = 0; i < bch_nr_journal_buckets(ca->disk_sb.sb); i++) {
		unsigned long r = ca->mi.first_bucket + i;

		bch_mark_metadata_bucket(ca, &ca->buckets[r], true);
		set_journal_bucket(ca->disk_sb.sb, i, r);
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

static struct journal_entry_pin *
journal_get_next_pin(struct journal *j, u64 seq_to_flush)
{
	struct journal_entry_pin_list *pin_list;
	struct journal_entry_pin *ret = NULL;
	unsigned iter;

	/* so we don't iterate over empty fifo entries below: */
	if (!atomic_read(&fifo_front(&j->pin).count)) {
		spin_lock(&j->lock);
		journal_reclaim_fast(j);
		spin_unlock(&j->lock);
	}

	spin_lock_irq(&j->pin_lock);
	fifo_for_each_entry_ptr(pin_list, &j->pin, iter) {
		if (journal_pin_seq(j, pin_list) > seq_to_flush)
			break;

		ret = list_first_entry_or_null(&pin_list->list,
				struct journal_entry_pin, list);
		if (ret) {
			/* must be list_del_init(), see journal_pin_drop() */
			list_del_init(&ret->list);
			break;
		}
	}
	spin_unlock_irq(&j->pin_lock);

	return ret;
}

static bool should_discard_bucket(struct journal *j, struct journal_device *ja)
{
	bool ret;

	spin_lock(&j->lock);
	ret = (ja->last_idx != ja->cur_idx &&
	       ja->bucket_seq[ja->last_idx] < j->last_seq_ondisk);
	spin_unlock(&j->lock);

	return ret;
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
	struct journal_entry_pin *pin;
	u64 seq_to_flush = 0;
	unsigned iter, nr, bucket_to_flush;
	bool reclaim_lock_held = false;

	/*
	 * Advance last_idx to point to the oldest journal entry containing
	 * btree node updates that have not yet been written out
	 */
	group_for_each_cache(ca, &c->cache_tiers[0], iter) {
		struct journal_device *ja = &ca->journal;

		while (should_discard_bucket(j, ja)) {
			if (!reclaim_lock_held) {
				/*
				 * ugh:
				 * might be called from __journal_res_get()
				 * under wait_event() - have to go back to
				 * TASK_RUNNING before doing something that
				 * would block, but only if we're doing work:
				 */
				__set_current_state(TASK_RUNNING);

				mutex_lock(&j->reclaim_lock);
				reclaim_lock_held = true;
				/* recheck under reclaim_lock: */
				continue;
			}

			if (ca->mi.discard &&
			    blk_queue_discard(bdev_get_queue(ca->disk_sb.bdev)))
				blkdev_issue_discard(ca->disk_sb.bdev,
					bucket_to_sector(ca,
						journal_bucket(ca->disk_sb.sb,
							       ja->last_idx)),
					ca->mi.bucket_size, GFP_NOIO, 0);

			spin_lock(&j->lock);
			ja->last_idx = (ja->last_idx + 1) %
				bch_nr_journal_buckets(ca->disk_sb.sb);
			spin_unlock(&j->lock);

			wake_up(&j->wait);
		}

		/*
		 * Write out enough btree nodes to free up 50% journal
		 * buckets
		 */
		spin_lock(&j->lock);
		nr = bch_nr_journal_buckets(ca->disk_sb.sb),
		bucket_to_flush = (ja->cur_idx + (nr >> 1)) % nr;
		seq_to_flush = max_t(u64, seq_to_flush,
				     ja->bucket_seq[bucket_to_flush]);
		spin_unlock(&j->lock);
	}

	if (reclaim_lock_held)
		mutex_unlock(&j->reclaim_lock);

	/* Also flush if the pin fifo is more than half full */
	seq_to_flush = max_t(s64, seq_to_flush,
			     (s64) j->seq - (j->pin.size >> 1));

	while ((pin = journal_get_next_pin(j, seq_to_flush))) {
		__set_current_state(TASK_RUNNING);
		pin->flush(pin);
	}
}

/**
 * journal_next_bucket - move on to the next journal bucket if possible
 */
static int journal_write_alloc(struct journal *j, unsigned sectors)
{
	struct cache_set *c = container_of(j, struct cache_set, journal);
	struct bkey_s_extent e = bkey_i_to_s_extent(&j->key);
	struct bch_extent_ptr *ptr;
	struct cache *ca;
	unsigned iter, replicas, replicas_want =
		READ_ONCE(c->opts.metadata_replicas);

	spin_lock(&j->lock);
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
		    ca->mi.state != CACHE_ACTIVE ||
		    ca->journal.sectors_free <= sectors)
			__bch_extent_drop_ptr(e, ptr);

	replicas = bch_extent_nr_ptrs(e.c);

	/*
	 * Determine location of the next journal write:
	 * XXX: sort caches by free journal space
	 */
	group_for_each_cache_rcu(ca, &c->cache_tiers[0], iter) {
		struct journal_device *ja = &ca->journal;
		unsigned nr_buckets = bch_nr_journal_buckets(ca->disk_sb.sb);

		if (replicas >= replicas_want)
			break;

		/*
		 * Check that we can use this device, and aren't already using
		 * it:
		 */
		if (bch_extent_has_device(e.c, ca->sb.nr_this_dev) ||
		    !journal_dev_buckets_available(j, ca))
			continue;

		ja->sectors_free = ca->mi.bucket_size;
		ja->cur_idx = (ja->cur_idx + 1) % nr_buckets;
		ja->bucket_seq[ja->cur_idx] = j->seq;

		extent_ptr_append(bkey_i_to_extent(&j->key),
			(struct bch_extent_ptr) {
				  .offset = bucket_to_sector(ca,
					journal_bucket(ca->disk_sb.sb,
						       ja->cur_idx)),
				  .dev = ca->sb.nr_this_dev,
		});
		replicas++;

		trace_bcache_journal_next_bucket(ca, ja->cur_idx, ja->last_idx);
	}

	rcu_read_unlock();
	spin_unlock(&j->lock);

	if (replicas < replicas_want)
		return -EROFS;

	return 0;
}

static void journal_write_compact(struct jset *jset)
{
	struct jset_entry *i, *next, *prev = NULL;

	/*
	 * Simple compaction, dropping empty jset_entries (from journal
	 * reservations that weren't fully used) and merging jset_entries that
	 * can be.
	 *
	 * If we wanted to be really fancy here, we could sort all the keys in
	 * the jset and drop keys that were overwritten - probably not worth it:
	 */
	for (i = jset->start;
	     i < (struct jset_entry *) bkey_idx(jset, le32_to_cpu(jset->u64s)) &&
	     (next = jset_keys_next(i), true);
	     i = next) {
		unsigned u64s = le16_to_cpu(i->u64s);

		/* Empty entry: */
		if (!u64s)
			continue;

		/* Can we merge with previous entry? */
		if (prev &&
		    i->btree_id == prev->btree_id &&
		    i->level	== prev->level &&
		    JOURNAL_ENTRY_TYPE(i) == JOURNAL_ENTRY_TYPE(prev) &&
		    JOURNAL_ENTRY_TYPE(i) == JOURNAL_ENTRY_BTREE_KEYS) {
			memmove(jset_keys_next(prev),
				i->_data,
				u64s * sizeof(u64));
			le16_add_cpu(&prev->u64s, u64s);
			continue;
		}

		/* Couldn't merge, move i into new position (after prev): */
		prev = prev ? jset_keys_next(prev) : jset->start;
		if (i != prev)
			memmove(prev, i, jset_u64s(u64s) * sizeof(u64));
	}

	prev = prev ? jset_keys_next(prev) : jset->start;
	jset->u64s = cpu_to_le32((u64 *) prev - jset->_data);
}

static void journal_write_endio(struct bio *bio)
{
	struct cache *ca = container_of(bio, struct cache, journal.bio);
	struct journal *j = &ca->set->journal;

	if (cache_fatal_io_err_on(bio->bi_error, ca, "journal write") ||
	    bch_meta_write_fault("journal"))
		bch_journal_halt(j);

	closure_put(&j->io);
	percpu_ref_put(&ca->ref);
}

static void journal_write_done(struct closure *cl)
{
	struct journal *j = container_of(cl, struct journal, io);
	struct journal_buf *w = journal_prev_buf(j);

	j->last_seq_ondisk = le64_to_cpu(w->data->last_seq);

	__bch_time_stats_update(j->write_time, j->write_start_time);

	BUG_ON(!j->reservations.prev_buf_unwritten);
	atomic64_sub(((union journal_res_state) { .prev_buf_unwritten = 1 }).v,
		     &j->reservations.counter);

	/*
	 * XXX: this is racy, we could technically end up doing the wake up
	 * after the journal_buf struct has been reused for the next write
	 * (because we're clearing JOURNAL_IO_IN_FLIGHT) and wake up things that
	 * are waiting on the _next_ write, not this one.
	 *
	 * The wake up can't come before, because journal_flush_seq_async() is
	 * looking at JOURNAL_IO_IN_FLIGHT when it has to wait on a journal
	 * write that was already in flight.
	 *
	 * The right fix is to use a lock here, but using j.lock here means it
	 * has to be a spin_lock_irqsave() lock which then requires propagating
	 * the irq()ness to other locks and it's all kinds of nastiness.
	 */

	closure_wake_up(&w->wait);
	wake_up(&j->wait);

	if (journal_entry_is_open(j))
		mod_delayed_work(system_freezable_wq, &j->write_work,
				 test_bit(JOURNAL_NEED_WRITE, &j->flags)
				 ? 0 : msecs_to_jiffies(j->delay_ms));

	/*
	 * Updating last_seq_ondisk may let journal_reclaim_work() discard more
	 * buckets:
	 */
	queue_work(system_freezable_wq, &j->reclaim_work);
}

static void journal_write(struct closure *cl)
{
	struct journal *j =  container_of(cl, struct journal, io);
	struct cache_set *c = container_of(j, struct cache_set, journal);
	struct cache *ca;
	struct journal_buf *w = journal_prev_buf(j);
	struct bio *bio;
	struct bch_extent_ptr *ptr;
	unsigned i, sectors;

	j->write_start_time = local_clock();

	bch_journal_add_prios(j, w);

	mutex_lock(&c->btree_root_lock);
	for (i = 0; i < BTREE_ID_NR; i++) {
		struct btree_root *r = &c->btree_roots[i];

		if (r->alive)
			bch_journal_add_btree_root(w, i, &r->key, r->level);
	}
	mutex_unlock(&c->btree_root_lock);

	journal_write_compact(w->data);

	w->data->read_clock	= cpu_to_le16(c->prio_clock[READ].hand);
	w->data->write_clock	= cpu_to_le16(c->prio_clock[WRITE].hand);
	w->data->magic		= cpu_to_le64(jset_magic(&c->disk_sb));
	w->data->version	= cpu_to_le32(BCACHE_JSET_VERSION);

	SET_JSET_BIG_ENDIAN(w->data, CPU_BIG_ENDIAN);
	SET_JSET_CSUM_TYPE(w->data, c->opts.metadata_checksum);
	w->data->csum = cpu_to_le64(__csum_set(w->data,
					       le32_to_cpu(w->data->u64s),
					       JSET_CSUM_TYPE(w->data)));

	sectors = __set_blocks(w->data, le32_to_cpu(w->data->u64s),
			       block_bytes(c)) * c->sb.block_size;

	if (journal_write_alloc(j, sectors)) {
		BUG();
	}

	bch_check_mark_super(c, &j->key, true);

	extent_for_each_ptr(bkey_i_to_s_extent(&j->key), ptr) {
		rcu_read_lock();
		ca = PTR_CACHE(c, ptr);
		if (ca)
			percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		if (!ca) {
			/* XXX: fix this */
			bch_err(c, "missing device for journal write\n");
			continue;
		}

		BUG_ON(sectors > ca->journal.sectors_free);
		ca->journal.sectors_free -= sectors;

		bio = &ca->journal.bio;

		atomic64_add(sectors, &ca->meta_sectors_written);

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
		closure_bio_submit_punt(bio, cl, c);

		ptr->offset += sectors;

		ca->journal.bucket_seq[ca->journal.cur_idx] = le64_to_cpu(w->data->seq);
	}

	closure_return_with_destructor(cl, journal_write_done);
}

static void journal_write_work(struct work_struct *work)
{
	struct journal *j = container_of(to_delayed_work(work),
					 struct journal, write_work);
	spin_lock(&j->lock);
	set_bit(JOURNAL_NEED_WRITE, &j->flags);

	if (journal_buf_switch(j, false) != JOURNAL_UNLOCKED)
		spin_unlock(&j->lock);
}

void bch_journal_add_keys(struct journal *j, struct journal_res *res,
			  enum btree_id id, const struct bkey_i *k,
			  unsigned level)
{
	unsigned actual = jset_u64s(k->k.u64s);

	BUG_ON(!res->ref);
	BUG_ON(actual > res->u64s);

	bch_journal_add_entry_at(&j->buf[res->idx], k, k->k.u64s,
				 JOURNAL_ENTRY_BTREE_KEYS, id,
				 level, res->offset);

	res->offset	+= actual;
	res->u64s	-= actual;
}

/*
 * This function releases the journal write structure so other threads can
 * then proceed to add their keys as well.
 */
void bch_journal_res_put(struct journal *j, struct journal_res *res,
			 u64 *journal_seq)
{
	if (!res->ref)
		return;

	lock_release(&j->res_map, 0, _RET_IP_);

	while (res->u64s) {
		unsigned actual = jset_u64s(0);

		bch_journal_add_entry_at(&j->buf[res->idx], NULL, 0,
					 JOURNAL_ENTRY_BTREE_KEYS,
					 0, 0, res->offset);
		res->offset	+= actual;
		res->u64s	-= actual;
	}

	if (journal_seq)
		*journal_seq = j->buf[res->idx].data->seq;

	__journal_res_put(j, res->idx, false);

	memset(res, 0, sizeof(*res));
}

static inline int journal_res_get_fast(struct journal *j,
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
			return 0;

		res->offset	= old.cur_entry_offset;
		res->u64s	= min(u64s_max, j->cur_entry_u64s -
				      old.cur_entry_offset);

		journal_state_inc(&new);
		new.cur_entry_offset += res->u64s;
	} while ((v = atomic64_cmpxchg(&j->reservations.counter,
				       old.v, new.v)) != old.v);

	res->ref = true;
	res->idx = new.idx;
	return 1;
}

static int __journal_res_get(struct journal *j, struct journal_res *res,
			      unsigned u64s_min, unsigned u64s_max)
{
	struct cache_set *c = container_of(j, struct cache_set, journal);
	int ret;
retry:
	ret = journal_res_get_fast(j, res, u64s_min, u64s_max);
	if (ret)
		return ret;

	spin_lock(&j->lock);
	/*
	 * Recheck after taking the lock, so we don't race with another thread
	 * that just did journal_entry_open() and call journal_entry_close()
	 * unnecessarily
	 */
	ret = journal_res_get_fast(j, res, u64s_min, u64s_max);
	if (ret) {
		spin_unlock(&j->lock);
		return 1;
	}

	/*
	 * Ok, no more room in the current journal entry - try to start a new
	 * one:
	 */
	switch (journal_buf_switch(j, false)) {
	case JOURNAL_ENTRY_ERROR:
		spin_unlock(&j->lock);
		return -EIO;
	case JOURNAL_ENTRY_INUSE:
		/* haven't finished writing out the previous one: */
		spin_unlock(&j->lock);
		trace_bcache_journal_entry_full(c);
		goto blocked;
	case JOURNAL_ENTRY_CLOSED:
		break;
	case JOURNAL_UNLOCKED:
		goto retry;
	}

	/* We now have a new, closed journal buf - see if we can open it: */
	ret = journal_entry_open(j);
	spin_unlock(&j->lock);

	if (ret < 0)
		return ret;
	if (ret)
		goto retry;

	/* Journal's full, we have to wait */

	/*
	 * Direct reclaim - can't rely on reclaim from work item
	 * due to freezing..
	 */
	journal_reclaim_work(&j->reclaim_work);

	trace_bcache_journal_full(c);
blocked:
	if (!j->res_get_blocked_start)
		j->res_get_blocked_start = local_clock() ?: 1;
	return 0;
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
int bch_journal_res_get(struct journal *j, struct journal_res *res,
			unsigned u64s_min, unsigned u64s_max)
{
	int ret;

	BUG_ON(res->ref);
	BUG_ON(u64s_max < u64s_min);

	wait_event(j->wait,
		   (ret = __journal_res_get(j, res, u64s_min,
					    u64s_max)));
	if (ret < 0)
		return ret;

	lock_acquire_shared(&j->res_map, 0, 0, NULL, _RET_IP_);
	BUG_ON(!res->ref);
	return 0;
}

void bch_journal_flush_seq_async(struct journal *j, u64 seq, struct closure *parent)
{
	spin_lock(&j->lock);

	BUG_ON(seq > j->seq);

	if (bch_journal_error(j)) {
		spin_unlock(&j->lock);
		return;
	}

	if (seq == j->seq) {
		bool set_need_write = false;

		if (parent &&
		    !closure_wait(&journal_cur_buf(j)->wait, parent))
			BUG();

		if (!test_and_set_bit(JOURNAL_NEED_WRITE, &j->flags)) {
			j->need_write_time = local_clock();
			set_need_write = true;
		}

		switch (journal_buf_switch(j, set_need_write)) {
		case JOURNAL_ENTRY_ERROR:
			if (parent)
				closure_wake_up(&journal_cur_buf(j)->wait);
			break;
		case JOURNAL_ENTRY_CLOSED:
			/*
			 * Journal entry hasn't been opened yet, but caller
			 * claims it has something (seq == j->seq):
			 */
			BUG();
		case JOURNAL_ENTRY_INUSE:
			break;
		case JOURNAL_UNLOCKED:
			return;
		}
	} else if (parent &&
		   seq + 1 == j->seq &&
		   j->reservations.prev_buf_unwritten) {
		if (!closure_wait(&journal_prev_buf(j)->wait, parent))
			BUG();

		smp_mb();

		/* check if raced with write completion (or failure) */
		if (!j->reservations.prev_buf_unwritten ||
		    bch_journal_error(j))
			closure_wake_up(&journal_prev_buf(j)->wait);
	}

	spin_unlock(&j->lock);
}

int bch_journal_flush_seq(struct journal *j, u64 seq)
{
	struct closure cl;
	u64 start_time = local_clock();

	closure_init_stack(&cl);
	bch_journal_flush_seq_async(j, seq, &cl);
	closure_sync(&cl);

	bch_time_stats_update(j->flush_seq_time, start_time);

	return bch_journal_error(j);
}

void bch_journal_meta_async(struct journal *j, struct closure *parent)
{
	struct journal_res res;
	unsigned u64s = jset_u64s(0);
	u64 seq;

	memset(&res, 0, sizeof(res));

	bch_journal_res_get(j, &res, u64s, u64s);
	bch_journal_res_put(j, &res, &seq);

	bch_journal_flush_seq_async(j, seq, parent);
}

int bch_journal_meta(struct journal *j)
{
	struct journal_res res;
	unsigned u64s = jset_u64s(0);
	int ret;
	u64 seq;

	memset(&res, 0, sizeof(res));

	ret = bch_journal_res_get(j, &res, u64s, u64s);
	if (ret)
		return ret;

	bch_journal_res_put(j, &res, &seq);

	return bch_journal_flush_seq(j, seq);
}

void bch_journal_flush_async(struct journal *j, struct closure *parent)
{
	u64 seq;

	spin_lock(&j->lock);
	if (journal_entry_is_open(j)) {
		seq = j->seq;
	} else if (j->seq) {
		seq = j->seq - 1;
	} else {
		spin_unlock(&j->lock);
		return;
	}
	spin_unlock(&j->lock);

	bch_journal_flush_seq_async(j, seq, parent);
}

int bch_journal_flush(struct journal *j)
{
	u64 seq;

	spin_lock(&j->lock);
	if (journal_entry_is_open(j)) {
		seq = j->seq;
	} else if (j->seq) {
		seq = j->seq - 1;
	} else {
		spin_unlock(&j->lock);
		return 0;
	}
	spin_unlock(&j->lock);

	return bch_journal_flush_seq(j, seq);
}

void bch_journal_free(struct journal *j)
{
	free_pages((unsigned long) j->buf[1].data, JOURNAL_BUF_ORDER);
	free_pages((unsigned long) j->buf[0].data, JOURNAL_BUF_ORDER);
	free_fifo(&j->pin);
}

int bch_journal_alloc(struct journal *j)
{
	static struct lock_class_key res_key;

	spin_lock_init(&j->lock);
	spin_lock_init(&j->pin_lock);
	init_waitqueue_head(&j->wait);
	INIT_DELAYED_WORK(&j->write_work, journal_write_work);
	INIT_WORK(&j->reclaim_work, journal_reclaim_work);
	mutex_init(&j->blacklist_lock);
	INIT_LIST_HEAD(&j->seq_blacklist);
	mutex_init(&j->reclaim_lock);

	lockdep_init_map(&j->res_map, "journal res", &res_key, 0);

	j->delay_ms = 10;

	bkey_extent_init(&j->key);

	atomic64_set(&j->reservations.counter,
		((union journal_res_state)
		 { .cur_entry_offset = JOURNAL_ENTRY_CLOSED_VAL }).v);

	if (!(init_fifo(&j->pin, JOURNAL_PIN, GFP_KERNEL)) ||
	    !(j->buf[0].data = (void *) __get_free_pages(GFP_KERNEL,
						JOURNAL_BUF_ORDER)) ||
	    !(j->buf[1].data = (void *) __get_free_pages(GFP_KERNEL,
						JOURNAL_BUF_ORDER)))
		return -ENOMEM;

	return 0;
}

ssize_t bch_journal_print_debug(struct journal *j, char *buf)
{
	struct cache_set *c = container_of(j, struct cache_set, journal);
	union journal_res_state *s = &j->reservations;
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
			 journal_state_count(*s, s->idx),
			 s->cur_entry_offset,
			 j->cur_entry_u64s,
			 s->prev_buf_unwritten,
			 test_bit(JOURNAL_NEED_WRITE,	&j->flags),
			 journal_entry_is_open(j),
			 test_bit(JOURNAL_REPLAY_DONE,	&j->flags));

	group_for_each_cache_rcu(ca, &c->cache_tiers[0], iter) {
		struct journal_device *ja = &ca->journal;

		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "dev %u:\n"
				 "\tnr\t\t%u\n"
				 "\tcur_idx\t\t%u (seq %llu)\n"
				 "\tlast_idx\t%u (seq %llu)\n",
				 iter, bch_nr_journal_buckets(ca->disk_sb.sb),
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
	unsigned i, nr_buckets;
	u64 last_flushed_seq;
	struct cache_set *c = ca->set;
	struct journal *j = &c->journal;
	int ret = 0;		/* Success */

	if (bch_journal_writing_to_device(ca)) {
		/*
		 * bch_journal_meta will write a record and we'll wait
		 * for the write to complete.
		 * Actually writing the journal (journal_write_locked)
		 * will call journal_next_bucket which notices that the
		 * device is no longer writeable, and picks a new one.
		 */
		bch_journal_meta(j);
		BUG_ON(bch_journal_writing_to_device(ca));
	}

	/*
	 * Flush all btree updates to backing store so that any
	 * journal entries written to ca become stale and are no
	 * longer needed.
	 */

	/*
	 * XXX: switch to normal journal reclaim machinery
	 */
	bch_btree_flush(c);

	/*
	 * Force a meta-data journal entry to be written so that
	 * we have newer journal entries in devices other than ca,
	 * and wait for the meta data write to complete.
	 */
	bch_journal_meta(j);

	/*
	 * Verify that we no longer need any of the journal entries in
	 * the device
	 */
	spin_lock(&j->lock);
	last_flushed_seq = last_seq(j);
	spin_unlock(&j->lock);

	nr_buckets = bch_nr_journal_buckets(ca->disk_sb.sb);

	for (i = 0; i < nr_buckets; i += 1)
		BUG_ON(ca->journal.bucket_seq[i] > last_flushed_seq);

	return ret;
}
