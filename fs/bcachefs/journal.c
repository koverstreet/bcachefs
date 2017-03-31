/*
 * bcachefs journalling code, for btree insertions
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcachefs.h"
#include "alloc.h"
#include "bkey_methods.h"
#include "buckets.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "btree_io.h"
#include "checksum.h"
#include "debug.h"
#include "error.h"
#include "extents.h"
#include "io.h"
#include "keylist.h"
#include "journal.h"
#include "super-io.h"
#include "vstructs.h"

#include <trace/events/bcachefs.h>

static void journal_write(struct closure *);
static void journal_reclaim_fast(struct journal *);
static void journal_pin_add_entry(struct journal *,
				  struct journal_entry_pin_list *,
				  struct journal_entry_pin *,
				  journal_pin_flush_fn);

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
	return atomic64_read(&j->seq) - fifo_used(&j->pin) + 1;
}

static inline u64 journal_pin_seq(struct journal *j,
				  struct journal_entry_pin_list *pin_list)
{
	return last_seq(j) + fifo_entry_idx(&j->pin, pin_list);
}

static inline struct jset_entry *__jset_entry_type_next(struct jset *jset,
					struct jset_entry *entry, unsigned type)
{
	while (entry < vstruct_last(jset)) {
		if (JOURNAL_ENTRY_TYPE(entry) == type)
			return entry;

		entry = vstruct_next(entry);
	}

	return NULL;
}

#define for_each_jset_entry_type(entry, jset, type)			\
	for (entry = (jset)->start;					\
	     (entry = __jset_entry_type_next(jset, entry, type));	\
	     entry = vstruct_next(entry))

#define for_each_jset_key(k, _n, entry, jset)				\
	for_each_jset_entry_type(entry, jset, JOURNAL_ENTRY_BTREE_KEYS)	\
		vstruct_for_each_safe(entry, k, _n)

static inline void bch2_journal_add_entry(struct journal_buf *buf,
					 const void *data, size_t u64s,
					 unsigned type, enum btree_id id,
					 unsigned level)
{
	struct jset *jset = buf->data;

	bch2_journal_add_entry_at(buf, data, u64s, type, id, level,
				 le32_to_cpu(jset->u64s));
	le32_add_cpu(&jset->u64s, jset_u64s(u64s));
}

static struct jset_entry *bch2_journal_find_entry(struct jset *j, unsigned type,
						 enum btree_id id)
{
	struct jset_entry *entry;

	for_each_jset_entry_type(entry, j, type)
		if (entry->btree_id == id)
			return entry;

	return NULL;
}

struct bkey_i *bch2_journal_find_btree_root(struct bch_fs *c, struct jset *j,
					   enum btree_id id, unsigned *level)
{
	struct bkey_i *k;
	struct jset_entry *entry =
		bch2_journal_find_entry(j, JOURNAL_ENTRY_BTREE_ROOT, id);

	if (!entry)
		return NULL;

	k = entry->start;
	*level = entry->level;
	*level = entry->level;
	return k;
}

static void bch2_journal_add_btree_root(struct journal_buf *buf,
				       enum btree_id id, struct bkey_i *k,
				       unsigned level)
{
	bch2_journal_add_entry(buf, k, k->k.u64s,
			      JOURNAL_ENTRY_BTREE_ROOT, id, level);
}

static inline void bch2_journal_add_prios(struct journal *j,
					 struct journal_buf *buf)
{
	/*
	 * no prio bucket ptrs yet... XXX should change the allocator so this
	 * can't happen:
	 */
	if (!buf->nr_prio_buckets)
		return;

	bch2_journal_add_entry(buf, j->prio_buckets, buf->nr_prio_buckets,
			      JOURNAL_ENTRY_PRIO_PTRS, 0, 0);
}

static void journal_seq_blacklist_flush(struct journal *j,
					struct journal_entry_pin *pin)
{
	struct bch_fs *c =
		container_of(j, struct bch_fs, journal);
	struct journal_seq_blacklist *bl =
		container_of(pin, struct journal_seq_blacklist, pin);
	struct blacklisted_node n;
	struct closure cl;
	unsigned i;
	int ret;

	closure_init_stack(&cl);

	for (i = 0;; i++) {
		struct btree_iter iter;
		struct btree *b;

		mutex_lock(&j->blacklist_lock);
		if (i >= bl->nr_entries) {
			mutex_unlock(&j->blacklist_lock);
			break;
		}
		n = bl->entries[i];
		mutex_unlock(&j->blacklist_lock);

		bch2_btree_iter_init(&iter, c, n.btree_id, n.pos);
		iter.is_extents = false;
redo_peek:
		b = bch2_btree_iter_peek_node(&iter);

		/* The node might have already been rewritten: */

		if (b->data->keys.seq == n.seq &&
		    !bkey_cmp(b->key.k.p, n.pos)) {
			ret = bch2_btree_node_rewrite(&iter, b, &cl);
			if (ret) {
				bch2_btree_iter_unlock(&iter);
				closure_sync(&cl);

				if (ret == -EAGAIN ||
				    ret == -EINTR)
					goto redo_peek;

				/* -EROFS or perhaps -ENOSPC - bail out: */
				/* XXX warn here */
				return;
			}
		}

		bch2_btree_iter_unlock(&iter);
	}

	closure_sync(&cl);

	for (i = 0;; i++) {
		struct btree_interior_update *as;
		struct pending_btree_node_free *d;

		mutex_lock(&j->blacklist_lock);
		if (i >= bl->nr_entries) {
			mutex_unlock(&j->blacklist_lock);
			break;
		}
		n = bl->entries[i];
		mutex_unlock(&j->blacklist_lock);
redo_wait:
		mutex_lock(&c->btree_interior_update_lock);

		/*
		 * Is the node on the list of pending interior node updates -
		 * being freed? If so, wait for that to finish:
		 */
		for_each_pending_btree_node_free(c, as, d)
			if (n.seq	== d->seq &&
			    n.btree_id	== d->btree_id &&
			    !d->level &&
			    !bkey_cmp(n.pos, d->key.k.p)) {
				closure_wait(&as->wait, &cl);
				mutex_unlock(&c->btree_interior_update_lock);
				closure_sync(&cl);
				goto redo_wait;
			}

		mutex_unlock(&c->btree_interior_update_lock);
	}

	mutex_lock(&j->blacklist_lock);

	bch2_journal_pin_drop(j, &bl->pin);
	list_del(&bl->list);
	kfree(bl->entries);
	kfree(bl);

	mutex_unlock(&j->blacklist_lock);
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
bch2_journal_seq_blacklisted_new(struct journal *j, u64 seq)
{
	struct journal_seq_blacklist *bl;

	lockdep_assert_held(&j->blacklist_lock);

	bl = kzalloc(sizeof(*bl), GFP_KERNEL);
	if (!bl)
		return NULL;

	bl->seq = seq;
	list_add_tail(&bl->list, &j->seq_blacklist);
	return bl;
}

/*
 * Returns true if @seq is newer than the most recent journal entry that got
 * written, and data corresponding to @seq should be ignored - also marks @seq
 * as blacklisted so that on future restarts the corresponding data will still
 * be ignored:
 */
int bch2_journal_seq_should_ignore(struct bch_fs *c, u64 seq, struct btree *b)
{
	struct journal *j = &c->journal;
	struct journal_seq_blacklist *bl = NULL;
	struct blacklisted_node *n;
	u64 journal_seq, i;
	int ret = 0;

	if (!seq)
		return 0;

	journal_seq = atomic64_read(&j->seq);

	/* Interier updates aren't journalled: */
	BUG_ON(b->level);
	BUG_ON(seq > journal_seq && test_bit(BCH_FS_INITIAL_GC_DONE, &c->flags));

	if (seq <= journal_seq) {
		if (list_empty_careful(&j->seq_blacklist))
			return 0;

		mutex_lock(&j->blacklist_lock);
		ret = journal_seq_blacklist_find(j, seq) != NULL;
		mutex_unlock(&j->blacklist_lock);
		return ret;
	}

	/*
	 * Decrease this back to j->seq + 2 when we next rev the on disk format:
	 * increasing it temporarily to work around bug in old kernels
	 */
	bch2_fs_inconsistent_on(seq > journal_seq + 4, c,
			 "bset journal seq too far in the future: %llu > %llu",
			 seq, journal_seq);

	bch_verbose(c, "btree node %u:%llu:%llu has future journal sequence number %llu, blacklisting",
		    b->btree_id, b->key.k.p.inode, b->key.k.p.offset, seq);

	/*
	 * When we start the journal, bch2_journal_start() will skip over @seq:
	 */

	mutex_lock(&j->blacklist_lock);

	for (i = journal_seq + 1; i <= seq; i++) {
		bl = journal_seq_blacklist_find(j, i) ?:
			bch2_journal_seq_blacklisted_new(j, i);

		if (!bl) {
			ret = -ENOMEM;
			goto out;
		}
	}

	for (n = bl->entries; n < bl->entries + bl->nr_entries; n++)
		if (b->data->keys.seq	== n->seq &&
		    b->btree_id		== n->btree_id &&
		    !bkey_cmp(b->key.k.p, n->pos))
			goto found_entry;

	if (!bl->nr_entries ||
	    is_power_of_2(bl->nr_entries)) {
		n = krealloc(bl->entries,
			     max(bl->nr_entries * 2, 8UL) * sizeof(*n),
			     GFP_KERNEL);
		if (!n) {
			ret = -ENOMEM;
			goto out;
		}
		bl->entries = n;
	}

	bl->entries[bl->nr_entries++] = (struct blacklisted_node) {
		.seq		= b->data->keys.seq,
		.btree_id	= b->btree_id,
		.pos		= b->key.k.p,
	};
found_entry:
	ret = 1;
out:
	mutex_unlock(&j->blacklist_lock);
	return ret;
}

/*
 * Journal replay/recovery:
 *
 * This code is all driven from bch2_fs_start(); we first read the journal
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
	struct list_head	*head;
	int			ret;
};

#define JOURNAL_ENTRY_ADD_OK		0
#define JOURNAL_ENTRY_ADD_OUT_OF_RANGE	5

/*
 * Given a journal entry we just read, add it to the list of journal entries to
 * be replayed:
 */
static int journal_entry_add(struct bch_fs *c, struct journal_list *jlist,
		    struct jset *j)
{
	struct journal_replay *i, *pos;
	struct list_head *where;
	size_t bytes = vstruct_bytes(j);
	__le64 last_seq;
	int ret;

	mutex_lock(&jlist->lock);

	last_seq = !list_empty(jlist->head)
		? list_last_entry(jlist->head, struct journal_replay,
				  list)->j.last_seq
		: 0;

	/* Is this entry older than the range we need? */
	if (le64_to_cpu(j->seq) < le64_to_cpu(last_seq)) {
		ret = JOURNAL_ENTRY_ADD_OUT_OF_RANGE;
		goto out;
	}

	/* Drop entries we don't need anymore */
	list_for_each_entry_safe(i, pos, jlist->head, list) {
		if (le64_to_cpu(i->j.seq) >= le64_to_cpu(j->last_seq))
			break;
		list_del(&i->list);
		kfree(i);
	}

	list_for_each_entry_reverse(i, jlist->head, list) {
		/* Duplicate? */
		if (le64_to_cpu(j->seq) == le64_to_cpu(i->j.seq)) {
			fsck_err_on(bytes != vstruct_bytes(&i->j) ||
				    memcmp(j, &i->j, bytes), c,
				    "found duplicate but non identical journal entries (seq %llu)",
				    le64_to_cpu(j->seq));

			ret = JOURNAL_ENTRY_ADD_OK;
			goto out;
		}

		if (le64_to_cpu(j->seq) > le64_to_cpu(i->j.seq)) {
			where = &i->list;
			goto add;
		}
	}

	where = jlist->head;
add:
	i = kvmalloc(offsetof(struct journal_replay, j) + bytes, GFP_KERNEL);
	if (!i) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(&i->j, j, bytes);
	list_add(&i->list, where);
	ret = JOURNAL_ENTRY_ADD_OK;
out:
fsck_err:
	mutex_unlock(&jlist->lock);
	return ret;
}

static struct nonce journal_nonce(const struct jset *jset)
{
	return (struct nonce) {{
		[0] = 0,
		[1] = ((__le32 *) &jset->seq)[0],
		[2] = ((__le32 *) &jset->seq)[1],
		[3] = BCH_NONCE_JOURNAL,
	}};
}

static void journal_entry_null_range(void *start, void *end)
{
	struct jset_entry *entry;

	for (entry = start; entry != end; entry = vstruct_next(entry)) {
		entry->u64s	= 0;
		entry->btree_id	= 0;
		entry->level	= 0;
		entry->flags	= 0;
		SET_JOURNAL_ENTRY_TYPE(entry, 0);
	}
}

static int journal_validate_key(struct bch_fs *c, struct jset *j,
				struct jset_entry *entry,
				struct bkey_i *k, enum bkey_type key_type,
				const char *type)
{
	void *next = vstruct_next(entry);
	const char *invalid;
	char buf[160];
	int ret = 0;

	if (mustfix_fsck_err_on(!k->k.u64s, c,
			"invalid %s in journal: k->u64s 0", type)) {
		entry->u64s = cpu_to_le16((u64 *) k - entry->_data);
		journal_entry_null_range(vstruct_next(entry), next);
		return 0;
	}

	if (mustfix_fsck_err_on((void *) bkey_next(k) >
				(void *) vstruct_next(entry), c,
			"invalid %s in journal: extends past end of journal entry",
			type)) {
		entry->u64s = cpu_to_le16((u64 *) k - entry->_data);
		journal_entry_null_range(vstruct_next(entry), next);
		return 0;
	}

	if (mustfix_fsck_err_on(k->k.format != KEY_FORMAT_CURRENT, c,
			"invalid %s in journal: bad format %u",
			type, k->k.format)) {
		le16_add_cpu(&entry->u64s, -k->k.u64s);
		memmove(k, bkey_next(k), next - (void *) bkey_next(k));
		journal_entry_null_range(vstruct_next(entry), next);
		return 0;
	}

	if (JSET_BIG_ENDIAN(j) != CPU_BIG_ENDIAN)
		bch2_bkey_swab(key_type, NULL, bkey_to_packed(k));

	invalid = bch2_bkey_invalid(c, key_type, bkey_i_to_s_c(k));
	if (invalid) {
		bch2_bkey_val_to_text(c, key_type, buf, sizeof(buf),
				     bkey_i_to_s_c(k));
		mustfix_fsck_err(c, "invalid %s in journal: %s", type, buf);

		le16_add_cpu(&entry->u64s, -k->k.u64s);
		memmove(k, bkey_next(k), next - (void *) bkey_next(k));
		journal_entry_null_range(vstruct_next(entry), next);
		return 0;
	}
fsck_err:
	return ret;
}

#define JOURNAL_ENTRY_REREAD	5
#define JOURNAL_ENTRY_NONE	6
#define JOURNAL_ENTRY_BAD	7

static int journal_entry_validate(struct bch_fs *c,
				  struct jset *j, u64 sector,
				  unsigned bucket_sectors_left,
				  unsigned sectors_read)
{
	struct jset_entry *entry;
	size_t bytes = vstruct_bytes(j);
	struct bch_csum csum;
	int ret = 0;

	if (le64_to_cpu(j->magic) != jset_magic(c))
		return JOURNAL_ENTRY_NONE;

	if (le32_to_cpu(j->version) != BCACHE_JSET_VERSION) {
		bch_err(c, "unknown journal entry version %u",
			le32_to_cpu(j->version));
		return BCH_FSCK_UNKNOWN_VERSION;
	}

	if (mustfix_fsck_err_on(bytes > bucket_sectors_left << 9, c,
			"journal entry too big (%zu bytes), sector %lluu",
			bytes, sector)) {
		/* XXX: note we might have missing journal entries */
		return JOURNAL_ENTRY_BAD;
	}

	if (bytes > sectors_read << 9)
		return JOURNAL_ENTRY_REREAD;

	if (fsck_err_on(!bch2_checksum_type_valid(c, JSET_CSUM_TYPE(j)), c,
			"journal entry with unknown csum type %llu sector %lluu",
			JSET_CSUM_TYPE(j), sector))
		return JOURNAL_ENTRY_BAD;

	csum = csum_vstruct(c, JSET_CSUM_TYPE(j), journal_nonce(j), j);
	if (mustfix_fsck_err_on(bch2_crc_cmp(csum, j->csum), c,
			"journal checksum bad, sector %llu", sector)) {
		/* XXX: retry IO, when we start retrying checksum errors */
		/* XXX: note we might have missing journal entries */
		return JOURNAL_ENTRY_BAD;
	}

	bch2_encrypt(c, JSET_CSUM_TYPE(j), journal_nonce(j),
		    j->encrypted_start,
		    vstruct_end(j) - (void *) j->encrypted_start);

	if (mustfix_fsck_err_on(le64_to_cpu(j->last_seq) > le64_to_cpu(j->seq), c,
			"invalid journal entry: last_seq > seq"))
		j->last_seq = j->seq;

	vstruct_for_each(j, entry) {
		struct bkey_i *k;

		if (mustfix_fsck_err_on(vstruct_next(entry) >
					vstruct_last(j), c,
				"journal entry extents past end of jset")) {
			j->u64s = cpu_to_le64((u64 *) entry - j->_data);
			break;
		}

		switch (JOURNAL_ENTRY_TYPE(entry)) {
		case JOURNAL_ENTRY_BTREE_KEYS:
			vstruct_for_each(entry, k) {
				ret = journal_validate_key(c, j, entry, k,
						bkey_type(entry->level,
							  entry->btree_id),
						"key");
				if (ret)
					goto fsck_err;
			}
			break;

		case JOURNAL_ENTRY_BTREE_ROOT:
			k = entry->start;

			if (mustfix_fsck_err_on(!entry->u64s ||
					le16_to_cpu(entry->u64s) != k->k.u64s, c,
					"invalid btree root journal entry: wrong number of keys")) {
				journal_entry_null_range(entry,
						vstruct_next(entry));
				continue;
			}

			ret = journal_validate_key(c, j, entry, k,
						   BKEY_TYPE_BTREE, "btree root");
			if (ret)
				goto fsck_err;
			break;

		case JOURNAL_ENTRY_PRIO_PTRS:
			break;

		case JOURNAL_ENTRY_JOURNAL_SEQ_BLACKLISTED:
			if (mustfix_fsck_err_on(le16_to_cpu(entry->u64s) != 1, c,
				"invalid journal seq blacklist entry: bad size")) {
				journal_entry_null_range(entry,
						vstruct_next(entry));
			}

			break;
		default:
			mustfix_fsck_err(c, "invalid journal entry type %llu",
				 JOURNAL_ENTRY_TYPE(entry));
			journal_entry_null_range(entry, vstruct_next(entry));
			break;
		}
	}

fsck_err:
	return ret;
}

struct journal_read_buf {
	void		*data;
	size_t		size;
};

static int journal_read_buf_realloc(struct journal_read_buf *b,
				    size_t new_size)
{
	void *n;

	new_size = roundup_pow_of_two(new_size);
	n = (void *) __get_free_pages(GFP_KERNEL, get_order(new_size));
	if (!n)
		return -ENOMEM;

	free_pages((unsigned long) b->data, get_order(b->size));
	b->data = n;
	b->size = new_size;
	return 0;
}

static int journal_read_bucket(struct bch_dev *ca,
			       struct journal_read_buf *buf,
			       struct journal_list *jlist,
			       unsigned bucket, u64 *seq, bool *entries_found)
{
	struct bch_fs *c = ca->fs;
	struct journal_device *ja = &ca->journal;
	struct bio *bio = ja->bio;
	struct jset *j = NULL;
	unsigned sectors, sectors_read = 0;
	u64 offset = bucket_to_sector(ca, ja->buckets[bucket]),
	    end = offset + ca->mi.bucket_size;
	bool saw_bad = false;
	int ret = 0;

	pr_debug("reading %u", bucket);

	while (offset < end) {
		if (!sectors_read) {
reread:			sectors_read = min_t(unsigned,
				end - offset, buf->size >> 9);

			bio_reset(bio);
			bio->bi_bdev		= ca->disk_sb.bdev;
			bio->bi_iter.bi_sector	= offset;
			bio->bi_iter.bi_size	= sectors_read << 9;
			bio_set_op_attrs(bio, REQ_OP_READ, 0);
			bch2_bio_map(bio, buf->data);

			ret = submit_bio_wait(bio);

			if (bch2_dev_fatal_io_err_on(ret, ca,
						  "journal read from sector %llu",
						  offset) ||
			    bch2_meta_read_fault("journal"))
				return -EIO;

			j = buf->data;
		}

		ret = journal_entry_validate(c, j, offset,
					end - offset, sectors_read);
		switch (ret) {
		case BCH_FSCK_OK:
			break;
		case JOURNAL_ENTRY_REREAD:
			if (vstruct_bytes(j) > buf->size) {
				ret = journal_read_buf_realloc(buf,
							vstruct_bytes(j));
				if (ret)
					return ret;
			}
			goto reread;
		case JOURNAL_ENTRY_NONE:
			if (!saw_bad)
				return 0;
			sectors = c->sb.block_size;
			goto next_block;
		case JOURNAL_ENTRY_BAD:
			saw_bad = true;
			sectors = c->sb.block_size;
			goto next_block;
		default:
			return ret;
		}

		/*
		 * This happens sometimes if we don't have discards on -
		 * when we've partially overwritten a bucket with new
		 * journal entries. We don't need the rest of the
		 * bucket:
		 */
		if (le64_to_cpu(j->seq) < ja->bucket_seq[bucket])
			return 0;

		ja->bucket_seq[bucket] = le64_to_cpu(j->seq);

		ret = journal_entry_add(c, jlist, j);
		switch (ret) {
		case JOURNAL_ENTRY_ADD_OK:
			*entries_found = true;
			break;
		case JOURNAL_ENTRY_ADD_OUT_OF_RANGE:
			break;
		default:
			return ret;
		}

		if (le64_to_cpu(j->seq) > *seq)
			*seq = le64_to_cpu(j->seq);

		sectors = vstruct_sectors(j, c->block_bits);
next_block:
		pr_debug("next");
		offset		+= sectors;
		sectors_read	-= sectors;
		j = ((void *) j) + (sectors << 9);
	}

	return 0;
}

static void bch2_journal_read_device(struct closure *cl)
{
#define read_bucket(b)							\
	({								\
		bool entries_found = false;				\
		ret = journal_read_bucket(ca, &buf, jlist, b, &seq,	\
					  &entries_found);		\
		if (ret)						\
			goto err;					\
		__set_bit(b, bitmap);					\
		entries_found;						\
	 })

	struct journal_device *ja =
		container_of(cl, struct journal_device, read);
	struct bch_dev *ca = container_of(ja, struct bch_dev, journal);
	struct journal_list *jlist =
		container_of(cl->parent, struct journal_list, cl);
	struct request_queue *q = bdev_get_queue(ca->disk_sb.bdev);
	struct journal_read_buf buf = { NULL, 0 };

	DECLARE_BITMAP(bitmap, ja->nr);
	unsigned i, l, r;
	u64 seq = 0;
	int ret;

	if (!ja->nr)
		goto out;

	bitmap_zero(bitmap, ja->nr);
	ret = journal_read_buf_realloc(&buf, PAGE_SIZE);
	if (ret)
		goto err;

	pr_debug("%u journal buckets", ja->nr);

	/*
	 * If the device supports discard but not secure discard, we can't do
	 * the fancy fibonacci hash/binary search because the live journal
	 * entries might not form a contiguous range:
	 */
	for (i = 0; i < ja->nr; i++)
		read_bucket(i);
	goto search_done;

	if (!blk_queue_nonrot(q))
		goto linear_scan;

	/*
	 * Read journal buckets ordered by golden ratio hash to quickly
	 * find a sequence of buckets with valid journal entries
	 */
	for (i = 0; i < ja->nr; i++) {
		l = (i * 2654435769U) % ja->nr;

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
	for (l = find_first_zero_bit(bitmap, ja->nr);
	     l < ja->nr;
	     l = find_next_zero_bit(bitmap, ja->nr, l + 1))
		if (read_bucket(l))
			goto bsearch;

	/* no journal entries on this device? */
	if (l == ja->nr)
		goto out;
bsearch:
	/* Binary search */
	r = find_next_bit(bitmap, ja->nr, l + 1);
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
	/*
	 * Find the journal bucket with the highest sequence number:
	 *
	 * If there's duplicate journal entries in multiple buckets (which
	 * definitely isn't supposed to happen, but...) - make sure to start
	 * cur_idx at the last of those buckets, so we don't deadlock trying to
	 * allocate
	 */
	seq = 0;

	for (i = 0; i < ja->nr; i++)
		if (ja->bucket_seq[i] >= seq &&
		    ja->bucket_seq[i] != ja->bucket_seq[(i + 1) % ja->nr]) {
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
	ja->last_idx = (ja->cur_idx + 1) % ja->nr;

	/*
	 * Read buckets in reverse order until we stop finding more journal
	 * entries:
	 */
	for (i = (ja->cur_idx + ja->nr - 1) % ja->nr;
	     i != ja->cur_idx;
	     i = (i + ja->nr - 1) % ja->nr)
		if (!test_bit(i, bitmap) &&
		    !read_bucket(i))
			break;
out:
	free_pages((unsigned long) buf.data, get_order(buf.size));
	percpu_ref_put(&ca->io_ref);
	closure_return(cl);
err:
	mutex_lock(&jlist->lock);
	jlist->ret = ret;
	mutex_unlock(&jlist->lock);
	goto out;
#undef read_bucket
}

void bch2_journal_entries_free(struct list_head *list)
{

	while (!list_empty(list)) {
		struct journal_replay *i =
			list_first_entry(list, struct journal_replay, list);
		list_del(&i->list);
		kvfree(i);
	}
}

static int journal_seq_blacklist_read(struct journal *j,
				      struct journal_replay *i,
				      struct journal_entry_pin_list *p)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct jset_entry *entry;
	struct journal_seq_blacklist *bl;
	u64 seq;

	for_each_jset_entry_type(entry, &i->j,
			JOURNAL_ENTRY_JOURNAL_SEQ_BLACKLISTED) {
		seq = le64_to_cpu(entry->_data[0]);

		bch_verbose(c, "blacklisting existing journal seq %llu", seq);

		bl = bch2_journal_seq_blacklisted_new(j, seq);
		if (!bl)
			return -ENOMEM;

		journal_pin_add_entry(j, p, &bl->pin,
				  journal_seq_blacklist_flush);
		bl->written = true;
	}

	return 0;
}

static inline bool journal_has_keys(struct list_head *list)
{
	struct journal_replay *i;
	struct jset_entry *entry;
	struct bkey_i *k, *_n;

	list_for_each_entry(i, list, list)
		for_each_jset_key(k, _n, entry, &i->j)
			return true;

	return false;
}

int bch2_journal_read(struct bch_fs *c, struct list_head *list)
{
	struct jset_entry *prio_ptrs;
	struct journal_list jlist;
	struct journal_replay *i;
	struct jset *j;
	struct journal_entry_pin_list *p;
	struct bch_dev *ca;
	u64 cur_seq, end_seq;
	unsigned iter;
	int ret = 0;

	closure_init_stack(&jlist.cl);
	mutex_init(&jlist.lock);
	jlist.head = list;
	jlist.ret = 0;

	for_each_readable_member(ca, c, iter) {
		percpu_ref_get(&ca->io_ref);
		closure_call(&ca->journal.read,
			     bch2_journal_read_device,
			     system_unbound_wq,
			     &jlist.cl);
	}

	closure_sync(&jlist.cl);

	if (jlist.ret)
		return jlist.ret;

	if (list_empty(list)){
		bch_err(c, "no journal entries found");
		return BCH_FSCK_REPAIR_IMPOSSIBLE;
	}

	fsck_err_on(c->sb.clean && journal_has_keys(list), c,
		    "filesystem marked clean but journal has keys to replay");

	j = &list_entry(list->prev, struct journal_replay, list)->j;

	unfixable_fsck_err_on(le64_to_cpu(j->seq) -
			le64_to_cpu(j->last_seq) + 1 >
			c->journal.pin.size, c,
			"too many journal entries open for refcount fifo");

	c->journal.pin.back = le64_to_cpu(j->seq) -
		le64_to_cpu(j->last_seq) + 1;

	atomic64_set(&c->journal.seq, le64_to_cpu(j->seq));
	c->journal.last_seq_ondisk = le64_to_cpu(j->last_seq);

	BUG_ON(last_seq(&c->journal) != le64_to_cpu(j->last_seq));

	i = list_first_entry(list, struct journal_replay, list);

	mutex_lock(&c->journal.blacklist_lock);

	fifo_for_each_entry_ptr(p, &c->journal.pin, iter) {
		u64 seq = journal_pin_seq(&c->journal, p);

		INIT_LIST_HEAD(&p->list);

		if (i && le64_to_cpu(i->j.seq) == seq) {
			atomic_set(&p->count, 1);

			if (journal_seq_blacklist_read(&c->journal, i, p)) {
				mutex_unlock(&c->journal.blacklist_lock);
				return -ENOMEM;
			}

			i = list_is_last(&i->list, list)
				? NULL
				: list_next_entry(i, list);
		} else {
			atomic_set(&p->count, 0);
		}
	}

	mutex_unlock(&c->journal.blacklist_lock);

	cur_seq = last_seq(&c->journal);
	end_seq = le64_to_cpu(list_last_entry(list,
				struct journal_replay, list)->j.seq);

	list_for_each_entry(i, list, list) {
		bool blacklisted;

		mutex_lock(&c->journal.blacklist_lock);
		while (cur_seq < le64_to_cpu(i->j.seq) &&
		       journal_seq_blacklist_find(&c->journal, cur_seq))
			cur_seq++;

		blacklisted = journal_seq_blacklist_find(&c->journal,
							 le64_to_cpu(i->j.seq));
		mutex_unlock(&c->journal.blacklist_lock);

		fsck_err_on(blacklisted, c,
			    "found blacklisted journal entry %llu",
			    le64_to_cpu(i->j.seq));

		fsck_err_on(le64_to_cpu(i->j.seq) != cur_seq, c,
			"journal entries %llu-%llu missing! (replaying %llu-%llu)",
			cur_seq, le64_to_cpu(i->j.seq) - 1,
			last_seq(&c->journal), end_seq);

		cur_seq = le64_to_cpu(i->j.seq) + 1;
	}

	prio_ptrs = bch2_journal_find_entry(j, JOURNAL_ENTRY_PRIO_PTRS, 0);
	if (prio_ptrs) {
		memcpy_u64s(c->journal.prio_buckets,
			    prio_ptrs->_data,
			    le16_to_cpu(prio_ptrs->u64s));
		c->journal.nr_prio_buckets = le16_to_cpu(prio_ptrs->u64s);
	}
fsck_err:
	return ret;
}

int bch2_journal_mark(struct bch_fs *c, struct list_head *list)
{
	struct bkey_i *k, *n;
	struct jset_entry *j;
	struct journal_replay *r;
	int ret;

	list_for_each_entry(r, list, list)
		for_each_jset_key(k, n, j, &r->j) {
			enum bkey_type type = bkey_type(j->level, j->btree_id);
			struct bkey_s_c k_s_c = bkey_i_to_s_c(k);

			if (btree_type_has_ptrs(type)) {
				ret = bch2_btree_mark_key_initial(c, type, k_s_c);
				if (ret)
					return ret;
			}
		}

	return 0;
}

static bool journal_entry_is_open(struct journal *j)
{
	return j->reservations.cur_entry_offset < JOURNAL_ENTRY_CLOSED_VAL;
}

void bch2_journal_buf_put_slowpath(struct journal *j, bool need_write_just_set)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);

	if (!need_write_just_set &&
	    test_bit(JOURNAL_NEED_WRITE, &j->flags))
		__bch2_time_stats_update(j->delay_time,
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

static void __bch2_journal_next_entry(struct journal *j)
{
	struct journal_entry_pin_list pin_list, *p;
	struct journal_buf *buf;

	/*
	 * The fifo_push() needs to happen at the same time as j->seq is
	 * incremented for last_seq() to be calculated correctly
	 */
	atomic64_inc(&j->seq);
	BUG_ON(!fifo_push(&j->pin, pin_list));
	p = &fifo_peek_back(&j->pin);

	INIT_LIST_HEAD(&p->list);
	atomic_set(&p->count, 1);

	if (test_bit(JOURNAL_REPLAY_DONE, &j->flags)) {
		smp_wmb();
		j->cur_pin_list = p;
	}

	buf = journal_cur_buf(j);
	memset(buf->has_inode, 0, sizeof(buf->has_inode));

	memset(buf->data, 0, sizeof(*buf->data));
	buf->data->seq	= cpu_to_le64(atomic64_read(&j->seq));
	buf->data->u64s	= 0;

	BUG_ON(journal_pin_seq(j, p) != atomic64_read(&j->seq));
}

static inline size_t journal_entry_u64s_reserve(struct journal_buf *buf)
{
	unsigned ret = BTREE_ID_NR * (JSET_KEYS_U64s + BKEY_EXTENT_U64s_MAX);

	if (buf->nr_prio_buckets)
		ret += JSET_KEYS_U64s + buf->nr_prio_buckets;

	return ret;
}

static enum {
	JOURNAL_ENTRY_ERROR,
	JOURNAL_ENTRY_INUSE,
	JOURNAL_ENTRY_CLOSED,
	JOURNAL_UNLOCKED,
} journal_buf_switch(struct journal *j, bool need_write_just_set)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
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

	j->prev_buf_sectors =
		vstruct_blocks_plus(buf->data, c->block_bits,
				    journal_entry_u64s_reserve(buf)) *
		c->sb.block_size;

	BUG_ON(j->prev_buf_sectors > j->cur_buf_sectors);

	atomic_dec_bug(&fifo_peek_back(&j->pin).count);
	__bch2_journal_next_entry(j);

	cancel_delayed_work(&j->write_work);
	spin_unlock(&j->lock);

	if (c->bucket_journal_seq > 1 << 14) {
		c->bucket_journal_seq = 0;
		bch2_bucket_seq_cleanup(c);
	}

	/* ugh - might be called from __journal_res_get() under wait_event() */
	__set_current_state(TASK_RUNNING);
	bch2_journal_buf_put(j, old.idx, need_write_just_set);

	return JOURNAL_UNLOCKED;
}

void bch2_journal_halt(struct journal *j)
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
					      struct bch_dev *ca)
{
	struct journal_device *ja = &ca->journal;
	unsigned next = (ja->cur_idx + 1) % ja->nr;
	unsigned available = (ja->last_idx + ja->nr - next) % ja->nr;

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
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct bch_dev *ca;
	struct bkey_s_extent e = bkey_i_to_s_extent(&j->key);
	unsigned sectors_available = j->entry_size_max >> 9;
	unsigned i, nr_online = 0, nr_devs = 0;

	lockdep_assert_held(&j->lock);

	spin_lock(&j->devs.lock);
	group_for_each_dev(ca, &j->devs, i) {
		unsigned buckets_required = 0;

		sectors_available = min_t(unsigned, sectors_available,
					  ca->mi.bucket_size);

		/*
		 * Note that we don't allocate the space for a journal entry
		 * until we write it out - thus, if we haven't started the write
		 * for the previous entry we have to make sure we have space for
		 * it too:
		 */
		if (bch2_extent_has_device(e.c, ca->dev_idx)) {
			if (j->prev_buf_sectors > ca->journal.sectors_free)
				buckets_required++;

			if (j->prev_buf_sectors + sectors_available >
			    ca->journal.sectors_free)
				buckets_required++;
		} else {
			if (j->prev_buf_sectors + sectors_available >
			    ca->mi.bucket_size)
				buckets_required++;

			buckets_required++;
		}

		if (journal_dev_buckets_available(j, ca) >= buckets_required)
			nr_devs++;
		nr_online++;
	}
	spin_unlock(&j->devs.lock);

	if (nr_online < c->opts.metadata_replicas_required)
		return -EROFS;

	if (nr_devs < min_t(unsigned, nr_online, c->opts.metadata_replicas))
		return 0;

	return sectors_available;
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

	j->cur_buf_sectors	= sectors;
	buf->nr_prio_buckets	= j->nr_prio_buckets;

	u64s = (sectors << 9) / sizeof(u64);

	/* Subtract the journal header */
	u64s -= sizeof(struct jset) / sizeof(u64);
	/*
	 * Btree roots, prio pointers don't get added until right before we do
	 * the write:
	 */
	u64s -= journal_entry_u64s_reserve(buf);
	u64s  = max_t(ssize_t, 0L, u64s);

	BUG_ON(u64s >= JOURNAL_ENTRY_CLOSED_VAL);

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
			__bch2_time_stats_update(j->blocked_time,
						j->res_get_blocked_start);
			j->res_get_blocked_start = 0;
		}

		mod_delayed_work(system_freezable_wq,
				 &j->write_work,
				 msecs_to_jiffies(j->write_delay_ms));
	}

	return ret;
}

void bch2_journal_start(struct bch_fs *c)
{
	struct journal *j = &c->journal;
	struct journal_seq_blacklist *bl;
	u64 new_seq = 0;

	list_for_each_entry(bl, &j->seq_blacklist, list)
		new_seq = max(new_seq, bl->seq);

	spin_lock(&j->lock);

	set_bit(JOURNAL_STARTED, &j->flags);

	while (atomic64_read(&j->seq) < new_seq) {
		struct journal_entry_pin_list pin_list, *p;

		BUG_ON(!fifo_push(&j->pin, pin_list));
		p = &fifo_peek_back(&j->pin);

		INIT_LIST_HEAD(&p->list);
		atomic_set(&p->count, 0);
		atomic64_inc(&j->seq);
	}

	/*
	 * journal_buf_switch() only inits the next journal entry when it
	 * closes an open journal entry - the very first journal entry gets
	 * initialized here:
	 */
	__bch2_journal_next_entry(j);

	/*
	 * Adding entries to the next journal entry before allocating space on
	 * disk for the next journal entry - this is ok, because these entries
	 * only have to go down with the next journal entry we write:
	 */
	list_for_each_entry(bl, &j->seq_blacklist, list)
		if (!bl->written) {
			bch2_journal_add_entry(journal_cur_buf(j), &bl->seq, 1,
					JOURNAL_ENTRY_JOURNAL_SEQ_BLACKLISTED,
					0, 0);

			journal_pin_add_entry(j,
					      &fifo_peek_back(&j->pin),
					      &bl->pin,
					      journal_seq_blacklist_flush);
			bl->written = true;
		}

	spin_unlock(&j->lock);

	queue_delayed_work(system_freezable_wq, &j->reclaim_work, 0);
}

int bch2_journal_replay(struct bch_fs *c, struct list_head *list)
{
	int ret = 0, keys = 0, entries = 0;
	struct journal *j = &c->journal;
	struct bkey_i *k, *_n;
	struct jset_entry *entry;
	struct journal_replay *i, *n;

	list_for_each_entry_safe(i, n, list, list) {
		j->cur_pin_list =
			&j->pin.data[((j->pin.back - 1 -
				       (atomic64_read(&j->seq) -
					le64_to_cpu(i->j.seq))) &
				      j->pin.mask)];

		for_each_jset_key(k, _n, entry, &i->j) {
			struct disk_reservation disk_res;

			/*
			 * We might cause compressed extents to be split, so we
			 * need to pass in a disk_reservation:
			 */
			BUG_ON(bch2_disk_reservation_get(c, &disk_res, 0, 0));

			ret = bch2_btree_insert(c, entry->btree_id, k,
					       &disk_res, NULL, NULL,
					       BTREE_INSERT_NOFAIL|
					       BTREE_INSERT_JOURNAL_REPLAY);
			bch2_disk_reservation_put(c, &disk_res);

			if (ret)
				goto err;

			cond_resched();
			keys++;
		}

		if (atomic_dec_and_test(&j->cur_pin_list->count))
			wake_up(&j->wait);

		entries++;
	}

	if (keys) {
		bch2_btree_flush(c);

		/*
		 * Write a new journal entry _before_ we start journalling new data -
		 * otherwise, we could end up with btree node bsets with journal seqs
		 * arbitrarily far in the future vs. the most recently written journal
		 * entry on disk, if we crash before writing the next journal entry:
		 */
		ret = bch2_journal_meta(&c->journal);
		if (ret)
			goto err;
	}

	bch_info(c, "journal replay done, %i keys in %i entries, seq %llu",
		 keys, entries, (u64) atomic64_read(&j->seq));

	bch2_journal_set_replay_done(&c->journal);
err:
	if (ret)
		bch_err(c, "journal replay error: %d", ret);

	bch2_journal_entries_free(list);

	return ret;
}

#if 0
/*
 * Allocate more journal space at runtime - not currently making use if it, but
 * the code works:
 */
static int bch2_set_nr_journal_buckets(struct bch_fs *c, struct bch_dev *ca,
				      unsigned nr)
{
	struct journal *j = &c->journal;
	struct journal_device *ja = &ca->journal;
	struct bch_sb_field_journal *journal_buckets;
	struct disk_reservation disk_res = { 0, 0 };
	struct closure cl;
	u64 *new_bucket_seq = NULL, *new_buckets = NULL;
	int ret = 0;

	closure_init_stack(&cl);

	/* don't handle reducing nr of buckets yet: */
	if (nr <= ja->nr)
		return 0;

	/*
	 * note: journal buckets aren't really counted as _sectors_ used yet, so
	 * we don't need the disk reservation to avoid the BUG_ON() in buckets.c
	 * when space used goes up without a reservation - but we do need the
	 * reservation to ensure we'll actually be able to allocate:
	 */

	if (bch2_disk_reservation_get(c, &disk_res,
			(nr - ja->nr) << ca->bucket_bits, 0))
		return -ENOSPC;

	mutex_lock(&c->sb_lock);

	ret = -ENOMEM;
	new_buckets	= kzalloc(nr * sizeof(u64), GFP_KERNEL);
	new_bucket_seq	= kzalloc(nr * sizeof(u64), GFP_KERNEL);
	if (!new_buckets || !new_bucket_seq)
		goto err;

	journal_buckets = bch2_sb_resize_journal(&ca->disk_sb,
				nr + sizeof(*journal_buckets) / sizeof(u64));
	if (!journal_buckets)
		goto err;

	spin_lock(&j->lock);
	memcpy(new_buckets,	ja->buckets,	ja->nr * sizeof(u64));
	memcpy(new_bucket_seq,	ja->bucket_seq,	ja->nr * sizeof(u64));
	swap(new_buckets,	ja->buckets);
	swap(new_bucket_seq,	ja->bucket_seq);

	while (ja->nr < nr) {
		/* must happen under journal lock, to avoid racing with gc: */
		u64 b = bch2_bucket_alloc(ca, RESERVE_NONE);
		if (!b) {
			if (!closure_wait(&c->freelist_wait, &cl)) {
				spin_unlock(&j->lock);
				closure_sync(&cl);
				spin_lock(&j->lock);
			}
			continue;
		}

		bch2_mark_metadata_bucket(ca, &ca->buckets[b],
					 BUCKET_JOURNAL, false);
		bch2_mark_alloc_bucket(ca, &ca->buckets[b], false);

		memmove(ja->buckets + ja->last_idx + 1,
			ja->buckets + ja->last_idx,
			(ja->nr - ja->last_idx) * sizeof(u64));
		memmove(ja->bucket_seq + ja->last_idx + 1,
			ja->bucket_seq + ja->last_idx,
			(ja->nr - ja->last_idx) * sizeof(u64));
		memmove(journal_buckets->buckets + ja->last_idx + 1,
			journal_buckets->buckets + ja->last_idx,
			(ja->nr - ja->last_idx) * sizeof(u64));

		ja->buckets[ja->last_idx] = b;
		journal_buckets->buckets[ja->last_idx] = cpu_to_le64(b);

		if (ja->last_idx < ja->nr) {
			if (ja->cur_idx >= ja->last_idx)
				ja->cur_idx++;
			ja->last_idx++;
		}
		ja->nr++;

	}
	spin_unlock(&j->lock);

	BUG_ON(bch2_validate_journal_layout(ca->disk_sb.sb, ca->mi));

	bch2_write_super(c);

	ret = 0;
err:
	mutex_unlock(&c->sb_lock);

	kfree(new_bucket_seq);
	kfree(new_buckets);
	bch2_disk_reservation_put(c, &disk_res);

	return ret;
}
#endif

int bch2_dev_journal_alloc(struct bch_dev *ca)
{
	struct journal_device *ja = &ca->journal;
	struct bch_sb_field_journal *journal_buckets;
	unsigned i, nr;
	u64 b, *p;

	if (dynamic_fault("bcachefs:add:journal_alloc"))
		return -ENOMEM;

	/*
	 * clamp journal size to 1024 buckets or 512MB (in sectors), whichever
	 * is smaller:
	 */
	nr = clamp_t(unsigned, ca->mi.nbuckets >> 8,
		     BCH_JOURNAL_BUCKETS_MIN,
		     min(1 << 10,
			 (1 << 20) / ca->mi.bucket_size));

	p = krealloc(ja->bucket_seq, nr * sizeof(u64),
		     GFP_KERNEL|__GFP_ZERO);
	if (!p)
		return -ENOMEM;

	ja->bucket_seq = p;

	p = krealloc(ja->buckets, nr * sizeof(u64),
		     GFP_KERNEL|__GFP_ZERO);
	if (!p)
		return -ENOMEM;

	ja->buckets = p;

	journal_buckets = bch2_sb_resize_journal(&ca->disk_sb,
				nr + sizeof(*journal_buckets) / sizeof(u64));
	if (!journal_buckets)
		return -ENOMEM;

	for (i = 0, b = ca->mi.first_bucket;
	     i < nr && b < ca->mi.nbuckets; b++) {
		if (!is_available_bucket(ca->buckets[b].mark))
			continue;

		bch2_mark_metadata_bucket(ca, &ca->buckets[b],
					 BUCKET_JOURNAL, true);
		ja->buckets[i] = b;
		journal_buckets->buckets[i] = cpu_to_le64(b);
		i++;
	}

	if (i < nr)
		return -ENOSPC;

	BUG_ON(bch2_validate_journal_layout(ca->disk_sb.sb, ca->mi));

	ja->nr = nr;

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
	bool popped = false;

	lockdep_assert_held(&j->lock);

	/*
	 * Unpin journal entries whose reference counts reached zero, meaning
	 * all btree nodes got written out
	 */
	while (!atomic_read(&fifo_peek_front(&j->pin).count)) {
		BUG_ON(!list_empty(&fifo_peek_front(&j->pin).list));
		BUG_ON(!fifo_pop(&j->pin, temp));
		popped = true;
	}

	if (popped)
		wake_up(&j->wait);
}

/*
 * Journal entry pinning - machinery for holding a reference on a given journal
 * entry, marking it as dirty:
 */

static inline void __journal_pin_add(struct journal *j,
				     struct journal_entry_pin_list *pin_list,
				     struct journal_entry_pin *pin,
				     journal_pin_flush_fn flush_fn)
{
	BUG_ON(journal_pin_active(pin));

	atomic_inc(&pin_list->count);
	pin->pin_list	= pin_list;
	pin->flush	= flush_fn;

	if (flush_fn)
		list_add(&pin->list, &pin_list->list);
	else
		INIT_LIST_HEAD(&pin->list);
}

static void journal_pin_add_entry(struct journal *j,
				  struct journal_entry_pin_list *pin_list,
				  struct journal_entry_pin *pin,
				  journal_pin_flush_fn flush_fn)
{
	spin_lock_irq(&j->pin_lock);
	__journal_pin_add(j, pin_list, pin, flush_fn);
	spin_unlock_irq(&j->pin_lock);
}

void bch2_journal_pin_add(struct journal *j,
			 struct journal_entry_pin *pin,
			 journal_pin_flush_fn flush_fn)
{
	spin_lock_irq(&j->pin_lock);
	__journal_pin_add(j, j->cur_pin_list, pin, flush_fn);
	spin_unlock_irq(&j->pin_lock);
}

static inline bool __journal_pin_drop(struct journal *j,
				      struct journal_entry_pin *pin)
{
	struct journal_entry_pin_list *pin_list = pin->pin_list;

	pin->pin_list = NULL;

	/* journal_reclaim_work() might have already taken us off the list */
	if (!list_empty_careful(&pin->list))
		list_del_init(&pin->list);

	return atomic_dec_and_test(&pin_list->count);
}

void bch2_journal_pin_drop(struct journal *j,
			  struct journal_entry_pin *pin)
{
	unsigned long flags;
	bool wakeup;

	if (!journal_pin_active(pin))
		return;

	spin_lock_irqsave(&j->pin_lock, flags);
	wakeup = __journal_pin_drop(j, pin);
	spin_unlock_irqrestore(&j->pin_lock, flags);

	/*
	 * Unpinning a journal entry make make journal_next_bucket() succeed, if
	 * writing a new last_seq will now make another bucket available:
	 *
	 * Nested irqsave is expensive, don't do the wakeup with lock held:
	 */
	if (wakeup)
		wake_up(&j->wait);
}

void bch2_journal_pin_add_if_older(struct journal *j,
				  struct journal_entry_pin *src_pin,
				  struct journal_entry_pin *pin,
				  journal_pin_flush_fn flush_fn)
{
	spin_lock_irq(&j->pin_lock);

	if (journal_pin_active(src_pin) &&
	    (!journal_pin_active(pin) ||
	     fifo_entry_idx(&j->pin, src_pin->pin_list) <
	     fifo_entry_idx(&j->pin, pin->pin_list))) {
		if (journal_pin_active(pin))
			__journal_pin_drop(j, pin);
		__journal_pin_add(j, src_pin->pin_list, pin, flush_fn);
	}

	spin_unlock_irq(&j->pin_lock);
}

static struct journal_entry_pin *
journal_get_next_pin(struct journal *j, u64 seq_to_flush)
{
	struct journal_entry_pin_list *pin_list;
	struct journal_entry_pin *ret = NULL;
	unsigned iter;

	/* so we don't iterate over empty fifo entries below: */
	if (!atomic_read(&fifo_peek_front(&j->pin).count)) {
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
			/* must be list_del_init(), see bch2_journal_pin_drop() */
			list_del_init(&ret->list);
			break;
		}
	}
	spin_unlock_irq(&j->pin_lock);

	return ret;
}

static bool journal_has_pins(struct journal *j)
{
	bool ret;

	spin_lock(&j->lock);
	journal_reclaim_fast(j);
	ret = fifo_used(&j->pin) > 1 ||
		atomic_read(&fifo_peek_front(&j->pin).count) > 1;
	spin_unlock(&j->lock);

	return ret;
}

void bch2_journal_flush_pins(struct journal *j)
{
	struct journal_entry_pin *pin;

	while ((pin = journal_get_next_pin(j, U64_MAX)))
		pin->flush(j, pin);

	wait_event(j->wait, !journal_has_pins(j) || bch2_journal_error(j));
}

static bool should_discard_bucket(struct journal *j, struct journal_device *ja)
{
	bool ret;

	spin_lock(&j->lock);
	ret = ja->nr &&
		(ja->last_idx != ja->cur_idx &&
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
	struct bch_fs *c = container_of(to_delayed_work(work),
				struct bch_fs, journal.reclaim_work);
	struct journal *j = &c->journal;
	struct bch_dev *ca;
	struct journal_entry_pin *pin;
	u64 seq_to_flush = 0;
	unsigned iter, bucket_to_flush;
	unsigned long next_flush;
	bool reclaim_lock_held = false, need_flush;

	/*
	 * Advance last_idx to point to the oldest journal entry containing
	 * btree node updates that have not yet been written out
	 */
	for_each_rw_member(ca, c, iter) {
		struct journal_device *ja = &ca->journal;

		if (!ja->nr)
			continue;

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
						ja->buckets[ja->last_idx]),
					ca->mi.bucket_size, GFP_NOIO, 0);

			spin_lock(&j->lock);
			ja->last_idx = (ja->last_idx + 1) % ja->nr;
			spin_unlock(&j->lock);

			wake_up(&j->wait);
		}

		/*
		 * Write out enough btree nodes to free up 50% journal
		 * buckets
		 */
		spin_lock(&j->lock);
		bucket_to_flush = (ja->cur_idx + (ja->nr >> 1)) % ja->nr;
		seq_to_flush = max_t(u64, seq_to_flush,
				     ja->bucket_seq[bucket_to_flush]);
		spin_unlock(&j->lock);
	}

	if (reclaim_lock_held)
		mutex_unlock(&j->reclaim_lock);

	/* Also flush if the pin fifo is more than half full */
	seq_to_flush = max_t(s64, seq_to_flush,
			     (s64) atomic64_read(&j->seq) -
			     (j->pin.size >> 1));

	/*
	 * If it's been longer than j->reclaim_delay_ms since we last flushed,
	 * make sure to flush at least one journal pin:
	 */
	next_flush = j->last_flushed + msecs_to_jiffies(j->reclaim_delay_ms);
	need_flush = time_after(jiffies, next_flush);

	while ((pin = journal_get_next_pin(j, need_flush
					   ? U64_MAX
					   : seq_to_flush))) {
		__set_current_state(TASK_RUNNING);
		pin->flush(j, pin);
		need_flush = false;

		j->last_flushed = jiffies;
	}

	if (!test_bit(BCH_FS_RO, &c->flags))
		queue_delayed_work(system_freezable_wq, &j->reclaim_work,
				   msecs_to_jiffies(j->reclaim_delay_ms));
}

/**
 * journal_next_bucket - move on to the next journal bucket if possible
 */
static int journal_write_alloc(struct journal *j, unsigned sectors)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct bkey_s_extent e = bkey_i_to_s_extent(&j->key);
	struct bch_extent_ptr *ptr;
	struct journal_device *ja;
	struct bch_dev *ca;
	bool swapped;
	unsigned i, replicas, replicas_want =
		READ_ONCE(c->opts.metadata_replicas);

	spin_lock(&j->lock);

	/*
	 * Drop any pointers to devices that have been removed, are no longer
	 * empty, or filled up their current journal bucket:
	 *
	 * Note that a device may have had a small amount of free space (perhaps
	 * one sector) that wasn't enough for the smallest possible journal
	 * entry - that's why we drop pointers to devices <= current free space,
	 * i.e. whichever device was limiting the current journal entry size.
	 */
	extent_for_each_ptr_backwards(e, ptr) {
		ca = c->devs[ptr->dev];

		if (ca->mi.state != BCH_MEMBER_STATE_RW ||
		    ca->journal.sectors_free <= sectors)
			__bch2_extent_drop_ptr(e, ptr);
		else
			ca->journal.sectors_free -= sectors;
	}

	replicas = bch2_extent_nr_ptrs(e.c);

	spin_lock(&j->devs.lock);

	/* Sort by tier: */
	do {
		swapped = false;

		for (i = 0; i + 1 < j->devs.nr; i++)
			if (j->devs.d[i + 0].dev->mi.tier >
			    j->devs.d[i + 1].dev->mi.tier) {
				swap(j->devs.d[i], j->devs.d[i + 1]);
				swapped = true;
			}
	} while (swapped);

	/*
	 * Pick devices for next journal write:
	 * XXX: sort devices by free journal space?
	 */
	group_for_each_dev(ca, &j->devs, i) {
		ja = &ca->journal;

		if (replicas >= replicas_want)
			break;

		/*
		 * Check that we can use this device, and aren't already using
		 * it:
		 */
		if (bch2_extent_has_device(e.c, ca->dev_idx) ||
		    !journal_dev_buckets_available(j, ca) ||
		    sectors > ca->mi.bucket_size)
			continue;

		ja->sectors_free = ca->mi.bucket_size - sectors;
		ja->cur_idx = (ja->cur_idx + 1) % ja->nr;
		ja->bucket_seq[ja->cur_idx] = atomic64_read(&j->seq);

		extent_ptr_append(bkey_i_to_extent(&j->key),
			(struct bch_extent_ptr) {
				  .offset = bucket_to_sector(ca,
					ja->buckets[ja->cur_idx]),
				  .dev = ca->dev_idx,
		});
		replicas++;
	}
	spin_unlock(&j->devs.lock);

	j->prev_buf_sectors = 0;
	spin_unlock(&j->lock);

	if (replicas < c->opts.metadata_replicas_required)
		return -EROFS;

	BUG_ON(!replicas);

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
	vstruct_for_each_safe(jset, i, next) {
		unsigned u64s = le16_to_cpu(i->u64s);

		/* Empty entry: */
		if (!u64s)
			continue;

		/* Can we merge with previous entry? */
		if (prev &&
		    i->btree_id == prev->btree_id &&
		    i->level	== prev->level &&
		    JOURNAL_ENTRY_TYPE(i) == JOURNAL_ENTRY_TYPE(prev) &&
		    JOURNAL_ENTRY_TYPE(i) == JOURNAL_ENTRY_BTREE_KEYS &&
		    le16_to_cpu(prev->u64s) + u64s <= U16_MAX) {
			memmove_u64s_down(vstruct_next(prev),
					  i->_data,
					  u64s);
			le16_add_cpu(&prev->u64s, u64s);
			continue;
		}

		/* Couldn't merge, move i into new position (after prev): */
		prev = prev ? vstruct_next(prev) : jset->start;
		if (i != prev)
			memmove_u64s_down(prev, i, jset_u64s(u64s));
	}

	prev = prev ? vstruct_next(prev) : jset->start;
	jset->u64s = cpu_to_le32((u64 *) prev - jset->_data);
}

static void journal_write_endio(struct bio *bio)
{
	struct bch_dev *ca = bio->bi_private;
	struct journal *j = &ca->fs->journal;

	if (bch2_dev_fatal_io_err_on(bio->bi_error, ca, "journal write") ||
	    bch2_meta_write_fault("journal"))
		bch2_journal_halt(j);

	closure_put(&j->io);
	percpu_ref_put(&ca->io_ref);
}

static void journal_write_done(struct closure *cl)
{
	struct journal *j = container_of(cl, struct journal, io);
	struct journal_buf *w = journal_prev_buf(j);

	j->last_seq_ondisk = le64_to_cpu(w->data->last_seq);

	__bch2_time_stats_update(j->write_time, j->write_start_time);

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

	/*
	 * Updating last_seq_ondisk may let journal_reclaim_work() discard more
	 * buckets:
	 */
	mod_delayed_work(system_freezable_wq, &j->reclaim_work, 0);
}

static void journal_write(struct closure *cl)
{
	struct journal *j = container_of(cl, struct journal, io);
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct bch_dev *ca;
	struct journal_buf *w = journal_prev_buf(j);
	struct jset *jset = w->data;
	struct bio *bio;
	struct bch_extent_ptr *ptr;
	unsigned i, sectors, bytes;

	j->write_start_time = local_clock();

	bch2_journal_add_prios(j, w);

	mutex_lock(&c->btree_root_lock);
	for (i = 0; i < BTREE_ID_NR; i++) {
		struct btree_root *r = &c->btree_roots[i];

		if (r->alive)
			bch2_journal_add_btree_root(w, i, &r->key, r->level);
	}
	mutex_unlock(&c->btree_root_lock);

	journal_write_compact(jset);

	jset->read_clock	= cpu_to_le16(c->prio_clock[READ].hand);
	jset->write_clock	= cpu_to_le16(c->prio_clock[WRITE].hand);
	jset->magic		= cpu_to_le64(jset_magic(c));
	jset->version		= cpu_to_le32(BCACHE_JSET_VERSION);

	SET_JSET_BIG_ENDIAN(jset, CPU_BIG_ENDIAN);
	SET_JSET_CSUM_TYPE(jset, bch2_meta_checksum_type(c));

	bch2_encrypt(c, JSET_CSUM_TYPE(jset), journal_nonce(jset),
		    jset->encrypted_start,
		    vstruct_end(jset) - (void *) jset->encrypted_start);

	jset->csum = csum_vstruct(c, JSET_CSUM_TYPE(jset),
				  journal_nonce(jset), jset);

	sectors = vstruct_sectors(jset, c->block_bits);
	BUG_ON(sectors > j->prev_buf_sectors);

	bytes = vstruct_bytes(w->data);
	memset((void *) w->data + bytes, 0, (sectors << 9) - bytes);

	if (journal_write_alloc(j, sectors)) {
		bch2_journal_halt(j);
		bch_err(c, "Unable to allocate journal write");
		bch2_fatal_error(c);
		closure_return_with_destructor(cl, journal_write_done);
	}

	bch2_check_mark_super(c, &j->key, true);

	/*
	 * XXX: we really should just disable the entire journal in nochanges
	 * mode
	 */
	if (c->opts.nochanges)
		goto no_io;

	extent_for_each_ptr(bkey_i_to_s_extent(&j->key), ptr) {
		ca = c->devs[ptr->dev];
		if (!percpu_ref_tryget(&ca->io_ref)) {
			/* XXX: fix this */
			bch_err(c, "missing device for journal write\n");
			continue;
		}

		atomic64_add(sectors, &ca->meta_sectors_written);

		bio = ca->journal.bio;
		bio_reset(bio);
		bio->bi_iter.bi_sector	= ptr->offset;
		bio->bi_bdev		= ca->disk_sb.bdev;
		bio->bi_iter.bi_size	= sectors << 9;
		bio->bi_end_io		= journal_write_endio;
		bio->bi_private		= ca;
		bio_set_op_attrs(bio, REQ_OP_WRITE,
				 REQ_SYNC|REQ_META|REQ_PREFLUSH|REQ_FUA);
		bch2_bio_map(bio, jset);

		trace_journal_write(bio);
		closure_bio_submit(bio, cl);

		ca->journal.bucket_seq[ca->journal.cur_idx] = le64_to_cpu(w->data->seq);
	}

	for_each_rw_member(ca, c, i)
		if (journal_flushes_device(ca) &&
		    !bch2_extent_has_device(bkey_i_to_s_c_extent(&j->key), i)) {
			percpu_ref_get(&ca->io_ref);

			bio = ca->journal.bio;
			bio_reset(bio);
			bio->bi_bdev		= ca->disk_sb.bdev;
			bio->bi_end_io		= journal_write_endio;
			bio->bi_private		= ca;
			bio_set_op_attrs(bio, REQ_OP_WRITE, WRITE_FLUSH);
			closure_bio_submit(bio, cl);
		}

no_io:
	extent_for_each_ptr(bkey_i_to_s_extent(&j->key), ptr)
		ptr->offset += sectors;

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

/*
 * Given an inode number, if that inode number has data in the journal that
 * hasn't yet been flushed, return the journal sequence number that needs to be
 * flushed:
 */
u64 bch2_inode_journal_seq(struct journal *j, u64 inode)
{
	size_t h = hash_64(inode, ilog2(sizeof(j->buf[0].has_inode) * 8));
	u64 seq = 0;

	if (!test_bit(h, j->buf[0].has_inode) &&
	    !test_bit(h, j->buf[1].has_inode))
		return 0;

	spin_lock(&j->lock);
	if (test_bit(h, journal_cur_buf(j)->has_inode))
		seq = atomic64_read(&j->seq);
	else if (test_bit(h, journal_prev_buf(j)->has_inode))
		seq = atomic64_read(&j->seq) - 1;
	spin_unlock(&j->lock);

	return seq;
}

static int __journal_res_get(struct journal *j, struct journal_res *res,
			      unsigned u64s_min, unsigned u64s_max)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
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
		trace_journal_entry_full(c);
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
	journal_reclaim_work(&j->reclaim_work.work);

	trace_journal_full(c);
blocked:
	if (!j->res_get_blocked_start)
		j->res_get_blocked_start = local_clock() ?: 1;
	return 0;
}

/*
 * Essentially the entry function to the journaling code. When bcachefs is doing
 * a btree insert, it calls this function to get the current journal write.
 * Journal write is the structure used set up journal writes. The calling
 * function will then add its keys to the structure, queuing them for the next
 * write.
 *
 * To ensure forward progress, the current task must not be holding any
 * btree node write locks.
 */
int bch2_journal_res_get_slowpath(struct journal *j, struct journal_res *res,
				 unsigned u64s_min, unsigned u64s_max)
{
	int ret;

	wait_event(j->wait,
		   (ret = __journal_res_get(j, res, u64s_min,
					    u64s_max)));
	return ret < 0 ? ret : 0;
}

void bch2_journal_wait_on_seq(struct journal *j, u64 seq, struct closure *parent)
{
	spin_lock(&j->lock);

	BUG_ON(seq > atomic64_read(&j->seq));

	if (bch2_journal_error(j)) {
		spin_unlock(&j->lock);
		return;
	}

	if (seq == atomic64_read(&j->seq)) {
		if (!closure_wait(&journal_cur_buf(j)->wait, parent))
			BUG();
	} else if (seq + 1 == atomic64_read(&j->seq) &&
		   j->reservations.prev_buf_unwritten) {
		if (!closure_wait(&journal_prev_buf(j)->wait, parent))
			BUG();

		smp_mb();

		/* check if raced with write completion (or failure) */
		if (!j->reservations.prev_buf_unwritten ||
		    bch2_journal_error(j))
			closure_wake_up(&journal_prev_buf(j)->wait);
	}

	spin_unlock(&j->lock);
}

void bch2_journal_flush_seq_async(struct journal *j, u64 seq, struct closure *parent)
{
	spin_lock(&j->lock);

	BUG_ON(seq > atomic64_read(&j->seq));

	if (bch2_journal_error(j)) {
		spin_unlock(&j->lock);
		return;
	}

	if (seq == atomic64_read(&j->seq)) {
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
		   seq + 1 == atomic64_read(&j->seq) &&
		   j->reservations.prev_buf_unwritten) {
		if (!closure_wait(&journal_prev_buf(j)->wait, parent))
			BUG();

		smp_mb();

		/* check if raced with write completion (or failure) */
		if (!j->reservations.prev_buf_unwritten ||
		    bch2_journal_error(j))
			closure_wake_up(&journal_prev_buf(j)->wait);
	}

	spin_unlock(&j->lock);
}

int bch2_journal_flush_seq(struct journal *j, u64 seq)
{
	struct closure cl;
	u64 start_time = local_clock();

	closure_init_stack(&cl);
	bch2_journal_flush_seq_async(j, seq, &cl);
	closure_sync(&cl);

	bch2_time_stats_update(j->flush_seq_time, start_time);

	return bch2_journal_error(j);
}

void bch2_journal_meta_async(struct journal *j, struct closure *parent)
{
	struct journal_res res;
	unsigned u64s = jset_u64s(0);

	memset(&res, 0, sizeof(res));

	bch2_journal_res_get(j, &res, u64s, u64s);
	bch2_journal_res_put(j, &res);

	bch2_journal_flush_seq_async(j, res.seq, parent);
}

int bch2_journal_meta(struct journal *j)
{
	struct journal_res res;
	unsigned u64s = jset_u64s(0);
	int ret;

	memset(&res, 0, sizeof(res));

	ret = bch2_journal_res_get(j, &res, u64s, u64s);
	if (ret)
		return ret;

	bch2_journal_res_put(j, &res);

	return bch2_journal_flush_seq(j, res.seq);
}

void bch2_journal_flush_async(struct journal *j, struct closure *parent)
{
	u64 seq, journal_seq;

	spin_lock(&j->lock);
	journal_seq = atomic64_read(&j->seq);

	if (journal_entry_is_open(j)) {
		seq = journal_seq;
	} else if (journal_seq) {
		seq = journal_seq - 1;
	} else {
		spin_unlock(&j->lock);
		return;
	}
	spin_unlock(&j->lock);

	bch2_journal_flush_seq_async(j, seq, parent);
}

int bch2_journal_flush(struct journal *j)
{
	u64 seq, journal_seq;

	spin_lock(&j->lock);
	journal_seq = atomic64_read(&j->seq);

	if (journal_entry_is_open(j)) {
		seq = journal_seq;
	} else if (journal_seq) {
		seq = journal_seq - 1;
	} else {
		spin_unlock(&j->lock);
		return 0;
	}
	spin_unlock(&j->lock);

	return bch2_journal_flush_seq(j, seq);
}

ssize_t bch2_journal_print_debug(struct journal *j, char *buf)
{
	union journal_res_state *s = &j->reservations;
	struct bch_dev *ca;
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
			 (u64) atomic64_read(&j->seq),
			 last_seq(j),
			 j->last_seq_ondisk,
			 journal_state_count(*s, s->idx),
			 s->cur_entry_offset,
			 j->cur_entry_u64s,
			 s->prev_buf_unwritten,
			 test_bit(JOURNAL_NEED_WRITE,	&j->flags),
			 journal_entry_is_open(j),
			 test_bit(JOURNAL_REPLAY_DONE,	&j->flags));

	spin_lock(&j->devs.lock);
	group_for_each_dev(ca, &j->devs, iter) {
		struct journal_device *ja = &ca->journal;

		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "dev %u:\n"
				 "\tnr\t\t%u\n"
				 "\tcur_idx\t\t%u (seq %llu)\n"
				 "\tlast_idx\t%u (seq %llu)\n",
				 iter, ja->nr,
				 ja->cur_idx,	ja->bucket_seq[ja->cur_idx],
				 ja->last_idx,	ja->bucket_seq[ja->last_idx]);
	}
	spin_unlock(&j->devs.lock);

	spin_unlock(&j->lock);
	rcu_read_unlock();

	return ret;
}

static bool bch2_journal_writing_to_device(struct bch_dev *ca)
{
	struct journal *j = &ca->fs->journal;
	bool ret;

	spin_lock(&j->lock);
	ret = bch2_extent_has_device(bkey_i_to_s_c_extent(&j->key),
				    ca->dev_idx);
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

int bch2_journal_move(struct bch_dev *ca)
{
	u64 last_flushed_seq;
	struct journal_device *ja = &ca->journal;
	struct bch_fs *c = ca->fs;
	struct journal *j = &c->journal;
	unsigned i;
	int ret = 0;		/* Success */

	if (bch2_journal_writing_to_device(ca)) {
		/*
		 * bch_journal_meta will write a record and we'll wait
		 * for the write to complete.
		 * Actually writing the journal (journal_write_locked)
		 * will call journal_next_bucket which notices that the
		 * device is no longer writeable, and picks a new one.
		 */
		bch2_journal_meta(j);
		BUG_ON(bch2_journal_writing_to_device(ca));
	}

	/*
	 * Flush all btree updates to backing store so that any
	 * journal entries written to ca become stale and are no
	 * longer needed.
	 */

	/*
	 * XXX: switch to normal journal reclaim machinery
	 */
	bch2_btree_flush(c);

	/*
	 * Force a meta-data journal entry to be written so that
	 * we have newer journal entries in devices other than ca,
	 * and wait for the meta data write to complete.
	 */
	bch2_journal_meta(j);

	/*
	 * Verify that we no longer need any of the journal entries in
	 * the device
	 */
	spin_lock(&j->lock);
	last_flushed_seq = last_seq(j);
	spin_unlock(&j->lock);

	for (i = 0; i < ja->nr; i += 1)
		BUG_ON(ja->bucket_seq[i] > last_flushed_seq);

	return ret;
}

void bch2_fs_journal_stop(struct journal *j)
{
	if (!test_bit(JOURNAL_STARTED, &j->flags))
		return;

	/*
	 * Empty out the journal by first flushing everything pinning existing
	 * journal entries, then force a brand new empty journal entry to be
	 * written:
	 */
	bch2_journal_flush_pins(j);
	bch2_journal_flush_async(j, NULL);
	bch2_journal_meta(j);

	cancel_delayed_work_sync(&j->write_work);
	cancel_delayed_work_sync(&j->reclaim_work);
}

void bch2_dev_journal_exit(struct bch_dev *ca)
{
	kfree(ca->journal.bio);
	kfree(ca->journal.buckets);
	kfree(ca->journal.bucket_seq);

	ca->journal.bio		= NULL;
	ca->journal.buckets	= NULL;
	ca->journal.bucket_seq	= NULL;
}

int bch2_dev_journal_init(struct bch_dev *ca, struct bch_sb *sb)
{
	struct journal_device *ja = &ca->journal;
	struct bch_sb_field_journal *journal_buckets =
		bch2_sb_get_journal(sb);
	unsigned i, journal_entry_pages;

	journal_entry_pages =
		DIV_ROUND_UP(1U << BCH_SB_JOURNAL_ENTRY_SIZE(sb),
			     PAGE_SECTORS);

	ja->nr = bch2_nr_journal_buckets(journal_buckets);

	ja->bucket_seq = kcalloc(ja->nr, sizeof(u64), GFP_KERNEL);
	if (!ja->bucket_seq)
		return -ENOMEM;

	ca->journal.bio = bio_kmalloc(GFP_KERNEL, journal_entry_pages);
	if (!ca->journal.bio)
		return -ENOMEM;

	ja->buckets = kcalloc(ja->nr, sizeof(u64), GFP_KERNEL);
	if (!ja->buckets)
		return -ENOMEM;

	for (i = 0; i < ja->nr; i++)
		ja->buckets[i] = le64_to_cpu(journal_buckets->buckets[i]);

	return 0;
}

void bch2_fs_journal_exit(struct journal *j)
{
	unsigned order = get_order(j->entry_size_max);

	free_pages((unsigned long) j->buf[1].data, order);
	free_pages((unsigned long) j->buf[0].data, order);
	free_fifo(&j->pin);
}

int bch2_fs_journal_init(struct journal *j, unsigned entry_size_max)
{
	static struct lock_class_key res_key;
	unsigned order = get_order(entry_size_max);

	spin_lock_init(&j->lock);
	spin_lock_init(&j->pin_lock);
	init_waitqueue_head(&j->wait);
	INIT_DELAYED_WORK(&j->write_work, journal_write_work);
	INIT_DELAYED_WORK(&j->reclaim_work, journal_reclaim_work);
	mutex_init(&j->blacklist_lock);
	INIT_LIST_HEAD(&j->seq_blacklist);
	spin_lock_init(&j->devs.lock);
	mutex_init(&j->reclaim_lock);

	lockdep_init_map(&j->res_map, "journal res", &res_key, 0);

	j->entry_size_max	= entry_size_max;
	j->write_delay_ms	= 100;
	j->reclaim_delay_ms	= 100;

	bkey_extent_init(&j->key);

	atomic64_set(&j->reservations.counter,
		((union journal_res_state)
		 { .cur_entry_offset = JOURNAL_ENTRY_CLOSED_VAL }).v);

	if (!(init_fifo(&j->pin, JOURNAL_PIN, GFP_KERNEL)) ||
	    !(j->buf[0].data = (void *) __get_free_pages(GFP_KERNEL, order)) ||
	    !(j->buf[1].data = (void *) __get_free_pages(GFP_KERNEL, order)))
		return -ENOMEM;

	return 0;
}
