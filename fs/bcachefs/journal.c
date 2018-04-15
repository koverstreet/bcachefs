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
#include "btree_update_interior.h"
#include "btree_io.h"
#include "checksum.h"
#include "debug.h"
#include "error.h"
#include "extents.h"
#include "io.h"
#include "keylist.h"
#include "journal.h"
#include "replicas.h"
#include "super-io.h"
#include "vstructs.h"

#include <trace/events/bcachefs.h>

static void journal_write(struct closure *);
static void journal_reclaim_fast(struct journal *);
static void journal_pin_add_entry(struct journal *,
				  struct journal_entry_pin_list *,
				  struct journal_entry_pin *,
				  journal_pin_flush_fn);

static inline void journal_wake(struct journal *j)
{
	wake_up(&j->wait);
	closure_wake_up(&j->async_wait);
}

static inline struct journal_buf *journal_cur_buf(struct journal *j)
{
	return j->buf + j->reservations.idx;
}

static inline struct journal_buf *journal_prev_buf(struct journal *j)
{
	return j->buf + !j->reservations.idx;
}

/* Sequence number of oldest dirty journal entry */

static inline u64 journal_last_seq(struct journal *j)
{
	return j->pin.front;
}

static inline u64 journal_cur_seq(struct journal *j)
{
	BUG_ON(j->pin.back - 1 != atomic64_read(&j->seq));

	return j->pin.back - 1;
}

static inline u64 journal_pin_seq(struct journal *j,
				  struct journal_entry_pin_list *pin_list)
{
	return fifo_entry_idx_abs(&j->pin, pin_list);
}

u64 bch2_journal_pin_seq(struct journal *j, struct journal_entry_pin *pin)
{
	u64 ret = 0;

	spin_lock(&j->lock);
	if (journal_pin_active(pin))
		ret = journal_pin_seq(j, pin->pin_list);
	spin_unlock(&j->lock);

	return ret;
}

static inline void bch2_journal_add_entry_noreservation(struct journal_buf *buf,
				 unsigned type, enum btree_id id,
				 unsigned level,
				 const void *data, size_t u64s)
{
	struct jset *jset = buf->data;

	bch2_journal_add_entry_at(buf, le32_to_cpu(jset->u64s),
				  type, id, level, data, u64s);
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

	if (!entry->u64s)
		return ERR_PTR(-EINVAL);

	k = entry->start;
	*level = entry->level;
	*level = entry->level;
	return k;
}

static void bch2_journal_add_btree_root(struct journal_buf *buf,
				       enum btree_id id, struct bkey_i *k,
				       unsigned level)
{
	bch2_journal_add_entry_noreservation(buf,
			      JOURNAL_ENTRY_BTREE_ROOT, id, level,
			      k, k->k.u64s);
}

static void journal_seq_blacklist_flush(struct journal *j,
				struct journal_entry_pin *pin, u64 seq)
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

		__bch2_btree_iter_init(&iter, c, n.btree_id, n.pos, 0, 0, 0);

		b = bch2_btree_iter_peek_node(&iter);

		/* The node might have already been rewritten: */

		if (b->data->keys.seq == n.seq) {
			ret = bch2_btree_node_rewrite(c, &iter, n.seq, 0);
			if (ret) {
				bch2_btree_iter_unlock(&iter);
				bch2_fs_fatal_error(c,
					"error %i rewriting btree node with blacklisted journal seq",
					ret);
				bch2_journal_halt(j);
				return;
			}
		}

		bch2_btree_iter_unlock(&iter);
	}

	for (i = 0;; i++) {
		struct btree_update *as;
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

	/*
	 * When we start the journal, bch2_journal_start() will skip over @seq:
	 */

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

	spin_lock(&j->lock);
	journal_seq = journal_cur_seq(j);
	spin_unlock(&j->lock);

	/* Interier updates aren't journalled: */
	BUG_ON(b->level);
	BUG_ON(seq > journal_seq && test_bit(BCH_FS_INITIAL_GC_DONE, &c->flags));

	/*
	 * Decrease this back to j->seq + 2 when we next rev the on disk format:
	 * increasing it temporarily to work around bug in old kernels
	 */
	bch2_fs_inconsistent_on(seq > journal_seq + 4, c,
			 "bset journal seq too far in the future: %llu > %llu",
			 seq, journal_seq);

	if (seq <= journal_seq &&
	    list_empty_careful(&j->seq_blacklist))
		return 0;

	mutex_lock(&j->blacklist_lock);

	if (seq <= journal_seq) {
		bl = journal_seq_blacklist_find(j, seq);
		if (!bl)
			goto out;
	} else {
		bch_verbose(c, "btree node %u:%llu:%llu has future journal sequence number %llu, blacklisting",
			    b->btree_id, b->key.k.p.inode, b->key.k.p.offset, seq);

		for (i = journal_seq + 1; i <= seq; i++) {
			bl = journal_seq_blacklist_find(j, i) ?:
				bch2_journal_seq_blacklisted_new(j, i);
			if (!bl) {
				ret = -ENOMEM;
				goto out;
			}
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
static int journal_entry_add(struct bch_fs *c, struct bch_dev *ca,
			     struct journal_list *jlist, struct jset *j)
{
	struct journal_replay *i, *pos;
	struct list_head *where;
	size_t bytes = vstruct_bytes(j);
	__le64 last_seq;
	int ret;

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
		kvpfree(i, offsetof(struct journal_replay, j) +
			vstruct_bytes(&i->j));
	}

	list_for_each_entry_reverse(i, jlist->head, list) {
		/* Duplicate? */
		if (le64_to_cpu(j->seq) == le64_to_cpu(i->j.seq)) {
			fsck_err_on(bytes != vstruct_bytes(&i->j) ||
				    memcmp(j, &i->j, bytes), c,
				    "found duplicate but non identical journal entries (seq %llu)",
				    le64_to_cpu(j->seq));
			goto found;
		}

		if (le64_to_cpu(j->seq) > le64_to_cpu(i->j.seq)) {
			where = &i->list;
			goto add;
		}
	}

	where = jlist->head;
add:
	i = kvpmalloc(offsetof(struct journal_replay, j) + bytes, GFP_KERNEL);
	if (!i) {
		ret = -ENOMEM;
		goto out;
	}

	list_add(&i->list, where);
	i->devs.nr = 0;
	memcpy(&i->j, j, bytes);
found:
	if (!bch2_dev_list_has_dev(i->devs, ca->dev_idx))
		bch2_dev_list_add_dev(&i->devs, ca->dev_idx);
	else
		fsck_err_on(1, c, "duplicate journal entries on same device");
	ret = JOURNAL_ENTRY_ADD_OK;
out:
fsck_err:
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

/* this fills in a range with empty jset_entries: */
static void journal_entry_null_range(void *start, void *end)
{
	struct jset_entry *entry;

	for (entry = start; entry != end; entry = vstruct_next(entry))
		memset(entry, 0, sizeof(*entry));
}

static int journal_validate_key(struct bch_fs *c, struct jset *jset,
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

	if (JSET_BIG_ENDIAN(jset) != CPU_BIG_ENDIAN)
		bch2_bkey_swab(key_type, NULL, bkey_to_packed(k));

	invalid = bch2_bkey_invalid(c, key_type, bkey_i_to_s_c(k));
	if (invalid) {
		bch2_bkey_val_to_text(c, key_type, buf, sizeof(buf),
				     bkey_i_to_s_c(k));
		mustfix_fsck_err(c, "invalid %s in journal: %s\n%s",
				 type, invalid, buf);

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

#define journal_entry_err(c, msg, ...)					\
({									\
	if (write == READ) {						\
		mustfix_fsck_err(c, msg, ##__VA_ARGS__);		\
	} else {							\
		bch_err(c, "detected corrupt metadata before write:\n"	\
	                msg, ##__VA_ARGS__);				\
		ret = BCH_FSCK_ERRORS_NOT_FIXED;			\
		goto fsck_err;						\
	}								\
	true;								\
})

#define journal_entry_err_on(cond, c, msg, ...)				\
	((cond) ? journal_entry_err(c, msg, ##__VA_ARGS__) : false)

static int journal_entry_validate_entries(struct bch_fs *c, struct jset *jset,
					  int write)
{
	struct jset_entry *entry;
	int ret = 0;

	vstruct_for_each(jset, entry) {
		void *next = vstruct_next(entry);
		struct bkey_i *k;

		if (journal_entry_err_on(vstruct_next(entry) >
					 vstruct_last(jset), c,
				"journal entry extends past end of jset")) {
			jset->u64s = cpu_to_le32((u64 *) entry - jset->_data);
			break;
		}

		switch (entry->type) {
		case JOURNAL_ENTRY_BTREE_KEYS:
			vstruct_for_each(entry, k) {
				ret = journal_validate_key(c, jset, entry, k,
						bkey_type(entry->level,
							  entry->btree_id),
						"key");
				if (ret)
					goto fsck_err;
			}
			break;

		case JOURNAL_ENTRY_BTREE_ROOT:
			k = entry->start;

			if (journal_entry_err_on(!entry->u64s ||
					le16_to_cpu(entry->u64s) != k->k.u64s, c,
					"invalid btree root journal entry: wrong number of keys")) {
				/*
				 * we don't want to null out this jset_entry,
				 * just the contents, so that later we can tell
				 * we were _supposed_ to have a btree root
				 */
				entry->u64s = 0;
				journal_entry_null_range(vstruct_next(entry), next);
				continue;
			}

			ret = journal_validate_key(c, jset, entry, k,
						   BKEY_TYPE_BTREE, "btree root");
			if (ret)
				goto fsck_err;
			break;

		case JOURNAL_ENTRY_PRIO_PTRS:
			break;

		case JOURNAL_ENTRY_JOURNAL_SEQ_BLACKLISTED:
			if (journal_entry_err_on(le16_to_cpu(entry->u64s) != 1, c,
				"invalid journal seq blacklist entry: bad size")) {
				journal_entry_null_range(entry,
						vstruct_next(entry));
			}

			break;
		default:
			journal_entry_err(c, "invalid journal entry type %u",
					  entry->type);
			journal_entry_null_range(entry, vstruct_next(entry));
			break;
		}
	}

fsck_err:
	return ret;
}

static int journal_entry_validate(struct bch_fs *c,
				  struct jset *jset, u64 sector,
				  unsigned bucket_sectors_left,
				  unsigned sectors_read,
				  int write)
{
	size_t bytes = vstruct_bytes(jset);
	struct bch_csum csum;
	int ret = 0;

	if (le64_to_cpu(jset->magic) != jset_magic(c))
		return JOURNAL_ENTRY_NONE;

	if (le32_to_cpu(jset->version) != BCACHE_JSET_VERSION) {
		bch_err(c, "unknown journal entry version %u",
			le32_to_cpu(jset->version));
		return BCH_FSCK_UNKNOWN_VERSION;
	}

	if (journal_entry_err_on(bytes > bucket_sectors_left << 9, c,
			"journal entry too big (%zu bytes), sector %lluu",
			bytes, sector)) {
		/* XXX: note we might have missing journal entries */
		return JOURNAL_ENTRY_BAD;
	}

	if (bytes > sectors_read << 9)
		return JOURNAL_ENTRY_REREAD;

	if (fsck_err_on(!bch2_checksum_type_valid(c, JSET_CSUM_TYPE(jset)), c,
			"journal entry with unknown csum type %llu sector %lluu",
			JSET_CSUM_TYPE(jset), sector))
		return JOURNAL_ENTRY_BAD;

	csum = csum_vstruct(c, JSET_CSUM_TYPE(jset), journal_nonce(jset), jset);
	if (journal_entry_err_on(bch2_crc_cmp(csum, jset->csum), c,
			"journal checksum bad, sector %llu", sector)) {
		/* XXX: retry IO, when we start retrying checksum errors */
		/* XXX: note we might have missing journal entries */
		return JOURNAL_ENTRY_BAD;
	}

	bch2_encrypt(c, JSET_CSUM_TYPE(jset), journal_nonce(jset),
		    jset->encrypted_start,
		    vstruct_end(jset) - (void *) jset->encrypted_start);

	if (journal_entry_err_on(le64_to_cpu(jset->last_seq) > le64_to_cpu(jset->seq), c,
			"invalid journal entry: last_seq > seq"))
		jset->last_seq = jset->seq;

	return 0;
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

	/* the bios are sized for this many pages, max: */
	if (new_size > JOURNAL_ENTRY_SIZE_MAX)
		return -ENOMEM;

	new_size = roundup_pow_of_two(new_size);
	n = kvpmalloc(new_size, GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	kvpfree(b->data, b->size);
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
			bio_set_dev(bio, ca->disk_sb.bdev);
			bio->bi_iter.bi_sector	= offset;
			bio->bi_iter.bi_size	= sectors_read << 9;
			bio_set_op_attrs(bio, REQ_OP_READ, 0);
			bch2_bio_map(bio, buf->data);

			ret = submit_bio_wait(bio);

			if (bch2_dev_io_err_on(ret, ca,
					       "journal read from sector %llu",
					       offset) ||
			    bch2_meta_read_fault("journal"))
				return -EIO;

			j = buf->data;
		}

		ret = journal_entry_validate(c, j, offset,
					end - offset, sectors_read,
					READ);
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
			sectors = c->opts.block_size;
			goto next_block;
		case JOURNAL_ENTRY_BAD:
			saw_bad = true;
			sectors = c->opts.block_size;
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

		mutex_lock(&jlist->lock);
		ret = journal_entry_add(c, ca, jlist, j);
		mutex_unlock(&jlist->lock);

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
	kvpfree(buf.data, buf.size);
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
		kvpfree(i, offsetof(struct journal_replay, j) +
			vstruct_bytes(&i->j));
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
		struct jset_entry_blacklist *bl_entry =
			container_of(entry, struct jset_entry_blacklist, entry);
		seq = le64_to_cpu(bl_entry->seq);

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
	struct journal *j = &c->journal;
	struct journal_list jlist;
	struct journal_replay *i;
	struct journal_entry_pin_list *p;
	struct bch_dev *ca;
	u64 cur_seq, end_seq, seq;
	unsigned iter, keys = 0, entries = 0;
	size_t nr;
	bool degraded = false;
	int ret = 0;

	closure_init_stack(&jlist.cl);
	mutex_init(&jlist.lock);
	jlist.head = list;
	jlist.ret = 0;

	for_each_member_device(ca, c, iter) {
		if (!(bch2_dev_has_data(c, ca) & (1 << BCH_DATA_JOURNAL)))
			continue;

		if ((ca->mi.state == BCH_MEMBER_STATE_RW ||
		     ca->mi.state == BCH_MEMBER_STATE_RO) &&
		    percpu_ref_tryget(&ca->io_ref))
			closure_call(&ca->journal.read,
				     bch2_journal_read_device,
				     system_unbound_wq,
				     &jlist.cl);
		else
			degraded = true;
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

	list_for_each_entry(i, list, list) {
		ret = journal_entry_validate_entries(c, &i->j, READ);
		if (ret)
			goto fsck_err;

		/*
		 * If we're mounting in degraded mode - if we didn't read all
		 * the devices - this is wrong:
		 */

		if (!degraded &&
		    (test_bit(BCH_FS_REBUILD_REPLICAS, &c->flags) ||
		     fsck_err_on(!bch2_replicas_marked(c, BCH_DATA_JOURNAL,
						       i->devs), c,
				 "superblock not marked as containing replicas (type %u)",
				 BCH_DATA_JOURNAL))) {
			ret = bch2_mark_replicas(c, BCH_DATA_JOURNAL, i->devs);
			if (ret)
				return ret;
		}
	}

	i = list_last_entry(list, struct journal_replay, list);

	nr = le64_to_cpu(i->j.seq) - le64_to_cpu(i->j.last_seq) + 1;

	if (nr > j->pin.size) {
		free_fifo(&j->pin);
		init_fifo(&j->pin, roundup_pow_of_two(nr), GFP_KERNEL);
		if (!j->pin.data) {
			bch_err(c, "error reallocating journal fifo (%zu open entries)", nr);
			return -ENOMEM;
		}
	}

	atomic64_set(&j->seq, le64_to_cpu(i->j.seq));
	j->last_seq_ondisk = le64_to_cpu(i->j.last_seq);

	j->pin.front	= le64_to_cpu(i->j.last_seq);
	j->pin.back	= le64_to_cpu(i->j.seq) + 1;

	fifo_for_each_entry_ptr(p, &j->pin, seq) {
		INIT_LIST_HEAD(&p->list);
		INIT_LIST_HEAD(&p->flushed);
		atomic_set(&p->count, 0);
		p->devs.nr = 0;
	}

	mutex_lock(&j->blacklist_lock);

	list_for_each_entry(i, list, list) {
		p = journal_seq_pin(j, le64_to_cpu(i->j.seq));

		atomic_set(&p->count, 1);
		p->devs = i->devs;

		if (journal_seq_blacklist_read(j, i, p)) {
			mutex_unlock(&j->blacklist_lock);
			return -ENOMEM;
		}
	}

	mutex_unlock(&j->blacklist_lock);

	cur_seq = journal_last_seq(j);
	end_seq = le64_to_cpu(list_last_entry(list,
				struct journal_replay, list)->j.seq);

	list_for_each_entry(i, list, list) {
		struct jset_entry *entry;
		struct bkey_i *k, *_n;
		bool blacklisted;

		mutex_lock(&j->blacklist_lock);
		while (cur_seq < le64_to_cpu(i->j.seq) &&
		       journal_seq_blacklist_find(j, cur_seq))
			cur_seq++;

		blacklisted = journal_seq_blacklist_find(j,
							 le64_to_cpu(i->j.seq));
		mutex_unlock(&j->blacklist_lock);

		fsck_err_on(blacklisted, c,
			    "found blacklisted journal entry %llu",
			    le64_to_cpu(i->j.seq));

		fsck_err_on(le64_to_cpu(i->j.seq) != cur_seq, c,
			"journal entries %llu-%llu missing! (replaying %llu-%llu)",
			cur_seq, le64_to_cpu(i->j.seq) - 1,
			journal_last_seq(j), end_seq);

		cur_seq = le64_to_cpu(i->j.seq) + 1;

		for_each_jset_key(k, _n, entry, &i->j)
			keys++;
		entries++;
	}

	bch_info(c, "journal read done, %i keys in %i entries, seq %llu",
		 keys, entries, journal_cur_seq(j));
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
	struct journal_buf *w = journal_prev_buf(j);

	atomic_dec_bug(&journal_seq_pin(j, le64_to_cpu(w->data->seq))->count);

	if (!need_write_just_set &&
	    test_bit(JOURNAL_NEED_WRITE, &j->flags))
		__bch2_time_stats_update(j->delay_time,
					j->need_write_time);
#if 0
	closure_call(&j->io, journal_write, NULL, NULL);
#else
	/* Shut sparse up: */
	closure_init(&j->io, NULL);
	set_closure_fn(&j->io, journal_write, NULL);
	journal_write(&j->io);
#endif
}

static void journal_pin_new_entry(struct journal *j, int count)
{
	struct journal_entry_pin_list *p;

	/*
	 * The fifo_push() needs to happen at the same time as j->seq is
	 * incremented for journal_last_seq() to be calculated correctly
	 */
	atomic64_inc(&j->seq);
	p = fifo_push_ref(&j->pin);

	INIT_LIST_HEAD(&p->list);
	INIT_LIST_HEAD(&p->flushed);
	atomic_set(&p->count, count);
	p->devs.nr = 0;
}

static void bch2_journal_buf_init(struct journal *j)
{
	struct journal_buf *buf = journal_cur_buf(j);

	memset(buf->has_inode, 0, sizeof(buf->has_inode));

	memset(buf->data, 0, sizeof(*buf->data));
	buf->data->seq	= cpu_to_le64(journal_cur_seq(j));
	buf->data->u64s	= 0;
}

static inline size_t journal_entry_u64s_reserve(struct journal_buf *buf)
{
	return BTREE_ID_NR * (JSET_KEYS_U64s + BKEY_EXTENT_U64s_MAX);
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

	lockdep_assert_held(&j->lock);

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

	clear_bit(JOURNAL_NEED_WRITE, &j->flags);

	buf = &j->buf[old.idx];
	buf->data->u64s		= cpu_to_le32(old.cur_entry_offset);

	j->prev_buf_sectors =
		vstruct_blocks_plus(buf->data, c->block_bits,
				    journal_entry_u64s_reserve(buf)) *
		c->opts.block_size;
	BUG_ON(j->prev_buf_sectors > j->cur_buf_sectors);

	journal_reclaim_fast(j);
	/* XXX: why set this here, and not in journal_write()? */
	buf->data->last_seq	= cpu_to_le64(journal_last_seq(j));

	journal_pin_new_entry(j, 1);

	bch2_journal_buf_init(j);

	cancel_delayed_work(&j->write_work);
	spin_unlock(&j->lock);

	if (c->bucket_journal_seq > 1 << 14) {
		c->bucket_journal_seq = 0;
		bch2_bucket_seq_cleanup(c);
	}

	c->bucket_journal_seq++;

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

	journal_wake(j);
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
	if (ja->bucket_seq[ja->last_idx] >= journal_last_seq(j))
		available = max((int) available - 1, 0);

	return available;
}

/* returns number of sectors available for next journal entry: */
static int journal_entry_sectors(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct bch_dev *ca;
	struct bkey_s_extent e = bkey_i_to_s_extent(&j->key);
	unsigned sectors_available = UINT_MAX;
	unsigned i, nr_online = 0, nr_devs = 0;

	lockdep_assert_held(&j->lock);

	rcu_read_lock();
	for_each_member_device_rcu(ca, c, i,
				   &c->rw_devs[BCH_DATA_JOURNAL]) {
		struct journal_device *ja = &ca->journal;
		unsigned buckets_required = 0;

		if (!ja->nr)
			continue;

		sectors_available = min_t(unsigned, sectors_available,
					  ca->mi.bucket_size);

		/*
		 * Note that we don't allocate the space for a journal entry
		 * until we write it out - thus, if we haven't started the write
		 * for the previous entry we have to make sure we have space for
		 * it too:
		 */
		if (bch2_extent_has_device(e.c, ca->dev_idx)) {
			if (j->prev_buf_sectors > ja->sectors_free)
				buckets_required++;

			if (j->prev_buf_sectors + sectors_available >
			    ja->sectors_free)
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
	rcu_read_unlock();

	if (nr_online < c->opts.metadata_replicas_required)
		return -EROFS;

	if (nr_devs < min_t(unsigned, nr_online, c->opts.metadata_replicas))
		return 0;

	return sectors_available;
}

/*
 * should _only_ called from journal_res_get() - when we actually want a
 * journal reservation - journal entry is open means journal is dirty:
 *
 * returns:
 * 1:		success
 * 0:		journal currently full (must wait)
 * -EROFS:	insufficient rw devices
 * -EIO:	journal error
 */
static int journal_entry_open(struct journal *j)
{
	struct journal_buf *buf = journal_cur_buf(j);
	union journal_res_state old, new;
	ssize_t u64s;
	int sectors;
	u64 v;

	lockdep_assert_held(&j->lock);
	BUG_ON(journal_entry_is_open(j));

	if (!fifo_free(&j->pin))
		return 0;

	sectors = journal_entry_sectors(j);
	if (sectors <= 0)
		return sectors;

	buf->disk_sectors	= sectors;

	sectors = min_t(unsigned, sectors, buf->size >> 9);
	j->cur_buf_sectors	= sectors;

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

	if (u64s <= le32_to_cpu(buf->data->u64s))
		return 0;

	/*
	 * Must be set before marking the journal entry as open:
	 */
	j->cur_entry_u64s = u64s;

	v = atomic64_read(&j->reservations.counter);
	do {
		old.v = new.v = v;

		if (old.cur_entry_offset == JOURNAL_ENTRY_ERROR_VAL)
			return -EIO;

		/* Handle any already added entries */
		new.cur_entry_offset = le32_to_cpu(buf->data->u64s);
	} while ((v = atomic64_cmpxchg(&j->reservations.counter,
				       old.v, new.v)) != old.v);

	if (j->res_get_blocked_start)
		__bch2_time_stats_update(j->blocked_time,
					j->res_get_blocked_start);
	j->res_get_blocked_start = 0;

	mod_delayed_work(system_freezable_wq,
			 &j->write_work,
			 msecs_to_jiffies(j->write_delay_ms));
	journal_wake(j);
	return 1;
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

	while (journal_cur_seq(j) < new_seq)
		journal_pin_new_entry(j, 0);

	/*
	 * journal_buf_switch() only inits the next journal entry when it
	 * closes an open journal entry - the very first journal entry gets
	 * initialized here:
	 */
	journal_pin_new_entry(j, 1);
	bch2_journal_buf_init(j);

	spin_unlock(&j->lock);

	/*
	 * Adding entries to the next journal entry before allocating space on
	 * disk for the next journal entry - this is ok, because these entries
	 * only have to go down with the next journal entry we write:
	 */
	list_for_each_entry(bl, &j->seq_blacklist, list)
		if (!bl->written) {
			bch2_journal_add_entry_noreservation(journal_cur_buf(j),
					JOURNAL_ENTRY_JOURNAL_SEQ_BLACKLISTED,
					0, 0, &bl->seq, 1);

			journal_pin_add_entry(j,
					      &fifo_peek_back(&j->pin),
					      &bl->pin,
					      journal_seq_blacklist_flush);
			bl->written = true;
		}

	queue_delayed_work(system_freezable_wq, &j->reclaim_work, 0);
}

int bch2_journal_replay(struct bch_fs *c, struct list_head *list)
{
	struct journal *j = &c->journal;
	struct bkey_i *k, *_n;
	struct jset_entry *entry;
	struct journal_replay *i, *n;
	int ret = 0;

	list_for_each_entry_safe(i, n, list, list) {
		j->replay_pin_list =
			journal_seq_pin(j, le64_to_cpu(i->j.seq));

		for_each_jset_key(k, _n, entry, &i->j) {

			if (entry->btree_id == BTREE_ID_ALLOC) {
				/*
				 * allocation code handles replay for
				 * BTREE_ID_ALLOC keys:
				 */
				ret = bch2_alloc_replay_key(c, k->k.p);
			} else {
				/*
				 * We might cause compressed extents to be
				 * split, so we need to pass in a
				 * disk_reservation:
				 */
				struct disk_reservation disk_res =
					bch2_disk_reservation_init(c, 0);

				ret = bch2_btree_insert(c, entry->btree_id, k,
							&disk_res, NULL, NULL,
							BTREE_INSERT_NOFAIL|
							BTREE_INSERT_JOURNAL_REPLAY);
			}

			if (ret) {
				bch_err(c, "journal replay: error %d while replaying key",
					ret);
				goto err;
			}

			cond_resched();
		}

		if (atomic_dec_and_test(&j->replay_pin_list->count))
			journal_wake(j);
	}

	j->replay_pin_list = NULL;

	bch2_journal_set_replay_done(j);
	ret = bch2_journal_flush_all_pins(j);
err:
	bch2_journal_entries_free(list);
	return ret;
}

static int __bch2_set_nr_journal_buckets(struct bch_dev *ca, unsigned nr,
					 bool new_fs, struct closure *cl)
{
	struct bch_fs *c = ca->fs;
	struct journal_device *ja = &ca->journal;
	struct bch_sb_field_journal *journal_buckets;
	u64 *new_bucket_seq = NULL, *new_buckets = NULL;
	int ret = 0;

	/* don't handle reducing nr of buckets yet: */
	if (nr <= ja->nr)
		return 0;

	ret = -ENOMEM;
	new_buckets	= kzalloc(nr * sizeof(u64), GFP_KERNEL);
	new_bucket_seq	= kzalloc(nr * sizeof(u64), GFP_KERNEL);
	if (!new_buckets || !new_bucket_seq)
		goto err;

	journal_buckets = bch2_sb_resize_journal(&ca->disk_sb,
				nr + sizeof(*journal_buckets) / sizeof(u64));
	if (!journal_buckets)
		goto err;

	if (c)
		spin_lock(&c->journal.lock);

	memcpy(new_buckets,	ja->buckets,	ja->nr * sizeof(u64));
	memcpy(new_bucket_seq,	ja->bucket_seq,	ja->nr * sizeof(u64));
	swap(new_buckets,	ja->buckets);
	swap(new_bucket_seq,	ja->bucket_seq);

	if (c)
		spin_unlock(&c->journal.lock);

	while (ja->nr < nr) {
		struct open_bucket *ob = NULL;
		long bucket;

		if (new_fs) {
			bucket = bch2_bucket_alloc_new_fs(ca);
			if (bucket < 0) {
				ret = -ENOSPC;
				goto err;
			}
		} else {
			int ob_idx = bch2_bucket_alloc(c, ca, RESERVE_ALLOC, false, cl);
			if (ob_idx < 0) {
				ret = cl ? -EAGAIN : -ENOSPC;
				goto err;
			}

			ob = c->open_buckets + ob_idx;
			bucket = sector_to_bucket(ca, ob->ptr.offset);
		}

		if (c)
			spin_lock(&c->journal.lock);

		__array_insert_item(ja->buckets,		ja->nr, ja->last_idx);
		__array_insert_item(ja->bucket_seq,		ja->nr, ja->last_idx);
		__array_insert_item(journal_buckets->buckets,	ja->nr, ja->last_idx);

		ja->buckets[ja->last_idx] = bucket;
		ja->bucket_seq[ja->last_idx] = 0;
		journal_buckets->buckets[ja->last_idx] = cpu_to_le64(bucket);

		if (ja->last_idx < ja->nr) {
			if (ja->cur_idx >= ja->last_idx)
				ja->cur_idx++;
			ja->last_idx++;
		}
		ja->nr++;

		if (c)
			spin_unlock(&c->journal.lock);

		bch2_mark_metadata_bucket(c, ca, bucket, BCH_DATA_JOURNAL,
				ca->mi.bucket_size,
				gc_phase(GC_PHASE_SB),
				new_fs
				? BCH_BUCKET_MARK_MAY_MAKE_UNAVAILABLE
				: 0);

		if (!new_fs)
			bch2_open_bucket_put(c, ob);
	}

	ret = 0;
err:
	kfree(new_bucket_seq);
	kfree(new_buckets);

	return ret;
}

/*
 * Allocate more journal space at runtime - not currently making use if it, but
 * the code works:
 */
int bch2_set_nr_journal_buckets(struct bch_fs *c, struct bch_dev *ca,
				unsigned nr)
{
	struct journal_device *ja = &ca->journal;
	struct closure cl;
	unsigned current_nr;
	int ret;

	closure_init_stack(&cl);

	do {
		struct disk_reservation disk_res = { 0, 0 };

		closure_sync(&cl);

		mutex_lock(&c->sb_lock);
		current_nr = ja->nr;

		/*
		 * note: journal buckets aren't really counted as _sectors_ used yet, so
		 * we don't need the disk reservation to avoid the BUG_ON() in buckets.c
		 * when space used goes up without a reservation - but we do need the
		 * reservation to ensure we'll actually be able to allocate:
		 */

		if (bch2_disk_reservation_get(c, &disk_res,
				bucket_to_sector(ca, nr - ja->nr), 1, 0)) {
			mutex_unlock(&c->sb_lock);
			return -ENOSPC;
		}

		ret = __bch2_set_nr_journal_buckets(ca, nr, false, &cl);

		bch2_disk_reservation_put(c, &disk_res);

		if (ja->nr != current_nr)
			bch2_write_super(c);
		mutex_unlock(&c->sb_lock);
	} while (ret == -EAGAIN);

	return ret;
}

int bch2_dev_journal_alloc(struct bch_dev *ca)
{
	unsigned nr;

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

	return __bch2_set_nr_journal_buckets(ca, nr, true, NULL);
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
		journal_wake(j);
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
	BUG_ON(!atomic_read(&pin_list->count));

	atomic_inc(&pin_list->count);
	pin->pin_list	= pin_list;
	pin->flush	= flush_fn;

	if (flush_fn)
		list_add(&pin->list, &pin_list->list);
	else
		INIT_LIST_HEAD(&pin->list);

	/*
	 * If the journal is currently full,  we might want to call flush_fn
	 * immediately:
	 */
	journal_wake(j);
}

static void journal_pin_add_entry(struct journal *j,
				  struct journal_entry_pin_list *pin_list,
				  struct journal_entry_pin *pin,
				  journal_pin_flush_fn flush_fn)
{
	spin_lock(&j->lock);
	__journal_pin_add(j, pin_list, pin, flush_fn);
	spin_unlock(&j->lock);
}

void bch2_journal_pin_add(struct journal *j,
			  struct journal_res *res,
			  struct journal_entry_pin *pin,
			  journal_pin_flush_fn flush_fn)
{
	struct journal_entry_pin_list *pin_list = res->ref
		? journal_seq_pin(j, res->seq)
		: j->replay_pin_list;

	spin_lock(&j->lock);
	__journal_pin_add(j, pin_list, pin, flush_fn);
	spin_unlock(&j->lock);
}

static inline void __journal_pin_drop(struct journal *j,
				      struct journal_entry_pin *pin)
{
	struct journal_entry_pin_list *pin_list = pin->pin_list;

	if (!journal_pin_active(pin))
		return;

	pin->pin_list = NULL;
	list_del_init(&pin->list);

	/*
	 * Unpinning a journal entry make make journal_next_bucket() succeed, if
	 * writing a new last_seq will now make another bucket available:
	 */
	if (atomic_dec_and_test(&pin_list->count) &&
	    pin_list == &fifo_peek_front(&j->pin))
		journal_reclaim_fast(j);
}

void bch2_journal_pin_drop(struct journal *j,
			  struct journal_entry_pin *pin)
{
	spin_lock(&j->lock);
	__journal_pin_drop(j, pin);
	spin_unlock(&j->lock);
}

void bch2_journal_pin_add_if_older(struct journal *j,
				  struct journal_entry_pin *src_pin,
				  struct journal_entry_pin *pin,
				  journal_pin_flush_fn flush_fn)
{
	spin_lock(&j->lock);

	if (journal_pin_active(src_pin) &&
	    (!journal_pin_active(pin) ||
	     journal_pin_seq(j, src_pin->pin_list) <
	     journal_pin_seq(j, pin->pin_list))) {
		__journal_pin_drop(j, pin);
		__journal_pin_add(j, src_pin->pin_list, pin, flush_fn);
	}

	spin_unlock(&j->lock);
}

static struct journal_entry_pin *
__journal_get_next_pin(struct journal *j, u64 seq_to_flush, u64 *seq)
{
	struct journal_entry_pin_list *pin_list;
	struct journal_entry_pin *ret;
	u64 iter;

	/* no need to iterate over empty fifo entries: */
	journal_reclaim_fast(j);

	fifo_for_each_entry_ptr(pin_list, &j->pin, iter) {
		if (iter > seq_to_flush)
			break;

		ret = list_first_entry_or_null(&pin_list->list,
				struct journal_entry_pin, list);
		if (ret) {
			/* must be list_del_init(), see bch2_journal_pin_drop() */
			list_move(&ret->list, &pin_list->flushed);
			*seq = iter;
			return ret;
		}
	}

	return NULL;
}

static struct journal_entry_pin *
journal_get_next_pin(struct journal *j, u64 seq_to_flush, u64 *seq)
{
	struct journal_entry_pin *ret;

	spin_lock(&j->lock);
	ret = __journal_get_next_pin(j, seq_to_flush, seq);
	spin_unlock(&j->lock);

	return ret;
}

static int journal_flush_done(struct journal *j, u64 seq_to_flush,
			      struct journal_entry_pin **pin,
			      u64 *pin_seq)
{
	int ret;

	*pin = NULL;

	ret = bch2_journal_error(j);
	if (ret)
		return ret;

	spin_lock(&j->lock);
	/*
	 * If journal replay hasn't completed, the unreplayed journal entries
	 * hold refs on their corresponding sequence numbers
	 */
	ret = (*pin = __journal_get_next_pin(j, seq_to_flush, pin_seq)) != NULL ||
		!test_bit(JOURNAL_REPLAY_DONE, &j->flags) ||
		journal_last_seq(j) > seq_to_flush ||
		(fifo_used(&j->pin) == 1 &&
		 atomic_read(&fifo_peek_front(&j->pin).count) == 1);
	spin_unlock(&j->lock);

	return ret;
}

int bch2_journal_flush_pins(struct journal *j, u64 seq_to_flush)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_entry_pin *pin;
	u64 pin_seq;
	bool flush;

	if (!test_bit(JOURNAL_STARTED, &j->flags))
		return 0;
again:
	wait_event(j->wait, journal_flush_done(j, seq_to_flush, &pin, &pin_seq));
	if (pin) {
		/* flushing a journal pin might cause a new one to be added: */
		pin->flush(j, pin, pin_seq);
		goto again;
	}

	spin_lock(&j->lock);
	flush = journal_last_seq(j) != j->last_seq_ondisk ||
		(seq_to_flush == U64_MAX && c->btree_roots_dirty);
	spin_unlock(&j->lock);

	return flush ? bch2_journal_meta(j) : 0;
}

int bch2_journal_flush_all_pins(struct journal *j)
{
	return bch2_journal_flush_pins(j, U64_MAX);
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
	u64 seq, seq_to_flush = 0;
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

			journal_wake(j);
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
	spin_lock(&j->lock);
	seq_to_flush = max_t(s64, seq_to_flush,
			     (s64) journal_cur_seq(j) -
			     (j->pin.size >> 1));
	spin_unlock(&j->lock);

	/*
	 * If it's been longer than j->reclaim_delay_ms since we last flushed,
	 * make sure to flush at least one journal pin:
	 */
	next_flush = j->last_flushed + msecs_to_jiffies(j->reclaim_delay_ms);
	need_flush = time_after(jiffies, next_flush);

	while ((pin = journal_get_next_pin(j, need_flush
					   ? U64_MAX
					   : seq_to_flush, &seq))) {
		__set_current_state(TASK_RUNNING);
		pin->flush(j, pin, seq);
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
static int journal_write_alloc(struct journal *j, struct journal_buf *w,
			       unsigned sectors)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct bkey_s_extent e;
	struct bch_extent_ptr *ptr;
	struct journal_device *ja;
	struct bch_dev *ca;
	struct dev_alloc_list devs_sorted;
	unsigned i, replicas, replicas_want =
		READ_ONCE(c->opts.metadata_replicas);

	spin_lock(&j->lock);
	e = bkey_i_to_s_extent(&j->key);

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
		   ca = bch_dev_bkey_exists(c, ptr->dev);

		if (ca->mi.state != BCH_MEMBER_STATE_RW ||
		    ca->journal.sectors_free <= sectors)
			__bch2_extent_drop_ptr(e, ptr);
		else
			ca->journal.sectors_free -= sectors;
	}

	replicas = bch2_extent_nr_ptrs(e.c);

	rcu_read_lock();
	devs_sorted = bch2_wp_alloc_list(c, &j->wp,
					 &c->rw_devs[BCH_DATA_JOURNAL]);

	for (i = 0; i < devs_sorted.nr; i++) {
		ca = rcu_dereference(c->devs[devs_sorted.devs[i]]);
		if (!ca)
			continue;

		if (!ca->mi.durability)
			continue;

		ja = &ca->journal;
		if (!ja->nr)
			continue;

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

		j->wp.next_alloc[ca->dev_idx] += U32_MAX;
		bch2_wp_rescale(c, ca, &j->wp);

		ja->sectors_free = ca->mi.bucket_size - sectors;
		ja->cur_idx = (ja->cur_idx + 1) % ja->nr;
		ja->bucket_seq[ja->cur_idx] = le64_to_cpu(w->data->seq);

		extent_ptr_append(bkey_i_to_extent(&j->key),
			(struct bch_extent_ptr) {
				  .offset = bucket_to_sector(ca,
					ja->buckets[ja->cur_idx]),
				  .dev = ca->dev_idx,
		});

		replicas += ca->mi.durability;
	}
	rcu_read_unlock();

	j->prev_buf_sectors = 0;

	bkey_copy(&w->key, &j->key);
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
		    i->type	== prev->type &&
		    i->type	== JOURNAL_ENTRY_BTREE_KEYS &&
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

static void journal_buf_realloc(struct journal *j, struct journal_buf *buf)
{
	/* we aren't holding j->lock: */
	unsigned new_size = READ_ONCE(j->buf_size_want);
	void *new_buf;

	if (buf->size >= new_size)
		return;

	new_buf = kvpmalloc(new_size, GFP_NOIO|__GFP_NOWARN);
	if (!new_buf)
		return;

	memcpy(new_buf, buf->data, buf->size);
	kvpfree(buf->data, buf->size);
	buf->data	= new_buf;
	buf->size	= new_size;
}

static void journal_write_done(struct closure *cl)
{
	struct journal *j = container_of(cl, struct journal, io);
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_buf *w = journal_prev_buf(j);
	struct bch_devs_list devs =
		bch2_extent_devs(bkey_i_to_s_c_extent(&w->key));

	if (!devs.nr) {
		bch_err(c, "unable to write journal to sufficient devices");
		goto err;
	}

	if (bch2_mark_replicas(c, BCH_DATA_JOURNAL, devs))
		goto err;
out:
	__bch2_time_stats_update(j->write_time, j->write_start_time);

	spin_lock(&j->lock);
	j->last_seq_ondisk = le64_to_cpu(w->data->last_seq);

	journal_seq_pin(j, le64_to_cpu(w->data->seq))->devs = devs;

	/*
	 * Updating last_seq_ondisk may let journal_reclaim_work() discard more
	 * buckets:
	 *
	 * Must come before signaling write completion, for
	 * bch2_fs_journal_stop():
	 */
	mod_delayed_work(system_freezable_wq, &j->reclaim_work, 0);

	/* also must come before signalling write completion: */
	closure_debug_destroy(cl);

	BUG_ON(!j->reservations.prev_buf_unwritten);
	atomic64_sub(((union journal_res_state) { .prev_buf_unwritten = 1 }).v,
		     &j->reservations.counter);

	closure_wake_up(&w->wait);
	journal_wake(j);

	if (test_bit(JOURNAL_NEED_WRITE, &j->flags))
		mod_delayed_work(system_freezable_wq, &j->write_work, 0);
	spin_unlock(&j->lock);
	return;
err:
	bch2_fatal_error(c);
	bch2_journal_halt(j);
	goto out;
}

static void journal_write_endio(struct bio *bio)
{
	struct bch_dev *ca = bio->bi_private;
	struct journal *j = &ca->fs->journal;

	if (bch2_dev_io_err_on(bio->bi_status, ca, "journal write") ||
	    bch2_meta_write_fault("journal")) {
		struct journal_buf *w = journal_prev_buf(j);
		unsigned long flags;

		spin_lock_irqsave(&j->err_lock, flags);
		bch2_extent_drop_device(bkey_i_to_s_extent(&w->key), ca->dev_idx);
		spin_unlock_irqrestore(&j->err_lock, flags);
	}

	closure_put(&j->io);
	percpu_ref_put(&ca->io_ref);
}

static void journal_write(struct closure *cl)
{
	struct journal *j = container_of(cl, struct journal, io);
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct bch_dev *ca;
	struct journal_buf *w = journal_prev_buf(j);
	struct jset *jset;
	struct bio *bio;
	struct bch_extent_ptr *ptr;
	unsigned i, sectors, bytes;

	journal_buf_realloc(j, w);
	jset = w->data;

	j->write_start_time = local_clock();
	mutex_lock(&c->btree_root_lock);
	for (i = 0; i < BTREE_ID_NR; i++) {
		struct btree_root *r = &c->btree_roots[i];

		if (r->alive)
			bch2_journal_add_btree_root(w, i, &r->key, r->level);
	}
	c->btree_roots_dirty = false;
	mutex_unlock(&c->btree_root_lock);

	journal_write_compact(jset);

	jset->read_clock	= cpu_to_le16(c->bucket_clock[READ].hand);
	jset->write_clock	= cpu_to_le16(c->bucket_clock[WRITE].hand);
	jset->magic		= cpu_to_le64(jset_magic(c));
	jset->version		= cpu_to_le32(BCACHE_JSET_VERSION);

	SET_JSET_BIG_ENDIAN(jset, CPU_BIG_ENDIAN);
	SET_JSET_CSUM_TYPE(jset, bch2_meta_checksum_type(c));

	if (bch2_csum_type_is_encryption(JSET_CSUM_TYPE(jset)) &&
	    journal_entry_validate_entries(c, jset, WRITE))
		goto err;

	bch2_encrypt(c, JSET_CSUM_TYPE(jset), journal_nonce(jset),
		    jset->encrypted_start,
		    vstruct_end(jset) - (void *) jset->encrypted_start);

	jset->csum = csum_vstruct(c, JSET_CSUM_TYPE(jset),
				  journal_nonce(jset), jset);

	if (!bch2_csum_type_is_encryption(JSET_CSUM_TYPE(jset)) &&
	    journal_entry_validate_entries(c, jset, WRITE))
		goto err;

	sectors = vstruct_sectors(jset, c->block_bits);
	BUG_ON(sectors > j->prev_buf_sectors);

	bytes = vstruct_bytes(w->data);
	memset((void *) w->data + bytes, 0, (sectors << 9) - bytes);

	if (journal_write_alloc(j, w, sectors)) {
		bch2_journal_halt(j);
		bch_err(c, "Unable to allocate journal write");
		bch2_fatal_error(c);
		continue_at(cl, journal_write_done, system_highpri_wq);
	}

	/*
	 * XXX: we really should just disable the entire journal in nochanges
	 * mode
	 */
	if (c->opts.nochanges)
		goto no_io;

	extent_for_each_ptr(bkey_i_to_s_extent(&w->key), ptr) {
		ca = bch_dev_bkey_exists(c, ptr->dev);
		if (!percpu_ref_tryget(&ca->io_ref)) {
			/* XXX: fix this */
			bch_err(c, "missing device for journal write\n");
			continue;
		}

		this_cpu_add(ca->io_done->sectors[WRITE][BCH_DATA_JOURNAL],
			     sectors);

		bio = ca->journal.bio;
		bio_reset(bio);
		bio_set_dev(bio, ca->disk_sb.bdev);
		bio->bi_iter.bi_sector	= ptr->offset;
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
		    !bch2_extent_has_device(bkey_i_to_s_c_extent(&w->key), i)) {
			percpu_ref_get(&ca->io_ref);

			bio = ca->journal.bio;
			bio_reset(bio);
			bio_set_dev(bio, ca->disk_sb.bdev);
			bio->bi_opf		= REQ_OP_FLUSH;
			bio->bi_end_io		= journal_write_endio;
			bio->bi_private		= ca;
			closure_bio_submit(bio, cl);
		}

no_io:
	extent_for_each_ptr(bkey_i_to_s_extent(&j->key), ptr)
		ptr->offset += sectors;

	continue_at(cl, journal_write_done, system_highpri_wq);
err:
	bch2_inconsistent_error(c);
	continue_at(cl, journal_write_done, system_highpri_wq);
}

/*
 * returns true if there's nothing to flush and no journal write still in flight
 */
static bool journal_flush_write(struct journal *j)
{
	bool ret;

	spin_lock(&j->lock);
	ret = !j->reservations.prev_buf_unwritten;

	if (!journal_entry_is_open(j)) {
		spin_unlock(&j->lock);
		return ret;
	}

	set_bit(JOURNAL_NEED_WRITE, &j->flags);
	if (journal_buf_switch(j, false) == JOURNAL_UNLOCKED)
		ret = false;
	else
		spin_unlock(&j->lock);
	return ret;
}

static void journal_write_work(struct work_struct *work)
{
	struct journal *j = container_of(work, struct journal, write_work.work);

	journal_flush_write(j);
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
		seq = journal_cur_seq(j);
	else if (test_bit(h, journal_prev_buf(j)->has_inode))
		seq = journal_cur_seq(j) - 1;
	spin_unlock(&j->lock);

	return seq;
}

static int __journal_res_get(struct journal *j, struct journal_res *res,
			      unsigned u64s_min, unsigned u64s_max)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_buf *buf;
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
	 * If we couldn't get a reservation because the current buf filled up,
	 * and we had room for a bigger entry on disk, signal that we want to
	 * realloc the journal bufs:
	 */
	buf = journal_cur_buf(j);
	if (journal_entry_is_open(j) &&
	    buf->size >> 9 < buf->disk_sectors &&
	    buf->size < JOURNAL_ENTRY_SIZE_MAX)
		j->buf_size_want = max(j->buf_size_want, buf->size << 1);

	/*
	 * Close the current journal entry if necessary, then try to start a new
	 * one:
	 */
	switch (journal_buf_switch(j, false)) {
	case JOURNAL_ENTRY_ERROR:
		spin_unlock(&j->lock);
		return -EROFS;
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

u64 bch2_journal_last_unwritten_seq(struct journal *j)
{
	u64 seq;

	spin_lock(&j->lock);
	seq = journal_cur_seq(j);
	if (j->reservations.prev_buf_unwritten)
		seq--;
	spin_unlock(&j->lock);

	return seq;
}

int bch2_journal_open_seq_async(struct journal *j, u64 seq, struct closure *parent)
{
	int ret;

	spin_lock(&j->lock);
	BUG_ON(seq > journal_cur_seq(j));

	if (seq < journal_cur_seq(j) ||
	    journal_entry_is_open(j)) {
		spin_unlock(&j->lock);
		return 1;
	}

	ret = journal_entry_open(j);
	if (!ret)
		closure_wait(&j->async_wait, parent);
	spin_unlock(&j->lock);

	if (!ret)
		journal_reclaim_work(&j->reclaim_work.work);

	return ret;
}

void bch2_journal_wait_on_seq(struct journal *j, u64 seq, struct closure *parent)
{
	spin_lock(&j->lock);

	BUG_ON(seq > journal_cur_seq(j));

	if (bch2_journal_error(j)) {
		spin_unlock(&j->lock);
		return;
	}

	if (seq == journal_cur_seq(j)) {
		if (!closure_wait(&journal_cur_buf(j)->wait, parent))
			BUG();
	} else if (seq + 1 == journal_cur_seq(j) &&
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
	struct journal_buf *buf;

	spin_lock(&j->lock);

	BUG_ON(seq > journal_cur_seq(j));

	if (bch2_journal_error(j)) {
		spin_unlock(&j->lock);
		return;
	}

	if (seq == journal_cur_seq(j)) {
		bool set_need_write = false;

		buf = journal_cur_buf(j);

		if (parent && !closure_wait(&buf->wait, parent))
			BUG();

		if (!test_and_set_bit(JOURNAL_NEED_WRITE, &j->flags)) {
			j->need_write_time = local_clock();
			set_need_write = true;
		}

		switch (journal_buf_switch(j, set_need_write)) {
		case JOURNAL_ENTRY_ERROR:
			if (parent)
				closure_wake_up(&buf->wait);
			break;
		case JOURNAL_ENTRY_CLOSED:
			/*
			 * Journal entry hasn't been opened yet, but caller
			 * claims it has something
			 */
			BUG();
		case JOURNAL_ENTRY_INUSE:
			break;
		case JOURNAL_UNLOCKED:
			return;
		}
	} else if (parent &&
		   seq + 1 == journal_cur_seq(j) &&
		   j->reservations.prev_buf_unwritten) {
		buf = journal_prev_buf(j);

		if (!closure_wait(&buf->wait, parent))
			BUG();

		smp_mb();

		/* check if raced with write completion (or failure) */
		if (!j->reservations.prev_buf_unwritten ||
		    bch2_journal_error(j))
			closure_wake_up(&buf->wait);
	}

	spin_unlock(&j->lock);
}

static int journal_seq_flushed(struct journal *j, u64 seq)
{
	struct journal_buf *buf;
	int ret = 1;

	spin_lock(&j->lock);
	BUG_ON(seq > journal_cur_seq(j));

	if (seq == journal_cur_seq(j)) {
		bool set_need_write = false;

		ret = 0;

		buf = journal_cur_buf(j);

		if (!test_and_set_bit(JOURNAL_NEED_WRITE, &j->flags)) {
			j->need_write_time = local_clock();
			set_need_write = true;
		}

		switch (journal_buf_switch(j, set_need_write)) {
		case JOURNAL_ENTRY_ERROR:
			ret = -EIO;
			break;
		case JOURNAL_ENTRY_CLOSED:
			/*
			 * Journal entry hasn't been opened yet, but caller
			 * claims it has something
			 */
			BUG();
		case JOURNAL_ENTRY_INUSE:
			break;
		case JOURNAL_UNLOCKED:
			return 0;
		}
	} else if (seq + 1 == journal_cur_seq(j) &&
		   j->reservations.prev_buf_unwritten) {
		ret = bch2_journal_error(j);
	}

	spin_unlock(&j->lock);

	return ret;
}

int bch2_journal_flush_seq(struct journal *j, u64 seq)
{
	u64 start_time = local_clock();
	int ret, ret2;

	ret = wait_event_killable(j->wait, (ret2 = journal_seq_flushed(j, seq)));

	bch2_time_stats_update(j->flush_seq_time, start_time);

	return ret ?: ret2 < 0 ? ret2 : 0;
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
	journal_seq = journal_cur_seq(j);

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
	journal_seq = journal_cur_seq(j);

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

int bch2_journal_flush_device(struct journal *j, int dev_idx)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	struct journal_entry_pin_list *p;
	struct bch_devs_list devs;
	u64 iter, seq = 0;
	int ret = 0;

	spin_lock(&j->lock);
	fifo_for_each_entry_ptr(p, &j->pin, iter)
		if (dev_idx >= 0
		    ? bch2_dev_list_has_dev(p->devs, dev_idx)
		    : p->devs.nr < c->opts.metadata_replicas)
			seq = iter;
	spin_unlock(&j->lock);

	ret = bch2_journal_flush_pins(j, seq);
	if (ret)
		return ret;

	mutex_lock(&c->replicas_gc_lock);
	bch2_replicas_gc_start(c, 1 << BCH_DATA_JOURNAL);

	seq = 0;

	spin_lock(&j->lock);
	while (!ret && seq < j->pin.back) {
		seq = max(seq, journal_last_seq(j));
		devs = journal_seq_pin(j, seq)->devs;
		seq++;

		spin_unlock(&j->lock);
		ret = bch2_mark_replicas(c, BCH_DATA_JOURNAL, devs);
		spin_lock(&j->lock);
	}
	spin_unlock(&j->lock);

	bch2_replicas_gc_end(c, ret);
	mutex_unlock(&c->replicas_gc_lock);

	return ret;
}

/* startup/shutdown: */

static bool bch2_journal_writing_to_device(struct journal *j, unsigned dev_idx)
{
	union journal_res_state state;
	struct journal_buf *w;
	bool ret;

	spin_lock(&j->lock);
	state = READ_ONCE(j->reservations);
	w = j->buf + !state.idx;

	ret = state.prev_buf_unwritten &&
		bch2_extent_has_device(bkey_i_to_s_c_extent(&w->key), dev_idx);
	spin_unlock(&j->lock);

	return ret;
}

void bch2_dev_journal_stop(struct journal *j, struct bch_dev *ca)
{
	spin_lock(&j->lock);
	bch2_extent_drop_device(bkey_i_to_s_extent(&j->key), ca->dev_idx);
	spin_unlock(&j->lock);

	wait_event(j->wait, !bch2_journal_writing_to_device(j, ca->dev_idx));
}

void bch2_fs_journal_stop(struct journal *j)
{
	wait_event(j->wait, journal_flush_write(j));

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
	unsigned i;

	ja->nr = bch2_nr_journal_buckets(journal_buckets);

	ja->bucket_seq = kcalloc(ja->nr, sizeof(u64), GFP_KERNEL);
	if (!ja->bucket_seq)
		return -ENOMEM;

	ca->journal.bio = bio_kmalloc(GFP_KERNEL,
			DIV_ROUND_UP(JOURNAL_ENTRY_SIZE_MAX, PAGE_SIZE));
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
	kvpfree(j->buf[1].data, j->buf[1].size);
	kvpfree(j->buf[0].data, j->buf[0].size);
	free_fifo(&j->pin);
}

int bch2_fs_journal_init(struct journal *j)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	static struct lock_class_key res_key;
	int ret = 0;

	pr_verbose_init(c->opts, "");

	spin_lock_init(&j->lock);
	spin_lock_init(&j->err_lock);
	init_waitqueue_head(&j->wait);
	INIT_DELAYED_WORK(&j->write_work, journal_write_work);
	INIT_DELAYED_WORK(&j->reclaim_work, journal_reclaim_work);
	mutex_init(&j->blacklist_lock);
	INIT_LIST_HEAD(&j->seq_blacklist);
	mutex_init(&j->reclaim_lock);

	lockdep_init_map(&j->res_map, "journal res", &res_key, 0);

	j->buf[0].size		= JOURNAL_ENTRY_SIZE_MIN;
	j->buf[1].size		= JOURNAL_ENTRY_SIZE_MIN;
	j->write_delay_ms	= 1000;
	j->reclaim_delay_ms	= 100;

	bkey_extent_init(&j->key);

	atomic64_set(&j->reservations.counter,
		((union journal_res_state)
		 { .cur_entry_offset = JOURNAL_ENTRY_CLOSED_VAL }).v);

	if (!(init_fifo(&j->pin, JOURNAL_PIN, GFP_KERNEL)) ||
	    !(j->buf[0].data = kvpmalloc(j->buf[0].size, GFP_KERNEL)) ||
	    !(j->buf[1].data = kvpmalloc(j->buf[1].size, GFP_KERNEL))) {
		ret = -ENOMEM;
		goto out;
	}

	j->pin.front = j->pin.back = 1;
out:
	pr_verbose_init(c->opts, "ret %i", ret);
	return ret;
}

/* debug: */

ssize_t bch2_journal_print_debug(struct journal *j, char *buf)
{
	struct bch_fs *c = container_of(j, struct bch_fs, journal);
	union journal_res_state *s = &j->reservations;
	struct bch_dev *ca;
	unsigned iter;
	ssize_t ret = 0;

	rcu_read_lock();
	spin_lock(&j->lock);

	ret += scnprintf(buf + ret, PAGE_SIZE - ret,
			 "active journal entries:\t%llu\n"
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
			 journal_cur_seq(j),
			 journal_last_seq(j),
			 j->last_seq_ondisk,
			 journal_state_count(*s, s->idx),
			 s->cur_entry_offset,
			 j->cur_entry_u64s,
			 s->prev_buf_unwritten,
			 test_bit(JOURNAL_NEED_WRITE,	&j->flags),
			 journal_entry_is_open(j),
			 test_bit(JOURNAL_REPLAY_DONE,	&j->flags));

	for_each_member_device_rcu(ca, c, iter,
				   &c->rw_devs[BCH_DATA_JOURNAL]) {
		struct journal_device *ja = &ca->journal;

		if (!ja->nr)
			continue;

		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "dev %u:\n"
				 "\tnr\t\t%u\n"
				 "\tcur_idx\t\t%u (seq %llu)\n"
				 "\tlast_idx\t%u (seq %llu)\n",
				 iter, ja->nr,
				 ja->cur_idx,	ja->bucket_seq[ja->cur_idx],
				 ja->last_idx,	ja->bucket_seq[ja->last_idx]);
	}

	spin_unlock(&j->lock);
	rcu_read_unlock();

	return ret;
}

ssize_t bch2_journal_print_pins(struct journal *j, char *buf)
{
	struct journal_entry_pin_list *pin_list;
	struct journal_entry_pin *pin;
	ssize_t ret = 0;
	u64 i;

	spin_lock(&j->lock);
	fifo_for_each_entry_ptr(pin_list, &j->pin, i) {
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "%llu: count %u\n",
				 i, atomic_read(&pin_list->count));

		list_for_each_entry(pin, &pin_list->list, list)
			ret += scnprintf(buf + ret, PAGE_SIZE - ret,
					 "\t%p %pf\n",
					 pin, pin->flush);

		if (!list_empty(&pin_list->flushed))
			ret += scnprintf(buf + ret, PAGE_SIZE - ret,
					 "flushed:\n");

		list_for_each_entry(pin, &pin_list->flushed, list)
			ret += scnprintf(buf + ret, PAGE_SIZE - ret,
					 "\t%p %pf\n",
					 pin, pin->flush);
	}
	spin_unlock(&j->lock);

	return ret;
}
