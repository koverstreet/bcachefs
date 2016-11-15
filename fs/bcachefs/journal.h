#ifndef _BCACHE_JOURNAL_H
#define _BCACHE_JOURNAL_H

/*
 * THE JOURNAL:
 *
 * The primary purpose of the journal is to log updates (insertions) to the
 * b-tree, to avoid having to do synchronous updates to the b-tree on disk.
 *
 * Without the journal, the b-tree is always internally consistent on
 * disk - and in fact, in the earliest incarnations bcache didn't have a journal
 * but did handle unclean shutdowns by doing all index updates synchronously
 * (with coalescing).
 *
 * Updates to interior nodes still happen synchronously and without the journal
 * (for simplicity) - this may change eventually but updates to interior nodes
 * are rare enough it's not a huge priority.
 *
 * This means the journal is relatively separate from the b-tree; it consists of
 * just a list of keys and journal replay consists of just redoing those
 * insertions in same order that they appear in the journal.
 *
 * PERSISTENCE:
 *
 * For synchronous updates (where we're waiting on the index update to hit
 * disk), the journal entry will be written out immediately (or as soon as
 * possible, if the write for the previous journal entry was still in flight).
 *
 * Synchronous updates are specified by passing a closure (@flush_cl) to
 * bch_btree_insert() or bch_btree_insert_node(), which then pass that parameter
 * down to the journalling code. That closure will will wait on the journal
 * write to complete (via closure_wait()).
 *
 * If the index update wasn't synchronous, the journal entry will be
 * written out after 10 ms have elapsed, by default (the delay_ms field
 * in struct journal).
 *
 * JOURNAL ENTRIES:
 *
 * A journal entry is variable size (struct jset), it's got a fixed length
 * header and then a variable number of struct jset_entry entries.
 *
 * Journal entries are identified by monotonically increasing 64 bit sequence
 * numbers - jset->seq; other places in the code refer to this sequence number.
 *
 * A jset_entry entry contains one or more bkeys (which is what gets inserted
 * into the b-tree). We need a container to indicate which b-tree the key is
 * for; also, the roots of the various b-trees are stored in jset_entry entries
 * (one for each b-tree) - this lets us add new b-tree types without changing
 * the on disk format.
 *
 * We also keep some things in the journal header that are logically part of the
 * superblock - all the things that are frequently updated. This is for future
 * bcache on raw flash support; the superblock (which will become another
 * journal) can't be moved or wear leveled, so it contains just enough
 * information to find the main journal, and the superblock only has to be
 * rewritten when we want to move/wear level the main journal.
 *
 * JOURNAL LAYOUT ON DISK:
 *
 * The journal is written to a ringbuffer of buckets (which is kept in the
 * superblock); the individual buckets are not necessarily contiguous on disk
 * which means that journal entries are not allowed to span buckets, but also
 * that we can resize the journal at runtime if desired (unimplemented).
 *
 * The journal buckets exist in the same pool as all the other buckets that are
 * managed by the allocator and garbage collection - garbage collection marks
 * the journal buckets as metadata buckets.
 *
 * OPEN/DIRTY JOURNAL ENTRIES:
 *
 * Open/dirty journal entries are journal entries that contain b-tree updates
 * that have not yet been written out to the b-tree on disk. We have to track
 * which journal entries are dirty, and we also have to avoid wrapping around
 * the journal and overwriting old but still dirty journal entries with new
 * journal entries.
 *
 * On disk, this is represented with the "last_seq" field of struct jset;
 * last_seq is the first sequence number that journal replay has to replay.
 *
 * To avoid overwriting dirty journal entries on disk, we keep a mapping (in
 * journal_device->seq) of for each journal bucket, the highest sequence number
 * any journal entry it contains. Then, by comparing that against last_seq we
 * can determine whether that journal bucket contains dirty journal entries or
 * not.
 *
 * To track which journal entries are dirty, we maintain a fifo of refcounts
 * (where each entry corresponds to a specific sequence number) - when a ref
 * goes to 0, that journal entry is no longer dirty.
 *
 * Journalling of index updates is done at the same time as the b-tree itself is
 * being modified (see btree_insert_key()); when we add the key to the journal
 * the pending b-tree write takes a ref on the journal entry the key was added
 * to. If a pending b-tree write would need to take refs on multiple dirty
 * journal entries, it only keeps the ref on the oldest one (since a newer
 * journal entry will still be replayed if an older entry was dirty).
 *
 * JOURNAL FILLING UP:
 *
 * There are two ways the journal could fill up; either we could run out of
 * space to write to, or we could have too many open journal entries and run out
 * of room in the fifo of refcounts. Since those refcounts are decremented
 * without any locking we can't safely resize that fifo, so we handle it the
 * same way.
 *
 * If the journal fills up, we start flushing dirty btree nodes until we can
 * allocate space for a journal write again - preferentially flushing btree
 * nodes that are pinning the oldest journal entries first.
 */

#include "journal_types.h"

static inline struct jset_entry *jset_keys_next(struct jset_entry *j)
{
	return (void *) __bkey_idx(j, le16_to_cpu(j->u64s));
}

/*
 * Only used for holding the journal entries we read in btree_journal_read()
 * during cache_registration
 */
struct journal_replay {
	struct list_head	list;
	struct jset		j;
};

#define JOURNAL_PIN	((32 * 1024) - 1)

static inline bool journal_pin_active(struct journal_entry_pin *pin)
{
	return pin->pin_list != NULL;
}

void bch_journal_pin_add(struct journal *, struct journal_entry_pin *,
			 journal_pin_flush_fn);
void bch_journal_pin_drop(struct journal *, struct journal_entry_pin *);
void bch_journal_pin_add_if_older(struct journal *,
				  struct journal_entry_pin *,
				  struct journal_entry_pin *,
				  journal_pin_flush_fn);

struct closure;
struct cache_set;
struct keylist;

struct bkey_i *bch_journal_find_btree_root(struct cache_set *, struct jset *,
					   enum btree_id, unsigned *);

int bch_journal_seq_should_ignore(struct cache_set *, u64, struct btree *);

u64 bch_inode_journal_seq(struct journal *, u64);

static inline int journal_state_count(union journal_res_state s, int idx)
{
	return idx == 0 ? s.buf0_count : s.buf1_count;
}

static inline void journal_state_inc(union journal_res_state *s)
{
	s->buf0_count += s->idx == 0;
	s->buf1_count += s->idx == 1;
}

static inline u64 bch_journal_res_seq(struct journal *j,
				      struct journal_res *res)
{
	struct journal_buf *buf = &j->buf[res->idx];

	return le64_to_cpu(buf->data->seq);
}

static inline void bch_journal_set_has_inode(struct journal_buf *buf, u64 inum)
{
	set_bit(hash_64(inum, sizeof(buf->has_inode) * 8), buf->has_inode);
}

/*
 * Amount of space that will be taken up by some keys in the journal (i.e.
 * including the jset header)
 */
static inline unsigned jset_u64s(unsigned u64s)
{
	return u64s + sizeof(struct jset_entry) / sizeof(u64);
}

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

	memcpy_u64s(entry->_data, data, u64s);
}

static inline void bch_journal_add_keys(struct journal *j, struct journal_res *res,
					enum btree_id id, const struct bkey_i *k)
{
	struct journal_buf *buf = &j->buf[res->idx];
	unsigned actual = jset_u64s(k->k.u64s);

	EBUG_ON(!res->ref);
	BUG_ON(actual > res->u64s);

	bch_journal_set_has_inode(buf, k->k.p.inode);

	bch_journal_add_entry_at(buf, k, k->k.u64s,
				 JOURNAL_ENTRY_BTREE_KEYS, id,
				 0, res->offset);

	res->offset	+= actual;
	res->u64s	-= actual;
}

void bch_journal_buf_put_slowpath(struct journal *, bool);

static inline void bch_journal_buf_put(struct journal *j, unsigned idx,
				       bool need_write_just_set)
{
	union journal_res_state s;

	s.v = atomic64_sub_return(((union journal_res_state) {
				    .buf0_count = idx == 0,
				    .buf1_count = idx == 1,
				    }).v, &j->reservations.counter);

	EBUG_ON(s.idx != idx && !s.prev_buf_unwritten);

	/*
	 * Do not initiate a journal write if the journal is in an error state
	 * (previous journal entry write may have failed)
	 */
	if (s.idx != idx &&
	    !journal_state_count(s, idx) &&
	    s.cur_entry_offset != JOURNAL_ENTRY_ERROR_VAL)
		bch_journal_buf_put_slowpath(j, need_write_just_set);
}

/*
 * This function releases the journal write structure so other threads can
 * then proceed to add their keys as well.
 */
static inline void bch_journal_res_put(struct journal *j,
				       struct journal_res *res,
				       u64 *journal_seq)
{
	if (!res->ref)
		return;

	lock_release(&j->res_map, 0, _RET_IP_);

	while (res->u64s) {
		bch_journal_add_entry_at(&j->buf[res->idx], NULL, 0,
					 JOURNAL_ENTRY_BTREE_KEYS,
					 0, 0, res->offset);
		res->offset	+= jset_u64s(0);
		res->u64s	-= jset_u64s(0);
	}

	if (journal_seq)
		*journal_seq = bch_journal_res_seq(j, res);

	bch_journal_buf_put(j, res->idx, false);

	memset(res, 0, sizeof(*res));
}

int bch_journal_res_get_slowpath(struct journal *, struct journal_res *,
				 unsigned, unsigned);

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

static inline int bch_journal_res_get(struct journal *j, struct journal_res *res,
				      unsigned u64s_min, unsigned u64s_max)
{
	int ret;

	EBUG_ON(res->ref);
	EBUG_ON(u64s_max < u64s_min);

	if (journal_res_get_fast(j, res, u64s_min, u64s_max))
		goto out;

	ret = bch_journal_res_get_slowpath(j, res, u64s_min, u64s_max);
	if (ret)
		return ret;
out:
	lock_acquire_shared(&j->res_map, 0, 0, NULL, _THIS_IP_);
	EBUG_ON(!res->ref);
	return 0;
}

void bch_journal_flush_seq_async(struct journal *, u64, struct closure *);
void bch_journal_flush_async(struct journal *, struct closure *);
void bch_journal_meta_async(struct journal *, struct closure *);

int bch_journal_flush_seq(struct journal *, u64);
int bch_journal_flush(struct journal *);
int bch_journal_meta(struct journal *);

void bch_journal_halt(struct journal *);

static inline int bch_journal_error(struct journal *j)
{
	return j->reservations.cur_entry_offset == JOURNAL_ENTRY_ERROR_VAL
		? -EIO : 0;
}

static inline bool journal_flushes_device(struct cache *ca)
{
	return true;
}

void bch_journal_start(struct cache_set *);
void bch_journal_mark(struct cache_set *, struct list_head *);
const char *bch_journal_read(struct cache_set *, struct list_head *);
int bch_journal_replay(struct cache_set *, struct list_head *);

static inline void bch_journal_set_replay_done(struct journal *j)
{
	spin_lock(&j->lock);
	set_bit(JOURNAL_REPLAY_DONE, &j->flags);
	j->cur_pin_list = &fifo_peek_back(&j->pin);
	spin_unlock(&j->lock);
}

void bch_journal_free(struct journal *);
int bch_journal_alloc(struct journal *);

ssize_t bch_journal_print_debug(struct journal *, char *);

int bch_cache_journal_alloc(struct cache *);

static inline __le64 *__journal_buckets(struct cache_sb *sb)
{
	return sb->_data + bch_journal_buckets_offset(sb);
}

static inline u64 journal_bucket(struct cache_sb *sb, unsigned nr)
{
	return le64_to_cpu(__journal_buckets(sb)[nr]);
}

static inline void set_journal_bucket(struct cache_sb *sb, unsigned nr, u64 bucket)
{
	__journal_buckets(sb)[nr] = cpu_to_le64(bucket);
}

int bch_journal_move(struct cache *);

#endif /* _BCACHE_JOURNAL_H */
