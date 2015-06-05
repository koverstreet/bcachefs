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
	return (void *) __bset_bkey_last(j);
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

static inline void journal_pin_add(struct journal *j,
				   struct journal_entry_pin_list *pin_list,
				   struct journal_entry_pin *pin,
				   journal_pin_flush_fn flush_fn)
{
	spin_lock_irq(&j->pin_lock);

	atomic_inc(&pin_list->count);
	pin->pin_list	= pin_list;
	pin->flush	= flush_fn;

	if (flush_fn)
		list_add(&pin->list, &pin_list->list);
	else
		INIT_LIST_HEAD(&pin->list);

	spin_unlock_irq(&j->pin_lock);
}

static inline void journal_pin_drop(struct journal *j,
				    struct journal_entry_pin *pin)
{
	unsigned long flags;

	/* journal_reclaim_work() might have already taken us off the list */
	if (!list_empty_careful(&pin->list)) {
		spin_lock_irqsave(&j->pin_lock, flags);
		list_del_init(&pin->list);
		spin_unlock_irqrestore(&j->pin_lock, flags);
	}

	if (atomic_dec_and_test(&pin->pin_list->count)) {
		/*
		 * Unpinning a journal entry make make journal_next_bucket()
		 * succeed, if writing a new last_seq will now make another
		 * bucket available:
		 */
		wake_up(&j->wait);
	}

	pin->pin_list = NULL;
}

#define journal_full(j)						\
	(!(j)->sectors_free || fifo_free(&(j)->pin) <= 1)

struct closure;
struct cache_set;
struct keylist;

struct bkey_i *bch_journal_find_btree_root(struct cache_set *, struct jset *,
					   enum btree_id, unsigned *);

int bch_journal_seq_blacklisted(struct cache_set *, u64, struct btree *);

static inline struct journal_write *journal_cur_write(struct journal *j)
{

	return j->w + test_bit(JOURNAL_WRITE_IDX, &j->flags);
}

static inline struct journal_write *journal_prev_write(struct journal *j)
{

	return j->w + !test_bit(JOURNAL_WRITE_IDX, &j->flags);
}

void bch_journal_add_keys(struct journal *, struct journal_res *,
			  enum btree_id, const struct bkey_i *,
			  unsigned);

void bch_journal_res_put(struct journal *, struct journal_res *);
void bch_journal_res_get(struct journal *, struct journal_res *,
			 unsigned, unsigned);

void bch_journal_flush_seq_async(struct journal *, u64, struct closure *);
void bch_journal_flush_async(struct journal *, struct closure *);
void bch_journal_meta_async(struct journal *, struct closure *);

int bch_journal_flush_seq(struct journal *, u64);
int bch_journal_flush(struct journal *);
int bch_journal_meta(struct journal *);

static inline int bch_journal_error(struct journal *j)
{
	return test_bit(JOURNAL_ERROR, &j->flags) ? -EIO : 0;
}

/*
 * Amount of space that will be taken up by some keys in the journal (i.e.
 * including the jset header)
 */
static inline unsigned jset_u64s(unsigned u64s)
{
	return u64s + sizeof(struct jset_entry) / sizeof(u64);
}

static inline bool journal_res_full(struct journal_res *res,
				    struct bkey *k)
{
	return res->offset && jset_u64s(k->u64s) * 2 > res->u64s;
}

void bch_journal_start(struct cache_set *);
void bch_journal_mark(struct cache_set *, struct list_head *);
const char *bch_journal_read(struct cache_set *, struct list_head *);
int bch_journal_replay(struct cache_set *, struct list_head *);

static inline void bch_journal_set_replay_done(struct journal *j)
{
	spin_lock(&j->lock);
	set_bit(JOURNAL_REPLAY_DONE, &j->flags);
	j->cur_pin_list = &fifo_back(&j->pin);
	spin_unlock(&j->lock);
}

void bch_journal_free(struct journal *);
int bch_journal_alloc(struct journal *);

ssize_t bch_journal_print_debug(struct journal *, char *);

int bch_cache_journal_alloc(struct cache *);

static inline u64 *__journal_buckets(struct cache *ca)
{
	return ca->disk_sb.sb->_data + bch_journal_buckets_offset(&ca->sb);
}

static inline u64 journal_bucket(struct cache *ca, unsigned nr)
{
	return le64_to_cpu(__journal_buckets(ca)[nr]);
}

static inline void set_journal_bucket(struct cache *ca, unsigned nr, u64 bucket)
{
	__journal_buckets(ca)[nr] = cpu_to_le64(bucket);
}

int bch_journal_move(struct cache *);

#endif /* _BCACHE_JOURNAL_H */
