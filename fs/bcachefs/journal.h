#ifndef _BCACHE_JOURNAL_H
#define _BCACHE_JOURNAL_H

/*
 * THE JOURNAL:
 *
 * The journal is treated as a circular buffer of buckets - a journal entry
 * never spans two buckets. This means (not implemented yet) we can resize the
 * journal at runtime, and will be needed for bcache on raw flash support.
 *
 * Journal entries contain a list of keys, ordered by the time they were
 * inserted; thus journal replay just has to reinsert the keys.
 *
 * We also keep some things in the journal header that are logically part of the
 * superblock - all the things that are frequently updated. This is for future
 * bcache on raw flash support; the superblock (which will become another
 * journal) can't be moved or wear leveled, so it contains just enough
 * information to find the main journal, and the superblock only has to be
 * rewritten when we want to move/wear level the main journal.
 *
 * Currently, we don't journal BTREE_REPLACE operations - this will hopefully be
 * fixed eventually. This isn't a bug - BTREE_REPLACE is used for insertions
 * from cache misses, which don't have to be journaled, and for writeback and
 * moving gc we work around it by flushing the btree to disk before updating the
 * gc information. But it is a potential issue with incremental garbage
 * collection, and it's fragile.
 *
 * OPEN JOURNAL ENTRIES:
 *
 * Each journal entry contains, in the header, the sequence number of the last
 * journal entry still open - i.e. that has keys that haven't been flushed to
 * disk in the btree.
 *
 * We track this by maintaining a refcount for every open journal entry, in a
 * fifo; each entry in the fifo corresponds to a particular journal
 * entry/sequence number. When the refcount at the tail of the fifo goes to
 * zero, we pop it off - thus, the size of the fifo tells us the number of open
 * journal entries
 *
 * We take a refcount on a journal entry when we add some keys to a journal
 * entry that we're going to insert (held by struct btree_op), and then when we
 * insert those keys into the btree the btree write we're setting up takes a
 * copy of that refcount (held by struct btree_write). That refcount is dropped
 * when the btree write completes.
 *
 * A struct btree_write can only hold a refcount on a single journal entry, but
 * might contain keys for many journal entries - we handle this by making sure
 * it always has a refcount on the _oldest_ journal entry of all the journal
 * entries it has keys for.
 *
 * JOURNAL RECLAIM:
 *
 * As mentioned previously, our fifo of refcounts tells us the number of open
 * journal entries; from that and the current journal sequence number we compute
 * last_seq - the oldest journal entry we still need. We write last_seq in each
 * journal entry, and we also have to keep track of where it exists on disk so
 * we don't overwrite it when we loop around the journal.
 *
 * To do that we track, for each journal bucket, the sequence number of the
 * newest journal entry it contains - if we don't need that journal entry we
 * don't need anything in that bucket anymore. From that we track the last
 * journal bucket we still need; all this is tracked in struct journal_device
 * and updated by journal_reclaim().
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

static inline struct jset_keys *jset_keys_next(struct jset_keys *j)
{
	return (void *) (&j->d[j->keys]);

}

/*
 * Only used for holding the journal entries we read in btree_journal_read()
 * during cache_registration
 */
struct journal_replay {
	struct list_head	list;
	struct jset		j;
};

#define journal_pin_cmp(c, l, r)				\
	(fifo_idx(&(c)->journal.pin, (l)) > fifo_idx(&(c)->journal.pin, (r)))

#define JOURNAL_PIN	20000

#define journal_full(j)						\
	(!(j)->blocks_free || fifo_free(&(j)->pin) <= 1)

#define for_each_jset_jkeys(jkeys, jset)			\
	for (jkeys = (jset)->start;				\
	     jkeys < (struct jset_keys *) bset_bkey_last(jset);	\
	     jkeys = jset_keys_next(jkeys))

struct closure;
struct cache_set;
struct btree_op;
struct keylist;

struct bkey *bch_journal_find_btree_root(struct cache_set *, struct jset *,
					 enum btree_id, unsigned *);

void btree_flush_write(struct cache_set *);
struct journal_write *bch_journal_write_get(struct cache_set *, unsigned)
	__acquires(c->journal.lock);
void bch_journal_write_put(struct cache_set *, struct journal_write *,
			   struct closure *)
	__releases(c->journal.lock);

static inline size_t journal_write_u64s_remaining(struct cache_set *c,
						  struct journal_write *w)
{
	ssize_t u64s = (min_t(size_t,
			     c->journal.blocks_free * block_bytes(c),
			     PAGE_SIZE << JSET_BITS) -
			set_bytes(w->data)) / sizeof(u64);

	/* Subtract off some for the btree roots */
	u64s -= BTREE_ID_NR * (JSET_KEYS_U64s + BKEY_U64s + BKEY_PAD_PTRS);

	/* And for the prio pointers */
	u64s -= JSET_KEYS_U64s + c->sb.nr_in_set;

	return max_t(ssize_t, 0L, u64s);
}

static inline void __bch_journal_add_keys(struct jset *j, enum btree_id id,
					  struct bkey *k, unsigned nkeys,
					  unsigned level, unsigned type)
{
	struct jset_keys *jkeys = (struct jset_keys *) bset_bkey_last(j);

	jkeys->keys = nkeys;
	jkeys->btree_id = id;
	jkeys->level = level;
	jkeys->flags = 0;
	SET_JKEYS_TYPE(jkeys, type);

	memcpy(jkeys->start, k, sizeof(u64) * nkeys);
	j->keys += sizeof(struct jset_keys) / sizeof(u64) + nkeys;
}

static inline void bch_journal_add_keys(struct jset *j, enum btree_id id,
					struct bkey *k, unsigned nkeys,
					unsigned level)
{
	return __bch_journal_add_keys(j, id, k, nkeys, level,
				      JKEYS_BTREE_KEYS);
}

void bch_journal_next(struct journal *);
void bch_journal_mark(struct cache_set *, struct list_head *);
void bch_journal_meta(struct cache_set *, struct closure *);
int bch_journal_read(struct cache_set *, struct list_head *);
int bch_journal_replay(struct cache_set *, struct list_head *);

void bch_journal_free(struct cache_set *);
int bch_journal_alloc(struct cache_set *);

#endif /* _BCACHE_JOURNAL_H */
