/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_JOURNAL_H
#define _BCACHEFS_JOURNAL_H

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
 * bch2_btree_insert() or bch_btree_insert_node(), which then pass that parameter
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

#include <linux/hash.h>

#include "journal_types.h"

struct bch_fs;

static inline void journal_wake(struct journal *j)
{
	wake_up(&j->wait);
	closure_wake_up(&j->async_wait);
	closure_wake_up(&j->preres_wait);
}

static inline struct journal_buf *journal_cur_buf(struct journal *j)
{
	return j->buf + j->reservations.idx;
}

/* Sequence number of oldest dirty journal entry */

static inline u64 journal_last_seq(struct journal *j)
{
	return j->pin.front;
}

static inline u64 journal_cur_seq(struct journal *j)
{
	EBUG_ON(j->pin.back - 1 != atomic64_read(&j->seq));

	return j->pin.back - 1;
}

u64 bch2_inode_journal_seq(struct journal *, u64);
void bch2_journal_set_has_inum(struct journal *, u64, u64);

static inline int journal_state_count(union journal_res_state s, int idx)
{
	switch (idx) {
	case 0: return s.buf0_count;
	case 1: return s.buf1_count;
	case 2: return s.buf2_count;
	case 3: return s.buf3_count;
	}
	BUG();
}

static inline void journal_state_inc(union journal_res_state *s)
{
	s->buf0_count += s->idx == 0;
	s->buf1_count += s->idx == 1;
	s->buf2_count += s->idx == 2;
	s->buf3_count += s->idx == 3;
}

static inline void bch2_journal_set_has_inode(struct journal *j,
					      struct journal_res *res,
					      u64 inum)
{
	struct journal_buf *buf = &j->buf[res->idx];
	unsigned long bit = hash_64(inum, ilog2(sizeof(buf->has_inode) * 8));

	/* avoid atomic op if possible */
	if (unlikely(!test_bit(bit, buf->has_inode)))
		set_bit(bit, buf->has_inode);
}

/*
 * Amount of space that will be taken up by some keys in the journal (i.e.
 * including the jset header)
 */
static inline unsigned jset_u64s(unsigned u64s)
{
	return u64s + sizeof(struct jset_entry) / sizeof(u64);
}

static inline int journal_entry_overhead(struct journal *j)
{
	return sizeof(struct jset) / sizeof(u64) + j->entry_u64s_reserved;
}

static inline struct jset_entry *
bch2_journal_add_entry_noreservation(struct journal_buf *buf, size_t u64s)
{
	struct jset *jset = buf->data;
	struct jset_entry *entry = vstruct_idx(jset, le32_to_cpu(jset->u64s));

	memset(entry, 0, sizeof(*entry));
	entry->u64s = cpu_to_le16(u64s);

	le32_add_cpu(&jset->u64s, jset_u64s(u64s));

	return entry;
}

static inline struct jset_entry *
journal_res_entry(struct journal *j, struct journal_res *res)
{
	return vstruct_idx(j->buf[res->idx].data, res->offset);
}

static inline unsigned journal_entry_set(struct jset_entry *entry, unsigned type,
					  enum btree_id id, unsigned level,
					  const void *data, unsigned u64s)
{
	entry->u64s	= cpu_to_le16(u64s);
	entry->btree_id = id;
	entry->level	= level;
	entry->type	= type;
	entry->pad[0]	= 0;
	entry->pad[1]	= 0;
	entry->pad[2]	= 0;
	memcpy_u64s_small(entry->_data, data, u64s);

	return jset_u64s(u64s);
}

static inline void bch2_journal_add_entry(struct journal *j, struct journal_res *res,
					  unsigned type, enum btree_id id,
					  unsigned level,
					  const void *data, unsigned u64s)
{
	unsigned actual = journal_entry_set(journal_res_entry(j, res),
			       type, id, level, data, u64s);

	EBUG_ON(!res->ref);
	EBUG_ON(actual > res->u64s);

	res->offset	+= actual;
	res->u64s	-= actual;
}

static inline void bch2_journal_add_keys(struct journal *j, struct journal_res *res,
					enum btree_id id, unsigned level,
					const struct bkey_i *k)
{
	bch2_journal_add_entry(j, res, BCH_JSET_ENTRY_btree_keys,
			       id, level, k, k->k.u64s);
}

static inline bool journal_entry_empty(struct jset *j)
{
	struct jset_entry *i;

	if (j->seq != j->last_seq)
		return false;

	vstruct_for_each(j, i)
		if (i->type == BCH_JSET_ENTRY_btree_keys && i->u64s)
			return false;
	return true;
}

void __bch2_journal_buf_put(struct journal *);

static inline void bch2_journal_buf_put(struct journal *j, unsigned idx)
{
	union journal_res_state s;

	s.v = atomic64_sub_return(((union journal_res_state) {
				    .buf0_count = idx == 0,
				    .buf1_count = idx == 1,
				    .buf2_count = idx == 2,
				    .buf3_count = idx == 3,
				    }).v, &j->reservations.counter);

	EBUG_ON(((s.idx - idx) & 3) >
		((s.idx - s.unwritten_idx) & 3));

	if (!journal_state_count(s, idx) && idx == s.unwritten_idx)
		__bch2_journal_buf_put(j);
}

/*
 * This function releases the journal write structure so other threads can
 * then proceed to add their keys as well.
 */
static inline void bch2_journal_res_put(struct journal *j,
				       struct journal_res *res)
{
	if (!res->ref)
		return;

	lock_release(&j->res_map, _THIS_IP_);

	while (res->u64s)
		bch2_journal_add_entry(j, res,
				       BCH_JSET_ENTRY_btree_keys,
				       0, 0, NULL, 0);

	bch2_journal_buf_put(j, res->idx);

	res->ref = 0;
}

int bch2_journal_res_get_slowpath(struct journal *, struct journal_res *,
				  unsigned);

#define JOURNAL_RES_GET_NONBLOCK	(1 << 0)
#define JOURNAL_RES_GET_CHECK		(1 << 1)
#define JOURNAL_RES_GET_RESERVED	(1 << 2)

static inline int journal_res_get_fast(struct journal *j,
				       struct journal_res *res,
				       unsigned flags)
{
	union journal_res_state old, new;
	u64 v = atomic64_read(&j->reservations.counter);

	do {
		old.v = new.v = v;

		/*
		 * Check if there is still room in the current journal
		 * entry:
		 */
		if (new.cur_entry_offset + res->u64s > j->cur_entry_u64s)
			return 0;

		EBUG_ON(!journal_state_count(new, new.idx));

		if (!(flags & JOURNAL_RES_GET_RESERVED) &&
		    !test_bit(JOURNAL_MAY_GET_UNRESERVED, &j->flags))
			return 0;

		new.cur_entry_offset += res->u64s;
		journal_state_inc(&new);

		/*
		 * If the refcount would overflow, we have to wait:
		 * XXX - tracepoint this:
		 */
		if (!journal_state_count(new, new.idx))
			return 0;

		if (flags & JOURNAL_RES_GET_CHECK)
			return 1;
	} while ((v = atomic64_cmpxchg(&j->reservations.counter,
				       old.v, new.v)) != old.v);

	res->ref	= true;
	res->idx	= old.idx;
	res->offset	= old.cur_entry_offset;
	res->seq	= le64_to_cpu(j->buf[old.idx].data->seq);
	return 1;
}

static inline int bch2_journal_res_get(struct journal *j, struct journal_res *res,
				       unsigned u64s, unsigned flags)
{
	int ret;

	EBUG_ON(res->ref);
	EBUG_ON(!test_bit(JOURNAL_STARTED, &j->flags));

	res->u64s = u64s;

	if (journal_res_get_fast(j, res, flags))
		goto out;

	ret = bch2_journal_res_get_slowpath(j, res, flags);
	if (ret)
		return ret;
out:
	if (!(flags & JOURNAL_RES_GET_CHECK)) {
		lock_acquire_shared(&j->res_map, 0,
				    (flags & JOURNAL_RES_GET_NONBLOCK) != 0,
				    NULL, _THIS_IP_);
		EBUG_ON(!res->ref);
	}
	return 0;
}

/* journal_preres: */

static inline bool journal_check_may_get_unreserved(struct journal *j)
{
	union journal_preres_state s = READ_ONCE(j->prereserved);
	bool ret = s.reserved < s.remaining &&
		fifo_free(&j->pin) > 8;

	lockdep_assert_held(&j->lock);

	if (ret != test_bit(JOURNAL_MAY_GET_UNRESERVED, &j->flags)) {
		if (ret) {
			set_bit(JOURNAL_MAY_GET_UNRESERVED, &j->flags);
			journal_wake(j);
		} else {
			clear_bit(JOURNAL_MAY_GET_UNRESERVED, &j->flags);
		}
	}
	return ret;
}

static inline void bch2_journal_preres_put(struct journal *j,
					   struct journal_preres *res)
{
	union journal_preres_state s = { .reserved = res->u64s };

	if (!res->u64s)
		return;

	s.v = atomic64_sub_return(s.v, &j->prereserved.counter);
	res->u64s = 0;

	if (unlikely(s.waiting)) {
		clear_bit(ilog2((((union journal_preres_state) { .waiting = 1 }).v)),
			  (unsigned long *) &j->prereserved.v);
		closure_wake_up(&j->preres_wait);
	}

	if (s.reserved <= s.remaining &&
	    !test_bit(JOURNAL_MAY_GET_UNRESERVED, &j->flags)) {
		spin_lock(&j->lock);
		journal_check_may_get_unreserved(j);
		spin_unlock(&j->lock);
	}
}

int __bch2_journal_preres_get(struct journal *,
			struct journal_preres *, unsigned, unsigned);

static inline int bch2_journal_preres_get_fast(struct journal *j,
					       struct journal_preres *res,
					       unsigned new_u64s,
					       unsigned flags,
					       bool set_waiting)
{
	int d = new_u64s - res->u64s;
	union journal_preres_state old, new;
	u64 v = atomic64_read(&j->prereserved.counter);
	int ret;

	do {
		old.v = new.v = v;
		ret = 0;

		if ((flags & JOURNAL_RES_GET_RESERVED) ||
		    new.reserved + d < new.remaining) {
			new.reserved += d;
			ret = 1;
		} else if (set_waiting && !new.waiting)
			new.waiting = true;
		else
			return 0;
	} while ((v = atomic64_cmpxchg(&j->prereserved.counter,
				       old.v, new.v)) != old.v);

	if (ret)
		res->u64s += d;
	return ret;
}

static inline int bch2_journal_preres_get(struct journal *j,
					  struct journal_preres *res,
					  unsigned new_u64s,
					  unsigned flags)
{
	if (new_u64s <= res->u64s)
		return 0;

	if (bch2_journal_preres_get_fast(j, res, new_u64s, flags, false))
		return 0;

	if (flags & JOURNAL_RES_GET_NONBLOCK)
		return -EAGAIN;

	return __bch2_journal_preres_get(j, res, new_u64s, flags);
}

/* journal_entry_res: */

void bch2_journal_entry_res_resize(struct journal *,
				   struct journal_entry_res *,
				   unsigned);

int bch2_journal_flush_seq_async(struct journal *, u64, struct closure *);
void bch2_journal_flush_async(struct journal *, struct closure *);

int bch2_journal_flush_seq(struct journal *, u64);
int bch2_journal_flush(struct journal *);
int bch2_journal_meta(struct journal *);

void bch2_journal_halt(struct journal *);

static inline int bch2_journal_error(struct journal *j)
{
	return j->reservations.cur_entry_offset == JOURNAL_ENTRY_ERROR_VAL
		? -EIO : 0;
}

struct bch_dev;

static inline void bch2_journal_set_replay_done(struct journal *j)
{
	BUG_ON(!test_bit(JOURNAL_STARTED, &j->flags));
	set_bit(JOURNAL_REPLAY_DONE, &j->flags);
}

void bch2_journal_unblock(struct journal *);
void bch2_journal_block(struct journal *);

void __bch2_journal_debug_to_text(struct printbuf *, struct journal *);
void bch2_journal_debug_to_text(struct printbuf *, struct journal *);
void bch2_journal_pins_to_text(struct printbuf *, struct journal *);

int bch2_set_nr_journal_buckets(struct bch_fs *, struct bch_dev *,
				unsigned nr);
int bch2_dev_journal_alloc(struct bch_dev *);

void bch2_dev_journal_stop(struct journal *, struct bch_dev *);

void bch2_fs_journal_stop(struct journal *);
int bch2_fs_journal_start(struct journal *, u64, struct list_head *);

void bch2_dev_journal_exit(struct bch_dev *);
int bch2_dev_journal_init(struct bch_dev *, struct bch_sb *);
void bch2_fs_journal_exit(struct journal *);
int bch2_fs_journal_init(struct journal *);

#endif /* _BCACHEFS_JOURNAL_H */
