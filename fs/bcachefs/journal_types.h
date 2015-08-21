#ifndef _BCACHE_JOURNAL_TYPES_H
#define _BCACHE_JOURNAL_TYPES_H

#include <linux/cache.h>
#include <linux/workqueue.h>
#include "fifo.h"

struct journal_res;

/*
 * We put two of these in struct journal; we used them for writes to the
 * journal that are being staged or in flight.
 */
struct journal_write {
	struct jset		*data;
#define JSET_BITS		5

	struct journal		*j;
	struct closure_waitlist	wait;
};

/*
 * Something that makes a journal entry dirty - i.e. a btree node that has to be
 * flushed:
 */

struct journal_entry_pin_list {
	struct list_head		list;
	atomic_t			count;
};

struct journal_entry_pin;
typedef void (*journal_pin_flush_fn)(struct journal_entry_pin *);

struct journal_entry_pin {
	struct list_head		list;
	journal_pin_flush_fn		flush;
	struct journal_entry_pin_list	*pin_list;
};

struct journal_seq_blacklist {
	struct cache_set	*c;
	struct list_head	list;
	u64			seq;
	bool			written;
	struct journal_entry_pin pin;

	/* Btree nodes to be flushed: */
	struct list_head	nodes;
};

struct journal_res {
	bool			ref;
	u16			offset;
	u16			u64s;
};

union journal_res_state {
	struct {
		atomic64_t	counter;
	};

	struct {
		u64		v;
	};

	struct {
		unsigned	count;
		unsigned	cur_entry_offset;
	};
};

/*
 * JOURNAL_DIRTY - current journal entry has stuff in it to write
 *
 * JOURNAL_NEED_WRITE - current (pending) journal entry should be written ASAP,
 * either because something's waiting on the write to complete or because it's
 * been dirty too long and the timer's expired.
 *
 * If JOURNAL_NEED_WRITE is set, JOURNAL_DIRTY must be set.
 */

enum {
	JOURNAL_DIRTY,
	JOURNAL_NEED_WRITE,
	JOURNAL_IO_IN_FLIGHT,
	JOURNAL_WRITE_IDX,
	JOURNAL_REPLAY_DONE,
	JOURNAL_ERROR,
};

/* Embedded in struct cache_set */
struct journal {
	/* Fastpath stuff up front: */

	unsigned long		flags;

	union journal_res_state reservations;
	unsigned		cur_entry_u64s;

	/*
	 * Two journal entries -- one is currently open for new entries, the
	 * other is possibly being written out.
	 */
	struct journal_write	w[2];

	spinlock_t		lock;

	/* minimum sectors free in the bucket(s) we're currently writing to */
	unsigned		sectors_free;

	/* Used when waiting because the journal was full */
	wait_queue_head_t	wait;

	struct closure		io;
	struct delayed_work	write_work;

	unsigned		delay_ms;

	/* Sequence number of most recent journal entry (last entry in @pin) */
	u64			seq;

	/* last_seq from the most recent journal entry written */
	u64			last_seq_ondisk;

	/*
	 * FIFO of journal entries whose btree updates have not yet been
	 * written out.
	 *
	 * Each entry is a reference count. The position in the FIFO is the
	 * entry's sequence number relative to @seq.
	 *
	 * The journal entry itself holds a reference count, put when the
	 * journal entry is written out. Each btree node modified by the journal
	 * entry also holds a reference count, put when the btree node is
	 * written.
	 *
	 * When a reference count reaches zero, the journal entry is no longer
	 * needed. When all journal entries in the oldest journal bucket are no
	 * longer needed, the bucket can be discarded and reused.
	 */
	DECLARE_FIFO(struct journal_entry_pin_list, pin);
	struct journal_entry_pin_list *cur_pin_list;

	/*
	 * Protects the pin lists - the fifo itself is still protected by
	 * j->lock though:
	 */
	spinlock_t		pin_lock;

	struct mutex		blacklist_lock;
	struct list_head	seq_blacklist;

	BKEY_PADDED(key);

	struct work_struct	reclaim_work;

	u64			prio_buckets[MAX_CACHES_PER_SET];
	unsigned		nr_prio_buckets;


	u64			need_write_time;
	u64			write_start_time;

	struct time_stats	*write_time;
	struct time_stats	*delay_time;
	struct time_stats	*full_time;
	struct time_stats	*flush_seq_time;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	res_map;
#endif
};

/*
 * Embedded in struct cache. First three fields refer to the array of journal
 * buckets, in cache_sb.
 */
struct journal_device {
	/*
	 * For each journal bucket, contains the max sequence number of the
	 * journal writes it contains - so we know when a bucket can be reused.
	 */
	u64			*bucket_seq;

	unsigned		sectors_free;

	/* Journal bucket we're currently writing to */
	unsigned		cur_idx;

	/* Last journal bucket that still contains an open journal entry */
	unsigned		last_idx;

	/* Bio for journal reads/writes to this device */
	struct bio		bio;
	struct bio_vec		bv[1 << JSET_BITS];

	/* for bch_journal_read_device */
	struct closure		read;
};

#endif /* _BCACHE_JOURNAL_TYPES_H */
