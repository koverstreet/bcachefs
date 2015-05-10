#ifndef _BCACHE_JOURNAL_TYPES_H
#define _BCACHE_JOURNAL_TYPES_H

/*
 * We put two of these in struct journal; we used them for writes to the
 * journal that are being staged or in flight.
 */
struct journal_write {
	struct jset		*data;
#define JSET_BITS		5

	struct cache_set	*c;
	struct closure_waitlist	wait;
};

/* Embedded in struct cache_set */
struct journal {
	unsigned long		flags;
#define JOURNAL_NEED_WRITE	0
#define JOURNAL_DIRTY		1
#define JOURNAL_REPLAY_DONE	2
	atomic_t		in_flight;

	spinlock_t		lock;

	unsigned		u64s_remaining;
	unsigned		res_count;

	/* Number of blocks free in the bucket(s) we're currently writing to */
	unsigned		blocks_free;

	/* used when waiting because the journal was full */
	wait_queue_head_t	wait;
	struct closure		io;
	struct delayed_work	work;

	unsigned		delay_ms;

	u64			seq;
	DECLARE_FIFO(atomic_t, pin);

	BKEY_PADDED(key);

	struct journal_write	w[2], *cur;
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
	u64			*seq;

	/* Journal bucket we're currently writing to */
	unsigned		cur_idx;

	/* Last journal bucket that still contains an open journal entry */
	unsigned		last_idx;

	/* Next journal bucket to be discarded */
	unsigned		discard_idx;

#define DISCARD_READY		0
#define DISCARD_IN_FLIGHT	1
#define DISCARD_DONE		2
	/* 1 - discard in flight, -1 - discard completed */
	atomic_t		discard_in_flight;

	struct work_struct	discard_work;
	struct bio		discard_bio;
	struct bio_vec		discard_bv;

	/* Bio for journal reads/writes to this device */
	struct bio		bio;
	struct bio_vec		bv[1 << JSET_BITS];

	/* for bch_journal_read_device */
	struct closure		read;
};

#endif /* _BCACHE_JOURNAL_TYPES_H */
