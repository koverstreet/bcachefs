/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_DISK_ACCOUNTING_FORMAT_H
#define _BCACHEFS_DISK_ACCOUNTING_FORMAT_H

#include "replicas_format.h"

/*
 * Disk accounting - KEY_TYPE_accounting - on disk format:
 *
 * Here, the key has considerably more structure than a typical key (bpos); an
 * accounting key is 'struct disk_accounting_pos', which is a union of bpos.
 *
 * More specifically: a key is just a muliword integer (where word endianness
 * matches native byte order), so we're treating bpos as an opaque 20 byte
 * integer and mapping bch_accounting_key to that.
 *
 * This is a type-tagged union of all our various subtypes; a disk accounting
 * key can be device counters, replicas counters, et cetera - it's extensible.
 *
 * The value is a list of u64s or s64s; the number of counters is specific to a
 * given accounting type.
 *
 * Unlike with other key types, updates are _deltas_, and the deltas are not
 * resolved until the update to the underlying btree, done by btree write buffer
 * flush or journal replay.
 *
 * Journal replay in particular requires special handling. The journal tracks a
 * range of entries which may possibly have not yet been applied to the btree
 * yet - it does not know definitively whether individual entries are dirty and
 * still need to be applied.
 *
 * To handle this, we use the version field of struct bkey, and give every
 * accounting update a unique version number - a total ordering in time; the
 * version number is derived from the key's position in the journal. Then
 * journal replay can compare the version number of the key from the journal
 * with the version number of the key in the btree to determine if a key needs
 * to be replayed.
 *
 * For this to work, we must maintain this strict time ordering of updates as
 * they are flushed to the btree, both via write buffer flush and via journal
 * replay. This has complications for the write buffer code while journal replay
 * is still in progress; the write buffer cannot flush any accounting keys to
 * the btree until journal replay has finished replaying its accounting keys, or
 * the (newer) version number of the keys from the write buffer will cause
 * updates from journal replay to be lost.
 */

struct bch_accounting {
	struct bch_val		v;
	__u64			d[];
};

#define BCH_ACCOUNTING_MAX_COUNTERS		3

#define BCH_DATA_TYPES()		\
	x(free,		0)		\
	x(sb,		1)		\
	x(journal,	2)		\
	x(btree,	3)		\
	x(user,		4)		\
	x(cached,	5)		\
	x(parity,	6)		\
	x(stripe,	7)		\
	x(need_gc_gens,	8)		\
	x(need_discard,	9)		\
	x(unstriped,	10)

enum bch_data_type {
#define x(t, n) BCH_DATA_##t,
	BCH_DATA_TYPES()
#undef x
	BCH_DATA_NR
};

static inline bool data_type_is_empty(enum bch_data_type type)
{
	switch (type) {
	case BCH_DATA_free:
	case BCH_DATA_need_gc_gens:
	case BCH_DATA_need_discard:
		return true;
	default:
		return false;
	}
}

static inline bool data_type_is_hidden(enum bch_data_type type)
{
	switch (type) {
	case BCH_DATA_sb:
	case BCH_DATA_journal:
		return true;
	default:
		return false;
	}
}

#define BCH_DISK_ACCOUNTING_TYPES()		\
	x(nr_inodes,		0)		\
	x(persistent_reserved,	1)		\
	x(replicas,		2)		\
	x(dev_data_type,	3)		\
	x(compression,		4)		\
	x(snapshot,		5)		\
	x(btree,		6)		\
	x(rebalance_work,	7)

enum disk_accounting_type {
#define x(f, nr)	BCH_DISK_ACCOUNTING_##f	= nr,
	BCH_DISK_ACCOUNTING_TYPES()
#undef x
	BCH_DISK_ACCOUNTING_TYPE_NR,
};

struct bch_nr_inodes {
};

struct bch_persistent_reserved {
	__u8			nr_replicas;
};

struct bch_dev_data_type {
	__u8			dev;
	__u8			data_type;
};

struct bch_dev_stripe_buckets {
	__u8			dev;
};

struct bch_acct_compression {
	__u8			type;
};

struct bch_acct_snapshot {
	__u32			id;
};

struct bch_acct_btree {
	__u32			id;
};

struct disk_accounting_pos {
	union {
	struct {
		__u8				type;
		union {
		struct bch_nr_inodes		nr_inodes;
		struct bch_persistent_reserved	persistent_reserved;
		struct bch_replicas_entry_v1	replicas;
		struct bch_dev_data_type	dev_data_type;
		struct bch_dev_stripe_buckets	dev_stripe_buckets;
		struct bch_acct_compression	compression;
		struct bch_acct_snapshot	snapshot;
		struct bch_acct_btree		btree;
		};
	};
		struct bpos			_pad;
	};
};

#endif /* _BCACHEFS_DISK_ACCOUNTING_FORMAT_H */
