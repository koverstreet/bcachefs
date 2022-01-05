/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BUCKETS_WAITING_FOR_JOURNAL_TYPES_H
#define _BUCKETS_WAITING_FOR_JOURNAL_TYPES_H

struct bucket_hashed {
	u64			dev_bucket;
	u64			journal_seq;
};

struct buckets_waiting_for_journal {
	struct mutex		lock;
	size_t			nr;
	struct bucket_hashed	*d;
};

#endif /* _BUCKETS_WAITING_FOR_JOURNAL_TYPES_H */
