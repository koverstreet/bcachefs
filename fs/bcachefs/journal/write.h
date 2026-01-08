/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_JOURNAL_WRITE_H
#define _BCACHEFS_JOURNAL_WRITE_H

CLOSURE_CALLBACK(bch2_journal_write);

static inline struct jset_entry *jset_entry_init(struct jset_entry **end, size_t size)
{
	struct jset_entry *entry = *end;
	unsigned u64s = DIV_ROUND_UP(size, sizeof(u64));

	memset(entry, 0, u64s * sizeof(u64));
	/*
	 * The u64s field counts from the start of data, ignoring the shared
	 * fields.
	 */
	entry->u64s = cpu_to_le16(u64s - 1);

	*end = vstruct_next(*end);
	return entry;
}

#endif /* _BCACHEFS_JOURNAL_WRITE_H */
