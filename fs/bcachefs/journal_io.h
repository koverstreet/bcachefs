/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_JOURNAL_IO_H
#define _BCACHEFS_JOURNAL_IO_H

/*
 * Only used for holding the journal entries we read in btree_journal_read()
 * during cache_registration
 */
struct journal_replay {
	struct journal_ptr {
		bool		csum_good;
		u8		dev;
		u32		bucket;
		u32		bucket_offset;
		u64		sector;
	}			ptrs[BCH_REPLICAS_MAX];
	unsigned		nr_ptrs;

	bool			csum_good;
	bool			ignore;
	/* must be last: */
	struct jset		j;
};

static inline struct jset_entry *__jset_entry_type_next(struct jset *jset,
					struct jset_entry *entry, unsigned type)
{
	while (entry < vstruct_last(jset)) {
		if (entry->type == type)
			return entry;

		entry = vstruct_next(entry);
	}

	return NULL;
}

#define for_each_jset_entry_type(entry, jset, type)			\
	for (entry = (jset)->start;					\
	     (entry = __jset_entry_type_next(jset, entry, type));	\
	     entry = vstruct_next(entry))

#define jset_entry_for_each_key(_e, _k)					\
	for (_k = (_e)->start;						\
	     _k < vstruct_last(_e);					\
	     _k = bkey_next(_k))

#define for_each_jset_key(k, entry, jset)				\
	for_each_jset_entry_type(entry, jset, BCH_JSET_ENTRY_btree_keys)\
		jset_entry_for_each_key(entry, k)

int bch2_journal_entry_validate(struct bch_fs *, struct jset *,
				struct jset_entry *, unsigned, int, int);
void bch2_journal_entry_to_text(struct printbuf *, struct bch_fs *,
				struct jset_entry *);

void bch2_journal_ptrs_to_text(struct printbuf *, struct bch_fs *,
			       struct journal_replay *);

int bch2_journal_read(struct bch_fs *, u64 *, u64 *, u64 *);

void bch2_journal_write(struct closure *);

#endif /* _BCACHEFS_JOURNAL_IO_H */
