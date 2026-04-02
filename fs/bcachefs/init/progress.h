/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_PROGRESS_H
#define _BCACHEFS_PROGRESS_H

#include "btree/bbpos_types.h"

/*
 * Lame progress indicators
 *
 * We don't like to use these because they print to the dmesg console, which is
 * spammy - we much prefer to be wired up to a userspace program (e.g. via
 * thread_with_file) and have it print the progress indicator.
 *
 * But some code is old and doesn't support that, or runs in a context where
 * that's not yet practical (mount).
 */

struct progress_indicator {
	const char		*msg;
	struct bbpos		pos;
	unsigned long		next_print;
	u64			nodes_seen;
	u64			nodes_total;
	struct btree		*last_node;
	bool			silent;
};

void bch2_progress_init(struct progress_indicator *s,
			      const char *msg,
			      struct bch_fs *c,
			      u64 leaf_btree_id_mask,
			      u64 inner_btree_id_mask);

int bch2_progress_update_iter(struct btree_trans *,
			      struct progress_indicator *,
			      struct btree_iter *);

void bch2_progress_to_text(struct printbuf *, struct progress_indicator *);

#endif /* _BCACHEFS_PROGRESS_H */
