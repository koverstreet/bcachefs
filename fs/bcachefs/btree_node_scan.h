/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_NODE_SCAN_H
#define _BCACHEFS_BTREE_NODE_SCAN_H

int bch2_scan_for_btree_nodes(struct bch_fs *);
int bch2_repair_missing_btree_node(struct bch_fs *, enum btree_id,
				   unsigned, struct bpos, struct bpos);
void bch2_find_btree_nodes_exit(struct find_btree_nodes *);

#endif /* _BCACHEFS_BTREE_NODE_SCAN_H */
