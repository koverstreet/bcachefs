/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_NODE_SCAN_H
#define _BCACHEFS_BTREE_NODE_SCAN_H

void bch2_found_btree_node_to_text(struct printbuf *, struct bch_fs *,
				   const struct found_btree_node *);

int bch2_scan_for_btree_nodes(struct bch_fs *);
bool bch2_btree_node_is_stale(struct bch_fs *, struct btree *);
int bch2_btree_has_scanned_nodes(struct bch_fs *, enum btree_id, struct printbuf *);
int bch2_get_scanned_nodes(struct bch_fs *, enum btree_id, unsigned,
			   struct bpos, struct bpos,
			   struct printbuf *, size_t *);

void bch2_find_btree_nodes_exit(struct find_btree_nodes *);
void bch2_find_btree_nodes_init(struct find_btree_nodes *);

#endif /* _BCACHEFS_BTREE_NODE_SCAN_H */
