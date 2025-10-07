/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_BTREE_IO_H
#define _BCACHEFS_BTREE_IO_H

#include "btree/bkey_methods.h"
#include "btree/bset.h"
#include "btree/locking.h"
#include "data/checksum.h"
#include "data/extents.h"

struct bch_fs;
struct btree;
struct btree_node_read_all;

static inline unsigned btree_ptr_sectors_written(struct bkey_s_c k)
{
	return k.k->type == KEY_TYPE_btree_ptr_v2
		? le16_to_cpu(bkey_s_c_to_btree_ptr_v2(k).v->sectors_written)
		: 0;
}

struct btree_read_bio {
	struct bch_fs		*c;
	struct btree		*b;
	struct btree_node_read_all *ra;
	u64			start_time;
	unsigned		have_ioref:1;
	unsigned		idx:7;
#ifdef CONFIG_BCACHEFS_ASYNC_OBJECT_LISTS
	unsigned		list_idx;
#endif
	struct extent_ptr_decoded	pick;
	struct work_struct	work;
	struct bio		bio;
};

void bch2_btree_node_io_unlock(struct btree *);
void bch2_btree_node_io_lock(struct btree *);
void __bch2_btree_node_wait_on_read(struct btree *);
void __bch2_btree_node_wait_on_write(struct btree *);
void bch2_btree_node_wait_on_read(struct btree *);
void bch2_btree_node_wait_on_write(struct btree *);

static inline struct nonce btree_nonce(struct bset *i, unsigned offset)
{
	return (struct nonce) {{
		[0] = cpu_to_le32(offset),
		[1] = ((__le32 *) &i->seq)[0],
		[2] = ((__le32 *) &i->seq)[1],
		[3] = ((__le32 *) &i->journal_seq)[0]^BCH_NONCE_BTREE,
	}};
}

static inline int bset_encrypt(struct bch_fs *c, struct bset *i, unsigned offset)
{
	struct nonce nonce = btree_nonce(i, offset);
	int ret;

	if (!offset) {
		struct btree_node *bn = container_of(i, struct btree_node, keys);
		unsigned bytes = (void *) &bn->keys - (void *) &bn->flags;

		ret = bch2_encrypt(c, BSET_CSUM_TYPE(i), nonce,
				   &bn->flags, bytes);
		if (ret)
			return ret;

		nonce = nonce_add(nonce, round_up(bytes, CHACHA_BLOCK_SIZE));
	}

	return bch2_encrypt(c, BSET_CSUM_TYPE(i), nonce, i->_data,
			    vstruct_end(i) - (void *) i->_data);
}

void bch2_btree_node_drop_keys_outside_node(struct btree *);

int bch2_validate_bset_keys(struct bch_fs *, struct btree *,
			    struct bset *, int,
			    struct bch_io_failures *,
			    struct printbuf *);
int bch2_validate_bset(struct bch_fs *, struct bch_dev *,
		       struct btree *, struct bset *,
		       unsigned, int,
		       struct bch_io_failures *,
		       struct printbuf *);

int bch2_btree_node_read_done(struct bch_fs *, struct bch_dev *,
			      struct btree *,
			      struct bch_io_failures *,
			      struct printbuf *);
void bch2_btree_node_read(struct btree_trans *, struct btree *, bool);
int bch2_btree_root_read(struct bch_fs *, enum btree_id,
			 const struct bkey_i *, unsigned);

void bch2_btree_read_bio_to_text(struct printbuf *, struct btree_read_bio *);

int bch2_btree_node_scrub(struct btree_trans *, enum btree_id, unsigned,
			  struct bkey_s_c, unsigned);

bool bch2_btree_flush_all_reads(struct bch_fs *);
bool bch2_btree_flush_all_writes(struct bch_fs *);

static inline void compat_bformat(unsigned level, enum btree_id btree_id,
				  unsigned version, unsigned big_endian,
				  int write, struct bkey_format *f)
{
	if (version < bcachefs_metadata_version_inode_btree_change &&
	    btree_id == BTREE_ID_inodes) {
		swap(f->bits_per_field[BKEY_FIELD_INODE],
		     f->bits_per_field[BKEY_FIELD_OFFSET]);
		swap(f->field_offset[BKEY_FIELD_INODE],
		     f->field_offset[BKEY_FIELD_OFFSET]);
	}

	if (version < bcachefs_metadata_version_snapshot &&
	    (level || btree_type_has_snapshots(btree_id))) {
		u64 max_packed =
			~(~0ULL << f->bits_per_field[BKEY_FIELD_SNAPSHOT]);

		f->field_offset[BKEY_FIELD_SNAPSHOT] = write
			? 0
			: cpu_to_le64(U32_MAX - max_packed);
	}
}

static inline void compat_bpos(unsigned level, enum btree_id btree_id,
			       unsigned version, unsigned big_endian,
			       int write, struct bpos *p)
{
	if (big_endian != CPU_BIG_ENDIAN)
		bch2_bpos_swab(p);

	if (version < bcachefs_metadata_version_inode_btree_change &&
	    btree_id == BTREE_ID_inodes)
		swap(p->inode, p->offset);
}

static inline void compat_btree_node(unsigned level, enum btree_id btree_id,
				     unsigned version, unsigned big_endian,
				     int write,
				     struct btree_node *bn)
{
	if (version < bcachefs_metadata_version_inode_btree_change &&
	    btree_id_is_extents(btree_id) &&
	    !bpos_eq(bn->min_key, POS_MIN) &&
	    write)
		bn->min_key = bpos_nosnap_predecessor(bn->min_key);

	if (version < bcachefs_metadata_version_snapshot &&
	    write)
		bn->max_key.snapshot = 0;

	compat_bpos(level, btree_id, version, big_endian, write, &bn->min_key);
	compat_bpos(level, btree_id, version, big_endian, write, &bn->max_key);

	if (version < bcachefs_metadata_version_snapshot &&
	    !write)
		bn->max_key.snapshot = U32_MAX;

	if (version < bcachefs_metadata_version_inode_btree_change &&
	    btree_id_is_extents(btree_id) &&
	    !bpos_eq(bn->min_key, POS_MIN) &&
	    !write)
		bn->min_key = bpos_nosnap_successor(bn->min_key);
}

#endif /* _BCACHEFS_BTREE_IO_H */
