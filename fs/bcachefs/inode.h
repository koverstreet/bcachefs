#ifndef _BCACHE_INODE_H
#define _BCACHE_INODE_H

#include <linux/math64.h>

extern const struct bkey_ops bch2_bkey_inode_ops;

struct bch_inode_unpacked {
	u64			inum;
	__le64			i_hash_seed;
	u32			i_flags;
	u16			i_mode;

#define BCH_INODE_FIELD(_name, _bits)	u##_bits _name;
	BCH_INODE_FIELDS()
#undef  BCH_INODE_FIELD
};

struct bkey_inode_buf {
	struct bkey_i_inode	inode;

#define BCH_INODE_FIELD(_name, _bits)		+ 8 + _bits / 8
	u8		_pad[0 + BCH_INODE_FIELDS()];
#undef  BCH_INODE_FIELD
};

void bch2_inode_pack(struct bkey_inode_buf *, const struct bch_inode_unpacked *);
int bch2_inode_unpack(struct bkey_s_c_inode, struct bch_inode_unpacked *);

void bch2_inode_init(struct bch_fs *, struct bch_inode_unpacked *,
		    uid_t, gid_t, umode_t, dev_t);
int bch2_inode_create(struct bch_fs *, struct bkey_i *, u64, u64, u64 *);
int bch2_inode_truncate(struct bch_fs *, u64, u64,
		       struct extent_insert_hook *, u64 *);
int bch2_inode_rm(struct bch_fs *, u64);

int bch2_inode_find_by_inum(struct bch_fs *, u64,
			   struct bch_inode_unpacked *);
int bch2_cached_dev_inode_find_by_uuid(struct bch_fs *, uuid_le *,
				      struct bkey_i_inode_blockdev *);

static inline struct timespec bch2_time_to_timespec(struct bch_fs *c, u64 time)
{
	return ns_to_timespec(time * c->sb.time_precision + c->sb.time_base_lo);
}

static inline u64 timespec_to_bch2_time(struct bch_fs *c, struct timespec ts)
{
	s64 ns = timespec_to_ns(&ts) - c->sb.time_base_lo;

	if (c->sb.time_precision == 1)
		return ns;

	return div_s64(ns, c->sb.time_precision);
}

#ifdef CONFIG_BCACHEFS_DEBUG
void bch2_inode_pack_test(void);
#else
static inline void bch2_inode_pack_test(void) {}
#endif

#endif
