#ifndef _BCACHEFS_QUOTA_H
#define _BCACHEFS_QUOTA_H

#include "quota_types.h"

extern const struct bkey_ops bch2_bkey_quota_ops;

enum quota_acct_mode {
	BCH_QUOTA_PREALLOC,
	BCH_QUOTA_WARN,
	BCH_QUOTA_NOCHECK,
};

static inline struct bch_qid bch_qid(struct bch_inode_unpacked *u)
{
	return (struct bch_qid) {
		.q[QTYP_USR] = u->bi_uid,
		.q[QTYP_GRP] = u->bi_gid,
		.q[QTYP_PRJ] = u->bi_project,
	};
}

#ifdef CONFIG_BCACHEFS_QUOTA

int bch2_quota_acct(struct bch_fs *, struct bch_qid, enum quota_counters,
		    s64, enum quota_acct_mode);

int bch2_quota_transfer(struct bch_fs *, unsigned, struct bch_qid,
			struct bch_qid, u64);

void bch2_fs_quota_exit(struct bch_fs *);
void bch2_fs_quota_init(struct bch_fs *);
int bch2_fs_quota_read(struct bch_fs *);

extern const struct quotactl_ops bch2_quotactl_operations;

#else

#define bch2_quota_acct(_c, _uid, _gid, _counter, _v) (0)
#define bch2_quota_transfer(_c, _type, _src, _dst, _v) (0)

static inline void bch2_fs_quota_exit(struct bch_fs *c) {}
static inline void bch2_fs_quota_init(struct bch_fs *c) {}
static inline int bch2_fs_quota_read(struct bch_fs *c) { return 0; }

#endif

#endif /* _BCACHEFS_QUOTA_H */
