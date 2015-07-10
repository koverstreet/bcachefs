#ifndef _BCACHE_DIRENT_H
#define _BCACHE_DIRENT_H

extern const struct btree_keys_ops bch_dirent_ops;
extern const struct bkey_ops bch_bkey_dirent_ops;

struct qstr;
struct file;
struct dir_context;
struct cache_set;

int bch_dirent_create(struct cache_set *, u64, u8, const struct qstr *,
		      u64, u64 *);
int bch_dirent_delete(struct cache_set *, u64, const struct qstr *);
int bch_dirent_rename(struct cache_set *, u64, const struct qstr *,
		      u64, const struct qstr *, u64 *, bool);
u64 bch_dirent_lookup(struct cache_set *, u64, const struct qstr *);
int bch_empty_dir(struct cache_set *, u64);
int bch_readdir(struct file *, struct dir_context *);

#endif /* _BCACHE_DIRENT_H */

