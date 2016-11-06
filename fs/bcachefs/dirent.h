#ifndef _BCACHE_DIRENT_H
#define _BCACHE_DIRENT_H

extern const struct bkey_ops bch_bkey_dirent_ops;

struct qstr;
struct file;
struct dir_context;
struct cache_set;

int bch_dirent_create(struct inode *, u8, const struct qstr *, u64);
int bch_dirent_delete(struct inode *, const struct qstr *);

enum bch_rename_mode {
	BCH_RENAME,
	BCH_RENAME_OVERWRITE,
	BCH_RENAME_EXCHANGE,
};

int bch_dirent_rename(struct cache_set *,
		      struct inode *, const struct qstr *,
		      struct inode *, const struct qstr *,
		      u64 *, enum bch_rename_mode);

u64 bch_dirent_lookup(struct inode *, const struct qstr *);
int bch_empty_dir(struct cache_set *, u64);
int bch_readdir(struct file *, struct dir_context *);

#endif /* _BCACHE_DIRENT_H */

