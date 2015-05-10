#ifndef _BCACHE_BKEY_METHODS_H
#define _BCACHE_BKEY_METHODS_H

#define DEF_BTREE_ID(kwd, val, name) BKEY_TYPE_##kwd = val,

enum bkey_type {
	DEFINE_BCH_BTREE_IDS()
	BKEY_TYPE_BTREE,
};

struct cache_set;
struct btree;
struct bkey;

struct bkey_ops {
	bool		(*key_invalid)(const struct cache_set *,
				       const struct bkey *);
	void		(*key_debugcheck)(struct btree *,
					  const struct bkey *);
	void		(*val_to_text)(const struct btree *, char *,
				       size_t, const struct bkey *);

	bool		is_extents;
};

bool bkey_invalid(struct cache_set *, enum bkey_type, const struct bkey *);
void bkey_debugcheck(struct btree *, struct bkey *);
void bch_bkey_val_to_text(struct btree *, char *, size_t, const struct bkey *);

#undef DEF_BTREE_ID

#endif /* _BCACHE_BKEY_METHODS_H */
