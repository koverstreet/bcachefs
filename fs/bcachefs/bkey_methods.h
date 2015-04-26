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
				       struct bkey_s_c);
	void		(*key_debugcheck)(struct btree *, struct bkey_s_c);
	void		(*val_to_text)(const struct btree *, char *, size_t,
				       struct bkey_s_c);

	bool		is_extents;
};

bool bkey_invalid(struct cache_set *, enum bkey_type, struct bkey_s_c);
void bkey_debugcheck(struct btree *, struct bkey_s_c);
void bch_bkey_val_to_text(struct btree *, char *, size_t, struct bkey_s_c);

#undef DEF_BTREE_ID

#endif /* _BCACHE_BKEY_METHODS_H */
