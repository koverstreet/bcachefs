#ifndef _BCACHE_BKEY_METHODS_H
#define _BCACHE_BKEY_METHODS_H

#define DEF_BTREE_ID(kwd, val, name) BKEY_TYPE_##kwd = val,

enum bkey_type {
	DEFINE_BCH_BTREE_IDS()
	BKEY_TYPE_BTREE,
};

/* Type of a key in btree @id at level @level: */
static inline enum bkey_type bkey_type(unsigned level, enum btree_id id)
{
	return level ? BKEY_TYPE_BTREE : id;
}

static inline bool btree_type_has_ptrs(enum bkey_type type)
{
	switch (type) {
	case BKEY_TYPE_BTREE:
	case BKEY_TYPE_EXTENTS:
		return true;
	default:
		return false;
	}
}

struct cache_set;
struct btree_keys;
struct btree;
struct bkey;

enum merge_result {
	BCH_MERGE_NOMERGE,

	/*
	 * The keys were mergeable, but would have overflowed size - so instead
	 * l was changed to the maximum size, and both keys were modified:
	 */
	BCH_MERGE_PARTIAL,
	BCH_MERGE_MERGE,
};

typedef bool (*key_filter_fn)(struct cache_set *, struct btree_keys *,
			      struct bkey_s);
typedef enum merge_result (*key_merge_fn)(struct cache_set *,
					  struct btree_keys *,
					  struct bkey_i *, struct bkey_i *);

struct bkey_ops {
	/* Returns reason for being invalid if invalid, else NULL: */
	const char *	(*key_invalid)(const struct cache_set *,
				       struct bkey_s_c);
	void		(*key_debugcheck)(struct cache_set *, struct btree *,
					  struct bkey_s_c);
	void		(*val_to_text)(struct cache_set *, char *,
				       size_t, struct bkey_s_c);
	void		(*swab)(const struct bkey_format *, struct bkey_packed *);
	key_filter_fn	key_normalize;
	key_merge_fn	key_merge;
	bool		is_extents;
};

const char *bkey_invalid(struct cache_set *, enum bkey_type, struct bkey_s_c);
const char *btree_bkey_invalid(struct cache_set *, struct btree *,
			       struct bkey_s_c);

void bkey_debugcheck(struct cache_set *, struct btree *, struct bkey_s_c);
void bch_bkey_val_to_text(struct cache_set *, enum bkey_type,
			  char *, size_t, struct bkey_s_c);

void bch_bkey_swab(enum bkey_type, const struct bkey_format *,
		   struct bkey_packed *);

extern const struct bkey_ops *bch_bkey_ops[];

#undef DEF_BTREE_ID

#endif /* _BCACHE_BKEY_METHODS_H */
