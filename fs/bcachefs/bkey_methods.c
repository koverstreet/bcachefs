
#include "bcache.h"
#include "bkey_methods.h"
#include "btree.h"
#include "extents.h"
#include "inode.h"

static const struct bkey_ops *bch_bkey_ops[] = {
	[BKEY_TYPE_EXTENTS]	= &bch_bkey_extent_ops,
	[BKEY_TYPE_INODES]	= &bch_bkey_inode_ops,
	[BKEY_TYPE_BTREE]	= &bch_bkey_btree_ops,
};

bool bkey_invalid(struct cache_set *c,
		  enum bkey_type type,
		  struct bkey_s_c k)
{
	const struct bkey_ops *ops = bch_bkey_ops[type];

	if (k.k->u64s < BKEY_U64s)
		return true;

	if (k.k->size &&
	    (bkey_deleted(k.k) || !ops->is_extents))
		return true;

	switch (k.k->type) {
	case KEY_TYPE_DELETED:
		return false;

	case KEY_TYPE_DISCARD:
	case KEY_TYPE_ERROR:
		return bkey_val_bytes(k.k) != 0;

	case KEY_TYPE_COOKIE:
		return (bkey_val_bytes(k.k) != sizeof(struct bch_cookie));

	default:
		if (k.k->type < KEY_TYPE_GENERIC_NR)
			return true;

		return ops->key_invalid(c, k);
	}
}

void bkey_debugcheck(struct cache_set *c, struct btree *b, struct bkey_s_c k)
{
	enum bkey_type type = btree_node_type(b);
	const struct bkey_ops *ops = bch_bkey_ops[type];

	BUG_ON(!k.k->u64s);

	cache_set_bug_on(bkey_cmp(bkey_start_pos(k.k),
				  b->data->min_key) < 0,
			 c, "key before start of btree node");

	cache_set_bug_on(bkey_cmp(k.k->p,
				  b->data->max_key) > 0,
			 c, "key past end of btree node");

	if (bkey_invalid(c, type, k)) {
		char buf[160];

		bch_bkey_val_to_text(c, b, buf, sizeof(buf), k);
		cache_set_bug(c, "invalid bkey %s", buf);
		return;
	}

	if (k.k->type >= KEY_TYPE_GENERIC_NR &&
	    ops->key_debugcheck)
		ops->key_debugcheck(c, b, k);
}

void bch_bkey_val_to_text(struct cache_set *c, struct btree *b,
			  char *buf, size_t size, struct bkey_s_c k)
{
	enum bkey_type type = btree_node_type(b);
	const struct bkey_ops *ops = bch_bkey_ops[type];
	char *out = buf, *end = buf + size;

	out += bch_bkey_to_text(out, end - out, k.k);

	if (k.k->type >= KEY_TYPE_GENERIC_NR &&
	    ops->val_to_text) {
		out += scnprintf(out, end - out, " -> ");
		ops->val_to_text(c, out, end - out, k);
	}
}
