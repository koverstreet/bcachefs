#ifndef _BCACHEFS_HASHTABLE_H
#define _BCACHEFS_HASHTABLE_H

#include <linux/rhashtable.h>

struct htable_params {
	u16			key_len;
	u16			key_offset;
	u16			head_offset;
};

struct htable {
	struct mutex		lock;
	unsigned		hash_seed;
	unsigned		nelems;
	unsigned		max_chain;
	unsigned long		table;
};

void bch2_htable_expand(struct htable *, const struct htable_params);

static inline unsigned htable_key_get_hash(const void *key,
					   unsigned hash_rnd,
					   const struct htable_params p)
{
	return p.key_len % sizeof(u32)
		? jhash(key, p.key_len, hash_rnd)
		: jhash2(key, p.key_len / sizeof(u32), hash_rnd);
}

static inline unsigned htable_obj_get_hash(const void *obj,
					   unsigned hash_rnd,
					   const struct htable_params p)
{
	return htable_key_get_hash(obj + p.key_offset, hash_rnd, p);
}

struct htable_ptr {
	struct hlist_head	*table;
	unsigned		size;
};

static inline struct htable_ptr htable_read_ptr(struct htable *ht)
{
	unsigned long table = READ_ONCE(ht->table);

	return (struct htable_ptr) {
		.table = (void *) (table & PAGE_MASK),
		.size = (PAGE_SIZE / sizeof(void *)) << (table & ~PAGE_MASK),
	};
}

static inline struct hlist_head *htable_bucket(struct htable_ptr t,
					       unsigned hash)
{
	return t.table + (hash & (t.size - 1));
}

static inline void *htable_obj(struct hlist_node *n,
			       const struct htable_params p)
{
	return (char *)n - p.head_offset;
}

static inline int htable_cmp(const void *key, const void *obj,
			     const struct htable_params p)
{
	return memcmp(obj + p.key_offset, key, p.key_len);
}

static inline void *__htable_lookup(struct hlist_head *hash_head,
				    const void *key,
				    const struct htable_params p)
{
	struct hlist_node *n;

	__hlist_for_each_rcu(n, hash_head)
		if (!htable_cmp(key, htable_obj(n, p), p))
			return htable_obj(n, p);

	return NULL;
}

static inline void *htable_lookup(struct htable *ht, const void *key,
				  const struct htable_params p)
{
	struct htable_ptr t;
	unsigned hash;
	void *ret = NULL;

	rcu_read_lock();
	t		= htable_read_ptr(ht);
	hash		= htable_key_get_hash(key, ht->hash_seed, p);

	ret = __htable_lookup(htable_bucket(t, hash), key, p);
	rcu_read_unlock();

	return ret;
}

static inline void htable_remove(struct htable *ht, void *obj,
				 const struct htable_params p)
{
	struct hlist_node *n;
	struct htable_ptr t;
	unsigned hash;
	int ret = -ENOENT;

	mutex_lock(&ht->lock);
	t		= htable_read_ptr(ht);
	hash		= htable_obj_get_hash(obj, ht->hash_seed, p);

	__hlist_for_each_rcu(n, htable_bucket(t, hash))
		if (obj == htable_obj(n, p)) {
			hlist_del_rcu(obj + p.head_offset);
			ht->nelems--;
			ret = 0;
			break;
		}

	mutex_unlock(&ht->lock);
}

static inline int htable_insert(struct htable *ht, void *obj,
				const struct htable_params p)
{
	struct htable_ptr t;
	struct hlist_head *head;
	struct hlist_node *n;
	unsigned hash, chainlen = 1;

	hash = htable_obj_get_hash(obj, ht->hash_seed, p);

	mutex_lock(&ht->lock);
	t		= htable_read_ptr(ht);
	head	= htable_bucket(t, hash);

	__hlist_for_each_rcu(n, head) {
		if (!htable_cmp(obj + p.key_offset, htable_obj(n, p), p)) {
			mutex_unlock(&ht->lock);
			return -EEXIST;
		}
		chainlen++;
	}

	hlist_add_head_rcu(obj + p.head_offset, head);
	ht->nelems++;

	if (chainlen > ht->max_chain) {
		ht->max_chain = chainlen;
		printk(KERN_INFO "%pf ht with %u/%u has chain %u",
		       (void *) _THIS_IP_, ht->nelems, t.size, ht->max_chain);
	}

	if (ht->nelems > t.size >> 2)
		bch2_htable_expand(ht, p);
	mutex_unlock(&ht->lock);

	return 0;
}

void bch2_htable_exit(struct htable *);
int bch2_htable_init(struct htable *);

#endif /* _BCACHEFS_HASHTABLE_H */
