#include "hashtable.h"

#include "linux/random.h"
#include <linux/slab.h>

struct htable_free_rcu {
	struct rcu_head		rcu;
	unsigned		order;
	unsigned long		addr;
};

static void htable_free_rcu(struct rcu_head *rcu)
{
	struct htable_free_rcu *free_rcu =
		container_of(rcu, struct htable_free_rcu, rcu);

	free_pages(free_rcu->addr, free_rcu->order);
	kfree(free_rcu);
}

void bch2_htable_expand(struct htable *ht, const struct htable_params p)
{
	struct htable_ptr old, new;
	struct hlist_node *pos, *n;
	struct htable_free_rcu *free_rcu;
	unsigned shift = ht->table & ~PAGE_MASK;
	unsigned i;

	old = htable_read_ptr(ht);
	new.size = old.size * 2;

	free_rcu = kmalloc(sizeof(*free_rcu), GFP_KERNEL);
	if (!free_rcu)
		return;

	free_rcu->order = shift;
	free_rcu->addr = (unsigned long) old.table;

	new.table = (void *) __get_free_pages(GFP_KERNEL|__GFP_ZERO, shift + 1);
	if (!new.table) {
		kfree(free_rcu);
		return;
	}

	for (i = 0; i < old.size; i++) {
		hlist_for_each_safe(pos, n, old.table + i) {
			void *obj = htable_obj(pos, p);
			unsigned hash = htable_obj_get_hash(obj, ht->hash_seed, p);

			hlist_del_rcu(pos);
			hlist_add_head_rcu(pos, htable_bucket(new, hash));
		}
	}

	smp_store_release(&ht->table, (unsigned long) new.table | (shift + 1));

	call_rcu(&free_rcu->rcu, htable_free_rcu);
}

void bch2_htable_exit(struct htable *ht)
{
	unsigned long table = ht->table & PAGE_MASK;
	unsigned order = ht->table & ~PAGE_MASK;

	free_pages(table, order);
}

int bch2_htable_init(struct htable *ht)
{
	mutex_init(&ht->lock);

	ht->hash_seed = get_random_u32();
	ht->nelems = 0;
	ht->table = __get_free_page(GFP_KERNEL|__GFP_ZERO);
	if (!ht->table)
		return -ENOMEM;

	return 0;
}
