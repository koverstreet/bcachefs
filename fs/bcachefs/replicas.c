// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "buckets.h"
#include "journal.h"
#include "replicas.h"
#include "super-io.h"

static int bch2_cpu_replicas_to_sb_replicas(struct bch_fs *,
					    struct bch_replicas_cpu *);

/* Replicas tracking - in memory: */

static void verify_replicas_entry(struct bch_replicas_entry *e)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	unsigned i;

	BUG_ON(e->data_type >= BCH_DATA_NR);
	BUG_ON(!e->nr_devs);
	BUG_ON(e->nr_required > 1 &&
	       e->nr_required >= e->nr_devs);

	for (i = 0; i + 1 < e->nr_devs; i++)
		BUG_ON(e->devs[i] >= e->devs[i + 1]);
#endif
}

void bch2_replicas_entry_sort(struct bch_replicas_entry *e)
{
	bubble_sort(e->devs, e->nr_devs, u8_cmp);
}

static void bch2_cpu_replicas_sort(struct bch_replicas_cpu *r)
{
	eytzinger0_sort(r->entries, r->nr, r->entry_size, memcmp, NULL);
}

void bch2_replicas_entry_to_text(struct printbuf *out,
				 struct bch_replicas_entry *e)
{
	unsigned i;

	pr_buf(out, "%s: %u/%u [",
	       bch2_data_types[e->data_type],
	       e->nr_required,
	       e->nr_devs);

	for (i = 0; i < e->nr_devs; i++)
		pr_buf(out, i ? " %u" : "%u", e->devs[i]);
	pr_buf(out, "]");
}

void bch2_cpu_replicas_to_text(struct printbuf *out,
			      struct bch_replicas_cpu *r)
{
	struct bch_replicas_entry *e;
	bool first = true;

	for_each_cpu_replicas_entry(r, e) {
		if (!first)
			pr_buf(out, " ");
		first = false;

		bch2_replicas_entry_to_text(out, e);
	}
}

static void extent_to_replicas(struct bkey_s_c k,
			       struct bch_replicas_entry *r)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
	const union bch_extent_entry *entry;
	struct extent_ptr_decoded p;

	r->nr_required	= 1;

	bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
		if (p.ptr.cached)
			continue;

		if (!p.has_ec)
			r->devs[r->nr_devs++] = p.ptr.dev;
		else
			r->nr_required = 0;
	}
}

static void stripe_to_replicas(struct bkey_s_c k,
			       struct bch_replicas_entry *r)
{
	struct bkey_s_c_stripe s = bkey_s_c_to_stripe(k);
	const struct bch_extent_ptr *ptr;

	r->nr_required	= s.v->nr_blocks - s.v->nr_redundant;

	for (ptr = s.v->ptrs;
	     ptr < s.v->ptrs + s.v->nr_blocks;
	     ptr++)
		r->devs[r->nr_devs++] = ptr->dev;
}

void bch2_bkey_to_replicas(struct bch_replicas_entry *e,
			   struct bkey_s_c k)
{
	e->nr_devs = 0;

	switch (k.k->type) {
	case KEY_TYPE_btree_ptr:
	case KEY_TYPE_btree_ptr_v2:
		e->data_type = BCH_DATA_btree;
		extent_to_replicas(k, e);
		break;
	case KEY_TYPE_extent:
	case KEY_TYPE_reflink_v:
		e->data_type = BCH_DATA_user;
		extent_to_replicas(k, e);
		break;
	case KEY_TYPE_stripe:
		e->data_type = BCH_DATA_parity;
		stripe_to_replicas(k, e);
		break;
	}

	bch2_replicas_entry_sort(e);
}

void bch2_devlist_to_replicas(struct bch_replicas_entry *e,
			      enum bch_data_type data_type,
			      struct bch_devs_list devs)
{
	unsigned i;

	BUG_ON(!data_type ||
	       data_type == BCH_DATA_sb ||
	       data_type >= BCH_DATA_NR);

	e->data_type	= data_type;
	e->nr_devs	= 0;
	e->nr_required	= 1;

	for (i = 0; i < devs.nr; i++)
		e->devs[e->nr_devs++] = devs.devs[i];

	bch2_replicas_entry_sort(e);
}

static struct bch_replicas_cpu
cpu_replicas_add_entry(struct bch_replicas_cpu *old,
		       struct bch_replicas_entry *new_entry)
{
	unsigned i;
	struct bch_replicas_cpu new = {
		.nr		= old->nr + 1,
		.entry_size	= max_t(unsigned, old->entry_size,
					replicas_entry_bytes(new_entry)),
	};

	BUG_ON(!new_entry->data_type);
	verify_replicas_entry(new_entry);

	new.entries = kcalloc(new.nr, new.entry_size, GFP_KERNEL);
	if (!new.entries)
		return new;

	for (i = 0; i < old->nr; i++)
		memcpy(cpu_replicas_entry(&new, i),
		       cpu_replicas_entry(old, i),
		       old->entry_size);

	memcpy(cpu_replicas_entry(&new, old->nr),
	       new_entry,
	       replicas_entry_bytes(new_entry));

	bch2_cpu_replicas_sort(&new);
	return new;
}

static inline int __replicas_entry_idx(struct bch_replicas_cpu *r,
				       struct bch_replicas_entry *search)
{
	int idx, entry_size = replicas_entry_bytes(search);

	if (unlikely(entry_size > r->entry_size))
		return -1;

	verify_replicas_entry(search);

#define entry_cmp(_l, _r, size)	memcmp(_l, _r, entry_size)
	idx = eytzinger0_find(r->entries, r->nr, r->entry_size,
			      entry_cmp, search);
#undef entry_cmp

	return idx < r->nr ? idx : -1;
}

int bch2_replicas_entry_idx(struct bch_fs *c,
			    struct bch_replicas_entry *search)
{
	bch2_replicas_entry_sort(search);

	return __replicas_entry_idx(&c->replicas, search);
}

static bool __replicas_has_entry(struct bch_replicas_cpu *r,
				 struct bch_replicas_entry *search)
{
	return __replicas_entry_idx(r, search) >= 0;
}

bool bch2_replicas_marked(struct bch_fs *c,
			  struct bch_replicas_entry *search)
{
	bool marked;

	if (!search->nr_devs)
		return true;

	verify_replicas_entry(search);

	percpu_down_read(&c->mark_lock);
	marked = __replicas_has_entry(&c->replicas, search) &&
		(likely((!c->replicas_gc.entries)) ||
		 __replicas_has_entry(&c->replicas_gc, search));
	percpu_up_read(&c->mark_lock);

	return marked;
}

static void __replicas_table_update(struct bch_fs_usage *dst,
				    struct bch_replicas_cpu *dst_r,
				    struct bch_fs_usage *src,
				    struct bch_replicas_cpu *src_r)
{
	int src_idx, dst_idx;

	*dst = *src;

	for (src_idx = 0; src_idx < src_r->nr; src_idx++) {
		if (!src->replicas[src_idx])
			continue;

		dst_idx = __replicas_entry_idx(dst_r,
				cpu_replicas_entry(src_r, src_idx));
		BUG_ON(dst_idx < 0);

		dst->replicas[dst_idx] = src->replicas[src_idx];
	}
}

static void __replicas_table_update_pcpu(struct bch_fs_usage __percpu *dst_p,
				    struct bch_replicas_cpu *dst_r,
				    struct bch_fs_usage __percpu *src_p,
				    struct bch_replicas_cpu *src_r)
{
	unsigned src_nr = sizeof(struct bch_fs_usage) / sizeof(u64) + src_r->nr;
	struct bch_fs_usage *dst, *src = (void *)
		bch2_acc_percpu_u64s((void *) src_p, src_nr);

	preempt_disable();
	dst = this_cpu_ptr(dst_p);
	preempt_enable();

	__replicas_table_update(dst, dst_r, src, src_r);
}

/*
 * Resize filesystem accounting:
 */
static int replicas_table_update(struct bch_fs *c,
				 struct bch_replicas_cpu *new_r)
{
	struct bch_fs_usage __percpu *new_usage[JOURNAL_BUF_NR];
	struct bch_fs_usage_online *new_scratch = NULL;
	struct bch_fs_usage __percpu *new_gc = NULL;
	struct bch_fs_usage *new_base = NULL;
	unsigned i, bytes = sizeof(struct bch_fs_usage) +
		sizeof(u64) * new_r->nr;
	unsigned scratch_bytes = sizeof(struct bch_fs_usage_online) +
		sizeof(u64) * new_r->nr;
	int ret = 0;

	memset(new_usage, 0, sizeof(new_usage));

	for (i = 0; i < ARRAY_SIZE(new_usage); i++)
		if (!(new_usage[i] = __alloc_percpu_gfp(bytes,
					sizeof(u64), GFP_KERNEL)))
			goto err;

	memset(new_usage, 0, sizeof(new_usage));

	for (i = 0; i < ARRAY_SIZE(new_usage); i++)
		if (!(new_usage[i] = __alloc_percpu_gfp(bytes,
					sizeof(u64), GFP_KERNEL)))
			goto err;

	if (!(new_base = kzalloc(bytes, GFP_KERNEL)) ||
	    !(new_scratch  = kmalloc(scratch_bytes, GFP_KERNEL)) ||
	    (c->usage_gc &&
	     !(new_gc = __alloc_percpu_gfp(bytes, sizeof(u64), GFP_KERNEL))))
		goto err;

	for (i = 0; i < ARRAY_SIZE(new_usage); i++)
		if (c->usage[i])
			__replicas_table_update_pcpu(new_usage[i], new_r,
						     c->usage[i], &c->replicas);
	if (c->usage_base)
		__replicas_table_update(new_base,		new_r,
					c->usage_base,		&c->replicas);
	if (c->usage_gc)
		__replicas_table_update_pcpu(new_gc,		new_r,
					     c->usage_gc,	&c->replicas);

	for (i = 0; i < ARRAY_SIZE(new_usage); i++)
		swap(c->usage[i],	new_usage[i]);
	swap(c->usage_base,	new_base);
	swap(c->usage_scratch,	new_scratch);
	swap(c->usage_gc,	new_gc);
	swap(c->replicas,	*new_r);
out:
	free_percpu(new_gc);
	kfree(new_scratch);
	for (i = 0; i < ARRAY_SIZE(new_usage); i++)
		free_percpu(new_usage[i]);
	kfree(new_base);
	return ret;
err:
	bch_err(c, "error updating replicas table: memory allocation failure");
	ret = -ENOMEM;
	goto out;
}

static unsigned reserve_journal_replicas(struct bch_fs *c,
				     struct bch_replicas_cpu *r)
{
	struct bch_replicas_entry *e;
	unsigned journal_res_u64s = 0;

	/* nr_inodes: */
	journal_res_u64s +=
		DIV_ROUND_UP(sizeof(struct jset_entry_usage), sizeof(u64));

	/* key_version: */
	journal_res_u64s +=
		DIV_ROUND_UP(sizeof(struct jset_entry_usage), sizeof(u64));

	/* persistent_reserved: */
	journal_res_u64s +=
		DIV_ROUND_UP(sizeof(struct jset_entry_usage), sizeof(u64)) *
		BCH_REPLICAS_MAX;

	for_each_cpu_replicas_entry(r, e)
		journal_res_u64s +=
			DIV_ROUND_UP(sizeof(struct jset_entry_data_usage) +
				     e->nr_devs, sizeof(u64));
	return journal_res_u64s;
}

noinline
static int bch2_mark_replicas_slowpath(struct bch_fs *c,
				struct bch_replicas_entry *new_entry)
{
	struct bch_replicas_cpu new_r, new_gc;
	int ret = 0;

	verify_replicas_entry(new_entry);

	memset(&new_r, 0, sizeof(new_r));
	memset(&new_gc, 0, sizeof(new_gc));

	mutex_lock(&c->sb_lock);

	if (c->replicas_gc.entries &&
	    !__replicas_has_entry(&c->replicas_gc, new_entry)) {
		new_gc = cpu_replicas_add_entry(&c->replicas_gc, new_entry);
		if (!new_gc.entries)
			goto err;
	}

	if (!__replicas_has_entry(&c->replicas, new_entry)) {
		new_r = cpu_replicas_add_entry(&c->replicas, new_entry);
		if (!new_r.entries)
			goto err;

		ret = bch2_cpu_replicas_to_sb_replicas(c, &new_r);
		if (ret)
			goto err;

		bch2_journal_entry_res_resize(&c->journal,
				&c->replicas_journal_res,
				reserve_journal_replicas(c, &new_r));
	}

	if (!new_r.entries &&
	    !new_gc.entries)
		goto out;

	/* allocations done, now commit: */

	if (new_r.entries)
		bch2_write_super(c);

	/* don't update in memory replicas until changes are persistent */
	percpu_down_write(&c->mark_lock);
	if (new_r.entries)
		ret = replicas_table_update(c, &new_r);
	if (new_gc.entries)
		swap(new_gc, c->replicas_gc);
	percpu_up_write(&c->mark_lock);
out:
	mutex_unlock(&c->sb_lock);

	kfree(new_r.entries);
	kfree(new_gc.entries);

	return ret;
err:
	bch_err(c, "error adding replicas entry: memory allocation failure");
	ret = -ENOMEM;
	goto out;
}

static int __bch2_mark_replicas(struct bch_fs *c,
				struct bch_replicas_entry *r,
				bool check)
{
	return likely(bch2_replicas_marked(c, r))	? 0
		: check					? -1
		: bch2_mark_replicas_slowpath(c, r);
}

int bch2_mark_replicas(struct bch_fs *c, struct bch_replicas_entry *r)
{
	return __bch2_mark_replicas(c, r, false);
}

static int __bch2_mark_bkey_replicas(struct bch_fs *c, struct bkey_s_c k,
				     bool check)
{
	struct bch_replicas_padded search;
	struct bch_devs_list cached = bch2_bkey_cached_devs(k);
	unsigned i;
	int ret;

	memset(&search, 0, sizeof(search));

	for (i = 0; i < cached.nr; i++) {
		bch2_replicas_entry_cached(&search.e, cached.devs[i]);

		ret = __bch2_mark_replicas(c, &search.e, check);
		if (ret)
			return ret;
	}

	bch2_bkey_to_replicas(&search.e, k);

	ret = __bch2_mark_replicas(c, &search.e, check);
	if (ret)
		return ret;

	if (search.e.data_type == BCH_DATA_parity) {
		search.e.data_type = BCH_DATA_cached;
		ret = __bch2_mark_replicas(c, &search.e, check);
		if (ret)
			return ret;

		search.e.data_type = BCH_DATA_user;
		ret = __bch2_mark_replicas(c, &search.e, check);
		if (ret)
			return ret;
	}

	return 0;
}

/* replicas delta list: */

bool bch2_replicas_delta_list_marked(struct bch_fs *c,
				     struct replicas_delta_list *r)
{
	struct replicas_delta *d = r->d;
	struct replicas_delta *top = (void *) r->d + r->used;

	percpu_rwsem_assert_held(&c->mark_lock);

	for (d = r->d; d != top; d = replicas_delta_next(d))
		if (bch2_replicas_entry_idx(c, &d->r) < 0)
			return false;
	return true;
}

int bch2_replicas_delta_list_mark(struct bch_fs *c,
				  struct replicas_delta_list *r)
{
	struct replicas_delta *d = r->d;
	struct replicas_delta *top = (void *) r->d + r->used;
	int ret = 0;

	for (d = r->d; !ret && d != top; d = replicas_delta_next(d))
		ret = bch2_mark_replicas(c, &d->r);
	return ret;
}

/* bkey replicas: */

bool bch2_bkey_replicas_marked(struct bch_fs *c,
			       struct bkey_s_c k)
{
	return __bch2_mark_bkey_replicas(c, k, true) == 0;
}

int bch2_mark_bkey_replicas(struct bch_fs *c, struct bkey_s_c k)
{
	return __bch2_mark_bkey_replicas(c, k, false);
}

/*
 * Old replicas_gc mechanism: only used for journal replicas entries now, should
 * die at some point:
 */

int bch2_replicas_gc_end(struct bch_fs *c, int ret)
{
	unsigned i;

	lockdep_assert_held(&c->replicas_gc_lock);

	mutex_lock(&c->sb_lock);
	percpu_down_write(&c->mark_lock);

	/*
	 * this is kind of crappy; the replicas gc mechanism needs to be ripped
	 * out
	 */

	for (i = 0; i < c->replicas.nr; i++) {
		struct bch_replicas_entry *e =
			cpu_replicas_entry(&c->replicas, i);
		struct bch_replicas_cpu n;

		if (!__replicas_has_entry(&c->replicas_gc, e) &&
		    bch2_fs_usage_read_one(c, &c->usage_base->replicas[i])) {
			n = cpu_replicas_add_entry(&c->replicas_gc, e);
			if (!n.entries) {
				ret = -ENOSPC;
				goto err;
			}

			swap(n, c->replicas_gc);
			kfree(n.entries);
		}
	}

	if (bch2_cpu_replicas_to_sb_replicas(c, &c->replicas_gc)) {
		ret = -ENOSPC;
		goto err;
	}

	ret = replicas_table_update(c, &c->replicas_gc);
err:
	kfree(c->replicas_gc.entries);
	c->replicas_gc.entries = NULL;

	percpu_up_write(&c->mark_lock);

	if (!ret)
		bch2_write_super(c);

	mutex_unlock(&c->sb_lock);

	return ret;
}

int bch2_replicas_gc_start(struct bch_fs *c, unsigned typemask)
{
	struct bch_replicas_entry *e;
	unsigned i = 0;

	lockdep_assert_held(&c->replicas_gc_lock);

	mutex_lock(&c->sb_lock);
	BUG_ON(c->replicas_gc.entries);

	c->replicas_gc.nr		= 0;
	c->replicas_gc.entry_size	= 0;

	for_each_cpu_replicas_entry(&c->replicas, e)
		if (!((1 << e->data_type) & typemask)) {
			c->replicas_gc.nr++;
			c->replicas_gc.entry_size =
				max_t(unsigned, c->replicas_gc.entry_size,
				      replicas_entry_bytes(e));
		}

	c->replicas_gc.entries = kcalloc(c->replicas_gc.nr,
					 c->replicas_gc.entry_size,
					 GFP_KERNEL);
	if (!c->replicas_gc.entries) {
		mutex_unlock(&c->sb_lock);
		bch_err(c, "error allocating c->replicas_gc");
		return -ENOMEM;
	}

	for_each_cpu_replicas_entry(&c->replicas, e)
		if (!((1 << e->data_type) & typemask))
			memcpy(cpu_replicas_entry(&c->replicas_gc, i++),
			       e, c->replicas_gc.entry_size);

	bch2_cpu_replicas_sort(&c->replicas_gc);
	mutex_unlock(&c->sb_lock);

	return 0;
}

/* New much simpler mechanism for clearing out unneeded replicas entries: */

int bch2_replicas_gc2(struct bch_fs *c)
{
	struct bch_replicas_cpu new = { 0 };
	unsigned i, nr;
	int ret = 0;

	bch2_journal_meta(&c->journal);
retry:
	nr		= READ_ONCE(c->replicas.nr);
	new.entry_size	= READ_ONCE(c->replicas.entry_size);
	new.entries	= kcalloc(nr, new.entry_size, GFP_KERNEL);
	if (!new.entries) {
		bch_err(c, "error allocating c->replicas_gc");
		return -ENOMEM;
	}

	mutex_lock(&c->sb_lock);
	percpu_down_write(&c->mark_lock);

	if (nr			!= c->replicas.nr ||
	    new.entry_size	!= c->replicas.entry_size) {
		percpu_up_write(&c->mark_lock);
		mutex_unlock(&c->sb_lock);
		kfree(new.entries);
		goto retry;
	}

	for (i = 0; i < c->replicas.nr; i++) {
		struct bch_replicas_entry *e =
			cpu_replicas_entry(&c->replicas, i);

		if (e->data_type == BCH_DATA_journal ||
		    c->usage_base->replicas[i] ||
		    percpu_u64_get(&c->usage[0]->replicas[i]) ||
		    percpu_u64_get(&c->usage[1]->replicas[i]) ||
		    percpu_u64_get(&c->usage[2]->replicas[i]) ||
		    percpu_u64_get(&c->usage[3]->replicas[i]))
			memcpy(cpu_replicas_entry(&new, new.nr++),
			       e, new.entry_size);
	}

	bch2_cpu_replicas_sort(&new);

	if (bch2_cpu_replicas_to_sb_replicas(c, &new)) {
		ret = -ENOSPC;
		goto err;
	}

	ret = replicas_table_update(c, &new);
err:
	kfree(new.entries);

	percpu_up_write(&c->mark_lock);

	if (!ret)
		bch2_write_super(c);

	mutex_unlock(&c->sb_lock);

	return ret;
}

int bch2_replicas_set_usage(struct bch_fs *c,
			    struct bch_replicas_entry *r,
			    u64 sectors)
{
	int ret, idx = bch2_replicas_entry_idx(c, r);

	if (idx < 0) {
		struct bch_replicas_cpu n;

		n = cpu_replicas_add_entry(&c->replicas, r);
		if (!n.entries)
			return -ENOMEM;

		ret = replicas_table_update(c, &n);
		if (ret)
			return ret;

		kfree(n.entries);

		idx = bch2_replicas_entry_idx(c, r);
		BUG_ON(ret < 0);
	}

	c->usage_base->replicas[idx] = sectors;

	return 0;
}

/* Replicas tracking - superblock: */

static int
__bch2_sb_replicas_to_cpu_replicas(struct bch_sb_field_replicas *sb_r,
				   struct bch_replicas_cpu *cpu_r)
{
	struct bch_replicas_entry *e, *dst;
	unsigned nr = 0, entry_size = 0, idx = 0;

	for_each_replicas_entry(sb_r, e) {
		entry_size = max_t(unsigned, entry_size,
				   replicas_entry_bytes(e));
		nr++;
	}

	cpu_r->entries = kcalloc(nr, entry_size, GFP_KERNEL);
	if (!cpu_r->entries)
		return -ENOMEM;

	cpu_r->nr		= nr;
	cpu_r->entry_size	= entry_size;

	for_each_replicas_entry(sb_r, e) {
		dst = cpu_replicas_entry(cpu_r, idx++);
		memcpy(dst, e, replicas_entry_bytes(e));
		bch2_replicas_entry_sort(dst);
	}

	return 0;
}

static int
__bch2_sb_replicas_v0_to_cpu_replicas(struct bch_sb_field_replicas_v0 *sb_r,
				      struct bch_replicas_cpu *cpu_r)
{
	struct bch_replicas_entry_v0 *e;
	unsigned nr = 0, entry_size = 0, idx = 0;

	for_each_replicas_entry(sb_r, e) {
		entry_size = max_t(unsigned, entry_size,
				   replicas_entry_bytes(e));
		nr++;
	}

	entry_size += sizeof(struct bch_replicas_entry) -
		sizeof(struct bch_replicas_entry_v0);

	cpu_r->entries = kcalloc(nr, entry_size, GFP_KERNEL);
	if (!cpu_r->entries)
		return -ENOMEM;

	cpu_r->nr		= nr;
	cpu_r->entry_size	= entry_size;

	for_each_replicas_entry(sb_r, e) {
		struct bch_replicas_entry *dst =
			cpu_replicas_entry(cpu_r, idx++);

		dst->data_type	= e->data_type;
		dst->nr_devs	= e->nr_devs;
		dst->nr_required = 1;
		memcpy(dst->devs, e->devs, e->nr_devs);
		bch2_replicas_entry_sort(dst);
	}

	return 0;
}

int bch2_sb_replicas_to_cpu_replicas(struct bch_fs *c)
{
	struct bch_sb_field_replicas *sb_v1;
	struct bch_sb_field_replicas_v0 *sb_v0;
	struct bch_replicas_cpu new_r = { 0, 0, NULL };
	int ret = 0;

	if ((sb_v1 = bch2_sb_get_replicas(c->disk_sb.sb)))
		ret = __bch2_sb_replicas_to_cpu_replicas(sb_v1, &new_r);
	else if ((sb_v0 = bch2_sb_get_replicas_v0(c->disk_sb.sb)))
		ret = __bch2_sb_replicas_v0_to_cpu_replicas(sb_v0, &new_r);

	if (ret)
		return -ENOMEM;

	bch2_cpu_replicas_sort(&new_r);

	percpu_down_write(&c->mark_lock);

	ret = replicas_table_update(c, &new_r);
	percpu_up_write(&c->mark_lock);

	kfree(new_r.entries);

	return 0;
}

static int bch2_cpu_replicas_to_sb_replicas_v0(struct bch_fs *c,
					       struct bch_replicas_cpu *r)
{
	struct bch_sb_field_replicas_v0 *sb_r;
	struct bch_replicas_entry_v0 *dst;
	struct bch_replicas_entry *src;
	size_t bytes;

	bytes = sizeof(struct bch_sb_field_replicas);

	for_each_cpu_replicas_entry(r, src)
		bytes += replicas_entry_bytes(src) - 1;

	sb_r = bch2_sb_resize_replicas_v0(&c->disk_sb,
			DIV_ROUND_UP(bytes, sizeof(u64)));
	if (!sb_r)
		return -ENOSPC;

	bch2_sb_field_delete(&c->disk_sb, BCH_SB_FIELD_replicas);
	sb_r = bch2_sb_get_replicas_v0(c->disk_sb.sb);

	memset(&sb_r->entries, 0,
	       vstruct_end(&sb_r->field) -
	       (void *) &sb_r->entries);

	dst = sb_r->entries;
	for_each_cpu_replicas_entry(r, src) {
		dst->data_type	= src->data_type;
		dst->nr_devs	= src->nr_devs;
		memcpy(dst->devs, src->devs, src->nr_devs);

		dst = replicas_entry_next(dst);

		BUG_ON((void *) dst > vstruct_end(&sb_r->field));
	}

	return 0;
}

static int bch2_cpu_replicas_to_sb_replicas(struct bch_fs *c,
					    struct bch_replicas_cpu *r)
{
	struct bch_sb_field_replicas *sb_r;
	struct bch_replicas_entry *dst, *src;
	bool need_v1 = false;
	size_t bytes;

	bytes = sizeof(struct bch_sb_field_replicas);

	for_each_cpu_replicas_entry(r, src) {
		bytes += replicas_entry_bytes(src);
		if (src->nr_required != 1)
			need_v1 = true;
	}

	if (!need_v1)
		return bch2_cpu_replicas_to_sb_replicas_v0(c, r);

	sb_r = bch2_sb_resize_replicas(&c->disk_sb,
			DIV_ROUND_UP(bytes, sizeof(u64)));
	if (!sb_r)
		return -ENOSPC;

	bch2_sb_field_delete(&c->disk_sb, BCH_SB_FIELD_replicas_v0);
	sb_r = bch2_sb_get_replicas(c->disk_sb.sb);

	memset(&sb_r->entries, 0,
	       vstruct_end(&sb_r->field) -
	       (void *) &sb_r->entries);

	dst = sb_r->entries;
	for_each_cpu_replicas_entry(r, src) {
		memcpy(dst, src, replicas_entry_bytes(src));

		dst = replicas_entry_next(dst);

		BUG_ON((void *) dst > vstruct_end(&sb_r->field));
	}

	return 0;
}

static const char *check_dup_replicas_entries(struct bch_replicas_cpu *cpu_r)
{
	unsigned i;

	sort_cmp_size(cpu_r->entries,
		      cpu_r->nr,
		      cpu_r->entry_size,
		      memcmp, NULL);

	for (i = 0; i + 1 < cpu_r->nr; i++) {
		struct bch_replicas_entry *l =
			cpu_replicas_entry(cpu_r, i);
		struct bch_replicas_entry *r =
			cpu_replicas_entry(cpu_r, i + 1);

		BUG_ON(memcmp(l, r, cpu_r->entry_size) > 0);

		if (!memcmp(l, r, cpu_r->entry_size))
			return "duplicate replicas entry";
	}

	return NULL;
}

static const char *bch2_sb_validate_replicas(struct bch_sb *sb, struct bch_sb_field *f)
{
	struct bch_sb_field_replicas *sb_r = field_to_type(f, replicas);
	struct bch_sb_field_members *mi = bch2_sb_get_members(sb);
	struct bch_replicas_cpu cpu_r = { .entries = NULL };
	struct bch_replicas_entry *e;
	const char *err;
	unsigned i;

	for_each_replicas_entry(sb_r, e) {
		err = "invalid replicas entry: invalid data type";
		if (e->data_type >= BCH_DATA_NR)
			goto err;

		err = "invalid replicas entry: no devices";
		if (!e->nr_devs)
			goto err;

		err = "invalid replicas entry: bad nr_required";
		if (e->nr_required > 1 &&
		    e->nr_required >= e->nr_devs)
			goto err;

		err = "invalid replicas entry: invalid device";
		for (i = 0; i < e->nr_devs; i++)
			if (!bch2_dev_exists(sb, mi, e->devs[i]))
				goto err;
	}

	err = "cannot allocate memory";
	if (__bch2_sb_replicas_to_cpu_replicas(sb_r, &cpu_r))
		goto err;

	err = check_dup_replicas_entries(&cpu_r);
err:
	kfree(cpu_r.entries);
	return err;
}

static void bch2_sb_replicas_to_text(struct printbuf *out,
				     struct bch_sb *sb,
				     struct bch_sb_field *f)
{
	struct bch_sb_field_replicas *r = field_to_type(f, replicas);
	struct bch_replicas_entry *e;
	bool first = true;

	for_each_replicas_entry(r, e) {
		if (!first)
			pr_buf(out, " ");
		first = false;

		bch2_replicas_entry_to_text(out, e);
	}
}

const struct bch_sb_field_ops bch_sb_field_ops_replicas = {
	.validate	= bch2_sb_validate_replicas,
	.to_text	= bch2_sb_replicas_to_text,
};

static const char *bch2_sb_validate_replicas_v0(struct bch_sb *sb, struct bch_sb_field *f)
{
	struct bch_sb_field_replicas_v0 *sb_r = field_to_type(f, replicas_v0);
	struct bch_sb_field_members *mi = bch2_sb_get_members(sb);
	struct bch_replicas_cpu cpu_r = { .entries = NULL };
	struct bch_replicas_entry_v0 *e;
	const char *err;
	unsigned i;

	for_each_replicas_entry_v0(sb_r, e) {
		err = "invalid replicas entry: invalid data type";
		if (e->data_type >= BCH_DATA_NR)
			goto err;

		err = "invalid replicas entry: no devices";
		if (!e->nr_devs)
			goto err;

		err = "invalid replicas entry: invalid device";
		for (i = 0; i < e->nr_devs; i++)
			if (!bch2_dev_exists(sb, mi, e->devs[i]))
				goto err;
	}

	err = "cannot allocate memory";
	if (__bch2_sb_replicas_v0_to_cpu_replicas(sb_r, &cpu_r))
		goto err;

	err = check_dup_replicas_entries(&cpu_r);
err:
	kfree(cpu_r.entries);
	return err;
}

const struct bch_sb_field_ops bch_sb_field_ops_replicas_v0 = {
	.validate	= bch2_sb_validate_replicas_v0,
};

/* Query replicas: */

bool bch2_have_enough_devs(struct bch_fs *c, struct bch_devs_mask devs,
			   unsigned flags, bool print)
{
	struct bch_replicas_entry *e;
	bool ret = true;

	percpu_down_read(&c->mark_lock);
	for_each_cpu_replicas_entry(&c->replicas, e) {
		unsigned i, nr_online = 0, nr_failed = 0, dflags = 0;
		bool metadata = e->data_type < BCH_DATA_user;

		for (i = 0; i < e->nr_devs; i++) {
			struct bch_dev *ca = bch_dev_bkey_exists(c, e->devs[i]);

			nr_online += test_bit(e->devs[i], devs.d);
			nr_failed += ca->mi.state == BCH_MEMBER_STATE_failed;
		}

		if (nr_failed == e->nr_devs)
			continue;

		if (nr_online < e->nr_required)
			dflags |= metadata
				? BCH_FORCE_IF_METADATA_LOST
				: BCH_FORCE_IF_DATA_LOST;

		if (nr_online < e->nr_devs)
			dflags |= metadata
				? BCH_FORCE_IF_METADATA_DEGRADED
				: BCH_FORCE_IF_DATA_DEGRADED;

		if (dflags & ~flags) {
			if (print) {
				char buf[100];

				bch2_replicas_entry_to_text(&PBUF(buf), e);
				bch_err(c, "insufficient devices online (%u) for replicas entry %s",
					nr_online, buf);
			}
			ret = false;
			break;
		}

	}
	percpu_up_read(&c->mark_lock);

	return ret;
}

unsigned bch2_dev_has_data(struct bch_fs *c, struct bch_dev *ca)
{
	struct bch_replicas_entry *e;
	unsigned i, ret = 0;

	percpu_down_read(&c->mark_lock);

	for_each_cpu_replicas_entry(&c->replicas, e)
		for (i = 0; i < e->nr_devs; i++)
			if (e->devs[i] == ca->dev_idx)
				ret |= 1 << e->data_type;

	percpu_up_read(&c->mark_lock);

	return ret;
}

void bch2_fs_replicas_exit(struct bch_fs *c)
{
	unsigned i;

	kfree(c->usage_scratch);
	for (i = 0; i < ARRAY_SIZE(c->usage); i++)
		free_percpu(c->usage[i]);
	kfree(c->usage_base);
	kfree(c->replicas.entries);
	kfree(c->replicas_gc.entries);

	mempool_exit(&c->replicas_delta_pool);
}

int bch2_fs_replicas_init(struct bch_fs *c)
{
	bch2_journal_entry_res_resize(&c->journal,
			&c->replicas_journal_res,
			reserve_journal_replicas(c, &c->replicas));

	return mempool_init_kmalloc_pool(&c->replicas_delta_pool, 1,
					 REPLICAS_DELTA_LIST_MAX) ?:
		replicas_table_update(c, &c->replicas);
}
