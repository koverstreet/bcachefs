// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "buckets.h"
#include "journal.h"
#include "replicas.h"
#include "super-io.h"

#include <linux/sort.h>

static int bch2_cpu_replicas_to_sb_replicas(struct bch_fs *,
					    struct bch_replicas_cpu *);

/* Some (buggy!) compilers don't allow memcmp to be passed as a pointer */
static int bch2_memcmp(const void *l, const void *r,  const void *priv)
{
	size_t size = (size_t) priv;
	return memcmp(l, r, size);
}

/* Replicas tracking - in memory: */

static void verify_replicas_entry(struct bch_replicas_entry_v1 *e)
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

void bch2_replicas_entry_sort(struct bch_replicas_entry_v1 *e)
{
	bubble_sort(e->devs, e->nr_devs, u8_cmp);
}

static void bch2_cpu_replicas_sort(struct bch_replicas_cpu *r)
{
	eytzinger0_sort_r(r->entries, r->nr, r->entry_size,
			  bch2_memcmp, NULL, (void *)(size_t)r->entry_size);
}

static void bch2_replicas_entry_v0_to_text(struct printbuf *out,
					   struct bch_replicas_entry_v0 *e)
{
	bch2_prt_data_type(out, e->data_type);

	prt_printf(out, ": %u [", e->nr_devs);
	for (unsigned i = 0; i < e->nr_devs; i++)
		prt_printf(out, i ? " %u" : "%u", e->devs[i]);
	prt_printf(out, "]");
}

void bch2_replicas_entry_to_text(struct printbuf *out,
				 struct bch_replicas_entry_v1 *e)
{
	bch2_prt_data_type(out, e->data_type);

	prt_printf(out, ": %u/%u [", e->nr_required, e->nr_devs);
	for (unsigned i = 0; i < e->nr_devs; i++)
		prt_printf(out, i ? " %u" : "%u", e->devs[i]);
	prt_printf(out, "]");
}

int bch2_replicas_entry_validate(struct bch_replicas_entry_v1 *r,
				 struct bch_sb *sb,
				 struct printbuf *err)
{
	if (!r->nr_devs) {
		prt_printf(err, "no devices in entry ");
		goto bad;
	}

	if (r->nr_required > 1 &&
	    r->nr_required >= r->nr_devs) {
		prt_printf(err, "bad nr_required in entry ");
		goto bad;
	}

	for (unsigned i = 0; i < r->nr_devs; i++)
		if (!bch2_dev_exists(sb, r->devs[i])) {
			prt_printf(err, "invalid device %u in entry ", r->devs[i]);
			goto bad;
		}

	return 0;
bad:
	bch2_replicas_entry_to_text(err, r);
	return -BCH_ERR_invalid_replicas_entry;
}

void bch2_cpu_replicas_to_text(struct printbuf *out,
			       struct bch_replicas_cpu *r)
{
	struct bch_replicas_entry_v1 *e;
	bool first = true;

	for_each_cpu_replicas_entry(r, e) {
		if (!first)
			prt_printf(out, " ");
		first = false;

		bch2_replicas_entry_to_text(out, e);
	}
}

static void extent_to_replicas(struct bkey_s_c k,
			       struct bch_replicas_entry_v1 *r)
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
			       struct bch_replicas_entry_v1 *r)
{
	struct bkey_s_c_stripe s = bkey_s_c_to_stripe(k);
	const struct bch_extent_ptr *ptr;

	r->nr_required	= s.v->nr_blocks - s.v->nr_redundant;

	for (ptr = s.v->ptrs;
	     ptr < s.v->ptrs + s.v->nr_blocks;
	     ptr++)
		r->devs[r->nr_devs++] = ptr->dev;
}

void bch2_bkey_to_replicas(struct bch_replicas_entry_v1 *e,
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

void bch2_devlist_to_replicas(struct bch_replicas_entry_v1 *e,
			      enum bch_data_type data_type,
			      struct bch_devs_list devs)
{
	BUG_ON(!data_type ||
	       data_type == BCH_DATA_sb ||
	       data_type >= BCH_DATA_NR);

	e->data_type	= data_type;
	e->nr_devs	= 0;
	e->nr_required	= 1;

	darray_for_each(devs, i)
		e->devs[e->nr_devs++] = *i;

	bch2_replicas_entry_sort(e);
}

static struct bch_replicas_cpu
cpu_replicas_add_entry(struct bch_fs *c,
		       struct bch_replicas_cpu *old,
		       struct bch_replicas_entry_v1 *new_entry)
{
	unsigned i;
	struct bch_replicas_cpu new = {
		.nr		= old->nr + 1,
		.entry_size	= max_t(unsigned, old->entry_size,
					replicas_entry_bytes(new_entry)),
	};

	for (i = 0; i < new_entry->nr_devs; i++)
		BUG_ON(!bch2_dev_exists2(c, new_entry->devs[i]));

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
				       struct bch_replicas_entry_v1 *search)
{
	int idx, entry_size = replicas_entry_bytes(search);

	if (unlikely(entry_size > r->entry_size))
		return -1;

	verify_replicas_entry(search);

#define entry_cmp(_l, _r)	memcmp(_l, _r, entry_size)
	idx = eytzinger0_find(r->entries, r->nr, r->entry_size,
			      entry_cmp, search);
#undef entry_cmp

	return idx < r->nr ? idx : -1;
}

int bch2_replicas_entry_idx(struct bch_fs *c,
			    struct bch_replicas_entry_v1 *search)
{
	bch2_replicas_entry_sort(search);

	return __replicas_entry_idx(&c->replicas, search);
}

static bool __replicas_has_entry(struct bch_replicas_cpu *r,
				 struct bch_replicas_entry_v1 *search)
{
	return __replicas_entry_idx(r, search) >= 0;
}

bool bch2_replicas_marked(struct bch_fs *c,
			  struct bch_replicas_entry_v1 *search)
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
		bch2_acc_percpu_u64s((u64 __percpu *) src_p, src_nr);

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
	ret = -BCH_ERR_ENOMEM_replicas_table;
	goto out;
}

static unsigned reserve_journal_replicas(struct bch_fs *c,
				     struct bch_replicas_cpu *r)
{
	struct bch_replicas_entry_v1 *e;
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
				struct bch_replicas_entry_v1 *new_entry)
{
	struct bch_replicas_cpu new_r, new_gc;
	int ret = 0;

	verify_replicas_entry(new_entry);

	memset(&new_r, 0, sizeof(new_r));
	memset(&new_gc, 0, sizeof(new_gc));

	mutex_lock(&c->sb_lock);

	if (c->replicas_gc.entries &&
	    !__replicas_has_entry(&c->replicas_gc, new_entry)) {
		new_gc = cpu_replicas_add_entry(c, &c->replicas_gc, new_entry);
		if (!new_gc.entries) {
			ret = -BCH_ERR_ENOMEM_cpu_replicas;
			goto err;
		}
	}

	if (!__replicas_has_entry(&c->replicas, new_entry)) {
		new_r = cpu_replicas_add_entry(c, &c->replicas, new_entry);
		if (!new_r.entries) {
			ret = -BCH_ERR_ENOMEM_cpu_replicas;
			goto err;
		}

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
	bch_err_msg(c, ret, "adding replicas entry");
	goto out;
}

int bch2_mark_replicas(struct bch_fs *c, struct bch_replicas_entry_v1 *r)
{
	return likely(bch2_replicas_marked(c, r))
		? 0 : bch2_mark_replicas_slowpath(c, r);
}

/* replicas delta list: */

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

/*
 * Old replicas_gc mechanism: only used for journal replicas entries now, should
 * die at some point:
 */

int bch2_replicas_gc_end(struct bch_fs *c, int ret)
{
	lockdep_assert_held(&c->replicas_gc_lock);

	mutex_lock(&c->sb_lock);
	percpu_down_write(&c->mark_lock);

	ret =   ret ?:
		bch2_cpu_replicas_to_sb_replicas(c, &c->replicas_gc) ?:
		replicas_table_update(c, &c->replicas_gc);

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
	struct bch_replicas_entry_v1 *e;
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
		return -BCH_ERR_ENOMEM_replicas_gc;
	}

	for_each_cpu_replicas_entry(&c->replicas, e)
		if (!((1 << e->data_type) & typemask))
			memcpy(cpu_replicas_entry(&c->replicas_gc, i++),
			       e, c->replicas_gc.entry_size);

	bch2_cpu_replicas_sort(&c->replicas_gc);
	mutex_unlock(&c->sb_lock);

	return 0;
}

/*
 * New much simpler mechanism for clearing out unneeded replicas entries - drop
 * replicas entries that have 0 sectors used.
 *
 * However, we don't track sector counts for journal usage, so this doesn't drop
 * any BCH_DATA_journal entries; the old bch2_replicas_gc_(start|end) mechanism
 * is retained for that.
 */
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
		return -BCH_ERR_ENOMEM_replicas_gc;
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
		struct bch_replicas_entry_v1 *e =
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

	ret =   bch2_cpu_replicas_to_sb_replicas(c, &new) ?:
		replicas_table_update(c, &new);

	kfree(new.entries);

	percpu_up_write(&c->mark_lock);

	if (!ret)
		bch2_write_super(c);

	mutex_unlock(&c->sb_lock);

	return ret;
}

int bch2_replicas_set_usage(struct bch_fs *c,
			    struct bch_replicas_entry_v1 *r,
			    u64 sectors)
{
	int ret, idx = bch2_replicas_entry_idx(c, r);

	if (idx < 0) {
		struct bch_replicas_cpu n;

		n = cpu_replicas_add_entry(c, &c->replicas, r);
		if (!n.entries)
			return -BCH_ERR_ENOMEM_cpu_replicas;

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
	struct bch_replicas_entry_v1 *e, *dst;
	unsigned nr = 0, entry_size = 0, idx = 0;

	for_each_replicas_entry(sb_r, e) {
		entry_size = max_t(unsigned, entry_size,
				   replicas_entry_bytes(e));
		nr++;
	}

	cpu_r->entries = kcalloc(nr, entry_size, GFP_KERNEL);
	if (!cpu_r->entries)
		return -BCH_ERR_ENOMEM_cpu_replicas;

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

	entry_size += sizeof(struct bch_replicas_entry_v1) -
		sizeof(struct bch_replicas_entry_v0);

	cpu_r->entries = kcalloc(nr, entry_size, GFP_KERNEL);
	if (!cpu_r->entries)
		return -BCH_ERR_ENOMEM_cpu_replicas;

	cpu_r->nr		= nr;
	cpu_r->entry_size	= entry_size;

	for_each_replicas_entry(sb_r, e) {
		struct bch_replicas_entry_v1 *dst =
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

	if ((sb_v1 = bch2_sb_field_get(c->disk_sb.sb, replicas)))
		ret = __bch2_sb_replicas_to_cpu_replicas(sb_v1, &new_r);
	else if ((sb_v0 = bch2_sb_field_get(c->disk_sb.sb, replicas_v0)))
		ret = __bch2_sb_replicas_v0_to_cpu_replicas(sb_v0, &new_r);
	if (ret)
		return ret;

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
	struct bch_replicas_entry_v1 *src;
	size_t bytes;

	bytes = sizeof(struct bch_sb_field_replicas);

	for_each_cpu_replicas_entry(r, src)
		bytes += replicas_entry_bytes(src) - 1;

	sb_r = bch2_sb_field_resize(&c->disk_sb, replicas_v0,
			DIV_ROUND_UP(bytes, sizeof(u64)));
	if (!sb_r)
		return -BCH_ERR_ENOSPC_sb_replicas;

	bch2_sb_field_delete(&c->disk_sb, BCH_SB_FIELD_replicas);
	sb_r = bch2_sb_field_get(c->disk_sb.sb, replicas_v0);

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
	struct bch_replicas_entry_v1 *dst, *src;
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

	sb_r = bch2_sb_field_resize(&c->disk_sb, replicas,
			DIV_ROUND_UP(bytes, sizeof(u64)));
	if (!sb_r)
		return -BCH_ERR_ENOSPC_sb_replicas;

	bch2_sb_field_delete(&c->disk_sb, BCH_SB_FIELD_replicas_v0);
	sb_r = bch2_sb_field_get(c->disk_sb.sb, replicas);

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

static int bch2_cpu_replicas_validate(struct bch_replicas_cpu *cpu_r,
				      struct bch_sb *sb,
				      struct printbuf *err)
{
	unsigned i;

	sort_r(cpu_r->entries,
	       cpu_r->nr,
	       cpu_r->entry_size,
	       bch2_memcmp, NULL,
	       (void *)(size_t)cpu_r->entry_size);

	for (i = 0; i < cpu_r->nr; i++) {
		struct bch_replicas_entry_v1 *e =
			cpu_replicas_entry(cpu_r, i);

		int ret = bch2_replicas_entry_validate(e, sb, err);
		if (ret)
			return ret;

		if (i + 1 < cpu_r->nr) {
			struct bch_replicas_entry_v1 *n =
				cpu_replicas_entry(cpu_r, i + 1);

			BUG_ON(memcmp(e, n, cpu_r->entry_size) > 0);

			if (!memcmp(e, n, cpu_r->entry_size)) {
				prt_printf(err, "duplicate replicas entry ");
				bch2_replicas_entry_to_text(err, e);
				return -BCH_ERR_invalid_sb_replicas;
			}
		}
	}

	return 0;
}

static int bch2_sb_replicas_validate(struct bch_sb *sb, struct bch_sb_field *f,
				     struct printbuf *err)
{
	struct bch_sb_field_replicas *sb_r = field_to_type(f, replicas);
	struct bch_replicas_cpu cpu_r;
	int ret;

	ret = __bch2_sb_replicas_to_cpu_replicas(sb_r, &cpu_r);
	if (ret)
		return ret;

	ret = bch2_cpu_replicas_validate(&cpu_r, sb, err);
	kfree(cpu_r.entries);
	return ret;
}

static void bch2_sb_replicas_to_text(struct printbuf *out,
				     struct bch_sb *sb,
				     struct bch_sb_field *f)
{
	struct bch_sb_field_replicas *r = field_to_type(f, replicas);
	struct bch_replicas_entry_v1 *e;
	bool first = true;

	for_each_replicas_entry(r, e) {
		if (!first)
			prt_printf(out, " ");
		first = false;

		bch2_replicas_entry_to_text(out, e);
	}
	prt_newline(out);
}

const struct bch_sb_field_ops bch_sb_field_ops_replicas = {
	.validate	= bch2_sb_replicas_validate,
	.to_text	= bch2_sb_replicas_to_text,
};

static int bch2_sb_replicas_v0_validate(struct bch_sb *sb, struct bch_sb_field *f,
					struct printbuf *err)
{
	struct bch_sb_field_replicas_v0 *sb_r = field_to_type(f, replicas_v0);
	struct bch_replicas_cpu cpu_r;
	int ret;

	ret = __bch2_sb_replicas_v0_to_cpu_replicas(sb_r, &cpu_r);
	if (ret)
		return ret;

	ret = bch2_cpu_replicas_validate(&cpu_r, sb, err);
	kfree(cpu_r.entries);
	return ret;
}

static void bch2_sb_replicas_v0_to_text(struct printbuf *out,
					struct bch_sb *sb,
					struct bch_sb_field *f)
{
	struct bch_sb_field_replicas_v0 *sb_r = field_to_type(f, replicas_v0);
	struct bch_replicas_entry_v0 *e;
	bool first = true;

	for_each_replicas_entry(sb_r, e) {
		if (!first)
			prt_printf(out, " ");
		first = false;

		bch2_replicas_entry_v0_to_text(out, e);
	}
	prt_newline(out);
}

const struct bch_sb_field_ops bch_sb_field_ops_replicas_v0 = {
	.validate	= bch2_sb_replicas_v0_validate,
	.to_text	= bch2_sb_replicas_v0_to_text,
};

/* Query replicas: */

bool bch2_have_enough_devs(struct bch_fs *c, struct bch_devs_mask devs,
			   unsigned flags, bool print)
{
	struct bch_replicas_entry_v1 *e;
	bool ret = true;

	percpu_down_read(&c->mark_lock);
	for_each_cpu_replicas_entry(&c->replicas, e) {
		unsigned i, nr_online = 0, nr_failed = 0, dflags = 0;
		bool metadata = e->data_type < BCH_DATA_user;

		if (e->data_type == BCH_DATA_cached)
			continue;

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
				struct printbuf buf = PRINTBUF;

				bch2_replicas_entry_to_text(&buf, e);
				bch_err(c, "insufficient devices online (%u) for replicas entry %s",
					nr_online, buf.buf);
				printbuf_exit(&buf);
			}
			ret = false;
			break;
		}

	}
	percpu_up_read(&c->mark_lock);

	return ret;
}

unsigned bch2_sb_dev_has_data(struct bch_sb *sb, unsigned dev)
{
	struct bch_sb_field_replicas *replicas;
	struct bch_sb_field_replicas_v0 *replicas_v0;
	unsigned i, data_has = 0;

	replicas = bch2_sb_field_get(sb, replicas);
	replicas_v0 = bch2_sb_field_get(sb, replicas_v0);

	if (replicas) {
		struct bch_replicas_entry_v1 *r;

		for_each_replicas_entry(replicas, r)
			for (i = 0; i < r->nr_devs; i++)
				if (r->devs[i] == dev)
					data_has |= 1 << r->data_type;
	} else if (replicas_v0) {
		struct bch_replicas_entry_v0 *r;

		for_each_replicas_entry_v0(replicas_v0, r)
			for (i = 0; i < r->nr_devs; i++)
				if (r->devs[i] == dev)
					data_has |= 1 << r->data_type;
	}


	return data_has;
}

unsigned bch2_dev_has_data(struct bch_fs *c, struct bch_dev *ca)
{
	unsigned ret;

	mutex_lock(&c->sb_lock);
	ret = bch2_sb_dev_has_data(c->disk_sb.sb, ca->dev_idx);
	mutex_unlock(&c->sb_lock);

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
