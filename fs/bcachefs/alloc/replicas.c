// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/accounting.h"
#include "alloc/buckets.h"
#include "alloc/replicas.h"

#include "journal/journal.h"

#include "sb/io.h"

#include <linux/sort.h>

DEFINE_CLASS(bch_replicas_cpu, struct bch_replicas_cpu,
	     kfree(_T.entries),
	     (struct bch_replicas_cpu) {}, void)

static inline struct bch_replicas_entry_cpu *
cpu_replicas_entry(struct bch_replicas_cpu *r, unsigned i)
{
	return (void *) r->entries + r->entry_size * i;
}

static inline unsigned __cpu_replicas_entry_bytes(unsigned v1_bytes)
{
	return offsetof(struct bch_replicas_entry_cpu, e) + v1_bytes;
}

static inline unsigned cpu_replicas_entry_bytes(struct bch_replicas_entry_cpu *e)
{
	return __cpu_replicas_entry_bytes(replicas_entry_bytes(&e->e));
}

#define for_each_cpu_replicas_entry(_r, _i)						\
	for (struct bch_replicas_entry_cpu *_i = (_r)->entries;				\
	     (void *) (_i) < (void *) (_r)->entries + (_r)->nr * (_r)->entry_size;	\
	     _i = (void *) (_i) + (_r)->entry_size)

static int bch2_cpu_replicas_to_sb_replicas(struct bch_fs *,
					    struct bch_replicas_cpu *);

static int cpu_replicas_entry_cmp(const struct bch_replicas_entry_cpu *l,
				  const struct bch_replicas_entry_cpu *r,
				  size_t size)
{
	return memcmp(&l->e, &r->e, size - offsetof(struct bch_replicas_entry_cpu, e));
}

static int cpu_replicas_entry_cmp_r(const void *l, const void *r,  const void *priv)
{
	return cpu_replicas_entry_cmp(l, r, (size_t) priv);
}

/* Replicas tracking - in memory: */

static void verify_replicas_entry(struct bch_replicas_entry_v1 *e)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	BUG_ON(!e->nr_devs);
	BUG_ON(e->nr_required > 1 &&
	       e->nr_required >= e->nr_devs);

	for (unsigned i = 0; i + 1 < e->nr_devs; i++)
		BUG_ON(e->devs[i] != BCH_SB_MEMBER_INVALID &&
		       e->devs[i] >= e->devs[i + 1]);
#endif
}

void bch2_replicas_entry_sort(struct bch_replicas_entry_v1 *e)
{
	bubble_sort(e->devs, e->nr_devs, u8_cmp);
}

static void bch2_cpu_replicas_sort(struct bch_replicas_cpu *r)
{
	eytzinger0_sort_r(r->entries, r->nr, r->entry_size,
			  cpu_replicas_entry_cmp_r, NULL,
			  (void *)(size_t)r->entry_size);
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

static void bch2_replicas_entry_cpu_to_text(struct printbuf *out,
					    struct bch_replicas_entry_cpu *e)
{
	prt_printf(out, "ref=%u ", atomic_read(&e->ref));
	bch2_replicas_entry_to_text(out, &e->e);
}

static int bch2_replicas_entry_sb_validate(struct bch_replicas_entry_v1 *r,
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
		if (r->devs[i] != BCH_SB_MEMBER_INVALID &&
		    !bch2_member_exists(sb, r->devs[i])) {
			prt_printf(err, "invalid device %u in entry ", r->devs[i]);
			goto bad;
		}

	return 0;
bad:
	bch2_replicas_entry_to_text(err, r);
	return -BCH_ERR_invalid_replicas_entry;
}

int bch2_replicas_entry_validate(struct bch_replicas_entry_v1 *r,
				 struct bch_fs *c,
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
		if (r->devs[i] != BCH_SB_MEMBER_INVALID &&
		    !bch2_dev_exists(c, r->devs[i])) {
			prt_printf(err, "invalid device %u in entry ", r->devs[i]);
			goto bad;
		}

	return 0;
bad:
	bch2_replicas_entry_to_text(err, r);
	return bch_err_throw(c, invalid_replicas_entry);
}

void bch2_cpu_replicas_to_text(struct printbuf *out,
			       struct bch_replicas_cpu *r)
{
	bool first = true;

	for_each_cpu_replicas_entry(r, i) {
		if (!first)
			prt_printf(out, " ");
		first = false;

		bch2_replicas_entry_cpu_to_text(out, i);
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
			replicas_entry_add_dev(r, p.ptr.dev);
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
		replicas_entry_add_dev(r, ptr->dev);
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
		replicas_entry_add_dev(e, *i);

	bch2_replicas_entry_sort(e);
}

/* @l is bch_replicas_entry_v1, @r is bch_replicas_entry_cpu */
static int replicas_entry_search_cmp(const void *_l, const void *_r,  const void *priv)
{
	const struct bch_replicas_entry_v1  *l = _l;
	const struct bch_replicas_entry_cpu *r = _r;
	size_t size = (size_t) priv;

	return memcmp(l, &r->e, size);
}

static inline struct bch_replicas_entry_cpu *
replicas_entry_search(struct bch_replicas_cpu *r,
		      struct bch_replicas_entry_v1 *search)
{
	verify_replicas_entry(search);

	size_t entry_size = replicas_entry_bytes(search);
	int idx = likely(__cpu_replicas_entry_bytes(entry_size) <= r->entry_size)
		? eytzinger0_find_r(r->entries, r->nr, r->entry_size,
				    replicas_entry_search_cmp,
				    (void *) entry_size, search)
		: -1;
	return idx >= 0 ? cpu_replicas_entry(r, idx) : NULL;
}

bool bch2_replicas_marked_locked(struct bch_fs *c,
			  struct bch_replicas_entry_v1 *search)
{
	return !search->nr_devs || replicas_entry_search(&c->replicas, search);
}

bool bch2_replicas_marked(struct bch_fs *c,
			  struct bch_replicas_entry_v1 *search)
{
	guard(percpu_read)(&c->mark_lock);
	return bch2_replicas_marked_locked(c, search);
}

static struct bch_replicas_cpu
cpu_replicas_add_entry(struct bch_fs *c,
		       struct bch_replicas_cpu *old,
		       struct bch_replicas_entry_v1 *new_entry)
{
	struct bch_replicas_cpu new = {
		.nr		= old->nr + 1,
		.entry_size	= max_t(unsigned, old->entry_size,
					__cpu_replicas_entry_bytes(replicas_entry_bytes(new_entry))),
	};

	/* alignment */
	new.entry_size = round_up(new.entry_size, sizeof(atomic_t));

	new.entries = kcalloc(new.nr, new.entry_size, GFP_KERNEL);
	if (!new.entries)
		return new;

	for (unsigned i = 0; i < old->nr; i++)
		memcpy(cpu_replicas_entry(&new, i),
		       cpu_replicas_entry(old, i),
		       old->entry_size);

	memcpy(&cpu_replicas_entry(&new, old->nr)->e,
	       new_entry,
	       replicas_entry_bytes(new_entry));

	bch2_cpu_replicas_sort(&new);
	return new;
}

noinline
static int bch2_mark_replicas_slowpath(struct bch_fs *c,
				struct bch_replicas_entry_v1 *new_entry,
				unsigned ref)
{
	verify_replicas_entry(new_entry);

	guard(mutex)(&c->sb_lock);
	bool write_sb = false;

	scoped_guard(percpu_write, &c->mark_lock) {
		if (!replicas_entry_search(&c->replicas, new_entry)) {
			CLASS(bch_replicas_cpu, new_r)();

			new_r = cpu_replicas_add_entry(c, &c->replicas, new_entry);
			if (!new_r.entries)
				return bch_err_throw(c, ENOMEM_cpu_replicas);

			try(bch2_cpu_replicas_to_sb_replicas(c, &new_r));

			swap(c->replicas, new_r);
			write_sb = true;
		}

		atomic_add(ref, &replicas_entry_search(&c->replicas, new_entry)->ref);
	}

	/* After dropping mark_lock */
	if (write_sb)
		bch2_write_super(c);

	return 0;
}

int bch2_mark_replicas(struct bch_fs *c, struct bch_replicas_entry_v1 *r)
{
	return likely(bch2_replicas_marked(c, r))
		? 0 : bch2_mark_replicas_slowpath(c, r, 0);
}

static void __replicas_entry_kill(struct bch_fs *c, struct bch_replicas_entry_cpu *e)
{
	struct bch_replicas_cpu *r = &c->replicas;

	memcpy(e, cpu_replicas_entry(r, --r->nr), r->entry_size);
	bch2_cpu_replicas_sort(r);

	int ret = bch2_cpu_replicas_to_sb_replicas(c, r);
	if (WARN(ret, "bch2_cpu_replicas_to_sb_replicas() error: %s", bch2_err_str(ret)))
		return;
}

void bch2_replicas_entry_kill(struct bch_fs *c, struct bch_replicas_entry_v1 *kill)
{
	lockdep_assert_held(&c->mark_lock);
	lockdep_assert_held(&c->sb_lock);

	struct bch_replicas_entry_cpu *e = replicas_entry_search(&c->replicas, kill);

	if (WARN(!e, "replicas entry not found in sb"))
		return;

	__replicas_entry_kill(c, e);

	/* caller does write_super() after dropping mark_lock */
}

void bch2_replicas_entry_put_many(struct bch_fs *c, struct bch_replicas_entry_v1 *r, unsigned nr)
{
	if (!r->nr_devs)
		return;

	BUG_ON(r->data_type != BCH_DATA_journal);
	verify_replicas_entry(r);

	scoped_guard(percpu_read, &c->mark_lock) {
		struct bch_replicas_entry_cpu *e = replicas_entry_search(&c->replicas, r);

		int v = atomic_sub_return(nr, &e->ref);
		BUG_ON(v < 0);
		if (v)
			return;
	}

	guard(mutex)(&c->sb_lock);
	scoped_guard(percpu_write, &c->mark_lock) {
		struct bch_replicas_entry_cpu *e = replicas_entry_search(&c->replicas, r);
		if (e && !atomic_read(&e->ref))
			__replicas_entry_kill(c, e);
	}

	bch2_write_super(c);
}

static inline bool bch2_replicas_entry_get_inmem(struct bch_fs *c, struct bch_replicas_entry_v1 *r)
{
	guard(percpu_read)(&c->mark_lock);
	struct bch_replicas_entry_cpu *e = replicas_entry_search(&c->replicas, r);
	if (e)
		atomic_inc(&e->ref);
	return e != NULL;
}

int bch2_replicas_entry_get(struct bch_fs *c, struct bch_replicas_entry_v1 *r)
{
	if (!r->nr_devs)
		return 0;

	BUG_ON(r->data_type != BCH_DATA_journal);
	verify_replicas_entry(r);

	return bch2_replicas_entry_get_inmem(c, r)
		? 0
		: bch2_mark_replicas_slowpath(c, r, 1);
}

int bch2_replicas_gc_reffed(struct bch_fs *c)
{
	bool write_sb = false;

	guard(mutex)(&c->sb_lock);

	scoped_guard(percpu_write, &c->mark_lock) {
		unsigned dst = 0;
		for (unsigned i = 0; i < c->replicas.nr; i++) {
			struct bch_replicas_entry_cpu *e =
				cpu_replicas_entry(&c->replicas, i);

			if (e->e.data_type != BCH_DATA_journal ||
			    atomic_read(&e->ref))
				memcpy(cpu_replicas_entry(&c->replicas, dst++),
				       e,
				       c->replicas.entry_size);
		}

		if (c->replicas.nr != dst) {
			c->replicas.nr = dst;
			bch2_cpu_replicas_sort(&c->replicas);

			try(bch2_cpu_replicas_to_sb_replicas(c, &c->replicas));
		}
	}

	if (write_sb)
		bch2_write_super(c);
	return 0;
}

/* Replicas tracking - superblock: */

static int
__bch2_sb_replicas_to_cpu_replicas(struct bch_sb_field_replicas *sb_r,
				   struct bch_replicas_cpu *cpu_r)
{
	unsigned nr = 0, entry_size = 0, idx = 0;

	for_each_replicas_entry(sb_r, e) {
		entry_size = max_t(unsigned, entry_size,
				   replicas_entry_bytes(e));
		nr++;
	}

	entry_size = __cpu_replicas_entry_bytes(entry_size);
	entry_size = round_up(entry_size, sizeof(atomic_t));

	cpu_r->entries = kcalloc(nr, entry_size, GFP_KERNEL);
	if (!cpu_r->entries)
		return -BCH_ERR_ENOMEM_cpu_replicas;

	cpu_r->nr		= nr;
	cpu_r->entry_size	= entry_size;

	for_each_replicas_entry(sb_r, src) {
		struct bch_replicas_entry_cpu *dst = cpu_replicas_entry(cpu_r, idx++);
		memcpy(&dst->e, src, replicas_entry_bytes(src));
		bch2_replicas_entry_sort(&dst->e);
	}

	return 0;
}

static int
__bch2_sb_replicas_v0_to_cpu_replicas(struct bch_sb_field_replicas_v0 *sb_r,
				      struct bch_replicas_cpu *cpu_r)
{
	unsigned nr = 0, entry_size = 0, idx = 0;

	for_each_replicas_entry(sb_r, e) {
		entry_size = max_t(unsigned, entry_size,
				   replicas_entry_bytes(e));
		nr++;
	}

	entry_size = __cpu_replicas_entry_bytes(entry_size);

	entry_size += sizeof(struct bch_replicas_entry_v1) -
		sizeof(struct bch_replicas_entry_v0);

	entry_size = round_up(entry_size, sizeof(atomic_t));

	cpu_r->entries = kcalloc(nr, entry_size, GFP_KERNEL);
	if (!cpu_r->entries)
		return -BCH_ERR_ENOMEM_cpu_replicas;

	cpu_r->nr		= nr;
	cpu_r->entry_size	= entry_size;

	for_each_replicas_entry(sb_r, src) {
		struct bch_replicas_entry_cpu *dst =
			cpu_replicas_entry(cpu_r, idx++);

		dst->e.data_type	= src->data_type;
		dst->e.nr_devs		= src->nr_devs;
		dst->e.nr_required	= 1;
		memcpy(dst->e.devs, src->devs, src->nr_devs);
		bch2_replicas_entry_sort(&dst->e);
	}

	return 0;
}

int bch2_sb_replicas_to_cpu_replicas(struct bch_fs *c)
{
	/*
	 * If called after fs is started (after journal read), we'll be blowing
	 * away refcounts
	 */
	BUG_ON(test_bit(BCH_FS_started, &c->flags));

	struct bch_sb_field_replicas *sb_v1;
	struct bch_sb_field_replicas_v0 *sb_v0;
	CLASS(bch_replicas_cpu, new_r)();

	if ((sb_v1 = bch2_sb_field_get(c->disk_sb.sb, replicas)))
		try(__bch2_sb_replicas_to_cpu_replicas(sb_v1, &new_r));
	else if ((sb_v0 = bch2_sb_field_get(c->disk_sb.sb, replicas_v0)))
		try(__bch2_sb_replicas_v0_to_cpu_replicas(sb_v0, &new_r));

	bch2_cpu_replicas_sort(&new_r);

	guard(percpu_write)(&c->mark_lock);
	swap(c->replicas, new_r);

	return 0;
}

static int bch2_cpu_replicas_to_sb_replicas_v0(struct bch_fs *c,
					       struct bch_replicas_cpu *r)
{
	struct bch_sb_field_replicas_v0 *sb_r;
	struct bch_replicas_entry_v0 *dst;
	size_t bytes;

	bytes = sizeof(struct bch_sb_field_replicas);

	for_each_cpu_replicas_entry(r, src)
		bytes += replicas_entry_bytes(&src->e) - 1;

	sb_r = bch2_sb_field_resize(&c->disk_sb, replicas_v0,
			DIV_ROUND_UP(bytes, sizeof(u64)));
	if (!sb_r)
		return bch_err_throw(c, ENOSPC_sb_replicas);

	bch2_sb_field_delete(&c->disk_sb, BCH_SB_FIELD_replicas);
	sb_r = bch2_sb_field_get(c->disk_sb.sb, replicas_v0);

	memset(&sb_r->entries, 0,
	       vstruct_end(&sb_r->field) -
	       (void *) &sb_r->entries);

	dst = sb_r->entries;
	for_each_cpu_replicas_entry(r, src) {
		dst->data_type	= src->e.data_type;
		dst->nr_devs	= src->e.nr_devs;
		memcpy(dst->devs, src->e.devs, src->e.nr_devs);

		dst = replicas_entry_next(dst);

		BUG_ON((void *) dst > vstruct_end(&sb_r->field));
	}

	return 0;
}

static int bch2_cpu_replicas_to_sb_replicas(struct bch_fs *c,
					    struct bch_replicas_cpu *r)
{
	struct bch_sb_field_replicas *sb_r;
	struct bch_replicas_entry_v1 *dst;
	bool need_v1 = false;
	size_t bytes;

	bytes = sizeof(struct bch_sb_field_replicas);

	for_each_cpu_replicas_entry(r, src) {
		bytes += replicas_entry_bytes(&src->e);
		if (src->e.nr_required != 1)
			need_v1 = true;
	}

	if (!need_v1)
		return bch2_cpu_replicas_to_sb_replicas_v0(c, r);

	sb_r = bch2_sb_field_resize(&c->disk_sb, replicas,
			DIV_ROUND_UP(bytes, sizeof(u64)));
	if (!sb_r)
		return bch_err_throw(c, ENOSPC_sb_replicas);

	bch2_sb_field_delete(&c->disk_sb, BCH_SB_FIELD_replicas_v0);
	sb_r = bch2_sb_field_get(c->disk_sb.sb, replicas);

	memset(&sb_r->entries, 0,
	       vstruct_end(&sb_r->field) -
	       (void *) &sb_r->entries);

	dst = sb_r->entries;
	for_each_cpu_replicas_entry(r, src) {
		memcpy(dst, &src->e, replicas_entry_bytes(&src->e));

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
	       cpu_replicas_entry_cmp_r, NULL,
	       (void *)(size_t)cpu_r->entry_size);

	for (i = 0; i < cpu_r->nr; i++) {
		struct bch_replicas_entry_cpu *e =
			cpu_replicas_entry(cpu_r, i);

		try(bch2_replicas_entry_sb_validate(&e->e, sb, err));

		if (i + 1 < cpu_r->nr) {
			struct bch_replicas_entry_cpu *n =
				cpu_replicas_entry(cpu_r, i + 1);

			int cmp = cpu_replicas_entry_cmp(e, n, cpu_r->entry_size);

			BUG_ON(cmp > 0);

			if (!cmp) {
				prt_printf(err, "duplicate replicas entry ");
				bch2_replicas_entry_to_text(err, &e->e);
				return -BCH_ERR_invalid_sb_replicas;
			}
		}
	}

	return 0;
}

static int bch2_sb_replicas_validate(struct bch_sb *sb, struct bch_sb_field *f,
				     enum bch_validate_flags flags, struct printbuf *err)
{
	struct bch_sb_field_replicas *sb_r = field_to_type(f, replicas);

	CLASS(bch_replicas_cpu, cpu_r)();
	try(__bch2_sb_replicas_to_cpu_replicas(sb_r, &cpu_r));
	try(bch2_cpu_replicas_validate(&cpu_r, sb, err));

	return 0;
}

static void bch2_sb_replicas_to_text(struct printbuf *out,
				     struct bch_sb *sb,
				     struct bch_sb_field *f)
{
	struct bch_sb_field_replicas *r = field_to_type(f, replicas);
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
					enum bch_validate_flags flags, struct printbuf *err)
{
	struct bch_sb_field_replicas_v0 *sb_r = field_to_type(f, replicas_v0);

	CLASS(bch_replicas_cpu, cpu_r)();
	try(__bch2_sb_replicas_v0_to_cpu_replicas(sb_r, &cpu_r));
	try(bch2_cpu_replicas_validate(&cpu_r, sb, err));

	return 0;
}

static void bch2_sb_replicas_v0_to_text(struct printbuf *out,
					struct bch_sb *sb,
					struct bch_sb_field *f)
{
	struct bch_sb_field_replicas_v0 *sb_r = field_to_type(f, replicas_v0);
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

bool bch2_can_read_fs_with_devs(struct bch_fs *c, struct bch_devs_mask devs,
				unsigned flags, struct printbuf *err)
{
	guard(percpu_read)(&c->mark_lock);
	for_each_cpu_replicas_entry(&c->replicas, i) {
		struct bch_replicas_entry_v1 *e = &i->e;

		unsigned nr_online = 0, nr_failed = 0, dflags = 0;
		bool metadata = e->data_type < BCH_DATA_user;

		if (e->data_type == BCH_DATA_cached)
			continue;

		scoped_guard(rcu)
			for (unsigned i = 0; i < e->nr_devs; i++) {
				if (e->devs[i] == BCH_SB_MEMBER_INVALID) {
					nr_failed++;
					continue;
				}

				nr_online += test_bit(e->devs[i], devs.d);

				struct bch_dev *ca = bch2_dev_rcu_noerror(c, e->devs[i]);
				nr_failed += !ca || ca->mi.state == BCH_MEMBER_STATE_failed;
			}

		if (nr_online + nr_failed == e->nr_devs)
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
			if (err) {
				prt_printf(err, "insufficient devices online (%u) for replicas entry ",
					   nr_online);
				bch2_replicas_entry_to_text(err, e);
				prt_newline(err);
			}
			return false;
		}
	}

	return true;
}

bool bch2_have_enough_devs(struct bch_fs *c, struct bch_devs_mask devs,
			   unsigned flags, struct printbuf *err,
			   bool write)
{
	if (write) {
		unsigned nr_have[BCH_DATA_NR];
		memset(nr_have, 0, sizeof(nr_have));

		unsigned nr_online[BCH_DATA_NR];
		memset(nr_online, 0, sizeof(nr_online));

		scoped_guard(rcu)
			for_each_member_device_rcu(c, ca, &devs) {
				if (!ca->mi.durability)
					continue;

				bool online = ca->mi.state == BCH_MEMBER_STATE_rw &&
					test_bit(ca->dev_idx, devs.d);

				for (unsigned i = 0; i < BCH_DATA_NR; i++) {
					nr_have[i] += ca->mi.data_allowed & BIT(i) ? ca->mi.durability : 0;

					if (online)
						nr_online[i] += ca->mi.data_allowed & BIT(i) ? ca->mi.durability : 0;
				}
			}

		if (!nr_online[BCH_DATA_journal]) {
			prt_printf(err, "No rw journal devices online\n");
			return false;
		}

		if (!nr_online[BCH_DATA_btree]) {
			prt_printf(err, "No rw btree devices online\n");
			return false;
		}

		if (!nr_online[BCH_DATA_user]) {
			prt_printf(err, "No rw user data devices online\n");
			return false;
		}

		if (!(flags & BCH_FORCE_IF_METADATA_DEGRADED)) {
			if (nr_online[BCH_DATA_journal] < nr_have[BCH_DATA_journal] &&
			    nr_online[BCH_DATA_journal] < c->opts.metadata_replicas) {
				prt_printf(err, "Insufficient rw journal devices (%u) online\n",
					   nr_online[BCH_DATA_journal]);
				return false;
			}

			if (nr_online[BCH_DATA_btree] < nr_have[BCH_DATA_btree] &&
			    nr_online[BCH_DATA_btree] < c->opts.metadata_replicas) {
				prt_printf(err, "Insufficient rw btree devices (%u) online\n",
					   nr_online[BCH_DATA_btree]);
				return false;
			}
		}

		if (!(flags & BCH_FORCE_IF_DATA_DEGRADED)) {
			if (nr_online[BCH_DATA_user] < nr_have[BCH_DATA_user] &&
			    nr_online[BCH_DATA_user] < c->opts.data_replicas) {
				prt_printf(err, "Insufficient rw user data devices (%u) online\n",
					   nr_online[BCH_DATA_user]);
				return false;
			}
		}
	}

	return bch2_can_read_fs_with_devs(c, devs, flags, err);
}

bool bch2_sb_has_journal(struct bch_sb *sb)
{
	struct bch_sb_field_replicas *replicas = bch2_sb_field_get(sb, replicas);
	struct bch_sb_field_replicas_v0 *replicas_v0 = bch2_sb_field_get(sb, replicas_v0);

	if (replicas) {
		for_each_replicas_entry(replicas, r)
			if (r->data_type == BCH_DATA_journal)
				return true;
	} else if (replicas_v0) {
		for_each_replicas_entry(replicas_v0, r)
			if (r->data_type == BCH_DATA_journal)
				return true;
	}


	return false;
}

unsigned bch2_sb_dev_has_data(struct bch_sb *sb, unsigned dev)
{
	struct bch_sb_field_replicas *replicas;
	struct bch_sb_field_replicas_v0 *replicas_v0;
	unsigned data_has = 0;

	replicas = bch2_sb_field_get(sb, replicas);
	replicas_v0 = bch2_sb_field_get(sb, replicas_v0);

	if (replicas) {
		for_each_replicas_entry(replicas, r) {
			if (r->data_type >= sizeof(data_has) * 8)
				continue;

			for (unsigned i = 0; i < r->nr_devs; i++)
				if (r->devs[i] == dev)
					data_has |= 1 << r->data_type;
		}

	} else if (replicas_v0) {
		for_each_replicas_entry(replicas_v0, r) {
			if (r->data_type >= sizeof(data_has) * 8)
				continue;

			for (unsigned i = 0; i < r->nr_devs; i++)
				if (r->devs[i] == dev)
					data_has |= 1 << r->data_type;
		}
	}


	return data_has;
}

unsigned bch2_dev_has_data(struct bch_fs *c, struct bch_dev *ca)
{
	guard(mutex)(&c->sb_lock);
	return bch2_sb_dev_has_data(c->disk_sb.sb, ca->dev_idx);
}

void bch2_fs_replicas_exit(struct bch_fs *c)
{
	kfree(c->replicas.entries);
}
