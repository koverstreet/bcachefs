// SPDX-License-Identifier: GPL-2.0-only
#include <linux/codetag.h>
#include <linux/darray.h>
#include <linux/eytzinger.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/seq_buf.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#ifdef DEBUG
#define EBUG_ON(cond)	BUG_ON(cond)
#else
#define EBUG_ON(cond)	do {} while (0)
#endif

struct codetag_eytz_entry {
	u16				idx;
};

struct codetag_module {
	unsigned			idx;
	unsigned			nr;
	struct codetag			*start;
	struct module			*mod;
};

struct codetag_modules {
	struct rcu_head			rcu;
	u16				nr_modules;
	u16				eytz_extra;
	struct codetag_eytz_entry	e[];
	/*
	 * Additionally, we have an array of @nr_modules codetag_modules after
	 * e[nr_modules]
	 */
};

static inline size_t codetag_modules_bytes(unsigned nr_modules)
{
	return sizeof(struct codetag_modules) +
		sizeof(struct codetag_eytz_entry) * nr_modules +
		sizeof(struct codetag_module) * nr_modules;
}

static inline struct codetag_module *codetag_mods_array(struct codetag_modules *m)
{
	return (void *) &m->e[m->nr_modules];
}

static void codetag_modules_init_eytz(struct codetag_modules *mods)
{
	mods->eytz_extra = eytzinger0_extra(mods->nr_modules);

	for (unsigned i = 0; i < mods->nr_modules; i++)
		mods->e[__inorder_to_eytzinger0(i, mods->nr_modules, mods->eytz_extra)].idx =
			codetag_mods_array(mods)[i].idx;
}

struct codetag_type {
	struct list_head		link;
	unsigned int			count;
	struct rw_semaphore		mod_lock; /* protects mods */
	struct codetag_modules __rcu	*mods_rcu;
	struct codetag_type_desc	desc;
};

static DEFINE_MUTEX(codetag_lock);
static LIST_HEAD(codetag_types);

void codetag_lock_module_list(struct codetag_type *cttype, bool lock)
{
	if (lock)
		down_read(&cttype->mod_lock);
	else
		up_read(&cttype->mod_lock);
}

bool codetag_trylock_module_list(struct codetag_type *cttype)
{
	return down_read_trylock(&cttype->mod_lock) != 0;
}

#define cmp_int(l, r)		((l > r) - (l < r))

static inline int codetag_eytz_entry_cmp(const void *_l, const void *_r)
{
	const struct codetag_eytz_entry *l = _l;
	const struct codetag_eytz_entry *r = _r;

	return cmp_int(l->idx, r->idx);
}

__always_inline
static inline struct codetag_module *codetag_idx_to_cmod(struct codetag_modules *mods, unsigned idx)
{
	struct codetag_eytz_entry search = { .idx = idx };
	unsigned e = eytzinger0_find_le(mods->e,
					mods->nr_modules,
					sizeof(mods->e[0]),
					codetag_eytz_entry_cmp,
					&search);
	if (e >= mods->nr_modules)
		return NULL;

	struct codetag_module *mod = codetag_mods_array(mods) +
		__eytzinger0_to_inorder(e, mods->nr_modules, mods->eytz_extra);

	EBUG_ON(mods->e[e].idx != mod->idx);
	return mod;
}

static struct codetag *__idx_to_codetag(struct codetag_type *cttype,
					struct codetag_module *cmod,
					unsigned idx)
{
	EBUG_ON(idx < cmod->idx);
	EBUG_ON(idx >= cmod->idx + cmod->nr);

	return (void *) cmod->start + (idx - cmod->idx) * cttype->desc.tag_size;
}

/* @idx must point to a valid codetag, not a gap */
struct codetag *idx_to_codetag(struct codetag_type *cttype, unsigned idx)
{
	rcu_read_lock();
	struct codetag_modules *mods = rcu_dereference(cttype->mods_rcu);
	struct codetag *ct = __idx_to_codetag(cttype, codetag_idx_to_cmod(mods, idx), idx);
	rcu_read_unlock();
	return ct;
}

/* finds the first valid codetag at idx >= iter->idx, or returns NULL */
static struct codetag *__codetag_iter_peek(struct codetag_iter *iter)
{
	struct codetag_type *cttype = iter->cttype;
	struct codetag_modules *mods = rcu_dereference(cttype->mods_rcu);

	iter->cmod = codetag_idx_to_cmod(mods, iter->idx);
	if (!iter->cmod)
		return NULL;

	if (iter->cmod->idx + iter->cmod->nr <= iter->idx) {
		iter->cmod++;
		if (iter->cmod == codetag_mods_array(mods) + mods->nr_modules)
			return NULL;
	}

	iter->idx = max(iter->idx, iter->cmod->idx);

	return __idx_to_codetag(cttype, iter->cmod, iter->idx);
}

struct codetag *codetag_iter_peek(struct codetag_iter *iter)
{
	rcu_read_lock();
	struct codetag *ct = __codetag_iter_peek(iter);
	rcu_read_unlock();
	return ct;

}

void codetag_to_text(struct seq_buf *out, struct codetag *ct)
{
	seq_buf_printf(out, "%s:%u", ct->filename, ct->lineno);
	if (ct->modname)
		seq_buf_printf(out, " [%s]", ct->modname);
	seq_buf_printf(out, " func:%s", ct->function);
}

#ifdef CONFIG_MODULES
static void *get_symbol(struct module *mod, const char *prefix, const char *name)
{
	DECLARE_SEQ_BUF(sb, KSYM_NAME_LEN);
	const char *buf;
	void *ret;

	seq_buf_printf(&sb, "%s%s", prefix, name);
	if (seq_buf_has_overflowed(&sb))
		return NULL;

	buf = seq_buf_str(&sb);
	preempt_disable();
	ret = mod ?
		(void *)find_kallsyms_symbol_value(mod, buf) :
		(void *)kallsyms_lookup_name(buf);
	preempt_enable();

	return ret;
}

static int __codetag_module_init(struct codetag_type *cttype, struct module *mod)
{
	struct codetag *start	= get_symbol(mod, "__start_", cttype->desc.section);
	struct codetag *stop	= get_symbol(mod, "__stop_", cttype->desc.section);

	BUG_ON(start > stop);

	if (!start || !stop) {
		pr_warn("Failed to load code tags of type %s from the module %s\n",
			cttype->desc.section, mod ? mod->name : "(built-in)");
		return -EINVAL;
	}

	struct codetag_module cmod = {
		.nr	= ((void *) stop - (void *) start) / cttype->desc.tag_size,
		.start	= start,
		.mod	= mod,
	};

	/* Ignore empty ranges */
	if (!cmod.nr)
		return 0;

	struct codetag_modules *old_mods =
		rcu_dereference_protected(cttype->mods_rcu, lockdep_is_held(&cttype->mod_lock));
	unsigned old_nr_modules = old_mods ? old_mods->nr_modules : 0;
	unsigned new_nr_modules = old_nr_modules + 1;
	struct codetag_modules *new_mods = kzalloc(codetag_modules_bytes(new_nr_modules), GFP_KERNEL);

	if (!new_mods)
		return -ENOMEM;

	new_mods->nr_modules = new_nr_modules;
	struct codetag_module *mod_a = codetag_mods_array(new_mods);

	if (old_mods)
		memcpy(mod_a, codetag_mods_array(old_mods),
		       sizeof(struct codetag_module) * old_mods->nr_modules);


	for (unsigned i = 0; i < old_nr_modules; i++) {
		if (cmod.idx + cmod.nr <= mod_a[i].idx) {
			array_insert_item(mod_a, old_nr_modules, i, cmod);
			goto insert_done;
		}

		cmod.idx = mod_a[i].idx + mod_a[i].nr;
	}

	mod_a[old_nr_modules] = cmod;
insert_done:
	codetag_modules_init_eytz(new_mods);

	rcu_assign_pointer(cttype->mods_rcu, new_mods);
	kfree_rcu(old_mods, rcu);

	for (unsigned i = 0; i < cmod.nr; i++)
		__idx_to_codetag(cttype, &cmod, cmod.idx + i)->idx = cmod.idx + i;

	return 0;
}

static int codetag_module_init(struct codetag_type *cttype, struct module *mod)
{
	down_write(&cttype->mod_lock);
	int ret = __codetag_module_init(cttype, mod);
	up_write(&cttype->mod_lock);

	return ret;
}

#else /* CONFIG_MODULES */
static int codetag_module_init(struct codetag_type *cttype, struct module *mod) { return 0; }
#endif /* CONFIG_MODULES */

struct codetag_type *
codetag_register_type(const struct codetag_type_desc *desc)
{
	struct codetag_type *cttype;
	int err;

	BUG_ON(desc->tag_size <= 0);

	cttype = kzalloc(sizeof(*cttype), GFP_KERNEL);
	if (unlikely(!cttype))
		return ERR_PTR(-ENOMEM);

	cttype->desc = *desc;
	init_rwsem(&cttype->mod_lock);

	err = codetag_module_init(cttype, NULL);
	if (unlikely(err)) {
		kfree(cttype);
		return ERR_PTR(err);
	}

	mutex_lock(&codetag_lock);
	list_add_tail(&cttype->link, &codetag_types);
	mutex_unlock(&codetag_lock);

	return cttype;
}

void codetag_load_module(struct module *mod)
{
	struct codetag_type *cttype;

	if (!mod)
		return;

	mutex_lock(&codetag_lock);
	list_for_each_entry(cttype, &codetag_types, link)
		codetag_module_init(cttype, mod);
	mutex_unlock(&codetag_lock);
}

static bool cttype_unload_module(struct codetag_type *cttype, struct module *mod)
{
	bool unload_ok = true;

	struct codetag_modules *new_mods = NULL;
	struct codetag_modules *old_mods =
		rcu_dereference_protected(cttype->mods_rcu, lockdep_is_held(&cttype->mod_lock));
	struct codetag_module *mod_a = codetag_mods_array(old_mods);

	unsigned pos;
	for (pos = 0; pos < old_mods->nr_modules; pos++)
		if (mod_a[pos].mod == mod)
			goto found;
	return true;
found:
	if (cttype->desc.module_unload &&
	    !cttype->desc.module_unload(cttype, &mod_a[pos]))
		unload_ok = false;
	cttype->count -= mod_a[pos].nr;

	unsigned new_nr = old_mods->nr_modules - 1;
	if (!new_nr)
		goto out;

	new_mods = kzalloc(codetag_modules_bytes(old_mods->nr_modules), GFP_KERNEL);
	if (!new_mods)
		return false;

	new_mods->nr_modules = new_nr;
	mod_a = codetag_mods_array(new_mods);

	memcpy(mod_a, codetag_mods_array(old_mods),
	       sizeof(struct codetag_module) * old_mods->nr_modules);
	memmove(&mod_a[pos],
		&mod_a[pos + 1],
		sizeof(mod_a[0]) * new_nr - pos);

	codetag_modules_init_eytz(new_mods);
out:
	rcu_assign_pointer(cttype->mods_rcu, new_mods);
	kfree_rcu(old_mods, rcu);
	return unload_ok;
}

bool codetag_unload_module(struct module *mod)
{
	struct codetag_type *cttype;
	bool unload_ok = true;

	if (!mod)
		return true;

	mutex_lock(&codetag_lock);
	list_for_each_entry(cttype, &codetag_types, link) {
		down_write(&cttype->mod_lock);
		if (!cttype_unload_module(cttype, mod))
			unload_ok = false;
		up_write(&cttype->mod_lock);
	}
	mutex_unlock(&codetag_lock);

	return unload_ok;
}
