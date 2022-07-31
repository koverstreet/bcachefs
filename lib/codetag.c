// SPDX-License-Identifier: GPL-2.0-only
#include <linux/codetag.h>
#include <linux/codetag_ctx.h>
#include <linux/idr.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/seq_buf.h>
#include <linux/slab.h>

struct codetag_type {
	struct list_head link;
	unsigned int count;
	struct idr mod_idr;
	struct rw_semaphore mod_lock; /* protects mod_idr */
	struct codetag_type_desc desc;
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

void codetag_init_iter(struct codetag_iterator *iter,
		       struct codetag_type *cttype)
{
	iter->cttype = cttype;
	iter->cmod = NULL;
	iter->mod_id = 0;
	iter->ct = NULL;
	iter->ctx = NULL;
}

static inline struct codetag *get_first_module_ct(struct codetag_module *cmod)
{
	return cmod->range.start < cmod->range.stop ? cmod->range.start : NULL;
}

static inline
struct codetag *get_next_module_ct(struct codetag_iterator *iter)
{
	struct codetag *res = (struct codetag *)
			((char *)iter->ct + iter->cttype->desc.tag_size);

	return res < iter->cmod->range.stop ? res : NULL;
}

struct codetag *codetag_next_ct(struct codetag_iterator *iter)
{
	struct codetag_type *cttype = iter->cttype;
	struct codetag_module *cmod;
	struct codetag *ct;

	lockdep_assert_held(&cttype->mod_lock);

	if (unlikely(idr_is_empty(&cttype->mod_idr)))
		return NULL;

	ct = NULL;
	while (true) {
		cmod = idr_find(&cttype->mod_idr, iter->mod_id);

		/* If module was removed move to the next one */
		if (!cmod)
			cmod = idr_get_next_ul(&cttype->mod_idr,
					       &iter->mod_id);

		/* Exit if no more modules */
		if (!cmod)
			break;

		if (cmod != iter->cmod) {
			iter->cmod = cmod;
			ct = get_first_module_ct(cmod);
		} else
			ct = get_next_module_ct(iter);

		if (ct)
			break;

		iter->mod_id++;
	}

	iter->ct = ct;
	return ct;
}

static struct codetag_ctx *next_ctx_from_ct(struct codetag_iterator *iter)
{
	struct codetag_with_ctx *ctc;
	struct codetag_ctx *ctx = NULL;
	struct codetag *ct = iter->ct;

	while (ct) {
		if (!(ct->flags & CTC_FLAG_CTX_READY))
			goto next;

		ctc = ct_to_ctc(ct);
		spin_lock(&ctc->ctx_lock);
		if (!list_empty(&ctc->ctx_head)) {
			ctx = list_first_entry(&ctc->ctx_head,
					       struct codetag_ctx, node);
			kref_get(&ctx->refcount);
		}
		spin_unlock(&ctc->ctx_lock);
		if (ctx)
			break;
next:
		ct = codetag_next_ct(iter);
	}

	iter->ctx = ctx;
	return ctx;
}

struct codetag_ctx *codetag_next_ctx(struct codetag_iterator *iter)
{
	struct codetag_ctx *ctx = iter->ctx;
	struct codetag_ctx *found = NULL;

	lockdep_assert_held(&iter->cttype->mod_lock);

	/* Move to the first codetag if search just started */
	if (!iter->ct)
		codetag_next_ct(iter);

	if (!ctx)
		return next_ctx_from_ct(iter);

	spin_lock(&ctx->ctc->ctx_lock);
	/*
	 * Do not advance if the object was isolated, restart at the same tag.
	 */
	if (!list_empty(&ctx->node)) {
		if (list_is_last(&ctx->node, &ctx->ctc->ctx_head)) {
			/* Finished with this tag, advance to the next */
			codetag_next_ct(iter);
		} else {
			found = list_next_entry(ctx, node);
			kref_get(&found->refcount);
		}
	}
	spin_unlock(&ctx->ctc->ctx_lock);
	kref_put(&ctx->refcount, iter->cttype->desc.free_ctx);

	if (!found)
		return next_ctx_from_ct(iter);

	iter->ctx = found;
	return found;
}

static struct codetag_type *find_cttype(struct codetag *ct)
{
	struct codetag_module *cmod;
	struct codetag_type *cttype;
	unsigned long mod_id;
	unsigned long tmp;

	mutex_lock(&codetag_lock);
	list_for_each_entry(cttype, &codetag_types, link) {
		down_read(&cttype->mod_lock);
		idr_for_each_entry_ul(&cttype->mod_idr, cmod, tmp, mod_id) {
			if (ct >= cmod->range.start && ct < cmod->range.stop) {
				up_read(&cttype->mod_lock);
				goto found;
			}
		}
		up_read(&cttype->mod_lock);
	}
	cttype = NULL;
found:
	mutex_unlock(&codetag_lock);

	return cttype;
}

bool codetag_enable_ctx(struct codetag_with_ctx *ctc, bool enable)
{
	struct codetag_type *cttype = find_cttype(&ctc->ct);

	if (!cttype || !cttype->desc.free_ctx)
		return false;

	lockdep_assert_held(&cttype->mod_lock);
	BUG_ON(!rwsem_is_locked(&cttype->mod_lock));

	if (codetag_ctx_enabled(ctc) == enable)
		return false;

	if (enable) {
		/* Initialize context capture fields only once */
		if (!(ctc->ct.flags & CTC_FLAG_CTX_READY)) {
			spin_lock_init(&ctc->ctx_lock);
			INIT_LIST_HEAD(&ctc->ctx_head);
			ctc->ct.flags |= CTC_FLAG_CTX_READY;
		}
		ctc->ct.flags |= CTC_FLAG_CTX_ENABLED;
	} else {
		/*
		 * The list of context objects is intentionally left untouched.
		 * It can be read back and if context capture is re-enablied it
		 * will append new objects.
		 */
		ctc->ct.flags &= ~CTC_FLAG_CTX_ENABLED;
	}

	return true;
}

bool codetag_has_ctx(struct codetag_with_ctx *ctc)
{
	bool no_ctx;

	if (!(ctc->ct.flags & CTC_FLAG_CTX_READY))
		return false;

	spin_lock(&ctc->ctx_lock);
	no_ctx = list_empty(&ctc->ctx_head);
	spin_unlock(&ctc->ctx_lock);

	return !no_ctx;
}

void codetag_to_text(struct seq_buf *out, struct codetag *ct)
{
	seq_buf_printf(out, "%s:%u module:%s func:%s",
		       ct->filename, ct->lineno,
		       ct->modname, ct->function);
}

static inline size_t range_size(const struct codetag_type *cttype,
				const struct codetag_range *range)
{
	return ((char *)range->stop - (char *)range->start) /
			cttype->desc.tag_size;
}

static void *get_symbol(struct module *mod, const char *prefix, const char *name)
{
	char buf[64];
	int res;

	res = snprintf(buf, sizeof(buf), "%s%s", prefix, name);
	if (WARN_ON(res < 1 || res > sizeof(buf)))
		return NULL;

	return mod ?
		(void *)find_kallsyms_symbol_value(mod, buf) :
		(void *)kallsyms_lookup_name(buf);
}

static struct codetag_range get_section_range(struct module *mod,
					      const char *section)
{
	return (struct codetag_range) {
		get_symbol(mod, "__start_", section),
		get_symbol(mod, "__stop_", section),
	};
}

static int codetag_module_init(struct codetag_type *cttype, struct module *mod)
{
	struct codetag_range range;
	struct codetag_module *cmod;
	int err;

	range = get_section_range(mod, cttype->desc.section);
	if (!range.start || !range.stop) {
		pr_warn("Failed to load code tags of type %s from the module %s\n",
			cttype->desc.section,
			mod ? mod->name : "(built-in)");
		return -EINVAL;
	}

	/* Ignore empty ranges */
	if (range.start == range.stop)
		return 0;

	BUG_ON(range.start > range.stop);

	cmod = kmalloc(sizeof(*cmod), GFP_KERNEL);
	if (unlikely(!cmod))
		return -ENOMEM;

	cmod->mod = mod;
	cmod->range = range;

	down_write(&cttype->mod_lock);
	err = idr_alloc(&cttype->mod_idr, cmod, 0, 0, GFP_KERNEL);
	if (err >= 0) {
		cttype->count += range_size(cttype, &range);
		if (cttype->desc.module_load)
			cttype->desc.module_load(cttype, cmod);
	}
	up_write(&cttype->mod_lock);

	if (err < 0) {
		kfree(cmod);
		return err;
	}

	return 0;
}

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
	idr_init(&cttype->mod_idr);
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

void codetag_unload_module(struct module *mod)
{
	struct codetag_type *cttype;

	if (!mod)
		return;

	mutex_lock(&codetag_lock);
	list_for_each_entry(cttype, &codetag_types, link) {
		struct codetag_module *found = NULL;
		struct codetag_module *cmod;
		unsigned long mod_id, tmp;

		down_write(&cttype->mod_lock);
		idr_for_each_entry_ul(&cttype->mod_idr, cmod, tmp, mod_id) {
			if (cmod->mod && cmod->mod == mod) {
				found = cmod;
				break;
			}
		}
		if (found) {
			if (cttype->desc.module_unload)
				cttype->desc.module_unload(cttype, cmod);

			cttype->count -= range_size(cttype, &cmod->range);
			idr_remove(&cttype->mod_idr, mod_id);
			kfree(cmod);
		}
		up_write(&cttype->mod_lock);
	}
	mutex_unlock(&codetag_lock);
}

/* Codetag query parsing */

#define CODETAG_QUERY_TOKENS()	\
	x(func)			\
	x(file)			\
	x(line)			\
	x(module)		\
	x(class)		\
	x(index)

enum tokens {
#define x(name)		TOK_##name,
	CODETAG_QUERY_TOKENS()
#undef x
};

static const char * const token_strs[] = {
#define x(name)		#name,
	CODETAG_QUERY_TOKENS()
#undef x
	NULL
};

static int parse_range(char *str, unsigned int *first, unsigned int *last)
{
	char *first_str = str;
	char *last_str = strchr(first_str, '-');

	if (last_str)
		*last_str++ = '\0';

	if (kstrtouint(first_str, 10, first))
		return -EINVAL;

	if (!last_str)
		*last = *first;
	else if (kstrtouint(last_str, 10, last))
		return -EINVAL;

	return 0;
}

char *codetag_query_parse(struct codetag_query *q, char *buf)
{
	while (1) {
		char *p = buf;
		char *str1 = strsep_no_empty(&p, " \t\r\n");
		char *str2 = strsep_no_empty(&p, " \t\r\n");
		int ret, token;

		if (!str1 || !str2)
			break;

		token = match_string(token_strs, ARRAY_SIZE(token_strs), str1);
		if (token < 0)
			break;

		switch (token) {
		case TOK_func:
			q->function = str2;
			break;
		case TOK_file:
			q->filename = str2;
			break;
		case TOK_line:
			ret = parse_range(str2, &q->first_line, &q->last_line);
			if (ret)
				return ERR_PTR(ret);
			q->match_line = true;
			break;
		case TOK_module:
			q->module = str2;
			break;
		case TOK_class:
			q->class = str2;
			break;
		case TOK_index:
			ret = parse_range(str2, &q->first_index, &q->last_index);
			if (ret)
				return ERR_PTR(ret);
			q->match_index = true;
			break;
		}

		buf = p;
	}

	return buf;
}

bool codetag_matches_query(struct codetag_query *q,
			   const struct codetag *ct,
			   const struct codetag_module *mod,
			   const char *class)
{
	size_t classlen = q->class ? strlen(q->class) : 0;

	if (q->module &&
	    (!mod->mod ||
	     strcmp(q->module, ct->modname)))
		return false;

	if (q->filename &&
	    strcmp(q->filename, ct->filename) &&
	    strcmp(q->filename, kbasename(ct->filename)))
		return false;

	if (q->function &&
	    strcmp(q->function, ct->function))
		return false;

	/* match against the line number range */
	if (q->match_line &&
	    (ct->lineno < q->first_line ||
	     ct->lineno > q->last_line))
		return false;

	/* match against the class */
	if (classlen &&
	    (strncmp(q->class, class, classlen) ||
	     (class[classlen] && class[classlen] != ':')))
		return false;

	/* match against the fault index */
	if (q->match_index &&
	    (q->cur_index < q->first_index ||
	     q->cur_index > q->last_index)) {
		q->cur_index++;
		return false;
	}

	q->cur_index++;
	return true;
}
