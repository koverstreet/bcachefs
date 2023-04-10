// SPDX-License-Identifier: GPL-2.0-only
#include <linux/alloc_tag.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/page_ext.h>
#include <linux/proc_fs.h>
#include <linux/seq_buf.h>
#include <linux/seq_file.h>

static struct codetag_type *alloc_tag_cttype;

DEFINE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
			mem_alloc_profiling_key);

static void *allocinfo_start(struct seq_file *m, loff_t *pos)
{
	struct codetag_iterator *iter;
	struct codetag *ct;
	loff_t node = *pos;

	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	m->private = iter;
	if (!iter)
		return NULL;

	codetag_lock_module_list(alloc_tag_cttype, true);
	*iter = codetag_get_ct_iter(alloc_tag_cttype);
	while ((ct = codetag_next_ct(iter)) != NULL && node)
		node--;

	return ct ? iter : NULL;
}

static void *allocinfo_next(struct seq_file *m, void *arg, loff_t *pos)
{
	struct codetag_iterator *iter = (struct codetag_iterator *)arg;
	struct codetag *ct = codetag_next_ct(iter);

	(*pos)++;
	if (!ct)
		return NULL;

	return iter;
}

static void allocinfo_stop(struct seq_file *m, void *arg)
{
	struct codetag_iterator *iter = (struct codetag_iterator *)m->private;

	if (iter) {
		codetag_lock_module_list(alloc_tag_cttype, false);
		kfree(iter);
	}
}

static void alloc_tag_to_text(struct seq_buf *out, struct codetag *ct)
{
	struct alloc_tag *tag = ct_to_alloc_tag(ct);
	struct alloc_tag_counters counter = alloc_tag_read(tag);
	s64 bytes = counter.bytes;
	char val[10], *p = val;

	if (bytes < 0) {
		*p++ = '-';
		bytes = -bytes;
	}

	string_get_size(bytes, 1,
			STRING_SIZE_BASE2|STRING_SIZE_NOSPACE,
			p, val + ARRAY_SIZE(val) - p);

	seq_buf_printf(out, "%8s %8llu ", val, counter.calls);
	codetag_to_text(out, ct);
	seq_buf_putc(out, ' ');
	seq_buf_putc(out, '\n');
}

static int allocinfo_show(struct seq_file *m, void *arg)
{
	struct codetag_iterator *iter = (struct codetag_iterator *)arg;
	char *bufp;
	size_t n = seq_get_buf(m, &bufp);
	struct seq_buf buf;

	seq_buf_init(&buf, bufp, n);
	alloc_tag_to_text(&buf, iter->ct);
	seq_commit(m, seq_buf_used(&buf));
	return 0;
}

static const struct seq_operations allocinfo_seq_op = {
	.start	= allocinfo_start,
	.next	= allocinfo_next,
	.stop	= allocinfo_stop,
	.show	= allocinfo_show,
};

void alloc_tags_show_mem_report(struct seq_buf *s)
{
	struct codetag_iterator iter;
	struct codetag *ct;
	struct {
		struct codetag		*tag;
		size_t			bytes;
	} tags[10], n;
	unsigned int i, nr = 0;

	codetag_lock_module_list(alloc_tag_cttype, true);
	iter = codetag_get_ct_iter(alloc_tag_cttype);
	while ((ct = codetag_next_ct(&iter))) {
		struct alloc_tag_counters counter = alloc_tag_read(ct_to_alloc_tag(ct));
		n.tag	= ct;
		n.bytes = counter.bytes;

		for (i = 0; i < nr; i++)
			if (n.bytes > tags[i].bytes)
				break;

		if (i < ARRAY_SIZE(tags)) {
			nr -= nr == ARRAY_SIZE(tags);
			memmove(&tags[i + 1],
				&tags[i],
				sizeof(tags[0]) * (nr - i));
			nr++;
			tags[i] = n;
		}
	}

	for (i = 0; i < nr; i++)
		alloc_tag_to_text(s, tags[i].tag);

	codetag_lock_module_list(alloc_tag_cttype, false);
}

static void __init procfs_init(void)
{
	proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
}

static bool alloc_tag_module_unload(struct codetag_type *cttype,
				    struct codetag_module *cmod)
{
	struct codetag_iterator iter = codetag_get_ct_iter(cttype);
	struct alloc_tag_counters counter;
	bool module_unused = true;
	struct alloc_tag *tag;
	struct codetag *ct;

	for (ct = codetag_next_ct(&iter); ct; ct = codetag_next_ct(&iter)) {
		if (iter.cmod != cmod)
			continue;

		tag = ct_to_alloc_tag(ct);
		counter = alloc_tag_read(tag);

		if (WARN(counter.bytes, "%s:%u module %s func:%s has %llu allocated at module unload",
			  ct->filename, ct->lineno, ct->modname, ct->function, counter.bytes))
			module_unused = false;
	}

	return module_unused;
}

static __init bool need_page_alloc_tagging(void)
{
	return true;
}

static __init void init_page_alloc_tagging(void)
{
}

struct page_ext_operations page_alloc_tagging_ops = {
	.size = sizeof(union codetag_ref),
	.need = need_page_alloc_tagging,
	.init = init_page_alloc_tagging,
};
EXPORT_SYMBOL(page_alloc_tagging_ops);

static struct ctl_table memory_allocation_profiling_sysctls[] = {
	{
		.procname	= "mem_profiling",
		.data		= &mem_alloc_profiling_key,
#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
		.mode		= 0444,
#else
		.mode		= 0644,
#endif
		.proc_handler	= proc_do_static_key,
	},
	{ }
};

static int __init alloc_tag_init(void)
{
	const struct codetag_type_desc desc = {
		.section	= "alloc_tags",
		.tag_size	= sizeof(struct alloc_tag),
		.module_unload	= alloc_tag_module_unload,
	};

	alloc_tag_cttype = codetag_register_type(&desc);
	if (IS_ERR_OR_NULL(alloc_tag_cttype))
		return PTR_ERR(alloc_tag_cttype);

	register_sysctl_init("vm", memory_allocation_profiling_sysctls);
	procfs_init();

	return 0;
}
module_init(alloc_tag_init);
