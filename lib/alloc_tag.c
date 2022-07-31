// SPDX-License-Identifier: GPL-2.0-only
#include <linux/alloc_tag.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/page_ext.h>
#include <linux/seq_buf.h>
#include <linux/uaccess.h>

DEFINE_STATIC_KEY_TRUE(mem_alloc_profiling_key);

/*
 * Won't need to be exported once page allocation accounting is moved to the
 * correct place:
 */
EXPORT_SYMBOL(mem_alloc_profiling_key);

static int __init mem_alloc_profiling_disable(char *s)
{
	static_branch_disable(&mem_alloc_profiling_key);
	return 1;
}
__setup("nomem_profiling", mem_alloc_profiling_disable);

struct alloc_tag_file_iterator {
	struct codetag_iterator ct_iter;
	struct seq_buf		buf;
	char			rawbuf[4096];
};

struct user_buf {
	char __user		*buf;	/* destination user buffer */
	size_t			size;	/* size of requested read */
	ssize_t			ret;	/* bytes read so far */
};

static int flush_ubuf(struct user_buf *dst, struct seq_buf *src)
{
	if (src->len) {
		size_t bytes = min_t(size_t, src->len, dst->size);
		int err = copy_to_user(dst->buf, src->buffer, bytes);

		if (err)
			return err;

		dst->ret	+= bytes;
		dst->buf	+= bytes;
		dst->size	-= bytes;
		src->len	-= bytes;
		memmove(src->buffer, src->buffer + bytes, src->len);
	}

	return 0;
}

static int allocations_file_open(struct inode *inode, struct file *file)
{
	struct codetag_type *cttype = inode->i_private;
	struct alloc_tag_file_iterator *iter;

	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter)
		return -ENOMEM;

	codetag_lock_module_list(cttype, true);
	iter->ct_iter = codetag_get_ct_iter(cttype);
	codetag_lock_module_list(cttype, false);
	seq_buf_init(&iter->buf, iter->rawbuf, sizeof(iter->rawbuf));
	file->private_data = iter;

	return 0;
}

static int allocations_file_release(struct inode *inode, struct file *file)
{
	struct alloc_tag_file_iterator *iter = file->private_data;

	kfree(iter);
	return 0;
}

static void alloc_tag_to_text(struct seq_buf *out, struct codetag *ct)
{
	struct alloc_tag *tag = ct_to_alloc_tag(ct);
	char buf[10];

	string_get_size(lazy_percpu_counter_read(&tag->bytes_allocated), 1,
			STRING_UNITS_2, buf, sizeof(buf));

	seq_buf_printf(out, "%8s ", buf);
	codetag_to_text(out, ct);
	seq_buf_putc(out, '\n');
}

static ssize_t allocations_file_read(struct file *file, char __user *ubuf,
				     size_t size, loff_t *ppos)
{
	struct alloc_tag_file_iterator *iter = file->private_data;
	struct user_buf	buf = { .buf = ubuf, .size = size };
	struct codetag *ct;
	int err = 0;

	codetag_lock_module_list(iter->ct_iter.cttype, true);
	while (1) {
		err = flush_ubuf(&buf, &iter->buf);
		if (err || !buf.size)
			break;

		ct = codetag_next_ct(&iter->ct_iter);
		if (!ct)
			break;

		alloc_tag_to_text(&iter->buf, ct);
	}
	codetag_lock_module_list(iter->ct_iter.cttype, false);

	return err ? : buf.ret;
}

static const struct file_operations allocations_file_ops = {
	.owner	= THIS_MODULE,
	.open	= allocations_file_open,
	.release = allocations_file_release,
	.read	= allocations_file_read,
};

static int __init dbgfs_init(struct codetag_type *cttype)
{
	struct dentry *file;

	file = debugfs_create_file("allocations", 0444, NULL, cttype,
				   &allocations_file_ops);

	return IS_ERR(file) ? PTR_ERR(file) : 0;
}

static void alloc_tag_module_unload(struct codetag_type *cttype, struct codetag_module *cmod)
{
	struct codetag_iterator iter = codetag_get_ct_iter(cttype);
	struct codetag *ct;

	for (ct = codetag_next_ct(&iter); ct; ct = codetag_next_ct(&iter)) {
		struct alloc_tag *tag = ct_to_alloc_tag(ct);

		lazy_percpu_counter_exit(&tag->bytes_allocated);
	}
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

static int __init alloc_tag_init(void)
{
	struct codetag_type *cttype;
	const struct codetag_type_desc desc = {
		.section	= "alloc_tags",
		.tag_size	= sizeof(struct alloc_tag),
		.module_unload	= alloc_tag_module_unload,
	};

	cttype = codetag_register_type(&desc);
	if (IS_ERR_OR_NULL(cttype))
		return PTR_ERR(cttype);

	return dbgfs_init(cttype);
}
module_init(alloc_tag_init);
