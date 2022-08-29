// SPDX-License-Identifier: GPL-2.0-only

#include <linux/codetag_time_stats.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/seq_buf.h>

static struct codetag_type *cttype;

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

struct time_stats_iter {
	struct codetag_iterator ct_iter;
	struct seq_buf		buf;
	char			rawbuf[4096];
	bool			first;
};

static int time_stats_open(struct inode *inode, struct file *file)
{
	struct time_stats_iter *iter;

	pr_debug("called");

	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter)
		return -ENOMEM;

	codetag_lock_module_list(cttype, true);
	codetag_init_iter(&iter->ct_iter, cttype);
	codetag_lock_module_list(cttype, false);

	file->private_data = iter;
	seq_buf_init(&iter->buf, iter->rawbuf, sizeof(iter->rawbuf));
	iter->first = true;
	return 0;
}

static int time_stats_release(struct inode *inode, struct file *file)
{
	struct time_stats_iter *i = file->private_data;

	kfree(i);
	return 0;
}

static ssize_t time_stats_read(struct file *file, char __user *ubuf,
			       size_t size, loff_t *ppos)
{
	struct time_stats_iter *iter = file->private_data;
	struct user_buf	buf = { .buf = ubuf, .size = size };
	struct codetag_time_stats *s;
	struct codetag *ct;
	int err;

	codetag_lock_module_list(iter->ct_iter.cttype, true);
	while (1) {
		err = flush_ubuf(&buf, &iter->buf);
		if (err || !buf.size)
			break;

		ct = codetag_next_ct(&iter->ct_iter);
		if (!ct)
			break;

		s = container_of(ct, struct codetag_time_stats, tag);
		if (s->stats.count) {
			if (!iter->first) {
				seq_buf_putc(&iter->buf, '\n');
				iter->first = true;
			}

			codetag_to_text(&iter->buf, &s->tag);
			seq_buf_putc(&iter->buf, '\n');
			time_stats_to_text(&iter->buf, &s->stats);
		}
	}
	codetag_lock_module_list(iter->ct_iter.cttype, false);

	return err ?: buf.ret;
}

static const struct file_operations time_stats_ops = {
	.owner	= THIS_MODULE,
	.open	= time_stats_open,
	.release = time_stats_release,
	.read	= time_stats_read,
};

static void time_stats_module_unload(struct codetag_type *cttype, struct codetag_module *mod)
{
	struct codetag_time_stats *i, *start = (void *) mod->range.start;
	struct codetag_time_stats *end = (void *) mod->range.stop;

	for (i = start; i != end; i++)
		time_stats_exit(&i->stats);
}

static int __init codetag_time_stats_init(void)
{
	const struct codetag_type_desc desc = {
		.section	= "time_stats_tags",
		.tag_size	= sizeof(struct codetag_time_stats),
		.module_unload	= time_stats_module_unload,
	};
	struct dentry *debugfs_file;

	cttype = codetag_register_type(&desc);
	if (IS_ERR_OR_NULL(cttype))
		return PTR_ERR(cttype);

	debugfs_file = debugfs_create_file("time_stats", 0666, NULL, NULL, &time_stats_ops);
	if (IS_ERR(debugfs_file))
		return PTR_ERR(debugfs_file);

	return 0;
}
module_init(codetag_time_stats_init);
