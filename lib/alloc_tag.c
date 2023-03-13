// SPDX-License-Identifier: GPL-2.0-only
#include <linux/alloc_tag.h>
#include <linux/codetag_ctx.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/page_ext.h>
#include <linux/sched/clock.h>
#include <linux/seq_buf.h>
#include <linux/stackdepot.h>
#include <linux/uaccess.h>

#define STACK_BUF_SIZE 1024

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

struct alloc_call_ctx {
	struct codetag_ctx ctx;
	size_t size;
	pid_t pid;
	pid_t tgid;
	char comm[TASK_COMM_LEN];
	u64 ts_nsec;
	depot_stack_handle_t stack_handle;
} __aligned(8);

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
	codetag_init_iter(&iter->ct_iter, cttype);
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

static void alloc_tag_ops_free_ctx(struct kref *refcount)
{
	kfree(container_of(kref_to_ctx(refcount), struct alloc_call_ctx, ctx));
}

struct codetag_ctx *alloc_tag_create_ctx(struct alloc_tag *tag, size_t size)
{
	struct alloc_call_ctx *ac_ctx;

	/* TODO: use a dedicated kmem_cache */
	ac_ctx = kmalloc(sizeof(struct alloc_call_ctx), GFP_KERNEL);
	if (WARN_ON(!ac_ctx))
		return NULL;

	ac_ctx->size = size;
	ac_ctx->pid = current->pid;
	ac_ctx->tgid = current->tgid;
	strscpy(ac_ctx->comm, current->comm, sizeof(ac_ctx->comm));
	ac_ctx->ts_nsec = local_clock();
	ac_ctx->stack_handle =
			stack_depot_capture_stack(GFP_NOWAIT | __GFP_NOWARN);
	add_ctx(&ac_ctx->ctx, &tag->ctc);

	return &ac_ctx->ctx;
}
EXPORT_SYMBOL_GPL(alloc_tag_create_ctx);

void alloc_tag_free_ctx(struct codetag_ctx *ctx, struct alloc_tag **ptag)
{
	*ptag = ctc_to_alloc_tag(ctx->ctc);
	rem_ctx(ctx, alloc_tag_ops_free_ctx);
}
EXPORT_SYMBOL_GPL(alloc_tag_free_ctx);

bool alloc_tag_enable_ctx(struct alloc_tag *tag, bool enable)
{
	static bool stack_depot_ready;

	if (enable && !stack_depot_ready) {
		stack_depot_init();
		stack_depot_capture_init();
		stack_depot_ready = true;
	}

	return codetag_enable_ctx(&tag->ctc, enable);
}

static void alloc_tag_ctx_to_text(struct seq_buf *out, struct codetag_ctx *ctx)
{
	struct alloc_call_ctx *ac_ctx;
	char *buf;

	ac_ctx = container_of(ctx, struct alloc_call_ctx, ctx);
	seq_buf_printf(out, "    size: %zu\n", ac_ctx->size);
	seq_buf_printf(out, "    pid: %d\n", ac_ctx->pid);
	seq_buf_printf(out, "    tgid: %d\n", ac_ctx->tgid);
	seq_buf_printf(out, "    comm: %s\n", ac_ctx->comm);
	seq_buf_printf(out, "    ts: %llu\n", ac_ctx->ts_nsec);

	buf = kmalloc(STACK_BUF_SIZE, GFP_KERNEL);
	if (buf) {
		int bytes_read = stack_depot_snprint(ac_ctx->stack_handle, buf,
						     STACK_BUF_SIZE - 1, 8);
		buf[bytes_read] = '\0';
		seq_buf_printf(out, "    call stack:\n%s\n", buf);
	}
	kfree(buf);
}

static ssize_t allocations_ctx_file_read(struct file *file, char __user *ubuf,
					 size_t size, loff_t *ppos)
{
	struct alloc_tag_file_iterator *iter = file->private_data;
	struct codetag_iterator *ct_iter = &iter->ct_iter;
	struct user_buf	buf = { .buf = ubuf, .size = size };
	struct codetag_ctx *ctx;
	struct codetag *prev_ct;
	int err = 0;

	codetag_lock_module_list(ct_iter->cttype, true);
	while (1) {
		err = flush_ubuf(&buf, &iter->buf);
		if (err || !buf.size)
			break;

		prev_ct = ct_iter->ct;
		ctx = codetag_next_ctx(ct_iter);
		if (!ctx)
			break;

		if (prev_ct != &ctx->ctc->ct)
			alloc_tag_to_text(&iter->buf, &ctx->ctc->ct);
		alloc_tag_ctx_to_text(&iter->buf, ctx);
	}
	codetag_lock_module_list(ct_iter->cttype, false);

	return err ? : buf.ret;
}

#define CTX_CAPTURE_TOKENS()	\
	x(disable,	0)	\
	x(enable,	0)

static const char * const ctx_capture_token_strs[] = {
#define x(name, nr_args)	#name,
	CTX_CAPTURE_TOKENS()
#undef x
	NULL
};

enum ctx_capture_token {
#define x(name, nr_args)	TOK_##name,
	CTX_CAPTURE_TOKENS()
#undef x
};

static int enable_ctx_capture(struct codetag_type *cttype,
			      struct codetag_query *query, bool enable)
{
	struct codetag_iterator ct_iter;
	struct codetag_with_ctx *ctc;
	struct codetag *ct;
	unsigned int nfound = 0;

	codetag_lock_module_list(cttype, true);

	codetag_init_iter(&ct_iter, cttype);
	while ((ct = codetag_next_ct(&ct_iter))) {
		if (!codetag_matches_query(query, ct, ct_iter.cmod, NULL))
			continue;

		ctc = ct_to_ctc(ct);
		if (codetag_ctx_enabled(ctc) == enable)
			continue;

		if (!alloc_tag_enable_ctx(ctc_to_alloc_tag(ctc), enable)) {
			pr_warn("Failed to toggle context capture\n");
			continue;
		}

		nfound++;
	}

	codetag_lock_module_list(cttype, false);

	return nfound ? 0 : -ENOENT;
}

static int parse_command(struct codetag_type *cttype, char *buf)
{
	struct codetag_query query = { NULL };
	char *cmd;
	int ret;
	int tok;

	buf = codetag_query_parse(&query, buf);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	cmd = strsep_no_empty(&buf, " \t\r\n");
	if (!cmd)
		return -EINVAL;	/* no command */

	tok = match_string(ctx_capture_token_strs,
			   ARRAY_SIZE(ctx_capture_token_strs), cmd);
	if (tok < 0)
		return -EINVAL;	/* unknown command */

	ret = enable_ctx_capture(cttype, &query, tok == TOK_enable);
	if (ret < 0)
		return ret;

	return 0;
}

static ssize_t allocations_ctx_file_write(struct file *file, const char __user *ubuf,
					  size_t len, loff_t *offp)
{
	struct alloc_tag_file_iterator *iter = file->private_data;
	char tmpbuf[256];

	if (len == 0)
		return 0;
	/* we don't check *offp -- multiple writes() are allowed */
	if (len > sizeof(tmpbuf) - 1)
		return -E2BIG;

	if (copy_from_user(tmpbuf, ubuf, len))
		return -EFAULT;

	tmpbuf[len] = '\0';
	parse_command(iter->ct_iter.cttype, tmpbuf);

	*offp += len;
	return len;
}

static const struct file_operations allocations_ctx_file_ops = {
	.owner	= THIS_MODULE,
	.open	= allocations_file_open,
	.release = allocations_file_release,
	.read	= allocations_ctx_file_read,
	.write	= allocations_ctx_file_write,
};

static int __init dbgfs_init(struct codetag_type *cttype)
{
	struct dentry *file;
	struct dentry *ctx_file;

	file = debugfs_create_file("allocations", 0444, NULL, cttype,
				   &allocations_file_ops);
	if (IS_ERR(file))
		return PTR_ERR(file);

	ctx_file = debugfs_create_file("allocations.ctx", 0666, NULL, cttype,
				       &allocations_ctx_file_ops);
	if (IS_ERR(ctx_file)) {
		debugfs_remove(file);
		return PTR_ERR(ctx_file);
	}

	return 0;
}

static void alloc_tag_module_unload(struct codetag_type *cttype, struct codetag_module *cmod)
{
	struct codetag_iterator iter;
	struct codetag *ct;

	codetag_init_iter(&iter, cttype);
	for (ct = codetag_next_ct(&iter); ct; ct = codetag_next_ct(&iter)) {
		struct alloc_tag *tag = ct_to_alloc_tag(ct);
		size_t bytes = lazy_percpu_counter_read(&tag->bytes_allocated);

		if (!WARN(bytes, "%s:%u module %s func:%s has %zu allocated at module unload",
			  ct->filename, ct->lineno, ct->modname, ct->function))
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
		.free_ctx	= alloc_tag_ops_free_ctx,
	};

	cttype = codetag_register_type(&desc);
	if (IS_ERR_OR_NULL(cttype))
		return PTR_ERR(cttype);

	return dbgfs_init(cttype);
}
module_init(alloc_tag_init);
