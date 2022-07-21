// SPDX-License-Identifier: GPL-2.0-only

#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/dynamic_fault.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/seq_buf.h>

static struct codetag_type *cttype;

bool __dynamic_fault_enabled(struct dfault *df)
{
	union dfault_state old, new;
	unsigned int v = df->state.v;
	bool ret;

	do {
		old.v = new.v = v;

		if (new.enabled == DFAULT_disabled)
			return false;

		ret = df->frequency
			? ++new.count >= df->frequency
			: true;
		if (ret)
			new.count = 0;
		if (ret && new.enabled == DFAULT_oneshot)
			new.enabled = DFAULT_disabled;
	} while ((v = cmpxchg(&df->state.v, old.v, new.v)) != old.v);

	if (ret)
		pr_debug("returned true for %s:%u", df->tag.filename, df->tag.lineno);

	return ret;
}
EXPORT_SYMBOL(__dynamic_fault_enabled);

static const char * const dfault_state_strs[] = {
#define x(n)	#n,
	DFAULT_STATES()
#undef x
	NULL
};

static void dynamic_fault_to_text(struct seq_buf *out, struct dfault *df)
{
	codetag_to_text(out, &df->tag);
	seq_buf_printf(out, "class:%s %s \"", df->class,
		       dfault_state_strs[df->state.enabled]);
}

struct dfault_query {
	struct codetag_query q;

	bool		set_enabled:1;
	unsigned int	enabled:2;

	bool		set_frequency:1;
	unsigned int	frequency;
};

/*
 * Search the tables for _dfault's which match the given
 * `query' and apply the `flags' and `mask' to them.  Tells
 * the user which dfault's were changed, or whether none
 * were matched.
 */
static int dfault_change(struct dfault_query *query)
{
	struct codetag_iterator ct_iter;
	struct codetag *ct;
	unsigned int nfound = 0;

	codetag_lock_module_list(cttype, true);
	codetag_init_iter(&ct_iter, cttype);

	while ((ct = codetag_next_ct(&ct_iter))) {
		struct dfault *df = container_of(ct, struct dfault, tag);

		if (!codetag_matches_query(&query->q, ct, ct_iter.cmod, df->class))
			continue;

		if (query->set_enabled &&
		    query->enabled != df->state.enabled) {
			if (query->enabled != DFAULT_disabled)
				static_key_slow_inc(&df->enabled.key);
			else if (df->state.enabled != DFAULT_disabled)
				static_key_slow_dec(&df->enabled.key);

			df->state.enabled = query->enabled;
		}

		if (query->set_frequency)
			df->frequency = query->frequency;

		pr_debug("changed %s:%d [%s]%s #%d %s",
			 df->tag.filename, df->tag.lineno, df->tag.modname,
			 df->tag.function, query->q.cur_index,
			 dfault_state_strs[df->state.enabled]);

		nfound++;
	}

	pr_debug("dfault: %u matches", nfound);

	codetag_lock_module_list(cttype, false);

	return nfound ? 0 : -ENOENT;
}

#define DFAULT_TOKENS()		\
	x(disable,	0)	\
	x(enable,	0)	\
	x(oneshot,	0)	\
	x(frequency,	1)

enum dfault_token {
#define x(name, nr_args)	TOK_##name,
	DFAULT_TOKENS()
#undef x
};

static const char * const dfault_token_strs[] = {
#define x(name, nr_args)	#name,
	DFAULT_TOKENS()
#undef x
	NULL
};

static unsigned int dfault_token_nr_args[] = {
#define x(name, nr_args)	nr_args,
	DFAULT_TOKENS()
#undef x
};

static enum dfault_token str_to_token(const char *word, unsigned int nr_words)
{
	int tok = match_string(dfault_token_strs, ARRAY_SIZE(dfault_token_strs), word);

	if (tok < 0) {
		pr_debug("unknown keyword \"%s\"", word);
		return tok;
	}

	if (nr_words < dfault_token_nr_args[tok]) {
		pr_debug("insufficient arguments to \"%s\"", word);
		return -EINVAL;
	}

	return tok;
}

static int dfault_parse_command(struct dfault_query *query,
				enum dfault_token tok,
				char *words[], size_t nr_words)
{
	unsigned int i = 0;
	int ret;

	switch (tok) {
	case TOK_disable:
		query->set_enabled = true;
		query->enabled = DFAULT_disabled;
		break;
	case TOK_enable:
		query->set_enabled = true;
		query->enabled = DFAULT_enabled;
		break;
	case TOK_oneshot:
		query->set_enabled = true;
		query->enabled = DFAULT_oneshot;
		break;
	case TOK_frequency:
		query->set_frequency = 1;
		ret = kstrtouint(words[i++], 10, &query->frequency);
		if (ret)
			return ret;

		if (!query->set_enabled) {
			query->set_enabled = 1;
			query->enabled = DFAULT_enabled;
		}
		break;
	}

	return i;
}

static int dynamic_fault_store(char *buf)
{
	struct dfault_query query = { NULL };
#define MAXWORDS 9
	char *tok, *words[MAXWORDS];
	int ret, nr_words, i = 0;

	buf = codetag_query_parse(&query.q, buf);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	while ((tok = strsep_no_empty(&buf, " \t\r\n"))) {
		if (nr_words == ARRAY_SIZE(words))
			return -EINVAL;	/* ran out of words[] before bytes */
		words[nr_words++] = tok;
	}

	while (i < nr_words) {
		const char *tok_str = words[i++];
		enum dfault_token tok = str_to_token(tok_str, nr_words - i);

		if (tok < 0)
			return tok;

		ret = dfault_parse_command(&query, tok, words + i, nr_words - i);
		if (ret < 0)
			return ret;

		i += ret;
		BUG_ON(i > nr_words);
	}

	pr_debug("q->function=\"%s\" q->filename=\"%s\" "
		 "q->module=\"%s\" q->line=%u-%u\n q->index=%u-%u",
		 query.q.function, query.q.filename, query.q.module,
		 query.q.first_line, query.q.last_line,
		 query.q.first_index, query.q.last_index);

	ret = dfault_change(&query);
	if (ret < 0)
		return ret;

	return 0;
}

struct dfault_iter {
	struct codetag_iterator ct_iter;

	struct seq_buf		buf;
	char			rawbuf[4096];
};

static int dfault_open(struct inode *inode, struct file *file)
{
	struct dfault_iter *iter;

	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter)
		return -ENOMEM;

	codetag_lock_module_list(cttype, true);
	codetag_init_iter(&iter->ct_iter, cttype);
	codetag_lock_module_list(cttype, false);

	file->private_data = iter;
	seq_buf_init(&iter->buf, iter->rawbuf, sizeof(iter->rawbuf));
	return 0;
}

static int dfault_release(struct inode *inode, struct file *file)
{
	struct dfault_iter *iter = file->private_data;

	kfree(iter);
	return 0;
}

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

static ssize_t dfault_read(struct file *file, char __user *ubuf,
			   size_t size, loff_t *ppos)
{
	struct dfault_iter *iter = file->private_data;
	struct user_buf	buf = { .buf = ubuf, .size = size };
	struct codetag *ct;
	struct dfault *df;
	int err;

	codetag_lock_module_list(iter->ct_iter.cttype, true);
	while (1) {
		err = flush_ubuf(&buf, &iter->buf);
		if (err || !buf.size)
			break;

		ct = codetag_next_ct(&iter->ct_iter);
		if (!ct)
			break;

		df = container_of(ct, struct dfault, tag);
		dynamic_fault_to_text(&iter->buf, df);
		seq_buf_putc(&iter->buf, '\n');
	}
	codetag_lock_module_list(iter->ct_iter.cttype, false);

	return err ?: buf.ret;
}

/*
 * File_ops->write method for <debugfs>/dynamic_fault/conrol.  Gathers the
 * command text from userspace, parses and executes it.
 */
static ssize_t dfault_write(struct file *file, const char __user *ubuf,
			    size_t len, loff_t *offp)
{
	char tmpbuf[256];

	if (len == 0)
		return 0;
	/* we don't check *offp -- multiple writes() are allowed */
	if (len > sizeof(tmpbuf)-1)
		return -E2BIG;
	if (copy_from_user(tmpbuf, ubuf, len))
		return -EFAULT;
	tmpbuf[len] = '\0';
	pr_debug("read %zu bytes from userspace", len);

	dynamic_fault_store(tmpbuf);

	*offp += len;
	return len;
}

static const struct file_operations dfault_ops = {
	.owner	= THIS_MODULE,
	.open	= dfault_open,
	.release = dfault_release,
	.read	= dfault_read,
	.write	= dfault_write
};

static int __init dynamic_fault_init(void)
{
	const struct codetag_type_desc desc = {
		.section = "dynamic_fault_tags",
		.tag_size = sizeof(struct dfault),
	};
	struct dentry *debugfs_file;

	cttype = codetag_register_type(&desc);
	if (IS_ERR_OR_NULL(cttype))
		return PTR_ERR(cttype);

	debugfs_file = debugfs_create_file("dynamic_faults", 0666, NULL, NULL, &dfault_ops);
	if (IS_ERR(debugfs_file))
		return PTR_ERR(debugfs_file);

	return 0;
}
module_init(dynamic_fault_init);
