/*
 * lib/dynamic_fault.c
 *
 * make dynamic_fault() calls runtime configurable based upon their
 * source module.
 *
 * Copyright (C) 2011 Adam Berkan <aberkan@google.com>
 * Based on dynamic_debug.c:
 * Copyright (C) 2008 Jason Baron <jbaron@redhat.com>
 * By Greg Banks <gnb@melbourne.sgi.com>
 * Copyright (c) 2008 Silicon Graphics Inc.  All Rights Reserved.
 *
 */

#define pr_fmt(fmt) "dfault: " fmt "\n"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/sysctl.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/dynamic_fault.h>
#include <linux/debugfs.h>
#include <linux/slab.h>

#undef kzalloc

extern struct _dfault __start___faults[];
extern struct _dfault __stop___faults[];

struct dfault_table {
	struct list_head link;
	char *mod_name;
	unsigned int num_dfaults;
	struct _dfault *dfaults;
};

struct dfault_query {
	const char	*filename;
	const char	*module;
	const char	*function;
	const char	*class;
	unsigned int	first_line, last_line;
	unsigned int	first_index, last_index;

	unsigned	match_line:1;
	unsigned	match_index:1;

	unsigned	set_enabled:1;
	unsigned	enabled:2;

	unsigned	set_frequency:1;
	unsigned	frequency;
};

struct dfault_iter {
	struct dfault_table *table;
	unsigned int idx;
};

static DEFINE_MUTEX(dfault_lock);
static LIST_HEAD(dfault_tables);

bool __dynamic_fault_enabled(struct _dfault *df)
{
	union dfault_state old, new;
	unsigned v = df->state.v;
	bool ret;

	do {
		old.v = new.v = v;

		if (new.enabled == DFAULT_DISABLED)
			return false;

		ret = df->frequency
			? ++new.count >= df->frequency
			: true;
		if (ret)
			new.count = 0;
		if (ret && new.enabled == DFAULT_ONESHOT)
			new.enabled = DFAULT_DISABLED;
	} while ((v = cmpxchg(&df->state.v, old.v, new.v)) != old.v);

	if (ret)
		pr_debug("returned true for %s:%u", df->filename, df->line);

	return ret;
}
EXPORT_SYMBOL(__dynamic_fault_enabled);

/* Return the last part of a pathname */
static inline const char *basename(const char *path)
{
	const char *tail = strrchr(path, '/');

	return tail ? tail + 1 : path;
}

/* format a string into buf[] which describes the _dfault's flags */
static char *dfault_describe_flags(struct _dfault *df, char *buf, size_t buflen)
{
	switch (df->state.enabled) {
	case DFAULT_DISABLED:
		strlcpy(buf, "disabled", buflen);
		break;
	case DFAULT_ENABLED:
		strlcpy(buf, "enabled", buflen);
		break;
	case DFAULT_ONESHOT:
		strlcpy(buf, "oneshot", buflen);
		break;
	default:
		BUG();
	}

	return buf;
}

/*
 * must be called with dfault_lock held
 */

/*
 * Search the tables for _dfault's which match the given
 * `query' and apply the `flags' and `mask' to them.  Tells
 * the user which dfault's were changed, or whether none
 * were matched.
 */
static int dfault_change(const struct dfault_query *query)
{
	struct dfault_table *dt;
	unsigned int nfound = 0;
	unsigned i, index = 0;
	char flagbuf[16];

	/* search for matching dfaults */
	mutex_lock(&dfault_lock);
	list_for_each_entry(dt, &dfault_tables, link) {

		/* match against the module name */
		if (query->module != NULL &&
		    strcmp(query->module, dt->mod_name))
			continue;

		for (i = 0 ; i < dt->num_dfaults ; i++) {
			struct _dfault *df = &dt->dfaults[i];

			/* match against the source filename */
			if (query->filename != NULL &&
			    strcmp(query->filename, df->filename) &&
			    strcmp(query->filename, basename(df->filename)))
				continue;

			/* match against the function */
			if (query->function != NULL &&
			    strcmp(query->function, df->function))
				continue;

			/* match against the class */
			if (query->class) {
				size_t len = strlen(query->class);

				if (strncmp(query->class, df->class, len))
					continue;

				if (df->class[len] && df->class[len] != ':')
					continue;
			}

			/* match against the line number range */
			if (query->match_line &&
			    (df->line < query->first_line ||
			     df->line > query->last_line))
				continue;

			/* match against the fault index */
			if (query->match_index &&
			    (index < query->first_index ||
			     index > query->last_index)) {
				index++;
				continue;
			}

			if (query->set_enabled &&
			    query->enabled != df->state.enabled) {
				if (query->enabled != DFAULT_DISABLED)
					static_key_slow_inc(&df->enabled);
				else if (df->state.enabled != DFAULT_DISABLED)
					static_key_slow_dec(&df->enabled);

				df->state.enabled = query->enabled;
			}

			if (query->set_frequency)
				df->frequency = query->frequency;

			pr_debug("changed %s:%d [%s]%s #%d %s",
				 df->filename, df->line, dt->mod_name,
				 df->function, index,
				 dfault_describe_flags(df, flagbuf,
						       sizeof(flagbuf)));

			index++;
			nfound++;
		}
	}
	mutex_unlock(&dfault_lock);

	pr_debug("dfault: %u matches", nfound);

	return nfound ? 0 : -ENOENT;
}

/*
 * Split the buffer `buf' into space-separated words.
 * Handles simple " and ' quoting, i.e. without nested,
 * embedded or escaped \".  Return the number of words
 * or <0 on error.
 */
static int dfault_tokenize(char *buf, char *words[], int maxwords)
{
	int nwords = 0;

	while (*buf) {
		char *end;

		/* Skip leading whitespace */
		buf = skip_spaces(buf);
		if (!*buf)
			break;	/* oh, it was trailing whitespace */

		/* Run `end' over a word, either whitespace separated or quoted
		 */
		if (*buf == '"' || *buf == '\'') {
			int quote = *buf++;

			for (end = buf ; *end && *end != quote ; end++)
				;
			if (!*end)
				return -EINVAL;	/* unclosed quote */
		} else {
			for (end = buf ; *end && !isspace(*end) ; end++)
				;
			BUG_ON(end == buf);
		}
		/* Here `buf' is the start of the word, `end' is one past the
		 * end
		 */

		if (nwords == maxwords)
			return -EINVAL;	/* ran out of words[] before bytes */
		if (*end)
			*end++ = '\0';	/* terminate the word */
		words[nwords++] = buf;
		buf = end;
	}

	return nwords;
}

/*
 * Parse a range.
 */
static inline int parse_range(char *str,
			      unsigned int *first,
			      unsigned int *last)
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

enum dfault_token {
	TOK_INVALID,

	/* Queries */
	TOK_FUNC,
	TOK_FILE,
	TOK_LINE,
	TOK_MODULE,
	TOK_CLASS,
	TOK_INDEX,

	/* Commands */
	TOK_DISABLE,
	TOK_ENABLE,
	TOK_ONESHOT,
	TOK_FREQUENCY,
};

static const struct {
	const char		*str;
	enum dfault_token	tok;
	unsigned		args_required;
} dfault_token_strs[] = {
	{ "func",	TOK_FUNC,	1,	},
	{ "file",	TOK_FILE,	1,	},
	{ "line",	TOK_LINE,	1,	},
	{ "module",	TOK_MODULE,	1,	},
	{ "class",	TOK_CLASS,	1,	},
	{ "index",	TOK_INDEX,	1,	},
	{ "disable",	TOK_DISABLE,	0,	},
	{ "enable",	TOK_ENABLE,	0,	},
	{ "oneshot",	TOK_ONESHOT,	0,	},
	{ "frequency",	TOK_FREQUENCY,	1,	},
};

static enum dfault_token str_to_token(const char *word, unsigned nr_words)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(dfault_token_strs); i++)
		if (!strcmp(word, dfault_token_strs[i].str)) {
			if (nr_words < dfault_token_strs[i].args_required) {
				pr_debug("insufficient arguments to \"%s\"",
					 word);
				return TOK_INVALID;
			}

			return dfault_token_strs[i].tok;
		}

	pr_debug("unknown keyword \"%s\"", word);

	return TOK_INVALID;
}

static int dfault_parse_command(struct dfault_query *query,
				enum dfault_token tok,
				char *words[], size_t nr_words)
{
	unsigned i = 0;
	int ret;

	switch (tok) {
	case TOK_INVALID:
		return -EINVAL;
	case TOK_FUNC:
		query->function = words[i++];
	case TOK_FILE:
		query->filename = words[i++];
		return 1;
	case TOK_LINE:
		ret = parse_range(words[i++],
				  &query->first_line,
				  &query->last_line);
		if (ret)
			return ret;
		query->match_line = true;
		break;
	case TOK_MODULE:
		query->module = words[i++];
		break;
	case TOK_CLASS:
		query->class = words[i++];
		break;
	case TOK_INDEX:
		ret = parse_range(words[i++],
				  &query->first_index,
				  &query->last_index);
		if (ret)
			return ret;
		query->match_index = true;
		break;
	case TOK_DISABLE:
		query->set_enabled = true;
		query->enabled = DFAULT_DISABLED;
		break;
	case TOK_ENABLE:
		query->set_enabled = true;
		query->enabled = DFAULT_ENABLED;
		break;
	case TOK_ONESHOT:
		query->set_enabled = true;
		query->enabled = DFAULT_ONESHOT;
		break;
	case TOK_FREQUENCY:
		query->set_frequency = 1;
		ret = kstrtouint(words[i++], 10, &query->frequency);
		if (ret)
			return ret;

		if (!query->set_enabled) {
			query->set_enabled = 1;
			query->enabled = DFAULT_ENABLED;
		}
		break;
	}

	return i;
}

/*
 * Parse words[] as a dfault query specification, which is a series
 * of (keyword, value) pairs chosen from these possibilities:
 *
 * func <function-name>
 * file <full-pathname>
 * file <base-filename>
 * module <module-name>
 * line <lineno>
 * line <first-lineno>-<last-lineno> // where either may be empty
 * index <m>-<n>                     // dynamic faults numbered from <m>
 *                                   // to <n> inside each matching function
 */
static int dfault_parse_query(struct dfault_query *query,
			      char *words[], size_t nr_words)
{
	unsigned i = 0;

	while (i < nr_words) {
		const char *tok_str = words[i++];
		enum dfault_token tok = str_to_token(tok_str, nr_words - i);
		int ret = dfault_parse_command(query, tok, words + i,
					       nr_words - i);

		if (ret < 0)
			return ret;
		i += ret;
		BUG_ON(i > nr_words);
	}

	return 0;
}

/*
 * File_ops->write method for <debugfs>/dynamic_fault/conrol.  Gathers the
 * command text from userspace, parses and executes it.
 */
static ssize_t dfault_proc_write(struct file *file, const char __user *ubuf,
				  size_t len, loff_t *offp)
{
	struct dfault_query query;
#define MAXWORDS 9
	int nwords;
	char *words[MAXWORDS];
	char tmpbuf[256];
	int ret;

	memset(&query, 0, sizeof(query));

	if (len == 0)
		return 0;
	/* we don't check *offp -- multiple writes() are allowed */
	if (len > sizeof(tmpbuf)-1)
		return -E2BIG;
	if (copy_from_user(tmpbuf, ubuf, len))
		return -EFAULT;
	tmpbuf[len] = '\0';

	pr_debug("read %zu bytes from userspace", len);

	nwords = dfault_tokenize(tmpbuf, words, MAXWORDS);
	if (nwords < 0)
		return -EINVAL;
	if (dfault_parse_query(&query, words, nwords))
		return -EINVAL;

	/* actually go and implement the change */
	ret = dfault_change(&query);
	if (ret < 0)
		return ret;

	*offp += len;
	return len;
}

/* Control file read code */

/*
 * Set the iterator to point to the first _dfault object
 * and return a pointer to that first object.  Returns
 * NULL if there are no _dfaults at all.
 */
static struct _dfault *dfault_iter_first(struct dfault_iter *iter)
{
	if (list_empty(&dfault_tables)) {
		iter->table = NULL;
		iter->idx = 0;
		return NULL;
	}
	iter->table = list_entry(dfault_tables.next,
				 struct dfault_table, link);
	iter->idx = 0;
	return &iter->table->dfaults[iter->idx];
}

/*
 * Advance the iterator to point to the next _dfault
 * object from the one the iterator currently points at,
 * and returns a pointer to the new _dfault.  Returns
 * NULL if the iterator has seen all the _dfaults.
 */
static struct _dfault *dfault_iter_next(struct dfault_iter *iter)
{
	if (iter->table == NULL)
		return NULL;
	if (++iter->idx == iter->table->num_dfaults) {
		/* iterate to next table */
		iter->idx = 0;
		if (list_is_last(&iter->table->link, &dfault_tables)) {
			iter->table = NULL;
			return NULL;
		}
		iter->table = list_entry(iter->table->link.next,
					 struct dfault_table, link);
	}
	return &iter->table->dfaults[iter->idx];
}

/*
 * Seq_ops start method.  Called at the start of every
 * read() call from userspace.  Takes the dfault_lock and
 * seeks the seq_file's iterator to the given position.
 */
static void *dfault_proc_start(struct seq_file *m, loff_t *pos)
{
	struct dfault_iter *iter = m->private;
	struct _dfault *dp;
	int n = *pos;

	mutex_lock(&dfault_lock);

	if (n < 0)
		return NULL;
	dp = dfault_iter_first(iter);
	while (dp != NULL && --n >= 0)
		dp = dfault_iter_next(iter);
	return dp;
}

/*
 * Seq_ops next method.  Called several times within a read()
 * call from userspace, with dfault_lock held.  Walks to the
 * next _dfault object with a special case for the header line.
 */
static void *dfault_proc_next(struct seq_file *m, void *p, loff_t *pos)
{
	struct dfault_iter *iter = m->private;
	struct _dfault *dp;

	if (p == SEQ_START_TOKEN)
		dp = dfault_iter_first(iter);
	else
		dp = dfault_iter_next(iter);
	++*pos;
	return dp;
}

/*
 * Seq_ops show method.  Called several times within a read()
 * call from userspace, with dfault_lock held.  Formats the
 * current _dfault as a single human-readable line, with a
 * special case for the header line.
 */
static int dfault_proc_show(struct seq_file *m, void *p)
{
	struct dfault_iter *iter = m->private;
	struct _dfault *df = p;
	char flagsbuf[8];

	seq_printf(m, "%s:%u class:%s module:%s func:%s %s \"\"\n",
		   df->filename, df->line, df->class,
		   iter->table->mod_name, df->function,
		   dfault_describe_flags(df, flagsbuf, sizeof(flagsbuf)));

	return 0;
}

/*
 * Seq_ops stop method.  Called at the end of each read()
 * call from userspace.  Drops dfault_lock.
 */
static void dfault_proc_stop(struct seq_file *m, void *p)
{
	mutex_unlock(&dfault_lock);
}

static const struct seq_operations dfault_proc_seqops = {
	.start = dfault_proc_start,
	.next = dfault_proc_next,
	.show = dfault_proc_show,
	.stop = dfault_proc_stop
};

/*
 * File_ops->open method for <debugfs>/dynamic_fault/control.  Does the seq_file
 * setup dance, and also creates an iterator to walk the _dfaults.
 * Note that we create a seq_file always, even for O_WRONLY files
 * where it's not needed, as doing so simplifies the ->release method.
 */
static int dfault_proc_open(struct inode *inode, struct file *file)
{
	struct dfault_iter *iter;
	int err;

	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (iter == NULL)
		return -ENOMEM;

	err = seq_open(file, &dfault_proc_seqops);
	if (err) {
		kfree(iter);
		return err;
	}
	((struct seq_file *) file->private_data)->private = iter;
	return 0;
}

static const struct file_operations dfault_proc_fops = {
	.owner = THIS_MODULE,
	.open = dfault_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
	.write = dfault_proc_write
};

/*
 * Allocate a new dfault_table for the given module
 * and add it to the global list.
 */
int dfault_add_module(struct _dfault *tab, unsigned int n,
		      const char *name)
{
	struct dfault_table *dt;
	char *new_name;
	const char *func = NULL;
	int i;

	dt = kzalloc(sizeof(*dt), GFP_KERNEL);
	if (dt == NULL)
		return -ENOMEM;
	new_name = kstrdup(name, GFP_KERNEL);
	if (new_name == NULL) {
		kfree(dt);
		return -ENOMEM;
	}
	dt->mod_name = new_name;
	dt->num_dfaults = n;
	dt->dfaults = tab;

	mutex_lock(&dfault_lock);
	list_add_tail(&dt->link, &dfault_tables);
	mutex_unlock(&dfault_lock);

	/* __attribute__(("section")) emits things in reverse order */
	for (i = n - 1; i >= 0; i--)
		if (!func || strcmp(tab[i].function, func))
			func = tab[i].function;

	return 0;
}
EXPORT_SYMBOL_GPL(dfault_add_module);

static void dfault_table_free(struct dfault_table *dt)
{
	list_del_init(&dt->link);
	kfree(dt->mod_name);
	kfree(dt);
}

/*
 * Called in response to a module being unloaded.  Removes
 * any dfault_table's which point at the module.
 */
int dfault_remove_module(char *mod_name)
{
	struct dfault_table *dt, *nextdt;
	int ret = -ENOENT;

	mutex_lock(&dfault_lock);
	list_for_each_entry_safe(dt, nextdt, &dfault_tables, link) {
		if (!strcmp(dt->mod_name, mod_name)) {
			dfault_table_free(dt);
			ret = 0;
		}
	}
	mutex_unlock(&dfault_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(dfault_remove_module);

static void dfault_remove_all_tables(void)
{
	mutex_lock(&dfault_lock);
	while (!list_empty(&dfault_tables)) {
		struct dfault_table *dt = list_entry(dfault_tables.next,
						      struct dfault_table,
						      link);
		dfault_table_free(dt);
	}
	mutex_unlock(&dfault_lock);
}

static int __init dynamic_fault_init(void)
{
	struct dentry *dir, *file;
	struct _dfault *iter, *iter_start;
	const char *modname = NULL;
	int ret = 0;
	int n = 0;

	dir = debugfs_create_dir("dynamic_fault", NULL);
	if (!dir)
		return -ENOMEM;
	file = debugfs_create_file("control", 0644, dir, NULL,
					&dfault_proc_fops);
	if (!file) {
		debugfs_remove(dir);
		return -ENOMEM;
	}
	if (__start___faults != __stop___faults) {
		iter = __start___faults;
		modname = iter->modname;
		iter_start = iter;
		for (; iter < __stop___faults; iter++) {
			if (strcmp(modname, iter->modname)) {
				ret = dfault_add_module(iter_start, n, modname);
				if (ret)
					goto out_free;
				n = 0;
				modname = iter->modname;
				iter_start = iter;
			}
			n++;
		}
		ret = dfault_add_module(iter_start, n, modname);
	}
out_free:
	if (ret) {
		dfault_remove_all_tables();
		debugfs_remove(dir);
		debugfs_remove(file);
	}
	return 0;
}
module_init(dynamic_fault_init);
