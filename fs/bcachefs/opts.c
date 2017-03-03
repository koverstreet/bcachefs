
#include <linux/kernel.h>

#include "opts.h"
#include "util.h"

const char * const bch_error_actions[] = {
	"continue",
	"remount-ro",
	"panic",
	NULL
};

const char * const bch_csum_types[] = {
	"none",
	"crc32c",
	"crc64",
	NULL
};

const char * const bch_compression_types[] = {
	"none",
	"lz4",
	"gzip",
	NULL
};

const char * const bch_str_hash_types[] = {
	"crc32c",
	"crc64",
	"siphash",
	NULL
};

const char * const bch_cache_replacement_policies[] = {
	"lru",
	"fifo",
	"random",
	NULL
};

/* Default is -1; we skip past it for struct cached_dev's cache mode */
const char * const bch_cache_modes[] = {
	"default",
	"writethrough",
	"writeback",
	"writearound",
	"none",
	NULL
};

const char * const bch_dev_state[] = {
	"active",
	"readonly",
	"failed",
	"spare",
	NULL
};

const struct bch_option bch_opt_table[] = {
#define OPT_BOOL()		.type = BCH_OPT_BOOL
#define OPT_UINT(_min, _max)	.type = BCH_OPT_UINT, .min = _min, .max = _max
#define OPT_STR(_choices)	.type = BCH_OPT_STR, .choices = _choices

#define BCH_OPT(_name, _mode, _sb_opt, _bits, _type)			\
	[Opt_##_name] = {						\
		.name	= #_name,					\
		.set_sb	= SET_##_sb_opt,				\
		_type							\
	},
	BCH_VISIBLE_OPTS()
#undef BCH_OPT
};

static enum bch_opt_id bch_opt_lookup(const char *name)
{
	const struct bch_option *i;

	for (i = bch_opt_table;
	     i < bch_opt_table + ARRAY_SIZE(bch_opt_table);
	     i++)
		if (!strcmp(name, i->name))
			return i - bch_opt_table;

	return -1;
}

static u64 bch_opt_get(struct bch_opts *opts, enum bch_opt_id id)
{
	switch (id) {
#define BCH_OPT(_name, ...)						\
	case Opt_##_name:						\
		return opts->_name;					\

	BCH_VISIBLE_OPTS()
#undef BCH_OPT

	default:
		BUG();
	}
}

void bch_opt_set(struct bch_opts *opts, enum bch_opt_id id, u64 v)
{
	switch (id) {
#define BCH_OPT(_name, ...)						\
	case Opt_##_name:						\
		opts->_name = v;					\
		break;

	BCH_VISIBLE_OPTS()
#undef BCH_OPT

	default:
		BUG();
	}
}

/*
 * Initial options from superblock - here we don't want any options undefined,
 * any options the superblock doesn't specify are set to 0:
 */
struct bch_opts bch_sb_opts(struct bch_sb *sb)
{
	struct bch_opts opts = bch_opts_empty();

#define BCH_OPT(_name, _mode, _sb_opt, ...)				\
	if (_sb_opt != NO_SB_OPT)					\
		opts._name = _sb_opt(sb);

	BCH_OPTS()
#undef BCH_OPT

	return opts;
}

int parse_one_opt(enum bch_opt_id id, const char *val, u64 *res)
{
	const struct bch_option *opt = &bch_opt_table[id];
	ssize_t ret;

	switch (opt->type) {
	case BCH_OPT_BOOL:
		ret = kstrtou64(val, 10, res);
		if (ret < 0)
			return ret;

		if (*res > 1)
			return -ERANGE;
		break;
	case BCH_OPT_UINT:
		ret = kstrtou64(val, 10, res);
		if (ret < 0)
			return ret;

		if (*res < opt->min || *res >= opt->max)
			return -ERANGE;
		break;
	case BCH_OPT_STR:
		ret = bch_read_string_list(val, opt->choices);
		if (ret < 0)
			return ret;

		*res = ret;
		break;
	}

	return 0;
}

int bch_parse_mount_opts(struct bch_opts *opts, char *options)
{
	char *opt, *name, *val;
	enum bch_opt_id id;
	int ret;
	u64 v;

	while ((opt = strsep(&options, ",")) != NULL) {
		name	= strsep(&opt, "=");
		val	= opt;

		if (val) {
			id = bch_opt_lookup(name);
			if (id < 0)
				return -EINVAL;

			ret = parse_one_opt(id, val, &v);
			if (ret < 0)
				return ret;
		} else {
			id = bch_opt_lookup(name);
			v = 1;

			if (id < 0 &&
			    !strncmp("no", name, 2)) {
				id = bch_opt_lookup(name + 2);
				v = 0;
			}

			if (bch_opt_table[id].type != BCH_OPT_BOOL)
				return -EINVAL;
		}

		bch_opt_set(opts, id, v);
	}

	return 0;
}

enum bch_opt_id bch_parse_sysfs_opt(const char *name, const char *val,
				    u64 *res)
{
	enum bch_opt_id id = bch_opt_lookup(name);
	int ret;

	if (id < 0)
		return -EINVAL;

	ret = parse_one_opt(id, val, res);
	if (ret < 0)
		return ret;

	return id;
}

ssize_t bch_opt_show(struct bch_opts *opts, const char *name,
		     char *buf, size_t size)
{
	enum bch_opt_id id = bch_opt_lookup(name);
	const struct bch_option *opt;
	u64 v;

	if (id < 0)
		return -EINVAL;

	v = bch_opt_get(opts, id);
	opt = &bch_opt_table[id];

	return opt->type == BCH_OPT_STR
		? bch_snprint_string_list(buf, size, opt->choices, v)
		: snprintf(buf, size, "%lli\n", v);
}
