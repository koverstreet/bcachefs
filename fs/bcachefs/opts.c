
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

const char * const bch_cache_state[] = {
	"active",
	"readonly",
	"failed",
	"spare",
	NULL
};


const char * const bch_bool_opt[] = {
	"0",
	"1",
	NULL
};

const char * const bch_uint_opt[] = {
	NULL
};

enum bch_opts {
#define CACHE_SET_OPT(_name, _choices, _min, _max, _sb_opt, _perm)	\
	Opt_##_name,

	CACHE_SET_VISIBLE_OPTS()
#undef CACHE_SET_OPT

	Opt_bad_opt,
};

struct bch_option {
	const char		*name;
	const char * const	*opts;
	unsigned long		min, max;
};

struct bch_opt_result {
	enum bch_opts		opt;
	unsigned		val;
};

static int parse_bool_opt(const struct bch_option *opt, const char *s)
{
	if (!strcmp(opt->name, s))
		return true;

	if (!strncmp("no", s, 2) && !strcmp(opt->name, s + 2))
		return false;

	return -1;
}

static int parse_uint_opt(const struct bch_option *opt, const char *s)
{
	unsigned long v;
	int ret;

	if (strncmp(opt->name, s, strlen(opt->name)))
		return -1;

	s += strlen(opt->name);

	if (*s != '=')
		return -1;

	s++;

	ret = kstrtoul(s, 10, &v);
	if (ret)
		return ret;

	if (v < opt->min || v >= opt->max)
		return -ERANGE;

	return 0;
}

static int parse_string_opt(const struct bch_option *opt, const char *s)
{
	if (strncmp(opt->name, s, strlen(opt->name)))
		return -1;

	s += strlen(opt->name);

	if (*s != '=')
		return -1;

	s++;

	return bch_read_string_list(s, opt->opts);
}

static struct bch_opt_result parse_one_opt(const char *opt)
{
	static const struct bch_option opt_table[] = {
#define CACHE_SET_OPT(_name, _choices, _min, _max, _sb_opt, _perm)	\
		[Opt_##_name] = {					\
			.name = #_name,					\
			.opts = _choices,				\
			.min = _min,					\
			.max = _max,					\
		},
		CACHE_SET_VISIBLE_OPTS()
#undef CACHE_SET_OPT
	}, *i;

	for (i = opt_table;
	     i < opt_table + ARRAY_SIZE(opt_table);
	     i++) {
		int res = i->opts == bch_bool_opt ? parse_bool_opt(i, opt)
			: i->opts == bch_uint_opt ? parse_uint_opt(i, opt)
			: parse_string_opt(i, opt);

		if (res >= 0)
			return (struct bch_opt_result) {
				i - opt_table, res
			};
	}

	return (struct bch_opt_result) { Opt_bad_opt };
}

int bch_parse_options(struct cache_set_opts *opts, int flags, char *options)
{
	char *p;

	*opts = cache_set_opts_empty();

	opts->read_only = (flags & MS_RDONLY) != 0;

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		struct bch_opt_result res = parse_one_opt(p);

		switch (res.opt) {
#define CACHE_SET_OPT(_name, _choices, _min, _max, _sb_opt, _perm)	\
		case Opt_##_name:					\
			opts->_name = res.val;				\
			break;

		CACHE_SET_VISIBLE_OPTS()
#undef CACHE_SET_OPT

		case Opt_bad_opt:
			return -EINVAL;
		default:
			BUG();
		}
	}

	return 0;
}
