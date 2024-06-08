// SPDX-License-Identifier: GPL-2.0
/*
 * bcache sysfs interfaces
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#ifndef NO_BCACHEFS_SYSFS

#include "bcachefs.h"
#include "alloc_background.h"
#include "alloc_foreground.h"
#include "sysfs.h"
#include "btree_cache.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_key_cache.h"
#include "btree_update.h"
#include "btree_gc.h"
#include "buckets.h"
#include "clock.h"
#include "compress.h"
#include "disk_accounting.h"
#include "disk_groups.h"
#include "ec.h"
#include "inode.h"
#include "journal.h"
#include "journal_reclaim.h"
#include "keylist.h"
#include "move.h"
#include "movinggc.h"
#include "nocow_locking.h"
#include "opts.h"
#include "rebalance.h"
#include "replicas.h"
#include "super-io.h"
#include "tests.h"

#include <linux/blkdev.h>
#include <linux/sort.h>
#include <linux/sched/clock.h>

#include "util.h"

#define SYSFS_OPS(type)							\
const struct sysfs_ops type ## _sysfs_ops = {				\
	.show	= type ## _show,					\
	.store	= type ## _store					\
}

#define SHOW(fn)							\
static ssize_t fn ## _to_text(struct printbuf *,			\
			      struct kobject *, struct attribute *);	\
									\
static ssize_t fn ## _show(struct kobject *kobj, struct attribute *attr,\
			   char *buf)					\
{									\
	struct printbuf out = PRINTBUF;					\
	ssize_t ret = fn ## _to_text(&out, kobj, attr);			\
									\
	if (out.pos && out.buf[out.pos - 1] != '\n')			\
		prt_newline(&out);					\
									\
	if (!ret && out.allocation_failure)				\
		ret = -ENOMEM;						\
									\
	if (!ret) {							\
		ret = min_t(size_t, out.pos, PAGE_SIZE - 1);		\
		memcpy(buf, out.buf, ret);				\
	}								\
	printbuf_exit(&out);						\
	return bch2_err_class(ret);					\
}									\
									\
static ssize_t fn ## _to_text(struct printbuf *out, struct kobject *kobj,\
			      struct attribute *attr)

#define STORE(fn)							\
static ssize_t fn ## _store_inner(struct kobject *, struct attribute *,\
			    const char *, size_t);			\
									\
static ssize_t fn ## _store(struct kobject *kobj, struct attribute *attr,\
			    const char *buf, size_t size)		\
{									\
	return bch2_err_class(fn##_store_inner(kobj, attr, buf, size));	\
}									\
									\
static ssize_t fn ## _store_inner(struct kobject *kobj, struct attribute *attr,\
				  const char *buf, size_t size)

#define __sysfs_attribute(_name, _mode)					\
	static struct attribute sysfs_##_name =				\
		{ .name = #_name, .mode = _mode }

#define write_attribute(n)	__sysfs_attribute(n, 0200)
#define read_attribute(n)	__sysfs_attribute(n, 0444)
#define rw_attribute(n)		__sysfs_attribute(n, 0644)

#define sysfs_printf(file, fmt, ...)					\
do {									\
	if (attr == &sysfs_ ## file)					\
		prt_printf(out, fmt "\n", __VA_ARGS__);			\
} while (0)

#define sysfs_print(file, var)						\
do {									\
	if (attr == &sysfs_ ## file)					\
		snprint(out, var);					\
} while (0)

#define sysfs_hprint(file, val)						\
do {									\
	if (attr == &sysfs_ ## file)					\
		prt_human_readable_s64(out, val);			\
} while (0)

#define sysfs_strtoul(file, var)					\
do {									\
	if (attr == &sysfs_ ## file)					\
		return strtoul_safe(buf, var) ?: (ssize_t) size;	\
} while (0)

#define sysfs_strtoul_clamp(file, var, min, max)			\
do {									\
	if (attr == &sysfs_ ## file)					\
		return strtoul_safe_clamp(buf, var, min, max)		\
			?: (ssize_t) size;				\
} while (0)

#define strtoul_or_return(cp)						\
({									\
	unsigned long _v;						\
	int _r = kstrtoul(cp, 10, &_v);					\
	if (_r)								\
		return _r;						\
	_v;								\
})

write_attribute(trigger_gc);
write_attribute(trigger_discards);
write_attribute(trigger_invalidates);
write_attribute(trigger_journal_flush);
write_attribute(trigger_btree_cache_shrink);
write_attribute(trigger_btree_key_cache_shrink);
rw_attribute(gc_gens_pos);

read_attribute(uuid);
read_attribute(minor);
read_attribute(flags);
read_attribute(bucket_size);
read_attribute(first_bucket);
read_attribute(nbuckets);
rw_attribute(durability);
read_attribute(io_done);
read_attribute(io_errors);
write_attribute(io_errors_reset);

read_attribute(io_latency_read);
read_attribute(io_latency_write);
read_attribute(io_latency_stats_read);
read_attribute(io_latency_stats_write);
read_attribute(congested);

read_attribute(btree_write_stats);

read_attribute(btree_cache_size);
read_attribute(compression_stats);
read_attribute(journal_debug);
read_attribute(btree_cache);
read_attribute(btree_key_cache);
read_attribute(stripes_heap);
read_attribute(open_buckets);
read_attribute(open_buckets_partial);
read_attribute(write_points);
read_attribute(nocow_lock_table);

#ifdef BCH_WRITE_REF_DEBUG
read_attribute(write_refs);

static const char * const bch2_write_refs[] = {
#define x(n)	#n,
	BCH_WRITE_REFS()
#undef x
	NULL
};

static void bch2_write_refs_to_text(struct printbuf *out, struct bch_fs *c)
{
	bch2_printbuf_tabstop_push(out, 24);

	for (unsigned i = 0; i < ARRAY_SIZE(c->writes); i++)
		prt_printf(out, "%s\t%li\n", bch2_write_refs[i], atomic_long_read(&c->writes[i]));
}
#endif

read_attribute(internal_uuid);
read_attribute(disk_groups);

read_attribute(has_data);
read_attribute(alloc_debug);
read_attribute(accounting);
read_attribute(usage_base);

#define x(t, n, ...) read_attribute(t);
BCH_PERSISTENT_COUNTERS()
#undef x

rw_attribute(discard);
rw_attribute(label);

rw_attribute(copy_gc_enabled);
read_attribute(copy_gc_wait);

rw_attribute(rebalance_enabled);
sysfs_pd_controller_attribute(rebalance);
read_attribute(rebalance_status);
rw_attribute(promote_whole_extents);

read_attribute(new_stripes);

read_attribute(io_timers_read);
read_attribute(io_timers_write);

read_attribute(moving_ctxts);

#ifdef CONFIG_BCACHEFS_TESTS
write_attribute(perf_test);
#endif /* CONFIG_BCACHEFS_TESTS */

#define x(_name)						\
	static struct attribute sysfs_time_stat_##_name =		\
		{ .name = #_name, .mode = 0444 };
	BCH_TIME_STATS()
#undef x

static struct attribute sysfs_state_rw = {
	.name = "state",
	.mode =  0444,
};

static size_t bch2_btree_cache_size(struct bch_fs *c)
{
	size_t ret = 0;
	struct btree *b;

	mutex_lock(&c->btree_cache.lock);
	list_for_each_entry(b, &c->btree_cache.live, list)
		ret += btree_buf_bytes(b);

	mutex_unlock(&c->btree_cache.lock);
	return ret;
}

static int bch2_compression_stats_to_text(struct printbuf *out, struct bch_fs *c)
{
	prt_str(out, "type");
	printbuf_tabstop_push(out, 12);
	printbuf_tabstop_push(out, 16);
	printbuf_tabstop_push(out, 16);
	printbuf_tabstop_push(out, 24);
	prt_printf(out, "type\tcompressed\runcompressed\raverage extent size\r\n");

	for (unsigned i = 1; i < BCH_COMPRESSION_TYPE_NR; i++) {
		struct disk_accounting_pos a = {
			.type			= BCH_DISK_ACCOUNTING_compression,
			.compression.type	= i,
		};
		struct bpos p = disk_accounting_pos_to_bpos(&a);
		u64 v[3];
		bch2_accounting_mem_read(c, p, v, ARRAY_SIZE(v));

		u64 nr_extents			= v[0];
		u64 sectors_uncompressed	= v[1];
		u64 sectors_compressed		= v[2];

		bch2_prt_compression_type(out, i);
		prt_tab(out);

		prt_human_readable_u64(out, sectors_compressed << 9);
		prt_tab_rjust(out);

		prt_human_readable_u64(out, sectors_uncompressed << 9);
		prt_tab_rjust(out);

		prt_human_readable_u64(out, nr_extents
				       ? div_u64(sectors_uncompressed << 9, nr_extents)
				       : 0);
		prt_tab_rjust(out);
		prt_newline(out);
	}

	return 0;
}

static void bch2_gc_gens_pos_to_text(struct printbuf *out, struct bch_fs *c)
{
	prt_printf(out, "%s: ", bch2_btree_id_str(c->gc_gens_btree));
	bch2_bpos_to_text(out, c->gc_gens_pos);
	prt_printf(out, "\n");
}

static void bch2_fs_usage_base_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct bch_fs_usage_base b = {};

	acc_u64s_percpu(&b.hidden, &c->usage->hidden, sizeof(b) / sizeof(u64));

	prt_printf(out, "hidden:\t\t%llu\n",	b.hidden);
	prt_printf(out, "btree:\t\t%llu\n",	b.btree);
	prt_printf(out, "data:\t\t%llu\n",	b.data);
	prt_printf(out, "cached:\t%llu\n",	b.cached);
	prt_printf(out, "reserved:\t\t%llu\n",	b.reserved);
	prt_printf(out, "nr_inodes:\t%llu\n",	b.nr_inodes);
}

SHOW(bch2_fs)
{
	struct bch_fs *c = container_of(kobj, struct bch_fs, kobj);

	sysfs_print(minor,			c->minor);
	sysfs_printf(internal_uuid, "%pU",	c->sb.uuid.b);

	if (attr == &sysfs_flags)
		prt_bitflags(out, bch2_fs_flag_strs, c->flags);

	sysfs_hprint(btree_cache_size,		bch2_btree_cache_size(c));

	if (attr == &sysfs_btree_write_stats)
		bch2_btree_write_stats_to_text(out, c);

	if (attr == &sysfs_gc_gens_pos)
		bch2_gc_gens_pos_to_text(out, c);

	sysfs_printf(copy_gc_enabled, "%i", c->copy_gc_enabled);

	sysfs_printf(rebalance_enabled,		"%i", c->rebalance.enabled);
	sysfs_pd_controller_show(rebalance,	&c->rebalance.pd); /* XXX */

	if (attr == &sysfs_copy_gc_wait)
		bch2_copygc_wait_to_text(out, c);

	if (attr == &sysfs_rebalance_status)
		bch2_rebalance_status_to_text(out, c);

	sysfs_print(promote_whole_extents,	c->promote_whole_extents);

	/* Debugging: */

	if (attr == &sysfs_journal_debug)
		bch2_journal_debug_to_text(out, &c->journal);

	if (attr == &sysfs_btree_cache)
		bch2_btree_cache_to_text(out, &c->btree_cache);

	if (attr == &sysfs_btree_key_cache)
		bch2_btree_key_cache_to_text(out, &c->btree_key_cache);

	if (attr == &sysfs_stripes_heap)
		bch2_stripes_heap_to_text(out, c);

	if (attr == &sysfs_open_buckets)
		bch2_open_buckets_to_text(out, c);

	if (attr == &sysfs_open_buckets_partial)
		bch2_open_buckets_partial_to_text(out, c);

	if (attr == &sysfs_write_points)
		bch2_write_points_to_text(out, c);

	if (attr == &sysfs_compression_stats)
		bch2_compression_stats_to_text(out, c);

	if (attr == &sysfs_new_stripes)
		bch2_new_stripes_to_text(out, c);

	if (attr == &sysfs_io_timers_read)
		bch2_io_timers_to_text(out, &c->io_clock[READ]);

	if (attr == &sysfs_io_timers_write)
		bch2_io_timers_to_text(out, &c->io_clock[WRITE]);

	if (attr == &sysfs_moving_ctxts)
		bch2_fs_moving_ctxts_to_text(out, c);

#ifdef BCH_WRITE_REF_DEBUG
	if (attr == &sysfs_write_refs)
		bch2_write_refs_to_text(out, c);
#endif

	if (attr == &sysfs_nocow_lock_table)
		bch2_nocow_locks_to_text(out, &c->nocow_locks);

	if (attr == &sysfs_disk_groups)
		bch2_disk_groups_to_text(out, c);

	if (attr == &sysfs_alloc_debug)
		bch2_fs_alloc_debug_to_text(out, c);

	if (attr == &sysfs_accounting)
		bch2_fs_accounting_to_text(out, c);

	if (attr == &sysfs_usage_base)
		bch2_fs_usage_base_to_text(out, c);

	return 0;
}

STORE(bch2_fs)
{
	struct bch_fs *c = container_of(kobj, struct bch_fs, kobj);

	if (attr == &sysfs_copy_gc_enabled) {
		ssize_t ret = strtoul_safe(buf, c->copy_gc_enabled)
			?: (ssize_t) size;

		if (c->copygc_thread)
			wake_up_process(c->copygc_thread);
		return ret;
	}

	if (attr == &sysfs_rebalance_enabled) {
		ssize_t ret = strtoul_safe(buf, c->rebalance.enabled)
			?: (ssize_t) size;

		rebalance_wakeup(c);
		return ret;
	}

	sysfs_pd_controller_store(rebalance,	&c->rebalance.pd);

	sysfs_strtoul(promote_whole_extents,	c->promote_whole_extents);

	/* Debugging: */

	if (!test_bit(BCH_FS_started, &c->flags))
		return -EPERM;

	/* Debugging: */

	if (!bch2_write_ref_tryget(c, BCH_WRITE_REF_sysfs))
		return -EROFS;

	if (attr == &sysfs_trigger_btree_cache_shrink) {
		struct shrink_control sc;

		sc.gfp_mask = GFP_KERNEL;
		sc.nr_to_scan = strtoul_or_return(buf);
		c->btree_cache.shrink->scan_objects(c->btree_cache.shrink, &sc);
	}

	if (attr == &sysfs_trigger_btree_key_cache_shrink) {
		struct shrink_control sc;

		sc.gfp_mask = GFP_KERNEL;
		sc.nr_to_scan = strtoul_or_return(buf);
		c->btree_key_cache.shrink->scan_objects(c->btree_cache.shrink, &sc);
	}

	if (attr == &sysfs_trigger_gc)
		bch2_gc_gens(c);

	if (attr == &sysfs_trigger_discards)
		bch2_do_discards(c);

	if (attr == &sysfs_trigger_invalidates)
		bch2_do_invalidates(c);

	if (attr == &sysfs_trigger_journal_flush) {
		bch2_journal_flush_all_pins(&c->journal);
		bch2_journal_meta(&c->journal);
	}

#ifdef CONFIG_BCACHEFS_TESTS
	if (attr == &sysfs_perf_test) {
		char *tmp = kstrdup(buf, GFP_KERNEL), *p = tmp;
		char *test		= strsep(&p, " \t\n");
		char *nr_str		= strsep(&p, " \t\n");
		char *threads_str	= strsep(&p, " \t\n");
		unsigned threads;
		u64 nr;
		int ret = -EINVAL;

		if (threads_str &&
		    !(ret = kstrtouint(threads_str, 10, &threads)) &&
		    !(ret = bch2_strtoull_h(nr_str, &nr)))
			ret = bch2_btree_perf_test(c, test, nr, threads);
		kfree(tmp);

		if (ret)
			size = ret;
	}
#endif
	bch2_write_ref_put(c, BCH_WRITE_REF_sysfs);
	return size;
}
SYSFS_OPS(bch2_fs);

struct attribute *bch2_fs_files[] = {
	&sysfs_minor,
	&sysfs_btree_cache_size,
	&sysfs_btree_write_stats,

	&sysfs_promote_whole_extents,

	&sysfs_compression_stats,

#ifdef CONFIG_BCACHEFS_TESTS
	&sysfs_perf_test,
#endif
	NULL
};

/* counters dir */

SHOW(bch2_fs_counters)
{
	struct bch_fs *c = container_of(kobj, struct bch_fs, counters_kobj);
	u64 counter = 0;
	u64 counter_since_mount = 0;

	printbuf_tabstop_push(out, 32);

	#define x(t, ...) \
		if (attr == &sysfs_##t) {					\
			counter             = percpu_u64_get(&c->counters[BCH_COUNTER_##t]);\
			counter_since_mount = counter - c->counters_on_mount[BCH_COUNTER_##t];\
			prt_printf(out, "since mount:\t");			\
			prt_human_readable_u64(out, counter_since_mount);	\
			prt_newline(out);					\
										\
			prt_printf(out, "since filesystem creation:\t");	\
			prt_human_readable_u64(out, counter);			\
			prt_newline(out);					\
		}
	BCH_PERSISTENT_COUNTERS()
	#undef x
	return 0;
}

STORE(bch2_fs_counters) {
	return 0;
}

SYSFS_OPS(bch2_fs_counters);

struct attribute *bch2_fs_counters_files[] = {
#define x(t, ...) \
	&sysfs_##t,
	BCH_PERSISTENT_COUNTERS()
#undef x
	NULL
};
/* internal dir - just a wrapper */

SHOW(bch2_fs_internal)
{
	struct bch_fs *c = container_of(kobj, struct bch_fs, internal);

	return bch2_fs_to_text(out, &c->kobj, attr);
}

STORE(bch2_fs_internal)
{
	struct bch_fs *c = container_of(kobj, struct bch_fs, internal);

	return bch2_fs_store(&c->kobj, attr, buf, size);
}
SYSFS_OPS(bch2_fs_internal);

struct attribute *bch2_fs_internal_files[] = {
	&sysfs_flags,
	&sysfs_journal_debug,
	&sysfs_btree_cache,
	&sysfs_btree_key_cache,
	&sysfs_new_stripes,
	&sysfs_stripes_heap,
	&sysfs_open_buckets,
	&sysfs_open_buckets_partial,
	&sysfs_write_points,
#ifdef BCH_WRITE_REF_DEBUG
	&sysfs_write_refs,
#endif
	&sysfs_nocow_lock_table,
	&sysfs_io_timers_read,
	&sysfs_io_timers_write,

	&sysfs_trigger_gc,
	&sysfs_trigger_discards,
	&sysfs_trigger_invalidates,
	&sysfs_trigger_journal_flush,
	&sysfs_trigger_btree_cache_shrink,
	&sysfs_trigger_btree_key_cache_shrink,

	&sysfs_gc_gens_pos,

	&sysfs_copy_gc_enabled,
	&sysfs_copy_gc_wait,

	&sysfs_rebalance_enabled,
	&sysfs_rebalance_status,
	sysfs_pd_controller_files(rebalance),

	&sysfs_moving_ctxts,

	&sysfs_internal_uuid,

	&sysfs_disk_groups,
	&sysfs_alloc_debug,
	&sysfs_accounting,
	&sysfs_usage_base,
	NULL
};

/* options */

SHOW(bch2_fs_opts_dir)
{
	struct bch_fs *c = container_of(kobj, struct bch_fs, opts_dir);
	const struct bch_option *opt = container_of(attr, struct bch_option, attr);
	int id = opt - bch2_opt_table;
	u64 v = bch2_opt_get_by_id(&c->opts, id);

	bch2_opt_to_text(out, c, c->disk_sb.sb, opt, v, OPT_SHOW_FULL_LIST);
	prt_char(out, '\n');

	return 0;
}

STORE(bch2_fs_opts_dir)
{
	struct bch_fs *c = container_of(kobj, struct bch_fs, opts_dir);
	const struct bch_option *opt = container_of(attr, struct bch_option, attr);
	int ret, id = opt - bch2_opt_table;
	char *tmp;
	u64 v;

	/*
	 * We don't need to take c->writes for correctness, but it eliminates an
	 * unsightly error message in the dmesg log when we're RO:
	 */
	if (unlikely(!bch2_write_ref_tryget(c, BCH_WRITE_REF_sysfs)))
		return -EROFS;

	tmp = kstrdup(buf, GFP_KERNEL);
	if (!tmp) {
		ret = -ENOMEM;
		goto err;
	}

	ret = bch2_opt_parse(c, opt, strim(tmp), &v, NULL);
	kfree(tmp);

	if (ret < 0)
		goto err;

	ret = bch2_opt_check_may_set(c, id, v);
	if (ret < 0)
		goto err;

	bch2_opt_set_sb(c, opt, v);
	bch2_opt_set_by_id(&c->opts, id, v);

	if (v &&
	    (id == Opt_background_target ||
	     id == Opt_background_compression ||
	     (id == Opt_compression && !c->opts.background_compression)))
		bch2_set_rebalance_needs_scan(c, 0);

	ret = size;
err:
	bch2_write_ref_put(c, BCH_WRITE_REF_sysfs);
	return ret;
}
SYSFS_OPS(bch2_fs_opts_dir);

struct attribute *bch2_fs_opts_dir_files[] = { NULL };

int bch2_opts_create_sysfs_files(struct kobject *kobj)
{
	const struct bch_option *i;
	int ret;

	for (i = bch2_opt_table;
	     i < bch2_opt_table + bch2_opts_nr;
	     i++) {
		if (!(i->flags & OPT_FS))
			continue;

		ret = sysfs_create_file(kobj, &i->attr);
		if (ret)
			return ret;
	}

	return 0;
}

/* time stats */

SHOW(bch2_fs_time_stats)
{
	struct bch_fs *c = container_of(kobj, struct bch_fs, time_stats);

#define x(name)								\
	if (attr == &sysfs_time_stat_##name)				\
		bch2_time_stats_to_text(out, &c->times[BCH_TIME_##name]);
	BCH_TIME_STATS()
#undef x

	return 0;
}

STORE(bch2_fs_time_stats)
{
	return size;
}
SYSFS_OPS(bch2_fs_time_stats);

struct attribute *bch2_fs_time_stats_files[] = {
#define x(name)						\
	&sysfs_time_stat_##name,
	BCH_TIME_STATS()
#undef x
	NULL
};

static const char * const bch2_rw[] = {
	"read",
	"write",
	NULL
};

static void dev_io_done_to_text(struct printbuf *out, struct bch_dev *ca)
{
	int rw, i;

	for (rw = 0; rw < 2; rw++) {
		prt_printf(out, "%s:\n", bch2_rw[rw]);

		for (i = 1; i < BCH_DATA_NR; i++)
			prt_printf(out, "%-12s:%12llu\n",
			       bch2_data_type_str(i),
			       percpu_u64_get(&ca->io_done->sectors[rw][i]) << 9);
	}
}

SHOW(bch2_dev)
{
	struct bch_dev *ca = container_of(kobj, struct bch_dev, kobj);
	struct bch_fs *c = ca->fs;

	sysfs_printf(uuid,		"%pU\n", ca->uuid.b);

	sysfs_print(bucket_size,	bucket_bytes(ca));
	sysfs_print(first_bucket,	ca->mi.first_bucket);
	sysfs_print(nbuckets,		ca->mi.nbuckets);
	sysfs_print(durability,		ca->mi.durability);
	sysfs_print(discard,		ca->mi.discard);

	if (attr == &sysfs_label) {
		if (ca->mi.group)
			bch2_disk_path_to_text(out, c, ca->mi.group - 1);
		prt_char(out, '\n');
	}

	if (attr == &sysfs_has_data) {
		prt_bitflags(out, __bch2_data_types, bch2_dev_has_data(c, ca));
		prt_char(out, '\n');
	}

	if (attr == &sysfs_state_rw) {
		prt_string_option(out, bch2_member_states, ca->mi.state);
		prt_char(out, '\n');
	}

	if (attr == &sysfs_io_done)
		dev_io_done_to_text(out, ca);

	if (attr == &sysfs_io_errors)
		bch2_dev_io_errors_to_text(out, ca);

	sysfs_print(io_latency_read,		atomic64_read(&ca->cur_latency[READ]));
	sysfs_print(io_latency_write,		atomic64_read(&ca->cur_latency[WRITE]));

	if (attr == &sysfs_io_latency_stats_read)
		bch2_time_stats_to_text(out, &ca->io_latency[READ].stats);

	if (attr == &sysfs_io_latency_stats_write)
		bch2_time_stats_to_text(out, &ca->io_latency[WRITE].stats);

	sysfs_printf(congested,			"%u%%",
		     clamp(atomic_read(&ca->congested), 0, CONGESTED_MAX)
		     * 100 / CONGESTED_MAX);

	if (attr == &sysfs_alloc_debug)
		bch2_dev_alloc_debug_to_text(out, ca);

	return 0;
}

STORE(bch2_dev)
{
	struct bch_dev *ca = container_of(kobj, struct bch_dev, kobj);
	struct bch_fs *c = ca->fs;
	struct bch_member *mi;

	if (attr == &sysfs_discard) {
		bool v = strtoul_or_return(buf);

		mutex_lock(&c->sb_lock);
		mi = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);

		if (v != BCH_MEMBER_DISCARD(mi)) {
			SET_BCH_MEMBER_DISCARD(mi, v);
			bch2_write_super(c);
		}
		mutex_unlock(&c->sb_lock);
	}

	if (attr == &sysfs_durability) {
		u64 v = strtoul_or_return(buf);

		mutex_lock(&c->sb_lock);
		mi = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);

		if (v + 1 != BCH_MEMBER_DURABILITY(mi)) {
			SET_BCH_MEMBER_DURABILITY(mi, v + 1);
			bch2_write_super(c);
		}
		mutex_unlock(&c->sb_lock);
	}

	if (attr == &sysfs_label) {
		char *tmp;
		int ret;

		tmp = kstrdup(buf, GFP_KERNEL);
		if (!tmp)
			return -ENOMEM;

		ret = bch2_dev_group_set(c, ca, strim(tmp));
		kfree(tmp);
		if (ret)
			return ret;
	}

	if (attr == &sysfs_io_errors_reset)
		bch2_dev_errors_reset(ca);

	return size;
}
SYSFS_OPS(bch2_dev);

struct attribute *bch2_dev_files[] = {
	&sysfs_uuid,
	&sysfs_bucket_size,
	&sysfs_first_bucket,
	&sysfs_nbuckets,
	&sysfs_durability,

	/* settings: */
	&sysfs_discard,
	&sysfs_state_rw,
	&sysfs_label,

	&sysfs_has_data,
	&sysfs_io_done,
	&sysfs_io_errors,
	&sysfs_io_errors_reset,

	&sysfs_io_latency_read,
	&sysfs_io_latency_write,
	&sysfs_io_latency_stats_read,
	&sysfs_io_latency_stats_write,
	&sysfs_congested,

	/* debug: */
	&sysfs_alloc_debug,
	NULL
};

#endif  /* _BCACHEFS_SYSFS_H_ */
