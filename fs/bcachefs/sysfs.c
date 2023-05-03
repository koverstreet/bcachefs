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
#include "btree_update_interior.h"
#include "btree_gc.h"
#include "buckets.h"
#include "clock.h"
#include "disk_groups.h"
#include "ec.h"
#include "inode.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
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
struct sysfs_ops type ## _sysfs_ops = {					\
	.show	= type ## _show,					\
	.store	= type ## _store					\
}

#define SHOW(fn)							\
static ssize_t fn ## _to_text(struct printbuf *,			\
			      struct kobject *, struct attribute *);\
									\
static ssize_t fn ## _show(struct kobject *kobj, struct attribute *attr,\
			   char *buf)					\
{									\
	struct printbuf out = PRINTBUF;					\
	ssize_t ret = fn ## _to_text(&out, kobj, attr);			\
									\
	if (!ret && out.allocation_failure)				\
		ret = -ENOMEM;						\
									\
	if (!ret) {							\
		ret = min_t(size_t, out.pos, PAGE_SIZE - 1);		\
		memcpy(buf, out.buf, ret);				\
	}								\
	printbuf_exit(&out);						\
	return ret;							\
}									\
									\
static ssize_t fn ## _to_text(struct printbuf *out, struct kobject *kobj,\
			      struct attribute *attr)

#define STORE(fn)							\
static ssize_t fn ## _store(struct kobject *kobj, struct attribute *attr,\
			    const char *buf, size_t size)		\

#define __sysfs_attribute(_name, _mode)					\
	static struct attribute sysfs_##_name =				\
		{ .name = #_name, .mode = _mode }

#define write_attribute(n)	__sysfs_attribute(n, S_IWUSR)
#define read_attribute(n)	__sysfs_attribute(n, S_IRUGO)
#define rw_attribute(n)		__sysfs_attribute(n, S_IRUGO|S_IWUSR)

#define sysfs_printf(file, fmt, ...)					\
do {									\
	if (attr == &sysfs_ ## file)					\
		pr_buf(out, fmt "\n", __VA_ARGS__);			\
} while (0)

#define sysfs_print(file, var)						\
do {									\
	if (attr == &sysfs_ ## file)					\
		snprint(out, var);					\
} while (0)

#define sysfs_hprint(file, val)						\
do {									\
	if (attr == &sysfs_ ## file)					\
		bch2_hprint(out, val);					\
} while (0)

#define var_printf(_var, fmt)	sysfs_printf(_var, fmt, var(_var))
#define var_print(_var)		sysfs_print(_var, var(_var))
#define var_hprint(_var)	sysfs_hprint(_var, var(_var))

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

#define strtoul_restrict_or_return(cp, min, max)			\
({									\
	unsigned long __v = 0;						\
	int _r = strtoul_safe_restrict(cp, __v, min, max);		\
	if (_r)								\
		return _r;						\
	__v;								\
})

#define strtoi_h_or_return(cp)						\
({									\
	u64 _v;								\
	int _r = strtoi_h(cp, &_v);					\
	if (_r)								\
		return _r;						\
	_v;								\
})

#define sysfs_hatoi(file, var)						\
do {									\
	if (attr == &sysfs_ ## file)					\
		return strtoi_h(buf, &var) ?: (ssize_t) size;		\
} while (0)

write_attribute(trigger_gc);
write_attribute(trigger_discards);
write_attribute(prune_cache);
rw_attribute(btree_gc_periodic);
rw_attribute(gc_gens_pos);

read_attribute(uuid);
read_attribute(minor);
read_attribute(bucket_size);
read_attribute(first_bucket);
read_attribute(nbuckets);
read_attribute(durability);
read_attribute(iodone);

read_attribute(io_latency_read);
read_attribute(io_latency_write);
read_attribute(io_latency_stats_read);
read_attribute(io_latency_stats_write);
read_attribute(congested);

read_attribute(btree_avg_write_size);

read_attribute(btree_cache_size);
read_attribute(compression_stats);
read_attribute(journal_debug);
read_attribute(btree_updates);
read_attribute(btree_cache);
read_attribute(btree_key_cache);
read_attribute(btree_transactions);
read_attribute(stripes_heap);
read_attribute(open_buckets);
read_attribute(write_points);

read_attribute(internal_uuid);

read_attribute(has_data);
read_attribute(alloc_debug);

read_attribute(read_realloc_races);
read_attribute(extent_migrate_done);
read_attribute(extent_migrate_raced);
read_attribute(bucket_alloc_fail);

rw_attribute(discard);
rw_attribute(label);

rw_attribute(copy_gc_enabled);
read_attribute(copy_gc_wait);

rw_attribute(rebalance_enabled);
sysfs_pd_controller_attribute(rebalance);
read_attribute(rebalance_work);
rw_attribute(promote_whole_extents);

read_attribute(new_stripes);

read_attribute(io_timers_read);
read_attribute(io_timers_write);

read_attribute(data_jobs);

#ifdef CONFIG_BCACHEFS_TESTS
write_attribute(perf_test);
#endif /* CONFIG_BCACHEFS_TESTS */

#define x(_name)						\
	static struct attribute sysfs_time_stat_##_name =		\
		{ .name = #_name, .mode = S_IRUGO };
	BCH_TIME_STATS()
#undef x

static struct attribute sysfs_state_rw = {
	.name = "state",
	.mode = S_IRUGO
};

static size_t bch2_btree_cache_size(struct bch_fs *c)
{
	size_t ret = 0;
	struct btree *b;

	mutex_lock(&c->btree_cache.lock);
	list_for_each_entry(b, &c->btree_cache.live, list)
		ret += btree_bytes(c);

	mutex_unlock(&c->btree_cache.lock);
	return ret;
}

static size_t bch2_btree_avg_write_size(struct bch_fs *c)
{
	u64 nr = atomic64_read(&c->btree_writes_nr);
	u64 sectors = atomic64_read(&c->btree_writes_sectors);

	return nr ? div64_u64(sectors, nr) : 0;
}

static long data_progress_to_text(struct printbuf *out, struct bch_fs *c)
{
	long ret = 0;
	struct bch_move_stats *stats;

	mutex_lock(&c->data_progress_lock);
	list_for_each_entry(stats, &c->data_progress_list, list) {
		pr_buf(out, "%s: data type %s btree_id %s position: ",
		       stats->name,
		       bch2_data_types[stats->data_type],
		       bch2_btree_ids[stats->btree_id]);
		bch2_bpos_to_text(out, stats->pos);
		pr_buf(out, "%s", "\n");
	}

	mutex_unlock(&c->data_progress_lock);
	return ret;
}

static int bch2_compression_stats_to_text(struct printbuf *out, struct bch_fs *c)
{
	struct btree_trans trans;
	struct btree_iter iter;
	struct bkey_s_c k;
	enum btree_id id;
	u64 nr_uncompressed_extents = 0,
	    nr_compressed_extents = 0,
	    nr_incompressible_extents = 0,
	    uncompressed_sectors = 0,
	    incompressible_sectors = 0,
	    compressed_sectors_compressed = 0,
	    compressed_sectors_uncompressed = 0;
	int ret;

	if (!test_bit(BCH_FS_STARTED, &c->flags))
		return -EPERM;

	bch2_trans_init(&trans, c, 0, 0);

	for (id = 0; id < BTREE_ID_NR; id++) {
		if (!((1U << id) & BTREE_ID_HAS_PTRS))
			continue;

		for_each_btree_key(&trans, iter, id, POS_MIN,
				   BTREE_ITER_ALL_SNAPSHOTS, k, ret) {
			struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(k);
			const union bch_extent_entry *entry;
			struct extent_ptr_decoded p;
			bool compressed = false, uncompressed = false, incompressible = false;

			bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
				switch (p.crc.compression_type) {
				case BCH_COMPRESSION_TYPE_none:
					uncompressed = true;
					uncompressed_sectors += k.k->size;
					break;
				case BCH_COMPRESSION_TYPE_incompressible:
					incompressible = true;
					incompressible_sectors += k.k->size;
					break;
				default:
					compressed_sectors_compressed +=
						p.crc.compressed_size;
					compressed_sectors_uncompressed +=
						p.crc.uncompressed_size;
					compressed = true;
					break;
				}
			}

			if (incompressible)
				nr_incompressible_extents++;
			else if (uncompressed)
				nr_uncompressed_extents++;
			else if (compressed)
				nr_compressed_extents++;
		}
		bch2_trans_iter_exit(&trans, &iter);
	}

	bch2_trans_exit(&trans);

	if (ret)
		return ret;

	pr_buf(out, "uncompressed:\n");
	pr_buf(out, "	nr extents:		%llu\n", nr_uncompressed_extents);
	pr_buf(out, "	size:			");
	bch2_hprint(out, uncompressed_sectors << 9);
	pr_buf(out, "\n");

	pr_buf(out, "compressed:\n");
	pr_buf(out, "	nr extents:		%llu\n", nr_compressed_extents);
	pr_buf(out, "	compressed size:	");
	bch2_hprint(out, compressed_sectors_compressed << 9);
	pr_buf(out, "\n");
	pr_buf(out, "	uncompressed size:	");
	bch2_hprint(out, compressed_sectors_uncompressed << 9);
	pr_buf(out, "\n");

	pr_buf(out, "incompressible:\n");
	pr_buf(out, "	nr extents:		%llu\n", nr_incompressible_extents);
	pr_buf(out, "	size:			");
	bch2_hprint(out, incompressible_sectors << 9);
	pr_buf(out, "\n");
	return 0;
}

static void bch2_gc_gens_pos_to_text(struct printbuf *out, struct bch_fs *c)
{
	pr_buf(out, "%s: ", bch2_btree_ids[c->gc_gens_btree]);
	bch2_bpos_to_text(out, c->gc_gens_pos);
	pr_buf(out, "\n");
}

SHOW(bch2_fs)
{
	struct bch_fs *c = container_of(kobj, struct bch_fs, kobj);

	sysfs_print(minor,			c->minor);
	sysfs_printf(internal_uuid, "%pU",	c->sb.uuid.b);

	sysfs_hprint(btree_cache_size,		bch2_btree_cache_size(c));
	sysfs_hprint(btree_avg_write_size,	bch2_btree_avg_write_size(c));

	sysfs_print(read_realloc_races,
		    atomic_long_read(&c->read_realloc_races));
	sysfs_print(extent_migrate_done,
		    atomic_long_read(&c->extent_migrate_done));
	sysfs_print(extent_migrate_raced,
		    atomic_long_read(&c->extent_migrate_raced));
	sysfs_print(bucket_alloc_fail,
		    atomic_long_read(&c->bucket_alloc_fail));

	sysfs_printf(btree_gc_periodic, "%u",	(int) c->btree_gc_periodic);

	if (attr == &sysfs_gc_gens_pos)
		bch2_gc_gens_pos_to_text(out, c);

	sysfs_printf(copy_gc_enabled, "%i", c->copy_gc_enabled);

	sysfs_printf(rebalance_enabled,		"%i", c->rebalance.enabled);
	sysfs_pd_controller_show(rebalance,	&c->rebalance.pd); /* XXX */
	sysfs_hprint(copy_gc_wait,
		     max(0LL, c->copygc_wait -
			 atomic64_read(&c->io_clock[WRITE].now)) << 9);

	if (attr == &sysfs_rebalance_work)
		bch2_rebalance_work_to_text(out, c);

	sysfs_print(promote_whole_extents,	c->promote_whole_extents);

	/* Debugging: */

	if (attr == &sysfs_journal_debug)
		bch2_journal_debug_to_text(out, &c->journal);

	if (attr == &sysfs_btree_updates)
		bch2_btree_updates_to_text(out, c);

	if (attr == &sysfs_btree_cache)
		bch2_btree_cache_to_text(out, c);

	if (attr == &sysfs_btree_key_cache)
		bch2_btree_key_cache_to_text(out, &c->btree_key_cache);

	if (attr == &sysfs_btree_transactions)
		bch2_btree_trans_to_text(out, c);

	if (attr == &sysfs_stripes_heap)
		bch2_stripes_heap_to_text(out, c);

	if (attr == &sysfs_open_buckets)
		bch2_open_buckets_to_text(out, c);

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

	if (attr == &sysfs_data_jobs)
		data_progress_to_text(out, c);

	return 0;
}

STORE(bch2_fs)
{
	struct bch_fs *c = container_of(kobj, struct bch_fs, kobj);

	if (attr == &sysfs_btree_gc_periodic) {
		ssize_t ret = strtoul_safe(buf, c->btree_gc_periodic)
			?: (ssize_t) size;

		wake_up_process(c->gc_thread);
		return ret;
	}

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

	if (!test_bit(BCH_FS_STARTED, &c->flags))
		return -EPERM;

	/* Debugging: */

	if (!test_bit(BCH_FS_RW, &c->flags))
		return -EROFS;

	if (attr == &sysfs_prune_cache) {
		struct shrink_control sc;

		sc.gfp_mask = GFP_KERNEL;
		sc.nr_to_scan = strtoul_or_return(buf);
		c->btree_cache.shrink.scan_objects(&c->btree_cache.shrink, &sc);
	}

	if (attr == &sysfs_trigger_gc) {
		/*
		 * Full gc is currently incompatible with btree key cache:
		 */
#if 0
		down_read(&c->state_lock);
		bch2_gc(c, false, false);
		up_read(&c->state_lock);
#else
		bch2_gc_gens(c);
#endif
	}

	if (attr == &sysfs_trigger_discards)
		bch2_do_discards(c);

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
	return size;
}
SYSFS_OPS(bch2_fs);

struct attribute *bch2_fs_files[] = {
	&sysfs_minor,
	&sysfs_btree_cache_size,
	&sysfs_btree_avg_write_size,

	&sysfs_promote_whole_extents,

	&sysfs_compression_stats,

#ifdef CONFIG_BCACHEFS_TESTS
	&sysfs_perf_test,
#endif
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
	&sysfs_journal_debug,
	&sysfs_btree_updates,
	&sysfs_btree_cache,
	&sysfs_btree_key_cache,
	&sysfs_btree_transactions,
	&sysfs_new_stripes,
	&sysfs_stripes_heap,
	&sysfs_open_buckets,
	&sysfs_write_points,
	&sysfs_io_timers_read,
	&sysfs_io_timers_write,

	&sysfs_trigger_gc,
	&sysfs_trigger_discards,
	&sysfs_prune_cache,

	&sysfs_read_realloc_races,
	&sysfs_extent_migrate_done,
	&sysfs_extent_migrate_raced,
	&sysfs_bucket_alloc_fail,

	&sysfs_gc_gens_pos,

	&sysfs_copy_gc_enabled,
	&sysfs_copy_gc_wait,

	&sysfs_rebalance_enabled,
	&sysfs_rebalance_work,
	sysfs_pd_controller_files(rebalance),

	&sysfs_data_jobs,

	&sysfs_internal_uuid,
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
	pr_char(out, '\n');

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
	if (unlikely(!percpu_ref_tryget(&c->writes)))
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

	if ((id == Opt_background_target ||
	     id == Opt_background_compression) && v) {
		bch2_rebalance_add_work(c, S64_MAX);
		rebalance_wakeup(c);
	}

	ret = size;
err:
	percpu_ref_put(&c->writes);
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

static void dev_alloc_debug_to_text(struct printbuf *out, struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct bch_dev_usage stats = bch2_dev_usage_read(ca);
	unsigned i, nr[BCH_DATA_NR];

	memset(nr, 0, sizeof(nr));

	for (i = 0; i < ARRAY_SIZE(c->open_buckets); i++)
		nr[c->open_buckets[i].data_type]++;

	pr_buf(out,
	       "\t\t\t buckets\t sectors      fragmented\n"
	       "capacity\t%16llu\n",
	       ca->mi.nbuckets - ca->mi.first_bucket);

	for (i = 0; i < BCH_DATA_NR; i++)
		pr_buf(out, "%-16s%16llu%16llu%16llu\n",
		       bch2_data_types[i], stats.d[i].buckets,
		       stats.d[i].sectors, stats.d[i].fragmented);

	pr_buf(out,
	       "ec\t\t%16llu\n"
	       "\n"
	       "freelist_wait\t\t%s\n"
	       "open buckets allocated\t%u\n"
	       "open buckets this dev\t%u\n"
	       "open buckets total\t%u\n"
	       "open_buckets_wait\t%s\n"
	       "open_buckets_btree\t%u\n"
	       "open_buckets_user\t%u\n"
	       "btree reserve cache\t%u\n",
	       stats.buckets_ec,
	       c->freelist_wait.list.first		? "waiting" : "empty",
	       OPEN_BUCKETS_COUNT - c->open_buckets_nr_free,
	       ca->nr_open_buckets,
	       OPEN_BUCKETS_COUNT,
	       c->open_buckets_wait.list.first		? "waiting" : "empty",
	       nr[BCH_DATA_btree],
	       nr[BCH_DATA_user],
	       c->btree_reserve_cache_nr);
}

static const char * const bch2_rw[] = {
	"read",
	"write",
	NULL
};

static void dev_iodone_to_text(struct printbuf *out, struct bch_dev *ca)
{
	int rw, i;

	for (rw = 0; rw < 2; rw++) {
		pr_buf(out, "%s:\n", bch2_rw[rw]);

		for (i = 1; i < BCH_DATA_NR; i++)
			pr_buf(out, "%-12s:%12llu\n",
			       bch2_data_types[i],
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
		if (ca->mi.group) {
			mutex_lock(&c->sb_lock);
			bch2_disk_path_to_text(out, c->disk_sb.sb,
					       ca->mi.group - 1);
			mutex_unlock(&c->sb_lock);
		}

		pr_char(out, '\n');
	}

	if (attr == &sysfs_has_data) {
		bch2_flags_to_text(out, bch2_data_types,
				   bch2_dev_has_data(c, ca));
		pr_char(out, '\n');
	}

	if (attr == &sysfs_state_rw) {
		bch2_string_opt_to_text(out, bch2_member_states,
					ca->mi.state);
		pr_char(out, '\n');
	}

	if (attr == &sysfs_iodone)
		dev_iodone_to_text(out, ca);

	sysfs_print(io_latency_read,		atomic64_read(&ca->cur_latency[READ]));
	sysfs_print(io_latency_write,		atomic64_read(&ca->cur_latency[WRITE]));

	if (attr == &sysfs_io_latency_stats_read)
		bch2_time_stats_to_text(out, &ca->io_latency[READ]);

	if (attr == &sysfs_io_latency_stats_write)
		bch2_time_stats_to_text(out, &ca->io_latency[WRITE]);

	sysfs_printf(congested,			"%u%%",
		     clamp(atomic_read(&ca->congested), 0, CONGESTED_MAX)
		     * 100 / CONGESTED_MAX);

	if (attr == &sysfs_alloc_debug)
		dev_alloc_debug_to_text(out, ca);

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
		mi = &bch2_sb_get_members(c->disk_sb.sb)->members[ca->dev_idx];

		if (v != BCH_MEMBER_DISCARD(mi)) {
			SET_BCH_MEMBER_DISCARD(mi, v);
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
	&sysfs_iodone,

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
