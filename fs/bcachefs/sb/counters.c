// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "sb/io.h"
#include "sb/counters.h"

/* BCH_SB_FIELD_counters */

static const u8 counters_to_stable_map[] = {
#define x(n, id, ...)	[BCH_COUNTER_##n] = BCH_COUNTER_STABLE_##n,
	BCH_PERSISTENT_COUNTERS()
#undef x
};

const char * const bch2_counter_names[] = {
#define x(t, n, ...) (#t),
	BCH_PERSISTENT_COUNTERS()
#undef x
	NULL
};

static size_t bch2_sb_counter_nr_entries(struct bch_sb_field_counters *ctrs)
{
	if (!ctrs)
		return 0;

	return (__le64 *) vstruct_end(&ctrs->field) - &ctrs->d[0];
}

static int bch2_sb_counters_validate(struct bch_sb *sb, struct bch_sb_field *f,
				enum bch_validate_flags flags, struct printbuf *err)
{
	return 0;
}

static void bch2_sb_counters_to_text(struct printbuf *out,
				     struct bch_fs *c, struct bch_sb *sb,
				     struct bch_sb_field *f)
{
	struct bch_sb_field_counters *ctrs = field_to_type(f, counters);
	unsigned int nr = bch2_sb_counter_nr_entries(ctrs);

	for (unsigned i = 0; i < BCH_COUNTER_NR; i++) {
		unsigned stable = counters_to_stable_map[i];
		if (stable < nr)
			prt_printf(out, "%s \t%llu\n",
				   bch2_counter_names[i],
				   le64_to_cpu(ctrs->d[stable]));
	}
}

int bch2_sb_counters_to_cpu(struct bch_fs *c)
{
	struct bch_sb_field_counters *ctrs = bch2_sb_field_get(c->disk_sb.sb, counters);
	unsigned int nr = bch2_sb_counter_nr_entries(ctrs);

	for (unsigned i = 0; i < BCH_COUNTER_NR; i++)
		c->counters.mount[i] = 0;

	for (unsigned i = 0; i < BCH_COUNTER_NR; i++) {
		unsigned stable = counters_to_stable_map[i];
		if (stable < nr) {
			u64 v = le64_to_cpu(ctrs->d[stable]);
			percpu_u64_set(&c->counters.now[i], v);
			c->counters.mount[i] = v;
		}
	}

	return 0;
}

int bch2_sb_counters_from_cpu(struct bch_fs *c)
{
	struct bch_sb_field_counters *ctrs = bch2_sb_field_get(c->disk_sb.sb, counters);
	struct bch_sb_field_counters *ret;
	unsigned int nr = bch2_sb_counter_nr_entries(ctrs);

	if (nr < BCH_COUNTER_NR) {
		ret = bch2_sb_field_resize(&c->disk_sb, counters,
					   sizeof(*ctrs) / sizeof(u64) + BCH_COUNTER_NR);
		if (ret) {
			ctrs = ret;
			nr = bch2_sb_counter_nr_entries(ctrs);
		}
	}

	for (unsigned i = 0; i < BCH_COUNTER_NR; i++) {
		unsigned stable = counters_to_stable_map[i];
		if (stable < nr)
			ctrs->d[stable] = cpu_to_le64(percpu_u64_get(&c->counters.now[i]));
	}

	return 0;
}

static void bch2_sb_counters_work(struct work_struct *work)
{
	struct bch_fs_counters *c = container_of(work, struct bch_fs_counters, work.work);

	memmove((void *) c->recent + sizeof(u64) * BCH_COUNTER_NR,
		c->recent,
		sizeof(u64) *
		BCH_COUNTER_NR *
		(NR_RECENT_COUNTERS - 1));

	for (unsigned i = 0; i < BCH_COUNTER_NR; i++)
		c->recent[0][i] = percpu_u64_get(&c->now[i]);

	queue_delayed_work(system_unbound_wq, &c->work, HZ / 2);
}

void bch2_sb_recent_counters_to_text(struct printbuf *out, struct bch_fs_counters *c)
{
	unsigned long active[BITS_TO_LONGS(BCH_COUNTER_NR)];
	memset(active, 0, sizeof(active));

	for (unsigned i = 0; i < BCH_COUNTER_NR; i++)
		if (c->recent[NR_RECENT_COUNTERS - 1][i] != percpu_u64_get(&c->now[i]))
			__set_bit(i, active);

	for (unsigned i = 0; i < BCH_COUNTER_NR; i++) {
		if (!test_bit(i, active))
			continue;

		prt_printf(out, "%s:", bch2_counter_names[i]);

		u64 prev = percpu_u64_get(&c->now[i]);

		for (unsigned j = 0; j < NR_RECENT_COUNTERS; j++) {
			prt_printf(out, "\t%llu", prev - c->recent[j][i]);
			prev = c->recent[j][i];
		}
		prt_newline(out);
	}
}

void bch2_fs_counters_exit(struct bch_fs *c)
{
	cancel_delayed_work_sync(&c->counters.work);
	free_percpu(c->counters.now);
}

int bch2_fs_counters_init(struct bch_fs *c)
{
	c->counters.now = __alloc_percpu(sizeof(u64) * BCH_COUNTER_NR, sizeof(u64));
	if (!c->counters.now)
		return -BCH_ERR_ENOMEM_fs_counters_init;

	try(bch2_sb_counters_to_cpu(c));

	INIT_DELAYED_WORK(&c->counters.work, bch2_sb_counters_work);
	return 0;
}

int bch2_fs_counters_init_late(struct bch_fs *c)
{
	queue_delayed_work(system_unbound_wq, &c->counters.work, HZ / 2);
	return 0;
}

const struct bch_sb_field_ops bch_sb_field_ops_counters = {
	.validate	= bch2_sb_counters_validate,
	.to_text	= bch2_sb_counters_to_text,
};

#ifndef NO_BCACHEFS_CHARDEV
long bch2_ioctl_query_counters(struct bch_fs *c,
			struct bch_ioctl_query_counters __user *user_arg)
{
	struct bch_ioctl_query_counters arg;
	try(copy_from_user_errcode(&arg, user_arg, sizeof(arg)));

	if ((arg.flags & ~BCH_IOCTL_QUERY_COUNTERS_MOUNT) ||
	    arg.pad)
		return -EINVAL;

	arg.nr = min(arg.nr, BCH_COUNTER_NR);
	try(put_user(arg.nr, &user_arg->nr));

	for (unsigned i = 0; i < BCH_COUNTER_NR; i++) {
		unsigned stable = counters_to_stable_map[i];

		if (stable < arg.nr) {
			u64 v = !(arg.flags & BCH_IOCTL_QUERY_COUNTERS_MOUNT)
				? percpu_u64_get(&c->counters.now[i])
				: c->counters.mount[i];

			try(put_user(v, &user_arg->d[stable]));
		}
	}

	return 0;
}
#endif
