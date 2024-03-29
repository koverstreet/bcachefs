// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "alloc_background.h"
#include "backpointers.h"
#include "btree_gc.h"
#include "ec.h"
#include "fsck.h"
#include "inode.h"
#include "journal.h"
#include "lru.h"
#include "logged_ops.h"
#include "rebalance.h"
#include "recovery.h"
#include "recovery_passes.h"
#include "snapshot.h"
#include "subvolume.h"
#include "super.h"

const char * const bch2_recovery_passes[] = {
#define x(_fn, ...)	#_fn,
	BCH_RECOVERY_PASSES()
#undef x
	NULL
};

static int bch2_check_allocations(struct bch_fs *c)
{
	return bch2_gc(c, true, c->opts.norecovery);
}

static int bch2_set_may_go_rw(struct bch_fs *c)
{
	struct journal_keys *keys = &c->journal_keys;

	/*
	 * After we go RW, the journal keys buffer can't be modified (except for
	 * setting journal_key->overwritten: it will be accessed by multiple
	 * threads
	 */
	move_gap(keys, keys->nr);

	set_bit(BCH_FS_may_go_rw, &c->flags);

	if (keys->nr || c->opts.fsck || !c->sb.clean)
		return bch2_fs_read_write_early(c);
	return 0;
}

struct recovery_pass_fn {
	int		(*fn)(struct bch_fs *);
	unsigned	when;
};

static struct recovery_pass_fn recovery_pass_fns[] = {
#define x(_fn, _id, _when)	{ .fn = bch2_##_fn, .when = _when },
	BCH_RECOVERY_PASSES()
#undef x
};

u64 bch2_recovery_passes_to_stable(u64 v)
{
	static const u8 map[] = {
#define x(n, id, ...)	[BCH_RECOVERY_PASS_##n] = BCH_RECOVERY_PASS_STABLE_##n,
	BCH_RECOVERY_PASSES()
#undef x
	};

	u64 ret = 0;
	for (unsigned i = 0; i < ARRAY_SIZE(map); i++)
		if (v & BIT_ULL(i))
			ret |= BIT_ULL(map[i]);
	return ret;
}

u64 bch2_recovery_passes_from_stable(u64 v)
{
	static const u8 map[] = {
#define x(n, id, ...)	[BCH_RECOVERY_PASS_STABLE_##n] = BCH_RECOVERY_PASS_##n,
	BCH_RECOVERY_PASSES()
#undef x
	};

	u64 ret = 0;
	for (unsigned i = 0; i < ARRAY_SIZE(map); i++)
		if (v & BIT_ULL(i))
			ret |= BIT_ULL(map[i]);
	return ret;
}

/*
 * For when we need to rewind recovery passes and run a pass we skipped:
 */
int bch2_run_explicit_recovery_pass(struct bch_fs *c,
				    enum bch_recovery_pass pass)
{
	if (c->recovery_passes_explicit & BIT_ULL(pass))
		return 0;

	bch_info(c, "running explicit recovery pass %s (%u), currently at %s (%u)",
		 bch2_recovery_passes[pass], pass,
		 bch2_recovery_passes[c->curr_recovery_pass], c->curr_recovery_pass);

	c->recovery_passes_explicit |= BIT_ULL(pass);

	if (c->curr_recovery_pass >= pass) {
		c->curr_recovery_pass = pass;
		c->recovery_passes_complete &= (1ULL << pass) >> 1;
		return -BCH_ERR_restart_recovery;
	} else {
		return 0;
	}
}

u64 bch2_fsck_recovery_passes(void)
{
	u64 ret = 0;

	for (unsigned i = 0; i < ARRAY_SIZE(recovery_pass_fns); i++)
		if (recovery_pass_fns[i].when & PASS_FSCK)
			ret |= BIT_ULL(i);
	return ret;
}

static bool should_run_recovery_pass(struct bch_fs *c, enum bch_recovery_pass pass)
{
	struct recovery_pass_fn *p = recovery_pass_fns + pass;

	if (c->opts.norecovery && pass > BCH_RECOVERY_PASS_snapshots_read)
		return false;
	if (c->recovery_passes_explicit & BIT_ULL(pass))
		return true;
	if ((p->when & PASS_FSCK) && c->opts.fsck)
		return true;
	if ((p->when & PASS_UNCLEAN) && !c->sb.clean)
		return true;
	if (p->when & PASS_ALWAYS)
		return true;
	return false;
}

static int bch2_run_recovery_pass(struct bch_fs *c, enum bch_recovery_pass pass)
{
	struct recovery_pass_fn *p = recovery_pass_fns + pass;
	int ret;

	if (!(p->when & PASS_SILENT))
		bch2_print(c, KERN_INFO bch2_log_msg(c, "%s..."),
			   bch2_recovery_passes[pass]);
	ret = p->fn(c);
	if (ret)
		return ret;
	if (!(p->when & PASS_SILENT))
		bch2_print(c, KERN_CONT " done\n");

	return 0;
}

int bch2_run_online_recovery_passes(struct bch_fs *c)
{
	int ret = 0;

	for (unsigned i = 0; i < ARRAY_SIZE(recovery_pass_fns); i++) {
		struct recovery_pass_fn *p = recovery_pass_fns + i;

		if (!(p->when & PASS_ONLINE))
			continue;

		ret = bch2_run_recovery_pass(c, i);
		if (bch2_err_matches(ret, BCH_ERR_restart_recovery)) {
			i = c->curr_recovery_pass;
			continue;
		}
		if (ret)
			break;
	}

	return ret;
}

int bch2_run_recovery_passes(struct bch_fs *c)
{
	int ret = 0;

	while (c->curr_recovery_pass < ARRAY_SIZE(recovery_pass_fns)) {
		if (should_run_recovery_pass(c, c->curr_recovery_pass)) {
			unsigned pass = c->curr_recovery_pass;

			ret = bch2_run_recovery_pass(c, c->curr_recovery_pass);
			if (bch2_err_matches(ret, BCH_ERR_restart_recovery) ||
			    (ret && c->curr_recovery_pass < pass))
				continue;
			if (ret)
				break;

			c->recovery_passes_complete |= BIT_ULL(c->curr_recovery_pass);
		}
		c->curr_recovery_pass++;
		c->recovery_pass_done = max(c->recovery_pass_done, c->curr_recovery_pass);
	}

	return ret;
}
