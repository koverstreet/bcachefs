// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "btree_locking.h"
#include "btree_types.h"

static struct lock_class_key bch2_btree_node_lock_key;

void bch2_btree_lock_init(struct btree_bkey_cached_common *b,
			  enum six_lock_init_flags flags)
{
	__six_lock_init(&b->lock, "b->c.lock", &bch2_btree_node_lock_key, flags);
	lockdep_set_novalidate_class(&b->lock);
}

#ifdef CONFIG_LOCKDEP
void bch2_assert_btree_nodes_not_locked(void)
{
#if 0
	//Re-enable when lock_class_is_held() is merged:
	BUG_ON(lock_class_is_held(&bch2_btree_node_lock_key));
#endif
}
#endif

/* Btree node locking: */

struct six_lock_count bch2_btree_node_lock_counts(struct btree_trans *trans,
						  struct btree_path *skip,
						  struct btree_bkey_cached_common *b,
						  unsigned level)
{
	struct btree_path *path;
	struct six_lock_count ret;
	unsigned i;

	memset(&ret, 0, sizeof(ret));

	if (IS_ERR_OR_NULL(b))
		return ret;

	trans_for_each_path(trans, path, i)
		if (path != skip && &path->l[level].b->c == b) {
			int t = btree_node_locked_type(path, level);

			if (t != BTREE_NODE_UNLOCKED)
				ret.n[t]++;
		}

	return ret;
}

/* unlock */

void bch2_btree_node_unlock_write(struct btree_trans *trans,
			struct btree_path *path, struct btree *b)
{
	bch2_btree_node_unlock_write_inlined(trans, path, b);
}

/* lock */

/*
 * @trans wants to lock @b with type @type
 */
struct trans_waiting_for_lock {
	struct btree_trans		*trans;
	struct btree_bkey_cached_common	*node_want;
	enum six_lock_type		lock_want;

	/* for iterating over held locks :*/
	u8				path_idx;
	u8				level;
	u64				lock_start_time;
};

struct lock_graph {
	struct trans_waiting_for_lock	g[8];
	unsigned			nr;
};

static noinline void print_cycle(struct printbuf *out, struct lock_graph *g)
{
	struct trans_waiting_for_lock *i;

	prt_printf(out, "Found lock cycle (%u entries):\n", g->nr);

	for (i = g->g; i < g->g + g->nr; i++) {
		struct task_struct *task = READ_ONCE(i->trans->locking_wait.task);
		if (!task)
			continue;

		bch2_btree_trans_to_text(out, i->trans);
		bch2_prt_task_backtrace(out, task, i == g->g ? 5 : 1, GFP_NOWAIT);
	}
}

static noinline void print_chain(struct printbuf *out, struct lock_graph *g)
{
	struct trans_waiting_for_lock *i;

	for (i = g->g; i != g->g + g->nr; i++) {
		struct task_struct *task = i->trans->locking_wait.task;
		if (i != g->g)
			prt_str(out, "<- ");
		prt_printf(out, "%u ", task ?task->pid : 0);
	}
	prt_newline(out);
}

static void lock_graph_up(struct lock_graph *g)
{
	closure_put(&g->g[--g->nr].trans->ref);
}

static noinline void lock_graph_pop_all(struct lock_graph *g)
{
	while (g->nr)
		lock_graph_up(g);
}

static void __lock_graph_down(struct lock_graph *g, struct btree_trans *trans)
{
	g->g[g->nr++] = (struct trans_waiting_for_lock) {
		.trans		= trans,
		.node_want	= trans->locking,
		.lock_want	= trans->locking_wait.lock_want,
	};
}

static void lock_graph_down(struct lock_graph *g, struct btree_trans *trans)
{
	closure_get(&trans->ref);
	__lock_graph_down(g, trans);
}

static bool lock_graph_remove_non_waiters(struct lock_graph *g)
{
	struct trans_waiting_for_lock *i;

	for (i = g->g + 1; i < g->g + g->nr; i++)
		if (i->trans->locking != i->node_want ||
		    i->trans->locking_wait.start_time != i[-1].lock_start_time) {
			while (g->g + g->nr > i)
				lock_graph_up(g);
			return true;
		}

	return false;
}

static void trace_would_deadlock(struct lock_graph *g, struct btree_trans *trans)
{
	struct bch_fs *c = trans->c;

	count_event(c, trans_restart_would_deadlock);

	if (trace_trans_restart_would_deadlock_enabled()) {
		struct printbuf buf = PRINTBUF;

		buf.atomic++;
		print_cycle(&buf, g);

		trace_trans_restart_would_deadlock(trans, buf.buf);
		printbuf_exit(&buf);
	}
}

static int abort_lock(struct lock_graph *g, struct trans_waiting_for_lock *i)
{
	if (i == g->g) {
		trace_would_deadlock(g, i->trans);
		return btree_trans_restart(i->trans, BCH_ERR_transaction_restart_would_deadlock);
	} else {
		i->trans->lock_must_abort = true;
		wake_up_process(i->trans->locking_wait.task);
		return 0;
	}
}

static int btree_trans_abort_preference(struct btree_trans *trans)
{
	if (trans->lock_may_not_fail)
		return 0;
	if (trans->locking_wait.lock_want == SIX_LOCK_write)
		return 1;
	if (!trans->in_traverse_all)
		return 2;
	return 3;
}

static noinline int break_cycle(struct lock_graph *g, struct printbuf *cycle)
{
	struct trans_waiting_for_lock *i, *abort = NULL;
	unsigned best = 0, pref;
	int ret;

	if (lock_graph_remove_non_waiters(g))
		return 0;

	/* Only checking, for debugfs: */
	if (cycle) {
		print_cycle(cycle, g);
		ret = -1;
		goto out;
	}

	for (i = g->g; i < g->g + g->nr; i++) {
		pref = btree_trans_abort_preference(i->trans);
		if (pref > best) {
			abort = i;
			best = pref;
		}
	}

	if (unlikely(!best)) {
		struct printbuf buf = PRINTBUF;
		buf.atomic++;

		prt_printf(&buf, bch2_fmt(g->g->trans->c, "cycle of nofail locks"));

		for (i = g->g; i < g->g + g->nr; i++) {
			struct btree_trans *trans = i->trans;

			bch2_btree_trans_to_text(&buf, trans);

			prt_printf(&buf, "backtrace:\n");
			printbuf_indent_add(&buf, 2);
			bch2_prt_task_backtrace(&buf, trans->locking_wait.task, 2, GFP_NOWAIT);
			printbuf_indent_sub(&buf, 2);
			prt_newline(&buf);
		}

		bch2_print_string_as_lines(KERN_ERR, buf.buf);
		printbuf_exit(&buf);
		BUG();
	}

	ret = abort_lock(g, abort);
out:
	if (ret)
		while (g->nr)
			lock_graph_up(g);
	return ret;
}

static int lock_graph_descend(struct lock_graph *g, struct btree_trans *trans,
			      struct printbuf *cycle)
{
	struct btree_trans *orig_trans = g->g->trans;
	struct trans_waiting_for_lock *i;

	for (i = g->g; i < g->g + g->nr; i++)
		if (i->trans == trans) {
			closure_put(&trans->ref);
			return break_cycle(g, cycle);
		}

	if (g->nr == ARRAY_SIZE(g->g)) {
		closure_put(&trans->ref);

		if (orig_trans->lock_may_not_fail)
			return 0;

		while (g->nr)
			lock_graph_up(g);

		if (cycle)
			return 0;

		trace_and_count(trans->c, trans_restart_would_deadlock_recursion_limit, trans, _RET_IP_);
		return btree_trans_restart(orig_trans, BCH_ERR_transaction_restart_deadlock_recursion_limit);
	}

	__lock_graph_down(g, trans);
	return 0;
}

static bool lock_type_conflicts(enum six_lock_type t1, enum six_lock_type t2)
{
	return t1 + t2 > 1;
}

int bch2_check_for_deadlock(struct btree_trans *trans, struct printbuf *cycle)
{
	struct lock_graph g;
	struct trans_waiting_for_lock *top;
	struct btree_bkey_cached_common *b;
	btree_path_idx_t path_idx;
	int ret = 0;

	g.nr = 0;

	if (trans->lock_must_abort) {
		if (cycle)
			return -1;

		trace_would_deadlock(&g, trans);
		return btree_trans_restart(trans, BCH_ERR_transaction_restart_would_deadlock);
	}

	lock_graph_down(&g, trans);

	/* trans->paths is rcu protected vs. freeing */
	rcu_read_lock();
	if (cycle)
		cycle->atomic++;
next:
	if (!g.nr)
		goto out;

	top = &g.g[g.nr - 1];

	struct btree_path *paths = rcu_dereference(top->trans->paths);
	if (!paths)
		goto up;

	unsigned long *paths_allocated = trans_paths_allocated(paths);

	trans_for_each_path_idx_from(paths_allocated, *trans_paths_nr(paths),
				     path_idx, top->path_idx) {
		struct btree_path *path = paths + path_idx;
		if (!path->nodes_locked)
			continue;

		if (path_idx != top->path_idx) {
			top->path_idx		= path_idx;
			top->level		= 0;
			top->lock_start_time	= 0;
		}

		for (;
		     top->level < BTREE_MAX_DEPTH;
		     top->level++, top->lock_start_time = 0) {
			int lock_held = btree_node_locked_type(path, top->level);

			if (lock_held == BTREE_NODE_UNLOCKED)
				continue;

			b = &READ_ONCE(path->l[top->level].b)->c;

			if (IS_ERR_OR_NULL(b)) {
				/*
				 * If we get here, it means we raced with the
				 * other thread updating its btree_path
				 * structures - which means it can't be blocked
				 * waiting on a lock:
				 */
				if (!lock_graph_remove_non_waiters(&g)) {
					/*
					 * If lock_graph_remove_non_waiters()
					 * didn't do anything, it must be
					 * because we're being called by debugfs
					 * checking for lock cycles, which
					 * invokes us on btree_transactions that
					 * aren't actually waiting on anything.
					 * Just bail out:
					 */
					lock_graph_pop_all(&g);
				}

				goto next;
			}

			if (list_empty_careful(&b->lock.wait_list))
				continue;

			raw_spin_lock(&b->lock.wait_lock);
			list_for_each_entry(trans, &b->lock.wait_list, locking_wait.list) {
				BUG_ON(b != trans->locking);

				if (top->lock_start_time &&
				    time_after_eq64(top->lock_start_time, trans->locking_wait.start_time))
					continue;

				top->lock_start_time = trans->locking_wait.start_time;

				/* Don't check for self deadlock: */
				if (trans == top->trans ||
				    !lock_type_conflicts(lock_held, trans->locking_wait.lock_want))
					continue;

				closure_get(&trans->ref);
				raw_spin_unlock(&b->lock.wait_lock);

				ret = lock_graph_descend(&g, trans, cycle);
				if (ret)
					goto out;
				goto next;

			}
			raw_spin_unlock(&b->lock.wait_lock);
		}
	}
up:
	if (g.nr > 1 && cycle)
		print_chain(cycle, &g);
	lock_graph_up(&g);
	goto next;
out:
	if (cycle)
		--cycle->atomic;
	rcu_read_unlock();
	return ret;
}

int bch2_six_check_for_deadlock(struct six_lock *lock, void *p)
{
	struct btree_trans *trans = p;

	return bch2_check_for_deadlock(trans, NULL);
}

int __bch2_btree_node_lock_write(struct btree_trans *trans, struct btree_path *path,
				 struct btree_bkey_cached_common *b,
				 bool lock_may_not_fail)
{
	int readers = bch2_btree_node_lock_counts(trans, NULL, b, b->level).n[SIX_LOCK_read];
	int ret;

	/*
	 * Must drop our read locks before calling six_lock_write() -
	 * six_unlock() won't do wakeups until the reader count
	 * goes to 0, and it's safe because we have the node intent
	 * locked:
	 */
	six_lock_readers_add(&b->lock, -readers);
	ret = __btree_node_lock_nopath(trans, b, SIX_LOCK_write,
				       lock_may_not_fail, _RET_IP_);
	six_lock_readers_add(&b->lock, readers);

	if (ret)
		mark_btree_node_locked_noreset(path, b->level, BTREE_NODE_INTENT_LOCKED);

	return ret;
}

void bch2_btree_node_lock_write_nofail(struct btree_trans *trans,
				       struct btree_path *path,
				       struct btree_bkey_cached_common *b)
{
	int ret = __btree_node_lock_write(trans, path, b, true);
	BUG_ON(ret);
}

/* relock */

static inline bool btree_path_get_locks(struct btree_trans *trans,
					struct btree_path *path,
					bool upgrade,
					struct get_locks_fail *f)
{
	unsigned l = path->level;
	int fail_idx = -1;

	do {
		if (!btree_path_node(path, l))
			break;

		if (!(upgrade
		      ? bch2_btree_node_upgrade(trans, path, l)
		      : bch2_btree_node_relock(trans, path, l))) {
			fail_idx	= l;

			if (f) {
				f->l	= l;
				f->b	= path->l[l].b;
			}
		}

		l++;
	} while (l < path->locks_want);

	/*
	 * When we fail to get a lock, we have to ensure that any child nodes
	 * can't be relocked so bch2_btree_path_traverse has to walk back up to
	 * the node that we failed to relock:
	 */
	if (fail_idx >= 0) {
		__bch2_btree_path_unlock(trans, path);
		btree_path_set_dirty(path, BTREE_ITER_NEED_TRAVERSE);

		do {
			path->l[fail_idx].b = upgrade
				? ERR_PTR(-BCH_ERR_no_btree_node_upgrade)
				: ERR_PTR(-BCH_ERR_no_btree_node_relock);
			--fail_idx;
		} while (fail_idx >= 0);
	}

	if (path->uptodate == BTREE_ITER_NEED_RELOCK)
		path->uptodate = BTREE_ITER_UPTODATE;

	return path->uptodate < BTREE_ITER_NEED_RELOCK;
}

bool __bch2_btree_node_relock(struct btree_trans *trans,
			      struct btree_path *path, unsigned level,
			      bool trace)
{
	struct btree *b = btree_path_node(path, level);
	int want = __btree_lock_want(path, level);

	if (race_fault())
		goto fail;

	if (six_relock_type(&b->c.lock, want, path->l[level].lock_seq) ||
	    (btree_node_lock_seq_matches(path, b, level) &&
	     btree_node_lock_increment(trans, &b->c, level, want))) {
		mark_btree_node_locked(trans, path, level, want);
		return true;
	}
fail:
	if (trace && !trans->notrace_relock_fail)
		trace_and_count(trans->c, btree_path_relock_fail, trans, _RET_IP_, path, level);
	return false;
}

/* upgrade */

bool bch2_btree_node_upgrade(struct btree_trans *trans,
			     struct btree_path *path, unsigned level)
{
	struct btree *b = path->l[level].b;
	struct six_lock_count count = bch2_btree_node_lock_counts(trans, path, &b->c, level);

	if (!is_btree_node(path, level))
		return false;

	switch (btree_lock_want(path, level)) {
	case BTREE_NODE_UNLOCKED:
		BUG_ON(btree_node_locked(path, level));
		return true;
	case BTREE_NODE_READ_LOCKED:
		BUG_ON(btree_node_intent_locked(path, level));
		return bch2_btree_node_relock(trans, path, level);
	case BTREE_NODE_INTENT_LOCKED:
		break;
	case BTREE_NODE_WRITE_LOCKED:
		BUG();
	}

	if (btree_node_intent_locked(path, level))
		return true;

	if (race_fault())
		return false;

	if (btree_node_locked(path, level)) {
		bool ret;

		six_lock_readers_add(&b->c.lock, -count.n[SIX_LOCK_read]);
		ret = six_lock_tryupgrade(&b->c.lock);
		six_lock_readers_add(&b->c.lock, count.n[SIX_LOCK_read]);

		if (ret)
			goto success;
	} else {
		if (six_relock_type(&b->c.lock, SIX_LOCK_intent, path->l[level].lock_seq))
			goto success;
	}

	/*
	 * Do we already have an intent lock via another path? If so, just bump
	 * lock count:
	 */
	if (btree_node_lock_seq_matches(path, b, level) &&
	    btree_node_lock_increment(trans, &b->c, level, BTREE_NODE_INTENT_LOCKED)) {
		btree_node_unlock(trans, path, level);
		goto success;
	}

	trace_and_count(trans->c, btree_path_upgrade_fail, trans, _RET_IP_, path, level);
	return false;
success:
	mark_btree_node_locked_noreset(path, level, BTREE_NODE_INTENT_LOCKED);
	return true;
}

/* Btree path locking: */

/*
 * Only for btree_cache.c - only relocks intent locks
 */
int bch2_btree_path_relock_intent(struct btree_trans *trans,
				  struct btree_path *path)
{
	unsigned l;

	for (l = path->level;
	     l < path->locks_want && btree_path_node(path, l);
	     l++) {
		if (!bch2_btree_node_relock(trans, path, l)) {
			__bch2_btree_path_unlock(trans, path);
			btree_path_set_dirty(path, BTREE_ITER_NEED_TRAVERSE);
			trace_and_count(trans->c, trans_restart_relock_path_intent, trans, _RET_IP_, path);
			return btree_trans_restart(trans, BCH_ERR_transaction_restart_relock_path_intent);
		}
	}

	return 0;
}

__flatten
bool bch2_btree_path_relock_norestart(struct btree_trans *trans, struct btree_path *path)
{
	struct get_locks_fail f;

	bool ret = btree_path_get_locks(trans, path, false, &f);
	bch2_trans_verify_locks(trans);
	return ret;
}

int __bch2_btree_path_relock(struct btree_trans *trans,
			struct btree_path *path, unsigned long trace_ip)
{
	if (!bch2_btree_path_relock_norestart(trans, path)) {
		trace_and_count(trans->c, trans_restart_relock_path, trans, trace_ip, path);
		return btree_trans_restart(trans, BCH_ERR_transaction_restart_relock_path);
	}

	return 0;
}

bool bch2_btree_path_upgrade_noupgrade_sibs(struct btree_trans *trans,
			       struct btree_path *path,
			       unsigned new_locks_want,
			       struct get_locks_fail *f)
{
	EBUG_ON(path->locks_want >= new_locks_want);

	path->locks_want = new_locks_want;

	bool ret = btree_path_get_locks(trans, path, true, f);
	bch2_trans_verify_locks(trans);
	return ret;
}

bool __bch2_btree_path_upgrade(struct btree_trans *trans,
			       struct btree_path *path,
			       unsigned new_locks_want,
			       struct get_locks_fail *f)
{
	bool ret = bch2_btree_path_upgrade_noupgrade_sibs(trans, path, new_locks_want, f);
	if (ret)
		goto out;

	/*
	 * XXX: this is ugly - we'd prefer to not be mucking with other
	 * iterators in the btree_trans here.
	 *
	 * On failure to upgrade the iterator, setting iter->locks_want and
	 * calling get_locks() is sufficient to make bch2_btree_path_traverse()
	 * get the locks we want on transaction restart.
	 *
	 * But if this iterator was a clone, on transaction restart what we did
	 * to this iterator isn't going to be preserved.
	 *
	 * Possibly we could add an iterator field for the parent iterator when
	 * an iterator is a copy - for now, we'll just upgrade any other
	 * iterators with the same btree id.
	 *
	 * The code below used to be needed to ensure ancestor nodes get locked
	 * before interior nodes - now that's handled by
	 * bch2_btree_path_traverse_all().
	 */
	if (!path->cached && !trans->in_traverse_all) {
		struct btree_path *linked;
		unsigned i;

		trans_for_each_path(trans, linked, i)
			if (linked != path &&
			    linked->cached == path->cached &&
			    linked->btree_id == path->btree_id &&
			    linked->locks_want < new_locks_want) {
				linked->locks_want = new_locks_want;
				btree_path_get_locks(trans, linked, true, NULL);
			}
	}
out:
	bch2_trans_verify_locks(trans);
	return ret;
}

void __bch2_btree_path_downgrade(struct btree_trans *trans,
				 struct btree_path *path,
				 unsigned new_locks_want)
{
	unsigned l, old_locks_want = path->locks_want;

	if (trans->restarted)
		return;

	EBUG_ON(path->locks_want < new_locks_want);

	path->locks_want = new_locks_want;

	while (path->nodes_locked &&
	       (l = btree_path_highest_level_locked(path)) >= path->locks_want) {
		if (l > path->level) {
			btree_node_unlock(trans, path, l);
		} else {
			if (btree_node_intent_locked(path, l)) {
				six_lock_downgrade(&path->l[l].b->c.lock);
				mark_btree_node_locked_noreset(path, l, BTREE_NODE_READ_LOCKED);
			}
			break;
		}
	}

	bch2_btree_path_verify_locks(path);

	trace_path_downgrade(trans, _RET_IP_, path, old_locks_want);
}

/* Btree transaction locking: */

void bch2_trans_downgrade(struct btree_trans *trans)
{
	struct btree_path *path;
	unsigned i;

	if (trans->restarted)
		return;

	trans_for_each_path(trans, path, i)
		if (path->ref)
			bch2_btree_path_downgrade(trans, path);
}

static inline void __bch2_trans_unlock(struct btree_trans *trans)
{
	struct btree_path *path;
	unsigned i;

	trans_for_each_path(trans, path, i)
		__bch2_btree_path_unlock(trans, path);
}

static noinline __cold int bch2_trans_relock_fail(struct btree_trans *trans, struct btree_path *path,
						  struct get_locks_fail *f, bool trace)
{
	if (!trace)
		goto out;

	if (trace_trans_restart_relock_enabled()) {
		struct printbuf buf = PRINTBUF;

		bch2_bpos_to_text(&buf, path->pos);
		prt_printf(&buf, " l=%u seq=%u node seq=", f->l, path->l[f->l].lock_seq);
		if (IS_ERR_OR_NULL(f->b)) {
			prt_str(&buf, bch2_err_str(PTR_ERR(f->b)));
		} else {
			prt_printf(&buf, "%u", f->b->c.lock.seq);

			struct six_lock_count c =
				bch2_btree_node_lock_counts(trans, NULL, &f->b->c, f->l);
			prt_printf(&buf, " self locked %u.%u.%u", c.n[0], c.n[1], c.n[2]);

			c = six_lock_counts(&f->b->c.lock);
			prt_printf(&buf, " total locked %u.%u.%u", c.n[0], c.n[1], c.n[2]);
		}

		trace_trans_restart_relock(trans, _RET_IP_, buf.buf);
		printbuf_exit(&buf);
	}

	count_event(trans->c, trans_restart_relock);
out:
	__bch2_trans_unlock(trans);
	bch2_trans_verify_locks(trans);
	return btree_trans_restart(trans, BCH_ERR_transaction_restart_relock);
}

static inline int __bch2_trans_relock(struct btree_trans *trans, bool trace)
{
	bch2_trans_verify_locks(trans);

	if (unlikely(trans->restarted))
		return -((int) trans->restarted);
	if (unlikely(trans->locked))
		goto out;

	struct btree_path *path;
	unsigned i;

	trans_for_each_path(trans, path, i) {
		struct get_locks_fail f;

		if (path->should_be_locked &&
		    !btree_path_get_locks(trans, path, false, &f))
			return bch2_trans_relock_fail(trans, path, &f, trace);
	}

	trans->locked = true;
out:
	bch2_trans_verify_locks(trans);
	return 0;
}

int bch2_trans_relock(struct btree_trans *trans)
{
	return __bch2_trans_relock(trans, true);
}

int bch2_trans_relock_notrace(struct btree_trans *trans)
{
	return __bch2_trans_relock(trans, false);
}

void bch2_trans_unlock_noassert(struct btree_trans *trans)
{
	__bch2_trans_unlock(trans);

	trans->locked = false;
	trans->last_unlock_ip = _RET_IP_;
}

void bch2_trans_unlock(struct btree_trans *trans)
{
	__bch2_trans_unlock(trans);

	trans->locked = false;
	trans->last_unlock_ip = _RET_IP_;
}

void bch2_trans_unlock_long(struct btree_trans *trans)
{
	bch2_trans_unlock(trans);
	bch2_trans_srcu_unlock(trans);
}

int __bch2_trans_mutex_lock(struct btree_trans *trans,
			    struct mutex *lock)
{
	int ret = drop_locks_do(trans, (mutex_lock(lock), 0));

	if (ret)
		mutex_unlock(lock);
	return ret;
}

/* Debug */

#ifdef CONFIG_BCACHEFS_DEBUG

void bch2_btree_path_verify_locks(struct btree_path *path)
{
	/*
	 * A path may be uptodate and yet have nothing locked if and only if
	 * there is no node at path->level, which generally means we were
	 * iterating over all nodes and got to the end of the btree
	 */
	BUG_ON(path->uptodate == BTREE_ITER_UPTODATE &&
	       btree_path_node(path, path->level) &&
	       !path->nodes_locked);

	if (!path->nodes_locked)
		return;

	for (unsigned l = 0; l < BTREE_MAX_DEPTH; l++) {
		int want = btree_lock_want(path, l);
		int have = btree_node_locked_type(path, l);

		BUG_ON(!is_btree_node(path, l) && have != BTREE_NODE_UNLOCKED);

		BUG_ON(is_btree_node(path, l) &&
		       (want == BTREE_NODE_UNLOCKED ||
			have != BTREE_NODE_WRITE_LOCKED) &&
		       want != have);
	}
}

static bool bch2_trans_locked(struct btree_trans *trans)
{
	struct btree_path *path;
	unsigned i;

	trans_for_each_path(trans, path, i)
		if (path->nodes_locked)
			return true;
	return false;
}

void bch2_trans_verify_locks(struct btree_trans *trans)
{
	if (!trans->locked) {
		BUG_ON(bch2_trans_locked(trans));
		return;
	}

	struct btree_path *path;
	unsigned i;

	trans_for_each_path(trans, path, i)
		bch2_btree_path_verify_locks(path);
}

#endif
