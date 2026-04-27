// SPDX-License-Identifier: GPL-2.0

/* DOC(btree-node-cache)
 *
 * In-memory btree nodes are kept in a hash table indexed by their physical
 * on-disk pointer (not their logical position). This is because btree node
 * split and compact operations are copy-on-write: new nodes are allocated, the
 * parent is updated to point to them, and the old nodes are freed. Indexing by
 * physical pointer avoids the need to atomically update the hash table during
 * these operations.
 *
 * The `struct btree` objects themselves are never freed during normal operation
 * (only at shutdown), which means locks can be dropped and retaken without
 * reference counting. This enables the aggressive lock-dropping discipline
 * that keeps btree lock hold times bounded to in-memory operations: after
 * dropping a lock, a sequence number check determines whether the node has
 * changed and needs to be re-traversed.
 *
 * Btree roots are pinned in memory and accessed directly. All other nodes may
 * be evicted from the cache and reused for different on-disk nodes at any time
 * when unlocked, so after locking a node the caller must verify it is still
 * the expected node.
 *
 * Membership state machine
 * ------------------------
 *
 * A struct btree is in exactly one of five states at any time, recorded in
 * b->cache_state and maintained by bch2_btree_node_transition_state():
 *
 *   NONE      — off all lists, NOT hashed. Either kzalloc'd and not yet
 *               placed, transiently held by one thread mid-state-change,
 *               or claimed out of the cache by a caller for private use.
 *   FREED     — bc->freed_pcpu (level-0 pcpu-readers locks) or
 *               bc->freed_nonpcpu (interior nodes), NOT hashed, b->data NULL.
 *               struct btree shell pool: lock state preserved, data buffer
 *               released. Not counted (freed lists are unbounded scratch).
 *   FREEABLE  — bc->freeable, NOT hashed, b->data set. Buffer cache for hot
 *               alloc/free churn. Counted in bc->nr_freeable.
 *   CLEAN     — bc->live[btree_node_pinned(b)].clean, hashed, b->data set,
 *               BTREE_NODE_dirty clear. Findable by lookup; the shrinker
 *               walks this list to reclaim. Counted in
 *               bc->live[pinned].nr_clean and bc->nr_by_btree[].
 *   DIRTY     — bc->live[btree_node_pinned(b)].dirty, hashed, b->data set,
 *               BTREE_NODE_dirty set. Counted in bc->live[pinned].nr_dirty
 *               and bc->nr_by_btree[]. Not shrinker-eligible until written
 *               out and transitioned to CLEAN.
 *
 * Roots are CLEAN or DIRTY with BTREE_NODE_permanent set; the flag tells
 * the reclaim path to skip them. Roots are also tracked via
 * bc->roots_known[]/roots_extra (under bc->root_lock).
 *
 * All transitions go through one primitive:
 *
 *   bch2_btree_node_transition_state(bc, b, target)
 *      Takes bc->lock, detaches from b's current state (undoing hash/list/
 *      counter bookkeeping) then attaches to @target. Idempotent for
 *      current==target. Transition to CLEAN/DIRTY can fail (rhashtable
 *      insert collision) on the un-hashed→hashed transition; on failure
 *      b->hash_val is reset and b ends up in FREEABLE. Internal callers
 *      already holding bc->lock use the static _locked variant.
 *
 * The data-buffer swap inside bch2_btree_node_mem_alloc requires splitting
 * the transition: transition_state(b2, NONE) captures b2's old-state
 * bookkeeping while data is still attached, then swap(data), then
 * transition_state(b2, FREED) lists b2 with its (now-NULL) data.
 *
 * One non-state-machine transition: any live state → same state +
 * BTREE_NODE_permanent (bch2_btree_set_root_inmem just sets the flag; the
 * node stays put). Eviction (bch2_btree_node_evict) BUG_ONs on permanent
 * nodes — there's no legitimate caller path.
 *
 * Lock discipline:
 *
 *   bc->lock         — list membership, hash table mutation, counters
 *   bc->root_lock    — roots_known[]/roots_extra slot
 *   b->c.lock        — per-node six_lock (read/intent/write)
 *   bc->alloc_lock   — cmpxchg'd task pointer; serialises cannibalize so
 *                      only one thread reclaims under memory pressure
 *
 * Hash table lookups (rhashtable_lookup_fast) are RCU-safe; lookups can race
 * any LIVE↔NONE transition and may briefly miss a node that's hash-removed
 * mid-flight. After locking a node returned by lookup, callers must recheck
 * b->hash_val against the expected key to detect reuse.
 */

#include "bcachefs.h"

#include "btree/bbpos.h"
#include "btree/bkey_buf.h"
#include "btree/cache.h"
#include "btree/iter.h"
#include "btree/locking.h"
#include "btree/read.h"
#include "btree/write.h"

#include "debug/debug.h"

#include "init/error.h"

#include "journal/journal.h"

#include "sb/counters.h"

#include <linux/module.h>
#include <linux/prefetch.h>
#include <linux/sched/mm.h>
#include <linux/swap.h>

bool bch2_mm_avoid_compaction = true;
module_param_named(mm_avoid_compaction, bch2_mm_avoid_compaction, bool, 0644);
MODULE_PARM_DESC(force_read_device, "");

const char * const bch2_btree_node_flags[] = {
	"typebit",
	"typebit",
	"typebit",
#define x(f)	[BTREE_NODE_##f] = #f,
	BTREE_FLAGS()
#undef x
	NULL
};

void bch2_recalc_btree_reserve(struct bch_fs *c)
{
	unsigned reserve = 16;

	if (!c->btree.cache.roots_known[0].b)
		reserve += 8;

	for (unsigned i = 0; i < btree_id_nr_alive(c); i++) {
		struct btree_root *r = bch2_btree_id_root(c, i);

		if (r->b)
			reserve += min_t(unsigned, 1, r->b->c.level) * 8;
	}

	c->btree.cache.nr_reserve = reserve;
}

/* Btree node allocation */

struct btree_node_bufs {
	void		*data;
	void		*aux_data;
	unsigned	byte_order;
};

static void btree_node_bufs_free(struct btree_node_bufs *b)
{
	kvfree(b->data);
#ifdef __KERNEL__
	kvfree(b->aux_data);
#else
	if (b->aux_data)
		munmap(b->aux_data, __btree_aux_data_bytes(b->byte_order));
#endif
}

void bch2_btree_node_data_free(struct btree *b)
{
	EBUG_ON(btree_node_write_in_flight(b));

	if (!b->data)
		return;

	/*
	 * This should really be done in slub/vmalloc, but we're using the
	 * kmalloc_large() path, so we're working around a slub bug by doing
	 * this here:
	 */
	mm_account_reclaimed_pages(btree_buf_bytes(b) / PAGE_SIZE);
	if (b->aux_data)
		mm_account_reclaimed_pages(btree_aux_data_bytes(b) / PAGE_SIZE);

	clear_btree_node_just_written(b);

	struct btree_node_bufs bufs = {
		.data		= b->data,
		.aux_data	= b->aux_data,
		.byte_order	= b->byte_order,
	};
	b->data = NULL;
	b->aux_data = NULL;

	btree_node_bufs_free(&bufs);
}

void bch2_btree_node_mem_free(struct bch_fs *c, struct btree *b)
{
	six_lock_exit(&b->c.lock);
	kfree(b);
}

static int bch2_btree_cache_cmp_fn(struct rhashtable_compare_arg *arg,
				   const void *obj)
{
	const struct btree *b = obj;
	const u64 *v = arg->key;

	return b->hash_val == *v ? 0 : 1;
}

static const struct rhashtable_params bch_btree_cache_params = {
	.head_offset		= offsetof(struct btree, hash),
	.key_offset		= offsetof(struct btree, hash_val),
	.key_len		= sizeof(u64),
	.obj_cmpfn		= bch2_btree_cache_cmp_fn,
	.automatic_shrinking	= true,
};

static int __btree_node_data_alloc(struct bch_fs *c, struct btree_node_bufs *b,
				   gfp_t gfp, bool avoid_compaction)
{
	/*
	 * We probably ought to be using __GFP_RECLAIMABLE - but vmalloc barfs.
	 *
	 * Shrinkable memory accounting is fubar.
	 */
	gfp |= __GFP_ACCOUNT;

	if (!b->data) {
		unsigned bytes = 1U << b->byte_order;

		if (avoid_compaction && bch2_mm_avoid_compaction) {
			/*
			 * Cursed hack: mm doesn't know how to limit the amount of time
			 * we spend blocked on compaction, even if we specified a
			 * vmalloc fallback.
			 *
			 * So we have to do that ourselves: only try for a high order
			 * page allocation if we're GFP_NOWAIT, otherwise straight to
			 * vmalloc.
			 */
			b->data = gfp & __GFP_RECLAIM
				? __vmalloc(bytes, gfp)
				: kmalloc(bytes, gfp);
		}
		/*
		 * mm is cursed: vmalloc can fail for no sane reason, even on 64
		 * bit machines, so - fall back to the page allocator if that
		 * fails
		 */

		if (!b->data)
			b->data = kvmalloc(bytes, gfp);
		if (!b->data)
			return bch_err_throw(c, ENOMEM_btree_node_mem_alloc);
	}

	if (!b->aux_data) {
		unsigned bytes = __btree_aux_data_bytes(b->byte_order);

#ifdef __KERNEL__
		b->aux_data = kvmalloc(bytes, gfp);
#else
		b->aux_data = mmap(NULL, bytes,
				   PROT_READ|PROT_WRITE|PROT_EXEC,
				   MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
		if (b->aux_data == MAP_FAILED)
			b->aux_data = NULL;
#endif
		if (!b->aux_data)
			return bch_err_throw(c, ENOMEM_btree_node_mem_alloc);
	}

	return 0;
}

static struct btree *__btree_node_mem_alloc(struct bch_fs *c, bool pcpu_read_locks, gfp_t gfp)
{
	struct btree *b = kzalloc(sizeof(struct btree), gfp);
	if (!b)
		return NULL;

	bkey_btree_ptr_init(&b->key);
	INIT_LIST_HEAD(&b->list);
	INIT_LIST_HEAD(&b->write_blocked);
	b->byte_order = ilog2(c->opts.btree_node_size);
	bch2_btree_lock_init(&b->c, pcpu_read_locks ? SIX_LOCK_INIT_PCPU : 0, gfp);
	return b;
}

struct btree *__bch2_btree_node_mem_alloc(struct bch_fs *c)
{
	struct btree_node_bufs bufs = { .byte_order = ilog2(c->opts.btree_node_size) };
	struct btree *b;

	if (__btree_node_data_alloc(c, &bufs, GFP_KERNEL, false) ||
	    !(b = __btree_node_mem_alloc(c, false, GFP_KERNEL))) {
		btree_node_bufs_free(&bufs);
		return NULL;
	}

	b->data		= bufs.data;
	b->aux_data	= bufs.aux_data;
	return b;
}

/* Pinning */

static inline bool __btree_node_pinned(struct bch_fs_btree_cache *bc, struct btree *b)
{
	struct bbpos pos = BBPOS(b->c.btree_id, b->key.k.p);

	u64 mask = bc->pinned_nodes_mask[!!b->c.level];

	return ((mask & BIT_ULL(b->c.btree_id)) &&
		bbpos_cmp(bc->pinned_nodes_start, pos) < 0 &&
		bbpos_cmp(bc->pinned_nodes_end, pos) >= 0);
}

void bch2_node_pin(struct bch_fs *c, struct btree *b)
{
	struct bch_fs_btree_cache *bc = &c->btree.cache;

	guard(mutex)(&bc->lock);
	if (!btree_node_is_root(c, b) && !btree_node_pinned(b)) {
		set_btree_node_pinned(b);

		switch (b->cache_state) {
		case BTREE_NODE_CACHE_CLEAN:
			--bc->live[0].nr_clean;
			++bc->live[1].nr_clean;
			list_move_tail(&b->list, &bc->live[1].clean);
			break;
		case BTREE_NODE_CACHE_DIRTY:
			--bc->live[0].nr_dirty;
			++bc->live[1].nr_dirty;
			list_move_tail(&b->list, &bc->live[1].dirty);
			break;
		default:
			break;
		}
	}
}

void bch2_btree_cache_unpin(struct bch_fs *c)
{
	struct bch_fs_btree_cache *bc = &c->btree.cache;
	struct btree *b, *n;

	guard(mutex)(&bc->lock);
	bc->pinned_nodes_mask[0] = 0;
	bc->pinned_nodes_mask[1] = 0;

	list_for_each_entry_safe(b, n, &bc->live[1].clean, list)
		clear_btree_node_pinned(b);
	list_for_each_entry_safe(b, n, &bc->live[1].dirty, list)
		clear_btree_node_pinned(b);

	list_splice_tail_init(&bc->live[1].clean, &bc->live[0].clean);
	list_splice_tail_init(&bc->live[1].dirty, &bc->live[0].dirty);

	bc->live[0].nr_clean += bc->live[1].nr_clean;
	bc->live[0].nr_dirty += bc->live[1].nr_dirty;
	bc->live[1].nr_clean = 0;
	bc->live[1].nr_dirty = 0;
}

/* Cache state transitions — see DOC at top of file. */

static inline bool btree_node_state_hashed(enum btree_node_cache_state state)
{
	return state == BTREE_NODE_CACHE_CLEAN ||
	       state == BTREE_NODE_CACHE_DIRTY;
}

static inline bool btree_node_state_has_buffer(enum btree_node_cache_state state)
{
	return btree_node_state_hashed(state) ||
	       state == BTREE_NODE_CACHE_FREEABLE;
}

int bch2_btree_node_transition_state_locked(struct bch_fs_btree_cache *bc, struct btree *b,
					    enum btree_node_cache_state new)
{
	enum btree_node_cache_state old = b->cache_state;
	bool pinned = btree_node_pinned(b);
	int ret = 0;

	lockdep_assert_held(&bc->lock);
	/*
	 * Write lock required for transitions that touch the data buffer or
	 * hash table; CLEAN↔DIRTY swap only moves the node between live[]
	 * lists and is safe under bc->lock alone.
	 */
	EBUG_ON((!btree_node_state_hashed(old) || !btree_node_state_hashed(new)) &&
		!six_lock_counts(&b->c.lock).n[SIX_LOCK_write]);
	BUG_ON((btree_node_state_has_buffer(old) ||
		btree_node_state_has_buffer(new)) &&
	       !b->data);
	/*
	 * BTREE_NODE_dirty is meaningful only while a node is hashed (CLEAN /
	 * DIRTY); once unhashed (FREEABLE / FREED) it must already be clear.
	 * The dirty bit is what makes the cache_state DIRTY, so a FREEABLE
	 * node with the bit set is an inconsistent state — and consumers that
	 * need to scrub dirty nodes can rely on walking only live[].dirty.
	 */
	EBUG_ON(!btree_node_state_hashed(new) && btree_node_dirty(b));

	if (old == new)
		return 0;

	int hashed_delta = btree_node_state_hashed(new) - btree_node_state_hashed(old);
	if (hashed_delta > 0) {
		pinned = __btree_node_pinned(bc, b);
		mod_bit(BTREE_NODE_pinned, &b->flags, pinned);

		b->hash_val = btree_ptr_hash_val(&b->key);
		ret = rhashtable_lookup_insert_fast(&bc->table, &b->hash, bch_btree_cache_params);
		if (ret) {
			b->hash_val = 0;
			new = BTREE_NODE_CACHE_FREEABLE;
		} else {
			bc->nr_vmalloc += is_vmalloc_addr(b->data);
			if (b->c.btree_id < BTREE_ID_NR)
				++bc->nr_by_btree[b->c.btree_id];
		}
	}
	if (hashed_delta < 0) {
		BUG_ON(rhashtable_remove_fast(&bc->table, &b->hash, bch_btree_cache_params));
		b->hash_val = 0;
		clear_btree_node_just_written(b);

		if (b->c.btree_id < BTREE_ID_NR)
			--bc->nr_by_btree[b->c.btree_id];
		bc->nr_vmalloc -= is_vmalloc_addr(b->data);
	}

	/* Undo current state's bookkeeping. */
	switch (b->cache_state) {
	case BTREE_NODE_CACHE_CLEAN:
		--bc->live[pinned].nr_clean;
		break;
	case BTREE_NODE_CACHE_DIRTY:
		--bc->live[pinned].nr_dirty;
		break;
	case BTREE_NODE_CACHE_FREEABLE:
		--bc->nr_freeable;
		break;
	case BTREE_NODE_CACHE_FREED:
	case BTREE_NODE_CACHE_NONE:
		break;
	}

	list_del_init(&b->list);

	/* Attach to target state. */
	switch (new) {
	case BTREE_NODE_CACHE_NONE:
		break;
	case BTREE_NODE_CACHE_CLEAN:
		bc->live[pinned].nr_clean++;
		list_add_tail(&b->list, &bc->live[pinned].clean);
		break;
	case BTREE_NODE_CACHE_DIRTY:
		bc->live[pinned].nr_dirty++;
		list_add_tail(&b->list, &bc->live[pinned].dirty);
		break;
	case BTREE_NODE_CACHE_FREEABLE:
		BUG_ON(!b->data);
		bc->nr_freeable++;
		list_add(&b->list, &bc->freeable);
		break;
	case BTREE_NODE_CACHE_FREED:
		bch2_btree_node_data_free(b);
		list_add(&b->list, b->c.lock.readers
				 ? &bc->freed_pcpu
				 : &bc->freed_nonpcpu);
		break;
	}

	b->cache_state = new;
	return ret;
}

/*
 * Mark a btree node dirty: set the flag and, if the node is already
 * hashed, transition cache_state CLEAN → DIRTY. For nodes that aren't
 * yet hashed (e.g. fresh alloc out of prealloc_nodes — set_dirty fires
 * before hash insert there), only the flag is set; the eventual
 * hash-insert transition picks DIRTY via btree_node_live_state(b).
 *
 * Caller holds write lock on @b (commit / new-alloc path).
 * Idempotent if @b is already dirty.
 */
void bch2_btree_node_set_dirty(struct bch_fs *c, struct btree *b)
{
	struct bch_fs_btree_cache *bc = &c->btree.cache;

	guard(mutex)(&bc->lock);
	if (test_and_set_bit(BTREE_NODE_dirty, &b->flags))
		return;
	if (btree_node_state_hashed(b->cache_state))
		bch2_btree_node_transition_state_locked(bc, b, BTREE_NODE_CACHE_DIRTY);
}

/*
 * Settle a hashed node's cache_state from its current flag bits. Called from
 * the !rearm branch of __btree_node_write_done after the cmpxchg has cleared
 * write_in_flight; if the dirty bit is also clear the node moves to CLEAN,
 * otherwise btree_node_live_state returns DIRTY and the transition is a
 * no-op.
 *
 * Skipped when the node isn't in a hashed state — e.g. a node can sit on the
 * freeable list with a write still in flight, and we don't want to drag it
 * back into the live lists.
 */
void bch2_btree_node_write_done_clean(struct bch_fs *c, struct btree *b)
{
	struct bch_fs_btree_cache *bc = &c->btree.cache;

	guard(mutex)(&bc->lock);
	if (btree_node_state_hashed(b->cache_state))
		bch2_btree_node_transition_state_locked(bc, b, btree_node_live_state(b));
}

int bch2_btree_node_transition_state(struct bch_fs_btree_cache *bc, struct btree *b,
					      enum btree_node_cache_state target)
{
	guard(mutex)(&bc->lock);
	return bch2_btree_node_transition_state_locked(bc, b, target);
}

void bch2_btree_node_update_key_early(struct btree_trans *trans,
				      enum btree_id btree, unsigned level,
				      struct bkey_s_c old, struct bkey_i *new)
{
	struct bch_fs_btree_cache *bc = &trans->c->btree.cache;
	struct btree *b;
	struct bkey_buf tmp __cleanup(bch2_bkey_buf_exit);

	bch2_bkey_buf_init(&tmp);
	bch2_bkey_buf_reassemble(&tmp, old);

	b = bch2_btree_node_get_noiter(trans, tmp.k, btree, level, true);
	if (!IS_ERR_OR_NULL(b)) {
		/* unhash, rehash */
		BUG_ON(bch2_btree_node_transition_state(bc, b, BTREE_NODE_CACHE_FREEABLE));
		bkey_copy(&b->key, new);
		BUG_ON(bch2_btree_node_transition_state(bc, b, btree_node_live_state(b)));

		six_unlock_read(&b->c.lock);
	}
}

__flatten
static inline struct btree *btree_cache_find(struct bch_fs_btree_cache *bc,
					     const struct bkey_i *k)
{
	u64 v = btree_ptr_hash_val(k);

	return rhashtable_lookup_fast(&bc->table, &v, bch_btree_cache_params);
}

/* Reclaim and shrinker */

static inline size_t btree_cache_can_free(struct btree_cache_list *list)
{
	struct bch_fs_btree_cache *bc =
		container_of(list, struct bch_fs_btree_cache, live[list->idx]);

	size_t can_free = list->nr_clean;
	if (!list->idx)
		can_free = max_t(ssize_t, 0, can_free - bc->nr_reserve);
	return can_free;
}

static int __btree_node_reclaim_checks(struct bch_fs *c, struct btree *b,
				       bool flush, bool locked)
{
	struct bch_fs_btree_cache *bc = &c->btree.cache;

	lockdep_assert_held(&bc->lock);

	if (btree_node_permanent(b)) {
		bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_permanent]++;
		return bch_err_throw(c, ENOMEM_btree_node_reclaim);
	}
	if (btree_node_noevict(b)) {
		bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_noevict]++;
		return bch_err_throw(c, ENOMEM_btree_node_reclaim);
	}
	if (btree_node_write_blocked(b)) {
		bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_write_blocked]++;
		return bch_err_throw(c, ENOMEM_btree_node_reclaim);
	}
	if (btree_node_will_make_reachable(b)) {
		bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_will_make_reachable]++;
		return bch_err_throw(c, ENOMEM_btree_node_reclaim);
	}

	if (btree_node_dirty(b)) {
		if (!flush) {
			bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_dirty]++;
			return bch_err_throw(c, ENOMEM_btree_node_reclaim);
		}

		if (locked) {
			/*
			 * Don't compact bsets after the write — this node is
			 * about to be evicted.
			 */
			__bch2_btree_node_write(c, b, BTREE_WRITE_cache_reclaim);
		}
	}

	if (b->flags & ((1U << BTREE_NODE_read_in_flight)|
			(1U << BTREE_NODE_write_in_flight))) {
		if (!flush) {
			if (btree_node_read_in_flight(b))
				bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_read_in_flight]++;
			else if (btree_node_write_in_flight(b))
				bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_write_in_flight]++;
			return bch_err_throw(c, ENOMEM_btree_node_reclaim);
		}

		if (locked)
			return -EINTR;

		/* XXX: waiting on IO with btree cache lock held */
		bch2_btree_node_wait_on_read(b);
		bch2_btree_node_wait_on_write(b);
	}

	return 0;
}

/*
 * this version is for btree nodes that have already been freed (we're not
 * reaping a real btree node)
 */
static int __btree_node_reclaim(struct bch_fs *c, struct btree *b, bool flush)
{
	struct bch_fs_btree_cache *bc = &c->btree.cache;
	int ret = 0;

	lockdep_assert_held(&bc->lock);

	while (true) {
		try(__btree_node_reclaim_checks(c, b, flush, false));

		if (!six_trylock_intent(&b->c.lock)) {
			bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_lock_intent]++;
			return bch_err_throw(c, ENOMEM_btree_node_reclaim);
		}

		if (!six_trylock_write(&b->c.lock)) {
			bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_lock_write]++;
			six_unlock_intent(&b->c.lock);
			return bch_err_throw(c, ENOMEM_btree_node_reclaim);
		}

		/* recheck under lock */
		ret = __btree_node_reclaim_checks(c, b, flush, true);
		if (ret) {
			six_unlock_write(&b->c.lock);
			six_unlock_intent(&b->c.lock);
			if (ret == -EINTR)
				continue;
			return ret;
		}

		break;
	}

	if (b->hash_val && !ret)
		trace_btree_node(c, b, btree_cache_reap);

	return 0;
}

static int btree_node_reclaim(struct bch_fs *c, struct btree *b)
{
	return __btree_node_reclaim(c, b, false);
}

static int btree_node_write_and_reclaim(struct bch_fs *c, struct btree *b)
{
	return __btree_node_reclaim(c, b, true);
}

static unsigned long bch2_btree_cache_scan(struct shrinker *shrink,
					   struct shrink_control *sc)
{
	struct btree_cache_list *list = shrink->private_data;
	struct bch_fs_btree_cache *bc =
		container_of(list, struct bch_fs_btree_cache, live[list->idx]);
	struct bch_fs *c = container_of(bc, struct bch_fs, btree.cache);
	struct btree *b, *t;
	unsigned long nr = sc->nr_to_scan;
	unsigned long can_free = 0;
	unsigned long freed = 0;
	unsigned long touched = 0;
	unsigned i;
	unsigned long ret = SHRINK_STOP;

	if (static_branch_unlikely(&bch2_btree_shrinker_disabled))
		return SHRINK_STOP;

	u64 start_time = local_clock();
	mutex_lock(&bc->lock);
	guard(memalloc_flags)(PF_MEMALLOC_NOFS);

	bool trigger_writes = bc->live[0].nr_dirty + bc->live[1].nr_dirty + nr >=
		btree_cache_list_nr(list) * 3 / 4;

	/*
	 * It's _really_ critical that we don't free too many btree nodes - we
	 * have to always leave ourselves a reserve. The reserve is how we
	 * guarantee that allocating memory for a new btree node can always
	 * succeed, so that inserting keys into the btree can always succeed and
	 * IO can always make forward progress:
	 */
	can_free = btree_cache_can_free(list);
	if (nr > can_free) {
		bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_cache_reserve] += nr - can_free;
		nr = can_free;
	}

	i = 0;
	list_for_each_entry_safe(b, t, &bc->freeable, list) {
		/*
		 * Leave a few nodes on the freeable list, so that a btree split
		 * won't have to hit the system allocator:
		 */
		if (++i <= 3)
			continue;

		touched++;

		if (touched >= nr)
			goto out;

		if (!btree_node_reclaim(c, b)) {
			bch2_btree_node_transition_state_locked(bc, b, BTREE_NODE_CACHE_FREED);
			six_unlock_write(&b->c.lock);
			six_unlock_intent(&b->c.lock);
			freed++;
			bc->nr_freed++;
		}
	}
	list_for_each_entry_safe(b, t, &list->clean, list) {
		touched++;

		if (btree_node_accessed(b)) {
			clear_btree_node_accessed(b);
			bc->not_freed[BCH_BTREE_CACHE_NOT_FREED_access_bit]++;
			--touched;
		} else if (!btree_node_reclaim(c, b)) {
			bch2_btree_node_transition_state_locked(bc, b, BTREE_NODE_CACHE_FREED);

			freed++;
			bc->nr_freed++;

			six_unlock_write(&b->c.lock);
			six_unlock_intent(&b->c.lock);

			if (freed == nr)
				goto out_rotate;
		}

		if (touched >= nr)
			break;
	}
out_rotate:
	if (&t->list != &list->clean)
		list_move_tail(&list->clean, &t->list);

	/*
	 * Writeout-kick pass: under enough dirty pressure, walk the dirty
	 * list and kick writes for nodes that aren't blocked. The writes
	 * complete asynchronously and free the cache slots on a future
	 * scan.
	 */
	if (trigger_writes) {
restart_dirty:
		list_for_each_entry_safe(b, t, &list->dirty, list) {
			if (touched >= nr)
				break;

			if (!btree_node_dirty(b) ||
			    btree_node_will_make_reachable(b) ||
			    btree_node_write_blocked(b))
				continue;

			if (!six_trylock_read(&b->c.lock))
				continue;

			touched++;
			list_move_tail(&b->list, &list->dirty);
			mutex_unlock(&bc->lock);
			__bch2_btree_node_write(c, b, BTREE_WRITE_cache_reclaim);
			six_unlock_read(&b->c.lock);
			if (touched >= nr)
				goto out_nounlock;
			mutex_lock(&bc->lock);
			goto restart_dirty;
		}
	}
out:
	mutex_unlock(&bc->lock);
out_nounlock:
	bch2_time_stats_update(&c->times[BCH_TIME_btree_node_cache_scan], start_time);
	ret = freed;

	event_inc_trace(c, btree_cache_scan, buf,
		prt_printf(&buf, "scanned %li nodes, can free %li, ret %li",
			   sc->nr_to_scan, can_free, ret));
	return ret;
}

static unsigned long bch2_btree_cache_count(struct shrinker *shrink,
					    struct shrink_control *sc)
{
	struct btree_cache_list *list = shrink->private_data;

	if (static_branch_unlikely(&bch2_btree_shrinker_disabled))
		return 0;

	return btree_cache_can_free(list);
}

/*
 * We can only have one thread cannibalizing other cached btree nodes at a time,
 * or we'll deadlock. We use an open coded mutex to ensure that, which a
 * cannibalize_bucket() will take. This means every time we unlock the root of
 * the btree, we need to release this lock if we have it held.
 */
void bch2_btree_cache_cannibalize_unlock(struct btree_trans *trans)
{
	struct bch_fs_btree_cache *bc = &trans->c->btree.cache;

	if (bc->alloc_lock == current) {
		event_inc_trace(trans->c, btree_cache_cannibalize_unlock, buf,
			prt_str(&buf, trans->fn));
		bc->alloc_lock = NULL;
		closure_wake_up(&bc->alloc_wait);
	}
}

static int __btree_cache_cannibalize_lock(struct bch_fs *c, struct closure *cl)
{
	struct bch_fs_btree_cache *bc = &c->btree.cache;
	struct task_struct *old;

	old = NULL;
	if (try_cmpxchg(&bc->alloc_lock, &old, current) || old == current)
		return 0;

	if (!cl)
		return bch_err_throw(c, ENOMEM_btree_cache_cannibalize_lock);

	closure_wait(&bc->alloc_wait, cl);

	/* Try again, after adding ourselves to waitlist */
	old = NULL;
	if (try_cmpxchg(&bc->alloc_lock, &old, current) || old == current) {
		/* We raced */
		closure_wake_up(&bc->alloc_wait);
		return 0;
	}

	return bch_err_throw(c, btree_cache_cannibalize_lock_blocked);
}

int bch2_btree_cache_cannibalize_lock(struct btree_trans *trans, struct closure *cl)
{
	struct bch_fs *c = trans->c;
	int ret = __btree_cache_cannibalize_lock(c, cl);
	if (!ret)
		event_inc_trace(c, btree_cache_cannibalize_lock, buf, prt_str(&buf, trans->fn));
	else
		event_inc_trace(c, btree_cache_cannibalize_lock_fail, buf, prt_str(&buf, trans->fn));
	return ret;
}

/* Btree node alloc / lookup / evict */

static struct btree *bch2_btree_node_grab(struct bch_fs *c, struct list_head *head, bool pcpu_read_locks)
{
	struct bch_fs_btree_cache *bc = &c->btree.cache;
	guard(mutex)(&bc->lock);
	struct btree *b;
	list_for_each_entry(b, head, list)
		if (pcpu_read_locks == (b->c.lock.readers != NULL) &&
		    !btree_node_reclaim(c, b)) {
			bch2_btree_node_transition_state_locked(bc, b, BTREE_NODE_CACHE_NONE);
			return b;
		}

	return NULL;
}

static struct btree *btree_node_cannibalize(struct bch_fs *c, bool pcpu_read_locks)
{
	struct bch_fs_btree_cache *bc = &c->btree.cache;
	struct btree *b;

	for (unsigned i = 0; i < ARRAY_SIZE(bc->live); i++) {
		b = bch2_btree_node_grab(c, &bc->live[i].clean, pcpu_read_locks);
		if (b)
			return b;
	}

	while (1) {
		scoped_guard(mutex, &bc->lock)
			for (unsigned i = 0; i < ARRAY_SIZE(bc->live); i++) {
				struct list_head *heads[] = {
					&bc->live[i].dirty,
					&bc->live[i].clean,
				};
				for (unsigned j = 0; j < ARRAY_SIZE(heads); j++)
					list_for_each_entry_reverse(b, heads[j], list)
						if (pcpu_read_locks == !!b->c.lock.readers &&
						    !btree_node_write_and_reclaim(c, b)) {
							bch2_btree_node_transition_state_locked(bc, b, BTREE_NODE_CACHE_NONE);
							return b;
						}
			}

		/*
		 * Rare case: all matching-type nodes were intent-locked.
		 * Just busy-wait.
		 */
		WARN_ONCE(1, "btree cache cannibalize failed\n");
		cond_resched();
	}
}

struct btree *bch2_btree_node_mem_alloc(struct btree_trans *trans, bool pcpu_read_locks)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_btree_cache *bc = &c->btree.cache;
	struct list_head *freed = pcpu_read_locks
		? &bc->freed_pcpu
		: &bc->freed_nonpcpu;
	u64 start_time = local_clock();

	struct btree *b = bch2_btree_node_grab(c, &bc->freeable, pcpu_read_locks);
	if (b)
		goto got_mem;

	struct btree_node_bufs bufs = { .byte_order = ilog2(c->opts.btree_node_size) };
	if (__btree_node_data_alloc(c, &bufs, GFP_NOWAIT, true)) {
		bch2_trans_unlock(trans);
		if (__btree_node_data_alloc(c, &bufs, GFP_KERNEL|__GFP_NOWARN, true)) {
			btree_node_bufs_free(&bufs);
			goto err;
		}
	}

	b = bch2_btree_node_grab(c, freed, pcpu_read_locks);
	if (!b) {
		b = __btree_node_mem_alloc(c, pcpu_read_locks, GFP_NOWAIT);
		if (!b) {
			bch2_trans_unlock(trans);
			b = __btree_node_mem_alloc(c, pcpu_read_locks, GFP_KERNEL);
			if (!b) {
				btree_node_bufs_free(&bufs);
				goto err;
			}
		}

		BUG_ON(!six_trylock_intent(&b->c.lock));
		BUG_ON(!six_trylock_write(&b->c.lock));
	}

	b->data			= bufs.data;
	b->aux_data		= bufs.aux_data;
got_mem:
	BUG_ON(!list_empty(&b->list));
	BUG_ON(btree_node_hashed(b));
	BUG_ON(btree_node_dirty(b));
	BUG_ON(btree_node_write_in_flight(b));
	BUG_ON(!b->data);

	b->flags		= 0;
	b->written		= 0;
	b->nsets		= 0;
	b->sib_u64s[0]		= 0;
	b->sib_u64s[1]		= 0;
	b->whiteout_u64s	= 0;
	bch2_btree_keys_init(b);

	bch2_time_stats_update(&c->times[BCH_TIME_btree_node_mem_alloc],
			       start_time);

	int ret = bch2_trans_relock(trans);
	if (unlikely(ret)) {
		bch2_btree_node_transition_state(bc, b, BTREE_NODE_CACHE_FREEABLE);
		six_unlock_write(&b->c.lock);
		six_unlock_intent(&b->c.lock);
		return ERR_PTR(ret);
	}

	return b;
err:
	/* Try to cannibalize another cached btree node: */
	if (bc->alloc_lock == current &&
	    (b = btree_node_cannibalize(c, pcpu_read_locks))) {
		event_inc_trace(c, btree_cache_cannibalize, buf, prt_str(&buf, trans->fn));
		goto got_mem;
	}

	return ERR_PTR(-BCH_ERR_ENOMEM_btree_node_mem_alloc);
}

/* Slowpath, don't want it inlined into btree_iter_traverse() */
static noinline struct btree *bch2_btree_node_fill(struct btree_trans *trans,
				struct btree_path *path,
				const struct bkey_i *k,
				enum btree_id btree_id,
				unsigned level,
				enum six_lock_type lock_type,
				bool sync)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_btree_cache *bc = &c->btree.cache;
	struct btree *b;

	EBUG_ON(path && level + 1 != path->level);

	if (unlikely(level >= BTREE_MAX_DEPTH)) {
		int ret = bch2_fs_topology_error(c, "attempting to get btree node at level %u, >= max depth %u",
						 level, BTREE_MAX_DEPTH);
		return ERR_PTR(ret);
	}

	if (unlikely(!bkey_is_btree_ptr(&k->k))) {
		CLASS(printbuf, buf)();
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(k));

		int ret = bch2_fs_topology_error(c, "attempting to get btree node with non-btree key %s", buf.buf);
		return ERR_PTR(ret);
	}

	if (unlikely(k->k.u64s > BKEY_BTREE_PTR_U64s_MAX)) {
		CLASS(printbuf, buf)();
		bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(k));

		int ret = bch2_fs_topology_error(c, "attempting to get btree node with too big key %s", buf.buf);
		return ERR_PTR(ret);
	}

	/*
	 * Parent node must be locked, else we could read in a btree node that's
	 * been freed:
	 */
	if (path) {
		int ret = bch2_btree_path_relock(trans, path, _THIS_IP_);
		if (ret)
			return ERR_PTR(ret);
	}

	b = bch2_btree_node_mem_alloc(trans, level != 0);

	if (bch2_err_matches(PTR_ERR_OR_ZERO(b), ENOMEM)) {
		if (!path)
			return b;

		trans->memory_allocation_failure = true;

		event_inc_trace(c, trans_restart_memory_allocation_failure, buf, ({
			prt_printf(&buf, "%s\n", trans->fn);
			bch2_btree_path_to_text(&buf, trans, path - trans->paths, path);
		}));
		return ERR_PTR(btree_trans_restart(trans, BCH_ERR_transaction_restart_fill_mem_alloc_fail));
	}

	if (IS_ERR(b))
		return b;

	bkey_copy(&b->key, k);
	b->c.level	= level;
	b->c.btree_id	= btree_id;
	if (!bch2_btree_node_transition_state(bc, b, BTREE_NODE_CACHE_CLEAN)) {
		set_btree_node_read_in_flight(b);
		six_unlock_write(&b->c.lock);

		if (path) {
			u32 seq = six_lock_seq(&b->c.lock);

			/* Unlock before doing IO: */
			six_unlock_intent(&b->c.lock);
			bch2_trans_unlock(trans);

			bch2_btree_node_read(trans, b, sync);

			if (!sync)
				b = NULL;
			else if (!six_relock_type(&b->c.lock, lock_type, seq))
				b = NULL;
		} else {
			bch2_btree_node_read(trans, b, sync);
			if (lock_type == SIX_LOCK_read)
				six_lock_downgrade(&b->c.lock);
		}
	} else {
		/* raced with another fill: */
		six_unlock_write(&b->c.lock);
		six_unlock_intent(&b->c.lock);
		b = NULL;
	}
	/*
	 * bch2_btree_node_mem_alloc may have unlocked the trans for GFP_KERNEL
	 * allocation, and the if (path) { } block above unlocks for IO - ensure
	 * we're relocked before returning:
	 */
	if (path) {
		int ret = bch2_trans_relock(trans) ?:
			  bch2_btree_path_relock(trans, path, _THIS_IP_);
		if (ret) {
			if (b)
				six_unlock_type(&b->c.lock, lock_type);
			return ERR_PTR(ret);
		}
	}

	return b;
}

static noinline void btree_bad_header(struct bch_fs *c, struct btree *b)
{
	if (c->recovery.pass_done < BCH_RECOVERY_PASS_check_allocations)
		return;

	CLASS(printbuf, buf)();
	prt_printf(&buf,
		   "cached btree node header doesn't match expected (memory corruption?)\n"
		   "expected: ");
	bch2_btree_id_level_to_text(&buf, b->c.btree_id, b->c.level);
	prt_str(&buf, "\nptr: ");
	bch2_bkey_val_to_text(&buf, c, bkey_i_to_s_c(&b->key));

	prt_str(&buf, "\ngot: ");
	bch2_btree_id_level_to_text(&buf, BTREE_NODE_ID(b->data), BTREE_NODE_LEVEL(b->data));
	prt_str(&buf, "\nmin ");
	bch2_bpos_to_text(&buf, b->data->min_key);

	prt_printf(&buf, "\nmax ");
	bch2_bpos_to_text(&buf, b->data->max_key);

	bch2_fs_topology_error(c, "%s", buf.buf);
}

static inline void btree_check_header(struct bch_fs *c, struct btree *b)
{
	if (b->c.btree_id != BTREE_NODE_ID(b->data) ||
	    b->c.level != BTREE_NODE_LEVEL(b->data) ||
	    !bpos_eq(b->data->max_key, b->key.k.p) ||
	    (b->key.k.type == KEY_TYPE_btree_ptr_v2 &&
	     !bpos_eq(b->data->min_key,
		      bkey_i_to_btree_ptr_v2(&b->key)->v.min_key)))
		btree_bad_header(c, b);
}

static struct btree *__bch2_btree_node_get(struct btree_trans *trans, struct btree_path *path,
					   const struct bkey_i *k, unsigned level,
					   enum six_lock_type lock_type,
					   unsigned long trace_ip)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_btree_cache *bc = &c->btree.cache;
	struct btree *b;
	int ret;

	EBUG_ON(level >= BTREE_MAX_DEPTH);
retry:
	b = btree_cache_find(bc, k);
	if (unlikely(!b)) {
		/*
		 * We must have the parent locked to call bch2_btree_node_fill(),
		 * else we could read in a btree node from disk that's been
		 * freed:
		 */
		b = bch2_btree_node_fill(trans, path, k, path->btree_id,
					 level, lock_type, true);

		/* We raced and found the btree node in the cache */
		if (!b)
			goto retry;

		if (IS_ERR(b))
			return b;
	} else {
		if (btree_node_read_locked(path, level + 1))
			btree_node_unlock(trans, path, level + 1);

		ret = btree_node_lock(trans, path, &b->c, level, lock_type, trace_ip);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			return ERR_PTR(ret);

		BUG_ON(ret);

		if (unlikely(b->hash_val != btree_ptr_hash_val(k) ||
			     b->c.level != level ||
			     race_fault())) {
			six_unlock_type(&b->c.lock, lock_type);
			if (bch2_btree_node_relock(trans, path, level + 1))
				goto retry;

			event_inc_trace(c, trans_restart_btree_node_reused, buf, ({
				prt_printf(&buf, "%s\n", trans->fn);
				bch2_btree_path_to_text(&buf, trans, path - trans->paths, path);
			}));
			return ERR_PTR(btree_trans_restart(trans, BCH_ERR_transaction_restart_lock_node_reused));
		}

		/* avoid atomic set bit if it's not needed: */
		if (!btree_node_accessed(b))
			set_btree_node_accessed(b);
	}

	if (unlikely(btree_node_read_in_flight(b))) {
		u32 seq = six_lock_seq(&b->c.lock);

		six_unlock_type(&b->c.lock, lock_type);
		bch2_trans_unlock(trans);

		bch2_btree_node_wait_on_read(b);

		ret =   bch2_trans_relock(trans) ?:
			bch2_btree_path_relock(trans, path, _THIS_IP_);
		if (ret)
			return ERR_PTR(ret);

		/*
		 * should_be_locked is not set on this path yet, so we need to
		 * relock it specifically:
		 */
		if (!six_relock_type(&b->c.lock, lock_type, seq))
			goto retry;
	}

	prefetch(b->aux_data);

	for_each_bset(b, t) {
		void *p = (u64 *) b->aux_data + t->aux_data_offset;

		prefetch(p + L1_CACHE_BYTES * 0);
		prefetch(p + L1_CACHE_BYTES * 1);
		prefetch(p + L1_CACHE_BYTES * 2);
	}

	if (unlikely(btree_node_read_error(b))) {
		six_unlock_type(&b->c.lock, lock_type);
		return ERR_PTR(-BCH_ERR_btree_node_read_err_cached);
	}

	EBUG_ON(b->c.btree_id != path->btree_id);
	EBUG_ON(BTREE_NODE_LEVEL(b->data) != level);
	btree_check_header(c, b);

	return b;
}

/**
 * bch2_btree_node_get - find a btree node in the cache and lock it, reading it
 * in from disk if necessary.
 *
 * @trans:	btree transaction object
 * @path:	btree_path being traversed
 * @k:		pointer to btree node (generally KEY_TYPE_btree_ptr_v2)
 * @level:	level of btree node being looked up (0 == leaf node)
 * @lock_type:	SIX_LOCK_read or SIX_LOCK_intent
 * @trace_ip:	ip of caller of btree iterator code (i.e. caller of bch2_btree_iter_peek())
 *
 * The btree node will have either a read or a write lock held, depending on
 * the @write parameter.
 *
 * Returns: btree node or ERR_PTR()
 */
struct btree *bch2_btree_node_get(struct btree_trans *trans, struct btree_path *path,
				  const struct bkey_i *k, unsigned level,
				  enum six_lock_type lock_type,
				  unsigned long trace_ip)
{
	struct bch_fs *c = trans->c;
	struct btree *b;
	int ret;

	EBUG_ON(level >= BTREE_MAX_DEPTH);
	EBUG_ON(level + 1 != path->level);

	b = btree_node_mem_ptr(k);

	/*
	 * Check b->hash_val _before_ calling btree_node_lock() - this might not
	 * be the node we want anymore, and trying to lock the wrong node could
	 * cause an unneccessary transaction restart:
	 */
	if (unlikely(!c->opts.btree_node_mem_ptr_optimization ||
		     !b ||
		     b->hash_val != btree_ptr_hash_val(k)))
		return __bch2_btree_node_get(trans, path, k, level, lock_type, trace_ip);

	if (btree_node_read_locked(path, level + 1))
		btree_node_unlock(trans, path, level + 1);

	ret = btree_node_lock(trans, path, &b->c, level, lock_type, trace_ip);
	if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
		return ERR_PTR(ret);

	BUG_ON(ret);

	if (unlikely(b->hash_val != btree_ptr_hash_val(k) ||
		     b->c.level != level ||
		     race_fault())) {
		six_unlock_type(&b->c.lock, lock_type);
		if (bch2_btree_node_relock(trans, path, level + 1))
			return __bch2_btree_node_get(trans, path, k, level, lock_type, trace_ip);

		event_inc_trace(c, trans_restart_btree_node_reused, buf, ({
			prt_printf(&buf, "%s\n", trans->fn);
			bch2_btree_path_to_text(&buf, trans, path - trans->paths, path);
		}));
		return ERR_PTR(btree_trans_restart(trans, BCH_ERR_transaction_restart_lock_node_reused));
	}

	if (unlikely(btree_node_read_in_flight(b))) {
		six_unlock_type(&b->c.lock, lock_type);
		return __bch2_btree_node_get(trans, path, k, level, lock_type, trace_ip);
	}

	prefetch(b->aux_data);

	for_each_bset(b, t) {
		void *p = (u64 *) b->aux_data + t->aux_data_offset;

		prefetch(p + L1_CACHE_BYTES * 0);
		prefetch(p + L1_CACHE_BYTES * 1);
		prefetch(p + L1_CACHE_BYTES * 2);
	}

	/* avoid atomic set bit if it's not needed: */
	if (!btree_node_accessed(b))
		set_btree_node_accessed(b);

	if (unlikely(btree_node_read_error(b))) {
		six_unlock_type(&b->c.lock, lock_type);
		return ERR_PTR(-BCH_ERR_btree_node_read_err_cached);
	}

	EBUG_ON(b->c.btree_id != path->btree_id);
	EBUG_ON(BTREE_NODE_LEVEL(b->data) != level);
	btree_check_header(c, b);

	return b;
}

struct btree *bch2_btree_node_get_noiter(struct btree_trans *trans,
					 const struct bkey_i *k,
					 enum btree_id btree_id,
					 unsigned level,
					 bool nofill)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_btree_cache *bc = &c->btree.cache;
	struct btree *b;
	int ret;

	EBUG_ON(level >= BTREE_MAX_DEPTH);

	if (c->opts.btree_node_mem_ptr_optimization) {
		b = btree_node_mem_ptr(k);
		if (b)
			goto lock_node;
	}
retry:
	b = btree_cache_find(bc, k);
	if (unlikely(!b)) {
		if (nofill)
			goto out;

		b = bch2_btree_node_fill(trans, NULL, k, btree_id,
					 level, SIX_LOCK_read, true);

		/* We raced and found the btree node in the cache */
		if (!b)
			goto retry;

		if (IS_ERR(b) &&
		    !bch2_btree_cache_cannibalize_lock(trans, NULL))
			goto retry;

		if (IS_ERR(b))
			goto out;
	} else {
lock_node:
		ret = btree_node_lock_nopath(trans, &b->c, SIX_LOCK_read, _THIS_IP_);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart)) {
			b = ERR_PTR(ret);
			goto out;
		}

		BUG_ON(ret);

		if (unlikely(b->hash_val != btree_ptr_hash_val(k) ||
			     b->c.btree_id != btree_id ||
			     b->c.level != level)) {
			six_unlock_read(&b->c.lock);
			goto retry;
		}

		/* avoid atomic set bit if it's not needed: */
		if (!btree_node_accessed(b))
			set_btree_node_accessed(b);
	}

	/* XXX: waiting on IO with btree locks held: */
	__bch2_btree_node_wait_on_read(b);

	prefetch(b->aux_data);

	for_each_bset(b, t) {
		void *p = (u64 *) b->aux_data + t->aux_data_offset;

		prefetch(p + L1_CACHE_BYTES * 0);
		prefetch(p + L1_CACHE_BYTES * 1);
		prefetch(p + L1_CACHE_BYTES * 2);
	}

	if (unlikely(btree_node_read_error(b))) {
		six_unlock_read(&b->c.lock);
		b = ERR_PTR(-BCH_ERR_btree_node_read_err_cached);
		goto out;
	}

	EBUG_ON(b->c.btree_id != btree_id);
	EBUG_ON(BTREE_NODE_LEVEL(b->data) != level);
	btree_check_header(c, b);
out:
	bch2_btree_cache_cannibalize_unlock(trans);
	return b;
}

int bch2_btree_node_prefetch(struct btree_trans *trans,
			     struct btree_path *path,
			     const struct bkey_i *k,
			     enum btree_id btree_id, unsigned level)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_btree_cache *bc = &c->btree.cache;

	BUG_ON(path && !btree_node_locked(path, level + 1));
	BUG_ON(level >= BTREE_MAX_DEPTH);

	struct btree *b = btree_cache_find(bc, k);
	if (b)
		return 0;

	b = errptr_try(bch2_btree_node_fill(trans, path, k, btree_id,
					    level, SIX_LOCK_read, false));
	if (b)
		six_unlock_read(&b->c.lock);
	return 0;
}

void bch2_btree_node_evict(struct btree_trans *trans, const struct bkey_i *k)
{
	struct bch_fs *c = trans->c;
	struct bch_fs_btree_cache *bc = &c->btree.cache;
	struct btree *b;

	b = btree_cache_find(bc, k);
	if (!b)
		return;

	BUG_ON(btree_node_permanent(b));
wait_on_io:
	/* not allowed to wait on io with btree locks held: */

	/* XXX we're called from btree_gc which will be holding other btree
	 * nodes locked
	 */
	__bch2_btree_node_wait_on_read(b);
	__bch2_btree_node_wait_on_write(b);

	btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_intent);
	btree_node_lock_nopath_nofail(trans, &b->c, SIX_LOCK_write);
	if (unlikely(b->hash_val != btree_ptr_hash_val(k)))
		goto out;

	if (btree_node_dirty(b)) {
		__bch2_btree_node_write(c, b, BTREE_WRITE_cache_reclaim);
		six_unlock_write(&b->c.lock);
		six_unlock_intent(&b->c.lock);
		goto wait_on_io;
	}

	BUG_ON(btree_node_dirty(b));

	bch2_btree_node_transition_state(bc, b, BTREE_NODE_CACHE_FREED);
out:
	six_unlock_write(&b->c.lock);
	six_unlock_intent(&b->c.lock);
}

/* Filesystem init / exit */

void bch2_fs_btree_cache_init_early(struct bch_fs_btree_cache *bc)
{
	mutex_init(&bc->root_lock);
	mutex_init(&bc->lock);
	for (unsigned i = 0; i < ARRAY_SIZE(bc->live); i++) {
		bc->live[i].idx = i;
		INIT_LIST_HEAD(&bc->live[i].clean);
		INIT_LIST_HEAD(&bc->live[i].dirty);
	}
	INIT_LIST_HEAD(&bc->freeable);
	INIT_LIST_HEAD(&bc->freed_pcpu);
	INIT_LIST_HEAD(&bc->freed_nonpcpu);
}

int bch2_fs_btree_cache_init(struct bch_fs *c)
{
	struct bch_fs_btree_cache *bc = &c->btree.cache;
	struct shrinker *shrink;

	if (rhashtable_init(&bc->table, &bch_btree_cache_params))
		return bch_err_throw(c, ENOMEM_fs_btree_cache_init);

	bc->table_init_done = true;

	bch2_recalc_btree_reserve(c);

	for (unsigned i = 0; i < bc->nr_reserve; i++) {
		struct btree *b = __bch2_btree_node_mem_alloc(c);
		if (!b)
			return bch_err_throw(c, ENOMEM_fs_btree_cache_init);

		BUG_ON(!six_trylock_intent(&b->c.lock));
		BUG_ON(!six_trylock_write(&b->c.lock));

		bch2_btree_node_transition_state(bc, b, BTREE_NODE_CACHE_FREEABLE);

		six_unlock_write(&b->c.lock);
		six_unlock_intent(&b->c.lock);
	}

	shrink = shrinker_alloc(0, "%s-btree_cache", c->name);
	if (!shrink)
		return bch_err_throw(c, ENOMEM_fs_btree_cache_init);
	bc->live[0].shrink	= shrink;
	shrink->count_objects	= bch2_btree_cache_count;
	shrink->scan_objects	= bch2_btree_cache_scan;
	shrink->seeks		= 2;
	shrink->private_data	= &bc->live[0];
	shrinker_register(shrink);

	shrink = shrinker_alloc(0, "%s-btree_cache-pinned", c->name);
	if (!shrink)
		return bch_err_throw(c, ENOMEM_fs_btree_cache_init);
	bc->live[1].shrink	= shrink;
	shrink->count_objects	= bch2_btree_cache_count;
	shrink->scan_objects	= bch2_btree_cache_scan;
	shrink->seeks		= 8;
	shrink->private_data	= &bc->live[1];
	shrinker_register(shrink);

	return 0;
}

void bch2_fs_btree_cache_exit(struct bch_fs *c)
{
	struct bch_fs_btree_cache *bc = &c->btree.cache;
	struct btree *b, *t;

	shrinker_free(bc->live[1].shrink);
	shrinker_free(bc->live[0].shrink);

	/*
	 * btree_node_write_work clears BTREE_NODE_write_in_flight before
	 * releasing its read lock on the node, so flush_all_writes returning
	 * doesn't guarantee the lock is unheld. Drain the workqueue so the
	 * walks below can rely on trylock succeeding without racing with
	 * still-finishing post-write work.
	 */
	if (c->btree.write_complete_wq)
		drain_workqueue(c->btree.write_complete_wq);

	/* vfree() can allocate memory: */
	scoped_guard(memalloc_flags, PF_MEMALLOC_NOFS) {
		guard(mutex)(&bc->lock);

		for (unsigned i = 0; i < ARRAY_SIZE(bc->live); i++) {
			struct list_head *heads[] = {
				&bc->live[i].dirty,
				&bc->live[i].clean,
			};
			for (unsigned j = 0; j < ARRAY_SIZE(heads); j++)
				list_for_each_entry_safe(b, t, heads[j], list) {
					BUG_ON(btree_node_read_in_flight(b) ||
					       btree_node_write_in_flight(b));
					BUG_ON(!six_trylock_intent(&b->c.lock));
					BUG_ON(!six_trylock_write(&b->c.lock));
					bch2_btree_node_transition_state_locked(bc, b, BTREE_NODE_CACHE_FREED);
					six_unlock_write(&b->c.lock);
					six_unlock_intent(&b->c.lock);
					cond_resched();
				}
		}

		list_for_each_entry_safe(b, t, &bc->freeable, list) {
			BUG_ON(btree_node_read_in_flight(b) ||
			       btree_node_write_in_flight(b));
			BUG_ON(!six_trylock_intent(&b->c.lock));
			BUG_ON(!six_trylock_write(&b->c.lock));
			bch2_btree_node_transition_state_locked(bc, b, BTREE_NODE_CACHE_FREED);
			six_unlock_write(&b->c.lock);
			six_unlock_intent(&b->c.lock);
			cond_resched();
		}

		BUG_ON(!bch2_journal_error(&c->journal) &&
		       (bc->live[0].nr_dirty || bc->live[1].nr_dirty));

		list_splice(&bc->freed_pcpu, &bc->freed_nonpcpu);

		list_for_each_entry_safe(b, t, &bc->freed_nonpcpu, list) {
			list_del_init(&b->list);
			bch2_btree_node_mem_free(c, b);
		}

		for (unsigned i = 0; i < ARRAY_SIZE(bc->nr_by_btree); i++)
			BUG_ON(bc->nr_by_btree[i]);
		WARN_ON(bc->live[0].nr_clean);
		WARN_ON(bc->live[0].nr_dirty);
		WARN_ON(bc->live[1].nr_clean);
		WARN_ON(bc->live[1].nr_dirty);
		WARN_ON(bc->nr_freeable);

		darray_exit(&bc->roots_extra);
	}

	if (bc->table_init_done)
		rhashtable_destroy(&bc->table);
}

/* Debug / text rendering */

const char *bch2_btree_id_str(enum btree_id btree)
{
	return btree < BTREE_ID_NR ? __bch2_btree_ids[btree] : "(unknown)";
}

void bch2_btree_id_to_text(struct printbuf *out, enum btree_id btree)
{
	if (btree < BTREE_ID_NR)
		prt_str(out, __bch2_btree_ids[btree]);
	else
		prt_printf(out, "(unknown btree %u)", btree);
}

void bch2_btree_id_level_to_text(struct printbuf *out, enum btree_id btree, unsigned level)
{
	prt_str(out, "btree=");
	bch2_btree_id_to_text(out, btree);
	prt_printf(out, " level=%u", level);
}

void __bch2_btree_pos_to_text(struct printbuf *out, struct bch_fs *c,
			      enum btree_id btree, unsigned level, struct bkey_s_c k)
{
	bch2_btree_id_to_text(out, btree);
	prt_printf(out, " level %u/", level);
	struct btree_root *r = bch2_btree_id_root(c, btree);
	if (r)
		prt_printf(out, "%u", r->level);
	else
		prt_printf(out, "(unknown)");
	prt_newline(out);

	bch2_bkey_val_to_text(out, c, k);
}

void bch2_btree_pos_to_text(struct printbuf *out, struct bch_fs *c, const struct btree *b)
{
	__bch2_btree_pos_to_text(out, c, b->c.btree_id, b->c.level, bkey_i_to_s_c(&b->key));
}

void bch2_btree_node_to_text(struct printbuf *out, struct bch_fs *c, const struct btree *b)
{
	struct bset_stats stats;

	memset(&stats, 0, sizeof(stats));

	bch2_btree_keys_stats(b, &stats);

	prt_printf(out, "l %u ", b->c.level);
	bch2_bpos_to_text(out, b->data->min_key);
	prt_printf(out, " - ");
	bch2_bpos_to_text(out, b->data->max_key);
	prt_printf(out, ":\n"
	       "    ptrs: ");
	bch2_val_to_text(out, c, bkey_i_to_s_c(&b->key));
	prt_newline(out);

	prt_printf(out,
	       "    format: ");
	bch2_bkey_format_to_text(out, &b->format);

	prt_printf(out,
	       "    unpack fn len: %u\n"
	       "    bytes used %zu/%zu (%zu%% full)\n"
	       "    sib u64s: %u, %u (merge threshold %u)\n"
	       "    nr packed keys %u\n"
	       "    nr unpacked keys %u\n"
	       "    floats %zu\n"
	       "    failed unpacked %zu\n",
	       b->unpack_fn_len,
	       b->nr.live_u64s * sizeof(u64),
	       btree_buf_bytes(b) - sizeof(struct btree_node),
	       b->nr.live_u64s * 100 / btree_max_u64s(c),
	       b->sib_u64s[0],
	       b->sib_u64s[1],
	       c->btree.foreground_merge_threshold,
	       b->nr.packed_keys,
	       b->nr.unpacked_keys,
	       stats.floats,
	       stats.failed);
}

static void prt_btree_cache_line(struct printbuf *out, const struct bch_fs *c,
				 const char *label, size_t nr)
{
	prt_printf(out, "%s\t", label);
	prt_human_readable_u64(out, nr * c->opts.btree_node_size);
	prt_printf(out, " (%zu)\n", nr);
}

static const char * const bch2_btree_cache_not_freed_reasons_strs[] = {
#define x(n) #n,
	BCH_BTREE_CACHE_NOT_FREED_REASONS()
#undef x
	NULL
};

void bch2_btree_cache_to_text(struct printbuf *out, const struct bch_fs_btree_cache *bc)
{
	struct bch_fs *c = container_of(bc, struct bch_fs, btree.cache);

	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 32);

	prt_btree_cache_line(out, c, "live:",		btree_cache_list_nr(&bc->live[0]));
	prt_btree_cache_line(out, c, "pinned:",		btree_cache_list_nr(&bc->live[1]));
	prt_btree_cache_line(out, c, "vmalloc:",	bc->nr_vmalloc);
	prt_btree_cache_line(out, c, "reserve:",	bc->nr_reserve);
	prt_btree_cache_line(out, c, "freeable:",	bc->nr_freeable);
	prt_btree_cache_line(out, c, "dirty:",		bc->live[0].nr_dirty + bc->live[1].nr_dirty);
	prt_btree_cache_line(out, c, "in flight:",	atomic_long_read(&bc->nr_in_flight));
	prt_printf(out, "cannibalize lock:\t%s\n",	bc->alloc_lock ? "held" : "not held");
	prt_newline(out);

	for (unsigned i = 0; i < ARRAY_SIZE(bc->nr_by_btree); i++) {
		bch2_btree_id_to_text(out, i);
		prt_printf(out, "\t");
		prt_human_readable_u64(out, bc->nr_by_btree[i] * c->opts.btree_node_size);
		prt_printf(out, " (%zu)\n", bc->nr_by_btree[i]);
	}

	prt_newline(out);
	prt_printf(out, "counters since mount:\n");
	prt_printf(out, "freed:\t%zu\n", bc->nr_freed);
	prt_printf(out, "not freed:\n");

	for (unsigned i = 0; i < ARRAY_SIZE(bc->not_freed); i++)
		prt_printf(out, "  %s\t%llu\n",
			   bch2_btree_cache_not_freed_reasons_strs[i], bc->not_freed[i]);
}
