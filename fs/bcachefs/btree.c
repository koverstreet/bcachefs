/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 *
 * Uses a block device as cache for other block devices; optimized for SSDs.
 * All allocation is done in buckets, which should match the erase block size
 * of the device.
 *
 * Buckets containing cached data are kept on a heap sorted by priority;
 * bucket priority is increased on cache hit, and periodically all the buckets
 * on the heap have their priority scaled down. This currently is just used as
 * an LRU but in the future should allow for more intelligent heuristics.
 *
 * Buckets have an 8 bit counter; freeing is accomplished by incrementing the
 * counter. Garbage collection is used to remove stale pointers.
 *
 * Indexing is done via a btree; nodes are not necessarily fully sorted, rather
 * as keys are inserted we only sort the pages that have not yet been written.
 * When garbage collection is run, we resort the entire node.
 *
 * All configuration is done via sysfs; see Documentation/bcache.txt.
 */

#include "bcache.h"
#include "alloc.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"
#include "gc.h"
#include "io.h"
#include "keylist.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "movinggc.h"
#include "super.h"
#include "writeback.h"

#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/hash.h>
#include <linux/jhash.h>
#include <linux/prefetch.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <trace/events/bcachefs.h>

#define DEF_BTREE_ID(kwd, val, name) name,

const char *bch_btree_id_names[BTREE_ID_NR] = {
	DEFINE_BCH_BTREE_IDS()
};

#undef DEF_BTREE_ID

static int bch_btree_iter_traverse(struct btree_iter *);

static inline void mark_btree_node_intent_locked(struct btree_iter *iter,
						 unsigned level)
{
	iter->nodes_locked |= 1 << level;
	iter->nodes_intent_locked |= 1 << level;
}

static inline void mark_btree_node_read_locked(struct btree_iter *iter,
					       unsigned level)
{
	iter->nodes_locked |= 1 << level;
}

static inline bool btree_node_intent_locked(struct btree_iter *iter,
					    unsigned level)
{
	return iter->nodes_intent_locked & (1 << level);
}

static inline bool btree_node_read_locked(struct btree_iter *iter,
					  unsigned level)
{
	return btree_node_locked(iter, level) &&
		!btree_node_intent_locked(iter, level);
}

static inline bool btree_want_intent(struct btree_iter *iter, int level)
{
	return level <= iter->locks_want;
}

static void __btree_node_unlock(struct btree_iter *iter, unsigned level,
				struct btree *b)
{
	if (btree_node_intent_locked(iter, level))
		six_unlock_intent(&b->lock);
	else if (btree_node_read_locked(iter, level))
		six_unlock_read(&b->lock);

	mark_btree_node_unlocked(iter, level);
}

static void btree_node_unlock(struct btree_iter *iter, unsigned level)
{
	__btree_node_unlock(iter, level, iter->nodes[level]);
}

#define __btree_node_lock(b, iter, _level, check_if_raced, type)	\
({									\
	bool _raced;							\
									\
	six_lock_##type(&(b)->lock);					\
	if ((_raced = ((check_if_raced) || ((b)->level != _level))))	\
		six_unlock_##type(&(b)->lock);				\
	else								\
		mark_btree_node_##type##_locked((iter), (_level));	\
									\
	!_raced;							\
})

#define btree_node_lock(b, iter, level, check_if_raced)			\
	(!race_fault() &&						\
	 (btree_want_intent(iter, level)				\
	  ? __btree_node_lock(b, iter, level, check_if_raced, intent)	\
	  : __btree_node_lock(b, iter, level, check_if_raced, read)))

#define __btree_node_relock(b, iter, _level, type)			\
({									\
	bool _locked = six_relock_##type(&(b)->lock,			\
					 (iter)->lock_seq[_level]);	\
									\
	if (_locked)							\
		mark_btree_node_##type##_locked((iter), (_level));	\
									\
	_locked;							\
})

static bool btree_node_relock(struct btree_iter *iter, unsigned level)
{
	struct btree *b = iter->nodes[level];

	return btree_node_locked(iter, level) ||
		(!race_fault() &&
		 (btree_want_intent(iter, level)
		  ? __btree_node_relock(b, iter, level, intent)
		  : __btree_node_relock(b, iter, level, read)));
}

static bool btree_lock_upgrade(struct btree_iter *iter, unsigned level)
{
	struct btree *b = iter->nodes[level];

	if (btree_node_intent_locked(iter, level))
		return true;

	if (btree_node_locked(iter, level)
	    ? six_trylock_convert(&b->lock, read, intent)
	    : six_relock_intent(&b->lock, iter->lock_seq[level])) {
		mark_btree_node_intent_locked(iter, level);
		trace_bcache_btree_upgrade_lock(b, iter);
		return true;
	}

	trace_bcache_btree_upgrade_lock_fail(b, iter);
	return false;
}

bool bch_btree_iter_upgrade(struct btree_iter *iter)
{
	int i;

	BUG_ON(iter->locks_want > BTREE_MAX_DEPTH);

	for (i = iter->locks_want; i >= iter->level; --i)
		if (iter->nodes[i] && !btree_lock_upgrade(iter, i)) {
			do {
				btree_node_unlock(iter, i);
			} while (--i >= 0);

			/*
			 * Make sure btree_node_relock() in
			 * btree_iter_traverse() fails, so that we keep going up
			 * and get all the intent locks we need
			 */
			for (i = iter->locks_want - 1; i >= 0; --i)
				iter->lock_seq[i]--;

			return false;
		}

	return true;
}

static inline struct btree_node_entry *write_block(struct cache_set *c,
						   struct btree *b)
{
	BUG_ON(!b->written);

	return (void *) b->data + (b->written << (c->block_bits + 9));
}

static void btree_node_sort(struct cache_set *c, struct btree *b,
			    unsigned from, struct btree_node_iter *iter,
			    btree_keys_sort_fn sort, bool is_write_locked)
{
	struct btree_node *out;
	bool used_mempool = false;
	unsigned order = b->keys.page_order;
	struct btree_nr_keys nr;

	if (from) {
		struct bset_tree *t;
		unsigned u64s = 0;

		for (t = b->keys.set + from;
		     t <= b->keys.set + b->keys.nsets; t++)
			u64s += t->data->u64s;

		order = get_order(__set_bytes(b->data, u64s));
	}

	out = (void *) __get_free_pages(__GFP_NOWARN|GFP_NOWAIT, order);
	if (!out) {
		struct page *outp;

		outp = mempool_alloc(&c->sort.pool, GFP_NOIO);
		out = page_address(outp);
		used_mempool = true;
	}

	nr = bch_sort_bsets(&out->keys, &b->keys, from, iter, sort, &c->sort);

	if (!is_write_locked)
		six_lock_write(&b->lock);

	if (!from) {
		unsigned u64s = out->keys.u64s;

		BUG_ON(order != b->keys.page_order);

		/*
		 * Our temporary buffer is the same size as the btree node's
		 * buffer, we can just swap buffers instead of doing a big
		 * memcpy()
		 */
		*out = *b->data;
		out->keys.u64s = u64s;
		swap(out, b->data);
		b->keys.set->data = &b->data->keys;
	} else {
		b->keys.set[from].data->u64s = out->keys.u64s;
		memcpy(b->keys.set[from].data->start, out->keys.start,
		       (void *) bset_bkey_last(&out->keys) -
		       (void *) out->keys.start);
	}

	b->keys.nsets = from;
	b->keys.nr = nr;
	bch_bset_build_written_tree(&b->keys);

	if (!is_write_locked)
		six_unlock_write(&b->lock);

	if (used_mempool)
		mempool_free(virt_to_page(out), &c->sort.pool);
	else
		free_pages((unsigned long) out, order);

	bch_verify_btree_nr_keys(&b->keys);
}

#define SORT_CRIT	(4096 / sizeof(u64))

/*
 * We're about to add another bset to the btree node, so if there's currently
 * too many bsets - sort some of them together:
 */
static bool btree_node_compact(struct cache_set *c, struct btree *b)
{
	unsigned crit = SORT_CRIT;
	int i = 0;

	/* Don't sort if nothing to do */
	if (!b->keys.nsets)
		goto nosort;

	/* If not a leaf node, always sort */
	if (b->level)
		goto sort;

	for (i = b->keys.nsets - 1; i >= 0; --i) {
		crit *= c->sort.crit_factor;

		if (b->keys.set[i].data->u64s < crit)
			goto sort;
	}

	/* Sort if we'd overflow */
	if (b->keys.nsets + 1 == MAX_BSETS) {
		i = 0;
		goto sort;
	}

nosort:
	six_lock_write(&b->lock);
	bch_bset_build_written_tree(&b->keys);
	six_unlock_write(&b->lock);
	return false;
sort:
	btree_node_sort(c, b, i, NULL, NULL, false);
	return true;
}

/* Returns true if we sorted (i.e. invalidated iterators */
static void bch_btree_init_next(struct cache_set *c, struct btree *b,
				struct btree_iter *iter)
{
	bool did_sort;

	BUG_ON(iter && iter->nodes[b->level] != b);

	did_sort = btree_node_compact(c, b);

	/* do verify if we sorted down to a single set: */
	if (did_sort && !b->keys.nsets)
		bch_btree_verify(c, b);

	if (b->written < btree_blocks(c)) {
		six_lock_write(&b->lock);
		bch_bset_init_next(&b->keys, &write_block(c, b)->keys);
		six_unlock_write(&b->lock);
	}

	if (iter && did_sort)
		btree_iter_node_set(iter, b);

	clear_btree_node_need_init_next(b);
}

/* Btree IO */

#define btree_csum_set(_b, _i)						\
({									\
	void *_data = (void *) (_i) + 8;				\
	void *_end = bset_bkey_last(&(_i)->keys);			\
									\
	bch_checksum_update(BSET_CSUM_TYPE(&(_i)->keys),		\
			    bkey_i_to_extent_c(&(_b)->key)->v.ptr[0]._val,\
			    _data,					\
			    _end - _data) ^ 0xffffffffffffffffULL;	\
})

#define btree_node_error(b, ca, ptr, fmt, ...)				\
	bch_cache_error(ca,						\
		"btree node error at btree %u level %u/%u bucket %zu block %u u64s %u: " fmt,\
		(b)->btree_id, (b)->level, btree_node_root(b)		\
			    ? btree_node_root(b)->level : -1,		\
		PTR_BUCKET_NR(ca, ptr), (b)->written,			\
		(i)->u64s, ##__VA_ARGS__)

static const char *validate_bset(struct cache_set *c, struct btree *b,
				 struct cache *ca,
				 const struct bch_extent_ptr *ptr,
				 struct bset *i, unsigned blocks)
{
	struct bkey_format *f = &b->keys.format;
	struct bkey_packed *k;

	if (i->version != BCACHE_BSET_VERSION)
		return "unsupported bset version";

	if (b->written + blocks > btree_blocks(c))
		return  "bset past end of btree node";

	if (i != &b->data->keys && !i->u64s)
		btree_node_error(b, ca, ptr, "empty set");

	for (k = i->start;
	     k != bset_bkey_last(i);) {
		struct bkey_tup tup;

		if (!k->u64s) {
			btree_node_error(b, ca, ptr,
				"KEY_U64s 0: %zu bytes of metadata lost",
				(void *) bset_bkey_last(i) - (void *) k);

			i->u64s = (u64 *) k - i->_data;
			break;
		}

		if (bkey_next(k) > bset_bkey_last(i)) {
			btree_node_error(b, ca, ptr,
					 "key extends past end of bset");

			i->u64s = (u64 *) k - i->_data;
			break;
		}

		bkey_disassemble(&tup, f, k);

		if (bkey_invalid(c, btree_node_type(b),
				 bkey_tup_to_s_c(&tup))) {
			char buf[160];

			bkey_disassemble(&tup, f, k);
			bch_bkey_val_to_text(c, b, buf, sizeof(buf),
					     bkey_tup_to_s_c(&tup));
			btree_node_error(b, ca, ptr,
					 "invalid bkey %s", buf);

			i->u64s -= k->u64s;
			memmove(k, bkey_next(k),
				(void *) bset_bkey_last(i) - (void *) k);
			continue;
		}

		k = bkey_next(k);
	}

	b->written += blocks;
	return NULL;
}

void bch_btree_node_read_done(struct cache_set *c, struct btree *b,
			      struct cache *ca,
			      const struct bch_extent_ptr *ptr)
{
	struct btree_node_entry *bne;
	struct bset *i = &b->data->keys;
	struct btree_node_iter *iter;
	const char *err;
	int ret;

	iter = mempool_alloc(&c->fill_iter, GFP_NOIO);
	__bch_btree_node_iter_init(iter, &b->keys);

	err = "dynamic fault";
	if (bch_meta_read_fault("btree"))
		goto err;

	err = "bad magic";
	if (b->data->magic != bset_magic(&c->sb))
		goto err;

	err = "bad btree header";
	if (!b->data->keys.seq)
		goto err;

	err = "incorrect max key";
	if (bkey_cmp(b->data->max_key, b->key.k.p))
		goto err;

	err = "incorrect level";
	if (BSET_BTREE_LEVEL(i) != b->level)
		goto err;

	err = bch_bkey_format_validate(&b->data->format);
	if (err)
		goto err;

	b->keys.format = b->data->format;
	b->keys.set->data = &b->data->keys;

	while (b->written < btree_blocks(c)) {
		unsigned blocks;

		if (!b->written) {
			i = &b->data->keys;

			err = "unknown checksum type";
			if (BSET_CSUM_TYPE(i) >= BCH_CSUM_NR)
				goto err;

			err = "bad checksum";
			if (b->data->csum != btree_csum_set(b, b->data))
				goto err;

			blocks = __set_blocks(b->data,
					      b->data->keys.u64s,
					      block_bytes(c));
		} else {
			bne = write_block(c, b);
			i = &bne->keys;

			if (i->seq != b->data->keys.seq)
				break;

			err = "unknown checksum type";
			if (BSET_CSUM_TYPE(i) >= BCH_CSUM_NR)
				goto err;

			err = "bad checksum";
			if (bne->csum != btree_csum_set(b, bne))
				goto err;

			blocks = __set_blocks(bne,
					      bne->keys.u64s,
					      block_bytes(c));
		}

		err = validate_bset(c, b, ca, ptr, i, blocks);
		if (err)
			goto err;

		err = "insufficient memory";
		ret = bch_journal_seq_blacklisted(c, i->journal_seq, b);
		if (ret < 0)
			goto err;

		if (ret)
			continue;

		bch_btree_node_iter_push(iter, &b->keys,
					 i->start, bset_bkey_last(i));
	}

	err = "corrupted btree";
	for (bne = write_block(c, b);
	     bset_byte_offset(b, bne) < btree_bytes(c);
	     bne = (void *) bne + block_bytes(c))
		if (bne->keys.seq == b->data->keys.seq)
			goto err;

	btree_node_sort(c, b, 0, iter,
			b->keys.ops->is_extents
			? bch_extent_sort_fix_overlapping
			: bch_key_sort_fix_overlapping,
			true);

	err = "short btree key";
	if (b->keys.set[0].size &&
	    bkey_cmp_packed(&b->keys.format, &b->key.k,
			    &b->keys.set[0].end) < 0)
		goto err;

	set_btree_node_need_init_next(b);
out:
	mempool_free(iter, &c->fill_iter);
	return;
err:
	set_btree_node_io_error(b);
	btree_node_error(b, ca, ptr, "%s", err);
	goto out;
}

static void btree_node_read_endio(struct bio *bio)
{
	bch_bbio_endio(to_bbio(bio), bio->bi_error, "reading btree");
}

static void bch_btree_node_read(struct cache_set *c, struct btree *b)
{
	uint64_t start_time = local_clock();
	struct closure cl;
	struct bio *bio;
	struct cache *ca;
	const struct bch_extent_ptr *ptr;

	trace_bcache_btree_read(b);

	closure_init_stack(&cl);

	ca = bch_btree_pick_ptr(c, b, &ptr);
	if (!ca) {
		set_btree_node_io_error(b);
		goto missing;
	}

	percpu_ref_get(&ca->ref);

	bio = bio_alloc_bioset(GFP_NOIO, btree_pages(c), &c->btree_bio);
	bio->bi_iter.bi_size	= btree_bytes(c);
	bio->bi_end_io		= btree_node_read_endio;
	bio->bi_private		= &cl;
	bio_set_op_attrs(bio, REQ_OP_READ, REQ_META|READ_SYNC);

	bch_bio_map(bio, b->data);

	bio_get(bio);
	bch_submit_bbio(to_bbio(bio), ca, &b->key, ptr, true);

	closure_sync(&cl);

	if (bio->bi_error ||
	    bch_meta_read_fault("btree"))
		set_btree_node_io_error(b);

	bio_put(bio);

	if (btree_node_io_error(b))
		goto err;

	bch_btree_node_read_done(c, b, ca, ptr);
	bch_time_stats_update(&c->btree_read_time, start_time);

	percpu_ref_put(&ca->ref);
	return;

missing:
	bch_cache_set_error(c, "no cache device for btree node");
	percpu_ref_put(&ca->ref);
	return;

err:
	bch_cache_error(ca, "IO error reading bucket %zu",
			PTR_BUCKET_NR(ca, ptr));
	percpu_ref_put(&ca->ref);
}

static void btree_complete_write(struct cache_set *c, struct btree *b,
				 struct btree_write *w)
{
	if (w->have_pin)
		journal_pin_drop(&c->journal, &w->journal);
	w->have_pin = false;
}

static void btree_node_write_unlock(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io);

	up(&b->io_mutex);
}

static void __btree_node_write_done(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io);
	struct btree_write *w = btree_prev_write(b);
	struct cache_set *c = b->c;

	bio_put(b->bio);
	b->bio = NULL;
	btree_complete_write(c, b, w);

	if (btree_node_dirty(b) && c->btree_flush_delay)
		schedule_delayed_work(&b->work, c->btree_flush_delay * HZ);

	closure_return_with_destructor(cl, btree_node_write_unlock);
}

static void btree_node_write_done(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io);

	bio_free_pages(b->bio);
	__btree_node_write_done(cl);
}

static void btree_node_write_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;
	struct btree *b = container_of(cl, struct btree, io);

	if (bio->bi_error || bch_meta_write_fault("btree"))
		set_btree_node_io_error(b);

	bch_bbio_endio(to_bbio(bio), bio->bi_error, "writing btree");
}

static void do_btree_node_write(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io);
	struct cache_set *c = b->c;
	struct bset *i = btree_bset_last(b);
	BKEY_PADDED(key) k;
	struct bkey_s_extent e;
	struct bch_extent_ptr *ptr;
	struct cache *ca;
	size_t blocks_to_write;
	void *data;

	trace_bcache_btree_write(b);

	BUG_ON(b->written >= btree_blocks(c));
	BUG_ON(b->written && !i->u64s);
	BUG_ON(btree_bset_first(b)->seq != i->seq);

	cancel_delayed_work(&b->work);

	change_bit(BTREE_NODE_write_idx, &b->flags);
	set_btree_node_need_init_next(b);

	i->version	= BCACHE_BSET_VERSION;

	SET_BSET_CSUM_TYPE(i, CACHE_PREFERRED_CSUM_TYPE(&c->sb));

	if (!b->written) {
		BUG_ON(b->data->magic != bset_magic(&c->sb));

		b->data->format	= b->keys.format;
		data		= b->data;
		b->data->csum	= btree_csum_set(b, b->data);
		blocks_to_write	= __set_blocks(b->data,
					       b->data->keys.u64s,
					       block_bytes(c));

	} else {
		struct btree_node_entry *bne = write_block(c, b);

		data		= bne;
		bne->csum	= btree_csum_set(b, bne);
		blocks_to_write	= __set_blocks(bne,
					       bne->keys.u64s,
					       block_bytes(c));
	}

	BUG_ON(b->written + blocks_to_write > btree_blocks(c));

	BUG_ON(b->bio);
	b->bio = bio_alloc_bioset(GFP_NOIO, btree_pages(c), &c->btree_bio);

	/*
	 * Take an extra reference so that the bio_put() in
	 * btree_node_write_endio() doesn't call bio_free()
	 */
	bio_get(b->bio);

	b->bio->bi_end_io	= btree_node_write_endio;
	b->bio->bi_private	= cl;
	b->bio->bi_iter.bi_size	= blocks_to_write << (c->block_bits + 9);
	bio_set_op_attrs(b->bio, REQ_OP_WRITE, REQ_META|WRITE_SYNC|REQ_FUA);
	bch_bio_map(b->bio, data);

	/*
	 * If we're appending to a leaf node, we don't technically need FUA -
	 * this write just needs to be persisted before the next journal write,
	 * which will be marked FLUSH|FUA.
	 *
	 * Similarly if we're writing a new btree root - the pointer is going to
	 * be in the next journal entry.
	 *
	 * But if we're writing a new btree node (that isn't a root) or
	 * appending to a non leaf btree node, we need either FUA or a flush
	 * when we write the parent with the new pointer. FUA is cheaper than a
	 * flush, and writes appending to leaf nodes aren't blocking anything so
	 * just make all btree node writes FUA to keep things sane.
	 */

	bkey_copy(&k.key, &b->key);
	e = bkey_i_to_s_extent(&k.key);

	extent_for_each_ptr(e, ptr)
		SET_PTR_OFFSET(ptr, PTR_OFFSET(ptr) +
			       (b->written << c->block_bits));

	rcu_read_lock();
	extent_for_each_online_device(c, e, ptr, ca)
		atomic_long_add(blocks_to_write << c->block_bits,
				&ca->btree_sectors_written);
	rcu_read_unlock();

	b->written += blocks_to_write;

	if (!bio_alloc_pages(b->bio, __GFP_NOWARN|GFP_NOWAIT)) {
		int j;
		struct bio_vec *bv;
		void *base = (void *) ((unsigned long) data & ~(PAGE_SIZE - 1));

		bio_for_each_segment_all(bv, b->bio, j)
			memcpy(page_address(bv->bv_page),
			       base + (j << PAGE_SHIFT), PAGE_SIZE);

		bch_submit_bbio_replicas(b->bio, c, &k.key, 0, true);
		continue_at(cl, btree_node_write_done, NULL);
	} else {
		trace_bcache_btree_bounce_write_fail(b);

		b->bio->bi_vcnt = 0;
		bch_bio_map(b->bio, data);

		bch_submit_bbio_replicas(b->bio, c, &k.key, 0, true);

		closure_sync(cl);
		continue_at_nobarrier(cl, __btree_node_write_done, NULL);
	}
}

/*
 * Only requires a read lock:
 */
static void __bch_btree_node_write(struct btree *b, struct closure *parent,
				   int idx_to_write)
{
	/*
	 * We may only have a read lock on the btree node - the dirty bit is our
	 * "lock" against racing with other threads that may be trying to start
	 * a write, we do a write iff we clear the dirty bit. Since setting the
	 * dirty bit requires a write lock, we can't race with other threads
	 * redirtying it:
	 */
	if (!test_and_clear_bit(BTREE_NODE_dirty, &b->flags))
		return;

	/*
	 * io_mutex ensures only a single IO in flight to a btree node at a
	 * time, and also protects use of the b->io closure.
	 * do_btree_node_write() will drop it asynchronously.
	 */
	down(&b->io_mutex);
#if 0
	if (idx_to_write != -1 &&
	    idx_to_write != btree_node_write_idx(b)) {
		up(&b->io_mutex);
		return;
	}
#endif
	/*
	 * do_btree_node_write() must not run asynchronously (NULL is passed for
	 * workqueue) - it needs the lock we have on the btree node
	 */
	closure_call(&b->io, do_btree_node_write, NULL, parent ?: &b->c->cl);
}

/*
 * Use this one if the node is intent locked:
 */
void bch_btree_node_write(struct btree *b, struct closure *parent,
			  struct btree_iter *iter)
{
	__bch_btree_node_write(b, parent, -1);

	bch_btree_init_next(b->c, b, iter);
}

static void bch_btree_node_write_sync(struct btree *b, struct btree_iter *iter)
{
	struct closure cl;

	closure_init_stack(&cl);

	bch_btree_node_write(b, &cl, iter);
	closure_sync(&cl);
}

static void bch_btree_node_write_dirty(struct btree *b, struct closure *parent)
{
	six_lock_read(&b->lock);
	__bch_btree_node_write(b, parent, -1);
	six_unlock_read(&b->lock);
}

static void btree_node_write_work(struct work_struct *w)
{
	struct btree *b = container_of(to_delayed_work(w), struct btree, work);

	bch_btree_node_write_dirty(b, NULL);
}

/*
 * Write all dirty btree nodes to disk, including roots
 */
void bch_btree_flush(struct cache_set *c)
{
	struct closure cl;
	struct btree *b;
	struct bucket_table *tbl;
	struct rhash_head *pos;
	bool dropped_lock;
	unsigned i;

	closure_init_stack(&cl);

	rcu_read_lock();

	do {
		dropped_lock = false;
		i = 0;
restart:
		tbl = rht_dereference_rcu(c->btree_cache_table.tbl,
					  &c->btree_cache_table);

		for (; i < tbl->size; i++)
			rht_for_each_entry_rcu(b, pos, tbl, i, hash)
				if (btree_node_dirty(b)) {
					rcu_read_unlock();
					bch_btree_node_write_dirty(b, &cl);
					dropped_lock = true;
					rcu_read_lock();
					goto restart;
				}
	} while (dropped_lock);

	rcu_read_unlock();

	closure_sync(&cl);
}

void bch_btree_push_journal_seq(struct cache_set *c, struct btree *b,
				struct closure *cl)
{
	int i;

	for (i = b->keys.nsets; i >= 0; --i) {
		u64 seq = b->keys.set[i].data->journal_seq;

		if (seq) {
			bch_journal_push_seq(&c->journal, seq, cl);
			break;
		}
	}
}

/*
 * Btree in memory cache - allocation/freeing
 * mca -> memory cache
 */

void bch_recalc_btree_reserve(struct cache_set *c)
{
	unsigned i, reserve = 16;

	if (!c->btree_roots[0])
		reserve += 8;

	for (i = 0; i < BTREE_ID_NR; i++)
		if (c->btree_roots[i])
			reserve += min_t(unsigned, 1,
					 c->btree_roots[i]->level) * 8;

	c->btree_cache_reserve = reserve;
}

#define mca_can_free(c)						\
	max_t(int, 0, c->btree_cache_used - c->btree_cache_reserve)

static void mca_data_free(struct cache_set *c, struct btree *b)
{
	BUG_ON(b->io_mutex.count != 1);

	free_pages((unsigned long) b->data, b->keys.page_order);
	b->data = NULL;
	bch_btree_keys_free(&b->keys);

	c->btree_cache_used--;
	list_move(&b->list, &c->btree_cache_freed);
}

static const struct rhashtable_params bch_btree_cache_params = {
	.head_offset	= offsetof(struct btree, hash),
	.key_offset	= offsetof(struct btree, key.v),
	.key_len	= sizeof(struct bch_extent_ptr),
	.hashfn		= jhash,
};

static void mca_bucket_free(struct cache_set *c, struct btree *b)
{
	BUG_ON(btree_node_dirty(b));
	BUG_ON(!list_empty_careful(&b->journal_seq_blacklisted));

	b->keys.nsets = 0;
	b->keys.set[0].data = NULL;

	rhashtable_remove_fast(&c->btree_cache_table, &b->hash,
			       bch_btree_cache_params);

	/* Cause future lookups for this node to fail: */
	bkey_i_to_extent(&b->key)->v.ptr[0]._val = 0;
	list_move(&b->list, &c->btree_cache_freeable);
}

static void mca_data_alloc(struct cache_set *c, struct btree *b, gfp_t gfp)
{
	unsigned order = ilog2(btree_pages(c));

	b->data = (void *) __get_free_pages(gfp, order);
	if (!b->data)
		goto err;

	if (bch_btree_keys_alloc(&b->keys, order, gfp))
		goto err;

	c->btree_cache_used++;
	list_move(&b->list, &c->btree_cache_freeable);
	return;
err:
	free_pages((unsigned long) b->data, order);
	b->data = NULL;
	list_move(&b->list, &c->btree_cache_freed);
}

static struct btree *mca_bucket_alloc(struct cache_set *c, gfp_t gfp)
{
	struct btree *b = kzalloc(sizeof(struct btree), gfp);
	if (!b)
		return NULL;

	six_lock_init(&b->lock);
	INIT_LIST_HEAD(&b->list);
	INIT_DELAYED_WORK(&b->work, btree_node_write_work);
	b->c = c;
	sema_init(&b->io_mutex, 1);
	INIT_LIST_HEAD(&b->journal_seq_blacklisted);
	b->writes[1].index = 1;

	mca_data_alloc(c, b, gfp);
	return b->data ? b : NULL;
}

/*
 * this version is for btree nodes that have already been freed (we're not
 * reaping a real btree node)
 */
static int mca_reap_notrace(struct cache_set *c, struct btree *b, bool flush)
{
	struct closure cl;
	struct bset *i;

	closure_init_stack(&cl);
	lockdep_assert_held(&c->btree_cache_lock);

	if (!six_trylock_intent(&b->lock))
		return -ENOMEM;

	if (!six_trylock_write(&b->lock))
		goto out_unlock_intent;

	i = btree_bset_last(b);
	BUG_ON(!i && btree_node_dirty(b));
	BUG_ON(i && i->u64s &&
	       b->io_mutex.count == 1 &&
	       !btree_node_dirty(b) &&
	       (((void *) i - (void *) b->data) >>
		(c->block_bits + 9) >= b->written));

	/* XXX: we need a better solution for this, this will cause deadlocks */
	if (!list_empty_careful(&b->journal_seq_blacklisted))
		goto out_unlock;

	if (!flush) {
		if (btree_node_dirty(b))
			goto out_unlock;

		if (down_trylock(&b->io_mutex))
			goto out_unlock;
		up(&b->io_mutex);
	}

	if (btree_node_dirty(b))
		__bch_btree_node_write(b, &cl, -1);

	closure_sync(&cl);

	/* wait for any in flight btree write */
	down(&b->io_mutex);
	up(&b->io_mutex);

	return 0;
out_unlock:
	six_unlock_write(&b->lock);
out_unlock_intent:
	six_unlock_intent(&b->lock);
	return -ENOMEM;
}

static int mca_reap(struct cache_set *c, struct btree *b, bool flush)
{
	int ret = mca_reap_notrace(c, b, flush);

	trace_bcache_mca_reap(b, ret);
	return ret;
}

static unsigned long bch_mca_scan(struct shrinker *shrink,
				  struct shrink_control *sc)
{
	struct cache_set *c = container_of(shrink, struct cache_set,
					   btree_cache_shrink);
	struct btree *b, *t;
	unsigned long nr = sc->nr_to_scan;
	unsigned long can_free;
	unsigned long touched = 0;
	unsigned long freed = 0;
	unsigned i;

	u64 start_time = local_clock();

	if (c->shrinker_disabled)
		return SHRINK_STOP;

	if (c->btree_cache_alloc_lock)
		return SHRINK_STOP;

	/* Return -1 if we can't do anything right now */
	if (sc->gfp_mask & __GFP_IO)
		mutex_lock(&c->btree_cache_lock);
	else if (!mutex_trylock(&c->btree_cache_lock))
		return -1;

	/*
	 * It's _really_ critical that we don't free too many btree nodes - we
	 * have to always leave ourselves a reserve. The reserve is how we
	 * guarantee that allocating memory for a new btree node can always
	 * succeed, so that inserting keys into the btree can always succeed and
	 * IO can always make forward progress:
	 */
	nr /= btree_pages(c);
	can_free = mca_can_free(c);
	nr = min_t(unsigned long, nr, can_free);

	i = 0;
	list_for_each_entry_safe(b, t, &c->btree_cache_freeable, list) {
		touched++;

		if (freed >= nr)
			break;

		if (++i > 3 &&
		    !mca_reap_notrace(c, b, false)) {
			mca_data_free(c, b);
			six_unlock_write(&b->lock);
			six_unlock_intent(&b->lock);
			freed++;
		}
	}

	list_for_each_entry_safe(b, t, &c->btree_cache, list) {
		touched++;

		if (freed >= nr) {
			/* Save position */
			if (&t->list != &c->btree_cache)
				list_move_tail(&c->btree_cache, &t->list);
			break;
		}

		if (!b->accessed &&
		    !mca_reap(c, b, false)) {
			mca_bucket_free(c, b);
			mca_data_free(c, b);
			six_unlock_write(&b->lock);
			six_unlock_intent(&b->lock);
			freed++;
		} else
			b->accessed = 0;
	}

	mutex_unlock(&c->btree_cache_lock);

	bch_time_stats_update(&c->mca_scan_time, start_time);

	trace_bcache_mca_scan(c,
			      touched * btree_pages(c),
			      freed * btree_pages(c),
			      can_free * btree_pages(c),
			      sc->nr_to_scan);

	return (unsigned long) freed * btree_pages(c);
}

static unsigned long bch_mca_count(struct shrinker *shrink,
				   struct shrink_control *sc)
{
	struct cache_set *c = container_of(shrink, struct cache_set,
					   btree_cache_shrink);

	if (c->shrinker_disabled)
		return 0;

	if (c->btree_cache_alloc_lock)
		return 0;

	return mca_can_free(c) * btree_pages(c);
}

void bch_btree_cache_free(struct cache_set *c)
{
	struct btree *b;
	struct closure cl;
	unsigned i;

	closure_init_stack(&cl);

	if (c->btree_cache_shrink.list.next)
		unregister_shrinker(&c->btree_cache_shrink);

	mutex_lock(&c->btree_cache_lock);

#ifdef CONFIG_BCACHEFS_DEBUG
	if (c->verify_data)
		list_move(&c->verify_data->list, &c->btree_cache);

	free_pages((unsigned long) c->verify_ondisk, ilog2(btree_pages(c)));
#endif

	for (i = 0; i < BTREE_ID_NR; i++)
		if (c->btree_roots[i])
			list_add(&c->btree_roots[i]->list, &c->btree_cache);

	list_splice(&c->btree_cache_freeable,
		    &c->btree_cache);

	while (!list_empty(&c->btree_cache)) {
		b = list_first_entry(&c->btree_cache, struct btree, list);

		if (btree_node_dirty(b))
			btree_complete_write(c, b, btree_current_write(b));
		clear_btree_node_dirty(b);

		mca_data_free(c, b);
	}

	while (!list_empty(&c->btree_cache_freed)) {
		b = list_first_entry(&c->btree_cache_freed,
				     struct btree, list);
		list_del(&b->list);
		cancel_delayed_work_sync(&b->work);
		kfree(b);
	}

	rhashtable_destroy(&c->btree_cache_table);
	mutex_unlock(&c->btree_cache_lock);
}

int bch_btree_cache_alloc(struct cache_set *c)
{
	unsigned i;
	int ret;

	ret = rhashtable_init(&c->btree_cache_table, &bch_btree_cache_params);
	if (ret)
		return ret;

	bch_recalc_btree_reserve(c);

	for (i = 0; i < c->btree_cache_reserve; i++)
		if (!mca_bucket_alloc(c, GFP_KERNEL))
			return -ENOMEM;

	list_splice_init(&c->btree_cache,
			 &c->btree_cache_freeable);

#ifdef CONFIG_BCACHEFS_DEBUG
	mutex_init(&c->verify_lock);

	c->verify_ondisk = (void *)
		__get_free_pages(GFP_KERNEL, ilog2(btree_pages(c)));

	c->verify_data = mca_bucket_alloc(c, GFP_KERNEL);
	if (c->verify_data)
		list_del_init(&c->verify_data->list);
#endif

	c->btree_cache_shrink.count_objects = bch_mca_count;
	c->btree_cache_shrink.scan_objects = bch_mca_scan;
	c->btree_cache_shrink.seeks = 4;
	c->btree_cache_shrink.batch = btree_pages(c) * 2;
	register_shrinker(&c->btree_cache_shrink);

	return 0;
}

/* Btree in memory cache - hash table */

#define PTR_HASH(_k)	(bkey_i_to_extent_c(_k)->v.ptr[0]._val)

static inline struct btree *mca_find(struct cache_set *c,
				     const struct bkey_i *k)
{
	return rhashtable_lookup_fast(&c->btree_cache_table, &PTR_HASH(k),
				      bch_btree_cache_params);
}

static void mca_hash_insert(struct cache_set *c, struct btree *b,
			    unsigned level, enum btree_id id)
{
	b->level	= level;
	b->btree_id	= id;

	bch_btree_keys_init(&b->keys, b->level
			    ? &bch_btree_interior_node_ops
			    : bch_btree_ops[id],
			    &c->expensive_debug_checks);

	BUG_ON(rhashtable_insert_fast(&c->btree_cache_table, &b->hash,
				      bch_btree_cache_params));
}

static int mca_cannibalize_lock(struct cache_set *c, struct closure *cl)
{
	struct task_struct *old;

	old = cmpxchg(&c->btree_cache_alloc_lock, NULL, current);
	if (old == NULL || old == current)
		goto success;

	if (!cl) {
		trace_bcache_mca_cannibalize_lock_fail(c, cl);
		return -EINTR;
	}

	closure_wait(&c->mca_wait, cl);

	/* Try again, after adding ourselves to waitlist */
	old = cmpxchg(&c->btree_cache_alloc_lock, NULL, current);
	if (old == NULL || old == current) {
		/* We raced */
		closure_wake_up(&c->mca_wait);
		goto success;
	}

	trace_bcache_mca_cannibalize_lock_fail(c, cl);
	return -EAGAIN;

success:
	trace_bcache_mca_cannibalize_lock(c, cl);
	return 0;
}

static struct btree *mca_cannibalize(struct cache_set *c, struct closure *cl)
{
	struct btree *b;
	int ret;

	ret = mca_cannibalize_lock(c, cl);
	if (ret)
		return ERR_PTR(ret);

	while (1) {
		trace_bcache_mca_cannibalize(c, cl);

		list_for_each_entry_reverse(b, &c->btree_cache, list)
			if (!mca_reap(c, b, false))
				goto out;

		list_for_each_entry_reverse(b, &c->btree_cache, list)
			if (!mca_reap(c, b, true))
				goto out;

		/*
		 * Rare case: all nodes were intent-locked.
		 * Just busy-wait.
		 */
		WARN_ONCE(1, "btree cache cannibalize failed\n");
		cond_resched();
	}
out:
	mca_bucket_free(c, b);
	return b;
}

/*
 * We can only have one thread cannibalizing other cached btree nodes at a time,
 * or we'll deadlock. We use an open coded mutex to ensure that, which a
 * cannibalize_bucket() will take. This means every time we unlock the root of
 * the btree, we need to release this lock if we have it held.
 */
static void mca_cannibalize_unlock(struct cache_set *c)
{
	if (c->btree_cache_alloc_lock == current) {
		trace_bcache_mca_cannibalize_unlock(c);
		c->btree_cache_alloc_lock = NULL;
		closure_wake_up(&c->mca_wait);
	}
}

static struct btree *mca_alloc(struct cache_set *c, const struct bkey_i *k,
			       int level, enum btree_id id, struct closure *cl)
{
	struct btree *b = NULL;

	u64 start_time = local_clock();

	mutex_lock(&c->btree_cache_lock);

	if (k && mca_find(c, k))
		goto out_unlock;

	/* btree_free() doesn't free memory; it sticks the node on the end of
	 * the list. Check if there's any freed nodes there:
	 */
	list_for_each_entry(b, &c->btree_cache_freeable, list)
		if (!mca_reap_notrace(c, b, false))
			goto out;

	/* We never free struct btree itself, just the memory that holds the on
	 * disk node. Check the freed list before allocating a new one:
	 */
	list_for_each_entry(b, &c->btree_cache_freed, list)
		if (!mca_reap_notrace(c, b, false)) {
			mca_data_alloc(c, b, __GFP_NOWARN|GFP_NOIO);
			if (!b->data)
				goto err;
			else
				goto out;
		}

	b = mca_bucket_alloc(c, __GFP_NOWARN|GFP_NOIO);
	if (!b)
		goto err;

	BUG_ON(!six_trylock_intent(&b->lock));
	BUG_ON(!six_trylock_write(&b->lock));
out:
	BUG_ON(b->key.k.type == BCH_EXTENT && PTR_HASH(&b->key));
	BUG_ON(b->io_mutex.count != 1);

	list_move(&b->list, &c->btree_cache);

	b->flags	= 0;
	b->written	= 0;

	if (k) {
		bkey_copy(&b->key, k);
		mca_hash_insert(c, b, level, id);
	}

out_unlock:
	mutex_unlock(&c->btree_cache_lock);

	bch_time_stats_update(&c->mca_alloc_time, start_time);

	return b;
err:
	if (b) {
		six_unlock_write(&b->lock);
		six_unlock_intent(&b->lock);
	}

	b = mca_cannibalize(c, cl);
	if (!IS_ERR(b))
		goto out;

	goto out_unlock;
}

/* Slowpath, don't want it inlined into btree_iter_traverse() */
static noinline struct btree *bch_btree_node_fill(struct btree_iter *iter,
						  const struct bkey_i *k,
						  int level)
{
	struct btree *b;

	b = mca_alloc(iter->c, k, level, iter->btree_id, &iter->cl);
	if (IS_ERR_OR_NULL(b))
		return b;

	mca_cannibalize_unlock(iter->c);

	/*
	 * If the btree node wasn't cached, we can't drop our lock on
	 * the parent until after it's added to the cache - because
	 * otherwise we could race with a btree_split() freeing the node
	 * we're trying to lock.
	 *
	 * But the deadlock described below doesn't exist in this case,
	 * so it's safe to not drop the parent lock until here:
	 */
	if (btree_node_read_locked(iter, level + 1))
		btree_node_unlock(iter, level + 1);

	bch_btree_node_read(iter->c, b);
	six_unlock_write(&b->lock);

	if (btree_want_intent(iter, level)) {
		mark_btree_node_intent_locked(iter, level);
	} else {
		mark_btree_node_read_locked(iter, level);
		BUG_ON(!six_trylock_convert(&b->lock, intent, read));
	}

	return b;
}

/**
 * bch_btree_node_get - find a btree node in the cache and lock it, reading it
 * in from disk if necessary.
 *
 * If IO is necessary and running under generic_make_request, returns -EAGAIN.
 *
 * The btree node will have either a read or a write lock held, depending on
 * the @write parameter.
 */
static struct btree *bch_btree_node_get(struct btree_iter *iter,
					const struct bkey_i *k, int level)
{
	int i = 0;
	struct btree *b;

	BUG_ON(level < 0);
retry:
	rcu_read_lock();
	b = mca_find(iter->c, k);
	rcu_read_unlock();

	if (unlikely(!b)) {
		b = bch_btree_node_fill(iter, k, level);

		/* We raced and found the btree node in the cache */
		if (!b)
			goto retry;

		if (IS_ERR(b)) {
			BUG_ON(PTR_ERR(b) != -EAGAIN);
			return b;
		}
	} else {
		/*
		 * There's a potential deadlock with splits and insertions into
		 * interior nodes we have to avoid:
		 *
		 * The other thread might be holding an intent lock on the node
		 * we want, and they want to update its parent node so they're
		 * going to upgrade their intent lock on the parent node to a
		 * write lock.
		 *
		 * But if we're holding a read lock on the parent, and we're
		 * trying to get the intent lock they're holding, we deadlock.
		 *
		 * So to avoid this we drop the read locks on parent nodes when
		 * we're starting to take intent locks - and handle the race.
		 *
		 * The race is that they might be about to free the node we
		 * want, and dropping our read lock lets them add the
		 * replacement node's pointer to the parent and then free the
		 * old node (the node we're trying to lock).
		 *
		 * After we take the intent lock on the node we want (which
		 * protects against it being freed), we check if we might have
		 * raced (and the node was freed before we locked it) with a
		 * global sequence number for freed btree nodes.
		 */
		if (btree_node_read_locked(iter, level + 1))
			btree_node_unlock(iter, level + 1);

		if (!btree_node_lock(b, iter, level,
				     PTR_HASH(&b->key) != PTR_HASH(k))) {
			if (!btree_node_relock(iter, level + 1)) {
				trace_bcache_btree_intent_lock_fail(b, iter);
				return ERR_PTR(-EINTR);
			}

			goto retry;
		}

		BUG_ON(b->level != level);
	}

	b->accessed = 1;

	for (; i <= b->keys.nsets; i++) {
		prefetch(b->keys.set[i].tree);
		prefetch(b->keys.set[i].data);
	}

	if (btree_node_io_error(b)) {
		__btree_node_unlock(iter, level, b);
		return ERR_PTR(-EIO);
	}

	BUG_ON(!b->written);

	return b;
}

/* Btree alloc */

void btree_node_free(struct cache_set *c, struct btree *b)
{
	struct bch_extent_ptr *ptr;
	struct cache *ca;
	BKEY_PADDED(k) tmp;

	bkey_copy(&tmp.k, &b->key);

	trace_bcache_btree_node_free(b);

	BUG_ON(b == btree_node_root(b));
	BUG_ON(b->ob);

	if (btree_node_dirty(b))
		btree_complete_write(c, b, btree_current_write(b));
	clear_btree_node_dirty(b);
	cancel_delayed_work(&b->work);

	if (!list_empty_careful(&b->journal_seq_blacklisted)) {
		mutex_lock(&c->journal.blacklist_lock);
		list_del_init(&b->journal_seq_blacklisted);
		mutex_unlock(&c->journal.blacklist_lock);
	}

	six_lock_write(&b->lock);

	mutex_lock(&c->btree_cache_lock);
	mca_bucket_free(c, b);
	mutex_unlock(&c->btree_cache_lock);

	six_unlock_write(&b->lock);

	rcu_read_lock();
	extent_for_each_online_device(c, bkey_i_to_s_extent(&tmp.k), ptr, ca)
		bch_unmark_meta_bucket(ca, PTR_BUCKET(ca, ptr));
	rcu_read_unlock();
}

/**
 * bch_btree_set_root - update the root in memory and on disk
 *
 * To ensure forward progress, the current task must not be holding any
 * btree node write locks. However, you must hold an intent lock on the
 * old root.
 *
 * Frees the old root.
 *
 * Note: This allocates a journal entry but doesn't add any keys to
 * it.  All the btree roots are part of every journal write, so there
 * is nothing new to be done.  This just guarantees that there is a
 * journal write.
 */
static void bch_btree_set_root(struct cache_set *c, struct btree *b)
{
	struct journal_res res;
	struct btree *old;

	memset(&res, 0, sizeof(res));

	trace_bcache_btree_set_root(b);
	BUG_ON(!b->written);

	old = btree_node_root(b);
	if (old) {
		/*
		 * Ensure no one is using the old root while we switch to the
		 * new root:
		 */
		six_lock_write(&old->lock);
	}

	/* Root nodes cannot be reaped */
	mutex_lock(&c->btree_cache_lock);
	list_del_init(&b->list);
	mutex_unlock(&c->btree_cache_lock);

	spin_lock(&c->btree_root_lock);
	btree_node_root(b) = b;

	if (b->btree_id != c->gc_cur_btree
	    ? b->btree_id < c->gc_cur_btree
	    : b->level <= c->gc_cur_level) {
		struct bch_extent_ptr *ptr;
		struct cache *ca;

		rcu_read_lock();
		extent_for_each_online_device(c, bkey_i_to_s_extent(&b->key), ptr, ca)
			bch_mark_metadata_bucket(ca, PTR_BUCKET(ca, ptr), false);
		rcu_read_unlock();
	}
	spin_unlock(&c->btree_root_lock);

	bch_recalc_btree_reserve(c);

	if (old) {
		struct closure cl;

		closure_init_stack(&cl);

		/*
		 * Unlock old root after new root is visible:
		 *
		 * The new root isn't persistent, but that's ok: we still have
		 * an intent lock on the new root, and any updates that would
		 * depend on the new root would have to update the new root.
		 */
		six_unlock_write(&old->lock);

		/*
		 * Ensure new btree root is persistent (reachable via the
		 * journal) before returning and the caller unlocking it:
		 */
		bch_journal_meta(&c->journal, &cl);
		closure_sync(&cl);
	}
}

static struct btree *__bch_btree_node_alloc(struct cache_set *c,
					    bool check_enospc,
					    struct closure *cl)
{
	struct open_bucket *ob;
	struct btree *b;

	ob = bch_open_bucket_alloc(c, &c->btree_write_point, check_enospc, cl);
	if (IS_ERR(ob))
		return ERR_CAST(ob);

	spin_unlock(&ob->lock);

	b = mca_alloc(c, NULL, 0, 0, NULL);

	/* we hold cannibalize_lock: */
	BUG_ON(IS_ERR_OR_NULL(b));
	BUG_ON(b->ob);

	bkey_extent_init(&b->key);
	memcpy(&b->key.v, ob->ptrs,
	       sizeof(struct bch_extent_ptr) * ob->nr_ptrs);
	bch_set_extent_ptrs(bkey_i_to_s_extent(&b->key), ob->nr_ptrs);

	b->ob = ob;

	return b;
}

static struct btree *bch_btree_node_alloc(struct cache_set *c,
					  unsigned level, enum btree_id id,
					  struct btree_reserve *reserve)
{
	struct btree *b;

	BUG_ON(!reserve->nr);

	b = reserve->b[--reserve->nr];

	mutex_lock(&c->btree_cache_lock);
	mca_hash_insert(c, b, level, id);
	mutex_unlock(&c->btree_cache_lock);

	b->accessed = 1;
	set_btree_node_dirty(b);

	bch_bset_init_first(&b->keys, &b->data->keys);
	b->data->magic = bset_magic(&c->sb);
	SET_BSET_BTREE_LEVEL(&b->data->keys, level);

	bch_check_mark_super(c, &b->key, true);

	trace_bcache_btree_node_alloc(b);
	return b;
}

struct btree *__btree_node_alloc_replacement(struct cache_set *c,
					     struct btree *b,
					     struct bkey_format format,
					     struct btree_reserve *reserve)
{
	struct btree *n;

	n = bch_btree_node_alloc(c, b->level, b->btree_id, reserve);

	n->data->min_key	= b->data->min_key;
	n->data->max_key	= b->data->max_key;
	n->data->format		= format;
	n->keys.format		= format;

	bch_btree_sort_into(&n->keys, &b->keys,
			    b->keys.ops->key_normalize,
			    &c->sort);

	n->key.k.p = b->key.k.p;
	trace_bcache_btree_node_alloc_replacement(b, n);

	return n;
}

void __bch_btree_calc_format(struct bkey_format_state *s, struct btree *b)
{
	struct btree_node_iter iter;
	struct bkey_tup tup;

	for_each_btree_node_key_unpack(&b->keys, &tup, &iter)
		bch_bkey_format_add_key(s, &tup.k);

	if (b->keys.ops->is_extents) {
		/*
		 * Extents need special consideration because of
		 * bch_insert_fixup_extent() - they have to be modified in
		 * place, and successfully repack, when insert an overlapping
		 * extent:
		 */
		bch_bkey_format_add_pos(s, b->data->min_key);
		bch_bkey_format_add_pos(s, b->data->max_key);

		/*
		 * If we span multiple inodes, need to be able to store an
		 * offset of 0:
		 */
		if (s->field_min[BKEY_FIELD_INODE] !=
		    s->field_max[BKEY_FIELD_INODE])
			s->field_min[BKEY_FIELD_OFFSET] = 0;

		/* Make sure we can store a size of 0: */
		s->field_min[BKEY_FIELD_SIZE] = 0;
	}
}

static struct bkey_format bch_btree_calc_format(struct btree *b)
{
	struct bkey_format_state s;

	bch_bkey_format_init(&s);
	__bch_btree_calc_format(&s, b);

	return bch_bkey_format_done(&s);
}

struct btree *btree_node_alloc_replacement(struct cache_set *c,
					   struct btree *b,
					   struct btree_reserve *reserve)
{
	struct bkey_format new_f = bch_btree_calc_format(b);

	/*
	 * The keys might expand with the new format - if they wouldn't fit in
	 * the btree node anymore, use the old format for now:
	 */
	if (!btree_node_format_fits(b, &new_f))
		new_f = b->keys.format;

	return __btree_node_alloc_replacement(c, b, new_f, reserve);
}

void bch_btree_reserve_put(struct cache_set *c, struct btree_reserve *reserve)
{
	while (reserve->nr) {
		struct btree *b = reserve->b[--reserve->nr];
		struct open_bucket *ob = b->ob;

		b->ob = NULL;

		/* Mark that it's not actually hashed: */
		bkey_i_to_extent(&b->key)->v.ptr->_val = 0;

		mutex_lock(&c->btree_cache_lock);
		list_move(&b->list, &c->btree_cache_freeable);
		mutex_unlock(&c->btree_cache_lock);

		six_unlock_write(&b->lock);
		six_unlock_intent(&b->lock);

		bch_open_bucket_put(c, ob);
	}

	mempool_free(reserve, &c->btree_reserve_pool);
}

static struct btree_reserve *__bch_btree_reserve_get(struct cache_set *c,
					bool check_enospc,
					unsigned nr_nodes,
					struct closure *cl)
{
	struct btree_reserve *reserve;
	struct btree *b;
	int ret;

	BUG_ON(nr_nodes > BTREE_RESERVE_MAX);

	/*
	 * Protects reaping from the btree node cache and using the btree node
	 * open bucket reserve:
	 */
	ret = mca_cannibalize_lock(c, cl);
	if (ret)
		return ERR_PTR(ret);

	reserve = mempool_alloc(&c->btree_reserve_pool, GFP_NOIO);

	reserve->nr = 0;

	while (reserve->nr < nr_nodes) {
		b = __bch_btree_node_alloc(c, check_enospc, cl);
		if (IS_ERR(b)) {
			ret = PTR_ERR(b);
			goto err_free;
		}

		reserve->b[reserve->nr++] = b;
	}

	mca_cannibalize_unlock(c);
	return reserve;
err_free:
	bch_btree_reserve_put(c, reserve);
	mca_cannibalize_unlock(c);
	trace_bcache_btree_reserve_get_fail(c, nr_nodes, cl);
	return ERR_PTR(ret);
}

struct btree_reserve *bch_btree_reserve_get(struct cache_set *c,
					    struct btree *b,
					    struct btree_iter *iter,
					    unsigned extra_nodes,
					    bool check_enospc)
{
	unsigned depth = btree_node_root(b)->level - b->level;
	unsigned nr_nodes = btree_reserve_required_nodes(depth) + extra_nodes;

	return __bch_btree_reserve_get(c, check_enospc, nr_nodes,
				       iter ? &iter->cl : NULL);

}

static struct btree *__btree_root_alloc(struct cache_set *c, unsigned level,
					enum btree_id id,
					struct btree_reserve *reserve)
{
	struct btree *b = bch_btree_node_alloc(c, level, id, reserve);

	b->data->min_key = POS_MIN;
	b->data->max_key = POS_MAX;
	b->data->format = bch_btree_calc_format(b);
	b->key.k.p = POS_MAX;

	six_unlock_write(&b->lock);

	return b;
}

int bch_btree_root_alloc(struct cache_set *c, enum btree_id id,
			 struct closure *writes)
{
	struct closure cl;
	struct btree_reserve *reserve;
	struct btree *b;

	closure_init_stack(&cl);

	while (1) {
		reserve = __bch_btree_reserve_get(c, true, 1, &cl);
		if (!IS_ERR(reserve))
			break;

		if (PTR_ERR(reserve) == -ENOSPC)
			return PTR_ERR(reserve);

		closure_sync(&cl);
	}

	b = __btree_root_alloc(c, 0, id, reserve);
	bch_btree_reserve_put(c, reserve);

	bch_btree_node_write(b, writes, NULL);

	bch_btree_set_root(c, b);
	btree_open_bucket_put(c, b);
	six_unlock_intent(&b->lock);

	return 0;
}

int bch_btree_root_read(struct cache_set *c, enum btree_id id,
			const struct bkey_i *k, unsigned level)
{
	struct closure cl;
	struct btree *b;

	closure_init_stack(&cl);

	while (IS_ERR(b = mca_alloc(c, k, level, id, &cl))) {
		BUG_ON(PTR_ERR(b) != -EAGAIN);
		closure_sync(&cl);
	}
	BUG_ON(!b);

	bch_btree_node_read(c, b);
	six_unlock_write(&b->lock);

	if (btree_node_io_error(b)) {
		six_unlock_intent(&b->lock);
		return -EIO;
	}

	bch_btree_set_root(c, b);
	six_unlock_intent(&b->lock);

	return 0;
}

/**
 * bch_btree_node_rewrite - Rewrite/move a btree node
 *
 * Returns 0 on success, -EINTR or -EAGAIN on failure (i.e.
 * btree_check_reserve() has to wait)
 */
int bch_btree_node_rewrite(struct btree *b, struct btree_iter *iter, bool wait)
{
	struct cache_set *c = iter->c;
	struct btree *n, *parent = iter->nodes[b->level + 1];
	struct btree_reserve *reserve;
	struct closure cl;
	int ret;

	closure_init_stack(&cl);

	iter->locks_want = BTREE_MAX_DEPTH;
	if (!bch_btree_iter_upgrade(iter))
		return -EINTR;

	reserve = bch_btree_reserve_get(c, b, wait ? iter : NULL, 1, true);
	if (IS_ERR(reserve)) {
		trace_bcache_btree_gc_rewrite_node_fail(b);
		return PTR_ERR(reserve);
	}

	bch_btree_push_journal_seq(c, b, &cl);

	n = btree_node_alloc_replacement(c, b, reserve);
	six_unlock_write(&n->lock);

	trace_bcache_btree_gc_rewrite_node(b);

	bch_btree_node_write(n, &cl, NULL);
	closure_sync(&cl);

	if (parent) {
		ret = bch_btree_insert_node(parent, iter,
					    &keylist_single(&n->key),
					    NULL, NULL,
					    BTREE_INSERT_NOFAIL,
					    reserve);
		BUG_ON(ret);
	} else {
		bch_btree_set_root(c, n);
	}

	btree_open_bucket_put(iter->c, n);
	btree_node_free(iter->c, b);

	BUG_ON(iter->nodes[b->level] != b);

	six_unlock_intent(&b->lock);
	btree_iter_node_set(iter, n);
	bch_btree_reserve_put(c, reserve);
	return 0;
}

static void btree_node_flush(struct journal_entry_pin *pin)
{
	struct btree_write *w = container_of(pin, struct btree_write, journal);
	struct btree *b = container_of(w, struct btree, writes[w->index]);

	six_lock_read(&b->lock);
	__bch_btree_node_write(b, NULL, w->index);
	six_unlock_read(&b->lock);
}

/* Btree insertion */

/**
 * bch_btree_insert_and_journal - insert a non-overlapping key into a btree node
 *
 * This is called from bch_insert_fixup_extent().
 *
 * The insert is journalled.
 */
void bch_btree_insert_and_journal(struct cache_set *c, struct btree *b,
				  struct btree_node_iter *node_iter,
				  struct bkey_i *insert,
				  struct journal_res *res)
{
	bch_bset_insert(&b->keys, node_iter, insert);

	if (!btree_node_dirty(b)) {
		set_btree_node_dirty(b);

		if (c->btree_flush_delay)
			schedule_delayed_work(&b->work,
					      c->btree_flush_delay * HZ);
	}

	if (res->ref ||
	    !test_bit(JOURNAL_REPLAY_DONE, &c->journal.flags)) {
		struct btree_write *w = btree_current_write(b);

		if (!w->have_pin) {
			journal_pin_add(&c->journal,
					c->journal.cur_pin_list,
					&w->journal,
					btree_node_flush);
			w->have_pin = true;
		}
	}

	if (res->ref) {
		bch_journal_add_keys(&c->journal, res, b->btree_id,
				     insert, b->level);
		btree_bset_last(b)->journal_seq = c->journal.seq;
	}
}

/**
 * btree_insert_key - insert a key into a btree node, handling overlapping extents.
 *
 * The insert is journalled.
 *
 * @iter:		btree iterator
 * @insert_keys:	list of keys to insert
 * @replace:		old key for for exchange (+ stats)
 * @res:		journal reservation
 * @flags:		FAIL_IF_STALE
 *
 * Inserts the first key from @insert_keys
 */
static bool btree_insert_key(struct btree_iter *iter, struct btree *b,
			     struct keylist *insert_keys,
			     struct bch_replace_info *replace,
			     struct journal_res *res, unsigned flags)
{
	bool dequeue = false;
	struct btree_node_iter *node_iter = &iter->node_iters[b->level];
	struct bkey_i *insert = bch_keylist_front(insert_keys), *orig = insert;
	BKEY_PADDED(key) temp;
	struct bpos done;
	s64 newsize, oldsize = bch_count_data(&b->keys);
	bool do_insert;

	BUG_ON(bkey_deleted(&insert->k) && bkey_val_u64s(&insert->k));
	BUG_ON(!b->level &&
	       bkey_cmp(bkey_start_pos(&insert->k), iter->pos) < 0);
	bch_btree_node_iter_verify(node_iter, &b->keys);

	if (b->level) {
		BUG_ON(bkey_cmp(insert->k.p, b->key.k.p) > 0);

		do_insert = bch_insert_fixup_btree_ptr(iter->c, b, insert,
						       node_iter, replace,
						       &done, res);
		dequeue = true;
	} else if (!b->keys.ops->is_extents) {
		BUG_ON(bkey_cmp(insert->k.p, b->key.k.p) > 0);

		do_insert = bch_insert_fixup_key(iter->c, b, insert, node_iter,
						 replace, &done, res);
		dequeue = true;
	} else {
		bkey_copy(&temp.key, insert);
		insert = &temp.key;

		if (bkey_cmp(insert->k.p, b->key.k.p) > 0)
			bch_cut_back(b->key.k.p, &insert->k);

		do_insert = bch_insert_fixup_extent(iter->c, b, insert,
						    node_iter, replace,
						    &done, res, flags);
		bch_cut_front(done, orig);
		dequeue = (orig->k.size == 0);
	}

	if (dequeue)
		bch_keylist_dequeue(insert_keys);

	newsize = bch_count_data(&b->keys);
	BUG_ON(newsize != -1 && newsize < oldsize);

	trace_bcache_btree_insert_key(b, insert, replace != NULL, do_insert);

	return do_insert;
}

enum btree_insert_status {
	BTREE_INSERT_NO_INSERT,
	BTREE_INSERT_INSERTED,
	BTREE_INSERT_NEED_SPLIT,
};

static bool have_enough_space(struct btree *b, struct keylist *insert_keys)
{
	/*
	 * For updates to interior nodes, everything on the
	 * keylist has to be inserted atomically.
	 *
	 * For updates to extents, bch_insert_fixup_extent()
	 * needs room for at least three keys to make forward
	 * progress.
	 */
	unsigned u64s = b->level
		? bch_keylist_nkeys(insert_keys)
		: b->keys.ops->is_extents
		? BKEY_EXTENT_MAX_U64s * 3
		: bch_keylist_front(insert_keys)->k.u64s;

	return u64s <= bch_btree_keys_u64s_remaining(b);
}

static void verify_keys_sorted(struct keylist *l)
{
#ifdef CONFIG_BCACHEFS_DEBUG
	struct bkey_i *k;

	for (k = l->bot;
	     k < l->top && bkey_next(k) < l->top;
	     k = bkey_next(k))
		BUG_ON(bkey_cmp(k->k.p, bkey_next(k)->k.p) > 0);
#endif
}

/**
 * bch_btree_insert_keys - insert keys from @insert_keys into btree node @b,
 * until the node is full.
 *
 * If keys couldn't be inserted because @b was full, the caller must split @b
 * and bch_btree_insert_keys() will be called again from btree_split().
 *
 * Caller must either be holding an intent lock on this node only, or intent
 * locks on all nodes all the way up to the root. Caller must not be holding
 * read locks on any nodes.
 */
static enum btree_insert_status
bch_btree_insert_keys(struct btree *b,
		      struct btree_iter *iter,
		      struct keylist *insert_keys,
		      struct bch_replace_info *replace,
		      u64 *journal_seq, unsigned flags)
{
	bool done = false, inserted = false, need_split = false;
	struct journal_res res = { 0, 0 };
	struct bkey_i *k = bch_keylist_front(insert_keys);

	verify_keys_sorted(insert_keys);
	BUG_ON(!btree_node_intent_locked(iter, b->level));
	BUG_ON(iter->nodes[b->level] != b);

	while (!done && !bch_keylist_empty(insert_keys)) {
		/*
		 * We need room to insert at least two keys in the journal
		 * reservation -- the insert key itself, as well as a subset
		 * of it, in the bkey_cmpxchg() or handle_existing_key_newer()
		 * cases
		 */
		unsigned n_min = bch_keylist_front(insert_keys)->k.u64s;
		unsigned n_max = bch_keylist_nkeys(insert_keys);

		unsigned actual_min = jset_u64s(n_min) * 2;
		unsigned actual_max = max_t(unsigned, actual_min,
					    jset_u64s(n_max));

		if (!b->level &&
		    test_bit(JOURNAL_REPLAY_DONE, &iter->c->journal.flags))
			bch_journal_res_get(&iter->c->journal, &res,
					    actual_min, actual_max);

		/* just wrote a set? */
		if (btree_node_need_init_next(b))
do_init_next:		bch_btree_init_next(iter->c, b, iter);

		six_lock_write(&b->lock);

		/*
		 * Recheck after taking the write lock, because it can be set
		 * (because of the btree node being written) with only a read
		 * lock:
		 */
		if (btree_node_need_init_next(b)) {
			six_unlock_write(&b->lock);
			goto do_init_next;
		}

		while (!bch_keylist_empty(insert_keys)) {
			k = bch_keylist_front(insert_keys);

			/* finished for this node */
			if (b->keys.ops->is_extents
			    ? bkey_cmp(bkey_start_pos(&k->k), b->key.k.p) >= 0
			    : bkey_cmp(k->k.p, b->key.k.p) > 0) {
				done = true;
				break;
			}

			if (!have_enough_space(b, insert_keys)) {
				done = true;
				need_split = true;
				break;
			}

			if (!b->level && journal_res_full(&res, &k->k))
				break;

			if (btree_insert_key(iter, b, insert_keys,
					     replace, &res, flags)) {
				inserted = true;
				if (journal_seq)
					*journal_seq = iter->c->journal.seq;
			}
		}

		six_unlock_write(&b->lock);

		if (res.ref)
			bch_journal_res_put(&iter->c->journal, &res);
	}

	if (inserted && b->written) {
		/*
		 * Force write if set is too big (or if it's an interior
		 * node, since those aren't journalled yet)
		 */
		if (b->level)
			bch_btree_node_write_sync(b, iter);
		else {
			struct btree_node_entry *bne =
				container_of(btree_bset_last(b),
					     struct btree_node_entry, keys);
			unsigned long bytes = __set_bytes(bne, bne->keys.u64s);

			if (b->io_mutex.count > 0 &&
			    ((max(roundup(bytes, block_bytes(iter->c)),
				  PAGE_SIZE) - bytes < 48) ||
			     bytes > (16 << 10)))
				bch_btree_node_write(b, NULL, iter);
		}
	}

	iter->lock_seq[b->level] = b->lock.state.seq;

	BUG_ON(!bch_keylist_empty(insert_keys) && inserted && b->level);

	return need_split ? BTREE_INSERT_NEED_SPLIT :
		 inserted ? BTREE_INSERT_INSERTED : BTREE_INSERT_NO_INSERT;
}

struct btree_split_state {
	struct closure		stack_cl;
	struct keylist		parent_keys;
	struct btree_reserve	*reserve;
};

static int __bch_btree_insert_node(struct btree *, struct btree_iter *,
				   struct keylist *, struct bch_replace_info *,
				   u64 *, unsigned, struct btree_split_state *);

static void btree_split(struct btree *b, struct btree_iter *iter,
			struct keylist *insert_keys, unsigned flags,
			struct btree_split_state *state)
{
	struct cache_set *c = iter->c;
	struct btree *parent = iter->nodes[b->level + 1];
	struct btree *n1, *n2 = NULL, *n3 = NULL;
	struct bset *set1, *set2;
	uint64_t start_time = local_clock();
	struct bkey_packed *k;
	enum btree_insert_status status;
	unsigned u64s_to_insert = b->level
		? bch_keylist_nkeys(insert_keys) : 0;

	BUG_ON(!parent && (b != btree_node_root(b)));
	BUG_ON(!btree_node_intent_locked(iter, btree_node_root(b)->level));

	bch_btree_push_journal_seq(c, b, &state->stack_cl);

	n1 = btree_node_alloc_replacement(c, b, state->reserve);
	set1 = btree_bset_first(n1);

	if (__set_blocks(n1->data,
			 n1->data->keys.u64s + u64s_to_insert,
			 block_bytes(n1->c)) > btree_blocks(c) * 3 / 4) {
		size_t nr_packed = 0, nr_unpacked = 0;

		trace_bcache_btree_node_split(b, set1->u64s);

		n2 = bch_btree_node_alloc(c, b->level,
					  iter->btree_id,
					  state->reserve);
		n2->data->max_key = n1->data->max_key;
		n2->keys.format = n1->keys.format;
		set2 = btree_bset_first(n2);

		if (!parent)
			n3 = __btree_root_alloc(c, b->level + 1,
						iter->btree_id,
						state->reserve);

		/*
		 * Has to be a linear search because we don't have an auxiliary
		 * search tree yet
		 */
		k = set1->start;
		while (1) {
			if (bkey_packed(k))
				nr_packed++;
			else
				nr_unpacked++;
			if (k->_data - set1->_data >= (set1->u64s * 3) / 5)
				break;
			k = bkey_next(k);
		}

		n1->key.k.p = bkey_unpack_key(&n1->keys.format, k).p;
		k = bkey_next(k);

		n1->data->max_key = n1->key.k.p;
		n2->data->min_key =
			__bch_btree_iter_advance_pos(iter, n1->key.k.p);

		set2->u64s = (u64 *) bset_bkey_last(set1) - (u64 *) k;
		set1->u64s -= set2->u64s;

		n2->keys.nr.live_u64s = set2->u64s;
		n2->keys.nr.packed_keys
			= n1->keys.nr.packed_keys - nr_packed;
		n2->keys.nr.unpacked_keys
			= n1->keys.nr.unpacked_keys - nr_unpacked;

		n1->keys.nr.live_u64s = set1->u64s;
		n1->keys.nr.packed_keys = nr_packed;
		n1->keys.nr.unpacked_keys = nr_unpacked;

		BUG_ON(!set1->u64s);
		BUG_ON(!set2->u64s);

		memcpy(set2->start,
		       bset_bkey_last(set1),
		       set2->u64s * sizeof(u64));

		n2->key.k.p = b->key.k.p;

		n1->keys.set->size = 0;
		n2->keys.set->size = 0;

		six_unlock_write(&n1->lock);
		six_unlock_write(&n2->lock);

		bch_verify_btree_nr_keys(&n1->keys);
		bch_verify_btree_nr_keys(&n2->keys);

		/*
		 * For updates to interior nodes, we've got to do the insert
		 * before we split because the stuff we're inserting has to be
		 * inserted atomically. Post split, the keys might have to go in
		 * different nodes and the split would no longer be atomic.
		 */
		if (b->level) {
			btree_iter_node_set(iter, n1);
			status = bch_btree_insert_keys(n1, iter, insert_keys,
						       NULL, NULL, 0);
			BUG_ON(status == BTREE_INSERT_NEED_SPLIT);

			btree_iter_node_set(iter, n2);
			status = bch_btree_insert_keys(n2, iter, insert_keys,
						       NULL, NULL, 0);
			BUG_ON(status == BTREE_INSERT_NEED_SPLIT);
			BUG_ON(!bch_keylist_empty(insert_keys));
			iter->nodes[b->level] = b; /* still have b locked */
		}

		/*
		 * Note that on recursive parent_keys == insert_keys, so we
		 * can't start adding new keys to parent_keys before emptying it
		 * out (by doing the insert, which we just did above)
		 */
		bch_keylist_add(&state->parent_keys, &n1->key);
		bch_keylist_add(&state->parent_keys, &n2->key);

		bch_btree_node_write(n2, &state->stack_cl, NULL);

		/*
		 * Just created a new node - if gc is still going to visit the
		 * old node, but not the node we just created, mark it:
		 */
		six_lock_write(&b->lock);
		if (gc_will_visit_node(c, n2) &&
		    !gc_will_visit_node(c, n1))
			btree_gc_mark_node(c, n1, NULL);
		six_unlock_write(&b->lock);
	} else {
		trace_bcache_btree_node_compact(b, set1->u64s);
		six_unlock_write(&n1->lock);

		if (b->level) {
			btree_iter_node_set(iter, n1);
			status = bch_btree_insert_keys(n1, iter, insert_keys,
						       NULL, NULL, 0);
			BUG_ON(status != BTREE_INSERT_INSERTED);
			BUG_ON(!bch_keylist_empty(insert_keys));
			iter->nodes[b->level] = b; /* still have b locked */
		}

		bch_keylist_add(&state->parent_keys, &n1->key);
	}

	bch_btree_node_write(n1, &state->stack_cl, NULL);

	if (n3) {
		/* Depth increases, make a new root */
		mark_btree_node_intent_locked(iter, n3->level);

		/* once for bch_btree_insert_keys(): */
		btree_iter_node_set(iter, n3);

		bch_btree_insert_keys(n3, iter, &state->parent_keys,
				      NULL, NULL, 0);
		bch_btree_node_write(n3, &state->stack_cl, NULL);

		/*
		 * then again so the node iterator points to the keys we just
		 * inserted:
		 */
		btree_iter_node_set(iter, n3);

		closure_sync(&state->stack_cl);

		bch_btree_set_root(c, n3);
	} else if (!parent) {
		BUG_ON(state->parent_keys.start_keys_p !=
		       state->parent_keys.inline_keys);
		bch_keylist_init(&state->parent_keys);

		/* Root filled up but didn't need to be split */
		closure_sync(&state->stack_cl);

		bch_btree_set_root(c, n1);
	} else {
		int ret;

		/* Split a non root node */
		closure_sync(&state->stack_cl);

		ret = __bch_btree_insert_node(parent, iter, &state->parent_keys,
					      NULL, NULL, BTREE_INSERT_NOFAIL,
					      state);
		BUG_ON(ret || !bch_keylist_empty(&state->parent_keys));
	}

	btree_open_bucket_put(c, n1);
	if (n2)
		btree_open_bucket_put(c, n2);
	if (n3)
		btree_open_bucket_put(c, n3);

	btree_node_free(c, b);

	/* Update iterator, and finish insert now that new nodes are visible: */
	BUG_ON(iter->nodes[b->level] != b);
	six_unlock_intent(&b->lock);

	if (n2 && bkey_cmp(iter->pos, n1->key.k.p) > 0) {
		six_unlock_intent(&n1->lock);
		btree_iter_node_set(iter, n2);
	} else if (n2) {
		six_unlock_intent(&n2->lock);
		btree_iter_node_set(iter, n1);
	} else {
		btree_iter_node_set(iter, n1);
	}

	bch_time_stats_update(&c->btree_split_time, start_time);
}

static int __bch_btree_insert_node(struct btree *b,
				   struct btree_iter *iter,
				   struct keylist *insert_keys,
				   struct bch_replace_info *replace,
				   u64 *journal_seq, unsigned flags,
				   struct btree_split_state *state)
{
	BUG_ON(iter->nodes[b->level] != b);
	BUG_ON(!btree_node_intent_locked(iter, b->level));
	BUG_ON(b->level &&
	       !btree_node_intent_locked(iter, btree_node_root(b)->level));
	BUG_ON(b->level && replace);
	BUG_ON(b->level && !state->reserve);
	BUG_ON(!b->written);

	if (bch_btree_insert_keys(b, iter, insert_keys, replace, journal_seq,
				  flags) == BTREE_INSERT_NEED_SPLIT) {
		if (!b->level) {
			struct btree_reserve *res;

			BUG_ON(state->reserve);

			/*
			 * XXX: figure out how far we might need to split,
			 * instead of locking/reserving all the way to the root:
			 */

			iter->locks_want = BTREE_MAX_DEPTH;
			if (!bch_btree_iter_upgrade(iter))
				return -EINTR;

			res = bch_btree_reserve_get(iter->c, b, iter, 0,
						!(flags & BTREE_INSERT_NOFAIL));
			if (IS_ERR(res))
				return PTR_ERR(res);

			state->reserve = res;
		}

		btree_split(b, iter, insert_keys, flags, state);

		if (!b->level) {
			bch_btree_reserve_put(iter->c, state->reserve);
			state->reserve = NULL;
		}
	}

	return 0;
}

/**
 * bch_btree_insert_node - insert bkeys into a given btree node
 *
 * @iter:		btree iterator
 * @insert_keys:	list of keys to insert
 * @replace:		old key for compare exchange (+ stats)
 * @persistent:		if not null, @persistent will wait on journal write
 * @flags:		FAIL_IF_STALE
 *
 * Inserts as many keys as it can into a given btree node, splitting it if full.
 * If a split occurred, this function will return early. This can only happen
 * for leaf nodes -- inserts into interior nodes have to be atomic.
 */
int bch_btree_insert_node(struct btree *b,
			  struct btree_iter *iter,
			  struct keylist *insert_keys,
			  struct bch_replace_info *replace,
			  u64 *journal_seq, unsigned flags,
			  struct btree_reserve *reserve)
{
	struct btree_split_state state;

	closure_init_stack(&state.stack_cl);
	bch_keylist_init(&state.parent_keys);
	state.reserve = reserve;

	if (replace)
		flags |= FAIL_IF_STALE;

	return __bch_btree_insert_node(b, iter, insert_keys, replace,
				       journal_seq, flags, &state);
}

/**
 * bch_btree_insert_at - insert bkeys starting at a given btree node
 * @iter:		btree iterator
 * @insert_keys:	list of keys to insert
 * @replace:		old key for compare exchange (+ stats)
 * @persistent:		if not null, @persistent will wait on journal write
 * @flags:		BTREE_INSERT_ATOMIC | FAIL_IF_STALE
 *
 * The FAIL_IF_STALE flag is set automatically if @replace is not NULL.
 *
 * This is top level for common btree insertion/index update code. The control
 * flow goes roughly like:
 *
 * bch_btree_insert_at -- split keys that span interior nodes
 *   bch_btree_insert_node -- split btree nodes when full
 *     btree_split
 *     bch_btree_insert_keys -- get and put journal reservations
 *       btree_insert_key -- call fixup and remove key from keylist
 *         bch_insert_fixup_extent -- handle overlapping extents
 *           bch_btree_insert_and_journal -- add the key to the journal
 *             bch_bset_insert -- actually insert into the bset
 *
 * This function will split keys that span multiple nodes, calling
 * bch_btree_insert_node() for each one. It will not return until all keys
 * have been inserted, or an insert has failed.
 *
 * @persistent will only wait on the journal write if the full keylist was
 * inserted.
 *
 * Return values:
 * -EINTR: locking changed, this function should be called again.
 * -EROFS: cache set read only
 */
int bch_btree_insert_at(struct btree_iter *iter,
			struct keylist *insert_keys,
			struct bch_replace_info *replace,
			u64 *journal_seq, unsigned flags)
{
	int ret = -EINTR;

	BUG_ON(iter->level);

	if (!percpu_ref_tryget(&iter->c->writes))
		return -EROFS;

	iter->locks_want = 0;
	if (!bch_btree_iter_upgrade(iter))
		goto traverse;

	while (1) {
		ret = bch_btree_insert_node(iter->nodes[0], iter, insert_keys,
					    replace, journal_seq, flags, NULL);

		/*
		 * We don't test against success because we might have
		 * successfully inserted the keys on the keylist, but have more
		 * to insert in the next leaf node:
		 */
		if (likely(bch_keylist_empty(insert_keys)))
			break;

		/*
		 * -EAGAIN means we have to drop locks and wait on
		 *  mca_cannibalize_lock - btree_iter_unlock() does this
		 */
		if (ret == -EAGAIN)
			bch_btree_iter_unlock(iter);
		else if (ret && ret != -EINTR)
			break;
traverse:
		/*
		 * Can't retry, make sure we return an error:
		 */
		if (flags & BTREE_INSERT_ATOMIC) {
			ret = ret ?: -EINTR;
			break;
		}

		bch_btree_iter_set_pos(iter,
			bkey_start_pos(&bch_keylist_front(insert_keys)->k));

		ret = bch_btree_iter_traverse(iter);
		if (ret)
			break;
	}
	percpu_ref_put(&iter->c->writes);

	return ret;
}

/**
 * bch_btree_insert_check_key - insert dummy key into btree
 *
 * We insert a random key on a cache miss, then compare exchange on it
 * once the cache promotion or backing device read completes. This
 * ensures that if this key is written to after the read, the read will
 * lose and not overwrite the key with stale data.
 *
 * Return values:
 * -EAGAIN: @iter->cl was put on a waitlist waiting for btree node allocation
 * -EINTR: btree node was changed while upgrading to write lock
 */
int bch_btree_insert_check_key(struct btree_iter *iter,
			       struct bkey_i *check_key)
{
	struct bkey_i_cookie *cookie;
	BKEY_PADDED(key) tmp;

	check_key->k.type = KEY_TYPE_COOKIE;
	set_bkey_val_bytes(&check_key->k, sizeof(struct bch_cookie));

	cookie = bkey_i_to_cookie(check_key);
	get_random_bytes(&cookie->v, sizeof(cookie->v));

	bkey_copy(&tmp.key, check_key);

	__btree_iter_node_set(iter, iter->nodes[0],
			      bkey_start_pos(&check_key->k));

	return bch_btree_insert_at(iter, &keylist_single(&tmp.key),
				   NULL, NULL, BTREE_INSERT_ATOMIC);
}

/**
 * bch_btree_insert - insert keys into the extent btree
 * @c:			pointer to struct cache_set
 * @id:			btree to insert into
 * @insert_keys:	list of keys to insert
 * @replace:		old key for compare exchange (+ stats)
 */
int bch_btree_insert(struct cache_set *c, enum btree_id id,
		     struct keylist *keys, struct bch_replace_info *replace,
		     struct closure *persistent, u64 *journal_seq, int flags)
{
	struct btree_iter iter;
	u64 jseq = 0;
	int ret, ret2;

	if (!journal_seq)
		journal_seq = &jseq;

	bch_btree_iter_init_intent(&iter, c, id,
				   bkey_start_pos(&bch_keylist_front(keys)->k));

	ret = bch_btree_iter_traverse(&iter);
	if (unlikely(ret))
		goto out;

	ret = bch_btree_insert_at(&iter, keys, replace,
				  journal_seq, flags);
out:	ret2 = bch_btree_iter_unlock(&iter);

	if (persistent)
		bch_journal_push_seq(&c->journal, *journal_seq, persistent);

	return ret ?: ret2;
}

/**
 * bch_btree_update - like bch_btree_insert(), but asserts that we're
 * overwriting an existing key
 */
int bch_btree_update(struct cache_set *c, enum btree_id id, struct bkey_i *k,
		     struct closure *persistent, u64 *journal_seq)
{
	struct btree_iter iter;
	struct bkey_s_c u;
	u64 jseq = 0;
	int ret, ret2;

	if (!journal_seq)
		journal_seq = &jseq;

	EBUG_ON(id == BTREE_ID_EXTENTS);

	bch_btree_iter_init_intent(&iter, c, id, k->k.p);

	ret = bch_btree_iter_traverse(&iter);
	if (unlikely(ret))
		goto out;

	u = bch_btree_iter_peek_with_holes(&iter);
	BUG_ON(!u.k || bkey_deleted(u.k));

	ret = bch_btree_insert_at(&iter, &keylist_single(k), NULL,
				  journal_seq, 0);
out:	ret2 = bch_btree_iter_unlock(&iter);

	if (persistent)
		bch_journal_push_seq(&c->journal, *journal_seq, persistent);

	return ret ?: ret2;
}

/* Btree iterator: */

int bch_btree_iter_unlock(struct btree_iter *iter)
{
	unsigned l;

	for (l = 0; l < ARRAY_SIZE(iter->nodes); l++)
		btree_node_unlock(iter, l);

	closure_sync(&iter->cl);

	return iter->error;
}

/* peek_all() doesn't skip deleted keys */
static inline struct bkey_s_c __btree_iter_peek_all(struct btree_iter *iter)
{
	const struct bkey_format *f = &iter->nodes[iter->level]->keys.format;
	struct bkey_packed *k =
		bch_btree_node_iter_peek_all(&iter->node_iters[iter->level],
					     &iter->nodes[iter->level]->keys);
	struct bkey_s_c ret;

	if (!k)
		return bkey_s_c_null;

	bkey_disassemble(&iter->tup, f, k);
	ret = bkey_tup_to_s_c(&iter->tup);

	if (expensive_debug_checks(iter->c))
		bkey_debugcheck(iter->c, iter->nodes[iter->level], ret);

	return ret;
}

static inline struct bkey_s_c __btree_iter_peek(struct btree_iter *iter)
{
	const struct bkey_format *f = &iter->nodes[iter->level]->keys.format;
	struct bkey_packed *k =
		bch_btree_node_iter_peek(&iter->node_iters[iter->level],
					 &iter->nodes[iter->level]->keys);
	struct bkey_s_c ret;

	if (!k)
		return bkey_s_c_null;

	bkey_disassemble(&iter->tup, f, k);
	ret = bkey_tup_to_s_c(&iter->tup);

	if (expensive_debug_checks(iter->c))
		bkey_debugcheck(iter->c, iter->nodes[iter->level], ret);

	return ret;
}

static inline void __btree_iter_next_all(struct btree_iter *iter)
{
	bch_btree_node_iter_next_all(&iter->node_iters[iter->level],
				     &iter->nodes[iter->level]->keys);
}

static bool btree_iter_cmp(struct btree_iter *iter,
			   struct bpos pos, struct bpos k)
{
	return iter->is_extents
		? bkey_cmp(pos, k) < 0
		: bkey_cmp(pos, k) <= 0;
}

static inline bool is_btree_node(struct btree_iter *iter, unsigned l)
{
	return ((unsigned long) iter->nodes[l]) > 1;
}

static void btree_iter_lock_root(struct btree_iter *iter, struct bpos pos)
{
	iter->nodes_locked		= 0;
	iter->nodes_intent_locked	= 0;
	memset(iter->nodes, 0, sizeof(iter->nodes));

	while (1) {
		struct btree *b = iter->c->btree_roots[iter->btree_id];

		iter->level = b->level;

		if (btree_node_lock(b, iter, iter->level,
				(b != iter->c->btree_roots[iter->btree_id]))) {
			__btree_iter_node_set(iter, b, pos);
			break;
		}
	}
}

static int btree_iter_down(struct btree_iter *iter, struct bpos pos)
{
	struct btree *b;
	struct bkey_s_c k = __btree_iter_peek(iter);
	BKEY_PADDED(k) tmp;

	bkey_reassemble(&tmp.k, k);

	b = bch_btree_node_get(iter, &tmp.k, iter->level - 1);
	if (unlikely(IS_ERR(b)))
		return PTR_ERR(b);

	--iter->level;
	__btree_iter_node_set(iter, b, pos);
	return 0;
}

static void btree_iter_up(struct btree_iter *iter)
{
	btree_node_unlock(iter, iter->level++);
}

/*
 * This is the main state machine for walking down the btree - walks down to a
 * specified depth
 */
static int __bch_btree_iter_traverse(struct btree_iter *iter, unsigned l,
				     struct bpos pos)
{
	if (!iter->nodes[iter->level])
		return 0;
retry:
	/*
	 * If the current node isn't locked, go up until we have a locked node
	 * or run out of nodes:
	 */
	while (iter->nodes[iter->level] &&
	       !(is_btree_node(iter, iter->level) &&
		 btree_node_relock(iter, iter->level) &&
		 btree_iter_cmp(iter, pos, iter->nodes[iter->level]->key.k.p)))
		btree_iter_up(iter);

	/*
	 * If we've got a btree node locked (i.e. we aren't about to relock the
	 * root) - advance its node iterator if necessary:
	 */
	if (iter->nodes[iter->level]) {
		struct bkey_s_c k;

		while ((k = __btree_iter_peek_all(iter)).k &&
		       !btree_iter_cmp(iter, pos, k.k->p))
			__btree_iter_next_all(iter);
	}

	/*
	 * Note: iter->nodes[iter->level] may be temporarily NULL here - that
	 * would indicate to other code that we got to the end of the btree,
	 * here it indicates that relocking the root failed - it's critical that
	 * btree_iter_lock_root() comes next and that it can't fail
	 */
	while (iter->level > l)
		if (iter->nodes[iter->level]) {
			int ret = btree_iter_down(iter, pos);

			if (unlikely(ret)) {
				bch_btree_iter_unlock(iter);

				/*
				 * We just dropped all our locks - so if we need
				 * intent locks, make sure to get them again:
				 */
				if (ret == -EAGAIN || ret == -EINTR) {
					bch_btree_iter_upgrade(iter);
					goto retry;
				}

				iter->error = ret;
				iter->level = BTREE_MAX_DEPTH;
				return ret;
			}
		} else {
			btree_iter_lock_root(iter, pos);
		}

	return 0;
}

static int bch_btree_iter_traverse(struct btree_iter *iter)
{
	return __bch_btree_iter_traverse(iter, iter->level, iter->pos);
}

/* Iterate across nodes (leaf and interior nodes) */

struct btree *bch_btree_iter_peek_node(struct btree_iter *iter)
{
	struct btree *b;

	BUG_ON(iter->is_extents);

	bch_btree_iter_traverse(iter);

	if ((b = iter->nodes[iter->level])) {
		BUG_ON(bkey_cmp(b->key.k.p, iter->pos) < 0);
		iter->pos = b->key.k.p;
	}

	return b;
}

struct btree *bch_btree_iter_next_node(struct btree_iter *iter)
{
	struct btree *b;
	int ret;

	BUG_ON(iter->is_extents);

	btree_iter_up(iter);

	if (!iter->nodes[iter->level])
		return NULL;

	/* parent node usually won't be locked: redo traversal if necessary */
	ret = bch_btree_iter_traverse(iter);
	if (ret)
		return NULL;

	b = iter->nodes[iter->level];

	if (bkey_cmp(iter->pos, b->key.k.p) < 0) {
		struct bpos pos = bkey_successor(iter->pos);

		__bch_btree_iter_traverse(iter, 0, pos);
		b = iter->nodes[iter->level];
	}

	iter->pos = b->key.k.p;

	return b;
}

/* Iterate across keys (in leaf nodes only) */

void bch_btree_iter_set_pos(struct btree_iter *iter, struct bpos new_pos)
{
	BUG_ON(bkey_cmp(new_pos, iter->pos) < 0);
	iter->pos = new_pos;
}

void bch_btree_iter_advance_pos(struct btree_iter *iter)
{
	bch_btree_iter_set_pos(iter,
		__bch_btree_iter_advance_pos(iter, iter->tup.k.p));
}

struct bkey_s_c bch_btree_iter_peek(struct btree_iter *iter)
{
	struct bkey_s_c k;
	struct bpos pos = iter->pos;
	int ret;

	while (1) {
		ret = __bch_btree_iter_traverse(iter, 0, pos);
		if (ret)
			return bkey_s_c_null;

		if (likely((k = __btree_iter_peek(iter)).k)) {
			BUG_ON(bkey_cmp(k.k->p, pos) < 0);
			return k;
		}

		pos = iter->nodes[0]->key.k.p;

		if (!bkey_cmp(pos, POS_MAX))
			return (struct bkey_s_c) { NULL, NULL };

		pos = __bch_btree_iter_advance_pos(iter, pos);
	}
}

struct bkey_s_c bch_btree_iter_peek_with_holes(struct btree_iter *iter)
{
	struct bkey_s_c k;
	struct bkey n;
	int ret;

	while (1) {
		ret = __bch_btree_iter_traverse(iter, 0, iter->pos);
		if (ret)
			return bkey_s_c_null;

		k = __btree_iter_peek_all(iter);
recheck:
		if (!k.k || bkey_cmp(bkey_start_pos(k.k), iter->pos) > 0) {
			/* hole */
			bkey_init(&n);
			n.p = iter->pos;

			if (!k.k)
				k.k = &iter->nodes[0]->key.k;

			if (iter->btree_id == BTREE_ID_EXTENTS) {
				if (n.p.offset == KEY_OFFSET_MAX) {
					iter->pos = bkey_successor(iter->pos);
					goto recheck;
				}

				bch_key_resize(&n,
				       min_t(u64, KEY_SIZE_MAX,
					     (k.k->p.inode == n.p.inode
					      ? bkey_start_offset(k.k)
					      : KEY_OFFSET_MAX) -
					     n.p.offset));

				BUG_ON(!n.size);
			}

			iter->tup.k = n;
			return bkey_tup_to_s_c(&iter->tup);
		} else if (!bkey_deleted(k.k)) {
			return k;
		} else {
			__btree_iter_next_all(iter);
		}
	}

	BUG_ON(!iter->error &&
	       (iter->btree_id != BTREE_ID_INODES
		? bkey_cmp(iter->pos, POS_MAX)
		: iter->pos.inode != KEY_INODE_MAX));

	return bkey_s_c_null;
}

void __bch_btree_iter_init(struct btree_iter *iter, struct cache_set *c,
			   enum btree_id btree_id, struct bpos pos,
			   int locks_want)
{
	closure_init_stack(&iter->cl);

	iter->level			= 0;
	iter->is_extents		= btree_id == BTREE_ID_EXTENTS;
	iter->nodes_locked		= 0;
	iter->nodes_intent_locked	= 0;
	iter->locks_want		= locks_want;
	iter->btree_id			= btree_id;
	iter->error			= 0;
	iter->c				= c;
	iter->pos			= pos;
	iter->nodes[iter->level]	= (void *) 1;
	iter->nodes[iter->level + 1]	= NULL;
}
