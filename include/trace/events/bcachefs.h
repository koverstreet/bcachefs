#undef TRACE_SYSTEM
#define TRACE_SYSTEM bcachefs

#if !defined(_TRACE_BCACHE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BCACHE_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(bcache_request,
	TP_PROTO(struct bcache_device *d, struct bio *bio),
	TP_ARGS(d, bio),

	TP_STRUCT__entry(
		__field(dev_t,		dev			)
		__field(unsigned int,	orig_major		)
		__field(unsigned int,	orig_minor		)
		__field(sector_t,	sector			)
		__field(dev_t,		orig_sector		)
		__field(unsigned int,	nr_sector		)
		__array(char,		rwbs,	6		)
	),

	TP_fast_assign(
		__entry->dev		= bio->bi_bdev->bd_dev;
		__entry->orig_major	= d->disk->major;
		__entry->orig_minor	= d->disk->first_minor;
		__entry->sector		= bio->bi_iter.bi_sector;
		__entry->orig_sector	= bio->bi_iter.bi_sector - 16;
		__entry->nr_sector	= bio->bi_iter.bi_size >> 9;
		blk_fill_rwbs(__entry->rwbs, bio_op(bio), bio->bi_opf,
			      bio->bi_iter.bi_size);
	),

	TP_printk("%d,%d %s %llu + %u (from %d,%d @ %llu)",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->rwbs, (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->orig_major, __entry->orig_minor,
		  (unsigned long long)__entry->orig_sector)
);

DECLARE_EVENT_CLASS(bkey,
	TP_PROTO(struct bkey *k),
	TP_ARGS(k),

	TP_STRUCT__entry(
		__field(u32,	size				)
		__field(u32,	inode				)
		__field(u64,	offset				)
		__field(bool,	cached				)
	),

	TP_fast_assign(
		__entry->inode	= KEY_INODE(k);
		__entry->offset	= KEY_OFFSET(k);
		__entry->size	= KEY_SIZE(k);
		__entry->cached = KEY_CACHED(k);
	),

	TP_printk("%u:%llu len %u%s", __entry->inode,
		  __entry->offset, __entry->size,
		  __entry->cached ? " cached" : "")
);

/* request.c */

DEFINE_EVENT(bcache_request, bcache_request_start,
	TP_PROTO(struct bcache_device *d, struct bio *bio),
	TP_ARGS(d, bio)
);

DEFINE_EVENT(bcache_request, bcache_request_end,
	TP_PROTO(struct bcache_device *d, struct bio *bio),
	TP_ARGS(d, bio)
);

DECLARE_EVENT_CLASS(bcache_bio,
	TP_PROTO(struct bio *bio),
	TP_ARGS(bio),

	TP_STRUCT__entry(
		__field(dev_t,		dev			)
		__field(sector_t,	sector			)
		__field(unsigned int,	nr_sector		)
		__array(char,		rwbs,	6		)
	),

	TP_fast_assign(
		__entry->dev		= bio->bi_bdev->bd_dev;
		__entry->sector		= bio->bi_iter.bi_sector;
		__entry->nr_sector	= bio->bi_iter.bi_size >> 9;
		blk_fill_rwbs(__entry->rwbs, bio_op(bio), bio->bi_opf,
			      bio->bi_iter.bi_size);
	),

	TP_printk("%d,%d  %s %llu + %u",
		  MAJOR(__entry->dev), MINOR(__entry->dev), __entry->rwbs,
		  (unsigned long long)__entry->sector, __entry->nr_sector)
);

DEFINE_EVENT(bcache_bio, bcache_bypass_sequential,
	TP_PROTO(struct bio *bio),
	TP_ARGS(bio)
);

DEFINE_EVENT(bcache_bio, bcache_bypass_congested,
	TP_PROTO(struct bio *bio),
	TP_ARGS(bio)
);

TRACE_EVENT(bcache_read,
	TP_PROTO(struct bio *bio, bool hit, bool bypass),
	TP_ARGS(bio, hit, bypass),

	TP_STRUCT__entry(
		__field(dev_t,		dev			)
		__field(sector_t,	sector			)
		__field(unsigned int,	nr_sector		)
		__array(char,		rwbs,	6		)
		__field(bool,		cache_hit		)
		__field(bool,		bypass			)
	),

	TP_fast_assign(
		__entry->dev		= bio->bi_bdev->bd_dev;
		__entry->sector		= bio->bi_iter.bi_sector;
		__entry->nr_sector	= bio->bi_iter.bi_size >> 9;
		blk_fill_rwbs(__entry->rwbs, bio_op(bio), bio->bi_opf,
			      bio->bi_iter.bi_size);
		__entry->cache_hit = hit;
		__entry->bypass = bypass;
	),

	TP_printk("%d,%d  %s %llu + %u hit %u bypass %u",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->rwbs, (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->cache_hit, __entry->bypass)
);

TRACE_EVENT(bcache_write,
	TP_PROTO(struct cache_set *c, u64 inode, struct bio *bio,
		bool writeback, bool bypass),
	TP_ARGS(c, inode, bio, writeback, bypass),

	TP_STRUCT__entry(
		__array(char,		uuid,	16		)
		__field(u64,		inode			)
		__field(sector_t,	sector			)
		__field(unsigned int,	nr_sector		)
		__array(char,		rwbs,	6		)
		__field(bool,		writeback		)
		__field(bool,		bypass			)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->sb.set_uuid.b, 16);
		__entry->inode		= inode;
		__entry->sector		= bio->bi_iter.bi_sector;
		__entry->nr_sector	= bio->bi_iter.bi_size >> 9;
		blk_fill_rwbs(__entry->rwbs, bio_op(bio), bio->bi_opf,
			      bio->bi_iter.bi_size);
		__entry->writeback = writeback;
		__entry->bypass = bypass;
	),

	TP_printk("%pU inode %llu  %s %llu + %u hit %u bypass %u",
		  __entry->uuid, __entry->inode,
		  __entry->rwbs, (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->writeback, __entry->bypass)
);

DEFINE_EVENT(bcache_bio, bcache_read_retry,
	TP_PROTO(struct bio *bio),
	TP_ARGS(bio)
);

DEFINE_EVENT(bkey, bcache_cache_insert,
	TP_PROTO(struct bkey *k),
	TP_ARGS(k)
);

/* Journal */

DECLARE_EVENT_CLASS(cache_set,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c),

	TP_STRUCT__entry(
		__array(char,		uuid,	16 )
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->sb.set_uuid.b, 16);
	),

	TP_printk("%pU", __entry->uuid)
);

DEFINE_EVENT(bkey, bcache_journal_replay_key,
	TP_PROTO(struct bkey *k),
	TP_ARGS(k)
);

DEFINE_EVENT(cache_set, bcache_journal_full,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DEFINE_EVENT(cache_set, bcache_journal_entry_full,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DEFINE_EVENT(bcache_bio, bcache_journal_write,
	TP_PROTO(struct bio *bio),
	TP_ARGS(bio)
);

/* Btree */

DEFINE_EVENT(cache_set, bcache_btree_cache_cannibalize,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DECLARE_EVENT_CLASS(btree_node,
	TP_PROTO(struct btree *b),
	TP_ARGS(b),

	TP_STRUCT__entry(
		__array(char,		uuid,	16		)
		__field(size_t,		bucket			)
		__field(enum btree_id,	id			)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, b->c->sb.set_uuid.b, 16);
		__entry->bucket	= PTR_BUCKET_NR(b->c, &b->key, 0);
		__entry->id = b->btree_id;
	),

	TP_printk("%pU bucket %zu id %u", __entry->uuid, __entry->bucket,
		__entry->id)
);

DEFINE_EVENT(btree_node, bcache_btree_read,
	TP_PROTO(struct btree *b),
	TP_ARGS(b)
);

TRACE_EVENT(bcache_btree_write,
	TP_PROTO(struct btree *b),
	TP_ARGS(b),

	TP_STRUCT__entry(
		__field(size_t,		bucket			)
		__field(unsigned,	block			)
		__field(unsigned,	keys			)
	),

	TP_fast_assign(
		__entry->bucket	= PTR_BUCKET_NR(b->c, &b->key, 0);
		__entry->block	= b->written;
		__entry->keys	= b->keys.set[b->keys.nsets].data->keys;
	),

	TP_printk("bucket %zu block %u keys %u",
		  __entry->bucket, __entry->block, __entry->keys)
);

DEFINE_EVENT(btree_node, bcache_btree_node_alloc,
	TP_PROTO(struct btree *b),
	TP_ARGS(b)
);

TRACE_EVENT(bcache_btree_node_alloc_fail,
	TP_PROTO(struct cache_set *c, enum btree_id id),
	TP_ARGS(c, id),

	TP_STRUCT__entry(
		__array(char,		uuid,	16		)
		__field(enum btree_id,	id			)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->sb.set_uuid.b, 16);
		__entry->id = id;
	),

	TP_printk("%pU id %u", __entry->uuid, __entry->id)
);

DEFINE_EVENT(btree_node, bcache_btree_node_free,
	TP_PROTO(struct btree *b),
	TP_ARGS(b)
);

/* Garbage collection */

TRACE_EVENT(bcache_btree_gc_coalesce,
	TP_PROTO(unsigned nodes),
	TP_ARGS(nodes),

	TP_STRUCT__entry(
		__field(unsigned,	nodes			)
	),

	TP_fast_assign(
		__entry->nodes	= nodes;
	),

	TP_printk("coalesced %u nodes", __entry->nodes)
);

DEFINE_EVENT(cache_set, bcache_gc_start,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DEFINE_EVENT(cache_set, bcache_gc_end,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DECLARE_EVENT_CLASS(cache,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca),

	TP_STRUCT__entry(
		__array(char,		uuid,	16 )
	),

	TP_fast_assign(
		memcpy(__entry->uuid, ca->sb.uuid.b, 16);
	),

	TP_printk("%pU", __entry->uuid)
);

DEFINE_EVENT(cache, bcache_alloc_wait,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

TRACE_EVENT(bcache_alloc_batch,
	TP_PROTO(struct cache *ca, size_t free, size_t total),
	TP_ARGS(ca, free, total),

	TP_STRUCT__entry(
		__array(char,		uuid,	16	)
		__field(size_t,		free		)
		__field(size_t,		total		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, ca->sb.uuid.b, 16);
		__entry->free = free;
		__entry->total = total;
	),

	TP_printk("%pU free %zu total %zu",
		__entry->uuid, __entry->free, __entry->total)
);

TRACE_EVENT(bcache_btree_check_reserve,
	TP_PROTO(struct cache *ca, enum btree_id id, size_t free),
	TP_ARGS(ca, id, free),

	TP_STRUCT__entry(
		__array(char,		uuid,	16	)
		__field(enum btree_id,	id		)
		__field(size_t,		free		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, ca->sb.uuid.b, 16);
		__entry->id = id;
		__entry->free = free;
	),

	TP_printk("%pU id %u free %zu",
		__entry->uuid, __entry->id, __entry->free)
);

DEFINE_EVENT(cache, bcache_moving_gc_start,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

TRACE_EVENT(bcache_moving_gc_end,
	TP_PROTO(struct cache *ca, u64 sectors_moved,
		u64 buckets_moved),
	TP_ARGS(ca, sectors_moved, buckets_moved),

	TP_STRUCT__entry(
		__array(char,		uuid,	16	)
		__field(u64,		sectors_moved	)
		__field(u64,		buckets_moved	)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, ca->sb.uuid.b, 16);
		__entry->sectors_moved = sectors_moved;
		__entry->buckets_moved = buckets_moved;
	),

	TP_printk("%pU sectors_moved %llu buckets_moved %llu",
		__entry->uuid, __entry->sectors_moved, __entry->buckets_moved)
);

DEFINE_EVENT(cache, bcache_prio_write_start,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

DEFINE_EVENT(cache, bcache_prio_write_end,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

DEFINE_EVENT(bkey, bcache_gc_copy,
	TP_PROTO(struct bkey *k),
	TP_ARGS(k)
);

DEFINE_EVENT(bkey, bcache_gc_copy_collision,
	TP_PROTO(struct bkey *k),
	TP_ARGS(k)
);

TRACE_EVENT(bcache_btree_insert_key,
	TP_PROTO(struct btree *b, struct bkey *k, unsigned op, unsigned status),
	TP_ARGS(b, k, op, status),

	TP_STRUCT__entry(
		__field(u64,	btree_node			)
		__field(u32,	btree_level			)
		__field(u32,	inode				)
		__field(u64,	offset				)
		__field(u32,	size				)
		__field(u8,	cached				)
		__field(u8,	op				)
		__field(u8,	status				)
	),

	TP_fast_assign(
		__entry->btree_node = PTR_BUCKET_NR(b->c, &b->key, 0);
		__entry->btree_level = b->level;
		__entry->inode	= KEY_INODE(k);
		__entry->offset	= KEY_OFFSET(k);
		__entry->size	= KEY_SIZE(k);
		__entry->cached	= KEY_CACHED(k);
		__entry->op = op;
		__entry->status = status;
	),

	TP_printk("%u for %u at %llu(%u): %u:%llu len %u%s",
		  __entry->status, __entry->op,
		  __entry->btree_node, __entry->btree_level,
		  __entry->inode, __entry->offset,
		  __entry->size, __entry->cached ? " cached" : "")
);

DECLARE_EVENT_CLASS(btree_split,
	TP_PROTO(struct btree *b, unsigned keys),
	TP_ARGS(b, keys),

	TP_STRUCT__entry(
		__field(size_t,		bucket			)
		__field(unsigned,	keys			)
	),

	TP_fast_assign(
		__entry->bucket	= PTR_BUCKET_NR(b->c, &b->key, 0);
		__entry->keys	= keys;
	),

	TP_printk("bucket %zu keys %u", __entry->bucket, __entry->keys)
);

DEFINE_EVENT(btree_split, bcache_btree_node_split,
	TP_PROTO(struct btree *b, unsigned keys),
	TP_ARGS(b, keys)
);

DEFINE_EVENT(btree_split, bcache_btree_node_compact,
	TP_PROTO(struct btree *b, unsigned keys),
	TP_ARGS(b, keys)
);

DEFINE_EVENT(btree_node, bcache_btree_set_root,
	TP_PROTO(struct btree *b),
	TP_ARGS(b)
);

TRACE_EVENT(bcache_keyscan,
	TP_PROTO(unsigned nr_found,
		 unsigned start_inode, uint64_t start_offset,
		 unsigned end_inode, uint64_t end_offset),
	TP_ARGS(nr_found,
		start_inode, start_offset,
		end_inode, end_offset),

	TP_STRUCT__entry(
		__field(__u32,	nr_found			)
		__field(__u32,	start_inode			)
		__field(__u64,	start_offset			)
		__field(__u32,	end_inode			)
		__field(__u64,	end_offset			)
	),

	TP_fast_assign(
		__entry->nr_found	= nr_found;
		__entry->start_inode	= start_inode;
		__entry->start_offset	= start_offset;
		__entry->end_inode	= end_inode;
		__entry->end_offset	= end_offset;
	),

	TP_printk("found %u keys from %u:%llu to %u:%llu", __entry->nr_found,
		  __entry->start_inode, __entry->start_offset,
		  __entry->end_inode, __entry->end_offset)
);

TRACE_EVENT(bcache_wait_for_next_gc,
	TP_PROTO(struct cache_set *c, unsigned gc_count, unsigned gc_check),
	TP_ARGS(c, gc_count, gc_check),

	TP_STRUCT__entry(
		__array(char,			uuid,	16	)
		__field(unsigned,		gc_count	)
		__field(unsigned,		gc_check	)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->sb.set_uuid.b, 16);
		__entry->gc_count	= gc_count;
		__entry->gc_check	= gc_check;
	),

	TP_printk("%pU gc_count %u gc_check %u",
		  __entry->uuid, __entry->gc_count, __entry->gc_check)
);

/* Allocator */

TRACE_EVENT(bcache_invalidate,
	TP_PROTO(struct cache *ca, size_t bucket),
	TP_ARGS(ca, bucket),

	TP_STRUCT__entry(
		__field(unsigned,	sectors			)
		__field(dev_t,		dev			)
		__field(__u64,		offset			)
	),

	TP_fast_assign(
		__entry->dev		= ca->bdev->bd_dev;
		__entry->offset		= bucket << ca->set->bucket_bits;
		__entry->sectors	= GC_SECTORS_USED(&ca->buckets[bucket]);
	),

	TP_printk("invalidated %u sectors at %d,%d sector=%llu",
		  __entry->sectors, MAJOR(__entry->dev),
		  MINOR(__entry->dev), __entry->offset)
);

DECLARE_EVENT_CLASS(bucket_alloc,
	TP_PROTO(struct cache *ca, enum alloc_reserve reserve,
		 struct closure *cl),
	TP_ARGS(ca, reserve, cl),

	TP_STRUCT__entry(
		__array(char,			uuid,	16)
		__field(enum alloc_reserve,	reserve	  )
		__field(struct closure *,	cl	  )
	),

	TP_fast_assign(
		memcpy(__entry->uuid, ca->sb.uuid.b, 16);
		__entry->reserve = reserve;
		__entry->cl = cl;
	),

	TP_printk("%pU reserve %d cl %p", __entry->uuid, __entry->reserve,
		  __entry->cl)
);

DEFINE_EVENT(bucket_alloc, bcache_bucket_alloc_fail,
	TP_PROTO(struct cache *ca, enum alloc_reserve reserve,
		 struct closure *cl),
	TP_ARGS(ca, reserve, cl)
);

DEFINE_EVENT(bucket_alloc, bcache_bucket_alloc,
	TP_PROTO(struct cache *ca, enum alloc_reserve reserve,
		 struct closure *cl),
	TP_ARGS(ca, reserve, cl)
);

TRACE_EVENT(bcache_bucket_alloc_set_fail,
	TP_PROTO(struct cache_set *c, enum alloc_reserve reserve,
		 struct closure *cl),
	TP_ARGS(c, reserve, cl),

	TP_STRUCT__entry(
		__array(char,			uuid,	16	)
		__field(enum alloc_reserve,	reserve		)
		__field(struct closure *,	cl		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->sb.set_uuid.b, 16);
		__entry->reserve = reserve;
		__entry->cl = cl;
	),

	TP_printk("%pU reserve %d cl %p", __entry->uuid, __entry->reserve,
		  __entry->cl)
);

DECLARE_EVENT_CLASS(open_bucket_alloc,
	TP_PROTO(struct cache_set *c, bool moving_gc, struct closure *cl),
	TP_ARGS(c, moving_gc, cl),

	TP_STRUCT__entry(
		__array(char,			uuid,	16	)
		__field(unsigned,		moving_gc	)
		__field(struct closure *,	cl		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->sb.set_uuid.b, 16);
		__entry->moving_gc = moving_gc;
		__entry->cl = cl;
	),

	TP_printk("%pU moving_gc %u cl %p",
		  __entry->uuid, __entry->moving_gc, __entry->cl)
);

DEFINE_EVENT(open_bucket_alloc, bcache_open_bucket_alloc,
	TP_PROTO(struct cache_set *c, bool moving_gc, struct closure *cl),
	TP_ARGS(c, moving_gc, cl)
);

DEFINE_EVENT(open_bucket_alloc, bcache_open_bucket_alloc_fail,
	TP_PROTO(struct cache_set *c, bool moving_gc, struct closure *cl),
	TP_ARGS(c, moving_gc, cl)
);

/* Background writeback */

DEFINE_EVENT(bkey, bcache_writeback,
	TP_PROTO(struct bkey *k),
	TP_ARGS(k)
);

DEFINE_EVENT(bkey, bcache_writeback_collision,
	TP_PROTO(struct bkey *k),
	TP_ARGS(k)
);

#endif /* _TRACE_BCACHE_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
