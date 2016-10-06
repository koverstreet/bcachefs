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
		__field(sector_t,	orig_sector		)
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

DECLARE_EVENT_CLASS(bpos,
	TP_PROTO(struct bpos p),
	TP_ARGS(p),

	TP_STRUCT__entry(
		__field(u64,	inode				)
		__field(u64,	offset				)
	),

	TP_fast_assign(
		__entry->inode	= p.inode;
		__entry->offset	= p.offset;
	),

	TP_printk("%llu:%llu", __entry->inode, __entry->offset)
);

DECLARE_EVENT_CLASS(bkey,
	TP_PROTO(const struct bkey *k),
	TP_ARGS(k),

	TP_STRUCT__entry(
		__field(u64,	inode				)
		__field(u64,	offset				)
		__field(u32,	size				)
	),

	TP_fast_assign(
		__entry->inode	= k->p.inode;
		__entry->offset	= k->p.offset;
		__entry->size	= k->size;
	),

	TP_printk("%llu:%llu len %u", __entry->inode,
		  __entry->offset, __entry->size)
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

DEFINE_EVENT(bcache_bio, bcache_promote,
	TP_PROTO(struct bio *bio),
	TP_ARGS(bio)
);

DEFINE_EVENT(bkey, bcache_promote_collision,
	TP_PROTO(const struct bkey *k),
	TP_ARGS(k)
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
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
		__entry->inode		= inode;
		__entry->sector		= bio->bi_iter.bi_sector;
		__entry->nr_sector	= bio->bi_iter.bi_size >> 9;
		blk_fill_rwbs(__entry->rwbs, bio_op(bio), bio->bi_opf,
			      bio->bi_iter.bi_size);
		__entry->writeback	= writeback;
		__entry->bypass		= bypass;
	),

	TP_printk("%pU inode %llu  %s %llu + %u hit %u bypass %u",
		  __entry->uuid, __entry->inode,
		  __entry->rwbs, (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->writeback, __entry->bypass)
);

TRACE_EVENT(bcache_write_throttle,
	TP_PROTO(struct cache_set *c, u64 inode, struct bio *bio, u64 delay),
	TP_ARGS(c, inode, bio, delay),

	TP_STRUCT__entry(
		__array(char,		uuid,	16		)
		__field(u64,		inode			)
		__field(sector_t,	sector			)
		__field(unsigned int,	nr_sector		)
		__array(char,		rwbs,	6		)
		__field(u64,		delay			)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
		__entry->inode		= inode;
		__entry->sector		= bio->bi_iter.bi_sector;
		__entry->nr_sector	= bio->bi_iter.bi_size >> 9;
		blk_fill_rwbs(__entry->rwbs, bio_op(bio), bio->bi_opf,
			      bio->bi_iter.bi_size);
		__entry->delay		= delay;
	),

	TP_printk("%pU inode %llu  %s %llu + %u delay %llu",
		  __entry->uuid, __entry->inode,
		  __entry->rwbs, (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->delay)
);

DEFINE_EVENT(bcache_bio, bcache_read_retry,
	TP_PROTO(struct bio *bio),
	TP_ARGS(bio)
);

DEFINE_EVENT(bkey, bcache_cache_insert,
	TP_PROTO(const struct bkey *k),
	TP_ARGS(k)
);

DECLARE_EVENT_CLASS(page_alloc_fail,
	TP_PROTO(struct cache_set *c, u64 size),
	TP_ARGS(c, size),

	TP_STRUCT__entry(
		__array(char,		uuid,	16	)
		__field(u64,		size		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
		__entry->size = size;
	),

	TP_printk("%pU size %llu", __entry->uuid, __entry->size)
);

/* Journal */

DECLARE_EVENT_CLASS(cache_set,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c),

	TP_STRUCT__entry(
		__array(char,		uuid,	16 )
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
	),

	TP_printk("%pU", __entry->uuid)
);

DEFINE_EVENT(bkey, bcache_journal_replay_key,
	TP_PROTO(const struct bkey *k),
	TP_ARGS(k)
);

TRACE_EVENT(bcache_journal_next_bucket,
	TP_PROTO(struct cache *ca, unsigned cur_idx, unsigned last_idx),
	TP_ARGS(ca, cur_idx, last_idx),

	TP_STRUCT__entry(
		__array(char,		uuid,	16	)
		__field(unsigned,	cur_idx		)
		__field(unsigned,	last_idx	)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, ca->disk_sb.sb->disk_uuid.b, 16);
		__entry->cur_idx	= cur_idx;
		__entry->last_idx	= last_idx;
	),

	TP_printk("%pU cur %u last %u", __entry->uuid,
		  __entry->cur_idx, __entry->last_idx)
);

TRACE_EVENT(bcache_journal_write_oldest,
	TP_PROTO(struct cache_set *c, u64 seq),
	TP_ARGS(c, seq),

	TP_STRUCT__entry(
		__array(char,		uuid,	16	)
		__field(u64,		seq		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
		__entry->seq		= seq;
	),

	TP_printk("%pU seq %llu", __entry->uuid, __entry->seq)
);

TRACE_EVENT(bcache_journal_write_oldest_done,
	TP_PROTO(struct cache_set *c, u64 seq, unsigned written),
	TP_ARGS(c, seq, written),

	TP_STRUCT__entry(
		__array(char,		uuid,	16	)
		__field(u64,		seq		)
		__field(unsigned,	written		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
		__entry->seq		= seq;
		__entry->written	= written;
	),

	TP_printk("%pU seq %llu written %u", __entry->uuid, __entry->seq,
		  __entry->written)
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

/* Device state changes */

DEFINE_EVENT(cache_set, bcache_cache_set_read_only,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DEFINE_EVENT(cache_set, bcache_cache_set_read_only_done,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DECLARE_EVENT_CLASS(cache,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca),

	TP_STRUCT__entry(
		__array(char,		uuid,	16	)
		__field(unsigned,	tier		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, ca->disk_sb.sb->disk_uuid.b, 16);
		__entry->tier = ca->mi.tier;
	),

	TP_printk("%pU tier %u", __entry->uuid, __entry->tier)
);

DEFINE_EVENT(cache, bcache_cache_read_only,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

DEFINE_EVENT(cache, bcache_cache_read_only_done,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

DEFINE_EVENT(cache, bcache_cache_read_write,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

DEFINE_EVENT(cache, bcache_cache_read_write_done,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

/* Searching */

DEFINE_EVENT(bpos, bkey_pack_pos_fail,
	TP_PROTO(struct bpos p),
	TP_ARGS(p)
);

DEFINE_EVENT(bpos, bkey_pack_pos_lossy_fail,
	TP_PROTO(struct bpos p),
	TP_ARGS(p)
);

/* Btree */

DECLARE_EVENT_CLASS(btree_node,
	TP_PROTO(struct btree *b),
	TP_ARGS(b),

	TP_STRUCT__entry(
		__array(char,		uuid,		16	)
		__field(u64,		bucket			)
		__field(u8,		level			)
		__field(u8,		id			)
		__field(u32,		inode			)
		__field(u64,		offset			)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, b->c->disk_sb.user_uuid.b, 16);
		__entry->bucket		= PTR_BUCKET_NR_TRACE(b->c, &b->key, 0);
		__entry->level		= b->level;
		__entry->id		= b->btree_id;
		__entry->inode		= b->key.k.p.inode;
		__entry->offset		= b->key.k.p.offset;
	),

	TP_printk("%pU bucket %llu(%u) id %u: %u:%llu",
		  __entry->uuid, __entry->bucket, __entry->level, __entry->id,
		  __entry->inode, __entry->offset)
);

DEFINE_EVENT(btree_node, bcache_btree_read,
	TP_PROTO(struct btree *b),
	TP_ARGS(b)
);

TRACE_EVENT(bcache_btree_write,
	TP_PROTO(struct btree *b),
	TP_ARGS(b),

	TP_STRUCT__entry(
		__field(u64,		bucket			)
		__field(unsigned,	block			)
		__field(unsigned,	u64s			)
	),

	TP_fast_assign(
		__entry->bucket	= PTR_BUCKET_NR_TRACE(b->c, &b->key, 0);
		__entry->block	= b->written;
		__entry->u64s	= le16_to_cpu(b->keys.set[b->keys.nsets].data->u64s);
	),

	TP_printk("bucket %llu block %u u64s %u",
		  __entry->bucket, __entry->block, __entry->u64s)
);

DEFINE_EVENT(btree_node, bcache_btree_bounce_write_fail,
	TP_PROTO(struct btree *b),
	TP_ARGS(b)
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
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
		__entry->id = id;
	),

	TP_printk("%pU id %u", __entry->uuid, __entry->id)
);

DEFINE_EVENT(btree_node, bcache_btree_node_free,
	TP_PROTO(struct btree *b),
	TP_ARGS(b)
);

TRACE_EVENT(bcache_mca_reap,
	TP_PROTO(struct btree *b, int ret),
	TP_ARGS(b, ret),

	TP_STRUCT__entry(
		__field(u64,			bucket		)
		__field(int,			ret		)
	),

	TP_fast_assign(
		__entry->bucket	= PTR_BUCKET_NR_TRACE(b->c, &b->key, 0);
		__entry->ret = ret;
	),

	TP_printk("bucket %llu ret %d", __entry->bucket, __entry->ret)
);

TRACE_EVENT(bcache_mca_scan,
	TP_PROTO(struct cache_set *c, unsigned touched, unsigned freed,
		 unsigned can_free, unsigned long nr),
	TP_ARGS(c, touched, freed, can_free, nr),

	TP_STRUCT__entry(
		__array(char,		uuid,	16	)
		__field(unsigned long,	touched		)
		__field(unsigned long,	freed		)
		__field(unsigned long,	can_free	)
		__field(unsigned long,	nr		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
		__entry->touched	= touched;
		__entry->freed		= freed;
		__entry->can_free	= can_free;
		__entry->nr		= nr;
	),

	TP_printk("%pU touched %lu freed %lu can_free %lu nr %lu",
		  __entry->uuid, __entry->touched, __entry->freed,
		  __entry->can_free, __entry->nr)
);

DECLARE_EVENT_CLASS(mca_cannibalize_lock,
	TP_PROTO(struct cache_set *c, struct closure *cl),
	TP_ARGS(c, cl),

	TP_STRUCT__entry(
		__array(char,			uuid,	16	)
		__field(struct closure *,	cl		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
		__entry->cl = cl;
	),

	TP_printk("%pU cl %p", __entry->uuid, __entry->cl)
);

DEFINE_EVENT(mca_cannibalize_lock, bcache_mca_cannibalize_lock_fail,
	TP_PROTO(struct cache_set *c, struct closure *cl),
	TP_ARGS(c, cl)
);

DEFINE_EVENT(mca_cannibalize_lock, bcache_mca_cannibalize_lock,
	TP_PROTO(struct cache_set *c, struct closure *cl),
	TP_ARGS(c, cl)
);

DEFINE_EVENT(mca_cannibalize_lock, bcache_mca_cannibalize,
	TP_PROTO(struct cache_set *c, struct closure *cl),
	TP_ARGS(c, cl)
);

DEFINE_EVENT(cache_set, bcache_mca_cannibalize_unlock,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DECLARE_EVENT_CLASS(btree_node_op,
	TP_PROTO(struct btree *b, void *op),
	TP_ARGS(b, op),

	TP_STRUCT__entry(
		__array(char,		uuid,	16		)
		__field(u64,		bucket			)
		__field(u8,		level			)
		__field(u8,		id			)
		__field(void *,		op			)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, b->c->disk_sb.user_uuid.b, 16);
		__entry->bucket	= PTR_BUCKET_NR_TRACE(b->c, &b->key, 0);
		__entry->level	= b->level;
		__entry->id	= b->btree_id;
		__entry->op	= op;
	),

	TP_printk("%pU bucket %llu(%u) id %u op %p",
		  __entry->uuid, __entry->bucket, __entry->level, __entry->id,
		  __entry->op)
);

DEFINE_EVENT(btree_node_op, bcache_btree_upgrade_lock,
	TP_PROTO(struct btree *b, void *op),
	TP_ARGS(b, op)
);

DEFINE_EVENT(btree_node_op, bcache_btree_upgrade_lock_fail,
	TP_PROTO(struct btree *b, void *op),
	TP_ARGS(b, op)
);

DEFINE_EVENT(btree_node_op, bcache_btree_intent_lock_fail,
	TP_PROTO(struct btree *b, void *op),
	TP_ARGS(b, op)
);

TRACE_EVENT(bcache_btree_insert_key,
	TP_PROTO(struct btree *b, struct bkey_i *k),
	TP_ARGS(b, k),

	TP_STRUCT__entry(
		__field(u64,		b_bucket		)
		__field(u64,		b_offset		)
		__field(u64,		offset			)
		__field(u32,		b_inode			)
		__field(u32,		inode			)
		__field(u32,		size			)
		__field(u8,		level			)
		__field(u8,		id			)
	),

	TP_fast_assign(
		__entry->b_bucket	= PTR_BUCKET_NR_TRACE(b->c, &b->key, 0);
		__entry->level		= b->level;
		__entry->id		= b->btree_id;
		__entry->b_inode	= b->key.k.p.inode;
		__entry->b_offset	= b->key.k.p.offset;
		__entry->inode		= k->k.p.inode;
		__entry->offset		= k->k.p.offset;
		__entry->size		= k->k.size;
	),

	TP_printk("bucket %llu(%u) id %u: %u:%llu %u:%llu len %u",
		  __entry->b_bucket, __entry->level, __entry->id,
		  __entry->b_inode, __entry->b_offset,
		  __entry->inode, __entry->offset, __entry->size)
);

DECLARE_EVENT_CLASS(btree_split,
	TP_PROTO(struct btree *b, unsigned keys),
	TP_ARGS(b, keys),

	TP_STRUCT__entry(
		__field(u64,		bucket			)
		__field(u8,		level			)
		__field(u8,		id			)
		__field(u32,		inode			)
		__field(u64,		offset			)
		__field(u32,		keys			)
	),

	TP_fast_assign(
		__entry->bucket	= PTR_BUCKET_NR_TRACE(b->c, &b->key, 0);
		__entry->level	= b->level;
		__entry->id	= b->btree_id;
		__entry->inode	= b->key.k.p.inode;
		__entry->offset	= b->key.k.p.offset;
		__entry->keys	= keys;
	),

	TP_printk("bucket %llu(%u) id %u: %u:%llu keys %u",
		  __entry->bucket, __entry->level, __entry->id,
		  __entry->inode, __entry->offset, __entry->keys)
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

/* Garbage collection */

TRACE_EVENT(bcache_btree_gc_coalesce,
	TP_PROTO(struct btree *b, unsigned nodes),
	TP_ARGS(b, nodes),

	TP_STRUCT__entry(
		__field(u64,		bucket			)
		__field(u8,		level			)
		__field(u8,		id			)
		__field(u32,		inode			)
		__field(u64,		offset			)
		__field(unsigned,	nodes			)
	),

	TP_fast_assign(
		__entry->bucket		= PTR_BUCKET_NR_TRACE(b->c, &b->key, 0);
		__entry->level		= b->level;
		__entry->id		= b->btree_id;
		__entry->inode		= b->key.k.p.inode;
		__entry->offset		= b->key.k.p.offset;
		__entry->nodes		= nodes;
	),

	TP_printk("bucket %llu(%u) id %u: %u:%llu nodes %u",
		  __entry->bucket, __entry->level, __entry->id,
		  __entry->inode, __entry->offset, __entry->nodes)
);

DEFINE_EVENT(cache_set, bcache_btree_gc_coalesce_fail,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

TRACE_EVENT(bcache_btree_node_alloc_replacement,
	TP_PROTO(struct btree *old, struct btree *b),
	TP_ARGS(old, b),

	TP_STRUCT__entry(
		__array(char,		uuid,		16	)
		__field(u64,		bucket			)
		__field(u64,		old_bucket		)
		__field(u8,		level			)
		__field(u8,		id			)
		__field(u32,		inode			)
		__field(u64,		offset			)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, b->c->disk_sb.user_uuid.b, 16);
		__entry->old_bucket	= PTR_BUCKET_NR_TRACE(old->c,
							      &old->key, 0);
		__entry->bucket		= PTR_BUCKET_NR_TRACE(b->c, &b->key, 0);
		__entry->level		= b->level;
		__entry->id		= b->btree_id;
		__entry->inode		= b->key.k.p.inode;
		__entry->offset		= b->key.k.p.offset;
	),

	TP_printk("%pU for %llu bucket %llu(%u) id %u: %u:%llu",
		  __entry->uuid, __entry->old_bucket, __entry->bucket,
		  __entry->level, __entry->id,
		  __entry->inode, __entry->offset)
);

DEFINE_EVENT(btree_node, bcache_btree_gc_rewrite_node,
	TP_PROTO(struct btree *b),
	TP_ARGS(b)
);

DEFINE_EVENT(btree_node, bcache_btree_gc_rewrite_node_fail,
	TP_PROTO(struct btree *b),
	TP_ARGS(b)
);

DEFINE_EVENT(cache_set, bcache_gc_start,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DEFINE_EVENT(cache_set, bcache_gc_end,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DEFINE_EVENT(cache_set, bcache_gc_coalesce_start,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DEFINE_EVENT(cache_set, bcache_gc_coalesce_end,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DEFINE_EVENT(cache, bcache_sectors_saturated,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

DEFINE_EVENT(cache_set, bcache_gc_sectors_saturated,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DEFINE_EVENT(cache_set, bcache_gc_cannot_inc_gens,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DEFINE_EVENT(cache_set, bcache_gc_periodic,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

TRACE_EVENT(bcache_mark_bucket,
	TP_PROTO(struct cache *ca, const struct bkey *k,
		 const struct bch_extent_ptr *ptr,
		 int sectors, bool dirty),
	TP_ARGS(ca, k, ptr, sectors, dirty),

	TP_STRUCT__entry(
		__array(char,		uuid,		16	)
		__field(u32,		inode			)
		__field(u64,		offset			)
		__field(u32,		sectors			)
		__field(u64,		bucket			)
		__field(bool,		dirty			)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, ca->disk_sb.sb->disk_uuid.b, 16);
		__entry->inode		= k->p.inode;
		__entry->offset		= k->p.offset;
		__entry->sectors	= sectors;
		__entry->bucket		= PTR_BUCKET_NR(ca, ptr);
		__entry->dirty		= dirty;
	),

	TP_printk("%pU %u:%llu sectors %i bucket %llu dirty %i",
		  __entry->uuid, __entry->inode, __entry->offset,
		  __entry->sectors, __entry->bucket, __entry->dirty)
);

/* Allocator */

TRACE_EVENT(bcache_alloc_batch,
	TP_PROTO(struct cache *ca, size_t free, size_t total),
	TP_ARGS(ca, free, total),

	TP_STRUCT__entry(
		__array(char,		uuid,	16	)
		__field(size_t,		free		)
		__field(size_t,		total		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, ca->disk_sb.sb->disk_uuid.b, 16);
		__entry->free = free;
		__entry->total = total;
	),

	TP_printk("%pU free %zu total %zu",
		__entry->uuid, __entry->free, __entry->total)
);

TRACE_EVENT(bcache_btree_reserve_get_fail,
	TP_PROTO(struct cache_set *c, size_t required, struct closure *cl),
	TP_ARGS(c, required, cl),

	TP_STRUCT__entry(
		__array(char,			uuid,	16	)
		__field(size_t,			required	)
		__field(struct closure *,	cl		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
		__entry->required = required;
		__entry->cl = cl;
	),

	TP_printk("%pU required %zu by %p", __entry->uuid,
		  __entry->required, __entry->cl)
);

DEFINE_EVENT(cache, bcache_prio_write_start,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

DEFINE_EVENT(cache, bcache_prio_write_end,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

TRACE_EVENT(bcache_invalidate,
	TP_PROTO(struct cache *ca, size_t bucket, unsigned sectors),
	TP_ARGS(ca, bucket, sectors),

	TP_STRUCT__entry(
		__field(unsigned,	sectors			)
		__field(dev_t,		dev			)
		__field(__u64,		offset			)
	),

	TP_fast_assign(
		__entry->dev		= ca->disk_sb.bdev->bd_dev;
		__entry->offset		= bucket << ca->bucket_bits;
		__entry->sectors	= sectors;
	),

	TP_printk("invalidated %u sectors at %d,%d sector=%llu",
		  __entry->sectors, MAJOR(__entry->dev),
		  MINOR(__entry->dev), __entry->offset)
);

DEFINE_EVENT(cache_set, bcache_rescale_prios,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DECLARE_EVENT_CLASS(cache_bucket_alloc,
	TP_PROTO(struct cache *ca, enum alloc_reserve reserve),
	TP_ARGS(ca, reserve),

	TP_STRUCT__entry(
		__array(char,			uuid,	16)
		__field(enum alloc_reserve,	reserve	  )
	),

	TP_fast_assign(
		memcpy(__entry->uuid, ca->disk_sb.sb->disk_uuid.b, 16);
		__entry->reserve = reserve;
	),

	TP_printk("%pU reserve %d", __entry->uuid, __entry->reserve)
);

DEFINE_EVENT(cache_bucket_alloc, bcache_bucket_alloc,
	TP_PROTO(struct cache *ca, enum alloc_reserve reserve),
	TP_ARGS(ca, reserve)
);

DEFINE_EVENT(cache_bucket_alloc, bcache_bucket_alloc_fail,
	TP_PROTO(struct cache *ca, enum alloc_reserve reserve),
	TP_ARGS(ca, reserve)
);

DECLARE_EVENT_CLASS(cache_set_bucket_alloc,
	TP_PROTO(struct cache_set *c, enum alloc_reserve reserve,
		 struct closure *cl),
	TP_ARGS(c, reserve, cl),

	TP_STRUCT__entry(
		__array(char,			uuid,	16	)
		__field(enum alloc_reserve,	reserve		)
		__field(struct closure *,	cl		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
		__entry->reserve = reserve;
		__entry->cl = cl;
	),

	TP_printk("%pU reserve %d cl %p", __entry->uuid, __entry->reserve,
		  __entry->cl)
);

DEFINE_EVENT(cache_set_bucket_alloc, bcache_freelist_empty_fail,
	TP_PROTO(struct cache_set *c, enum alloc_reserve reserve,
		 struct closure *cl),
	TP_ARGS(c, reserve, cl)
);

DECLARE_EVENT_CLASS(open_bucket_alloc,
	TP_PROTO(struct cache_set *c, struct closure *cl),
	TP_ARGS(c, cl),

	TP_STRUCT__entry(
		__array(char,			uuid,	16	)
		__field(struct closure *,	cl		)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
		__entry->cl = cl;
	),

	TP_printk("%pU cl %p",
		  __entry->uuid, __entry->cl)
);

DEFINE_EVENT(open_bucket_alloc, bcache_open_bucket_alloc,
	TP_PROTO(struct cache_set *c, struct closure *cl),
	TP_ARGS(c, cl)
);

DEFINE_EVENT(open_bucket_alloc, bcache_open_bucket_alloc_fail,
	TP_PROTO(struct cache_set *c, struct closure *cl),
	TP_ARGS(c, cl)
);

/* Keylists */

TRACE_EVENT(bcache_keyscan,
	TP_PROTO(unsigned nr_found,
		 unsigned start_inode, u64 start_offset,
		 unsigned end_inode, u64 end_offset),
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

/* Moving IO */

DECLARE_EVENT_CLASS(moving_io,
	TP_PROTO(struct moving_queue *q, struct bkey *k),
	TP_ARGS(q, k),

	TP_STRUCT__entry(
		__field(void *,		q			)
		__field(__u32,		inode			)
		__field(__u64,		offset			)
		__field(__u32,		sectors			)
		__field(unsigned,	count			)
		__field(unsigned,	read_count		)
		__field(unsigned,	write_count		)
	),

	TP_fast_assign(
		__entry->q		= q;
		__entry->inode		= k->p.inode;
		__entry->offset		= k->p.offset;
		__entry->sectors	= k->size;
		__entry->count		= atomic_read(&q->count);
		__entry->read_count	= atomic_read(&q->read_count);
		__entry->write_count	= atomic_read(&q->write_count);
	),

	TP_printk("%p %u:%llu sectors %u queue %u reads %u writes %u",
		  __entry->q, __entry->inode, __entry->offset,
		  __entry->sectors, __entry->count,
		  __entry->read_count, __entry->write_count)
);

DEFINE_EVENT(moving_io, bcache_move_read,
	TP_PROTO(struct moving_queue *q, struct bkey *k),
	TP_ARGS(q, k)
);

DEFINE_EVENT(moving_io, bcache_move_read_done,
	TP_PROTO(struct moving_queue *q, struct bkey *k),
	TP_ARGS(q, k)
);

DEFINE_EVENT(moving_io, bcache_move_write,
	TP_PROTO(struct moving_queue *q, struct bkey *k),
	TP_ARGS(q, k)
);

DEFINE_EVENT(moving_io, bcache_move_write_done,
	TP_PROTO(struct moving_queue *q, struct bkey *k),
	TP_ARGS(q, k)
);

DEFINE_EVENT(moving_io, bcache_copy_collision,
	TP_PROTO(struct moving_queue *q, struct bkey *k),
	TP_ARGS(q, k)
);

/* Copy GC */

DEFINE_EVENT(page_alloc_fail, bcache_moving_gc_alloc_fail,
	TP_PROTO(struct cache_set *c, u64 size),
	TP_ARGS(c, size)
);

DEFINE_EVENT(cache, bcache_moving_gc_start,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

TRACE_EVENT(bcache_moving_gc_end,
	TP_PROTO(struct cache *ca, u64 sectors_moved, u64 keys_moved,
		u64 buckets_moved),
	TP_ARGS(ca, sectors_moved, keys_moved, buckets_moved),

	TP_STRUCT__entry(
		__array(char,		uuid,	16	)
		__field(u64,		sectors_moved	)
		__field(u64,		keys_moved	)
		__field(u64,		buckets_moved	)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, ca->disk_sb.sb->disk_uuid.b, 16);
		__entry->sectors_moved = sectors_moved;
		__entry->keys_moved = keys_moved;
		__entry->buckets_moved = buckets_moved;
	),

	TP_printk("%pU sectors_moved %llu keys_moved %llu buckets_moved %llu",
		__entry->uuid, __entry->sectors_moved, __entry->keys_moved,
		__entry->buckets_moved)
);

DEFINE_EVENT(cache, bcache_moving_gc_reserve_empty,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

DEFINE_EVENT(cache, bcache_moving_gc_no_work,
	TP_PROTO(struct cache *ca),
	TP_ARGS(ca)
);

DEFINE_EVENT(bkey, bcache_gc_copy,
	TP_PROTO(const struct bkey *k),
	TP_ARGS(k)
);

/* Tiering */

DEFINE_EVENT(cache_set, bcache_tiering_refill_start,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DEFINE_EVENT(cache_set, bcache_tiering_refill_end,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

DEFINE_EVENT(page_alloc_fail, bcache_tiering_alloc_fail,
	TP_PROTO(struct cache_set *c, u64 size),
	TP_ARGS(c, size)
);

DEFINE_EVENT(cache_set, bcache_tiering_start,
	TP_PROTO(struct cache_set *c),
	TP_ARGS(c)
);

TRACE_EVENT(bcache_tiering_end,
	TP_PROTO(struct cache_set *c, u64 sectors_moved,
		u64 keys_moved),
	TP_ARGS(c, sectors_moved, keys_moved),

	TP_STRUCT__entry(
		__array(char,		uuid,	16	)
		__field(u64,		sectors_moved	)
		__field(u64,		keys_moved	)
	),

	TP_fast_assign(
		memcpy(__entry->uuid, c->disk_sb.user_uuid.b, 16);
		__entry->sectors_moved = sectors_moved;
		__entry->keys_moved = keys_moved;
	),

	TP_printk("%pU sectors_moved %llu keys_moved %llu",
		__entry->uuid, __entry->sectors_moved, __entry->keys_moved)
);

DEFINE_EVENT(bkey, bcache_tiering_copy,
	TP_PROTO(const struct bkey *k),
	TP_ARGS(k)
);

/* Background writeback */

DEFINE_EVENT(bkey, bcache_writeback,
	TP_PROTO(const struct bkey *k),
	TP_ARGS(k)
);

DEFINE_EVENT(bkey, bcache_writeback_collision,
	TP_PROTO(const struct bkey *k),
	TP_ARGS(k)
);

TRACE_EVENT(bcache_writeback_error,
	TP_PROTO(struct bkey *k, bool write, int error),
	TP_ARGS(k, write, error),

	TP_STRUCT__entry(
		__field(u32,	size				)
		__field(u32,	inode				)
		__field(u64,	offset				)
		__field(bool,	write				)
		__field(int,	error				)
	),

	TP_fast_assign(
		__entry->inode	= k->p.inode;
		__entry->offset	= k->p.offset;
		__entry->size	= k->size;
		__entry->write	= write;
		__entry->error	= error;
	),

	TP_printk("%u:%llu len %u %s error %d", __entry->inode,
		  __entry->offset, __entry->size,
		  __entry->write ? "write" : "read",
		  __entry->error)
);

DEFINE_EVENT(page_alloc_fail, bcache_writeback_alloc_fail,
	TP_PROTO(struct cache_set *c, u64 size),
	TP_ARGS(c, size)
);

#endif /* _TRACE_BCACHE_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
