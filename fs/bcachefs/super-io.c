
#include "bcache.h"
#include "blockdev.h"
#include "checksum.h"
#include "error.h"
#include "io.h"
#include "journal.h"
#include "super-io.h"
#include "super.h"
#include "vstructs.h"

#include <linux/backing-dev.h>

static inline void __bch_sb_layout_size_assert(void)
{
	BUILD_BUG_ON(sizeof(struct bch_sb_layout) != 512);
}

struct bch_sb_field *bch_sb_field_get(struct bch_sb *sb,
				      enum bch_sb_field_types type)
{
	struct bch_sb_field *f;

	/* XXX: need locking around superblock to access optional fields */

	vstruct_for_each(sb, f)
		if (le32_to_cpu(f->type) == type)
			return f;
	return NULL;
}

void bch_free_super(struct bcache_superblock *sb)
{
	if (sb->bio)
		bio_put(sb->bio);
	if (!IS_ERR_OR_NULL(sb->bdev))
		blkdev_put(sb->bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);

	free_pages((unsigned long) sb->sb, sb->page_order);
	memset(sb, 0, sizeof(*sb));
}

static int __bch_super_realloc(struct bcache_superblock *sb, unsigned order)
{
	struct bch_sb *new_sb;
	struct bio *bio;

	if (sb->page_order >= order && sb->sb)
		return 0;

	if (dynamic_fault("bcache:add:super_realloc"))
		return -ENOMEM;

	bio = bio_kmalloc(GFP_KERNEL, 1 << order);
	if (!bio)
		return -ENOMEM;

	if (sb->bio)
		bio_put(sb->bio);
	sb->bio = bio;

	new_sb = (void *) __get_free_pages(GFP_KERNEL, order);
	if (!new_sb)
		return -ENOMEM;

	if (sb->sb)
		memcpy(new_sb, sb->sb, PAGE_SIZE << sb->page_order);

	free_pages((unsigned long) sb->sb, sb->page_order);
	sb->sb = new_sb;

	sb->page_order = order;

	return 0;
}

int bch_dev_sb_realloc(struct bcache_superblock *sb, unsigned u64s)
{
	u64 new_bytes = __vstruct_bytes(struct bch_sb, u64s);
	u64 max_bytes = 512 << sb->sb->layout.sb_max_size_bits;

	if (new_bytes > max_bytes) {
		char buf[BDEVNAME_SIZE];

		pr_err("%s: superblock too big: want %llu but have %llu",
		       bdevname(sb->bdev, buf), new_bytes, max_bytes);
		return -ENOSPC;
	}

	return __bch_super_realloc(sb, get_order(new_bytes));
}

static int bch_fs_sb_realloc(struct cache_set *c, unsigned u64s)
{
	u64 bytes = __vstruct_bytes(struct bch_sb, u64s);
	struct bch_sb *sb;
	unsigned order = get_order(bytes);

	if (c->disk_sb && order <= c->disk_sb_order)
		return 0;

	sb = (void *) __get_free_pages(GFP_KERNEL|__GFP_ZERO, order);
	if (!sb)
		return -ENOMEM;

	if (c->disk_sb)
		memcpy(sb, c->disk_sb, PAGE_SIZE << c->disk_sb_order);

	free_pages((unsigned long) c->disk_sb, c->disk_sb_order);

	c->disk_sb = sb;
	c->disk_sb_order = order;
	return 0;
}

static struct bch_sb_field *__bch_sb_field_resize(struct bch_sb *sb,
						  struct bch_sb_field *f,
						  unsigned u64s)
{
	unsigned old_u64s = f ? le32_to_cpu(f->u64s) : 0;

	if (!f) {
		f = vstruct_last(sb);
		memset(f, 0, sizeof(u64) * u64s);
		f->u64s = cpu_to_le32(u64s);
		f->type = 0;
	} else {
		void *src, *dst;

		src = vstruct_end(f);
		f->u64s = cpu_to_le32(u64s);
		dst = vstruct_end(f);

		memmove(dst, src, vstruct_end(sb) - src);

		if (dst > src)
			memset(src, 0, dst - src);
	}

	le32_add_cpu(&sb->u64s, u64s - old_u64s);

	return f;

}

struct bch_sb_field *bch_fs_sb_field_resize(struct cache_set *c,
					    struct bch_sb_field *f,
					    unsigned u64s)
{
	ssize_t old_u64s = f ? le32_to_cpu(f->u64s) : 0;
	ssize_t d = -old_u64s + u64s;
	struct cache *ca;
	unsigned i;

	lockdep_assert_held(&c->sb_lock);

	if (bch_fs_sb_realloc(c, le32_to_cpu(c->disk_sb->u64s) + d))
		return NULL;

	for_each_cache(ca, c, i) {
		struct bcache_superblock *sb = &ca->disk_sb;

		if (bch_dev_sb_realloc(sb, le32_to_cpu(sb->sb->u64s) + d)) {
			percpu_ref_put(&ca->ref);
			return NULL;
		}
	}

	return __bch_sb_field_resize(c->disk_sb, f, u64s);
}

struct bch_sb_field *bch_dev_sb_field_resize(struct bcache_superblock *sb,
					     struct bch_sb_field *f,
					     unsigned u64s)
{
	ssize_t old_u64s = f ? le32_to_cpu(f->u64s) : 0;
	ssize_t d = -old_u64s + u64s;

	if (bch_dev_sb_realloc(sb, le32_to_cpu(sb->sb->u64s) + d))
		return NULL;

	return __bch_sb_field_resize(sb->sb, f, u64s);
}

static const char *validate_sb_layout(struct bch_sb_layout *layout)
{
	u64 offset, prev_offset, max_sectors;
	unsigned i;

	if (uuid_le_cmp(layout->magic, BCACHE_MAGIC))
		return "Not a bcache superblock layout";

	if (layout->layout_type != 0)
		return "Invalid superblock layout type";

	if (!layout->nr_superblocks)
		return "Invalid superblock layout: no superblocks";

	if (layout->nr_superblocks > ARRAY_SIZE(layout->sb_offset))
		return "Invalid superblock layout: too many superblocks";

	max_sectors = 1 << layout->sb_max_size_bits;

	prev_offset = le64_to_cpu(layout->sb_offset[0]);

	if (prev_offset != BCH_SB_SECTOR)
		return "Invalid superblock layout: doesn't have default superblock location";

	for (i = 1; i < layout->nr_superblocks; i++) {
		offset = le64_to_cpu(layout->sb_offset[i]);

		if (offset < prev_offset + max_sectors)
			return "Invalid superblock layout: superblocks overlap";
		prev_offset = offset;
	}

	return NULL;
}

const char *bch_validate_cache_super(struct bcache_superblock *disk_sb)
{
	struct bch_sb *sb = disk_sb->sb;
	struct bch_sb_field *f;
	struct bch_sb_field_members *sb_mi;
	struct bch_sb_field_journal *journal;
	struct cache_member_cpu	mi;
	const char *err;
	u16 block_size;
	unsigned i;

	switch (le64_to_cpu(sb->version)) {
	case BCACHE_SB_VERSION_CDEV_V4:
		break;
	default:
		return"Unsupported superblock version";
	}

	if (BCH_SB_INITIALIZED(sb) &&
	    le64_to_cpu(sb->version) != BCACHE_SB_VERSION_CDEV_V4)
		return "Unsupported superblock version";

	block_size = le16_to_cpu(sb->block_size);

	if (!is_power_of_2(block_size) ||
	    block_size > PAGE_SECTORS)
		return "Bad block size";

	if (bch_is_zero(sb->user_uuid.b, sizeof(uuid_le)))
		return "Bad user UUID";

	if (bch_is_zero(sb->uuid.b, sizeof(uuid_le)))
		return "Bad internal UUID";

	if (!sb->nr_devices ||
	    sb->nr_devices <= sb->dev_idx ||
	    sb->nr_devices > BCH_SB_MEMBERS_MAX)
		return "Bad cache device number in set";

	if (!BCH_SB_META_REPLICAS_WANT(sb) ||
	    BCH_SB_META_REPLICAS_WANT(sb) >= BCH_REPLICAS_MAX)
		return "Invalid number of metadata replicas";

	if (!BCH_SB_META_REPLICAS_HAVE(sb) ||
	    BCH_SB_META_REPLICAS_HAVE(sb) >
	    BCH_SB_META_REPLICAS_WANT(sb))
		return "Invalid number of metadata replicas";

	if (!BCH_SB_DATA_REPLICAS_WANT(sb) ||
	    BCH_SB_DATA_REPLICAS_WANT(sb) >= BCH_REPLICAS_MAX)
		return "Invalid number of data replicas";

	if (!BCH_SB_DATA_REPLICAS_HAVE(sb) ||
	    BCH_SB_DATA_REPLICAS_HAVE(sb) >
	    BCH_SB_DATA_REPLICAS_WANT(sb))
		return "Invalid number of data replicas";

	if (!BCH_SB_BTREE_NODE_SIZE(sb))
		return "Btree node size not set";

	if (!is_power_of_2(BCH_SB_BTREE_NODE_SIZE(sb)))
		return "Btree node size not a power of two";

	if (BCH_SB_BTREE_NODE_SIZE(sb) > BTREE_NODE_SIZE_MAX)
		return "Btree node size too large";

	if (BCH_SB_GC_RESERVE(sb) < 5)
		return "gc reserve percentage too small";

	if (1U << BCH_SB_JOURNAL_ENTRY_SIZE(sb) < block_size)
		return "max journal entry size too small";

	/* 4 mb max: */
	if (512U << BCH_SB_JOURNAL_ENTRY_SIZE(sb) > JOURNAL_ENTRY_SIZE_MAX)
		return "max journal entry size too big";

	if (!sb->time_precision ||
	    le32_to_cpu(sb->time_precision) > NSEC_PER_SEC)
		return "invalid time precision";

	/* validate layout */
	err = validate_sb_layout(&sb->layout);
	if (err)
		return err;

	vstruct_for_each(sb, f) {
		if (!f->u64s)
			return "Invalid superblock: invalid optional field";

		if (vstruct_next(f) > vstruct_last(sb))
			return "Invalid superblock: invalid optional field";

		if (le32_to_cpu(f->type) >= BCH_SB_FIELD_NR)
			return "Invalid superblock: unknown optional field type";
	}

	/* Validate member info: */
	sb_mi = bch_sb_get_members(sb);
	if (!sb_mi)
		return "Invalid superblock: member info area missing";

	if ((void *) (sb_mi->members + sb->nr_devices) >
	    vstruct_end(&sb_mi->field))
		return "Invalid superblock: bad member info";

	mi = cache_mi_to_cpu_mi(sb_mi->members + sb->dev_idx);

	for (i = 0; i < sb->layout.nr_superblocks; i++) {
		u64 offset = le64_to_cpu(sb->layout.sb_offset[i]);
		u64 max_size = 1 << sb->layout.sb_max_size_bits;

		if (offset + max_size > mi.first_bucket * mi.bucket_size)
			return "Invalid superblock: first bucket comes before end of super";
	}

	if (mi.nbuckets > LONG_MAX)
		return "Too many buckets";

	if (mi.nbuckets - mi.first_bucket < 1 << 10)
		return "Not enough buckets";

	if (!is_power_of_2(mi.bucket_size) ||
	    mi.bucket_size < PAGE_SECTORS ||
	    mi.bucket_size < block_size)
		return "Bad bucket size";

	if (get_capacity(disk_sb->bdev->bd_disk) <
	    mi.bucket_size * mi.nbuckets)
		return "Invalid superblock: device too small";

	/* Validate journal buckets: */
	journal = bch_sb_get_journal(sb);
	if (journal) {
		for (i = 0; i < bch_nr_journal_buckets(journal); i++) {
			u64 b = le64_to_cpu(journal->buckets[i]);

			if (b <  mi.first_bucket || b >= mi.nbuckets)
				return "bad journal bucket";
		}
	}

	return NULL;
}

/* device open: */

static bool bch_is_open_cache(struct block_device *bdev)
{
	struct cache_set *c;
	struct cache *ca;
	unsigned i;

	rcu_read_lock();
	list_for_each_entry(c, &bch_fs_list, list)
		for_each_cache_rcu(ca, c, i)
			if (ca->disk_sb.bdev == bdev) {
				rcu_read_unlock();
				return true;
			}
	rcu_read_unlock();
	return false;
}

static bool bch_is_open(struct block_device *bdev)
{
	lockdep_assert_held(&bch_register_lock);

	return bch_is_open_cache(bdev) || bch_is_open_backing_dev(bdev);
}

static const char *bch_blkdev_open(const char *path, void *holder,
				   struct bch_opts opts,
				   struct block_device **ret)
{
	struct block_device *bdev;
	fmode_t mode = opts.nochanges > 0
		? FMODE_READ
		: FMODE_READ|FMODE_WRITE|FMODE_EXCL;
	const char *err;

	*ret = NULL;
	bdev = blkdev_get_by_path(path, mode, holder);

	if (bdev == ERR_PTR(-EBUSY)) {
		bdev = lookup_bdev(path);
		if (IS_ERR(bdev))
			return "device busy";

		err = bch_is_open(bdev)
			? "device already registered"
			: "device busy";

		bdput(bdev);
		return err;
	}

	if (IS_ERR(bdev))
		return "failed to open device";

	bdev_get_queue(bdev)->backing_dev_info.capabilities |= BDI_CAP_STABLE_WRITES;

	*ret = bdev;
	return NULL;
}

/* Update cached mi: */
int bch_fs_mi_update(struct cache_set *c, struct bch_member *mi,
		     unsigned nr_devices)
{
	struct cache_member_rcu *new, *old;
	struct cache *ca;
	unsigned i;

	lockdep_assert_held(&c->sb_lock);

	new = kzalloc(sizeof(struct cache_member_rcu) +
		      sizeof(struct cache_member_cpu) * nr_devices,
		      GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	new->nr_devices = nr_devices;

	for (i = 0; i < nr_devices; i++)
		new->m[i] = cache_mi_to_cpu_mi(&mi[i]);

	rcu_read_lock();
	for_each_cache(ca, c, i)
		ca->mi = new->m[i];
	rcu_read_unlock();

	old = rcu_dereference_protected(c->members,
				lockdep_is_held(&c->sb_lock));

	rcu_assign_pointer(c->members, new);
	if (old)
		kfree_rcu(old, rcu);

	return 0;
}

static void bch_sb_update(struct cache_set *c)
{
	struct bch_sb *src = c->disk_sb;

	lockdep_assert_held(&c->sb_lock);

	c->sb.uuid		= src->uuid;
	c->sb.user_uuid		= src->user_uuid;
	c->sb.block_size	= le16_to_cpu(src->block_size);
	c->sb.btree_node_size	= BCH_SB_BTREE_NODE_SIZE(src);
	c->sb.nr_devices	= src->nr_devices;
	c->sb.clean		= BCH_SB_CLEAN(src);
	c->sb.meta_replicas_have= BCH_SB_META_REPLICAS_HAVE(src);
	c->sb.data_replicas_have= BCH_SB_DATA_REPLICAS_HAVE(src);
	c->sb.str_hash_type	= BCH_SB_STR_HASH_TYPE(src);
	c->sb.encryption_type	= BCH_SB_ENCRYPTION_TYPE(src);
	c->sb.time_base_lo	= le64_to_cpu(src->time_base_lo);
	c->sb.time_base_hi	= le32_to_cpu(src->time_base_hi);
	c->sb.time_precision	= le32_to_cpu(src->time_precision);
}

/* doesn't copy member info */
static void __copy_super(struct bch_sb *dst, struct bch_sb *src)
{
	struct bch_sb_field *src_f, *dst_f;

	dst->version		= src->version;
	dst->seq		= src->seq;
	dst->uuid		= src->uuid;
	dst->user_uuid		= src->user_uuid;
	memcpy(dst->label,	src->label, sizeof(dst->label));

	dst->block_size		= src->block_size;
	dst->nr_devices		= src->nr_devices;

	dst->time_base_lo	= src->time_base_lo;
	dst->time_base_hi	= src->time_base_hi;
	dst->time_precision	= src->time_precision;

	memcpy(dst->flags,	src->flags,	sizeof(dst->flags));
	memcpy(dst->features,	src->features,	sizeof(dst->features));
	memcpy(dst->compat,	src->compat,	sizeof(dst->compat));

	vstruct_for_each(src, src_f) {
		if (src_f->type == BCH_SB_FIELD_journal)
			continue;

		dst_f = bch_sb_field_get(dst, src_f->type);
		dst_f = __bch_sb_field_resize(dst, dst_f,
				le32_to_cpu(src_f->u64s));

		memcpy(dst_f, src_f, vstruct_bytes(src_f));
	}
}

int bch_sb_to_cache_set(struct cache_set *c, struct bch_sb *src)
{
	struct bch_sb_field_members *members =
		bch_sb_get_members(src);
	struct bch_sb_field_journal *journal_buckets =
		bch_sb_get_journal(src);
	unsigned journal_u64s = journal_buckets
		? le32_to_cpu(journal_buckets->field.u64s)
		: 0;

	lockdep_assert_held(&c->sb_lock);

	if (bch_fs_sb_realloc(c, le32_to_cpu(src->u64s) - journal_u64s))
		return -ENOMEM;

	if (bch_fs_mi_update(c, members->members, src->nr_devices))
		return -ENOMEM;

	__copy_super(c->disk_sb, src);
	bch_sb_update(c);

	return 0;
}

int bch_sb_from_cache_set(struct cache_set *c, struct cache *ca)
{
	struct bch_sb *src = c->disk_sb, *dst = ca->disk_sb.sb;
	struct bch_sb_field_journal *journal_buckets =
		bch_sb_get_journal(dst);
	unsigned journal_u64s = journal_buckets
		? le32_to_cpu(journal_buckets->field.u64s)
		: 0;
	unsigned u64s = le32_to_cpu(src->u64s) + journal_u64s;
	int ret;

	ret = bch_dev_sb_realloc(&ca->disk_sb, u64s);
	if (ret)
		return ret;

	__copy_super(dst, src);

	return 0;
}

/* read superblock: */

static const char *read_one_super(struct bcache_superblock *sb, u64 offset)
{
	struct bch_csum csum;
	size_t bytes;
	unsigned order;
reread:
	bio_reset(sb->bio);
	sb->bio->bi_bdev = sb->bdev;
	sb->bio->bi_iter.bi_sector = BCH_SB_SECTOR;
	sb->bio->bi_iter.bi_size = PAGE_SIZE << sb->page_order;
	bio_set_op_attrs(sb->bio, REQ_OP_READ, REQ_SYNC|REQ_META);
	bch_bio_map(sb->bio, sb->sb);

	if (submit_bio_wait(sb->bio))
		return "IO error";

	if (uuid_le_cmp(sb->sb->magic, BCACHE_MAGIC))
		return "Not a bcache superblock";

	if (le64_to_cpu(sb->sb->version) != BCACHE_SB_VERSION_CDEV_V4)
		return "Unsupported superblock version";

	bytes = vstruct_bytes(sb->sb);

	if (bytes > 512 << sb->sb->layout.sb_max_size_bits)
		return "Bad superblock: too big";

	order = get_order(bytes);
	if (order > sb->page_order) {
		if (__bch_super_realloc(sb, order))
			return "cannot allocate memory";
		goto reread;
	}

	if (BCH_SB_CSUM_TYPE(sb->sb) >= BCH_CSUM_NR)
		return "unknown csum type";

	/* XXX: verify MACs */
	csum = csum_vstruct(NULL, BCH_SB_CSUM_TYPE(sb->sb),
			    (struct nonce) { 0 }, sb->sb);

	if (bch_crc_cmp(csum, sb->sb->csum))
		return "bad checksum reading superblock";

	return NULL;
}

const char *bch_read_super(struct bcache_superblock *sb,
			   struct bch_opts opts,
			   const char *path)
{
	struct bch_sb_layout layout;
	const char *err;
	unsigned i;

	lockdep_assert_held(&bch_register_lock);

	memset(sb, 0, sizeof(*sb));

	err = bch_blkdev_open(path, &sb, opts, &sb->bdev);
	if (err)
		return err;

	err = "cannot allocate memory";
	if (__bch_super_realloc(sb, 0))
		goto err;

	err = "dynamic fault";
	if (bch_fs_init_fault("read_super"))
		goto err;

	err = read_one_super(sb, BCH_SB_SECTOR);
	if (!err)
		goto got_super;

	pr_err("error reading default super: %s", err);

	/*
	 * Error reading primary superblock - read location of backup
	 * superblocks:
	 */
	bio_reset(sb->bio);
	sb->bio->bi_bdev = sb->bdev;
	sb->bio->bi_iter.bi_sector = BCH_SB_LAYOUT_SECTOR;
	sb->bio->bi_iter.bi_size = sizeof(struct bch_sb_layout);
	bio_set_op_attrs(sb->bio, REQ_OP_READ, REQ_SYNC|REQ_META);
	/*
	 * use sb buffer to read layout, since sb buffer is page aligned but
	 * layout won't be:
	 */
	bch_bio_map(sb->bio, sb->sb);

	err = "IO error";
	if (submit_bio_wait(sb->bio))
		goto err;

	memcpy(&layout, sb->sb, sizeof(layout));
	err = validate_sb_layout(&layout);
	if (err)
		goto err;

	for (i = 0; i < layout.nr_superblocks; i++) {
		u64 offset = le64_to_cpu(layout.sb_offset[i]);

		if (offset == BCH_SB_SECTOR)
			continue;

		err = read_one_super(sb, offset);
		if (!err)
			goto got_super;
	}
	goto err;
got_super:
	pr_debug("read sb version %llu, flags %llu, seq %llu, journal size %u",
		 le64_to_cpu(sb->sb->version),
		 le64_to_cpu(sb->sb->flags),
		 le64_to_cpu(sb->sb->seq),
		 le16_to_cpu(sb->sb->u64s));

	err = "Superblock block size smaller than device block size";
	if (le16_to_cpu(sb->sb->block_size) << 9 <
	    bdev_logical_block_size(sb->bdev))
		goto err;

	return NULL;
err:
	bch_free_super(sb);
	return err;
}

/* write superblock: */

static void write_super_endio(struct bio *bio)
{
	struct cache *ca = bio->bi_private;

	/* XXX: return errors directly */

	bch_dev_fatal_io_err_on(bio->bi_error, ca, "superblock write");

	bch_account_io_completion(ca);

	closure_put(&ca->set->sb_write);
	percpu_ref_put(&ca->ref);
}

static bool write_one_super(struct cache_set *c, struct cache *ca, unsigned idx)
{
	struct bch_sb *sb = ca->disk_sb.sb;
	struct bio *bio = ca->disk_sb.bio;

	if (idx >= sb->layout.nr_superblocks)
		return false;

	sb->offset = sb->layout.sb_offset[idx];

	SET_BCH_SB_CSUM_TYPE(sb, c->opts.metadata_checksum);
	sb->csum = csum_vstruct(c, BCH_SB_CSUM_TYPE(sb),
				(struct nonce) { 0 }, sb);

	bio_reset(bio);
	bio->bi_bdev		= ca->disk_sb.bdev;
	bio->bi_iter.bi_sector	= le64_to_cpu(sb->offset);
	bio->bi_iter.bi_size	=
		roundup(vstruct_bytes(sb),
			bdev_logical_block_size(ca->disk_sb.bdev));
	bio->bi_end_io		= write_super_endio;
	bio->bi_private		= ca;
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_SYNC|REQ_META);
	bch_bio_map(bio, sb);

	percpu_ref_get(&ca->ref);
	closure_bio_submit_punt(bio, &c->sb_write, c);

	return true;
}

void bch_write_super(struct cache_set *c)
{
	struct bch_sb_field_members *members =
		bch_sb_get_members(c->disk_sb);
	struct closure *cl = &c->sb_write;
	struct cache *ca;
	unsigned i, super_idx = 0;
	bool wrote;

	lockdep_assert_held(&c->sb_lock);

	closure_init_stack(cl);

	le64_add_cpu(&c->disk_sb->seq, 1);

	for_each_cache(ca, c, i)
		bch_sb_from_cache_set(c, ca);

	do {
		wrote = false;
		for_each_cache(ca, c, i)
			if (write_one_super(c, ca, super_idx))
				wrote = true;

		closure_sync(cl);
		super_idx++;
	} while (wrote);

	/* Make new options visible after they're persistent: */
	bch_fs_mi_update(c, members->members, c->sb.nr_devices);
	bch_sb_update(c);
}

void bch_check_mark_super_slowpath(struct cache_set *c, const struct bkey_i *k,
				   bool meta)
{
	struct bch_member *mi;
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
	const struct bch_extent_ptr *ptr;

	mutex_lock(&c->sb_lock);

	/* recheck, might have raced */
	if (bch_check_super_marked(c, k, meta)) {
		mutex_unlock(&c->sb_lock);
		return;
	}

	mi = bch_sb_get_members(c->disk_sb)->members;

	extent_for_each_ptr(e, ptr)
		if (!ptr->cached)
			(meta
			 ? SET_BCH_MEMBER_HAS_METADATA
			 : SET_BCH_MEMBER_HAS_DATA)(mi + ptr->dev, true);

	bch_write_super(c);
	mutex_unlock(&c->sb_lock);
}
