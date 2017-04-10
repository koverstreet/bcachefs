
#include "bcachefs.h"
#include "checksum.h"
#include "error.h"
#include "io.h"
#include "journal.h"
#include "super-io.h"
#include "super.h"
#include "vstructs.h"

#include <linux/backing-dev.h>
#include <linux/sort.h>

static inline void __bch2_sb_layout_size_assert(void)
{
	BUILD_BUG_ON(sizeof(struct bch_sb_layout) != 512);
}

struct bch_sb_field *bch2_sb_field_get(struct bch_sb *sb,
				      enum bch_sb_field_type type)
{
	struct bch_sb_field *f;

	/* XXX: need locking around superblock to access optional fields */

	vstruct_for_each(sb, f)
		if (le32_to_cpu(f->type) == type)
			return f;
	return NULL;
}

void bch2_free_super(struct bcache_superblock *sb)
{
	if (sb->bio)
		bio_put(sb->bio);
	if (!IS_ERR_OR_NULL(sb->bdev))
		blkdev_put(sb->bdev, sb->mode);

	free_pages((unsigned long) sb->sb, sb->page_order);
	memset(sb, 0, sizeof(*sb));
}

static int __bch2_super_realloc(struct bcache_superblock *sb, unsigned order)
{
	struct bch_sb *new_sb;
	struct bio *bio;

	if (sb->page_order >= order && sb->sb)
		return 0;

	if (dynamic_fault("bcachefs:add:super_realloc"))
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

static int bch2_sb_realloc(struct bcache_superblock *sb, unsigned u64s)
{
	u64 new_bytes = __vstruct_bytes(struct bch_sb, u64s);
	u64 max_bytes = 512 << sb->sb->layout.sb_max_size_bits;

	if (new_bytes > max_bytes) {
		char buf[BDEVNAME_SIZE];

		pr_err("%s: superblock too big: want %llu but have %llu",
		       bdevname(sb->bdev, buf), new_bytes, max_bytes);
		return -ENOSPC;
	}

	return __bch2_super_realloc(sb, get_order(new_bytes));
}

static int bch2_fs_sb_realloc(struct bch_fs *c, unsigned u64s)
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

static struct bch_sb_field *__bch2_sb_field_resize(struct bch_sb *sb,
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

struct bch_sb_field *bch2_sb_field_resize(struct bcache_superblock *sb,
					 enum bch_sb_field_type type,
					 unsigned u64s)
{
	struct bch_sb_field *f = bch2_sb_field_get(sb->sb, type);
	ssize_t old_u64s = f ? le32_to_cpu(f->u64s) : 0;
	ssize_t d = -old_u64s + u64s;

	if (bch2_sb_realloc(sb, le32_to_cpu(sb->sb->u64s) + d))
		return NULL;

	f = __bch2_sb_field_resize(sb->sb, f, u64s);
	f->type = type;
	return f;
}

struct bch_sb_field *bch2_fs_sb_field_resize(struct bch_fs *c,
					    enum bch_sb_field_type type,
					    unsigned u64s)
{
	struct bch_sb_field *f = bch2_sb_field_get(c->disk_sb, type);
	ssize_t old_u64s = f ? le32_to_cpu(f->u64s) : 0;
	ssize_t d = -old_u64s + u64s;
	struct bch_dev *ca;
	unsigned i;

	lockdep_assert_held(&c->sb_lock);

	if (bch2_fs_sb_realloc(c, le32_to_cpu(c->disk_sb->u64s) + d))
		return NULL;

	/* XXX: we're not checking that offline device have enough space */

	for_each_online_member(ca, c, i) {
		struct bcache_superblock *sb = &ca->disk_sb;

		if (bch2_sb_realloc(sb, le32_to_cpu(sb->sb->u64s) + d)) {
			percpu_ref_put(&ca->ref);
			return NULL;
		}
	}

	f = __bch2_sb_field_resize(c->disk_sb, f, u64s);
	f->type = type;
	return f;
}

static const char *validate_sb_layout(struct bch_sb_layout *layout)
{
	u64 offset, prev_offset, max_sectors;
	unsigned i;

	if (uuid_le_cmp(layout->magic, BCACHE_MAGIC))
		return "Not a bcachefs superblock layout";

	if (layout->layout_type != 0)
		return "Invalid superblock layout type";

	if (!layout->nr_superblocks)
		return "Invalid superblock layout: no superblocks";

	if (layout->nr_superblocks > ARRAY_SIZE(layout->sb_offset))
		return "Invalid superblock layout: too many superblocks";

	max_sectors = 1 << layout->sb_max_size_bits;

	prev_offset = le64_to_cpu(layout->sb_offset[0]);

	for (i = 1; i < layout->nr_superblocks; i++) {
		offset = le64_to_cpu(layout->sb_offset[i]);

		if (offset < prev_offset + max_sectors)
			return "Invalid superblock layout: superblocks overlap";
		prev_offset = offset;
	}

	return NULL;
}

static int u64_cmp(const void *_l, const void *_r)
{
	u64 l = *((const u64 *) _l), r = *((const u64 *) _r);

	return l < r ? -1 : l > r ? 1 : 0;
}

const char *bch2_validate_journal_layout(struct bch_sb *sb,
					struct bch_member_cpu mi)
{
	struct bch_sb_field_journal *journal;
	const char *err;
	unsigned nr;
	unsigned i;
	u64 *b;

	journal = bch2_sb_get_journal(sb);
	if (!journal)
		return NULL;

	nr = bch2_nr_journal_buckets(journal);
	if (!nr)
		return NULL;

	b = kmalloc_array(sizeof(u64), nr, GFP_KERNEL);
	if (!b)
		return "cannot allocate memory";

	for (i = 0; i < nr; i++)
		b[i] = le64_to_cpu(journal->buckets[i]);

	sort(b, nr, sizeof(u64), u64_cmp, NULL);

	err = "journal bucket at sector 0";
	if (!b[0])
		goto err;

	err = "journal bucket before first bucket";
	if (b[0] < mi.first_bucket)
		goto err;

	err = "journal bucket past end of device";
	if (b[nr - 1] >= mi.nbuckets)
		goto err;

	err = "duplicate journal buckets";
	for (i = 0; i + 1 < nr; i++)
		if (b[i] == b[i + 1])
			goto err;

	err = NULL;
err:
	kfree(b);
	return err;
}

static const char *bch2_sb_validate_members(struct bch_sb *sb)
{
	struct bch_sb_field_members *mi;
	unsigned i;

	mi = bch2_sb_get_members(sb);
	if (!mi)
		return "Invalid superblock: member info area missing";

	if ((void *) (mi->members + sb->nr_devices) >
	    vstruct_end(&mi->field))
		return "Invalid superblock: bad member info";

	for (i = 0; i < sb->nr_devices; i++) {
		if (bch2_is_zero(mi->members[i].uuid.b, sizeof(uuid_le)))
			continue;

		if (le16_to_cpu(mi->members[i].bucket_size) <
		    BCH_SB_BTREE_NODE_SIZE(sb))
			return "bucket size smaller than btree node size";
	}

	return NULL;
}

const char *bch2_validate_cache_super(struct bcache_superblock *disk_sb)
{
	struct bch_sb *sb = disk_sb->sb;
	struct bch_sb_field *f;
	struct bch_sb_field_members *sb_mi;
	struct bch_member_cpu mi;
	const char *err;
	u16 block_size;

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

	if (bch2_is_zero(sb->user_uuid.b, sizeof(uuid_le)))
		return "Bad user UUID";

	if (bch2_is_zero(sb->uuid.b, sizeof(uuid_le)))
		return "Bad internal UUID";

	if (!sb->nr_devices ||
	    sb->nr_devices <= sb->dev_idx ||
	    sb->nr_devices > BCH_SB_MEMBERS_MAX)
		return "Bad cache device number in set";

	if (!BCH_SB_META_REPLICAS_WANT(sb) ||
	    BCH_SB_META_REPLICAS_WANT(sb) >= BCH_REPLICAS_MAX)
		return "Invalid number of metadata replicas";

	if (!BCH_SB_META_REPLICAS_REQ(sb) ||
	    BCH_SB_META_REPLICAS_REQ(sb) >= BCH_REPLICAS_MAX)
		return "Invalid number of metadata replicas";

	if (!BCH_SB_META_REPLICAS_HAVE(sb) ||
	    BCH_SB_META_REPLICAS_HAVE(sb) >
	    BCH_SB_META_REPLICAS_WANT(sb))
		return "Invalid number of metadata replicas";

	if (!BCH_SB_DATA_REPLICAS_WANT(sb) ||
	    BCH_SB_DATA_REPLICAS_WANT(sb) >= BCH_REPLICAS_MAX)
		return "Invalid number of data replicas";

	if (!BCH_SB_DATA_REPLICAS_REQ(sb) ||
	    BCH_SB_DATA_REPLICAS_REQ(sb) >= BCH_REPLICAS_MAX)
		return "Invalid number of metadata replicas";

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

	err = bch2_sb_validate_members(sb);
	if (err)
		return err;

	sb_mi = bch2_sb_get_members(sb);
	mi = bch2_mi_to_cpu(sb_mi->members + sb->dev_idx);

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

	err = bch2_validate_journal_layout(sb, mi);
	if (err)
		return err;

	return NULL;
}

/* device open: */

static const char *bch2_blkdev_open(const char *path, fmode_t mode,
				   void *holder, struct block_device **ret)
{
	struct block_device *bdev;

	*ret = NULL;
	bdev = blkdev_get_by_path(path, mode, holder);
	if (bdev == ERR_PTR(-EBUSY))
		return "device busy";

	if (IS_ERR(bdev))
		return "failed to open device";

	if (mode & FMODE_WRITE)
		bdev_get_queue(bdev)->backing_dev_info.capabilities
			|= BDI_CAP_STABLE_WRITES;

	*ret = bdev;
	return NULL;
}

static void bch2_sb_update(struct bch_fs *c)
{
	struct bch_sb *src = c->disk_sb;
	struct bch_sb_field_members *mi = bch2_sb_get_members(src);
	struct bch_dev *ca;
	unsigned i;

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

	for_each_member_device(ca, c, i)
		ca->mi = bch2_mi_to_cpu(mi->members + i);
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

		dst_f = bch2_sb_field_get(dst, src_f->type);
		dst_f = __bch2_sb_field_resize(dst, dst_f,
				le32_to_cpu(src_f->u64s));

		memcpy(dst_f, src_f, vstruct_bytes(src_f));
	}
}

int bch2_sb_to_fs(struct bch_fs *c, struct bch_sb *src)
{
	struct bch_sb_field_journal *journal_buckets =
		bch2_sb_get_journal(src);
	unsigned journal_u64s = journal_buckets
		? le32_to_cpu(journal_buckets->field.u64s)
		: 0;

	lockdep_assert_held(&c->sb_lock);

	if (bch2_fs_sb_realloc(c, le32_to_cpu(src->u64s) - journal_u64s))
		return -ENOMEM;

	__copy_super(c->disk_sb, src);
	bch2_sb_update(c);

	return 0;
}

int bch2_sb_from_fs(struct bch_fs *c, struct bch_dev *ca)
{
	struct bch_sb *src = c->disk_sb, *dst = ca->disk_sb.sb;
	struct bch_sb_field_journal *journal_buckets =
		bch2_sb_get_journal(dst);
	unsigned journal_u64s = journal_buckets
		? le32_to_cpu(journal_buckets->field.u64s)
		: 0;
	unsigned u64s = le32_to_cpu(src->u64s) + journal_u64s;
	int ret;

	ret = bch2_sb_realloc(&ca->disk_sb, u64s);
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
	sb->bio->bi_iter.bi_sector = offset;
	sb->bio->bi_iter.bi_size = PAGE_SIZE << sb->page_order;
	bio_set_op_attrs(sb->bio, REQ_OP_READ, REQ_SYNC|REQ_META);
	bch2_bio_map(sb->bio, sb->sb);

	if (submit_bio_wait(sb->bio))
		return "IO error";

	if (uuid_le_cmp(sb->sb->magic, BCACHE_MAGIC))
		return "Not a bcachefs superblock";

	if (le64_to_cpu(sb->sb->version) != BCACHE_SB_VERSION_CDEV_V4)
		return "Unsupported superblock version";

	bytes = vstruct_bytes(sb->sb);

	if (bytes > 512 << sb->sb->layout.sb_max_size_bits)
		return "Bad superblock: too big";

	order = get_order(bytes);
	if (order > sb->page_order) {
		if (__bch2_super_realloc(sb, order))
			return "cannot allocate memory";
		goto reread;
	}

	if (BCH_SB_CSUM_TYPE(sb->sb) >= BCH_CSUM_NR)
		return "unknown csum type";

	/* XXX: verify MACs */
	csum = csum_vstruct(NULL, BCH_SB_CSUM_TYPE(sb->sb),
			    (struct nonce) { 0 }, sb->sb);

	if (bch2_crc_cmp(csum, sb->sb->csum))
		return "bad checksum reading superblock";

	return NULL;
}

const char *bch2_read_super(struct bcache_superblock *sb,
			   struct bch_opts opts,
			   const char *path)
{
	u64 offset = opt_defined(opts.sb) ? opts.sb : BCH_SB_SECTOR;
	struct bch_sb_layout layout;
	const char *err;
	unsigned i;

	memset(sb, 0, sizeof(*sb));
	sb->mode = FMODE_READ;

	if (!(opt_defined(opts.noexcl) && opts.noexcl))
		sb->mode |= FMODE_EXCL;

	if (!(opt_defined(opts.nochanges) && opts.nochanges))
		sb->mode |= FMODE_WRITE;

	err = bch2_blkdev_open(path, sb->mode, sb, &sb->bdev);
	if (err)
		return err;

	err = "cannot allocate memory";
	if (__bch2_super_realloc(sb, 0))
		goto err;

	err = "dynamic fault";
	if (bch2_fs_init_fault("read_super"))
		goto err;

	err = read_one_super(sb, offset);
	if (!err)
		goto got_super;

	if (offset != BCH_SB_SECTOR) {
		pr_err("error reading superblock: %s", err);
		goto err;
	}

	pr_err("error reading default superblock: %s", err);

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
	bch2_bio_map(sb->bio, sb->sb);

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
	bch2_free_super(sb);
	return err;
}

/* write superblock: */

static void write_super_endio(struct bio *bio)
{
	struct bch_dev *ca = bio->bi_private;

	/* XXX: return errors directly */

	bch2_dev_fatal_io_err_on(bio->bi_error, ca, "superblock write");

	closure_put(&ca->fs->sb_write);
	percpu_ref_put(&ca->io_ref);
}

static bool write_one_super(struct bch_fs *c, struct bch_dev *ca, unsigned idx)
{
	struct bch_sb *sb = ca->disk_sb.sb;
	struct bio *bio = ca->disk_sb.bio;

	if (idx >= sb->layout.nr_superblocks)
		return false;

	if (!percpu_ref_tryget(&ca->io_ref))
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
	bch2_bio_map(bio, sb);

	closure_bio_submit(bio, &c->sb_write);
	return true;
}

void bch2_write_super(struct bch_fs *c)
{
	struct closure *cl = &c->sb_write;
	struct bch_dev *ca;
	unsigned i, super_idx = 0;
	bool wrote;

	lockdep_assert_held(&c->sb_lock);

	closure_init_stack(cl);

	le64_add_cpu(&c->disk_sb->seq, 1);

	for_each_online_member(ca, c, i)
		bch2_sb_from_fs(c, ca);

	if (c->opts.nochanges)
		goto out;

	do {
		wrote = false;
		for_each_online_member(ca, c, i)
			if (write_one_super(c, ca, super_idx))
				wrote = true;

		closure_sync(cl);
		super_idx++;
	} while (wrote);
out:
	/* Make new options visible after they're persistent: */
	bch2_sb_update(c);
}

void bch2_check_mark_super_slowpath(struct bch_fs *c, const struct bkey_i *k,
				   bool meta)
{
	struct bch_member *mi;
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
	const struct bch_extent_ptr *ptr;
	unsigned nr_replicas = 0;

	mutex_lock(&c->sb_lock);

	/* recheck, might have raced */
	if (bch2_check_super_marked(c, k, meta)) {
		mutex_unlock(&c->sb_lock);
		return;
	}

	mi = bch2_sb_get_members(c->disk_sb)->members;

	extent_for_each_ptr(e, ptr)
		if (!ptr->cached) {
			(meta
			 ? SET_BCH_MEMBER_HAS_METADATA
			 : SET_BCH_MEMBER_HAS_DATA)(mi + ptr->dev, true);
			nr_replicas++;
		}

	nr_replicas = min_t(unsigned, nr_replicas,
			    (meta
			     ? BCH_SB_META_REPLICAS_HAVE
			     : BCH_SB_DATA_REPLICAS_HAVE)(c->disk_sb));
	(meta
	 ? SET_BCH_SB_META_REPLICAS_HAVE
	 : SET_BCH_SB_DATA_REPLICAS_HAVE)(c->disk_sb, nr_replicas);

	bch2_write_super(c);
	mutex_unlock(&c->sb_lock);
}
