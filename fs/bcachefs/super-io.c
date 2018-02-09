
#include "bcachefs.h"
#include "checksum.h"
#include "error.h"
#include "io.h"
#include "super-io.h"
#include "super.h"
#include "vstructs.h"

#include <linux/backing-dev.h>
#include <linux/sort.h>

static int bch2_sb_replicas_to_cpu_replicas(struct bch_fs *);
static int bch2_cpu_replicas_to_sb_replicas(struct bch_fs *,
					    struct bch_replicas_cpu *);
static int bch2_sb_disk_groups_to_cpu(struct bch_fs *);

/* superblock fields (optional/variable size sections: */

const char * const bch2_sb_fields[] = {
#define x(name, nr)	#name,
	BCH_SB_FIELDS()
#undef x
	NULL
};

#define x(f, nr)					\
static const char *bch2_sb_validate_##f(struct bch_sb *, struct bch_sb_field *);
	BCH_SB_FIELDS()
#undef x

struct bch_sb_field_ops {
	const char *	(*validate)(struct bch_sb *, struct bch_sb_field *);
};

static const struct bch_sb_field_ops bch2_sb_field_ops[] = {
#define x(f, nr)					\
	[BCH_SB_FIELD_##f] = {				\
		.validate = bch2_sb_validate_##f,	\
	},
	BCH_SB_FIELDS()
#undef x
};

static const char *bch2_sb_field_validate(struct bch_sb *sb,
					  struct bch_sb_field *f)

{
	unsigned type = le32_to_cpu(f->type);

	return type < BCH_SB_FIELD_NR
		? bch2_sb_field_ops[type].validate(sb, f)
		: NULL;
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

/* Superblock realloc/free: */

void bch2_free_super(struct bch_sb_handle *sb)
{
	if (sb->bio)
		bio_put(sb->bio);
	if (!IS_ERR_OR_NULL(sb->bdev))
		blkdev_put(sb->bdev, sb->mode);

	free_pages((unsigned long) sb->sb, sb->page_order);
	memset(sb, 0, sizeof(*sb));
}

static int __bch2_super_realloc(struct bch_sb_handle *sb, unsigned order)
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

static int bch2_sb_realloc(struct bch_sb_handle *sb, unsigned u64s)
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

struct bch_sb_field *bch2_sb_field_resize(struct bch_sb_handle *sb,
					  enum bch_sb_field_type type,
					  unsigned u64s)
{
	struct bch_sb_field *f = bch2_sb_field_get(sb->sb, type);
	ssize_t old_u64s = f ? le32_to_cpu(f->u64s) : 0;
	ssize_t d = -old_u64s + u64s;

	if (bch2_sb_realloc(sb, le32_to_cpu(sb->sb->u64s) + d))
		return NULL;

	f = __bch2_sb_field_resize(sb->sb, f, u64s);
	f->type = cpu_to_le32(type);
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
		struct bch_sb_handle *sb = &ca->disk_sb;

		if (bch2_sb_realloc(sb, le32_to_cpu(sb->sb->u64s) + d)) {
			percpu_ref_put(&ca->ref);
			return NULL;
		}
	}

	f = __bch2_sb_field_resize(c->disk_sb, f, u64s);
	f->type = cpu_to_le32(type);
	return f;
}

/* Superblock validate: */

static inline void __bch2_sb_layout_size_assert(void)
{
	BUILD_BUG_ON(sizeof(struct bch_sb_layout) != 512);
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

const char *bch2_sb_validate(struct bch_sb_handle *disk_sb)
{
	struct bch_sb *sb = disk_sb->sb;
	struct bch_sb_field *f;
	struct bch_sb_field_members *mi;
	const char *err;
	u16 block_size;

	if (le64_to_cpu(sb->version) < BCH_SB_VERSION_MIN ||
	    le64_to_cpu(sb->version) > BCH_SB_VERSION_MAX)
		return"Unsupported superblock version";

	if (le64_to_cpu(sb->version) < BCH_SB_VERSION_EXTENT_MAX) {
		SET_BCH_SB_ENCODED_EXTENT_MAX_BITS(sb, 7);
		SET_BCH_SB_POSIX_ACL(sb, 1);
	}

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
		return "Bad number of member devices";

	if (!BCH_SB_META_REPLICAS_WANT(sb) ||
	    BCH_SB_META_REPLICAS_WANT(sb) >= BCH_REPLICAS_MAX)
		return "Invalid number of metadata replicas";

	if (!BCH_SB_META_REPLICAS_REQ(sb) ||
	    BCH_SB_META_REPLICAS_REQ(sb) >= BCH_REPLICAS_MAX)
		return "Invalid number of metadata replicas";

	if (!BCH_SB_DATA_REPLICAS_WANT(sb) ||
	    BCH_SB_DATA_REPLICAS_WANT(sb) >= BCH_REPLICAS_MAX)
		return "Invalid number of data replicas";

	if (!BCH_SB_DATA_REPLICAS_REQ(sb) ||
	    BCH_SB_DATA_REPLICAS_REQ(sb) >= BCH_REPLICAS_MAX)
		return "Invalid number of data replicas";

	if (BCH_SB_META_CSUM_TYPE(sb) >= BCH_CSUM_OPT_NR)
		return "Invalid metadata checksum type";

	if (BCH_SB_DATA_CSUM_TYPE(sb) >= BCH_CSUM_OPT_NR)
		return "Invalid metadata checksum type";

	if (BCH_SB_COMPRESSION_TYPE(sb) >= BCH_COMPRESSION_OPT_NR)
		return "Invalid compression type";

	if (!BCH_SB_BTREE_NODE_SIZE(sb))
		return "Btree node size not set";

	if (!is_power_of_2(BCH_SB_BTREE_NODE_SIZE(sb)))
		return "Btree node size not a power of two";

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
	}

	/* members must be validated first: */
	mi = bch2_sb_get_members(sb);
	if (!mi)
		return "Invalid superblock: member info area missing";

	err = bch2_sb_field_validate(sb, &mi->field);
	if (err)
		return err;

	vstruct_for_each(sb, f) {
		if (le32_to_cpu(f->type) == BCH_SB_FIELD_members)
			continue;

		err = bch2_sb_field_validate(sb, f);
		if (err)
			return err;
	}

	if (le64_to_cpu(sb->version) < BCH_SB_VERSION_EXTENT_NONCE_V1 &&
	    bch2_sb_get_crypt(sb) &&
	    BCH_SB_INITIALIZED(sb))
		return "Incompatible extent nonces";

	sb->version = cpu_to_le64(BCH_SB_VERSION_MAX);

	return NULL;
}

/* device open: */

static void bch2_sb_update(struct bch_fs *c)
{
	struct bch_sb *src = c->disk_sb;
	struct bch_sb_field_members *mi = bch2_sb_get_members(src);
	struct bch_dev *ca;
	unsigned i;

	lockdep_assert_held(&c->sb_lock);

	c->sb.uuid		= src->uuid;
	c->sb.user_uuid		= src->user_uuid;
	c->sb.nr_devices	= src->nr_devices;
	c->sb.clean		= BCH_SB_CLEAN(src);
	c->sb.encryption_type	= BCH_SB_ENCRYPTION_TYPE(src);
	c->sb.encoded_extent_max= 1 << BCH_SB_ENCODED_EXTENT_MAX_BITS(src);
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

		dst_f = bch2_sb_field_get(dst, le32_to_cpu(src_f->type));
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
	int ret;

	lockdep_assert_held(&c->sb_lock);

	ret = bch2_fs_sb_realloc(c, le32_to_cpu(src->u64s) - journal_u64s);
	if (ret)
		return ret;

	__copy_super(c->disk_sb, src);

	ret = bch2_sb_replicas_to_cpu_replicas(c);
	if (ret)
		return ret;

	ret = bch2_sb_disk_groups_to_cpu(c);
	if (ret)
		return ret;

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

static const char *read_one_super(struct bch_sb_handle *sb, u64 offset)
{
	struct bch_csum csum;
	size_t bytes;
	unsigned order;
reread:
	bio_reset(sb->bio);
	bio_set_dev(sb->bio, sb->bdev);
	sb->bio->bi_iter.bi_sector = offset;
	sb->bio->bi_iter.bi_size = PAGE_SIZE << sb->page_order;
	bio_set_op_attrs(sb->bio, REQ_OP_READ, REQ_SYNC|REQ_META);
	bch2_bio_map(sb->bio, sb->sb);

	if (submit_bio_wait(sb->bio))
		return "IO error";

	if (uuid_le_cmp(sb->sb->magic, BCACHE_MAGIC))
		return "Not a bcachefs superblock";

	if (le64_to_cpu(sb->sb->version) < BCH_SB_VERSION_MIN ||
	    le64_to_cpu(sb->sb->version) > BCH_SB_VERSION_MAX)
		return"Unsupported superblock version";

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
			    null_nonce(), sb->sb);

	if (bch2_crc_cmp(csum, sb->sb->csum))
		return "bad checksum reading superblock";

	return NULL;
}

int bch2_read_super(const char *path, struct bch_opts *opts,
		    struct bch_sb_handle *sb)
{
	u64 offset = opt_get(*opts, sb);
	struct bch_sb_layout layout;
	const char *err;
	__le64 *i;
	int ret;

	pr_verbose_init(*opts, "");

	memset(sb, 0, sizeof(*sb));
	sb->mode = FMODE_READ;

	if (!opt_get(*opts, noexcl))
		sb->mode |= FMODE_EXCL;

	if (!opt_get(*opts, nochanges))
		sb->mode |= FMODE_WRITE;

	sb->bdev = blkdev_get_by_path(path, sb->mode, sb);
	if (IS_ERR(sb->bdev) &&
	    PTR_ERR(sb->bdev) == -EACCES &&
	    opt_get(*opts, read_only)) {
		sb->mode &= ~FMODE_WRITE;

		sb->bdev = blkdev_get_by_path(path, sb->mode, sb);
		if (!IS_ERR(sb->bdev))
			opt_set(*opts, nochanges, true);
	}

	if (IS_ERR(sb->bdev)) {
		ret = PTR_ERR(sb->bdev);
		goto out;
	}

	err = "cannot allocate memory";
	ret = __bch2_super_realloc(sb, 0);
	if (ret)
		goto err;

	ret = -EFAULT;
	err = "dynamic fault";
	if (bch2_fs_init_fault("read_super"))
		goto err;

	ret = -EINVAL;
	err = read_one_super(sb, offset);
	if (!err)
		goto got_super;

	if (opt_defined(*opts, sb))
		goto err;

	pr_err("error reading default superblock: %s", err);

	/*
	 * Error reading primary superblock - read location of backup
	 * superblocks:
	 */
	bio_reset(sb->bio);
	bio_set_dev(sb->bio, sb->bdev);
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

	for (i = layout.sb_offset;
	     i < layout.sb_offset + layout.nr_superblocks; i++) {
		offset = le64_to_cpu(*i);

		if (offset == opt_get(*opts, sb))
			continue;

		err = read_one_super(sb, offset);
		if (!err)
			goto got_super;
	}

	ret = -EINVAL;
	goto err;

got_super:
	err = "Superblock block size smaller than device block size";
	ret = -EINVAL;
	if (le16_to_cpu(sb->sb->block_size) << 9 <
	    bdev_logical_block_size(sb->bdev))
		goto err;

	if (sb->mode & FMODE_WRITE)
		bdev_get_queue(sb->bdev)->backing_dev_info->capabilities
			|= BDI_CAP_STABLE_WRITES;
	ret = 0;
out:
	pr_verbose_init(*opts, "ret %i", ret);
	return ret;
err:
	bch2_free_super(sb);
	pr_err("error reading superblock: %s", err);
	goto out;
}

/* write superblock: */

static void write_super_endio(struct bio *bio)
{
	struct bch_dev *ca = bio->bi_private;

	/* XXX: return errors directly */

	if (bch2_dev_io_err_on(bio->bi_status, ca, "superblock write"))
		ca->sb_write_error = 1;

	closure_put(&ca->fs->sb_write);
	percpu_ref_put(&ca->io_ref);
}

static void write_one_super(struct bch_fs *c, struct bch_dev *ca, unsigned idx)
{
	struct bch_sb *sb = ca->disk_sb.sb;
	struct bio *bio = ca->disk_sb.bio;

	sb->offset = sb->layout.sb_offset[idx];

	SET_BCH_SB_CSUM_TYPE(sb, c->opts.metadata_checksum);
	sb->csum = csum_vstruct(c, BCH_SB_CSUM_TYPE(sb),
				null_nonce(), sb);

	bio_reset(bio);
	bio_set_dev(bio, ca->disk_sb.bdev);
	bio->bi_iter.bi_sector	= le64_to_cpu(sb->offset);
	bio->bi_iter.bi_size	=
		roundup(vstruct_bytes(sb),
			bdev_logical_block_size(ca->disk_sb.bdev));
	bio->bi_end_io		= write_super_endio;
	bio->bi_private		= ca;
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_SYNC|REQ_META);
	bch2_bio_map(bio, sb);

	this_cpu_add(ca->io_done->sectors[WRITE][BCH_DATA_SB],
		     bio_sectors(bio));

	percpu_ref_get(&ca->io_ref);
	closure_bio_submit(bio, &c->sb_write);
}

void bch2_write_super(struct bch_fs *c)
{
	struct closure *cl = &c->sb_write;
	struct bch_dev *ca;
	unsigned i, sb = 0, nr_wrote;
	const char *err;
	struct bch_devs_mask sb_written;
	bool wrote, can_mount_without_written, can_mount_with_written;

	lockdep_assert_held(&c->sb_lock);

	closure_init_stack(cl);
	memset(&sb_written, 0, sizeof(sb_written));

	le64_add_cpu(&c->disk_sb->seq, 1);

	for_each_online_member(ca, c, i)
		bch2_sb_from_fs(c, ca);

	for_each_online_member(ca, c, i) {
		err = bch2_sb_validate(&ca->disk_sb);
		if (err) {
			bch2_fs_inconsistent(c, "sb invalid before write: %s", err);
			goto out;
		}
	}

	if (c->opts.nochanges ||
	    test_bit(BCH_FS_ERROR, &c->flags))
		goto out;

	for_each_online_member(ca, c, i) {
		__set_bit(ca->dev_idx, sb_written.d);
		ca->sb_write_error = 0;
	}

	do {
		wrote = false;
		for_each_online_member(ca, c, i)
			if (sb < ca->disk_sb.sb->layout.nr_superblocks) {
				write_one_super(c, ca, sb);
				wrote = true;
			}
		closure_sync(cl);
		sb++;
	} while (wrote);

	for_each_online_member(ca, c, i)
		if (ca->sb_write_error)
			__clear_bit(ca->dev_idx, sb_written.d);

	nr_wrote = dev_mask_nr(&sb_written);

	can_mount_with_written =
		bch2_have_enough_devs(__bch2_replicas_status(c, sb_written),
				      BCH_FORCE_IF_DEGRADED);

	for (i = 0; i < ARRAY_SIZE(sb_written.d); i++)
		sb_written.d[i] = ~sb_written.d[i];

	can_mount_without_written =
		bch2_have_enough_devs(__bch2_replicas_status(c, sb_written),
				      BCH_FORCE_IF_DEGRADED);

	/*
	 * If we would be able to mount _without_ the devices we successfully
	 * wrote superblocks to, we weren't able to write to enough devices:
	 *
	 * Exception: if we can mount without the successes because we haven't
	 * written anything (new filesystem), we continue if we'd be able to
	 * mount with the devices we did successfully write to:
	 */
	bch2_fs_fatal_err_on(!nr_wrote ||
			     (can_mount_without_written &&
			      !can_mount_with_written), c,
		"Unable to write superblock to sufficient devices");
out:
	/* Make new options visible after they're persistent: */
	bch2_sb_update(c);
}

/* BCH_SB_FIELD_journal: */

static int u64_cmp(const void *_l, const void *_r)
{
	u64 l = *((const u64 *) _l), r = *((const u64 *) _r);

	return l < r ? -1 : l > r ? 1 : 0;
}

static const char *bch2_sb_validate_journal(struct bch_sb *sb,
					    struct bch_sb_field *f)
{
	struct bch_sb_field_journal *journal = field_to_type(f, journal);
	struct bch_member *m = bch2_sb_get_members(sb)->members + sb->dev_idx;
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
	if (m && b[0] < le16_to_cpu(m->first_bucket))
		goto err;

	err = "journal bucket past end of device";
	if (m && b[nr - 1] >= le64_to_cpu(m->nbuckets))
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

/* BCH_SB_FIELD_members: */

static const char *bch2_sb_validate_members(struct bch_sb *sb,
					    struct bch_sb_field *f)
{
	struct bch_sb_field_members *mi = field_to_type(f, members);
	struct bch_member *m;

	if ((void *) (mi->members + sb->nr_devices) >
	    vstruct_end(&mi->field))
		return "Invalid superblock: bad member info";

	for (m = mi->members;
	     m < mi->members + sb->nr_devices;
	     m++) {
		if (!bch2_member_exists(m))
			continue;

		if (le64_to_cpu(m->nbuckets) > LONG_MAX)
			return "Too many buckets";

		if (le64_to_cpu(m->nbuckets) -
		    le16_to_cpu(m->first_bucket) < 1 << 10)
			return "Not enough buckets";

		if (le16_to_cpu(m->bucket_size) <
		    le16_to_cpu(sb->block_size))
			return "bucket size smaller than block size";

		if (le16_to_cpu(m->bucket_size) <
		    BCH_SB_BTREE_NODE_SIZE(sb))
			return "bucket size smaller than btree node size";
	}

	if (le64_to_cpu(sb->version) < BCH_SB_VERSION_EXTENT_MAX)
		for (m = mi->members;
		     m < mi->members + sb->nr_devices;
		     m++)
			SET_BCH_MEMBER_DATA_ALLOWED(m, ~0);

	return NULL;
}

/* BCH_SB_FIELD_crypt: */

static const char *bch2_sb_validate_crypt(struct bch_sb *sb,
					  struct bch_sb_field *f)
{
	struct bch_sb_field_crypt *crypt = field_to_type(f, crypt);

	if (vstruct_bytes(&crypt->field) != sizeof(*crypt))
		return "invalid field crypt: wrong size";

	if (BCH_CRYPT_KDF_TYPE(crypt))
		return "invalid field crypt: bad kdf type";

	return NULL;
}

/* BCH_SB_FIELD_replicas: */

/* Replicas tracking - in memory: */

#define for_each_cpu_replicas_entry(_r, _i)				\
	for (_i = (_r)->entries;					\
	     (void *) (_i) < (void *) (_r)->entries + (_r)->nr * (_r)->entry_size;\
	     _i = (void *) (_i) + (_r)->entry_size)

static inline struct bch_replicas_cpu_entry *
cpu_replicas_entry(struct bch_replicas_cpu *r, unsigned i)
{
	return (void *) r->entries + r->entry_size * i;
}

static void bch2_cpu_replicas_sort(struct bch_replicas_cpu *r)
{
	eytzinger0_sort(r->entries, r->nr, r->entry_size, memcmp, NULL);
}

static inline bool replicas_test_dev(struct bch_replicas_cpu_entry *e,
				     unsigned dev)
{
	return (e->devs[dev >> 3] & (1 << (dev & 7))) != 0;
}

static inline void replicas_set_dev(struct bch_replicas_cpu_entry *e,
				    unsigned dev)
{
	e->devs[dev >> 3] |= 1 << (dev & 7);
}

static inline unsigned replicas_dev_slots(struct bch_replicas_cpu *r)
{
	return (r->entry_size -
		offsetof(struct bch_replicas_cpu_entry, devs)) * 8;
}

int bch2_cpu_replicas_to_text(struct bch_replicas_cpu *r,
			      char *buf, size_t size)
{
	char *out = buf, *end = out + size;
	struct bch_replicas_cpu_entry *e;
	bool first = true;
	unsigned i;

	for_each_cpu_replicas_entry(r, e) {
		bool first_e = true;

		if (!first)
			out += scnprintf(out, end - out, " ");
		first = false;

		out += scnprintf(out, end - out, "%u: [", e->data_type);

		for (i = 0; i < replicas_dev_slots(r); i++)
			if (replicas_test_dev(e, i)) {
				if (!first_e)
					out += scnprintf(out, end - out, " ");
				first_e = false;
				out += scnprintf(out, end - out, "%u", i);
			}
		out += scnprintf(out, end - out, "]");
	}

	return out - buf;
}

static inline unsigned bkey_to_replicas(struct bkey_s_c_extent e,
					enum bch_data_type data_type,
					struct bch_replicas_cpu_entry *r,
					unsigned *max_dev)
{
	const struct bch_extent_ptr *ptr;
	unsigned nr = 0;

	BUG_ON(!data_type ||
	       data_type == BCH_DATA_SB ||
	       data_type >= BCH_DATA_NR);

	memset(r, 0, sizeof(*r));
	r->data_type = data_type;

	*max_dev = 0;

	extent_for_each_ptr(e, ptr)
		if (!ptr->cached) {
			*max_dev = max_t(unsigned, *max_dev, ptr->dev);
			replicas_set_dev(r, ptr->dev);
			nr++;
		}
	return nr;
}

static inline void devlist_to_replicas(struct bch_devs_list devs,
				       enum bch_data_type data_type,
				       struct bch_replicas_cpu_entry *r,
				       unsigned *max_dev)
{
	unsigned i;

	BUG_ON(!data_type ||
	       data_type == BCH_DATA_SB ||
	       data_type >= BCH_DATA_NR);

	memset(r, 0, sizeof(*r));
	r->data_type = data_type;

	*max_dev = 0;

	for (i = 0; i < devs.nr; i++) {
		*max_dev = max_t(unsigned, *max_dev, devs.devs[i]);
		replicas_set_dev(r, devs.devs[i]);
	}
}

static struct bch_replicas_cpu *
cpu_replicas_add_entry(struct bch_replicas_cpu *old,
		       struct bch_replicas_cpu_entry new_entry,
		       unsigned max_dev)
{
	struct bch_replicas_cpu *new;
	unsigned i, nr, entry_size;

	entry_size = offsetof(struct bch_replicas_cpu_entry, devs) +
		DIV_ROUND_UP(max_dev + 1, 8);
	entry_size = max(entry_size, old->entry_size);
	nr = old->nr + 1;

	new = kzalloc(sizeof(struct bch_replicas_cpu) +
		      nr * entry_size, GFP_NOIO);
	if (!new)
		return NULL;

	new->nr		= nr;
	new->entry_size	= entry_size;

	for (i = 0; i < old->nr; i++)
		memcpy(cpu_replicas_entry(new, i),
		       cpu_replicas_entry(old, i),
		       min(new->entry_size, old->entry_size));

	memcpy(cpu_replicas_entry(new, old->nr),
	       &new_entry,
	       new->entry_size);

	bch2_cpu_replicas_sort(new);
	return new;
}

static bool replicas_has_entry(struct bch_replicas_cpu *r,
				struct bch_replicas_cpu_entry search,
				unsigned max_dev)
{
	return max_dev < replicas_dev_slots(r) &&
		eytzinger0_find(r->entries, r->nr,
				r->entry_size,
				memcmp, &search) < r->nr;
}

noinline
static int bch2_mark_replicas_slowpath(struct bch_fs *c,
				struct bch_replicas_cpu_entry new_entry,
				unsigned max_dev)
{
	struct bch_replicas_cpu *old_gc, *new_gc = NULL, *old_r, *new_r = NULL;
	int ret = -ENOMEM;

	mutex_lock(&c->sb_lock);

	old_gc = rcu_dereference_protected(c->replicas_gc,
					   lockdep_is_held(&c->sb_lock));
	if (old_gc && !replicas_has_entry(old_gc, new_entry, max_dev)) {
		new_gc = cpu_replicas_add_entry(old_gc, new_entry, max_dev);
		if (!new_gc)
			goto err;
	}

	old_r = rcu_dereference_protected(c->replicas,
					  lockdep_is_held(&c->sb_lock));
	if (!replicas_has_entry(old_r, new_entry, max_dev)) {
		new_r = cpu_replicas_add_entry(old_r, new_entry, max_dev);
		if (!new_r)
			goto err;

		ret = bch2_cpu_replicas_to_sb_replicas(c, new_r);
		if (ret)
			goto err;
	}

	/* allocations done, now commit: */

	if (new_r)
		bch2_write_super(c);

	/* don't update in memory replicas until changes are persistent */

	if (new_gc) {
		rcu_assign_pointer(c->replicas_gc, new_gc);
		kfree_rcu(old_gc, rcu);
	}

	if (new_r) {
		rcu_assign_pointer(c->replicas, new_r);
		kfree_rcu(old_r, rcu);
	}

	mutex_unlock(&c->sb_lock);
	return 0;
err:
	mutex_unlock(&c->sb_lock);
	if (new_gc)
		kfree(new_gc);
	if (new_r)
		kfree(new_r);
	return ret;
}

int bch2_mark_replicas(struct bch_fs *c,
		       enum bch_data_type data_type,
		       struct bch_devs_list devs)
{
	struct bch_replicas_cpu_entry search;
	struct bch_replicas_cpu *r, *gc_r;
	unsigned max_dev;
	bool marked;

	if (!devs.nr)
		return 0;

	BUG_ON(devs.nr >= BCH_REPLICAS_MAX);

	devlist_to_replicas(devs, data_type, &search, &max_dev);

	rcu_read_lock();
	r = rcu_dereference(c->replicas);
	gc_r = rcu_dereference(c->replicas_gc);
	marked = replicas_has_entry(r, search, max_dev) &&
		(!likely(gc_r) || replicas_has_entry(gc_r, search, max_dev));
	rcu_read_unlock();

	return likely(marked) ? 0
		: bch2_mark_replicas_slowpath(c, search, max_dev);
}

int bch2_mark_bkey_replicas(struct bch_fs *c,
			    enum bch_data_type data_type,
			    struct bkey_s_c k)
{
	struct bch_devs_list cached = bch2_bkey_cached_devs(k);
	unsigned i;
	int ret;

	for (i = 0; i < cached.nr; i++)
		if ((ret = bch2_mark_replicas(c, BCH_DATA_CACHED,
					      bch2_dev_list_single(cached.devs[i]))))
			return ret;

	return bch2_mark_replicas(c, data_type, bch2_bkey_dirty_devs(k));
}

int bch2_replicas_gc_end(struct bch_fs *c, int err)
{
	struct bch_replicas_cpu *new_r, *old_r;
	int ret = 0;

	lockdep_assert_held(&c->replicas_gc_lock);

	mutex_lock(&c->sb_lock);

	new_r = rcu_dereference_protected(c->replicas_gc,
					  lockdep_is_held(&c->sb_lock));

	if (err) {
		rcu_assign_pointer(c->replicas_gc, NULL);
		kfree_rcu(new_r, rcu);
		goto err;
	}

	if (bch2_cpu_replicas_to_sb_replicas(c, new_r)) {
		ret = -ENOSPC;
		goto err;
	}

	old_r = rcu_dereference_protected(c->replicas,
					  lockdep_is_held(&c->sb_lock));

	rcu_assign_pointer(c->replicas, new_r);
	rcu_assign_pointer(c->replicas_gc, NULL);
	kfree_rcu(old_r, rcu);

	bch2_write_super(c);
err:
	mutex_unlock(&c->sb_lock);
	return ret;
}

int bch2_replicas_gc_start(struct bch_fs *c, unsigned typemask)
{
	struct bch_replicas_cpu *dst, *src;
	struct bch_replicas_cpu_entry *e;

	lockdep_assert_held(&c->replicas_gc_lock);

	mutex_lock(&c->sb_lock);
	BUG_ON(c->replicas_gc);

	src = rcu_dereference_protected(c->replicas,
					lockdep_is_held(&c->sb_lock));

	dst = kzalloc(sizeof(struct bch_replicas_cpu) +
		      src->nr * src->entry_size, GFP_NOIO);
	if (!dst) {
		mutex_unlock(&c->sb_lock);
		return -ENOMEM;
	}

	dst->nr		= 0;
	dst->entry_size	= src->entry_size;

	for_each_cpu_replicas_entry(src, e)
		if (!((1 << e->data_type) & typemask))
			memcpy(cpu_replicas_entry(dst, dst->nr++),
			       e, dst->entry_size);

	bch2_cpu_replicas_sort(dst);

	rcu_assign_pointer(c->replicas_gc, dst);
	mutex_unlock(&c->sb_lock);

	return 0;
}

/* Replicas tracking - superblock: */

static void bch2_sb_replicas_nr_entries(struct bch_sb_field_replicas *r,
					unsigned *nr,
					unsigned *bytes,
					unsigned *max_dev)
{
	struct bch_replicas_entry *i;
	unsigned j;

	*nr	= 0;
	*bytes	= sizeof(*r);
	*max_dev = 0;

	if (!r)
		return;

	for_each_replicas_entry(r, i) {
		for (j = 0; j < i->nr; j++)
			*max_dev = max_t(unsigned, *max_dev, i->devs[j]);
		(*nr)++;
	}

	*bytes = (void *) i - (void *) r;
}

static struct bch_replicas_cpu *
__bch2_sb_replicas_to_cpu_replicas(struct bch_sb_field_replicas *sb_r)
{
	struct bch_replicas_cpu *cpu_r;
	unsigned i, nr, bytes, max_dev, entry_size;

	bch2_sb_replicas_nr_entries(sb_r, &nr, &bytes, &max_dev);

	entry_size = offsetof(struct bch_replicas_cpu_entry, devs) +
		DIV_ROUND_UP(max_dev + 1, 8);

	cpu_r = kzalloc(sizeof(struct bch_replicas_cpu) +
			nr * entry_size, GFP_NOIO);
	if (!cpu_r)
		return NULL;

	cpu_r->nr		= nr;
	cpu_r->entry_size	= entry_size;

	if (nr) {
		struct bch_replicas_cpu_entry *dst =
			cpu_replicas_entry(cpu_r, 0);
		struct bch_replicas_entry *src = sb_r->entries;

		while (dst < cpu_replicas_entry(cpu_r, nr)) {
			dst->data_type = src->data_type;
			for (i = 0; i < src->nr; i++)
				replicas_set_dev(dst, src->devs[i]);

			src	= replicas_entry_next(src);
			dst	= (void *) dst + entry_size;
		}
	}

	bch2_cpu_replicas_sort(cpu_r);
	return cpu_r;
}

static int bch2_sb_replicas_to_cpu_replicas(struct bch_fs *c)
{
	struct bch_sb_field_replicas *sb_r;
	struct bch_replicas_cpu *cpu_r, *old_r;

	sb_r	= bch2_sb_get_replicas(c->disk_sb);
	cpu_r	= __bch2_sb_replicas_to_cpu_replicas(sb_r);
	if (!cpu_r)
		return -ENOMEM;

	old_r = rcu_dereference_check(c->replicas, lockdep_is_held(&c->sb_lock));
	rcu_assign_pointer(c->replicas, cpu_r);
	if (old_r)
		kfree_rcu(old_r, rcu);

	return 0;
}

static int bch2_cpu_replicas_to_sb_replicas(struct bch_fs *c,
					    struct bch_replicas_cpu *r)
{
	struct bch_sb_field_replicas *sb_r;
	struct bch_replicas_entry *sb_e;
	struct bch_replicas_cpu_entry *e;
	size_t i, bytes;

	bytes = sizeof(struct bch_sb_field_replicas);

	for_each_cpu_replicas_entry(r, e) {
		bytes += sizeof(struct bch_replicas_entry);
		for (i = 0; i < r->entry_size - 1; i++)
			bytes += hweight8(e->devs[i]);
	}

	sb_r = bch2_fs_sb_resize_replicas(c,
			DIV_ROUND_UP(sizeof(*sb_r) + bytes, sizeof(u64)));
	if (!sb_r)
		return -ENOSPC;

	memset(&sb_r->entries, 0,
	       vstruct_end(&sb_r->field) -
	       (void *) &sb_r->entries);

	sb_e = sb_r->entries;
	for_each_cpu_replicas_entry(r, e) {
		sb_e->data_type = e->data_type;

		for (i = 0; i < replicas_dev_slots(r); i++)
			if (replicas_test_dev(e, i))
				sb_e->devs[sb_e->nr++] = i;

		sb_e = replicas_entry_next(sb_e);

		BUG_ON((void *) sb_e > vstruct_end(&sb_r->field));
	}

	return 0;
}

static const char *bch2_sb_validate_replicas(struct bch_sb *sb,
					     struct bch_sb_field *f)
{
	struct bch_sb_field_replicas *sb_r = field_to_type(f, replicas);
	struct bch_sb_field_members *mi = bch2_sb_get_members(sb);
	struct bch_replicas_cpu *cpu_r = NULL;
	struct bch_replicas_entry *e;
	const char *err;
	unsigned i;

	for_each_replicas_entry(sb_r, e) {
		err = "invalid replicas entry: invalid data type";
		if (e->data_type >= BCH_DATA_NR)
			goto err;

		err = "invalid replicas entry: no devices";
		if (!e->nr)
			goto err;

		err = "invalid replicas entry: too many devices";
		if (e->nr >= BCH_REPLICAS_MAX)
			goto err;

		err = "invalid replicas entry: invalid device";
		for (i = 0; i < e->nr; i++)
			if (!bch2_dev_exists(sb, mi, e->devs[i]))
				goto err;
	}

	err = "cannot allocate memory";
	cpu_r = __bch2_sb_replicas_to_cpu_replicas(sb_r);
	if (!cpu_r)
		goto err;

	sort_cmp_size(cpu_r->entries,
		      cpu_r->nr,
		      cpu_r->entry_size,
		      memcmp, NULL);

	for (i = 0; i + 1 < cpu_r->nr; i++) {
		struct bch_replicas_cpu_entry *l =
			cpu_replicas_entry(cpu_r, i);
		struct bch_replicas_cpu_entry *r =
			cpu_replicas_entry(cpu_r, i + 1);

		BUG_ON(memcmp(l, r, cpu_r->entry_size) > 0);

		err = "duplicate replicas entry";
		if (!memcmp(l, r, cpu_r->entry_size))
			goto err;
	}

	err = NULL;
err:
	kfree(cpu_r);
	return err;
}

int bch2_sb_replicas_to_text(struct bch_sb_field_replicas *r, char *buf, size_t size)
{
	char *out = buf, *end = out + size;
	struct bch_replicas_entry *e;
	bool first = true;
	unsigned i;

	if (!r) {
		out += scnprintf(out, end - out, "(no replicas section found)");
		return out - buf;
	}

	for_each_replicas_entry(r, e) {
		if (!first)
			out += scnprintf(out, end - out, " ");
		first = false;

		out += scnprintf(out, end - out, "%u: [", e->data_type);

		for (i = 0; i < e->nr; i++)
			out += scnprintf(out, end - out,
					 i ? " %u" : "%u", e->devs[i]);
		out += scnprintf(out, end - out, "]");
	}

	return out - buf;
}

/* Query replicas: */

bool bch2_replicas_marked(struct bch_fs *c,
			  enum bch_data_type data_type,
			  struct bch_devs_list devs)
{
	struct bch_replicas_cpu_entry search;
	unsigned max_dev;
	bool ret;

	if (!devs.nr)
		return true;

	devlist_to_replicas(devs, data_type, &search, &max_dev);

	rcu_read_lock();
	ret = replicas_has_entry(rcu_dereference(c->replicas),
				 search, max_dev);
	rcu_read_unlock();

	return ret;
}

bool bch2_bkey_replicas_marked(struct bch_fs *c,
			       enum bch_data_type data_type,
			       struct bkey_s_c k)
{
	struct bch_devs_list cached = bch2_bkey_cached_devs(k);
	unsigned i;

	for (i = 0; i < cached.nr; i++)
		if (!bch2_replicas_marked(c, BCH_DATA_CACHED,
					  bch2_dev_list_single(cached.devs[i])))
			return false;

	return bch2_replicas_marked(c, data_type, bch2_bkey_dirty_devs(k));
}

struct replicas_status __bch2_replicas_status(struct bch_fs *c,
					      struct bch_devs_mask online_devs)
{
	struct bch_sb_field_members *mi;
	struct bch_replicas_cpu_entry *e;
	struct bch_replicas_cpu *r;
	unsigned i, dev, dev_slots, nr_online, nr_offline;
	struct replicas_status ret;

	memset(&ret, 0, sizeof(ret));

	for (i = 0; i < ARRAY_SIZE(ret.replicas); i++)
		ret.replicas[i].nr_online = UINT_MAX;

	mi = bch2_sb_get_members(c->disk_sb);
	rcu_read_lock();

	r = rcu_dereference(c->replicas);
	dev_slots = replicas_dev_slots(r);

	for_each_cpu_replicas_entry(r, e) {
		if (e->data_type >= ARRAY_SIZE(ret.replicas))
			panic("e %p data_type %u\n", e, e->data_type);

		nr_online = nr_offline = 0;

		for (dev = 0; dev < dev_slots; dev++) {
			if (!replicas_test_dev(e, dev))
				continue;

			BUG_ON(!bch2_dev_exists(c->disk_sb, mi, dev));

			if (test_bit(dev, online_devs.d))
				nr_online++;
			else
				nr_offline++;
		}

		ret.replicas[e->data_type].nr_online =
			min(ret.replicas[e->data_type].nr_online,
			    nr_online);

		ret.replicas[e->data_type].nr_offline =
			max(ret.replicas[e->data_type].nr_offline,
			    nr_offline);
	}

	rcu_read_unlock();

	return ret;
}

struct replicas_status bch2_replicas_status(struct bch_fs *c)
{
	return __bch2_replicas_status(c, bch2_online_devs(c));
}

static bool have_enough_devs(struct replicas_status s,
			     enum bch_data_type type,
			     bool force_if_degraded,
			     bool force_if_lost)
{
	return (!s.replicas[type].nr_offline || force_if_degraded) &&
		(s.replicas[type].nr_online || force_if_lost);
}

bool bch2_have_enough_devs(struct replicas_status s, unsigned flags)
{
	return (have_enough_devs(s, BCH_DATA_JOURNAL,
				 flags & BCH_FORCE_IF_METADATA_DEGRADED,
				 flags & BCH_FORCE_IF_METADATA_LOST) &&
		have_enough_devs(s, BCH_DATA_BTREE,
				 flags & BCH_FORCE_IF_METADATA_DEGRADED,
				 flags & BCH_FORCE_IF_METADATA_LOST) &&
		have_enough_devs(s, BCH_DATA_USER,
				 flags & BCH_FORCE_IF_DATA_DEGRADED,
				 flags & BCH_FORCE_IF_DATA_LOST));
}

unsigned bch2_replicas_online(struct bch_fs *c, bool meta)
{
	struct replicas_status s = bch2_replicas_status(c);

	return meta
		? min(s.replicas[BCH_DATA_JOURNAL].nr_online,
		      s.replicas[BCH_DATA_BTREE].nr_online)
		: s.replicas[BCH_DATA_USER].nr_online;
}

unsigned bch2_dev_has_data(struct bch_fs *c, struct bch_dev *ca)
{
	struct bch_replicas_cpu_entry *e;
	struct bch_replicas_cpu *r;
	unsigned ret = 0;

	rcu_read_lock();
	r = rcu_dereference(c->replicas);

	if (ca->dev_idx >= replicas_dev_slots(r))
		goto out;

	for_each_cpu_replicas_entry(r, e)
		if (replicas_test_dev(e, ca->dev_idx))
			ret |= 1 << e->data_type;
out:
	rcu_read_unlock();

	return ret;
}

/* Quotas: */

static const char *bch2_sb_validate_quota(struct bch_sb *sb,
					  struct bch_sb_field *f)
{
	struct bch_sb_field_quota *q = field_to_type(f, quota);

	if (vstruct_bytes(&q->field) != sizeof(*q))
		return "invalid field quota: wrong size";

	return NULL;
}

/* Disk groups: */

#if 0
static size_t trim_nulls(const char *str, size_t len)
{
	while (len && !str[len - 1])
		--len;
	return len;
}
#endif

static const char *bch2_sb_validate_disk_groups(struct bch_sb *sb,
						struct bch_sb_field *f)
{
	struct bch_sb_field_disk_groups *groups =
		field_to_type(f, disk_groups);
	struct bch_sb_field_members *mi;
	struct bch_member *m;
	struct bch_disk_group *g;
	unsigned nr_groups;

	mi		= bch2_sb_get_members(sb);
	groups		= bch2_sb_get_disk_groups(sb);
	nr_groups	= disk_groups_nr(groups);

	for (m = mi->members;
	     m < mi->members + sb->nr_devices;
	     m++) {
		if (!BCH_MEMBER_GROUP(m))
			continue;

		if (BCH_MEMBER_GROUP(m) >= nr_groups)
			return "disk has invalid group";

		g = &groups->entries[BCH_MEMBER_GROUP(m)];
		if (BCH_GROUP_DELETED(g))
			return "disk has invalid group";
	}
#if 0
	if (!groups)
		return NULL;

	char **labels;
	labels = kcalloc(nr_groups, sizeof(char *), GFP_KERNEL);
	if (!labels)
		return "cannot allocate memory";

	for (g = groups->groups;
	     g < groups->groups + nr_groups;
	     g++) {

	}
#endif
	return NULL;
}

static int bch2_sb_disk_groups_to_cpu(struct bch_fs *c)
{
	struct bch_sb_field_members *mi;
	struct bch_sb_field_disk_groups *groups;
	struct bch_disk_groups_cpu *cpu_g, *old_g;
	unsigned i, nr_groups;

	lockdep_assert_held(&c->sb_lock);

	mi		= bch2_sb_get_members(c->disk_sb);
	groups		= bch2_sb_get_disk_groups(c->disk_sb);
	nr_groups	= disk_groups_nr(groups);

	if (!groups)
		return 0;

	cpu_g = kzalloc(sizeof(*cpu_g) +
			sizeof(cpu_g->entries[0]) * nr_groups, GFP_KERNEL);
	if (!cpu_g)
		return -ENOMEM;

	cpu_g->nr = nr_groups;

	for (i = 0; i < nr_groups; i++) {
		struct bch_disk_group *src	= &groups->entries[i];
		struct bch_disk_group_cpu *dst	= &cpu_g->entries[i];

		dst->deleted = BCH_GROUP_DELETED(src);
	}

	for (i = 0; i < c->disk_sb->nr_devices; i++) {
		struct bch_member *m = mi->members + i;
		struct bch_disk_group_cpu *dst =
			&cpu_g->entries[BCH_MEMBER_GROUP(m)];

		if (!bch2_member_exists(m))
			continue;

		__set_bit(i, dst->devs.d);
	}

	old_g = c->disk_groups;
	rcu_assign_pointer(c->disk_groups, cpu_g);
	if (old_g)
		kfree_rcu(old_g, rcu);

	return 0;
}

const struct bch_devs_mask *bch2_target_to_mask(struct bch_fs *c, unsigned target)
{
	struct target t = target_decode(target);

	switch (t.type) {
	case TARGET_DEV:
		BUG_ON(t.dev >= c->sb.nr_devices && !c->devs[t.dev]);
		return &c->devs[t.dev]->self;
	case TARGET_GROUP: {
		struct bch_disk_groups_cpu *g =
			rcu_dereference(c->disk_groups);

		/* XXX: what to do here? */
		BUG_ON(t.group >= g->nr || g->entries[t.group].deleted);
		return &g->entries[t.group].devs;
	}
	default:
		BUG();
	}
}
