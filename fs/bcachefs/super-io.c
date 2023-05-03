// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "checksum.h"
#include "disk_groups.h"
#include "ec.h"
#include "error.h"
#include "io.h"
#include "journal.h"
#include "replicas.h"
#include "quota.h"
#include "super-io.h"
#include "super.h"
#include "vstructs.h"

#include <linux/backing-dev.h>
#include <linux/sort.h>

const char * const bch2_sb_fields[] = {
#define x(name, nr)	#name,
	BCH_SB_FIELDS()
#undef x
	NULL
};

static const char *bch2_sb_field_validate(struct bch_sb *,
					  struct bch_sb_field *);

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

static struct bch_sb_field *__bch2_sb_field_resize(struct bch_sb_handle *sb,
						   struct bch_sb_field *f,
						   unsigned u64s)
{
	unsigned old_u64s = f ? le32_to_cpu(f->u64s) : 0;
	unsigned sb_u64s = le32_to_cpu(sb->sb->u64s) + u64s - old_u64s;

	BUG_ON(get_order(__vstruct_bytes(struct bch_sb, sb_u64s)) >
	       sb->page_order);

	if (!f) {
		f = vstruct_last(sb->sb);
		memset(f, 0, sizeof(u64) * u64s);
		f->u64s = cpu_to_le32(u64s);
		f->type = 0;
	} else {
		void *src, *dst;

		src = vstruct_end(f);

		if (u64s) {
			f->u64s = cpu_to_le32(u64s);
			dst = vstruct_end(f);
		} else {
			dst = f;
		}

		memmove(dst, src, vstruct_end(sb->sb) - src);

		if (dst > src)
			memset(src, 0, dst - src);
	}

	sb->sb->u64s = cpu_to_le32(sb_u64s);

	return u64s ? f : NULL;
}

void bch2_sb_field_delete(struct bch_sb_handle *sb,
			  enum bch_sb_field_type type)
{
	struct bch_sb_field *f = bch2_sb_field_get(sb->sb, type);

	if (f)
		__bch2_sb_field_resize(sb, f, 0);
}

/* Superblock realloc/free: */

void bch2_free_super(struct bch_sb_handle *sb)
{
	if (sb->bio)
		kfree(sb->bio);
	if (!IS_ERR_OR_NULL(sb->bdev))
		blkdev_put(sb->bdev, sb->mode);

	free_pages((unsigned long) sb->sb, sb->page_order);
	memset(sb, 0, sizeof(*sb));
}

int bch2_sb_realloc(struct bch_sb_handle *sb, unsigned u64s)
{
	size_t new_bytes = __vstruct_bytes(struct bch_sb, u64s);
	unsigned order = get_order(new_bytes);
	struct bch_sb *new_sb;
	struct bio *bio;

	if (sb->sb && sb->page_order >= order)
		return 0;

	if (sb->have_layout) {
		u64 max_bytes = 512 << sb->sb->layout.sb_max_size_bits;

		if (new_bytes > max_bytes) {
			pr_err("%pg: superblock too big: want %zu but have %llu",
			       sb->bdev, new_bytes, max_bytes);
			return -ENOSPC;
		}
	}

	if (sb->page_order >= order && sb->sb)
		return 0;

	if (dynamic_fault("bcachefs:add:super_realloc"))
		return -ENOMEM;

	if (sb->have_bio) {
		unsigned nr_bvecs = 1 << order;

		bio = bio_kmalloc(nr_bvecs, GFP_KERNEL);
		if (!bio)
			return -ENOMEM;

		bio_init(bio, NULL, bio->bi_inline_vecs, nr_bvecs, 0);

		if (sb->bio)
			kfree(sb->bio);
		sb->bio = bio;
	}

	new_sb = (void *) __get_free_pages(GFP_KERNEL|__GFP_ZERO, order);
	if (!new_sb)
		return -ENOMEM;

	if (sb->sb)
		memcpy(new_sb, sb->sb, PAGE_SIZE << sb->page_order);

	free_pages((unsigned long) sb->sb, sb->page_order);
	sb->sb = new_sb;

	sb->page_order = order;

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

	if (sb->fs_sb) {
		struct bch_fs *c = container_of(sb, struct bch_fs, disk_sb);
		struct bch_dev *ca;
		unsigned i;

		lockdep_assert_held(&c->sb_lock);

		/* XXX: we're not checking that offline device have enough space */

		for_each_online_member(ca, c, i) {
			struct bch_sb_handle *sb = &ca->disk_sb;

			if (bch2_sb_realloc(sb, le32_to_cpu(sb->sb->u64s) + d)) {
				percpu_ref_put(&ca->ref);
				return NULL;
			}
		}
	}

	f = bch2_sb_field_get(sb->sb, type);
	f = __bch2_sb_field_resize(sb, f, u64s);
	if (f)
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

	if (uuid_le_cmp(layout->magic, BCACHE_MAGIC) &&
	    uuid_le_cmp(layout->magic, BCHFS_MAGIC))
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
	u32 version, version_min;
	u16 block_size;

	version		= le16_to_cpu(sb->version);
	version_min	= version >= bcachefs_metadata_version_new_versioning
		? le16_to_cpu(sb->version_min)
		: version;

	if (version    >= bcachefs_metadata_version_max ||
	    version_min < bcachefs_metadata_version_min)
		return "Unsupported superblock version";

	if (version_min > version)
		return "Bad minimum version";

	if (sb->features[1] ||
	    (le64_to_cpu(sb->features[0]) & (~0ULL << BCH_FEATURE_NR)))
		return "Filesystem has incompatible features";

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

	return NULL;
}

/* device open: */

static void bch2_sb_update(struct bch_fs *c)
{
	struct bch_sb *src = c->disk_sb.sb;
	struct bch_sb_field_members *mi = bch2_sb_get_members(src);
	struct bch_dev *ca;
	unsigned i;

	lockdep_assert_held(&c->sb_lock);

	c->sb.uuid		= src->uuid;
	c->sb.user_uuid		= src->user_uuid;
	c->sb.version		= le16_to_cpu(src->version);
	c->sb.nr_devices	= src->nr_devices;
	c->sb.clean		= BCH_SB_CLEAN(src);
	c->sb.encryption_type	= BCH_SB_ENCRYPTION_TYPE(src);
	c->sb.encoded_extent_max= 1 << BCH_SB_ENCODED_EXTENT_MAX_BITS(src);
	c->sb.time_base_lo	= le64_to_cpu(src->time_base_lo);
	c->sb.time_base_hi	= le32_to_cpu(src->time_base_hi);
	c->sb.time_precision	= le32_to_cpu(src->time_precision);
	c->sb.features		= le64_to_cpu(src->features[0]);

	for_each_member_device(ca, c, i)
		ca->mi = bch2_mi_to_cpu(mi->members + i);
}

/* doesn't copy member info */
static void __copy_super(struct bch_sb_handle *dst_handle, struct bch_sb *src)
{
	struct bch_sb_field *src_f, *dst_f;
	struct bch_sb *dst = dst_handle->sb;
	unsigned i;

	dst->version		= src->version;
	dst->version_min	= src->version_min;
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

	for (i = 0; i < BCH_SB_FIELD_NR; i++) {
		if (i == BCH_SB_FIELD_journal)
			continue;

		src_f = bch2_sb_field_get(src, i);
		dst_f = bch2_sb_field_get(dst, i);
		dst_f = __bch2_sb_field_resize(dst_handle, dst_f,
				src_f ? le32_to_cpu(src_f->u64s) : 0);

		if (src_f)
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

	ret = bch2_sb_realloc(&c->disk_sb,
			      le32_to_cpu(src->u64s) - journal_u64s);
	if (ret)
		return ret;

	__copy_super(&c->disk_sb, src);

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
	struct bch_sb *src = c->disk_sb.sb, *dst = ca->disk_sb.sb;
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

	__copy_super(&ca->disk_sb, src);
	return 0;
}

/* read superblock: */

static const char *read_one_super(struct bch_sb_handle *sb, u64 offset)
{
	struct bch_csum csum;
	size_t bytes;
reread:
	bio_reset(sb->bio, sb->bdev, REQ_OP_READ|REQ_SYNC|REQ_META);
	sb->bio->bi_iter.bi_sector = offset;
	sb->bio->bi_iter.bi_size = PAGE_SIZE << sb->page_order;
	bch2_bio_map(sb->bio, sb->sb);

	if (submit_bio_wait(sb->bio))
		return "IO error";

	if (uuid_le_cmp(sb->sb->magic, BCACHE_MAGIC) &&
	    uuid_le_cmp(sb->sb->magic, BCHFS_MAGIC))
		return "Not a bcachefs superblock";

	if (le16_to_cpu(sb->sb->version) <  bcachefs_metadata_version_min ||
	    le16_to_cpu(sb->sb->version) >= bcachefs_metadata_version_max)
		return "Unsupported superblock version";

	bytes = vstruct_bytes(sb->sb);

	if (bytes > 512 << sb->sb->layout.sb_max_size_bits)
		return "Bad superblock: too big";

	if (get_order(bytes) > sb->page_order) {
		if (bch2_sb_realloc(sb, le32_to_cpu(sb->sb->u64s)))
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
	sb->mode	= FMODE_READ;
	sb->have_bio	= true;

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
	ret = bch2_sb_realloc(sb, 0);
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
	bio_reset(sb->bio, sb->bdev, REQ_OP_READ|REQ_SYNC|REQ_META);
	sb->bio->bi_iter.bi_sector = BCH_SB_LAYOUT_SECTOR;
	sb->bio->bi_iter.bi_size = sizeof(struct bch_sb_layout);
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

	ret = 0;
	sb->have_layout = true;
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

	bio_reset(bio, ca->disk_sb.bdev, REQ_OP_WRITE|REQ_SYNC|REQ_META);
	bio->bi_iter.bi_sector	= le64_to_cpu(sb->offset);
	bio->bi_iter.bi_size	=
		roundup((size_t) vstruct_bytes(sb),
			bdev_logical_block_size(ca->disk_sb.bdev));
	bio->bi_end_io		= write_super_endio;
	bio->bi_private		= ca;
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

	le64_add_cpu(&c->disk_sb.sb->seq, 1);

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

static const struct bch_sb_field_ops bch_sb_field_ops_journal = {
	.validate	= bch2_sb_validate_journal,
};

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
		    le16_to_cpu(m->first_bucket) < BCH_MIN_NR_NBUCKETS)
			return "Not enough buckets";

		if (le16_to_cpu(m->bucket_size) <
		    le16_to_cpu(sb->block_size))
			return "bucket size smaller than block size";

		if (le16_to_cpu(m->bucket_size) <
		    BCH_SB_BTREE_NODE_SIZE(sb))
			return "bucket size smaller than btree node size";
	}

	return NULL;
}

static const struct bch_sb_field_ops bch_sb_field_ops_members = {
	.validate	= bch2_sb_validate_members,
};

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

static const struct bch_sb_field_ops bch_sb_field_ops_crypt = {
	.validate	= bch2_sb_validate_crypt,
};

/* BCH_SB_FIELD_clean: */

void bch2_sb_clean_renumber(struct bch_sb_field_clean *clean, int write)
{
	struct jset_entry *entry;

	for (entry = clean->start;
	     entry < (struct jset_entry *) vstruct_end(&clean->field);
	     entry = vstruct_next(entry))
		bch2_bkey_renumber(BKEY_TYPE_BTREE, bkey_to_packed(entry->start), write);
}

void bch2_fs_mark_clean(struct bch_fs *c, bool clean)
{
	struct bch_sb_field_clean *sb_clean;
	unsigned u64s = sizeof(*sb_clean) / sizeof(u64);
	struct jset_entry *entry;
	struct btree_root *r;

	mutex_lock(&c->sb_lock);
	if (clean == BCH_SB_CLEAN(c->disk_sb.sb))
		goto out;

	SET_BCH_SB_CLEAN(c->disk_sb.sb, clean);

	if (!clean)
		goto write_super;

	mutex_lock(&c->btree_root_lock);

	for (r = c->btree_roots;
	     r < c->btree_roots + BTREE_ID_NR;
	     r++)
		if (r->alive)
			u64s += jset_u64s(r->key.u64s);

	sb_clean = bch2_sb_resize_clean(&c->disk_sb, u64s);
	if (!sb_clean) {
		bch_err(c, "error resizing superblock while setting filesystem clean");
		goto out;
	}

	sb_clean->flags		= 0;
	sb_clean->read_clock	= cpu_to_le16(c->bucket_clock[READ].hand);
	sb_clean->write_clock	= cpu_to_le16(c->bucket_clock[WRITE].hand);
	sb_clean->journal_seq	= journal_cur_seq(&c->journal) - 1;

	entry = sb_clean->start;
	memset(entry, 0,
	       vstruct_end(&sb_clean->field) - (void *) entry);

	for (r = c->btree_roots;
	     r < c->btree_roots + BTREE_ID_NR;
	     r++)
		if (r->alive) {
			entry->u64s	= r->key.u64s;
			entry->btree_id	= r - c->btree_roots;
			entry->level	= r->level;
			entry->type	= BCH_JSET_ENTRY_btree_root;
			bkey_copy(&entry->start[0], &r->key);
			entry = vstruct_next(entry);
			BUG_ON((void *) entry > vstruct_end(&sb_clean->field));
		}

	BUG_ON(entry != vstruct_end(&sb_clean->field));

	if (le16_to_cpu(c->disk_sb.sb->version) <
	    bcachefs_metadata_version_bkey_renumber)
		bch2_sb_clean_renumber(sb_clean, WRITE);

	mutex_unlock(&c->btree_root_lock);
write_super:
	bch2_write_super(c);
out:
	mutex_unlock(&c->sb_lock);
}

static const char *bch2_sb_validate_clean(struct bch_sb *sb,
					  struct bch_sb_field *f)
{
	struct bch_sb_field_clean *clean = field_to_type(f, clean);

	if (vstruct_bytes(&clean->field) < sizeof(*clean))
		return "invalid field crypt: wrong size";

	return NULL;
}

static const struct bch_sb_field_ops bch_sb_field_ops_clean = {
	.validate	= bch2_sb_validate_clean,
};

static const struct bch_sb_field_ops *bch2_sb_field_ops[] = {
#define x(f, nr)					\
	[BCH_SB_FIELD_##f] = &bch_sb_field_ops_##f,
	BCH_SB_FIELDS()
#undef x
};

static const char *bch2_sb_field_validate(struct bch_sb *sb,
					  struct bch_sb_field *f)
{
	unsigned type = le32_to_cpu(f->type);

	return type < BCH_SB_FIELD_NR
		? bch2_sb_field_ops[type]->validate(sb, f)
		: NULL;
}

void bch2_sb_field_to_text(struct printbuf *out, struct bch_sb *sb,
			   struct bch_sb_field *f)
{
	unsigned type = le32_to_cpu(f->type);
	const struct bch_sb_field_ops *ops = type < BCH_SB_FIELD_NR
		? bch2_sb_field_ops[type] : NULL;

	if (ops)
		pr_buf(out, "%s", bch2_sb_fields[type]);
	else
		pr_buf(out, "(unknown field %u)", type);

	pr_buf(out, " (size %llu):", vstruct_bytes(f));

	if (ops && ops->to_text)
		bch2_sb_field_ops[type]->to_text(out, sb, f);
}
