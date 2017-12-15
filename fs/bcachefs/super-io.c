
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

static int bch2_sb_replicas_to_cpu_replicas(struct bch_fs *);
static const char *bch2_sb_validate_replicas(struct bch_sb *);

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
		struct bch_sb_handle *sb = &ca->disk_sb;

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

const char *bch2_sb_validate_journal(struct bch_sb *sb,
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
		if (!bch2_dev_exists(sb, mi, i))
			continue;

		if (le16_to_cpu(mi->members[i].bucket_size) <
		    BCH_SB_BTREE_NODE_SIZE(sb))
			return "bucket size smaller than btree node size";
	}

	return NULL;
}

const char *bch2_sb_validate(struct bch_sb_handle *disk_sb)
{
	struct bch_sb *sb = disk_sb->sb;
	struct bch_sb_field *f;
	struct bch_sb_field_members *sb_mi;
	struct bch_member_cpu mi;
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
		return "Bad cache device number in set";

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

	if (le64_to_cpu(sb->version) < BCH_SB_VERSION_EXTENT_MAX) {
		struct bch_member *m;

		for (m = sb_mi->members;
		     m < sb_mi->members + sb->nr_devices;
		     m++)
			SET_BCH_MEMBER_DATA_ALLOWED(m, ~0);
	}

	if (mi.nbuckets > LONG_MAX)
		return "Too many buckets";

	if (mi.nbuckets - mi.first_bucket < 1 << 10)
		return "Not enough buckets";

	if (mi.bucket_size < block_size)
		return "Bad bucket size";

	if (get_capacity(disk_sb->bdev->bd_disk) <
	    mi.bucket_size * mi.nbuckets)
		return "Invalid superblock: device too small";

	err = bch2_sb_validate_journal(sb, mi);
	if (err)
		return err;

	err = bch2_sb_validate_replicas(sb);
	if (err)
		return err;

	if (le64_to_cpu(sb->version) < BCH_SB_VERSION_EXTENT_NONCE_V1 &&
	    bch2_sb_get_crypt(sb) &&
	    BCH_SB_INITIALIZED(sb))
		return "Incompatible extent nonces";

	sb->version = cpu_to_le64(BCH_SB_VERSION_MAX);

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
		bdev_get_queue(bdev)->backing_dev_info->capabilities
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
	int ret;

	lockdep_assert_held(&c->sb_lock);

	if (bch2_fs_sb_realloc(c, le32_to_cpu(src->u64s) - journal_u64s))
		return -ENOMEM;

	__copy_super(c->disk_sb, src);

	ret = bch2_sb_replicas_to_cpu_replicas(c);
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
			    (struct nonce) { 0 }, sb->sb);

	if (bch2_crc_cmp(csum, sb->sb->csum))
		return "bad checksum reading superblock";

	return NULL;
}

const char *bch2_read_super(const char *path,
			    struct bch_opts opts,
			    struct bch_sb_handle *ret)
{
	u64 offset = opt_get(opts, sb);
	struct bch_sb_layout layout;
	const char *err;
	unsigned i;

	memset(ret, 0, sizeof(*ret));
	ret->mode = FMODE_READ;

	if (!opt_get(opts, noexcl))
		ret->mode |= FMODE_EXCL;

	if (!opt_get(opts, nochanges))
		ret->mode |= FMODE_WRITE;

	err = bch2_blkdev_open(path, ret->mode, ret, &ret->bdev);
	if (err)
		return err;

	err = "cannot allocate memory";
	if (__bch2_super_realloc(ret, 0))
		goto err;

	err = "dynamic fault";
	if (bch2_fs_init_fault("read_super"))
		goto err;

	err = read_one_super(ret, offset);
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
	bio_reset(ret->bio);
	bio_set_dev(ret->bio, ret->bdev);
	ret->bio->bi_iter.bi_sector = BCH_SB_LAYOUT_SECTOR;
	ret->bio->bi_iter.bi_size = sizeof(struct bch_sb_layout);
	bio_set_op_attrs(ret->bio, REQ_OP_READ, REQ_SYNC|REQ_META);
	/*
	 * use sb buffer to read layout, since sb buffer is page aligned but
	 * layout won't be:
	 */
	bch2_bio_map(ret->bio, ret->sb);

	err = "IO error";
	if (submit_bio_wait(ret->bio))
		goto err;

	memcpy(&layout, ret->sb, sizeof(layout));
	err = validate_sb_layout(&layout);
	if (err)
		goto err;

	for (i = 0; i < layout.nr_superblocks; i++) {
		u64 offset = le64_to_cpu(layout.sb_offset[i]);

		if (offset == BCH_SB_SECTOR)
			continue;

		err = read_one_super(ret, offset);
		if (!err)
			goto got_super;
	}
	goto err;
got_super:
	pr_debug("read sb version %llu, flags %llu, seq %llu, journal size %u",
		 le64_to_cpu(ret->sb->version),
		 le64_to_cpu(ret->sb->flags),
		 le64_to_cpu(ret->sb->seq),
		 le16_to_cpu(ret->sb->u64s));

	err = "Superblock block size smaller than device block size";
	if (le16_to_cpu(ret->sb->block_size) << 9 <
	    bdev_logical_block_size(ret->bdev))
		goto err;

	return NULL;
err:
	bch2_free_super(ret);
	return err;
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
				(struct nonce) { 0 }, sb);

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
		bch2_have_enough_devs(c,
			__bch2_replicas_status(c, sb_written),
			BCH_FORCE_IF_DEGRADED);

	for (i = 0; i < ARRAY_SIZE(sb_written.d); i++)
		sb_written.d[i] = ~sb_written.d[i];

	can_mount_without_written =
		bch2_have_enough_devs(c,
			__bch2_replicas_status(c, sb_written),
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

/* replica information: */

static inline struct bch_replicas_cpu_entry *
cpu_replicas_entry(struct bch_replicas_cpu *r, unsigned i)
{
	return (void *) r->entries + r->entry_size * i;
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

	eytzinger0_sort(cpu_r->entries,
			cpu_r->nr,
			cpu_r->entry_size,
			memcmp, NULL);
	return cpu_r;
}

static int bch2_sb_replicas_to_cpu_replicas(struct bch_fs *c)
{
	struct bch_sb_field_replicas *sb_r;
	struct bch_replicas_cpu *cpu_r, *old_r;

	lockdep_assert_held(&c->sb_lock);

	sb_r	= bch2_sb_get_replicas(c->disk_sb);
	cpu_r	= __bch2_sb_replicas_to_cpu_replicas(sb_r);
	if (!cpu_r)
		return -ENOMEM;

	old_r = c->replicas;
	rcu_assign_pointer(c->replicas, cpu_r);
	if (old_r)
		kfree_rcu(old_r, rcu);

	return 0;
}

static void bkey_to_replicas(struct bkey_s_c_extent e,
			     enum bch_data_type data_type,
			     struct bch_replicas_cpu_entry *r,
			     unsigned *max_dev)
{
	const struct bch_extent_ptr *ptr;

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
		}
}

/*
 * for when gc of replica information is in progress:
 */
static int bch2_update_gc_replicas(struct bch_fs *c,
				   struct bch_replicas_cpu *gc_r,
				   struct bkey_s_c_extent e,
				   enum bch_data_type data_type)
{
	struct bch_replicas_cpu_entry new_e;
	struct bch_replicas_cpu *new;
	unsigned i, nr, entry_size, max_dev;

	bkey_to_replicas(e, data_type, &new_e, &max_dev);

	entry_size = offsetof(struct bch_replicas_cpu_entry, devs) +
		DIV_ROUND_UP(max_dev + 1, 8);
	entry_size = max(entry_size, gc_r->entry_size);
	nr = gc_r->nr + 1;

	new = kzalloc(sizeof(struct bch_replicas_cpu) +
		      nr * entry_size, GFP_NOIO);
	if (!new)
		return -ENOMEM;

	new->nr		= nr;
	new->entry_size	= entry_size;

	for (i = 0; i < gc_r->nr; i++)
		memcpy(cpu_replicas_entry(new, i),
		       cpu_replicas_entry(gc_r, i),
		       gc_r->entry_size);

	memcpy(cpu_replicas_entry(new, nr - 1),
	       &new_e,
	       new->entry_size);

	eytzinger0_sort(new->entries,
			new->nr,
			new->entry_size,
			memcmp, NULL);

	rcu_assign_pointer(c->replicas_gc, new);
	kfree_rcu(gc_r, rcu);
	return 0;
}

static bool replicas_has_extent(struct bch_replicas_cpu *r,
				struct bkey_s_c_extent e,
				enum bch_data_type data_type)
{
	struct bch_replicas_cpu_entry search;
	unsigned max_dev;

	bkey_to_replicas(e, data_type, &search, &max_dev);

	return max_dev < replicas_dev_slots(r) &&
		eytzinger0_find(r->entries, r->nr,
				r->entry_size,
				memcmp, &search) < r->nr;
}

bool bch2_sb_has_replicas(struct bch_fs *c, struct bkey_s_c_extent e,
			  enum bch_data_type data_type)
{
	bool ret;

	rcu_read_lock();
	ret = replicas_has_extent(rcu_dereference(c->replicas),
				  e, data_type);
	rcu_read_unlock();

	return ret;
}

noinline
static int bch2_check_mark_super_slowpath(struct bch_fs *c,
					  struct bkey_s_c_extent e,
					  enum bch_data_type data_type)
{
	struct bch_replicas_cpu *gc_r;
	const struct bch_extent_ptr *ptr;
	struct bch_sb_field_replicas *sb_r;
	struct bch_replicas_entry *new_entry;
	unsigned new_entry_bytes, new_u64s, nr, bytes, max_dev;
	int ret = 0;

	mutex_lock(&c->sb_lock);

	gc_r = rcu_dereference_protected(c->replicas_gc,
					 lockdep_is_held(&c->sb_lock));
	if (gc_r &&
	    !replicas_has_extent(gc_r, e, data_type)) {
		ret = bch2_update_gc_replicas(c, gc_r, e, data_type);
		if (ret)
			goto err;
	}

	/* recheck, might have raced */
	if (bch2_sb_has_replicas(c, e, data_type)) {
		mutex_unlock(&c->sb_lock);
		return 0;
	}

	new_entry_bytes = sizeof(struct bch_replicas_entry) +
		bch2_extent_nr_dirty_ptrs(e.s_c);

	sb_r = bch2_sb_get_replicas(c->disk_sb);

	bch2_sb_replicas_nr_entries(sb_r, &nr, &bytes, &max_dev);

	new_u64s = DIV_ROUND_UP(bytes + new_entry_bytes, sizeof(u64));

	sb_r = bch2_fs_sb_resize_replicas(c,
			DIV_ROUND_UP(sizeof(*sb_r) + bytes + new_entry_bytes,
				     sizeof(u64)));
	if (!sb_r) {
		ret = -ENOSPC;
		goto err;
	}

	new_entry = (void *) sb_r + bytes;
	new_entry->data_type = data_type;
	new_entry->nr = 0;

	extent_for_each_ptr(e, ptr)
		if (!ptr->cached)
			new_entry->devs[new_entry->nr++] = ptr->dev;

	ret = bch2_sb_replicas_to_cpu_replicas(c);
	if (ret) {
		memset(new_entry, 0,
		       vstruct_end(&sb_r->field) - (void *) new_entry);
		goto err;
	}

	bch2_write_super(c);
err:
	mutex_unlock(&c->sb_lock);
	return ret;
}

int bch2_check_mark_super(struct bch_fs *c, struct bkey_s_c_extent e,
			  enum bch_data_type data_type)
{
	struct bch_replicas_cpu *gc_r;
	bool marked;

	rcu_read_lock();
	marked = replicas_has_extent(rcu_dereference(c->replicas),
				     e, data_type) &&
		(!(gc_r = rcu_dereference(c->replicas_gc)) ||
		 replicas_has_extent(gc_r, e, data_type));
	rcu_read_unlock();

	if (marked)
		return 0;

	return bch2_check_mark_super_slowpath(c, e, data_type);
}

struct replicas_status __bch2_replicas_status(struct bch_fs *c,
					struct bch_devs_mask online_devs)
{
	struct bch_replicas_cpu_entry *e;
	struct bch_replicas_cpu *r;
	unsigned i, dev, dev_slots, nr_online, nr_offline;
	struct replicas_status ret;

	memset(&ret, 0, sizeof(ret));

	for (i = 0; i < ARRAY_SIZE(ret.replicas); i++)
		ret.replicas[i].nr_online = UINT_MAX;

	rcu_read_lock();
	r = rcu_dereference(c->replicas);
	dev_slots = min_t(unsigned, replicas_dev_slots(r), c->sb.nr_devices);

	for (i = 0; i < r->nr; i++) {
		e = cpu_replicas_entry(r, i);

		BUG_ON(e->data_type >= ARRAY_SIZE(ret.replicas));

		nr_online = nr_offline = 0;

		for (dev = 0; dev < dev_slots; dev++) {
			if (!replicas_test_dev(e, dev))
				continue;

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

bool bch2_have_enough_devs(struct bch_fs *c,
			   struct replicas_status s,
			   unsigned flags)
{
	if ((s.replicas[BCH_DATA_JOURNAL].nr_offline ||
	     s.replicas[BCH_DATA_BTREE].nr_offline) &&
	    !(flags & BCH_FORCE_IF_METADATA_DEGRADED))
		return false;

	if ((!s.replicas[BCH_DATA_JOURNAL].nr_online ||
	     !s.replicas[BCH_DATA_BTREE].nr_online) &&
	    !(flags & BCH_FORCE_IF_METADATA_LOST))
		return false;

	if (s.replicas[BCH_DATA_USER].nr_offline &&
	    !(flags & BCH_FORCE_IF_DATA_DEGRADED))
		return false;

	if (!s.replicas[BCH_DATA_USER].nr_online &&
	    !(flags & BCH_FORCE_IF_DATA_LOST))
		return false;

	return true;
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
	unsigned i, ret = 0;

	rcu_read_lock();
	r = rcu_dereference(c->replicas);

	if (ca->dev_idx >= replicas_dev_slots(r))
		goto out;

	for (i = 0; i < r->nr; i++) {
		e = cpu_replicas_entry(r, i);

		if (replicas_test_dev(e, ca->dev_idx)) {
			ret |= 1 << e->data_type;
			break;
		}
	}
out:
	rcu_read_unlock();

	return ret;
}

static const char *bch2_sb_validate_replicas(struct bch_sb *sb)
{
	struct bch_sb_field_members *mi;
	struct bch_sb_field_replicas *sb_r;
	struct bch_replicas_cpu *cpu_r = NULL;
	struct bch_replicas_entry *e;
	const char *err;
	unsigned i;

	mi	= bch2_sb_get_members(sb);
	sb_r	= bch2_sb_get_replicas(sb);
	if (!sb_r)
		return NULL;

	for_each_replicas_entry(sb_r, e) {
		err = "invalid replicas entry: invalid data type";
		if (e->data_type >= BCH_DATA_NR)
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

int bch2_replicas_gc_end(struct bch_fs *c, int err)
{
	struct bch_sb_field_replicas *sb_r;
	struct bch_replicas_cpu *r, *old_r;
	struct bch_replicas_entry *dst_e;
	size_t i, j, bytes, dev_slots;
	int ret = 0;

	lockdep_assert_held(&c->replicas_gc_lock);

	mutex_lock(&c->sb_lock);

	r = rcu_dereference_protected(c->replicas_gc,
				      lockdep_is_held(&c->sb_lock));

	if (err) {
		rcu_assign_pointer(c->replicas_gc, NULL);
		kfree_rcu(r, rcu);
		goto err;
	}

	dev_slots = replicas_dev_slots(r);

	bytes = sizeof(struct bch_sb_field_replicas);

	for (i = 0; i < r->nr; i++) {
		struct bch_replicas_cpu_entry *e =
			cpu_replicas_entry(r, i);

		bytes += sizeof(struct bch_replicas_entry);
		for (j = 0; j < r->entry_size - 1; j++)
			bytes += hweight8(e->devs[j]);
	}

	sb_r = bch2_fs_sb_resize_replicas(c,
			DIV_ROUND_UP(sizeof(*sb_r) + bytes, sizeof(u64)));
	if (!sb_r) {
		ret = -ENOSPC;
		goto err;
	}

	memset(&sb_r->entries, 0,
	       vstruct_end(&sb_r->field) -
	       (void *) &sb_r->entries);

	dst_e = sb_r->entries;
	for (i = 0; i < r->nr; i++) {
		struct bch_replicas_cpu_entry *src_e =
			cpu_replicas_entry(r, i);

		dst_e->data_type = src_e->data_type;

		for (j = 0; j < dev_slots; j++)
			if (replicas_test_dev(src_e, j))
				dst_e->devs[dst_e->nr++] = j;

		dst_e = replicas_entry_next(dst_e);
	}

	old_r = rcu_dereference_protected(c->replicas,
					  lockdep_is_held(&c->sb_lock));
	rcu_assign_pointer(c->replicas, r);
	rcu_assign_pointer(c->replicas_gc, NULL);
	kfree_rcu(old_r, rcu);

	bch2_write_super(c);
err:
	mutex_unlock(&c->sb_lock);
	return ret;
}

int bch2_replicas_gc_start(struct bch_fs *c, unsigned typemask)
{
	struct bch_replicas_cpu *r, *src;
	unsigned i;

	lockdep_assert_held(&c->replicas_gc_lock);

	mutex_lock(&c->sb_lock);
	BUG_ON(c->replicas_gc);

	src = rcu_dereference_protected(c->replicas,
					lockdep_is_held(&c->sb_lock));

	r = kzalloc(sizeof(struct bch_replicas_cpu) +
		    src->nr * src->entry_size, GFP_NOIO);
	if (!r) {
		mutex_unlock(&c->sb_lock);
		return -ENOMEM;
	}

	r->entry_size = src->entry_size;
	r->nr = 0;

	for (i = 0; i < src->nr; i++) {
		struct bch_replicas_cpu_entry *dst_e =
			cpu_replicas_entry(r, r->nr);
		struct bch_replicas_cpu_entry *src_e =
			cpu_replicas_entry(src, i);

		if (!(src_e->data_type & typemask)) {
			memcpy(dst_e, src_e, r->entry_size);
			r->nr++;
		}
	}

	eytzinger0_sort(r->entries,
			r->nr,
			r->entry_size,
			memcmp, NULL);

	rcu_assign_pointer(c->replicas_gc, r);
	mutex_unlock(&c->sb_lock);

	return 0;
}
