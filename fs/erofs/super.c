// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 */
#include <linux/module.h>
#include <linux/buffer_head.h>
#include <linux/statfs.h>
#include <linux/parser.h>
#include <linux/seq_file.h>
#include <linux/crc32c.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/dax.h>
#include "xattr.h"

#define CREATE_TRACE_POINTS
#include <trace/events/erofs.h>

static struct kmem_cache *erofs_inode_cachep __read_mostly;

void _erofs_err(struct super_block *sb, const char *function,
		const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	pr_err("(device %s): %s: %pV", sb->s_id, function, &vaf);
	va_end(args);
}

void _erofs_info(struct super_block *sb, const char *function,
		 const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	pr_info("(device %s): %pV", sb->s_id, &vaf);
	va_end(args);
}

static int erofs_superblock_csum_verify(struct super_block *sb, void *sbdata)
{
	struct erofs_super_block *dsb;
	u32 expected_crc, crc;

	dsb = kmemdup(sbdata + EROFS_SUPER_OFFSET,
		      EROFS_BLKSIZ - EROFS_SUPER_OFFSET, GFP_KERNEL);
	if (!dsb)
		return -ENOMEM;

	expected_crc = le32_to_cpu(dsb->checksum);
	dsb->checksum = 0;
	/* to allow for x86 boot sectors and other oddities. */
	crc = crc32c(~0, dsb, EROFS_BLKSIZ - EROFS_SUPER_OFFSET);
	kfree(dsb);

	if (crc != expected_crc) {
		erofs_err(sb, "invalid checksum 0x%08x, 0x%08x expected",
			  crc, expected_crc);
		return -EBADMSG;
	}
	return 0;
}

static void erofs_inode_init_once(void *ptr)
{
	struct erofs_inode *vi = ptr;

	inode_init_once(&vi->vfs_inode);
}

static struct inode *erofs_alloc_inode(struct super_block *sb)
{
	struct erofs_inode *vi =
		kmem_cache_alloc(erofs_inode_cachep, GFP_KERNEL);

	if (!vi)
		return NULL;

	/* zero out everything except vfs_inode */
	memset(vi, 0, offsetof(struct erofs_inode, vfs_inode));
	return &vi->vfs_inode;
}

static void erofs_free_inode(struct inode *inode)
{
	struct erofs_inode *vi = EROFS_I(inode);

	/* be careful of RCU symlink path */
	if (inode->i_op == &erofs_fast_symlink_iops)
		kfree(inode->i_link);
	kfree(vi->xattr_shared_xattrs);

	kmem_cache_free(erofs_inode_cachep, vi);
}

static bool check_layout_compatibility(struct super_block *sb,
				       struct erofs_super_block *dsb)
{
	const unsigned int feature = le32_to_cpu(dsb->feature_incompat);

	EROFS_SB(sb)->feature_incompat = feature;

	/* check if current kernel meets all mandatory requirements */
	if (feature & (~EROFS_ALL_FEATURE_INCOMPAT)) {
		erofs_err(sb,
			  "unidentified incompatible feature %x, please upgrade kernel version",
			   feature & ~EROFS_ALL_FEATURE_INCOMPAT);
		return false;
	}
	return true;
}

#ifdef CONFIG_EROFS_FS_ZIP
/* read variable-sized metadata, offset will be aligned by 4-byte */
static void *erofs_read_metadata(struct super_block *sb, struct page **pagep,
				 erofs_off_t *offset, int *lengthp)
{
	struct page *page = *pagep;
	u8 *buffer, *ptr;
	int len, i, cnt;
	erofs_blk_t blk;

	*offset = round_up(*offset, 4);
	blk = erofs_blknr(*offset);

	if (!page || page->index != blk) {
		if (page) {
			unlock_page(page);
			put_page(page);
		}
		page = erofs_get_meta_page(sb, blk);
		if (IS_ERR(page))
			goto err_nullpage;
	}

	ptr = kmap(page);
	len = le16_to_cpu(*(__le16 *)&ptr[erofs_blkoff(*offset)]);
	if (!len)
		len = U16_MAX + 1;
	buffer = kmalloc(len, GFP_KERNEL);
	if (!buffer) {
		buffer = ERR_PTR(-ENOMEM);
		goto out;
	}
	*offset += sizeof(__le16);
	*lengthp = len;

	for (i = 0; i < len; i += cnt) {
		cnt = min(EROFS_BLKSIZ - (int)erofs_blkoff(*offset), len - i);
		blk = erofs_blknr(*offset);

		if (!page || page->index != blk) {
			if (page) {
				kunmap(page);
				unlock_page(page);
				put_page(page);
			}
			page = erofs_get_meta_page(sb, blk);
			if (IS_ERR(page)) {
				kfree(buffer);
				goto err_nullpage;
			}
			ptr = kmap(page);
		}
		memcpy(buffer + i, ptr + erofs_blkoff(*offset), cnt);
		*offset += cnt;
	}
out:
	kunmap(page);
	*pagep = page;
	return buffer;
err_nullpage:
	*pagep = NULL;
	return page;
}

static int erofs_load_compr_cfgs(struct super_block *sb,
				 struct erofs_super_block *dsb)
{
	struct erofs_sb_info *sbi;
	struct page *page;
	unsigned int algs, alg;
	erofs_off_t offset;
	int size, ret;

	sbi = EROFS_SB(sb);
	sbi->available_compr_algs = le16_to_cpu(dsb->u1.available_compr_algs);

	if (sbi->available_compr_algs & ~Z_EROFS_ALL_COMPR_ALGS) {
		erofs_err(sb, "try to load compressed fs with unsupported algorithms %x",
			  sbi->available_compr_algs & ~Z_EROFS_ALL_COMPR_ALGS);
		return -EINVAL;
	}

	offset = EROFS_SUPER_OFFSET + sbi->sb_size;
	page = NULL;
	alg = 0;
	ret = 0;

	for (algs = sbi->available_compr_algs; algs; algs >>= 1, ++alg) {
		void *data;

		if (!(algs & 1))
			continue;

		data = erofs_read_metadata(sb, &page, &offset, &size);
		if (IS_ERR(data)) {
			ret = PTR_ERR(data);
			goto err;
		}

		switch (alg) {
		case Z_EROFS_COMPRESSION_LZ4:
			ret = z_erofs_load_lz4_config(sb, dsb, data, size);
			break;
		case Z_EROFS_COMPRESSION_LZMA:
			ret = z_erofs_load_lzma_config(sb, dsb, data, size);
			break;
		default:
			DBG_BUGON(1);
			ret = -EFAULT;
		}
		kfree(data);
		if (ret)
			goto err;
	}
err:
	if (page) {
		unlock_page(page);
		put_page(page);
	}
	return ret;
}
#else
static int erofs_load_compr_cfgs(struct super_block *sb,
				 struct erofs_super_block *dsb)
{
	if (dsb->u1.available_compr_algs) {
		erofs_err(sb, "try to load compressed fs when compression is disabled");
		return -EINVAL;
	}
	return 0;
}
#endif

static int erofs_init_devices(struct super_block *sb,
			      struct erofs_super_block *dsb)
{
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	unsigned int ondisk_extradevs;
	erofs_off_t pos;
	struct page *page = NULL;
	struct erofs_device_info *dif;
	struct erofs_deviceslot *dis;
	void *ptr;
	int id, err = 0;

	sbi->total_blocks = sbi->primarydevice_blocks;
	if (!erofs_sb_has_device_table(sbi))
		ondisk_extradevs = 0;
	else
		ondisk_extradevs = le16_to_cpu(dsb->extra_devices);

	if (ondisk_extradevs != sbi->devs->extra_devices) {
		erofs_err(sb, "extra devices don't match (ondisk %u, given %u)",
			  ondisk_extradevs, sbi->devs->extra_devices);
		return -EINVAL;
	}
	if (!ondisk_extradevs)
		return 0;

	sbi->device_id_mask = roundup_pow_of_two(ondisk_extradevs + 1) - 1;
	pos = le16_to_cpu(dsb->devt_slotoff) * EROFS_DEVT_SLOT_SIZE;
	down_read(&sbi->devs->rwsem);
	idr_for_each_entry(&sbi->devs->tree, dif, id) {
		erofs_blk_t blk = erofs_blknr(pos);
		struct block_device *bdev;

		if (!page || page->index != blk) {
			if (page) {
				kunmap(page);
				unlock_page(page);
				put_page(page);
			}

			page = erofs_get_meta_page(sb, blk);
			if (IS_ERR(page)) {
				up_read(&sbi->devs->rwsem);
				return PTR_ERR(page);
			}
			ptr = kmap(page);
		}
		dis = ptr + erofs_blkoff(pos);

		bdev = blkdev_get_by_path(dif->path,
					  FMODE_READ | FMODE_EXCL,
					  sb->s_type);
		if (IS_ERR(bdev)) {
			err = PTR_ERR(bdev);
			goto err_out;
		}
		dif->bdev = bdev;
		dif->dax_dev = fs_dax_get_by_bdev(bdev);
		dif->blocks = le32_to_cpu(dis->blocks);
		dif->mapped_blkaddr = le32_to_cpu(dis->mapped_blkaddr);
		sbi->total_blocks += dif->blocks;
		pos += EROFS_DEVT_SLOT_SIZE;
	}
err_out:
	up_read(&sbi->devs->rwsem);
	if (page) {
		kunmap(page);
		unlock_page(page);
		put_page(page);
	}
	return err;
}

static int erofs_read_superblock(struct super_block *sb)
{
	struct erofs_sb_info *sbi;
	struct page *page;
	struct erofs_super_block *dsb;
	unsigned int blkszbits;
	void *data;
	int ret;

	page = read_mapping_page(sb->s_bdev->bd_inode->i_mapping, 0, NULL);
	if (IS_ERR(page)) {
		erofs_err(sb, "cannot read erofs superblock");
		return PTR_ERR(page);
	}

	sbi = EROFS_SB(sb);

	data = kmap(page);
	dsb = (struct erofs_super_block *)(data + EROFS_SUPER_OFFSET);

	ret = -EINVAL;
	if (le32_to_cpu(dsb->magic) != EROFS_SUPER_MAGIC_V1) {
		erofs_err(sb, "cannot find valid erofs superblock");
		goto out;
	}

	sbi->feature_compat = le32_to_cpu(dsb->feature_compat);
	if (erofs_sb_has_sb_chksum(sbi)) {
		ret = erofs_superblock_csum_verify(sb, data);
		if (ret)
			goto out;
	}

	ret = -EINVAL;
	blkszbits = dsb->blkszbits;
	/* 9(512 bytes) + LOG_SECTORS_PER_BLOCK == LOG_BLOCK_SIZE */
	if (blkszbits != LOG_BLOCK_SIZE) {
		erofs_err(sb, "blkszbits %u isn't supported on this platform",
			  blkszbits);
		goto out;
	}

	if (!check_layout_compatibility(sb, dsb))
		goto out;

	sbi->sb_size = 128 + dsb->sb_extslots * EROFS_SB_EXTSLOT_SIZE;
	if (sbi->sb_size > EROFS_BLKSIZ) {
		erofs_err(sb, "invalid sb_extslots %u (more than a fs block)",
			  sbi->sb_size);
		goto out;
	}
	sbi->primarydevice_blocks = le32_to_cpu(dsb->blocks);
	sbi->meta_blkaddr = le32_to_cpu(dsb->meta_blkaddr);
#ifdef CONFIG_EROFS_FS_XATTR
	sbi->xattr_blkaddr = le32_to_cpu(dsb->xattr_blkaddr);
#endif
	sbi->islotbits = ilog2(sizeof(struct erofs_inode_compact));
	sbi->root_nid = le16_to_cpu(dsb->root_nid);
	sbi->inos = le64_to_cpu(dsb->inos);

	sbi->build_time = le64_to_cpu(dsb->build_time);
	sbi->build_time_nsec = le32_to_cpu(dsb->build_time_nsec);

	memcpy(&sb->s_uuid, dsb->uuid, sizeof(dsb->uuid));

	ret = strscpy(sbi->volume_name, dsb->volume_name,
		      sizeof(dsb->volume_name));
	if (ret < 0) {	/* -E2BIG */
		erofs_err(sb, "bad volume name without NIL terminator");
		ret = -EFSCORRUPTED;
		goto out;
	}

	/* parse on-disk compression configurations */
	if (erofs_sb_has_compr_cfgs(sbi))
		ret = erofs_load_compr_cfgs(sb, dsb);
	else
		ret = z_erofs_load_lz4_config(sb, dsb, NULL, 0);
	if (ret < 0)
		goto out;

	/* handle multiple devices */
	ret = erofs_init_devices(sb, dsb);
out:
	kunmap(page);
	put_page(page);
	return ret;
}

/* set up default EROFS parameters */
static void erofs_default_options(struct erofs_fs_context *ctx)
{
#ifdef CONFIG_EROFS_FS_ZIP
	ctx->opt.cache_strategy = EROFS_ZIP_CACHE_READAROUND;
	ctx->opt.max_sync_decompress_pages = 3;
	ctx->opt.readahead_sync_decompress = false;
#endif
#ifdef CONFIG_EROFS_FS_XATTR
	set_opt(&ctx->opt, XATTR_USER);
#endif
#ifdef CONFIG_EROFS_FS_POSIX_ACL
	set_opt(&ctx->opt, POSIX_ACL);
#endif
}

enum {
	Opt_user_xattr,
	Opt_acl,
	Opt_cache_strategy,
	Opt_dax,
	Opt_dax_enum,
	Opt_device,
	Opt_err
};

static const struct constant_table erofs_param_cache_strategy[] = {
	{"disabled",	EROFS_ZIP_CACHE_DISABLED},
	{"readahead",	EROFS_ZIP_CACHE_READAHEAD},
	{"readaround",	EROFS_ZIP_CACHE_READAROUND},
	{}
};

static const struct constant_table erofs_dax_param_enums[] = {
	{"always",	EROFS_MOUNT_DAX_ALWAYS},
	{"never",	EROFS_MOUNT_DAX_NEVER},
	{}
};

static const struct fs_parameter_spec erofs_fs_parameters[] = {
	fsparam_flag_no("user_xattr",	Opt_user_xattr),
	fsparam_flag_no("acl",		Opt_acl),
	fsparam_enum("cache_strategy",	Opt_cache_strategy,
		     erofs_param_cache_strategy),
	fsparam_flag("dax",             Opt_dax),
	fsparam_enum("dax",		Opt_dax_enum, erofs_dax_param_enums),
	fsparam_string("device",	Opt_device),
	{}
};

static bool erofs_fc_set_dax_mode(struct fs_context *fc, unsigned int mode)
{
#ifdef CONFIG_FS_DAX
	struct erofs_fs_context *ctx = fc->fs_private;

	switch (mode) {
	case EROFS_MOUNT_DAX_ALWAYS:
		warnfc(fc, "DAX enabled. Warning: EXPERIMENTAL, use at your own risk");
		set_opt(&ctx->opt, DAX_ALWAYS);
		clear_opt(&ctx->opt, DAX_NEVER);
		return true;
	case EROFS_MOUNT_DAX_NEVER:
		set_opt(&ctx->opt, DAX_NEVER);
		clear_opt(&ctx->opt, DAX_ALWAYS);
		return true;
	default:
		DBG_BUGON(1);
		return false;
	}
#else
	errorfc(fc, "dax options not supported");
	return false;
#endif
}

static int erofs_fc_parse_param(struct fs_context *fc,
				struct fs_parameter *param)
{
	struct erofs_fs_context *ctx = fc->fs_private;
	struct fs_parse_result result;
	struct erofs_device_info *dif;
	int opt, ret;

	opt = fs_parse(fc, erofs_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_user_xattr:
#ifdef CONFIG_EROFS_FS_XATTR
		if (result.boolean)
			set_opt(&ctx->opt, XATTR_USER);
		else
			clear_opt(&ctx->opt, XATTR_USER);
#else
		errorfc(fc, "{,no}user_xattr options not supported");
#endif
		break;
	case Opt_acl:
#ifdef CONFIG_EROFS_FS_POSIX_ACL
		if (result.boolean)
			set_opt(&ctx->opt, POSIX_ACL);
		else
			clear_opt(&ctx->opt, POSIX_ACL);
#else
		errorfc(fc, "{,no}acl options not supported");
#endif
		break;
	case Opt_cache_strategy:
#ifdef CONFIG_EROFS_FS_ZIP
		ctx->opt.cache_strategy = result.uint_32;
#else
		errorfc(fc, "compression not supported, cache_strategy ignored");
#endif
		break;
	case Opt_dax:
		if (!erofs_fc_set_dax_mode(fc, EROFS_MOUNT_DAX_ALWAYS))
			return -EINVAL;
		break;
	case Opt_dax_enum:
		if (!erofs_fc_set_dax_mode(fc, result.uint_32))
			return -EINVAL;
		break;
	case Opt_device:
		dif = kzalloc(sizeof(*dif), GFP_KERNEL);
		if (!dif)
			return -ENOMEM;
		dif->path = kstrdup(param->string, GFP_KERNEL);
		if (!dif->path) {
			kfree(dif);
			return -ENOMEM;
		}
		down_write(&ctx->devs->rwsem);
		ret = idr_alloc(&ctx->devs->tree, dif, 0, 0, GFP_KERNEL);
		up_write(&ctx->devs->rwsem);
		if (ret < 0) {
			kfree(dif->path);
			kfree(dif);
			return ret;
		}
		++ctx->devs->extra_devices;
		break;
	default:
		return -ENOPARAM;
	}
	return 0;
}

#ifdef CONFIG_EROFS_FS_ZIP
static const struct address_space_operations managed_cache_aops;

static int erofs_managed_cache_releasepage(struct page *page, gfp_t gfp_mask)
{
	int ret = 1;	/* 0 - busy */
	struct address_space *const mapping = page->mapping;

	DBG_BUGON(!PageLocked(page));
	DBG_BUGON(mapping->a_ops != &managed_cache_aops);

	if (PagePrivate(page))
		ret = erofs_try_to_free_cached_page(page);

	return ret;
}

static void erofs_managed_cache_invalidatepage(struct page *page,
					       unsigned int offset,
					       unsigned int length)
{
	const unsigned int stop = length + offset;

	DBG_BUGON(!PageLocked(page));

	/* Check for potential overflow in debug mode */
	DBG_BUGON(stop > PAGE_SIZE || stop < length);

	if (offset == 0 && stop == PAGE_SIZE)
		while (!erofs_managed_cache_releasepage(page, GFP_NOFS))
			cond_resched();
}

static const struct address_space_operations managed_cache_aops = {
	.releasepage = erofs_managed_cache_releasepage,
	.invalidatepage = erofs_managed_cache_invalidatepage,
};

static int erofs_init_managed_cache(struct super_block *sb)
{
	struct erofs_sb_info *const sbi = EROFS_SB(sb);
	struct inode *const inode = new_inode(sb);

	if (!inode)
		return -ENOMEM;

	set_nlink(inode, 1);
	inode->i_size = OFFSET_MAX;

	inode->i_mapping->a_ops = &managed_cache_aops;
	mapping_set_gfp_mask(inode->i_mapping,
			     GFP_NOFS | __GFP_HIGHMEM | __GFP_MOVABLE);
	sbi->managed_cache = inode;
	return 0;
}
#else
static int erofs_init_managed_cache(struct super_block *sb) { return 0; }
#endif

static int erofs_fc_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct inode *inode;
	struct erofs_sb_info *sbi;
	struct erofs_fs_context *ctx = fc->fs_private;
	int err;

	sb->s_magic = EROFS_SUPER_MAGIC;

	if (!sb_set_blocksize(sb, EROFS_BLKSIZ)) {
		erofs_err(sb, "failed to set erofs blksize");
		return -EINVAL;
	}

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sb->s_fs_info = sbi;
	sbi->opt = ctx->opt;
	sbi->dax_dev = fs_dax_get_by_bdev(sb->s_bdev);
	sbi->devs = ctx->devs;
	ctx->devs = NULL;

	err = erofs_read_superblock(sb);
	if (err)
		return err;

	if (test_opt(&sbi->opt, DAX_ALWAYS) &&
	    !dax_supported(sbi->dax_dev, sb->s_bdev, EROFS_BLKSIZ, 0, bdev_nr_sectors(sb->s_bdev))) {
		errorfc(fc, "DAX unsupported by block device. Turning off DAX.");
		clear_opt(&sbi->opt, DAX_ALWAYS);
	}
	sb->s_flags |= SB_RDONLY | SB_NOATIME;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_time_gran = 1;

	sb->s_op = &erofs_sops;
	sb->s_xattr = erofs_xattr_handlers;

	if (test_opt(&sbi->opt, POSIX_ACL))
		sb->s_flags |= SB_POSIXACL;
	else
		sb->s_flags &= ~SB_POSIXACL;

#ifdef CONFIG_EROFS_FS_ZIP
	xa_init(&sbi->managed_pslots);
#endif

	/* get the root inode */
	inode = erofs_iget(sb, ROOT_NID(sbi), true);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	if (!S_ISDIR(inode->i_mode)) {
		erofs_err(sb, "rootino(nid %llu) is not a directory(i_mode %o)",
			  ROOT_NID(sbi), inode->i_mode);
		iput(inode);
		return -EINVAL;
	}

	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	erofs_shrinker_register(sb);
	/* sb->s_umount is already locked, SB_ACTIVE and SB_BORN are not set */
	err = erofs_init_managed_cache(sb);
	if (err)
		return err;

	erofs_info(sb, "mounted with root inode @ nid %llu.", ROOT_NID(sbi));
	return 0;
}

static int erofs_fc_get_tree(struct fs_context *fc)
{
	return get_tree_bdev(fc, erofs_fc_fill_super);
}

static int erofs_fc_reconfigure(struct fs_context *fc)
{
	struct super_block *sb = fc->root->d_sb;
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	struct erofs_fs_context *ctx = fc->fs_private;

	DBG_BUGON(!sb_rdonly(sb));

	if (test_opt(&ctx->opt, POSIX_ACL))
		fc->sb_flags |= SB_POSIXACL;
	else
		fc->sb_flags &= ~SB_POSIXACL;

	sbi->opt = ctx->opt;

	fc->sb_flags |= SB_RDONLY;
	return 0;
}

static int erofs_release_device_info(int id, void *ptr, void *data)
{
	struct erofs_device_info *dif = ptr;

	fs_put_dax(dif->dax_dev);
	if (dif->bdev)
		blkdev_put(dif->bdev, FMODE_READ | FMODE_EXCL);
	kfree(dif->path);
	kfree(dif);
	return 0;
}

static void erofs_free_dev_context(struct erofs_dev_context *devs)
{
	if (!devs)
		return;
	idr_for_each(&devs->tree, &erofs_release_device_info, NULL);
	idr_destroy(&devs->tree);
	kfree(devs);
}

static void erofs_fc_free(struct fs_context *fc)
{
	struct erofs_fs_context *ctx = fc->fs_private;

	erofs_free_dev_context(ctx->devs);
	kfree(ctx);
}

static const struct fs_context_operations erofs_context_ops = {
	.parse_param	= erofs_fc_parse_param,
	.get_tree       = erofs_fc_get_tree,
	.reconfigure    = erofs_fc_reconfigure,
	.free		= erofs_fc_free,
};

static int erofs_init_fs_context(struct fs_context *fc)
{
	struct erofs_fs_context *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

	if (!ctx)
		return -ENOMEM;
	ctx->devs = kzalloc(sizeof(struct erofs_dev_context), GFP_KERNEL);
	if (!ctx->devs) {
		kfree(ctx);
		return -ENOMEM;
	}
	fc->fs_private = ctx;

	idr_init(&ctx->devs->tree);
	init_rwsem(&ctx->devs->rwsem);
	erofs_default_options(ctx);
	fc->ops = &erofs_context_ops;
	return 0;
}

/*
 * could be triggered after deactivate_locked_super()
 * is called, thus including umount and failed to initialize.
 */
static void erofs_kill_sb(struct super_block *sb)
{
	struct erofs_sb_info *sbi;

	WARN_ON(sb->s_magic != EROFS_SUPER_MAGIC);

	kill_block_super(sb);

	sbi = EROFS_SB(sb);
	if (!sbi)
		return;

	erofs_free_dev_context(sbi->devs);
	fs_put_dax(sbi->dax_dev);
	kfree(sbi);
	sb->s_fs_info = NULL;
}

/* called when ->s_root is non-NULL */
static void erofs_put_super(struct super_block *sb)
{
	struct erofs_sb_info *const sbi = EROFS_SB(sb);

	DBG_BUGON(!sbi);

	erofs_shrinker_unregister(sb);
#ifdef CONFIG_EROFS_FS_ZIP
	iput(sbi->managed_cache);
	sbi->managed_cache = NULL;
#endif
}

static struct file_system_type erofs_fs_type = {
	.owner          = THIS_MODULE,
	.name           = "erofs",
	.init_fs_context = erofs_init_fs_context,
	.kill_sb        = erofs_kill_sb,
	.fs_flags       = FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("erofs");

static int __init erofs_module_init(void)
{
	int err;

	erofs_check_ondisk_layout_definitions();

	erofs_inode_cachep = kmem_cache_create("erofs_inode",
					       sizeof(struct erofs_inode), 0,
					       SLAB_RECLAIM_ACCOUNT,
					       erofs_inode_init_once);
	if (!erofs_inode_cachep) {
		err = -ENOMEM;
		goto icache_err;
	}

	err = erofs_init_shrinker();
	if (err)
		goto shrinker_err;

	err = z_erofs_lzma_init();
	if (err)
		goto lzma_err;

	erofs_pcpubuf_init();
	err = z_erofs_init_zip_subsystem();
	if (err)
		goto zip_err;

	err = register_filesystem(&erofs_fs_type);
	if (err)
		goto fs_err;

	return 0;

fs_err:
	z_erofs_exit_zip_subsystem();
zip_err:
	z_erofs_lzma_exit();
lzma_err:
	erofs_exit_shrinker();
shrinker_err:
	kmem_cache_destroy(erofs_inode_cachep);
icache_err:
	return err;
}

static void __exit erofs_module_exit(void)
{
	unregister_filesystem(&erofs_fs_type);

	/* Ensure all RCU free inodes / pclusters are safe to be destroyed. */
	rcu_barrier();

	z_erofs_exit_zip_subsystem();
	z_erofs_lzma_exit();
	erofs_exit_shrinker();
	kmem_cache_destroy(erofs_inode_cachep);
	erofs_pcpubuf_exit();
}

/* get filesystem statistics */
static int erofs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	buf->f_type = sb->s_magic;
	buf->f_bsize = EROFS_BLKSIZ;
	buf->f_blocks = sbi->total_blocks;
	buf->f_bfree = buf->f_bavail = 0;

	buf->f_files = ULLONG_MAX;
	buf->f_ffree = ULLONG_MAX - sbi->inos;

	buf->f_namelen = EROFS_NAME_LEN;

	buf->f_fsid    = u64_to_fsid(id);
	return 0;
}

static int erofs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct erofs_sb_info *sbi = EROFS_SB(root->d_sb);
	struct erofs_mount_opts *opt = &sbi->opt;

#ifdef CONFIG_EROFS_FS_XATTR
	if (test_opt(opt, XATTR_USER))
		seq_puts(seq, ",user_xattr");
	else
		seq_puts(seq, ",nouser_xattr");
#endif
#ifdef CONFIG_EROFS_FS_POSIX_ACL
	if (test_opt(opt, POSIX_ACL))
		seq_puts(seq, ",acl");
	else
		seq_puts(seq, ",noacl");
#endif
#ifdef CONFIG_EROFS_FS_ZIP
	if (opt->cache_strategy == EROFS_ZIP_CACHE_DISABLED)
		seq_puts(seq, ",cache_strategy=disabled");
	else if (opt->cache_strategy == EROFS_ZIP_CACHE_READAHEAD)
		seq_puts(seq, ",cache_strategy=readahead");
	else if (opt->cache_strategy == EROFS_ZIP_CACHE_READAROUND)
		seq_puts(seq, ",cache_strategy=readaround");
#endif
	if (test_opt(opt, DAX_ALWAYS))
		seq_puts(seq, ",dax=always");
	if (test_opt(opt, DAX_NEVER))
		seq_puts(seq, ",dax=never");
	return 0;
}

const struct super_operations erofs_sops = {
	.put_super = erofs_put_super,
	.alloc_inode = erofs_alloc_inode,
	.free_inode = erofs_free_inode,
	.statfs = erofs_statfs,
	.show_options = erofs_show_options,
};

module_init(erofs_module_init);
module_exit(erofs_module_exit);

MODULE_DESCRIPTION("Enhanced ROM File System");
MODULE_AUTHOR("Gao Xiang, Chao Yu, Miao Xie, CONSUMER BG, HUAWEI Inc.");
MODULE_LICENSE("GPL");
