// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Filesystem management and hooks
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 * Copyright © 2021-2025 Microsoft Corporation
 * Copyright © 2022 Günther Noack <gnoack3000@gmail.com>
 * Copyright © 2023-2024 Google LLC
 */

#include <asm/ioctls.h>
#include <kunit/test.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/bits.h>
#include <linux/compiler_types.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/falloc.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/lsm_audit.h>
#include <linux/lsm_hooks.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/wait_bit.h>
#include <linux/workqueue.h>
#include <uapi/linux/fiemap.h>
#include <uapi/linux/landlock.h>

#include "access.h"
#include "audit.h"
#include "common.h"
#include "cred.h"
#include "domain.h"
#include "fs.h"
#include "limits.h"
#include "object.h"
#include "ruleset.h"
#include "setup.h"

/* Underlying object management */

static void release_inode(struct landlock_object *const object)
	__releases(object->lock)
{
	struct inode *const inode = object->underobj;
	struct super_block *sb;

	if (!inode) {
		spin_unlock(&object->lock);
		return;
	}

	/*
	 * Protects against concurrent use by hook_sb_delete() of the reference
	 * to the underlying inode.
	 */
	object->underobj = NULL;
	/*
	 * Makes sure that if the filesystem is concurrently unmounted,
	 * hook_sb_delete() will wait for us to finish iput().
	 */
	sb = inode->i_sb;
	atomic_long_inc(&landlock_superblock(sb)->inode_refs);
	spin_unlock(&object->lock);
	/*
	 * Because object->underobj was not NULL, hook_sb_delete() and
	 * get_inode_object() guarantee that it is safe to reset
	 * landlock_inode(inode)->object while it is not NULL.  It is therefore
	 * not necessary to lock inode->i_lock.
	 */
	rcu_assign_pointer(landlock_inode(inode)->object, NULL);
	/*
	 * Now, new rules can safely be tied to @inode with get_inode_object().
	 */

	iput(inode);
	if (atomic_long_dec_and_test(&landlock_superblock(sb)->inode_refs))
		wake_up_var(&landlock_superblock(sb)->inode_refs);
}

static const struct landlock_object_underops landlock_fs_underops = {
	.release = release_inode
};

/* IOCTL helpers */

/**
 * is_masked_device_ioctl - Determine whether an IOCTL command is always
 * permitted with Landlock for device files.  These commands can not be
 * restricted on device files by enforcing a Landlock policy.
 *
 * @cmd: The IOCTL command that is supposed to be run.
 *
 * By default, any IOCTL on a device file requires the
 * LANDLOCK_ACCESS_FS_IOCTL_DEV right.  However, we blanket-permit some
 * commands, if:
 *
 * 1. The command is implemented in fs/ioctl.c's do_vfs_ioctl(),
 *    not in f_ops->unlocked_ioctl() or f_ops->compat_ioctl().
 *
 * 2. The command is harmless when invoked on devices.
 *
 * We also permit commands that do not make sense for devices, but where the
 * do_vfs_ioctl() implementation returns a more conventional error code.
 *
 * Any new IOCTL commands that are implemented in fs/ioctl.c's do_vfs_ioctl()
 * should be considered for inclusion here.
 *
 * Returns: true if the IOCTL @cmd can not be restricted with Landlock for
 * device files.
 */
static __attribute_const__ bool is_masked_device_ioctl(const unsigned int cmd)
{
	switch (cmd) {
	/*
	 * FIOCLEX, FIONCLEX, FIONBIO and FIOASYNC manipulate the FD's
	 * close-on-exec and the file's buffered-IO and async flags.  These
	 * operations are also available through fcntl(2), and are
	 * unconditionally permitted in Landlock.
	 */
	case FIOCLEX:
	case FIONCLEX:
	case FIONBIO:
	case FIOASYNC:
	/*
	 * FIOQSIZE queries the size of a regular file, directory, or link.
	 *
	 * We still permit it, because it always returns -ENOTTY for
	 * other file types.
	 */
	case FIOQSIZE:
	/*
	 * FIFREEZE and FITHAW freeze and thaw the file system which the
	 * given file belongs to.  Requires CAP_SYS_ADMIN.
	 *
	 * These commands operate on the file system's superblock rather
	 * than on the file itself.  The same operations can also be
	 * done through any other file or directory on the same file
	 * system, so it is safe to permit these.
	 */
	case FIFREEZE:
	case FITHAW:
	/*
	 * FS_IOC_FIEMAP queries information about the allocation of
	 * blocks within a file.
	 *
	 * This IOCTL command only makes sense for regular files and is
	 * not implemented by devices. It is harmless to permit.
	 */
	case FS_IOC_FIEMAP:
	/*
	 * FIGETBSZ queries the file system's block size for a file or
	 * directory.
	 *
	 * This command operates on the file system's superblock rather
	 * than on the file itself.  The same operation can also be done
	 * through any other file or directory on the same file system,
	 * so it is safe to permit it.
	 */
	case FIGETBSZ:
	/*
	 * FICLONE, FICLONERANGE and FIDEDUPERANGE make files share
	 * their underlying storage ("reflink") between source and
	 * destination FDs, on file systems which support that.
	 *
	 * These IOCTL commands only apply to regular files
	 * and are harmless to permit for device files.
	 */
	case FICLONE:
	case FICLONERANGE:
	case FIDEDUPERANGE:
	/*
	 * FS_IOC_GETFSUUID and FS_IOC_GETFSSYSFSPATH both operate on
	 * the file system superblock, not on the specific file, so
	 * these operations are available through any other file on the
	 * same file system as well.
	 */
	case FS_IOC_GETFSUUID:
	case FS_IOC_GETFSSYSFSPATH:
		return true;

	/*
	 * FIONREAD, FS_IOC_GETFLAGS, FS_IOC_SETFLAGS, FS_IOC_FSGETXATTR and
	 * FS_IOC_FSSETXATTR are forwarded to device implementations.
	 */

	/*
	 * file_ioctl() commands (FIBMAP, FS_IOC_RESVSP, FS_IOC_RESVSP64,
	 * FS_IOC_UNRESVSP, FS_IOC_UNRESVSP64 and FS_IOC_ZERO_RANGE) are
	 * forwarded to device implementations, so not permitted.
	 */

	/* Other commands are guarded by the access right. */
	default:
		return false;
	}
}

/*
 * is_masked_device_ioctl_compat - same as the helper above, but checking the
 * "compat" IOCTL commands.
 *
 * The IOCTL commands with special handling in compat-mode should behave the
 * same as their non-compat counterparts.
 */
static __attribute_const__ bool
is_masked_device_ioctl_compat(const unsigned int cmd)
{
	switch (cmd) {
	/* FICLONE is permitted, same as in the non-compat variant. */
	case FICLONE:
		return true;

#if defined(CONFIG_X86_64)
	/*
	 * FS_IOC_RESVSP_32, FS_IOC_RESVSP64_32, FS_IOC_UNRESVSP_32,
	 * FS_IOC_UNRESVSP64_32, FS_IOC_ZERO_RANGE_32: not blanket-permitted,
	 * for consistency with their non-compat variants.
	 */
	case FS_IOC_RESVSP_32:
	case FS_IOC_RESVSP64_32:
	case FS_IOC_UNRESVSP_32:
	case FS_IOC_UNRESVSP64_32:
	case FS_IOC_ZERO_RANGE_32:
#endif

	/*
	 * FS_IOC32_GETFLAGS, FS_IOC32_SETFLAGS are forwarded to their device
	 * implementations.
	 */
	case FS_IOC32_GETFLAGS:
	case FS_IOC32_SETFLAGS:
		return false;
	default:
		return is_masked_device_ioctl(cmd);
	}
}

/* Ruleset management */

static struct landlock_object *get_inode_object(struct inode *const inode)
{
	struct landlock_object *object, *new_object;
	struct landlock_inode_security *inode_sec = landlock_inode(inode);

	rcu_read_lock();
retry:
	object = rcu_dereference(inode_sec->object);
	if (object) {
		if (likely(refcount_inc_not_zero(&object->usage))) {
			rcu_read_unlock();
			return object;
		}
		/*
		 * We are racing with release_inode(), the object is going
		 * away.  Wait for release_inode(), then retry.
		 */
		spin_lock(&object->lock);
		spin_unlock(&object->lock);
		goto retry;
	}
	rcu_read_unlock();

	/*
	 * If there is no object tied to @inode, then create a new one (without
	 * holding any locks).
	 */
	new_object = landlock_create_object(&landlock_fs_underops, inode);
	if (IS_ERR(new_object))
		return new_object;

	/*
	 * Protects against concurrent calls to get_inode_object() or
	 * hook_sb_delete().
	 */
	spin_lock(&inode->i_lock);
	if (unlikely(rcu_access_pointer(inode_sec->object))) {
		/* Someone else just created the object, bail out and retry. */
		spin_unlock(&inode->i_lock);
		kfree(new_object);

		rcu_read_lock();
		goto retry;
	}

	/*
	 * @inode will be released by hook_sb_delete() on its superblock
	 * shutdown, or by release_inode() when no more ruleset references the
	 * related object.
	 */
	ihold(inode);
	rcu_assign_pointer(inode_sec->object, new_object);
	spin_unlock(&inode->i_lock);
	return new_object;
}

/* All access rights that can be tied to files. */
/* clang-format off */
#define ACCESS_FILE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_TRUNCATE | \
	LANDLOCK_ACCESS_FS_IOCTL_DEV)
/* clang-format on */

/*
 * @path: Should have been checked by get_path_from_fd().
 */
int landlock_append_fs_rule(struct landlock_ruleset *const ruleset,
			    const struct path *const path,
			    access_mask_t access_rights)
{
	int err;
	struct landlock_id id = {
		.type = LANDLOCK_KEY_INODE,
	};

	/* Files only get access rights that make sense. */
	if (!d_is_dir(path->dentry) &&
	    (access_rights | ACCESS_FILE) != ACCESS_FILE)
		return -EINVAL;
	if (WARN_ON_ONCE(ruleset->num_layers != 1))
		return -EINVAL;

	/* Transforms relative access rights to absolute ones. */
	access_rights |= LANDLOCK_MASK_ACCESS_FS &
			 ~landlock_get_fs_access_mask(ruleset, 0);
	id.key.object = get_inode_object(d_backing_inode(path->dentry));
	if (IS_ERR(id.key.object))
		return PTR_ERR(id.key.object);
	mutex_lock(&ruleset->lock);
	err = landlock_insert_rule(ruleset, id, access_rights);
	mutex_unlock(&ruleset->lock);
	/*
	 * No need to check for an error because landlock_insert_rule()
	 * increments the refcount for the new object if needed.
	 */
	landlock_put_object(id.key.object);
	return err;
}

/* Access-control management */

/*
 * The lifetime of the returned rule is tied to @domain.
 *
 * Returns NULL if no rule is found or if @dentry is negative.
 */
static const struct landlock_rule *
find_rule(const struct landlock_ruleset *const domain,
	  const struct dentry *const dentry)
{
	const struct landlock_rule *rule;
	const struct inode *inode;
	struct landlock_id id = {
		.type = LANDLOCK_KEY_INODE,
	};

	/* Ignores nonexistent leafs. */
	if (d_is_negative(dentry))
		return NULL;

	inode = d_backing_inode(dentry);
	rcu_read_lock();
	id.key.object = rcu_dereference(landlock_inode(inode)->object);
	rule = landlock_find_rule(domain, id);
	rcu_read_unlock();
	return rule;
}

/*
 * Allows access to pseudo filesystems that will never be mountable (e.g.
 * sockfs, pipefs), but can still be reachable through
 * /proc/<pid>/fd/<file-descriptor>
 */
static bool is_nouser_or_private(const struct dentry *dentry)
{
	return (dentry->d_sb->s_flags & SB_NOUSER) ||
	       (d_is_positive(dentry) &&
		unlikely(IS_PRIVATE(d_backing_inode(dentry))));
}

static const struct access_masks any_fs = {
	.fs = ~0,
};

/*
 * Check that a destination file hierarchy has more restrictions than a source
 * file hierarchy.  This is only used for link and rename actions.
 *
 * @layer_masks_child2: Optional child masks.
 */
static bool no_more_access(
	const layer_mask_t (*const layer_masks_parent1)[LANDLOCK_NUM_ACCESS_FS],
	const layer_mask_t (*const layer_masks_child1)[LANDLOCK_NUM_ACCESS_FS],
	const bool child1_is_directory,
	const layer_mask_t (*const layer_masks_parent2)[LANDLOCK_NUM_ACCESS_FS],
	const layer_mask_t (*const layer_masks_child2)[LANDLOCK_NUM_ACCESS_FS],
	const bool child2_is_directory)
{
	unsigned long access_bit;

	for (access_bit = 0; access_bit < ARRAY_SIZE(*layer_masks_parent2);
	     access_bit++) {
		/* Ignores accesses that only make sense for directories. */
		const bool is_file_access =
			!!(BIT_ULL(access_bit) & ACCESS_FILE);

		if (child1_is_directory || is_file_access) {
			/*
			 * Checks if the destination restrictions are a
			 * superset of the source ones (i.e. inherited access
			 * rights without child exceptions):
			 * restrictions(parent2) >= restrictions(child1)
			 */
			if ((((*layer_masks_parent1)[access_bit] &
			      (*layer_masks_child1)[access_bit]) |
			     (*layer_masks_parent2)[access_bit]) !=
			    (*layer_masks_parent2)[access_bit])
				return false;
		}

		if (!layer_masks_child2)
			continue;
		if (child2_is_directory || is_file_access) {
			/*
			 * Checks inverted restrictions for RENAME_EXCHANGE:
			 * restrictions(parent1) >= restrictions(child2)
			 */
			if ((((*layer_masks_parent2)[access_bit] &
			      (*layer_masks_child2)[access_bit]) |
			     (*layer_masks_parent1)[access_bit]) !=
			    (*layer_masks_parent1)[access_bit])
				return false;
		}
	}
	return true;
}

#define NMA_TRUE(...) KUNIT_EXPECT_TRUE(test, no_more_access(__VA_ARGS__))
#define NMA_FALSE(...) KUNIT_EXPECT_FALSE(test, no_more_access(__VA_ARGS__))

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST

static void test_no_more_access(struct kunit *const test)
{
	const layer_mask_t rx0[LANDLOCK_NUM_ACCESS_FS] = {
		[BIT_INDEX(LANDLOCK_ACCESS_FS_EXECUTE)] = BIT_ULL(0),
		[BIT_INDEX(LANDLOCK_ACCESS_FS_READ_FILE)] = BIT_ULL(0),
	};
	const layer_mask_t mx0[LANDLOCK_NUM_ACCESS_FS] = {
		[BIT_INDEX(LANDLOCK_ACCESS_FS_EXECUTE)] = BIT_ULL(0),
		[BIT_INDEX(LANDLOCK_ACCESS_FS_MAKE_REG)] = BIT_ULL(0),
	};
	const layer_mask_t x0[LANDLOCK_NUM_ACCESS_FS] = {
		[BIT_INDEX(LANDLOCK_ACCESS_FS_EXECUTE)] = BIT_ULL(0),
	};
	const layer_mask_t x1[LANDLOCK_NUM_ACCESS_FS] = {
		[BIT_INDEX(LANDLOCK_ACCESS_FS_EXECUTE)] = BIT_ULL(1),
	};
	const layer_mask_t x01[LANDLOCK_NUM_ACCESS_FS] = {
		[BIT_INDEX(LANDLOCK_ACCESS_FS_EXECUTE)] = BIT_ULL(0) |
							  BIT_ULL(1),
	};
	const layer_mask_t allows_all[LANDLOCK_NUM_ACCESS_FS] = {};

	/* Checks without restriction. */
	NMA_TRUE(&x0, &allows_all, false, &allows_all, NULL, false);
	NMA_TRUE(&allows_all, &x0, false, &allows_all, NULL, false);
	NMA_FALSE(&x0, &x0, false, &allows_all, NULL, false);

	/*
	 * Checks that we can only refer a file if no more access could be
	 * inherited.
	 */
	NMA_TRUE(&x0, &x0, false, &rx0, NULL, false);
	NMA_TRUE(&rx0, &rx0, false, &rx0, NULL, false);
	NMA_FALSE(&rx0, &rx0, false, &x0, NULL, false);
	NMA_FALSE(&rx0, &rx0, false, &x1, NULL, false);

	/* Checks allowed referring with different nested domains. */
	NMA_TRUE(&x0, &x1, false, &x0, NULL, false);
	NMA_TRUE(&x1, &x0, false, &x0, NULL, false);
	NMA_TRUE(&x0, &x01, false, &x0, NULL, false);
	NMA_TRUE(&x0, &x01, false, &rx0, NULL, false);
	NMA_TRUE(&x01, &x0, false, &x0, NULL, false);
	NMA_TRUE(&x01, &x0, false, &rx0, NULL, false);
	NMA_FALSE(&x01, &x01, false, &x0, NULL, false);

	/* Checks that file access rights are also enforced for a directory. */
	NMA_FALSE(&rx0, &rx0, true, &x0, NULL, false);

	/* Checks that directory access rights don't impact file referring... */
	NMA_TRUE(&mx0, &mx0, false, &x0, NULL, false);
	/* ...but only directory referring. */
	NMA_FALSE(&mx0, &mx0, true, &x0, NULL, false);

	/* Checks directory exchange. */
	NMA_TRUE(&mx0, &mx0, true, &mx0, &mx0, true);
	NMA_TRUE(&mx0, &mx0, true, &mx0, &x0, true);
	NMA_FALSE(&mx0, &mx0, true, &x0, &mx0, true);
	NMA_FALSE(&mx0, &mx0, true, &x0, &x0, true);
	NMA_FALSE(&mx0, &mx0, true, &x1, &x1, true);

	/* Checks file exchange with directory access rights... */
	NMA_TRUE(&mx0, &mx0, false, &mx0, &mx0, false);
	NMA_TRUE(&mx0, &mx0, false, &mx0, &x0, false);
	NMA_TRUE(&mx0, &mx0, false, &x0, &mx0, false);
	NMA_TRUE(&mx0, &mx0, false, &x0, &x0, false);
	/* ...and with file access rights. */
	NMA_TRUE(&rx0, &rx0, false, &rx0, &rx0, false);
	NMA_TRUE(&rx0, &rx0, false, &rx0, &x0, false);
	NMA_FALSE(&rx0, &rx0, false, &x0, &rx0, false);
	NMA_FALSE(&rx0, &rx0, false, &x0, &x0, false);
	NMA_FALSE(&rx0, &rx0, false, &x1, &x1, false);

	/*
	 * Allowing the following requests should not be a security risk
	 * because domain 0 denies execute access, and domain 1 is always
	 * nested with domain 0.  However, adding an exception for this case
	 * would mean to check all nested domains to make sure none can get
	 * more privileges (e.g. processes only sandboxed by domain 0).
	 * Moreover, this behavior (i.e. composition of N domains) could then
	 * be inconsistent compared to domain 1's ruleset alone (e.g. it might
	 * be denied to link/rename with domain 1's ruleset, whereas it would
	 * be allowed if nested on top of domain 0).  Another drawback would be
	 * to create a cover channel that could enable sandboxed processes to
	 * infer most of the filesystem restrictions from their domain.  To
	 * make it simple, efficient, safe, and more consistent, this case is
	 * always denied.
	 */
	NMA_FALSE(&x1, &x1, false, &x0, NULL, false);
	NMA_FALSE(&x1, &x1, false, &rx0, NULL, false);
	NMA_FALSE(&x1, &x1, true, &x0, NULL, false);
	NMA_FALSE(&x1, &x1, true, &rx0, NULL, false);

	/* Checks the same case of exclusive domains with a file... */
	NMA_TRUE(&x1, &x1, false, &x01, NULL, false);
	NMA_FALSE(&x1, &x1, false, &x01, &x0, false);
	NMA_FALSE(&x1, &x1, false, &x01, &x01, false);
	NMA_FALSE(&x1, &x1, false, &x0, &x0, false);
	/* ...and with a directory. */
	NMA_FALSE(&x1, &x1, false, &x0, &x0, true);
	NMA_FALSE(&x1, &x1, true, &x0, &x0, false);
	NMA_FALSE(&x1, &x1, true, &x0, &x0, true);
}

#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */

#undef NMA_TRUE
#undef NMA_FALSE

static bool is_layer_masks_allowed(
	layer_mask_t (*const layer_masks)[LANDLOCK_NUM_ACCESS_FS])
{
	return !memchr_inv(layer_masks, 0, sizeof(*layer_masks));
}

/*
 * Removes @layer_masks accesses that are not requested.
 *
 * Returns true if the request is allowed, false otherwise.
 */
static bool
scope_to_request(const access_mask_t access_request,
		 layer_mask_t (*const layer_masks)[LANDLOCK_NUM_ACCESS_FS])
{
	const unsigned long access_req = access_request;
	unsigned long access_bit;

	if (WARN_ON_ONCE(!layer_masks))
		return true;

	for_each_clear_bit(access_bit, &access_req, ARRAY_SIZE(*layer_masks))
		(*layer_masks)[access_bit] = 0;

	return is_layer_masks_allowed(layer_masks);
}

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST

static void test_scope_to_request_with_exec_none(struct kunit *const test)
{
	/* Allows everything. */
	layer_mask_t layer_masks[LANDLOCK_NUM_ACCESS_FS] = {};

	/* Checks and scopes with execute. */
	KUNIT_EXPECT_TRUE(test, scope_to_request(LANDLOCK_ACCESS_FS_EXECUTE,
						 &layer_masks));
	KUNIT_EXPECT_EQ(test, 0,
			layer_masks[BIT_INDEX(LANDLOCK_ACCESS_FS_EXECUTE)]);
	KUNIT_EXPECT_EQ(test, 0,
			layer_masks[BIT_INDEX(LANDLOCK_ACCESS_FS_WRITE_FILE)]);
}

static void test_scope_to_request_with_exec_some(struct kunit *const test)
{
	/* Denies execute and write. */
	layer_mask_t layer_masks[LANDLOCK_NUM_ACCESS_FS] = {
		[BIT_INDEX(LANDLOCK_ACCESS_FS_EXECUTE)] = BIT_ULL(0),
		[BIT_INDEX(LANDLOCK_ACCESS_FS_WRITE_FILE)] = BIT_ULL(1),
	};

	/* Checks and scopes with execute. */
	KUNIT_EXPECT_FALSE(test, scope_to_request(LANDLOCK_ACCESS_FS_EXECUTE,
						  &layer_masks));
	KUNIT_EXPECT_EQ(test, BIT_ULL(0),
			layer_masks[BIT_INDEX(LANDLOCK_ACCESS_FS_EXECUTE)]);
	KUNIT_EXPECT_EQ(test, 0,
			layer_masks[BIT_INDEX(LANDLOCK_ACCESS_FS_WRITE_FILE)]);
}

static void test_scope_to_request_without_access(struct kunit *const test)
{
	/* Denies execute and write. */
	layer_mask_t layer_masks[LANDLOCK_NUM_ACCESS_FS] = {
		[BIT_INDEX(LANDLOCK_ACCESS_FS_EXECUTE)] = BIT_ULL(0),
		[BIT_INDEX(LANDLOCK_ACCESS_FS_WRITE_FILE)] = BIT_ULL(1),
	};

	/* Checks and scopes without access request. */
	KUNIT_EXPECT_TRUE(test, scope_to_request(0, &layer_masks));
	KUNIT_EXPECT_EQ(test, 0,
			layer_masks[BIT_INDEX(LANDLOCK_ACCESS_FS_EXECUTE)]);
	KUNIT_EXPECT_EQ(test, 0,
			layer_masks[BIT_INDEX(LANDLOCK_ACCESS_FS_WRITE_FILE)]);
}

#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */

/*
 * Returns true if there is at least one access right different than
 * LANDLOCK_ACCESS_FS_REFER.
 */
static bool
is_eacces(const layer_mask_t (*const layer_masks)[LANDLOCK_NUM_ACCESS_FS],
	  const access_mask_t access_request)
{
	unsigned long access_bit;
	/* LANDLOCK_ACCESS_FS_REFER alone must return -EXDEV. */
	const unsigned long access_check = access_request &
					   ~LANDLOCK_ACCESS_FS_REFER;

	if (!layer_masks)
		return false;

	for_each_set_bit(access_bit, &access_check, ARRAY_SIZE(*layer_masks)) {
		if ((*layer_masks)[access_bit])
			return true;
	}
	return false;
}

#define IE_TRUE(...) KUNIT_EXPECT_TRUE(test, is_eacces(__VA_ARGS__))
#define IE_FALSE(...) KUNIT_EXPECT_FALSE(test, is_eacces(__VA_ARGS__))

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST

static void test_is_eacces_with_none(struct kunit *const test)
{
	const layer_mask_t layer_masks[LANDLOCK_NUM_ACCESS_FS] = {};

	IE_FALSE(&layer_masks, 0);
	IE_FALSE(&layer_masks, LANDLOCK_ACCESS_FS_REFER);
	IE_FALSE(&layer_masks, LANDLOCK_ACCESS_FS_EXECUTE);
	IE_FALSE(&layer_masks, LANDLOCK_ACCESS_FS_WRITE_FILE);
}

static void test_is_eacces_with_refer(struct kunit *const test)
{
	const layer_mask_t layer_masks[LANDLOCK_NUM_ACCESS_FS] = {
		[BIT_INDEX(LANDLOCK_ACCESS_FS_REFER)] = BIT_ULL(0),
	};

	IE_FALSE(&layer_masks, 0);
	IE_FALSE(&layer_masks, LANDLOCK_ACCESS_FS_REFER);
	IE_FALSE(&layer_masks, LANDLOCK_ACCESS_FS_EXECUTE);
	IE_FALSE(&layer_masks, LANDLOCK_ACCESS_FS_WRITE_FILE);
}

static void test_is_eacces_with_write(struct kunit *const test)
{
	const layer_mask_t layer_masks[LANDLOCK_NUM_ACCESS_FS] = {
		[BIT_INDEX(LANDLOCK_ACCESS_FS_WRITE_FILE)] = BIT_ULL(0),
	};

	IE_FALSE(&layer_masks, 0);
	IE_FALSE(&layer_masks, LANDLOCK_ACCESS_FS_REFER);
	IE_FALSE(&layer_masks, LANDLOCK_ACCESS_FS_EXECUTE);

	IE_TRUE(&layer_masks, LANDLOCK_ACCESS_FS_WRITE_FILE);
}

#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */

#undef IE_TRUE
#undef IE_FALSE

/**
 * is_access_to_paths_allowed - Check accesses for requests with a common path
 *
 * @domain: Domain to check against.
 * @path: File hierarchy to walk through.
 * @access_request_parent1: Accesses to check, once @layer_masks_parent1 is
 *     equal to @layer_masks_parent2 (if any).  This is tied to the unique
 *     requested path for most actions, or the source in case of a refer action
 *     (i.e. rename or link), or the source and destination in case of
 *     RENAME_EXCHANGE.
 * @layer_masks_parent1: Pointer to a matrix of layer masks per access
 *     masks, identifying the layers that forbid a specific access.  Bits from
 *     this matrix can be unset according to the @path walk.  An empty matrix
 *     means that @domain allows all possible Landlock accesses (i.e. not only
 *     those identified by @access_request_parent1).  This matrix can
 *     initially refer to domain layer masks and, when the accesses for the
 *     destination and source are the same, to requested layer masks.
 * @log_request_parent1: Audit request to fill if the related access is denied.
 * @dentry_child1: Dentry to the initial child of the parent1 path.  This
 *     pointer must be NULL for non-refer actions (i.e. not link nor rename).
 * @access_request_parent2: Similar to @access_request_parent1 but for a
 *     request involving a source and a destination.  This refers to the
 *     destination, except in case of RENAME_EXCHANGE where it also refers to
 *     the source.  Must be set to 0 when using a simple path request.
 * @layer_masks_parent2: Similar to @layer_masks_parent1 but for a refer
 *     action.  This must be NULL otherwise.
 * @log_request_parent2: Audit request to fill if the related access is denied.
 * @dentry_child2: Dentry to the initial child of the parent2 path.  This
 *     pointer is only set for RENAME_EXCHANGE actions and must be NULL
 *     otherwise.
 *
 * This helper first checks that the destination has a superset of restrictions
 * compared to the source (if any) for a common path.  Because of
 * RENAME_EXCHANGE actions, source and destinations may be swapped.  It then
 * checks that the collected accesses and the remaining ones are enough to
 * allow the request.
 *
 * Returns:
 * - true if the access request is granted;
 * - false otherwise.
 */
static bool is_access_to_paths_allowed(
	const struct landlock_ruleset *const domain,
	const struct path *const path,
	const access_mask_t access_request_parent1,
	layer_mask_t (*const layer_masks_parent1)[LANDLOCK_NUM_ACCESS_FS],
	struct landlock_request *const log_request_parent1,
	struct dentry *const dentry_child1,
	const access_mask_t access_request_parent2,
	layer_mask_t (*const layer_masks_parent2)[LANDLOCK_NUM_ACCESS_FS],
	struct landlock_request *const log_request_parent2,
	struct dentry *const dentry_child2)
{
	bool allowed_parent1 = false, allowed_parent2 = false, is_dom_check,
	     child1_is_directory = true, child2_is_directory = true;
	struct path walker_path;
	access_mask_t access_masked_parent1, access_masked_parent2;
	layer_mask_t _layer_masks_child1[LANDLOCK_NUM_ACCESS_FS],
		_layer_masks_child2[LANDLOCK_NUM_ACCESS_FS];
	layer_mask_t(*layer_masks_child1)[LANDLOCK_NUM_ACCESS_FS] = NULL,
	(*layer_masks_child2)[LANDLOCK_NUM_ACCESS_FS] = NULL;

	if (!access_request_parent1 && !access_request_parent2)
		return true;

	if (WARN_ON_ONCE(!path))
		return true;

	if (is_nouser_or_private(path->dentry))
		return true;

	if (WARN_ON_ONCE(!layer_masks_parent1))
		return false;

	allowed_parent1 = is_layer_masks_allowed(layer_masks_parent1);

	if (unlikely(layer_masks_parent2)) {
		if (WARN_ON_ONCE(!dentry_child1))
			return false;

		allowed_parent2 = is_layer_masks_allowed(layer_masks_parent2);

		/*
		 * For a double request, first check for potential privilege
		 * escalation by looking at domain handled accesses (which are
		 * a superset of the meaningful requested accesses).
		 */
		access_masked_parent1 = access_masked_parent2 =
			landlock_union_access_masks(domain).fs;
		is_dom_check = true;
	} else {
		if (WARN_ON_ONCE(dentry_child1 || dentry_child2))
			return false;
		/* For a simple request, only check for requested accesses. */
		access_masked_parent1 = access_request_parent1;
		access_masked_parent2 = access_request_parent2;
		is_dom_check = false;
	}

	if (unlikely(dentry_child1)) {
		landlock_unmask_layers(
			find_rule(domain, dentry_child1),
			landlock_init_layer_masks(
				domain, LANDLOCK_MASK_ACCESS_FS,
				&_layer_masks_child1, LANDLOCK_KEY_INODE),
			&_layer_masks_child1, ARRAY_SIZE(_layer_masks_child1));
		layer_masks_child1 = &_layer_masks_child1;
		child1_is_directory = d_is_dir(dentry_child1);
	}
	if (unlikely(dentry_child2)) {
		landlock_unmask_layers(
			find_rule(domain, dentry_child2),
			landlock_init_layer_masks(
				domain, LANDLOCK_MASK_ACCESS_FS,
				&_layer_masks_child2, LANDLOCK_KEY_INODE),
			&_layer_masks_child2, ARRAY_SIZE(_layer_masks_child2));
		layer_masks_child2 = &_layer_masks_child2;
		child2_is_directory = d_is_dir(dentry_child2);
	}

	walker_path = *path;
	path_get(&walker_path);
	/*
	 * We need to walk through all the hierarchy to not miss any relevant
	 * restriction.
	 */
	while (true) {
		struct dentry *parent_dentry;
		const struct landlock_rule *rule;

		/*
		 * If at least all accesses allowed on the destination are
		 * already allowed on the source, respectively if there is at
		 * least as much as restrictions on the destination than on the
		 * source, then we can safely refer files from the source to
		 * the destination without risking a privilege escalation.
		 * This also applies in the case of RENAME_EXCHANGE, which
		 * implies checks on both direction.  This is crucial for
		 * standalone multilayered security policies.  Furthermore,
		 * this helps avoid policy writers to shoot themselves in the
		 * foot.
		 */
		if (unlikely(is_dom_check &&
			     no_more_access(
				     layer_masks_parent1, layer_masks_child1,
				     child1_is_directory, layer_masks_parent2,
				     layer_masks_child2,
				     child2_is_directory))) {
			/*
			 * Now, downgrades the remaining checks from domain
			 * handled accesses to requested accesses.
			 */
			is_dom_check = false;
			access_masked_parent1 = access_request_parent1;
			access_masked_parent2 = access_request_parent2;

			allowed_parent1 =
				allowed_parent1 ||
				scope_to_request(access_masked_parent1,
						 layer_masks_parent1);
			allowed_parent2 =
				allowed_parent2 ||
				scope_to_request(access_masked_parent2,
						 layer_masks_parent2);

			/* Stops when all accesses are granted. */
			if (allowed_parent1 && allowed_parent2)
				break;
		}

		rule = find_rule(domain, walker_path.dentry);
		allowed_parent1 = allowed_parent1 ||
				  landlock_unmask_layers(
					  rule, access_masked_parent1,
					  layer_masks_parent1,
					  ARRAY_SIZE(*layer_masks_parent1));
		allowed_parent2 = allowed_parent2 ||
				  landlock_unmask_layers(
					  rule, access_masked_parent2,
					  layer_masks_parent2,
					  ARRAY_SIZE(*layer_masks_parent2));

		/* Stops when a rule from each layer grants access. */
		if (allowed_parent1 && allowed_parent2)
			break;

jump_up:
		if (walker_path.dentry == walker_path.mnt->mnt_root) {
			if (follow_up(&walker_path)) {
				/* Ignores hidden mount points. */
				goto jump_up;
			} else {
				/*
				 * Stops at the real root.  Denies access
				 * because not all layers have granted access.
				 */
				break;
			}
		}
		if (unlikely(IS_ROOT(walker_path.dentry))) {
			/*
			 * Stops at disconnected root directories.  Only allows
			 * access to internal filesystems (e.g. nsfs, which is
			 * reachable through /proc/<pid>/ns/<namespace>).
			 */
			if (walker_path.mnt->mnt_flags & MNT_INTERNAL) {
				allowed_parent1 = true;
				allowed_parent2 = true;
			}
			break;
		}
		parent_dentry = dget_parent(walker_path.dentry);
		dput(walker_path.dentry);
		walker_path.dentry = parent_dentry;
	}
	path_put(&walker_path);

	if (!allowed_parent1) {
		log_request_parent1->type = LANDLOCK_REQUEST_FS_ACCESS;
		log_request_parent1->audit.type = LSM_AUDIT_DATA_PATH;
		log_request_parent1->audit.u.path = *path;
		log_request_parent1->access = access_masked_parent1;
		log_request_parent1->layer_masks = layer_masks_parent1;
		log_request_parent1->layer_masks_size =
			ARRAY_SIZE(*layer_masks_parent1);
	}

	if (!allowed_parent2) {
		log_request_parent2->type = LANDLOCK_REQUEST_FS_ACCESS;
		log_request_parent2->audit.type = LSM_AUDIT_DATA_PATH;
		log_request_parent2->audit.u.path = *path;
		log_request_parent2->access = access_masked_parent2;
		log_request_parent2->layer_masks = layer_masks_parent2;
		log_request_parent2->layer_masks_size =
			ARRAY_SIZE(*layer_masks_parent2);
	}
	return allowed_parent1 && allowed_parent2;
}

static int current_check_access_path(const struct path *const path,
				     access_mask_t access_request)
{
	const struct access_masks masks = {
		.fs = access_request,
	};
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), masks, NULL);
	layer_mask_t layer_masks[LANDLOCK_NUM_ACCESS_FS] = {};
	struct landlock_request request = {};

	if (!subject)
		return 0;

	access_request = landlock_init_layer_masks(subject->domain,
						   access_request, &layer_masks,
						   LANDLOCK_KEY_INODE);
	if (is_access_to_paths_allowed(subject->domain, path, access_request,
				       &layer_masks, &request, NULL, 0, NULL,
				       NULL, NULL))
		return 0;

	landlock_log_denial(subject, &request);
	return -EACCES;
}

static __attribute_const__ access_mask_t get_mode_access(const umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFLNK:
		return LANDLOCK_ACCESS_FS_MAKE_SYM;
	case S_IFDIR:
		return LANDLOCK_ACCESS_FS_MAKE_DIR;
	case S_IFCHR:
		return LANDLOCK_ACCESS_FS_MAKE_CHAR;
	case S_IFBLK:
		return LANDLOCK_ACCESS_FS_MAKE_BLOCK;
	case S_IFIFO:
		return LANDLOCK_ACCESS_FS_MAKE_FIFO;
	case S_IFSOCK:
		return LANDLOCK_ACCESS_FS_MAKE_SOCK;
	case S_IFREG:
	case 0:
		/* A zero mode translates to S_IFREG. */
	default:
		/* Treats weird files as regular files. */
		return LANDLOCK_ACCESS_FS_MAKE_REG;
	}
}

static access_mask_t maybe_remove(const struct dentry *const dentry)
{
	if (d_is_negative(dentry))
		return 0;
	return d_is_dir(dentry) ? LANDLOCK_ACCESS_FS_REMOVE_DIR :
				  LANDLOCK_ACCESS_FS_REMOVE_FILE;
}

/**
 * collect_domain_accesses - Walk through a file path and collect accesses
 *
 * @domain: Domain to check against.
 * @mnt_root: Last directory to check.
 * @dir: Directory to start the walk from.
 * @layer_masks_dom: Where to store the collected accesses.
 *
 * This helper is useful to begin a path walk from the @dir directory to a
 * @mnt_root directory used as a mount point.  This mount point is the common
 * ancestor between the source and the destination of a renamed and linked
 * file.  While walking from @dir to @mnt_root, we record all the domain's
 * allowed accesses in @layer_masks_dom.
 *
 * This is similar to is_access_to_paths_allowed() but much simpler because it
 * only handles walking on the same mount point and only checks one set of
 * accesses.
 *
 * Returns:
 * - true if all the domain access rights are allowed for @dir;
 * - false if the walk reached @mnt_root.
 */
static bool collect_domain_accesses(
	const struct landlock_ruleset *const domain,
	const struct dentry *const mnt_root, struct dentry *dir,
	layer_mask_t (*const layer_masks_dom)[LANDLOCK_NUM_ACCESS_FS])
{
	unsigned long access_dom;
	bool ret = false;

	if (WARN_ON_ONCE(!domain || !mnt_root || !dir || !layer_masks_dom))
		return true;
	if (is_nouser_or_private(dir))
		return true;

	access_dom = landlock_init_layer_masks(domain, LANDLOCK_MASK_ACCESS_FS,
					       layer_masks_dom,
					       LANDLOCK_KEY_INODE);

	dget(dir);
	while (true) {
		struct dentry *parent_dentry;

		/* Gets all layers allowing all domain accesses. */
		if (landlock_unmask_layers(find_rule(domain, dir), access_dom,
					   layer_masks_dom,
					   ARRAY_SIZE(*layer_masks_dom))) {
			/*
			 * Stops when all handled accesses are allowed by at
			 * least one rule in each layer.
			 */
			ret = true;
			break;
		}

		/* We should not reach a root other than @mnt_root. */
		if (dir == mnt_root || WARN_ON_ONCE(IS_ROOT(dir)))
			break;

		parent_dentry = dget_parent(dir);
		dput(dir);
		dir = parent_dentry;
	}
	dput(dir);
	return ret;
}

/**
 * current_check_refer_path - Check if a rename or link action is allowed
 *
 * @old_dentry: File or directory requested to be moved or linked.
 * @new_dir: Destination parent directory.
 * @new_dentry: Destination file or directory.
 * @removable: Sets to true if it is a rename operation.
 * @exchange: Sets to true if it is a rename operation with RENAME_EXCHANGE.
 *
 * Because of its unprivileged constraints, Landlock relies on file hierarchies
 * (and not only inodes) to tie access rights to files.  Being able to link or
 * rename a file hierarchy brings some challenges.  Indeed, moving or linking a
 * file (i.e. creating a new reference to an inode) can have an impact on the
 * actions allowed for a set of files if it would change its parent directory
 * (i.e. reparenting).
 *
 * To avoid trivial access right bypasses, Landlock first checks if the file or
 * directory requested to be moved would gain new access rights inherited from
 * its new hierarchy.  Before returning any error, Landlock then checks that
 * the parent source hierarchy and the destination hierarchy would allow the
 * link or rename action.  If it is not the case, an error with EACCES is
 * returned to inform user space that there is no way to remove or create the
 * requested source file type.  If it should be allowed but the new inherited
 * access rights would be greater than the source access rights, then the
 * kernel returns an error with EXDEV.  Prioritizing EACCES over EXDEV enables
 * user space to abort the whole operation if there is no way to do it, or to
 * manually copy the source to the destination if this remains allowed, e.g.
 * because file creation is allowed on the destination directory but not direct
 * linking.
 *
 * To achieve this goal, the kernel needs to compare two file hierarchies: the
 * one identifying the source file or directory (including itself), and the
 * destination one.  This can be seen as a multilayer partial ordering problem.
 * The kernel walks through these paths and collects in a matrix the access
 * rights that are denied per layer.  These matrices are then compared to see
 * if the destination one has more (or the same) restrictions as the source
 * one.  If this is the case, the requested action will not return EXDEV, which
 * doesn't mean the action is allowed.  The parent hierarchy of the source
 * (i.e. parent directory), and the destination hierarchy must also be checked
 * to verify that they explicitly allow such action (i.e.  referencing,
 * creation and potentially removal rights).  The kernel implementation is then
 * required to rely on potentially four matrices of access rights: one for the
 * source file or directory (i.e. the child), a potentially other one for the
 * other source/destination (in case of RENAME_EXCHANGE), one for the source
 * parent hierarchy and a last one for the destination hierarchy.  These
 * ephemeral matrices take some space on the stack, which limits the number of
 * layers to a deemed reasonable number: 16.
 *
 * Returns:
 * - 0 if access is allowed;
 * - -EXDEV if @old_dentry would inherit new access rights from @new_dir;
 * - -EACCES if file removal or creation is denied.
 */
static int current_check_refer_path(struct dentry *const old_dentry,
				    const struct path *const new_dir,
				    struct dentry *const new_dentry,
				    const bool removable, const bool exchange)
{
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), any_fs, NULL);
	bool allow_parent1, allow_parent2;
	access_mask_t access_request_parent1, access_request_parent2;
	struct path mnt_dir;
	struct dentry *old_parent;
	layer_mask_t layer_masks_parent1[LANDLOCK_NUM_ACCESS_FS] = {},
		     layer_masks_parent2[LANDLOCK_NUM_ACCESS_FS] = {};
	struct landlock_request request1 = {}, request2 = {};

	if (!subject)
		return 0;

	if (unlikely(d_is_negative(old_dentry)))
		return -ENOENT;
	if (exchange) {
		if (unlikely(d_is_negative(new_dentry)))
			return -ENOENT;
		access_request_parent1 =
			get_mode_access(d_backing_inode(new_dentry)->i_mode);
	} else {
		access_request_parent1 = 0;
	}
	access_request_parent2 =
		get_mode_access(d_backing_inode(old_dentry)->i_mode);
	if (removable) {
		access_request_parent1 |= maybe_remove(old_dentry);
		access_request_parent2 |= maybe_remove(new_dentry);
	}

	/* The mount points are the same for old and new paths, cf. EXDEV. */
	if (old_dentry->d_parent == new_dir->dentry) {
		/*
		 * The LANDLOCK_ACCESS_FS_REFER access right is not required
		 * for same-directory referer (i.e. no reparenting).
		 */
		access_request_parent1 = landlock_init_layer_masks(
			subject->domain,
			access_request_parent1 | access_request_parent2,
			&layer_masks_parent1, LANDLOCK_KEY_INODE);
		if (is_access_to_paths_allowed(subject->domain, new_dir,
					       access_request_parent1,
					       &layer_masks_parent1, &request1,
					       NULL, 0, NULL, NULL, NULL))
			return 0;

		landlock_log_denial(subject, &request1);
		return -EACCES;
	}

	access_request_parent1 |= LANDLOCK_ACCESS_FS_REFER;
	access_request_parent2 |= LANDLOCK_ACCESS_FS_REFER;

	/* Saves the common mount point. */
	mnt_dir.mnt = new_dir->mnt;
	mnt_dir.dentry = new_dir->mnt->mnt_root;

	/*
	 * old_dentry may be the root of the common mount point and
	 * !IS_ROOT(old_dentry) at the same time (e.g. with open_tree() and
	 * OPEN_TREE_CLONE).  We do not need to call dget(old_parent) because
	 * we keep a reference to old_dentry.
	 */
	old_parent = (old_dentry == mnt_dir.dentry) ? old_dentry :
						      old_dentry->d_parent;

	/* new_dir->dentry is equal to new_dentry->d_parent */
	allow_parent1 = collect_domain_accesses(subject->domain, mnt_dir.dentry,
						old_parent,
						&layer_masks_parent1);
	allow_parent2 = collect_domain_accesses(subject->domain, mnt_dir.dentry,
						new_dir->dentry,
						&layer_masks_parent2);

	if (allow_parent1 && allow_parent2)
		return 0;

	/*
	 * To be able to compare source and destination domain access rights,
	 * take into account the @old_dentry access rights aggregated with its
	 * parent access rights.  This will be useful to compare with the
	 * destination parent access rights.
	 */
	if (is_access_to_paths_allowed(
		    subject->domain, &mnt_dir, access_request_parent1,
		    &layer_masks_parent1, &request1, old_dentry,
		    access_request_parent2, &layer_masks_parent2, &request2,
		    exchange ? new_dentry : NULL))
		return 0;

	if (request1.access) {
		request1.audit.u.path.dentry = old_parent;
		landlock_log_denial(subject, &request1);
	}
	if (request2.access) {
		request2.audit.u.path.dentry = new_dir->dentry;
		landlock_log_denial(subject, &request2);
	}

	/*
	 * This prioritizes EACCES over EXDEV for all actions, including
	 * renames with RENAME_EXCHANGE.
	 */
	if (likely(is_eacces(&layer_masks_parent1, access_request_parent1) ||
		   is_eacces(&layer_masks_parent2, access_request_parent2)))
		return -EACCES;

	/*
	 * Gracefully forbids reparenting if the destination directory
	 * hierarchy is not a superset of restrictions of the source directory
	 * hierarchy, or if LANDLOCK_ACCESS_FS_REFER is not allowed by the
	 * source or the destination.
	 */
	return -EXDEV;
}

/* Inode hooks */

static void hook_inode_free_security_rcu(void *inode_security)
{
	struct landlock_inode_security *inode_sec;

	/*
	 * All inodes must already have been untied from their object by
	 * release_inode() or hook_sb_delete().
	 */
	inode_sec = inode_security + landlock_blob_sizes.lbs_inode;
	WARN_ON_ONCE(inode_sec->object);
}

/* Super-block hooks */

/*
 * Release the inodes used in a security policy.
 *
 * Cf. fsnotify_unmount_inodes() and evict_inodes()
 */
static void hook_sb_delete(struct super_block *const sb)
{
	struct genradix_iter iter;
	void **i;

	if (!landlock_initialized)
		return;

	rcu_read_lock();
	genradix_for_each(&sb->s_inodes.items, iter, i) {
		struct inode *inode = *((struct inode **) i);
		if (!inode)
			continue;

		struct landlock_object *object;

		/* Only handles referenced inodes. */
		if (!atomic_read(&inode->i_count))
			continue;

		/*
		 * Protects against concurrent modification of inode (e.g.
		 * from get_inode_object()).
		 */
		spin_lock(&inode->i_lock);
		/*
		 * Checks I_FREEING and I_WILL_FREE  to protect against a race
		 * condition when release_inode() just called iput(), which
		 * could lead to a NULL dereference of inode->security or a
		 * second call to iput() for the same Landlock object.  Also
		 * checks I_NEW because such inode cannot be tied to an object.
		 */
		if (inode->i_state & (I_FREEING | I_WILL_FREE | I_NEW)) {
			spin_unlock(&inode->i_lock);
			continue;
		}

		object = rcu_dereference(landlock_inode(inode)->object);
		if (!object) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		/* Keeps a reference to this inode until the next loop walk. */
		__iget(inode);
		spin_unlock(&inode->i_lock);

		/*
		 * If there is no concurrent release_inode() ongoing, then we
		 * are in charge of calling iput() on this inode, otherwise we
		 * will just wait for it to finish.
		 */
		spin_lock(&object->lock);
		if (object->underobj == inode) {
			object->underobj = NULL;
			spin_unlock(&object->lock);

			/*
			 * Because object->underobj was not NULL,
			 * release_inode() and get_inode_object() guarantee
			 * that it is safe to reset
			 * landlock_inode(inode)->object while it is not NULL.
			 * It is therefore not necessary to lock inode->i_lock.
			 */
			rcu_assign_pointer(landlock_inode(inode)->object, NULL);
			/*
			 * At this point, we own the ihold() reference that was
			 * originally set up by get_inode_object() and the
			 * __iget() reference that we just set in this loop
			 * walk.  Therefore the following call to iput() will
			 * not sleep nor drop the inode because there is now at
			 * least two references to it.
			 */
			iput(inode);
		} else {
			spin_unlock(&object->lock);
		}

		rcu_read_unlock();
		iput(inode);
		cond_resched();
		rcu_read_lock();
	}
	rcu_read_unlock();

	/* Waits for pending iput() in release_inode(). */
	wait_var_event(&landlock_superblock(sb)->inode_refs,
		       !atomic_long_read(&landlock_superblock(sb)->inode_refs));
}

static void
log_fs_change_topology_path(const struct landlock_cred_security *const subject,
			    size_t handle_layer, const struct path *const path)
{
	landlock_log_denial(subject, &(struct landlock_request) {
		.type = LANDLOCK_REQUEST_FS_CHANGE_TOPOLOGY,
		.audit = {
			.type = LSM_AUDIT_DATA_PATH,
			.u.path = *path,
		},
		.layer_plus_one = handle_layer + 1,
	});
}

static void log_fs_change_topology_dentry(
	const struct landlock_cred_security *const subject, size_t handle_layer,
	struct dentry *const dentry)
{
	landlock_log_denial(subject, &(struct landlock_request) {
		.type = LANDLOCK_REQUEST_FS_CHANGE_TOPOLOGY,
		.audit = {
			.type = LSM_AUDIT_DATA_DENTRY,
			.u.dentry = dentry,
		},
		.layer_plus_one = handle_layer + 1,
	});
}

/*
 * Because a Landlock security policy is defined according to the filesystem
 * topology (i.e. the mount namespace), changing it may grant access to files
 * not previously allowed.
 *
 * To make it simple, deny any filesystem topology modification by landlocked
 * processes.  Non-landlocked processes may still change the namespace of a
 * landlocked process, but this kind of threat must be handled by a system-wide
 * access-control security policy.
 *
 * This could be lifted in the future if Landlock can safely handle mount
 * namespace updates requested by a landlocked process.  Indeed, we could
 * update the current domain (which is currently read-only) by taking into
 * account the accesses of the source and the destination of a new mount point.
 * However, it would also require to make all the child domains dynamically
 * inherit these new constraints.  Anyway, for backward compatibility reasons,
 * a dedicated user space option would be required (e.g. as a ruleset flag).
 */
static int hook_sb_mount(const char *const dev_name,
			 const struct path *const path, const char *const type,
			 const unsigned long flags, void *const data)
{
	size_t handle_layer;
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), any_fs,
						&handle_layer);

	if (!subject)
		return 0;

	log_fs_change_topology_path(subject, handle_layer, path);
	return -EPERM;
}

static int hook_move_mount(const struct path *const from_path,
			   const struct path *const to_path)
{
	size_t handle_layer;
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), any_fs,
						&handle_layer);

	if (!subject)
		return 0;

	log_fs_change_topology_path(subject, handle_layer, to_path);
	return -EPERM;
}

/*
 * Removing a mount point may reveal a previously hidden file hierarchy, which
 * may then grant access to files, which may have previously been forbidden.
 */
static int hook_sb_umount(struct vfsmount *const mnt, const int flags)
{
	size_t handle_layer;
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), any_fs,
						&handle_layer);

	if (!subject)
		return 0;

	log_fs_change_topology_dentry(subject, handle_layer, mnt->mnt_root);
	return -EPERM;
}

static int hook_sb_remount(struct super_block *const sb, void *const mnt_opts)
{
	size_t handle_layer;
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), any_fs,
						&handle_layer);

	if (!subject)
		return 0;

	log_fs_change_topology_dentry(subject, handle_layer, sb->s_root);
	return -EPERM;
}

/*
 * pivot_root(2), like mount(2), changes the current mount namespace.  It must
 * then be forbidden for a landlocked process.
 *
 * However, chroot(2) may be allowed because it only changes the relative root
 * directory of the current process.  Moreover, it can be used to restrict the
 * view of the filesystem.
 */
static int hook_sb_pivotroot(const struct path *const old_path,
			     const struct path *const new_path)
{
	size_t handle_layer;
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), any_fs,
						&handle_layer);

	if (!subject)
		return 0;

	log_fs_change_topology_path(subject, handle_layer, new_path);
	return -EPERM;
}

/* Path hooks */

static int hook_path_link(struct dentry *const old_dentry,
			  const struct path *const new_dir,
			  struct dentry *const new_dentry)
{
	return current_check_refer_path(old_dentry, new_dir, new_dentry, false,
					false);
}

static int hook_path_rename(const struct path *const old_dir,
			    struct dentry *const old_dentry,
			    const struct path *const new_dir,
			    struct dentry *const new_dentry,
			    const unsigned int flags)
{
	/* old_dir refers to old_dentry->d_parent and new_dir->mnt */
	return current_check_refer_path(old_dentry, new_dir, new_dentry, true,
					!!(flags & RENAME_EXCHANGE));
}

static int hook_path_mkdir(const struct path *const dir,
			   struct dentry *const dentry, const umode_t mode)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_MAKE_DIR);
}

static int hook_path_mknod(const struct path *const dir,
			   struct dentry *const dentry, const umode_t mode,
			   const unsigned int dev)
{
	return current_check_access_path(dir, get_mode_access(mode));
}

static int hook_path_symlink(const struct path *const dir,
			     struct dentry *const dentry,
			     const char *const old_name)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_MAKE_SYM);
}

static int hook_path_unlink(const struct path *const dir,
			    struct dentry *const dentry)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_REMOVE_FILE);
}

static int hook_path_rmdir(const struct path *const dir,
			   struct dentry *const dentry)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_REMOVE_DIR);
}

static int hook_path_truncate(const struct path *const path)
{
	return current_check_access_path(path, LANDLOCK_ACCESS_FS_TRUNCATE);
}

/* File hooks */

/**
 * get_required_file_open_access - Get access needed to open a file
 *
 * @file: File being opened.
 *
 * Returns the access rights that are required for opening the given file,
 * depending on the file type and open mode.
 */
static access_mask_t
get_required_file_open_access(const struct file *const file)
{
	access_mask_t access = 0;

	if (file->f_mode & FMODE_READ) {
		/* A directory can only be opened in read mode. */
		if (S_ISDIR(file_inode(file)->i_mode))
			return LANDLOCK_ACCESS_FS_READ_DIR;
		access = LANDLOCK_ACCESS_FS_READ_FILE;
	}
	if (file->f_mode & FMODE_WRITE)
		access |= LANDLOCK_ACCESS_FS_WRITE_FILE;
	/* __FMODE_EXEC is indeed part of f_flags, not f_mode. */
	if (file->f_flags & __FMODE_EXEC)
		access |= LANDLOCK_ACCESS_FS_EXECUTE;
	return access;
}

static int hook_file_alloc_security(struct file *const file)
{
	/*
	 * Grants all access rights, even if most of them are not checked later
	 * on. It is more consistent.
	 *
	 * Notably, file descriptors for regular files can also be acquired
	 * without going through the file_open hook, for example when using
	 * memfd_create(2).
	 */
	landlock_file(file)->allowed_access = LANDLOCK_MASK_ACCESS_FS;
	return 0;
}

static bool is_device(const struct file *const file)
{
	const struct inode *inode = file_inode(file);

	return S_ISBLK(inode->i_mode) || S_ISCHR(inode->i_mode);
}

static int hook_file_open(struct file *const file)
{
	layer_mask_t layer_masks[LANDLOCK_NUM_ACCESS_FS] = {};
	access_mask_t open_access_request, full_access_request, allowed_access,
		optional_access;
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(file->f_cred, any_fs, NULL);
	struct landlock_request request = {};

	if (!subject)
		return 0;

	/*
	 * Because a file may be opened with O_PATH, get_required_file_open_access()
	 * may return 0.  This case will be handled with a future Landlock
	 * evolution.
	 */
	open_access_request = get_required_file_open_access(file);

	/*
	 * We look up more access than what we immediately need for open(), so
	 * that we can later authorize operations on opened files.
	 */
	optional_access = LANDLOCK_ACCESS_FS_TRUNCATE;
	if (is_device(file))
		optional_access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;

	full_access_request = open_access_request | optional_access;

	if (is_access_to_paths_allowed(
		    subject->domain, &file->f_path,
		    landlock_init_layer_masks(subject->domain,
					      full_access_request, &layer_masks,
					      LANDLOCK_KEY_INODE),
		    &layer_masks, &request, NULL, 0, NULL, NULL, NULL)) {
		allowed_access = full_access_request;
	} else {
		unsigned long access_bit;
		const unsigned long access_req = full_access_request;

		/*
		 * Calculate the actual allowed access rights from layer_masks.
		 * Add each access right to allowed_access which has not been
		 * vetoed by any layer.
		 */
		allowed_access = 0;
		for_each_set_bit(access_bit, &access_req,
				 ARRAY_SIZE(layer_masks)) {
			if (!layer_masks[access_bit])
				allowed_access |= BIT_ULL(access_bit);
		}
	}

	/*
	 * For operations on already opened files (i.e. ftruncate()), it is the
	 * access rights at the time of open() which decide whether the
	 * operation is permitted. Therefore, we record the relevant subset of
	 * file access rights in the opened struct file.
	 */
	landlock_file(file)->allowed_access = allowed_access;
#ifdef CONFIG_AUDIT
	landlock_file(file)->deny_masks = landlock_get_deny_masks(
		_LANDLOCK_ACCESS_FS_OPTIONAL, optional_access, &layer_masks,
		ARRAY_SIZE(layer_masks));
#endif /* CONFIG_AUDIT */

	if ((open_access_request & allowed_access) == open_access_request)
		return 0;

	/* Sets access to reflect the actual request. */
	request.access = open_access_request;
	landlock_log_denial(subject, &request);
	return -EACCES;
}

static int hook_file_truncate(struct file *const file)
{
	/*
	 * Allows truncation if the truncate right was available at the time of
	 * opening the file, to get a consistent access check as for read, write
	 * and execute operations.
	 *
	 * Note: For checks done based on the file's Landlock allowed access, we
	 * enforce them independently of whether the current thread is in a
	 * Landlock domain, so that open files passed between independent
	 * processes retain their behaviour.
	 */
	if (landlock_file(file)->allowed_access & LANDLOCK_ACCESS_FS_TRUNCATE)
		return 0;

	landlock_log_denial(landlock_cred(file->f_cred), &(struct landlock_request) {
		.type = LANDLOCK_REQUEST_FS_ACCESS,
		.audit = {
			.type = LSM_AUDIT_DATA_FILE,
			.u.file = file,
		},
		.all_existing_optional_access = _LANDLOCK_ACCESS_FS_OPTIONAL,
		.access = LANDLOCK_ACCESS_FS_TRUNCATE,
#ifdef CONFIG_AUDIT
		.deny_masks = landlock_file(file)->deny_masks,
#endif /* CONFIG_AUDIT */
	});
	return -EACCES;
}

static int hook_file_ioctl_common(const struct file *const file,
				  const unsigned int cmd, const bool is_compat)
{
	access_mask_t allowed_access = landlock_file(file)->allowed_access;

	/*
	 * It is the access rights at the time of opening the file which
	 * determine whether IOCTL can be used on the opened file later.
	 *
	 * The access right is attached to the opened file in hook_file_open().
	 */
	if (allowed_access & LANDLOCK_ACCESS_FS_IOCTL_DEV)
		return 0;

	if (!is_device(file))
		return 0;

	if (unlikely(is_compat) ? is_masked_device_ioctl_compat(cmd) :
				  is_masked_device_ioctl(cmd))
		return 0;

	landlock_log_denial(landlock_cred(file->f_cred), &(struct landlock_request) {
		.type = LANDLOCK_REQUEST_FS_ACCESS,
		.audit = {
			.type = LSM_AUDIT_DATA_IOCTL_OP,
			.u.op = &(struct lsm_ioctlop_audit) {
				.path = file->f_path,
				.cmd = cmd,
			},
		},
		.all_existing_optional_access = _LANDLOCK_ACCESS_FS_OPTIONAL,
		.access = LANDLOCK_ACCESS_FS_IOCTL_DEV,
#ifdef CONFIG_AUDIT
		.deny_masks = landlock_file(file)->deny_masks,
#endif /* CONFIG_AUDIT */
	});
	return -EACCES;
}

static int hook_file_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	return hook_file_ioctl_common(file, cmd, false);
}

static int hook_file_ioctl_compat(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	return hook_file_ioctl_common(file, cmd, true);
}

/*
 * Always allow sending signals between threads of the same process.  This
 * ensures consistency with hook_task_kill().
 */
static bool control_current_fowner(struct fown_struct *const fown)
{
	struct task_struct *p;

	/*
	 * Lock already held by __f_setown(), see commit 26f204380a3c ("fs: Fix
	 * file_set_fowner LSM hook inconsistencies").
	 */
	lockdep_assert_held(&fown->lock);

	/*
	 * Some callers (e.g. fcntl_dirnotify) may not be in an RCU read-side
	 * critical section.
	 */
	guard(rcu)();
	p = pid_task(fown->pid, fown->pid_type);
	if (!p)
		return true;

	return !same_thread_group(p, current);
}

static void hook_file_set_fowner(struct file *file)
{
	struct landlock_ruleset *prev_dom;
	struct landlock_cred_security fown_subject = {};
	size_t fown_layer = 0;

	if (control_current_fowner(file_f_owner(file))) {
		static const struct access_masks signal_scope = {
			.scope = LANDLOCK_SCOPE_SIGNAL,
		};
		const struct landlock_cred_security *new_subject =
			landlock_get_applicable_subject(
				current_cred(), signal_scope, &fown_layer);
		if (new_subject) {
			landlock_get_ruleset(new_subject->domain);
			fown_subject = *new_subject;
		}
	}

	prev_dom = landlock_file(file)->fown_subject.domain;
	landlock_file(file)->fown_subject = fown_subject;
#ifdef CONFIG_AUDIT
	landlock_file(file)->fown_layer = fown_layer;
#endif /* CONFIG_AUDIT*/

	/* May be called in an RCU read-side critical section. */
	landlock_put_ruleset_deferred(prev_dom);
}

static void hook_file_free_security(struct file *file)
{
	landlock_put_ruleset_deferred(landlock_file(file)->fown_subject.domain);
}

static struct security_hook_list landlock_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_free_security_rcu, hook_inode_free_security_rcu),

	LSM_HOOK_INIT(sb_delete, hook_sb_delete),
	LSM_HOOK_INIT(sb_mount, hook_sb_mount),
	LSM_HOOK_INIT(move_mount, hook_move_mount),
	LSM_HOOK_INIT(sb_umount, hook_sb_umount),
	LSM_HOOK_INIT(sb_remount, hook_sb_remount),
	LSM_HOOK_INIT(sb_pivotroot, hook_sb_pivotroot),

	LSM_HOOK_INIT(path_link, hook_path_link),
	LSM_HOOK_INIT(path_rename, hook_path_rename),
	LSM_HOOK_INIT(path_mkdir, hook_path_mkdir),
	LSM_HOOK_INIT(path_mknod, hook_path_mknod),
	LSM_HOOK_INIT(path_symlink, hook_path_symlink),
	LSM_HOOK_INIT(path_unlink, hook_path_unlink),
	LSM_HOOK_INIT(path_rmdir, hook_path_rmdir),
	LSM_HOOK_INIT(path_truncate, hook_path_truncate),

	LSM_HOOK_INIT(file_alloc_security, hook_file_alloc_security),
	LSM_HOOK_INIT(file_open, hook_file_open),
	LSM_HOOK_INIT(file_truncate, hook_file_truncate),
	LSM_HOOK_INIT(file_ioctl, hook_file_ioctl),
	LSM_HOOK_INIT(file_ioctl_compat, hook_file_ioctl_compat),
	LSM_HOOK_INIT(file_set_fowner, hook_file_set_fowner),
	LSM_HOOK_INIT(file_free_security, hook_file_free_security),
};

__init void landlock_add_fs_hooks(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			   &landlock_lsmid);
}

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST

/* clang-format off */
static struct kunit_case test_cases[] = {
	KUNIT_CASE(test_no_more_access),
	KUNIT_CASE(test_scope_to_request_with_exec_none),
	KUNIT_CASE(test_scope_to_request_with_exec_some),
	KUNIT_CASE(test_scope_to_request_without_access),
	KUNIT_CASE(test_is_eacces_with_none),
	KUNIT_CASE(test_is_eacces_with_refer),
	KUNIT_CASE(test_is_eacces_with_write),
	{}
};
/* clang-format on */

static struct kunit_suite test_suite = {
	.name = "landlock_fs",
	.test_cases = test_cases,
};

kunit_test_suite(test_suite);

#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */
