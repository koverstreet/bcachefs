/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_IOCTL_H
#define _BCACHEFS_IOCTL_H

#include <linux/uuid.h>
#include <asm/ioctl.h>
#include "bcachefs_format.h"

/*
 * Flags common to multiple ioctls:
 */
#define BCH_FORCE_IF_DATA_LOST		(1 << 0)
#define BCH_FORCE_IF_METADATA_LOST	(1 << 1)
#define BCH_FORCE_IF_DATA_DEGRADED	(1 << 2)
#define BCH_FORCE_IF_METADATA_DEGRADED	(1 << 3)

#define BCH_FORCE_IF_LOST			\
	(BCH_FORCE_IF_DATA_LOST|		\
	 BCH_FORCE_IF_METADATA_LOST)
#define BCH_FORCE_IF_DEGRADED			\
	(BCH_FORCE_IF_DATA_DEGRADED|		\
	 BCH_FORCE_IF_METADATA_DEGRADED)

/*
 * If cleared, ioctl that refer to a device pass it as a pointer to a pathname
 * (e.g. /dev/sda1); if set, the dev field is the device's index within the
 * filesystem:
 */
#define BCH_BY_INDEX			(1 << 4)

/*
 * For BCH_IOCTL_READ_SUPER: get superblock of a specific device, not filesystem
 * wide superblock:
 */
#define BCH_READ_DEV			(1 << 5)

/* global control dev: */

/* These are currently broken, and probably unnecessary: */
#if 0
#define BCH_IOCTL_ASSEMBLE	_IOW(0xbc, 1, struct bch_ioctl_assemble)
#define BCH_IOCTL_INCREMENTAL	_IOW(0xbc, 2, struct bch_ioctl_incremental)

struct bch_ioctl_assemble {
	__u32			flags;
	__u32			nr_devs;
	__u64			pad;
	__u64			devs[];
};

struct bch_ioctl_incremental {
	__u32			flags;
	__u64			pad;
	__u64			dev;
};
#endif

/* filesystem ioctls: */

#define BCH_IOCTL_QUERY_UUID	_IOR(0xbc,	1,  struct bch_ioctl_query_uuid)

/* These only make sense when we also have incremental assembly */
#if 0
#define BCH_IOCTL_START		_IOW(0xbc,	2,  struct bch_ioctl_start)
#define BCH_IOCTL_STOP		_IO(0xbc,	3)
#endif

#define BCH_IOCTL_DISK_ADD	_IOW(0xbc,	4,  struct bch_ioctl_disk)
#define BCH_IOCTL_DISK_REMOVE	_IOW(0xbc,	5,  struct bch_ioctl_disk)
#define BCH_IOCTL_DISK_ONLINE	_IOW(0xbc,	6,  struct bch_ioctl_disk)
#define BCH_IOCTL_DISK_OFFLINE	_IOW(0xbc,	7,  struct bch_ioctl_disk)
#define BCH_IOCTL_DISK_SET_STATE _IOW(0xbc,	8,  struct bch_ioctl_disk_set_state)
#define BCH_IOCTL_DATA		_IOW(0xbc,	10, struct bch_ioctl_data)
#define BCH_IOCTL_FS_USAGE	_IOWR(0xbc,	11, struct bch_ioctl_fs_usage)
#define BCH_IOCTL_DEV_USAGE	_IOWR(0xbc,	11, struct bch_ioctl_dev_usage)
#define BCH_IOCTL_READ_SUPER	_IOW(0xbc,	12, struct bch_ioctl_read_super)
#define BCH_IOCTL_DISK_GET_IDX	_IOW(0xbc,	13,  struct bch_ioctl_disk_get_idx)
#define BCH_IOCTL_DISK_RESIZE	_IOW(0xbc,	14,  struct bch_ioctl_disk_resize)
#define BCH_IOCTL_DISK_RESIZE_JOURNAL _IOW(0xbc,15,  struct bch_ioctl_disk_resize_journal)

/* ioctl below act on a particular file, not the filesystem as a whole: */

#define BCHFS_IOC_REINHERIT_ATTRS	_IOR(0xbc, 64, const char __user *)

/*
 * BCH_IOCTL_QUERY_UUID: get filesystem UUID
 *
 * Returns user visible UUID, not internal UUID (which may not ever be changed);
 * the filesystem's sysfs directory may be found under /sys/fs/bcachefs with
 * this UUID.
 */
struct bch_ioctl_query_uuid {
	uuid_le			uuid;
};

#if 0
struct bch_ioctl_start {
	__u32			flags;
	__u32			pad;
};
#endif

/*
 * BCH_IOCTL_DISK_ADD: add a new device to an existing filesystem
 *
 * The specified device must not be open or in use. On success, the new device
 * will be an online member of the filesystem just like any other member.
 *
 * The device must first be prepared by userspace by formatting with a bcachefs
 * superblock, which is only used for passing in superblock options/parameters
 * for that device (in struct bch_member). The new device's superblock should
 * not claim to be a member of any existing filesystem - UUIDs on it will be
 * ignored.
 */

/*
 * BCH_IOCTL_DISK_REMOVE: permanently remove a member device from a filesystem
 *
 * Any data present on @dev will be permanently deleted, and @dev will be
 * removed from its slot in the filesystem's list of member devices. The device
 * may be either offline or offline.
 *
 * Will fail removing @dev would leave us with insufficient read write devices
 * or degraded/unavailable data, unless the approprate BCH_FORCE_IF_* flags are
 * set.
 */

/*
 * BCH_IOCTL_DISK_ONLINE: given a disk that is already a member of a filesystem
 * but is not open (e.g. because we started in degraded mode), bring it online
 *
 * all existing data on @dev will be available once the device is online,
 * exactly as if @dev was present when the filesystem was first mounted
 */

/*
 * BCH_IOCTL_DISK_OFFLINE: offline a disk, causing the kernel to close that
 * block device, without removing it from the filesystem (so it can be brought
 * back online later)
 *
 * Data present on @dev will be unavailable while @dev is offline (unless
 * replicated), but will still be intact and untouched if @dev is brought back
 * online
 *
 * Will fail (similarly to BCH_IOCTL_DISK_SET_STATE) if offlining @dev would
 * leave us with insufficient read write devices or degraded/unavailable data,
 * unless the approprate BCH_FORCE_IF_* flags are set.
 */

struct bch_ioctl_disk {
	__u32			flags;
	__u32			pad;
	__u64			dev;
};

/*
 * BCH_IOCTL_DISK_SET_STATE: modify state of a member device of a filesystem
 *
 * @new_state		- one of the bch_member_state states (rw, ro, failed,
 *			  spare)
 *
 * Will refuse to change member state if we would then have insufficient devices
 * to write to, or if it would result in degraded data (when @new_state is
 * failed or spare) unless the appropriate BCH_FORCE_IF_* flags are set.
 */
struct bch_ioctl_disk_set_state {
	__u32			flags;
	__u8			new_state;
	__u8			pad[3];
	__u64			dev;
};

enum bch_data_ops {
	BCH_DATA_OP_SCRUB		= 0,
	BCH_DATA_OP_REREPLICATE		= 1,
	BCH_DATA_OP_MIGRATE		= 2,
	BCH_DATA_OP_REWRITE_OLD_NODES	= 3,
	BCH_DATA_OP_NR			= 4,
};

/*
 * BCH_IOCTL_DATA: operations that walk and manipulate filesystem data (e.g.
 * scrub, rereplicate, migrate).
 *
 * This ioctl kicks off a job in the background, and returns a file descriptor.
 * Reading from the file descriptor returns a struct bch_ioctl_data_event,
 * indicating current progress, and closing the file descriptor will stop the
 * job. The file descriptor is O_CLOEXEC.
 */
struct bch_ioctl_data {
	__u16			op;
	__u8			start_btree;
	__u8			end_btree;
	__u32			flags;

	struct bpos		start_pos;
	struct bpos		end_pos;

	union {
	struct {
		__u32		dev;
		__u32		pad;
	}			migrate;
	struct {
		__u64		pad[8];
	};
	};
} __attribute__((packed, aligned(8)));

enum bch_data_event {
	BCH_DATA_EVENT_PROGRESS	= 0,
	/* XXX: add an event for reporting errors */
	BCH_DATA_EVENT_NR	= 1,
};

struct bch_ioctl_data_progress {
	__u8			data_type;
	__u8			btree_id;
	__u8			pad[2];
	struct bpos		pos;

	__u64			sectors_done;
	__u64			sectors_total;
} __attribute__((packed, aligned(8)));

struct bch_ioctl_data_event {
	__u8			type;
	__u8			pad[7];
	union {
	struct bch_ioctl_data_progress p;
	__u64			pad2[15];
	};
} __attribute__((packed, aligned(8)));

struct bch_replicas_usage {
	__u64			sectors;
	struct bch_replicas_entry r;
} __attribute__((packed));

static inline struct bch_replicas_usage *
replicas_usage_next(struct bch_replicas_usage *u)
{
	return (void *) u + replicas_entry_bytes(&u->r) + 8;
}

/*
 * BCH_IOCTL_FS_USAGE: query filesystem disk space usage
 *
 * Returns disk space usage broken out by data type, number of replicas, and
 * by component device
 *
 * @replica_entries_bytes - size, in bytes, allocated for replica usage entries
 *
 * On success, @replica_entries_bytes will be changed to indicate the number of
 * bytes actually used.
 *
 * Returns -ERANGE if @replica_entries_bytes was too small
 */
struct bch_ioctl_fs_usage {
	__u64			capacity;
	__u64			used;
	__u64			online_reserved;
	__u64			persistent_reserved[BCH_REPLICAS_MAX];

	__u32			replica_entries_bytes;
	__u32			pad;

	struct bch_replicas_usage replicas[0];
};

/*
 * BCH_IOCTL_DEV_USAGE: query device disk space usage
 *
 * Returns disk space usage broken out by data type - both by buckets and
 * sectors.
 */
struct bch_ioctl_dev_usage {
	__u64			dev;
	__u32			flags;
	__u8			state;
	__u8			pad[7];

	__u32			bucket_size;
	__u64			nr_buckets;
	__u64			available_buckets;

	__u64			buckets[BCH_DATA_NR];
	__u64			sectors[BCH_DATA_NR];

	__u64			ec_buckets;
	__u64			ec_sectors;
};

/*
 * BCH_IOCTL_READ_SUPER: read filesystem superblock
 *
 * Equivalent to reading the superblock directly from the block device, except
 * avoids racing with the kernel writing the superblock or having to figure out
 * which block device to read
 *
 * @sb		- buffer to read into
 * @size	- size of userspace allocated buffer
 * @dev		- device to read superblock for, if BCH_READ_DEV flag is
 *		  specified
 *
 * Returns -ERANGE if buffer provided is too small
 */
struct bch_ioctl_read_super {
	__u32			flags;
	__u32			pad;
	__u64			dev;
	__u64			size;
	__u64			sb;
};

/*
 * BCH_IOCTL_DISK_GET_IDX: give a path to a block device, query filesystem to
 * determine if disk is a (online) member - if so, returns device's index
 *
 * Returns -ENOENT if not found
 */
struct bch_ioctl_disk_get_idx {
	__u64			dev;
};

/*
 * BCH_IOCTL_DISK_RESIZE: resize filesystem on a device
 *
 * @dev		- member to resize
 * @nbuckets	- new number of buckets
 */
struct bch_ioctl_disk_resize {
	__u32			flags;
	__u32			pad;
	__u64			dev;
	__u64			nbuckets;
};

/*
 * BCH_IOCTL_DISK_RESIZE_JOURNAL: resize journal on a device
 *
 * @dev		- member to resize
 * @nbuckets	- new number of buckets
 */
struct bch_ioctl_disk_resize_journal {
	__u32			flags;
	__u32			pad;
	__u64			dev;
	__u64			nbuckets;
};

#endif /* _BCACHEFS_IOCTL_H */
