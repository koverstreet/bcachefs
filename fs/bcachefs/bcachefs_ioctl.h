#ifndef _BCACHEFS_IOCTL_H
#define _BCACHEFS_IOCTL_H

#include <linux/uuid.h>
#include "bcachefs_format.h"

#define BCH_FORCE_IF_DATA_LOST		(1 << 0)
#define BCH_FORCE_IF_METADATA_LOST	(1 << 1)
#define BCH_FORCE_IF_DATA_DEGRADED	(1 << 2)
#define BCH_FORCE_IF_METADATA_DEGRADED	(1 << 3)

#define BCH_FORCE_IF_DEGRADED			\
	(BCH_FORCE_IF_DATA_DEGRADED|		\
	 BCH_FORCE_IF_METADATA_DEGRADED)

#define BCH_BY_INDEX			(1 << 4)

/* global control dev: */

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

/* filesystem ioctls: */

#define BCH_IOCTL_QUERY_UUID	_IOR(0xbc,	1,  struct bch_ioctl_query_uuid)
#define BCH_IOCTL_START		_IOW(0xbc,	2,  struct bch_ioctl_start)
#define BCH_IOCTL_STOP		_IO(0xbc,	3)
#define BCH_IOCTL_DISK_ADD	_IOW(0xbc,	4,  struct bch_ioctl_disk)
#define BCH_IOCTL_DISK_REMOVE	_IOW(0xbc,	5,  struct bch_ioctl_disk)
#define BCH_IOCTL_DISK_ONLINE	_IOW(0xbc,	6,  struct bch_ioctl_disk)
#define BCH_IOCTL_DISK_OFFLINE	_IOW(0xbc,	7,  struct bch_ioctl_disk)
#define BCH_IOCTL_DISK_SET_STATE _IOW(0xbc,	8,  struct bch_ioctl_disk_set_state)
#define BCH_IOCTL_DISK_EVACUATE	_IOW(0xbc,	9,  struct bch_ioctl_disk)
#define BCH_IOCTL_DATA		_IOW(0xbc,	10, struct bch_ioctl_data)
#define BCH_IOCTL_USAGE		_IOWR(0xbc,	11, struct bch_ioctl_usage)

struct bch_ioctl_query_uuid {
	uuid_le			uuid;
};

struct bch_ioctl_start {
	__u32			flags;
	__u32			pad;
};

struct bch_ioctl_disk {
	__u32			flags;
	__u32			pad;
	__u64			dev;
};

struct bch_ioctl_disk_set_state {
	__u32			flags;
	__u8			new_state;
	__u8			pad[3];
	__u64			dev;
};

#define BCH_REWRITE_INCREASE_REPLICAS	(1 << 0)
#define BCH_REWRITE_DECREASE_REPLICAS	(1 << 1)

#define BCH_REWRITE_RECOMPRESS		(1 << 0)
#define BCH_REWRITE_DECREASE_REPLICAS	(1 << 1)

enum bch_data_ops {
	BCH_DATA_SCRUB,
};

struct bch_data_op {
	__u8			type;
};

struct bch_ioctl_data {
	__u32			flags;
	__u32			pad;

	__u64			start_inode;
	__u64			start_offset;

	__u64			end_inode;
	__u64			end_offset;
};

struct bch_ioctl_dev_usage {
	__u8			state;
	__u8			alive;
	__u8			pad[6];
	__u32			dev;

	__u32			bucket_size;
	__u64			nr_buckets;

	__u64			buckets[BCH_DATA_NR];
	__u64			sectors[BCH_DATA_NR];
};

struct bch_ioctl_fs_usage {
	__u64			capacity;
	__u64			used;
	__u64			online_reserved;
	__u64			persistent_reserved[BCH_REPLICAS_MAX];
	__u64			sectors[BCH_DATA_NR][BCH_REPLICAS_MAX];
};

struct bch_ioctl_usage {
	__u16			nr_devices;
	__u16			pad[3];

	struct bch_ioctl_fs_usage fs;
	struct bch_ioctl_dev_usage devs[0];
};

#endif /* _BCACHEFS_IOCTL_H */
