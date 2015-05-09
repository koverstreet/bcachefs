#ifndef _LINUX_BCACHE_IOCTL_H
#define _LINUX_BCACHE_IOCTL_H

#include <linux/uuid.h>
#include "bcachefs_format.h"

#ifdef __cplusplus
extern "C" {
#endif

/* global control dev: */

#define BCH_FORCE_IF_DATA_MISSING	(1 << 0)
#define BCH_FORCE_IF_METADATA_MISSING	(1 << 1)

#define BCH_IOCTL_ASSEMBLE	_IOW('r', 1, struct bch_ioctl_assemble)
#define BCH_IOCTL_INCREMENTAL	_IOW('r', 1, struct bch_ioctl_incremental)

/* cache set control dev: */

#define BCH_IOCTL_RUN		_IO('r', 2)
#define BCH_IOCTL_STOP		_IO('r', 3)

#define BCH_IOCTL_DISK_ADD	_IOW('r', 4, struct bch_ioctl_disk_add)
#define BCH_IOCTL_DISK_REMOVE	_IOW('r', 5, struct bch_ioctl_disk_remove)
#define BCH_IOCTL_DISK_FAIL	_IOW('r', 6, struct bch_ioctl_disk_fail)

#define BCH_IOCTL_DISK_REMOVE_BY_UUID					\
	_IOW('r', 5, struct bch_ioctl_disk_remove_by_uuid)
#define BCH_IOCTL_DISK_FAIL_BY_UUID					\
	_IOW('r', 6, struct bch_ioctl_disk_fail_by_uuid)

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

struct bch_ioctl_disk_add {
	__u32			flags;
	__u32			pad;
	__u64			dev;
};

struct bch_ioctl_disk_remove {
	__u32			flags;
	__u32			pad;
	__u64			dev;
};

struct bch_ioctl_disk_fail {
	__u32			flags;
	__u32			pad;
	__u64			dev;
};

struct bch_ioctl_disk_remove_by_uuid {
	__u32			flags;
	__u32			pad;
	uuid_le			dev;
};

struct bch_ioctl_disk_fail_by_uuid {
	__u32			flags;
	__u32			pad;
	uuid_le			dev;
};

#ifdef __cplusplus
}
#endif

#endif /* _LINUX_BCACHE_IOCTL_H */
