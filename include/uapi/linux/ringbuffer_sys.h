/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_RINGBUFFER_SYS_H
#define _UAPI_LINUX_RINGBUFFER_SYS_H

#include <uapi/linux/types.h>

/*
 * ringbuffer_desc - head and tail pointers for a ringbuffer, mappped to
 * userspace:
 */
struct ringbuffer_desc {
	/*
	 * We use u32s because this type is shared between the kernel and
	 * userspace - ulong/size_t won't work here, we might be 32bit userland
	 * and 64 bit kernel, and u64 would be preferable (reduced probability
	 * of ABA) but not all architectures can atomically read/write to a u64;
	 * we need to avoid torn reads/writes.
	 *
	 * head and tail pointers are incremented and stored without masking;
	 * this is to avoid ABA and differentiate between a full and empty
	 * buffer - they must be masked with @mask to get an actual offset into
	 * the data buffer.
	 *
	 * All units are in bytes.
	 *
	 * Data is emitted at head, consumed from tail.
	 */
	__u32		head;
	__u32		tail;
	__u32		size;	/* always a power of two */
	__u32		mask;	/* size - 1 */

	/*
	 * Starting offset of data buffer, from the start of this struct - will
	 * always be PAGE_SIZE.
	 */
	__u32		data_offset;
};

#endif /* _UAPI_LINUX_RINGBUFFER_SYS_H */
