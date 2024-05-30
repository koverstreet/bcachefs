/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RINGBUFFER_SYS_H
#define _LINUX_RINGBUFFER_SYS_H

#include <linux/darray_types.h>
#include <linux/spinlock_types.h>
#include <uapi/linux/ringbuffer_sys.h>

struct mm_struct;
void ringbuffer_mm_exit(struct mm_struct *mm);

void ringbuffer_free(struct ringbuffer *rb);
struct ringbuffer *ringbuffer_alloc(u32 size);

ssize_t ringbuffer_read_iter(struct ringbuffer *rb, struct iov_iter *iter, bool nonblock);
ssize_t ringbuffer_write_iter(struct ringbuffer *rb, struct iov_iter *iter, bool nonblock);

#endif /* _LINUX_RINGBUFFER_SYS_H */
