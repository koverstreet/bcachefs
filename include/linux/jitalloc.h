/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_JITALLOC_H
#define _LINUX_JITALLOC_H

void jit_update(void *buf, void *new_buf, size_t len);
void jit_free(void *buf);
void *jit_alloc(void *buf, size_t len);

#endif /* _LINUX_JITALLOC_H */
