/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ACCEL_H
#define _BCACHEFS_ACCEL_H

#include <linux/types.h>

/**
 * Dispatch handlers for underlying storage algorithms to enable ISA-L/Kernel abstraction. 
 */

u64 accel_crc64(u64 crc, const void* p, size_t len);
u32 accel_crc32c(u32 crc, const void* p, size_t len);

void accel_erasure_encode(int nd, int np, size_t size, void **v);
void accel_erasure_decode(int nr, int *ir, int nd, int np, size_t size, void **v);

#endif /* _BCACHEFS_ACCEL_H */
