/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_ACCEL_H
#define _BCACHEFS_ACCEL_H

#include <linux/types.h>

/**
 * Dispatch handlers for underlying storage algorithms to enable ISA-L/Kernel abstraction. 
 */

u64 accel_crc64(u64 crc, const void* p, size_t len);
u64 accel_crc32c(u32 crc, const void* p, size_t len);

/**
 * Sysfs hook for running primitive benchmarks.
 *
 * Returns a non-zero value if running the benchmarks failed.
 */
int accel_benchmark(const char* prim);

#endif /* _BCACHEFS_ACCEL_H */
