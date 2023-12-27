/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_REPLICAS_FORMAT_H
#define _BCACHEFS_REPLICAS_FORMAT_H

struct bch_replicas_entry_v0 {
	__u8			data_type;
	__u8			nr_devs;
	__u8			devs[];
} __packed;

struct bch_replicas_entry_v1 {
	__u8			data_type;
	__u8			nr_devs;
	__u8			nr_required;
	__u8			devs[];
} __packed;

#define replicas_entry_bytes(_i)					\
	(offsetof(typeof(*(_i)), devs) + (_i)->nr_devs)

#endif /* _BCACHEFS_REPLICAS_FORMAT_H */
