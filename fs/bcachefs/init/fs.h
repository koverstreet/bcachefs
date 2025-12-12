/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_SUPER_H
#define _BCACHEFS_SUPER_H

#include "data/extents.h"

#include "bcachefs_ioctl.h"

#include <linux/math64.h>

#define KTYPE(type)							\
static const struct attribute_group type ## _group = {			\
	.attrs = type ## _files						\
};									\
									\
static const struct attribute_group *type ## _groups[] = {		\
	&type ## _group,						\
	NULL								\
};									\
									\
static const struct kobj_type type ## _ktype = {			\
	.release	= type ## _release,				\
	.sysfs_ops	= &type ## _sysfs_ops,				\
	.default_groups = type ## _groups				\
}

extern const char * const bch2_fs_flag_strs[];
extern const char * const bch2_write_refs[];
extern const char * const bch2_dev_read_refs[];
extern const char * const bch2_dev_write_refs[];

extern struct list_head bch2_fs_list;
extern struct mutex bch2_fs_list_lock;

struct bch_fs *__bch2_uuid_to_fs(__uuid_t uuid);
struct bch_fs *bch2_uuid_to_fs(__uuid_t);

bool bch2_fs_emergency_read_only(struct bch_fs *, struct printbuf *);
bool bch2_fs_emergency_read_only_locked(struct bch_fs *, struct printbuf *out);

void bch2_fs_read_only(struct bch_fs *);

int bch2_fs_read_write(struct bch_fs *);
int bch2_fs_read_write_early(struct bch_fs *);
int bch2_fs_init_rw(struct bch_fs *);

int bch2_fs_resize_on_mount(struct bch_fs *);

int bch2_fs_start(struct bch_fs *);
int bch2_fs_stop(struct bch_fs *);

int bch2_fs_exit(struct bch_fs *);
struct bch_fs *bch2_fs_open(darray_const_str *, struct bch_opts *);

#endif /* _BCACHEFS_SUPER_H */
