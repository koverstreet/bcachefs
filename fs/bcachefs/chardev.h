#ifndef _BCACHE_CHARDEV_H
#define _BCACHE_CHARDEV_H

long bch_fs_ioctl(struct cache_set *, unsigned, void __user *);
extern const struct file_operations bch_chardev_fops;

#endif /* _BCACHE_CHARDEV_H */
