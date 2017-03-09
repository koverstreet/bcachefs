#ifndef _BCACHE_CHARDEV_H
#define _BCACHE_CHARDEV_H

#ifndef NO_BCACHE_CHARDEV

long bch_fs_ioctl(struct bch_fs *, unsigned, void __user *);

void bch_fs_chardev_exit(struct bch_fs *);
int bch_fs_chardev_init(struct bch_fs *);

void bch_chardev_exit(void);
int __init bch_chardev_init(void);

#else

static inline long bch_fs_ioctl(struct bch_fs *c,
				unsigned cmd, void __user * arg)
{
	return -ENOSYS;
}

static inline void bch_fs_chardev_exit(struct bch_fs *c) {}
static inline int bch_fs_chardev_init(struct bch_fs *c) { return 0; }

static inline void bch_chardev_exit(void) {}
static inline int __init bch_chardev_init(void) { return 0; }

#endif

#endif /* _BCACHE_CHARDEV_H */
