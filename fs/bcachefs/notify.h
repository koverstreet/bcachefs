/*
 * Code for sending uevent notifications to user-space.
 *
 * Copyright 2015 Datera, Inc.
 */

#ifndef _NOTIFY_H
#define _NOTIFY_H

#ifndef NO_BCACHE_NOTIFY

void bch_notify_fs_read_write(struct bch_fs *);
void bch_notify_fs_read_only(struct bch_fs *);
void bch_notify_fs_stopped(struct bch_fs *);

void bch_notify_dev_read_write(struct bch_dev *);
void bch_notify_dev_read_only(struct bch_dev *);
void bch_notify_dev_added(struct bch_dev *);
void bch_notify_dev_error(struct bch_dev *, bool);

#else

static inline void bch_notify_fs_read_write(struct bch_fs *c) {}
static inline void bch_notify_fs_read_only(struct bch_fs *c) {}
static inline void bch_notify_fs_stopped(struct bch_fs *c) {}

static inline void bch_notify_dev_read_write(struct bch_dev *ca) {}
static inline void bch_notify_dev_read_only(struct bch_dev *ca) {}
static inline void bch_notify_dev_added(struct bch_dev *ca) {}
static inline void bch_notify_dev_error(struct bch_dev *ca, bool b) {}

#endif

#endif /* _NOTIFY_H */
