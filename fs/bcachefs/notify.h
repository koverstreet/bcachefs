/*
 * Code for sending uevent notifications to user-space.
 *
 * Copyright 2015 Datera, Inc.
 */

#ifndef _NOTIFY_H
#define _NOTIFY_H

void bch_notify_fs_read_write(struct cache_set *);
void bch_notify_fs_read_only(struct cache_set *);
void bch_notify_fs_stopped(struct cache_set *);

void bch_notify_dev_read_write(struct cache *);
void bch_notify_dev_read_only(struct cache *);
void bch_notify_dev_added(struct cache *);
void bch_notify_dev_removing(struct cache *);
void bch_notify_dev_removed(struct cache *);
void bch_notify_dev_remove_failed(struct cache *);
void bch_notify_dev_error(struct cache *, bool);

#endif /* _NOTIFY_H */
