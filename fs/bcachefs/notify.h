/*
 * Code for sending uevent notifications to user-space.
 *
 * Copyright 2015 Datera, Inc.
 */

#ifndef _NOTIFY_H
#define _NOTIFY_H

void bch_notify_cache_set_read_write(struct cache_set *);
void bch_notify_cache_set_read_only(struct cache_set *);
void bch_notify_cache_set_stopped(struct cache_set *);

void bch_notify_cache_read_write(struct cache *);
void bch_notify_cache_read_only(struct cache *);
void bch_notify_cache_added(struct cache *);
void bch_notify_cache_removing(struct cache *);
void bch_notify_cache_removed(struct cache *);
void bch_notify_cache_error(struct cache *, bool);

#endif /* _NOTIFY_H */
