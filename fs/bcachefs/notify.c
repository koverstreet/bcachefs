/*
 * Code for sending uevent notifications to user-space.
 *
 * Copyright 2015 Datera, Inc.
 */

#include "bcache.h"
#include "notify.h"

#include <linux/kobject.h>

#define notify_var(c, format, ...)					\
({									\
	int ret;							\
	lockdep_assert_held(&(c)->uevent_lock);				\
	ret = add_uevent_var(&(c)->uevent_env, format, ##__VA_ARGS__);	\
	WARN_ON_ONCE(ret);						\
})

static void notify_get(struct cache_set *c)
{
	struct kobj_uevent_env *env = &c->uevent_env;

	mutex_lock(&c->uevent_lock);
	env->envp_idx = 0;
	env->buflen = 0;

	notify_var(c, "SET_UUID=%pU", c->sb.set_uuid.b);
}

static void notify_get_cache(struct cache *ca)
{
	struct cache_set *c = ca->set;
	char buf[BDEVNAME_SIZE];

	notify_get(c);
	notify_var(c, "UUID=%pU", ca->sb.disk_uuid.b);
	notify_var(c, "BLOCKDEV=%s", bdevname(ca->disk_sb.bdev, buf));
}

static void notify_put(struct cache_set *c)
{
	struct kobj_uevent_env *env = &c->uevent_env;

	env->envp[env->envp_idx] = NULL;
	kobject_uevent_env(&c->kobj, KOBJ_CHANGE, env->envp);
	mutex_unlock(&c->uevent_lock);
}

void bch_notify_cache_set_read_write(struct cache_set *c)
{
	notify_get(c);
	notify_var(c, "STATE=active");
	notify_put(c);
}

void bch_notify_cache_set_read_only(struct cache_set *c)
{
	notify_get(c);
	notify_var(c, "STATE=readonly");
	notify_put(c);
}

void bch_notify_cache_set_stopped(struct cache_set *c)
{
	notify_get(c);
	notify_var(c, "STATE=stopped");
	notify_put(c);
}

void bch_notify_cache_read_write(struct cache *ca)
{
	struct cache_set *c = ca->set;

	notify_get_cache(ca);
	notify_var(c, "STATE=active");
	notify_put(c);
}

void bch_notify_cache_read_only(struct cache *ca)
{
	struct cache_set *c = ca->set;

	notify_get_cache(ca);
	notify_var(c, "STATE=readonly");
	notify_put(c);
}

void bch_notify_cache_added(struct cache *ca)
{
	struct cache_set *c = ca->set;

	notify_get_cache(ca);
	notify_var(c, "STATE=removing");
	notify_put(c);
}

void bch_notify_cache_removing(struct cache *ca)
{
	struct cache_set *c = ca->set;

	notify_get_cache(ca);
	notify_var(c, "STATE=removing");
	notify_put(c);
}

void bch_notify_cache_removed(struct cache *ca)
{
	struct cache_set *c = ca->set;

	notify_get_cache(ca);
	notify_var(c, "STATE=removed");
	notify_put(c);
}

void bch_notify_cache_error(struct cache *ca, bool fatal)
{
	struct cache_set *c = ca->set;

	notify_get_cache(ca);
	notify_var(c, "STATE=error");
	notify_var(c, "FATAL=%d", fatal);
	notify_put(c);
}
