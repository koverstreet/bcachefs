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

static void notify_get(struct bch_fs *c)
{
	struct kobj_uevent_env *env = &c->uevent_env;

	mutex_lock(&c->uevent_lock);
	env->envp_idx = 0;
	env->buflen = 0;

	notify_var(c, "SET_UUID=%pU", c->sb.user_uuid.b);
}

static void notify_get_cache(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;

	notify_get(c);
	notify_var(c, "UUID=%pU", ca->uuid.b);
	notify_var(c, "BLOCKDEV=%s", ca->name);
}

static void notify_put(struct bch_fs *c)
{
	struct kobj_uevent_env *env = &c->uevent_env;

	env->envp[env->envp_idx] = NULL;
	kobject_uevent_env(&c->kobj, KOBJ_CHANGE, env->envp);
	mutex_unlock(&c->uevent_lock);
}

void bch_notify_fs_read_write(struct bch_fs *c)
{
	notify_get(c);
	notify_var(c, "STATE=active");
	notify_put(c);
}

void bch_notify_fs_read_only(struct bch_fs *c)
{
	notify_get(c);
	notify_var(c, "STATE=readonly");
	notify_put(c);
}

void bch_notify_fs_stopped(struct bch_fs *c)
{
	notify_get(c);
	notify_var(c, "STATE=stopped");
	notify_put(c);
}

void bch_notify_dev_read_write(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;

	notify_get_cache(ca);
	notify_var(c, "STATE=active");
	notify_put(c);
}

void bch_notify_dev_read_only(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;

	notify_get_cache(ca);
	notify_var(c, "STATE=readonly");
	notify_put(c);
}

void bch_notify_dev_added(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;

	notify_get_cache(ca);
	notify_var(c, "STATE=removing");
	notify_put(c);
}

void bch_notify_dev_error(struct bch_dev *ca, bool fatal)
{
	struct bch_fs *c = ca->fs;

	notify_get_cache(ca);
	notify_var(c, "STATE=error");
	notify_var(c, "FATAL=%d", fatal);
	notify_put(c);
}
