// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"
#include "disk_groups.h"
#include "super-io.h"

#include <linux/sort.h>

static int strcmp_void(const void *l, const void *r)
{
	return strcmp(l, r);
}

const char *bch2_sb_validate_disk_groups(struct bch_sb *sb,
					 struct bch_sb_field *f)
{
	struct bch_sb_field_disk_groups *groups =
		field_to_type(f, disk_groups);
	struct bch_disk_group *g;
	struct bch_sb_field_members *mi;
	struct bch_member *m;
	unsigned i, nr_groups, nr_live = 0, len;
	char **labels, *l;
	const char *err = NULL;

	mi		= bch2_sb_get_members(sb);
	groups		= bch2_sb_get_disk_groups(sb);
	nr_groups	= disk_groups_nr(groups);

	for (m = mi->members;
	     m < mi->members + sb->nr_devices;
	     m++) {
		unsigned g;

		if (!BCH_MEMBER_GROUP(m))
			continue;

		g = BCH_MEMBER_GROUP(m) - 1;

		if (g >= nr_groups ||
		    BCH_GROUP_DELETED(&groups->entries[g]))
			return "disk has invalid group";
	}

	if (!nr_groups)
		return NULL;

	labels = kcalloc(nr_groups, sizeof(char *), GFP_KERNEL);
	if (!labels)
		return "cannot allocate memory";

	for (g = groups->entries;
	     g < groups->entries + nr_groups;
	     g++) {
		if (BCH_GROUP_DELETED(g))
			continue;

		len = strnlen(g->label, sizeof(g->label));

		labels[nr_live++] = l = kmalloc(len + 1, GFP_KERNEL);
		if (!l) {
			err = "cannot allocate memory";
			goto err;
		}

		memcpy(l, g->label, len);
		l[len] = '\0';
	}

	sort(labels, nr_live, sizeof(labels[0]), strcmp_void, NULL);

	for (i = 0; i + 1 < nr_live; i++)
		if (!strcmp(labels[i], labels[i + 1])) {
			err = "duplicate group labels";
			goto err;
		}

	err = NULL;
err:
	for (i = 0; i < nr_live; i++)
		kfree(labels[i]);
	kfree(labels);
	return err;
}

int bch2_sb_disk_groups_to_cpu(struct bch_fs *c)
{
	struct bch_sb_field_members *mi;
	struct bch_sb_field_disk_groups *groups;
	struct bch_disk_groups_cpu *cpu_g, *old_g;
	unsigned i, nr_groups;

	lockdep_assert_held(&c->sb_lock);

	mi		= bch2_sb_get_members(c->disk_sb);
	groups		= bch2_sb_get_disk_groups(c->disk_sb);
	nr_groups	= disk_groups_nr(groups);

	if (!groups)
		return 0;

	cpu_g = kzalloc(sizeof(*cpu_g) +
			sizeof(cpu_g->entries[0]) * nr_groups, GFP_KERNEL);
	if (!cpu_g)
		return -ENOMEM;

	cpu_g->nr = nr_groups;

	for (i = 0; i < nr_groups; i++) {
		struct bch_disk_group *src	= &groups->entries[i];
		struct bch_disk_group_cpu *dst	= &cpu_g->entries[i];

		dst->deleted = BCH_GROUP_DELETED(src);
	}

	for (i = 0; i < c->disk_sb->nr_devices; i++) {
		struct bch_member *m = mi->members + i;
		struct bch_disk_group_cpu *dst =
			&cpu_g->entries[BCH_MEMBER_GROUP(m)];

		if (!bch2_member_exists(m))
			continue;

		dst = BCH_MEMBER_GROUP(m)
			? &cpu_g->entries[BCH_MEMBER_GROUP(m) - 1]
			: NULL;
		if (dst)
			__set_bit(i, dst->devs.d);
	}

	old_g = c->disk_groups;
	rcu_assign_pointer(c->disk_groups, cpu_g);
	if (old_g)
		kfree_rcu(old_g, rcu);

	return 0;
}

const struct bch_devs_mask *bch2_target_to_mask(struct bch_fs *c, unsigned target)
{
	struct target t = target_decode(target);

	switch (t.type) {
	case TARGET_NULL:
		return NULL;
	case TARGET_DEV: {
		struct bch_dev *ca = t.dev < c->sb.nr_devices
			? rcu_dereference(c->devs[t.dev])
			: NULL;
		return ca ? &ca->self : NULL;
	}
	case TARGET_GROUP: {
		struct bch_disk_groups_cpu *g = rcu_dereference(c->disk_groups);

		return t.group < g->nr && !g->entries[t.group].deleted
			? &g->entries[t.group].devs
			: NULL;
	}
	default:
		BUG();
	}
}

static int __bch2_disk_group_find(struct bch_sb_field_disk_groups *groups,
			   const char *name)
{
	unsigned i, nr_groups = disk_groups_nr(groups);
	unsigned len = strlen(name);

	for (i = 0; i < nr_groups; i++) {
		struct bch_disk_group *g = groups->entries + i;

		if (BCH_GROUP_DELETED(g))
			continue;

		if (strnlen(g->label, sizeof(g->label)) == len &&
		    !memcmp(name, g->label, len))
			return i;
	}

	return -1;
}

static int bch2_disk_group_find(struct bch_fs *c, const char *name)
{
	int ret;

	mutex_lock(&c->sb_lock);
	ret = __bch2_disk_group_find(bch2_sb_get_disk_groups(c->disk_sb), name);
	mutex_unlock(&c->sb_lock);

	return ret;
}

int bch2_dev_group_set(struct bch_fs *c, struct bch_dev *ca, const char *label)
{
	struct bch_sb_field_disk_groups *groups;
	struct bch_disk_group *g;
	struct bch_member *mi;
	unsigned i, v, nr_groups;
	int ret;

	if (strlen(label) > BCH_SB_LABEL_SIZE)
		return -EINVAL;

	mutex_lock(&c->sb_lock);
	groups		= bch2_sb_get_disk_groups(c->disk_sb);
	nr_groups	= disk_groups_nr(groups);

	if (!strcmp(label, "none")) {
		v = 0;
		goto write_sb;
	}

	ret = __bch2_disk_group_find(groups, label);
	if (ret >= 0) {
		v = ret + 1;
		goto write_sb;
	}

	/* not found - create a new disk group: */

	for (i = 0;
	     i < nr_groups && !BCH_GROUP_DELETED(&groups->entries[i]);
	     i++)
		;

	if (i == nr_groups) {
		unsigned u64s =
			(sizeof(struct bch_sb_field_disk_groups) +
			 sizeof(struct bch_disk_group) * (nr_groups + 1)) /
			sizeof(u64);

		groups = bch2_fs_sb_resize_disk_groups(c, u64s);
		if (!groups) {
			mutex_unlock(&c->sb_lock);
			return -ENOSPC;
		}

		nr_groups = disk_groups_nr(groups);
	}

	BUG_ON(i >= nr_groups);

	g = &groups->entries[i];
	v = i + 1;

	memcpy(g->label, label, strlen(label));
	if (strlen(label) < sizeof(g->label))
		g->label[strlen(label)] = '\0';
	SET_BCH_GROUP_DELETED(g, 0);
	SET_BCH_GROUP_DATA_ALLOWED(g, ~0);
write_sb:
	mi = &bch2_sb_get_members(c->disk_sb)->members[ca->dev_idx];
	SET_BCH_MEMBER_GROUP(mi, v);

	bch2_write_super(c);
	mutex_unlock(&c->sb_lock);

	return 0;
}

int bch2_opt_target_parse(struct bch_fs *c, const char *buf, u64 *v)
{
	struct bch_dev *ca;
	int g;

	if (!strlen(buf) || !strcmp(buf, "none")) {
		*v = 0;
		return 0;
	}

	/* Is it a device? */
	ca = bch2_dev_lookup(c, buf);
	if (!IS_ERR(ca)) {
		*v = dev_to_target(ca->dev_idx);
		percpu_ref_put(&ca->ref);
		return 0;
	}

	g = bch2_disk_group_find(c, buf);
	if (g >= 0) {
		*v = group_to_target(g);
		return 0;
	}

	return -EINVAL;
}

int bch2_opt_target_print(struct bch_fs *c, char *buf, size_t len, u64 v)
{
	struct target t = target_decode(v);
	int ret;

	switch (t.type) {
	case TARGET_NULL:
		return scnprintf(buf, len, "none");
	case TARGET_DEV: {
		struct bch_dev *ca;

		rcu_read_lock();
		ca = t.dev < c->sb.nr_devices
			? rcu_dereference(c->devs[t.dev])
			: NULL;

		if (ca && percpu_ref_tryget(&ca->io_ref)) {
			ret = scnprintf(buf, len, "/dev/%pg",
					ca->disk_sb.bdev);
			percpu_ref_put(&ca->io_ref);
		} else if (ca) {
			ret = scnprintf(buf, len, "offline device %u", t.dev);
		} else {
			ret = scnprintf(buf, len, "invalid device %u", t.dev);
		}

		rcu_read_unlock();
		break;
	}
	case TARGET_GROUP: {
		struct bch_sb_field_disk_groups *groups;
		struct bch_disk_group *g;

		mutex_lock(&c->sb_lock);
		groups = bch2_sb_get_disk_groups(c->disk_sb);

		g = t.group < disk_groups_nr(groups)
			? groups->entries + t.group
			: NULL;

		if (g && !BCH_GROUP_DELETED(g)) {
			ret = len ? min(len - 1, strnlen(g->label, sizeof(g->label))) : 0;

			memcpy(buf, g->label, ret);
			if (len)
				buf[ret] = '\0';
		} else {
			ret = scnprintf(buf, len, "invalid group %u", t.group);
		}

		mutex_unlock(&c->sb_lock);
		break;
	}
	default:
		BUG();
	}

	return ret;
}
