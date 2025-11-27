// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/buckets.h"
#include "alloc/disk_groups.h"
#include "alloc/replicas.h"

#include "btree/cache.h"
#include "btree/iter.h"

#include "sb/members.h"
#include "sb/io.h"

#include "init/error.h"
#include "init/passes.h"
#include "init/progress.h"

int bch2_dev_missing_bkey(struct bch_fs *c, struct bkey_s_c k, unsigned dev)
{
	CLASS(printbuf, buf)();
	bch2_log_msg_start(c, &buf);

	bool removed = test_bit(dev, c->devs_removed.d);

	prt_printf(&buf, "pointer to %s device %u in key\n",
		   removed ? "removed" : "nonexistent", dev);
	bch2_bkey_val_to_text(&buf, c, k);
	prt_newline(&buf);

	bool print = removed
		? bch2_count_fsck_err(c, ptr_to_removed_device, &buf)
		: bch2_count_fsck_err(c, ptr_to_invalid_device, &buf);

	int ret = bch2_run_explicit_recovery_pass(c, &buf,
					BCH_RECOVERY_PASS_check_allocations, 0);

	if (print)
		bch2_print_str(c, KERN_ERR, buf.buf);
	return ret;
}

void bch2_dev_missing_atomic(struct bch_fs *c, unsigned dev)
{
	if (dev != BCH_SB_MEMBER_INVALID)
		bch2_fs_inconsistent(c, "pointer to %s device %u",
				     test_bit(dev, c->devs_removed.d)
				     ? "removed" : "nonexistent", dev);
}

void bch2_dev_bucket_missing(struct bch_dev *ca, u64 bucket)
{
	bch2_fs_inconsistent(ca->fs,
		"pointer to nonexistent bucket %llu on device %s (valid range %u-%llu)",
		bucket, ca->name, ca->mi.first_bucket, ca->mi.nbuckets);
}

#define x(t, n, ...) [n] = #t,
static const char * const bch2_iops_measurements[] = {
	BCH_IOPS_MEASUREMENTS()
	NULL
};

char * const bch2_member_error_strs[] = {
	BCH_MEMBER_ERROR_TYPES()
	NULL
};
#undef x

/* Code for bch_sb_field_members_v1: */

struct bch_member *bch2_members_v2_get_mut(struct bch_sb *sb, int i)
{
	return __bch2_members_v2_get_mut(bch2_sb_field_get(sb, members_v2), i);
}

struct bch_member bch2_sb_member_get(struct bch_sb *sb, int i)
{
	struct bch_sb_field_members_v2 *mi2 = bch2_sb_field_get(sb, members_v2);
	if (mi2)
		return bch2_members_v2_get(mi2, i);
	struct bch_sb_field_members_v1 *mi1 = bch2_sb_field_get(sb, members_v1);
	return bch2_members_v1_get(mi1, i);
}

static int sb_members_v2_resize_entries(struct bch_fs *c)
{
	struct bch_sb_field_members_v2 *mi = bch2_sb_field_get(c->disk_sb.sb, members_v2);

	if (le16_to_cpu(mi->member_bytes) < sizeof(struct bch_member)) {
		unsigned u64s = DIV_ROUND_UP((sizeof(*mi) + sizeof(mi->_members[0]) *
					      c->disk_sb.sb->nr_devices), 8);

		mi = bch2_sb_field_resize(&c->disk_sb, members_v2, u64s);
		if (!mi)
			return bch_err_throw(c, ENOSPC_sb_members_v2);

		for (int i = c->disk_sb.sb->nr_devices - 1; i >= 0; --i) {
			void *dst = (void *) mi->_members + (i * sizeof(struct bch_member));
			memmove(dst, __bch2_members_v2_get_mut(mi, i), le16_to_cpu(mi->member_bytes));
			memset(dst + le16_to_cpu(mi->member_bytes),
			       0, (sizeof(struct bch_member) - le16_to_cpu(mi->member_bytes)));
		}
		mi->member_bytes = cpu_to_le16(sizeof(struct bch_member));
	}
	return 0;
}

int bch2_sb_members_v2_init(struct bch_fs *c)
{
	struct bch_sb_field_members_v1 *mi1;
	struct bch_sb_field_members_v2 *mi2;

	if (!bch2_sb_field_get(c->disk_sb.sb, members_v2)) {
		mi2 = bch2_sb_field_resize(&c->disk_sb, members_v2,
				DIV_ROUND_UP(sizeof(*mi2) +
					     sizeof(struct bch_member) * c->sb.nr_devices,
					     sizeof(u64)));
		mi1 = bch2_sb_field_get(c->disk_sb.sb, members_v1);
		memcpy(&mi2->_members[0], &mi1->_members[0],
		       BCH_MEMBER_V1_BYTES * c->sb.nr_devices);
		memset(&mi2->pad[0], 0, sizeof(mi2->pad));
		mi2->member_bytes = cpu_to_le16(BCH_MEMBER_V1_BYTES);
	}

	return sb_members_v2_resize_entries(c);
}

int bch2_sb_members_cpy_v2_v1(struct bch_sb_handle *disk_sb)
{
	struct bch_sb_field_members_v1 *mi1;
	struct bch_sb_field_members_v2 *mi2;

	if (BCH_SB_VERSION_INCOMPAT(disk_sb->sb) > bcachefs_metadata_version_extent_flags) {
		bch2_sb_field_resize(disk_sb, members_v1, 0);
		return 0;
	}

	mi1 = bch2_sb_field_resize(disk_sb, members_v1,
			DIV_ROUND_UP(sizeof(*mi1) + BCH_MEMBER_V1_BYTES *
				     disk_sb->sb->nr_devices, sizeof(u64)));
	if (!mi1)
		return -BCH_ERR_ENOSPC_sb_members;

	mi2 = bch2_sb_field_get(disk_sb->sb, members_v2);

	for (unsigned i = 0; i < disk_sb->sb->nr_devices; i++)
		memcpy(members_v1_get_mut(mi1, i), __bch2_members_v2_get_mut(mi2, i), BCH_MEMBER_V1_BYTES);

	return 0;
}

static int validate_member(struct printbuf *err,
			   struct bch_member m,
			   struct bch_sb *sb,
			   int i)
{
	if (le64_to_cpu(m.nbuckets) > BCH_MEMBER_NBUCKETS_MAX) {
		prt_printf(err, "device %u: too many buckets (got %llu, max %u)",
			   i, le64_to_cpu(m.nbuckets), BCH_MEMBER_NBUCKETS_MAX);
		return -BCH_ERR_invalid_sb_members;
	}

	if (le64_to_cpu(m.nbuckets) -
	    le16_to_cpu(m.first_bucket) < BCH_MIN_NR_NBUCKETS) {
		prt_printf(err, "device %u: not enough buckets (got %llu, max %u)",
			   i, le64_to_cpu(m.nbuckets), BCH_MIN_NR_NBUCKETS);
		return -BCH_ERR_invalid_sb_members;
	}

	if (le16_to_cpu(m.bucket_size) <
	    le16_to_cpu(sb->block_size)) {
		prt_printf(err, "device %u: bucket size %u smaller than block size %u",
			   i, le16_to_cpu(m.bucket_size), le16_to_cpu(sb->block_size));
		return -BCH_ERR_invalid_sb_members;
	}

	if (le16_to_cpu(m.bucket_size) <
	    BCH_SB_BTREE_NODE_SIZE(sb)) {
		prt_printf(err, "device %u: bucket size %u smaller than btree node size %llu",
			   i, le16_to_cpu(m.bucket_size), BCH_SB_BTREE_NODE_SIZE(sb));
		return -BCH_ERR_invalid_sb_members;
	}

	if (m.btree_bitmap_shift >= BCH_MI_BTREE_BITMAP_SHIFT_MAX) {
		prt_printf(err, "device %u: invalid btree_bitmap_shift %u", i, m.btree_bitmap_shift);
		return -BCH_ERR_invalid_sb_members;
	}

	if (BCH_MEMBER_FREESPACE_INITIALIZED(&m) &&
	    sb->features[0] & cpu_to_le64(BIT_ULL(BCH_FEATURE_no_alloc_info))) {
		prt_printf(err, "device %u: freespace initialized but fs has no alloc info", i);
		return -BCH_ERR_invalid_sb_members;
	}

	return 0;
}

void bch2_member_to_text(struct printbuf *out,
			 struct bch_member *m,
			 struct bch_sb_field_disk_groups *gi,
			 struct bch_sb *sb,
			 unsigned idx)
{
	u64 bucket_size = le16_to_cpu(m->bucket_size);
	u64 device_size = le64_to_cpu(m->nbuckets) * bucket_size;

	prt_printf(out, "Label:\t");
	if (BCH_MEMBER_GROUP(m))
		bch2_disk_path_to_text_sb(out, sb,
				BCH_MEMBER_GROUP(m) - 1);
	else
		prt_printf(out, "(none)");
	prt_newline(out);

	prt_printf(out, "UUID:\t");
	pr_uuid(out, m->uuid.b);
	prt_newline(out);

	prt_printf(out, "Size:\t");
	prt_units_u64(out, device_size << 9);
	prt_newline(out);

	for (unsigned i = 0; i < BCH_MEMBER_ERROR_NR; i++)
		prt_printf(out, "%s errors:\t%llu\n", bch2_member_error_strs[i], le64_to_cpu(m->errors[i]));

	for (unsigned i = 0; i < BCH_IOPS_NR; i++)
		prt_printf(out, "%s iops:\t%u\n", bch2_iops_measurements[i], le32_to_cpu(m->iops[i]));

	prt_printf(out, "Bucket size:\t");
	prt_units_u64(out, bucket_size << 9);
	prt_newline(out);

	prt_printf(out, "First bucket:\t%u\n", le16_to_cpu(m->first_bucket));
	prt_printf(out, "Buckets:\t%llu\n", le64_to_cpu(m->nbuckets));

	prt_printf(out, "Last mount:\t");
	if (m->last_mount)
		bch2_prt_datetime(out, le64_to_cpu(m->last_mount));
	else
		prt_printf(out, "(never)");
	prt_newline(out);

	prt_printf(out, "Last superblock write:\t%llu\n", le64_to_cpu(m->seq));

	prt_printf(out, "State:\t%s\n",
		   BCH_MEMBER_STATE(m) < BCH_MEMBER_STATE_NR
		   ? bch2_member_states[BCH_MEMBER_STATE(m)]
		   : "unknown");

	prt_printf(out, "Data allowed:\t");
	if (BCH_MEMBER_DATA_ALLOWED(m))
		prt_bitflags(out, __bch2_data_types, BCH_MEMBER_DATA_ALLOWED(m));
	else
		prt_printf(out, "(none)");
	prt_newline(out);

	prt_printf(out, "Has data:\t");
	unsigned data_have = bch2_sb_dev_has_data(sb, idx);
	if (data_have)
		prt_bitflags(out, __bch2_data_types, data_have);
	else
		prt_printf(out, "(none)");
	prt_newline(out);

	prt_printf(out, "Rotational:\t%llu\n", BCH_MEMBER_ROTATIONAL(m));

	prt_printf(out, "Btree allocated bitmap blocksize:\t");
	if (m->btree_bitmap_shift < 64)
		prt_units_u64(out, 1ULL << m->btree_bitmap_shift);
	else
		prt_printf(out, "(invalid shift %u)", m->btree_bitmap_shift);
	prt_newline(out);

	prt_printf(out, "Btree allocated bitmap:\t");
	bch2_prt_u64_base2_nbits(out, le64_to_cpu(m->btree_allocated_bitmap), 64);
	prt_newline(out);

	prt_printf(out, "Durability:\t%llu\n", BCH_MEMBER_DURABILITY(m) ? BCH_MEMBER_DURABILITY(m) - 1 : 1);

	prt_printf(out, "Discard:\t%llu\n", BCH_MEMBER_DISCARD(m));
	prt_printf(out, "Freespace initialized:\t%llu\n", BCH_MEMBER_FREESPACE_INITIALIZED(m));
	prt_printf(out, "Resize on mount:\t%llu\n", BCH_MEMBER_RESIZE_ON_MOUNT(m));

	prt_printf(out, "Last device name:\t%.*s\n", (int) sizeof(m->device_name), m->device_name);
	prt_printf(out, "Last device model:\t%.*s\n", (int) sizeof(m->device_model), m->device_model);
}

static void bch2_member_to_text_short_sb(struct printbuf *out,
					 struct bch_member *m,
					 struct bch_sb_field_disk_groups *gi,
					 struct bch_sb *sb,
					 unsigned idx)
{
	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 16 + out->indent);

	if (BCH_MEMBER_GROUP(m)) {
		prt_printf(out, "Label:\t");
		bch2_disk_path_to_text_sb(out, sb,
				BCH_MEMBER_GROUP(m) - 1);
		prt_newline(out);
	}

	prt_printf(out, "Device:\t%.*s\n", (int) sizeof(m->device_name), m->device_name);
	prt_printf(out, "Model:\t%.*s\n", (int) sizeof(m->device_model), m->device_model);

	prt_printf(out, "State:\t%s\n",
		   BCH_MEMBER_STATE(m) < BCH_MEMBER_STATE_NR
		   ? bch2_member_states[BCH_MEMBER_STATE(m)]
		   : "unknown");

	prt_printf(out, "Has data:\t");
	unsigned data_have = bch2_sb_dev_has_data(sb, idx);
	if (data_have)
		prt_bitflags(out, __bch2_data_types, data_have);
	else
		prt_printf(out, "(none)");
	prt_newline(out);
}

static void bch2_member_to_text_short_locked(struct printbuf *out,
			       struct bch_fs *c,
			       struct bch_dev *ca)
{
	struct bch_member m = bch2_sb_member_get(c->disk_sb.sb, ca->dev_idx);
	bch2_member_to_text_short_sb(out, &m,
				     bch2_sb_field_get(c->disk_sb.sb, disk_groups),
				     c->disk_sb.sb,
				     ca->dev_idx);
}

void bch2_member_to_text_short(struct printbuf *out,
			       struct bch_fs *c,
			       struct bch_dev *ca)
{
	guard(mutex)(&c->sb_lock);
	bch2_member_to_text_short_locked(out, c, ca);
}

void bch2_devs_mask_to_text_locked(struct printbuf *out, struct bch_fs *c,
				   struct bch_devs_mask *devs)
{
	for_each_member_device(c, ca)
		if (test_bit(ca->dev_idx, devs->d))
			bch2_member_to_text_short_locked(out, c, ca);
}

static void member_to_text(struct printbuf *out,
			   struct bch_member m,
			   struct bch_sb_field_disk_groups *gi,
			   struct bch_sb *sb,
			   unsigned idx)
{
	if (!bch2_member_alive(&m))
		return;

	prt_printf(out, "Device:\t%u\n", idx);
	guard(printbuf_indent)(out);

	bch2_member_to_text(out, &m, gi, sb, idx);
}

static int bch2_sb_members_v1_validate(struct bch_sb *sb, struct bch_sb_field *f,
				enum bch_validate_flags flags, struct printbuf *err)
{
	struct bch_sb_field_members_v1 *mi = field_to_type(f, members_v1);

	if ((void *) members_v1_get_mut(mi, sb->nr_devices) > vstruct_end(&mi->field)) {
		prt_printf(err, "too many devices for section size");
		return -BCH_ERR_invalid_sb_members;
	}

	for (unsigned i = 0; i < sb->nr_devices; i++)
		try(validate_member(err, bch2_members_v1_get(mi, i), sb, i));

	return 0;
}

static void bch2_sb_members_v1_to_text(struct printbuf *out, struct bch_sb *sb,
				       struct bch_sb_field *f)
{
	struct bch_sb_field_members_v1 *mi = field_to_type(f, members_v1);
	struct bch_sb_field_disk_groups *gi = bch2_sb_field_get(sb, disk_groups);

	if (vstruct_end(&mi->field) <= (void *) &mi->_members[0]) {
		prt_printf(out, "field ends before start of entries");
		return;
	}

	unsigned nr = (vstruct_end(&mi->field) - (void *) &mi->_members[0]) / sizeof(mi->_members[0]);
	if (nr != sb->nr_devices)
		prt_printf(out, "nr_devices mismatch: have %i entries, should be %u", nr, sb->nr_devices);

	for (unsigned i = 0; i < min(sb->nr_devices, nr); i++)
		member_to_text(out, bch2_members_v1_get(mi, i), gi, sb, i);
}

const struct bch_sb_field_ops bch_sb_field_ops_members_v1 = {
	.validate	= bch2_sb_members_v1_validate,
	.to_text	= bch2_sb_members_v1_to_text,
};

static void bch2_sb_members_v2_to_text(struct printbuf *out, struct bch_sb *sb,
				       struct bch_sb_field *f)
{
	struct bch_sb_field_members_v2 *mi = field_to_type(f, members_v2);
	struct bch_sb_field_disk_groups *gi = bch2_sb_field_get(sb, disk_groups);

	if (vstruct_end(&mi->field) <= (void *) &mi->_members[0]) {
		prt_printf(out, "field ends before start of entries");
		return;
	}

	if (!le16_to_cpu(mi->member_bytes)) {
		prt_printf(out, "member_bytes 0");
		return;
	}

	unsigned nr = (vstruct_end(&mi->field) - (void *) &mi->_members[0]) / le16_to_cpu(mi->member_bytes);
	if (nr != sb->nr_devices)
		prt_printf(out, "nr_devices mismatch: have %i entries, should be %u", nr, sb->nr_devices);

	/*
	 * We call to_text() on superblock sections that haven't passed
	 * validate, so we can't trust sb->nr_devices.
	 */

	for (unsigned i = 0; i < min(sb->nr_devices, nr); i++)
		member_to_text(out, bch2_members_v2_get(mi, i), gi, sb, i);
}

static int bch2_sb_members_v2_validate(struct bch_sb *sb, struct bch_sb_field *f,
				enum bch_validate_flags flags, struct printbuf *err)
{
	struct bch_sb_field_members_v2 *mi = field_to_type(f, members_v2);
	size_t mi_bytes = (void *) __bch2_members_v2_get_mut(mi, sb->nr_devices) -
		(void *) mi;

	if (mi_bytes > vstruct_bytes(&mi->field)) {
		prt_printf(err, "section too small (%zu > %zu)",
			   mi_bytes, vstruct_bytes(&mi->field));
		return -BCH_ERR_invalid_sb_members;
	}

	for (unsigned i = 0; i < sb->nr_devices; i++)
		try(validate_member(err, bch2_members_v2_get(mi, i), sb, i));

	return 0;
}

const struct bch_sb_field_ops bch_sb_field_ops_members_v2 = {
	.validate	= bch2_sb_members_v2_validate,
	.to_text	= bch2_sb_members_v2_to_text,
};

void bch2_sb_members_from_cpu(struct bch_fs *c)
{
	struct bch_sb_field_members_v2 *mi = bch2_sb_field_get(c->disk_sb.sb, members_v2);

	guard(rcu)();
	for_each_member_device_rcu(c, ca, NULL) {
		struct bch_member *m = __bch2_members_v2_get_mut(mi, ca->dev_idx);

		for (unsigned e = 0; e < BCH_MEMBER_ERROR_NR; e++)
			m->errors[e] = cpu_to_le64(atomic64_read(&ca->errors[e]));
	}
}

void bch2_sb_members_to_cpu(struct bch_fs *c)
{
	for_each_member_device(c, ca) {
		struct bch_member m = bch2_sb_member_get(c->disk_sb.sb, ca->dev_idx);
		ca->mi = bch2_mi_to_cpu(&m);

		mod_bit(ca->dev_idx, c->devs_rotational.d, ca->mi.rotational);
	}

	struct bch_sb_field_members_v2 *mi2 = bch2_sb_field_get(c->disk_sb.sb, members_v2);
	if (mi2)
		for (unsigned i = 0; i < c->sb.nr_devices; i++) {
			struct bch_member m = bch2_members_v2_get(mi2, i);
			bool removed = uuid_equal(&m.uuid, &BCH_SB_MEMBER_DELETED_UUID);
			mod_bit(i, c->devs_removed.d, removed);
		}
}

void bch2_dev_io_errors_to_text(struct printbuf *out, struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	struct bch_member m;

	scoped_guard(mutex, &ca->fs->sb_lock)
		m = bch2_sb_member_get(c->disk_sb.sb, ca->dev_idx);

	printbuf_tabstop_push(out, 12);

	prt_str(out, "IO errors since filesystem creation");
	prt_newline(out);

	scoped_guard(printbuf_indent, out)
		for (unsigned i = 0; i < BCH_MEMBER_ERROR_NR; i++)
			prt_printf(out, "%s:\t%llu\n", bch2_member_error_strs[i], atomic64_read(&ca->errors[i]));

	prt_str(out, "IO errors since ");
	bch2_pr_time_units(out, (ktime_get_real_seconds() - le64_to_cpu(m.errors_reset_time)) * NSEC_PER_SEC);
	prt_str(out, " ago");
	prt_newline(out);

	scoped_guard(printbuf_indent, out)
		for (unsigned i = 0; i < BCH_MEMBER_ERROR_NR; i++)
			prt_printf(out, "%s:\t%llu\n", bch2_member_error_strs[i],
				   atomic64_read(&ca->errors[i]) - le64_to_cpu(m.errors_at_reset[i]));
}

void bch2_dev_errors_reset(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;

	guard(mutex)(&c->sb_lock);

	struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);
	for (unsigned i = 0; i < ARRAY_SIZE(m->errors_at_reset); i++)
		m->errors_at_reset[i] = cpu_to_le64(atomic64_read(&ca->errors[i]));
	m->errors_reset_time = cpu_to_le64(ktime_get_real_seconds());

	bch2_write_super(c);
}

/*
 * Per member "range has btree nodes" bitmap:
 *
 * This is so that if we ever have to run the btree node scan to repair we don't
 * have to scan full devices:
 */

static bool __bch2_dev_btree_bitmap_marked(struct bch_fs *c, struct bkey_s_c k, bool with_gc)
{
	guard(rcu)();
	bkey_for_each_ptr(bch2_bkey_ptrs_c(k), ptr) {
		struct bch_dev *ca = bch2_dev_rcu_noerror(c, ptr->dev);
		if (ca &&
		    !__bch2_dev_btree_bitmap_marked_sectors(ca, ptr->offset, btree_sectors(c), with_gc))
			return false;
	}
	return true;
}

bool bch2_dev_btree_bitmap_marked(struct bch_fs *c, struct bkey_s_c k)
{
	return __bch2_dev_btree_bitmap_marked(c, k, true);
}

bool bch2_dev_btree_bitmap_marked_nogc(struct bch_fs *c, struct bkey_s_c k)
{
	return __bch2_dev_btree_bitmap_marked(c, k, false);
}

static void __bch2_dev_btree_bitmap_mark(struct bch_dev *ca,
					 struct bch_sb_field_members_v2 *mi,
					 u64 start, unsigned sectors, bool *write_sb)
{
	struct bch_member *m = __bch2_members_v2_get_mut(mi, ca->dev_idx);

	u64 end = start + sectors;

	int resize = ilog2(roundup_pow_of_two(end)) - (m->btree_bitmap_shift + 6);
	if (resize > 0) {
		u64 old_bitmap = le64_to_cpu(m->btree_allocated_bitmap);
		u64 new_bitmap = 0;
		u64 new_gc_bitmap = 0;

		for (unsigned i = 0; i < 64; i++) {
			if (old_bitmap & BIT_ULL(i))
				new_bitmap |= BIT_ULL(i >> resize);
			if (ca->btree_allocated_bitmap_gc & BIT_ULL(i))
				new_gc_bitmap |= BIT_ULL(i >> resize);
		}

		m->btree_allocated_bitmap = cpu_to_le64(new_bitmap);
		m->btree_bitmap_shift += resize;
		*write_sb = true;

		ca->btree_allocated_bitmap_gc = new_gc_bitmap;
	}

	BUG_ON(m->btree_bitmap_shift >= BCH_MI_BTREE_BITMAP_SHIFT_MAX);
	BUG_ON(end > 64ULL << m->btree_bitmap_shift);

	for (unsigned bit = start >> m->btree_bitmap_shift;
	     (u64) bit << m->btree_bitmap_shift < end;
	     bit++) {
		__le64 b = cpu_to_le64(BIT_ULL(bit));

		if (!(m->btree_allocated_bitmap & b)) {
			m->btree_allocated_bitmap |= b;
			*write_sb = true;
		}

		ca->btree_allocated_bitmap_gc |= BIT_ULL(bit);
	}
}

void bch2_dev_btree_bitmap_mark_locked(struct bch_fs *c, struct bkey_s_c k, bool *write_sb)
{
	lockdep_assert_held(&c->sb_lock);

	struct bch_sb_field_members_v2 *mi = bch2_sb_field_get(c->disk_sb.sb, members_v2);

	guard(rcu)();
	bkey_for_each_ptr(bch2_bkey_ptrs_c(k), ptr) {
		struct bch_dev *ca = bch2_dev_rcu_noerror(c, ptr->dev);
		if (!ca)
			continue;

		__bch2_dev_btree_bitmap_mark(ca, mi, ptr->offset, btree_sectors(c), write_sb);
	}
}

void bch2_dev_btree_bitmap_mark(struct bch_fs *c, struct bkey_s_c k)
{
	guard(mutex)(&c->sb_lock);
	bool write_sb = false;
	bch2_dev_btree_bitmap_mark_locked(c, k, &write_sb);
	if (write_sb)
		bch2_write_super(c);
}

static int btree_bitmap_gc_btree_level(struct btree_trans *trans,
				       struct progress_indicator *progress,
				       enum btree_id btree, unsigned level)
{
	struct bch_fs *c = trans->c;
	CLASS(btree_node_iter, iter)(trans, btree, POS_MIN, 0, level, BTREE_ITER_prefetch);

	try(for_each_btree_key_continue(trans, iter, 0, k, ({
		if (!bch2_dev_btree_bitmap_marked(c, k))
			bch2_dev_btree_bitmap_mark(c, k);

		bch2_progress_update_iter(trans, progress, &iter, "btree_bitmap_gc");
	})));

	return 0;
}

int bch2_btree_bitmap_gc(struct bch_fs *c)
{
	struct progress_indicator progress;
	bch2_progress_init_inner(&progress, c, 0, ~0ULL);

	scoped_guard(mutex, &c->sb_lock) {
		guard(rcu)();
		for_each_member_device_rcu(c, ca, NULL)
			ca->btree_allocated_bitmap_gc = 0;
	}

	{
		CLASS(btree_trans, trans)(c);

		for (unsigned btree = 0; btree < btree_id_nr_alive(c); btree++) {
			for (unsigned level = 1; level < BTREE_MAX_DEPTH; level++)
				try(btree_bitmap_gc_btree_level(trans, &progress, btree, level));

			CLASS(btree_node_iter, iter)(trans, btree, POS_MIN, 0,
						     bch2_btree_id_root(c, btree)->b->c.level, 0);
			struct btree *b;
			try(lockrestart_do(trans, PTR_ERR_OR_ZERO(b = bch2_btree_iter_peek_node(&iter))));

			if (!bch2_dev_btree_bitmap_marked(c, bkey_i_to_s_c(&b->key)))
				bch2_dev_btree_bitmap_mark(c, bkey_i_to_s_c(&b->key));
		}
	}

	u64 sectors_marked_old = 0, sectors_marked_new = 0;

	scoped_guard(mutex, &c->sb_lock) {
		struct bch_sb_field_members_v2 *mi = bch2_sb_field_get(c->disk_sb.sb, members_v2);

		scoped_guard(rcu)
			for_each_member_device_rcu(c, ca, NULL) {
				sectors_marked_old += hweight64(ca->mi.btree_allocated_bitmap) << ca->mi.btree_bitmap_shift;
				sectors_marked_new += hweight64(ca->btree_allocated_bitmap_gc) << ca->mi.btree_bitmap_shift;

				struct bch_member *m = __bch2_members_v2_get_mut(mi, ca->dev_idx);
				m->btree_allocated_bitmap = cpu_to_le64(ca->btree_allocated_bitmap_gc);
			}
		bch2_write_super(c);
	}

	CLASS(printbuf, buf)();
	prt_str(&buf, "mi_btree_bitmap sectors ");
	prt_human_readable_u64(&buf, sectors_marked_old << 9);
	prt_str(&buf, " -> ");
	prt_human_readable_u64(&buf, sectors_marked_new << 9);
	bch_info(c, "%s", buf.buf);

	return 0;
}

static void bch2_maybe_schedule_btree_bitmap_gc_work(struct work_struct *work)
{
	struct bch_fs *c = container_of(work, struct bch_fs, maybe_schedule_btree_bitmap_gc.work);

	if (bch2_recovery_pass_want_ratelimit(c, BCH_RECOVERY_PASS_btree_bitmap_gc, 1000))
		return;

	CLASS(printbuf, buf)();
	bch2_log_msg_start(c, &buf);

	bool want_schedule = false;
	for_each_member_device(c, ca) {
		struct bch_dev_usage u;
		bch2_dev_usage_read_fast(ca, &u);

		u64 btree_sectors = bucket_to_sector(ca, u.buckets[BCH_DATA_btree]);
		u64 bitmap_sectors = hweight64(ca->mi.btree_allocated_bitmap) << ca->mi.btree_bitmap_shift;

		if (btree_sectors * 4 < bitmap_sectors) {
			prt_printf(&buf, "%s has ", ca->name);
			prt_human_readable_u64(&buf, btree_sectors << 9);
			prt_printf(&buf, " btree buckets and ");
			prt_human_readable_u64(&buf, bitmap_sectors << 9);
			prt_printf(&buf, " marked in bitmap\n");
			want_schedule = true;
		}
	}

	if (want_schedule) {
		bch2_run_explicit_recovery_pass(c, &buf,
			BCH_RECOVERY_PASS_btree_bitmap_gc,
			RUN_RECOVERY_PASS_ratelimit);
		bch2_print_str(c, KERN_NOTICE, buf.buf);
	}

	queue_delayed_work(system_long_wq, &c->maybe_schedule_btree_bitmap_gc, HZ * 60 * 60 * 24);
}

void bch2_maybe_schedule_btree_bitmap_gc_stop(struct bch_fs *c)
{
	cancel_delayed_work_sync(&c->maybe_schedule_btree_bitmap_gc);
}

void bch2_maybe_schedule_btree_bitmap_gc(struct bch_fs *c)
{
	INIT_DELAYED_WORK(&c->maybe_schedule_btree_bitmap_gc,
			  bch2_maybe_schedule_btree_bitmap_gc_work);
	bch2_maybe_schedule_btree_bitmap_gc_work(&c->maybe_schedule_btree_bitmap_gc.work);
}

unsigned bch2_sb_nr_devices(const struct bch_sb *sb)
{
	unsigned nr = 0;

	for (unsigned i = 0; i < sb->nr_devices; i++)
		nr += bch2_member_exists((struct bch_sb *) sb, i);
	return nr;
}

static int bch2_sb_member_find_slot(struct bch_fs *c)
{
	int best = -1;
	u64 best_last_mount = 0;
	unsigned nr_deleted = 0;

	if (c->sb.nr_devices < BCH_SB_MEMBERS_MAX)
		return c->sb.nr_devices;

	for (unsigned dev_idx = 0; dev_idx < BCH_SB_MEMBERS_MAX; dev_idx++) {
		/* eventually BCH_SB_MEMBERS_MAX will be raised */
		if (dev_idx == BCH_SB_MEMBER_INVALID)
			continue;

		struct bch_member m = bch2_sb_member_get(c->disk_sb.sb, dev_idx);

		nr_deleted += uuid_equal(&m.uuid, &BCH_SB_MEMBER_DELETED_UUID);

		if (!bch2_is_zero(&m.uuid, sizeof(m.uuid)))
			continue;

		u64 last_mount = le64_to_cpu(m.last_mount);
		if (best < 0 || last_mount < best_last_mount) {
			best = dev_idx;
			best_last_mount = last_mount;
		}
	}
	if (best >= 0)
		return best;

	if (nr_deleted)
		bch_err(c, "unable to allocate new member, but have %u deleted: run fsck",
			nr_deleted);

	return -BCH_ERR_ENOSPC_sb_members;
}

int bch2_sb_member_alloc(struct bch_fs *c)
{
	int dev_idx = bch2_sb_member_find_slot(c);
	if (dev_idx < 0)
		return dev_idx;

	struct bch_sb_field_members_v2 *mi = bch2_sb_field_get(c->disk_sb.sb, members_v2);

	unsigned nr_devices = max_t(unsigned, dev_idx + 1, c->sb.nr_devices);
	unsigned u64s = DIV_ROUND_UP(sizeof(struct bch_sb_field_members_v2) +
			    le16_to_cpu(mi->member_bytes) * nr_devices, sizeof(u64));

	mi = bch2_sb_field_resize(&c->disk_sb, members_v2, u64s);
	if (!mi)
		return -BCH_ERR_ENOSPC_sb_members;

	c->disk_sb.sb->nr_devices = nr_devices;
	return dev_idx;
}

void bch2_sb_members_clean_deleted(struct bch_fs *c)
{
	guard(mutex)(&c->sb_lock);
	bool write_sb = false;

	for (unsigned i = 0; i < c->sb.nr_devices; i++) {
		struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, i);

		if (uuid_equal(&m->uuid, &BCH_SB_MEMBER_DELETED_UUID)) {
			memset(&m->uuid, 0, sizeof(m->uuid));
			write_sb = true;
		}
	}

	if (write_sb)
		bch2_write_super(c);
}

void __bch2_dev_mi_field_upgrades(struct bch_fs *c, struct bch_dev *ca, bool *write_sb)
{
	struct bch_member *m = bch2_members_v2_get_mut(c->disk_sb.sb, ca->dev_idx);

	if (!BCH_MEMBER_ROTATIONAL_SET(m)) {
		SET_BCH_MEMBER_ROTATIONAL(m, !bdev_nonrot(ca->disk_sb.bdev));
		SET_BCH_MEMBER_ROTATIONAL_SET(m, true);
		*write_sb = true;
	}
}

void bch2_dev_mi_field_upgrades(struct bch_dev *ca)
{
	struct bch_fs *c = ca->fs;
	guard(mutex)(&c->sb_lock);
	bool write_sb = false;

	__bch2_dev_mi_field_upgrades(c, ca, &write_sb);

	if (write_sb)
		bch2_write_super(c);
}

/*
 * Set BCH_MEMBER_ROTATIONAL, if it hasn't been initialized
 */
void bch2_fs_mi_field_upgrades(struct bch_fs *c)
{
	guard(mutex)(&c->sb_lock);
	bool write_sb = false;

	scoped_guard(rcu)
		for_each_online_member_rcu(c, ca)
			__bch2_dev_mi_field_upgrades(c, ca, &write_sb);

	if (write_sb)
		bch2_write_super(c);
}
