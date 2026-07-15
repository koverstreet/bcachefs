// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/disk_groups.h"
#include "alloc/replicas.h"

#include "data/checksum.h"
#include "data/extents_sb.h"

#include "journal/journal.h"
#include "journal/sb.h"
#include "journal/seq_blacklist.h"

#include "fs/quota.h"

#include "init/dev.h"
#include "init/error.h"
#include "init/fs.h"
#include "init/passes.h"

#include "sb/clean.h"
#include "sb/counters.h"
#include "sb/downgrade.h"
#include "sb/errors.h"
#include "sb/members.h"
#include "sb/io.h"

#include "util/vstructs.h"

/* DOC_LATEX(superblock)
 * \subsubsection{Layout and redundancy}
 *
 * The primary superblock is located at sector 8 (4\,KB from the start of the
 * device). A \texttt{bch\_sb\_layout} structure at sector 7 records the locations
 * of all superblock copies---typically three: the primary, one immediately
 * following it, and one at the end of the device. Up to 61 backup locations can
 * be recorded. The layout structure has its own magic number so that it can be
 * found independently.
 *
 * Only the primary superblock and the layout structure are at fixed,
 * known-without-context offsets. Backup superblock locations are recorded only
 * inside the layout (and inside each superblock's own embedded layout copy);
 * recovery from a lost layout therefore requires either falling back to a
 * second known offset, or scanning the device. The end-of-device backup is at
 * an offset computable from the device size, which gives a second escape valve
 * when sector 7 itself is unreadable.
 *
 * The layout structure is intentionally minimal---a magic number, a small
 * offset table, no checksum---and lives in its own 512-byte sector so that it
 * shares a physical block with as little else as possible. All checksumming
 * and validation logic lives in the superblock itself. The embedded
 * \texttt{bch\_sb\_layout} inside each superblock is what's used in the
 * common case (the standalone copy at sector 7 is consulted only when the
 * primary superblock cannot be read).
 *
 * The superblock is written with a monotonically increasing sequence number
 * (\texttt{seq}); on read, the copy with the highest valid sequence number is
 * authoritative. The \texttt{bcachefs recover-super} command can reconstruct a
 * device's superblock from backup copies or from another device in the same
 * filesystem.
 *
 * \subsubsection{Threat model}
 *
 * Redundancy exists to survive several distinct failure modes, in roughly
 * descending order of how often they're observed in practice:
 *
 * \begin{itemize}
 * \item \textbf{Torn writes during power loss}. The actual superblock size
 *   varies---a few kilobytes on a single-device laptop filesystem, larger on
 *   big multi-device filesystems---but is generally well beyond a single
 *   sector or physical block, and the on-disk reservation can grow to 32\,MB.
 *   That's beyond any device's atomic write granularity, so power loss
 *   mid-write can leave a torn superblock; the checksum catches it and a
 *   backup is consulted. This was the original driver for redundant
 *   superblocks.
 * \item \textbf{Media errors and bit rot}. Bad sectors, single-sector unrecoverable
 *   reads, slow long-term decay on backup copies that are written infrequently.
 *   Front-of-device and end-of-device backups are physically separated on
 *   rotating media, providing some independence.
 * \item \textbf{Legacy bootloader coexistence and large physical block sizes}.
 *   Sector 7 is adjacent to sector 0 (where ancient-style bootloaders live)
 *   and the start of the primary superblock (sector 8). On disks with logical
 *   sector size 512 and physical block size $\geq$\,4\,KB---increasingly
 *   common, especially on SSDs reporting 8\,KB or 16\,KB physical blocks---a
 *   sub-physical-block write triggers a read-modify-write of the whole
 *   physical block. A torn RMW on physical block 0 can take out the boot
 *   sector, the layout, and the start of the primary superblock together.
 *   The end-of-device backup superblock is the escape valve here, since it
 *   lives in its own physical block far away.
 * \item \textbf{Whole-device failure}. A single device dropping out: covered
 *   trivially by replication of the filesystem-wide state across all member
 *   devices' superblocks.
 * \end{itemize}
 *
 * \subsubsection{Fixed fields}
 *
 * The superblock header contains:
 *
 * \begin{itemize}
 * \item \textbf{Identity}: filesystem UUID (immutable), user-visible UUID
 *   (mutable), filesystem label (up to 32 bytes)
 * \item \textbf{Geometry}: block size, btree node size, number of devices
 * \item \textbf{Versioning}: current metadata version, minimum version of any
 *   data still on disk (see the Metadata versions section)
 * \item \textbf{State}: initialized and clean flags, sequence number, write
 *   timestamp
 * \item \textbf{Options}: all persistent filesystem options are encoded as
 *   bitfields in the superblock flags---replication counts, checksum and
 *   compression types, error handling policy, targets, quotas, journal
 *   parameters, and more. Mount options override these at runtime;
 *   \texttt{bcachefs set-fs-option} persists changes.
 * \end{itemize}
 *
 * \subsubsection{Variable-length fields}
 *
 * The superblock is extensible via type-tagged variable-length fields
 * (\texttt{BCH\_SB\_FIELD\_*}). Some are per-device (journal bucket lists);
 * most are shared across all devices (members, encryption, replicas, disk
 * groups, error log, recovery state). See the On disk format section for the
 * complete field list.
 *
 * Key fields for operators:
 *
 * \begin{description}
 * \item[\texttt{members\_v2}] Per-\hyperref[sec:devices]{device} metadata: UUID,
 *   bucket count and size, state (rw/ro/evacuating/spare), durability,
 *   data-type restrictions, error counters, performance measurements, and
 *   hardware identifiers.
 * \item[\texttt{disk\_groups}] Device label hierarchy and group definitions,
 *   used for target-based allocation (see
 *   \hyperref[sec:disk-groups]{Device labels and targets}).
 * \item[\texttt{replicas}] All unique replication configurations in the
 *   filesystem (see Replicas tracking).
 * \item[\texttt{clean}] Written on clean shutdown: contains btree roots and
 *   usage counters, allowing the next mount to skip
 *   \hyperref[sec:journal]{journal} replay entirely.
 * \item[\texttt{errors}] Persistent error log recording operational errors and
 *   fsck findings across mounts.
 * \item[\texttt{ext}] Extended metadata including required recovery passes and
 *   silenced errors.
 * \end{description}
 *
 * \subsubsection{Version upgrades}
 *
 * The superblock records both the current metadata version and the minimum
 * version of any data still on disk. This two-version scheme allows the
 * filesystem to upgrade incrementally: new data is written with the current
 * version while old data retains the format it was written with. The
 * \texttt{version\_upgrade} option controls upgrade behavior at mount time:
 * \texttt{compatible} (allow new features), \texttt{incompatible} (upgrade to
 * latest), or \texttt{none} (don't upgrade). Downgrade information is stored
 * separately so that a filesystem can be safely used by older tools after an
 * upgrade if no incompatible features have been used.
 *
 * \subsubsection{Consistency and self-healing}
 *
 * Every superblock copy is checksummed; reads validate the checksum and fall
 * back to alternative copies on failure. The sequence number provides
 * unambiguous ordering when copies disagree. The \texttt{recover-super} command
 * can reconstruct a completely overwritten superblock from the backup copies on
 * the same device or from any other device in the filesystem. Recovery passes
 * \texttt{check\_alloc\_info} and \texttt{check\_topology} verify that
 * superblock-recorded state matches the actual on-disk data.
 */

#include <linux/backing-dev.h>
#include <linux/sort.h>
#include <linux/string_choices.h>

struct bch2_metadata_version {
	u16		version;
	const char	*name;
};

static const struct bch2_metadata_version bch2_metadata_versions[] = {
#define x(n, v, ...) {		\
	.version = v,				\
	.name = #n,				\
},
	BCH_METADATA_VERSIONS()
#undef x
};

void bch2_version_to_text(struct printbuf *out, enum bcachefs_metadata_version v)
{
	const char *str = "(unknown version)";

	for (unsigned i = 0; i < ARRAY_SIZE(bch2_metadata_versions); i++)
		if (bch2_metadata_versions[i].version == v) {
			str = bch2_metadata_versions[i].name;
			break;
		}

	prt_printf(out, "%s (%u.%u)", str, BCH_VERSION_MAJOR(v), BCH_VERSION_MINOR(v));
}

enum bcachefs_metadata_version bch2_latest_compatible_version(enum bcachefs_metadata_version v)
{
	if (!BCH_VERSION_MAJOR(v))
		return v;

	for (unsigned i = 0; i < ARRAY_SIZE(bch2_metadata_versions); i++)
		if (bch2_metadata_versions[i].version > v &&
		    BCH_VERSION_MAJOR(bch2_metadata_versions[i].version) ==
		    BCH_VERSION_MAJOR(v))
			v = bch2_metadata_versions[i].version;

	return v;
}

int bch2_set_version_incompat(struct bch_fs *c, enum bcachefs_metadata_version version)
{
	if (((c->sb.features & BIT_ULL(BCH_FEATURE_incompat_version_field)) &&
	     version <= c->sb.version_incompat_allowed)) {
		guard(memalloc_flags)(PF_MEMALLOC_NOFS);
		guard(mutex)(&c->sb_lock);

		if (version > c->sb.version_incompat) {
			SET_BCH_SB_VERSION_INCOMPAT(c->disk_sb.sb,
				max(BCH_SB_VERSION_INCOMPAT(c->disk_sb.sb), version));
			bch2_write_super(c);
		}
		return 0;
	} else {
		BUILD_BUG_ON(BCH_VERSION_MAJOR(bcachefs_metadata_version_current) != 1);

		unsigned minor = BCH_VERSION_MINOR(version);

		if (!test_bit(minor, c->incompat_versions_requested) &&
		    !test_and_set_bit(minor, c->incompat_versions_requested)) {
			CLASS(printbuf, buf)();
			prt_str(&buf, "requested incompat feature ");
			bch2_version_to_text(&buf, version);
			prt_str(&buf, " currently not enabled, allowed up to ");
			bch2_version_to_text(&buf, c->sb.version_incompat_allowed);
			prt_printf(&buf, "\n  set version_upgrade=incompatible to enable");

			bch_notice(c, "%s", buf.buf);
		}

		return bch_err_throw(c, may_not_use_incompat_feature);
	}
}

const char * const bch2_sb_fields[] = {
#define x(name, nr, ...)	#name,
	BCH_SB_FIELDS()
#undef x
	NULL
};

static int bch2_sb_field_validate(struct bch_sb *, struct bch_sb_field *,
				  enum bch_validate_flags, struct printbuf *);

struct bch_sb_field *bch2_sb_field_get_id(struct bch_sb *sb,
				      enum bch_sb_field_type type)
{
	/* XXX: need locking around superblock to access optional fields */

	vstruct_for_each(sb, f)
		if (le32_to_cpu(f->type) == type)
			return f;
	return NULL;
}

static struct bch_sb_field *__bch2_sb_field_resize(struct bch_sb_handle *sb,
						   struct bch_sb_field *f,
						   unsigned u64s)
{
	unsigned old_u64s = f ? le32_to_cpu(f->u64s) : 0;
	unsigned sb_u64s = le32_to_cpu(sb->sb->u64s) + u64s - old_u64s;

	BUG_ON(__vstruct_bytes(struct bch_sb, sb_u64s) > sb->buffer_size);

	if (!f && !u64s) {
		/* nothing to do: */
	} else if (!f) {
		f = vstruct_last(sb->sb);
		memset(f, 0, sizeof(u64) * u64s);
		f->u64s = cpu_to_le32(u64s);
		f->type = 0;
	} else {
		void *src, *dst;

		src = vstruct_end(f);

		if (u64s) {
			f->u64s = cpu_to_le32(u64s);
			dst = vstruct_end(f);
		} else {
			dst = f;
		}

		memmove(dst, src, vstruct_end(sb->sb) - src);

		if (dst > src)
			memset(src, 0, dst - src);
	}

	sb->sb->u64s = cpu_to_le32(sb_u64s);

	return u64s ? f : NULL;
}

void bch2_sb_field_delete(struct bch_sb_handle *sb,
			  enum bch_sb_field_type type)
{
	struct bch_sb_field *f = bch2_sb_field_get_id(sb->sb, type);

	if (f)
		__bch2_sb_field_resize(sb, f, 0);
}

/* Superblock realloc/free: */

void bch2_free_super(struct bch_sb_handle *sb)
{
	kfree(sb->bio);
	if (!IS_ERR_OR_NULL(sb->s_bdev_file))
		bdev_fput(sb->s_bdev_file);
	kfree(sb->holder);
	kfree(sb->sb_name);

	kvfree(sb->sb);
	memset(sb, 0, sizeof(*sb));
}

int bch2_sb_realloc(struct bch_sb_handle *sb, unsigned u64s)
{
	size_t new_bytes = __vstruct_bytes(struct bch_sb, u64s);
	size_t new_buffer_size;
	struct bch_sb *new_sb;
	struct bio *bio;

	if (sb->bdev)
		new_bytes = max_t(size_t, new_bytes, bdev_logical_block_size(sb->bdev));

	new_buffer_size = roundup_pow_of_two(new_bytes);

	if (sb->sb && sb->buffer_size >= new_buffer_size)
		return 0;

	if (sb->sb && sb->have_layout) {
		u64 max_bytes = 512 << sb->sb->layout.sb_max_size_bits;

		if (new_bytes > max_bytes) {
			CLASS(printbuf, buf)();

			prt_bdevname(&buf, sb->bdev);
			prt_printf(&buf, ": superblock too big: want %zu but have %llu", new_bytes, max_bytes);
			pr_err("%s", buf.buf);
			return -BCH_ERR_ENOSPC_sb;
		}
	}

	if (sb->buffer_size >= new_buffer_size && sb->sb)
		return 0;

	if (dynamic_fault("bcachefs:add:super_realloc"))
		return -BCH_ERR_ENOMEM_sb_realloc_injected;

	new_sb = kvrealloc(sb->sb, new_buffer_size, GFP_NOFS|__GFP_ZERO);
	if (!new_sb)
		return -BCH_ERR_ENOMEM_sb_buf_realloc;

	sb->sb = new_sb;

	if (sb->have_bio) {
		unsigned nr_bvecs = buf_nr_bvecs(sb->sb, new_buffer_size);

		bio = bio_kmalloc(nr_bvecs, GFP_KERNEL);
		if (!bio)
			return -BCH_ERR_ENOMEM_sb_bio_realloc;

		bio_init(bio, NULL, bio_inline_vecs(bio), nr_bvecs, 0);

		kfree(sb->bio);
		sb->bio = bio;
	}

	sb->buffer_size = new_buffer_size;

	return 0;
}

struct bch_sb_field *bch2_sb_field_resize_id(struct bch_sb_handle *sb,
					  enum bch_sb_field_type type,
					  unsigned u64s)
{
	struct bch_sb_field *f = bch2_sb_field_get_id(sb->sb, type);
	ssize_t old_u64s = f ? le32_to_cpu(f->u64s) : 0;
	ssize_t d = -old_u64s + u64s;

	if (bch2_sb_realloc(sb, le32_to_cpu(sb->sb->u64s) + d))
		return NULL;

	if (sb->fs_sb) {
		struct bch_fs *c = container_of(sb, struct bch_fs, disk_sb);

		lockdep_assert_held(&c->sb_lock);

		/* XXX: we're not checking that offline device have enough space */

		for_each_online_member(c, ca, BCH_DEV_READ_REF_sb_field_resize) {
			struct bch_sb_handle *dev_sb = &ca->disk_sb;

			if (bch2_sb_realloc(dev_sb, le32_to_cpu(dev_sb->sb->u64s) + d)) {
				enumerated_ref_put(&ca->io_ref[READ], BCH_DEV_READ_REF_sb_field_resize);
				return NULL;
			}
		}
	}

	f = bch2_sb_field_get_id(sb->sb, type);
	f = __bch2_sb_field_resize(sb, f, u64s);
	if (f)
		f->type = cpu_to_le32(type);
	return f;
}

struct bch_sb_field *bch2_sb_field_get_minsize_id(struct bch_sb_handle *sb,
						  enum bch_sb_field_type type,
						  unsigned u64s)
{
	struct bch_sb_field *f = bch2_sb_field_get_id(sb->sb, type);

	if (!f || le32_to_cpu(f->u64s) < u64s)
		f = bch2_sb_field_resize_id(sb, type, u64s);
	return f;
}

/* Superblock validate: */

static int validate_sb_layout(struct bch_sb_layout *layout, struct printbuf *out)
{
	u64 offset, prev_offset, max_sectors;
	unsigned i;

	BUILD_BUG_ON(sizeof(struct bch_sb_layout) != 512);

	if (!uuid_equal(&layout->magic, &BCACHE_MAGIC) &&
	    !uuid_equal(&layout->magic, &BCHFS_MAGIC)) {
		prt_printf(out, "Not a bcachefs superblock layout");
		return -BCH_ERR_invalid_sb_layout;
	}

	if (layout->layout_type != 0) {
		prt_printf(out, "Invalid superblock layout type %u",
		       layout->layout_type);
		return -BCH_ERR_invalid_sb_layout_type;
	}

	if (!layout->nr_superblocks) {
		prt_printf(out, "Invalid superblock layout: no superblocks");
		return -BCH_ERR_invalid_sb_layout_nr_superblocks;
	}

	if (layout->nr_superblocks > ARRAY_SIZE(layout->sb_offset)) {
		prt_printf(out, "Invalid superblock layout: too many superblocks");
		return -BCH_ERR_invalid_sb_layout_nr_superblocks;
	}

	if (layout->sb_max_size_bits > BCH_SB_LAYOUT_SIZE_BITS_MAX) {
		prt_printf(out, "Invalid superblock layout: max_size_bits too high");
		return -BCH_ERR_invalid_sb_layout_sb_max_size_bits;
	}

	max_sectors = 1 << layout->sb_max_size_bits;

	prev_offset = le64_to_cpu(layout->sb_offset[0]);

	for (i = 1; i < layout->nr_superblocks; i++) {
		offset = le64_to_cpu(layout->sb_offset[i]);

		if (offset < prev_offset + max_sectors) {
			prt_printf(out, "Invalid superblock layout: superblocks overlap\n"
			       "  (sb %u ends at %llu next starts at %llu",
			       i - 1, prev_offset + max_sectors, offset);
			return -BCH_ERR_invalid_sb_layout_superblocks_overlap;
		}
		prev_offset = offset;
	}

	return 0;
}

static int bch2_sb_compatible(struct bch_sb *sb, struct printbuf *out)
{
	u16 version		= le16_to_cpu(sb->version);
	u16 version_min		= le16_to_cpu(sb->version_min);

	if (!bch2_version_compatible(version)) {
		prt_str(out, "Unsupported superblock version ");
		bch2_version_to_text(out, version);
		prt_str(out, " (min ");
		bch2_version_to_text(out, bcachefs_metadata_version_min);
		prt_str(out, ", max ");
		bch2_version_to_text(out, bcachefs_metadata_version_current);
		prt_str(out, ")");
		return -BCH_ERR_invalid_sb_version;
	}

	if (!bch2_version_compatible(version_min)) {
		prt_str(out, "Unsupported superblock version_min ");
		bch2_version_to_text(out, version_min);
		prt_str(out, " (min ");
		bch2_version_to_text(out, bcachefs_metadata_version_min);
		prt_str(out, ", max ");
		bch2_version_to_text(out, bcachefs_metadata_version_current);
		prt_str(out, ")");
		return -BCH_ERR_invalid_sb_version;
	}

	if (version_min > version) {
		prt_str(out, "Bad minimum version ");
		bch2_version_to_text(out, version_min);
		prt_str(out, ", greater than version field ");
		bch2_version_to_text(out, version);
		return -BCH_ERR_invalid_sb_version;
	}

	return 0;
}

int bch2_sb_validate(struct bch_sb *sb, struct bch_opts *opts, u64 read_offset,
		     enum bch_validate_flags flags, struct printbuf *out)
{
	try(bch2_sb_compatible(sb, out));

	if (!opts->no_version_check) {
		u64 incompat = le64_to_cpu(sb->features[0]) & (~0ULL << BCH_FEATURE_NR);
		unsigned incompat_bit = 0;
		if (incompat)
			incompat_bit = __ffs64(incompat);
		else if (sb->features[1])
			incompat_bit = 64 + __ffs64(le64_to_cpu(sb->features[1]));

		if (incompat_bit) {
			prt_printf(out, "Filesystem has incompatible feature bit %u, highest supported %s (%u)",
				   incompat_bit,
				   bch2_sb_features[BCH_FEATURE_NR - 1],
				   BCH_FEATURE_NR - 1);
			return -BCH_ERR_invalid_sb_features;
		}

		if (BCH_VERSION_MAJOR(le16_to_cpu(sb->version)) > BCH_VERSION_MAJOR(bcachefs_metadata_version_current) ||
		    BCH_SB_VERSION_INCOMPAT(sb) > bcachefs_metadata_version_current) {
			prt_str(out, "Filesystem has incompatible version ");
			bch2_version_to_text(out, le16_to_cpu(sb->version));
			prt_str(out, ", current version ");
			bch2_version_to_text(out, bcachefs_metadata_version_current);
			return -BCH_ERR_invalid_sb_features;
		}
	}

	if (bch2_is_zero(sb->user_uuid.b, sizeof(sb->user_uuid))) {
		prt_printf(out, "Bad user UUID (got zeroes)");
		return -BCH_ERR_invalid_sb_uuid;
	}

	if (bch2_is_zero(sb->uuid.b, sizeof(sb->uuid))) {
		prt_printf(out, "Bad internal UUID (got zeroes)");
		return -BCH_ERR_invalid_sb_uuid;
	}

	if (!(flags & BCH_VALIDATE_write) &&
	    le64_to_cpu(sb->offset) != read_offset) {
		prt_printf(out, "Bad sb offset (got %llu, read from %llu)",
			   le64_to_cpu(sb->offset), read_offset);
		return -BCH_ERR_invalid_sb_offset;
	}

	if (!sb->nr_devices ||
	    sb->nr_devices > BCH_SB_MEMBERS_MAX) {
		prt_printf(out, "Bad number of member devices %u (max %u)",
		       sb->nr_devices, BCH_SB_MEMBERS_MAX);
		return -BCH_ERR_invalid_sb_too_many_members;
	}

	if (sb->dev_idx >= sb->nr_devices) {
		prt_printf(out, "Bad dev_idx (got %u, nr_devices %u)",
		       sb->dev_idx, sb->nr_devices);
		return -BCH_ERR_invalid_sb_dev_idx;
	}

	if (!sb->time_precision ||
	    le32_to_cpu(sb->time_precision) > NSEC_PER_SEC) {
		prt_printf(out, "Invalid time precision: %u (min 1, max %lu)",
		       le32_to_cpu(sb->time_precision), NSEC_PER_SEC);
		return -BCH_ERR_invalid_sb_time_precision;
	}

	/* old versions didn't know to downgrade this field */
	if (BCH_SB_VERSION_INCOMPAT_ALLOWED(sb) > le16_to_cpu(sb->version))
		SET_BCH_SB_VERSION_INCOMPAT_ALLOWED(sb, le16_to_cpu(sb->version));

	if (BCH_SB_VERSION_INCOMPAT(sb) > BCH_SB_VERSION_INCOMPAT_ALLOWED(sb)) {
		prt_printf(out, "Invalid version_incompat ");
		bch2_version_to_text(out, BCH_SB_VERSION_INCOMPAT(sb));
		prt_str(out, " > incompat_allowed ");
		bch2_version_to_text(out, BCH_SB_VERSION_INCOMPAT_ALLOWED(sb));
		if (flags & BCH_VALIDATE_write)
			return -BCH_ERR_invalid_sb_version;
		else
			SET_BCH_SB_VERSION_INCOMPAT_ALLOWED(sb, BCH_SB_VERSION_INCOMPAT(sb));
	}

	if (sb->nr_devices > 1)
		SET_BCH_SB_MULTI_DEVICE(sb, true);

#ifdef __KERNEL__
	if (!BCH_SB_SHARD_INUMS_NBITS(sb))
		SET_BCH_SB_SHARD_INUMS_NBITS(sb, ilog2(roundup_pow_of_two(num_online_cpus())));
#endif

	/* validate layout */
	try(validate_sb_layout(&sb->layout, out));

	vstruct_for_each(sb, f) {
		if (!f->u64s) {
			prt_printf(out, "Invalid superblock: optional field with size 0 (type %u)",
			       le32_to_cpu(f->type));
			return -BCH_ERR_invalid_sb_field_size;
		}

		if (vstruct_next(f) > vstruct_last(sb)) {
			prt_printf(out, "Invalid superblock: optional field extends past end of superblock (type %u)",
			       le32_to_cpu(f->type));
			return -BCH_ERR_invalid_sb_field_size;
		}
	}

	struct bch_sb_field *mi =
		bch2_sb_field_get_id(sb, BCH_SB_FIELD_members_v2) ?:
		bch2_sb_field_get_id(sb, BCH_SB_FIELD_members_v1);

	/* members must be validated first: */
	if (!mi) {
		prt_printf(out, "Invalid superblock: member info area missing");
		return -BCH_ERR_invalid_sb_members_missing;
	}

	try(bch2_sb_field_validate(sb, mi, flags, out));

	vstruct_for_each(sb, f) {
		if (le32_to_cpu(f->type) == BCH_SB_FIELD_members_v1)
			continue;

		try(bch2_sb_field_validate(sb, f, flags, out));
	}

	if ((flags & BCH_VALIDATE_write) &&
	    bch2_sb_member_get(sb, sb->dev_idx).seq != sb->seq) {
		prt_printf(out, "Invalid superblock: member seq %llu != sb seq %llu",
			   le64_to_cpu(bch2_sb_member_get(sb, sb->dev_idx).seq),
			   le64_to_cpu(sb->seq));
		return -BCH_ERR_invalid_sb_members_missing;
	}

	return 0;
}

/* device open: */

static unsigned long le_ulong_to_cpu(unsigned long v)
{
	return sizeof(unsigned long) == 8
		? le64_to_cpu(v)
		: le32_to_cpu(v);
}

static void le_bitvector_to_cpu(unsigned long *dst, unsigned long *src, unsigned nr)
{
	BUG_ON(nr & (BITS_PER_TYPE(long) - 1));

	for (unsigned i = 0; i < BITS_TO_LONGS(nr); i++)
		dst[i] = le_ulong_to_cpu(src[i]);
}

static void bch2_sb_update(struct bch_fs *c)
{
	struct bch_sb *src = c->disk_sb.sb;

	lockdep_assert_held(&c->sb_lock);

	c->sb.uuid		= src->uuid;
	c->sb.user_uuid		= src->user_uuid;
	c->sb.version		= le16_to_cpu(src->version);
	c->sb.version_incompat	= BCH_SB_VERSION_INCOMPAT(src);
	c->sb.version_incompat_allowed
				= BCH_SB_VERSION_INCOMPAT_ALLOWED(src);
	c->sb.version_min	= le16_to_cpu(src->version_min);
	c->sb.version_upgrade_complete = BCH_SB_VERSION_UPGRADE_COMPLETE(src);
	c->sb.nr_devices	= src->nr_devices;
	c->sb.clean		= BCH_SB_CLEAN(src);
	c->sb.encryption_type	= BCH_SB_ENCRYPTION_TYPE(src);

	c->sb.extent_bp_shift = BCH_SB_EXTENT_BP_SHIFT(c->disk_sb.sb) ?:
		BCH_SB_EXTENT_BP_SHIFT_DEFAULT;

	c->sb.nsec_per_time_unit = le32_to_cpu(src->time_precision);
	c->sb.time_units_per_sec = NSEC_PER_SEC / c->sb.nsec_per_time_unit;

	/* XXX this is wrong, we need a 96 or 128 bit integer type */
	c->sb.time_base_lo	= div_u64(le64_to_cpu(src->time_base_lo),
					  c->sb.nsec_per_time_unit);
	c->sb.time_base_hi	= le32_to_cpu(src->time_base_hi);

	c->sb.features		= le64_to_cpu(src->features[0]);
	c->sb.compat		= le64_to_cpu(src->compat[0]);
	c->sb.multi_device	= BCH_SB_MULTI_DEVICE(src);

	struct bch_sb_field_ext *ext = bch2_sb_field_get(src, ext);
	if (ext) {
		c->sb.recovery_passes_required =
			bch2_recovery_passes_from_stable(le64_to_cpu(ext->recovery_passes_required[0]));

		le_bitvector_to_cpu(c->sb.errors_silent, (void *) ext->errors_silent,
				    sizeof(c->sb.errors_silent) * 8);
		c->sb.btrees_lost_data = le64_to_cpu(ext->btrees_lost_data);
	} else {
		memset(c->sb.errors_silent, 0, sizeof(c->sb.errors_silent));
	}

	bch2_sb_members_to_cpu(c);
}

static int __copy_super(struct bch_sb_handle *dst_handle, struct bch_sb *src)
{
	struct bch_sb_field *src_f, *dst_f;
	struct bch_sb *dst = dst_handle->sb;
	unsigned i;

	dst->version		= src->version;
	dst->version_min	= src->version_min;
	dst->seq		= src->seq;
	dst->uuid		= src->uuid;
	dst->user_uuid		= src->user_uuid;
	memcpy(dst->label,	src->label, sizeof(dst->label));

	dst->block_size		= src->block_size;
	dst->nr_devices		= src->nr_devices;

	dst->time_base_lo	= src->time_base_lo;
	dst->time_base_hi	= src->time_base_hi;
	dst->time_precision	= src->time_precision;
	dst->write_time		= src->write_time;

	memcpy(dst->flags,	src->flags,	sizeof(dst->flags));
	memcpy(dst->features,	src->features,	sizeof(dst->features));
	memcpy(dst->compat,	src->compat,	sizeof(dst->compat));

	for (i = 0; i < BCH_SB_FIELD_NR; i++) {
		int d;

		if ((1U << i) & BCH_SINGLE_DEVICE_SB_FIELDS)
			continue;

		src_f = bch2_sb_field_get_id(src, i);
		dst_f = bch2_sb_field_get_id(dst, i);

		d = (src_f ? le32_to_cpu(src_f->u64s) : 0) -
		    (dst_f ? le32_to_cpu(dst_f->u64s) : 0);
		if (d > 0) {
			try(bch2_sb_realloc(dst_handle, le32_to_cpu(dst_handle->sb->u64s) + d));

			dst = dst_handle->sb;
			dst_f = bch2_sb_field_get_id(dst, i);
		}

		dst_f = __bch2_sb_field_resize(dst_handle, dst_f,
				src_f ? le32_to_cpu(src_f->u64s) : 0);

		if (src_f)
			memcpy(dst_f, src_f, vstruct_bytes(src_f));
	}

	return 0;
}

int bch2_sb_to_fs(struct bch_fs *c, struct bch_sb *src)
{
	lockdep_assert_held(&c->sb_lock);

	try(bch2_sb_realloc(&c->disk_sb, 0));
	try(__copy_super(&c->disk_sb, src));
	try(bch2_sb_replicas_to_cpu_replicas(c));
	try(bch2_sb_disk_groups_to_cpu(c));

	bch2_sb_extent_type_u64s_to_cpu(c);

	bch2_sb_update(c);
	return 0;
}

int bch2_sb_from_fs(struct bch_fs *c, struct bch_dev *ca)
{
	return __copy_super(&ca->disk_sb, c->disk_sb.sb);
}

/* read superblock: */

static int read_one_super(struct bch_sb_handle *sb, u64 offset, struct printbuf *err)
{
	while (true) {
		bio_reset(sb->bio, sb->bdev, REQ_OP_READ|REQ_SYNC|REQ_META);
		sb->bio->bi_iter.bi_sector = offset;
		bch2_bio_map(sb->bio, sb->sb, sb->buffer_size);

		int ret = submit_bio_wait(sb->bio);
		if (ret) {
			prt_printf(err, "IO error: %i", ret);
			return ret;
		}

		if (!uuid_equal(&sb->sb->magic, &BCACHE_MAGIC) &&
		    !uuid_equal(&sb->sb->magic, &BCHFS_MAGIC)) {
			prt_str(err, "Not a bcachefs superblock (got magic ");
			pr_uuid(err, sb->sb->magic.b);
			prt_str(err, ")");
			return -BCH_ERR_invalid_sb_magic;
		}

		try(bch2_sb_compatible(sb->sb, err));

		size_t bytes = vstruct_bytes(sb->sb);

		u64 sb_size = 512ULL << min(BCH_SB_LAYOUT_SIZE_BITS_MAX, sb->sb->layout.sb_max_size_bits);
		if (bytes > sb_size) {
			prt_printf(err, "Invalid superblock: too big (got %zu bytes, layout max %llu)",
				   bytes, sb_size);
			return -BCH_ERR_invalid_sb_too_big;
		}

		if (bytes > sb->buffer_size) {
			try(bch2_sb_realloc(sb, le32_to_cpu(sb->sb->u64s)));
			continue;
		}

		enum bch_csum_type csum_type = BCH_SB_CSUM_TYPE(sb->sb);
		if (csum_type >= BCH_CSUM_NR ||
		    bch2_csum_type_is_encryption(csum_type)) {
			prt_printf(err, "unknown checksum type %llu", BCH_SB_CSUM_TYPE(sb->sb));
			return -BCH_ERR_invalid_sb_csum_type;
		}

		/* XXX: verify MACs */
		struct bch_csum csum = csum_vstruct(NULL, csum_type, null_nonce(), sb->sb);
		if (bch2_crc_cmp(csum, sb->sb->csum)) {
			bch2_csum_err_msg(err, csum_type, sb->sb->csum, csum);
			return -BCH_ERR_invalid_sb_csum;
		}

		sb->seq = le64_to_cpu(sb->sb->seq);
		return 0;
	}
}

static int read_layout_sector(struct bch_sb_handle *sb,
			      struct bch_sb_layout *layout,
			      struct printbuf *err)
{
	bio_reset(sb->bio, sb->bdev, REQ_OP_READ|REQ_SYNC|REQ_META);
	sb->bio->bi_iter.bi_sector = BCH_SB_LAYOUT_SECTOR;
	/*
	 * use sb buffer to read layout, since sb buffer is page aligned but
	 * layout won't be:
	 */
	bch2_bio_map(sb->bio, sb->sb, sizeof(*layout));

	try(submit_bio_wait(sb->bio));

	memcpy(layout, sb->sb, sizeof(*layout));
	return validate_sb_layout(layout, err);
}

/*
 * Scan the backup superblock copies in @layout (the primary is already
 * attempted by the caller) and return the offset of the highest-seq valid
 * copy across primary + backups. On exit sb->sb holds the authoritative copy
 * at *best_offset.
 *
 * The caller passes primary_seq = 0 if the primary read failed; nonzero
 * otherwise (in which case sb->sb holds the primary's content on entry and is
 * a candidate for best).
 *
 * Reading every copy defends against several failure modes:
 *   - torn write to the primary (csum fails; pick a backup at the same seq)
 *   - stale primary from a write that succeeded against slot 1+ but not the
 *     primary (older seq on slot 0; pick the higher-seq backup)
 *   - bit rot on a backup we didn't visit since last write (gets noticed when
 *     the primary is also down)
 *
 * The "highest seq, last-scanned wins on a tie" rule keeps the common case
 * (all slots at the same seq) free of re-reads.
 */
static int read_backup_supers(struct bch_sb_handle *sb,
			      struct bch_sb_layout *layout,
			      bool primary_valid,
			      u64 *best_offset,
			      struct printbuf *err)
{
	u64 primary_offset = le64_to_cpu(layout->sb_offset[0]);
	u64 best_seq	= primary_valid ? le64_to_cpu(sb->sb->seq) : 0;
	u64 last_read	= primary_valid ? primary_offset : 0;
	bool any_valid	= primary_valid;

	*best_offset	= primary_offset;

	for (unsigned i = 1; i < layout->nr_superblocks; i++) {
		u64 offset = le64_to_cpu(layout->sb_offset[i]);

		struct printbuf slot_err = PRINTBUF;
		int ret = read_one_super(sb, offset, &slot_err);
		/*
		 * read_one_super reads into sb->sb before validating; on
		 * failure the buffer holds the unvalidated data. Track
		 * last_read regardless of success so the post-loop check
		 * knows whether to re-read the winning slot.
		 */
		last_read = offset;
		if (ret) {
			prt_printf(err, "  sb @ %llu: %s\n", offset, slot_err.buf);
			printbuf_exit(&slot_err);
			continue;
		}
		printbuf_exit(&slot_err);

		any_valid = true;
		if (sb->seq >= best_seq) {
			best_seq = sb->seq;
			*best_offset = offset;
		}
	}

	if (!any_valid)
		return -BCH_ERR_invalid;

	/*
	 * If the winning slot wasn't the one we read last, re-read it so
	 * sb->sb holds the authoritative copy on return.
	 */
	if (last_read != *best_offset)
		try(read_one_super(sb, *best_offset, err));

	return 0;
}

static int read_super_and_backups(struct bch_sb_handle *sb,
			     const char *path,
			     struct bch_opts *opts,
			     struct printbuf *err)
{
	memset(sb, 0, sizeof(*sb));
	sb->mode	= BLK_OPEN_READ;
	sb->have_bio	= true;
	sb->holder	= kzalloc(sizeof(*sb->holder), GFP_KERNEL);
	if (!sb->holder)
		return -ENOMEM;

	sb->sb_name = kstrdup(path, GFP_KERNEL);
	if (!sb->sb_name)
		return -ENOMEM;

#ifndef __KERNEL__
	if (opt_get(*opts, direct_io) == false)
		sb->mode |= BLK_OPEN_BUFFERED;
#endif

	if (!opt_get(*opts, noexcl))
		sb->mode |= BLK_OPEN_EXCL;

	if (!opt_get(*opts, nochanges))
		sb->mode |= BLK_OPEN_WRITE;

	sb->s_bdev_file = bdev_file_open_by_path(path, sb->mode, sb->holder, &bch2_sb_handle_bdev_ops);
	if (IS_ERR(sb->s_bdev_file) &&
	    PTR_ERR(sb->s_bdev_file) == -EACCES &&
	    opt_get(*opts, read_only)) {
		sb->mode &= ~BLK_OPEN_WRITE;

		sb->s_bdev_file = bdev_file_open_by_path(path, sb->mode, sb->holder, &bch2_sb_handle_bdev_ops);
		if (!IS_ERR(sb->s_bdev_file))
			opt_set(*opts, nochanges, true);
	}

	if (IS_ERR(sb->s_bdev_file))
		return PTR_ERR(sb->s_bdev_file);

	sb->bdev = file_bdev(sb->s_bdev_file);

	try(bch2_sb_realloc(sb, 0));

	if (bch2_fs_init_fault("read_super"))
		return -EFAULT;

	u64 sb_offset;

	/*
	 * If the user requested a specific superblock offset (recovery /
	 * debug), respect it: don't scan, don't fall back.
	 */
	if (opt_defined(*opts, sb)) {
		sb_offset = opt_get(*opts, sb);
		try(read_one_super(sb, sb_offset, err));
	} else {
		struct bch_sb_layout layout;

		/*
		 * Read the primary first so we can pick up its embedded
		 * layout in the common case; if it fails, fall back to the
		 * standalone layout sector.
		 */
		CLASS(printbuf, primary_err)();
		int ret = read_one_super(sb, BCH_SB_SECTOR, &primary_err);
		if (!ret) {
			memcpy(&layout, &sb->sb->layout, sizeof(layout));
			try(validate_sb_layout(&layout, err));
			try(read_backup_supers(sb, &layout, true, &sb_offset, err));
		} else {
			prt_printf(err, "primary superblock unreadable: %s\n", primary_err.buf);
			try(read_layout_sector(sb, &layout, err));
			try(read_backup_supers(sb, &layout, false, &sb_offset, err));
		}
	}

	if (le16_to_cpu(sb->sb->block_size) << 9 <
	    bdev_logical_block_size(sb->bdev) &&
	    opt_get(*opts, direct_io)) {
#ifndef __KERNEL__
		opt_set(*opts, direct_io, false);
		return -EINTR;
#endif
		prt_printf(err, "block size (%u) smaller than device block size (%u)",
			   le16_to_cpu(sb->sb->block_size) << 9,
			   bdev_logical_block_size(sb->bdev));
		return -BCH_ERR_block_size_too_small;
	}

	sb->have_layout = true;
	try(bch2_sb_validate(sb->sb, opts, sb_offset, 0, err));

	return 0;
}

static int __bch2_read_super(struct bch_sb_handle *sb,
			     const char *path,
			     struct bch_opts *opts,
			     struct printbuf *err)
{
	while (true) {
		int ret = read_super_and_backups(sb, path, opts, err);
		if (ret)
			bch2_free_super(sb);
		if (ret != -EINTR)
			return ret;

		printbuf_reset(err);
		/* fallback to buffered IO */
	}
}

int bch2_read_super(const char *path, struct bch_opts *opts,
		    struct bch_sb_handle *sb)
{
	CLASS(printbuf, err)();
	int ret = __bch2_read_super(sb, path, opts, &err);
	if (ret)
		bch2_free_super(sb);

	if (ret && err.pos)
		bch2_print_opts(opts, KERN_ERR "bcachefs (%s): error reading superblock: %s\n%s",
				path, bch2_err_str(ret), err.buf);
	else if (ret)
		bch2_print_opts(opts, KERN_ERR "bcachefs (%s): error reading superblock: %s",
				path, bch2_err_str(ret));
	else if (err.pos) {
		prt_printf(&err, "successful read from backup");
		bch2_print_opts(opts, KERN_NOTICE "bcachefs (%s): %s", path, err.buf);
	}

	return ret;
}

/* provide a silenced version for mount.bcachefs */

int bch2_read_super_silent(const char *path, struct bch_opts *opts,
		    struct bch_sb_handle *sb)
{
	CLASS(printbuf, err)();
	int ret = __bch2_read_super(sb, path, opts, &err);
	if (ret)
		bch2_free_super(sb);
	return ret;
}

/* write superblock: */

static void write_super_endio(struct bio *bio)
{
	struct bch_dev *ca = bio->bi_private;

	bch2_account_io_success_fail(ca, bio_data_dir(bio), !bio->bi_status);

	if (bio->bi_status)
		ca->sb_write_error =
			__bch2_err_throw(ca->fs, -blk_status_to_bch_err(bio->bi_status));

	closure_put(&ca->fs->sb_write);
}

static void read_back_super(struct bch_fs *c, struct bch_dev *ca)
{
	struct bch_sb *sb = ca->disk_sb.sb;
	struct bio *bio = ca->disk_sb.bio;

	memset(ca->sb_read_scratch, 0, BCH_SB_READ_SCRATCH_BUF_SIZE);

	bio_reset(bio, ca->disk_sb.bdev, REQ_OP_READ|REQ_SYNC|REQ_META);
	bio->bi_iter.bi_sector	= le64_to_cpu(sb->layout.sb_offset[0]);
	bio->bi_end_io		= write_super_endio;
	bio->bi_private		= ca;
	bch2_bio_map(bio, ca->sb_read_scratch, BCH_SB_READ_SCRATCH_BUF_SIZE);

	this_cpu_add(ca->io_done->sectors[READ][BCH_DATA_sb], bio_sectors(bio));

	closure_bio_submit(bio, &c->sb_write);
}

static void write_one_super(struct bch_fs *c, struct bch_dev *ca, unsigned idx)
{
	struct bch_sb *sb = ca->disk_sb.sb;
	struct bio *bio = ca->disk_sb.bio;

	sb->offset = sb->layout.sb_offset[idx];

	SET_BCH_SB_CSUM_TYPE(sb, bch2_csum_opt_to_type(c->opts.metadata_checksum, false));
	sb->csum = csum_vstruct(c, BCH_SB_CSUM_TYPE(sb),
				null_nonce(), sb);

	/*
	 * blk-wbt.c throttles all writes except those that have both REQ_SYNC
	 * and REQ_IDLE set...
	 */

	bio_reset(bio, ca->disk_sb.bdev, REQ_OP_WRITE|REQ_SYNC|REQ_IDLE|REQ_META|REQ_FUA);
	bio->bi_iter.bi_sector	= le64_to_cpu(sb->offset);
	bio->bi_end_io		= write_super_endio;
	bio->bi_private		= ca;
	bch2_bio_map(bio, sb,
		     roundup((size_t) vstruct_bytes(sb),
			     bdev_logical_block_size(ca->disk_sb.bdev)));

	this_cpu_add(ca->io_done->sectors[WRITE][BCH_DATA_sb],
		     bio_sectors(bio));

	closure_bio_submit(bio, &c->sb_write);
}

typedef struct {
	int		err;
	u64		offset;
} sb_offset_err;
DEFINE_DARRAY(sb_offset_err);

typedef struct {
	struct bch_dev		*ca;
	darray_sb_offset_err	failures;
} write_sb_dev;

static void write_sb_dev_put(write_sb_dev d)
{
	enumerated_ref_put(&d.ca->io_ref[READ], BCH_DEV_READ_REF_write_super);
	darray_exit(&d.failures);
}

DEFINE_DARRAY_FREE_ITEM(write_sb_dev, write_sb_dev_put);

static int __bch2_write_super(struct bch_fs *c)
{
	struct closure *cl = &c->sb_write;
	unsigned degraded_flags = BCH_FORCE_IF_DEGRADED;
	CLASS(darray_write_sb_dev, online_devices)();

	if (!test_bit(BCH_FS_may_upgrade_downgrade, &c->flags))
		return 0;

	event_inc_trace(c, write_super, buf);

	if (c->opts.degraded == BCH_DEGRADED_very)
		degraded_flags |= BCH_FORCE_IF_LOST;

	lockdep_assert_held(&c->sb_lock);

	closure_init_stack(cl);

	if (bch2_sb_has_journal(c->disk_sb.sb))
		bch2_fs_mark_dirty(c);
	else
		bch2_fs_mark_clean(c);

	/*
	 * Note: we do writes to RO devices here, and we might want to change
	 * that in the future.
	 *
	 * For now, we expect to be able to call write_super() when we're not
	 * yet RW:
	 */
	for_each_online_member(c, ca, BCH_DEV_READ_REF_write_super) {
		int ret = darray_push(&online_devices, ((write_sb_dev) { ca }));
		if (bch2_fs_fatal_err_on(ret, c, "%s: error allocating online devices", __func__))
			return ret;
		enumerated_ref_get(&ca->io_ref[READ], BCH_DEV_READ_REF_write_super);
	}

	/* Make sure we're using the new magic numbers: */
	c->disk_sb.sb->magic = BCHFS_MAGIC;
	c->disk_sb.sb->layout.magic = BCHFS_MAGIC;

	le64_add_cpu(&c->disk_sb.sb->seq, 1);

	struct bch_sb_field_members_v2 *mi = bch2_sb_field_get(c->disk_sb.sb, members_v2);
	darray_for_each(online_devices, i)
		__bch2_members_v2_get_mut(mi, i->ca->dev_idx)->seq = c->disk_sb.sb->seq;
	c->disk_sb.sb->write_time = cpu_to_le64(ktime_get_real_seconds());

	if (test_bit(BCH_FS_error, &c->flags))
		SET_BCH_SB_HAS_ERRORS(c->disk_sb.sb, 1);
	if (test_bit(BCH_FS_topology_error, &c->flags))
		SET_BCH_SB_HAS_TOPOLOGY_ERRORS(c->disk_sb.sb, 1);

	SET_BCH_SB_BIG_ENDIAN(c->disk_sb.sb, CPU_BIG_ENDIAN);

	bch2_sb_counters_from_cpu(c);
	bch2_sb_members_from_cpu(c);
	bch2_sb_members_cpy_v2_v1(&c->disk_sb);
	bch2_sb_errors_from_cpu(c);
	bch2_sb_downgrade_update(c);
	try(bch2_sb_extent_type_u64s_from_cpu(c));

	darray_for_each(online_devices, i)
		bch2_sb_from_fs(c, i->ca);

	darray_for_each(online_devices, i) {
		struct bch_opts opts = bch2_opts_empty();
		CLASS(printbuf, err)();

		int ret = bch2_sb_validate(i->ca->disk_sb.sb, &opts, 0, BCH_VALIDATE_write, &err);
		if (ret) {
			bch2_fs_inconsistent(c, "sb invalid before write: %s", err.buf);
			return 0;
		}
	}

	if (c->opts.nochanges)
		return 0;

	/*
	 * Defer writing the superblock until filesystem initialization is
	 * complete - don't write out a partly initialized superblock:
	 */
	if (!BCH_SB_INITIALIZED(c->disk_sb.sb))
		return 0;

	if (le16_to_cpu(c->disk_sb.sb->version) > bcachefs_metadata_version_current) {
		CLASS(printbuf, buf)();
		prt_printf(&buf, "attempting to write superblock that wasn't version downgraded (");
		bch2_version_to_text(&buf, le16_to_cpu(c->disk_sb.sb->version));
		prt_str(&buf, " > ");
		bch2_version_to_text(&buf, bcachefs_metadata_version_current);
		prt_str(&buf, ")");
		bch2_fs_fatal_error(c, ": %s", buf.buf);
		return bch_err_throw(c, sb_not_downgraded);
	}

	struct bch_devs_mask sb_written = {};

	darray_for_each(online_devices, i)
		i->ca->sb_write_error = 0;

	darray_for_each(online_devices, i)
		read_back_super(c, i->ca);
	closure_sync(cl);

	darray_for_each(online_devices, i) {
		struct bch_dev *ca = i->ca;

		if (ca->sb_write_error)
			continue;

		if (le64_to_cpu(ca->sb_read_scratch->seq) < ca->disk_sb.seq) {
			CLASS(bch_log_msg, msg)(c);
			prt_bdevname(&msg.m, ca->disk_sb.bdev);
			prt_printf(&msg.m, ": Superblock write was silently dropped! (seq %llu expected %llu)",
				   le64_to_cpu(ca->sb_read_scratch->seq),
				   ca->disk_sb.seq);

			if (c->opts.errors != BCH_ON_ERROR_continue &&
			    c->opts.errors != BCH_ON_ERROR_fix_safe) {
				bch2_fs_emergency_read_only(c, &msg.m);
				return bch_err_throw(c, erofs_sb_err);
			}
		}

		if (le64_to_cpu(ca->sb_read_scratch->seq) > ca->disk_sb.seq) {
			CLASS(bch_log_msg, msg)(c);
			prt_bdevname(&msg.m, ca->disk_sb.bdev);
			prt_printf(&msg.m, ": Superblock modified by another process (seq %llu expected %llu)",
				   le64_to_cpu(ca->sb_read_scratch->seq),
				   ca->disk_sb.seq);
			bch2_fs_emergency_read_only(c, &msg.m);
			return bch_err_throw(c, erofs_sb_err);
		}
	}

	unsigned sb = 0;
	bool have_errors = false, wrote;
	do {
		darray_for_each(online_devices, i)
			i->ca->sb_write_error = 0;

		wrote = false;
		darray_for_each(online_devices, i) {
			struct bch_sb_layout *l = &i->ca->disk_sb.sb->layout;
			if (sb >= l->nr_superblocks)
				continue;

			write_one_super(c, i->ca, sb);
			wrote = true;
		}

		closure_sync(cl);

		darray_for_each(online_devices, i) {
			struct bch_sb_layout *l = &i->ca->disk_sb.sb->layout;
			if (sb >= l->nr_superblocks)
				continue;

			if (i->ca->sb_write_error) {
				darray_push(&i->failures, ((sb_offset_err) {
							   i->ca->sb_write_error,
							   le64_to_cpu(l->sb_offset[sb])
				}));
				have_errors = true;
			} else {
				__set_bit(i->ca->dev_idx, sb_written.d);
			}
		}
		sb++;
	} while (wrote);

	darray_for_each(online_devices, i)
		if (test_bit(i->ca->dev_idx, sb_written.d))
			i->ca->disk_sb.seq = le64_to_cpu(i->ca->disk_sb.sb->seq);

	unsigned nr_wrote =	dev_mask_nr(&sb_written);
	unsigned nr_members =	bch2_sb_nr_devices(c->disk_sb.sb);
	bool fatal = !nr_wrote ||
		!bch2_can_read_fs_with_devs(c, &sb_written, degraded_flags, NULL);

	if (!have_errors && !fatal)
		return 0;

	CLASS(bch_log_msg, msg)(c);

	prt_printf(&msg.m, "Error writing superblock, wrote to %u/%u devices:\n",
		   nr_wrote, nr_members);

	struct bch_devs_mask sb_unwritten;
	memset(sb_unwritten.d, 0xFF, sizeof(sb_unwritten));

	darray_for_each(online_devices, i) {
		__clear_bit(i->ca->dev_idx, sb_unwritten.d);
		bch2_member_to_text_short_locked(&msg.m, c, i->ca);

		if (i->failures.nr) {
			darray_for_each(i->failures, j)
				prt_printf(&msg.m, " %llu=%s", j->offset, bch2_err_str(j->err));

			if (!test_bit(i->ca->dev_idx, sb_written.d))
				prt_str(&msg.m, " (all failed)");
			else
				prt_str(&msg.m, " (partial success)");
		} else {
			prt_str(&msg.m, " (success)");
		}
		prt_newline(&msg.m);
	}

	prt_printf(&msg.m, "Offline devices:\n");
	scoped_guard(printbuf_indent, &msg.m)
		bch2_devs_mask_to_text_locked(&msg.m, c, &sb_unwritten);

	if (fatal) {
		prt_printf(&msg.m, "Unable to write superblock to sufficient devices (from %ps)\n",
			   (void *) _RET_IP_);
		prt_printf(&msg.m, "Would not be able to mount with written devices\n");
		bch2_can_read_fs_with_devs(c, &sb_written, degraded_flags, &msg.m);
		bch2_fs_emergency_read_only(c, &msg.m);
	}

	return 0;
}

int bch2_write_super(struct bch_fs *c)
{
	int ret = __bch2_write_super(c);
	/* Make new options visible after they're persistent: */
	bch2_sb_update(c);
	return ret;
}

void __bch2_check_set_feature(struct bch_fs *c, unsigned feat)
{
	guard(memalloc_flags)(PF_MEMALLOC_NOFS);
	guard(mutex)(&c->sb_lock);
	if (!(c->sb.features & BIT_ULL(feat))) {
		c->disk_sb.sb->features[0] |= cpu_to_le64(BIT_ULL(feat));

		bch2_write_super(c);
	}
}

/* Downgrade if superblock is at a higher version than currently supported: */
bool bch2_check_version_downgrade(struct bch_fs *c)
{
	bool ret = bcachefs_metadata_version_current < c->sb.version;

	lockdep_assert_held(&c->sb_lock);

	/*
	 * Downgrade, if superblock is at a higher version than currently
	 * supported:
	 *
	 * c->sb will be checked before we write the superblock, so update it as
	 * well:
	 */
	if (BCH_SB_VERSION_UPGRADE_COMPLETE(c->disk_sb.sb) > bcachefs_metadata_version_current)
		SET_BCH_SB_VERSION_UPGRADE_COMPLETE(c->disk_sb.sb, bcachefs_metadata_version_current);
	if (BCH_SB_VERSION_INCOMPAT_ALLOWED(c->disk_sb.sb) > bcachefs_metadata_version_current)
		SET_BCH_SB_VERSION_INCOMPAT_ALLOWED(c->disk_sb.sb, bcachefs_metadata_version_current);
	if (c->sb.version > bcachefs_metadata_version_current)
		c->disk_sb.sb->version = cpu_to_le16(bcachefs_metadata_version_current);
	if (c->sb.version_min > bcachefs_metadata_version_current)
		c->disk_sb.sb->version_min = cpu_to_le16(bcachefs_metadata_version_current);
	c->disk_sb.sb->compat[0] &= cpu_to_le64((1ULL << BCH_COMPAT_NR) - 1);
	return ret;
}

void bch2_sb_upgrade(struct bch_fs *c, unsigned new_version, bool incompat)
{
	lockdep_assert_held(&c->sb_lock);

	if (BCH_VERSION_MAJOR(new_version) >
	    BCH_VERSION_MAJOR(le16_to_cpu(c->disk_sb.sb->version)))
		bch2_sb_field_resize(&c->disk_sb, downgrade, 0);

	c->disk_sb.sb->version = cpu_to_le16(new_version);

	if (incompat) {
		c->disk_sb.sb->features[0] |= cpu_to_le64(BCH_SB_FEATURES_ALL);
		SET_BCH_SB_VERSION_INCOMPAT_ALLOWED(c->disk_sb.sb,
			max(BCH_SB_VERSION_INCOMPAT_ALLOWED(c->disk_sb.sb), new_version));
	}
}

void bch2_sb_upgrade_incompat(struct bch_fs *c)
{
	guard(memalloc_flags)(PF_MEMALLOC_NOFS);
	guard(mutex)(&c->sb_lock);

	if (c->sb.version == c->sb.version_incompat_allowed)
		return;

	CLASS(printbuf, buf)();

	prt_str(&buf, "Now allowing incompatible features up to ");
	bch2_version_to_text(&buf, c->sb.version);
	prt_str(&buf, ", previously allowed up to ");
	bch2_version_to_text(&buf, c->sb.version_incompat_allowed);
	prt_newline(&buf);

	bch_notice(c, "%s", buf.buf);

	c->disk_sb.sb->features[0] |= cpu_to_le64(BCH_SB_FEATURES_ALL);
	SET_BCH_SB_VERSION_INCOMPAT_ALLOWED(c->disk_sb.sb,
			max(BCH_SB_VERSION_INCOMPAT_ALLOWED(c->disk_sb.sb), c->sb.version));

	bch2_sb_set_upgrade_incompat(c, c->sb.version_incompat_allowed, c->sb.version);
	bch2_write_super(c);

	bch2_run_async_recovery_passes(c);
}

static int bch2_sb_ext_validate(struct bch_sb *sb, struct bch_sb_field *f,
				enum bch_validate_flags flags, struct printbuf *err)
{
	if (vstruct_bytes(f) < 88) {
		prt_printf(err, "field too small (%zu < %u)", vstruct_bytes(f), 88);
		return -BCH_ERR_invalid_sb_ext;
	}

	return 0;
}

static void bch2_sb_ext_to_text(struct printbuf *out,
				struct bch_fs *c,
				struct bch_sb *sb,
				struct bch_sb_field *f)
{
	struct bch_sb_field_ext *e = field_to_type(f, ext);

	prt_printf(out, "Recovery passes required:\t");
	prt_bitflags(out, bch2_recovery_passes,
		     bch2_recovery_passes_from_stable(le64_to_cpu(e->recovery_passes_required[0])));
	prt_newline(out);

	unsigned long *errors_silent = kmalloc(sizeof(e->errors_silent), GFP_KERNEL);
	if (errors_silent) {
		le_bitvector_to_cpu(errors_silent, (void *) e->errors_silent, sizeof(e->errors_silent) * 8);

		prt_printf(out, "Errors to silently fix:\t");
		prt_bitflags_vector(out, bch2_sb_error_strs, errors_silent,
				    min(BCH_FSCK_ERR_MAX, sizeof(e->errors_silent) * 8));
		prt_newline(out);

		kfree(errors_silent);
	}

	prt_printf(out, "Btrees with missing data:\t");
	prt_bitflags(out, __bch2_btree_ids, le64_to_cpu(e->btrees_lost_data));
	prt_newline(out);
}

static const struct bch_sb_field_ops bch_sb_field_ops_ext = {
	.validate	= bch2_sb_ext_validate,
	.to_text	= bch2_sb_ext_to_text,
};

static const struct bch_sb_field_ops *bch2_sb_field_ops[] = {
#define x(f, nr, ...)					\
	[BCH_SB_FIELD_##f] = &bch_sb_field_ops_##f,
	BCH_SB_FIELDS()
#undef x
};

static const struct bch_sb_field_ops bch2_sb_field_null_ops;

static const struct bch_sb_field_ops *bch2_sb_field_type_ops(unsigned type)
{
	return likely(type < ARRAY_SIZE(bch2_sb_field_ops))
		? bch2_sb_field_ops[type]
		: &bch2_sb_field_null_ops;
}

static int bch2_sb_field_validate(struct bch_sb *sb, struct bch_sb_field *f,
				  enum bch_validate_flags flags, struct printbuf *err)
{
	unsigned type = le32_to_cpu(f->type);
	CLASS(printbuf, field_err)();
	const struct bch_sb_field_ops *ops = bch2_sb_field_type_ops(type);
	int ret;

	ret = ops->validate ? ops->validate(sb, f, flags, &field_err) : 0;
	if (ret) {
		prt_printf(err, "Invalid superblock section %s: %s",
			   bch2_sb_fields[type], field_err.buf);
		prt_newline(err);
		bch2_sb_field_to_text(err, NULL, sb, f);
	}

	return ret;
}

void __bch2_sb_field_to_text(struct printbuf *out,
			     struct bch_fs *c,
			     struct bch_sb *sb,
			     struct bch_sb_field *f)
{
	unsigned type = le32_to_cpu(f->type);
	const struct bch_sb_field_ops *ops = bch2_sb_field_type_ops(type);

	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 32);

	if (ops->to_text)
		ops->to_text(out, c, sb, f);
}

void bch2_sb_field_to_text(struct printbuf *out,
			   struct bch_fs *c,
			   struct bch_sb *sb,
			   struct bch_sb_field *f)
{
	unsigned type = le32_to_cpu(f->type);

	if (type < BCH_SB_FIELD_NR)
		prt_printf(out, "%s", bch2_sb_fields[type]);
	else
		prt_printf(out, "(unknown field %u)", type);

	prt_printf(out, " (size %zu):", vstruct_bytes(f));
	prt_newline(out);

	__bch2_sb_field_to_text(out, c, sb, f);
}

void bch2_sb_layout_to_text(struct printbuf *out, struct bch_sb_layout *l)
{
	prt_printf(out, "Type:                    %u", l->layout_type);
	prt_newline(out);

	prt_str(out, "Superblock max size:     ");
	prt_units_u64(out, 512 << l->sb_max_size_bits);
	prt_newline(out);

	prt_printf(out, "Nr superblocks:          %u", l->nr_superblocks);
	prt_newline(out);

	prt_str(out, "Offsets:                 ");
	for (unsigned i = 0; i < l->nr_superblocks; i++) {
		if (i)
			prt_str(out, ", ");
		prt_printf(out, "%llu", le64_to_cpu(l->sb_offset[i]));
	}
	prt_newline(out);
}

void bch2_sb_to_text(struct printbuf *out,
		     struct bch_fs *c, struct bch_sb *sb,
		     bool print_layout, unsigned fields)
{
	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 44);

	prt_printf(out, "External UUID:\t");
	pr_uuid(out, sb->user_uuid.b);
	prt_newline(out);

	prt_printf(out, "Internal UUID:\t");
	pr_uuid(out, sb->uuid.b);
	prt_newline(out);

	prt_printf(out, "Magic number:\t");
	pr_uuid(out, sb->magic.b);
	prt_newline(out);

	prt_printf(out, "Device index:\t%u\n", sb->dev_idx);

	prt_printf(out, "Label:\t");
	if (!strlen(sb->label))
		prt_printf(out, "(none)");
	else
		prt_printf(out, "%.*s", (int) sizeof(sb->label), sb->label);
	prt_newline(out);

	prt_printf(out, "Version:\t");
	bch2_version_to_text(out, le16_to_cpu(sb->version));
	prt_newline(out);

	prt_printf(out, "Incompatible features allowed:\t");
	bch2_version_to_text(out, BCH_SB_VERSION_INCOMPAT_ALLOWED(sb));
	prt_newline(out);

	prt_printf(out, "Incompatible features in use:\t");
	bch2_version_to_text(out, BCH_SB_VERSION_INCOMPAT(sb));
	prt_newline(out);

	prt_printf(out, "Version upgrade complete:\t");
	bch2_version_to_text(out, BCH_SB_VERSION_UPGRADE_COMPLETE(sb));
	prt_newline(out);

	prt_printf(out, "Oldest version on disk:\t");
	bch2_version_to_text(out, le16_to_cpu(sb->version_min));
	prt_newline(out);

	prt_printf(out, "Created:\t");
	if (sb->time_base_lo)
		bch2_prt_datetime(out, div_u64(le64_to_cpu(sb->time_base_lo), NSEC_PER_SEC));
	else
		prt_printf(out, "(not set)");
	prt_newline(out);

	prt_printf(out, "Sequence number:\t");
	prt_printf(out, "%llu", le64_to_cpu(sb->seq));
	prt_newline(out);

	prt_printf(out, "Time of last write:\t");
	bch2_prt_datetime(out, le64_to_cpu(sb->write_time));
	prt_newline(out);

	prt_printf(out, "Superblock size:\t");
	prt_units_u64(out, vstruct_bytes(sb));
	prt_str(out, "/");
	prt_units_u64(out, 512ULL << sb->layout.sb_max_size_bits);
	prt_newline(out);

	prt_printf(out, "Clean:\t%llu\n", BCH_SB_CLEAN(sb));
	prt_printf(out, "Devices:\t%u\n", bch2_sb_nr_devices(sb));

	prt_printf(out, "Sections:\t");
	u64 fields_have = 0;
	vstruct_for_each(sb, f)
		fields_have |= 1 << le32_to_cpu(f->type);
	prt_bitflags(out, bch2_sb_fields, fields_have);
	prt_newline(out);

	prt_printf(out, "Features:\t");
	prt_bitflags(out, bch2_sb_features, le64_to_cpu(sb->features[0]));
	prt_newline(out);

	prt_printf(out, "Compat features:\t");
	prt_bitflags(out, bch2_sb_compat, le64_to_cpu(sb->compat[0]));
	prt_newline(out);

	prt_newline(out);
	prt_printf(out, "Options:");
	prt_newline(out);
	scoped_guard(printbuf_indent, out) {
		enum bch_opt_id id;

		for (id = 0; id < bch2_opts_nr; id++) {
			const struct bch_option *opt = bch2_opt_table + id;

			if (opt->get_sb || opt->get_ext) {
				u64 v = bch2_opt_from_sb(sb, id, -1);

				prt_printf(out, "%s:\t", opt->attr.name);
				bch2_opt_to_text(out, NULL, sb, opt, v,
						 OPT_HUMAN_READABLE|OPT_SHOW_FULL_LIST);
				prt_newline(out);
			}
		}
	}

	if (print_layout) {
		prt_newline(out);
		prt_printf(out, "layout:");
		prt_newline(out);
		scoped_guard(printbuf_indent, out)
			bch2_sb_layout_to_text(out, &sb->layout);
	}

	vstruct_for_each(sb, f)
		if (fields & (1 << le32_to_cpu(f->type))) {
			prt_newline(out);
			bch2_sb_field_to_text(out, c, sb, f);
		}
}
