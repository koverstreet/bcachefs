#ifndef _BCACHEFS_SUPER_IO_H
#define _BCACHEFS_SUPER_IO_H

#include "extents.h"
#include "eytzinger.h"
#include "super_types.h"
#include "super.h"

#include <asm/byteorder.h>

struct bch_sb_field *bch2_sb_field_get(struct bch_sb *, enum bch_sb_field_type);
struct bch_sb_field *bch2_sb_field_resize(struct bch_sb_handle *,
					  enum bch_sb_field_type, unsigned);
struct bch_sb_field *bch2_fs_sb_field_resize(struct bch_fs *,
					 enum bch_sb_field_type, unsigned);

#define field_to_type(_f, _name)					\
	container_of_or_null(_f, struct bch_sb_field_##_name, field)

#define x(_name, _nr)							\
static inline struct bch_sb_field_##_name *				\
bch2_sb_get_##_name(struct bch_sb *sb)					\
{									\
	return field_to_type(bch2_sb_field_get(sb,			\
				BCH_SB_FIELD_##_name), _name);		\
}									\
									\
static inline struct bch_sb_field_##_name *				\
bch2_sb_resize_##_name(struct bch_sb_handle *sb, unsigned u64s)	\
{									\
	return field_to_type(bch2_sb_field_resize(sb,			\
				BCH_SB_FIELD_##_name, u64s), _name);	\
}									\
									\
static inline struct bch_sb_field_##_name *				\
bch2_fs_sb_resize_##_name(struct bch_fs *c, unsigned u64s)		\
{									\
	return field_to_type(bch2_fs_sb_field_resize(c,			\
				BCH_SB_FIELD_##_name, u64s), _name);	\
}

BCH_SB_FIELDS()
#undef x

extern const char * const bch2_sb_fields[];

static inline bool bch2_sb_test_feature(struct bch_sb *sb,
					enum bch_sb_features f)
{
	unsigned w = f / 64;
	unsigned b = f % 64;

	return le64_to_cpu(sb->features[w]) & (1ULL << b);
}

static inline void bch2_sb_set_feature(struct bch_sb *sb,
				       enum bch_sb_features f)
{
	if (!bch2_sb_test_feature(sb, f)) {
		unsigned w = f / 64;
		unsigned b = f % 64;

		le64_add_cpu(&sb->features[w], 1ULL << b);
	}
}

static inline __le64 bch2_sb_magic(struct bch_fs *c)
{
	__le64 ret;
	memcpy(&ret, &c->sb.uuid, sizeof(ret));
	return ret;
}

static inline __u64 jset_magic(struct bch_fs *c)
{
	return __le64_to_cpu(bch2_sb_magic(c) ^ JSET_MAGIC);
}

static inline __u64 pset_magic(struct bch_fs *c)
{
	return __le64_to_cpu(bch2_sb_magic(c) ^ PSET_MAGIC);
}

static inline __u64 bset_magic(struct bch_fs *c)
{
	return __le64_to_cpu(bch2_sb_magic(c) ^ BSET_MAGIC);
}

int bch2_sb_to_fs(struct bch_fs *, struct bch_sb *);
int bch2_sb_from_fs(struct bch_fs *, struct bch_dev *);

void bch2_free_super(struct bch_sb_handle *);
int bch2_super_realloc(struct bch_sb_handle *, unsigned);

const char *bch2_sb_validate(struct bch_sb_handle *);

int bch2_read_super(const char *, struct bch_opts, struct bch_sb_handle *);
void bch2_write_super(struct bch_fs *);

/* BCH_SB_FIELD_journal: */

static inline unsigned bch2_nr_journal_buckets(struct bch_sb_field_journal *j)
{
	return j
		? (__le64 *) vstruct_end(&j->field) - j->buckets
		: 0;
}

/* BCH_SB_FIELD_members: */

static inline bool bch2_member_exists(struct bch_member *m)
{
	return !bch2_is_zero(m->uuid.b, sizeof(uuid_le));
}

static inline bool bch2_dev_exists(struct bch_sb *sb,
				   struct bch_sb_field_members *mi,
				   unsigned dev)
{
	return dev < sb->nr_devices &&
		bch2_member_exists(&mi->members[dev]);
}

static inline struct bch_member_cpu bch2_mi_to_cpu(struct bch_member *mi)
{
	return (struct bch_member_cpu) {
		.nbuckets	= le64_to_cpu(mi->nbuckets),
		.first_bucket	= le16_to_cpu(mi->first_bucket),
		.bucket_size	= le16_to_cpu(mi->bucket_size),
		.state		= BCH_MEMBER_STATE(mi),
		.tier		= BCH_MEMBER_TIER(mi),
		.replacement	= BCH_MEMBER_REPLACEMENT(mi),
		.discard	= BCH_MEMBER_DISCARD(mi),
		.data_allowed	= BCH_MEMBER_DATA_ALLOWED(mi),
		.valid		= !bch2_is_zero(mi->uuid.b, sizeof(uuid_le)),
	};
}

/* BCH_SB_FIELD_replicas: */

bool bch2_sb_has_replicas(struct bch_fs *, struct bkey_s_c_extent,
			  enum bch_data_type);
bool bch2_sb_has_replicas_devlist(struct bch_fs *, struct bch_devs_list *,
				  enum bch_data_type);
int bch2_check_mark_super(struct bch_fs *, struct bkey_s_c_extent,
			  enum bch_data_type);
int bch2_check_mark_super_devlist(struct bch_fs *, struct bch_devs_list *,
				  enum bch_data_type);

int bch2_cpu_replicas_to_text(struct bch_replicas_cpu *, char *, size_t);
int bch2_sb_replicas_to_text(struct bch_sb_field_replicas *, char *, size_t);

struct replicas_status {
	struct {
		unsigned	nr_online;
		unsigned	nr_offline;
	}			replicas[BCH_DATA_NR];
};

struct replicas_status __bch2_replicas_status(struct bch_fs *,
					      struct bch_devs_mask);
struct replicas_status bch2_replicas_status(struct bch_fs *);
bool bch2_have_enough_devs(struct bch_fs *, struct replicas_status, unsigned);

unsigned bch2_replicas_online(struct bch_fs *, bool);
unsigned bch2_dev_has_data(struct bch_fs *, struct bch_dev *);

int bch2_replicas_gc_end(struct bch_fs *, int);
int bch2_replicas_gc_start(struct bch_fs *, unsigned);

/* iterate over superblock replicas - used by userspace tools: */

static inline struct bch_replicas_entry *
replicas_entry_next(struct bch_replicas_entry *i)
{
	return (void *) i + offsetof(struct bch_replicas_entry, devs) + i->nr;
}

#define for_each_replicas_entry(_r, _i)					\
	for (_i = (_r)->entries;					\
	     (void *) (_i) < vstruct_end(&(_r)->field) && (_i)->data_type;\
	     (_i) = replicas_entry_next(_i))

#endif /* _BCACHEFS_SUPER_IO_H */
