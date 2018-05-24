#ifndef _BCACHEFS_ACL_H
#define _BCACHEFS_ACL_H

#ifdef CONFIG_BCACHEFS_POSIX_ACL

#define BCH_ACL_VERSION	0x0001

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
	__le32		e_id;
} bch_acl_entry;

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
} bch_acl_entry_short;

typedef struct {
	__le32		a_version;
} bch_acl_header;

static inline size_t bch2_acl_size(int count)
{
	if (count <= 4) {
		return sizeof(bch_acl_header) +
		       count * sizeof(bch_acl_entry_short);
	} else {
		return sizeof(bch_acl_header) +
		       4 * sizeof(bch_acl_entry_short) +
		       (count - 4) * sizeof(bch_acl_entry);
	}
}

static inline int bch2_acl_count(size_t size)
{
	ssize_t s;

	size -= sizeof(bch_acl_header);
	s = size - 4 * sizeof(bch_acl_entry_short);
	if (s < 0) {
		if (size % sizeof(bch_acl_entry_short))
			return -1;
		return size / sizeof(bch_acl_entry_short);
	} else {
		if (s % sizeof(bch_acl_entry))
			return -1;
		return s / sizeof(bch_acl_entry) + 4;
	}
}

struct posix_acl;

extern struct posix_acl *bch2_get_acl(struct inode *, int);
extern int __bch2_set_acl(struct inode *, struct posix_acl *, int);
extern int bch2_set_acl(struct inode *, struct posix_acl *, int);

#else

static inline int __bch2_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	return 0;
}

static inline int bch2_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	return 0;
}

#endif /* CONFIG_BCACHEFS_POSIX_ACL */

#endif /* _BCACHEFS_ACL_H */
