/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_INIT_DEV_H
#define _BCACHEFS_INIT_DEV_H

void bch2_devs_list_to_text(struct printbuf *, struct bch_devs_list *);

struct bch_fs *bch2_dev_to_fs(dev_t);
int bch2_dev_in_fs(struct bch_sb_handle *,
		   struct bch_sb_handle *,
		   struct bch_opts *);

void bch2_dev_io_ref_stop(struct bch_dev *, int);
void bch2_dev_unlink(struct bch_dev *);
void bch2_dev_free(struct bch_dev *);
void __bch2_dev_offline(struct bch_fs *, struct bch_dev *);
int bch2_dev_sysfs_online(struct bch_fs *, struct bch_dev *);
int bch2_dev_alloc(struct bch_fs *, unsigned);
int bch2_dev_attach_bdev(struct bch_fs *, struct bch_sb_handle *, struct printbuf *);

bool bch2_dev_state_allowed(struct bch_fs *, struct bch_dev *,
			    enum bch_member_state, int,
			    struct printbuf *);
int __bch2_dev_set_state(struct bch_fs *, struct bch_dev *,
			 enum bch_member_state, int,
			 struct printbuf *);
int bch2_dev_set_state(struct bch_fs *, struct bch_dev *,
		       enum bch_member_state, int,
		       struct printbuf *);

int bch2_dev_remove(struct bch_fs *, struct bch_dev *, int, struct printbuf *);
int bch2_dev_add(struct bch_fs *, const char *, struct printbuf *);
int bch2_dev_online(struct bch_fs *, const char *, struct printbuf *);
int bch2_dev_offline(struct bch_fs *, struct bch_dev *, int, struct printbuf *);
int bch2_dev_resize(struct bch_fs *, struct bch_dev *, u64, struct printbuf *);

int __bch2_dev_resize_alloc(struct bch_dev *, u64, u64);

struct bch_dev *bch2_dev_lookup(struct bch_fs *, const char *);

extern const struct blk_holder_ops bch2_sb_handle_bdev_ops;

#endif /* _BCACHEFS_INIT_DEV_H */

