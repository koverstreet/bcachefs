// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"

#include "alloc/buckets.h"

#include "btree/bkey_buf.h"
#include "btree/bkey_methods.h"
#include "btree/cache.h"
#include "btree/iter.h"
#include "btree/locking.h"
#include "btree/read.h"
#include "btree/sort.h"
#include "btree/update.h"

#include "data/checksum.h"
#include "data/extents.h"

#include "debug/async_objs.h"

#include "init/error.h"
#include "init/fs.h"
#include "init/recovery.h"

#include "journal/seq_blacklist.h"

#include "sb/counters.h"

#include "sb/io.h"

#include "util/enumerated_ref.h"

#include <linux/moduleparam.h>
#include <linux/sched/mm.h>

static __maybe_unused unsigned bch2_btree_read_corrupt_ratio;
static __maybe_unused int bch2_btree_read_corrupt_device;

#ifdef CONFIG_BCACHEFS_DEBUG
module_param_named(btree_read_corrupt_ratio, bch2_btree_read_corrupt_ratio, uint, 0644);
MODULE_PARM_DESC(btree_read_corrupt_ratio, "");

module_param_named(btree_read_corrupt_device, bch2_btree_read_corrupt_device, int, 0644);
MODULE_PARM_DESC(btree_read_corrupt_ratio, "");
#endif

static void bch2_btree_node_header_to_text(struct printbuf *out, struct btree_node *bn)
{
	bch2_btree_id_level_to_text(out, BTREE_NODE_ID(bn), BTREE_NODE_LEVEL(bn));
	prt_printf(out, " seq %llx %llu\n", bn->keys.seq, BTREE_NODE_SEQ(bn));
	prt_str(out, "min: ");
	bch2_bpos_to_text(out, bn->min_key);
	prt_newline(out);
	prt_str(out, "max: ");
	bch2_bpos_to_text(out, bn->max_key);
}

void bch2_btree_node_io_unlock(struct btree *b)
{
	EBUG_ON(!btree_node_write_in_flight(b));

	clear_btree_node_write_in_flight_inner(b);
	clear_btree_node_write_in_flight(b);
	smp_mb__after_atomic();
	wake_up_bit(&b->flags, BTREE_NODE_write_in_flight);
}

void bch2_btree_node_io_lock(struct btree *b)
{
	wait_on_bit_lock_io(&b->flags, BTREE_NODE_write_in_flight,
			    TASK_UNINTERRUPTIBLE);
}

void __bch2_btree_node_wait_on_read(struct btree *b)
{
	wait_on_bit_io(&b->flags, BTREE_NODE_read_in_flight,
		       TASK_UNINTERRUPTIBLE);
}

void __bch2_btree_node_wait_on_write(struct btree *b)
{
	wait_on_bit_io(&b->flags, BTREE_NODE_write_in_flight,
		       TASK_UNINTERRUPTIBLE);
}

void bch2_btree_node_wait_on_read(struct btree *b)
{
	wait_on_bit_io(&b->flags, BTREE_NODE_read_in_flight,
		       TASK_UNINTERRUPTIBLE);
}

void bch2_btree_node_wait_on_write(struct btree *b)
{
	wait_on_bit_io(&b->flags, BTREE_NODE_write_in_flight,
		       TASK_UNINTERRUPTIBLE);
}

__printf(7, 0)
static void btree_err_msg(struct printbuf *out, struct bch_fs *c, struct bch_dev *ca,
			  struct btree *b, struct bset *i, struct bkey_packed *k,
			  const char *fmt, va_list args)
{
	if (ca)
		prt_printf(out, "%s ", ca->name);

	prt_printf(out, "node offset %u/%u",
		   b->written, btree_ptr_sectors_written(bkey_i_to_s_c(&b->key)));
	if (i)
		prt_printf(out, " bset u64s %u", le16_to_cpu(i->u64s));
	if (k)
		prt_printf(out, " bset byte offset %lu",
			   (unsigned long)(void *)k -
			   ((unsigned long)(void *)i & ~511UL));
	prt_str(out, ": ");

	prt_vprintf(out, fmt, args);
	prt_newline(out);
}

__printf(11, 12)
static int __btree_err(enum bch_fsck_flags flags,
		       struct bch_fs *c,
		       struct bch_dev *ca,
		       struct btree *b,
		       struct bset *i,
		       struct bkey_packed *k,
		       int rw,
		       enum bch_sb_error_id err_type,
		       struct bch_io_failures *failed,
		       struct printbuf *err_msg,
		       const char *fmt, ...)
{
	if (c->recovery.current_pass == BCH_RECOVERY_PASS_scan_for_btree_nodes)
		return flags & FSCK_CAN_FIX
			? bch_err_throw(c, fsck_fix)
			: bch_err_throw(c, btree_node_validate_err);

	bch2_sb_error_count(c, err_type);

	if (rw == READ) {
		va_list args;
		va_start(args, fmt);
		btree_err_msg(err_msg, c, ca, b, i, k, fmt, args);
		va_end(args);

		bch2_dev_io_failures_mut(failed, ca->dev_idx)->errcode =
			bch_err_throw(c, btree_node_validate_err);

		struct extent_ptr_decoded pick;
		bool have_retry = bch2_bkey_pick_read_device(c,
					bkey_i_to_s_c(&b->key),
					failed, &pick, -1) == 1;

		return !have_retry &&
			(flags & FSCK_CAN_FIX) &&
			bch2_fsck_err_opt(c, FSCK_CAN_FIX, err_type) == -BCH_ERR_fsck_fix
			? bch_err_throw(c, fsck_fix)
			: bch_err_throw(c, btree_node_validate_err);
	} else {
		CLASS(bch_log_msg, msg)(c);

		prt_str(&msg.m, "corrupt btree node before write at btree ");
		bch2_btree_pos_to_text(&msg.m, c, b);
		prt_newline(&msg.m);

		va_list args;
		va_start(args, fmt);
		btree_err_msg(&msg.m, c, NULL, b, i, k, fmt, args);
		va_end(args);

		bch2_fs_emergency_read_only(c, &msg.m);

		return bch_err_throw(c, fsck_errors_not_fixed);
	}
}

#define btree_err(type, c, ca, b, i, k, _err_type, msg, ...)		\
({									\
	int _ret = __btree_err(type, c, ca, b, i, k, write,		\
			       BCH_FSCK_ERR_##_err_type,		\
			       failed, err_msg,				\
			       msg, ##__VA_ARGS__);			\
									\
	if (!bch2_err_matches(_ret, BCH_ERR_fsck_fix)) {		\
		ret = _ret;						\
		goto fsck_err;						\
	}								\
									\
	true;								\
})

#define btree_err_on(cond, ...)	((cond) ? btree_err(__VA_ARGS__) : false)

/*
 * When btree topology repair changes the start or end of a node, that might
 * mean we have to drop keys that are no longer inside the node:
 */
__cold
void bch2_btree_node_drop_keys_outside_node(struct btree *b)
{
	for_each_bset(b, t) {
		struct bset *i = bset(b, t);
		struct bkey_packed *k;

		for (k = i->start; k != vstruct_last(i); k = bkey_p_next(k))
			if (bkey_cmp_left_packed(b, k, &b->data->min_key) >= 0)
				break;

		if (k != i->start) {
			unsigned shift = (u64 *) k - (u64 *) i->start;

			memmove_u64s_down(i->start, k,
					  (u64 *) vstruct_end(i) - (u64 *) k);
			i->u64s = cpu_to_le16(le16_to_cpu(i->u64s) - shift);
			set_btree_bset_end(b, t);
		}

		for (k = i->start; k != vstruct_last(i); k = bkey_p_next(k))
			if (bkey_cmp_left_packed(b, k, &b->data->max_key) > 0)
				break;

		if (k != vstruct_last(i)) {
			i->u64s = cpu_to_le16((u64 *) k - (u64 *) i->start);
			set_btree_bset_end(b, t);
		}
	}

	/*
	 * Always rebuild search trees: eytzinger search tree nodes directly
	 * depend on the values of min/max key:
	 */
	bch2_bset_set_no_aux_tree(b, b->set);
	bch2_btree_build_aux_trees(b);
	b->nr = bch2_btree_node_count_keys(b);

	struct bkey_s_c k;
	struct bkey unpacked;
	struct btree_node_iter iter;
	for_each_btree_node_key_unpack(b, k, &iter, &unpacked) {
		BUG_ON(bpos_lt(k.k->p, b->data->min_key));
		BUG_ON(bpos_gt(k.k->p, b->data->max_key));
	}
}

int bch2_validate_bset(struct bch_fs *c, struct bch_dev *ca,
		       struct btree *b, struct bset *i,
		       unsigned offset, int write,
		       struct bch_io_failures *failed,
		       struct printbuf *err_msg)
{
	unsigned version = le16_to_cpu(i->version);
	CLASS(printbuf, buf1)();
	CLASS(printbuf, buf2)();
	int ret = 0;

	btree_err_on(!bch2_version_compatible(version),
		     0,
		     c, ca, b, i, NULL,
		     btree_node_unsupported_version,
		     "unsupported bset version %u.%u",
		     BCH_VERSION_MAJOR(version),
		     BCH_VERSION_MINOR(version));

	if (c->recovery.current_pass != BCH_RECOVERY_PASS_scan_for_btree_nodes &&
	    btree_err_on(version < c->sb.version_min,
			 FSCK_CAN_FIX,
			 c, ca, b, i, NULL,
			 btree_node_bset_older_than_sb_min,
			 "bset version %u older than superblock version_min %u",
			 version, c->sb.version_min)) {
		if (bch2_version_compatible(version)) {
			guard(mutex)(&c->sb_lock);
			c->disk_sb.sb->version_min = cpu_to_le16(version);
			bch2_write_super(c);
		} else {
			/* We have no idea what's going on: */
			i->version = cpu_to_le16(c->sb.version);
		}
	}

	if (btree_err_on(BCH_VERSION_MAJOR(version) >
			 BCH_VERSION_MAJOR(c->sb.version),
			 FSCK_CAN_FIX,
			 c, ca, b, i, NULL,
			 btree_node_bset_newer_than_sb,
			 "bset version %u newer than superblock version %u",
			 version, c->sb.version)) {
		guard(mutex)(&c->sb_lock);
		c->disk_sb.sb->version = cpu_to_le16(version);
		bch2_write_super(c);
	}

	btree_err_on(BSET_SEPARATE_WHITEOUTS(i),
		     0,
		     c, ca, b, i, NULL,
		     btree_node_unsupported_version,
		     "BSET_SEPARATE_WHITEOUTS no longer supported");

	btree_err_on(offset && !i->u64s,
		     FSCK_CAN_FIX,
		     c, ca, b, i, NULL,
		     bset_empty,
		     "empty bset");

	btree_err_on(BSET_OFFSET(i) && BSET_OFFSET(i) != offset,
		     FSCK_CAN_FIX,
		     c, ca, b, i, NULL,
		     bset_wrong_sector_offset,
		     "bset at wrong sector offset");

	if (!offset) {
		struct btree_node *bn =
			container_of(i, struct btree_node, keys);
		/* These indicate that we read the wrong btree node: */

		if (b->key.k.type == KEY_TYPE_btree_ptr_v2) {
			struct bch_btree_ptr_v2 *bp =
				&bkey_i_to_btree_ptr_v2(&b->key)->v;

			/* XXX endianness */
			btree_err_on(bp->seq != bn->keys.seq,
				     0,
				     c, ca, b, NULL, NULL,
				     bset_bad_seq,
				     "incorrect sequence number (wrong btree node)");
		}

		btree_err_on(BTREE_NODE_ID(bn) != b->c.btree_id,
			     0,
			     c, ca, b, i, NULL,
			     btree_node_bad_btree,
			     "incorrect btree id");

		btree_err_on(BTREE_NODE_LEVEL(bn) != b->c.level,
			     0,
			     c, ca, b, i, NULL,
			     btree_node_bad_level,
			     "incorrect level");

		if (!write)
			compat_btree_node(b->c.level, b->c.btree_id, version,
					  BSET_BIG_ENDIAN(i), write, bn);

		if (b->key.k.type == KEY_TYPE_btree_ptr_v2) {
			struct bch_btree_ptr_v2 *bp =
				&bkey_i_to_btree_ptr_v2(&b->key)->v;

			if (BTREE_PTR_RANGE_UPDATED(bp)) {
				b->data->min_key = bp->min_key;
				b->data->max_key = b->key.k.p;
			}

			btree_err_on(!bpos_eq(b->data->min_key, bp->min_key),
				     0,
				     c, ca, b, NULL, NULL,
				     btree_node_bad_min_key,
				     "incorrect min_key: got %s should be %s",
				     (printbuf_reset(&buf1),
				      bch2_bpos_to_text(&buf1, bn->min_key), buf1.buf),
				     (printbuf_reset(&buf2),
				      bch2_bpos_to_text(&buf2, bp->min_key), buf2.buf));
		}

		btree_err_on(!bpos_eq(bn->max_key, b->key.k.p),
			     0,
			     c, ca, b, i, NULL,
			     btree_node_bad_max_key,
			     "incorrect max key %s",
			     (printbuf_reset(&buf1),
			      bch2_bpos_to_text(&buf1, bn->max_key), buf1.buf));

		if (write)
			compat_btree_node(b->c.level, b->c.btree_id, version,
					  BSET_BIG_ENDIAN(i), write, bn);

		btree_err_on(bch2_bkey_format_invalid(c, &bn->format, write, &buf1),
			     0,
			     c, ca, b, i, NULL,
			     btree_node_bad_format,
			     "invalid bkey format: %s\n%s", buf1.buf,
			     (printbuf_reset(&buf2),
			      bch2_bkey_format_to_text(&buf2, &bn->format), buf2.buf));
		printbuf_reset(&buf1);

		compat_bformat(b->c.level, b->c.btree_id, version,
			       BSET_BIG_ENDIAN(i), write,
			       &bn->format);
	}
fsck_err:
	return ret;
}

static int btree_node_bkey_val_validate(struct bch_fs *c, struct btree *b,
					struct bkey_s_c k,
					enum bch_validate_flags flags)
{
	return bch2_bkey_val_validate(c, k, (struct bkey_validate_context) {
		.from	= BKEY_VALIDATE_btree_node,
		.level	= b->c.level,
		.btree	= b->c.btree_id,
		.flags	= flags
	});
}

static int bset_key_validate(struct bch_fs *c, struct btree *b,
			     struct bkey_s_c k,
			     bool updated_range,
			     enum bch_validate_flags flags)
{
	struct bkey_validate_context from = (struct bkey_validate_context) {
		.from	= BKEY_VALIDATE_btree_node,
		.level	= b->c.level,
		.btree	= b->c.btree_id,
		.flags	= flags,
	};
	return __bch2_bkey_validate(c, k, from) ?:
		(!updated_range ? bch2_bkey_in_btree_node(c, b, k, from) : 0) ?:
		(flags & BCH_VALIDATE_write ? btree_node_bkey_val_validate(c, b, k, flags) : 0);
}

static bool bkey_packed_valid(struct bch_fs *c, struct btree *b,
			 struct bset *i, struct bkey_packed *k)
{
	if (bkey_p_next(k) > vstruct_last(i))
		return false;

	if (k->format > KEY_FORMAT_CURRENT)
		return false;

	if (!bkeyp_u64s_valid(&b->format, k))
		return false;

	struct bkey tmp;
	struct bkey_s u = __bkey_disassemble(b, k, &tmp);
	return !__bch2_bkey_validate(c, u.s_c,
				     (struct bkey_validate_context) {
					.from	= BKEY_VALIDATE_btree_node,
					.level	= b->c.level,
					.btree	= b->c.btree_id,
					.flags	= BCH_VALIDATE_silent
				     });
}

static inline int btree_node_read_bkey_cmp(const struct btree *b,
				const struct bkey_packed *l,
				const struct bkey_packed *r)
{
	return bch2_bkey_cmp_packed(b, l, r)
		?: (int) bkey_deleted(r) - (int) bkey_deleted(l);
}

int bch2_validate_bset_keys(struct bch_fs *c,
			    struct bch_dev *ca,
			    struct btree *b,
			    struct bset *i, int write,
			    struct bch_io_failures *failed,
			    struct printbuf *err_msg)
{
	unsigned version = le16_to_cpu(i->version);
	struct bkey_packed *k, *prev = NULL;
	CLASS(printbuf, buf)();
	bool updated_range = b->key.k.type == KEY_TYPE_btree_ptr_v2 &&
		BTREE_PTR_RANGE_UPDATED(&bkey_i_to_btree_ptr_v2(&b->key)->v);
	int ret = 0;

	for (k = i->start;
	     k != vstruct_last(i);) {
		struct bkey_s u;
		struct bkey tmp;
		unsigned next_good_key;

		if (btree_err_on(bkey_p_next(k) > vstruct_last(i),
				 FSCK_CAN_FIX,
				 c, ca, b, i, k,
				 btree_node_bkey_past_bset_end,
				 "key extends past end of bset")) {
			i->u64s = cpu_to_le16((u64 *) k - i->_data);
			break;
		}

		if (btree_err_on(k->format > KEY_FORMAT_CURRENT,
				 FSCK_CAN_FIX,
				 c, ca, b, i, k,
				 btree_node_bkey_bad_format,
				 "invalid bkey format %u", k->format))
			goto drop_this_key;

		if (btree_err_on(!bkeyp_u64s_valid(&b->format, k),
				 FSCK_CAN_FIX,
				 c, ca, b, i, k,
				 btree_node_bkey_bad_u64s,
				 "bad k->u64s %u (min %u max %zu)", k->u64s,
				 bkeyp_key_u64s(&b->format, k),
				 U8_MAX - BKEY_U64s + bkeyp_key_u64s(&b->format, k)))
			goto drop_this_key;

		if (!write)
			bch2_bkey_compat(c, b->c.level, b->c.btree_id, version,
				    BSET_BIG_ENDIAN(i), write,
				    &b->format, k);

		u = __bkey_disassemble(b, k, &tmp);

		ret = bset_key_validate(c, b, u.s_c, updated_range, write);
		if (ret == -BCH_ERR_fsck_delete_bkey)
			goto drop_this_key;
		if (ret)
			goto fsck_err;

		if (write)
			bch2_bkey_compat(c, b->c.level, b->c.btree_id, version,
				    BSET_BIG_ENDIAN(i), write,
				    &b->format, k);

		if (prev && btree_node_read_bkey_cmp(b, prev, k) >= 0) {
			struct bkey up = bkey_unpack_key(b, prev);

			printbuf_reset(&buf);
			prt_printf(&buf, "keys out of order: ");
			bch2_bkey_to_text(&buf, &up);
			prt_printf(&buf, " > ");
			bch2_bkey_to_text(&buf, u.k);

			if (btree_err(FSCK_CAN_FIX,
				      c, ca, b, i, k,
				      btree_node_bkey_out_of_order,
				      "%s", buf.buf))
				goto drop_this_key;
		}

		prev = k;
		k = bkey_p_next(k);
		continue;
drop_this_key:
		ret = 0;
		next_good_key = k->u64s;

		if (!next_good_key ||
		    (BSET_BIG_ENDIAN(i) == CPU_BIG_ENDIAN &&
		     version >= bcachefs_metadata_version_snapshot)) {
			/*
			 * only do scanning if bch2_bkey_compat() has nothing to
			 * do
			 */

			if (!bkey_packed_valid(c, b, i, (void *) ((u64 *) k + next_good_key))) {
				for (next_good_key = 1;
				     next_good_key < (u64 *) vstruct_last(i) - (u64 *) k;
				     next_good_key++)
					if (bkey_packed_valid(c, b, i, (void *) ((u64 *) k + next_good_key)))
						goto got_good_key;
			}

			/*
			 * didn't find a good key, have to truncate the rest of
			 * the bset
			 */
			next_good_key = (u64 *) vstruct_last(i) - (u64 *) k;
		}
got_good_key:
		le16_add_cpu(&i->u64s, -next_good_key);
		memmove_u64s_down(k, (u64 *) k + next_good_key, (u64 *) vstruct_end(i) - (u64 *) k);
		set_btree_node_need_rewrite(b);
		set_btree_node_need_rewrite_error(b);
	}
fsck_err:
	return ret;
}

static bool btree_node_degraded(struct bch_fs *c, struct btree *b)
{
	guard(rcu)();
	bkey_for_each_ptr(bch2_bkey_ptrs(bkey_i_to_s(&b->key)), ptr) {
		if (ptr->dev == BCH_SB_MEMBER_INVALID)
			continue;

		struct bch_dev *ca = bch2_dev_rcu(c, ptr->dev);
		if (!ca || ca->mi.state != BCH_MEMBER_STATE_rw)
			return true;
	}
	return false;
}

int bch2_btree_node_read_done(struct bch_fs *c, struct bch_dev *ca,
			      struct btree *b,
			      struct bch_io_failures *failed,
			      struct printbuf *err_msg)
{
	struct btree_node_entry *bne;
	struct sort_iter *iter;
	struct btree_node *sorted;
	struct bkey_packed *k;
	struct bset *i;
	bool used_mempool, blacklisted;
	bool updated_range = b->key.k.type == KEY_TYPE_btree_ptr_v2 &&
		BTREE_PTR_RANGE_UPDATED(&bkey_i_to_btree_ptr_v2(&b->key)->v);
	unsigned ptr_written = btree_ptr_sectors_written(bkey_i_to_s_c(&b->key));
	u64 max_journal_seq = 0;
	CLASS(printbuf, buf)();
	int ret = 0, write = READ;
	u64 start_time = local_clock();

	b->version_ondisk = U16_MAX;
	/* We might get called multiple times on read retry: */
	b->written = 0;

	iter = mempool_alloc(&c->btree.fill_iter, GFP_NOFS);
	sort_iter_init(iter, b, (btree_blocks(c) + 1) * 2);

	if (bch2_meta_read_fault("btree"))
		btree_err(0,
			  c, ca, b, NULL, NULL,
			  btree_node_fault_injected,
			  "dynamic fault");

	btree_err_on(le64_to_cpu(b->data->magic) != bset_magic(c),
		     0,
		     c, ca, b, NULL, NULL,
		     btree_node_bad_magic,
		     "bad magic: want %llx, got %llx",
		     bset_magic(c), le64_to_cpu(b->data->magic));

	while (b->written < (ptr_written ?: btree_sectors(c))) {
		unsigned sectors;
		bool first = !b->written;

		if (first) {
			bne = NULL;
			i = &b->data->keys;
		} else {
			bne = write_block(b);
			i = &bne->keys;

			if (i->seq != b->data->keys.seq)
				break;
		}

		struct nonce nonce = btree_nonce(i, b->written << 9);
		bool good_csum_type = bch2_checksum_type_valid(c, BSET_CSUM_TYPE(i));

		btree_err_on(!good_csum_type,
			     bch2_csum_type_is_encryption(BSET_CSUM_TYPE(i))
			     ? 0
			     : FSCK_CAN_FIX,
			     c, ca, b, i, NULL,
			     bset_unknown_csum,
			     "unknown checksum type %llu", BSET_CSUM_TYPE(i));

		if (first) {
			sectors = vstruct_sectors(b->data, c->block_bits);
			if (btree_err_on(b->written + sectors > (ptr_written ?: btree_sectors(c)),
					 FSCK_CAN_FIX,
					 c, ca, b, i, NULL,
					 bset_past_end_of_btree_node,
					 "bset past end of btree node (offset %u len %u but written %zu)",
					 b->written, sectors, ptr_written ?: btree_sectors(c)))
				i->u64s = 0;
			if (good_csum_type) {
				struct bch_csum csum = csum_vstruct(c, BSET_CSUM_TYPE(i), nonce, b->data);
				bool csum_bad = bch2_crc_cmp(b->data->csum, csum);
				if (csum_bad)
					bch2_io_error(ca, BCH_MEMBER_ERROR_checksum);

				btree_err_on(csum_bad,
					     FSCK_CAN_FIX,
					     c, ca, b, i, NULL,
					     bset_bad_csum,
					     "%s",
					     (printbuf_reset(&buf),
					      bch2_csum_err_msg(&buf, BSET_CSUM_TYPE(i), b->data->csum, csum),
					      buf.buf));

				ret = bset_encrypt(c, i, b->written << 9);
				if (bch2_fs_fatal_err_on(ret, c,
							 "decrypting btree node: %s", bch2_err_str(ret)))
					goto fsck_err;
			}

			if (b->key.k.type == KEY_TYPE_btree_ptr_v2) {
				struct bch_btree_ptr_v2 *bp =
					&bkey_i_to_btree_ptr_v2(&b->key)->v;

				bch2_bpos_to_text(&buf, b->data->min_key);
				prt_str(&buf, "-");
				bch2_bpos_to_text(&buf, b->data->max_key);

				btree_err_on(b->data->keys.seq != bp->seq,
					     0,
					     c, ca, b, NULL, NULL,
					     btree_node_bad_seq,
					     "got wrong btree node: got\n%s",
					     (printbuf_reset(&buf),
					      printbuf_indent_add(&buf, 2),
					      bch2_btree_node_header_to_text(&buf, b->data),
					      buf.buf));
			} else {
				btree_err_on(!b->data->keys.seq,
					     0,
					     c, ca, b, NULL, NULL,
					     btree_node_bad_seq,
					     "bad btree header: seq 0\n%s",
					     (printbuf_reset(&buf),
					      bch2_btree_node_header_to_text(&buf, b->data),
					      buf.buf));
			}

			btree_err_on(btree_node_type_is_extents(btree_node_type(b)) &&
				     !BTREE_NODE_NEW_EXTENT_OVERWRITE(b->data),
				     0,
				     c, ca, b, NULL, NULL,
				     btree_node_unsupported_version,
				     "btree node does not have NEW_EXTENT_OVERWRITE set");
		} else {
			sectors = vstruct_sectors(bne, c->block_bits);
			if (btree_err_on(b->written + sectors > (ptr_written ?: btree_sectors(c)),
					 FSCK_CAN_FIX,
					 c, ca, b, i, NULL,
					 bset_past_end_of_btree_node,
					 "bset past end of btree node (offset %u len %u but written %zu)",
					 b->written, sectors, ptr_written ?: btree_sectors(c)))
				i->u64s = 0;
			if (good_csum_type) {
				struct bch_csum csum = csum_vstruct(c, BSET_CSUM_TYPE(i), nonce, bne);
				bool csum_bad = bch2_crc_cmp(bne->csum, csum);
				if (ca && csum_bad)
					bch2_io_error(ca, BCH_MEMBER_ERROR_checksum);

				btree_err_on(csum_bad,
					     FSCK_CAN_FIX,
					     c, ca, b, i, NULL,
					     bset_bad_csum,
					     "%s",
					     (printbuf_reset(&buf),
					      bch2_csum_err_msg(&buf, BSET_CSUM_TYPE(i), bne->csum, csum),
					      buf.buf));

				ret = bset_encrypt(c, i, b->written << 9);
				if (bch2_fs_fatal_err_on(ret, c,
						"decrypting btree node: %s", bch2_err_str(ret)))
					goto fsck_err;
			}
		}

		b->version_ondisk = min(b->version_ondisk,
					le16_to_cpu(i->version));

		ret = bch2_validate_bset(c, ca, b, i, b->written, READ, failed, err_msg);
		if (ret)
			goto fsck_err;

		if (!b->written)
			btree_node_set_format(b, b->data->format);

		ret = bch2_validate_bset_keys(c, ca, b, i, READ, failed, err_msg);
		if (ret)
			goto fsck_err;

		SET_BSET_BIG_ENDIAN(i, CPU_BIG_ENDIAN);

		blacklisted = bch2_journal_seq_is_blacklisted(c,
					le64_to_cpu(i->journal_seq),
					true);

		btree_err_on(blacklisted && first,
			     FSCK_CAN_FIX,
			     c, ca, b, i, NULL,
			     bset_blacklisted_journal_seq,
			     "first btree node btree/bset.has blacklisted journal seq (%llu)",
			     le64_to_cpu(i->journal_seq));

		btree_err_on(blacklisted && ptr_written,
			     FSCK_CAN_FIX,
			     c, ca, b, i, NULL,
			     first_bset_blacklisted_journal_seq,
			     "found blacklisted bset (journal seq %llu) in btree node at offset %u-%u/%u",
			     le64_to_cpu(i->journal_seq),
			     b->written, b->written + sectors, ptr_written);

		b->written = min(b->written + sectors, btree_sectors(c));

		if (blacklisted && !first)
			continue;

		sort_iter_add(iter,
			      vstruct_idx(i, 0),
			      vstruct_last(i));

		max_journal_seq = max(max_journal_seq, le64_to_cpu(i->journal_seq));
	}

	if (ptr_written) {
		btree_err_on(b->written < ptr_written,
			     FSCK_CAN_FIX,
			     c, ca, b, NULL, NULL,
			     btree_node_data_missing,
			     "btree node data missing: expected %u sectors, found %u",
			     ptr_written, b->written);
	} else {
		for (bne = write_block(b);
		     bset_byte_offset(b, bne) < btree_buf_bytes(b);
		     bne = (void *) bne + block_bytes(c))
			btree_err_on(bne->keys.seq == b->data->keys.seq &&
				     !bch2_journal_seq_is_blacklisted(c,
								      le64_to_cpu(bne->keys.journal_seq),
								      true),
				     FSCK_CAN_FIX,
				     c, ca, b, NULL, NULL,
				     btree_node_bset_after_end,
				     "found bset signature after last bset");
	}

	sorted = bch2_btree_bounce_alloc(c, btree_buf_bytes(b), &used_mempool);
	sorted->keys.u64s = 0;

	b->nr = bch2_key_sort_fix_overlapping(c, &sorted->keys, iter);
	memset((uint8_t *)(sorted + 1) + b->nr.live_u64s * sizeof(u64), 0,
			btree_buf_bytes(b) -
			sizeof(struct btree_node) -
			b->nr.live_u64s * sizeof(u64));

	b->data->keys.u64s = sorted->keys.u64s;
	*sorted = *b->data;
	swap(sorted, b->data);
	set_btree_bset(b, b->set, &b->data->keys);
	b->nsets = 1;
	b->data->keys.journal_seq = cpu_to_le64(max_journal_seq);

	BUG_ON(b->nr.live_u64s != le16_to_cpu(b->data->keys.u64s));

	bch2_btree_bounce_free(c, btree_buf_bytes(b), used_mempool, sorted);

	i = &b->data->keys;
	for (k = i->start; k != vstruct_last(i);) {
		struct bkey tmp;
		struct bkey_s u = __bkey_disassemble(b, k, &tmp);

		ret = btree_node_bkey_val_validate(c, b, u.s_c, READ);
		if (ret == -BCH_ERR_fsck_delete_bkey ||
		    (static_branch_unlikely(&bch2_inject_invalid_keys) &&
		     !bversion_cmp(u.k->bversion, MAX_VERSION))) {
			btree_keys_account_key_drop(&b->nr, 0, k);

			i->u64s = cpu_to_le16(le16_to_cpu(i->u64s) - k->u64s);
			memmove_u64s_down(k, bkey_p_next(k),
					  (u64 *) vstruct_end(i) - (u64 *) k);
			set_btree_bset_end(b, b->set);
			set_btree_node_need_rewrite(b);
			set_btree_node_need_rewrite_error(b);
			ret = 0;
			continue;
		}
		if (ret)
			goto fsck_err;

		if (u.k->type == KEY_TYPE_btree_ptr_v2) {
			struct bkey_s_btree_ptr_v2 bp = bkey_s_to_btree_ptr_v2(u);

			bp.v->mem_ptr = 0;
		}

		k = bkey_p_next(k);
	}

	bch2_bset_build_aux_tree(b, b->set, false);

	bch2_set_bset_needs_whiteout(btree_bset_first(b), true);

	btree_node_reset_sib_u64s(b);

	if (updated_range)
		bch2_btree_node_drop_keys_outside_node(b);

	if (!ptr_written) {
		set_btree_node_need_rewrite(b);
		set_btree_node_need_rewrite_ptr_written_zero(b);
	}
fsck_err:
	mempool_free(iter, &c->btree.fill_iter);
	bch2_time_stats_update(&c->times[BCH_TIME_btree_node_read_done], start_time);
	return ret;
}

static void btree_node_read_work(struct work_struct *work)
{
	struct btree_read_bio *rb =
		container_of(work, struct btree_read_bio, work);
	struct bch_fs *c	= rb->c;
	struct bch_dev *ca	= rb->have_ioref ? bch2_dev_have_ref(c, rb->pick.ptr.dev) : NULL;
	struct btree *b		= rb->b;
	struct bio *bio		= &rb->bio;
	struct bch_io_failures failed = { .nr = 0 };
	int ret = 0;

	CLASS(printbuf, buf)();
	bch2_log_msg_start(c, &buf);

	prt_printf(&buf, "btree node read error at btree ");
	bch2_btree_pos_to_text(&buf, c, b);
	prt_newline(&buf);

	while (1) {
		if (rb->have_ioref)
			enumerated_ref_put(&ca->io_ref[READ], BCH_DEV_READ_REF_btree_node_read);
		rb->have_ioref = false;

		if (!bio->bi_status) {
			memset(&bio->bi_iter, 0, sizeof(bio->bi_iter));
			bio->bi_iter.bi_size	= btree_buf_bytes(b);

			if (bch2_btree_read_corrupt_device == rb->pick.ptr.dev ||
			    bch2_btree_read_corrupt_device < 0)
				bch2_maybe_corrupt_bio(bio, bch2_btree_read_corrupt_ratio);

			ret = bch2_btree_node_read_done(c, ca, b, &failed, &buf);
		} else {
			ret = __bch2_err_throw(c, -blk_status_to_bch_err(bio->bi_status));
			bch2_mark_io_failure(&failed, &rb->pick, ret);
		}

		if (!ret ||
		    bch2_bkey_pick_read_device(c,
					       bkey_i_to_s_c(&b->key),
					       &failed, &rb->pick, -1) <= 0)
			break;

		ca = bch2_dev_get_ioref(c, rb->pick.ptr.dev, READ, BCH_DEV_READ_REF_btree_node_read);
		rb->have_ioref		= ca != NULL;
		rb->start_time		= local_clock();
		bio_reset(bio, NULL, REQ_OP_READ|REQ_SYNC|REQ_META);
		bio->bi_iter.bi_sector	= rb->pick.ptr.offset;
		bio->bi_iter.bi_size	= btree_buf_bytes(b);

		if (rb->have_ioref) {
			bio_set_dev(bio, ca->disk_sb.bdev);
			submit_bio_wait(bio);
		} else {
			bio->bi_status = BLK_STS_REMOVED;
		}

		bch2_account_io_completion(ca, BCH_MEMBER_ERROR_read,
					   rb->start_time, !bio->bi_status);
	}

	bch2_io_failures_to_text(&buf, c, &failed);

	/*
	 * only print retry success if we read from a replica with no errors
	 */
	if (ret) {
		/*
		 * Initialize buf.suppress before btree_lost_data(); that will
		 * clear it if it did any work (scheduling recovery passes,
		 * marking superblock
		 */
		buf.suppress = !__bch2_ratelimit(c, &c->btree.read_errors_hard);

		set_btree_node_read_error(b);
		bch2_btree_lost_data(c, &buf, b->c.btree_id);
		prt_printf(&buf, "error %s\n", bch2_err_str(ret));
	} else if (failed.nr) {
		/* Separate ratelimit states for soft vs. hard errors */
		buf.suppress = !__bch2_ratelimit(c, &c->btree.read_errors_soft);

		if (!bch2_dev_io_failures(&failed, rb->pick.ptr.dev))
			prt_printf(&buf, "retry success");
		else
			prt_printf(&buf, "repair success");

		if ((failed.nr || btree_node_need_rewrite(b)) &&
		    c->recovery.current_pass != BCH_RECOVERY_PASS_scan_for_btree_nodes) {
			prt_printf(&buf, " (rewriting node)");
			bch2_btree_node_rewrite_async(c, b);
		}

		prt_newline(&buf);
	} else {
		buf.suppress = true;
	}

	if (!buf.suppress)
		bch2_print_str(c, ret ? KERN_ERR : KERN_NOTICE, buf.buf);

	/*
	 * Do this late; unlike other btree_node_need_rewrite() cases if a node
	 * is merely degraded we should rewrite it before we update it, but we
	 * don't need to kick off an async rewrite now:
	 */
	if (btree_node_degraded(c, b)) {
		set_btree_node_need_rewrite(b);
		set_btree_node_need_rewrite_degraded(b);
	}

	async_object_list_del(c, btree_read_bio, rb->list_idx);
	bch2_time_stats_update(&c->times[BCH_TIME_btree_node_read],
			       rb->start_time);
	bio_put(&rb->bio);
	clear_btree_node_read_in_flight(b);
	smp_mb__after_atomic();
	wake_up_bit(&b->flags, BTREE_NODE_read_in_flight);
}

static void btree_node_read_endio(struct bio *bio)
{
	struct btree_read_bio *rb =
		container_of(bio, struct btree_read_bio, bio);
	struct bch_fs *c	= rb->c;
	struct bch_dev *ca	= rb->have_ioref
		? bch2_dev_have_ref(c, rb->pick.ptr.dev) : NULL;

	bch2_account_io_completion(ca, BCH_MEMBER_ERROR_read,
				   rb->start_time, !bio->bi_status);

	queue_work(c->btree.read_complete_wq, &rb->work);
}

void bch2_btree_read_bio_to_text(struct printbuf *out, struct btree_read_bio *rbio)
{
	bch2_bio_to_text(out, &rbio->bio);
}

void bch2_btree_node_read(struct btree_trans *trans, struct btree *b,
			  bool sync)
{
	struct bch_fs *c = trans->c;
	struct extent_ptr_decoded pick;
	struct btree_read_bio *rb;
	struct bch_dev *ca;
	struct bio *bio;
	int ret;

	trace_btree_node(c, b, btree_node_read);

	ret = bch2_bkey_pick_read_device(c, bkey_i_to_s_c(&b->key),
					 NULL, &pick, -1);

	if (ret <= 0) {
		CLASS(bch_log_msg_ratelimited, msg)(c);

		prt_str(&msg.m, "btree node read error: no device to read from\n at ");
		bch2_btree_pos_to_text(&msg.m, c, b);
		prt_newline(&msg.m);
		bch2_btree_lost_data(c, &msg.m, b->c.btree_id);

		if (c->recovery.passes_complete & BIT_ULL(BCH_RECOVERY_PASS_check_topology))
			bch2_fs_emergency_read_only(c, &msg.m);

		set_btree_node_read_error(b);
		clear_btree_node_read_in_flight(b);
		smp_mb__after_atomic();
		wake_up_bit(&b->flags, BTREE_NODE_read_in_flight);
		return;
	}

	ca = bch2_dev_get_ioref(c, pick.ptr.dev, READ, BCH_DEV_READ_REF_btree_node_read);

	bio = bio_alloc_bioset(NULL,
			       buf_pages(b->data, btree_buf_bytes(b)),
			       REQ_OP_READ|REQ_SYNC|REQ_META,
			       GFP_NOFS,
			       &c->btree.bio);
	rb = container_of(bio, struct btree_read_bio, bio);
	rb->c			= c;
	rb->b			= b;
	rb->start_time		= local_clock();
	rb->have_ioref		= ca != NULL;
	rb->pick		= pick;
	INIT_WORK(&rb->work, btree_node_read_work);
	bio->bi_iter.bi_sector	= pick.ptr.offset;
	bio->bi_end_io		= btree_node_read_endio;
	bch2_bio_map(bio, b->data, btree_buf_bytes(b));

	async_object_list_add(c, btree_read_bio, rb, &rb->list_idx);

	if (rb->have_ioref) {
		this_cpu_add(ca->io_done->sectors[READ][BCH_DATA_btree],
			     bio_sectors(bio));
		bio_set_dev(bio, ca->disk_sb.bdev);

		if (sync) {
			submit_bio_wait(bio);
			bch2_latency_acct(ca, rb->start_time, READ);
			btree_node_read_work(&rb->work);
		} else {
			submit_bio(bio);
		}
	} else {
		bio->bi_status = BLK_STS_REMOVED;

		if (sync)
			btree_node_read_work(&rb->work);
		else
			queue_work(c->btree.read_complete_wq, &rb->work);
	}
}

static int __bch2_btree_root_read(struct btree_trans *trans, enum btree_id id,
				  const struct bkey_i *k, unsigned level)
{
	struct bch_fs *c = trans->c;
	struct btree *b;
	int ret;

	CLASS(closure_stack, cl)();

	do {
		ret = bch2_btree_cache_cannibalize_lock(trans, &cl);
		closure_sync(&cl);
	} while (ret);

	b = bch2_btree_node_mem_alloc(trans, level != 0);
	bch2_btree_cache_cannibalize_unlock(trans);

	BUG_ON(IS_ERR(b));

	bkey_copy(&b->key, k);
	BUG_ON(bch2_btree_node_hash_insert(&c->btree.cache, b, level, id));

	set_btree_node_read_in_flight(b);

	/* we can't pass the trans to read_done() for fsck errors, so it must be unlocked */
	bch2_trans_unlock(trans);
	bch2_btree_node_read(trans, b, true);

	if (btree_node_read_error(b)) {
		scoped_guard(mutex, &c->btree.cache.lock)
			bch2_btree_node_hash_remove(&c->btree.cache, b);

		ret = bch_err_throw(c, btree_node_read_error);
		goto err;
	}

	bch2_btree_set_root_for_read(c, b);
err:
	six_unlock_write(&b->c.lock);
	six_unlock_intent(&b->c.lock);

	return ret;
}

int bch2_btree_root_read(struct bch_fs *c, enum btree_id id,
			const struct bkey_i *k, unsigned level)
{
	CLASS(btree_trans, trans)(c);
	return __bch2_btree_root_read(trans, id, k, level);
}

struct btree_node_scrub {
	struct bch_fs		*c;
	struct bch_dev		*ca;
	void			*buf;
	bool			used_mempool;
	unsigned		written;

	enum btree_id		btree;
	unsigned		level;
	struct bkey_buf		key;
	__le64			seq;

	struct work_struct	work;
	struct bio		bio;
	struct bio_vec		inline_vecs[];
};

static bool btree_node_scrub_check(struct bch_fs *c, struct btree_node *data, unsigned ptr_written,
				   struct printbuf *err)
{
	unsigned written = 0;

	if (le64_to_cpu(data->magic) != bset_magic(c)) {
		prt_printf(err, "bad magic: want %llx, got %llx",
			   bset_magic(c), le64_to_cpu(data->magic));
		return false;
	}

	while (written < (ptr_written ?: btree_sectors(c))) {
		struct btree_node_entry *bne;
		struct bset *i;
		bool first = !written;

		if (first) {
			bne = NULL;
			i = &data->keys;
		} else {
			bne = (void *) data + (written << 9);
			i = &bne->keys;

			if (!ptr_written && i->seq != data->keys.seq)
				break;
		}

		struct nonce nonce = btree_nonce(i, written << 9);
		bool good_csum_type = bch2_checksum_type_valid(c, BSET_CSUM_TYPE(i));

		if (first) {
			if (good_csum_type) {
				struct bch_csum csum = csum_vstruct(c, BSET_CSUM_TYPE(i), nonce, data);
				if (bch2_crc_cmp(data->csum, csum)) {
					bch2_csum_err_msg(err, BSET_CSUM_TYPE(i), data->csum, csum);
					return false;
				}
			}

			written += vstruct_sectors(data, c->block_bits);
		} else {
			if (good_csum_type) {
				struct bch_csum csum = csum_vstruct(c, BSET_CSUM_TYPE(i), nonce, bne);
				if (bch2_crc_cmp(bne->csum, csum)) {
					bch2_csum_err_msg(err, BSET_CSUM_TYPE(i), bne->csum, csum);
					return false;
				}
			}

			written += vstruct_sectors(bne, c->block_bits);
		}
	}

	return true;
}

static void btree_node_scrub_work(struct work_struct *work)
{
	struct btree_node_scrub *scrub = container_of(work, struct btree_node_scrub, work);
	struct bch_fs *c = scrub->c;
	CLASS(printbuf, err)();

	__bch2_btree_pos_to_text(&err, c, scrub->btree, scrub->level,
				 bkey_i_to_s_c(scrub->key.k));
	prt_newline(&err);

	if (!btree_node_scrub_check(c, scrub->buf, scrub->written, &err)) {
		int ret = bch2_trans_do(c,
			bch2_btree_node_rewrite_key(trans, scrub->btree, scrub->level - 1,
						    scrub->key.k, 0));
		if (!bch2_err_matches(ret, ENOENT) &&
		    !bch2_err_matches(ret, EROFS))
			bch_err_fn_ratelimited(c, ret);
	}

	bch2_bkey_buf_exit(&scrub->key);
	bch2_btree_bounce_free(c, c->opts.btree_node_size, scrub->used_mempool, scrub->buf);
	enumerated_ref_put(&scrub->ca->io_ref[READ], BCH_DEV_READ_REF_btree_node_scrub);
	kfree(scrub);
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_btree_node_scrub);
}

static void btree_node_scrub_endio(struct bio *bio)
{
	struct btree_node_scrub *scrub = container_of(bio, struct btree_node_scrub, bio);

	queue_work(scrub->c->btree.read_complete_wq, &scrub->work);
}

int bch2_btree_node_scrub(struct btree_trans *trans,
			  enum btree_id btree, unsigned level,
			  struct bkey_s_c k, unsigned dev)
{
	if (k.k->type != KEY_TYPE_btree_ptr_v2)
		return 0;

	struct bch_fs *c = trans->c;

	if (!enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_btree_node_scrub))
		return bch_err_throw(c, erofs_no_writes);

	struct extent_ptr_decoded pick;
	int ret = bch2_bkey_pick_read_device(c, k, NULL, &pick, dev);
	if (ret <= 0)
		goto err;

	struct bch_dev *ca = bch2_dev_get_ioref(c, pick.ptr.dev, READ,
						BCH_DEV_READ_REF_btree_node_scrub);
	if (!ca) {
		ret = bch_err_throw(c, device_offline);
		goto err;
	}

	bool used_mempool = false;
	void *buf = bch2_btree_bounce_alloc(c, c->opts.btree_node_size, &used_mempool);

	unsigned vecs = buf_pages(buf, c->opts.btree_node_size);

	struct btree_node_scrub *scrub =
		kzalloc(sizeof(*scrub) + sizeof(struct bio_vec) * vecs, GFP_KERNEL);
	if (!scrub) {
		ret = -ENOMEM;
		goto err_free;
	}

	scrub->c		= c;
	scrub->ca		= ca;
	scrub->buf		= buf;
	scrub->used_mempool	= used_mempool;
	scrub->written		= btree_ptr_sectors_written(k);

	scrub->btree		= btree;
	scrub->level		= level;
	bch2_bkey_buf_init(&scrub->key);
	bch2_bkey_buf_reassemble(&scrub->key, k);
	scrub->seq		= bkey_s_c_to_btree_ptr_v2(k).v->seq;

	INIT_WORK(&scrub->work, btree_node_scrub_work);

	bio_init(&scrub->bio, ca->disk_sb.bdev, scrub->inline_vecs, vecs, REQ_OP_READ);
	bch2_bio_map(&scrub->bio, scrub->buf, c->opts.btree_node_size);
	scrub->bio.bi_iter.bi_sector	= pick.ptr.offset;
	scrub->bio.bi_end_io		= btree_node_scrub_endio;
	submit_bio(&scrub->bio);
	return 0;
err_free:
	bch2_btree_bounce_free(c, c->opts.btree_node_size, used_mempool, buf);
	enumerated_ref_put(&ca->io_ref[READ], BCH_DEV_READ_REF_btree_node_scrub);
err:
	enumerated_ref_put(&c->writes, BCH_WRITE_REF_btree_node_scrub);
	return ret;
}
