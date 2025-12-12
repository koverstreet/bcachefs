
ifdef BCACHEFS_DKMS
	CONFIG_BCACHEFS_FS := m
	# Enable other features here?
endif

obj-$(CONFIG_BCACHEFS_FS)	+= bcachefs.o

bcachefs-y		:=			\
	alloc/accounting.o			\
	alloc/background.o			\
	alloc/backpointers.o			\
	alloc/buckets.o				\
	alloc/buckets_waiting_for_journal.o	\
	alloc/check.o				\
	alloc/disk_groups.o			\
	alloc/foreground.o			\
	alloc/lru.o				\
	alloc/replicas.o			\
	btree/bkey.o				\
	btree/bkey_methods.o			\
	btree/bset.o				\
	btree/cache.o				\
	btree/check.o				\
	btree/commit.o				\
	btree/init.o				\
	btree/interior.o			\
	btree/iter.o				\
	btree/journal_overlay.o			\
	btree/key_cache.o			\
	btree/locking.o				\
	btree/node_scan.o			\
	btree/read.o				\
	btree/sort.o				\
	btree/update.o				\
	btree/write.o				\
	btree/write_buffer.o			\
	data/checksum.o				\
	data/compress.o				\
	data/copygc.o				\
	data/ec.o				\
	data/extents.o				\
	data/extents_sb.o			\
	data/extent_update.o			\
	data/io_misc.o				\
	data/keylist.o				\
	data/migrate.o				\
	data/move.o				\
	data/nocow_locking.o			\
	data/read.o				\
	data/reconcile.o			\
	data/reflink.o				\
	data/update.o				\
	data/write.o				\
	debug/debug.o				\
	debug/sysfs.o				\
	debug/tests.o				\
	debug/trace.o				\
	errcode.o				\
	fs/acl.o				\
	fs/check.o				\
	fs/check_dir_structure.o		\
	fs/check_extents.o			\
	fs/check_nlinks.o			\
	fs/dirent.o				\
	fs/inode.o				\
	fs/logged_ops.o				\
	fs/namei.o				\
	fs/quota.o				\
	fs/str_hash.o				\
	fs/xattr.o				\
	init/chardev.o				\
	init/dev.o				\
	init/error.o				\
	init/fs.o				\
	init/progress.o				\
	init/recovery.o				\
	init/passes.o				\
	journal/init.o				\
	journal/journal.o			\
	journal/read.o				\
	journal/reclaim.o			\
	journal/sb.o				\
	journal/seq_blacklist.o			\
	journal/write.o				\
	opts.o					\
	sb/clean.o				\
	sb/counters.o				\
	sb/downgrade.o				\
	sb/errors.o				\
	sb/io.o					\
	sb/members.o				\
	snapshots/check_snapshots.o		\
	snapshots/delete.o			\
	snapshots/snapshot.o			\
	snapshots/subvolume.o			\
	util/clock.o				\
	util/darray.o				\
	util/enumerated_ref.o			\
	util/eytzinger.o			\
	util/fast_list.o			\
	util/mean_and_variance.o		\
	util/printbuf.o				\
	util/rcu_pending.o			\
	util/siphash.o				\
	util/six.o				\
	util/time_stats.o			\
	util/thread_with_file.o			\
	util/two_state_shared_lock.o		\
	util/util.o				\
	util/varint.o				\
	vendor/bio_iov_iter.o			\
	vendor/closure.o			\
	vendor/min_heap.o			\
	vfs/fiemap.o				\
	vfs/fs.o				\
	vfs/ioctl.o				\
	vfs/io.o				\
	vfs/buffered.o				\
	vfs/direct.o				\
	vfs/pagecache.o

ifdef CONFIG_DEBUG_FS
	bcachefs-y += debug/async_objs.o
endif

ifndef BCACHEFS_DKMS
	obj-$(CONFIG_MEAN_AND_VARIANCE_UNIT_TEST)   += util/mean_and_variance_test.o
endif

# Silence "note: xyz changed in GCC X.X" messages
subdir-ccflags-y += $(call cc-disable-warning, psabi)

# kbuild weirdness - sometimes this gets passed automatically, other times we
# need to specify it. no idea why:
subdir-ccflags-y += -I$(src)
