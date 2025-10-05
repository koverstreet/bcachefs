
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
	btree/bkey_sort.o			\
	btree/bset.o				\
	btree/cache.o				\
	btree/check.o				\
	btree/io.o				\
	btree/iter.o				\
	btree/journal_overlay.o			\
	btree/key_cache.o			\
	btree/locking.o				\
	btree/node_scan.o			\
	btree/commit.o				\
	btree/update.o				\
	btree/interior.o			\
	btree/write_buffer.o			\
	data/checksum.o				\
	data/compress.o				\
	data/copygc.o				\
	data/ec.o				\
	data/extents.o				\
	data/extent_update.o			\
	data/io_misc.o				\
	data/keylist.o				\
	data/migrate.o				\
	data/move.o				\
	data/nocow_locking.o			\
	data/read.o				\
	data/rebalance.o			\
	data/reflink.o				\
	data/update.o				\
	data/write.o				\
	debug/async_objs.o			\
	debug/debug.o				\
	debug/sysfs.o				\
	debug/tests.o				\
	debug/trace.o				\
	fs/acl.o				\
	fs/chardev.o				\
	fs/check.o				\
	fs/check_dir_structure.o		\
	fs/check_extents.o			\
	fs/check_nlinks.o			\
	fs/check_snapshots.o			\
	fs/dirent.o				\
	fs/inode.o				\
	fs/logged_ops.o				\
	fs/namei.o				\
	fs/quota.o				\
	fs/snapshot.o				\
	fs/str_hash.o				\
	fs/subvolume.o				\
	fs/xattr.o				\
	init/dev.o				\
	init/errcode.o				\
	init/error.o				\
	init/fs.o				\
	init/opts.o				\
	init/progress.o				\
	init/recovery.o				\
	init/passes.o				\
	journal/init.o				\
	journal/io.o				\
	journal/journal.o			\
	journal/reclaim.o			\
	journal/sb.o				\
	journal/seq_blacklist.o			\
	sb/clean.o				\
	sb/counters.o				\
	sb/downgrade.o				\
	sb/errors.o				\
	sb/io.o					\
	sb/members.o				\
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
	vendor/closure.o			\
	vendor/min_heap.o			\
	vfs/fs.o				\
	vfs/ioctl.o				\
	vfs/io.o				\
	vfs/buffered.o				\
	vfs/direct.o				\
	vfs/pagecache.o	

ifndef BCACHEFS_DKMS
	obj-$(CONFIG_MEAN_AND_VARIANCE_UNIT_TEST)   += util/mean_and_variance_test.o
endif

# Silence "note: xyz changed in GCC X.X" messages
subdir-ccflags-y += $(call cc-disable-warning, psabi)

ifdef BCACHEFS_DKMS
	subdir-ccflags-y += -I$(src)
endif
