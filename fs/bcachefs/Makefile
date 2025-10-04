
ifdef BCACHEFS_DKMS
	CONFIG_BCACHEFS_FS := m
	# Enable other features here?
endif

obj-$(CONFIG_BCACHEFS_FS)	+= bcachefs.o

bcachefs-y		:=			\
	acl.o					\
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
	async_objs.o				\
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
	chardev.o				\
	debug.o					\
	dirent.o				\
	errcode.o				\
	error.o					\
	fs.o					\
	fs-ioctl.o				\
	fs-io.o					\
	fs-io-buffered.o			\
	fs-io-direct.o				\
	fs-io-pagecache.o			\
	fsck.o					\
	inode.o					\
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
	journal/journal.o			\
	journal/io.o				\
	journal/reclaim.o			\
	journal/sb.o				\
	journal/seq_blacklist.o			\
	logged_ops.o				\
	namei.o					\
	opts.o					\
	progress.o				\
	quota.o					\
	recovery.o				\
	recovery_passes.o			\
	sb/clean.o				\
	sb/counters.o				\
	sb/downgrade.o				\
	sb/errors.o				\
	sb/io.o					\
	sb/members.o				\
	snapshot.o				\
	str_hash.o				\
	subvolume.o				\
	super.o					\
	sysfs.o					\
	tests.o					\
	trace.o					\
	xattr.o					\
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
	vendor/min_heap.o

ifndef BCACHEFS_DKMS
	obj-$(CONFIG_MEAN_AND_VARIANCE_UNIT_TEST)   += util/mean_and_variance_test.o
endif

# Silence "note: xyz changed in GCC X.X" messages
subdir-ccflags-y += $(call cc-disable-warning, psabi)

ifdef BCACHEFS_DKMS
	subdir-ccflags-y += -I$(src)
endif
