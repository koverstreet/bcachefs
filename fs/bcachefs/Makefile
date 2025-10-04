
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
	bkey.o					\
	bkey_methods.o				\
	bkey_sort.o				\
	bset.o					\
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
	checksum.o				\
	compress.o				\
	data_update.o				\
	debug.o					\
	dirent.o				\
	ec.o					\
	errcode.o				\
	error.o					\
	extents.o				\
	extent_update.o				\
	fs.o					\
	fs-ioctl.o				\
	fs-io.o					\
	fs-io-buffered.o			\
	fs-io-direct.o				\
	fs-io-pagecache.o			\
	fsck.o					\
	inode.o					\
	io_read.o				\
	io_misc.o				\
	io_write.o				\
	journal.o				\
	journal_io.o				\
	journal_reclaim.o			\
	journal_sb.o				\
	journal_seq_blacklist.o			\
	keylist.o				\
	logged_ops.o				\
	migrate.o				\
	move.o					\
	movinggc.o				\
	namei.o					\
	nocow_locking.o				\
	opts.o					\
	progress.o				\
	quota.o					\
	rebalance.o				\
	recovery.o				\
	recovery_passes.o			\
	reflink.o				\
	sb-clean.o				\
	sb-counters.o				\
	sb-downgrade.o				\
	sb-errors.o				\
	sb-members.o				\
	snapshot.o				\
	str_hash.o				\
	subvolume.o				\
	super.o					\
	super-io.o				\
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
