
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
	btree/key_cache.o			\
	btree/locking.o				\
	btree/node_scan.o			\
	btree/commit.o				\
	btree/update.o				\
	btree/interior.o			\
	btree/write_buffer.o			\
	btree_journal_iter.o			\
	chardev.o				\
	checksum.o				\
	clock.o					\
	compress.o				\
	darray.o				\
	data_update.o				\
	debug.o					\
	dirent.o				\
	ec.o					\
	enumerated_ref.o			\
	errcode.o				\
	error.o					\
	extents.o				\
	extent_update.o				\
	eytzinger.o				\
	fast_list.o				\
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
	mean_and_variance.o			\
	migrate.o				\
	move.o					\
	movinggc.o				\
	namei.o					\
	nocow_locking.o				\
	opts.o					\
	printbuf.o				\
	progress.o				\
	quota.o					\
	rebalance.o				\
	rcu_pending.o				\
	recovery.o				\
	recovery_passes.o			\
	reflink.o				\
	sb-clean.o				\
	sb-counters.o				\
	sb-downgrade.o				\
	sb-errors.o				\
	sb-members.o				\
	siphash.o				\
	six.o					\
	snapshot.o				\
	str_hash.o				\
	subvolume.o				\
	super.o					\
	super-io.o				\
	sysfs.o					\
	tests.o					\
	time_stats.o				\
	thread_with_file.o			\
	trace.o					\
	two_state_shared_lock.o			\
	util.o					\
	varint.o				\
	xattr.o					\
	vendor/closure.o			\
	vendor/min_heap.o

ifndef BCACHEFS_DKMS
	obj-$(CONFIG_MEAN_AND_VARIANCE_UNIT_TEST)   += mean_and_variance_test.o
endif

# Silence "note: xyz changed in GCC X.X" messages
subdir-ccflags-y += $(call cc-disable-warning, psabi)

ifdef BCACHEFS_DKMS
	subdir-ccflags-y += -I$(src)
endif
