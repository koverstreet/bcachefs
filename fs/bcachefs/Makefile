
obj-$(CONFIG_BCACHE_FS)	+= bcachefs.o

bcachefs-y		:= alloc.o bkey.o bkey_methods.o blockdev.o bset.o\
	btree.o buckets.o clock.o debug.o extents.o gc.o inode.o io.o journal.o\
	keybuf.o keylist.o migrate.o move.o movinggc.o notify.o request.o six.o\
	stats.o super.o sysfs.o tier.o trace.o util.o writeback.o

ccflags-y		:= -Werror
