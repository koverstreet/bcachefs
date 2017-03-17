
obj-$(CONFIG_BCACHE_FS)	+= bcachefs.o

bcachefs-y		:= alloc.o bset.o btree.o debug.o extents.o io.o\
	journal.o movinggc.o request.o stats.o super.o sysfs.o trace.o util.o\
	writeback.o

CFLAGS_request.o	+= -Iblock
