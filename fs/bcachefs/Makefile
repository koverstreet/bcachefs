obj-$(CONFIG_BCACHEFS_FS)	+= bcachefs.o 

bcachefs-y	:=	\
	accel.o \
	acl.o			\
	alloc_background.o	\
	alloc_foreground.o	\
	bkey.o			\
	bkey_methods.o		\
	bkey_sort.o		\
	bset.o			\
	btree_cache.o		\
	btree_gc.o		\
	btree_io.o		\
	btree_iter.o		\
	btree_update_interior.o	\
	btree_update_leaf.o	\
	buckets.o		\
	chardev.o		\
	checksum.o		\
	clock.o			\
	compress.o		\
	debug.o			\
	dirent.o		\
	disk_groups.o		\
	ec.o			\
	error.o			\
	extents.o		\
	extent_update.o		\
	fs.o			\
	fs-common.o		\
	fs-ioctl.o		\
	fs-io.o			\
	fsck.o			\
	inode.o			\
	io.o			\
	journal.o		\
	journal_io.o		\
	journal_reclaim.o	\
	journal_seq_blacklist.o	\
	keylist.o		\
	migrate.o		\
	move.o			\
	movinggc.o		\
	opts.o			\
	quota.o			\
	rebalance.o		\
	recovery.o		\
	reflink.o		\
	replicas.o		\
	siphash.o		\
	super.o			\
	super-io.o		\
	sysfs.o			\
	tests.o			\
	trace.o			\
	util.o			\
	xattr.o			

ISAL_INCLUDE = -I$(src)/isal/include -I$(src)/isal/crc
ISAL_C_FLAGS = $(ISAL_INCLUDE) -O2 -Wall -D NDEBUG
ccflags-$(CONFIG_BCACHEFS_ISAL_BACKEND) +=$(ISAL_INCLUDE)

ASSEMBLE=nasm -f elf64 -D NDEBUG $(ISAL_INCLUDE) -DAS_FEATURE_LEVEL=10 -DHAVE_AS_KNOWS_AVX512

CFLAGS_isal/crc/crc64_base.o = $(ISAL_C_FLAGS)
CFLAGS_isal/crc/crc_base.o = $(ISAL_C_FLAGS)

bcachefs-$(CONFIG_BCACHEFS_ISAL_BACKEND) += \
    isal/crc/crc64_base.o \
    isal/crc/crc_base.o \
	isal/crc/crc64_ecma_norm_by8.o \
	isal/crc/crc64_iso_refl_by16_10.o \
	isal/crc/crc64_ecma_norm_by16_10.o \
	isal/crc/crc64_ecma_refl_by8.o \
	isal/crc/crc16_t10dif_copy_by4.o \
	isal/crc/crc32_ieee_by4.o \
	isal/crc/crc32_iscsi_00.o \
	isal/crc/crc64_iso_norm_by16_10.o \
	isal/crc/crc32_iscsi_01.o \
	isal/crc/crc64_jones_norm_by8.o \
	isal/crc/crc64_iso_norm_by8.o \
	isal/crc/crc64_multibinary.o \
	isal/crc/crc16_t10dif_by4.o \
	isal/crc/crc64_ecma_refl_by16_10.o \
	isal/crc/crc32_ieee_01.o \
	isal/crc/crc64_iso_refl_by8.o \
	isal/crc/crc64_jones_refl_by16_10.o \
	isal/crc/crc_multibinary.o \
	isal/crc/crc64_jones_norm_by16_10.o \
	isal/crc/crc64_jones_refl_by8.o \
	isal/crc/crc32_gzip_refl_by8.o \
	isal/crc/crc16_t10dif_01.o

$(obj)/isal/crc/crc64_ecma_norm_by8.o: $(src)/isal/crc/crc64_ecma_norm_by8.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_ecma_norm_by8.o $(src)/isal/crc/crc64_ecma_norm_by8.asm
$(obj)/isal/crc/crc64_iso_refl_by16_10.o: $(src)/isal/crc/crc64_iso_refl_by16_10.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_iso_refl_by16_10.o $(src)/isal/crc/crc64_iso_refl_by16_10.asm
$(obj)/isal/crc/crc64_ecma_norm_by16_10.o: $(src)/isal/crc/crc64_ecma_norm_by16_10.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_ecma_norm_by16_10.o $(src)/isal/crc/crc64_ecma_norm_by16_10.asm
$(obj)/isal/crc/crc64_ecma_refl_by8.o: $(src)/isal/crc/crc64_ecma_refl_by8.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_ecma_refl_by8.o $(src)/isal/crc/crc64_ecma_refl_by8.asm
$(obj)/isal/crc/crc16_t10dif_copy_by4.o: $(src)/isal/crc/crc16_t10dif_copy_by4.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc16_t10dif_copy_by4.o $(src)/isal/crc/crc16_t10dif_copy_by4.asm
$(obj)/isal/crc/crc32_ieee_by4.o: $(src)/isal/crc/crc32_ieee_by4.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc32_ieee_by4.o $(src)/isal/crc/crc32_ieee_by4.asm
$(obj)/isal/crc/crc32_iscsi_00.o: $(src)/isal/crc/crc32_iscsi_00.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc32_iscsi_00.o $(src)/isal/crc/crc32_iscsi_00.asm
$(obj)/isal/crc/crc64_iso_norm_by16_10.o: $(src)/isal/crc/crc64_iso_norm_by16_10.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_iso_norm_by16_10.o $(src)/isal/crc/crc64_iso_norm_by16_10.asm
$(obj)/isal/crc/crc32_iscsi_01.o: $(src)/isal/crc/crc32_iscsi_01.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc32_iscsi_01.o $(src)/isal/crc/crc32_iscsi_01.asm
$(obj)/isal/crc/crc64_jones_norm_by8.o: $(src)/isal/crc/crc64_jones_norm_by8.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_jones_norm_by8.o $(src)/isal/crc/crc64_jones_norm_by8.asm
$(obj)/isal/crc/crc64_iso_norm_by8.o: $(src)/isal/crc/crc64_iso_norm_by8.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_iso_norm_by8.o $(src)/isal/crc/crc64_iso_norm_by8.asm
$(obj)/isal/crc/crc64_multibinary.o: $(src)/isal/crc/crc64_multibinary.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_multibinary.o $(src)/isal/crc/crc64_multibinary.asm
$(obj)/isal/crc/crc16_t10dif_by4.o: $(src)/isal/crc/crc16_t10dif_by4.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc16_t10dif_by4.o $(src)/isal/crc/crc16_t10dif_by4.asm
$(obj)/isal/crc/crc64_ecma_refl_by16_10.o: $(src)/isal/crc/crc64_ecma_refl_by16_10.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_ecma_refl_by16_10.o $(src)/isal/crc/crc64_ecma_refl_by16_10.asm
$(obj)/isal/crc/crc32_ieee_01.o: $(src)/isal/crc/crc32_ieee_01.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc32_ieee_01.o $(src)/isal/crc/crc32_ieee_01.asm
$(obj)/isal/crc/crc64_iso_refl_by8.o: $(src)/isal/crc/crc64_iso_refl_by8.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_iso_refl_by8.o $(src)/isal/crc/crc64_iso_refl_by8.asm
$(obj)/isal/crc/crc64_jones_refl_by16_10.o: $(src)/isal/crc/crc64_jones_refl_by16_10.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_jones_refl_by16_10.o $(src)/isal/crc/crc64_jones_refl_by16_10.asm
$(obj)/isal/crc/crc_multibinary.o: $(src)/isal/crc/crc_multibinary.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc_multibinary.o $(src)/isal/crc/crc_multibinary.asm
$(obj)/isal/crc/crc64_jones_norm_by16_10.o: $(src)/isal/crc/crc64_jones_norm_by16_10.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_jones_norm_by16_10.o $(src)/isal/crc/crc64_jones_norm_by16_10.asm
$(obj)/isal/crc/crc64_jones_refl_by8.o: $(src)/isal/crc/crc64_jones_refl_by8.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_jones_refl_by8.o $(src)/isal/crc/crc64_jones_refl_by8.asm
$(obj)/isal/crc/crc32_gzip_refl_by8.o: $(src)/isal/crc/crc32_gzip_refl_by8.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc32_gzip_refl_by8.o $(src)/isal/crc/crc32_gzip_refl_by8.asm
$(obj)/isal/crc/crc16_t10dif_01.o: $(src)/isal/crc/crc16_t10dif_01.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc16_t10dif_01.o $(src)/isal/crc/crc16_t10dif_01.asm