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
ccflags-$(CONFIG_BCACHEFS_ISAL_BACKEND) +=$(ISAL_INCLUDE)

ASSEMBLE=nasm -f elf64 -D NDEBUG $(ISAL_INCLUDE) -DAS_FEATURE_LEVEL=10 -DHAVE_AS_KNOWS_AVX512

ISAL_C_FLAGS = $(ISAL_INCLUDE) -O2 -Wall -DNDEBUG -DGF_LARGE_TABLES -DAS_FEATURE_LEVEL=10 -DHAVE_AS_KNOWS_AVX512
CFLAGS_crc64_base.o = $(ISAL_C_FLAGS)
CFLAGS_crc_base.o = $(ISAL_C_FLAGS)
CFLAGS_ec_base.o = $(ISAL_C_FLAGS)
CFLAGS_ec_highlevel_func.o = $(ISAL_C_FLAGS)

bcachefs-$(CONFIG_BCACHEFS_ISAL_BACKEND) += \
    isal/crc/crc64_base.o \
	isal/crc/crc64_ecma_norm_by8.o \
	isal/crc/crc64_ecma_norm_by16_10.o \
	isal/crc/crc64_multibinary.o 

bcachefs-$(CONFIG_BCACHEFS_ISAL_ERASURE) += \
	isal/erasure_code/ec_base.o \
	isal/erasure_code/ec_highlevel_func.o \
	isal/erasure_code/ec_multibinary.o \
	isal/erasure_code/gf_2vect_dot_prod_sse.o \
	isal/erasure_code/gf_2vect_mad_sse.o \
	isal/erasure_code/gf_3vect_dot_prod_sse.o \
	isal/erasure_code/gf_3vect_mad_sse.o \
	isal/erasure_code/gf_4vect_dot_prod_sse.o \
	isal/erasure_code/gf_4vect_mad_sse.o \
	isal/erasure_code/gf_5vect_dot_prod_sse.o \
	isal/erasure_code/gf_5vect_mad_sse.o \
	isal/erasure_code/gf_6vect_dot_prod_sse.o \
	isal/erasure_code/gf_6vect_mad_sse.o \
	isal/erasure_code/gf_vect_dot_prod_sse.o \
	isal/erasure_code/gf_vect_mad_sse.o \
	isal/erasure_code/gf_vect_mul_sse.o
	
	#isal/erasure_code/gf_2vect_dot_prod_avx.o \
	isal/erasure_code/gf_2vect_dot_prod_avx2.o \
	isal/erasure_code/gf_2vect_dot_prod_avx512.o \
	isal/erasure_code/gf_2vect_mad_avx.o \
	isal/erasure_code/gf_2vect_mad_avx2.o \
	isal/erasure_code/gf_2vect_mad_avx512.o \
	isal/erasure_code/gf_3vect_dot_prod_avx.o \
	isal/erasure_code/gf_3vect_dot_prod_avx2.o \
	isal/erasure_code/gf_3vect_dot_prod_avx512.o \
	isal/erasure_code/gf_3vect_mad_avx.o \
	isal/erasure_code/gf_3vect_mad_avx2.o \
	isal/erasure_code/gf_3vect_mad_avx512.o \
	isal/erasure_code/gf_4vect_dot_prod_avx.o \
	isal/erasure_code/gf_4vect_dot_prod_avx2.o \
	isal/erasure_code/gf_4vect_dot_prod_avx512.o \
	isal/erasure_code/gf_4vect_mad_avx.o \
	isal/erasure_code/gf_4vect_mad_avx2.o \
	isal/erasure_code/gf_4vect_mad_avx512.o \
	isal/erasure_code/gf_5vect_dot_prod_avx.o \
	isal/erasure_code/gf_5vect_dot_prod_avx2.o \
	isal/erasure_code/gf_5vect_dot_prod_avx512.o \
	isal/erasure_code/gf_5vect_mad_avx.o \
	isal/erasure_code/gf_5vect_mad_avx2.o \
	isal/erasure_code/gf_5vect_mad_avx512.o \
	isal/erasure_code/gf_6vect_dot_prod_avx.o \
	isal/erasure_code/gf_6vect_dot_prod_avx2.o \
	isal/erasure_code/gf_6vect_dot_prod_avx512.o \
	isal/erasure_code/gf_6vect_mad_avx.o \
	isal/erasure_code/gf_6vect_mad_avx2.o \
	isal/erasure_code/gf_6vect_mad_avx512.o \
	isal/erasure_code/gf_vect_dot_prod_avx.o \
	isal/erasure_code/gf_vect_dot_prod_avx2.o \
	isal/erasure_code/gf_vect_dot_prod_avx512.o \
	isal/erasure_code/gf_vect_mad_avx.o \
	isal/erasure_code/gf_vect_mad_avx2.o \
	isal/erasure_code/gf_vect_mad_avx512.o \
	isal/erasure_code/gf_vect_mul_avx.o \

# CRC ASM
$(obj)/isal/crc/crc64_multibinary.o: $(src)/isal/crc/crc64_multibinary.asm
	$(ASSEMBLE) -o $(obj)/isal/crc/crc64_multibinary.o $(src)/isal/crc/crc64_multibinary.asm

# Erasure Coding ASM
$(obj)/isal/erasure_code/ec_multibinary.o: $(src)/isal/erasure_code/ec_multibinary.asm
	$(ASSEMBLE) -o $(obj)/isal/erasure_code/ec_multibinary.o $(src)/isal/erasure_code/ec_multibinary.asm