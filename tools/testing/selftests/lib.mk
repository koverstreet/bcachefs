# This mimics the top-level Makefile. We do it explicitly here so that this
# Makefile can operate with or without the kbuild infrastructure.
ifneq ($(LLVM),)
CC := clang
else
CC := $(CROSS_COMPILE)gcc
endif

ifeq (0,$(MAKELEVEL))
    ifeq ($(OUTPUT),)
	OUTPUT := $(shell pwd)
	DEFAULT_INSTALL_HDR_PATH := 1
    endif
endif

# The following are built by lib.mk common compile rules.
# TEST_CUSTOM_PROGS should be used by tests that require
# custom build rule and prevent common build rule use.
# TEST_PROGS are for test shell scripts.
# TEST_CUSTOM_PROGS and TEST_PROGS will be run by common run_tests
# and install targets. Common clean doesn't touch them.
TEST_GEN_PROGS := $(patsubst %,$(OUTPUT)/%,$(TEST_GEN_PROGS))
TEST_GEN_PROGS_EXTENDED := $(patsubst %,$(OUTPUT)/%,$(TEST_GEN_PROGS_EXTENDED))
TEST_GEN_FILES := $(patsubst %,$(OUTPUT)/%,$(TEST_GEN_FILES))

ifdef KSFT_KHDR_INSTALL
top_srcdir ?= ../../../..
include $(top_srcdir)/scripts/subarch.include
ARCH		?= $(SUBARCH)

# set default goal to all, so make without a target runs all, even when
# all isn't the first target in the file.
.DEFAULT_GOAL := all

# Invoke headers install with --no-builtin-rules to avoid circular
# dependency in "make kselftest" case. In this case, second level
# make inherits builtin-rules which will use the rule generate
# Makefile.o and runs into
# "Circular Makefile.o <- prepare dependency dropped."
# and headers_install fails and test compile fails.
# O= KBUILD_OUTPUT cases don't run into this error, since main Makefile
# invokes them as sub-makes and --no-builtin-rules is not necessary,
# but doesn't cause any failures. Keep it simple and use the same
# flags in both cases.
# Note that the support to install headers from lib.mk is necessary
# when test Makefile is run directly with "make -C".
# When local build is done, headers are installed in the default
# INSTALL_HDR_PATH usr/include.
.PHONY: khdr
.NOTPARALLEL:
khdr:
ifndef KSFT_KHDR_INSTALL_DONE
ifeq (1,$(DEFAULT_INSTALL_HDR_PATH))
	make --no-builtin-rules ARCH=$(ARCH) -C $(top_srcdir) headers_install
else
	make --no-builtin-rules INSTALL_HDR_PATH=$$OUTPUT/usr \
		ARCH=$(ARCH) -C $(top_srcdir) headers_install
endif
endif

all: khdr $(TEST_GEN_PROGS) $(TEST_GEN_PROGS_EXTENDED) $(TEST_GEN_FILES)
else
all: $(TEST_GEN_PROGS) $(TEST_GEN_PROGS_EXTENDED) $(TEST_GEN_FILES)
endif

.ONESHELL:
define RUN_TESTS
	@export KSFT_TAP_LEVEL=`echo 1`;		\
	test_num=`echo 0`;				\
	skip=`echo 4`;					\
	echo "TAP version 13";				\
	for TEST in $(1); do				\
		BASENAME_TEST=`basename $$TEST`;	\
		test_num=`echo $$test_num+1 | bc`;	\
		echo "selftests: $$BASENAME_TEST";	\
		echo "========================================";	\
		if [ ! -x $$TEST ]; then	\
			echo "selftests: Warning: file $$BASENAME_TEST is not executable, correct this.";\
			echo "not ok 1..$$test_num selftests: $$BASENAME_TEST [FAIL]"; \
		else					\
			cd `dirname $$TEST` > /dev/null; \
			if [ "X$(summary)" != "X" ]; then	\
				(./$$BASENAME_TEST > /tmp/$$BASENAME_TEST 2>&1 && \
				echo "ok 1..$$test_num selftests: $$BASENAME_TEST [PASS]") || \
				(if [ $$? -eq $$skip ]; then	\
					echo "not ok 1..$$test_num selftests:  $$BASENAME_TEST [SKIP]";				\
				else echo "not ok 1..$$test_num selftests:  $$BASENAME_TEST [FAIL]";					\
				fi;)			\
			else				\
				(./$$BASENAME_TEST &&	\
				echo "ok 1..$$test_num selftests: $$BASENAME_TEST [PASS]") ||						\
				(if [ $$? -eq $$skip ]; then \
					echo "not ok 1..$$test_num selftests:  $$BASENAME_TEST [SKIP]"; \
				else echo "not ok 1..$$test_num selftests:  $$BASENAME_TEST [FAIL]";				\
				fi;)		\
			fi;				\
			cd - > /dev/null;		\
		fi;					\
	done;
endef

run_tests: all
ifneq ($(KBUILD_SRC),)
	@if [ "X$(TEST_PROGS) $(TEST_PROGS_EXTENDED) $(TEST_FILES)" != "X" ]; then
		@rsync -aq $(TEST_PROGS) $(TEST_PROGS_EXTENDED) $(TEST_FILES) $(OUTPUT)
	fi
	@if [ "X$(TEST_PROGS)" != "X" ]; then
		$(call RUN_TESTS, $(TEST_GEN_PROGS) $(TEST_CUSTOM_PROGS) $(OUTPUT)/$(TEST_PROGS))
	else
		$(call RUN_TESTS, $(TEST_GEN_PROGS) $(TEST_CUSTOM_PROGS))
	fi
else
	$(call RUN_TESTS, $(TEST_GEN_PROGS) $(TEST_CUSTOM_PROGS) $(TEST_PROGS))
endif

define INSTALL_SINGLE_RULE
	$(if $(INSTALL_LIST),@mkdir -p $(INSTALL_PATH))
	$(if $(INSTALL_LIST),@echo rsync -a $(INSTALL_LIST) $(INSTALL_PATH)/)
	$(if $(INSTALL_LIST),@rsync -a $(INSTALL_LIST) $(INSTALL_PATH)/)
endef

define INSTALL_RULE
	$(eval INSTALL_LIST = $(TEST_PROGS)) $(INSTALL_SINGLE_RULE)
	$(eval INSTALL_LIST = $(TEST_PROGS_EXTENDED)) $(INSTALL_SINGLE_RULE)
	$(eval INSTALL_LIST = $(TEST_FILES)) $(INSTALL_SINGLE_RULE)
	$(eval INSTALL_LIST = $(TEST_GEN_PROGS)) $(INSTALL_SINGLE_RULE)
	$(eval INSTALL_LIST = $(TEST_CUSTOM_PROGS)) $(INSTALL_SINGLE_RULE)
	$(eval INSTALL_LIST = $(TEST_GEN_PROGS_EXTENDED)) $(INSTALL_SINGLE_RULE)
	$(eval INSTALL_LIST = $(TEST_GEN_FILES)) $(INSTALL_SINGLE_RULE)
endef

install: all
ifdef INSTALL_PATH
	$(INSTALL_RULE)
else
	$(error Error: set INSTALL_PATH to use install)
endif

define EMIT_TESTS
	@for TEST in $(TEST_GEN_PROGS) $(TEST_CUSTOM_PROGS) $(TEST_PROGS); do \
		BASENAME_TEST=`basename $$TEST`;	\
		echo "(./$$BASENAME_TEST >> \$$OUTPUT 2>&1 && echo \"selftests: $$BASENAME_TEST [PASS]\") || echo \"selftests: $$BASENAME_TEST [FAIL]\""; \
	done;
endef

emit_tests:
	$(EMIT_TESTS)

# define if isn't already. It is undefined in make O= case.
ifeq ($(RM),)
RM := rm -f
endif

define CLEAN
	$(RM) -r $(TEST_GEN_PROGS) $(TEST_GEN_PROGS_EXTENDED) $(TEST_GEN_FILES) $(EXTRA_CLEAN)
endef

clean:
	$(CLEAN)

# When make O= with kselftest target from main level
# the following aren't defined.
#
ifneq ($(KBUILD_SRC),)
LINK.c = $(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH)
COMPILE.S = $(CC) $(ASFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
LINK.S = $(CC) $(ASFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH)
endif

$(OUTPUT)/%:%.c
	$(LINK.c) $^ $(LDLIBS) -o $@

$(OUTPUT)/%.o:%.S
	$(COMPILE.S) $^ -o $@

$(OUTPUT)/%:%.S
	$(LINK.S) $^ $(LDLIBS) -o $@

.PHONY: run_tests all clean install emit_tests
