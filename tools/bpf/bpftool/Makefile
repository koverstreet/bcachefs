include ../../scripts/Makefile.include

include ../../scripts/utilities.mak

ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
#$(info Determined 'srctree' to be $(srctree))
endif

ifneq ($(objtree),)
#$(info Determined 'objtree' to be $(objtree))
endif

ifneq ($(OUTPUT),)
#$(info Determined 'OUTPUT' to be $(OUTPUT))
# Adding $(OUTPUT) as a directory to look for source files,
# because use generated output files as sources dependency
# for flex/bison parsers.
VPATH += $(OUTPUT)
export VPATH
endif

ifeq ($(V),1)
  Q =
else
  Q = @
endif

BPF_DIR	= $(srctree)/tools/lib/bpf/

ifneq ($(OUTPUT),)
  BPF_PATH=$(OUTPUT)
else
  BPF_PATH=$(BPF_DIR)
endif

LIBBPF = $(BPF_PATH)libbpf.a

$(LIBBPF): FORCE
	$(Q)$(MAKE) -C $(BPF_DIR) OUTPUT=$(OUTPUT) $(OUTPUT)libbpf.a FEATURES_DUMP=$(FEATURE_DUMP_EXPORT)

$(LIBBPF)-clean:
	$(call QUIET_CLEAN, libbpf)
	$(Q)$(MAKE) -C $(BPF_DIR) OUTPUT=$(OUTPUT) clean >/dev/null

prefix = /usr/local
bash_compdir ?= /usr/share/bash-completion/completions

CC = gcc

CFLAGS += -O2
CFLAGS += -W -Wall -Wextra -Wno-unused-parameter -Wshadow
CFLAGS += -D__EXPORTED_HEADERS__ -I$(srctree)/tools/include/uapi -I$(srctree)/tools/include -I$(srctree)/tools/lib/bpf -I$(srctree)/kernel/bpf/
LIBS = -lelf $(LIBBPF)

FEATURE_USER = .bpftool
FEATURE_TESTS = libbfd disassembler-four-args
FEATURE_DISPLAY = libbfd disassembler-four-args

check_feat := 1
NON_CHECK_FEAT_TARGETS := clean uninstall doc doc-clean doc-install doc-uninstall
ifdef MAKECMDGOALS
ifeq ($(filter-out $(NON_CHECK_FEAT_TARGETS),$(MAKECMDGOALS)),)
  check_feat := 0
endif
endif

ifeq ($(check_feat),1)
ifeq ($(FEATURES_DUMP),)
include $(srctree)/tools/build/Makefile.feature
else
include $(FEATURES_DUMP)
endif
endif

ifeq ($(feature-disassembler-four-args), 1)
CFLAGS += -DDISASM_FOUR_ARGS_SIGNATURE
endif

include $(wildcard *.d)

all: $(OUTPUT)bpftool

BFD_SRCS = jit_disasm.c

SRCS = $(filter-out $(BFD_SRCS),$(wildcard *.c))

ifeq ($(feature-libbfd),1)
CFLAGS += -DHAVE_LIBBFD_SUPPORT
SRCS += $(BFD_SRCS)
LIBS += -lbfd -lopcodes
endif

OBJS=$(patsubst %.c,$(OUTPUT)%.o,$(SRCS)) $(OUTPUT)disasm.o

$(OUTPUT)disasm.o: $(srctree)/kernel/bpf/disasm.c
	$(QUIET_CC)$(COMPILE.c) -MMD -o $@ $<

$(OUTPUT)bpftool: $(OBJS) $(LIBBPF)
	$(QUIET_LINK)$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(OUTPUT)%.o: %.c
	$(QUIET_CC)$(COMPILE.c) -MMD -o $@ $<

clean: $(LIBBPF)-clean
	$(call QUIET_CLEAN, bpftool)
	$(Q)rm -rf $(OUTPUT)bpftool $(OUTPUT)*.o $(OUTPUT)*.d

install:
	install -m 0755 -d $(prefix)/sbin
	install $(OUTPUT)bpftool $(prefix)/sbin/bpftool
	install -m 0755 -d $(bash_compdir)
	install -m 0644 bash-completion/bpftool $(bash_compdir)

doc:
	$(Q)$(MAKE) -C Documentation/

doc-install:
	$(Q)$(MAKE) -C Documentation/ install

FORCE:

.PHONY: all clean FORCE install doc doc-install
.DEFAULT_GOAL := all
