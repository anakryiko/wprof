# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
CARGO ?= $(shell which cargo)
RELEASE ?=
BLAZESYM_DEBUG ?=

LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBLAZESYM_SRC := $(abspath ../blazesym/)
LIBBLAZESYM_INC := $(abspath $(LIBBLAZESYM_SRC)/capi/include)
LIBBLAZESYM_OBJ := $(abspath $(OUTPUT)/libblazesym_c.a)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := ../vmlinux.h/include/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../include -I../libbpf/include/uapi -I../libbpf/include -I$(dir $(VMLINUX)) -I$(LIBBLAZESYM_INC)
CFLAGS := -g -Wall -O$(if $(RELEASE),2,0) -fno-omit-frame-pointer -Wno-c23-extensions
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS) -lrt -ldl -lpthread -lm

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: wprof sim

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) wprof $(LIBBLAZESYM_SRC)/target

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    EXTRA_CFLAGS="-g -O$(if $(RELEASE),2,0)" 		      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build blazesym
$(LIBBLAZESYM_SRC)/target/$(if $(BLAZESYM_DEBUG),debug,release)/libblazesym_c.a::
	$(Q)cd $(LIBBLAZESYM_SRC) && $(CARGO) build --package=blazesym-c $(if $(BLAZESYM_DEBUG),,--release)

$(LIBBLAZESYM_OBJ): $(LIBBLAZESYM_SRC)/target/$(if $(BLAZESYM_DEBUG),debug,release)/libblazesym_c.a | $(OUTPUT)
	$(call msg,LIB, $@)
	$(Q)cp $(LIBBLAZESYM_SRC)/target/$(if $(BLAZESYM_DEBUG),debug,release)/libblazesym_c.a $@

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -Wall -O2 -target bpf -mcpu=v4 -D__TARGET_ARCH_$(ARCH)			\
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      			\
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

$(OUTPUT)/wprof.bpf.o: wprof.h wprof.bpf.h
$(OUTPUT)/utils.bpf.o: wprof.h wprof.bpf.h

# Generate BPF skeletons
$(OUTPUT)/wprof.skel.h: $(OUTPUT)/wprof.bpf.o $(OUTPUT)/utils.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen object $(OUTPUT)/wprof-final.bpf.o $^
	$(Q)$(BPFTOOL) gen skeleton $(OUTPUT)/wprof-final.bpf.o name wprof_bpf > $@

WPROF_SRCS := wprof.c utils.c env.c protobuf.c emit.c stacktrace.c		\
	      pb_common.c pb_encode.c perfetto_trace.pb.c topology.c
WPROF_HDRS := wprof.h utils.h env.h protobuf.h emit.h stacktrace.h data.h topology.h

# Build user space object files
$(OUTPUT)/%.o: %.c $(OUTPUT)/wprof.skel.h $(WPROF_HDRS) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
wprof: wprof.h utils.h 								\
		$(patsubst %.c,$(OUTPUT)/%.o,$(WPROF_SRCS)) 			\
		$(LIBBPF_OBJ) $(LIBBLAZESYM_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(filter %.c %.a %.o,$^) $(ALL_LDFLAGS) -lelf -lz -o $@

sim: $(OUTPUT)/sim.o | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(filter %.c %.a %.o,$^) $(ALL_LDFLAGS) -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
