# ============================================================
#  My_eBPF_Poj - Unified Build System
#  自动扫描 */bpf.c 和 */user.c，无需手动注册模块
# ============================================================

CLANG ?= clang
CC    ?= gcc
AR    ?= ar

OUTPUT         := build

LIBBPF_SRC     := $(abspath ./lib/libbpf/src)
BPFTOOL_SRC    := $(abspath ./lib/bpftool/src)
BPFTOOL_OUTPUT := $(abspath $(OUTPUT)/bpftool)
BPFTOOL        := $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBPF_OBJ     := $(abspath $(BPFTOOL_OUTPUT)/bootstrap/libbpf/libbpf.a)

BLAZESYM_DIR   := $(abspath ./lib/blazesym)
BLAZESYM_LIB   := $(BLAZESYM_DIR)/target/release/libblazesym_c.a

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/arm.*/arm/;s/riscv64/riscv/')

VMLINUX_H      := $(OUTPUT)/vmlinux.h
VMLINUX_SRC    := $(firstword $(filter-out ./vmlinux/$(ARCH)/vmlinux.h,$(wildcard ./vmlinux/$(ARCH)/vmlinux_*.h)))
ifeq ($(VMLINUX_SRC),)
$(error 未找到 vmlinux.h，请在 vmlinux/$(ARCH)/ 下放置 vmlinux_*.h)
endif

INCLUDES := \
	-I. \
	-I$(OUTPUT) \
	-I$(BPFTOOL_OUTPUT)/bootstrap/libbpf/include \
	-I$(LIBBPF_SRC)/../include/uapi \
	-I$(BLAZESYM_DIR)/capi/include

CFLAGS  := -g -Wall
LDFLAGS := -lelf -lz -pthread -lstdc++ -lrt -ldl -lm
LDFLAGS += -L$(BLAZESYM_DIR)/target/release -lblazesym_c

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# ============================================================
# 自动扫描
# ============================================================
BPF_SRCS  := $(shell find . -path ./lib -prune -o -path ./build -prune -o -path ./vmlinux -prune -o -name *.bpf.c -print | sort)
USER_SRCS := $(shell find . -path ./lib -prune -o -path ./build -prune -o -path ./vmlinux -prune -o -name user.c -print | sort)

# bpf.c 的路径： ./fs/read/bpf.c → MOD_DIR = fs/read
MOD_DIRS  := $(sort $(dir $(BPF_SRCS)))
MOD_DIRS  := $(MOD_DIRS:./%=%)
MOD_DIRS  := $(MOD_DIRS:/=)

BPF_OBJS  := $(addprefix $(OUTPUT)/, $(addsuffix .bpf.o, $(MOD_DIRS)))
BPF_SKELS := $(addprefix $(OUTPUT)/, $(addsuffix /skel.h, $(MOD_DIRS)))

# user.c 编译目标：每个模块生成一个 user.o
USER_OBJS := $(addprefix $(OUTPUT)/, $(addsuffix /user.o, $(MOD_DIRS)))
USER_LIB  := $(OUTPUT)/libmodules.a

TARGET     := test
MAIN_SRC   := common/main.c
MAIN_OBJ   := $(OUTPUT)/common/main.o
CLI_SRC    := common/cli.c
CLI_OBJ    := $(OUTPUT)/common/cli.o

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-10s %s\n'
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all clean

all: $(TARGET)
	@echo -e "\033[32m========================================="
	@echo "  编译完成！可执行文件: ./$(TARGET)"
	@echo -e "=========================================\033[0m"

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(TARGET)

$(OUTPUT):
	$(Q)mkdir -p $@

# ============================================================
# bpftool + libbpf
# ============================================================
$(LIBBPF_OBJ): $(BPFTOOL)

$(BPFTOOL): | $(OUTPUT)
	$(call msg,TOOL,bpftool)
	$(Q)mkdir -p $(BPFTOOL_OUTPUT)
	$(Q)$(MAKE) -C $(BPFTOOL_SRC) OUTPUT=$(BPFTOOL_OUTPUT)/ bootstrap

$(VMLINUX_H): $(VMLINUX_SRC) | $(OUTPUT)
	$(call msg,COPY,vmlinux.h)
	$(Q)cp $< $@

# ============================================================
# BPF 编译 + skeleton 生成 (每个模块)
# ============================================================
define BUILD_MODULE
BPF_SRC_$(1) := $(1)/$(notdir $(1)).bpf.c

$$(OUTPUT)/$(1).bpf.o: $$(BPF_SRC_$(1)) $(VMLINUX_H) $(BPFTOOL)
	$(call msg,BPF,$(1))
	$(Q)mkdir -p $$(dir $$@)
	$(Q)$$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$$(INCLUDES) $$(CLANG_BPF_SYS_INCLUDES) \
		-c $$< -o $$@.tmp
	$(Q)$(BPFTOOL) gen object $$@ $$@.tmp
	$(Q)rm -f $$@.tmp

$$(OUTPUT)/$(1)/skel.h: $$(OUTPUT)/$(1).bpf.o
	$(call msg,SKEL,$(1)/skel.h)
	$(Q)mkdir -p $$(dir $$@)
	$(Q)$(BPFTOOL) gen skeleton $$< > $$@

$$(OUTPUT)/$(1)/user.o: $(1)/user.c $$(OUTPUT)/$(1)/skel.h $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,CC,$(1)/user.c)
	$(Q)mkdir -p $$(dir $$@)
	$(Q)$$(CC) $$(CFLAGS) $$(INCLUDES) -c $$< -o $$@
endef

$(foreach mod,$(MOD_DIRS),$(eval $(call BUILD_MODULE,$(mod))))

# ============================================================
# common 基础设施
# ============================================================
$(OUTPUT)/common/main.o: common/main.c
	$(call msg,CC,common/main.c)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/common/cli.o: common/cli.c
	$(call msg,CC,common/cli.c)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ============================================================
# 链接
# ============================================================
$(USER_LIB): $(USER_OBJS)
	$(call msg,AR,libmodules.a)
	$(Q)rm -f $@
	$(Q)$(AR) rcs $@ $^

$(TARGET): $(MAIN_OBJ) $(CLI_OBJ) $(USER_LIB) $(LIBBPF_OBJ) $(BLAZESYM_LIB)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(MAIN_OBJ) $(CLI_OBJ) $(USER_LIB) $(LIBBPF_OBJ) $(BLAZESYM_LIB) $(LDFLAGS) -o $@

.DELETE_ON_ERROR:
.SECONDARY:
