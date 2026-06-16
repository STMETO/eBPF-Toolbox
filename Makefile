# 编译输出目录
OUTPUT := build

# 编译器
CLANG ?= clang
CC ?= gcc
AR ?= ar

# ==============================
# 第三方子模块路径
# ==============================
LIBBPF_SRC := $(abspath ./libbpf/src)
BPFTOOL_SRC := $(abspath ./bpftool/src)
BPFTOOL_OUTPUT := $(abspath $(OUTPUT)/bpftool)
BPFTOOL := $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBPF_OBJ := $(abspath $(BPFTOOL_OUTPUT)/bootstrap/libbpf/libbpf.a)

# ==============================
# 系统架构
# ==============================
ARCH ?= $(shell uname -m)
ARCH := $(shell printf '%s' '$(ARCH)' | sed 's/x86_64/x86/;s/aarch64/arm64/;s/arm.*/arm/;s/riscv64/riscv/')

# ==============================
# vmlinux.h
# ==============================
VMLINUX_H := $(OUTPUT)/vmlinux.h
# 在对应架构目录下查找 vmlinux_*.h 文件（排除 vmlinux.h）
VMLINUX_SRC := $(firstword $(filter-out ./vmlinux/$(ARCH)/vmlinux.h,$(wildcard ./vmlinux/$(ARCH)/vmlinux_*.h)))

ifeq ($(VMLINUX_SRC),)
$(error 未找到 vmlinux.h 文件，请在 vmlinux/$(ARCH)/ 目录下放置 vmlinux_*.h 文件)
endif

# ==============================
# 【你的项目架构】
# ==============================
BPF_DIR      := bpf
SRC_ROOT     := src

# ==============================
# 包含路径
# ==============================
INCLUDES := \
	-I$(OUTPUT) \
	-I$(OUTPUT)/include \
	-I$(BPFTOOL_OUTPUT)/bootstrap/libbpf/include \
	-I$(LIBBPF_SRC)/../include/uapi \
	-I$(BPF_DIR)/include \
	-I./src/include \
	-I$(LIBBPF_SRC)/..

# ==============================
# 编译 & 链接参数
# ==============================
CFLAGS := -g -Wall
LDFLAGS := -lelf -lz -pthread -lstdc++

# ==============================
# BPF 程序列表（自动扫描 bpf/ 下所有 *.bpf.c）
# ==============================
BPF_SRCS := $(shell find $(BPF_DIR) -type f -name '*.bpf.c' | sort)
BPF_ALL := $(patsubst $(BPF_DIR)/%.bpf.c,%,$(BPF_SRCS))

# 生成编译路径
BPF_OBJS := $(addprefix $(OUTPUT)/, $(addsuffix .bpf.o, $(BPF_ALL)))
BPF_SKELS := $(BPF_OBJS:.bpf.o=.skel.h)

# ==============================
# 用户态可执行程序
# ==============================
TARGET_PERF := test

# ==============================
# 用户态源文件
# ==============================
USER_MAIN_SRC := $(SRC_ROOT)/main.c
USER_SRCS := $(shell find $(SRC_ROOT) -type f -name '*.c' ! -path '$(SRC_ROOT)/include/*' | sort)
USER_MODULE_SRCS := $(filter-out $(USER_MAIN_SRC),$(USER_SRCS))

USER_MAIN_OBJ := $(OUTPUT)/$(USER_MAIN_SRC:.c=.o)
USER_MODULE_OBJS := $(addprefix $(OUTPUT)/,$(USER_MODULE_SRCS:.c=.o))
USER_MODULE_LIB := $(OUTPUT)/libapp.a

# ==============================
# Clang 系统头文件
# ==============================
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

################################################################################
# 编译输出精简模式
################################################################################
ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-10s %s\n' "$1" "$(patsubst $(OUTPUT)/%,%,$@)"
MAKEFLAGS += --no-print-directory
endif

################################################################################
# 总目标
################################################################################
.PHONY: all clean

all: $(TARGET_PERF) success

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(TARGET_PERF)

$(OUTPUT):
	$(Q)mkdir -p $@/bpftool/bootstrap $@/libbpf $@/libbpf/include/uapi

################################################################################
# 编译依赖库
################################################################################
$(LIBBPF_OBJ): $(BPFTOOL)

$(BPFTOOL): | $(OUTPUT)
	$(call msg,TOOL,bpftool)
	$(Q)$(MAKE) -C $(BPFTOOL_SRC) OUTPUT=$(BPFTOOL_OUTPUT)/ bootstrap

$(VMLINUX_H): $(VMLINUX_SRC) | $(OUTPUT)
	$(call msg,COPY,vmlinux.h)
	$(Q)cp $< $@

################################################################################
# 编译 BPF 代码
################################################################################
define BUILD_BPF
$(OUTPUT)/$(1).bpf.o: $(BPF_DIR)/$(1).bpf.c $(VMLINUX_H) $(BPFTOOL)
	$(call msg,BPF,$(1).bpf.c)
	$(Q)mkdir -p $$(dir $$@)
	$(Q)$$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$$(INCLUDES) $$(CLANG_BPF_SYS_INCLUDES) \
		-c $$< -o $$@.tmp
	$(Q)$(BPFTOOL) gen object $$@ $$@.tmp
	$(Q)rm -f $$@.tmp
endef

$(foreach bpf,$(BPF_ALL),$(eval $(call BUILD_BPF,$(bpf))))

################################################################################
# 生成 BPF 骨架头文件
################################################################################
define BUILD_SKEL
$(OUTPUT)/$(1).skel.h: $(OUTPUT)/$(1).bpf.o
	$(call msg,SKEL,$(notdir $$@))
	$(Q)mkdir -p $$(dir $$@)
	$(Q)$(BPFTOOL) gen skeleton $$< > $$@
endef

$(foreach bpf,$(BPF_ALL),$(eval $(call BUILD_SKEL,$(bpf))))

################################################################################
# 编译用户态代码（自动扫描 src/，排除 src/include）
################################################################################
$(OUTPUT)/%.o: %.c $(BPF_SKELS) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,CC,$<)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

################################################################################
# 链接最终程序
$(USER_MODULE_LIB): $(USER_MODULE_OBJS) | $(OUTPUT)
	$(call msg,AR,$@)
	$(Q)rm -f $@
	$(Q)$(AR) rcs $@ $^

$(TARGET_PERF): $(USER_MAIN_OBJ) $(USER_MODULE_LIB) $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(USER_MAIN_OBJ) $(USER_MODULE_LIB) $(LIBBPF_OBJ) $(LDFLAGS) -o $@

################################################################################
# 成功提示
success:
	@echo -e "\033[32m========================================="
	@echo "  编译完成！"
	@echo -e "=========================================\033[0m"

.DELETE_ON_ERROR:
.SECONDARY:
