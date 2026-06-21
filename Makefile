# ============================================================
#  eBPF 性能监控项目 - Makefile
# ============================================================

# ---- 1. 工具链 ----
CLANG ?= clang
CC    ?= gcc
AR    ?= ar

# ---- 2. 目录 & 第三方库 ----
OUTPUT         := build
BPF_DIR        := bpf
SRC_ROOT       := src

LIBBPF_SRC     := $(abspath ./libbpf/src)
BPFTOOL_SRC    := $(abspath ./bpftool/src)
BPFTOOL_OUTPUT := $(abspath $(OUTPUT)/bpftool)
BPFTOOL        := $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBPF_OBJ     := $(abspath $(BPFTOOL_OUTPUT)/bootstrap/libbpf/libbpf.a)

# ---- 3. 目标架构 ----
ARCH ?= $(shell uname -m)
ARCH := $(shell printf '%s' '$(ARCH)' | sed 's/x86_64/x86/;s/aarch64/arm64/;s/arm.*/arm/;s/riscv64/riscv/')

# ---- 4. vmlinux.h ----
VMLINUX_H  := $(OUTPUT)/vmlinux.h
VMLINUX_SRC := $(firstword $(filter-out ./vmlinux/$(ARCH)/vmlinux.h,$(wildcard ./vmlinux/$(ARCH)/vmlinux_*.h)))
ifeq ($(VMLINUX_SRC),)
$(error 未找到 vmlinux.h，请在 vmlinux/$(ARCH)/ 下放置 vmlinux_*.h)
endif

# ---- 5. 包含路径 ----
BLAZESYM_DIR  := $(abspath ./blazesym)
BLAZESYM_LIB  := $(BLAZESYM_DIR)/target/release/libblazesym_c.a

INCLUDES := \
	-I$(OUTPUT) \
	-I$(BPFTOOL_OUTPUT)/bootstrap/libbpf/include \
	-I$(LIBBPF_SRC)/../include/uapi \
	-I$(BPF_DIR)/include \
	-I$(SRC_ROOT)/include \
	-I$(LIBBPF_SRC)/.. \
	-I$(BLAZESYM_DIR)/capi/include

# ---- 6. 编译参数 ----
CFLAGS  := -g -Wall
LDFLAGS := -lelf -lz -pthread -lstdc++ -lrt -ldl -lpthread -lm
LDFLAGS += -L$(BLAZESYM_DIR)/target/release -lblazesym_c

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# ---- 7. BPF 程序 (自动扫描 bpf/ 下所有 *.bpf.c) ----
BPF_SRCS  := $(shell find $(BPF_DIR) -type f -name '*.bpf.c' | sort)
BPF_ALL   := $(patsubst $(BPF_DIR)/%.bpf.c,%,$(BPF_SRCS))
BPF_OBJS  := $(addprefix $(OUTPUT)/, $(addsuffix .bpf.o, $(BPF_ALL)))
BPF_SKELS := $(BPF_OBJS:.bpf.o=.skel.h)

# ---- 8. 用户态程序 ----
TARGET         := test
MAIN_SRC       := $(SRC_ROOT)/main.c
USER_SRCS      := $(shell find $(SRC_ROOT) -type f -name '*.c' ! -path '$(SRC_ROOT)/include/*' | sort)
MODULE_SRCS    := $(filter-out $(MAIN_SRC),$(USER_SRCS))
MAIN_OBJ       := $(OUTPUT)/$(MAIN_SRC:.c=.o)
MODULE_OBJS    := $(addprefix $(OUTPUT)/,$(MODULE_SRCS:.c=.o))
MODULE_LIB     := $(OUTPUT)/libapp.a

# ---- 9. 编译输出精简 (make V=1 显示完整命令) ----
ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-10s %s\n' "$1" "$(patsubst $(OUTPUT)/%,%,$@)"
MAKEFLAGS += --no-print-directory
endif

# ################################################################
#  目标
# ################################################################
.PHONY: all clean

all: $(TARGET)
	@echo -e "\033[32m========================================="
	@echo "  编译完成！可执行文件: ./$(TARGET)"
	@echo -e "=========================================\033[0m"

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(TARGET)

# ################################################################
#  构建目录
# ################################################################
$(OUTPUT):
	$(Q)mkdir -p $@/bpftool/bootstrap

# ################################################################
#  bpftool + libbpf
# ################################################################
$(LIBBPF_OBJ): $(BPFTOOL)

$(BPFTOOL): | $(OUTPUT)
	$(call msg,TOOL,bpftool)
	$(Q)$(MAKE) -C $(BPFTOOL_SRC) OUTPUT=$(BPFTOOL_OUTPUT)/ bootstrap

$(VMLINUX_H): $(VMLINUX_SRC) | $(OUTPUT)
	$(call msg,COPY,vmlinux.h)
	$(Q)cp $< $@

# ################################################################
#  BPF 内核态编译
# ################################################################
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

# ################################################################
#  BPF 骨架生成
# ################################################################
define BUILD_SKEL
$(OUTPUT)/$(1).skel.h: $(OUTPUT)/$(1).bpf.o
	$(call msg,SKEL,$(notdir $$@))
	$(Q)mkdir -p $$(dir $$@)
	$(Q)$(BPFTOOL) gen skeleton $$< > $$@
endef

$(foreach bpf,$(BPF_ALL),$(eval $(call BUILD_SKEL,$(bpf))))

# ################################################################
#  用户态编译
# ################################################################
$(OUTPUT)/%.o: %.c $(BPF_SKELS) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,CC,$<)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ################################################################
#  链接
# ################################################################
$(MODULE_LIB): $(MODULE_OBJS)
	$(call msg,AR,libapp.a)
	$(Q)rm -f $@
	$(Q)$(AR) rcs $@ $^

$(TARGET): $(MAIN_OBJ) $(MODULE_LIB) $(LIBBPF_OBJ) $(BLAZESYM_LIB)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(MAIN_OBJ) $(MODULE_LIB) $(LIBBPF_OBJ) $(BLAZESYM_LIB) $(LDFLAGS) -o $@

.DELETE_ON_ERROR:
.SECONDARY:
