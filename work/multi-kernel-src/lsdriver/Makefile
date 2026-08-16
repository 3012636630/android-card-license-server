# 驱动名称
# 最终生成的模块名字叫 lsdriver.ko
obj-m += lsdriver.o

# 告诉系统，lsdriver.ko 是由 main.o, hook.o 和 conceal_driver.o 组成的

lsdriver-y := main.o \
              hook/hook.o \
              conceal_driver.o \
              kgsl_hide.o \
              page_.o \
              Reading_and_Writing.o \
              map.o \
              tool.o \
              dbg_hook.o \
              vtime.o \
              stale_itlb.o \
              target_guard.o \
              coom.o \
              touch_inject.o
# ========================================================
# 终极免死金牌：屏蔽硬件安全特性与编译器检查
# ========================================================

# 1. 彻底关闭 PACIASP / BTI (针对指针验证)
# 这是解决你提到的 PACIASP 的核心开关
LS_RELAX_TARGET_HARDENING ?= n
ifeq ($(LS_RELAX_TARGET_HARDENING),y)
ccflags-y += -mbranch-protection=none
# 2. 禁用所有 Sanitizer (CFI, 硬件地址检查, 影子栈)
ccflags-y += -fno-sanitize=cfi 
ccflags-y += -fno-sanitize=hwaddress 
ccflags-y += -fno-sanitize=shadow-call-stack

# 3. 禁用堆栈保护器 (防止因 Hook 破坏栈结构导致的 Kernel Panic)
ccflags-y += -fno-stack-protector
endif

ccflags-y += -Wno-declaration-after-statement

# Keep DWARF in carrier modules for target internal-KABI verification.
LS_ENABLE_DWARF ?= y
ifeq ($(LS_ENABLE_DWARF),y)
ccflags-y += -g
endif

# 4. 其他兼容性修正
ccflags-y += -mno-outline-atomics
ccflags-y += -Wno-error
ccflags-y += -Wno-incompatible-pointer-types
ccflags-y += -Wno-unused-function

# 如果你的内核源码有特定的平台宏，可以加上（可选）
# ccflags-y += -DCONFIG_OPLUS_CHG_OOBE

# ========================================================

# 指向真我原厂的 out 目录
# 确保该目录下有生成的 .config 和构建软链接
KDIR ?= /home/juym/realme_neo8_src/realme_neo8-AndroidB-common-source-master/out

# 获取当前路径
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
