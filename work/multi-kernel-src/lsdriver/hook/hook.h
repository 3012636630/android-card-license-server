#ifndef HOOK_H
#define HOOK_H
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/kprobes.h>
#include <linux/moduleloader.h> // 🌟 新增：用来申请可执行内存 (module_alloc)
#include <asm/cacheflush.h>
#include "hook.h"
#include <linux/types.h>


// Hook 实例大管家
struct inline_hook {
    void *target_addr;       // 被 Hook 的原函数真实内核地址
    void *trampoline;        // 动态分配的跳板内存 (可执行)
    void *stub_entry;        // 拦截入口点
    uint8_t orig_code[16];   // 保存原函数的前 16 字节指令
    uint8_t jump_code[16];   // 替换到原函数头部的跳转指令
};

// 核心 API
// 参数 hk: 传入你的结构体指针
// 参数 name: 目标函数的符号名 (比如 "__arm64_sys_openat")
// 参数 new_func: 你的 C 语言假函数
int do_inline_hook(struct inline_hook *hk, const char *name, void *new_func);

// 卸载并清理内存
int restore_inline_hook(struct inline_hook *hk);
void release_inline_hook(struct inline_hook *hk);
void undo_inline_hook(struct inline_hook *hk);
void* dbi_compile_code_range(void *orig_insn_buffer, void *real_pc, size_t code_size, void *map_address);
unsigned long get_symbol_addr(const char *symbol_name);


#endif
