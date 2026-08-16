#ifndef _LS_TOOL_H_
#define _LS_TOOL_H_

#include <linux/kprobes.h>

// 声明：利用 Kprobe 获取未导出内核函数的绝对地址
unsigned long resolve_unexported_symbol(const char *name);
pid_t get_pid_by_full_name_kernel(const char *full_name);
struct mm_struct* get_mm_by_pid_robust(pid_t target_pid);
uintptr_t get_module_base_by_index(pid_t pid, const char* module_name, int target_index, int perm_type);
uintptr_t get_anon_region_by_index(pid_t pid, const char* target_name, int target_index, int perm_type);
#endif // _LS_TOOL_H_
