#ifndef DBG_HOOK_H
#define DBG_HOOK_H

#include <linux/types.h>
// 👇 极其重要：必须引入通信协议头文件，这样才能认识 ls_bp_action 和共用的 bm_slot
#include "coom.h" 

#define BM_MAX_BREAKPOINTS 6

// 💡 提示：这里的 struct bm_slot 已经由 coom.h 提供，故在此处删除以避免重复定义冲突。

// =========================================================
// 暴露给 main.c 调用的核心函数声明
// =========================================================

int setup_hardware_breakpoints(u64 hook_addr, int hw_type,
                               const struct ls_bp_action *action);
int ls_breakpoint_update_action(int slot_idx, u64 target_addr,
                                const struct ls_bp_action *action);
void ls_debug_runtime_init(void);
int ls_snapshot_read_slot(int slot_idx, struct ls_regs_info *out);
int ls_snapshot_write_slot(int slot_idx, const struct ls_regs_info *in);
void ls_snapshot_reset_slot(int slot_idx);

// 清理函数
void clear_all_hw_breakpoints(void);

// 声明全局目标 PID (实体定义在 main.c 中)
extern int target_pid;

#endif // DBG_HOOK_H
