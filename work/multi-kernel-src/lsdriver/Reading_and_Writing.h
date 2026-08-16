#ifndef _LS_Reading_and_Writing_H_
#define _LS_Reading_and_Writing_H_

#include "page_.h"

// 声明底层核心函数
long phys_rw_memory(pid_t target_pid, unsigned long va, void *buffer, size_t size, int is_write);
int ls_remote_read_init(void);
void ls_remote_read_exit(void);

// ✅ 把宏改成真正的函数声明
int read_phys(pid_t pid, u64 addr, void *buf, size_t size);
int write_phys(pid_t pid, u64 addr, void *buf, size_t size);

#endif
