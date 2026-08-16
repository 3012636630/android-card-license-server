#ifndef LS_TARGET_GUARD_H
#define LS_TARGET_GUARD_H

#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

extern int target_pid;
extern struct pid *g_target_tgid;

static inline bool ls_target_matches(const struct task_struct *task)
{
    struct pid *target = READ_ONCE(g_target_tgid);

    return target && task && task_tgid(task) == target;
}

int ls_target_set(pid_t nr);
void ls_target_clear(void);

#endif
