#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>

#include "target_guard.h"

int target_pid;
struct pid *g_target_tgid;

static DEFINE_MUTEX(g_target_lock);

int ls_target_set(pid_t nr)
{
    struct pid *lookup;
    struct pid *tgid;
    struct pid *old;
    struct task_struct *task;

    if (nr <= 0)
        return -EINVAL;

    lookup = find_get_pid(nr);
    if (!lookup)
        return -ESRCH;

    task = get_pid_task(lookup, PIDTYPE_PID);
    put_pid(lookup);
    if (!task)
        return -ESRCH;

    tgid = get_pid(task_tgid(task));
    put_task_struct(task);
    if (!tgid)
        return -ESRCH;

    mutex_lock(&g_target_lock);
    old = READ_ONCE(g_target_tgid);
    WRITE_ONCE(target_pid, pid_nr(tgid));
    smp_wmb();
    WRITE_ONCE(g_target_tgid, tgid);
    mutex_unlock(&g_target_lock);

    if (old)
        put_pid(old);
    return 0;
}

void ls_target_clear(void)
{
    struct pid *old;

    mutex_lock(&g_target_lock);
    old = READ_ONCE(g_target_tgid);
    WRITE_ONCE(g_target_tgid, NULL);
    smp_wmb();
    WRITE_ONCE(target_pid, 0);
    mutex_unlock(&g_target_lock);

    if (old)
        put_pid(old);
}
