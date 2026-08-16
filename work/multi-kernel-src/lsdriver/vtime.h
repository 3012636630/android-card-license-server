#ifndef LSDRIVER_VTIME_H
#define LSDRIVER_VTIME_H

#include <linux/types.h>

struct task_struct;

int ls_vtime_start(void);
void ls_vtime_stop(void);
void ls_vtime_shutdown(void);
void ls_vtime_sched_switch(struct task_struct *prev, struct task_struct *next);
u64 ls_vtime_read_counter(void);
void ls_vtime_account_debug(u64 start);
bool ls_vtime_is_active(void);

#endif
