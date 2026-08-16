#ifndef LSDRIVER_STALE_ITLB_H
#define LSDRIVER_STALE_ITLB_H

#include <linux/types.h>
#include <linux/uaccess.h>

#include "coom.h"

void ls_stale_itlb_runtime_init(void);
void ls_stale_itlb_clear_all(void);

long ls_stale_itlb_load_user(void __user *arg);
long ls_stale_itlb_arm_user(void __user *arg);
long ls_stale_itlb_restore_user(void __user *arg);
long ls_stale_itlb_status_user(void __user *arg);
long ls_stale_itlb_disable_user(void __user *arg);

#endif
