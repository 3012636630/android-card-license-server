#ifndef LS_APP_HOOKS_H
#define LS_APP_HOOKS_H

#include <linux/types.h>

int lsdriver_seal_app_hooks(void);
bool lsdriver_app_hooks_sealed(void);

#endif
