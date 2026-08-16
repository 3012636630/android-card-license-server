#ifndef LSDRIVER_KERNEL_COMPAT_H
#define LSDRIVER_KERNEL_COMPAT_H

#include <linux/kconfig.h>
#include <linux/version.h>

/* Android vendor 5.15 trees carry anonymous VMA names before upstream 5.17. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0) && \
    IS_ENABLED(CONFIG_ANON_VMA_NAME)
#define LS_HAVE_ANON_VMA_NAME 1
#else
#define LS_HAVE_ANON_VMA_NAME 0
#endif

/* Android 6.1 and newer use Maple Tree for the process VMA index. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define LS_HAVE_MAPLE_TREE_VMA 1
#define LS_SCHED_SWITCH_HAS_PREV_STATE 1
#define LS_VTIME_ESR_IS_ULONG 1
#else
#define LS_HAVE_MAPLE_TREE_VMA 0
#define LS_SCHED_SWITCH_HAS_PREV_STATE 0
#define LS_VTIME_ESR_IS_ULONG 0
#endif

/* 6.1+ Android common kernels use KCFI; 5.15 uses legacy Clang CFI. */
#if IS_ENABLED(CONFIG_CFI_CLANG) && \
    LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define LS_TARGET_USES_KCFI 1
#else
#define LS_TARGET_USES_KCFI 0
#endif

#endif
