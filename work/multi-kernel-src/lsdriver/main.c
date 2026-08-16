#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/kprobes.h>
#include <linux/err.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/list.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <asm/set_memory.h>

#include "quiet_log.h"
#include "hook/hook.h"
#include "conceal_driver.h"
#include "page_.h"
#include "Reading_and_Writing.h"
#include "map.h"
#include "tool.h"
#include "dbg_hook.h"
#include "vtime.h"
#include "coom.h"
#include "touch_inject.h"
#include "app_hooks.h"
#include "kgsl_hide.h"
#include "target_guard.h"
#include "stale_itlb.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
#include <linux/execmem.h>
#else
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#endif

enum ls_hook_id {
    LS_HOOK_MINCORE = 0,
    LS_HOOK_FILLDIR64,
    LS_HOOK_PROC_ROOT_LOOKUP,
    LS_HOOK_FILENAME_LOOKUP,
    LS_HOOK_PRCTL,
    LS_HOOK_COUNT,
};

struct ls_hook_spec {
    const char *symbol;
    void *handler;
};

static struct inline_hook g_hooks[LS_HOOK_COUNT];
static unsigned int g_hooks_installed;
static DEFINE_MUTEX(g_app_hook_lock);
static bool g_app_hooks_sealed;
static bool g_install_app_hooks;
module_param_named(install_app_hooks, g_install_app_hooks, bool, 0600);

static struct ls_hook_spec g_hook_specs[LS_HOOK_COUNT] = {
    [LS_HOOK_MINCORE]          = { "__arm64_sys_mincore", my_mincore_hook },
    [LS_HOOK_FILLDIR64]        = { "filldir64",            my_filldir64 },
    [LS_HOOK_PROC_ROOT_LOOKUP] = { "proc_root_lookup",     my_proc_root_lookup },
    [LS_HOOK_FILENAME_LOOKUP]  = { "filename_lookup",      my_filename_lookup },
    [LS_HOOK_PRCTL]            = { "__arm64_sys_prctl",    prctl_entry_handler },
};

static int lsdriver_restore_app_hooks_locked(void)
{
    unsigned int i;
    int ret;

    for (i = 0; i < g_hooks_installed; i++) {
        ret = restore_inline_hook(&g_hooks[i]);
        if (ret)
            return ret;
    }
    return 0;
}

static void lsdriver_release_app_hooks_locked(void)
{
    unsigned int i;

    if (!g_hooks_installed)
        return;

    ls_synchronize_hook_readers();
    for (i = 0; i < g_hooks_installed; i++)
        release_inline_hook(&g_hooks[i]);
    g_hooks_installed = 0;
}

static void lsdriver_unhook_all(void)
{
    int ret;

    mutex_lock(&g_app_hook_lock);
    ret = lsdriver_restore_app_hooks_locked();
    if (!ret)
        lsdriver_release_app_hooks_locked();
    WRITE_ONCE(g_app_hooks_sealed, false);
    mutex_unlock(&g_app_hook_lock);
}

int lsdriver_seal_app_hooks(void)
{
    int ret;

    mutex_lock(&g_app_hook_lock);
    if (g_app_hooks_sealed) {
        mutex_unlock(&g_app_hook_lock);
        return 0;
    }

    ret = lsdriver_restore_app_hooks_locked();
    if (!ret) {
        lsdriver_release_app_hooks_locked();
        smp_wmb();
        WRITE_ONCE(g_app_hooks_sealed, true);
    }
    mutex_unlock(&g_app_hook_lock);
    return ret;
}

bool lsdriver_app_hooks_sealed(void)
{
    return READ_ONCE(g_app_hooks_sealed);
}

static int lsdriver_install_app_hooks(void)
{
    int i, ret;

    mutex_lock(&g_app_hook_lock);
    if (g_hooks_installed) {
        mutex_unlock(&g_app_hook_lock);
        return 0;
    }

    for (i = 0; i < LS_HOOK_COUNT; i++) {
        ret = do_inline_hook(&g_hooks[i], g_hook_specs[i].symbol, g_hook_specs[i].handler);
        if (ret) {
            LS_PRINTK(KERN_ERR "[lsdriver] hook %s failed: %d\n", g_hook_specs[i].symbol, ret);
            mutex_unlock(&g_app_hook_lock);
            lsdriver_unhook_all();
            return ret;
        }
        g_hooks_installed++;
    }
    mutex_unlock(&g_app_hook_lock);
    return 0;
}

static int __init lsdriver_init(void)
{
    int ret;

    ls_debug_runtime_init();
    ls_stale_itlb_runtime_init();

    ret = ls_remote_read_init();
    if (ret)
        return ret;

    ret = lsdriver_control_register();
    if (ret) {
        ls_remote_read_exit();
        return ret;
    }

    ret = ls_kgsl_hide_install();
    if (ret) {
        lsdriver_control_unregister();
        ls_remote_read_exit();
        return ret;
    }

    if (READ_ONCE(g_install_app_hooks)) {
        ret = lsdriver_install_app_hooks();
        if (ret) {
            ls_kgsl_hide_remove();
            lsdriver_control_unregister();
            ls_remote_read_exit();
            return ret;
        }
    }

    hide_myself();
    return 0;
}

static void __exit lsdriver_exit(void)
{
    ls_stale_itlb_clear_all();
    ls_target_clear();
    ls_kgsl_hide_remove();
    v_touch_destroy();
    clear_all_hw_breakpoints();
    ls_vtime_shutdown();
    lsdriver_unhook_all();
    lsdriver_control_unregister();
    ls_remote_read_exit();
    clear_hide_rules();
    lsdriver_shared_free();
}

module_init(lsdriver_init);
module_exit(lsdriver_exit);
MODULE_LICENSE("GPL");
