#include <linux/errno.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <asm/ptrace.h>

#include "hook/hook.h"
#include "kgsl_hide.h"
#include "target_guard.h"

struct kgsl_hook_spec {
    const char *symbol;
    void *handler;
};

enum kgsl_hook_id {
    KGSL_HOOK_PROCESS_SYSFS = 0,
    KGSL_HOOK_PROCESS_DEBUGFS,
    KGSL_HOOK_SYSFS_CREATE_GROUP,
    KGSL_HOOK_COUNT,
};

static struct inline_hook g_kgsl_hooks[KGSL_HOOK_COUNT];
static unsigned int g_kgsl_hooks_installed;
static DEFINE_MUTEX(g_kgsl_hook_lock);

static bool kgsl_kobject_matches(const struct kobject *kobj)
{
    const struct kobject *parent;
    unsigned int depth = 0;

    for (parent = kobj; parent && depth < 8; parent = parent->parent, depth++) {
        if (parent->name && strstr(parent->name, "kgsl"))
            return true;
    }

    return false;
}

static int kgsl_process_init_hook(struct pt_regs *regs)
{
    if (!regs || !ls_target_matches(current))
        return 0;

    regs->regs[0] = (u64)(long)-ENOMEM;
    return 1;
}

static int kgsl_sysfs_create_group_hook(struct pt_regs *regs)
{
    const struct kobject *kobj;

    if (!regs || !ls_target_matches(current))
        return 0;

    kobj = (const struct kobject *)regs->regs[0];
    if (!kobj || !kgsl_kobject_matches(kobj))
        return 0;

    regs->regs[0] = (u64)(long)-ENOMEM;
    return 1;
}

static const struct kgsl_hook_spec g_kgsl_hook_specs[KGSL_HOOK_COUNT] = {
    [KGSL_HOOK_PROCESS_SYSFS] = {
        .symbol = "kgsl_process_init_sysfs",
        .handler = kgsl_process_init_hook,
    },
    [KGSL_HOOK_PROCESS_DEBUGFS] = {
        .symbol = "kgsl_process_init_debugfs",
        .handler = kgsl_process_init_hook,
    },
    [KGSL_HOOK_SYSFS_CREATE_GROUP] = {
        .symbol = "sysfs_create_group",
        .handler = kgsl_sysfs_create_group_hook,
    },
};

static int kgsl_restore_hooks_locked(void)
{
    unsigned int i;
    int ret;

    for (i = 0; i < g_kgsl_hooks_installed; i++) {
        ret = restore_inline_hook(&g_kgsl_hooks[i]);
        if (ret)
            return ret;
    }

    return 0;
}

static void kgsl_release_hooks_locked(void)
{
    unsigned int i;

    if (!g_kgsl_hooks_installed)
        return;

    synchronize_rcu_tasks();
    for (i = 0; i < g_kgsl_hooks_installed; i++)
        release_inline_hook(&g_kgsl_hooks[i]);
    g_kgsl_hooks_installed = 0;
}

int ls_kgsl_hide_install(void)
{
    unsigned int i;
    int ret;

    mutex_lock(&g_kgsl_hook_lock);
    if (g_kgsl_hooks_installed == KGSL_HOOK_COUNT) {
        mutex_unlock(&g_kgsl_hook_lock);
        return 0;
    }

    if (g_kgsl_hooks_installed) {
        ret = kgsl_restore_hooks_locked();
        if (ret)
            goto out_unlock;
        kgsl_release_hooks_locked();
    }

    for (i = 0; i < KGSL_HOOK_COUNT; i++) {
        ret = do_inline_hook(&g_kgsl_hooks[i],
                             g_kgsl_hook_specs[i].symbol,
                             g_kgsl_hook_specs[i].handler);
        if (ret) {
            pr_err("lsdriver: KGSL hook %s failed: %d\n",
                   g_kgsl_hook_specs[i].symbol, ret);
            if (!kgsl_restore_hooks_locked())
                kgsl_release_hooks_locked();
            goto out_unlock;
        }
        g_kgsl_hooks_installed++;
    }

    ret = 0;

out_unlock:
    mutex_unlock(&g_kgsl_hook_lock);
    return ret;
}

void ls_kgsl_hide_remove(void)
{
    int ret;

    mutex_lock(&g_kgsl_hook_lock);
    ret = kgsl_restore_hooks_locked();
    if (!ret)
        kgsl_release_hooks_locked();
    else
        pr_err("lsdriver: failed to restore KGSL hooks: %d\n", ret);
    mutex_unlock(&g_kgsl_hook_lock);
}
