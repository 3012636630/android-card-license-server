#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/version.h>

#include <asm/barrier.h>
#include <asm/esr.h>
#include <asm/ptrace.h>

#include "tool.h"
#include "vtime.h"
#include "target_guard.h"
#include "kernel_compat.h"

#define LS_CNTKCTL_EL0VCTEN       (1ULL << 1)
#define LS_VTIME_MAX_TABLE_HOOKS  8
#define LS_VTIME_MAX_TABLE_SCAN   16
#define LS_VTIME_USEC_PER_SEC     1000000ULL
#define LS_VTIME_CALIBRATION_LOOPS 32

#ifndef ESR_ELx_SYS64_ISS_SYS_CNTVCTSS
#define ESR_ELx_SYS64_ISS_SYS_CNTVCTSS \
    (ESR_ELx_SYS64_ISS_SYS_VAL(3, 3, 6, 14, 0) | \
     ESR_ELx_SYS64_ISS_DIR_READ)
#endif

#ifndef ESR_ELx_CP15_64_ISS_SYS_CNTVCTSS
#define ESR_ELx_CP15_64_ISS_SYS_CNTVCTSS \
    (ESR_ELx_CP15_64_ISS_SYS_VAL(9, 14) | \
     ESR_ELx_CP15_64_ISS_DIR_READ)
#endif

#if LS_VTIME_ESR_IS_ULONG
typedef unsigned long ls_vtime_esr_t;
struct ls_vtime_hook_entry {
    unsigned long esr_mask;
    unsigned long esr_val;
    void (*handler)(unsigned long esr, struct pt_regs *regs);
};
#else
typedef unsigned int ls_vtime_esr_t;
struct ls_vtime_hook_entry {
    unsigned int esr_mask;
    unsigned int esr_val;
    void (*handler)(unsigned int esr, struct pt_regs *regs);
};
#endif

typedef void (*ls_vtime_handler_t)(ls_vtime_esr_t esr,
                                   struct pt_regs *regs);
typedef void (*ls_vtime_skip_fn_t)(struct pt_regs *regs,
                                   unsigned long size);
typedef int (*ls_vtime_set_memory_t)(unsigned long addr, int numpages);

enum ls_vtime_table_kind {
    LS_VTIME_TABLE_SYS64 = 0,
    LS_VTIME_TABLE_CP15_64,
    LS_VTIME_TABLE_CP15_32,
};

struct ls_vtime_patch {
    struct ls_vtime_hook_entry *entry;
    ls_vtime_handler_t original;
    enum ls_vtime_table_kind kind;
};

static DEFINE_MUTEX(g_vtime_lock);
static DEFINE_PER_CPU(u64, g_vtime_saved_cntkctl);
static DEFINE_PER_CPU(bool, g_vtime_cntkctl_saved);
static DEFINE_PER_CPU(u64, g_vtime_read_overhead_ticks);
static DEFINE_PER_CPU(u64, g_vtime_debug_auto_bias_ticks);
static DEFINE_PER_CPU(u64, g_vtime_sysread_auto_bias_ticks);

static atomic64_t g_vtime_debt = ATOMIC64_INIT(0);
static atomic64_t g_vtime_floor = ATOMIC64_INIT(0);
static atomic64_t g_vtime_last_raw = ATOMIC64_INIT(0);
static bool g_vtime_active;
static bool g_vtime_tables_installed;
static u64 g_vtime_freq_cached;

static struct ls_vtime_patch g_vtime_patches[LS_VTIME_MAX_TABLE_HOOKS];
static int g_vtime_patch_count;
static ls_vtime_set_memory_t g_vtime_set_memory_rw;
static ls_vtime_set_memory_t g_vtime_set_memory_ro;
static ls_vtime_skip_fn_t g_vtime_skip_instruction;

static unsigned long g_vtime_debug_bias_ticks;
static unsigned long g_vtime_sysread_bias_ticks;
static bool g_vtime_auto_calibrate = true;
static unsigned long g_vtime_debug_auto_scale = 8;
static unsigned long g_vtime_sysread_auto_scale = 4;
static unsigned long g_vtime_slew_max_us = 128;
module_param_named(vtime_debug_bias_ticks, g_vtime_debug_bias_ticks, ulong, 0600);
module_param_named(vtime_sysread_bias_ticks, g_vtime_sysread_bias_ticks, ulong, 0600);
module_param_named(vtime_auto_calibrate, g_vtime_auto_calibrate, bool, 0600);
module_param_named(vtime_debug_auto_scale, g_vtime_debug_auto_scale, ulong, 0600);
module_param_named(vtime_sysread_auto_scale, g_vtime_sysread_auto_scale, ulong, 0600);
module_param_named(vtime_slew_max_us, g_vtime_slew_max_us, ulong, 0600);

static void ls_vtime_sys64_handler(ls_vtime_esr_t esr,
                                   struct pt_regs *regs);
static void ls_vtime_cp15_64_handler(ls_vtime_esr_t esr,
                                     struct pt_regs *regs);
static void ls_vtime_cp15_32_handler(ls_vtime_esr_t esr,
                                     struct pt_regs *regs);

u64 ls_vtime_read_counter(void)
{
    u64 value;

    asm volatile("isb\n\tmrs %0, cntvct_el0" : "=r" (value));
    return value;
}

static inline u64 ls_vtime_read_frequency(void)
{
    u64 value;

    asm volatile("mrs %0, cntfrq_el0" : "=r" (value));
    return value;
}

static u64 ls_vtime_ticks_from_us(unsigned long usec)
{
    u64 freq = READ_ONCE(g_vtime_freq_cached);
    u64 ticks_per_us;

    if (usec > 1000000UL)
        usec = 1000000UL;
    if (!freq)
        freq = ls_vtime_read_frequency();

    ticks_per_us = freq / LS_VTIME_USEC_PER_SEC;
    if (!ticks_per_us)
        ticks_per_us = 1;
    return ticks_per_us * usec;
}

static u64 ls_vtime_calibrate_read_cost(void)
{
    u64 best = ~0ULL;
    u64 a;
    u64 b;
    u64 delta;
    int i;

    for (i = 0; i < LS_VTIME_CALIBRATION_LOOPS; i++) {
        a = ls_vtime_read_counter();
        b = ls_vtime_read_counter();
        delta = b - a;
        if (delta && delta < best)
            best = delta;
    }
    if (best == ~0ULL)
        best = 1;
    return best;
}

static void ls_vtime_calibrate_this_cpu(void)
{
    u64 base;
    u64 cap;
    unsigned long debug_scale;
    unsigned long sysread_scale;

    if (!READ_ONCE(g_vtime_auto_calibrate))
        return;

    base = ls_vtime_calibrate_read_cost();
    cap = ls_vtime_ticks_from_us(64);
    if (base > cap)
        base = cap;

    debug_scale = READ_ONCE(g_vtime_debug_auto_scale);
    sysread_scale = READ_ONCE(g_vtime_sysread_auto_scale);
    if (!debug_scale)
        debug_scale = 1;
    if (!sysread_scale)
        sysread_scale = 1;
    if (debug_scale > 1024)
        debug_scale = 1024;
    if (sysread_scale > 1024)
        sysread_scale = 1024;

    this_cpu_write(g_vtime_read_overhead_ticks, base);
    this_cpu_write(g_vtime_debug_auto_bias_ticks,
                   (base * debug_scale) > cap ? cap : base * debug_scale);
    this_cpu_write(g_vtime_sysread_auto_bias_ticks,
                   (base * sysread_scale) > cap ? cap : base * sysread_scale);
}

static void ls_vtime_calibrate_cpu_cb(void *unused)
{
    ls_vtime_calibrate_this_cpu();
}

static inline u64 ls_vtime_debug_bias(void)
{
    u64 manual = READ_ONCE(g_vtime_debug_bias_ticks);

    if (manual)
        return manual;
    if (!READ_ONCE(g_vtime_auto_calibrate))
        return 0;
    if (!this_cpu_read(g_vtime_read_overhead_ticks))
        ls_vtime_calibrate_this_cpu();
    return this_cpu_read(g_vtime_debug_auto_bias_ticks);
}

static inline u64 ls_vtime_sysread_bias(void)
{
    u64 manual = READ_ONCE(g_vtime_sysread_bias_ticks);

    if (manual)
        return manual;
    if (!READ_ONCE(g_vtime_auto_calibrate))
        return 0;
    if (!this_cpu_read(g_vtime_read_overhead_ticks))
        ls_vtime_calibrate_this_cpu();
    return this_cpu_read(g_vtime_sysread_auto_bias_ticks);
}

static u64 ls_vtime_slew_budget(u64 now)
{
    unsigned long max_us = READ_ONCE(g_vtime_slew_max_us);
    s64 last;
    u64 elapsed;
    u64 time_budget;
    u64 param_budget;

    if (!max_us)
        return ~0ULL;

    param_budget = ls_vtime_ticks_from_us(max_us);
    last = atomic64_read(&g_vtime_last_raw);
    elapsed = (last > 0 && now > (u64)last) ? now - (u64)last : 0;
    time_budget = elapsed >> 1;
    if (time_budget < param_budget)
        time_budget = param_budget;
    if (!time_budget)
        time_budget = 1;
    return time_budget;
}

static inline u64 ls_vtime_read_cntkctl(void)
{
    u64 value;

    asm volatile("mrs %0, cntkctl_el1" : "=r" (value));
    return value;
}

static inline void ls_vtime_write_cntkctl(u64 value)
{
    asm volatile("msr cntkctl_el1, %0\n\tisb" :: "r" (value) : "memory");
}

static void ls_vtime_arm_this_cpu(void)
{
    u64 cntkctl;

    if (this_cpu_read(g_vtime_cntkctl_saved))
        return;

    cntkctl = ls_vtime_read_cntkctl();
    this_cpu_write(g_vtime_saved_cntkctl, cntkctl);
    this_cpu_write(g_vtime_cntkctl_saved, true);
    ls_vtime_write_cntkctl(cntkctl & ~LS_CNTKCTL_EL0VCTEN);
}

static void ls_vtime_restore_this_cpu(void)
{
    u64 saved;

    if (!this_cpu_read(g_vtime_cntkctl_saved))
        return;

    saved = this_cpu_read(g_vtime_saved_cntkctl);
    ls_vtime_write_cntkctl(saved);
    this_cpu_write(g_vtime_cntkctl_saved, false);
}

static void ls_vtime_arm_if_target_on_cpu(void *unused)
{
    if (READ_ONCE(g_vtime_active) && ls_target_matches(current))
        ls_vtime_arm_this_cpu();
}

static void ls_vtime_restore_on_cpu(void *unused)
{
    ls_vtime_restore_this_cpu();
}

static bool ls_vtime_is_target(void)
{
    if (!READ_ONCE(g_vtime_active))
        return false;

    return ls_target_matches(current);
}

bool ls_vtime_is_active(void)
{
    return READ_ONCE(g_vtime_active);
}

static bool ls_vtime_entry_matches(enum ls_vtime_table_kind kind,
                                   unsigned long value)
{
    if (kind == LS_VTIME_TABLE_SYS64) {
        return value == ESR_ELx_SYS64_ISS_SYS_CNTVCT ||
               value == ESR_ELx_SYS64_ISS_SYS_CNTVCTSS ||
               value == ESR_ELx_SYS64_ISS_SYS_CNTFRQ;
    }

    if (kind == LS_VTIME_TABLE_CP15_64) {
        return value == ESR_ELx_CP15_64_ISS_SYS_CNTVCT ||
               value == ESR_ELx_CP15_64_ISS_SYS_CNTVCTSS;
    }

    return value == ESR_ELx_CP15_32_ISS_SYS_CNTFRQ;
}

static ls_vtime_handler_t ls_vtime_replacement(enum ls_vtime_table_kind kind)
{
    if (kind == LS_VTIME_TABLE_SYS64)
        return ls_vtime_sys64_handler;
    if (kind == LS_VTIME_TABLE_CP15_64)
        return ls_vtime_cp15_64_handler;
    return ls_vtime_cp15_32_handler;
}

static int ls_vtime_patch_entry(struct ls_vtime_hook_entry *entry,
                                enum ls_vtime_table_kind kind)
{
    struct ls_vtime_patch *patch;
    unsigned long page;
    int ret;

    if (g_vtime_patch_count >= LS_VTIME_MAX_TABLE_HOOKS)
        return -ENOSPC;

    page = (unsigned long)&entry->handler & PAGE_MASK;
    ret = g_vtime_set_memory_rw(page, 1);
    if (ret)
        return ret;

    patch = &g_vtime_patches[g_vtime_patch_count++];
    patch->entry = entry;
    patch->original = READ_ONCE(entry->handler);
    patch->kind = kind;
    WRITE_ONCE(entry->handler, ls_vtime_replacement(kind));
    dsb(ish);
    isb();

    ret = g_vtime_set_memory_ro(page, 1);
    return ret;
}

static int ls_vtime_patch_table(const char *symbol,
                                enum ls_vtime_table_kind kind,
                                bool required)
{
    struct ls_vtime_hook_entry *table;
    unsigned long address;
    int i;
    int matched = 0;
    int ret;

    address = resolve_unexported_symbol(symbol);
    if (!address)
        return required ? -ENOENT : 0;

    table = (struct ls_vtime_hook_entry *)address;
    for (i = 0; i < LS_VTIME_MAX_TABLE_SCAN; i++) {
        if (!READ_ONCE(table[i].handler))
            break;
        if (!ls_vtime_entry_matches(kind, table[i].esr_val))
            continue;

        ret = ls_vtime_patch_entry(&table[i], kind);
        if (ret)
            return ret;
        matched++;
    }

    if (required && matched < 2)
        return -ENOENT;
    return 0;
}

static int ls_vtime_restore_tables(void)
{
    struct ls_vtime_patch *patch;
    unsigned long page;
    int i;
    int ret;
    int first_error = 0;

    for (i = g_vtime_patch_count - 1; i >= 0; i--) {
        patch = &g_vtime_patches[i];
        page = (unsigned long)&patch->entry->handler & PAGE_MASK;
        ret = g_vtime_set_memory_rw(page, 1);
        if (ret) {
            if (!first_error)
                first_error = ret;
            continue;
        }
        WRITE_ONCE(patch->entry->handler, patch->original);
        dsb(ish);
        isb();
        ret = g_vtime_set_memory_ro(page, 1);
        if (ret && !first_error)
            first_error = ret;
    }

    if (!first_error) {
        g_vtime_patch_count = 0;
        g_vtime_tables_installed = false;
    } else {
        g_vtime_tables_installed = true;
    }
    return first_error;
}

static int ls_vtime_install_tables(void)
{
    unsigned long address;
    int ret;
    int restore_ret;

    if (g_vtime_tables_installed)
        return 0;

    address = resolve_unexported_symbol("set_memory_rw");
    g_vtime_set_memory_rw = (ls_vtime_set_memory_t)address;
    address = resolve_unexported_symbol("set_memory_ro");
    g_vtime_set_memory_ro = (ls_vtime_set_memory_t)address;
    if (!g_vtime_set_memory_rw || !g_vtime_set_memory_ro)
        return -ENOENT;

    address = resolve_unexported_symbol("arm64_skip_faulting_instruction");
    g_vtime_skip_instruction = (ls_vtime_skip_fn_t)address;

    ret = ls_vtime_patch_table("sys64_hooks", LS_VTIME_TABLE_SYS64, true);
    if (ret)
        goto rollback;

    if (g_vtime_skip_instruction) {
        ret = ls_vtime_patch_table("cp15_64_hooks",
                                   LS_VTIME_TABLE_CP15_64, false);
        if (ret)
            goto rollback;
        ret = ls_vtime_patch_table("cp15_32_hooks",
                                   LS_VTIME_TABLE_CP15_32, false);
        if (ret)
            goto rollback;
    }

    g_vtime_tables_installed = true;
    return 0;

rollback:
    restore_ret = ls_vtime_restore_tables();
    if (restore_ret)
        return restore_ret;
    return ret;
}

int ls_vtime_start(void)
{
    u64 now;
    int ret;

    mutex_lock(&g_vtime_lock);
    if (g_vtime_active) {
        mutex_unlock(&g_vtime_lock);
        return 0;
    }

    ret = ls_vtime_install_tables();
    if (ret) {
        mutex_unlock(&g_vtime_lock);
        return ret;
    }

    now = ls_vtime_read_counter();
    WRITE_ONCE(g_vtime_freq_cached, ls_vtime_read_frequency());
    on_each_cpu(ls_vtime_calibrate_cpu_cb, NULL, 1);
    atomic64_set(&g_vtime_debt, 0);
    atomic64_set(&g_vtime_floor, (s64)now);
    atomic64_set(&g_vtime_last_raw, (s64)now);
    smp_wmb();
    WRITE_ONCE(g_vtime_active, true);
    on_each_cpu(ls_vtime_arm_if_target_on_cpu, NULL, 1);
    mutex_unlock(&g_vtime_lock);
    return 0;
}

void ls_vtime_stop(void)
{
    mutex_lock(&g_vtime_lock);
    WRITE_ONCE(g_vtime_active, false);
    on_each_cpu(ls_vtime_restore_on_cpu, NULL, 1);
    atomic64_set(&g_vtime_debt, 0);
    atomic64_set(&g_vtime_floor, 0);
    atomic64_set(&g_vtime_last_raw, 0);
    mutex_unlock(&g_vtime_lock);
}

void ls_vtime_shutdown(void)
{
    ls_vtime_stop();
    mutex_lock(&g_vtime_lock);
    if (g_vtime_tables_installed)
        ls_vtime_restore_tables();
    mutex_unlock(&g_vtime_lock);
}

void ls_vtime_sched_switch(struct task_struct *prev, struct task_struct *next)
{
    bool prev_target;
    bool next_target;

    if (!READ_ONCE(g_vtime_active))
        return;

    prev_target = ls_target_matches(prev);
    next_target = ls_target_matches(next);

    if (prev_target && !next_target)
        ls_vtime_restore_this_cpu();
    else if (!prev_target && next_target)
        ls_vtime_arm_this_cpu();
}

void ls_vtime_account_debug(u64 start)
{
    u64 end;
    u64 delta;

    if (!ls_vtime_is_target())
        return;

    end = ls_vtime_read_counter();
    delta = end - start + ls_vtime_debug_bias();
    atomic64_add((s64)delta, &g_vtime_debt);
}

static u64 ls_vtime_publish_monotonic(u64 candidate)
{
    s64 old;
    s64 desired;
    s64 observed;

    for (;;) {
        old = atomic64_read(&g_vtime_floor);
        desired = (s64)candidate;
        if (desired <= old)
            desired = old + 1;

        observed = atomic64_cmpxchg(&g_vtime_floor, old, desired);
        if (observed == old)
            return (u64)desired;
    }
}

static u64 ls_vtime_virtual_counter(u64 handler_start)
{
    u64 now;
    u64 pending;
    u64 budget;
    u64 compensation;
    u64 leftover;
    u64 candidate;

    now = ls_vtime_read_counter();
    pending = (u64)atomic64_xchg(&g_vtime_debt, 0);
    compensation = pending + (now - handler_start) + ls_vtime_sysread_bias();
    budget = ls_vtime_slew_budget(now);
    atomic64_set(&g_vtime_last_raw, (s64)now);
    if (compensation > budget) {
        leftover = compensation - budget;
        compensation = budget;
        atomic64_add((s64)leftover, &g_vtime_debt);
    }
    candidate = now > compensation ? now - compensation : 0;
    return ls_vtime_publish_monotonic(candidate);
}

static void ls_vtime_account_frequency_read(u64 handler_start)
{
    u64 now = ls_vtime_read_counter();

    atomic64_add((s64)(now - handler_start +
                 ls_vtime_sysread_bias()),
                 &g_vtime_debt);
}

static ls_vtime_handler_t ls_vtime_find_original(
    enum ls_vtime_table_kind kind, ls_vtime_esr_t esr)
{
    struct ls_vtime_patch *patch;
    int i;

    for (i = 0; i < g_vtime_patch_count; i++) {
        patch = &g_vtime_patches[i];
        if (patch->kind != kind)
            continue;
        if ((patch->entry->esr_mask & esr) == patch->entry->esr_val)
            return patch->original;
    }
    return NULL;
}

static void ls_vtime_call_original(enum ls_vtime_table_kind kind,
                                   ls_vtime_esr_t esr,
                                   struct pt_regs *regs)
{
    ls_vtime_handler_t original;

    original = ls_vtime_find_original(kind, esr);
    if (original)
        original(esr, regs);
}

static void ls_vtime_sys64_handler(ls_vtime_esr_t esr,
                                   struct pt_regs *regs)
{
    unsigned long sysop;
    unsigned int rt;
    u64 start;
    u64 value;

    if (!ls_vtime_is_target()) {
        ls_vtime_call_original(LS_VTIME_TABLE_SYS64, esr, regs);
        return;
    }

    sysop = esr & ESR_ELx_SYS64_ISS_SYS_OP_MASK;
    start = ls_vtime_read_counter();
    rt = (esr & ESR_ELx_SYS64_ISS_RT_MASK) >>
         ESR_ELx_SYS64_ISS_RT_SHIFT;

    if (sysop == ESR_ELx_SYS64_ISS_SYS_CNTFRQ) {
        value = ls_vtime_read_frequency();
        ls_vtime_account_frequency_read(start);
    } else {
        value = ls_vtime_virtual_counter(start);
    }

    if (rt != 31)
        regs->regs[rt] = value;
    regs->pc += 4;
}

static void ls_vtime_cp15_64_handler(ls_vtime_esr_t esr,
                                     struct pt_regs *regs)
{
    unsigned int rt;
    unsigned int rt2;
    u64 value;

    if (!ls_vtime_is_target() || !g_vtime_skip_instruction) {
        ls_vtime_call_original(LS_VTIME_TABLE_CP15_64, esr, regs);
        return;
    }

    rt = (esr & ESR_ELx_CP15_64_ISS_RT_MASK) >>
         ESR_ELx_CP15_64_ISS_RT_SHIFT;
    rt2 = (esr & ESR_ELx_CP15_64_ISS_RT2_MASK) >>
          ESR_ELx_CP15_64_ISS_RT2_SHIFT;
    value = ls_vtime_virtual_counter(ls_vtime_read_counter());
    regs->regs[rt] = lower_32_bits(value);
    regs->regs[rt2] = upper_32_bits(value);
    g_vtime_skip_instruction(regs, 4);
}

static void ls_vtime_cp15_32_handler(ls_vtime_esr_t esr,
                                     struct pt_regs *regs)
{
    unsigned int rt;
    u64 start;

    if (!ls_vtime_is_target() || !g_vtime_skip_instruction) {
        ls_vtime_call_original(LS_VTIME_TABLE_CP15_32, esr, regs);
        return;
    }

    start = ls_vtime_read_counter();
    rt = (esr & ESR_ELx_CP15_32_ISS_RT_MASK) >>
         ESR_ELx_CP15_32_ISS_RT_SHIFT;
    regs->regs[rt] = (u32)ls_vtime_read_frequency();
    ls_vtime_account_frequency_read(start);
    g_vtime_skip_instruction(regs, 4);
}
