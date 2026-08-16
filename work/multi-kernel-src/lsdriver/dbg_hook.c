#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <asm/ptrace.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <trace/events/sched.h> 
#include <linux/version.h> 
#include <linux/delay.h>   // 馃専 蹇呴』寮曞叆锛岀敤浜?usleep_range
#include <linux/sched/signal.h> // 馃専 蹇呴』寮曞叆锛岀敤浜?fatal_signal_pending
#include <asm/barrier.h>
#include <asm/fpsimd.h>
#include "quiet_log.h"
#include "tool.h"
#include "dbg_hook.h"
#include "vtime.h"
#include "target_guard.h"
#include "emulate_insn.h"
#include "coom.h"   
#include "kernel_compat.h"
#include <asm/neon.h>


#define LS_HW_WATERMARK (0x9ULL << 16)
#define LS_MAX_HW_BRP 6
#define LS_MAX_HW_WRP 4
#define LS_MUX_OWNER_NONE (-1)




// 瀹氫箟鍏ㄥ眬鍑芥暟鎸囬拡
long (*g_safe_read_fn)(void *dst, const void __user *src, size_t size) = NULL;

ulong target_addr = 0;
#define BM_MAX_BREAKPOINTS 6  

extern struct req_obj *g_req; 
#define g_slots (g_req->slots)

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name = NULL;

static int my_custom_bp_handler(unsigned long addr, unsigned long esr, struct pt_regs *regs);
static int my_custom_step_handler(unsigned long addr, unsigned long esr, struct pt_regs *regs);
static void clear_all_hw_breakpoints_locked(void);

struct fault_info {
    int (*fn)(unsigned long addr, unsigned long esr, struct pt_regs *regs);
    int sig;
    int code;
    const char *name;
};

static struct fault_info *kernel_debug_fault_info = NULL;
static int (*original_bp_handler)(unsigned long, unsigned long, struct pt_regs *);
static int (*original_step_handler)(unsigned long, unsigned long, struct pt_regs *);
static int (*original_wp_handler)(unsigned long, unsigned int, struct pt_regs *);
static int (*my_set_memory_rw)(unsigned long addr, int numpages) = NULL;
static int (*my_set_memory_ro)(unsigned long addr, int numpages) = NULL;

static int g_hw_brp_count = BM_MAX_BREAKPOINTS;
static int g_hw_wrp_count = 4;
static bool g_hw_caps_ready;
static raw_spinlock_t g_snapshot_locks[BM_MAX_BREAKPOINTS];
static DEFINE_MUTEX(g_breakpoint_lifecycle_lock);
static bool g_sync_snapshot_always = true;

struct ls_mux_saved_slot {
    u64 addr;
    u64 ctrl;
};

struct ls_debug_mux_cpu {
    struct hrtimer timer;
    raw_spinlock_t lock;
    bool initialized;
    bool target_active;
    bool driver_phase;
    bool mdscr_saved;
    bool ownership_lost;
    unsigned int brp_cursor;
    unsigned int wrp_cursor;
    unsigned int brp_phys_cursor;
    unsigned int wrp_phys_cursor;
    unsigned long owned_brp_mask;
    unsigned long owned_wrp_mask;
    unsigned long borrowed_brp_mask;
    unsigned long borrowed_wrp_mask;
    u64 saved_mdscr;
    u64 session_start_jiffies;
    u64 foreign_last_hit_brp[LS_MAX_HW_BRP];
    u64 foreign_last_hit_wrp[LS_MAX_HW_WRP];
    struct ls_mux_saved_slot saved_brp[LS_MAX_HW_BRP];
    struct ls_mux_saved_slot saved_wrp[LS_MAX_HW_WRP];
    s8 brp_owner[LS_MAX_HW_BRP];
    s8 wrp_owner[LS_MAX_HW_WRP];
};

static DEFINE_PER_CPU(struct ls_debug_mux_cpu, g_debug_mux_cpu);
static bool g_debug_mux_enabled;
static bool g_vtime_with_breakpoints;
static unsigned long g_debug_mux_arm_delay_us = 5;
static unsigned long g_debug_mux_period_us = 250;
static unsigned long g_debug_mux_jitter_us = 100;
static unsigned long g_debug_mux_idle_backoff_us = 2000;
static unsigned long g_debug_mux_hot_guard_ms = 20;
static unsigned long g_debug_mux_start_grace_ms = 8;
static unsigned long g_debug_mux_brp_leases = 1;
static unsigned long g_debug_mux_wrp_leases = 1;

module_param_named(debug_mux_enabled, g_debug_mux_enabled, bool, 0600);
module_param_named(vtime_with_breakpoints, g_vtime_with_breakpoints, bool, 0600);
module_param_named(debug_mux_arm_delay_us, g_debug_mux_arm_delay_us, ulong, 0600);
module_param_named(debug_mux_period_us, g_debug_mux_period_us, ulong, 0600);
module_param_named(debug_mux_jitter_us, g_debug_mux_jitter_us, ulong, 0600);
module_param_named(debug_mux_idle_backoff_us, g_debug_mux_idle_backoff_us, ulong, 0600);
module_param_named(debug_mux_hot_guard_ms, g_debug_mux_hot_guard_ms, ulong, 0600);
module_param_named(debug_mux_start_grace_ms, g_debug_mux_start_grace_ms, ulong, 0600);
module_param_named(debug_mux_brp_leases, g_debug_mux_brp_leases, ulong, 0600);
module_param_named(debug_mux_wrp_leases, g_debug_mux_wrp_leases, ulong, 0600);
module_param_named(sync_snapshot_always, g_sync_snapshot_always, bool, 0600);

void ls_debug_runtime_init(void)
{
    int i;

    for (i = 0; i < BM_MAX_BREAKPOINTS; i++)
        raw_spin_lock_init(&g_snapshot_locks[i]);
}

static void ls_publish_regs_snapshot(int slot_idx, struct pt_regs *regs)
{
    struct bm_slot *slot;
    struct ls_regs_info local;
    unsigned long irq_flags;
    u32 seq;

    if (unlikely(!g_req || !regs || slot_idx < 0 ||
                 slot_idx >= BM_MAX_BREAKPOINTS))
        return;

    memset(&local, 0, sizeof(local));
    local.target_addr = READ_ONCE(g_slots[slot_idx].target_addr);
    memcpy(local.regs, regs->regs, sizeof(local.regs));
    local.sp = regs->sp;
    local.pc = regs->pc;
    local.pstate = regs->pstate;

    slot = &g_slots[slot_idx];
    raw_spin_lock_irqsave(&g_snapshot_locks[slot_idx], irq_flags);
    seq = READ_ONCE(slot->sync_state);
    if (seq & 1)
        seq++;
    WRITE_ONCE(slot->sync_state, seq + 1);
    smp_wmb();
    memcpy(&slot->hit_snapshot, &local, sizeof(local));
    smp_wmb();
    WRITE_ONCE(slot->sync_state, seq + 2);
    raw_spin_unlock_irqrestore(&g_snapshot_locks[slot_idx], irq_flags);
}

int ls_snapshot_read_slot(int slot_idx, struct ls_regs_info *out)
{
    u32 seq_before;
    u32 seq_after;
    int attempt;

    if (!g_req || !out || slot_idx < 0 || slot_idx >= BM_MAX_BREAKPOINTS)
        return -EINVAL;

    /* Readers never hold the writer lock, so an ioctl reader cannot delay the
     * synchronous debug exception path. */
    for (attempt = 0; attempt < 8; attempt++) {
        seq_before = READ_ONCE(g_slots[slot_idx].sync_state);
        if (seq_before & 1)
            continue;
        smp_rmb();
        memcpy(out, &g_slots[slot_idx].hit_snapshot, sizeof(*out));
        smp_rmb();
        seq_after = READ_ONCE(g_slots[slot_idx].sync_state);
        if (seq_before == seq_after && !(seq_after & 1))
            return 0;
    }
    return -EAGAIN;
}

int ls_snapshot_write_slot(int slot_idx, const struct ls_regs_info *in)
{
    struct bm_slot *slot;
    unsigned long irq_flags;
    u32 seq;

    if (!g_req || !in || slot_idx < 0 || slot_idx >= BM_MAX_BREAKPOINTS)
        return -EINVAL;

    slot = &g_slots[slot_idx];
    raw_spin_lock_irqsave(&g_snapshot_locks[slot_idx], irq_flags);
    seq = READ_ONCE(slot->sync_state);
    if (seq & 1)
        seq++;
    WRITE_ONCE(slot->sync_state, seq + 1);
    smp_wmb();
    memcpy(&slot->hit_snapshot, in, sizeof(*in));
    smp_wmb();
    WRITE_ONCE(slot->sync_state, seq + 2);
    raw_spin_unlock_irqrestore(&g_snapshot_locks[slot_idx], irq_flags);
    return 0;
}

void ls_snapshot_reset_slot(int slot_idx)
{
    unsigned long irq_flags;

    if (!g_req || slot_idx < 0 || slot_idx >= BM_MAX_BREAKPOINTS)
        return;

    raw_spin_lock_irqsave(&g_snapshot_locks[slot_idx], irq_flags);
    memset(&g_slots[slot_idx].hit_snapshot, 0,
           sizeof(g_slots[slot_idx].hit_snapshot));
    smp_wmb();
    WRITE_ONCE(g_slots[slot_idx].sync_state, 0);
    raw_spin_unlock_irqrestore(&g_snapshot_locks[slot_idx], irq_flags);
}

static inline bool ls_slot_is_active(const struct bm_slot *slot)
{
    return smp_load_acquire(&slot->active);
}

static bool ls_copy_slot_action(int slot_idx, struct ls_bp_action *out)
{
    struct bm_slot *slot;
    unsigned long irq_flags;
    bool active;

    if (!g_req || !out || slot_idx < 0 || slot_idx >= BM_MAX_BREAKPOINTS)
        return false;

    slot = &g_slots[slot_idx];
    raw_spin_lock_irqsave(&g_snapshot_locks[slot_idx], irq_flags);
    active = ls_slot_is_active(slot);
    if (active) {
        smp_rmb();
        *out = slot->action;
    }
    raw_spin_unlock_irqrestore(&g_snapshot_locks[slot_idx], irq_flags);
    return active;
}

static int ls_update_slot_action_locked(int slot_idx,
                                        const struct ls_bp_action *action)
{
    struct bm_slot *slot;
    unsigned long irq_flags;

    if (!g_req || !action || slot_idx < 0 || slot_idx >= BM_MAX_BREAKPOINTS)
        return -EINVAL;
    if (action->q_reg_mask)
        return -EOPNOTSUPP;

    slot = &g_slots[slot_idx];
    raw_spin_lock_irqsave(&g_snapshot_locks[slot_idx], irq_flags);
    if (!ls_slot_is_active(slot)) {
        raw_spin_unlock_irqrestore(&g_snapshot_locks[slot_idx], irq_flags);
        return -EAGAIN;
    }

    slot->action = *action;
    smp_wmb();
    raw_spin_unlock_irqrestore(&g_snapshot_locks[slot_idx], irq_flags);
    return 0;
}

int ls_breakpoint_update_action(int slot_idx, u64 target_addr,
                                const struct ls_bp_action *action)
{
    int i;
    int ret = -EAGAIN;

    if (!action)
        return -EINVAL;

    mutex_lock(&g_breakpoint_lifecycle_lock);
    if (slot_idx >= 0 && slot_idx < BM_MAX_BREAKPOINTS) {
        ret = ls_update_slot_action_locked(slot_idx, action);
    } else if (g_req) {
        for (i = 0; i < BM_MAX_BREAKPOINTS; i++) {
            if (READ_ONCE(g_slots[i].target_addr) == target_addr) {
                ret = ls_update_slot_action_locked(i, action);
                break;
            }
        }
    }
    mutex_unlock(&g_breakpoint_lifecycle_lock);
    return ret;
}

static void detect_hw_debug_caps(void)
{
    u64 dfr0;
    int brps, wrps;

    if (g_hw_caps_ready)
        return;

    asm volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr0));
    brps = (int)(((dfr0 >> 12) & 0xf) + 1);
    wrps = (int)(((dfr0 >> 20) & 0xf) + 1);

    if (brps > 0 && brps < BM_MAX_BREAKPOINTS)
        g_hw_brp_count = brps;
    if (wrps > 0 && wrps < 4)
        g_hw_wrp_count = wrps;

    g_hw_caps_ready = true;
}

static inline int hw_slot_limit(bool is_wp)
{
    detect_hw_debug_caps();
    return is_wp ? g_hw_wrp_count : g_hw_brp_count;
}

static u64 read_hw_ctrl(bool is_wp, int idx)
{
    u64 ctrl = 0;

    if (idx < 0 || idx >= hw_slot_limit(is_wp))
        return 0;

    if (!is_wp) {
        switch (idx) {
        case 0: asm volatile("mrs %0, dbgbcr0_el1" : "=r"(ctrl)); break;
        case 1: asm volatile("mrs %0, dbgbcr1_el1" : "=r"(ctrl)); break;
        case 2: asm volatile("mrs %0, dbgbcr2_el1" : "=r"(ctrl)); break;
        case 3: asm volatile("mrs %0, dbgbcr3_el1" : "=r"(ctrl)); break;
        case 4: asm volatile("mrs %0, dbgbcr4_el1" : "=r"(ctrl)); break;
        case 5: asm volatile("mrs %0, dbgbcr5_el1" : "=r"(ctrl)); break;
        }
    } else {
        switch (idx) {
        case 0: asm volatile("mrs %0, dbgwcr0_el1" : "=r"(ctrl)); break;
        case 1: asm volatile("mrs %0, dbgwcr1_el1" : "=r"(ctrl)); break;
        case 2: asm volatile("mrs %0, dbgwcr2_el1" : "=r"(ctrl)); break;
        case 3: asm volatile("mrs %0, dbgwcr3_el1" : "=r"(ctrl)); break;
        }
    }

    return ctrl;
}

static u64 read_hw_addr(bool is_wp, int idx)
{
    u64 addr = 0;

    if (idx < 0 || idx >= hw_slot_limit(is_wp))
        return 0;

    if (!is_wp) {
        switch (idx) {
        case 0: asm volatile("mrs %0, dbgbvr0_el1" : "=r"(addr)); break;
        case 1: asm volatile("mrs %0, dbgbvr1_el1" : "=r"(addr)); break;
        case 2: asm volatile("mrs %0, dbgbvr2_el1" : "=r"(addr)); break;
        case 3: asm volatile("mrs %0, dbgbvr3_el1" : "=r"(addr)); break;
        case 4: asm volatile("mrs %0, dbgbvr4_el1" : "=r"(addr)); break;
        case 5: asm volatile("mrs %0, dbgbvr5_el1" : "=r"(addr)); break;
        }
    } else {
        switch (idx) {
        case 0: asm volatile("mrs %0, dbgwvr0_el1" : "=r"(addr)); break;
        case 1: asm volatile("mrs %0, dbgwvr1_el1" : "=r"(addr)); break;
        case 2: asm volatile("mrs %0, dbgwvr2_el1" : "=r"(addr)); break;
        case 3: asm volatile("mrs %0, dbgwvr3_el1" : "=r"(addr)); break;
        }
    }

    return addr;
}

static inline u64 read_mdscr(void)
{
    u64 value;

    asm volatile("mrs %0, mdscr_el1" : "=r"(value));
    return value;
}

static inline void write_mdscr(u64 value)
{
    asm volatile("msr mdscr_el1, %0\n\tisb" :: "r"(value) : "memory");
}

static inline void write_hw_reg(bool is_wp, int idx, u64 addr, u64 ctrl)
{
    u64 mdscr;

    if (idx < 0 || idx >= hw_slot_limit(is_wp))
        return;

    asm volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
    if (!(mdscr & (1ULL << 15))) {
        mdscr |= (1ULL << 15);
        asm volatile("msr mdscr_el1, %0\n\t isb" : : "r"(mdscr));
    }

    if (!is_wp) {
        switch (idx) {
        case 0: asm volatile("msr dbgbvr0_el1, %0\n\t msr dbgbcr0_el1, %1\n\t isb" : : "r"(addr), "r"(ctrl)); break;
        case 1: asm volatile("msr dbgbvr1_el1, %0\n\t msr dbgbcr1_el1, %1\n\t isb" : : "r"(addr), "r"(ctrl)); break;
        case 2: asm volatile("msr dbgbvr2_el1, %0\n\t msr dbgbcr2_el1, %1\n\t isb" : : "r"(addr), "r"(ctrl)); break;
        case 3: asm volatile("msr dbgbvr3_el1, %0\n\t msr dbgbcr3_el1, %1\n\t isb" : : "r"(addr), "r"(ctrl)); break;
        case 4: asm volatile("msr dbgbvr4_el1, %0\n\t msr dbgbcr4_el1, %1\n\t isb" : : "r"(addr), "r"(ctrl)); break;
        case 5: asm volatile("msr dbgbvr5_el1, %0\n\t msr dbgbcr5_el1, %1\n\t isb" : : "r"(addr), "r"(ctrl)); break;
        }
    } else {
        switch (idx) {
        case 0: asm volatile("msr dbgwvr0_el1, %0\n\t msr dbgwcr0_el1, %1\n\t isb" : : "r"(addr), "r"(ctrl)); break;
        case 1: asm volatile("msr dbgwvr1_el1, %0\n\t msr dbgwcr1_el1, %1\n\t isb" : : "r"(addr), "r"(ctrl)); break;
        case 2: asm volatile("msr dbgwvr2_el1, %0\n\t msr dbgwcr2_el1, %1\n\t isb" : : "r"(addr), "r"(ctrl)); break;
        case 3: asm volatile("msr dbgwvr3_el1, %0\n\t msr dbgwcr3_el1, %1\n\t isb" : : "r"(addr), "r"(ctrl)); break;
        }
    }
}

static inline void clear_hw_reg(bool is_wp, int idx)
{
    write_hw_reg(is_wp, idx, 0, 0);
}

static inline bool ls_mux_ctrl_is_ours(u64 ctrl)
{
    return (ctrl & 1) &&
           ((ctrl & LS_HW_WATERMARK) == LS_HW_WATERMARK);
}

static bool ls_hw_reg_matches_driver_slot(bool is_wp, int phys_idx)
{
    u64 addr;
    u64 ctrl;
    int i;

    if (!g_req)
        return false;

    addr = read_hw_addr(is_wp, phys_idx);
    ctrl = read_hw_ctrl(is_wp, phys_idx);
    if (!ls_mux_ctrl_is_ours(ctrl))
        return false;

    for (i = 0; i < BM_MAX_BREAKPOINTS; i++) {
        if (ls_slot_is_active(&g_slots[i]) &&
            READ_ONCE(g_slots[i].is_watchpoint) == is_wp &&
            READ_ONCE(g_slots[i].target_addr) == addr &&
            READ_ONCE(g_slots[i].hw_ctrl) == ctrl)
            return true;
    }
    return false;
}

static ktime_t ls_mux_period(bool idle)
{
    unsigned long period_us;
    unsigned long jitter_us = READ_ONCE(g_debug_mux_jitter_us);
    unsigned long span;

    period_us = idle ? READ_ONCE(g_debug_mux_idle_backoff_us) :
                       READ_ONCE(g_debug_mux_period_us);

    if (period_us < 50)
        period_us = 50;
    if (period_us > 1000000)
        period_us = 1000000;

    if (jitter_us > period_us - 50)
        jitter_us = period_us - 50;
    if (jitter_us > 500000)
        jitter_us = 500000;
    if (jitter_us) {
        span = jitter_us * 2 + 1;
        period_us = period_us - jitter_us +
                    (get_random_u32() % span);
    }
    return ns_to_ktime((u64)period_us * NSEC_PER_USEC);
}

static ktime_t ls_mux_arm_delay(void)
{
    unsigned long delay_us = READ_ONCE(g_debug_mux_arm_delay_us);

    if (delay_us < 1)
        delay_us = 1;
    if (delay_us > 1000)
        delay_us = 1000;
    return ns_to_ktime((u64)delay_us * NSEC_PER_USEC);
}

static void ls_mux_reset_owners(struct ls_debug_mux_cpu *state)
{
    int i;

    for (i = 0; i < LS_MAX_HW_BRP; i++)
        state->brp_owner[i] = LS_MUX_OWNER_NONE;
    for (i = 0; i < LS_MAX_HW_WRP; i++)
        state->wrp_owner[i] = LS_MUX_OWNER_NONE;
}

static void ls_mux_restore_one_locked(struct ls_debug_mux_cpu *state,
                                      bool is_wp, int phys_idx)
{
    struct ls_mux_saved_slot *saved;
    s8 *owners;
    unsigned long *owned_mask;
    unsigned long *borrowed_mask;
    int logical_idx;
    u64 ctrl;
    u64 addr;
    bool still_ours = false;

    saved = is_wp ? state->saved_wrp : state->saved_brp;
    owners = is_wp ? state->wrp_owner : state->brp_owner;
    owned_mask = is_wp ? &state->owned_wrp_mask :
                         &state->owned_brp_mask;
    borrowed_mask = is_wp ? &state->borrowed_wrp_mask :
                            &state->borrowed_brp_mask;

    if (!(*owned_mask & BIT(phys_idx)))
        return;

    logical_idx = owners[phys_idx];
    ctrl = read_hw_ctrl(is_wp, phys_idx);
    addr = read_hw_addr(is_wp, phys_idx);
    if (g_req && logical_idx >= 0 &&
        logical_idx < BM_MAX_BREAKPOINTS &&
        ls_mux_ctrl_is_ours(ctrl) &&
        addr == READ_ONCE(g_slots[logical_idx].target_addr))
        still_ours = true;

    /* A foreign writer may have reclaimed this register while our lease was
     * active.  Only restore the saved image when the hardware still contains
     * the exact lease owned by this driver. */
    if (still_ours)
        write_hw_reg(is_wp, phys_idx,
                     saved[phys_idx].addr, saved[phys_idx].ctrl);
    else
        state->ownership_lost = true;

    owners[phys_idx] = LS_MUX_OWNER_NONE;
    *owned_mask &= ~BIT(phys_idx);
    *borrowed_mask &= ~BIT(phys_idx);
}

static void ls_mux_restore_overlay_locked(struct ls_debug_mux_cpu *state)
{
    int i;

    for (i = 0; i < g_hw_brp_count; i++)
        ls_mux_restore_one_locked(state, false, i);
    for (i = 0; i < g_hw_wrp_count; i++)
        ls_mux_restore_one_locked(state, true, i);

    if (state->mdscr_saved && !state->ownership_lost) {
        write_mdscr(state->saved_mdscr);
    }
    state->mdscr_saved = false;
    state->ownership_lost = false;
}

static void ls_mux_restore_borrowed_locked(struct ls_debug_mux_cpu *state)
{
    int i;

    for (i = 0; i < g_hw_brp_count; i++) {
        if (state->borrowed_brp_mask & BIT(i))
            ls_mux_restore_one_locked(state, false, i);
    }
    for (i = 0; i < g_hw_wrp_count; i++) {
        if (state->borrowed_wrp_mask & BIT(i))
            ls_mux_restore_one_locked(state, true, i);
    }

    if (!state->owned_brp_mask && !state->owned_wrp_mask &&
        state->mdscr_saved) {
        if (!state->ownership_lost)
            write_mdscr(state->saved_mdscr);
        state->mdscr_saved = false;
        state->ownership_lost = false;
    }
}

static int ls_mux_next_logical(bool is_wp, unsigned int *cursor,
                               unsigned long used_mask)
{
    unsigned int start;
    unsigned int n;
    int idx;

    if (!g_req)
        return -1;

    start = *cursor % BM_MAX_BREAKPOINTS;
    for (n = 0; n < BM_MAX_BREAKPOINTS; n++) {
        idx = (start + n) % BM_MAX_BREAKPOINTS;
        if ((used_mask & BIT(idx)) ||
            !ls_slot_is_active(&g_slots[idx]) ||
            READ_ONCE(g_slots[idx].is_watchpoint) != is_wp)
            continue;

        *cursor = (idx + 1) % BM_MAX_BREAKPOINTS;
        return idx;
    }
    return -1;
}

static unsigned long
ls_mux_owned_logical_mask_locked(struct ls_debug_mux_cpu *state, bool is_wp)
{
    unsigned long owned_mask;
    unsigned long logical_mask = 0;
    s8 *owners;
    int limit;
    int i;

    owned_mask = is_wp ? state->owned_wrp_mask : state->owned_brp_mask;
    owners = is_wp ? state->wrp_owner : state->brp_owner;
    limit = hw_slot_limit(is_wp);
    for (i = 0; i < limit; i++) {
        if ((owned_mask & BIT(i)) && owners[i] >= 0 &&
            owners[i] < BM_MAX_BREAKPOINTS)
            logical_mask |= BIT(owners[i]);
    }
    return logical_mask;
}

static void
ls_mux_drop_stale_owners_type_locked(struct ls_debug_mux_cpu *state,
                                     bool is_wp)
{
    unsigned long owned_mask;
    s8 *owners;
    int logical_idx;
    int limit;
    int i;

    owned_mask = is_wp ? state->owned_wrp_mask : state->owned_brp_mask;
    owners = is_wp ? state->wrp_owner : state->brp_owner;
    limit = hw_slot_limit(is_wp);
    for (i = 0; i < limit; i++) {
        if (!(owned_mask & BIT(i)))
            continue;
        logical_idx = owners[i];
        if (logical_idx < 0 || logical_idx >= BM_MAX_BREAKPOINTS ||
            !g_req || !ls_slot_is_active(&g_slots[logical_idx]) ||
            READ_ONCE(g_slots[logical_idx].is_watchpoint) != is_wp ||
            !ls_mux_ctrl_is_ours(read_hw_ctrl(is_wp, i)) ||
            read_hw_addr(is_wp, i) !=
                READ_ONCE(g_slots[logical_idx].target_addr))
            ls_mux_restore_one_locked(state, is_wp, i);
    }
}

static bool ls_mux_rotation_needed_locked(struct ls_debug_mux_cpu *state)
{
    unsigned long owned_brp;
    unsigned long owned_wrp;
    int i;

    if (!g_req || !state->target_active)
        return false;
    if (state->borrowed_brp_mask || state->borrowed_wrp_mask)
        return true;

    owned_brp = ls_mux_owned_logical_mask_locked(state, false);
    owned_wrp = ls_mux_owned_logical_mask_locked(state, true);
    for (i = 0; i < BM_MAX_BREAKPOINTS; i++) {
        if (!ls_slot_is_active(&g_slots[i]))
            continue;
        if (READ_ONCE(g_slots[i].is_watchpoint)) {
            if (!(owned_wrp & BIT(i)))
                return true;
        } else if (!(owned_brp & BIT(i))) {
            return true;
        }
    }
    return false;
}

static int ls_mux_pick_physical(struct ls_debug_mux_cpu *state,
                                bool is_wp,
                                unsigned long selected_mask,
                                bool allow_borrow)
{
    int limit = hw_slot_limit(is_wp);
    unsigned int *cursor;
    u64 *last_hit;
    u64 oldest = ~0ULL;
    u64 now;
    unsigned long guard_jiffies;
    int best = -1;
    int offset;
    int idx;

    if (limit <= 0)
        return -1;

    cursor = is_wp ? &state->wrp_phys_cursor :
                     &state->brp_phys_cursor;
    last_hit = is_wp ? state->foreign_last_hit_wrp :
                       state->foreign_last_hit_brp;

    /* Prefer a genuinely free comparator before leasing a foreign one. */
    for (offset = 0; offset < limit; offset++) {
        idx = (*cursor + offset) % limit;
        if (!(selected_mask & BIT(idx)) &&
            !(read_hw_ctrl(is_wp, idx) & 1)) {
            *cursor = (idx + 1) % limit;
            return idx;
        }
    }

    if (!allow_borrow)
        return -1;

    now = get_jiffies_64();
    guard_jiffies = msecs_to_jiffies(
        READ_ONCE(g_debug_mux_start_grace_ms));
    if (state->session_start_jiffies && guard_jiffies &&
        now - state->session_start_jiffies < guard_jiffies)
        return -1;

    /* When all comparators are occupied, rotate physical leases and prefer
     * the foreign slot that has remained quiet for the longest time. */
    for (offset = 0; offset < limit; offset++) {
        idx = (*cursor + offset) % limit;
        if (selected_mask & BIT(idx))
            continue;
        if (last_hit[idx] < oldest) {
            oldest = last_hit[idx];
            best = idx;
        }
    }
    if (best >= 0)
        *cursor = (best + 1) % limit;
    now = get_jiffies_64();
    guard_jiffies = msecs_to_jiffies(
        READ_ONCE(g_debug_mux_hot_guard_ms));
    if (best >= 0 && oldest && guard_jiffies &&
        now - oldest < guard_jiffies)
        return -1;
    return best;
}

static void ls_mux_install_one_locked(struct ls_debug_mux_cpu *state,
                                      bool is_wp, int logical_idx,
                                      int phys_idx)
{
    struct ls_mux_saved_slot *saved;
    s8 *owners;
    unsigned long *owned_mask;
    unsigned long *borrowed_mask;
    struct bm_slot *slot;

    saved = is_wp ? state->saved_wrp : state->saved_brp;
    owners = is_wp ? state->wrp_owner : state->brp_owner;
    owned_mask = is_wp ? &state->owned_wrp_mask :
                         &state->owned_brp_mask;
    borrowed_mask = is_wp ? &state->borrowed_wrp_mask :
                            &state->borrowed_brp_mask;
    slot = &g_slots[logical_idx];

    saved[phys_idx].addr = read_hw_addr(is_wp, phys_idx);
    saved[phys_idx].ctrl = read_hw_ctrl(is_wp, phys_idx);
    owners[phys_idx] = (s8)logical_idx;
    *owned_mask |= BIT(phys_idx);
    if (saved[phys_idx].ctrl & 1)
        *borrowed_mask |= BIT(phys_idx);
    else
        *borrowed_mask &= ~BIT(phys_idx);
    WRITE_ONCE(slot->hw_slot, -1);
    write_hw_reg(is_wp, phys_idx,
                 READ_ONCE(slot->target_addr), READ_ONCE(slot->hw_ctrl));
}

static void ls_mux_apply_type_locked(struct ls_debug_mux_cpu *state,
                                     bool is_wp)
{
    unsigned long leases;
    unsigned long selected_mask;
    unsigned long used_logical_mask;
    unsigned int *cursor;
    unsigned int next_cursor;
    int limit;
    int logical_idx;
    int phys_idx;
    unsigned long count;

    leases = is_wp ? READ_ONCE(g_debug_mux_wrp_leases) :
                     READ_ONCE(g_debug_mux_brp_leases);
    limit = hw_slot_limit(is_wp);
    if (leases > (unsigned long)limit)
        leases = limit;
    cursor = is_wp ? &state->wrp_cursor : &state->brp_cursor;
    selected_mask = is_wp ? state->owned_wrp_mask : state->owned_brp_mask;
    used_logical_mask = ls_mux_owned_logical_mask_locked(state, is_wp);

    /* Free comparators are correctness resources, not leases. Fill every
     * available free slot before considering a foreign comparator. */
    for (count = 0; count < (unsigned long)limit; count++) {
        next_cursor = *cursor;
        logical_idx = ls_mux_next_logical(is_wp, &next_cursor,
                                          used_logical_mask);
        if (logical_idx < 0)
            break;
        phys_idx = ls_mux_pick_physical(state, is_wp, selected_mask, false);
        if (phys_idx < 0)
            break;

        *cursor = next_cursor;
        ls_mux_install_one_locked(state, is_wp, logical_idx, phys_idx);
        selected_mask |= BIT(phys_idx);
        used_logical_mask |= BIT(logical_idx);
    }

    /* Only displacement of an enabled foreign event is lease-limited. */
    for (count = 0; count < leases; count++) {
        next_cursor = *cursor;
        logical_idx = ls_mux_next_logical(is_wp, &next_cursor,
                                          used_logical_mask);
        if (logical_idx < 0)
            break;
        phys_idx = ls_mux_pick_physical(state, is_wp, selected_mask, true);
        if (phys_idx < 0)
            break;

        *cursor = next_cursor;
        ls_mux_install_one_locked(state, is_wp, logical_idx, phys_idx);
        selected_mask |= BIT(phys_idx);
        used_logical_mask |= BIT(logical_idx);
    }
}

static void ls_mux_apply_driver_locked(struct ls_debug_mux_cpu *state)
{
    if (!state->target_active || !g_req)
        return;

    ls_mux_drop_stale_owners_type_locked(state, false);
    ls_mux_drop_stale_owners_type_locked(state, true);
    if (!state->mdscr_saved) {
        state->saved_mdscr = read_mdscr();
        state->mdscr_saved = true;
        state->ownership_lost = false;
    }
    ls_mux_apply_type_locked(state, false);
    ls_mux_apply_type_locked(state, true);

    if (!state->owned_brp_mask && !state->owned_wrp_mask) {
        if (!state->ownership_lost)
            write_mdscr(state->saved_mdscr);
        state->mdscr_saved = false;
        state->ownership_lost = false;
    }
}

static enum hrtimer_restart ls_mux_timer_fn(struct hrtimer *timer)
{
    struct ls_debug_mux_cpu *state;
    unsigned long flags;
    bool restart = false;
    bool account_vtime = false;
    bool idle = false;
    u64 vtime_start = 0;

    state = container_of(timer, struct ls_debug_mux_cpu, timer);
    if (ls_target_matches(current)) {
        vtime_start = ls_vtime_read_counter();
        account_vtime = true;
    }
    raw_spin_lock_irqsave(&state->lock, flags);

    if (!READ_ONCE(g_debug_mux_enabled) || !state->target_active ||
        !g_req || !ls_target_matches(current)) {
        ls_mux_restore_overlay_locked(state);
        state->target_active = false;
        state->driver_phase = false;
    } else {
        ls_mux_drop_stale_owners_type_locked(state, false);
        ls_mux_drop_stale_owners_type_locked(state, true);
        if (state->driver_phase) {
            /* Free comparators stay resident across Game phase.  Only slots
             * that displaced an enabled foreign event are restored here. */
            ls_mux_restore_borrowed_locked(state);
            state->driver_phase = false;
        } else {
            ls_mux_apply_driver_locked(state);
            state->driver_phase = !!(state->owned_brp_mask ||
                                     state->owned_wrp_mask);
        }
        idle = !state->owned_brp_mask && !state->owned_wrp_mask;
        restart = ls_mux_rotation_needed_locked(state);
    }

    raw_spin_unlock_irqrestore(&state->lock, flags);
    if (account_vtime)
        ls_vtime_account_debug(vtime_start);
    if (!restart)
        return HRTIMER_NORESTART;

    hrtimer_forward_now(timer, ls_mux_period(idle));
    return HRTIMER_RESTART;
}

static struct ls_debug_mux_cpu *ls_mux_current_cpu_state(void)
{
    struct ls_debug_mux_cpu *state;

    state = this_cpu_ptr(&g_debug_mux_cpu);
    if (!state->initialized) {
        raw_spin_lock_init(&state->lock);
        hrtimer_init(&state->timer, CLOCK_MONOTONIC,
                     HRTIMER_MODE_REL_PINNED);
        state->timer.function = ls_mux_timer_fn;
        ls_mux_reset_owners(state);
        state->initialized = true;
    }
    return state;
}

static void ls_mux_enter_current_cpu(void)
{
    struct ls_debug_mux_cpu *state;
    unsigned long flags;

    if (!READ_ONCE(g_debug_mux_enabled))
        return;

    state = ls_mux_current_cpu_state();
    raw_spin_lock_irqsave(&state->lock, flags);
    ls_mux_restore_overlay_locked(state);
    if (!state->session_start_jiffies)
        state->session_start_jiffies = get_jiffies_64();
    state->target_active = true;
    state->driver_phase = false;
    raw_spin_unlock_irqrestore(&state->lock, flags);
    /* sched_switch fires before the architectural context switch. Arm once
     * with a short pinned delay so programming happens after the next task's
     * perf/debug state has been restored. Stable free-slot residency then
     * stops the timer instead of entering periodic mux operation. */
    hrtimer_start(&state->timer, ls_mux_arm_delay(),
                  HRTIMER_MODE_REL_PINNED);
}

static void ls_mux_leave_current_cpu(void)
{
    struct ls_debug_mux_cpu *state;
    unsigned long flags;

    state = this_cpu_ptr(&g_debug_mux_cpu);
    if (!state->initialized)
        return;

    raw_spin_lock_irqsave(&state->lock, flags);
    state->target_active = false;
    ls_mux_restore_overlay_locked(state);
    state->driver_phase = false;
    raw_spin_unlock_irqrestore(&state->lock, flags);
    hrtimer_try_to_cancel(&state->timer);
}

static void ls_mux_force_driver_current_cpu(void)
{
    struct ls_debug_mux_cpu *state;
    unsigned long flags;
    bool restart;

    if (!READ_ONCE(g_debug_mux_enabled) || !ls_target_matches(current))
        return;

    state = ls_mux_current_cpu_state();
    raw_spin_lock_irqsave(&state->lock, flags);
    if (!state->session_start_jiffies)
        state->session_start_jiffies = get_jiffies_64();
    state->target_active = true;
    ls_mux_apply_driver_locked(state);
    state->driver_phase = !!(state->owned_brp_mask ||
                             state->owned_wrp_mask);
    restart = ls_mux_rotation_needed_locked(state);
    raw_spin_unlock_irqrestore(&state->lock, flags);
    if (restart)
        hrtimer_start(&state->timer, ls_mux_period(false),
                      HRTIMER_MODE_REL_PINNED);
    else
        hrtimer_try_to_cancel(&state->timer);
}

static void ls_mux_remove_logical_current_cpu(int logical_idx)
{
    struct ls_debug_mux_cpu *state;
    unsigned long flags;
    int i;

    if (logical_idx < 0 || logical_idx >= BM_MAX_BREAKPOINTS)
        return;

    state = this_cpu_ptr(&g_debug_mux_cpu);
    if (!state->initialized)
        return;

    raw_spin_lock_irqsave(&state->lock, flags);
    for (i = 0; i < g_hw_brp_count; i++) {
        if (state->brp_owner[i] == logical_idx)
            ls_mux_restore_one_locked(state, false, i);
    }
    for (i = 0; i < g_hw_wrp_count; i++) {
        if (state->wrp_owner[i] == logical_idx)
            ls_mux_restore_one_locked(state, true, i);
    }
    if (!state->owned_brp_mask && !state->owned_wrp_mask &&
        state->mdscr_saved) {
        if (!state->ownership_lost)
            write_mdscr(state->saved_mdscr);
        state->mdscr_saved = false;
        state->ownership_lost = false;
    }
    raw_spin_unlock_irqrestore(&state->lock, flags);
}

static int ls_mux_find_owned_logical_current_cpu(unsigned long addr,
                                                 unsigned long pc)
{
    struct ls_debug_mux_cpu *state;
    unsigned long flags;
    u64 target;
    int logical_idx;
    int i;

    if (!g_req)
        return -1;
    if (!READ_ONCE(g_debug_mux_enabled)) {
        for (i = 0; i < BM_MAX_BREAKPOINTS; i++) {
            target = READ_ONCE(g_slots[i].target_addr);
            if (ls_slot_is_active(&g_slots[i]) &&
                (target == addr || target == pc))
                return i;
        }
        return -1;
    }

    state = this_cpu_ptr(&g_debug_mux_cpu);
    if (!state->initialized)
        return -1;

    raw_spin_lock_irqsave(&state->lock, flags);
    for (i = 0; i < g_hw_brp_count; i++) {
        if (!(state->owned_brp_mask & BIT(i)))
            continue;
        logical_idx = state->brp_owner[i];
        if (logical_idx < 0 || logical_idx >= BM_MAX_BREAKPOINTS)
            continue;
        target = READ_ONCE(g_slots[logical_idx].target_addr);
        if (ls_slot_is_active(&g_slots[logical_idx]) &&
            !READ_ONCE(g_slots[logical_idx].is_watchpoint) &&
            (target == addr || target == pc) &&
            ls_mux_ctrl_is_ours(read_hw_ctrl(false, i)) &&
            read_hw_addr(false, i) == target) {
            raw_spin_unlock_irqrestore(&state->lock, flags);
            return logical_idx;
        }
    }
    for (i = 0; i < g_hw_wrp_count; i++) {
        if (!(state->owned_wrp_mask & BIT(i)))
            continue;
        logical_idx = state->wrp_owner[i];
        if (logical_idx < 0 || logical_idx >= BM_MAX_BREAKPOINTS)
            continue;
        target = READ_ONCE(g_slots[logical_idx].target_addr);
        if (ls_slot_is_active(&g_slots[logical_idx]) &&
            READ_ONCE(g_slots[logical_idx].is_watchpoint) &&
            (target == addr || target == pc) &&
            ls_mux_ctrl_is_ours(read_hw_ctrl(true, i)) &&
            read_hw_addr(true, i) == target) {
            raw_spin_unlock_irqrestore(&state->lock, flags);
            return logical_idx;
        }
    }
    raw_spin_unlock_irqrestore(&state->lock, flags);
    return -1;
}

static void ls_mux_note_foreign_hit(unsigned long addr, unsigned long pc)
{
    struct ls_debug_mux_cpu *state;
    unsigned long flags;
    u64 stamp;
    u64 reg_addr;
    int i;

    if (!READ_ONCE(g_debug_mux_enabled))
        return;
    state = this_cpu_ptr(&g_debug_mux_cpu);
    if (!state->initialized)
        return;

    stamp = get_jiffies_64();
    raw_spin_lock_irqsave(&state->lock, flags);
    for (i = 0; i < g_hw_brp_count; i++) {
        if ((state->owned_brp_mask & BIT(i)) ||
            !(read_hw_ctrl(false, i) & 1))
            continue;
        reg_addr = read_hw_addr(false, i);
        if (reg_addr == addr || reg_addr == pc)
            state->foreign_last_hit_brp[i] = stamp;
    }
    for (i = 0; i < g_hw_wrp_count; i++) {
        if ((state->owned_wrp_mask & BIT(i)) ||
            !(read_hw_ctrl(true, i) & 1))
            continue;
        reg_addr = read_hw_addr(true, i);
        if ((reg_addr & ~7ULL) == ((u64)addr & ~7ULL))
            state->foreign_last_hit_wrp[i] = stamp;
    }
    raw_spin_unlock_irqrestore(&state->lock, flags);
}

static void ls_mux_stop_cpu(void *unused)
{
    struct ls_debug_mux_cpu *state;
    unsigned long flags;

    state = this_cpu_ptr(&g_debug_mux_cpu);
    if (!state->initialized)
        return;

    hrtimer_try_to_cancel(&state->timer);
    raw_spin_lock_irqsave(&state->lock, flags);
    state->target_active = false;
    ls_mux_restore_overlay_locked(state);
    state->driver_phase = false;
    state->session_start_jiffies = 0;
    raw_spin_unlock_irqrestore(&state->lock, flags);
}

static void ls_mux_stop_all(void)
{
    on_each_cpu(ls_mux_stop_cpu, NULL, 1);
}

static void safe_clear_bp_on_core(void *info)
{
    int i;
    u64 ctrl;
    u64 saved_mdscr = read_mdscr();
    bool changed = false;

    for (i = 0; i < g_hw_brp_count; i++) {
        ctrl = read_hw_ctrl(false, i);
        if (ls_mux_ctrl_is_ours(ctrl) &&
            ls_hw_reg_matches_driver_slot(false, i)) {
            clear_hw_reg(false, i);
            changed = true;
        }
    }

    for (i = 0; i < g_hw_wrp_count; i++) {
        ctrl = read_hw_ctrl(true, i);
        if (ls_mux_ctrl_is_ours(ctrl) &&
            ls_hw_reg_matches_driver_slot(true, i)) {
            clear_hw_reg(true, i);
            changed = true;
        }
    }

    if (changed)
        write_mdscr(saved_mdscr);
}

static int find_safe_hw_slot(bool is_wp)
{
    int i;
    int limit = hw_slot_limit(is_wp);
    u64 ctrl;

    for (i = limit - 1; i >= 0; i--) {
        ctrl = read_hw_ctrl(is_wp, i);
        if (!(ctrl & 1))
            return i;
    }

    return -1;
}

static inline void clear_slot_hw(struct bm_slot *slot)
{
    int logical_idx;
    u64 ctrl;
    u64 saved_mdscr;

    if (!slot)
        return;

    logical_idx = g_req ? (int)(slot - g_slots) : -1;
    ls_mux_remove_logical_current_cpu(logical_idx);

    if (slot->hw_slot >= 0) {
        ctrl = read_hw_ctrl(slot->is_watchpoint, slot->hw_slot);
        if (ls_mux_ctrl_is_ours(ctrl) &&
            read_hw_addr(slot->is_watchpoint, slot->hw_slot) ==
            slot->target_addr) {
            saved_mdscr = read_mdscr();
            clear_hw_reg(slot->is_watchpoint, slot->hw_slot);
            write_mdscr(saved_mdscr);
        }
        slot->hw_slot = -1;
    }
}

static int install_hw_slot(int slot_idx)
{
    struct bm_slot *slot;
    int hw_idx;
    u64 ctrl;

    if (!g_req || slot_idx < 0 || slot_idx >= BM_MAX_BREAKPOINTS)
        return -EINVAL;

    slot = &g_slots[slot_idx];
    if (!ls_slot_is_active(slot))
        return -EINVAL;

    if (slot->hw_slot >= 0) {
        ctrl = read_hw_ctrl(slot->is_watchpoint, slot->hw_slot);
        if (!(ctrl & 1) ||
            (ls_mux_ctrl_is_ours(ctrl) &&
             read_hw_addr(slot->is_watchpoint, slot->hw_slot) ==
             slot->target_addr)) {
            write_hw_reg(slot->is_watchpoint, slot->hw_slot,
                         slot->target_addr, slot->hw_ctrl);
            return slot->hw_slot;
        }
        slot->hw_slot = -1;
    }

    hw_idx = find_safe_hw_slot(slot->is_watchpoint);
    if (hw_idx < 0)
        return -EBUSY;

    slot->hw_slot = hw_idx;
    write_hw_reg(slot->is_watchpoint, hw_idx, slot->target_addr, slot->hw_ctrl);
    return hw_idx;
}



#if LS_SCHED_SWITCH_HAS_PREV_STATE
static void bm_sched_switch_probe(void *data, bool preempt, 
                                  struct task_struct *prev, 
                                  struct task_struct *next,
                                  unsigned int prev_state)
#else
static void bm_sched_switch_probe(void *data, bool preempt, 
                                  struct task_struct *prev, 
                                  struct task_struct *next)
#endif
{
    int i;
    bool prev_target;
    bool next_target;

    ls_vtime_sched_switch(prev, next);
    if (unlikely(!g_req))
        return;

    prev_target = ls_target_matches(prev);
    next_target = ls_target_matches(next);

    if (prev_target)
        ls_mux_leave_current_cpu();

    if (READ_ONCE(g_debug_mux_enabled)) {
        if (next_target)
            ls_mux_enter_current_cpu();
        return;
    }

    if (unlikely(next_target)) {
        for (i = 0; i < BM_MAX_BREAKPOINTS; i++) {
            if (ls_slot_is_active(&g_slots[i]))
                install_hw_slot(i);
        }
    } else if (unlikely(prev_target)) {
        for (i = 0; i < BM_MAX_BREAKPOINTS; i++) {
            if (ls_slot_is_active(&g_slots[i]))
                clear_slot_hw(&g_slots[i]);
        }
        safe_clear_bp_on_core(NULL);
    }
}

static inline void capture_q_regs(struct ls_regs_info *info)
{
    // 1. 鎶㈠崰 NEON 鍗曞厓锛屽己鍒跺唴鏍告妸纭欢 Q 瀵勫瓨鍣ㄦ暟鎹埛鍏ュ綋鍓嶇嚎绋嬪唴瀛?
    kernel_neon_begin(); 

    // 2. 姝ゆ椂 current 鍐呭瓨涓殑鏁版嵁缁濆鏄渶鏂扮殑纭欢鐜板満
    if (likely(current)) {
        memcpy(info->q_regs, current->thread.uw.fpsimd_state.vregs, sizeof(ls_qreg_t) * 32);
    }

    // 3. 褰掕繕鐘舵€?
    kernel_neon_end();
}

static void write_single_q_reg(int q_idx, ls_qreg_t *val)
{
    // 1. 鑾峰彇 NEON 鍗曞厓鐨勪娇鐢ㄦ潈锛岃繖浼氬己鍒跺唴鏍稿皢褰撳墠鐨勭‖浠?Q 瀵勫瓨鍣ㄤ笂涓嬫枃淇濆瓨鍒板綋鍓嶇嚎绋嬬殑鍐呭瓨涓?
    kernel_neon_begin();
    
    // 2. 姝ゆ椂锛岀‖浠剁姸鎬佸凡缁忓畨鍏ㄥ湴澶囦唤鍒颁簡 current 鍐呭瓨涓紝鐩存帴瑕嗙洊鎴戜滑鎯宠鐨勯偅涓?Q 瀵勫瓨鍣?
    if (q_idx >= 0 && q_idx < 32 && current) {
        
        // 娉ㄦ剰锛氬湪鏍囧噯鐨?Linux 6.12 鍙?Android GKI 鍐呮牳涓紝璺緞閫氬父鏄?thread.fpsimd_state
        // 濡傛灉浣犵殑鐗瑰畾榄旀敼鍐呮牳鐗堟湰渚濈劧鎶ラ敊娌℃湁 vregs锛屽彲浠ュ皾璇曟敼鍥?thread.uw.fpsimd_state
       memcpy(&current->thread.uw.fpsimd_state.vregs[q_idx], val, sizeof(ls_qreg_t));
        
    }
    
    // 3. 閲婃斁 NEON 鍗曞厓銆?
    // 馃専 杩斿洖鐢ㄦ埛鎬佹椂锛屽唴鏍镐細灏嗘垜浠慨鏀硅繃鐨?vregs 閲嶆柊鍒峰叆鐗╃悊纭欢锛?
    kernel_neon_end();
}

static bool is_hooked = false;


static int setup_hardware_breakpoints_locked(u64 hook_addr, int hw_type,
                                              const struct ls_bp_action *action)
{
    unsigned long fault_info_addr, rw_addr, ro_addr, kallsyms_addr;
    struct bm_slot *slot;
    u64 ctrl;
    int ret, i;

    if (unlikely(!g_req || !action || !hook_addr))
        return -EINVAL;
    if (action->q_reg_mask)
        return -EOPNOTSUPP;

    switch (hw_type) {
    case LS_HW_TYPE_EXEC:
        if (hook_addr & 0x3)
            return -EINVAL;
        break;
    case LS_HW_TYPE_READ:
    case LS_HW_TYPE_WRITE:
    case LS_HW_TYPE_RW:
        if (hook_addr & 0x7)
            return -EINVAL;
        break;
    default:
        return -EINVAL;
    }

    detect_hw_debug_caps();

    if (!is_hooked) {
        LS_PRINTK(KERN_INFO "[lsdriver] 棣栨鍚姩锛氬紑濮嬪姭鎸佸叏灞€寮傚父琛?..\n");

        // 馃専 1. 浼樺厛鑾峰彇鍏ㄥ眬瀹夊叏璇诲彇鍑芥暟锛堝繀椤诲姞鑺辨嫭鍙锋嫤鎴け璐ワ級
        g_safe_read_fn = (void *)resolve_unexported_symbol("copy_from_user_nofault");
        if (!g_safe_read_fn) {
            LS_PRINTK(KERN_ERR "[lsdriver] 涓ラ噸閿欒: 鎵句笉鍒?copy_from_user_nofault\n");
            return -EFAULT; 
        }

        // 馃専 2. 鑾峰彇鍐呮牳涓囪兘瀵诲潃鍑芥暟锛堝繀椤诲姞鑺辨嫭鍙锋嫤鎴け璐ワ級
        kallsyms_addr = resolve_unexported_symbol("kallsyms_lookup_name");
        if (!kallsyms_addr) {
            LS_PRINTK(KERN_ERR "[lsdriver] 涓ラ噸閿欒: 鎵句笉鍒?kallsyms_lookup_name\n");
            return -EFAULT; 
        }
        my_kallsyms_lookup_name = (kallsyms_lookup_name_t)kallsyms_addr;

        // 馃専 3. 鑾峰彇鍔寔鎵€闇€鐨勫叧閿澏鐐?
        fault_info_addr = my_kallsyms_lookup_name("debug_fault_info");
        rw_addr = my_kallsyms_lookup_name("set_memory_rw");
        ro_addr = my_kallsyms_lookup_name("set_memory_ro");

        if (!fault_info_addr || !rw_addr || !ro_addr) {
            LS_PRINTK(KERN_ERR "[lsdriver] 涓ラ噸閿欒: 鎵句笉鍒板簳灞傝皟璇曠粨鏋勪綋\n");
            return -EFAULT;
        }

        kernel_debug_fault_info = (struct fault_info *)fault_info_addr;
        my_set_memory_rw = (void *)rw_addr;
        my_set_memory_ro = (void *)ro_addr;

        original_bp_handler = kernel_debug_fault_info[0].fn;   
        original_step_handler = kernel_debug_fault_info[1].fn; 
        original_wp_handler = kernel_debug_fault_info[2].fn;   

        my_set_memory_rw(fault_info_addr & PAGE_MASK, 1); 
        kernel_debug_fault_info[0].fn = my_custom_bp_handler;
        kernel_debug_fault_info[1].fn = my_custom_step_handler;
        kernel_debug_fault_info[2].fn = my_custom_bp_handler; 
        my_set_memory_ro(fault_info_addr & PAGE_MASK, 1);
        
        ret = register_trace_sched_switch(bm_sched_switch_probe, NULL);
        if (ret) {
            my_set_memory_rw(fault_info_addr & PAGE_MASK, 1); 
            kernel_debug_fault_info[0].fn = original_bp_handler;
            kernel_debug_fault_info[1].fn = original_step_handler;
            kernel_debug_fault_info[2].fn = original_wp_handler;
            my_set_memory_ro(fault_info_addr & PAGE_MASK, 1);
            return ret;
        }
        is_hooked = true;
    }

    // ========== 娉ㄥ唽鏂偣妲戒綅閫昏緫 ==========
    for (i = 0; i < BM_MAX_BREAKPOINTS; i++) {
        if (!ls_slot_is_active(&g_slots[i]) &&
            READ_ONCE(g_slots[i].target_addr) == 0) {
            slot = &g_slots[i];
            
            slot->target_addr = hook_addr;
            slot->action = *action;
            ls_snapshot_reset_slot(i);
            WRITE_ONCE(slot->hw_slot, -1);
            
            if (hw_type == LS_HW_TYPE_EXEC) {
                slot->is_watchpoint = false;
                slot->hw_ctrl = 0x1E5 | LS_HW_WATERMARK;
            } else {
                slot->is_watchpoint = true;
                ctrl = (0xFF << 5) | (2 << 1) | 1;
                if (hw_type == LS_HW_TYPE_READ)       ctrl |= (1 << 3); 
                else if (hw_type == LS_HW_TYPE_WRITE) ctrl |= (2 << 3); 
                else if (hw_type == LS_HW_TYPE_RW)    ctrl |= (3 << 3); 
                slot->hw_ctrl = ctrl | LS_HW_WATERMARK;
            }
            smp_store_release(&slot->active, true);
            if (ls_target_matches(current)) {
                if (READ_ONCE(g_debug_mux_enabled)) {
                    ls_mux_force_driver_current_cpu();
                } else {
                    ret = install_hw_slot(i);
                    if (ret < 0) {
                        smp_store_release(&slot->active, false);
                        memset(slot, 0, sizeof(*slot));
                        WRITE_ONCE(slot->hw_slot, -1);
                        return ret;
                    }
                }
            }
            if (READ_ONCE(g_vtime_with_breakpoints)) {
                ret = ls_vtime_start();
                if (ret < 0) {
                    smp_store_release(&slot->active, false);
                    clear_slot_hw(slot);
                    memset(slot, 0, sizeof(*slot));
                    WRITE_ONCE(slot->hw_slot, -1);
                    clear_all_hw_breakpoints_locked();
                    return ret;
                }
            }
            return i;
}
    }
    return -ENOMEM;
}

int setup_hardware_breakpoints(u64 hook_addr, int hw_type,
                               const struct ls_bp_action *action)
{
    int ret;

    mutex_lock(&g_breakpoint_lifecycle_lock);
    ret = setup_hardware_breakpoints_locked(hook_addr, hw_type, action);
    mutex_unlock(&g_breakpoint_lifecycle_lock);
    return ret;
}

static int my_custom_step_handler(unsigned long addr, unsigned long esr, struct pt_regs *regs)
{
    int i;
    u64 vtime_start;
    bool vtime_started = false;
    if (unlikely(!g_req)) return -1;

    if (unlikely(ls_target_matches(current) &&
                 (regs->pstate & (1UL << 21)))) {
        if (READ_ONCE(g_vtime_with_breakpoints)) {
            vtime_start = ls_vtime_read_counter();
            vtime_started = true;
        }
        if (READ_ONCE(g_debug_mux_enabled)) {
            ls_mux_force_driver_current_cpu();
        } else {
            for (i = 0; i < BM_MAX_BREAKPOINTS; i++) {
                if (ls_slot_is_active(&g_slots[i]))
                    install_hw_slot(i);
            }
        }
        regs->pstate &= ~(1UL << 21);
        if (vtime_started)
            ls_vtime_account_debug(vtime_start);
        return 0; 
    }
    
    if (likely(original_step_handler)) return original_step_handler(addr, esr, regs);
    return -1;
}

static void clear_all_hw_breakpoints_locked(void)
{
    int i;
    unsigned long fault_info_addr;

    ls_vtime_stop();
    if (is_hooked)
        unregister_trace_sched_switch(bm_sched_switch_probe, NULL);
    ls_mux_stop_all();
    on_each_cpu(safe_clear_bp_on_core, NULL, 1);

    if (likely(g_req)) {
        for (i = 0; i < BM_MAX_BREAKPOINTS; i++) {
            smp_store_release(&g_slots[i].active, false);
            clear_slot_hw(&g_slots[i]);
            WRITE_ONCE(g_slots[i].target_addr, 0);
            ls_snapshot_reset_slot(i);
            WRITE_ONCE(g_slots[i].hw_slot, -1);
            memset(&g_slots[i].action, 0, sizeof(struct ls_bp_action));
        }
    }

    if (is_hooked && kernel_debug_fault_info && my_set_memory_rw) {
        fault_info_addr = (unsigned long)kernel_debug_fault_info;
        my_set_memory_rw(fault_info_addr & PAGE_MASK, 1);
        
        if (original_bp_handler) kernel_debug_fault_info[0].fn = original_bp_handler;
        if (original_step_handler) kernel_debug_fault_info[1].fn = original_step_handler;
        if (original_wp_handler) kernel_debug_fault_info[2].fn = original_wp_handler;

        my_set_memory_ro(fault_info_addr & PAGE_MASK, 1);
        is_hooked = false;
    }
}

void clear_all_hw_breakpoints(void)
{
    mutex_lock(&g_breakpoint_lifecycle_lock);
    clear_all_hw_breakpoints_locked();
    mutex_unlock(&g_breakpoint_lifecycle_lock);
}

// =================================================================
// 馃専 缁堟瀬鏍稿績锛氬绾跨▼闅旂鐨勬柇鐐瑰洖璋冨鐞嗗櫒
// =================================================================
static int my_custom_bp_handler(unsigned long addr, unsigned long esr, struct pt_regs *regs)
{
    struct bm_slot *my_slot = NULL; 
    struct ls_bp_action *act;
    struct ls_bp_action action;
    __u32 flags;
    u64 vtime_start = 0;
    bool vtime_started = false;
    int reg_idx;
    int found_idx = -1; 

    if (unlikely(!g_req)) goto out;

    if (unlikely(!ls_target_matches(current)))
        goto out;

    if (READ_ONCE(g_vtime_with_breakpoints)) {
        vtime_start = ls_vtime_read_counter();
        vtime_started = true;
    }
    
    // 缁忓吀閫昏緫锛氱函闈犵洰鏍囧湴鍧€鍜屽綋鍓?PC 鍦板潃鍖归厤
    found_idx = ls_mux_find_owned_logical_current_cpu(addr, regs->pc);
    if (found_idx >= 0)
        my_slot = &g_slots[found_idx];

    if (likely(my_slot && found_idx != -1)) {
        if (!ls_copy_slot_action(found_idx, &action))
            goto out;
        act = &action;
        flags = READ_ONCE(act->action_flags);

        /* Synchronous GPR capture is the default main path. FAST_HIT remains
         * available only when sync_snapshot_always is explicitly disabled. */
        if (likely(READ_ONCE(g_sync_snapshot_always) ||
                   !(flags & LS_ACTION_FAST_HIT)))
            ls_publish_regs_snapshot(found_idx, regs);


        // 馃専 3. 鎻愬彇鎸囦护

        // 馃専 4. 鎵归噺鎵ц绡℃敼
        if (unlikely(act->reg_mask != 0)) {
            for (reg_idx = 0; reg_idx < 31; reg_idx++) {
                if (act->reg_mask & (1ULL << reg_idx)) {
                    regs->regs[reg_idx] = act->new_regs[reg_idx]; 
                }
            }
        }

        // 馃専 5. 鐘舵€佽鐩?
        if (flags & LS_ACTION_MOD_SP) regs->sp = act->new_sp;
        if (flags & LS_ACTION_MOD_PSTATE) {
            #define PSTATE_NZCV_MASK 0xF0000000ULL
            regs->pstate = (regs->pstate & ~PSTATE_NZCV_MASK) | (act->new_pstate & PSTATE_NZCV_MASK);
        }
        if (flags & LS_ACTION_MOD_PC) {
            if (likely(!(act->new_pc & 0x3))) regs->pc = act->new_pc;
        }

        // 馃専 6. 鎾ら€€绛栫暐
        if (flags & LS_ACTION_SKIP) {
            if (!(flags & LS_ACTION_MOD_PC)) {
                regs->pc += 4; 
            }
        } 
        else if (flags & LS_ACTION_STEP) {
            if (!(flags & LS_ACTION_MOD_PC)) {
                  
                if (!emulate_insn(regs)) {
                  
                    clear_slot_hw(my_slot);
                    regs->pstate |= (1UL << 21); 
                }
            }
        }
        else {
            clear_slot_hw(my_slot);
            smp_store_release(&my_slot->active, false);
            WRITE_ONCE(my_slot->hw_slot, -1);
        }

        if (vtime_started)
            ls_vtime_account_debug(vtime_start);
        return 0; 
    }
    
out:
    if (g_req && ls_target_matches(current)) {
        ls_mux_note_foreign_hit(addr, regs->pc);
        if (vtime_started)
            ls_vtime_account_debug(vtime_start);
    }
    // 缁忓吀鏀捐锛氱粺涓€浜ょ粰鍘熺敓鐨?bp_handler 澶勭悊
    if (likely(original_bp_handler)) return original_bp_handler(addr, esr, regs);
    return -1;
}
