#include <linux/bits.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include "quiet_log.h"
#include "Reading_and_Writing.h"
#include "stale_itlb.h"
#include "target_guard.h"
#include "tool.h"

#define LS_STALE_PTE_PA_MASK GENMASK_ULL(47, 12)

#ifndef pmd_leaf
#define pmd_leaf(x) pmd_trans_huge(x)
#endif

struct ls_stale_itlb_slot_state {
    struct mutex lock;
    pid_t pid;
    unsigned long target_va;
    unsigned int page_count;
    unsigned int orig_count;
    unsigned int flags;
    unsigned long shadow_kaddr;
    unsigned int shadow_order;
    size_t shadow_size;
    pte_t orig_pte[LS_STALE_ITLB_MAX_PAGES];
    bool active;
    bool orig_valid;
    __u32 state;
    __s32 last_error;
    __u64 generation;
    __u64 active_cpus;
    __u64 reprime_count;
    __u64 restore_count;
};

static struct ls_stale_itlb_slot_state g_stale_slots[LS_STALE_ITLB_MAX_SLOTS];
static bool g_stale_itlb_enabled = true;
static bool g_stale_itlb_restore_tlbi;
static unsigned long g_stale_itlb_page_limit = LS_STALE_ITLB_MAX_PAGES;

module_param_named(stale_itlb_enabled, g_stale_itlb_enabled, bool, 0600);
module_param_named(stale_itlb_restore_tlbi, g_stale_itlb_restore_tlbi, bool, 0600);
module_param_named(stale_itlb_page_limit, g_stale_itlb_page_limit, ulong, 0600);

static inline void ls_stale_barrier(void)
{
    asm volatile("dsb ishst\n\tisb" ::: "memory");
}

static inline __u64 ls_stale_cpu_bit(void)
{
    unsigned int cpu = raw_smp_processor_id();

    if (cpu >= 64)
        return 0;
    return BIT_ULL(cpu);
}

static pid_t ls_stale_effective_pid(pid_t pid)
{
    if (pid > 0)
        return pid;
    return READ_ONCE(target_pid);
}

static int ls_stale_get_mm(pid_t pid, struct mm_struct **out_mm)
{
    struct pid *p;
    struct task_struct *task;
    struct mm_struct *mm;

    pid = ls_stale_effective_pid(pid);
    if (pid <= 0)
        return -ESRCH;

    p = find_get_pid(pid);
    if (!p)
        return -ESRCH;

    task = get_pid_task(p, PIDTYPE_PID);
    put_pid(p);
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return -ESRCH;

    *out_mm = mm;
    return 0;
}

static int ls_stale_pte_offset_locked(struct mm_struct *mm,
                                      unsigned long va,
                                      pte_t **out_ptep,
                                      spinlock_t **out_ptl)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;
    spinlock_t *ptl;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return -EFAULT;

    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return -EFAULT;

    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud))
        return -EFAULT;

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd))
        return -EFAULT;
    if (pmd_trans_huge(*pmd) || pmd_leaf(*pmd))
        return -EOPNOTSUPP;
    if (pmd_bad(*pmd))
        return -EFAULT;

    ptep = pte_offset_map_lock(mm, pmd, va, &ptl);
    if (!ptep)
        return -EFAULT;
    if (pte_none(*ptep) || !pte_present(*ptep)) {
        pte_unmap_unlock(ptep, ptl);
        return -EFAULT;
    }

    *out_ptep = ptep;
    *out_ptl = ptl;
    return 0;
}

static pte_t ls_stale_make_shadow_pte(pte_t orig, phys_addr_t pa)
{
    pteval_t val = pte_val(orig);

    val &= ~((pteval_t)LS_STALE_PTE_PA_MASK);
    val |= ((pteval_t)pa & (pteval_t)LS_STALE_PTE_PA_MASK);
    val |= PTE_VALID | PTE_TYPE_PAGE | PTE_AF | PTE_USER | PTE_RDONLY;
#ifdef PTE_PXN
    val |= PTE_PXN;
#endif
#ifdef PTE_UXN
    val &= ~PTE_UXN;
#endif
    return __pte(val);
}

static void ls_stale_fill_status_locked(struct ls_stale_itlb_req *req,
                                        const struct ls_stale_itlb_slot_state *slot)
{
    req->pid = slot->pid;
    req->flags = slot->flags;
    req->page_count = slot->page_count;
    req->state = slot->state;
    req->last_error = slot->last_error;
    req->target_va = slot->target_va;
    req->shadow_user = 0;
    req->shadow_size = slot->shadow_size;
    req->generation = slot->generation;
    req->active_cpus = slot->active_cpus;
    req->reprime_count = slot->reprime_count;
    req->restore_count = slot->restore_count;
}

static void ls_stale_free_shadow_locked(struct ls_stale_itlb_slot_state *slot)
{
    if (slot->shadow_kaddr)
        free_pages(slot->shadow_kaddr, slot->shadow_order);

    slot->pid = 0;
    slot->target_va = 0;
    slot->page_count = 0;
    slot->orig_count = 0;
    slot->flags = 0;
    slot->shadow_kaddr = 0;
    slot->shadow_order = 0;
    slot->shadow_size = 0;
    slot->active = false;
    slot->orig_valid = false;
    slot->state = LS_STALE_ITLB_STATE_EMPTY;
}

static void ls_stale_flush_shadow_icache(unsigned long kaddr, size_t size)
{
    if (!kaddr || !size)
        return;
    flush_icache_range(kaddr, kaddr + size);
    ls_stale_barrier();
}

static int ls_stale_force_tlbi_locked(struct ls_stale_itlb_slot_state *slot)
{
    struct mm_struct *mm;
    int ret;

    if (!slot->active || slot->pid <= 0)
        return 0;

    ret = ls_stale_get_mm(slot->pid, &mm);
    if (ret == -ESRCH)
        return 0;
    if (ret) {
        slot->last_error = ret;
        return ret;
    }

    ls_stale_barrier();
    ls_flush_tlb_mm(mm);
    ls_stale_barrier();
    mmput(mm);
    return 0;
}

static int ls_stale_restore_locked(struct ls_stale_itlb_slot_state *slot,
                                   bool force_tlbi)
{
    struct mm_struct *mm;
    unsigned int i;
    int ret;
    int first_error = 0;

    if (!slot->orig_valid)
        return force_tlbi ? ls_stale_force_tlbi_locked(slot) : 0;
    if (!slot->orig_count) {
        slot->orig_valid = false;
        if (force_tlbi)
            return ls_stale_force_tlbi_locked(slot);
        return 0;
    }

    ret = ls_stale_get_mm(slot->pid, &mm);
    if (ret) {
        slot->last_error = ret;
        slot->state = LS_STALE_ITLB_STATE_ERROR;
        return ret;
    }

    mmap_write_lock(mm);
    for (i = 0; i < slot->orig_count; i++) {
        pte_t *ptep;
        spinlock_t *ptl;
        unsigned long va = slot->target_va + (i * PAGE_SIZE);

        ret = ls_stale_pte_offset_locked(mm, va, &ptep, &ptl);
        if (ret) {
            if (!first_error)
                first_error = ret;
            continue;
        }
        set_pte(ptep, slot->orig_pte[i]);
        pte_unmap_unlock(ptep, ptl);
    }
    mmap_write_unlock(mm);

    ls_stale_barrier();
    if (force_tlbi || READ_ONCE(g_stale_itlb_restore_tlbi) ||
        (slot->flags & LS_STALE_ITLB_F_RESTORE_TLBI))
        ls_flush_tlb_mm(mm);
    ls_stale_barrier();
    mmput(mm);

    slot->orig_valid = false;
    slot->orig_count = 0;
    slot->restore_count++;
    slot->generation++;
    slot->last_error = first_error;
    slot->state = first_error ? LS_STALE_ITLB_STATE_ERROR : LS_STALE_ITLB_STATE_RESTORED;
    return first_error;
}

static int ls_stale_set_shadow_locked(struct ls_stale_itlb_slot_state *slot)
{
    struct mm_struct *mm;
    unsigned int i;
    int ret;

    if (!READ_ONCE(g_stale_itlb_enabled))
        return -EOPNOTSUPP;
    if (!slot->active || !slot->shadow_kaddr || !slot->page_count)
        return -EINVAL;

    if (slot->orig_valid)
        ls_stale_restore_locked(slot, true);

    ret = ls_stale_get_mm(slot->pid, &mm);
    if (ret)
        goto out_error;

    slot->orig_valid = true;
    slot->orig_count = 0;

    mmap_write_lock(mm);
    for (i = 0; i < slot->page_count; i++) {
        unsigned long va = slot->target_va + (i * PAGE_SIZE);
        unsigned long kpage = slot->shadow_kaddr + (i * PAGE_SIZE);
        phys_addr_t pa = __pa(kpage);
        pte_t *ptep;
        pte_t orig;
        pte_t shadow;
        spinlock_t *ptl;

        ret = ls_stale_pte_offset_locked(mm, va, &ptep, &ptl);
        if (ret)
            break;

        orig = READ_ONCE(*ptep);
        shadow = ls_stale_make_shadow_pte(orig, pa);
        slot->orig_pte[i] = orig;
        slot->orig_count = i + 1;
        /* Shadow contents were I-cache synchronized before this mapping. */
        set_pte(ptep, shadow);
        pte_unmap_unlock(ptep, ptl);
    }
    mmap_write_unlock(mm);

    ls_stale_barrier();
    ls_flush_tlb_mm(mm);
    ls_stale_barrier();
    mmput(mm);

    if (ret) {
        ls_stale_restore_locked(slot, true);
        goto out_error;
    }

    slot->state = LS_STALE_ITLB_STATE_ARMED;
    slot->last_error = 0;
    slot->generation++;
    slot->reprime_count++;
    slot->active_cpus |= ls_stale_cpu_bit();
    return 0;

out_error:
    slot->last_error = ret;
    slot->state = LS_STALE_ITLB_STATE_ERROR;
    return ret;
}

static int ls_stale_validate_request(const struct ls_stale_itlb_req *req,
                                     unsigned int *pages,
                                     size_t *total_size)
{
    unsigned long limit = READ_ONCE(g_stale_itlb_page_limit);
    unsigned int page_count = req->page_count;
    size_t total;

    if (req->slot >= LS_STALE_ITLB_MAX_SLOTS)
        return -EINVAL;
    if (!req->target_va)
        return -EINVAL;
    if (!page_count && req->shadow_size)
        page_count = (unsigned int)DIV_ROUND_UP(req->shadow_size, PAGE_SIZE);
    if (!page_count)
        return -EINVAL;
    if (limit == 0 || limit > LS_STALE_ITLB_MAX_PAGES)
        limit = LS_STALE_ITLB_MAX_PAGES;
    if (page_count > limit)
        return -EINVAL;

    total = (size_t)page_count * PAGE_SIZE;
    if (req->shadow_size > total)
        return -EINVAL;
    if (req->shadow_size && !req->shadow_user)
        return -EINVAL;

    *pages = page_count;
    *total_size = total;
    return 0;
}

void ls_stale_itlb_runtime_init(void)
{
    unsigned int i;

    for (i = 0; i < LS_STALE_ITLB_MAX_SLOTS; i++) {
        mutex_init(&g_stale_slots[i].lock);
        g_stale_slots[i].state = LS_STALE_ITLB_STATE_EMPTY;
    }
}

long ls_stale_itlb_load_user(void __user *arg)
{
    struct ls_stale_itlb_req req;
    struct ls_stale_itlb_slot_state *slot;
    unsigned long kaddr;
    unsigned int page_count;
    unsigned int order;
    size_t total;
    pid_t pid;
    int ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    ret = ls_stale_validate_request(&req, &page_count, &total);
    if (ret)
        return ret;

    pid = ls_stale_effective_pid(req.pid);
    if (pid <= 0)
        return -ESRCH;

    order = get_order(total);
    kaddr = __get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
    if (!kaddr)
        return -ENOMEM;

    if (req.flags & LS_STALE_ITLB_F_COPY_ORIG_TAIL) {
        ret = read_phys(pid, req.target_va & PAGE_MASK, (void *)kaddr, total);
        if (ret) {
            free_pages(kaddr, order);
            return ret;
        }
    }

    if (req.shadow_size && copy_from_user((void *)kaddr,
                                          (void __user *)(unsigned long)req.shadow_user,
                                          req.shadow_size)) {
        free_pages(kaddr, order);
        return -EFAULT;
    }

    ls_stale_flush_shadow_icache(kaddr, total);

    slot = &g_stale_slots[req.slot];
    mutex_lock(&slot->lock);
    if (slot->active) {
        ls_stale_restore_locked(slot, true);
        ls_stale_free_shadow_locked(slot);
    }

    slot->pid = pid;
    slot->target_va = req.target_va & PAGE_MASK;
    slot->page_count = page_count;
    slot->orig_count = 0;
    slot->flags = req.flags;
    slot->shadow_kaddr = kaddr;
    slot->shadow_order = order;
    slot->shadow_size = req.shadow_size;
    slot->active = true;
    slot->orig_valid = false;
    slot->state = LS_STALE_ITLB_STATE_LOADED;
    slot->last_error = 0;
    slot->generation++;
    ls_stale_fill_status_locked(&req, slot);
    mutex_unlock(&slot->lock);

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;
    return 0;
}

long ls_stale_itlb_arm_user(void __user *arg)
{
    struct ls_stale_itlb_req req;
    struct ls_stale_itlb_slot_state *slot;
    int ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.slot >= LS_STALE_ITLB_MAX_SLOTS)
        return -EINVAL;

    slot = &g_stale_slots[req.slot];
    mutex_lock(&slot->lock);
    ret = ls_stale_set_shadow_locked(slot);
    ls_stale_fill_status_locked(&req, slot);
    mutex_unlock(&slot->lock);

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;
    return ret;
}

long ls_stale_itlb_restore_user(void __user *arg)
{
    struct ls_stale_itlb_req req;
    struct ls_stale_itlb_slot_state *slot;
    bool force_tlbi;
    int ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.slot >= LS_STALE_ITLB_MAX_SLOTS)
        return -EINVAL;

    force_tlbi = (req.flags & LS_STALE_ITLB_F_RESTORE_TLBI) != 0;
    slot = &g_stale_slots[req.slot];
    mutex_lock(&slot->lock);
    ret = ls_stale_restore_locked(slot, force_tlbi);
    ls_stale_fill_status_locked(&req, slot);
    mutex_unlock(&slot->lock);

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;
    return ret;
}

long ls_stale_itlb_status_user(void __user *arg)
{
    struct ls_stale_itlb_req req;
    struct ls_stale_itlb_slot_state *slot;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.slot >= LS_STALE_ITLB_MAX_SLOTS)
        return -EINVAL;

    slot = &g_stale_slots[req.slot];
    mutex_lock(&slot->lock);
    ls_stale_fill_status_locked(&req, slot);
    mutex_unlock(&slot->lock);

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;
    return 0;
}

long ls_stale_itlb_disable_user(void __user *arg)
{
    struct ls_stale_itlb_req req;
    struct ls_stale_itlb_slot_state *slot;
    int ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.slot >= LS_STALE_ITLB_MAX_SLOTS)
        return -EINVAL;

    slot = &g_stale_slots[req.slot];
    mutex_lock(&slot->lock);
    ret = ls_stale_restore_locked(slot, true);
    ls_stale_free_shadow_locked(slot);
    slot->generation++;
    ls_stale_fill_status_locked(&req, slot);
    mutex_unlock(&slot->lock);

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;
    return ret;
}

void ls_stale_itlb_clear_all(void)
{
    unsigned int i;

    for (i = 0; i < LS_STALE_ITLB_MAX_SLOTS; i++) {
        struct ls_stale_itlb_slot_state *slot = &g_stale_slots[i];

        mutex_lock(&slot->lock);
        ls_stale_restore_locked(slot, true);
        ls_stale_free_shadow_locked(slot);
        slot->generation++;
        mutex_unlock(&slot->lock);
    }
}
