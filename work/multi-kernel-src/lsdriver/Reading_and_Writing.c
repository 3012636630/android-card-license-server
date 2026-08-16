#include <linux/errno.h>
#include <linux/bits.h>
#include <linux/err.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/preempt.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include <asm/barrier.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#include <asm/pgtable-prot.h>
#include <asm/tlbflush.h>

#include "Reading_and_Writing.h"
#include "tool.h"

typedef int (*ls_access_remote_vm_t)(struct mm_struct *mm,
                                     unsigned long addr,
                                     void *buf,
                                     int len,
                                     unsigned int gup_flags);
static DEFINE_MUTEX(g_access_remote_vm_lock);
static ls_access_remote_vm_t g_access_remote_vm;
static bool g_access_remote_vm_resolved;
static DEFINE_MUTEX(g_nc_slot_lock);
static void *g_nc_slot;
static pte_t *g_nc_slot_ptep;
static pte_t g_nc_slot_original;

#ifndef PTE_ATTRINDX_MASK
#define PTE_ATTRINDX_MASK PTE_ATTRINDX(7)
#endif

static ls_access_remote_vm_t ls_get_access_remote_vm(void)
{
    ls_access_remote_vm_t fn;

    if (smp_load_acquire(&g_access_remote_vm_resolved))
        return READ_ONCE(g_access_remote_vm);

    mutex_lock(&g_access_remote_vm_lock);
    if (!g_access_remote_vm_resolved) {
        unsigned long addr = resolve_unexported_symbol("access_remote_vm");

        if (addr)
            WRITE_ONCE(g_access_remote_vm, (ls_access_remote_vm_t)addr);
        smp_store_release(&g_access_remote_vm_resolved, true);
    }
    fn = READ_ONCE(g_access_remote_vm);
    mutex_unlock(&g_access_remote_vm_lock);
    return fn;
}

static pte_t *ls_nc_find_slot_pte(unsigned long addr)
{
    u64 ttbr1;
    phys_addr_t pgd_phys;
    pgd_t *pgd_base;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;

    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    pgd_phys = ttbr1 & GENMASK_ULL(47, PAGE_SHIFT);
    pgd_phys |= (ttbr1 & GENMASK_ULL(5, 2)) << 46;
    pgd_base = (pgd_t *)phys_to_virt(pgd_phys);

    pgd = pgd_base + pgd_index(addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_leaf(*pud) || pud_bad(*pud))
        return NULL;
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_leaf(*pmd) || pmd_bad(*pmd))
        return NULL;
    return pte_offset_kernel(pmd, addr);
}

static u64 ls_phys_to_ttbr(phys_addr_t phys)
{
    return (phys & GENMASK_ULL(47, 0)) |
           ((phys & GENMASK_ULL(51, 48)) >> 46);
}

static int ls_at_translate_page(struct mm_struct *mm, unsigned long va,
                                phys_addr_t *page_pa)
{
    u64 old_daif;
    u64 old_ttbr0;
    u64 par;
    u64 tlbi_arg;
    u64 ttbr0;

    if (!mm || !mm->pgd || !page_pa)
        return -EINVAL;

    va &= PAGE_MASK;
    tlbi_arg = (u64)va >> 12;
    ttbr0 = ls_phys_to_ttbr(virt_to_phys(mm->pgd));

    preempt_disable();
    asm volatile(
        "mrs %[daif], daif\n"
        "msr daifset, #0xf\n"
        "isb\n"
        "mrs %[old_ttbr], ttbr0_el1\n"
        "msr ttbr0_el1, %[new_ttbr]\n"
        "isb\n"
        "tlbi vaae1, %[tlbi]\n"
        "dsb nsh\n"
        "isb\n"
        "at s1e0r, %[addr]\n"
        "isb\n"
        "mrs %[par], par_el1\n"
        "tlbi vaae1, %[tlbi]\n"
        "dsb nsh\n"
        "isb\n"
        "msr ttbr0_el1, %[old_ttbr]\n"
        "isb\n"
        "msr daif, %[daif]\n"
        "isb\n"
        : [daif] "=&r"(old_daif), [old_ttbr] "=&r"(old_ttbr0),
          [par] "=&r"(par)
        : [new_ttbr] "r"(ttbr0), [tlbi] "r"(tlbi_arg),
          [addr] "r"((u64)va)
        : "cc", "memory");
    preempt_enable();

    if (par & 1)
        return -EFAULT;

    *page_pa = (phys_addr_t)(par & GENMASK_ULL(51, 12));
    return 0;
}

static void ls_nc_bbm_replace_locked(pte_t next)
{
    unsigned long addr = (unsigned long)g_nc_slot;

    dsb(ish);
    set_pte(g_nc_slot_ptep, __pte(0));
    flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
    set_pte(g_nc_slot_ptep, next);
    dsb(ishst);
    isb();
}

int ls_remote_read_init(void)
{
    void *slot;
    pte_t *ptep;
    pte_t original;
    int ret = 0;

    mutex_lock(&g_nc_slot_lock);
    if (g_nc_slot)
        goto out_unlock;

    slot = vmalloc(PAGE_SIZE);
    if (!slot) {
        ret = -ENOMEM;
        goto out_unlock;
    }
    memset(slot, 0, PAGE_SIZE);

    ptep = ls_nc_find_slot_pte((unsigned long)slot);
    if (!ptep) {
        ret = -EFAULT;
        goto out_free;
    }
    original = READ_ONCE(*ptep);
    if (!pte_valid(original) || pte_cont(original)) {
        ret = -EFAULT;
        goto out_free;
    }

    g_nc_slot = slot;
    g_nc_slot_ptep = ptep;
    g_nc_slot_original = original;
    goto out_unlock;

out_free:
    vfree(slot);
out_unlock:
    mutex_unlock(&g_nc_slot_lock);
    return ret;
}

void ls_remote_read_exit(void)
{
    mutex_lock(&g_nc_slot_lock);
    if (g_nc_slot) {
        if (pte_val(READ_ONCE(*g_nc_slot_ptep)) !=
            pte_val(g_nc_slot_original))
            ls_nc_bbm_replace_locked(g_nc_slot_original);
        vfree(g_nc_slot);
        g_nc_slot = NULL;
        g_nc_slot_ptep = NULL;
        g_nc_slot_original = __pte(0);
    }
    mutex_unlock(&g_nc_slot_lock);
}

static int ls_nc_copy_from_pfn(void *dst, unsigned long pfn,
                               size_t offset, size_t size)
{
    pteval_t protval;
    pte_t target;
    int ret = 0;

    if (!dst || offset >= PAGE_SIZE || size > PAGE_SIZE - offset)
        return -EINVAL;

    if (!pfn_valid(pfn))
        return -EOPNOTSUPP;

    protval = pgprot_val(PAGE_KERNEL);
    protval &= ~PTE_ATTRINDX_MASK;
    protval |= PTE_ATTRINDX(MT_NORMAL_NC);
    target = pfn_pte(pfn, __pgprot(protval));

    mutex_lock(&g_nc_slot_lock);
    if (!g_nc_slot || !g_nc_slot_ptep) {
        ret = -ENODEV;
        goto out_unlock;
    }

    ls_nc_bbm_replace_locked(target);
    memcpy(dst, (u8 *)g_nc_slot + offset, size);
    ls_nc_bbm_replace_locked(g_nc_slot_original);

out_unlock:
    mutex_unlock(&g_nc_slot_lock);
    return ret;
}

static int ls_read_remote_nc(pid_t target_pid, unsigned long va,
                             void *buffer, size_t size)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    size_t done = 0;
    int ret = 0;

    pid_struct = find_get_pid(target_pid);
    if (!pid_struct)
        return -ESRCH;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return -EINVAL;

    mmap_read_lock(mm);
    while (done < size) {
        unsigned long current_va = va + done;
        size_t page_offset = offset_in_page(current_va);
        size_t chunk = min_t(size_t, size - done, PAGE_SIZE - page_offset);
        struct vm_area_struct *vma;
        phys_addr_t translated_pa;
        unsigned long pfn;

        vma = find_vma(mm, current_va);
        if (!vma || current_va < vma->vm_start ||
            chunk > vma->vm_end - current_va) {
            ret = -EFAULT;
            break;
        }

        ret = ls_at_translate_page(mm, current_va, &translated_pa);
        if (!ret) {
            pfn = __phys_to_pfn(translated_pa);
            if (!pfn_valid(pfn))
                ret = -EFAULT;
        }
        if (!ret) {
            ret = ls_nc_copy_from_pfn((u8 *)buffer + done,
                                      pfn, page_offset, chunk);
        }
        if (ret)
            break;
        done += chunk;
    }
    mmap_read_unlock(mm);
    mmput(mm);

    if (ret)
        return ret;
    return done == size ? 0 : -EFAULT;
}

long phys_rw_memory(pid_t target_pid, unsigned long va, void *buffer,
                    size_t size, int is_write)
{
    ls_access_remote_vm_t access_remote_vm_fn;
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    int copied;

    if (target_pid <= 0 || !buffer || !size)
        return -EINVAL;
    if (size > INT_MAX)
        return -E2BIG;
    va = untagged_addr(va);
    if (!va)
        return -EINVAL;
    if (va > ULONG_MAX - (size - 1))
        return -EOVERFLOW;

    if (!is_write)
        return ls_read_remote_nc(target_pid, va, buffer, size);

    access_remote_vm_fn = ls_get_access_remote_vm();
    if (!access_remote_vm_fn)
        return -EOPNOTSUPP;

    pid_struct = find_get_pid(target_pid);
    if (!pid_struct)
        return -ESRCH;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return -EINVAL;

    copied = access_remote_vm_fn(mm, va, buffer, (int)size,
                                 FOLL_FORCE | FOLL_WRITE);
    mmput(mm);

    if (copied < 0)
        return copied;
    if (copied != (int)size)
        return -EFAULT;
    return 0;
}

int read_phys(pid_t pid, u64 addr, void *buf, size_t size)
{
    return (int)phys_rw_memory(pid, (unsigned long)addr, buf, size, 0);
}

int write_phys(pid_t pid, u64 addr, void *buf, size_t size)
{
    return (int)phys_rw_memory(pid, (unsigned long)addr, buf, size, 1);
}
