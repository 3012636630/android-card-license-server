
#include "quiet_log.h"
#include "page_.h"
#include "map.h"
#include "tool.h"
#include <linux/mm.h>
#include <linux/mman.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

// 1. 定义函数指针类型 (解决 lookup_address_t 报错)
typedef pte_t *(*lookup_address_t)(unsigned long address, unsigned int *level);

// 2. 声明外部函数 (告诉编译器去 hook.c 找这个函数)
extern void *get_symbol_addr(const char *symbol_name);
// 定义常量，方便外层判断
#define MAP_SIZE_4K  0x1000      // 4KB
#define MAP_SIZE_2M  0x200000    // 2MB


/**
 * 方式一：通过 PID 暴力遍历获取 mm_struct (最稳妥的方案)
 */




/**
 * 核心函数：模拟 MMU 翻译页表 (ARM64 4级页表体系)
 * @param mm: 目标进程的内存描述符
 * @param va: 你在 CE 里搜到的那个目标虚拟地址 (Virtual Address)
 * @return: 真实的物理地址 (Physical Address)，翻译失败返回 0
 */
 phys_addr_t translate_va_to_pa_ext(struct mm_struct *mm, unsigned long va, unsigned long *out_map_size) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    phys_addr_t pa = 0;

    // 默认给一个安全值，防止出错时未初始化
    if (out_map_size) {
        *out_map_size = 0; 
    }
pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        
        return 0;
    }

    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
       
        return 0;
    }

    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud)) {
       
        return 0;
    }

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd)) {
        // 注意：PMD 有时可能是一个 Huge Page (大页)，所以通常只判断 none。
        // 如果你的架构支持 THP (透明大页)，这里判断 bad 可能会误杀大页。
       
        return 0;
    }

    // 🚨 检查是否为 2MB 大页
    if (pmd_trans_huge(*pmd) || pmd_leaf(*pmd)) {
        pa = (pmd_pfn(*pmd) << PAGE_SHIFT) | (va & ~PMD_MASK);
        
        // 💡 关键修改：告诉外层这是一个 2MB 的大页！
        if (out_map_size) {
            *out_map_size = MAP_SIZE_2M; 
        }
        return pa;
    }

    if (pmd_bad(*pmd)) return 0;

    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte) || !pte_present(*pte)) return 0;

  
   pa = (pte_pfn(*pte) << PAGE_SHIFT) | (va & ~PAGE_MASK);
    if (out_map_size) {
        *out_map_size = MAP_SIZE_4K; 
    }
 
    return pa;
}


// ==============================================================
// 🎯 武器 1：任意地址 PTE 提取器 (双端通杀 + 大页切片适配)
// ==============================================================
pte_t pte_(struct mm_struct *mm, unsigned long va) {
    pgd_t *pgd_base, *pgd;
    p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
    pte_t empty_pte = {0}; 

    // 1. 双端 PGD 获取
    if (mm == NULL) {
        u64 ttbr1;
        asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
        pgd_base = (pgd_t *)phys_to_virt(ttbr1 & PAGE_MASK);
    } else {
        pgd_base = mm->pgd;
    }

    // 2. 标准多级页表游走
    pgd = pgd_base + pgd_index(va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return empty_pte;

    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return empty_pte;

    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud)) return empty_pte;

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd)) return empty_pte;

    // ==========================================
    // 🚀 核心适配：2MB 大页 (Huge Page) 降维切片
    // ==========================================
    if (pmd_trans_huge(*pmd) || pmd_leaf(*pmd)) {
        unsigned long pmd_raw = pmd_val(*pmd);
        phys_addr_t exact_pa;
        pte_t forged_pte;
        
        // 1. 算出目标 VA 在这 2MB 大块中的【精准 4KB 物理基址】
        // 公式：PMD大页基址 + (VA 在大页内的偏移量)
        exact_pa = (pmd_pfn(*pmd) << PAGE_SHIFT) | (va & ~PMD_MASK);
        exact_pa &= PAGE_MASK; // 严格对齐到 4KB 边界
        
        // 2. 剥离旧的物理地址，以及 Level 2 块标志
        pmd_raw &= ~PMD_MASK;       // 清除 2MB 的物理基址
        pmd_raw &= ~PTE_TYPE_MASK;  // 擦除最低的两比特类型标志位 (01)
        
        // 3. 缝合新的精准物理地址，并打上 Level 3 页标志 (11)
        pmd_raw |= exact_pa;
        pmd_raw |= PTE_TYPE_PAGE;   // PTE_TYPE_PAGE 的宏展开就是 3 (即二进制 11)
        
        pte_val(forged_pte) = pmd_raw; // 包装成正规的 pte_t
        
        // LS_PRINTK(KERN_INFO "[lsdriver] 🔪 大页降维打击成功！切出 4KB PTE\n");
        return forged_pte;
    }

    // ==========================================
    // 普通 4KB 页表处理
    // ==========================================
    if (pmd_bad(*pmd)) return empty_pte;

    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte) || !pte_present(*pte)) return empty_pte;

    return *pte; 
}




/*
 * @param mm: 目标进程 (游戏传进程 mm，内核传 &init_mm)
 * @param va: 目标虚拟地址
 * @param prot: 严格权限掩码 (PROT_READ, PROT_WRITE, PROT_EXEC, PROT_NONE)
 */
void modify_mem_prot_ext(struct mm_struct *mm, unsigned long va, int prot) {
    pgd_t *pgd_base;
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *ptep;
    unsigned long flush_size = MAP_SIZE_4K;
    unsigned long execute_never_mask;

    // ==========================================
    // 1. 获取顶级页表，并确定防执行掩码
    // ==========================================
    if (mm == NULL) {
        // 修改内核空间：读取 TTBR1_EL1 寄存器获取内核物理 PGD 基址
        u64 ttbr1;
        asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
        pgd_base = (pgd_t *)phys_to_virt(ttbr1 & PAGE_MASK);
        execute_never_mask = PTE_PXN; // 内核态防执行
    } else {
        // 修改用户空间：直接用进程的 PGD
        pgd_base = mm->pgd;
        execute_never_mask = PTE_UXN; // 用户态防执行
    }

    // ==========================================
    // 2. 标准页表遍历 (使用自定义基址)
    // ==========================================
    pgd = pgd_base + pgd_index(va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
    {
       
      return;
    }
     

    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) 
    {
     
      return;
    }
    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud))
      {
     
      return;
    }

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd)) {
     
      return;
    }
    // ==========================================
    // 3. 大页 (2MB) 处理分支
    // ==========================================
    if (pmd_trans_huge(*pmd) || pmd_leaf(*pmd)) {
        flush_size = MAP_SIZE_2M;
        pmd_t new_pmd = READ_ONCE(*pmd);
        
        // --- 🚀 核心权限覆盖引擎 (PMD 级) ---
        // 独立控制【写】(W)
        if (prot & PROT_WRITE) pmd_val(new_pmd) &= ~PTE_RDONLY; else pmd_val(new_pmd) |= PTE_RDONLY;
        // 独立控制【执行】(X)
        if (prot & PROT_EXEC)  pmd_val(new_pmd) &= ~execute_never_mask; else pmd_val(new_pmd) |= execute_never_mask;
        // 独立控制【读】(R) 与用户态访问权
        if (mm != NULL) {
            if (prot & (PROT_READ | PROT_WRITE)) {
                pmd_val(new_pmd) |= PTE_USER;
            } else {
                if (prot == PROT_EXEC) {
                    LS_PRINTK(KERN_INFO "[lsdriver] 👻 触发 2MB 只执行(XOM)隐身黑洞! VA: %lx\n", va);
                }
                pmd_val(new_pmd) &= ~PTE_USER;
            }
        }
        
        set_pmd(pmd, new_pmd);
    }
    // ==========================================
    // 4. 普通页 (4KB) 处理分支
    // ==========================================
    else {
        if (pmd_bad(*pmd)) return;
        ptep = pte_offset_kernel(pmd, va);
        if (pte_none(*ptep) || !pte_present(*ptep)) return;

        pte_t new_pte = READ_ONCE(*ptep);
        
        // --- 🚀 核心权限覆盖引擎 (PTE 级) ---
        // 独立控制【写】(W)
        if (prot & PROT_WRITE) pte_val(new_pte) &= ~PTE_RDONLY; else pte_val(new_pte) |= PTE_RDONLY;
        // 独立控制【执行】(X)
        if (prot & PROT_EXEC)  pte_val(new_pte) &= ~execute_never_mask; else pte_val(new_pte) |= execute_never_mask;
        // 独立控制【读】(R) 与用户态访问权
        if (mm != NULL) {
            if (prot & (PROT_READ | PROT_WRITE)) {
                pte_val(new_pte) |= PTE_USER;
            } else {
                if (prot == PROT_EXEC) {
                    LS_PRINTK(KERN_INFO "[lsdriver] 👻 触发 4KB 只执行(XOM)隐身黑洞! VA: %lx\n", va);
                }
                pte_val(new_pte) &= ~PTE_USER;
            }
        }
        
        set_pte(ptep, new_pte);
    }

    // ==========================================
    // 5. 硬件屏障与缓存刷新
    // ==========================================
    asm volatile("dsb ishst"); // 确保前面的页表写入指令真正落到内存中

    if (mm == NULL) {
        flush_tlb_kernel_range(va, va + flush_size);
    } else {
        ls_flush_tlb_mm(mm);
    }
    
    // 如果赋予了执行权限（或者为了安全起见，只要修改了权限），必须刷 I-Cache
    flush_icache_range(va, va + flush_size);
}
