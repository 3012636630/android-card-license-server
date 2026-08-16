#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include "quiet_log.h"
#include "Reading_and_Writing.h"
#include "tool.h"
// 1. 定义底层内部函数的指针类型
static int (*my_pmd_alloc_fn)(struct mm_struct *mm, pud_t *pud, unsigned long address) = NULL;
static int (*my_pte_alloc_fn)(struct mm_struct *mm, pmd_t *pmd) = NULL;
// ⚠️ 建议增加 out_kaddr 参数，方便你将来卸载驱动时用 free_pages 释放这块内存


// 👇 ================== 从这里开始插入 ================== 👇
// 3. 锻造我们自己的 ghost_pmd_alloc (完全替代内核原本的宏)
static inline pmd_t *ghost_pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address) {
    if (unlikely(pud_none(*pud))) {
        // 懒加载：第一次调用时去寻址
        if (!my_pmd_alloc_fn) 
            my_pmd_alloc_fn = (void *)resolve_unexported_symbol("__pmd_alloc");
            
        if (my_pmd_alloc_fn && my_pmd_alloc_fn(mm, pud, address))
            return NULL;
    }
    return pmd_offset(pud, address);
}

// 4. 锻造我们自己的 ghost_pte_alloc_map_lock
static inline pte_t *ghost_pte_alloc_map_lock(struct mm_struct *mm, pmd_t *pmd, unsigned long address, spinlock_t **ptlp) {
    if (unlikely(pmd_none(*pmd))) {
        // 懒加载：第一次调用时去寻址
        if (!my_pte_alloc_fn) 
            my_pte_alloc_fn = (void *)resolve_unexported_symbol("__pte_alloc");
            
        if (my_pte_alloc_fn && my_pte_alloc_fn(mm, pmd))
            return NULL;
    }
    // 这个函数是导出的，可以直接调
    return pte_offset_map_lock(mm, pmd, address, ptlp); 
}




pte_t forge_xom_pte_from_user(pid_t target_pid, unsigned long src_user_vaddr, 
                              size_t code_size, unsigned long *out_kaddr, 
                              bool copy_instructions) {  // 👈 新增参数
    unsigned long kaddr;
    phys_addr_t paddr;
    pteval_t pte_val_new = 0;
    int read_ret = 0;
    
    // 1. 计算需要多少个“阶 (Order)”的物理页
    unsigned int order = get_order(code_size);

    // ==========================================
    // 1. 向伙伴系统申请连续的物理页框群 (__GFP_ZERO 保证默认全 0)
    // ==========================================
    kaddr = __get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
    if (!kaddr) {
        LS_PRINTK(KERN_ERR "[lsdriver] ❌ 申请连续内核物理页失败！(Order: %u)\n", order);
        return __pte(0);
    }
    
    if (out_kaddr) {
        *out_kaddr = kaddr;
    }

    // ==========================================
    // 2. 🚀 按需提取指令
    // ==========================================
    if (copy_instructions) { // 👈 增加开关判断
        read_ret = read_phys(target_pid, src_user_vaddr, (void *)kaddr, code_size);

        if (read_ret != 0) {
            LS_PRINTK(KERN_ERR "[lsdriver] read_phys failed: %d, size: %zu\n", read_ret, code_size);
            free_pages(kaddr, order);
            return __pte(0);
        }
        LS_PRINTK(KERN_INFO "[lsdriver] instruction copy success, bytes: %zu\n", code_size);

        // ⚠️ 只有在写入了指令的情况下，才需要刷新 I-Cache
       // flush_icache_range(kaddr, kaddr + code_size);
        
    } 

    // 获取首个页的物理地址
    paddr = __pa(kaddr);

    // ==========================================
    // 4. 组装终极 PTE
    // ==========================================
    pte_val_new |= (paddr & GENMASK_ULL(47, 12));

    // 基础硬件属性
    pte_val_new |= PTE_VALID;
    pte_val_new |= PTE_TYPE_PAGE;
    pte_val_new |= PTE_ATTRINDX(MT_NORMAL);
    pte_val_new |= PTE_SHARED;
    pte_val_new |= PTE_AF;

    // 权限属性：用户态只读，严禁内核/用户态执行 (对抗扫描的绝佳属性)
    pte_val_new |= PTE_USER; 
    pte_val_new |= PTE_RDONLY;
    pte_val_new |= PTE_PXN;     
    pte_val_new |= PTE_UXN;
    
  
    return __pte(pte_val_new);
}


unsigned long find_hole_in_target_process(pid_t target_pid, size_t need_size) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    
    // 设定起始搜索地址 (从 4GB 以上开始找，避开 32 位低地址区的碎片)
    unsigned long addr = 0x100000000; 
    unsigned long len = PAGE_ALIGN(need_size);
    unsigned long target_addr = 0;

    // 1. 安全获取目标进程的 task_struct
    rcu_read_lock();
    task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) {
        LS_PR_ERR("[lsdriver] ❌ 找不到目标进程 PID: %d\n", target_pid);
        return 0;
    }

    // 2. 获取内存描述符 mm_struct
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        LS_PR_ERR("[lsdriver] ❌ 目标进程没有独立的虚拟内存空间\n");
        return 0;
    }

    // 3. ⚠️ 极其关键：必须加读锁！防止我们在遍历时，目标进程正在 mmap 改变内存结构
    mmap_read_lock(mm);

    // 4. 开始在目标空间中“见缝插针”
    while (true) {
        // find_vma 是内核神器：它会返回第一个 vm_end > addr 的 VMA 区域
        vma = find_vma(mm, addr);
        
        // 情况 A：后面没有任何 VMA 了，说明从 addr 到宇宙尽头都是空的
        if (!vma) {
            // 只要加上我们需要的大小不越界 (不超出 ARM64 的用户态最高地址)
            if (addr + len < TASK_SIZE) {
                target_addr = addr;
            }
            break;
        }

        // 情况 B：找到了 VMA，但我们要检查当前 addr 到这个 vma 的开头之间，有没有足够的缝隙
        if (addr + len <= vma->vm_start) {
            target_addr = addr;
            break; // 缝隙足够大，收工！
        }

        // 情况 C：缝隙不够，把雷达指针挪到当前这个 VMA 的末尾，继续往后扫描
        addr = PAGE_ALIGN(vma->vm_end);

        // 防御性编程：防止地址溢出用户态空间
        if (addr + len >= TASK_SIZE) {
            break;
        }
    }

    // 5. 释放读锁和 mm 引用
    mmap_read_unlock(mm);
    mmput(mm);

    if (target_addr) {
        LS_PR_INFO("[lsdriver] 🎯 成功在 PID %d 中找到完美空洞: 0x%lx (大小: %lu)\n", 
                target_pid, target_addr, len);
    } else {
        LS_PR_ERR("[lsdriver] ❌ 目标进程空间极度碎片化，找不到合适的空洞！\n");
    }

    return target_addr;
}



unsigned long inject_ghost_mapping(pid_t target_pid, unsigned long payload_src_addr, size_t payload_size,bool zero) {
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long target_vaddr;
    unsigned long kaddr_base = 0;
    pte_t base_pte;
    int num_pages;
    int i;

    // 1. 🎯 雷达扫描：在目标进程找一块风水宝地
    target_vaddr = find_hole_in_target_process(target_pid, payload_size);
    if (!target_vaddr) {
        LS_PRINTK(KERN_ERR "[lsdriver] ❌ 找不到合适的内存空洞，注入中止！\n");
        return 0;
    }

    // 2. 🔨 锻造核心：申请物理页并拷入指令，生成基址 PTE
    base_pte = forge_xom_pte_from_user(target_pid, payload_src_addr, payload_size, &kaddr_base,zero);
    if (pte_val(base_pte) == 0) {
        LS_PRINTK(KERN_ERR "[lsdriver] ❌ PTE 锻造失败，注入中止！\n");
        return 0;
    }

    // 计算总共需要覆盖多少个 4KB 页
    num_pages = PAGE_ALIGN(payload_size) / PAGE_SIZE;

    // 3. 🔒 获取目标进程的 mm_struct，准备暴力修改页表
    rcu_read_lock();
    task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) {
        // 极小概率：刚找到空洞，进程被杀了
        free_pages(kaddr_base, get_order(payload_size)); 
        return 0;
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        free_pages(kaddr_base, get_order(payload_size));
        return 0;
    }

    // ⚠️ 因为我们要分配页表层级，必须加写锁！
    mmap_write_lock(mm);

    // 4. 🔗 强制接管：逐页挂载硬件页表
    for (i = 0; i < num_pages; i++) {
        unsigned long current_vaddr = target_vaddr + (i * PAGE_SIZE);
        
        // 基于基址 PTE，计算当前页的 PTE 值 (物理地址每次偏移 1 个 PAGE_SIZE)
        pteval_t current_pte_val = pte_val(base_pte) + (i * PAGE_SIZE);
        pte_t final_pte = __pte(current_pte_val);

        // --- 核心动作：页表漫游与强制分配 ---
        // 因为我们找的是“空洞”，这里的各级页表目录很可能是不存在的，必须 alloc 出来
        pgd_t *pgd = pgd_offset(mm, current_vaddr);
        p4d_t *p4d = p4d_alloc(mm, pgd, current_vaddr);
       // ... (前面的 pgd 和 p4d 和 pud 保持不变) ...
        pud_t *pud = pud_alloc(mm, p4d, current_vaddr);

        // 💥 降维替换 1：使用我们自己的幽灵 PMD 分配器！
        pmd_t *pmd = ghost_pmd_alloc(mm, pud, current_vaddr);
        
        spinlock_t *ptl;
        // pte_alloc_map_lock 会确保最底层的页表存在，并锁定它防并发
      pte_t *ptep = ghost_pte_alloc_map_lock(mm, pmd, current_vaddr, &ptl);
        if (!ptep) {
            LS_PRINTK(KERN_ERR "[lsdriver] ❌ 为地址 0x%lx 分配页表项失败！\n", current_vaddr);
            continue; 
        }

        // 💥 降维打击：强行写入我们锻造的 PTE！
        // ARM64 标准 API: set_pte_at
        set_pte( ptep, final_pte);

        // 解锁当前 PTE
        pte_unmap_unlock(ptep, ptl);
    }

    mmap_write_unlock(mm);
    mmput(mm);

    // 5. 🧹 擦除痕迹：刷新 TLB (转换后备缓冲器)
    // 强制 CPU 遗忘这块地址之前的状态，立刻接受我们的新页表
    flush_tlb_all();

    LS_PRINTK(KERN_INFO "[lsdriver] 🌌 幽灵映射完成！Payload 已成功注入目标进程。\n");
    LS_PRINTK(KERN_INFO "[lsdriver] 📍 目标可执行基址: 0x%lx\n", target_vaddr);

    return target_vaddr;
}





bool inject_ghost_pte(struct mm_struct *mm, unsigned long va, pte_t new_pte) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;
    spinlock_t *ptl;

    if (!mm) return false;

    // 1. 标准页表漫游 (Page Table Walk)
    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        LS_PRINTK(KERN_ERR "[lsdriver] ❌ PGD 寻址失败: 0x%lx\n", va);
        return false;
    }

    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return false;

    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud)) {
        LS_PRINTK(KERN_ERR "[lsdriver] ❌ PUD 寻址失败: 0x%lx\n", va);
        return false;
    }

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        LS_PRINTK(KERN_ERR "[lsdriver] ❌ PMD 寻址失败: 0x%lx\n", va);
        return false;
    }

    // ==========================================
    // 🔒 2. 极其关键：获取 PTE 指针并上锁！
    // ==========================================
    // 我们必须锁住这张页表，防止内核的 Kswapd 守护进程或
    // 其他线程此时刚好在整理内存，导致我们写出脏数据引发 Panic。
    ptep = pte_offset_map_lock(mm, pmd, va, &ptl);
    if (!ptep) {
        LS_PRINTK(KERN_ERR "[lsdriver] ❌ 获取 PTE 锁失败!\n");
        return false;
    }

    // ==========================================
    // ⚔️ 3. 偷天换日：执行替换
    // ==========================================
    // set_pte_at 是 Linux 内核架构相关的安全写入宏
    set_pte(ptep, new_pte);

    // 4. 操作完成，安全解锁
    pte_unmap_unlock(ptep, ptl);

    // ==========================================
    // 💥 5. 终极硬件收尾：刷新 TLB
    // ==========================================
    // 如果不做这一步，CPU 内部的 TLB 缓存会认为这个地址依然是空的
    // 或者没有权限，导致目标进程一跳过来就触发段错误 (Segfault)！
    
    // 硬件屏障，确保 PTE 写入内存的动作已经彻底完成
    asm volatile("dsb ishst"); 
    

    
       
     ls_flush_tlb_mm(mm);
     
    
    return true;
}
