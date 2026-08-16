#ifndef _LS_PAGE_H_    // 这里的名字要和 page_.h 挂钩
#define _LS_PAGE_H_
#include <asm/cacheflush.h>     // 解决 flush_icache_range 报错
#include <linux/types.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <asm/pgtable.h>
#include <linux/hugetlb.h>

// 联合体允许你同时以“完整的64位整数”和“独立的比特位”两种方式访问同一块内存
typedef union {
    uint64_t pte_val;           // 直接读取或写入完整的 8 字节原始值
    
    struct {
        uint64_t valid      : 1;  // [0] 有效位 (1=Valid, 0=Fault)
        uint64_t is_page    : 1;  // [1] 类型标志 (L3 中 1 代表页，0 代表块)
        uint64_t attr_indx  : 3;  // [4:2] 内存属性索引 (MAIR)
        uint64_t ns         : 1;  // [5] 安全标志 (Non-secure)
        uint64_t ap         : 2;  // [7:6] 访问权限 (AP[2:1]：读写与用户态权限)
        uint64_t sh         : 2;  // [9:8] 共享属性 (Shareability)
        uint64_t af         : 1;  // [10] 访问标志 (Access Flag)
        uint64_t ng         : 1;  // [11] 非全局标志 (Not Global)
        uint64_t pfn        : 36; // [47:12] 物理页框号 (Physical Frame Number)
        uint64_t res0       : 4;  // [51:48] 硬件保留位 (必须为0)
        uint64_t contig     : 1;  // [52] 连续页标志 (Contiguous)
        uint64_t pxn        : 1;  // [53] 内核态禁执行 (Privileged Execute Never)
        uint64_t uxn        : 1;  // [54] 用户态禁执行 (Unprivileged Execute Never)
        uint64_t sw_use     : 9;  // [63:55] 软件保留位 (供 Linux 内核自己玩)
    } bits;
} arm64_l3_pte_t;


// 适用于 ARM64 的 L0 (PGD), L1 (PUD), L2 (PMD) 表项
typedef union {
    uint64_t desc_val;           // 完整的 8 字节原始值
    
    struct {
        uint64_t valid          : 1;  // [0] 有效位 (必须为1)
        uint64_t is_table       : 1;  // [1] 类型位 (必须为1，代表指向下一级表)
        uint64_t ignored        : 10; // [11:2] 硬件忽略，内核随便用
        uint64_t next_table_pfn : 36; // [47:12] 🌟核心：下一级页表的物理页框号🌟
        uint64_t res0           : 11; // [58:48] 硬件保留位 (通常为0)
        
        // --- 下面这几个是“一票否决”权限控制位 (Table limits) ---
        uint64_t pxntable       : 1;  // [59] 如果为1，下一级所有子页表全部禁止内核执行
        uint64_t xntable        : 1;  // [60] 如果为1，下一级所有子页表全部禁止用户态执行 (UXN)
        uint64_t aptable        : 2;  // [62:61] 强行限制下一级所有子页表的 AP 读写权限
        uint64_t nstable        : 1;  // [63] 限制下一级全部为非安全内存 (Non-secure)
    } bits;
} arm64_table_desc_t;




typedef union {
    uint64_t pmd_val;           
    
    struct {
        uint64_t valid      : 1;  // [0] 有效位
        uint64_t is_table   : 1;  // [1] = 0 (代表这是块描述符 Block)
        uint64_t attr_indx  : 3;  // [4:2] 内存属性
        uint64_t ns         : 1;  // [5] 
        uint64_t ap         : 2;  // [7:6] 🌟 关键：读写权限 (AP) 🌟
        uint64_t sh         : 2;  // [9:8]
        uint64_t af         : 1;  // [10]
        uint64_t ng         : 1;  // [11]
        uint64_t res0       : 9;  // [20:12] 保留位
        uint64_t pfn        : 27; // [47:21] 🌟 2MB 物理大页的基地址 🌟
        uint64_t res1       : 4;  // [51:48]
        uint64_t contig     : 1;  // [52]
        uint64_t pxn        : 1;  // [53] 🌟 内核禁执行 🌟
        uint64_t uxn        : 1;  // [54] 🌟 用户禁执行 🌟
        uint64_t sw_use     : 9;  // [63:55]
    } block;
} arm64_pmd_block_t;

void modify_mem_prot(void *addr, int prot);
pid_t get_pid_by_full_name_kernel(const char *full_name);
struct mm_struct* get_mm_by_pid_robust(pid_t target_pid) ;
void modify_mem_prot_ext(struct mm_struct *mm, unsigned long va, int prot);
phys_addr_t translate_va_to_pa_ext(struct mm_struct *mm, unsigned long va, unsigned long *out_map_size);
pte_t pte_(struct mm_struct *mm, unsigned long va);
#define PROT_R (1 << 0)
#define PROT_W (1 << 1)
#define PROT_X (1 << 2)


#endif