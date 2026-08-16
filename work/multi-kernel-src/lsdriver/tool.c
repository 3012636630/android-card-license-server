#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/version.h>
#include "kernel_compat.h"
#if LS_HAVE_ANON_VMA_NAME
#include <linux/mm_inline.h>
#endif
#include <linux/kprobes.h>
#include <linux/uaccess.h> 
#include "quiet_log.h"

// ==========================================
// 🛡️ 核心兼容宏定义：抹平 Linux 新老版本差异
// ==========================================

// 1. 兼容读写锁差异 (Linux 5.8 分水岭)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    #define LOCK_MMAP(mm) mmap_read_lock(mm)
    #define UNLOCK_MMAP(mm) mmap_read_unlock(mm)
#else
    #define LOCK_MMAP(mm) down_read(&mm->mmap_sem)
    #define UNLOCK_MMAP(mm) up_read(&mm->mmap_sem)
#endif

// 2. 兼容 VMA 遍历差异 (Linux 6.1 分水岭)
#if LS_HAVE_MAPLE_TREE_VMA
    #define FOR_EACH_VMA_START(mm, vma) \
        VMA_ITERATOR(vmi, mm, 0); \
        for_each_vma(vmi, vma) {
#else
    #define FOR_EACH_VMA_START(mm, vma) \
        for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
#endif
#define FOR_EACH_VMA_END }


// ==========================================
// 🏴‍☠️ 突破未导出符号限制：Kprobe 寻址引擎
// ==========================================
unsigned long resolve_unexported_symbol(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr = 0;

    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp); 
    } else {
        LS_PRINTK(KERN_ERR "[lsdriver-tool] ❌ 无法解析内核符号: %s\n", name);
    }
    
    return addr;
}


// ==========================================
// 🕵️‍♂️ 获取目标进程 PID (降维打击版，移除 access_process_vm)
// ==========================================
static bool wz_comm_match(const char *query, const char *comm)
{
    char head[TASK_COMM_LEN];
    char tail[TASK_COMM_LEN];
    size_t len;

    if (!query || !comm || !query[0] || !comm[0])
        return false;

    if (!strcmp(query, comm))
        return true;

    memset(head, 0, sizeof(head));
    strncpy(head, query, TASK_COMM_LEN - 1);
    if (!strcmp(head, comm))
        return true;

    len = strlen(query);
    if (len >= TASK_COMM_LEN) {
        memset(tail, 0, sizeof(tail));
        strncpy(tail, query + len - (TASK_COMM_LEN - 1), TASK_COMM_LEN - 1);
        if (!strcmp(tail, comm))
            return true;
    }

    return false;
}

typedef char *(*ls_get_task_comm_fn_t)(char *to, size_t len,
                                       struct task_struct *tsk);

static unsigned long g_get_task_comm_addr;

static ls_get_task_comm_fn_t ls_get_task_comm_resolve(void)
{
    unsigned long addr = READ_ONCE(g_get_task_comm_addr);

    if (!addr) {
        addr = resolve_unexported_symbol("__get_task_comm");
        if (addr)
            WRITE_ONCE(g_get_task_comm_addr, addr);
    }

    return (ls_get_task_comm_fn_t)addr;
}

pid_t get_pid_by_full_name_kernel(const char *full_name)
{
    ls_get_task_comm_fn_t get_comm;
    pid_t nr;
    const pid_t scan_limit = 131072;

    if (!full_name || !full_name[0])
        return -1;

    get_comm = ls_get_task_comm_resolve();
    if (!get_comm)
        return -1;

    for (nr = 1; nr <= scan_limit; nr++) {
        struct pid *p;
        struct task_struct *task;
        char comm[TASK_COMM_LEN];
        pid_t matched_pid = -1;
        bool matched = false;

        p = find_get_pid(nr);
        if (!p)
            continue;

        task = get_pid_task(p, PIDTYPE_PID);
        put_pid(p);
        if (task) {
            memset(comm, 0, sizeof(comm));
            get_comm(comm, sizeof(comm), task);
            matched = wz_comm_match(full_name, comm);
            if (matched)
                matched_pid = nr;
            put_task_struct(task);
        }

        if (matched)
            return matched_pid;
    }

    return -1;
}

// ==========================================
// 🛡️ O(1) 复杂度的高效 MM 结构获取 (修复内存泄漏版)
// ==========================================
struct mm_struct* get_mm_by_pid_robust(pid_t target_pid) {
    struct pid *pid_struct = find_get_pid(target_pid);
    struct task_struct *task;
    struct mm_struct *mm = NULL;

    if (!pid_struct) return NULL;
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (task) {
        // get_task_mm 内置了原子锁并会自动增加 mm 的引用计数 (mmget)
        mm = get_task_mm(task);
        put_task_struct(task);
    }
    
    // ⚠️ 注意：外部函数在使用完返回的 mm 后，务必调用 mmput(mm) 释放！
    return mm; 
}


uintptr_t get_module_base_by_index(pid_t pid, const char* module_name, int target_index, int perm_type) {
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t base_addr = 0;
    int current_index = 0; 

    // 1. 获取目标进程的基本结构
    pid_struct = find_get_pid(pid);
    if (!pid_struct) return 0;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) { 
        return 0; 
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) { 
        return 0; 
    }

    // 2. 加锁保护内存空间读取
    mmap_read_lock(mm);

    // 3. 🌟 跨版本遍历架构核心代码
#if LS_HAVE_MAPLE_TREE_VMA
    // 现代内核 (Linux 6.1+) 使用 Maple Tree 和 VMA 迭代器
    VMA_ITERATOR(vmi, mm, 0); 
    for_each_vma(vmi, vma) {
#else
    // 传统内核 (Linux 6.1 以下) 使用双向链表
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif

        if (vma->vm_file) {
            // 直接读取 dentry 名称，避开高风险的 d_path
            const char* vma_name = vma->vm_file->f_path.dentry->d_name.name;
            
            // 匹配目标模块名 (如 "libunity.so")
            if (vma_name && strstr(vma_name, module_name) != NULL) {
                
                // 提取当前内存段的 R/W/X 核心权限
                unsigned long check_flags = vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC);
                bool match = false;

                // 🚦 根据 App 传来的 perm_type 进行动态过滤
                switch (perm_type) {
                    case 0: // 【不限权限】全盘匹配
                        match = true; 
                        break;
                    case 1: // 【r--p】只读段 (文件头 / ELF)
                        match = (check_flags == VM_READ); 
                        break;
                    case 2: // 【rw-p】读写段 (数据段 Data/Bss)
                        match = (check_flags == (VM_READ | VM_WRITE)); 
                        break;
                    case 3: // 【r-xp】可执行段 (游戏代码区 Xa)
                        match = (check_flags == (VM_READ | VM_EXEC)); 
                        break;
                    default: 
                        match = true; 
                }

                // 权限匹配通过后，才判断是不是我们要的那个索引
                if (match) {
                    if (current_index == target_index) {
                        base_addr = vma->vm_start;
                        
                        // 打印调试日志，让你在 dmesg 里看个爽
                        char* perm_str = (perm_type==1) ? "r--p" : 
                                         (perm_type==2) ? "rw-p" : 
                                         (perm_type==3) ? "r-xp" : "ALL";
                                         
                     
                        break; // 找到目标，跳出遍历
                    }
                    current_index++; 
                }
            }
        }

// 🌟 必须闭合跨版本宏判断
#if LS_HAVE_MAPLE_TREE_VMA
    } // 结束 for_each_vma
#else
    } // 结束传统 for 循环
#endif

    // 4. 释放锁与清理引用计数（这部分绝对不能漏，否则死机）
    mmap_read_unlock(mm);
    mmput(mm);

    // 5. 返回最终找到的基址，没找到就是 0
    return base_addr;
}



uintptr_t get_anon_region_by_index(pid_t pid, const char* target_name, int target_index, int perm_type) {
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t base_addr = 0;
    int current_index = 0; 

    // 1. 获取目标进程的基本结构
    pid_struct = find_get_pid(pid);
    if (!pid_struct) return 0;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) { 
        return 0; 
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) { 
        return 0; 
    }

    // 2. 加锁保护内存空间读取
    mmap_read_lock(mm);

    // 3. 跨版本遍历架构核心代码
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    VMA_ITERATOR(vmi, mm, 0); 
    for_each_vma(vmi, vma) {
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        const char* vma_name = NULL;

        // 🌟 核心修改点：获取匿名内存的命名
        // 现代 Android 内核 (带 CONFIG_ANON_VMA_NAME 选项) 提供了 anon_vma_name() 函数
     #if LS_HAVE_ANON_VMA_NAME
    /* 在高版本内核中正常获取匿名 VMA 名字 */
    struct anon_vma_name *anon_name_struct = anon_vma_name(vma);
    if (anon_name_struct) {
        vma_name = anon_name_struct->name;
    }
#else
    /* 在 5.10 等低版本内核中，跳过此步骤以保证编译通过 */
    vma_name = NULL; 
#endif

        // 匹配目标匿名内存名 (注意：传参时直接传 "objects_external_alloc"，不要带 "[anon:" 前缀)
        if (vma_name && strstr(vma_name, target_name) != NULL) {
            
            // 提取当前内存段的 R/W/X 核心权限
            unsigned long check_flags = vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC);
            bool match = false;

            // 🚦 根据 perm_type 进行动态过滤
            switch (perm_type) {
                case 0: // 【不限权限】全盘匹配
                    match = true; 
                    break;
                case 1: // 【r--p】只读段
                    match = (check_flags == VM_READ); 
                    break;
                case 2: // 【rw-p】读写段
                    match = (check_flags == (VM_READ | VM_WRITE)); 
                    break;
                case 3: // 【r-xp】只读可执行段
                    match = (check_flags == (VM_READ | VM_EXEC)); 
                    break;
                case 4: // 🌟【rwxp】读写可执行段 (对应你截图中的内存权限)
                    match = (check_flags == (VM_READ | VM_WRITE | VM_EXEC)); 
                    break;
                default: 
                    match = true; 
            }

            // 权限匹配通过后，判断索引
            if (match) {
                if (current_index == target_index) {
                    base_addr = vma->vm_start;
                    break; // 找到目标，跳出遍历
                }
                current_index++; 
            }
        }

#if LS_HAVE_MAPLE_TREE_VMA
    } // 结束 for_each_vma
#else
    } // 结束传统 for 循环
#endif

    // 4. 释放锁与清理引用计数
    mmap_read_unlock(mm);
    mmput(mm);

    // 5. 返回最终找到的基址，没找到就是 0
    return base_addr;
}
