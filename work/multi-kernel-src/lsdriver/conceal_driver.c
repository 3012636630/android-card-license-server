
#include "quiet_log.h"
#include "conceal_driver.h"
#include <linux/atomic.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include "hook/hook.h"
#include "tool.h"
static DEFINE_PER_CPU(int, printk_hook_active);
static DEFINE_PER_CPU(int, writev_hook_active);
static DEFINE_PER_CPU(int, path_hook_active);
// 拦截规则结构体
struct hide_rule {
    char name[64];           // 要隐藏的名字或特征
    struct list_head list;
};

// 全局规则链表
static LIST_HEAD(hide_rules_list);
static DEFINE_RWLOCK(rules_lock); // 读写锁，保证多核扫描安全
static atomic_t hide_rule_count = ATOMIC_INIT(0);
static DEFINE_MUTEX(module_visibility_lock);
typedef int (*ls_kobject_rename_t)(struct kobject *kobj, const char *new_name);
static struct mutex *hidden_module_mutex;
static struct list_head *hidden_modules_head;
static ls_kobject_rename_t hidden_kobject_rename;
static bool module_is_hidden;

#define LS_HIDDEN_SYSFS_NAME "." KBUILD_MODNAME

bool hide_rules_active(void)
{
    return atomic_read(&hide_rule_count) != 0;
}

// 动态添加拦截目标 (由你的 prctl 通讯调用)
void add_hide_rule(const char *name) {
    struct hide_rule *rule;

    // 1. 防御性检查：拒绝空指针或空字符串
    if (!name || name[0] == '\0') {
        LS_PRINTK(KERN_WARNING "[lsdriver] ⚠️ 尝试添加无效或空的隐藏规则被拒绝！\n");
        return;
    }

    rule = kmalloc(sizeof(*rule), GFP_KERNEL);
    if (rule) {
        // 使用更安全的 strscpy 替代 strncpy，它天然保证末尾有 '\0'
        strscpy(rule->name, name, sizeof(rule->name));
        
        write_lock(&rules_lock);
        list_add(&rule->list, &hide_rules_list);
        atomic_inc(&hide_rule_count);
        write_unlock(&rules_lock);

        // 🖨️ 打印成功添加的规则
        LS_PRINTK(KERN_INFO "[lsdriver] ➕ 成功添加隐藏规则: [%s]\n", rule->name);
    } else {
        LS_PRINTK(KERN_ERR "[lsdriver] ❌ 内存不足，无法添加隐藏规则: [%s]\n", name);
    }
}

static int should_hide_logic(const char *target_name) {
    struct hide_rule *rule;
    int found = 0;

    if (likely(!hide_rules_active())) return 0;

    // 1. 空指针或空字符串直接放行
    if (!target_name || target_name[0] == '\0') return 0;

    // 2. 上读锁：允许反作弊多线程并发扫盘，互不干扰
    read_lock(&rules_lock);
    list_for_each_entry(rule, &hide_rules_list, list) {
        
        // 🌟 核心修复：全路径精确匹配
        // 只有当 target_name 和 rule->name 完完全全一模一样时才拦截！
        if (strcmp(target_name, rule->name) == 0) {
            found = 1;
            break; // 撞上特征，立刻判死刑
        }
    }
    read_unlock(&rules_lock);
    
    return found;
}

void clear_hide_rules(void)
{
    struct hide_rule *rule;
    struct hide_rule *tmp;

    write_lock(&rules_lock);
    list_for_each_entry_safe(rule, tmp, &hide_rules_list, list) {
        list_del(&rule->list);
        kfree(rule);
    }
    atomic_set(&hide_rule_count, 0);
    write_unlock(&rules_lock);
}



void hide_myself(void)
{
    int ret;

    mutex_lock(&module_visibility_lock);
    if (module_is_hidden)
        goto out;

    if (!hidden_module_mutex)
        hidden_module_mutex = (struct mutex *)get_symbol_addr("module_mutex");
    if (!hidden_modules_head)
        hidden_modules_head = (struct list_head *)get_symbol_addr("modules");
    if (!hidden_kobject_rename)
        hidden_kobject_rename = (ls_kobject_rename_t)
            get_symbol_addr("kobject_rename");
    if (!hidden_module_mutex || !hidden_modules_head || !hidden_kobject_rename)
        goto out;

    /* Renaming preserves the module's sysfs attributes for clean restoration. */
    ret = hidden_kobject_rename(&THIS_MODULE->mkobj.kobj,
                                LS_HIDDEN_SYSFS_NAME);
    if (ret)
        goto out;

    mutex_lock(hidden_module_mutex);
    if (!list_empty(&THIS_MODULE->list))
        list_del_init(&THIS_MODULE->list);
    mutex_unlock(hidden_module_mutex);

    /* list and mkobj have stable offsets across the supported Android ABIs. */
    module_is_hidden = true;
out:
    mutex_unlock(&module_visibility_lock);
}

int show_myself(void)
{
    int ret = 0;

    mutex_lock(&module_visibility_lock);
    if (!module_is_hidden)
        goto out;
    if (!hidden_module_mutex || !hidden_modules_head ||
        !hidden_kobject_rename) {
        ret = -ENOENT;
        goto out;
    }

    ret = hidden_kobject_rename(&THIS_MODULE->mkobj.kobj, KBUILD_MODNAME);
    if (ret)
        goto out;

    mutex_lock(hidden_module_mutex);
    if (list_empty(&THIS_MODULE->list))
        list_add(&THIS_MODULE->list, hidden_modules_head);
    mutex_unlock(hidden_module_mutex);
    module_is_hidden = false;
out:
    mutex_unlock(&module_visibility_lock);
    return ret;
}


int my_filename_lookup(struct pt_regs *regs) {
    // X1 corresponds to regs->regs[1]
    struct filename *fname = (struct filename *)regs->regs[1];
    char safe_name[256];

    if (likely(!hide_rules_active()))
        return 0;

    // 1. Basic pointer validation (first line of defense against panics)
    if (IS_ERR_OR_NULL(fname) || IS_ERR_OR_NULL(fname->name)) {
        return 0; // Allow execution
    }

    // 2. Use standard, safe kernel string copy (fixes modpost undefined error)
    // strscpy natively handles bounds and null-termination, so no need for memzero
    if (strscpy(safe_name, fname->name, sizeof(safe_name)) <= 0) {
        return 0;
    }

    // 3. Evaluate stealth logic
    if (should_hide_logic(safe_name)) {
        
        // 🎯 [NOP Trampoline Adaptation]
        // Manually push -ENOENT into X0 to forge the error pointer
        regs->regs[0] = (uint64_t)-ENOENT;

     
        // 🌟 Signal the trampoline: Intercept successful! Skip original function and RET
        return 1; 
    }

    // 🟢 Normal request, return 0 to let the trampoline execute the original function
    return 0;
}



int my_filldir64(struct pt_regs *regs) {
    // 🎯 补全参数映射 (ARM64 调用约定)
    struct dir_context *ctx = (struct dir_context *)regs->regs[0]; // X0: ctx
    const char *name = (const char *)regs->regs[1];                // X1: name
    int namelen = (int)regs->regs[2];                              // X2: namelen
    loff_t offset = (loff_t)regs->regs[3];                         // X3: offset (极其重要)
    
    char safe_name[64]; 

    if (likely(!hide_rules_active()))
        return 0;

    if (!name || namelen <= 0) return 0;

    int len = (namelen < 63) ? namelen : 63;
    memcpy(safe_name, name, len);
    safe_name[len] = '\0'; 

 
    if (should_hide_logic(safe_name)) {
        
        // 🎯 修复 1：手动推进系统的“阅读书签”
        // 既然我们跳过了原厂函数，我们就得替它把活干完，防止目录断层
        ctx->pos = offset;

        // 🎯 修复 2：在高版本内核中，返回 true(1) 才能让系统继续遍历！
        // 告诉内核：“这个文件我处理(吞掉)了，请继续发下一个”
        regs->regs[0] = 1; 

        // 告诉蹦床：拦截成功，跳过原厂 filldir64
        return 1; 
    }

    // 不是目标，正常放行
    return 0; 
}
// ==============================================================
// 5. 进程幽灵化：屏蔽 /proc/PID 探测
// ==============================================================
int my_proc_root_lookup(struct pt_regs *regs) {
    // 1. 在 proc_root_lookup 中，参数签名是 (inode, dentry, flags)
    // 所以 dentry 是第二个参数，对应 X1，也就是 regs->regs[1]
    struct dentry *dentry = (struct dentry *)regs->regs[1];
    char safe_name[64];

    if (likely(!hide_rules_active()))
        return 0;

    // 2. 基础安全检查（/proc 访问频率极高，不判空必死机）
    if (IS_ERR_OR_NULL(dentry) || IS_ERR_OR_NULL(dentry->d_name.name)) {
        return 0; // 放行
    }

    // 3. 🌟 终极修正：使用内核推荐的标准安全拷贝 strscpy
    // 彻底解决 "strncpy_from_kernel_nofault undefined" 编译报错！
    if (strscpy(safe_name, dentry->d_name.name, sizeof(safe_name)) <= 0) {
        return 0;
    }

    // 4. 判定隐身逻辑
    if (should_hide_logic(safe_name)) {
        
        // 🎯 【适配 NOP 蹦床 1】手动把 -ENOENT 塞进 X0 寄存器位置
        // 伪造一个错误指针返回给 VFS
        regs->regs[0] = (uint64_t)-ENOENT;

        // 🎯 【适配 NOP 蹦床 2】返回 1 给蹦床
        // 指挥汇编层跳过原函数，直接带着刚才改好的 X0 返回系统
        return 1; 
    }

    // 🟢 正常请求，返回 0 让蹦床执行原函数
    return 0; 
}


#include <linux/sched.h> // current 宏所在头文件


int get_current_full_name(char *buf, int buflen)
{
    struct mm_struct *mm;
    unsigned long arg_start, arg_end;
    int len;

    // 1. 获取当前进程的内存描述符
    mm = current->mm;
    if (!mm) return 0; // 内核线程没有 mm_struct

    // 2. 获取命令行参数在用户态的起始和结束地址
    arg_start = mm->arg_start;
    arg_end = mm->arg_end;

    if (arg_start >= arg_end) return 0;

    // 3. 计算长度并防止缓冲区溢出
    len = arg_end - arg_start;
    if (len > buflen - 1) {
        len = buflen - 1;
    }

    // 4. 跨界拷贝：从用户态空间读取字符串到内核 buf
    // 由于我们在 current 上下文中，直接使用 copy_from_user 是安全的
    if (copy_from_user(buf, (void __user *)arg_start, len)) {
        return 0; // 拷贝失败（如发生缺页异常）
    }

    // 5. 确保字符串以 \0 结尾
    buf[len] = '\0';
    return len;
}

typedef long (*sys_mincore_t)(const struct pt_regs *);

long my_mincore_hook(struct pt_regs *hook_regs)
{
    struct pt_regs *user_regs;
    unsigned long start;
    size_t len;
    unsigned char __user *vec;
    size_t pages;
    char full_name[128] = {0};

    if (likely(!hide_rules_active()))
        return 0;

    // ==========================================
    // 🛡️ 阶段一：身份校验
    // ==========================================
    if (get_current_full_name(full_name, sizeof(full_name)) > 0) {
        if (!should_hide_logic(full_name)) {
            return 0; // 不匹配，直接放行（让框架去调原函数）
        }
    } else {
        return 0; // 获取全名失败，保险起见放行
    }

    // ---------------- 命中目标，开始直接拦截 ----------------

    user_regs = (struct pt_regs *)hook_regs->regs[0];
    
    // 解析 mincore 参数
    start = user_regs->regs[0]; // addr
    len   = user_regs->regs[1]; // length
    vec   = (unsigned char __user *)user_regs->regs[2]; // vec array

    // ==========================================
    // 🎭 阶段二：直接伪造结果 (不用跳板，不查页表)
    // ==========================================
    if (len > 0 && vec != NULL) {
        pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;

        // 🌟 核心操作：直接将用户态的 vec 数组清零
        // clear_user 比 copy_to_user 更快，它直接在用户空间写 0
        // 效果：告诉游戏，所有被查询的页都不在物理内存中。
        if (clear_user(vec, pages)) {
            // 如果清零失败（比如 vec 地址非法），我们给游戏返回一个内存错误码
            user_regs->regs[0] = -EFAULT; 
        } else {
            // 如果成功，强制设置系统调用的返回值为 0 (成功)
            user_regs->regs[0] = 0; 
        }
    } else {
        // 参数无效时，返回标准的系统调用错误码
        user_regs->regs[0] = -EINVAL;
    }

    return 1; 
}
