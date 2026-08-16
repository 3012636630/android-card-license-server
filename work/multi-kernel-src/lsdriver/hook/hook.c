#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/kprobes.h>
#include <asm/cacheflush.h>
#include <linux/stop_machine.h>
#include <asm/ptrace.h>
#include "../quiet_log.h"
#include "hook.h"
#include "../page_.h"
#include <linux/mm.h>          // 内存管理核心
#include <asm/page.h>          // 页大小、页偏移等定义
#include <asm/pgtable.h>       // 页表项 (PTE) 操作定义
#include <asm/tlbflush.h>      // TLB 刷新相关
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
    #include <linux/execmem.h>
#else
    #include <linux/moduleloader.h>
    #include <linux/vmalloc.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
typedef void *(*execmem_alloc_t)(enum execmem_type type, size_t size);
typedef void (*execmem_free_t)(void *ptr);

static execmem_alloc_t p_execmem_alloc = NULL;
static execmem_free_t p_execmem_free = NULL;
#endif

static void free_trampoline(struct inline_hook *hk)
{
    if (!hk || !hk->trampoline)
        return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
    if (!p_execmem_free)
        p_execmem_free = (execmem_free_t)get_symbol_addr("execmem_free");
    if (p_execmem_free)
        p_execmem_free(hk->trampoline);
    else
        vfree(hk->trampoline);
#else
    vfree(hk->trampoline);
#endif

    hk->trampoline = NULL;
    hk->stub_entry = NULL;
}

// ========================================================
// 🛡️ 保存寄存器：加入 BTI 落地指令 (Android 16 必备)
// ========================================================
static const uint32_t save_regs_code[] = {
    0xd104c3ff, // SUB SP, SP, #0x130
    0xa90007e0, // STP X0, X1, [SP]
    0xa9010fe2, // STP X2, X3, [SP, #16]
    0xa90217e4, // STP X4, X5, [SP, #32]
    0xa9031fe6, // STP X6, X7, [SP, #48]
    0xa90427e8, // STP X8, X9, [SP, #64]
    0xa9052fea, // STP X10, X11, [SP, #80]
    0xa90637ec, // STP X12, X13, [SP, #96]
    0xa9073fee, // STP X14, X15, [SP, #112]
    0xa90847f0, // STP X16, X17, [SP, #128]
    0xa9094ff2, // STP X18, X19, [SP, #144]
    0xa90a57f4, // STP X20, X21, [SP, #160]
    0xa90b5ff6, // STP X22, X23, [SP, #176]
    0xa90c67f8, // STP X24, X25, [SP, #192]
    0xa90d6ffa, // STP X26, X27, [SP, #208]
    0xa90e77fc, // STP X28, X29, [SP, #224]
    0xf9007bfe, // STR X30, [SP, #240] (🌟 修正：保存回家的地图)
};

// ========================================================
// 🛡️ 恢复与拦截逻辑：先全恢复，后根据全局变量截断
// ========================================================
static uint32_t restore_regs_code[] = {
    0xf90083e0, // [0] STR X0, [SP, #0x100] (保存伪造返回值)
    0xa94007e0, // [1] LDP X0, X1, [SP]     (🌟 修复：正确的 a940，寄存器不再错位)
    0xa9410fe2, // [2] LDP X2, X3, [SP, #0x10]
    0xa94217e4, // [3] LDP X4, X5, [SP, #0x20]
    0xa9431fe6, // [4] LDP X6, X7, [SP, #0x30]
    0xa94427e8, // [5] LDP X8, X9, [SP, #0x40]
    0xa9452fea, // [6] LDP X10, X11, [SP, #0x50]
    0xa94637ec, // [7] LDP X12, X13, [SP, #0x60]
    0xa9473fee, // [8] LDP X14, X15, [SP, #0x70]
    0xa94847f0, // [9] LDP X16, X17, [SP, #0x80]
    0xa9494ff2, // [10] LDP X18, X19, [SP, #0x90]
    0xa94a57f4, // [11] LDP X20, X21, [SP, #0xA0]
    0xa94b5ff6, // [12] LDP X22, X23, [SP, #0xB0]
    0xa94c67f8, // [13] LDP X24, X25, [SP, #0xC0]
    0xa94d6ffa, // [14] LDP X26, X27, [SP, #0xD0]
    0xa94e77fc, // [15] LDP X28, X29, [SP, #0xE0]
    0xf9407bfe, // [16] LDR X30, [SP, #0xF0]
    0xf94083f0, // [17] LDR X16, [SP, #0x100] (🌟 返回值已存入 X16)
    0x9104c3ff, // [18] ADD SP, SP, #0x130    (释放栈空间，SP上移)
    0x34000070, // [19] CBZ W16, .+12         (检查W16，若为0则跳到放行分支)
    
    // 👇 终极绝杀修复：不再读取栈外危险内存，直接从 X16 拿数据！
    0xd503201f, // [20] MOV X0, X16 
    
    0xd65f03c0, // [21] RET
    0x58000010, // [22] LDR X16, #? (偏移留空，由动态计算填充)
    0xd61f0200, // [23] BR X16
};
// ========================================================
// 🔍 辅助函数
// ========================================================
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

// 这个钩子目标永远不变，就是为了偷 kallsyms_lookup_name
static struct kprobe kp_resolver = {
    .symbol_name = "kallsyms_lookup_name", 
};

// =========================================================================
// 🎯 万能内核符号解析器 (手动传参版)
// 参数: target_symbol_name - 你想要查找的内核隐藏函数名
// =========================================================================
unsigned long get_symbol_addr(const char *target_symbol_name) {
kallsyms_lookup_name_t my_kallsyms_lookup_name;
    unsigned long target_addr = 0;
    int ret;

    // ==========================================
    // 🌟 致命 Bug 修复：清空残留数据
    // ==========================================
    // 每次挂钩子前必须将 addr 清空！否则第二次调用该函数时，
    // 内核发现结构体里已经有地址了，会直接拒绝注册并返回 -22 (EINVAL)。
    kp_resolver.addr = NULL;

    // 1. 挂上钩子，让内核帮我们在底层的符号表里找到 kallsyms_lookup_name 的地址
    ret = register_kprobe(&kp_resolver);
    if (ret < 0) {
        LS_PRINTK(KERN_ERR "[lsdriver] ❌ Kprobe 套娃失败: 找不到 kallsyms_lookup_name (错误码: %d)\n", ret);
        return 0;
    }

    // 2. 强行将拿到的内存地址，转换为我们可以直接调用的函数指针
    my_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp_resolver.addr;

    // 3. 卸磨杀驴：地址已经偷到手了，立刻撤销 Kprobe，不要给系统留下痕迹
    unregister_kprobe(&kp_resolver);

    // 4. 利用我们刚偷到的神级函数，去查目标函数名！
    target_addr = my_kallsyms_lookup_name(target_symbol_name);

    if (target_addr) {
        LS_PRINTK(KERN_INFO "[lsdriver] 🎯 套娃成功！解析到 [%s] 动态地址: 0x%lx\n", target_symbol_name, target_addr);
    } else {
        LS_PRINTK(KERN_ERR "[lsdriver] ❌ kallsyms 查无此人: [%s]\n", target_symbol_name);
    }

    return target_addr;
}

// 🚨 ARM64 危险指令扫描器 (防止重启的核心防御)
int handle_existing_hook(void *orig_code) {
    uint32_t *code = (uint32_t *)orig_code;
    uint32_t ins0 = code[0];
    uint32_t ins1 = code[1];

    // 🌟 1. 完美接管：发现同行使用的 16 字节 LDR+BR 方案
    // 支持 X16 和 X17 寄存器
    if ((ins0 == 0x58000050 && ins1 == 0xd61f0200) || // LDR X16, #8; BR X16
        (ins0 == 0x58000051 && ins1 == 0xd61f0220)) { // LDR X17, #8; BR X17
        
        uint64_t other_hook_addr = *(uint64_t *)(&code[2]);
        LS_PRINTK(KERN_INFO "[lsdriver] 🥷 发现其他驱动 LDR+BR Hook！自动执行链式接管，流向: 0x%llx\n", other_hook_addr);
        
        // 返回 1 允许放行。
        // 你的 setup_trampoline 会把这段 LDR+BR 原封不动拷贝进 trampoline。
        // 因为这段代码天然是位置无关的，拷贝过去后执行，就是完美跳进上一个驱动的 Hook 之中！
        return 1; 
    }

    // 🚨 2. 致命冲突拦截：发现 4 字节的短跳转 (如 Ftrace / B 指令)
    if ((ins0 & 0xFC000000) == 0x14000000) {
        LS_PRINTK(KERN_ERR "[lsdriver] ❌ 致命拦截：目标已被 4 字节短跳转 (如 B 指令) 占用！\n");
        LS_PRINTK(KERN_ERR "[lsdriver] ⚠️ 若强行覆写 16 字节，会抹除原 Hook 蹦床返回所需的残留指令，必触发 Kernel Panic，已拒绝！\n");
        return -EBUSY;
    }

    // 🛡️ 3. 常规 PC 相对寻址检查 (你的原版逻辑)
    for (int i = 0; i < 4; i++) {
        uint32_t ins = code[i];
        if ((ins & 0xFC000000) == 0x14000000 || // B
            (ins & 0xFC000000) == 0x94000000 || // BL
            (ins & 0x9F000000) == 0x90000000 || // ADRP
            (ins & 0xFF000000) == 0x54000000 || // B.cond
            (ins & 0x7F000000) == 0x34000000 || // CBZ/CBNZ
            (ins & 0x7F000000) == 0x36000000 || // TBZ/TBNZ
            (ins & 0xBF000000) == 0x58000000) { // LDR (literal)
            LS_PRINTK(KERN_ERR "[lsdriver] 🚨 危险！前 16 字节存在相对寻址指令 (0x%08x)，已拒绝 Hook！\n", ins);
            return -1;
        }
    }

    return 0; // 干净无 Hook，正常放行
}







typedef pte_t *(*lookup_address_t)(unsigned long address, unsigned int *level);

void check_mem_permission(void *addr) {
    unsigned int level;
    pte_t *ptep;
    lookup_address_t p_lookup_address = (lookup_address_t)get_symbol_addr("lookup_address");

    if (!p_lookup_address) {
        LS_PRINTK(KERN_ERR "[lsdriver] 找不到 lookup_address 符号\n");
        return;
    }

    ptep = p_lookup_address((unsigned long)addr, &level);
    if (ptep) {
        pte_t pte = *ptep;
        
        // 在 ARM64 中：
        // PTE_PXN (Privileged Execute Never) 位如果被置 1，则不可执行
        // PTE_RDONLY 位如果被置 1，则为只读
        
        bool is_readonly = !!(pte_val(pte) & PTE_RDONLY);
        bool is_executable = !(pte_val(pte) & PTE_PXN); // PXN 为 0 表示可执行

   
    }
}




static int setup_trampoline(struct inline_hook *hk, void *new_func) {
    struct page *page;
    void *writable;
    uint32_t *code;
    int idx = 0, i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
    if (!p_execmem_alloc) {
        p_execmem_alloc = (execmem_alloc_t)get_symbol_addr("execmem_alloc");
        if (!p_execmem_alloc)
            return -ENOSYS;
    }
    hk->trampoline = p_execmem_alloc(EXECMEM_KPROBES, PAGE_SIZE);
#else
    {
        void *(*my_module_alloc)(unsigned long) = (void *)get_symbol_addr("module_alloc");
        if (!my_module_alloc)
            return -ENOSYS;
        hk->trampoline = my_module_alloc(PAGE_SIZE);
    }
#endif
    if (!hk->trampoline)
        return -ENOMEM;

    page = is_vmalloc_addr(hk->trampoline) ? vmalloc_to_page(hk->trampoline) : virt_to_page(hk->trampoline);
    if (!page) {
        free_trampoline(hk);
        return -ENOMEM;
    }

    writable = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
    if (!writable) {
        free_trampoline(hk);
        return -ENOMEM;
    }
code = (uint32_t *)writable;

    // 1. 拷贝原函数前16字节 (放行通道开头)
    memcpy(&code[idx], hk->orig_code, 16); 
    idx += 4;
    
    // 2. 原函数放行通道的 LDR/BR 逻辑
    int ldr_orig_ret_idx = idx;
    code[idx++] = 0x58000010; // LDR X16, #? (先占位，下面动态计算)
    code[idx++] = 0xd61f0200; // BR X16
    
    void *stub_entry_addr = hk->trampoline + (idx * 4);
    
    // 3. 拦截检查站：保存现场
    for (i = 0; i < ARRAY_SIZE(save_regs_code); i++) code[idx++] = save_regs_code[i];

    code[idx++] = 0x910003e0; // MOV X0, SP
    int ldr_fn_idx = idx;     
    code[idx++] = 0x58000010; // LDR X16, #? (先占位，下面动态计算)
    code[idx++] = 0xd63f0200; // BLR X16

    // 4. 拦截检查站：恢复现场
    int restore_start_idx = idx; 
    for (i = 0; i < ARRAY_SIZE(restore_regs_code); i++) code[idx++] = restore_regs_code[i];

    // ==========================================
    // 🧠 终极动态数据池：完美隔离，绝不踩踏代码！
    // ==========================================
    // 确保数据区 8 字节对齐
    if (idx % 2 != 0) code[idx++] = 0xd503201f; // NOP 对齐
    
    // 数据 1: 存 C 拦截函数的真实指针
    int data_fn_ptr = idx;
    *(uint64_t *)(&code[idx]) = (uint64_t)new_func; 
    idx += 2;

    // 数据 2: 存跳回原函数(+16)的真实指针
    int data_ret_ptr = idx;
    *(uint64_t *)(&code[idx]) = (uint64_t)hk->target_addr + 16;
    idx += 2;


    // 👇🌟 新增数据 3: 存蹦床头部的真实指针 (供尾部放行通道使用)
    int data_tramp_head_ptr = idx;
    *(uint64_t *)(&code[idx]) = (uint64_t)hk->trampoline;
    idx += 2;


    // ==========================================
    // 🔗 核心绝杀：动态修复所有 LDR 偏移，指哪打哪
    // ==========================================
    // 修复 1：原函数放行通道的跳转偏移
    uint32_t offset0 = data_ret_ptr - ldr_orig_ret_idx;
    code[ldr_orig_ret_idx] = 0x58000010 | ((offset0 & 0x7ffff) << 5);

    // 修复 2：调用 C 拦截函数的偏移 (准确指向 data_fn_ptr)
    uint32_t offset1 = data_fn_ptr - ldr_fn_idx;
    code[ldr_fn_idx] = 0x58000010 | ((offset1 & 0x7ffff) << 5);

// 👇🌟 修复 3：拦截放行后，跳回【蹦床头部】执行原函数前16字节 -> 指向数据 3！
    int ldr_final_ret_idx = restore_start_idx + 22; 
    uint32_t offset2 = data_tramp_head_ptr - ldr_final_ret_idx;
    code[ldr_final_ret_idx] = 0x58000010 | ((offset2 & 0x7ffff) << 5);

  

    flush_icache_range((unsigned long)hk->trampoline, (unsigned long)hk->trampoline + PAGE_SIZE);
    vunmap(writable);
    hk->stub_entry = stub_entry_addr;
    
    return 0;
}
// ========================================================
// 🛑 砸瓦鲁多：时停写入核心逻辑 (解决多核竞争)
// ========================================================
struct patch_args {
    void *addr;            // 原始执行地址 (RX)
    void *writable_addr;   // 已经映射好的可写别名地址 (RW)
    const void *code;      // 我们要写入的新指令
    size_t len;            // 长度 (16)
};

// ========================================================
// 🛑 砸瓦鲁多！极限精简的回调 (只管写，不刷 Cache，不刷 TLB)
// ========================================================
static int do_atomic_patch(void *data) {
    struct patch_args *args = (struct patch_args *)data;
    unsigned long offset = offset_in_page(args->addr);

    // 【唯一任务】：把指令写进去
    // 因为此时所有核心都停了，这里写完，物理内存里的值就是最新的了
    memcpy(args->writable_addr + offset, args->code, args->len);

    // 确保写入动作对所有核心可见（内存屏障）
    smp_wmb(); 

    return 0; 
}

// ========================================================
// 💉 善后大管家：所有重量级操作都在回调结束后执行
// ========================================================
int patch_kernel_text(void *addr, const void *code, size_t len) {
    struct page *page;
    void *writable_addr;
    struct patch_args args;
    unsigned long offset = offset_in_page(addr);

    // 🛡️ 核心防御：跨越物理边界死机拦截
    if (offset + len > PAGE_SIZE) {
        LS_PRINTK(KERN_ERR "[lsdriver] 🚨 致命拦截：地址 %px 跨越物理页边界！\n", addr);
        return -EINVAL; 
    }

    page = is_vmalloc_addr(addr) ? vmalloc_to_page(addr) : virt_to_page(addr);
    if (!page) return -EFAULT;

    writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
    if (!writable_addr) return -EFAULT;

    args.addr = addr;
    args.writable_addr = writable_addr;
    args.code = code;
    args.len = len;

    stop_machine(do_atomic_patch, &args, NULL);

    for (unsigned long i = 0; i < len; i += 4) {
        unsigned long va_w = (unsigned long)writable_addr + offset + i;
        unsigned long va_x = (unsigned long)addr + i;
        asm volatile("dc cvau, %0" : : "r" (va_w) : "memory");
        asm volatile("dsb ish" : : : "memory");
        asm volatile("ic ivau, %0" : : "r" (va_x) : "memory");
    }
    asm volatile("dsb ish; isb" : : : "memory");
    vunmap(writable_addr);
    
    return 0;
}

void prepare_jump(struct inline_hook *hk, void *entry) {
    uint32_t *j = (uint32_t *)hk->jump_code;
    j[0] = 0x58000050; // LDR X16, #8
    j[1] = 0xd61f0200; // BR X16
    *(uint64_t *)(hk->jump_code + 8) = (uint64_t)entry;
}

// ========================================================
// 🚀 API 入口
// ========================================================
int do_inline_hook(struct inline_hook *hk, const char *name, void *new_func) {
    int ret;

    memset(hk, 0, sizeof(*hk));
    hk->target_addr = (void *)get_symbol_addr(name);
    if (!hk->target_addr) return -ENOENT;
    
    // 🛡️ 提前安全读取前 16 字节
    if (copy_from_kernel_nofault(hk->orig_code, hk->target_addr, 16)) {
        return -EFAULT; 
    }

 int hook_status = handle_existing_hook(hk->orig_code);
    if (hook_status < 0) {
        return hook_status; // 如果遇到不兼容的 4字节Hook 或危险指令，果断退出保命
    }

    ret = setup_trampoline(hk, new_func);
    if (ret < 0)
        return ret;

    prepare_jump(hk, hk->stub_entry);
    
    // 🛡️ 写入并防止内存泄漏
    if (patch_kernel_text(hk->target_addr, hk->jump_code, 16) < 0) {
        LS_PRINTK(KERN_ERR "[lsdriver] patch failed, rollback trampoline\n");
        free_trampoline(hk);
        return -EFAULT;
    }
    
    LS_PRINTK(KERN_INFO "[lsdriver] 🟢 成功 Hook 函数: %s\n", name);
    return 0;
}

int restore_inline_hook(struct inline_hook *hk) {
    uint8_t verify[16];
    int ret;

    if (!hk || !hk->target_addr)
        return -EINVAL;

    ret = patch_kernel_text(hk->target_addr, hk->orig_code, 16);
    if (ret)
        return ret;
    if (copy_from_kernel_nofault(verify, hk->target_addr, sizeof(verify)))
        return -EFAULT;
    if (memcmp(verify, hk->orig_code, sizeof(verify)))
        return -EIO;
    return 0;
}

void release_inline_hook(struct inline_hook *hk) {
    if (!hk)
        return;

    free_trampoline(hk);
    memset(hk, 0, sizeof(*hk));
}

void undo_inline_hook(struct inline_hook *hk) {
    if (!hk || !hk->target_addr)
        return;

    if (!restore_inline_hook(hk))
        release_inline_hook(hk);
}


static inline uint32_t emit_ldr_x_pc(uint32_t xn, int32_t offset) {
    uint32_t imm19 = (offset / 4) & 0x7FFFF;
    return 0x58000000 | (imm19 << 5) | xn;
}

static inline uint32_t emit_blr_x(uint32_t xn) {
    return 0xD63F0000 | (xn << 5);
}

static inline uint32_t emit_b_imm(int32_t offset) {
    uint32_t imm26 = (offset / 4) & 0x3FFFFFF;
    return 0x14000000 | imm26;
}

// ==========================================
// 核心解算器 (剥离 PC 相对地址)
// ==========================================
static inline uint64_t calculate_bl_target(uint64_t pc, uint32_t insn) {
    int32_t imm26 = insn & 0x03FFFFFF;
    if (imm26 & 0x02000000) { 
        imm26 |= 0xFC000000;
    }
    return pc + (imm26 * 4);
}

static inline uint64_t calculate_adrp_target(uint64_t pc, uint32_t insn) {
    uint32_t immlo = (insn >> 29) & 0x3;
    uint32_t immhi = (insn >> 5) & 0x7FFFF;
    int32_t imm = (immhi << 2) | immlo;
    
    if (imm & 0x100000) {
        imm |= 0xFFE00000;
    }
    int64_t offset = (int64_t)imm << 12;
    return (pc & ~0xFFFULL) + offset;
}

// ==========================================
// 核心引擎：极简无痕重组引擎 (Pure Relocator)
// ==========================================
// ==========================================
// 核心引擎：零跳转纯线性版 (常数池后置)
// ==========================================
void* dbi_compile_code_range(void *orig_insn_buffer, void *real_pc, size_t code_size, void *map_address) {
    uint32_t *orig_insn = (uint32_t *)orig_insn_buffer;
    size_t num_insns = code_size / 4; 
    uint32_t *cache = (uint32_t *)map_address;
    
    uint32_t idx = 0;
    uint64_t data_pool[32];      
    uint32_t ldr_pos_idx[32];    
    uint32_t data_count = 0;

    for (size_t i = 0; i < num_insns; i++) {
        uint32_t insn = orig_insn[i];
        uint64_t current_pc = (uint64_t)real_pc + (i * 4);

        // ==========================================
        // 🌟 新增：链式 Hook 支持！拦截其他人的 LDR Xn, #imm 蹦床跳转
        // ==========================================
        if ((insn & 0xFF000000) == 0x58000000) { 
            // 这是一个 LDR (literal) 指令，通常用于加载蹦床的绝对地址
            uint32_t rt = insn & 0x1F; // 拿到目标寄存器 (通常是 16，即 X16)
            int32_t imm19 = ((int32_t)(insn << 8) >> 13); // 提取偏移量并符号扩展
            uint64_t literal_addr = current_pc + imm19; // 计算绝对地址

            // 从物理内存中读取那个绝对地址里存的值 (这就是套娃的下一个入口地址！)
            uint64_t target_jump_addr;
            if (copy_from_kernel_nofault(&target_jump_addr, (void*)literal_addr, 8) == 0) {
                // 成功读到了绝对地址！我们把它放进数据池
                ldr_pos_idx[data_count] = idx;
                data_pool[data_count] = target_jump_addr; 
                data_count++;
                
                // 在缓存里放一个新的 LDR 占位，等下回填
                cache[idx++] = emit_ldr_x_pc(rt, 0); 
                continue; // 处理完毕，跳过原指令
            }
        }

        // 拦截 BL
        if ((insn & 0xFC000000) == 0x94000000) {
            ldr_pos_idx[data_count] = idx;
            data_pool[data_count] = calculate_bl_target(current_pc, insn);
            data_count++;
            
            cache[idx++] = emit_ldr_x_pc(16, 0); 
            cache[idx++] = emit_blr_x(16);       
            continue;
        }

        // 拦截 ADRP
        if ((insn & 0x9F000000) == 0x90000000) {
            ldr_pos_idx[data_count] = idx;
            data_pool[data_count] = calculate_adrp_target(current_pc, insn);
            uint32_t xd = insn & 0x1F;
            data_count++;
            
            cache[idx++] = emit_ldr_x_pc(xd, 0); 
            continue;
        }

        // 普通指令原样搬运
        cache[idx++] = insn;
    }

    // --- 第二步：在函数末尾统一排放数据，并回填 LDR 偏移 ---
    // 此时 idx 已经指向了函数逻辑结束后的第一个空位
    for (uint32_t j = 0; j < data_count; j++) {
        uint32_t ldr_idx = ldr_pos_idx[j];
        // 计算从 LDR 指令到数据位置的精确距离 (单位：字节)
        int32_t offset = (idx - ldr_idx) * 4;
        
        // 修正 LDR 指令：回填正确的偏移量
        uint32_t x_reg = cache[ldr_idx] & 0x1F; 
        cache[ldr_idx] = emit_ldr_x_pc(x_reg, offset);
        
        // 在末尾写入 8 字节数据
        memcpy(&cache[idx], &data_pool[j], 8);
        idx += 2;
    }

    // --- 结尾：长跳回原函数 ---
    uint64_t resume_addr = (uint64_t)real_pc + code_size;
    uint32_t br_ldr_idx = idx;
    cache[idx++] = emit_ldr_x_pc(16, 8); // 这里的偏移固定为 8 字节
    cache[idx++] = 0xD61F0200;           // BR X16
    memcpy(&cache[idx], &resume_addr, 8);
    idx += 2;

    flush_icache_range((unsigned long)cache, (unsigned long)&cache[idx]);
    return cache;
}
