#ifndef ARM64_REG_H
#define ARM64_REG_H

#include <linux/types.h>

// 宏展开：用于生成 32 个 Q 寄存器的读取指令 (STR Qn, [val])
#define READ_Q_CASE(n) \
    case n: asm volatile("str q" #n ", [%0]" : : "r"(val) : "memory"); break;

// 宏展开：用于生成 32 个 Q 寄存器的写入指令 (LDR Qn, [val])
#define WRITE_Q_CASE(n) \
    case n: asm volatile("ldr q" #n ", [%0]" : : "r"(val) : "memory"); break;

// 🌟 核心修复 1：添加目标属性，告诉编译器这个函数允许使用 fp 和 simd 指令
__attribute__((target("fp,simd")))
static inline void read_q_reg(int reg, __uint128_t *val)
{
    switch (reg) {
        READ_Q_CASE(0)  READ_Q_CASE(1)  READ_Q_CASE(2)  READ_Q_CASE(3)
        READ_Q_CASE(4)  READ_Q_CASE(5)  READ_Q_CASE(6)  READ_Q_CASE(7)
        READ_Q_CASE(8)  READ_Q_CASE(9)  READ_Q_CASE(10) READ_Q_CASE(11)
        READ_Q_CASE(12) READ_Q_CASE(13) READ_Q_CASE(14) READ_Q_CASE(15)
        READ_Q_CASE(16) READ_Q_CASE(17) READ_Q_CASE(18) READ_Q_CASE(19)
        READ_Q_CASE(20) READ_Q_CASE(21) READ_Q_CASE(22) READ_Q_CASE(23)
        READ_Q_CASE(24) READ_Q_CASE(25) READ_Q_CASE(26) READ_Q_CASE(27)
        READ_Q_CASE(28) READ_Q_CASE(29) READ_Q_CASE(30) READ_Q_CASE(31)
    }
}

// 🌟 核心修复 1：添加目标属性
__attribute__((target("fp,simd")))
static inline void write_q_reg(int reg, const __uint128_t *val)
{
    switch (reg) {
        WRITE_Q_CASE(0)  WRITE_Q_CASE(1)  WRITE_Q_CASE(2)  WRITE_Q_CASE(3)
        WRITE_Q_CASE(4)  WRITE_Q_CASE(5)  WRITE_Q_CASE(6)  WRITE_Q_CASE(7)
        WRITE_Q_CASE(8)  WRITE_Q_CASE(9)  WRITE_Q_CASE(10) WRITE_Q_CASE(11)
        WRITE_Q_CASE(12) WRITE_Q_CASE(13) WRITE_Q_CASE(14) WRITE_Q_CASE(15)
        WRITE_Q_CASE(16) WRITE_Q_CASE(17) WRITE_Q_CASE(18) WRITE_Q_CASE(19)
        WRITE_Q_CASE(20) WRITE_Q_CASE(21) WRITE_Q_CASE(22) WRITE_Q_CASE(23)
        WRITE_Q_CASE(24) WRITE_Q_CASE(25) WRITE_Q_CASE(26) WRITE_Q_CASE(27)
        WRITE_Q_CASE(28) WRITE_Q_CASE(29) WRITE_Q_CASE(30) WRITE_Q_CASE(31)
    }
}

// 🌟 核心修复 2：系统寄存器只能用 64 位寄存器 (x) 读写，不能用 32 位 (w)
// 之前返回值是 uint32_t，导致编译器分配了 w 寄存器报错。现统一改为 uint64_t
// 🌟 核心修复 3：在内联汇编字符串内部强行开启 fp 架构扩展
static inline uint64_t read_fpsr(void) {
    uint64_t val;
    asm volatile(
        ".arch_extension fp\n\t"
        "mrs %0, fpsr" 
        : "=r"(val)
    );
    return val;
}

static inline void write_fpsr(uint64_t val) {
    asm volatile(
        ".arch_extension fp\n\t"
        "msr fpsr, %0" 
        : : "r"(val)
    );
}

static inline uint64_t read_fpcr(void) {
    uint64_t val;
    asm volatile(
        ".arch_extension fp\n\t"
        "mrs %0, fpcr" 
        : "=r"(val)
    );
    return val;
}

static inline void write_fpcr(uint64_t val) {
    asm volatile(
        ".arch_extension fp\n\t"
        "msr fpcr, %0" 
        : : "r"(val)
    );
}

#endif // ARM64_REG_H