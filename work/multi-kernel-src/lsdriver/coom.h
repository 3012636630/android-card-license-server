#ifndef COOM_H
#define COOM_H

/* =========================================================
 * 1. 基础类型与定义 (必须最先出现)
 * ========================================================= */
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#endif

#define LS_IOC_MAGIC 'L'

/* =========================================================
 * 2. 核心结构体定义 (前置，防 incomplete type，必须与应用层严格对齐)
 * ========================================================= */

#define MAX_CACHED_ENEMIES 30

struct CachedEntity {
    int32_t heroId;
    int32_t hp;
    int32_t max_hp;
    int32_t logic_x;
    int32_t logic_z;
    uint32_t ally;
    int32_t id;
} __attribute__((aligned(8)));

struct SharedGameData {
    uint32_t valid_count; 
    uint32_t _pad1; // 🌟 手动补齐，保证后面的数组按 8 字节对齐
    struct CachedEntity enemies[MAX_CACHED_ENEMIES];
} __attribute__((aligned(8)));

typedef struct {
    __u64 low;
    __u64 high;
} ls_qreg_t;

struct ls_bp_action {
    __u32 action_flags;
    __u32 _pad1;              // 🌟 补齐 4 字节
    __u64 reg_mask;
    __u64 new_regs[31];
    __u32 q_reg_mask;
    __u32 _pad2;              // 🌟 补齐 4 字节
    ls_qreg_t new_q_regs[32];
    __u64 new_pc;
    __u64 new_sp;
    __u64 new_pstate;
} __attribute__((aligned(8))); // 💥 彻底干掉 packed

struct ls_regs_info {
    __u64 target_addr;
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
    ls_qreg_t q_regs[32];
} __attribute__((aligned(8)));

struct bm_slot {
    /* Monotonic snapshot sequence. Odd means a writer is publishing and even
     * means hit_snapshot is stable. Readers that mmap this structure should
     * retry when the value is odd or changes across their copy. */
    volatile __u32 sync_state;
    bool active;
    bool is_watchpoint;
    __s16 hw_slot;             // mapped physical BRP/WRP slot, -1 when not installed
    __u64 target_addr;
    __u64 hw_ctrl;
    struct ls_bp_action action;
    struct ls_regs_info hit_snapshot;
} __attribute__((aligned(8)));

/* =========================================================
 * 3. 其余结构体与枚举
 * ========================================================= */
enum ls_sm_op { OP_NONE = 0, OP_SET_HWBP, OP_CLEAR_HWBP };

struct req_obj {
    __u32 op;
    __kernel_pid_t pid;
    __u64 target_addr;
    __u32 hw_type;
    __u32 _pad1; // 🌟 对齐
    
    struct bm_slot slots[6]; // 💥 独立隔离的数据舱
    struct SharedGameData game_data;
} __attribute__((aligned(8)));

struct ls_module_req {
    __kernel_pid_t pid;
    char module_name[64];
    int target_index;
    int perm_type;
    __u32 _pad1; // 🌟 补齐 4 字节，使 base_addr 的起始地址可以被 8 整除
    __u64 base_addr;
} __attribute__((aligned(8)));

struct ls_touch_cmd {
    int action;
    int slot;
    int x;
    int y;
    int w;
    int h;
    __u32 attribute_mask;
    __s32 pressure;
    __s32 touch_major;
    __s32 touch_minor;
    __s32 orientation;
};

#define LS_TOUCH_ABI_VERSION 10U
#define LS_TOUCH_CAP_INDEPENDENT_INPUT (1U << 0)
#define LS_TOUCH_CAP_PHYSICAL_STATE    (1U << 1)
#define LS_TOUCH_CAP_CONTACT_GEOMETRY  (1U << 2)
#define LS_TOUCH_CAP_PHYSICAL_REDIRECT (1U << 3)
#define LS_TOUCH_CAP_FIXED_WHEEL       (1U << 4)
#define LS_TOUCH_ATTR_PRESSURE          (1U << 0)
#define LS_TOUCH_ATTR_TOUCH_MAJOR       (1U << 1)
#define LS_TOUCH_ATTR_TOUCH_MINOR       (1U << 2)
#define LS_TOUCH_ATTR_ORIENTATION       (1U << 3)
struct ls_touch_caps { __u32 abi_version; __u32 flags; };

struct ls_physical_touch_state {
    __u32 abi_version;
    __u32 seq;
    __s32 active;
    __s32 slot;
    __s32 x;
    __s32 y;
    __s32 max_x;
    __s32 max_y;
    __s32 released_mask;
    __s32 _pad;
    __s32 pressure;
    __s32 touch_major;
    __s32 touch_minor;
    __s32 orientation;
    __u32 attribute_mask;
};

struct ls_rw_mem_info {
    __kernel_pid_t pid;
    __u32 _pad1; // 🌟 补齐 4 字节
    __u64 addr;
    __u64 buf;
    __kernel_size_t size;
    char target_name[64];
} __attribute__((aligned(8)));

struct ls_pid_req { 
    char process_name[64]; 
    __kernel_pid_t pid; 
    __u32 _pad1; // 🌟 补齐
} __attribute__((aligned(8)));

struct ls_target_info {
    __kernel_pid_t pid;
    __s32 slot_idx;
    __u64 target_addr;
    int hw_type;
    __u32 _pad1; // 🌟 补齐 4 字节
    struct ls_bp_action action;
} __attribute__((aligned(8)));


#define LS_STALE_ITLB_MAX_SLOTS 4
#define LS_STALE_ITLB_MAX_PAGES 16
#define LS_STALE_ITLB_MAX_IMAGE (LS_STALE_ITLB_MAX_PAGES * 4096ULL)

#define LS_STALE_ITLB_F_COPY_ORIG_TAIL (1U << 0)
#define LS_STALE_ITLB_F_RESTORE_TLBI   (1U << 1)

#define LS_STALE_ITLB_STATE_EMPTY    0U
#define LS_STALE_ITLB_STATE_LOADED   1U
#define LS_STALE_ITLB_STATE_ARMED    2U
#define LS_STALE_ITLB_STATE_RESTORED 3U
#define LS_STALE_ITLB_STATE_ERROR    4U

struct ls_stale_itlb_req {
    __kernel_pid_t pid;
    __u32 slot;
    __u32 flags;
    __u32 page_count;
    __u32 state;
    __s32 last_error;
    __u64 target_va;
    __u64 shadow_user;
    __u64 shadow_size;
    __u64 generation;
    __u64 active_cpus;
    __u64 reprime_count;
    __u64 restore_count;
} __attribute__((aligned(8)));

struct pt_regs;
int prctl_entry_handler(struct pt_regs *regs);

#ifdef __KERNEL__
extern struct req_obj *g_req;
extern struct bm_slot *g_slots;
int lsdriver_shared_alloc(void);
void lsdriver_shared_free(void);
unsigned long lsdriver_shared_map_size(void);
int lsdriver_control_register(void);
void lsdriver_control_unregister(void);
#endif


/* =========================================================
 * 4. 头文件包含 (放在结构体定义之后)
 * ========================================================= */
#ifdef __KERNEL__
#include "conceal_driver.h"
#include "emulate_insn.h"
#include "touch_inject.h"
#include "dbg_hook.h"
#endif

/* =========================================================
 * 5. 功能宏与函数声明
 * ========================================================= */
#define LS_HW_TYPE_EXEC  0
#define LS_HW_TYPE_READ  1
#define LS_HW_TYPE_WRITE 2
#define LS_HW_TYPE_RW    3

#define LS_ACTION_SKIP       (1 << 0)
#define LS_ACTION_STEP       (1 << 1)
#define LS_ACTION_MOD_PC     (1 << 2)
#define LS_ACTION_MOD_SP     (1 << 3)
#define LS_ACTION_MOD_PSTATE (1 << 4)
/* Bit 5 is reserved after removal of the legacy entity-cache action. */
/* Action-only low-jitter mode. Snapshot publication is skipped only when the
 * kernel parameter sync_snapshot_always is explicitly disabled. */
#define LS_ACTION_FAST_HIT   (1 << 6)

#ifdef __KERNEL__
extern void add_hide_rule(const char *rule);
extern int show_myself(void);
#endif

#define LS_IOC_SET_TARGET    _IOW(LS_IOC_MAGIC, 1, struct ls_target_info)
#define LS_IOC_READ_MEM      _IOWR(LS_IOC_MAGIC, 2, struct ls_rw_mem_info)
#define LS_IOC_WRITE_MEM     _IOW(LS_IOC_MAGIC, 3, struct ls_rw_mem_info)
#define LS_IOC_READ_REGS     _IOWR(LS_IOC_MAGIC, 4, struct ls_regs_info)
#define LS_IOC_WRITE_REGS    _IOW(LS_IOC_MAGIC, 5, struct ls_regs_info)
#define LS_IOC_GET_SNAPSHOT  _IOWR(LS_IOC_MAGIC, 6, struct ls_regs_info)
#define LS_IOC_UPDATE_ACTION _IOW(LS_IOC_MAGIC, 7, struct ls_target_info) 
#define LS_IOC_ADD_HIDE_RULE _IOW(LS_IOC_MAGIC, 8, struct ls_rw_mem_info)
#define LS_IOC_INJECT_TOUCH  _IOW(LS_IOC_MAGIC, 9, struct ls_touch_cmd)
#define LS_IOC_GET_MODULE_BASE _IOWR(LS_IOC_MAGIC, 10, struct ls_module_req)
#define LS_IOC_GET_PID         _IOWR(LS_IOC_MAGIC, 11, struct ls_pid_req)
#define LS_IOC_GET_ANON_BASE   _IOWR(LS_IOC_MAGIC, 12, struct ls_module_req)
#define LS_IOC_CLEAR_RUNTIME   _IO(LS_IOC_MAGIC, 13)
#define LS_IOC_SEAL_RUNTIME    _IO(LS_IOC_MAGIC, 14)
#define LS_IOC_STALE_ITLB_LOAD    _IOWR(LS_IOC_MAGIC, 15, struct ls_stale_itlb_req)
#define LS_IOC_STALE_ITLB_ARM     _IOWR(LS_IOC_MAGIC, 16, struct ls_stale_itlb_req)
#define LS_IOC_STALE_ITLB_RESTORE _IOWR(LS_IOC_MAGIC, 17, struct ls_stale_itlb_req)
#define LS_IOC_STALE_ITLB_STATUS  _IOWR(LS_IOC_MAGIC, 18, struct ls_stale_itlb_req)
#define LS_IOC_STALE_ITLB_DISABLE _IOWR(LS_IOC_MAGIC, 19, struct ls_stale_itlb_req)
#define LS_IOC_GET_TOUCH_CAPS      _IOR(LS_IOC_MAGIC, 20, struct ls_touch_caps)
#define LS_IOC_GET_PHYSICAL_TOUCH  _IOR(LS_IOC_MAGIC, 21, struct ls_physical_touch_state)
#define LS_IOC_SHOW_MODULE         _IO(LS_IOC_MAGIC, 22)

#endif // COOM_H
