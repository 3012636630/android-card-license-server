#include <linux/fs.h>
#include <linux/module.h>
#include <linux/atomic.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/dcache.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/miscdevice.h>
#include <linux/device.h>
#include <linux/limits.h>
#include <asm/ptrace.h>
#include <asm/div64.h>

#include "coom.h"
#include "dbg_hook.h"
#include "hook/hook.h"
#include "tool.h"
#include "Reading_and_Writing.h"
#include "touch_inject.h"
#include "app_hooks.h"
#include "kgsl_hide.h"
#include "target_guard.h"
#include "stale_itlb.h"

#define MAX_RW_SIZE (2 * 1024 * 1024)
#define LS_CONTROL_DEV_NAME ".ls_ctl"

#ifndef LS_COVERT_KNOCK
#define LS_COVERT_KNOCK 0x998877
#endif

struct req_obj *g_req = NULL;
struct bm_slot *g_slots = NULL;
static DEFINE_MUTEX(g_req_lock);
static unsigned int g_req_order;
static bool g_clear_on_fd_release = true;
static bool g_seal_app_hooks_on_fd_release;
static atomic_t g_control_fd_count = ATOMIC_INIT(0);
static DEFINE_MUTEX(g_control_dev_lock);
static DEFINE_MUTEX(g_control_fd_lock);
static DEFINE_MUTEX(g_rw_ioctl_lock);
static bool g_control_registered;
/*
 * Vendor kernels may randomize or extend task_struct/VMA internals without
 * exposing those layout changes through modversions.  Keep all ioctl paths
 * that enumerate private kernel objects disabled unless a build has been
 * validated against the exact running layout.  The Android client uses the
 * stable procfs ABI (with its root helper fallback) instead.
 */
static bool g_allow_kernel_object_enumeration;

module_param_named(clear_on_fd_release, g_clear_on_fd_release, bool, 0600);
module_param_named(seal_app_hooks_on_fd_release,
                   g_seal_app_hooks_on_fd_release, bool, 0600);
module_param_named(allow_kernel_object_enumeration,
                   g_allow_kernel_object_enumeration, bool, 0600);

unsigned long lsdriver_shared_map_size(void)
{
    return PAGE_SIZE << get_order(sizeof(struct req_obj));
}

static void lsdriver_mark_reserved(void *base, unsigned int order, bool reserved)
{
    unsigned long addr = (unsigned long)base;
    unsigned long size = PAGE_SIZE << order;
    unsigned long off;

    for (off = 0; off < size; off += PAGE_SIZE) {
        struct page *page = virt_to_page((void *)(addr + off));
        if (reserved)
            SetPageReserved(page);
        else
            ClearPageReserved(page);
    }
}

int lsdriver_shared_alloc(void)
{
    struct req_obj *new_req;
    unsigned int order;

    mutex_lock(&g_req_lock);
    if (g_req) {
        mutex_unlock(&g_req_lock);
        return 0;
    }

    order = get_order(sizeof(struct req_obj));
    new_req = (struct req_obj *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
    if (!new_req) {
        mutex_unlock(&g_req_lock);
        return -ENOMEM;
    }

    lsdriver_mark_reserved(new_req, order, true);
    g_req = new_req;
    g_req_order = order;
    g_slots = g_req->slots;
    smp_wmb();
    mutex_unlock(&g_req_lock);
    return 0;
}

void lsdriver_shared_free(void)
{
    struct req_obj *old_req;
    unsigned int old_order;

    mutex_lock(&g_req_lock);
    old_req = g_req;
    old_order = g_req_order;
    g_req = NULL;
    g_slots = NULL;
    g_req_order = 0;
    mutex_unlock(&g_req_lock);

    if (old_req) {
        lsdriver_mark_reserved(old_req, old_order, false);
        free_pages((unsigned long)old_req, old_order);
    }
}

static int lsdriver_open(struct inode *inode, struct file *file)
{
    int ret = lsdriver_shared_alloc();

    if (ret)
        return ret;
    mutex_lock(&g_control_fd_lock);
    atomic_inc(&g_control_fd_count);
    mutex_unlock(&g_control_fd_lock);
    return 0;
}


static int lsdriver_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long max_allowed_size;
    struct req_obj *req;

    if (lsdriver_shared_alloc())
        return -ENOMEM;

    mutex_lock(&g_req_lock);
    req = g_req;
    max_allowed_size = PAGE_SIZE << g_req_order;
    mutex_unlock(&g_req_lock);

    if (!req)
        return -EFAULT;
    if (size > max_allowed_size)
        return -EINVAL;
    if (vma->vm_pgoff != 0)
        return -EINVAL;

    if (remap_pfn_range(vma,
                        vma->vm_start,
                        virt_to_pfn(req),
                        size,
                        vma->vm_page_prot))
        return -EAGAIN;

    return 0;
}

int lsdriver_release(struct inode *inode, struct file *file)
{
    bool last_control_fd = false;

    mutex_lock(&g_control_fd_lock);
    if (atomic_read(&g_control_fd_count) > 0)
        last_control_fd = atomic_dec_and_test(&g_control_fd_count);

    if (last_control_fd && READ_ONCE(g_clear_on_fd_release)) {
        ls_stale_itlb_clear_all();
        ls_target_clear();
        ls_kgsl_hide_remove();
        clear_all_hw_breakpoints();
        v_touch_reset_contacts();
    }
    if (last_control_fd && READ_ONCE(g_seal_app_hooks_on_fd_release))
        lsdriver_seal_app_hooks();
    mutex_unlock(&g_control_fd_lock);
    return 0;
}

static long copy_snapshot_to_user(unsigned long arg, u64 search_addr)
{
    struct ls_regs_info r_info;
    int i;

    if (!g_req || !g_slots)
        return -EFAULT;

    for (i = 0; i < BM_MAX_BREAKPOINTS; i++) {
        if (g_slots[i].target_addr == search_addr) {
            if (ls_snapshot_read_slot(i, &r_info))
                return -EAGAIN;
            r_info.target_addr = search_addr;
            if (copy_to_user((void __user *)arg, &r_info, sizeof(r_info)))
                return -EFAULT;
            return 0;
        }
    }

    return -EAGAIN;
}

static int ls_check_u64_range(u64 addr, size_t size)
{
    if (!addr || !size)
        return -EINVAL;
    if (addr > (u64)ULONG_MAX)
        return -EOVERFLOW;
    if (addr + (u64)size - 1 < addr)
        return -EOVERFLOW;
    return 0;
}

static int ls_check_user_buffer(u64 user_buf, size_t size)
{
    int ret = ls_check_u64_range(user_buf, size);

    if (ret)
        return ret;
    if (!access_ok((void __user *)(unsigned long)user_buf, size))
        return -EFAULT;
    return 0;
}

static int ls_validate_rw_request(const struct ls_rw_mem_info *info)
{
    size_t size;
    int ret;

    if (!info)
        return -EINVAL;
    if (info->pid <= 0)
        return -ESRCH;

    size = (size_t)info->size;
    if (size == 0 || size > MAX_RW_SIZE)
        return -EINVAL;
    if ((__kernel_size_t)size != info->size)
        return -EOVERFLOW;

    ret = ls_check_u64_range(info->addr, size);
    if (ret)
        return ret;
    return ls_check_user_buffer(info->buf, size);
}

static long lsdriver_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct ls_rw_mem_info rw_info;
    void *kbuf = NULL;
    long ret = 0;

    switch (cmd) {
    case LS_IOC_SEAL_RUNTIME:
        return lsdriver_seal_app_hooks();

    case LS_IOC_CLEAR_RUNTIME:
        ls_stale_itlb_clear_all();
        ls_target_clear();
        ls_kgsl_hide_remove();
        clear_all_hw_breakpoints();
        v_touch_reset_contacts();
        return 0;

    case LS_IOC_SHOW_MODULE:
        return show_myself();


    case LS_IOC_STALE_ITLB_LOAD:
        return ls_stale_itlb_load_user((void __user *)arg);

    case LS_IOC_STALE_ITLB_ARM:
        return ls_stale_itlb_arm_user((void __user *)arg);

    case LS_IOC_STALE_ITLB_RESTORE:
        return ls_stale_itlb_restore_user((void __user *)arg);

    case LS_IOC_STALE_ITLB_STATUS:
        return ls_stale_itlb_status_user((void __user *)arg);

    case LS_IOC_STALE_ITLB_DISABLE:
        return ls_stale_itlb_disable_user((void __user *)arg);

    case LS_IOC_SET_TARGET:
    {
        struct ls_target_info *target_info;
        int alloc_slot;

        if (lsdriver_shared_alloc())
            return -ENOMEM;
        target_info = kzalloc(sizeof(*target_info), GFP_KERNEL);
        if (!target_info)
            return -ENOMEM;
        if (copy_from_user(target_info, (void __user *)arg, sizeof(*target_info))) {
            kfree(target_info);
            return -EFAULT;
        }

        ret = ls_target_set(target_info->pid);
        if (ret) {
            kfree(target_info);
            return ret;
        }
        ret = ls_kgsl_hide_install();
        if (ret) {
            ls_target_clear();
            kfree(target_info);
            return ret;
        }
        alloc_slot = setup_hardware_breakpoints(target_info->target_addr,
                                                 target_info->hw_type,
                                                 &target_info->action);
        kfree(target_info);
        return alloc_slot;
    }

    case LS_IOC_READ_MEM:
        if (!arg)
            return -EINVAL;
        if (copy_from_user(&rw_info, (void __user *)arg, sizeof(rw_info)))
            return -EFAULT;
        ret = ls_validate_rw_request(&rw_info);
        if (ret)
            return ret;

        kbuf = kvmalloc(rw_info.size, GFP_KERNEL);
        if (!kbuf)
            return -ENOMEM;

        mutex_lock(&g_rw_ioctl_lock);
        ret = read_phys(rw_info.pid, rw_info.addr, kbuf, rw_info.size);
        mutex_unlock(&g_rw_ioctl_lock);
        if (ret == 0 && copy_to_user((void __user *)rw_info.buf, kbuf, rw_info.size))
            ret = -EFAULT;

        kvfree(kbuf);
        return ret;

    case LS_IOC_WRITE_MEM:
        if (!arg)
            return -EINVAL;
        if (copy_from_user(&rw_info, (void __user *)arg, sizeof(rw_info)))
            return -EFAULT;
        ret = ls_validate_rw_request(&rw_info);
        if (ret)
            return ret;

        kbuf = kvmalloc(rw_info.size, GFP_KERNEL);
        if (!kbuf)
            return -ENOMEM;

        if (copy_from_user(kbuf, (void __user *)rw_info.buf, rw_info.size)) {
            kvfree(kbuf);
            return -EFAULT;
        }

        mutex_lock(&g_rw_ioctl_lock);
        ret = write_phys(rw_info.pid, rw_info.addr, kbuf, rw_info.size);
        mutex_unlock(&g_rw_ioctl_lock);
        kvfree(kbuf);
        return ret;

    case LS_IOC_GET_MODULE_BASE:
    {
        struct ls_module_req mod_req;

        if (copy_from_user(&mod_req, (void __user *)arg, sizeof(mod_req)))
            return -EFAULT;
        mod_req.module_name[sizeof(mod_req.module_name) - 1] = '\0';
        mod_req.base_addr = 0;
        if (READ_ONCE(g_allow_kernel_object_enumeration))
            mod_req.base_addr = get_module_base_by_index(mod_req.pid,
                                                         mod_req.module_name,
                                                         mod_req.target_index,
                                                         mod_req.perm_type);
        if (copy_to_user((void __user *)arg, &mod_req, sizeof(mod_req)))
            return -EFAULT;
        return 0;
    }

    case LS_IOC_GET_SNAPSHOT:
    case LS_IOC_READ_REGS:
    {
        struct ls_regs_info *r_info;
        u64 target_addr;

        r_info = kzalloc(sizeof(*r_info), GFP_KERNEL);
        if (!r_info)
            return -ENOMEM;
        if (copy_from_user(r_info, (void __user *)arg, sizeof(*r_info))) {
            kfree(r_info);
            return -EFAULT;
        }
        target_addr = r_info->target_addr;
        kfree(r_info);
        return copy_snapshot_to_user(arg, target_addr);
    }

    case LS_IOC_WRITE_REGS:
    {
        struct ls_regs_info *r_info;
        int i;

        if (!g_req || !g_slots)
            return -EFAULT;
        r_info = kzalloc(sizeof(*r_info), GFP_KERNEL);
        if (!r_info)
            return -ENOMEM;
        if (copy_from_user(r_info, (void __user *)arg, sizeof(*r_info))) {
            kfree(r_info);
            return -EFAULT;
        }

        for (i = 0; i < BM_MAX_BREAKPOINTS; i++) {
            if (g_slots[i].target_addr == r_info->target_addr) {
                ret = ls_snapshot_write_slot(i, r_info);
                kfree(r_info);
                return ret;
            }
        }
        kfree(r_info);
        return -EAGAIN;
    }

    case LS_IOC_UPDATE_ACTION:
    {
        struct ls_target_info *target_info;

        if (!g_req || !g_slots)
            return -EFAULT;
        target_info = kzalloc(sizeof(*target_info), GFP_KERNEL);
        if (!target_info)
            return -ENOMEM;
        if (copy_from_user(target_info, (void __user *)arg, sizeof(*target_info))) {
            kfree(target_info);
            return -EFAULT;
        }

        ret = ls_breakpoint_update_action(target_info->slot_idx,
                                          target_info->target_addr,
                                          &target_info->action);
        kfree(target_info);
        return ret;
    }

    case LS_IOC_ADD_HIDE_RULE:
    {
        struct ls_rw_mem_info info;

        if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
            return -EFAULT;
        info.target_name[sizeof(info.target_name) - 1] = '\0';
        add_hide_rule(info.target_name);
        return 0;
    }

    case LS_IOC_GET_TOUCH_CAPS:
    {
        struct ls_touch_caps caps = {
            .abi_version = LS_TOUCH_ABI_VERSION,
            .flags = LS_TOUCH_CAP_INDEPENDENT_INPUT | LS_TOUCH_CAP_PHYSICAL_STATE |
                      LS_TOUCH_CAP_CONTACT_GEOMETRY |
                      LS_TOUCH_CAP_PHYSICAL_REDIRECT | LS_TOUCH_CAP_FIXED_WHEEL,
        };

        if (copy_to_user((void __user *)arg, &caps, sizeof(caps)))
            return -EFAULT;
        return 0;
    }

    case LS_IOC_GET_PHYSICAL_TOUCH:
    {
        struct ls_physical_touch_state state;
        int ret;
        int max_x = 0, max_y = 0;

        ret = v_touch_init(&max_x, &max_y);
        if (ret)
            return ret;
        ret = v_touch_get_physical_state(&state);
        if (ret)
            return ret;
        if (copy_to_user((void __user *)arg, &state, sizeof(state)))
            return -EFAULT;
        return 0;
    }

    case LS_IOC_INJECT_TOUCH:
    {
        struct ls_touch_cmd touch_cmd;
        int max_x = 0, max_y = 0;
        u64 tmp_x, tmp_y, tmp_radius_x, tmp_radius_y;

        if (copy_from_user(&touch_cmd, (void __user *)arg, sizeof(touch_cmd)))
            return -EFAULT;
        if (touch_cmd.w <= 0 || touch_cmd.h <= 0 || touch_cmd.slot < 0 ||
            touch_cmd.action < op_down || touch_cmd.action > op_clear_fixed_wheel ||
            (touch_cmd.action <= op_move ? touch_cmd.slot >= 6 :
             touch_cmd.action <= op_clear_physical_redirect ? touch_cmd.slot >= 16 :
             touch_cmd.action == op_reset_contact ? touch_cmd.slot >= 6 :
             touch_cmd.action == op_configure_fixed_wheel ?
                     (touch_cmd.slot < 1 || touch_cmd.slot > 1000) :
                     touch_cmd.slot != 0))
            return -EINVAL;
        if (touch_cmd.action == op_reset_contact)
            return v_touch_reset_contact(touch_cmd.slot);
        if (touch_cmd.action == op_clear_fixed_wheel)
            return v_touch_clear_fixed_wheel();
        if (v_touch_init(&max_x, &max_y) != 0)
            return -ENODEV;

        tmp_x = (u64)touch_cmd.x * max_x;
        do_div(tmp_x, touch_cmd.w);
        touch_cmd.x = (int)tmp_x;

        tmp_y = (u64)touch_cmd.y * max_y;
        do_div(tmp_y, touch_cmd.h);
        touch_cmd.y = (int)tmp_y;

        if (touch_cmd.action <= op_move)
            return v_touch_event(&touch_cmd);
        if (touch_cmd.action == op_redirect_physical)
            return v_touch_redirect_physical(touch_cmd.slot,
                                             touch_cmd.x,
                                             touch_cmd.y);
        if (touch_cmd.action == op_clear_physical_redirect)
            return v_touch_clear_physical_redirect(touch_cmd.slot);
        if (touch_cmd.action == op_configure_fixed_wheel) {
            tmp_radius_x = (u64)touch_cmd.slot * max_x;
            do_div(tmp_radius_x, touch_cmd.w);
            tmp_radius_y = (u64)touch_cmd.slot * max_y;
            do_div(tmp_radius_y, touch_cmd.h);
            return v_touch_configure_fixed_wheel(touch_cmd.x, touch_cmd.y,
                                                 max_t(int, 1, (int)tmp_radius_x),
                                                 max_t(int, 1, (int)tmp_radius_y));
        }

        return -EOPNOTSUPP;
    }

    case LS_IOC_GET_PID:
    {
        struct ls_pid_req req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        req.process_name[sizeof(req.process_name) - 1] = '\0';
        req.pid = -1;
        if (READ_ONCE(g_allow_kernel_object_enumeration))
            req.pid = get_pid_by_full_name_kernel(req.process_name);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case LS_IOC_GET_ANON_BASE:
    {
        struct ls_module_req anon_req;

        if (copy_from_user(&anon_req, (void __user *)arg, sizeof(anon_req)))
            return -EFAULT;
        anon_req.module_name[sizeof(anon_req.module_name) - 1] = '\0';
        anon_req.base_addr = 0;
        if (READ_ONCE(g_allow_kernel_object_enumeration))
            anon_req.base_addr = get_anon_region_by_index(anon_req.pid,
                                                          anon_req.module_name,
                                                          anon_req.target_index,
                                                          anon_req.perm_type);
        if (copy_to_user((void __user *)arg, &anon_req, sizeof(anon_req)))
            return -EFAULT;
        return 0;
    }

    default:
        return -ENOTTY;
    }
}

const struct file_operations lsdriver_fops = {
    .owner = THIS_MODULE,
    .open = lsdriver_open,
    .unlocked_ioctl = lsdriver_ioctl,
    .mmap = lsdriver_mmap,
    .release = lsdriver_release,
};


static struct miscdevice lsdriver_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = LS_CONTROL_DEV_NAME,
    .fops = &lsdriver_fops,
    .mode = 0666,
};

int lsdriver_control_register(void)
{
    int ret = 0;

    mutex_lock(&g_control_dev_lock);
    if (!g_control_registered) {
        ret = misc_register(&lsdriver_miscdev);
        if (!ret)
            g_control_registered = true;
    }
    mutex_unlock(&g_control_dev_lock);
    return ret;
}

void lsdriver_control_unregister(void)
{
    mutex_lock(&g_control_dev_lock);
    if (g_control_registered) {
        misc_deregister(&lsdriver_miscdev);
        g_control_registered = false;
    }
    mutex_unlock(&g_control_dev_lock);
}

int prctl_entry_handler(struct pt_regs *regs)
{
    struct pt_regs *real_user_regs = (struct pt_regs *)regs->regs[0];
    long fd;

    if (IS_ERR_OR_NULL(real_user_regs))
        return 0;

    if ((int)real_user_regs->regs[0] != LS_COVERT_KNOCK)
        return 0;

    if (lsdriver_shared_alloc()) {
        regs->regs[0] = (u64)-ENOMEM;
        real_user_regs->regs[0] = (u64)-ENOMEM;
        return 1;
    }

    fd = anon_inode_getfd("[eventfd]", &lsdriver_fops, NULL,
                          O_CLOEXEC | O_RDWR);
    if (fd >= 0) {
        mutex_lock(&g_control_fd_lock);
        atomic_inc(&g_control_fd_count);
        mutex_unlock(&g_control_fd_lock);
    }
    regs->regs[0] = (u64)fd;
    real_user_regs->regs[0] = (u64)fd;
    return 1;
}
