#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/compiler.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include "quiet_log.h"
#include "coom.h"
#include "touch_inject.h"

struct vt_context vt = {
    .initialized = false,
};

static DEFINE_MUTEX(vt_lock);
static u64 source_area;

struct physical_touch_monitor {
    struct input_handle handle;
    spinlock_t lock;
    u32 seq;
    u32 snapshot_seq;
    u32 released_mask;
    u32 pending_mask;
    int current_slot;
    int reported_slot;
    int snapshot_cursor;
    int tracking_ids[16];
    int x[16];
    int y[16];
    int pressure[16];
    int touch_major[16];
    int touch_minor[16];
    int orientation[16];
    u32 x_valid_mask;
    u32 y_valid_mask;
    u32 pressure_valid_mask;
    u32 touch_major_valid_mask;
    u32 touch_minor_valid_mask;
    u32 orientation_valid_mask;
    int max_x;
    int max_y;
    u32 grab_release_count;
    /* EV_ABS and EV_KEY can arrive in separate input frames.  Keep the
     * physical key state latched so a synthetic UP cannot close a held
     * physical contact during that window. */
    bool physical_btn_touch;
    bool physical_btn_touch_seen;
    bool redirect_active;
    int redirect_slot;
    int redirect_x;
    int redirect_y;
    bool fixed_wheel_enabled;
    int fixed_wheel_x;
    int fixed_wheel_y;
    int fixed_wheel_radius_x;
    int fixed_wheel_radius_y;
    u32 fixed_wheel_pending_mask;
    u32 fixed_wheel_mapped_mask;
    int fixed_wheel_offset_x[16];
    int fixed_wheel_offset_y[16];
    struct delayed_work deferred_release_work;
    struct input_value deferred_release_vals[40];
    unsigned int deferred_release_count;
    struct input_value *capture_vals;
    unsigned int capture_capacity;
    unsigned int capture_count;
    bool capture_overflow;
    int release_path_slot;
    int release_path_start_x;
    int release_path_start_y;
    int release_path_target_x;
    int release_path_target_y;
    unsigned int release_path_step;
    int injected_slots[6];
    int injected_tracking_ids[6];
    u32 injected_seq;
};

static struct physical_touch_monitor ptm;

#define RELEASE_MOVE_COUNT 3U
#define INJECTED_LOGICAL_SLOTS 6

static unsigned int append_final_move(struct input_value *vals, int slot, int x, int y)
{
    vals[0] = (struct input_value) { EV_ABS, ABS_MT_SLOT, slot };
    vals[1] = (struct input_value) { EV_ABS, ABS_MT_POSITION_X, x };
    vals[2] = (struct input_value) { EV_ABS, ABS_MT_POSITION_Y, y };
    vals[3] = (struct input_value) { EV_SYN, SYN_REPORT, 0 };
    return 4;
}

static unsigned int ptm_input_to_handler(struct input_handle *handle,
                                         struct input_value *vals,
                                         unsigned int count)
{
    struct input_handler *handler = handle->handler;
    struct input_value *end = vals;
    struct input_value *value;

    if (handler->filter) {
        for (value = vals; value != vals + count; value++) {
            if (handler->filter(handle, value->type, value->code,
                                value->value))
                continue;
            if (end != value)
                *end = *value;
            end++;
        }
        count = end - vals;
    }

    if (!count)
        return 0;
    if (handler->events)
        handler->events(handle, vals, count);
    else if (handler->event)
        for (value = vals; value != vals + count; value++)
            handler->event(handle, value->type, value->code, value->value);
    return count;
}

static void ptm_send_downstream_locked(struct input_value *vals, unsigned int count)
{
    struct input_handle *cursor;
    struct input_dev *dev = ptm.handle.dev;

    if (!count || !dev)
        return;

    /* input_pass_values() normally clears MONO after each frame. This direct
     * downstream path bypasses it, so force evdev's input_get_timestamp() to
     * generate a fresh timestamp instead of reusing the last physical frame. */
    dev->timestamp[INPUT_CLK_MONO] = ktime_set(0, 0);
    rcu_read_lock();
    list_for_each_entry_rcu(cursor, &dev->h_list, d_node) {
        if (cursor == &ptm.handle)
            continue;
        if (cursor->open) {
            count = ptm_input_to_handler(cursor, vals, count);
            if (!count)
                break;
        }
    }
    rcu_read_unlock();
}

static void ptm_send_downstream(struct input_value *vals, unsigned int count)
{
    struct input_dev *dev = ptm.handle.dev;
    unsigned long flags;

    if (!count || !dev)
        return;

    spin_lock_irqsave(&dev->event_lock, flags);
    ptm_send_downstream_locked(vals, count);
    spin_unlock_irqrestore(&dev->event_lock, flags);
}

static int scale_contact_attribute(struct input_dev *dev, unsigned int code,
                                   int normalized, bool signed_value)
{
    const struct input_absinfo *info = &dev->absinfo[code];
    s64 numerator;

    if (signed_value) {
        normalized = clamp(normalized, -1024, 1024);
        numerator = (s64)(normalized + 1024) * (info->maximum - info->minimum);
        return info->minimum + div_s64(numerator, 2048);
    }
    normalized = clamp(normalized, 0, 1024);
    numerator = (s64)normalized * (info->maximum - info->minimum);
    return info->minimum + div_s64(numerator, 1024);
}

static void append_touch_value(struct input_value *vals, unsigned int *count,
                               unsigned int type, unsigned int code, int value)
{
    vals[*count] = (struct input_value) { type, code, value };
    (*count)++;
}

static bool physical_contact_active_locked(void)
{
    struct input_dev *dev = vt.source_dev;
    int slots;
    int i;

    if (ptm.physical_btn_touch_seen)
        return ptm.physical_btn_touch;

    for (i = 0; i < ARRAY_SIZE(ptm.tracking_ids); i++)
        if (ptm.tracking_ids[i] >= 0)
            return true;

    if (!dev || !dev->mt)
        return false;
    if (test_bit(BTN_TOUCH, dev->key))
        return true;

    slots = min_t(int, dev->mt->num_slots, ARRAY_SIZE(ptm.tracking_ids));
    for (i = 0; i < slots; i++)
        if (input_mt_is_active(&dev->mt->slots[i]))
            return true;
    return false;
}

static bool injected_contact_active_locked(void)
{
    int i;

    for (i = 0; i < INJECTED_LOGICAL_SLOTS; i++)
        if (ptm.injected_slots[i] >= 0)
            return true;
    return false;
}

static bool injected_slot_reserved_locked(int slot)
{
    int i;

    for (i = 0; i < INJECTED_LOGICAL_SLOTS; i++)
        if (ptm.injected_slots[i] == slot)
            return true;
    return false;
}

static int allocate_injected_slot_locked(void)
{
    int slots = min_t(int, vt.source_dev->mt->num_slots,
                      ARRAY_SIZE(ptm.tracking_ids));
    int slot;

    for (slot = slots - 1; slot >= 0; slot--)
        if (ptm.tracking_ids[slot] < 0 && !injected_slot_reserved_locked(slot))
            return slot;
    return -1;
}

static bool tracking_id_in_use_locked(int tracking_id)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(ptm.tracking_ids); i++)
        if (ptm.tracking_ids[i] == tracking_id)
            return true;
    for (i = 0; i < INJECTED_LOGICAL_SLOTS; i++)
        if (ptm.injected_tracking_ids[i] == tracking_id)
            return true;
    return false;
}

static int allocate_tracking_id_locked(int logical_slot)
{
    struct input_dev *dev = vt.source_dev;
    int minimum = max(0, input_abs_get_min(dev, ABS_MT_TRACKING_ID));
    int maximum = input_abs_get_max(dev, ABS_MT_TRACKING_ID);
    u64 span;
    u32 mixed;
    int attempt;
    int tracking_id;

    if (maximum < minimum)
        maximum = minimum + 65535;
    span = (u64)(maximum - minimum) + 1U;
    for (attempt = 0; attempt < 32; attempt++) {
        mixed = ++ptm.injected_seq * 1664525U + 1013904223U +
                logical_slot * 2246822519U + attempt * 3266489917U;
        tracking_id = minimum + (int)((u64)mixed % span);
        if (tracking_id != -1 && !tracking_id_in_use_locked(tracking_id))
            return tracking_id;
    }
    return minimum;
}

static void append_contact_attributes(struct input_value *vals, unsigned int *count,
                                      const struct ls_touch_cmd *cmd)
{
    struct input_dev *dev = vt.source_dev;

    if ((cmd->attribute_mask & LS_TOUCH_ATTR_PRESSURE) &&
        test_bit(ABS_MT_PRESSURE, dev->absbit))
        append_touch_value(vals, count, EV_ABS, ABS_MT_PRESSURE,
                           scale_contact_attribute(dev, ABS_MT_PRESSURE,
                                                   cmd->pressure, false));
    if ((cmd->attribute_mask & LS_TOUCH_ATTR_TOUCH_MAJOR) &&
        test_bit(ABS_MT_TOUCH_MAJOR, dev->absbit))
        append_touch_value(vals, count, EV_ABS, ABS_MT_TOUCH_MAJOR,
                           scale_contact_attribute(dev, ABS_MT_TOUCH_MAJOR,
                                                   cmd->touch_major, false));
    if ((cmd->attribute_mask & LS_TOUCH_ATTR_TOUCH_MINOR) &&
        test_bit(ABS_MT_TOUCH_MINOR, dev->absbit))
        append_touch_value(vals, count, EV_ABS, ABS_MT_TOUCH_MINOR,
                           scale_contact_attribute(dev, ABS_MT_TOUCH_MINOR,
                                                   cmd->touch_minor, false));
    if ((cmd->attribute_mask & LS_TOUCH_ATTR_ORIENTATION) &&
        test_bit(ABS_MT_ORIENTATION, dev->absbit))
        append_touch_value(vals, count, EV_ABS, ABS_MT_ORIENTATION,
                           scale_contact_attribute(dev, ABS_MT_ORIENTATION,
                                                   cmd->orientation, true));
}

static unsigned int release_path_progress(u32 seq, unsigned int step)
{
    u32 mixed = seq * 1664525U + 1013904223U + step * 2246822519U;

    if (step == 0)
        return 300U + mixed % 141U;
    if (step == 1)
        return 700U + mixed % 151U;
    return 1000U;
}

static unsigned long release_path_delay_jiffies(u32 seq, unsigned int next_step)
{
    u32 mixed = seq * 1664525U + 1013904223U + next_step * 2246822519U;
    unsigned int delay_ms = next_step >= RELEASE_MOVE_COUNT ?
                            10U + mixed % 5U : 6U + mixed % 5U;

    return max(1UL, msecs_to_jiffies(delay_ms));
}

static void ptm_deliver_deferred_release(struct work_struct *work)
{
    struct input_value vals[ARRAY_SIZE(ptm.deferred_release_vals)];
    struct input_dev *dev = ptm.handle.dev;
    unsigned long event_flags;
    unsigned long flags;
    unsigned int count = 0;
    unsigned long next_delay = 0;
    bool delivered_release = false;
    int release_slot;

    (void)work;
    if (!dev)
        return;
    spin_lock_irqsave(&dev->event_lock, event_flags);
    spin_lock_irqsave(&ptm.lock, flags);
    if (!ptm.deferred_release_count) {
        spin_unlock_irqrestore(&ptm.lock, flags);
        spin_unlock_irqrestore(&dev->event_lock, event_flags);
        return;
    }

    release_slot = ptm.release_path_slot;
    if (release_slot < 0 || release_slot >= ARRAY_SIZE(ptm.tracking_ids) ||
        ptm.tracking_ids[release_slot] >= 0 ||
        injected_slot_reserved_locked(release_slot)) {
        ptm.deferred_release_count = 0;
        ptm.release_path_slot = -1;
        spin_unlock_irqrestore(&ptm.lock, flags);
        spin_unlock_irqrestore(&dev->event_lock, event_flags);
        return;
    }

    if (ptm.release_path_step < RELEASE_MOVE_COUNT) {
        unsigned int step = ptm.release_path_step;
        unsigned int progress = release_path_progress(ptm.seq, step);
        int x = ptm.release_path_start_x +
                div_s64((s64)(ptm.release_path_target_x - ptm.release_path_start_x) *
                        progress, 1000);
        int y = ptm.release_path_start_y +
                div_s64((s64)(ptm.release_path_target_y - ptm.release_path_start_y) *
                        progress, 1000);

        count = append_final_move(vals, ptm.release_path_slot, x, y);
        ptm.release_path_step++;
        next_delay = release_path_delay_jiffies(ptm.seq, ptm.release_path_step);
    } else {
        count = min_t(unsigned int, ptm.deferred_release_count, ARRAY_SIZE(vals));
        memcpy(vals, ptm.deferred_release_vals, count * sizeof(*vals));
        ptm.deferred_release_count = 0;
        ptm.release_path_slot = -1;
        delivered_release = true;
    }
    spin_unlock_irqrestore(&ptm.lock, flags);

    ptm_send_downstream_locked(vals, count);
    spin_unlock_irqrestore(&dev->event_lock, event_flags);
    if (!delivered_release)
        mod_delayed_work(system_wq, &ptm.deferred_release_work, next_delay);
}

/* Discovery-only handler: retain the largest direct multitouch panel. */
static bool is_candidate_physical_panel(struct input_dev *dev, int *out_x, int *out_y)
{
    int max_x;
    int max_y;

    if (!dev || !dev->name ||
        !test_bit(EV_ABS, dev->evbit) ||
        !test_bit(ABS_MT_SLOT, dev->absbit) ||
        !test_bit(ABS_MT_POSITION_X, dev->absbit) ||
        !test_bit(ABS_MT_POSITION_Y, dev->absbit) ||
        !test_bit(BTN_TOUCH, dev->keybit) || !dev->mt || !dev->absinfo)
        return false;

    max_x = dev->absinfo[ABS_MT_POSITION_X].maximum;
    max_y = dev->absinfo[ABS_MT_POSITION_Y].maximum;
    if (max_x <= 0 || max_y <= 0)
        return false;
    if (out_x) *out_x = max_x;
    if (out_y) *out_y = max_y;
    return true;
}

static int spy_connect(struct input_handler *handler, struct input_dev *dev,
                       const struct input_device_id *id)
{
    int max_x;
    int max_y;
    u64 area;

    if (!is_candidate_physical_panel(dev, &max_x, &max_y))
        return -ENODEV;

    area = (u64)max_x * (u64)max_y;
    if (!vt.source_dev || area > source_area) {
        vt.source_dev = dev;
        source_area = area;
    }
    return -ENODEV;
}

static const struct input_device_id vtouch_ids[] = {
    { .driver_info = 1 },
    { },
};

static struct input_handler vtouch_spy = {
    .connect = spy_connect,
    .name = "input_panel_probe",
    .id_table = vtouch_ids,
};

static bool fixed_wheel_contains_locked(int x, int y)
{
    s64 normalized_x;
    s64 normalized_y;

    if (!ptm.fixed_wheel_enabled || ptm.fixed_wheel_radius_x <= 0 ||
        ptm.fixed_wheel_radius_y <= 0)
        return false;
    normalized_x = div_s64((s64)(x - ptm.fixed_wheel_x) * 1024,
                           ptm.fixed_wheel_radius_x);
    normalized_y = div_s64((s64)(y - ptm.fixed_wheel_y) * 1024,
                           ptm.fixed_wheel_radius_y);
    return normalized_x * normalized_x + normalized_y * normalized_y <=
           1024LL * 1024LL;
}

static int fixed_wheel_x_locked(int slot, int raw_x)
{
    if (!(ptm.fixed_wheel_mapped_mask & BIT(slot)))
        return raw_x;
    return clamp(raw_x + ptm.fixed_wheel_offset_x[slot], 0, ptm.max_x);
}

static int fixed_wheel_y_locked(int slot, int raw_y)
{
    if (!(ptm.fixed_wheel_mapped_mask & BIT(slot)))
        return raw_y;
    return clamp(raw_y + ptm.fixed_wheel_offset_y[slot], 0, ptm.max_y);
}

static void classify_fixed_wheel_contacts_locked(void)
{
    u32 pending = ptm.fixed_wheel_pending_mask;
    int slot;

    for (slot = 0; slot < ARRAY_SIZE(ptm.tracking_ids); slot++) {
        u32 bit = BIT(slot);

        if (!(pending & bit) || ptm.tracking_ids[slot] < 0 ||
            !(ptm.x_valid_mask & bit) || !(ptm.y_valid_mask & bit))
            continue;
        if (fixed_wheel_contains_locked(ptm.x[slot], ptm.y[slot])) {
            ptm.fixed_wheel_mapped_mask |= bit;
            ptm.fixed_wheel_offset_x[slot] = ptm.fixed_wheel_x - ptm.x[slot];
            ptm.fixed_wheel_offset_y[slot] = ptm.fixed_wheel_y - ptm.y[slot];
        } else {
            ptm.fixed_wheel_mapped_mask &= ~bit;
            ptm.fixed_wheel_offset_x[slot] = 0;
            ptm.fixed_wheel_offset_y[slot] = 0;
        }
        ptm.fixed_wheel_pending_mask &= ~bit;
    }
}

static void translate_fixed_wheel_values_locked(struct input_value *vals,
                                                 unsigned int count,
                                                 int initial_slot)
{
    int slot = initial_slot;
    unsigned int i;

    for (i = 0; i < count; i++) {
        struct input_value *value = &vals[i];

        if (value->type != EV_ABS)
            continue;
        if (value->code == ABS_MT_SLOT) {
            slot = value->value;
            continue;
        }
        if (slot < 0 || slot >= ARRAY_SIZE(ptm.tracking_ids))
            continue;
        if (value->code == ABS_MT_POSITION_X)
            value->value = fixed_wheel_x_locked(slot, value->value);
        else if (value->code == ABS_MT_POSITION_Y)
            value->value = fixed_wheel_y_locked(slot, value->value);
    }
}

static unsigned int complete_fixed_wheel_down_frames_locked(
        struct input_value *vals, unsigned int count, unsigned int capacity,
        int initial_slot, u32 new_contacts)
{
    int slot = initial_slot;
    unsigned int i = 0;
    u32 frame_new = 0;

    while (i < count) {
        struct input_value *value = &vals[i];

        if (value->type == EV_ABS && value->code == ABS_MT_SLOT) {
            slot = value->value;
        } else if (value->type == EV_ABS &&
                   value->code == ABS_MT_TRACKING_ID && value->value >= 0 &&
                   slot >= 0 && slot < ARRAY_SIZE(ptm.tracking_ids) &&
                   (new_contacts & BIT(slot))) {
            frame_new |= BIT(slot);
        } else if (value->type == EV_SYN && value->code == SYN_REPORT &&
                   frame_new) {
            u32 mapped_new = frame_new & ptm.fixed_wheel_mapped_mask;
            unsigned int contacts = 0;
            unsigned int needed;
            unsigned int write_at;
            int mapped_slot;

            for (mapped_slot = 0;
                 mapped_slot < ARRAY_SIZE(ptm.tracking_ids); mapped_slot++)
                if (mapped_new & BIT(mapped_slot))
                    contacts++;
            needed = contacts ? contacts * 3U + 1U : 0U;

            if (needed && count + needed <= capacity) {
                memmove(&vals[i + needed], &vals[i],
                        (count - i) * sizeof(*vals));
                write_at = i;
                for (mapped_slot = 0;
                     mapped_slot < ARRAY_SIZE(ptm.tracking_ids); mapped_slot++) {
                    if (!(mapped_new & BIT(mapped_slot)))
                        continue;
                    vals[write_at++] = (struct input_value) {
                        EV_ABS, ABS_MT_SLOT, mapped_slot
                    };
                    vals[write_at++] = (struct input_value) {
                        EV_ABS, ABS_MT_POSITION_X, ptm.x[mapped_slot]
                    };
                    vals[write_at++] = (struct input_value) {
                        EV_ABS, ABS_MT_POSITION_Y, ptm.y[mapped_slot]
                    };
                }
                vals[write_at] = (struct input_value) {
                    EV_ABS, ABS_MT_SLOT, slot
                };
                count += needed;
                i += needed;
            } else if (mapped_new) {
                ptm.fixed_wheel_mapped_mask &= ~mapped_new;
                for (mapped_slot = 0;
                     mapped_slot < ARRAY_SIZE(ptm.tracking_ids); mapped_slot++) {
                    if (!(mapped_new & BIT(mapped_slot)))
                        continue;
                    ptm.fixed_wheel_offset_x[mapped_slot] = 0;
                    ptm.fixed_wheel_offset_y[mapped_slot] = 0;
                }
            }
            frame_new = 0;
        }
        i++;
    }
    return count;
}


static unsigned int ptm_process_values(struct input_handle *handle,
                                       struct input_value *vals,
                                       unsigned int count)
{
    unsigned long flags;
    unsigned int release_at = count;
    unsigned int original_count = count;
    unsigned int segment_at = 0;
    unsigned int i;
    bool changed = false;
    u32 fixed_wheel_released_mask = 0;
    u32 fixed_wheel_new_mask = 0;
    int redirect_slot = -1;
    int redirect_x = 0;
    int redirect_y = 0;
    int initial_slot;
    int slot;

    spin_lock_irqsave(&ptm.lock, flags);
    initial_slot = ptm.current_slot;
    if (ptm.redirect_active) {
        redirect_slot = ptm.redirect_slot;
        redirect_x = ptm.redirect_x;
        redirect_y = ptm.redirect_y;
    }

    for (i = 0; i < original_count; i++) {
        struct input_value *value = &vals[i];

        if (value->type == EV_SYN && value->code == SYN_REPORT) {
            segment_at = i + 1;
            continue;
        }
        if (value->type == EV_KEY && value->code == BTN_TOUCH) {
            ptm.physical_btn_touch_seen = true;
            ptm.physical_btn_touch = value->value != 0;
            continue;
        }
        if (value->type != EV_ABS)
            continue;

        if (value->code == ABS_MT_SLOT) {
            if (value->value >= 0 && value->value < ARRAY_SIZE(ptm.tracking_ids)) {
                ptm.current_slot = value->value;
                segment_at = i;
            }
        } else {
            slot = ptm.current_slot;
            if (slot < 0 || slot >= ARRAY_SIZE(ptm.tracking_ids))
                continue;

            if (value->code == ABS_MT_TRACKING_ID) {
                if (value->value >= 0) {
                    ptm.tracking_ids[slot] = value->value;
                    if (handle->dev->mt && slot < handle->dev->mt->num_slots) {
                        ptm.x[slot] = input_mt_get_value(
                                &handle->dev->mt->slots[slot], ABS_MT_POSITION_X);
                        ptm.y[slot] = input_mt_get_value(
                                &handle->dev->mt->slots[slot], ABS_MT_POSITION_Y);
                        ptm.x_valid_mask |= BIT(slot);
                        ptm.y_valid_mask |= BIT(slot);
                    } else {
                        ptm.x_valid_mask &= ~BIT(slot);
                        ptm.y_valid_mask &= ~BIT(slot);
                    }
                    ptm.pressure_valid_mask &= ~BIT(slot);
                    ptm.touch_major_valid_mask &= ~BIT(slot);
                    ptm.touch_minor_valid_mask &= ~BIT(slot);
                    ptm.orientation_valid_mask &= ~BIT(slot);
                    ptm.pending_mask |= BIT(slot);
                    fixed_wheel_new_mask |= BIT(slot);
                    ptm.fixed_wheel_pending_mask |= BIT(slot);
                    ptm.fixed_wheel_mapped_mask &= ~BIT(slot);
                    ptm.fixed_wheel_offset_x[slot] = 0;
                    ptm.fixed_wheel_offset_y[slot] = 0;
                } else if (ptm.tracking_ids[slot] >= 0) {
                    ptm.tracking_ids[slot] = -1;
                    ptm.x_valid_mask &= ~BIT(slot);
                    ptm.y_valid_mask &= ~BIT(slot);
                    ptm.pending_mask &= ~BIT(slot);
                    ptm.released_mask |= BIT(slot);
                    ptm.fixed_wheel_pending_mask &= ~BIT(slot);
                    fixed_wheel_released_mask |= BIT(slot);
                }

                if (value->value < 0 && redirect_slot == slot) {
                    release_at = segment_at;
                    ptm.redirect_active = false;
                    ptm.redirect_slot = -1;
                }
                ptm.reported_slot = slot;
                changed = true;
            } else if (value->code == ABS_MT_POSITION_X) {
                ptm.x[slot] = value->value;
                ptm.x_valid_mask |= BIT(slot);
                ptm.reported_slot = slot;
                changed = true;
            } else if (value->code == ABS_MT_POSITION_Y) {
                ptm.y[slot] = value->value;
                ptm.y_valid_mask |= BIT(slot);
                ptm.reported_slot = slot;
                changed = true;
            } else if (value->code == ABS_MT_PRESSURE && value->value > 0) {
                ptm.pressure[slot] = value->value;
                ptm.pressure_valid_mask |= BIT(slot);
            } else if (value->code == ABS_MT_TOUCH_MAJOR && value->value > 0) {
                ptm.touch_major[slot] = value->value;
                ptm.touch_major_valid_mask |= BIT(slot);
            } else if (value->code == ABS_MT_TOUCH_MINOR && value->value > 0) {
                ptm.touch_minor[slot] = value->value;
                ptm.touch_minor_valid_mask |= BIT(slot);
            } else if (value->code == ABS_MT_ORIENTATION) {
                ptm.orientation[slot] = value->value;
                ptm.orientation_valid_mask |= BIT(slot);
            }
        }
    }

    classify_fixed_wheel_contacts_locked();
    if (release_at == original_count) {
        original_count = complete_fixed_wheel_down_frames_locked(
                vals, original_count, ptm.capture_capacity, initial_slot,
                fixed_wheel_new_mask);
        count = original_count;
        release_at = original_count;
    }
    translate_fixed_wheel_values_locked(vals, original_count, initial_slot);

    if (release_at < original_count) {
        unsigned int suffix_count = original_count - release_at;
        unsigned int suffix_offset = 0;
        unsigned int progress = release_path_progress(ptm.seq, 0);
        int release_start_x = fixed_wheel_x_locked(redirect_slot, ptm.x[redirect_slot]);
        int release_start_y = fixed_wheel_y_locked(redirect_slot, ptm.y[redirect_slot]);
        int first_x = release_start_x +
                      div_s64((s64)(redirect_x - release_start_x) * progress, 1000);
        int first_y = release_start_y +
                      div_s64((s64)(redirect_y - release_start_y) * progress, 1000);
        bool suffix_has_slot = vals[release_at].type == EV_ABS &&
                               vals[release_at].code == ABS_MT_SLOT &&
                               vals[release_at].value == redirect_slot;

        if (suffix_count + (suffix_has_slot ? 0 : 1) <=
                    ARRAY_SIZE(ptm.deferred_release_vals) &&
            release_at + 4 <= ptm.capture_capacity &&
            !ptm.deferred_release_count) {
            unsigned int j;
            int suffix_slot = redirect_slot;

            if (!suffix_has_slot) {
                ptm.deferred_release_vals[0] =
                    (struct input_value) { EV_ABS, ABS_MT_SLOT, redirect_slot };
                suffix_offset = 1;
            }
            memcpy(&ptm.deferred_release_vals[suffix_offset], &vals[release_at],
                   suffix_count * sizeof(*vals));
            ptm.deferred_release_count = suffix_count + suffix_offset;

            for (j = 0; j < ptm.deferred_release_count; j++) {
                struct input_value *deferred = &ptm.deferred_release_vals[j];

                if (deferred->type != EV_ABS)
                    continue;
                if (deferred->code == ABS_MT_SLOT)
                    suffix_slot = deferred->value;
                else if (suffix_slot == redirect_slot &&
                         deferred->code == ABS_MT_POSITION_X)
                    deferred->value = redirect_x;
                else if (suffix_slot == redirect_slot &&
                         deferred->code == ABS_MT_POSITION_Y)
                    deferred->value = redirect_y;
            }

            ptm.release_path_slot = redirect_slot;
            ptm.release_path_start_x = release_start_x;
            ptm.release_path_start_y = release_start_y;
            ptm.release_path_target_x = redirect_x;
            ptm.release_path_target_y = redirect_y;
            ptm.release_path_step = 1;
            count = release_at + append_final_move(&vals[release_at], redirect_slot,
                                                    first_x, first_y);
            mod_delayed_work(system_wq, &ptm.deferred_release_work,
                              release_path_delay_jiffies(ptm.seq, 1));
        }
    }

    if (fixed_wheel_released_mask) {
        int released_slot;

        ptm.fixed_wheel_mapped_mask &= ~fixed_wheel_released_mask;
        for (released_slot = 0;
             released_slot < ARRAY_SIZE(ptm.tracking_ids); released_slot++) {
            if (!(fixed_wheel_released_mask & BIT(released_slot)))
                continue;
            ptm.fixed_wheel_offset_x[released_slot] = 0;
            ptm.fixed_wheel_offset_y[released_slot] = 0;
        }
    }

    if (changed)
        ptm.seq++;
    spin_unlock_irqrestore(&ptm.lock, flags);
    return count;
}

static bool ptm_filter_marker(struct input_handle *handle, unsigned int type,
                              unsigned int code, int value)
{
    struct input_value *frame = NULL;
    unsigned long flags;
    unsigned int count = 0;

    spin_lock_irqsave(&ptm.lock, flags);
    if (!ptm.capture_vals || !ptm.capture_capacity) {
        spin_unlock_irqrestore(&ptm.lock, flags);
        return false;
    }

    if (!ptm.capture_overflow) {
        if (ptm.capture_count < ptm.capture_capacity) {
            ptm.capture_vals[ptm.capture_count++] =
                (struct input_value) { type, code, value };
        } else {
            ptm.capture_count = 0;
            ptm.capture_overflow = true;
        }
    }

    if (type == EV_SYN && code == SYN_REPORT) {
        if (!ptm.capture_overflow) {
            frame = ptm.capture_vals;
            count = ptm.capture_count;
        }
        ptm.capture_count = 0;
        ptm.capture_overflow = false;
    }
    spin_unlock_irqrestore(&ptm.lock, flags);

    if (frame && count) {
        count = ptm_process_values(handle, frame, count);
        ptm_send_downstream_locked(frame, count);
    }
    return true;
}

static int ptm_connect(struct input_handler *handler, struct input_dev *dev,
                       const struct input_device_id *id)
{
    struct input_handle *handle;
    int max_x;
    int max_y;
    int ret;
    int i;
    unsigned int capture_capacity;
    unsigned int slot_count;
    struct input_value *capture_vals;

    if (!is_candidate_physical_panel(dev, &max_x, &max_y) || dev != vt.source_dev)
        return -ENODEV;

    if (dev->max_vals > 4088)
        return -E2BIG;
    slot_count = dev->mt ? min_t(unsigned int, dev->mt->num_slots,
                                 ARRAY_SIZE(ptm.tracking_ids)) : 1;
    capture_capacity = max_t(unsigned int, dev->max_vals + 8,
                             slot_count * 12 + 16);
    if (capture_capacity > 4096)
        return -E2BIG;
    capture_vals = kcalloc(capture_capacity, sizeof(*capture_vals), GFP_KERNEL);
    if (!capture_vals)
        return -ENOMEM;

    handle = &ptm.handle;
    memset(handle, 0, sizeof(*handle));
    handle->dev = dev;
    handle->handler = handler;
    handle->name = "input_frame_observer";
    spin_lock_init(&ptm.lock);
    INIT_DELAYED_WORK(&ptm.deferred_release_work, ptm_deliver_deferred_release);
    ptm.seq = 0;
    ptm.snapshot_seq = 0;
    ptm.released_mask = 0;
    ptm.pending_mask = 0;
    ptm.current_slot = 0;
    ptm.reported_slot = 0;
    ptm.snapshot_cursor = -1;
    ptm.x_valid_mask = 0;
    ptm.y_valid_mask = 0;
    ptm.pressure_valid_mask = 0;
    ptm.touch_major_valid_mask = 0;
    ptm.touch_minor_valid_mask = 0;
    ptm.orientation_valid_mask = 0;
    ptm.redirect_active = false;
    ptm.redirect_slot = -1;
    ptm.redirect_x = 0;
    ptm.redirect_y = 0;
    ptm.fixed_wheel_enabled = false;
    ptm.fixed_wheel_x = 0;
    ptm.fixed_wheel_y = 0;
    ptm.fixed_wheel_radius_x = 0;
    ptm.fixed_wheel_radius_y = 0;
    ptm.fixed_wheel_pending_mask = 0;
    ptm.fixed_wheel_mapped_mask = 0;
    ptm.deferred_release_count = 0;
    ptm.capture_vals = capture_vals;
    ptm.capture_capacity = capture_capacity;
    ptm.capture_count = 0;
    ptm.capture_overflow = false;
    ptm.release_path_slot = -1;
    ptm.release_path_start_x = 0;
    ptm.release_path_start_y = 0;
    ptm.release_path_target_x = 0;
    ptm.release_path_target_y = 0;
    ptm.release_path_step = 0;
    ptm.injected_seq = 0;
    for (i = 0; i < INJECTED_LOGICAL_SLOTS; i++) {
        ptm.injected_slots[i] = -1;
        ptm.injected_tracking_ids[i] = -1;
    }
    for (i = 0; i < ARRAY_SIZE(ptm.tracking_ids); i++) {
        ptm.tracking_ids[i] = -1;
        ptm.x[i] = 0;
        ptm.y[i] = 0;
        ptm.pressure[i] = 0;
        ptm.touch_major[i] = 0;
        ptm.touch_minor[i] = 0;
        ptm.orientation[i] = 0;
        ptm.fixed_wheel_offset_x[i] = 0;
        ptm.fixed_wheel_offset_y[i] = 0;
    }
    ptm.max_x = max_x;
    ptm.max_y = max_y;
    ptm.grab_release_count = 0;
    ptm.physical_btn_touch = false;
    ptm.physical_btn_touch_seen = false;

    ret = input_register_handle(handle);
    if (ret) {
        kfree(ptm.capture_vals);
        ptm.capture_vals = NULL;
        ptm.capture_capacity = 0;
        return ret;
    }
    ret = input_open_device(handle);
    if (ret) {
        input_unregister_handle(handle);
        kfree(ptm.capture_vals);
        ptm.capture_vals = NULL;
        ptm.capture_capacity = 0;
        return ret;
    }

    vt.source_handle = handle;
    return 0;
}

static void ptm_disconnect(struct input_handle *handle)
{
    struct input_value *capture_vals;
    unsigned long flags;

    flush_delayed_work(&ptm.deferred_release_work);
    input_close_device(handle);
    input_unregister_handle(handle);
    spin_lock_irqsave(&ptm.lock, flags);
    capture_vals = ptm.capture_vals;
    ptm.capture_vals = NULL;
    ptm.capture_capacity = 0;
    ptm.capture_count = 0;
    ptm.capture_overflow = false;
    spin_unlock_irqrestore(&ptm.lock, flags);
    kfree(capture_vals);
    if (vt.source_handle == handle)
        vt.source_handle = NULL;
}

static struct input_handler physical_touch_monitor = {
    .filter = ptm_filter_marker,
    .connect = ptm_connect,
    .disconnect = ptm_disconnect,
    .name = "input_frame_observer",
    .id_table = vtouch_ids,
};

static void release_source_grab_if_needed(void)
{
    struct input_dev *dev = vt.source_dev;
    struct input_handle *handle;
    unsigned long flags;
    bool released = false;

    if (!dev || !rcu_access_pointer(dev->grab))
        return;

    mutex_lock(&dev->mutex);
    if (rcu_access_pointer(dev->grab)) {
        rcu_assign_pointer(dev->grab, NULL);
        synchronize_rcu();
        list_for_each_entry(handle, &dev->h_list, d_node)
            if (handle->open && handle->handler->start)
                handle->handler->start(handle);
        released = true;
    }
    mutex_unlock(&dev->mutex);

    if (released) {
        spin_lock_irqsave(&ptm.lock, flags);
        ptm.grab_release_count++;
        spin_unlock_irqrestore(&ptm.lock, flags);
    }
}

static int discover_source_panel(void)
{
    int ret;

    vt.source_dev = NULL;
    source_area = 0;
    ret = input_register_handler(&vtouch_spy);
    if (ret)
        return ret;
    input_unregister_handler(&vtouch_spy);
    return vt.source_dev ? 0 : -ENODEV;
}

int v_touch_init(int *max_x, int *max_y)
{
    int ret = 0;

    if (!max_x || !max_y)
        return -EINVAL;

    mutex_lock(&vt_lock);
    if (vt.initialized) {
        *max_x = vt.max_x;
        *max_y = vt.max_y;
        mutex_unlock(&vt_lock);
        return 0;
    }

    ret = discover_source_panel();
    if (ret)
        goto out;

    vt.max_x = vt.source_dev->absinfo[ABS_MT_POSITION_X].maximum;
    vt.max_y = vt.source_dev->absinfo[ABS_MT_POSITION_Y].maximum;

    ret = input_register_handler(&physical_touch_monitor);
    if (ret)
        goto out;
    if (!vt.source_handle) {
        input_unregister_handler(&physical_touch_monitor);
        ret = -ENODEV;
        goto out;
    }

    vt.initialized = true;
    *max_x = vt.max_x;
    *max_y = vt.max_y;

out:
    if (ret) {
        vt.source_dev = NULL;
        vt.max_x = 0;
        vt.max_y = 0;
    }
    mutex_unlock(&vt_lock);
    return ret;
}

static void clear_physical_redirect(void)
{
    unsigned long flags;

    spin_lock_irqsave(&ptm.lock, flags);
    ptm.redirect_active = false;
    ptm.redirect_slot = -1;
    spin_unlock_irqrestore(&ptm.lock, flags);
}

static void clear_fixed_wheel_state(void)
{
    unsigned long flags;
    int slot;

    spin_lock_irqsave(&ptm.lock, flags);
    ptm.fixed_wheel_enabled = false;
    ptm.fixed_wheel_pending_mask = 0;
    ptm.fixed_wheel_mapped_mask = 0;
    for (slot = 0; slot < ARRAY_SIZE(ptm.tracking_ids); slot++) {
        ptm.fixed_wheel_offset_x[slot] = 0;
        ptm.fixed_wheel_offset_y[slot] = 0;
    }
    spin_unlock_irqrestore(&ptm.lock, flags);
}

static void release_injected_contacts(void)
{
    struct input_value vals[INJECTED_LOGICAL_SLOTS * 2 + 4];
    unsigned long flags;
    unsigned int count = 0;
    bool released = false;
    bool physical_active;
    int logical_slot;

    spin_lock_irqsave(&ptm.lock, flags);
    for (logical_slot = 0; logical_slot < INJECTED_LOGICAL_SLOTS; logical_slot++) {
        int slot = ptm.injected_slots[logical_slot];

        if (slot < 0)
            continue;
        append_touch_value(vals, &count, EV_ABS, ABS_MT_SLOT, slot);
        append_touch_value(vals, &count, EV_ABS, ABS_MT_TRACKING_ID, -1);
        ptm.injected_slots[logical_slot] = -1;
        ptm.injected_tracking_ids[logical_slot] = -1;
        released = true;
    }
    physical_active = physical_contact_active_locked();
    if (released && !physical_active) {
        append_touch_value(vals, &count, EV_KEY, BTN_TOUCH, 0);
        if (test_bit(BTN_TOOL_FINGER, vt.source_dev->keybit))
            append_touch_value(vals, &count, EV_KEY, BTN_TOOL_FINGER, 0);
    }
    if (released) {
        append_touch_value(vals, &count, EV_ABS, ABS_MT_SLOT,
                           clamp(ptm.current_slot, 0,
                                 vt.source_dev->mt->num_slots - 1));
        append_touch_value(vals, &count, EV_SYN, SYN_REPORT, 0);
    }
    spin_unlock_irqrestore(&ptm.lock, flags);

    if (released)
        ptm_send_downstream(vals, count);
}

int v_touch_event(const struct ls_touch_cmd *cmd)
{
    struct input_value vals[16];
    unsigned long flags;
    unsigned int count = 0;
    enum sm_req_op op;
    int logical_slot;
    int physical_slot;
    int tracking_id;
    bool had_contacts;
    bool contacts_remain;
    int ret = 0;

    if (!cmd)
        return -EINVAL;
    op = (enum sm_req_op)cmd->action;
    logical_slot = cmd->slot;
    if (op < op_down || op > op_move || logical_slot < 0 ||
        logical_slot >= INJECTED_LOGICAL_SLOTS)
        return -EINVAL;

    mutex_lock(&vt_lock);
    if (!vt.initialized || !vt.source_dev || !vt.source_dev->mt) {
        ret = -ENODEV;
        goto out;
    }

    spin_lock_irqsave(&ptm.lock, flags);
    physical_slot = ptm.injected_slots[logical_slot];
    if (op == op_down) {
        if (physical_slot >= 0) {
            ret = -EALREADY;
            goto unlock;
        }
        physical_slot = allocate_injected_slot_locked();
        if (physical_slot < 0) {
            ret = -ENOSPC;
            goto unlock;
        }
        had_contacts = physical_contact_active_locked() || injected_contact_active_locked();
        tracking_id = allocate_tracking_id_locked(logical_slot);
        ptm.injected_slots[logical_slot] = physical_slot;
        ptm.injected_tracking_ids[logical_slot] = tracking_id;
        append_touch_value(vals, &count, EV_ABS, ABS_MT_SLOT, physical_slot);
        append_touch_value(vals, &count, EV_ABS, ABS_MT_TRACKING_ID, tracking_id);
        append_touch_value(vals, &count, EV_ABS, ABS_MT_POSITION_X,
                           clamp(cmd->x, 0, vt.max_x));
        append_touch_value(vals, &count, EV_ABS, ABS_MT_POSITION_Y,
                           clamp(cmd->y, 0, vt.max_y));
        append_contact_attributes(vals, &count, cmd);
        if (!had_contacts) {
            append_touch_value(vals, &count, EV_KEY, BTN_TOUCH, 1);
            if (test_bit(BTN_TOOL_FINGER, vt.source_dev->keybit))
                append_touch_value(vals, &count, EV_KEY, BTN_TOOL_FINGER, 1);
        }
    } else if (op == op_move) {
        if (physical_slot < 0) {
            ret = -ENOENT;
            goto unlock;
        }
        append_touch_value(vals, &count, EV_ABS, ABS_MT_SLOT, physical_slot);
        append_touch_value(vals, &count, EV_ABS, ABS_MT_POSITION_X,
                           clamp(cmd->x, 0, vt.max_x));
        append_touch_value(vals, &count, EV_ABS, ABS_MT_POSITION_Y,
                           clamp(cmd->y, 0, vt.max_y));
        append_contact_attributes(vals, &count, cmd);
    } else {
        if (physical_slot < 0) {
            ret = -ENOENT;
            goto unlock;
        }
        append_touch_value(vals, &count, EV_ABS, ABS_MT_SLOT, physical_slot);
        append_touch_value(vals, &count, EV_ABS, ABS_MT_TRACKING_ID, -1);
        ptm.injected_slots[logical_slot] = -1;
        ptm.injected_tracking_ids[logical_slot] = -1;
        contacts_remain = physical_contact_active_locked() ||
                          injected_contact_active_locked();
        if (!contacts_remain) {
            append_touch_value(vals, &count, EV_KEY, BTN_TOUCH, 0);
            if (test_bit(BTN_TOOL_FINGER, vt.source_dev->keybit))
                append_touch_value(vals, &count, EV_KEY, BTN_TOOL_FINGER, 0);
        }
    }
    /* Synthetic frames bypass input_mt, so restore evdev's slot selector to
     * the physical slot before slot-less hardware MOVE events resume. */
    append_touch_value(vals, &count, EV_ABS, ABS_MT_SLOT,
                       clamp(ptm.current_slot, 0,
                             vt.source_dev->mt->num_slots - 1));
    append_touch_value(vals, &count, EV_SYN, SYN_REPORT, 0);

unlock:
    spin_unlock_irqrestore(&ptm.lock, flags);
    if (!ret)
        ptm_send_downstream(vals, count);
out:
    mutex_unlock(&vt_lock);
    return ret;
}

int v_touch_reset_contact(int logical_slot)
{
    struct input_value vals[6];
    unsigned long flags;
    unsigned int count = 0;
    int physical_slot;
    bool contacts_remain;

    if (logical_slot < 0 || logical_slot >= INJECTED_LOGICAL_SLOTS)
        return -EINVAL;

    mutex_lock(&vt_lock);
    if (!vt.initialized || !vt.source_dev || !vt.source_dev->mt) {
        mutex_unlock(&vt_lock);
        return 0;
    }

    spin_lock_irqsave(&ptm.lock, flags);
    physical_slot = ptm.injected_slots[logical_slot];
    if (physical_slot >= 0) {
        append_touch_value(vals, &count, EV_ABS, ABS_MT_SLOT, physical_slot);
        append_touch_value(vals, &count, EV_ABS, ABS_MT_TRACKING_ID, -1);
        ptm.injected_slots[logical_slot] = -1;
        ptm.injected_tracking_ids[logical_slot] = -1;
        contacts_remain = physical_contact_active_locked() ||
                          injected_contact_active_locked();
        if (!contacts_remain) {
            append_touch_value(vals, &count, EV_KEY, BTN_TOUCH, 0);
            if (test_bit(BTN_TOOL_FINGER, vt.source_dev->keybit))
                append_touch_value(vals, &count, EV_KEY, BTN_TOOL_FINGER, 0);
        }
        append_touch_value(vals, &count, EV_ABS, ABS_MT_SLOT,
                           clamp(ptm.current_slot, 0,
                                 vt.source_dev->mt->num_slots - 1));
        append_touch_value(vals, &count, EV_SYN, SYN_REPORT, 0);
    }
    spin_unlock_irqrestore(&ptm.lock, flags);

    if (count)
        ptm_send_downstream(vals, count);
    mutex_unlock(&vt_lock);
    return 0;
}

void v_touch_reset_contacts(void)
{
    mutex_lock(&vt_lock);
    if (vt.initialized) {
        flush_delayed_work(&ptm.deferred_release_work);
        release_injected_contacts();
        clear_physical_redirect();
        clear_fixed_wheel_state();
    }
    mutex_unlock(&vt_lock);
}

void v_touch_destroy(void)
{
    mutex_lock(&vt_lock);
    if (!vt.initialized) {
        mutex_unlock(&vt_lock);
        return;
    }

    flush_delayed_work(&ptm.deferred_release_work);
    release_injected_contacts();
    clear_physical_redirect();
    clear_fixed_wheel_state();
    vt.initialized = false;
    input_unregister_handler(&physical_touch_monitor);

    vt.source_dev = NULL;
    vt.source_handle = NULL;
    vt.max_x = 0;
    vt.max_y = 0;
    source_area = 0;
    mutex_unlock(&vt_lock);
}

int v_touch_get_physical_state(struct ls_physical_touch_state *out)
{
    unsigned long flags;
    int slot;
    int i;
    int candidate;

    if (!out)
        return -EINVAL;

    memset(out, 0, sizeof(*out));
    mutex_lock(&vt_lock);
    if (!vt.initialized || !vt.source_handle) {
        mutex_unlock(&vt_lock);
        return -ENODEV;
    }

    spin_lock_irqsave(&ptm.lock, flags);
    slot = clamp(ptm.reported_slot, 0, (int)ARRAY_SIZE(ptm.tracking_ids) - 1);

    /*
     * A game normally keeps the movement stick and a skill wheel down at the
     * same time.  Returning only reported_slot lets the continuously moving
     * stick hide a newly pressed skill slot.  Prefer complete new contacts,
     * then round-robin all complete active contacts so userspace observes every
     * finger without changing the ABI or the captured coordinates.
     */
    for (i = 0; i < ARRAY_SIZE(ptm.tracking_ids); i++) {
        candidate = (ptm.snapshot_cursor + 1 + i) %
                    ARRAY_SIZE(ptm.tracking_ids);
        if ((ptm.pending_mask & BIT(candidate)) &&
            ptm.tracking_ids[candidate] >= 0 &&
            (ptm.x_valid_mask & BIT(candidate)) &&
            (ptm.y_valid_mask & BIT(candidate))) {
            slot = candidate;
            ptm.pending_mask &= ~BIT(candidate);
            break;
        }
    }
    if (i == ARRAY_SIZE(ptm.tracking_ids)) {
        for (i = 0; i < ARRAY_SIZE(ptm.tracking_ids); i++) {
            candidate = (ptm.snapshot_cursor + 1 + i) %
                        ARRAY_SIZE(ptm.tracking_ids);
            if (ptm.tracking_ids[candidate] >= 0 &&
                (ptm.x_valid_mask & BIT(candidate)) &&
                (ptm.y_valid_mask & BIT(candidate))) {
                slot = candidate;
                break;
            }
        }
    }
    if (ptm.tracking_ids[slot] >= 0 &&
        (ptm.x_valid_mask & BIT(slot)) && (ptm.y_valid_mask & BIT(slot)))
        ptm.snapshot_cursor = slot;
    out->abi_version = LS_TOUCH_ABI_VERSION;
    out->seq = ++ptm.snapshot_seq;
    out->active = ptm.tracking_ids[slot] >= 0 &&
                  (ptm.x_valid_mask & BIT(slot)) &&
                  (ptm.y_valid_mask & BIT(slot));
    out->slot = slot;
    out->x = ptm.x[slot];
    out->y = ptm.y[slot];
    out->max_x = ptm.max_x;
    out->max_y = ptm.max_y;
    out->released_mask = ptm.released_mask;
    out->_pad = ptm.grab_release_count;
    out->pressure = ptm.pressure[slot];
    out->touch_major = ptm.touch_major[slot];
    out->touch_minor = ptm.touch_minor[slot];
    out->orientation = ptm.orientation[slot];
    out->attribute_mask = 0;
    if (ptm.pressure_valid_mask & BIT(slot))
        out->attribute_mask |= LS_TOUCH_ATTR_PRESSURE;
    if (ptm.touch_major_valid_mask & BIT(slot))
        out->attribute_mask |= LS_TOUCH_ATTR_TOUCH_MAJOR;
    if (ptm.touch_minor_valid_mask & BIT(slot))
        out->attribute_mask |= LS_TOUCH_ATTR_TOUCH_MINOR;
    if (ptm.orientation_valid_mask & BIT(slot))
        out->attribute_mask |= LS_TOUCH_ATTR_ORIENTATION;
    ptm.released_mask = 0;
    spin_unlock_irqrestore(&ptm.lock, flags);

    mutex_unlock(&vt_lock);
    return 0;
}

static bool retarget_deferred_release_locked(int slot, int x, int y)
{
    unsigned int i;
    int deferred_slot = -1;

    if (!ptm.deferred_release_count || ptm.release_path_slot != slot)
        return false;

    ptm.release_path_target_x = x;
    ptm.release_path_target_y = y;
    for (i = 0; i < ptm.deferred_release_count; i++) {
        struct input_value *deferred = &ptm.deferred_release_vals[i];

        if (deferred->type != EV_ABS)
            continue;
        if (deferred->code == ABS_MT_SLOT)
            deferred_slot = deferred->value;
        else if (deferred_slot == slot &&
                 deferred->code == ABS_MT_POSITION_X)
            deferred->value = x;
        else if (deferred_slot == slot &&
                 deferred->code == ABS_MT_POSITION_Y)
            deferred->value = y;
    }
    return true;
}

int v_touch_redirect_physical(int slot, int x, int y)
{
    unsigned long monitor_flags;
    int redirect_x;
    int redirect_y;

    mutex_lock(&vt_lock);
    if (!vt.initialized || !vt.source_dev || !vt.source_dev->mt ||
        slot < 0 || slot >= vt.source_dev->mt->num_slots ||
        slot >= ARRAY_SIZE(ptm.tracking_ids)) {
        mutex_unlock(&vt_lock);
        return -EINVAL;
    }

    redirect_x = clamp(x, 0, vt.max_x);
    redirect_y = clamp(y, 0, vt.max_y);
    spin_lock_irqsave(&ptm.lock, monitor_flags);
    if (ptm.tracking_ids[slot] < 0) {
        if (retarget_deferred_release_locked(slot, redirect_x, redirect_y)) {
            spin_unlock_irqrestore(&ptm.lock, monitor_flags);
            mutex_unlock(&vt_lock);
            return 0;
        }
        spin_unlock_irqrestore(&ptm.lock, monitor_flags);
        mutex_unlock(&vt_lock);
        return -ENOENT;
    }
    ptm.redirect_slot = slot;
    ptm.redirect_x = redirect_x;
    ptm.redirect_y = redirect_y;
    ptm.redirect_active = true;
    spin_unlock_irqrestore(&ptm.lock, monitor_flags);

    mutex_unlock(&vt_lock);
    return 0;
}

int v_touch_clear_physical_redirect(int slot)
{
    unsigned long flags;

    if (slot < 0 || slot >= ARRAY_SIZE(ptm.tracking_ids))
        return -EINVAL;

    spin_lock_irqsave(&ptm.lock, flags);
    if (ptm.redirect_slot == slot) {
        ptm.redirect_active = false;
        ptm.redirect_slot = -1;
    }
    spin_unlock_irqrestore(&ptm.lock, flags);
    return 0;
}

int v_touch_configure_fixed_wheel(int x, int y, int radius_x, int radius_y)
{
    unsigned long flags;

    if (radius_x <= 0 || radius_y <= 0)
        return -EINVAL;
    mutex_lock(&vt_lock);
    if (!vt.initialized || !vt.source_dev || !vt.source_dev->mt) {
        mutex_unlock(&vt_lock);
        return -ENODEV;
    }
    spin_lock_irqsave(&ptm.lock, flags);
    ptm.fixed_wheel_x = clamp(x, 0, ptm.max_x);
    ptm.fixed_wheel_y = clamp(y, 0, ptm.max_y);
    ptm.fixed_wheel_radius_x = clamp(radius_x, 1, max_t(int, 1, ptm.max_x));
    ptm.fixed_wheel_radius_y = clamp(radius_y, 1, max_t(int, 1, ptm.max_y));
    ptm.fixed_wheel_enabled = true;
    spin_unlock_irqrestore(&ptm.lock, flags);
    mutex_unlock(&vt_lock);
    return 0;
}

int v_touch_clear_fixed_wheel(void)
{
    unsigned long flags;

    mutex_lock(&vt_lock);
    if (!vt.initialized) {
        mutex_unlock(&vt_lock);
        return 0;
    }
    spin_lock_irqsave(&ptm.lock, flags);
    ptm.fixed_wheel_enabled = false;
    ptm.fixed_wheel_pending_mask = 0;
    spin_unlock_irqrestore(&ptm.lock, flags);
    mutex_unlock(&vt_lock);
    return 0;
}
