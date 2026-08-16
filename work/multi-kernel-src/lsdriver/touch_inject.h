#ifndef TOUCH_INJECT_H
#define TOUCH_INJECT_H

#include <linux/input.h>
#include <linux/types.h>

enum sm_req_op {
    op_down = 0,
    op_up = 1,
    op_move = 2,
    op_redirect_physical = 3,
    op_clear_physical_redirect = 4,
    op_reset_contact = 5,
    op_configure_fixed_wheel = 6,
    op_clear_fixed_wheel = 7
};

/* Physical-panel observer and in-frame coordinate redirect state. */
struct vt_context {
    struct input_dev *source_dev;
    struct input_handle *source_handle;
    int max_x;
    int max_y;
    bool initialized;
};

extern struct vt_context vt;

struct ls_physical_touch_state;
struct ls_touch_cmd;

int v_touch_init(int *max_x, int *max_y);
int v_touch_event(const struct ls_touch_cmd *cmd);
int v_touch_reset_contact(int logical_slot);
void v_touch_reset_contacts(void);
void v_touch_destroy(void);
int v_touch_redirect_physical(int slot, int x, int y);
int v_touch_clear_physical_redirect(int slot);
int v_touch_configure_fixed_wheel(int x, int y, int radius_x, int radius_y);
int v_touch_clear_fixed_wheel(void);
int v_touch_get_physical_state(struct ls_physical_touch_state *out);

#endif
