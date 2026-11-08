#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "calib.h"
#include "lvgl.h"

#ifdef __cplusplus
extern "C" {
#endif

// Brings up the LCD + touch and registers them with LVGL. Private to the
// wireless_ui component: nothing outside ever includes this header.
lv_display_t *wireless_ui_port_init(void);
// Debug readback for calibration: raw XPT2046 values + mapped screen point.
bool wireless_ui_port_touch_read(int *raw_x, int *raw_y, int *screen_x, int *screen_y,
                                 bool *pressed);
int wireless_ui_port_touch_irq_level(void);
void wireless_ui_port_set_calib(const wui_calib_t *calib);
const wui_calib_t *wireless_ui_port_get_calib(void);
bool wireless_ui_port_lock(uint32_t timeout_ms);
void wireless_ui_port_unlock(void);

#ifdef __cplusplus
}
#endif
