// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "board_cyd/board_cyd.h"

#include <stddef.h>

#if CONFIG_WB_BOARD_CYD
esp_err_t cyd_lcd_init(plat_lcd_t *lcd);
void cyd_backlight(bool on);
esp_err_t cyd_touch_init(void);
bool cyd_touch_read(int *raw_x, int *raw_y);

static const plat_display_ops_t kOps = {
    .lcd_init = cyd_lcd_init,
    .backlight = cyd_backlight,
    .touch_init = cyd_touch_init,
    .touch_read = cyd_touch_read,
};
#endif

const plat_display_ops_t *board_cyd_display_ops(void) {
#if CONFIG_WB_BOARD_CYD
    return &kOps;
#else
    return NULL;
#endif
}
