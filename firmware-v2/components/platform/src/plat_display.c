// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "platform/plat_display.h"

#include <stddef.h>

static const plat_display_ops_t *s_ops;

void plat_display_bind(const plat_display_ops_t *ops) {
    s_ops = ops;
}

esp_err_t plat_lcd_init(plat_lcd_t *lcd) {
    if (s_ops == NULL || s_ops->lcd_init == NULL) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    return s_ops->lcd_init(lcd);
}

void plat_lcd_backlight(bool on) {
    if (s_ops != NULL && s_ops->backlight != NULL) {
        s_ops->backlight(on);
    }
}

esp_err_t plat_touch_init(void) {
    if (s_ops == NULL || s_ops->touch_init == NULL) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    return s_ops->touch_init();
}

bool plat_touch_read(int *raw_x, int *raw_y) {
    if (s_ops == NULL || s_ops->touch_read == NULL) {
        return false;
    }
    return s_ops->touch_read(raw_x, raw_y);
}
