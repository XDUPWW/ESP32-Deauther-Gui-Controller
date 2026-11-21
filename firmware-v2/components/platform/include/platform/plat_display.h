// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

typedef struct {
    void *panel;
    void *io;
    int16_t width;
    int16_t height;
} plat_lcd_t;

esp_err_t plat_lcd_init(plat_lcd_t *lcd);

void plat_lcd_backlight(bool on);

esp_err_t plat_touch_init(void);

bool plat_touch_read(int *raw_x, int *raw_y);
