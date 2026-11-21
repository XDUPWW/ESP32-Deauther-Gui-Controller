// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

// 板级显示/触摸端口的输出参数。面板类型不在这里体现，UI 只认这些字段。
typedef struct {
    void *panel;
    void *io;
    int16_t width;
    int16_t height;
    bool swap_xy;
    bool mirror_x;
    bool mirror_y;
} plat_lcd_t;

// 一块板要接屏幕，就实现这四个并把表 bind 进来；没 bind 就是无屏。
typedef struct {
    esp_err_t (*lcd_init)(plat_lcd_t *lcd);
    void (*backlight)(bool on);
    esp_err_t (*touch_init)(void);
    bool (*touch_read)(int *raw_x, int *raw_y);
} plat_display_ops_t;

void plat_display_bind(const plat_display_ops_t *ops);

esp_err_t plat_lcd_init(plat_lcd_t *lcd);

void plat_lcd_backlight(bool on);

esp_err_t plat_touch_init(void);

// 返回 true 表示此刻有手指按住，raw_x/raw_y 给的是触摸芯片的原始值。
bool plat_touch_read(int *raw_x, int *raw_y);
