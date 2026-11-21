// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define UI_CALIB_INSET 20

typedef struct {
    bool valid;
    uint8_t axis_x;
    uint8_t axis_y;
    float off_x;
    float gain_x;
    float off_y;
    float gain_y;
    float inset;
} ui_calib_t;

void ui_calib_defaults(ui_calib_t *calib);

bool ui_calib_solve(const int16_t raw[4][2], int16_t width, int16_t height, int16_t inset,
                    ui_calib_t *calib);

bool ui_calib_load(ui_calib_t *calib);

void ui_calib_save(const ui_calib_t *calib);

void ui_calib_clear(void);

void ui_calib_apply(const ui_calib_t *calib, int raw_x, int raw_y, int width, int height,
                    int *screen_x, int *screen_y);
