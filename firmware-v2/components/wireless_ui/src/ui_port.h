// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "lvgl.h"
#include "ui_calib.h"

bool ui_port_start(int16_t *width, int16_t *height);

bool ui_port_lock(uint32_t timeout_ms);

void ui_port_unlock(void);

void ui_port_set_calib(const ui_calib_t *calib);

bool ui_port_touch_raw(int *raw_x, int *raw_y);

uint32_t ui_port_flush_count(void);
