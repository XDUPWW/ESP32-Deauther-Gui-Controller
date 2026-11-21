// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "lvgl.h"

void ui_home_create(void);

void ui_home_push_line(const char *line);

void ui_home_refresh(uint32_t uptime_s, uint32_t heap_kb);

void ui_home_set_led_state(bool on);
