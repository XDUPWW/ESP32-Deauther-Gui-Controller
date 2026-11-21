// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>

bool wireless_ui_start(void);

bool wireless_ui_ready(void);

bool wireless_ui_selftest(int count);

void wireless_ui_status(char *buf, size_t cap);

void wireless_ui_calib_reset(void);
