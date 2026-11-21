// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>

bool wireless_ui_start(void);

bool wireless_ui_ready(void);

void wireless_ui_calib_reset(void);

bool wireless_ui_selftest(void);
