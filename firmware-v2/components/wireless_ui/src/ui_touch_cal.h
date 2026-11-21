// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>

// 起四点触摸校准：屏幕上依次出现四个圆点，按提示点完就算完事，结果存 NVS。
// 已经在校准中再次调用会从头开始。
bool ui_touch_cal_start(void);
