// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>

#include "esp_err.h"

esp_err_t plat_led_init(void);

void plat_led_set(bool on);
