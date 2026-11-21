// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

esp_err_t plat_console_init(void);

int plat_console_read(uint8_t *buf, size_t cap, uint32_t timeout_ms);

void plat_console_write(const char *text);

void plat_console_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
