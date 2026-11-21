// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

esp_err_t plat_storage_init(void);

bool plat_storage_get(const char *key, void *buf, size_t len);

esp_err_t plat_storage_set(const char *key, const void *buf, size_t len);

esp_err_t plat_storage_erase(const char *key);
