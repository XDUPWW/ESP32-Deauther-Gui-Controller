// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "wbus/wbus.h"

typedef struct attack_driver attack_driver_t;

struct attack_driver {
    const char *name;
    const wb_object_t *object;
    esp_err_t (*start)(wb_args_t *args);
    void (*stop)(void);
    void (*tick)(uint32_t now_ms);
    uint32_t (*frames)(void);
    bool (*active)(void);
};

esp_err_t attack_register(const attack_driver_t *driver);

const attack_driver_t *attack_find(const char *name);

const attack_driver_t *attack_at(size_t index);

size_t attack_count(void);

void attacks_start(void);

void attacks_stop_all(void);

void attacks_tick(uint32_t now_ms);
