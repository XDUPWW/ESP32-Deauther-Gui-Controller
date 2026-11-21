// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool (*screen)(int count);
    void (*status)(char *buf, size_t cap);
    void (*touch)(char *buf, size_t cap);
    bool (*touch_cal)(bool reset);
    bool (*tap)(int x, int y);
    void (*dump)(void);
} services_ui_ops_t;

void services_ui_bind(const services_ui_ops_t *ops);

void services_start(void);

void services_tick(uint32_t now_ms);
