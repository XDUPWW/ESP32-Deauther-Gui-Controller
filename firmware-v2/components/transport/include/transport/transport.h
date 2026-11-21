// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

typedef struct transport_plugin transport_plugin_t;

struct transport_plugin {
    const char *name;
    esp_err_t (*start)(transport_plugin_t *self);
    void (*stop)(transport_plugin_t *self);
    void (*poll)(transport_plugin_t *self, uint32_t now_ms);
    void (*line_out)(transport_plugin_t *self, const char *line);
    void *ctx;
};

esp_err_t transport_start(void);

esp_err_t transport_add(transport_plugin_t *plugin);

esp_err_t transport_submit(const char *line);

void transport_out(const char *line);

transport_plugin_t *transport_serial_text(void);

transport_plugin_t *transport_ble_text(void);
