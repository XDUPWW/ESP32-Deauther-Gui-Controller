// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include <string.h>

#include "esp_log.h"
#include "platform/plat_console.h"
#include "transport/transport.h"
#include "wbus/wbus.h"

static const char *TAG = "transport.serial";

#define LINE_CAP WB_LINE_MAX

typedef struct {
    transport_plugin_t plugin;
    char line[LINE_CAP];
    size_t len;
    bool overflow;
} serial_text_t;

static serial_text_t s_serial;

static esp_err_t serial_start(transport_plugin_t *self) {
    (void)self;
    return plat_console_init();
}

static void serial_line_out(transport_plugin_t *self, const char *line) {
    (void)self;
    plat_console_write(line);
    plat_console_write("\r\n");
}

static void serial_poll(transport_plugin_t *self, uint32_t now_ms) {
    (void)now_ms;
    serial_text_t *s = (serial_text_t *)self;
    uint8_t chunk[64];
    const int n = plat_console_read(chunk, sizeof(chunk), 10);
    for (int i = 0; i < n; i++) {
        const char c = (char)chunk[i];
        if (c == '\r' || c == '\n') {
            if (s->overflow) {
                transport_out("ERR syntax: line too long");
                s->overflow = false;
                s->len = 0;
                continue;
            }
            if (s->len == 0) {
                continue;
            }
            s->line[s->len] = '\0';
            s->len = 0;
            transport_submit(s->line);
            continue;
        }
        if (c == '\b' || c == 0x7F) {
            if (s->len > 0) {
                s->len--;
            }
            continue;
        }
        if ((unsigned char)c < 0x20) {
            continue;
        }
        if (s->len + 1 >= sizeof(s->line)) {
            s->overflow = true;
            s->len = 0;
            continue;
        }
        s->line[s->len++] = c;
    }
}

transport_plugin_t *transport_serial_text(void) {
    if (s_serial.plugin.name == NULL) {
        s_serial.plugin.name = "serial";
        s_serial.plugin.start = serial_start;
        s_serial.plugin.poll = serial_poll;
        s_serial.plugin.line_out = serial_line_out;
        ESP_LOGI(TAG, "plugin ready");
    }
    return &s_serial.plugin;
}
