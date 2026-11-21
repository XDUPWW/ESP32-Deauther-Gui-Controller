// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include <stdio.h>

#include "esp_system.h"
#include "esp_timer.h"
#include "platform/plat_display.h"
#include "services_private.h"
#include "wbus/wbus.h"

static esp_err_t system_ping(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    wb_reply_line(reply, "pong ms=%u", (unsigned)(esp_timer_get_time() / 1000));
    return ESP_OK;
}

static esp_err_t system_info(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    wb_reply_line(reply, "idf=%s", esp_get_idf_version());
    wb_reply_line(reply, "uptime_s=%u", (unsigned)(esp_timer_get_time() / 1000000));
    wb_reply_line(reply, "heap=%u min_heap=%u", (unsigned)esp_get_free_heap_size(),
                  (unsigned)esp_get_minimum_free_heap_size());
    wb_reply_line(reply, "objects=%u", (unsigned)wb_count());
    return ESP_OK;
}

static esp_err_t system_help(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    for (size_t i = 0; i < wb_count(); i++) {
        const wb_object_t *object = wb_at(i);
        for (uint8_t m = 0; m < object->n_methods; m++) {
            const wb_method_t *method = &object->methods[m];
            wb_reply_line(reply, "%-12s %-16s %s", object->name, method->name,
                          method->sig != NULL ? method->sig : "");
        }
    }
    return ESP_OK;
}

static esp_err_t system_touch(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    const services_ui_ops_t *ui = services_ui_ops();
    char text[WB_LINE_MAX];
    text[0] = '\0';
    if (ui->touch != NULL) {
        ui->touch(text, sizeof(text));
    }
    if (text[0] != '\0') {
        wb_reply_line(reply, "%s", text);
        return ESP_OK;
    }
    int raw_x = 0;
    int raw_y = 0;
    const bool pressed = plat_touch_read(&raw_x, &raw_y);
    wb_reply_line(reply, "touch raw_x=%d raw_y=%d pressed=%d", raw_x, raw_y, pressed ? 1 : 0);
    return ESP_OK;
}

static esp_err_t system_reset(wb_args_t *args, wb_reply_t *reply) {
    (void)args;
    wb_reply_line(reply, "restarting");
    esp_restart();
    return ESP_OK;
}

static const wb_method_t kSystemMethods[] = {
    {"ping", system_ping, "", NULL, 0},
    {"info", system_info, "", NULL, 0},
    {"help", system_help, "", NULL, 0},
    {"touch", system_touch, "", NULL, 0},
    {"reset", system_reset, "", NULL, 0},
};

static const wb_object_t kSystemObject = {
    .name = "system",
    .methods = kSystemMethods,
    .n_methods = sizeof(kSystemMethods) / sizeof(kSystemMethods[0]),
};

const wb_object_t *services_system_object(void) {
    return &kSystemObject;
}
