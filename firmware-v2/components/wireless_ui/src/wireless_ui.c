// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "wireless_ui/wireless_ui.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "platform/plat_console.h"
#include "transport/transport.h"
#include "ui_calib.h"
#include "ui_home.h"
#include "ui_port.h"

static const char *TAG = "wireless_ui";

#define LOG_QUEUE_DEPTH 12
#define LOG_LINE_LEN 64
#define TICK_PERIOD_MS 200
#define SELFTEST_STEP_MS 350

static const uint32_t kTestColors[] = {0xFF0000, 0x00FF00, 0x0000FF, 0xFFFFFF};
#define TEST_COLOR_COUNT (sizeof(kTestColors) / sizeof(kTestColors[0]))

static QueueHandle_t s_logs;
static bool s_ready;
static int s_test_step = -1;
static int s_test_limit = (int)TEST_COLOR_COUNT;
static uint32_t s_test_stamp;
static lv_obj_t *s_test_cover;

static void ui_line_out(transport_plugin_t *self, const char *line) {
    (void)self;
    if (s_logs == NULL || line == NULL) {
        return;
    }
    char copy[LOG_LINE_LEN];
    strncpy(copy, line, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
    xQueueSend(s_logs, copy, 0);
}

static transport_plugin_t s_plugin = {
    .name = "lvgl",
    .line_out = ui_line_out,
};

static void selftest_tick(void) {
    if (s_test_step < 0) {
        return;
    }
    const uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    if (s_test_step == 0) {
        s_test_cover = lv_obj_create(lv_layer_top());
        lv_obj_set_size(s_test_cover, LV_PCT(100), LV_PCT(100));
        lv_obj_center(s_test_cover);
        lv_obj_set_style_radius(s_test_cover, 0, 0);
        lv_obj_set_style_border_width(s_test_cover, 0, 0);
        lv_obj_set_style_bg_opa(s_test_cover, LV_OPA_COVER, 0);
        s_test_stamp = now;
    }
    if (s_test_step > 0 && (now - s_test_stamp) < SELFTEST_STEP_MS) {
        return;
    }
    if (s_test_step >= s_test_limit) {
        lv_obj_delete(s_test_cover);
        s_test_cover = NULL;
        s_test_step = -1;
        return;
    }
    lv_obj_set_style_bg_color(s_test_cover, lv_color_hex(kTestColors[s_test_step]), 0);
    s_test_step++;
    s_test_stamp = now;
}

static void ui_tick(lv_timer_t *timer) {
    (void)timer;
    char line[LOG_LINE_LEN];
    while (s_logs != NULL && xQueueReceive(s_logs, line, 0) == pdTRUE) {
        ui_home_push_line(line);
    }
    selftest_tick();
    ui_home_refresh((uint32_t)(esp_timer_get_time() / 1000000),
                    (uint32_t)(esp_get_free_heap_size() / 1024));
}

void wireless_ui_calib_reset(void) {
    ui_calib_clear();
    ui_calib_t calib;
    ui_calib_defaults(&calib);
    ui_port_set_calib(&calib);
}

bool wireless_ui_ready(void) {
    return s_ready;
}

bool wireless_ui_selftest(int count) {
    if (!s_ready) {
        return false;
    }
    if (count <= 0 || count > (int)TEST_COLOR_COUNT) {
        count = (int)TEST_COLOR_COUNT;
    }
    s_test_limit = count;
    s_test_step = 0;
    return true;
}

void wireless_ui_status(char *buf, size_t cap) {
    if (buf == NULL || cap == 0) {
        return;
    }
    snprintf(buf, cap, "ready=%d flush=%u heap=%uKB", s_ready ? 1 : 0,
             (unsigned)ui_port_flush_count(), (unsigned)(esp_get_free_heap_size() / 1024));
}

bool wireless_ui_start(void) {
    if (s_ready) {
        return true;
    }

    ui_calib_t calib;
    if (!ui_calib_load(&calib)) {
        ui_calib_defaults(&calib);
    }

    if (!ui_port_start(NULL, NULL)) {
        ESP_LOGE(TAG, "display port failed");
        return false;
    }
    ui_port_set_calib(&calib);

    s_logs = xQueueCreate(LOG_QUEUE_DEPTH, LOG_LINE_LEN);
    if (s_logs == NULL) {
        ESP_LOGE(TAG, "log queue alloc failed");
        return false;
    }

    if (!ui_port_lock(0)) {
        ESP_LOGE(TAG, "lvgl lock failed");
        return false;
    }
    ui_home_create();
    lv_timer_create(ui_tick, TICK_PERIOD_MS, NULL);
    ui_port_unlock();

    if (transport_add(&s_plugin) != ESP_OK) {
        ESP_LOGW(TAG, "plugin registration failed");
    }
    s_ready = true;
    ESP_LOGI(TAG, "ui ready");
    return true;
}
