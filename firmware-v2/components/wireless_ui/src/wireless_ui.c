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
#include "ui_touch_cal.h"

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

bool wireless_ui_touch_calib(bool reset) {
    if (!s_ready) {
        return false;
    }
    if (reset) {
        ui_calib_clear();
    }
    if (!ui_port_lock(100)) {
        return false;
    }
    const bool ok = ui_touch_cal_start();
    ui_port_unlock();
    return ok;
}

void wireless_ui_touch_report(char *buf, size_t cap) {    if (buf == NULL || cap == 0) {
        return;
    }
    if (!s_ready) {
        snprintf(buf, cap, "touch no display");
        return;
    }
    // 显示 buffer 压到 8 行之后刷新更密，LVGL 任务占锁时间变长，
    // 50ms 经常抢不到，这里给足一轮刷新的时间
    if (!ui_port_lock(200)) {
        snprintf(buf, cap, "touch busy");
        return;
    }
    int raw_x = 0;
    int raw_y = 0;
    const bool pressed = ui_port_touch_raw(&raw_x, &raw_y);
    int x = 0;
    int y = 0;
    ui_port_touch_map(raw_x, raw_y, &x, &y);
    ui_port_unlock();
    snprintf(buf, cap, "touch raw_x=%d raw_y=%d x=%d y=%d pressed=%d", raw_x, raw_y, x, y,
             pressed ? 1 : 0);
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

static void dump_obj(lv_obj_t *obj, int depth) {
    if (obj == NULL || depth > 6) {
        return;
    }
    lv_area_t a;
    lv_obj_get_coords(obj, &a);
    const char *cls = "obj";
    char text[24] = "";
    if (lv_obj_check_type(obj, &lv_label_class)) {
        cls = "label";
        const char *t = lv_label_get_text(obj);
        if (t != NULL) {
            size_t i = 0;
            for (; i < sizeof(text) - 1 && t[i] != '\0'; i++) {
                text[i] = (t[i] == '\n') ? ' ' : t[i];
            }
            text[i] = '\0';
        }
    } else if (lv_obj_check_type(obj, &lv_button_class)) {
        cls = "btn";
    } else if (lv_obj_check_type(obj, &lv_image_class)) {
        cls = "img";
    }
    char indent[9];
    const int pad = (depth < 4) ? depth * 2 : 8;
    memset(indent, ' ', (size_t)pad);
    indent[pad] = '\0';
    const char flags[3] = {
        lv_obj_has_flag(obj, LV_OBJ_FLAG_CLICKABLE) ? 'c' : '-',
        lv_obj_has_flag(obj, LV_OBJ_FLAG_HIDDEN) ? 'h' : '-',
        '\0',
    };
    char line[96];
    snprintf(line, sizeof(line), "UI %s%-6s %s %3d,%3d %3dx%-3d %.20s", indent, cls, flags,
             (int)a.x1, (int)a.y1, (int)(a.x2 - a.x1 + 1), (int)(a.y2 - a.y1 + 1), text);
    transport_out(line);
    const uint32_t n = lv_obj_get_child_count(obj);
    for (uint32_t i = 0; i < n; i++) {
        dump_obj(lv_obj_get_child(obj, (int32_t)i), depth + 1);
    }
}

void wireless_ui_dump(void) {
    if (!s_ready) {
        transport_out("WARN ui.dump: no display");
        return;
    }
    if (!ui_port_lock(120)) {
        transport_out("WARN ui.dump: lock timeout");
        return;
    }
    transport_out("UI screen");
    dump_obj(lv_screen_active(), 1);
    transport_out("UI top layer");
    dump_obj(lv_layer_top(), 1);
    ui_port_unlock();
}

bool wireless_ui_tap(int x, int y) {
    if (!s_ready || x < 0 || y < 0) {
        return false;
    }
    if (!ui_port_lock(120)) {
        return false;
    }
    ui_port_tap(x, y);
    ui_port_unlock();
    return true;
}

bool wireless_ui_start(void) {
    if (s_ready) {
        return true;
    }

    ui_calib_t calib;
    const bool calibrated = ui_calib_load(&calib);
    if (!calibrated) {
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
    if (!calibrated) {
        // 没存过校准值就直接进四点校准，默认映射只是按别人的板子猜的
        (void)ui_touch_cal_start();
    }
    ui_port_unlock();

    if (transport_add(&s_plugin) != ESP_OK) {
        ESP_LOGW(TAG, "plugin registration failed");
    }
    s_ready = true;
    ESP_LOGI(TAG, "ui ready");
    return true;
}
