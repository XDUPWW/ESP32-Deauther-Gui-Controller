// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "ui_port.h"

#include "esp_lcd_panel_ops.h"
#include "esp_log.h"
#include "esp_lvgl_port.h"
#include "platform/plat_display.h"

static const char *TAG = "ui_port";

// 每块 320*N*2 字节，直接从堆里出。N 越大刷得越少但堆越紧，
// 这块板子还要留堆给 WiFi 注入和 BLE。
#define LCD_DRAW_LINES 8

static ui_calib_t s_calib;
static lv_display_t *s_disp;
static volatile uint32_t s_flush_count;
static int s_tap_x;
static int s_tap_y;
static int s_tap_press;
static int s_tap_wait;

static void on_flush_start(lv_event_t *event) {
    if (lv_event_get_code(event) == LV_EVENT_FLUSH_START) {
        s_flush_count++;
    }
}

uint32_t ui_port_flush_count(void) {
    return s_flush_count;
}

static void touch_read_cb(lv_indev_t *indev, lv_indev_data_t *data) {
    (void)indev;
    static int16_t last_x;
    static int16_t last_y;
    int raw_x = 0;
    int raw_y = 0;
    const bool pressed = plat_touch_read(&raw_x, &raw_y);
    if (pressed) {
        int sx = 0;
        int sy = 0;
        ui_calib_apply(&s_calib, raw_x, raw_y, (int)lv_display_get_horizontal_resolution(s_disp),
                       (int)lv_display_get_vertical_resolution(s_disp), &sx, &sy);
        last_x = (int16_t)sx;
        last_y = (int16_t)sy;
    }
    data->point.x = last_x;
    data->point.y = last_y;
    data->state = pressed ? LV_INDEV_STATE_PRESSED : LV_INDEV_STATE_RELEASED;
}

void ui_port_set_calib(const ui_calib_t *calib) {
    if (calib != NULL && calib->valid) {
        s_calib = *calib;
    }
}

// 软件点一下屏幕：绕开触摸硬件，专门用来看按钮本身有没有接上事件
static void tap_read_cb(lv_indev_t *indev, lv_indev_data_t *data) {
    (void)indev;
    if (s_tap_press > 0) {
        s_tap_press--;
        data->state = LV_INDEV_STATE_PRESSED;
    } else {
        if (s_tap_wait > 0) {
            s_tap_wait--;
        }
        data->state = LV_INDEV_STATE_RELEASED;
    }
    data->point.x = (int16_t)s_tap_x;
    data->point.y = (int16_t)s_tap_y;
}

void ui_port_tap(int x, int y) {
    s_tap_x = x;
    s_tap_y = y;
    s_tap_press = 3;
    s_tap_wait = 3;
}

bool ui_port_touch_raw(int *raw_x, int *raw_y) {
    return plat_touch_read(raw_x, raw_y);
}

bool ui_port_touch_map(int raw_x, int raw_y, int *screen_x, int *screen_y) {
    if (s_disp == NULL) {
        return false;
    }
    ui_calib_apply(&s_calib, raw_x, raw_y, (int)lv_display_get_horizontal_resolution(s_disp),
                   (int)lv_display_get_vertical_resolution(s_disp), screen_x, screen_y);
    return true;
}

bool ui_port_lock(uint32_t timeout_ms) {
    return lvgl_port_lock(timeout_ms);
}

void ui_port_unlock(void) {
    lvgl_port_unlock();
}

bool ui_port_start(int16_t *width, int16_t *height) {
    plat_lcd_t lcd;
    if (plat_lcd_init(&lcd) != ESP_OK) {
        ESP_LOGE(TAG, "lcd init failed");
        return false;
    }

    const lvgl_port_cfg_t port_cfg = ESP_LVGL_PORT_INIT_CONFIG();
    if (lvgl_port_init(&port_cfg) != ESP_OK) {
        ESP_LOGE(TAG, "lvgl port init failed");
        return false;
    }

    const lvgl_port_display_cfg_t disp_cfg = {
        .io_handle = lcd.io,
        .panel_handle = lcd.panel,
        .buffer_size = (uint32_t)lcd.width * LCD_DRAW_LINES,
        .double_buffer = false,
        .hres = (uint32_t)lcd.width,
        .vres = (uint32_t)lcd.height,
        .monochrome = false,
        .color_format = LV_COLOR_FORMAT_RGB565,
        .rotation =
            {
                .swap_xy = lcd.swap_xy,
                .mirror_x = lcd.mirror_x,
                .mirror_y = lcd.mirror_y,
            },
        .flags =
            {
                .buff_dma = true,
                .swap_bytes = true,
            },
    };
    s_disp = lvgl_port_add_disp(&disp_cfg);
    if (s_disp == NULL) {
        ESP_LOGE(TAG, "lvgl display add failed");
        return false;
    }

    // lvgl_port_init 之后 LVGL 任务就在跑了，下面这些调用必须进锁，不然两边
    // 同时动 LVGL 内部链表，轻则丢事件重则死循环
    ui_port_lock(0);
    lv_display_add_event_cb(s_disp, on_flush_start, LV_EVENT_FLUSH_START, NULL);
    ui_port_unlock();

    if (plat_touch_init() != ESP_OK) {
        ESP_LOGW(TAG, "touch init failed, screen stays read-only");
    } else {
        ui_port_lock(0);
        lv_indev_t *indev = lv_indev_create();
        if (indev == NULL) {
            ESP_LOGW(TAG, "indev alloc failed");
        } else {
            lv_indev_set_type(indev, LV_INDEV_TYPE_POINTER);
            lv_indev_set_read_cb(indev, touch_read_cb);
            lv_indev_set_display(indev, s_disp);
        }
        ui_port_unlock();
    }

    ui_port_lock(0);
    lv_indev_t *fake = lv_indev_create();
    if (fake == NULL) {
        ESP_LOGW(TAG, "tap indev alloc failed");
    } else {
        lv_indev_set_type(fake, LV_INDEV_TYPE_POINTER);
        lv_indev_set_read_cb(fake, tap_read_cb);
        lv_indev_set_display(fake, s_disp);
    }
    ui_port_unlock();

    plat_lcd_backlight(true);
    if (width != NULL) {
        *width = (int16_t)lv_display_get_horizontal_resolution(s_disp);
    }
    if (height != NULL) {
        *height = (int16_t)lv_display_get_vertical_resolution(s_disp);
    }
    ESP_LOGI(TAG, "display up %dx%d", (int)lv_display_get_horizontal_resolution(s_disp),
             (int)lv_display_get_vertical_resolution(s_disp));
    return true;
}
