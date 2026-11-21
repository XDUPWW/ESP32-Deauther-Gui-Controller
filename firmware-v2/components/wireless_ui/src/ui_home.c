// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "ui_home.h"

#include <stdio.h>
#include <string.h>

#include "platform/plat_led.h"
#include "transport/transport.h"

#define LOG_LINES 9
#define LOG_COLS 46
#define LOG_TEXT_MAX (LOG_LINES * (LOG_COLS + 2) + 1)

static lv_obj_t *s_status;
static lv_obj_t *s_log;
static lv_obj_t *s_led_label;

static char s_log_text[LOG_TEXT_MAX];
static char s_log_lines[LOG_LINES][LOG_COLS + 1];

static bool s_led_on;

static void on_button(lv_event_t *event) {
    const char *line = (const char *)lv_event_get_user_data(event);
    if (line != NULL) {
        (void)transport_submit(line);
    }
}

static void on_led(lv_event_t *event) {
    (void)event;
    s_led_on = !s_led_on;
    plat_led_set(s_led_on);
    lv_label_set_text(s_led_label, s_led_on ? "LED on" : "LED off");
}

static lv_obj_t *make_button(lv_obj_t *row, const char *text, lv_event_cb_t cb,
                             const char *payload) {
    lv_obj_t *btn = lv_button_create(row);
    lv_obj_set_flex_grow(btn, 1);
    lv_obj_set_height(btn, 44);
    lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, (void *)payload);
    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, text);
    lv_obj_center(label);
    return btn;
}

static void rebuild_log(void) {
    size_t used = 0;
    s_log_text[0] = '\0';
    for (int i = 0; i < LOG_LINES; i++) {
        if (s_log_lines[i][0] == '\0') {
            continue;
        }
        const int n = snprintf(s_log_text + used, sizeof(s_log_text) - used, "%s\n",
                               s_log_lines[i]);
        if (n <= 0) {
            break;
        }
        used += (size_t)n;
        if (used >= sizeof(s_log_text) - 1) {
            break;
        }
    }
    if (s_log != NULL) {
        lv_label_set_text(s_log, s_log_text);
    }
}

void ui_home_push_line(const char *line) {
    if (line == NULL) {
        return;
    }
    for (int i = 1; i < LOG_LINES; i++) {
        memcpy(s_log_lines[i - 1], s_log_lines[i], sizeof(s_log_lines[0]));
    }
    strncpy(s_log_lines[LOG_LINES - 1], line, LOG_COLS);
    s_log_lines[LOG_LINES - 1][LOG_COLS] = '\0';
    rebuild_log();
}

void ui_home_refresh(uint32_t uptime_s, uint32_t heap_kb) {
    if (s_status == NULL) {
        return;
    }
    lv_label_set_text_fmt(s_status, "up %us   heap %uKB", (unsigned)uptime_s, (unsigned)heap_kb);
}

void ui_home_set_led_state(bool on) {
    s_led_on = on;
    if (s_led_label != NULL) {
        lv_label_set_text(s_led_label, on ? "LED on" : "LED off");
    }
}

void ui_home_create(void) {
    lv_obj_t *root = lv_screen_active();
    lv_obj_set_style_bg_color(root, lv_color_hex(0x0E1116), 0);
    lv_obj_set_style_bg_opa(root, LV_OPA_COVER, 0);
    lv_obj_set_style_text_color(root, lv_color_hex(0xE6EDF3), 0);
    lv_obj_set_style_pad_all(root, 8, 0);
    lv_obj_set_style_pad_row(root, 8, 0);
    lv_obj_set_flex_flow(root, LV_FLEX_FLOW_COLUMN);

    lv_obj_t *title = lv_label_create(root);
    lv_label_set_text(title, "AirBench");
    lv_obj_set_style_text_color(title, lv_color_hex(0x58A6FF), 0);

    s_status = lv_label_create(root);
    lv_label_set_text(s_status, "booting");
    lv_obj_set_style_text_color(s_status, lv_color_hex(0x8B949E), 0);

    lv_obj_t *log_box = lv_obj_create(root);
    lv_obj_set_width(log_box, LV_PCT(100));
    lv_obj_set_flex_grow(log_box, 1);
    lv_obj_set_style_bg_color(log_box, lv_color_hex(0x161B22), 0);
    lv_obj_set_style_border_color(log_box, lv_color_hex(0x30363D), 0);
    lv_obj_set_style_border_width(log_box, 1, 0);
    lv_obj_set_style_radius(log_box, 6, 0);
    lv_obj_set_style_pad_all(log_box, 6, 0);
    lv_obj_set_scroll_dir(log_box, LV_DIR_VER);

    s_log = lv_label_create(log_box);
    lv_obj_set_width(s_log, LV_PCT(100));
    lv_label_set_long_mode(s_log, LV_LABEL_LONG_MODE_WRAP);
    lv_label_set_text(s_log, "");
    lv_obj_set_style_text_color(s_log, lv_color_hex(0xC9D1D9), 0);

    lv_obj_t *row1 = lv_obj_create(root);
    lv_obj_set_width(row1, LV_PCT(100));
    lv_obj_set_height(row1, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(row1, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(row1, 0, 0);
    lv_obj_set_style_pad_all(row1, 0, 0);
    lv_obj_set_style_pad_column(row1, 8, 0);
    lv_obj_set_flex_flow(row1, LV_FLEX_FLOW_ROW);

    make_button(row1, "PING", on_button, "system.ping");
    make_button(row1, "INFO", on_button, "system.info");

    lv_obj_t *row2 = lv_obj_create(root);
    lv_obj_set_width(row2, LV_PCT(100));
    lv_obj_set_height(row2, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(row2, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(row2, 0, 0);
    lv_obj_set_style_pad_all(row2, 0, 0);
    lv_obj_set_style_pad_column(row2, 8, 0);
    lv_obj_set_flex_flow(row2, LV_FLEX_FLOW_ROW);

    s_led_label = lv_label_create(row2);
    lv_label_set_text(s_led_label, "LED off");
    lv_obj_set_flex_grow(s_led_label, 1);

    make_button(row2, "TOUCH", on_button, "system.touch");
    make_button(row2, "LED", on_led, NULL);

    ui_home_push_line("INFO ui ready");
}
