// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 XDUPWW

#include "ui_touch_cal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lvgl.h"
#include "transport/transport.h"
#include "ui_calib.h"
#include "ui_port.h"

#define CAL_TICK_MS 20
#define CAL_SAMPLES 6
#define CAL_MIN_SPAN 400
#define CAL_DOT 44

static const int16_t s_order[4][2] = {
    {-1, -1},  // 左上
    {1, -1},   // 右上
    {1, 1},    // 右下
    {-1, 1},   // 左下
};

static lv_obj_t *s_overlay;
static lv_obj_t *s_dot;
static lv_obj_t *s_hint;
static lv_timer_t *s_timer;

static int16_t s_raw[4][2];
static int s_step;
static int s_count;
static int s_fails;
static int32_t s_acc_x;
static int32_t s_acc_y;
static bool s_need_release;

// 串口日志默认级别是 WARN，用 transport 直接甩一行出去，校准过程才看得见
static void cal_line(const char *fmt, ...) {
    char line[96];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    transport_out(line);
}

static void target_pos(int step, int16_t width, int16_t height, int *x, int *y) {
    const int inset = UI_CALIB_INSET;
    *x = (s_order[step][0] < 0) ? inset : (width - 1 - inset);
    *y = (s_order[step][1] < 0) ? inset : (height - 1 - inset);
}

static void show_step(int step) {
    int16_t w = (int16_t)lv_display_get_horizontal_resolution(lv_display_get_default());
    int16_t h = (int16_t)lv_display_get_vertical_resolution(lv_display_get_default());
    int x = 0;
    int y = 0;
    target_pos(step, w, h, &x, &y);
    lv_obj_set_pos(s_dot, x - CAL_DOT / 2, y - CAL_DOT / 2);
    lv_label_set_text_fmt(s_hint, "tap the dot  %d/4", step + 1);
}

static void calib_stop(const char *reason) {
    if (s_timer != NULL) {
        lv_timer_delete(s_timer);
        s_timer = NULL;
    }
    if (s_overlay != NULL) {
        lv_obj_delete(s_overlay);
        s_overlay = NULL;
        s_dot = NULL;
        s_hint = NULL;
    }
    s_step = -1;
    cal_line("INFO cal stop %s", reason);
}

static void calib_retry(const char *why) {
    cal_line("WARN cal retry %s", why);
    if (++s_fails >= 2) {
        // 连着两次都采不到四个角，屏或触摸多半是坏的，退回默认映射别卡在这
        ui_calib_t fallback;
        ui_calib_defaults(&fallback);
        ui_calib_save(&fallback);
        ui_port_set_calib(&fallback);
        calib_stop("gave up, defaults saved");
        return;
    }
    s_step = 0;
    s_count = 0;
    s_acc_x = 0;
    s_acc_y = 0;
    s_need_release = true;
    show_step(0);
    lv_label_set_text_fmt(s_hint, "%s, tap again 1/4", why);
}

static void calib_finish(void) {
    int16_t w = (int16_t)lv_display_get_horizontal_resolution(lv_display_get_default());
    int16_t h = (int16_t)lv_display_get_vertical_resolution(lv_display_get_default());
    for (int i = 0; i < 4; i++) {
        cal_line("INFO cal corner%d %d,%d", i, s_raw[i][0], s_raw[i][1]);
    }

    // 四个角点出来的值太挤，多半是没真点到角上，这种数据不能存
    const int span_a = abs((int)s_raw[0][0] - (int)s_raw[2][0]);
    const int span_b = abs((int)s_raw[0][1] - (int)s_raw[2][1]);
    if (span_a < CAL_MIN_SPAN && span_b < CAL_MIN_SPAN) {
        calib_retry("corners too close");
        return;
    }

    ui_calib_t calib;
    if (!ui_calib_solve(s_raw, w, h, UI_CALIB_INSET, &calib)) {
        calib_retry("solve failed");
        return;
    }
    ui_calib_save(&calib);
    ui_port_set_calib(&calib);
    cal_line("INFO cal ok ax=%u ay=%u gx=%.4f gy=%.4f", calib.axis_x, calib.axis_y,
             calib.gain_x, calib.gain_y);
    calib_stop("saved");
}

static void cal_tick(lv_timer_t *timer) {
    (void)timer;
    if (s_step < 0) {
        return;
    }
    int raw_x = 0;
    int raw_y = 0;
    const bool pressed = ui_port_touch_raw(&raw_x, &raw_y);
    if (s_need_release) {
        s_need_release = pressed;
        return;
    }
    if (!pressed) {
        return;
    }
    s_acc_x += raw_x;
    s_acc_y += raw_y;
    s_count++;
    if (s_count < CAL_SAMPLES) {
        return;
    }
    s_raw[s_step][0] = (int16_t)(s_acc_x / CAL_SAMPLES);
    s_raw[s_step][1] = (int16_t)(s_acc_y / CAL_SAMPLES);
    s_acc_x = 0;
    s_acc_y = 0;
    s_count = 0;
    s_step++;
    s_need_release = true;

    if (s_step >= 4) {
        calib_finish();
        return;
    }
    show_step(s_step);
}

static lv_obj_t *make_dot(lv_obj_t *parent) {
    lv_obj_t *dot = lv_obj_create(parent);
    lv_obj_set_size(dot, CAL_DOT, CAL_DOT);
    lv_obj_set_style_radius(dot, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_bg_color(dot, lv_color_hex(0x1F6FEB), 0);
    lv_obj_set_style_bg_opa(dot, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(dot, 3, 0);
    lv_obj_set_style_border_color(dot, lv_color_hex(0xFFFFFF), 0);
    lv_obj_remove_flag(dot, LV_OBJ_FLAG_SCROLLABLE);
    return dot;
}

bool ui_touch_cal_start(void) {
    if (s_overlay != NULL) {
        calib_stop("restart");
    }
    s_overlay = lv_obj_create(lv_layer_top());
    if (s_overlay == NULL) {
        return false;
    }
    lv_obj_set_size(s_overlay, LV_PCT(100), LV_PCT(100));
    lv_obj_set_pos(s_overlay, 0, 0);
    lv_obj_set_style_radius(s_overlay, 0, 0);
    lv_obj_set_style_border_width(s_overlay, 0, 0);
    lv_obj_set_style_bg_color(s_overlay, lv_color_hex(0x000000), 0);
    lv_obj_set_style_bg_opa(s_overlay, LV_OPA_80, 0);
    lv_obj_remove_flag(s_overlay, LV_OBJ_FLAG_SCROLLABLE);

    s_dot = make_dot(s_overlay);
    s_hint = lv_label_create(s_overlay);
    lv_obj_center(s_hint);
    lv_obj_set_style_text_color(s_hint, lv_color_hex(0xFFFFFF), 0);

    s_step = 0;
    s_count = 0;
    s_fails = 0;
    s_acc_x = 0;
    s_acc_y = 0;
    s_need_release = true;
    show_step(0);

    s_timer = lv_timer_create(cal_tick, CAL_TICK_MS, NULL);
    if (s_timer == NULL) {
        calib_stop("no timer");
        return false;
    }
    cal_line("INFO cal start, tap the four dots");
    return true;
}
